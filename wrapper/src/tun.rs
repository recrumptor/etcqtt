//! Создание TUN-интерфейса и передача дескриптора ядру через абстрактный
//! Unix-сокет (SCM_RIGHTS) — тот же протокол, что у Android VpnService.
//! Контракт interface-only: маршруты/правила/DNS/firewall не трогаем.
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::{Duration, Instant};

// _IOW('T', 202, int). На MIPS/PowerPC/SPARC другая раскладка полей ioctl.
#[cfg(any(target_arch = "mips", target_arch = "mips64", target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64"))]
const IOC_WRITE: u64 = 4;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64", target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64")))]
const IOC_WRITE: u64 = 1;
#[cfg(any(target_arch = "mips", target_arch = "mips64", target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64"))]
const IOC_SIZEBITS: u64 = 13;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64", target_arch = "powerpc", target_arch = "powerpc64", target_arch = "sparc", target_arch = "sparc64")))]
const IOC_SIZEBITS: u64 = 14;
const IOC_DIRSHIFT: u64 = 8 + 8 + IOC_SIZEBITS;
const TUNSETIFF: u64 = (IOC_WRITE << IOC_DIRSHIFT) | (4 << 16) | ((b'T' as u64) << 8) | 202;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_UP: i16 = 0x1;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;
const SIOCSIFMTU: u64 = 0x8922;

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> io::Result<IfReq> {
        let b = name.as_bytes();
        if b.is_empty() || b.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "недопустимое имя интерфейса"));
        }
        let mut r = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
        r.name[..b.len()].copy_from_slice(b);
        Ok(r)
    }
    fn set_i16(&mut self, v: i16) {
        self.data[..2].copy_from_slice(&v.to_ne_bytes());
    }
    fn get_i16(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }
    fn set_i32(&mut self, v: i32) {
        self.data[..4].copy_from_slice(&v.to_ne_bytes());
    }
    fn set_addr(&mut self, a: Ipv4Addr) {
        let sa = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) },
            sin_zero: [0; 8],
        };
        let p = &sa as *const _ as *const u8;
        let n = mem::size_of::<libc::sockaddr_in>().min(24);
        self.data[..n].copy_from_slice(unsafe { std::slice::from_raw_parts(p, n) });
    }
}

fn set_addr_on(sock: RawFd, name: &str, ip: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let mut r = IfReq::new(name)?;
    r.set_addr(ip);
    ioctl(sock, SIOCSIFADDR, &mut r)?;
    let mask = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix.min(32) as u32) };
    let mut r = IfReq::new(name)?;
    r.set_addr(Ipv4Addr::from(mask));
    ioctl(sock, SIOCSIFNETMASK, &mut r)
}

/// Назначает (заменяет) IPv4-адрес существующего интерфейса. Нужен для адреса, выданного сервером
/// (TUNCONF): без адреса на csqtt0 привязанные через SO_BINDTODEVICE сокеты не выберут source-адрес.
pub fn set_addr(name: &str, ip: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    set_addr_on(sock.as_raw_fd(), name, ip, prefix)
}

/// "TUNCONF:10.66.67.3:1.1.1.1[:...]" → (клиентский IP, DNS)
pub fn parse_tunconf(s: &str) -> Option<(Ipv4Addr, String)> {
    let rest = s.trim().strip_prefix("TUNCONF:")?;
    let mut it = rest.splitn(3, ':');
    let ip: Ipv4Addr = it.next()?.trim().parse().ok()?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return None;
    }
    Some((ip, it.next().unwrap_or("").trim().to_string()))
}

pub struct Tun {
    pub fd: OwnedFd,
    pub name: String,
}

fn ioctl(fd: RawFd, req: u64, arg: *mut IfReq) -> io::Result<()> {
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

pub fn exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

/// Создаёт непостоянный TUN (исчезает при закрытии дескриптора), без PI-заголовка.
pub fn create(name: &str, mtu: u32, addr: Option<(Ipv4Addr, u8)>) -> io::Result<Tun> {
    let path = std::ffi::CString::new("/dev/net/tun").unwrap();
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut req = IfReq::new(name)?;
    req.set_i16(IFF_TUN | IFF_NO_PI);
    ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req)?;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    let s = sock.as_raw_fd();
    let mut r = IfReq::new(name)?;
    r.set_i32(mtu as i32);
    ioctl(s, SIOCSIFMTU, &mut r)?;
    if let Some((ip, prefix)) = addr {
        set_addr_on(s, name, ip, prefix)?;
    }
    let mut r = IfReq::new(name)?;
    ioctl(s, SIOCGIFFLAGS, &mut r)?;
    let fl = r.get_i16() | IFF_UP;
    r.set_i16(fl);
    ioctl(s, SIOCSIFFLAGS, &mut r)?;
    Ok(Tun { fd, name: name.to_string() })
}

/// "10.66.67.7/24" → (ip, prefix)
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (a, p) = s.trim().split_once('/')?;
    let ip: Ipv4Addr = a.parse().ok()?;
    let p: u8 = p.parse().ok()?;
    if p > 32 { None } else { Some((ip, p)) }
}

/// Отправляет дескриптор ядру: connect к абстрактному сокету `uds`, sendmsg+SCM_RIGHTS,
/// ждёт ack-байт. Ядро поднимает слушатель не мгновенно — повторяем connect до `timeout`.
#[allow(dead_code)]
pub fn send_fd(uds: &str, tun_fd: RawFd, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match try_send(uds, tun_fd) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let retry = matches!(e.raw_os_error(), Some(libc::ECONNREFUSED) | Some(libc::ENOENT));
                if !retry || Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

pub fn try_send(uds: &str, tun_fd: RawFd) -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let nb = uds.as_bytes();
    if nb.len() + 1 > addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "слишком длинное имя сокета"));
    }
    for (i, b) in nb.iter().enumerate() {
        addr.sun_path[i + 1] = *b as libc::c_char; // sun_path[0] = 0 → abstract
    }
    let len = (mem::size_of::<libc::sa_family_t>() + 1 + nb.len()) as libc::socklen_t;
    if unsafe { libc::connect(sock.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // sendmsg: 1 байт данных + SCM_RIGHTS
    let mut payload = [1u8];
    let mut iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut _, iov_len: 1 };
    let space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&tun_fd as *const RawFd as *const u8, libc::CMSG_DATA(c), mem::size_of::<RawFd>());
    }
    if unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // ack
    let mut pfd = libc::pollfd { fd: sock.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let pr = unsafe { libc::poll(&mut pfd, 1, 5000) };
    if pr <= 0 {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "ядро не подтвердило приём TUN"));
    }
    let mut ack = [0u8; 1];
    let n = unsafe { libc::recv(sock.as_raw_fd(), ack.as_mut_ptr() as *mut _, 1, 0) };
    if n != 1 || ack[0] != 1 {
        return Err(io::Error::new(io::ErrorKind::Other, "неверный ack от ядра"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr() {
        assert_eq!(parse_cidr("10.66.67.7/24"), Some((Ipv4Addr::new(10, 66, 67, 7), 24)));
        assert!(parse_cidr("10.0.0.1").is_none());
        assert!(parse_cidr("10.0.0.1/33").is_none());
    }
    #[test]
    fn tunconf() {
        assert_eq!(parse_tunconf("TUNCONF:10.66.67.3:1.1.1.1"), Some((Ipv4Addr::new(10, 66, 67, 3), "1.1.1.1".to_string())));
        assert_eq!(parse_tunconf(" TUNCONF:10.66.67.9:8.8.8.8:extra "), Some((Ipv4Addr::new(10, 66, 67, 9), "8.8.8.8".to_string())));
        assert_eq!(parse_tunconf("TUNCONF:10.66.67.4"), Some((Ipv4Addr::new(10, 66, 67, 4), String::new())));
        assert!(parse_tunconf("TUNCONF:0.0.0.0:1.1.1.1").is_none());
        assert!(parse_tunconf("TUNCONF:nope:1.1.1.1").is_none());
        assert!(parse_tunconf("CONFIG:10.66.67.3").is_none());
    }
    #[test]
    fn ioctl_number_x86() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(TUNSETIFF, 0x400454ca);
        #[cfg(target_arch = "mips")]
        assert_eq!(TUNSETIFF, 0x800454ca);
    }

    /// Требует root и /dev/net/tun: cargo test -- --ignored
    #[test]
    #[ignore]
    fn create_and_handoff() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        let name = "csqtt_t0";
        let uds = format!("csqtt-test-{}", std::process::id());
        let l = UnixListener::bind_addr(&SocketAddr::from_abstract_name(uds.as_bytes()).unwrap()).unwrap();
        let h = std::thread::spawn(move || {
            let (conn, _) = l.accept().unwrap();
            let fd = conn.as_raw_fd();
            let mut data = [0u8; 1];
            let mut iov = libc::iovec { iov_base: data.as_mut_ptr() as *mut _, iov_len: 1 };
            let mut cbuf = [0u8; 64];
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cbuf.len() as _;
            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            assert_eq!(n, 1);
            let got = unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                assert!(!c.is_null());
                assert_eq!((*c).cmsg_type, libc::SCM_RIGHTS);
                let mut f: RawFd = -1;
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut f as *mut RawFd as *mut u8, mem::size_of::<RawFd>());
                f
            };
            let ack = [1u8];
            unsafe { libc::send(fd, ack.as_ptr() as *const _, 1, 0) };
            got
        });
        let tun = create(name, 1280, Some((Ipv4Addr::new(10, 255, 77, 1), 30))).expect("create tun");
        assert!(exists(name));
        send_fd(&uds, tun.fd.as_raw_fd(), Duration::from_secs(3)).expect("send fd");
        let got = h.join().unwrap();
        assert!(got >= 0);
        // MTU проверим через sysfs
        let mtu = std::fs::read_to_string(format!("/sys/class/net/{}/mtu", name)).unwrap();
        assert_eq!(mtu.trim(), "1280");
        unsafe { libc::close(got) };
        drop(tun);
    }
}
