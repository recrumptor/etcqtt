//! Мелкие утилиты: время, атомарная запись, случайные идентификаторы, percent-кодирование.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Монотонные секунды (для интервалов; не зависит от смены системного времени).
pub fn mono_secs() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64
}

/// Атомарная запись: tmp в том же каталоге + rename. mode — права файла.
pub fn write_atomic(path: &str, data: &[u8], mode: u32) -> std::io::Result<()> {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        if !dir.as_os_str().is_empty() {
            let _ = fs::create_dir_all(dir);
        }
    }
    let tmp = format!("{}.tmp.{}", path, std::process::id());
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf
}

pub fn random_hex(nbytes: usize) -> String {
    random_bytes(nbytes).iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn uuid_v4() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{:02x}", x)).collect();
    format!("{}-{}-{}-{}-{}", h[0..4].concat(), h[4..6].concat(), h[6..8].concat(), h[8..10].concat(), h[10..16].concat())
}

pub fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 3 > b.len() {
                    return None;
                }
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{:02X}", c));
        }
    }
    o
}

/// Маскирование секретов в строках журнала.
pub fn redact(s: &str) -> String {
    let mut out = s.to_string();
    for key in ["password=", "token=", "vk_js_token=", "device_id=", "success_token=", "hashes="] {
        let mut from = 0;
        while let Some(pos) = out[from..].find(key) {
            let start = from + pos + key.len();
            let end = out[start..].find(|c: char| c == '&' || c.is_whitespace() || c == '"').map(|e| start + e).unwrap_or(out.len());
            out.replace_range(start..end, "…");
            from = start + 3;
        }
    }
    out
}

pub fn file_mtime(path: &str) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pct() {
        assert_eq!(pct_decode("p%40ss").unwrap(), "p@ss");
        assert_eq!(pct_decode("a%2Bb").unwrap(), "a+b");
        assert!(pct_decode("bad%2").is_none());
        assert_eq!(pct_encode("p@ss+"), "p%40ss%2B");
    }
    #[test]
    fn uuid_shape() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
    #[test]
    fn redact_works() {
        assert_eq!(redact("x password=abc&y=1"), "x password=…&y=1");
    }
}
