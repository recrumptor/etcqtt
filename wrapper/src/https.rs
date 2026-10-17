//! Минимальный HTTPS/1.1-клиент поверх rustls (Connection: close, без gzip).
//! Нужен только прокси CAPTCHA-помощника; наружу ходит лишь к allowlist-доменам VK/OK.
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

const MAX_BODY: usize = 8 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Дополнительные корни (например, корпоративный MITM-прокси): CSQTT_CA_FILE=/path/ca.pem
        if let Ok(path) = std::env::var("CSQTT_CA_FILE") {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for der in pem_certs(&text) {
                    let _ = roots.add(rustls::pki_types::CertificateDer::from(der));
                }
            }
        }
        Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
    })
    .clone()
}

fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn pem_certs(text: &str) -> Vec<Vec<u8>> {
    let mut res = Vec::new();
    let mut cur: Option<String> = None;
    for l in text.lines() {
        let l = l.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            if let Some(b) = cur.take() {
                res.push(b64_decode(&b));
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
        }
    }
    res
}

pub fn request(method: &str, host: &str, path_q: &str, headers: &[(String, String)], body: &[u8]) -> Result<Resp, String> {
    let addrs: Vec<_> = (host, 443u16).to_socket_addrs().map_err(|e| format!("DNS {}: {}", host, e))?.collect();
    let mut tcp = None;
    let mut last = String::from("нет адресов");
    for a in &addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(8)) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let tcp = tcp.ok_or_else(|| format!("connect {}: {}", host, last))?;
    tcp.set_read_timeout(Some(IO_TIMEOUT)).ok();
    tcp.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("SNI: {}", e))?;
    let conn = rustls::ClientConnection::new(tls_config(), name).map_err(|e| format!("TLS: {}", e))?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n", method, path_q, host);
    for (k, v) in headers {
        let kl = k.to_ascii_lowercase();
        if matches!(kl.as_str(), "host" | "connection" | "accept-encoding" | "content-length" | "transfer-encoding") {
            continue;
        }
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !body.is_empty() || method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| format!("write: {}", e))?;
    tls.write_all(body).map_err(|e| format!("write body: {}", e))?;
    tls.flush().ok();

    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY + 65536 {
                    return Err("ответ слишком большой".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // нет close_notify
            Err(e) => {
                if find(&raw, b"\r\n\r\n").is_some() {
                    break;
                }
                return Err(format!("read: {}", e));
            }
        }
    }
    parse_response(&raw)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub fn parse_response(raw: &[u8]) -> Result<Resp, String> {
    let sep = find(raw, b"\r\n\r\n").ok_or("нет заголовков в ответе")?;
    let head = String::from_utf8_lossy(&raw[..sep]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).ok_or("плохая статус-строка")?;
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let mut body = raw[sep + 4..].to_vec();
    let get = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
    if get("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) {
        body = dechunk(&body)?;
    } else if let Some(cl) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.truncate(cl);
    }
    if body.len() > MAX_BODY {
        return Err("тело ответа слишком большое".into());
    }
    Ok(Resp { status, headers, body })
}

fn dechunk(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let rel = find(&b[i..], b"\r\n").ok_or("chunked: обрыв")?;
        let size_s = String::from_utf8_lossy(&b[i..i + rel]).to_string();
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "chunked: размер")?;
        i += rel + 2;
        if size == 0 {
            return Ok(out);
        }
        if i + size > b.len() {
            return Err("chunked: обрыв данных".into());
        }
        out.extend_from_slice(&b[i..i + size]);
        i += size + 2;
        if i > b.len() {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_plain_and_chunked() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: y\r\n\r\nabcEXTRA").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"abc"[..]));
        let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.body, b"abcde");
    }
    /// Нужна сеть: cargo test -- --ignored
    #[test]
    #[ignore]
    fn live_tls() {
        let r = request("GET", "api.github.com", "/zen", &[("User-Agent".into(), "csqtt-test".into())], b"").unwrap();
        assert!(r.status == 200 || r.status == 403, "status {}", r.status);
        assert!(!r.body.is_empty());
    }
}
