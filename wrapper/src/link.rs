//! Ссылки csqtt://.
//!
//! Ядро/приложение 2.5.0+: `csqtt://` + base64url(IV(12) ‖ AES-256-GCM(шифртекст ‖ тег)), внутри
//! `connect?v=2&host=..&peer=PORT&password=..&hashes=a+b` (или `token=..` вместо хешей). Ключ — константа
//! (SHA-256("csqtt-chiper-key")), то есть это обфускация, а не защита; IV = первые 12 байт HMAC-SHA256(ключ, текст).
//! Для совместимости разбираются и прежние открытые ссылки `csqtt://connect?v=2&…` и `csqtt://пароль@host:port`.
use crate::util::{pct_decode, pct_encode};
use aws_lc_rs::{aead, digest, hmac};

const KEY_SEED: &str = "csqtt-chiper-key";
/// Приложение принимает до 7 хешей в ссылке; ядро использует первые 6 (`.take(MAX_VK_HASHES)`).
const MAX_HASHES: usize = 7;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Link {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub hashes: Vec<String>,
    /// VK access token (режим auto_js) — взаимоисключающ с хешами.
    pub token: String,
}

impl Link {
    pub fn peer(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn key_bytes() -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, KEY_SEED.as_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(d.as_ref());
    k
}

fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b64url_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = String::new();
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        if ch.len() > 1 {
            o.push(T[(n >> 6) as usize & 63] as char);
        }
        if ch.len() > 2 {
            o.push(T[n as usize & 63] as char);
        }
    }
    o
}

pub fn decrypt_payload(raw: &str) -> Option<String> {
    let bytes = b64_decode_any(raw.trim())?;
    if bytes.len() < 28 {
        return None;
    }
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes()).ok()?);
    let nonce = aead::Nonce::try_assume_unique_for_key(&bytes[..12]).ok()?;
    let mut buf = bytes[12..].to_vec();
    let plain = key.open_in_place(nonce, aead::Aad::empty(), &mut buf).ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

pub fn encrypt_payload(plain: &str) -> Option<String> {
    let k = key_bytes();
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &k), plain.as_bytes());
    let iv: [u8; 12] = tag.as_ref()[..12].try_into().ok()?;
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &k).ok()?);
    let mut buf = plain.as_bytes().to_vec();
    key.seal_in_place_append_tag(aead::Nonce::try_assume_unique_for_key(&iv).ok()?, aead::Aad::empty(), &mut buf).ok()?;
    let mut all = iv.to_vec();
    all.extend_from_slice(&buf);
    Some(b64url_encode(&all))
}

/// Хеш из вставленной ссылки на звонок → чистый хеш (как stripVkUrlStatic в приложении).
pub fn strip_vk_url(input: &str) -> String {
    let mut s = input.trim().to_string();
    let lower = s.to_ascii_lowercase();
    for p in ["https://vk.com/call/join/", "http://vk.com/call/join/", "https://m.vk.com/call/join/", "http://m.vk.com/call/join/", "m.vk.com/call/join/", "vk.com/call/join/",
        "https://vk.ru/call/join/", "http://vk.ru/call/join/", "https://m.vk.ru/call/join/", "http://m.vk.ru/call/join/", "m.vk.ru/call/join/", "vk.ru/call/join/"]
    {
        if lower.starts_with(p) {
            s = s[p.len()..].to_string();
            break;
        }
    }
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    s.trim_end_matches('/').to_string()
}

pub fn parse(raw: &str) -> Result<Link, String> {
    let t = raw.trim();
    if !t.to_ascii_lowercase().starts_with("csqtt://") {
        return Err("ссылка должна начинаться с csqtt://".into());
    }
    let rest = t[8..].trim();
    if rest.contains('#') {
        return Err("фрагмент (#) в ссылке не поддерживается".into());
    }
    let lower = rest.to_ascii_lowercase();
    // прежний открытый формат
    if lower.starts_with("connect?") || lower == "connect" {
        return parse_v2(rest.splitn(2, '?').nth(1).unwrap_or(""));
    }
    // legacy: password@host:port
    if let Some((pw, hp)) = rest.split_once('@') {
        let hp = hp.trim_end_matches('/');
        let (host, port) = hp.rsplit_once(':').ok_or("нет порта в legacy-ссылке")?;
        let port: u16 = port.parse().map_err(|_| "некорректный порт")?;
        let password = pct_decode(pw).ok_or("некорректное кодирование пароля")?;
        if host.is_empty() || password.is_empty() || port == 0 {
            return Err("пустой host/пароль/порт".into());
        }
        return Ok(Link { host: host.trim_matches(|c| c == '[' || c == ']').to_string(), port, password, ..Default::default() });
    }
    // зашифрованный формат 2.5.0+
    let plain = decrypt_payload(rest).ok_or("не удалось расшифровать ссылку: повреждена, обрезана или неизвестный формат")?;
    let query = plain
        .strip_prefix("csqtt://connect?")
        .or_else(|| plain.strip_prefix("connect?"))
        .or_else(|| plain.strip_prefix("csqtt://").map(|x| x.trim_start_matches("connect?")))
        .unwrap_or(&plain);
    parse_v2(query)
}

fn parse_v2(query: &str) -> Result<Link, String> {
    let q = query.replace("&amp;", "&");
    let (mut v, mut host, mut peer, mut password, mut hashes_raw, mut token_raw) = (None, None, None, None, None, None);
    for part in q.split(|c| c == '&' || c == ';') {
        let Some((k, val)) = part.split_once('=') else { continue };
        let slot = match k.to_ascii_lowercase().as_str() {
            "v" => &mut v,
            "host" => &mut host,
            "peer" => &mut peer,
            "password" => &mut password,
            "hashes" => &mut hashes_raw,
            "token" => &mut token_raw,
            _ => continue,
        };
        if slot.is_some() {
            return Err(format!("параметр {} повторяется", k));
        }
        *slot = Some(val.to_string());
    }
    if v.as_deref() != Some("2") {
        return Err("поддерживается только v=2".into());
    }
    let host = pct_decode(&host.ok_or("нет host")?).ok_or("host: плохое кодирование")?;
    if host.trim().is_empty() || host == "0.0.0.0" || host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost") {
        return Err("недопустимый host".into());
    }
    let port: u16 = pct_decode(&peer.ok_or("нет peer")?)
        .and_then(|s| s.parse().ok())
        .filter(|p| *p != 0)
        .ok_or("peer: некорректный порт")?;
    let password = match password {
        Some(p) => pct_decode(&p).ok_or("password: плохое кодирование")?.trim().to_string(),
        None => String::new(), // «ссылка владельца» / только хеши: пароль задаётся отдельно
    };
    if host.chars().any(char::is_whitespace) || password.chars().any(char::is_whitespace) {
        return Err("пробелы в host/password недопустимы".into());
    }
    let mut hashes = Vec::new();
    if let Some(h) = hashes_raw {
        // литеральный '+' = разделитель; плюс внутри хеша кодируется как %2B
        let parts: Vec<&str> = h.split('+').collect();
        if parts.is_empty() || parts.len() > MAX_HASHES || parts.iter().any(|p| p.is_empty()) {
            return Err(format!("hashes: ожидается от 1 до {} хешей", MAX_HASHES));
        }
        for item in parts {
            let d = strip_vk_url(&pct_decode(item).ok_or("hashes: плохое кодирование")?);
            if d.is_empty() || d.chars().any(char::is_whitespace) {
                return Err("hashes: пустой хеш или пробелы".into());
            }
            if hashes.contains(&d) {
                return Err("hashes: повторяющийся хеш".into());
            }
            hashes.push(d);
        }
    }
    let mut token = String::new();
    if let Some(t) = token_raw {
        token = pct_decode(&t).ok_or("token: плохое кодирование")?.trim().to_string();
        if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_whitespace) {
            return Err("token: пустой, длиннее 4096 или с пробелами".into());
        }
    }
    if !hashes.is_empty() && !token.is_empty() {
        return Err("в ссылке одновременно hashes и token".into());
    }
    Ok(Link { host, port, password, hashes, token })
}

/// Текст внутри ссылки: `connect?v=2&host=..&peer=..&password=..[&hashes=a+b | &token=..]`.
pub fn plain_query(l: &Link) -> String {
    let mut s = format!("connect?v=2&host={}&peer={}&password={}", pct_encode(&l.host), l.port, pct_encode(&l.password));
    if !l.hashes.is_empty() {
        s.push_str("&hashes=");
        s.push_str(&l.hashes.iter().map(|h| pct_encode(h)).collect::<Vec<_>>().join("+"));
    } else if !l.token.is_empty() {
        s.push_str("&token=");
        s.push_str(&pct_encode(&l.token));
    }
    s
}

/// `encrypted` = формат 2.5.0+ (зашифрованный); иначе прежний открытый.
pub fn export(l: &Link, encrypted: bool) -> String {
    let plain = plain_query(l);
    if encrypted {
        if let Some(e) = encrypt_payload(&plain) {
            return format!("csqtt://{}", e);
        }
    }
    format!("csqtt://{}", plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Ссылка из тестов приложения (CsqttLinkTest.parsesRustEncryptedLink), сгенерированная серверным кодом на Rust.
    const RUST_LINK: &str = "csqtt://GNANVH0fhD6MisDFiWP_P0Bm_FHr-frawgfwur3Zx4ipjJx8gk-M6ZZbnDr_2clwPmzO-QS8AkiHLaMXyYO1RHyPeehXPqTc6jJi_iw72fRQJ9AR918ne5XsBRg";

    #[test]
    fn decrypts_server_generated_link() {
        let l = parse(RUST_LINK).unwrap();
        assert_eq!((l.host.as_str(), l.port, l.password.as_str()), ("1.2.3.4", 46000, "testpass"));
        // лишний параметр workers=36 внутри ссылки приложение игнорирует — игнорируем и мы
        assert!(l.hashes.is_empty() && l.token.is_empty());
    }

    #[test]
    fn encryption_matches_independent_implementation() {
        // эталоны получены независимой реализацией (Python/cryptography): ключ SHA-256("csqtt-chiper-key"),
        // IV = HMAC-SHA256(ключ, текст)[..12], AES-256-GCM, base64url без паддинга
        assert_eq!(encrypt_payload("connect?v=2&host=203.0.113.7&peer=46000").unwrap(), "PprOshZXXGqHfnA8FWUe9YJPNKSpL8_2mLVfff0qmql9bHopUPMaLs3X2oI408LmTqPZL6N5O9twKiFwYv_R-9lddA");
        assert_eq!(
            encrypt_payload("connect?v=2&host=vps.example&peer=46000&password=Secret123&hashes=abcdefghijklmnop1+qrstuvwxyz012345").unwrap(),
            "PAn6iHjQbhvg7pfQK8V3sDf27HRVFWL7sMjSf0AM4rDrS6zb_hueGRIDWhp4LKcIDjHaPbYuzo0AxLkoNixRhcBQN0LGJUsOVLOJi-rQTXb33LeyALqS_tJBGjLBKgvDv_m1haddgBVYjKzdR2_8Z-LOum73PnnZsbffgGSF-RQ"
        );
        assert_eq!(decrypt_payload("PAn6iHjQbhvg7pfQK8V3sDf27HRVFWL7sMjSf0AM4rDrS6zb_hueGRIDWhp4LKcIDjHaPbYuzo0AxLkoNixRhcBQN0LGJUsOVLOJi-rQTXb33LeyALqS_tJBGjLBKgvDv_m1haddgBVYjKzdR2_8Z-LOum73PnnZsbffgGSF-RQ").unwrap(), "connect?v=2&host=vps.example&peer=46000&password=Secret123&hashes=abcdefghijklmnop1+qrstuvwxyz012345");
    }

    #[test]
    fn roundtrip_with_hashes_and_special_chars() {
        let l = Link { host: "vps.example".into(), port: 46000, password: "p@ss+w/rd".into(), hashes: vec!["abcdefghijklmnop1".into(), "q+r-s_t".into()], token: String::new() };
        let e = export(&l, true);
        assert!(e.starts_with("csqtt://") && !e.contains("vps.example") && !e.contains("connect"));
        assert_eq!(parse(&e).unwrap(), l);
        assert_eq!(export(&l, true), e, "шифрование детерминировано");
        assert_eq!(parse(&export(&l, false)).unwrap(), l, "открытый формат тоже читается");
    }

    #[test]
    fn token_link_and_owner_link() {
        let t = Link { host: "h.example".into(), port: 1, password: "pw".into(), hashes: vec![], token: "vk1.a.XYZ".into() };
        assert_eq!(parse(&export(&t, true)).unwrap(), t);
        let owner = parse(&format!("csqtt://{}", encrypt_payload("connect?v=2&host=203.0.113.7&peer=46000").unwrap())).unwrap();
        assert_eq!((owner.password.as_str(), owner.host.as_str(), owner.port), ("", "203.0.113.7", 46000));
        assert!(parse("csqtt://connect?v=2&host=h&peer=1&password=p&hashes=aaaa&token=t").is_err());
    }

    #[test]
    fn rejects_broken_links() {
        let good = RUST_LINK.trim_start_matches("csqtt://");
        let mut raw = b64_decode_any(good).unwrap();
        *raw.last_mut().unwrap() ^= 1; // подмена тега GCM
        assert!(parse(&format!("csqtt://{}", b64url_encode(&raw))).is_err());
        assert!(parse(&format!("csqtt://{}", b64url_encode(&[0u8; 10]))).is_err(), "обрезанная");
        assert!(parse("http://x").is_err());
        assert!(parse("csqtt://connect?v=3&host=h&peer=1&password=s").is_err());
        assert!(parse("csqtt://connect?v=2&host=h&peer=0&password=s").is_err());
        assert!(parse("csqtt://connect?v=2&host=127.0.0.1&peer=1&password=s").is_err());
        assert!(parse("csqtt://connect?v=2&host=h&peer=1&password=s&hashes=a+b+c+d+e+f+g").is_ok(), "7 хешей допустимы, как в приложении");
        assert!(parse("csqtt://connect?v=2&host=h&peer=1&password=s&hashes=a+b+c+d+e+f+g+h").is_err(), "больше 7 хешей");
        assert!(parse("csqtt://connect?v=2&host=h&peer=1&password=s&hashes=aa+aa").is_err(), "дубли");
    }

    #[test]
    fn legacy_and_plain_formats() {
        let l = parse("csqtt://connect?v=2&host=203.0.113.7&peer=46000&password=p%40ss").unwrap();
        assert_eq!((l.host.as_str(), l.port, l.password.as_str()), ("203.0.113.7", 46000, "p@ss"));
        let l = parse("csqtt://connect?v=2&host=h&peer=1&password=s&hashes=abc+def%2Bg").unwrap();
        assert_eq!(l.hashes, vec!["abc", "def+g"]);
        assert_eq!(parse("csqtt://secret@203.0.113.7:46000").unwrap().peer(), "203.0.113.7:46000");
    }

    #[test]
    fn strips_vk_call_urls() {
        assert_eq!(strip_vk_url("https://vk.com/call/join/AbC123-_x?utm=1#f"), "AbC123-_x");
        assert_eq!(strip_vk_url("vk.ru/call/join/Zz9/"), "Zz9");
        assert_eq!(strip_vk_url("plainhash"), "plainhash");
    }
}
