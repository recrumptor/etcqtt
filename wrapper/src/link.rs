//! Ссылки csqtt:// (формат Android-клиента): v2 `csqtt://connect?v=2&host=..&peer=PORT&password=..&hashes=a+b`
//! и legacy `csqtt://password@host:port`.
use crate::util::{pct_decode, pct_encode};

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub hashes: Vec<String>,
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

pub fn parse(raw: &str) -> Result<Link, String> {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    if !lower.starts_with("csqtt://") {
        return Err("ссылка должна начинаться с csqtt://".into());
    }
    let rest = &t[8..];
    if rest.contains('#') {
        return Err("фрагмент (#) в ссылке не поддерживается".into());
    }
    if rest.to_ascii_lowercase().starts_with("connect?") || rest.eq_ignore_ascii_case("connect") {
        return parse_v2(rest.splitn(2, '?').nth(1).unwrap_or(""));
    }
    // legacy: password@host:port
    let (pw, hp) = rest.split_once('@').ok_or("неизвестный формат ссылки")?;
    let hp = hp.trim_end_matches('/');
    let (host, port) = hp.rsplit_once(':').ok_or("нет порта в legacy-ссылке")?;
    let port: u16 = port.parse().map_err(|_| "некорректный порт")?;
    let password = pct_decode(pw).ok_or("некорректное кодирование пароля")?;
    if host.is_empty() || password.is_empty() || port == 0 {
        return Err("пустой host/пароль/порт".into());
    }
    Ok(Link { host: host.trim_matches(|c| c == '[' || c == ']').to_string(), port, password, hashes: vec![] })
}

fn parse_v2(query: &str) -> Result<Link, String> {
    let q = query.replace("&amp;", "&");
    let mut v = None;
    let mut host = None;
    let mut peer = None;
    let mut password = None;
    let mut hashes_raw = None;
    for part in q.split(|c| c == '&' || c == ';') {
        if part.is_empty() {
            continue;
        }
        let Some((k, val)) = part.split_once('=') else { continue };
        match k.to_ascii_lowercase().as_str() {
            "v" => v = Some(val.to_string()),
            "host" => host = Some(val.to_string()),
            "peer" => peer = Some(val.to_string()),
            "password" => password = Some(val.to_string()),
            "hashes" => hashes_raw = Some(val.to_string()),
            _ => {}
        }
    }
    if v.as_deref() != Some("2") {
        return Err("поддерживается только v=2".into());
    }
    let host = pct_decode(&host.ok_or("нет host")?).ok_or("host: плохое кодирование")?;
    let port: u16 = pct_decode(&peer.ok_or("нет peer")?)
        .and_then(|s| s.parse().ok())
        .filter(|p| *p != 0)
        .ok_or("peer: некорректный порт")?;
    let password = pct_decode(&password.ok_or("нет password")?).ok_or("password: плохое кодирование")?;
    if host.trim().is_empty() || password.trim().is_empty() {
        return Err("пустой host или password".into());
    }
    if host.chars().any(char::is_whitespace) || password.chars().any(char::is_whitespace) {
        return Err("пробелы в host/password недопустимы".into());
    }
    let mut hashes = Vec::new();
    if let Some(h) = hashes_raw {
        // литеральный '+' = разделитель; плюс внутри хеша кодируется как %2B
        for item in h.split('+') {
            let d = pct_decode(item).ok_or("hashes: плохое кодирование")?;
            if !d.trim().is_empty() {
                hashes.push(d.trim().to_string());
            }
        }
        if hashes.is_empty() {
            return Err("hashes пуст".into());
        }
    }
    Ok(Link { host, port, password, hashes })
}

pub fn export(l: &Link) -> String {
    let mut s = format!("csqtt://connect?v=2&host={}&peer={}&password={}", pct_encode(&l.host), l.port, pct_encode(&l.password));
    if !l.hashes.is_empty() {
        let hs: Vec<String> = l.hashes.iter().map(|h| pct_encode(h)).collect();
        s.push_str("&hashes=");
        s.push_str(&hs.join("+"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v2_basic() {
        let l = parse("csqtt://connect?v=2&host=203.0.113.7&peer=46000&password=p%40ss").unwrap();
        assert_eq!((l.host.as_str(), l.port, l.password.as_str()), ("203.0.113.7", 46000, "p@ss"));
        assert!(l.hashes.is_empty());
    }
    #[test]
    fn v2_hashes_and_plus() {
        let l = parse("csqtt://connect?v=2&host=h&peer=1&password=s&hashes=abc+def%2Bg").unwrap();
        assert_eq!(l.hashes, vec!["abc", "def+g"]);
        assert_eq!(parse(&export(&l)).unwrap(), l);
    }
    #[test]
    fn legacy() {
        let l = parse("csqtt://secret@203.0.113.7:46000").unwrap();
        assert_eq!(l.peer(), "203.0.113.7:46000");
    }
    #[test]
    fn rejects() {
        assert!(parse("http://x").is_err());
        assert!(parse("csqtt://connect?v=3&host=h&peer=1&password=s").is_err());
        assert!(parse("csqtt://connect?v=2&host=h&peer=0&password=s").is_err());
    }
}
