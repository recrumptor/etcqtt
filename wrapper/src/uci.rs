//! Разбор и правка /etc/config/csqtt (формат UCI) без внешнего `uci`.
//! Правки построчные: комментарии и порядок сохраняются, запись атомарная.
use crate::util;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub ty: String,
    pub name: String,
    pub opts: HashMap<String, String>,
}

impl Section {
    pub fn get(&self, k: &str) -> &str {
        self.opts.get(k).map(|s| s.as_str()).unwrap_or("")
    }
    pub fn get_or<'a>(&'a self, k: &str, d: &'a str) -> &'a str {
        match self.opts.get(k) {
            Some(v) if !v.is_empty() => v.as_str(),
            _ => d,
        }
    }
    pub fn int(&self, k: &str, d: i64) -> i64 {
        self.get(k).trim().parse().unwrap_or(d)
    }
    pub fn flag(&self, k: &str, d: bool) -> bool {
        match self.get(k).trim() {
            "1" | "true" | "yes" | "on" | "enabled" => true,
            "0" | "false" | "no" | "off" | "disabled" => false,
            _ => d,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub text: String,
    pub sections: Vec<Section>,
}

/// Поля, которые в новой схеме живут в main, а в старой — в профиле.
pub const SHARED_FIELDS: &[&str] = &[
    "vk", "vk_js_token", "vk_hash_mode", "vk_auth_mode", "workers", "obfs", "turn_transport",
    "captcha_mode", "fingerprint", "client_ids", "device_id",
];

fn unquote(v: &str) -> String {
    let v = v.trim();
    let mut out = String::new();
    let mut chars = v.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    out.push(d);
                }
            }
            '"' => {
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        '\\' => {
                            if let Some(e) = chars.next() {
                                out.push(e);
                            }
                        }
                        _ => out.push(d),
                    }
                }
            }
            '\\' => {
                if let Some(e) = chars.next() {
                    out.push(e);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

pub fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// Делит «ключевое слово + остаток».
fn kw_split(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    if t.starts_with('#') || t.is_empty() {
        return None;
    }
    let idx = t.find(|c: char| c.is_whitespace()).unwrap_or(t.len());
    Some((&t[..idx], t[idx..].trim()))
}

impl Config {
    pub fn parse(text: &str) -> Config {
        let mut sections: Vec<Section> = Vec::new();
        let mut anon = 0;
        for line in text.lines() {
            let Some((kw, rest)) = kw_split(line) else { continue };
            match kw {
                "config" => {
                    let mut parts = rest.splitn(2, char::is_whitespace);
                    let ty = unquote(parts.next().unwrap_or(""));
                    let name = parts.next().map(unquote).unwrap_or_else(|| {
                        anon += 1;
                        format!("cfg{:02}", anon)
                    });
                    sections.push(Section { ty, name, opts: HashMap::new() });
                }
                "option" | "list" => {
                    if let Some(sec) = sections.last_mut() {
                        let mut parts = rest.splitn(2, char::is_whitespace);
                        let k = unquote(parts.next().unwrap_or(""));
                        let v = parts.next().map(unquote).unwrap_or_default();
                        if kw == "list" {
                            let e = sec.opts.entry(k).or_default();
                            if !e.is_empty() {
                                e.push(',');
                            }
                            e.push_str(&v);
                        } else {
                            sec.opts.insert(k, v);
                        }
                    }
                }
                _ => {}
            }
        }
        Config { text: text.to_string(), sections }
    }

    pub fn load(path: &str) -> Result<Config, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
        Ok(Config::parse(&t))
    }

    pub fn main(&self) -> Section {
        self.sections.iter().find(|s| s.ty == "csqtt" && s.name == "main").cloned().unwrap_or_default()
    }
    #[allow(dead_code)]
    pub fn routing(&self) -> Section {
        self.sections.iter().find(|s| s.ty == "csqtt" && s.name == "routing").cloned().unwrap_or_default()
    }
    pub fn servers(&self) -> Vec<Section> {
        self.sections.iter().filter(|s| s.ty == "server").cloned().collect()
    }
    pub fn server(&self, id: &str) -> Option<Section> {
        self.sections.iter().find(|s| s.ty == "server" && s.name == id).cloned()
    }

    /// Значение общей настройки: сначала профиль (override/legacy), затем main.
    pub fn shared(&self, profile: &Section, key: &str) -> String {
        let p = profile.get(key).trim();
        if !p.is_empty() {
            return p.to_string();
        }
        self.main().get(key).trim().to_string()
    }

    // ---- правка текста ----

    /// Диапазон строк блока секции [start, end).
    fn block(lines: &[String], name: &str) -> Option<(usize, usize)> {
        let mut start = None;
        for (i, l) in lines.iter().enumerate() {
            if let Some(("config", rest)) = kw_split(l) {
                let mut parts = rest.splitn(2, char::is_whitespace);
                let _ty = parts.next();
                let n = parts.next().map(unquote).unwrap_or_default();
                if let Some(s) = start {
                    return Some((s, i));
                }
                if n == name {
                    start = Some(i);
                }
            }
        }
        start.map(|s| (s, lines.len()))
    }

    fn lines(&self) -> Vec<String> {
        self.text.lines().map(|s| s.to_string()).collect()
    }

    fn rebuild(&mut self, lines: Vec<String>) {
        let mut t = lines.join("\n");
        t.push('\n');
        *self = Config::parse(&t);
    }

    pub fn set_option(&mut self, section: &str, key: &str, value: &str) -> bool {
        let mut lines = self.lines();
        let Some((s, e)) = Self::block(&lines, section) else { return false };
        let new_line = format!("\toption {} {}", key, quote(value));
        for i in s + 1..e {
            if let Some(("option", rest)) = kw_split(&lines[i]) {
                if unquote(rest.split_whitespace().next().unwrap_or("")) == key {
                    lines[i] = new_line;
                    self.rebuild(lines);
                    return true;
                }
            }
        }
        // вставка после последней непустой, не-комментарной строки блока
        let mut at = s + 1;
        for i in s + 1..e {
            if kw_split(&lines[i]).is_some() {
                at = i + 1;
            }
        }
        lines.insert(at, new_line);
        self.rebuild(lines);
        true
    }

    pub fn remove_section(&mut self, name: &str) -> bool {
        let mut lines = self.lines();
        let Some((s, mut e)) = Self::block(&lines, name) else { return false };
        while e > s + 1 && lines[e - 1].trim().is_empty() {
            e -= 1;
        }
        lines.drain(s..e);
        self.rebuild(lines);
        true
    }

    pub fn append_section(&mut self, ty: &str, name: &str, opts: &[(&str, String)]) {
        let mut lines = self.lines();
        if lines.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
            lines.push(String::new());
        }
        lines.push(format!("config {} {}", ty, quote(name)));
        for (k, v) in opts {
            lines.push(format!("\toption {} {}", k, quote(v)));
        }
        self.rebuild(lines);
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        // UCI-конфиг содержит секреты → 0600
        util::write_atomic(path, self.text.as_bytes(), 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = "# c\nconfig csqtt 'main'\n\toption enabled '0'\n\toption active_profile ''\n\nconfig server 'p1'\n\toption name 'A b'\n\toption priority '10'\n\n# tail\nconfig server 'p2'\n\toption name \"X\"\n";
    #[test]
    fn parse_and_get() {
        let c = Config::parse(SAMPLE);
        assert_eq!(c.main().get("enabled"), "0");
        assert_eq!(c.servers().len(), 2);
        assert_eq!(c.server("p1").unwrap().get("name"), "A b");
        assert_eq!(c.server("p2").unwrap().int("priority", 5), 5);
    }
    #[test]
    fn edit_roundtrip() {
        let mut c = Config::parse(SAMPLE);
        assert!(c.set_option("p1", "priority", "20"));
        assert!(c.set_option("p1", "enabled", "1"));
        assert!(c.set_option("main", "active_profile", "p1"));
        assert!(!c.set_option("nope", "x", "y"));
        assert_eq!(c.server("p1").unwrap().get("priority"), "20");
        assert_eq!(c.server("p1").unwrap().get("enabled"), "1");
        assert_eq!(c.main().get("active_profile"), "p1");
        assert!(c.text.contains("# tail"));
        assert!(c.remove_section("p1"));
        assert!(c.server("p1").is_none());
        assert!(c.server("p2").is_some());
        c.append_section("server", "p3", &[("name", "it's".into())]);
        assert_eq!(c.server("p3").unwrap().get("name"), "it's");
    }
}
