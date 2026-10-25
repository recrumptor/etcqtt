//! `csqtt profile …`: управление профилями в UCI-конфиге (без показа секретов).
use crate::link;
use crate::uci::{Config, SHARED_FIELDS};
use crate::util;

fn load(path: &str) -> Result<Config, String> {
    Config::load(path)
}

fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn action(config: &str, action: &str, id: Option<&str>) -> Result<String, String> {
    let mut cfg = load(config)?;
    match action {
        "auto" => {
            cfg.set_option("main", "selection_mode", "priority");
            cfg.set_option("main", "active_profile", "");
            cfg.save(config).map_err(|e| e.to_string())?;
            Ok("selection_mode=priority".into())
        }
        "use" | "enable" | "disable" | "remove" => {
            let id = id.ok_or("нужен id профиля")?;
            if !id_ok(id) {
                return Err("некорректный id профиля".into());
            }
            let sec = cfg.server(id).ok_or_else(|| format!("профиль '{}' не найден", id))?;
            match action {
                "use" => {
                    if !sec.flag("enabled", false) {
                        cfg.set_option(id, "enabled", "1");
                    }
                    cfg.set_option("main", "selection_mode", "manual");
                    cfg.set_option("main", "active_profile", id);
                }
                "enable" => {
                    cfg.set_option(id, "enabled", "1");
                }
                "disable" => {
                    cfg.set_option(id, "enabled", "0");
                    if cfg.main().get("active_profile") == id {
                        cfg.set_option("main", "active_profile", "");
                    }
                }
                _ => {
                    cfg.remove_section(id);
                    if cfg.main().get("active_profile") == id {
                        cfg.set_option("main", "active_profile", "");
                    }
                }
            }
            cfg.save(config).map_err(|e| e.to_string())?;
            Ok(format!("{} {}: ok", action, id))
        }
        _ => Err("action: use|auto|enable|disable|remove".into()),
    }
}

pub struct ImportOpts {
    pub id: Option<String>,
    pub name: Option<String>,
    pub activate: bool,
    pub vk_to_shared: bool,
    pub commit: bool,
}

pub fn import(config: &str, raw: &str, o: &ImportOpts) -> Result<String, String> {
    import_with(config, raw, o, crate::supervisor::core_modern())
}

/// `modern` = ядро 2.5.0+: device_id не используется и не создаётся.
pub fn import_with(config: &str, raw: &str, o: &ImportOpts, modern: bool) -> Result<String, String> {
    let l = link::parse(raw)?;
    let mut cfg = load(config)?;
    let id = match &o.id {
        Some(i) => {
            if !id_ok(i) {
                return Err("некорректный id".into());
            }
            if cfg.server(i).is_some() {
                return Err(format!("профиль '{}' уже существует", i));
            }
            i.clone()
        }
        None => (1..1000).map(|n| format!("profile{}", n)).find(|c| cfg.server(c).is_none()).ok_or("нет свободного id")?,
    };
    let name = o.name.clone().unwrap_or_else(|| l.host.clone());
    let max_prio = cfg.servers().iter().map(|s| s.int("priority", 0)).max().unwrap_or(0);
    let mut notes = Vec::new();
    let mut opts: Vec<(&str, String)> = vec![
        ("name", name.clone()),
        ("enabled", "1".into()),
        ("priority", (max_prio + 10).to_string()),
        ("peer", l.peer()),
        ("password", l.password.clone()),
    ];
    let main_has_vk = !cfg.main().get("vk").trim().is_empty();
    if !l.hashes.is_empty() {
        let joined = l.hashes.join(",");
        if o.vk_to_shared || !main_has_vk {
            if o.commit {
                cfg.set_option("main", "vk", &joined);
            }
            notes.push(format!("хеши ({}) записаны в общие настройки", l.hashes.len()));
        } else {
            notes.push(format!("в ссылке {} хеш(ей); общие хеши уже заданы — используйте --vk-to-shared для замены", l.hashes.len()));
        }
    }
    if l.hashes.len() > 6 {
        notes.push(format!("в ссылке {} хешей: ядро использует только первые 6", l.hashes.len()));
    }
    if !l.token.is_empty() {
        let main = cfg.main();
        if o.vk_to_shared || main.get("vk_js_token").trim().is_empty() {
            if o.commit {
                cfg.set_option("main", "vk_hash_mode", "auto_js");
                cfg.set_option("main", "vk_js_token", &l.token);
            }
            notes.push("в ссылке VK-токен вместо хешей: включён режим vk_hash_mode=auto_js, токен записан в общие настройки".into());
        } else {
            notes.push("в ссылке VK-токен, но общий токен уже задан — используйте --vk-to-shared для замены".into());
        }
    }
    if l.password.is_empty() {
        notes.push(format!("в ссылке нет пароля (ссылка владельца) — задайте его: uci set csqtt.{}.password='…' && uci commit csqtt", id));
    }
    // device_id привязан к паролю на сервере: создаём один раз и дальше не меняем
    if !modern && cfg.shared(&cfg.main(), "device_id").is_empty() {
        let dev = util::uuid_v4();
        if o.commit {
            cfg.set_option("main", "device_id", &dev);
        }
        notes.push("создан device_id (хранится в общих настройках; не меняйте — он привязан к паролю)".into());
    }
    let _ = SHARED_FIELDS;
    let mut msg = format!("профиль {} ({}), peer {}", id, name, l.peer());
    if !notes.is_empty() {
        msg.push('\n');
        msg.push_str(&notes.join("\n"));
    }
    if !o.commit {
        return Ok(format!("[dry-run] {}\nДобавьте --commit для записи.", msg));
    }
    cfg.append_section("server", &id, &opts.drain(..).collect::<Vec<_>>());
    if o.activate {
        cfg.set_option("main", "selection_mode", "manual");
        cfg.set_option("main", "active_profile", &id);
    }
    cfg.save(config).map_err(|e| e.to_string())?;
    Ok(format!("импортирован: {}", msg))
}

/// Ссылка профиля: ядро 2.5.0+ — зашифрованный формат, иначе прежний открытый.
pub fn export(config: &str, id: &str) -> Result<String, String> {
    export_with(config, id, crate::supervisor::core_modern())
}

pub fn export_with(config: &str, id: &str, encrypted: bool) -> Result<String, String> {
    if !id_ok(id) {
        return Err("некорректный id профиля".into());
    }
    let cfg = load(config)?;
    let s = cfg.server(id).ok_or_else(|| format!("профиль '{}' не найден", id))?;
    let peer = s.get("peer").to_string();
    let (host, port) = peer.rsplit_once(':').ok_or("peer без порта")?;
    let mut hashes: Vec<String> = crate::supervisor::normalize_hashes(&cfg.shared(&s, "vk")).split(',').filter(|x| !x.is_empty()).map(String::from).collect();
    // режим auto_js: вместо хешей в ссылке токен (хеши и токен в ссылке взаимоисключающи)
    let mut token = String::new();
    if cfg.shared(&s, "vk_hash_mode") == "auto_js" && !cfg.shared(&s, "vk_js_token").is_empty() {
        token = cfg.shared(&s, "vk_js_token");
        hashes.clear();
    }
    let l = link::Link {
        host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port: port.parse().map_err(|_| "некорректный порт peer")?,
        password: s.get("password").to_string(),
        hashes,
        token,
    };
    if l.password.is_empty() {
        return Err("у профиля нет пароля".into());
    }
    Ok(link::export(&l, encrypted))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmp(content: &str) -> String {
        let p = format!("/tmp/csqtt-test-{}-{}.cfg", std::process::id(), util::random_hex(3));
        std::fs::write(&p, content).unwrap();
        p
    }
    const BASE: &str = "config csqtt 'main'\n\toption enabled '0'\n\toption selection_mode 'priority'\n\toption active_profile ''\n";

    #[test]
    fn import_use_export_remove() {
        let p = tmp(BASE);
        let o = ImportOpts { id: None, name: None, activate: false, vk_to_shared: false, commit: false };
        let r = import_with(&p, "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a+b", &o, false).unwrap();
        assert!(r.contains("dry-run"));
        assert!(Config::load(&p).unwrap().servers().is_empty());
        let o = ImportOpts { commit: true, activate: true, ..o };
        import_with(&p, "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a+b", &o, false).unwrap();
        let c = Config::load(&p).unwrap();
        let s = c.server("profile1").unwrap();
        assert_eq!(s.get("peer"), "h.example:46000");
        assert_eq!(c.main().get("vk"), "a,b");
        assert_eq!(c.main().get("active_profile"), "profile1");
        assert_eq!(c.main().get("selection_mode"), "manual");
        assert_eq!(c.main().get("device_id").len(), 36);
        assert_eq!(export_with(&p, "profile1", false).unwrap(), "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a%2Bb".replace("%2B", "+"));
        // 2.5.0+: зашифрованная ссылка, которую разбирает и наш parse, и приложение/сервер
        let enc = export_with(&p, "profile1", true).unwrap();
        assert!(enc.starts_with("csqtt://") && !enc.contains("h.example") && !enc.contains("connect"));
        let back = link::parse(&enc).unwrap();
        assert_eq!((back.host.as_str(), back.port, back.password.as_str(), back.hashes.clone()), ("h.example", 46000, "s3", vec!["a".to_string(), "b".to_string()]));
        action(&p, "disable", Some("profile1")).unwrap();
        assert_eq!(Config::load(&p).unwrap().server("profile1").unwrap().get("enabled"), "0");
        assert_eq!(Config::load(&p).unwrap().main().get("active_profile"), "");
        action(&p, "remove", Some("profile1")).unwrap();
        assert!(Config::load(&p).unwrap().server("profile1").is_none());
        assert!(action(&p, "use", Some("nope")).is_err());
        assert!(action(&p, "use", Some("bad id!")).is_err());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn modern_import_creates_no_device_id() {
        let p = tmp(BASE);
        let o = ImportOpts { id: None, name: None, activate: false, vk_to_shared: false, commit: true };
        let msg = import_with(&p, "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a", &o, true).unwrap();
        assert!(!msg.contains("device_id"));
        assert_eq!(Config::load(&p).unwrap().main().get("device_id"), "");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn import_encrypted_link_and_token_link() {
        let p = tmp(BASE);
        let o = ImportOpts { id: None, name: None, activate: false, vk_to_shared: false, commit: true };
        let enc = link::export(&link::Link { host: "enc.example".into(), port: 40001, password: "pw1".into(), hashes: vec!["hashAAAAAAAAAAAAAAAA".into()], token: String::new() }, true);
        import_with(&p, &enc, &o, true).unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.server("profile1").unwrap().get("peer"), "enc.example:40001");
        assert_eq!(c.main().get("vk"), "hashAAAAAAAAAAAAAAAA");
        // ссылка с токеном → режим auto_js
        let tok = link::export(&link::Link { host: "tok.example".into(), port: 40002, password: "pw2".into(), hashes: vec![], token: "vk1.a.TOKEN".into() }, true);
        import_with(&p, &tok, &o, true).unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.main().get("vk_hash_mode"), "auto_js");
        assert_eq!(c.main().get("vk_js_token"), "vk1.a.TOKEN");
        // экспорт профиля при auto_js отдаёт токен
        let out = export_with(&p, "profile2", true).unwrap();
        assert_eq!(link::parse(&out).unwrap().token, "vk1.a.TOKEN");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn owner_link_without_password_is_imported_with_a_note() {
        let p = tmp(BASE);
        let o = ImportOpts { id: None, name: None, activate: false, vk_to_shared: false, commit: true };
        let owner = format!("csqtt://{}", link::encrypt_payload("connect?v=2&host=203.0.113.7&peer=46000").unwrap());
        let msg = import_with(&p, &owner, &o, true).unwrap();
        assert!(msg.contains("нет пароля"));
        assert_eq!(Config::load(&p).unwrap().server("profile1").unwrap().get("password"), "");
        assert!(export_with(&p, "profile1", true).is_err());
        std::fs::remove_file(p).ok();
    }
}
