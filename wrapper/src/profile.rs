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
    // device_id привязан к паролю на сервере: создаём один раз и дальше не меняем
    if cfg.shared(&cfg.main(), "device_id").is_empty() {
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

pub fn export(config: &str, id: &str) -> Result<String, String> {
    if !id_ok(id) {
        return Err("некорректный id профиля".into());
    }
    let cfg = load(config)?;
    let s = cfg.server(id).ok_or_else(|| format!("профиль '{}' не найден", id))?;
    let peer = s.get("peer").to_string();
    let (host, port) = peer.rsplit_once(':').ok_or("peer без порта")?;
    let l = link::Link {
        host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        port: port.parse().map_err(|_| "некорректный порт peer")?,
        password: s.get("password").to_string(),
        hashes: crate::supervisor::normalize_hashes(&cfg.shared(&s, "vk")).split(',').filter(|x| !x.is_empty()).map(String::from).collect(),
    };
    if l.password.is_empty() {
        return Err("у профиля нет пароля".into());
    }
    Ok(link::export(&l))
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
        let r = import(&p, "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a+b", &o).unwrap();
        assert!(r.contains("dry-run"));
        assert!(Config::load(&p).unwrap().servers().is_empty());
        let o = ImportOpts { commit: true, activate: true, ..o };
        import(&p, "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a+b", &o).unwrap();
        let c = Config::load(&p).unwrap();
        let s = c.server("profile1").unwrap();
        assert_eq!(s.get("peer"), "h.example:46000");
        assert_eq!(c.main().get("vk"), "a,b");
        assert_eq!(c.main().get("active_profile"), "profile1");
        assert_eq!(c.main().get("selection_mode"), "manual");
        assert_eq!(c.main().get("device_id").len(), 36);
        assert_eq!(export(&p, "profile1").unwrap(), "csqtt://connect?v=2&host=h.example&peer=46000&password=s3&hashes=a%2Bb".replace("%2B", "+"));
        action(&p, "disable", Some("profile1")).unwrap();
        assert_eq!(Config::load(&p).unwrap().server("profile1").unwrap().get("enabled"), "0");
        assert_eq!(Config::load(&p).unwrap().main().get("active_profile"), "");
        action(&p, "remove", Some("profile1")).unwrap();
        assert!(Config::load(&p).unwrap().server("profile1").is_none());
        assert!(action(&p, "use", Some("nope")).is_err());
        assert!(action(&p, "use", Some("bad id!")).is_err());
        std::fs::remove_file(p).ok();
    }
}
