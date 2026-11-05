//! `csqtt doctor`: read-only диагностика. Код выхода: 0 — всё ок, 1 — WARN, 2 — FAIL.
use crate::supervisor::{core_args, core_bin, core_modern, core_version, hash_coverage, routing_active, Settings};
use crate::uci::Config;
use crate::{tun, util};
use serde_json::{json, Value};
use std::net::TcpListener;

pub struct Check {
    pub name: &'static str,
    pub status: &'static str,
    pub message: String,
}

fn c_(name: &'static str, status: &'static str, message: impl Into<String>) -> Check {
    Check { name, status, message: message.into() }
}

pub fn run_checks(config: &str, status_path: &str, helper_port: u16) -> Vec<Check> {
    let mut out = Vec::new();
    let cfg = match Config::load(config) {
        Ok(cfg) => {
            out.push(c_("config", "ok", format!("{} прочитан", config)));
            cfg
        }
        Err(e) => {
            out.push(c_("config", "fail", e));
            return out;
        }
    };
    let m = cfg.main();
    let set = Settings::from(&m);
    if cfg.sections.iter().all(|s| !(s.ty == "csqtt" && s.name == "main")) {
        out.push(c_("config.main", "fail", "нет секции config csqtt 'main'"));
    }
    if set.ifname.is_empty() || set.ifname.len() >= 16 || set.ifname.contains(['/', ' ']) {
        out.push(c_("config.ifname", "fail", format!("недопустимое имя интерфейса '{}'", set.ifname)));
    }
    if !set.tun_address.is_empty() && tun::parse_cidr(&set.tun_address).is_none() {
        out.push(c_("config.tun_address", "fail", format!("'{}' — ожидается a.b.c.d/N", set.tun_address)));
    }
    if m.get("tun_mtu").trim().parse::<u32>().map(|v| !(576..=9000).contains(&v)).unwrap_or(!m.get("tun_mtu").is_empty()) {
        out.push(c_("config.tun_mtu", "fail", "tun_mtu вне диапазона 576..9000"));
    }
    if !set.enabled {
        out.push(c_("enabled", "warn", "служба отключена (option enabled '0') — соединение не будет установлено"));
    }

    // TUN
    if std::path::Path::new("/dev/net/tun").exists() {
        out.push(c_("tun.device", "ok", "/dev/net/tun доступен"));
    } else {
        out.push(c_("tun.device", "fail", "нет /dev/net/tun (установите kmod-tun)"));
    }
    // ядро
    let bin = core_bin();
    match std::fs::metadata(&bin) {
        Ok(md) if md.is_file() => out.push(c_("core", "ok", format!("{} найден", bin))),
        _ => out.push(c_("core", "fail", format!("ядро {} не найдено", bin))),
    }
    // профили
    let servers = cfg.servers();
    let enabled: Vec<_> = servers.iter().filter(|s| s.flag("enabled", false)).collect();
    if servers.is_empty() {
        out.push(c_("profiles", "warn", "профилей нет: csqtt profile import 'csqtt://…' --commit"));
    } else if enabled.is_empty() {
        out.push(c_("profiles", "warn", "нет включённых профилей"));
    } else {
        out.push(c_("profiles", "ok", format!("профилей: {}, включено: {}", servers.len(), enabled.len())));
    }
    for s in &enabled {
        if let Err(e) = core_args(&cfg, s, "x") {
            out.push(c_("profile", "warn", format!("{}: {}", s.name, e)));
        }
    }
    {
        let (a, b, c) = core_version();
        let note = if core_modern() { "пароль передаётся через окружение, device_id не используется" } else { "режим совместимости: пароль и device_id аргументами" };
        out.push(c_("core.version", "ok", format!("ядро {}.{}.{} — {}", a, b, c, note)));
    }
    if core_modern() {
        for s in &enabled {
            if routing_active(&cfg, s) {
                out.push(c_("routing", "warn", format!("{}: включена маршрутизация по доменам/IP — пользовательский сетевой стек ядра заметно нагружает CPU и ОЗУ слабых роутеров", s.name)));
            }
        }
    }
    if core_modern() {
        for s in &enabled {
            if let Some((w, groups, hashes)) = hash_coverage(&cfg, s) {
                out.push(c_("workers", "warn", workers_warning(&s.name, w, groups, hashes)));
            }
        }
    }
    // остаточный интерфейс
    let running = status_running(status_path);
    if !running && tun::exists(&set.ifname) {
        out.push(c_("interface", "warn", format!("leftover {}: интерфейс существует, а служба не запущена", set.ifname)));
    }
    // rp_filter
    if let Ok(v) = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter") {
        if v.trim() == "1" {
            out.push(c_("rp_filter", "warn", "net.ipv4.conf.all.rp_filter=1 (strict) может отбрасывать трафик туннеля"));
        }
    }
    // порты помощника (только если служба не запущена)
    if !running {
        if TcpListener::bind(("127.0.0.1", helper_port)).is_err() {
            out.push(c_("helper.port", "warn", format!("порт {} занят другим процессом", helper_port)));
        } else {
            out.push(c_("helper.port", "ok", format!("порт {} свободен", helper_port)));
        }
    }
    // DNS пира (информативно)
    if let Some(p) = enabled.first() {
        let peer = p.get("peer");
        if let Some((host, _)) = peer.rsplit_once(':') {
            use std::net::ToSocketAddrs;
            if host.parse::<std::net::IpAddr>().is_err() && (peer, 0u16).to_socket_addrs().is_err() && (host, 0u16).to_socket_addrs().is_err() {
                out.push(c_("peer.dns", "warn", format!("{} не резолвится", host)));
            }
        }
    }
    out
}

/// Русское склонение: 1 хеш, 2–4 хеша, 5+ хешей (11–14 — «хешей»).
fn plural(n: usize, one: &str, few: &str, many: &str) -> String {
    let (n10, n100) = (n % 10, n % 100);
    let form = if n10 == 1 && n100 != 11 {
        one
    } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
        few
    } else {
        many
    };
    format!("{} {}", n, form)
}

/// Предупреждение «хешей больше, чем групп воркеров». Группа из 10 воркеров привязана к одному хешу
/// (номер группы mod число хешей), остальные хеши не используются.
pub fn workers_warning(name: &str, workers: usize, groups: usize, hashes: usize) -> String {
    let at = if hashes % 10 == 1 && hashes % 100 != 11 { format!("{} хеше", hashes) } else { format!("{} хешах", hashes) };
    let verb = if groups % 10 == 1 && groups % 100 != 11 { "используется" } else { "используются" };
    format!(
        "{}: {} ({}) при {} — {} только {} из {}; чтобы работали все, задайте workers ≥ {} или оставьте в списке только нужные хеши",
        name,
        plural(workers, "воркер", "воркера", "воркеров"),
        plural(groups, "группа", "группы", "групп"),
        at,
        verb,
        plural(groups, "хеш", "хеша", "хешей"),
        hashes,
        hashes * 10
    )
}

pub fn status_running(status_path: &str) -> bool {
    let Ok(t) = std::fs::read_to_string(status_path) else { return false };
    let Ok(v) = serde_json::from_str::<Value>(&t) else { return false };
    let pid = v["pid"].as_i64().unwrap_or(0) as i32;
    let gen = v["generated_at"].as_u64().unwrap_or(0);
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0 && util::now_secs().saturating_sub(gen) <= 30
}

pub fn exit_code(checks: &[Check]) -> i32 {
    if checks.iter().any(|c| c.status == "fail") { 2 } else if checks.iter().any(|c| c.status == "warn") { 1 } else { 0 }
}

pub fn to_json(checks: &[Check]) -> Value {
    json!({
        "checks": checks.iter().map(|c| json!({"name": c.name, "status": c.status, "message": c.message})).collect::<Vec<_>>(),
        "summary": {
            "ok": checks.iter().filter(|c| c.status == "ok").count(),
            "warn": checks.iter().filter(|c| c.status == "warn").count(),
            "fail": checks.iter().filter(|c| c.status == "fail").count(),
        },
        "exit": exit_code(checks),
    })
}

pub fn print_text(checks: &[Check]) {
    for c in checks {
        println!("[{:<4}] {} — {}", c.status.to_uppercase(), c.name, c.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plurals() {
        assert_eq!(plural(1, "хеш", "хеша", "хешей"), "1 хеш");
        assert_eq!(plural(2, "хеш", "хеша", "хешей"), "2 хеша");
        assert_eq!(plural(5, "хеш", "хеша", "хешей"), "5 хешей");
        assert_eq!(plural(11, "хеш", "хеша", "хешей"), "11 хешей");
        assert_eq!(plural(21, "хеш", "хеша", "хешей"), "21 хеш");
        assert_eq!(plural(14, "группа", "группы", "групп"), "14 групп");
    }

    #[test]
    fn workers_warning_text() {
        // случай со скриншота: 10 воркеров = 1 группа, 5 хешей
        assert_eq!(
            workers_warning("profile1", 10, 1, 5),
            "profile1: 10 воркеров (1 группа) при 5 хешах — используется только 1 хеш из 5; чтобы работали все, задайте workers ≥ 50 или оставьте в списке только нужные хеши"
        );
        let w = workers_warning("p", 20, 2, 5);
        assert!(w.contains("20 воркеров (2 группы)") && w.contains("используются только 2 хеша из 5") && w.contains("workers ≥ 50"), "{}", w);
        let w = workers_warning("p", 30, 3, 6);
        assert!(w.contains("при 6 хешах") && w.contains("3 хеша из 6") && w.contains("workers ≥ 60"), "{}", w);
        assert!(workers_warning("p", 10, 1, 2).contains("при 2 хешах — используется только 1 хеш из 2"));
    }
}
