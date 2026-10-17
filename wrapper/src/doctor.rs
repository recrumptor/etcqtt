//! `csqtt doctor`: read-only диагностика. Код выхода: 0 — всё ок, 1 — WARN, 2 — FAIL.
use crate::supervisor::{core_bin, core_args, Settings};
use crate::uci::Config;
use crate::{tun, util};
use serde_json::{json, Value};
use std::net::TcpListener;

pub struct Check {
    pub name: &'static str,
    pub status: &'static str,
    pub message: String,
}

fn c(name: &'static str, status: &'static str, message: impl Into<String>) -> Check {
    Check { name, status, message: message.into() }
}

pub fn run_checks(config: &str, status_path: &str, helper_port: u16) -> Vec<Check> {
    let mut out = Vec::new();
    let cfg = match Config::load(config) {
        Ok(cfg) => {
            out.push(c("config", "ok", format!("{} прочитан", config)));
            cfg
        }
        Err(e) => {
            out.push(c("config", "fail", e));
            return out;
        }
    };
    let m = cfg.main();
    let set = Settings::from(&m);
    if cfg.sections.iter().all(|s| !(s.ty == "csqtt" && s.name == "main")) {
        out.push(c("config.main", "fail", "нет секции config csqtt 'main'"));
    }
    if set.ifname.is_empty() || set.ifname.len() >= 16 || set.ifname.contains(['/', ' ']) {
        out.push(c("config.ifname", "fail", format!("недопустимое имя интерфейса '{}'", set.ifname)));
    }
    if !set.tun_address.is_empty() && tun::parse_cidr(&set.tun_address).is_none() {
        out.push(c("config.tun_address", "fail", format!("'{}' — ожидается a.b.c.d/N", set.tun_address)));
    }
    if m.get("tun_mtu").trim().parse::<u32>().map(|v| !(576..=9000).contains(&v)).unwrap_or(!m.get("tun_mtu").is_empty()) {
        out.push(c("config.tun_mtu", "fail", "tun_mtu вне диапазона 576..9000"));
    }
    if !set.enabled {
        out.push(c("enabled", "warn", "служба отключена (option enabled '0') — соединение не будет установлено"));
    }

    // TUN
    if std::path::Path::new("/dev/net/tun").exists() {
        out.push(c("tun.device", "ok", "/dev/net/tun доступен"));
    } else {
        out.push(c("tun.device", "fail", "нет /dev/net/tun (установите kmod-tun)"));
    }
    // ядро
    let bin = core_bin();
    match std::fs::metadata(&bin) {
        Ok(md) if md.is_file() => out.push(c("core", "ok", format!("{} найден", bin))),
        _ => out.push(c("core", "fail", format!("ядро {} не найдено", bin))),
    }
    // профили
    let servers = cfg.servers();
    let enabled: Vec<_> = servers.iter().filter(|s| s.flag("enabled", false)).collect();
    if servers.is_empty() {
        out.push(c("profiles", "warn", "профилей нет: csqtt profile import 'csqtt://…' --commit"));
    } else if enabled.is_empty() {
        out.push(c("profiles", "warn", "нет включённых профилей"));
    } else {
        out.push(c("profiles", "ok", format!("профилей: {}, включено: {}", servers.len(), enabled.len())));
    }
    for s in &enabled {
        if let Err(e) = core_args(&cfg, s, "x") {
            out.push(c("profile", "warn", format!("{}: {}", s.name, e)));
        }
    }
    // остаточный интерфейс
    let running = status_running(status_path);
    if !running && tun::exists(&set.ifname) {
        out.push(c("interface", "warn", format!("leftover {}: интерфейс существует, а служба не запущена", set.ifname)));
    }
    // rp_filter
    if let Ok(v) = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter") {
        if v.trim() == "1" {
            out.push(c("rp_filter", "warn", "net.ipv4.conf.all.rp_filter=1 (strict) может отбрасывать трафик туннеля"));
        }
    }
    // порты помощника (только если служба не запущена)
    if !running {
        if TcpListener::bind(("127.0.0.1", helper_port)).is_err() {
            out.push(c("helper.port", "warn", format!("порт {} занят другим процессом", helper_port)));
        } else {
            out.push(c("helper.port", "ok", format!("порт {} свободен", helper_port)));
        }
    }
    // DNS пира (информативно)
    if let Some(p) = enabled.first() {
        let peer = p.get("peer");
        if let Some((host, _)) = peer.rsplit_once(':') {
            use std::net::ToSocketAddrs;
            if host.parse::<std::net::IpAddr>().is_err() && (peer, 0u16).to_socket_addrs().is_err() && (host, 0u16).to_socket_addrs().is_err() {
                out.push(c("peer.dns", "warn", format!("{} не резолвится", host)));
            }
        }
    }
    out
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
