//! csqtt — OpenWrt-обёртка над ядром CSQTT: служба, TUN, пул профилей, CAPTCHA-помощник, CLI.
mod core;
mod doctor;
mod helper;
mod https;
mod link;
mod log;
mod profile;
mod supervisor;
mod tun;
mod uci;
mod util;

use serde_json::Value;

const DEF_CONFIG: &str = "/etc/config/csqtt";
const DEF_STATUS: &str = "/var/run/csqtt/status.json";
const DEF_LOG: &str = "/var/log/csqtt.log";

struct Args {
    pos: Vec<String>,
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(argv: &[String], valued: &[&str]) -> Args {
        let mut pos = Vec::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            if let Some(name) = a.strip_prefix("--") {
                if let Some((k, v)) = name.split_once('=') {
                    flags.push((k.to_string(), Some(v.to_string())));
                } else if valued.contains(&name) {
                    flags.push((name.to_string(), argv.get(i + 1).cloned()));
                    i += 1;
                } else {
                    flags.push((name.to_string(), None));
                }
            } else {
                pos.push(a.clone());
            }
            i += 1;
        }
        Args { pos, flags }
    }
    fn val(&self, k: &str) -> Option<String> {
        self.flags.iter().find(|(n, _)| n == k).and_then(|(_, v)| v.clone())
    }
    fn has(&self, k: &str) -> bool {
        self.flags.iter().any(|(n, _)| n == k)
    }
}

const VALUED: &[&str] = &["config", "status", "status-path", "log", "helper-port", "id", "name", "vk-file"];

fn usage() -> i32 {
    eprintln!(
        "csqtt {}\n\
         Использование:\n  \
         csqtt run --config F --status F --log F --helper-port N\n  \
         csqtt status [--json] [--status-path F]\n  \
         csqtt doctor [--json] [--config F] [--status-path F]\n  \
         csqtt profile use|auto|enable|disable|remove [ID] [--config F]\n  \
         csqtt profile import LINK [--id ID] [--name N] [--activate] [--vk-to-shared] [--commit] [--config F]\n  \
         csqtt profile export ID [--config F]\n  \
         csqtt --validate-vk-hashes --vk-file F [--config F]\n  \
         csqtt version",
        supervisor::version_string()
    );
    2
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(real_main(argv));
}

fn real_main(argv: Vec<String>) -> i32 {
    let a = Args::parse(&argv, VALUED);
    if a.has("validate-vk-hashes") {
        return validate_hashes_cli(&a);
    }
    if a.has("version") || a.has("V") {
        println!("csqtt {}", supervisor::version_string());
        return 0;
    }
    let Some(cmd) = a.pos.first().cloned() else { return usage() };
    let config = a.val("config").unwrap_or_else(|| DEF_CONFIG.to_string());
    match cmd.as_str() {
        "version" => {
            println!("csqtt {}", supervisor::version_string());
            0
        }
        "run" => {
            let port: u16 = a.val("helper-port").and_then(|v| v.parse().ok()).unwrap_or(8443);
            supervisor::run(supervisor::Opts {
                config,
                status: a.val("status").unwrap_or_else(|| DEF_STATUS.to_string()),
                log: a.val("log").unwrap_or_else(|| DEF_LOG.to_string()),
                helper_port: port,
            })
        }
        "status" => status_cmd(&a),
        "doctor" => {
            let sp = a.val("status-path").unwrap_or_else(|| DEF_STATUS.to_string());
            let port: u16 = a.val("helper-port").and_then(|v| v.parse().ok()).unwrap_or(8443);
            let checks = doctor::run_checks(&config, &sp, port);
            if a.has("json") {
                println!("{}", doctor::to_json(&checks));
            } else {
                doctor::print_text(&checks);
            }
            doctor::exit_code(&checks)
        }
        "profile" => profile_cmd(&a, &config),
        _ => usage(),
    }
}

fn status_cmd(a: &Args) -> i32 {
    let sp = a.val("status-path").unwrap_or_else(|| DEF_STATUS.to_string());
    let running = doctor::status_running(&sp);
    let mut v: Value = std::fs::read_to_string(&sp).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    if !running {
        if a.has("json") {
            println!("{}", serde_json::json!({"running": false, "connected": false}));
        } else {
            println!("служба CSQTT не запущена");
        }
        return 2;
    }
    let connected = v["connected"].as_bool().unwrap_or(false);
    if a.has("json") {
        v["running"] = Value::Bool(true);
        println!("{}", v);
    } else {
        let prof = v["active_profile"].as_str().unwrap_or("—");
        println!(
            "{}: профиль {} | tx {} B, rx {} B | переподключений {}",
            if connected { "подключён" } else { "не подключён" },
            prof,
            v["tx_bytes"],
            v["rx_bytes"],
            v["reconnects"]
        );
        if let Some(e) = v["last_error"].as_str() {
            println!("последняя ошибка: {}", e);
        }
    }
    if connected { 0 } else { 1 }
}

fn profile_cmd(a: &Args, config: &str) -> i32 {
    let sub = a.pos.get(1).map(|s| s.as_str()).unwrap_or("");
    let res = match sub {
        "import" => {
            let Some(link) = a.pos.get(2) else {
                eprintln!("нужна ссылка csqtt://…");
                return 2;
            };
            profile::import(
                config,
                link,
                &profile::ImportOpts {
                    id: a.val("id"),
                    name: a.val("name"),
                    activate: a.has("activate"),
                    vk_to_shared: a.has("vk-to-shared"),
                    commit: a.has("commit"),
                },
            )
        }
        "export" => match a.pos.get(2) {
            Some(id) => profile::export(config, id),
            None => Err("нужен id профиля".into()),
        },
        "use" | "auto" | "enable" | "disable" | "remove" => profile::action(config, sub, a.pos.get(2).map(|s| s.as_str())),
        _ => return usage(),
    };
    match res {
        Ok(m) => {
            println!("{}", m);
            0
        }
        Err(e) => {
            eprintln!("ошибка: {}", e);
            1
        }
    }
}

/// Делегирует проверку ядру; stdout ядра (HASH_CHECK:…) идёт напрямую вызывающему.
fn validate_hashes_cli(a: &Args) -> i32 {
    let Some(file) = a.val("vk-file") else {
        eprintln!("нужен --vk-file");
        return 2;
    };
    let raw = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: {}", file, e);
            return 2;
        }
    };
    let vk = supervisor::normalize_hashes(&raw);
    if vk.is_empty() {
        eprintln!("пустой список хешей");
        return 2;
    }
    let config = a.val("config").unwrap_or_else(|| DEF_CONFIG.to_string());
    let (mut fp, mut ids) = ("chrome".to_string(), String::new());
    if let Ok(cfg) = uci::Config::load(&config) {
        let m = cfg.main();
        if !m.get("fingerprint").is_empty() {
            fp = m.get("fingerprint").to_string();
        }
        ids = m.get("client_ids").to_string();
    }
    match std::process::Command::new(supervisor::core_bin())
        .args(["--validate-vk-hashes", "--vk", &vk, "--fingerprint", &fp, "--client-ids", &ids])
        .stdin(std::process::Stdio::null())
        .status()
    {
        Ok(st) => st.code().unwrap_or(1),
        Err(e) => {
            eprintln!("ядро не запущено: {}", e);
            2
        }
    }
}
