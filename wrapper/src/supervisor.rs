//! Служба `csqtt run`: держит TUN, запускает ядро для активного профиля,
//! ведёт пул профилей (failover/failback), обслуживает CAPTCHA и пишет status.json.
use crate::core::{Core, Msg};
use crate::helper::Helper;
use crate::uci::{Config, Section};
use crate::{loge, logd, logi, logw, tun, util};
use serde_json::{json, Value};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CORE_VERSION: &str = match option_env!("CSQTT_CORE_VERSION") {
    Some(v) => v,
    None => "unknown",
};
pub fn version_string() -> String {
    format!("{} (core {})", VERSION, CORE_VERSION)
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(150);
const STATUS_EVERY: Duration = Duration::from_secs(1);
const TICK: Duration = Duration::from_millis(200);

static SIG_HUP: AtomicBool = AtomicBool::new(false);
static SIG_TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_: libc::c_int) {
    SIG_HUP.store(true, Ordering::SeqCst);
}
extern "C" fn on_term(_: libc::c_int) {
    SIG_TERM.store(true, Ordering::SeqCst);
}

fn install_signals() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_hup as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
        sa.sa_sigaction = on_term as usize;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

pub struct Opts {
    pub config: String,
    pub status: String,
    pub log: String,
    pub helper_port: u16,
}

// ------------------------------------------------------------ настройки

#[derive(Clone, Debug)]
pub struct Settings {
    pub enabled: bool,
    pub ifname: String,
    pub mode: String, // priority | manual
    pub active_profile: String,
    pub failover: bool,
    pub failback: bool,
    pub health_interval: u64,
    pub fail_threshold: u64,
    pub success_threshold: u64,
    pub cooldown: u64,
    pub reconnect_delay: u64,
    pub failback_stable: u64,
    pub health_mode: String,
    pub health_target: String,
    pub captcha_policy: String,
    pub tun_address: String,
    pub tun_mtu: u32,
    pub log_level: String,
    pub log_size_kb: u64,
    pub helper_bind: String,
    pub helper_host: String,
    pub solve_port: Option<u16>,
}

impl Settings {
    pub fn from(m: &Section) -> Settings {
        let mode = match m.get("selection_mode").trim() {
            "manual" => "manual",
            _ => "priority",
        };
        Settings {
            enabled: m.flag("enabled", false),
            ifname: m.get_or("ifname", "csqtt0").to_string(),
            mode: mode.to_string(),
            active_profile: m.get("active_profile").trim().to_string(),
            failover: m.flag("failover", true),
            failback: m.flag("failback", false),
            health_interval: m.int("health_interval", 5).clamp(1, 3600) as u64,
            fail_threshold: m.int("fail_threshold", 3).clamp(1, 100) as u64,
            success_threshold: m.int("success_threshold", 2).clamp(1, 100) as u64,
            cooldown: m.int("cooldown", 60).clamp(0, 86400) as u64,
            reconnect_delay: m.int("reconnect_delay", 5).clamp(1, 3600) as u64,
            failback_stable: m.int("failback_stable_time", 60).clamp(0, 86400) as u64,
            health_mode: m.get_or("health_mode", "both").to_string(),
            health_target: m.get("health_target").trim().to_string(),
            captcha_policy: m.get_or("captcha_policy", "failover").to_string(),
            tun_address: m.get("tun_address").trim().to_string(),
            tun_mtu: m.int("tun_mtu", 1280).clamp(576, 9000) as u32,
            log_level: m.get_or("log_level", "info").to_string(),
            log_size_kb: m.int("log_size_kb", 512).clamp(32, 8192) as u64,
            helper_bind: m.get("helper_bind").trim().to_string(),
            helper_host: m.get("helper_host").trim().to_string(),
            solve_port: m.get("helper_solve_port").trim().parse().ok(),
        }
    }
}

pub fn core_bin() -> String {
    std::env::var("CSQTT_CORE").unwrap_or_else(|_| "/usr/libexec/csqtt/csqtt-core".to_string())
}

/// Хеши VK → «a,b,c» (допустимы разделители , ; + пробел).
pub fn normalize_hashes(s: &str) -> String {
    s.split(|c: char| c == ',' || c == ';' || c == '+' || c.is_whitespace()).map(str::trim).filter(|x| !x.is_empty()).collect::<Vec<_>>().join(",")
}

/// Эффективные транспорт и обфускация профиля (с учётом общих настроек и значений по умолчанию ядра).
pub fn effective_settings(cfg: &Config, prof: &Section) -> (String, String) {
    let or = |v: String, d: &str| if v.is_empty() { d.to_string() } else { v };
    (or(cfg.shared(prof, "turn_transport"), "udp"), or(cfg.shared(prof, "obfs"), "audio"))
}

/// Текущий MTU интерфейса из sysfs (None, если интерфейса нет).
fn iface_mtu(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/mtu", name)).ok()?.trim().parse().ok()
}

/// Аргументы ядра для профиля. Чистая функция — покрыта тестами.
pub fn core_args(cfg: &Config, prof: &Section, uds: &str) -> Result<Vec<String>, String> {
    let g = |k: &str| cfg.shared(prof, k);
    let peer = prof.get("peer").trim().to_string();
    let password = prof.get("password").to_string();
    if peer.is_empty() {
        return Err("у профиля не задан peer".into());
    }
    if password.is_empty() {
        return Err("у профиля не задан password".into());
    }
    let hash_mode = if g("vk_hash_mode").is_empty() { "manual".to_string() } else { g("vk_hash_mode") };
    let vk = normalize_hashes(&g("vk"));
    if hash_mode != "auto_js" && vk.is_empty() {
        return Err("не заданы хеши VK (vk)".into());
    }
    if hash_mode == "auto_js" && g("vk_js_token").is_empty() {
        return Err("режим auto_js требует vk_js_token".into());
    }
    let or = |v: String, d: &str| if v.is_empty() { d.to_string() } else { v };
    let workers = or(g("workers"), "18");
    if workers.parse::<usize>().map(|n| n == 0 || n > 126).unwrap_or(true) {
        return Err("workers: ожидается 1..126".into());
    }
    let mut a: Vec<String> = Vec::new();
    let mut push = |k: &str, v: String| {
        a.push(k.to_string());
        a.push(v);
    };
    push("--peer", peer);
    push("--password", password);
    push("--device-id", or(g("device_id"), "unknown"));
    push("--vk", vk);
    push("--vk-hash-mode", hash_mode);
    push("--vk-auth-mode", or(g("vk_auth_mode"), "vkcalls"));
    push("--captcha-mode", or(g("captcha_mode"), "auto"));
    push("--fingerprint", or(g("fingerprint"), "chrome"));
    push("--client-ids", g("client_ids"));
    push("-n", workers);
    let (transport, obfs) = effective_settings(cfg, prof);
    push("--obfs", obfs);
    push("--turn-transport", transport);
    push("--tun-uds", uds.to_string());
    Ok(a)
}

/// Отпечаток параметров профиля: изменился → сессию надо перезапустить.
fn fingerprint(cfg: &Config, prof: &Section) -> String {
    match core_args(cfg, prof, "x") {
        Ok(a) => a.join("\u{1}"),
        Err(e) => format!("ERR:{}", e),
    }
}

// ------------------------------------------------------------ состояние

#[derive(Clone, Debug)]
struct Prof {
    id: String,
    name: String,
    priority: i64,
    enabled: bool,
    complete: bool,
    problem: String,
    fails: u32,
    cooldown_until: u64,
    state_override: &'static str,
    last_error: String,
    fp: String,
}

#[derive(Clone, Default)]
struct HashInfo {
    checking: bool,
    session: u64,
    set_fp: String,
    results: Vec<String>, // verified|invalid|captcha|unavailable
}

struct Session {
    core: Core,
    prof_id: String,
    fp: String,
    num: u64,
    #[allow(dead_code)]
    started: Instant,
    deadline: Instant,
    connected_at: Option<Instant>,
    ready: usize,
    active: i32,
    up: i64,
    down: i64,
    zero_since: Option<Instant>,
    captcha: Option<String>,
    auto_js: bool,
    probe_fail: u64,
    probe_ok: u64,
    last_probe: Instant,
    probe_rx: Option<Receiver<bool>>,
    access: &'static str,
    access_checked_at: u64,
    tick_prev: Instant,
    uds: String,
    tun_sent: bool,
    tun_deadline: Instant,
    client_ip: Option<std::net::Ipv4Addr>,
    dns: String,
}

struct Sup {
    opts: Opts,
    cfg: Config,
    set: Settings,
    pool: Vec<Prof>,
    sess: Option<Session>,
    tun: Option<tun::Tun>,
    tun_err: String,
    tun_retry: Instant,
    helper: Arc<Helper>,
    retry_at: Instant,
    next_reason: &'static str,
    session_seq: u64,
    reconnects: u64,
    total_up: i64,
    total_down: i64,
    history: Vec<Value>,
    last_error: String,
    started_at: u64,
    last_status: Instant,
    access_req_seen: u64,
    hash_req_seen: u64,
    hashes: Arc<Mutex<HashInfo>>,
    prev_mode: String,
    prev_active: String,
    cpu_prev: Option<(u64, Instant)>,
    cpu_pct: f64,
    last_ifname: String,
}

fn build_pool(cfg: &Config, old: &[Prof]) -> Vec<Prof> {
    cfg.servers()
        .iter()
        .map(|s| {
            let prev = old.iter().find(|p| p.id == s.name);
            let (complete, problem) = match core_args(cfg, s, "x") {
                Ok(_) => (true, String::new()),
                Err(e) => (false, e),
            };
            let fp = fingerprint(cfg, s);
            let enabled = s.flag("enabled", false);
            // правка параметров профиля или его повторное включение = вмешательство пользователя → новая попытка
            let keep = prev.filter(|p| p.fp == fp && p.enabled == enabled);
            Prof {
                id: s.name.clone(),
                name: s.get_or("name", &s.name).to_string(),
                priority: s.int("priority", 0),
                enabled,
                complete,
                problem,
                fails: keep.map(|p| p.fails).unwrap_or(0),
                cooldown_until: keep.map(|p| p.cooldown_until).unwrap_or(0),
                state_override: keep.map(|p| p.state_override).unwrap_or(""),
                last_error: keep.map(|p| p.last_error.clone()).unwrap_or_default(),
                fp,
            }
        })
        .collect()
}

pub fn run(opts: Opts) -> i32 {
    install_signals();
    let cfg = match Config::load(&opts.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("csqtt: {}", e);
            return 2;
        }
    };
    let set = Settings::from(&cfg.main());
    crate::log::init(&opts.log, set.log_size_kb, &set.log_level, true);
    logi!("csqtt {} запущен, конфиг {}", version_string(), opts.config);

    let solve_port = set.solve_port.unwrap_or(opts.helper_port.wrapping_add(1));
    let helper = Helper::new(opts.helper_port, solve_port);
    helper.set_public_host(&set.helper_host);
    // страница решения: явный helper_bind, иначе LAN-адрес роутера (не WAN), иначе все интерфейсы
    let solve_bind = if !set.helper_bind.is_empty() { set.helper_bind.clone() } else { crate::helper::lan_ip().unwrap_or_else(|| "0.0.0.0".into()) };
    if let Err(e) = crate::helper::start(&helper, "127.0.0.1", &solve_bind) {
        loge!("CAPTCHA-помощник не запущен: {}", e);
    } else {
        logi!("CAPTCHA-помощник: API 127.0.0.1:{}, страница решения {}:{}", opts.helper_port, solve_bind, solve_port);
    }

    let pool = build_pool(&cfg, &[]);
    let mut sup = Sup {
        prev_mode: set.mode.clone(),
        prev_active: set.active_profile.clone(),
        last_ifname: set.ifname.clone(),
        opts,
        cfg,
        set,
        pool,
        sess: None,
        tun: None,
        tun_err: String::new(),
        tun_retry: Instant::now(),
        helper,
        retry_at: Instant::now(),
        next_reason: "initial",
        session_seq: 0,
        reconnects: 0,
        total_up: 0,
        total_down: 0,
        history: Vec::new(),
        last_error: String::new(),
        started_at: util::now_secs(),
        last_status: Instant::now() - Duration::from_secs(10),
        access_req_seen: util::file_mtime("/var/run/csqtt/access-check.request"),
        hash_req_seen: util::file_mtime("/var/run/csqtt/hash-check.request"),
        hashes: Arc::new(Mutex::new(HashInfo::default())),
        cpu_prev: None,
        cpu_pct: 0.0,
    };

    while !SIG_TERM.load(Ordering::SeqCst) {
        if SIG_HUP.swap(false, Ordering::SeqCst) {
            sup.reload();
        }
        sup.step();
        if sup.last_status.elapsed() >= STATUS_EVERY {
            sup.write_status();
            sup.last_status = Instant::now();
        }
        std::thread::sleep(TICK);
    }
    logi!("получен сигнал остановки");
    sup.shutdown();
    0
}

impl Sup {
    fn status_dir_files(&self) -> (String, String) {
        let dir = std::path::Path::new(&self.opts.status).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| "/var/run/csqtt".into());
        (format!("{}/access-check.request", dir), format!("{}/hash-check.request", dir))
    }

    fn reload(&mut self) {
        let cfg = match Config::load(&self.opts.config) {
            Ok(c) => c,
            Err(e) => {
                loge!("reload: {} — остаёмся на прежней конфигурации", e);
                return;
            }
        };
        let old_set = self.set.clone();
        self.set = Settings::from(&cfg.main());
        crate::log::set_level(&self.set.log_level);
        self.helper.set_public_host(&self.set.helper_host);
        self.cfg = cfg;
        self.pool = build_pool(&self.cfg, &self.pool);
        logi!("конфигурация перечитана (SIGHUP): профилей {}", self.pool.len());
        if old_set.ifname != self.set.ifname || old_set.tun_mtu != self.set.tun_mtu || old_set.tun_address != self.set.tun_address {
            if self.sess.is_none() {
                self.tun = None; // пересоздадим с новыми параметрами
            } else {
                logw!("параметры TUN изменены — применятся при следующем перезапуске службы");
            }
        }
        if let Some(reason) = self.reload_wants_switch() {
            logi!("reload: переключение сессии ({})", reason);
            self.restart_session("manual");
        }
        self.prev_mode = self.set.mode.clone();
        self.prev_active = self.set.active_profile.clone();
        if !self.set.enabled && self.sess.is_some() {
            logi!("служба отключена (enabled=0) — останавливаю сессию");
            self.stop_session(true);
        }
    }

    fn reload_wants_switch(&self) -> Option<String> {
        let s = self.sess.as_ref()?;
        let cur = self.pool.iter().find(|p| p.id == s.prof_id);
        match cur {
            None => return Some("профиль удалён".into()),
            Some(p) if !p.enabled => return Some("профиль выключен".into()),
            Some(p) if !p.complete => return Some("профиль неполный".into()),
            _ => {}
        }
        if let Some(sec) = self.cfg.server(&s.prof_id) {
            if fingerprint(&self.cfg, &sec) != s.fp {
                return Some("параметры профиля изменились".into());
            }
        }
        if self.set.mode != self.prev_mode || self.set.active_profile != self.prev_active {
            let want = self.pick(true);
            if want.as_deref().map(|w| w != s.prof_id).unwrap_or(false) {
                return Some("изменён режим/активный профиль".into());
            }
        }
        None
    }

    // -------- выбор профиля
    fn eligible(&self, p: &Prof, now: u64, ignore_cd: bool) -> bool {
        p.enabled && p.complete && (ignore_cd || now >= p.cooldown_until)
    }

    fn pick(&self, ignore_cd: bool) -> Option<String> {
        let now = util::mono_secs();
        if self.set.mode == "manual" {
            let id = &self.set.active_profile;
            return self.pool.iter().find(|p| &p.id == id && p.enabled && p.complete).map(|p| p.id.clone());
        }
        let mut c: Vec<&Prof> = self.pool.iter().filter(|p| self.eligible(p, now, ignore_cd)).collect();
        c.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
        c.first().map(|p| p.id.clone())
    }

    fn others_available(&self, except: &str) -> bool {
        let now = util::mono_secs();
        self.set.failover && self.set.mode == "priority" && self.pool.iter().any(|p| p.id != except && self.eligible(p, now, false))
    }

    // -------- TUN
    fn ensure_tun(&mut self) -> bool {
        if self.tun.is_some() {
            return true;
        }
        if Instant::now() < self.tun_retry {
            return false;
        }
        let addr = if self.set.tun_address.is_empty() { None } else { tun::parse_cidr(&self.set.tun_address) };
        if !self.set.tun_address.is_empty() && addr.is_none() {
            logw!("tun_address '{}' некорректен — адрес не назначается", self.set.tun_address);
        }
        match tun::create(&self.set.ifname, self.set.tun_mtu, addr) {
            Ok(t) => {
                logi!("TUN {} создан (mtu {})", t.name, self.set.tun_mtu);
                self.last_ifname = t.name.clone();
                self.tun = Some(t);
                self.tun_err.clear();
                true
            }
            Err(e) => {
                self.tun_err = format!("не удалось создать {}: {}", self.set.ifname, e);
                loge!("{}", self.tun_err);
                self.tun_retry = Instant::now() + Duration::from_secs(10);
                false
            }
        }
    }

    // -------- сессии
    fn start_session(&mut self, id: &str, reason: &'static str) {
        let Some(sec) = self.cfg.server(id) else { return };
        if !self.ensure_tun() {
            self.last_error = self.tun_err.clone();
            return;
        }
        let uds = format!("csqtt-tun-{}", std::process::id());
        let args = match core_args(&self.cfg, &sec, &uds) {
            Ok(a) => a,
            Err(e) => {
                self.mark_failed(id, &e, "failed");
                self.last_error = format!("{}: {}", id, e);
                return;
            }
        };
        let auto_js = self.cfg.shared(&sec, "vk_hash_mode") == "auto_js";
        let bin = core_bin();
        logi!("запуск ядра для профиля {} ({}), причина: {}", id, sec.get_or("name", id), reason);
        let mut core = match Core::spawn(&bin, &args, true) {
            Ok(c) => c,
            Err(e) => {
                let m = format!("не удалось запустить {}: {}", bin, e);
                loge!("{}", m);
                self.mark_failed(id, &m, "failed");
                self.last_error = m;
                let fails = self.pool.iter().find(|p| p.id == id).map(|p| p.fails).unwrap_or(1);
                // нарастающая пауза, чтобы не долбить запуск каждую секунду
                self.retry_at = Instant::now() + Duration::from_secs((self.set.reconnect_delay << fails.min(5)).min(300));
                return;
            }
        };
        if auto_js {
            let tok = self.cfg.shared(&sec, "vk_js_token");
            let enc = b64(format!("{{\"token\":{}}}", Value::String(tok)).as_bytes());
            core.send_line(&format!("VK_JS_BOOTSTRAP:{}", enc));
        }
        self.session_seq += 1;
        if self.session_seq > 1 {
            self.reconnects += 1;
        }
        let from = self.history.last().and_then(|h| h["to"].as_str()).unwrap_or("").to_string();
        self.history.push(json!({"at": util::now_secs(), "from": from, "to": id, "reason": reason}));
        if self.history.len() > 20 {
            self.history.remove(0);
        }
        let now = Instant::now();
        self.sess = Some(Session {
            fp: fingerprint(&self.cfg, &sec),
            core,
            prof_id: id.to_string(),
            num: self.session_seq,
            started: now,
            deadline: now + CONNECT_TIMEOUT,
            connected_at: None,
            ready: 0,
            active: 0,
            up: 0,
            down: 0,
            zero_since: None,
            captcha: None,
            auto_js,
            probe_fail: 0,
            probe_ok: 0,
            last_probe: now,
            probe_rx: None,
            access: "waiting",
            access_checked_at: 0,
            tick_prev: now,
            uds: uds.clone(),
            tun_sent: false,
            tun_deadline: now + Duration::from_secs(15),
            client_ip: None,
            dns: String::new(),
        });
        self.set_pool_state(id, "");
        self.last_error.clear();
    }

    fn stop_session(&mut self, graceful_finish: bool) {
        if let Some(mut s) = self.sess.take() {
            if let Some(cid) = &s.captcha {
                self.helper.cancel(cid);
            }
            let finish = graceful_finish && s.auto_js;
            s.core.stop(finish, Duration::from_secs(4));
            self.total_up += s.up;
            self.total_down += s.down;
            logi!("сессия {} (профиль {}) остановлена", s.num, s.prof_id);
        }
    }

    fn restart_session(&mut self, reason: &'static str) {
        self.stop_session(false);
        self.next_reason = reason;
        self.retry_at = Instant::now();
    }

    fn shutdown(&mut self) {
        self.helper.cancel_all("shutdown");
        self.stop_session(true);
        let _ = std::fs::remove_file(&self.opts.status);
        logi!("остановлен");
    }

    fn set_pool_state(&mut self, id: &str, st: &'static str) {
        if let Some(p) = self.pool.iter_mut().find(|p| p.id == id) {
            p.state_override = st;
        }
    }

    fn mark_failed(&mut self, id: &str, why: &str, state: &'static str) {
        if let Some(p) = self.pool.iter_mut().find(|p| p.id == id) {
            p.fails += 1;
            p.last_error = why.to_string();
            p.state_override = state;
        }
    }

    /// Сбой сессии: учёт, cooldown, выбор следующего шага.
    fn fail_session(&mut self, why: String, kind: &'static str) {
        let Some(s) = self.sess.as_ref() else { return };
        let id = s.prof_id.clone();
        logw!("сбой профиля {}: {}", id, why);
        self.stop_session(false);
        let state = match kind {
            "auth" => "auth_failed",
            "captcha" => "captcha_required",
            _ => "failed",
        };
        self.mark_failed(&id, &why, state);
        self.last_error = why;
        let fails = self.pool.iter().find(|p| p.id == id).map(|p| p.fails).unwrap_or(1);
        if self.others_available(&id) {
            if let Some(p) = self.pool.iter_mut().find(|p| p.id == id) {
                p.cooldown_until = util::mono_secs() + self.set.cooldown;
            }
            self.next_reason = match kind {
                "auth" => "auth",
                "captcha" => "captcha",
                _ => "failover",
            };
            self.retry_at = Instant::now();
        } else {
            let mut delay = (self.set.reconnect_delay << fails.min(5)).min(300);
            if kind == "auth" {
                delay = delay.max(30);
            }
            self.next_reason = "retry";
            self.retry_at = Instant::now() + Duration::from_secs(delay);
        }
    }

    // -------- один шаг цикла
    fn step(&mut self) {
        self.helper.tick();
        let mono = util::mono_secs();
        for p in self.pool.iter_mut() {
            if p.state_override == "cooldown" && mono >= p.cooldown_until {
                p.state_override = "";
            }
        }
        if self.sess.is_none() {
            if !self.set.enabled || Instant::now() < self.retry_at {
                return;
            }
            match self.pick(false) {
                Some(id) => {
                    let reason = self.next_reason;
                    self.start_session(&id, reason);
                    self.next_reason = "retry";
                }
                None => {
                    if self.last_error.is_empty() || !self.last_error.starts_with("нет ") {
                        logw!("нет доступных профилей для подключения");
                    }
                    self.last_error = "нет доступных профилей (проверьте enabled/приоритеты)".into();
                    self.retry_at = Instant::now() + Duration::from_secs(5);
                }
            }
            return;
        }
        self.pump_messages();
        self.check_requests();
        self.check_health();
    }

    fn pump_messages(&mut self) {
        let mut msgs = Vec::new();
        if let Some(s) = self.sess.as_mut() {
            while let Ok(m) = s.core.rx.try_recv() {
                msgs.push(m);
                if msgs.len() > 500 {
                    break;
                }
            }
        }
        let mut fail: Option<(String, &'static str)> = None;
        let ifname_cfg = self.set.ifname.clone();
        let server_addr = self.set.tun_address.is_empty(); // пусто = адрес, выданный сервером
        for m in msgs {
            let Some(s) = self.sess.as_mut() else { return };
            match m {
                Msg::Event { kind, data } => match kind.as_str() {
                    "READY" => {
                        s.ready += 1;
                        if s.connected_at.is_none() {
                            s.connected_at = Some(Instant::now());
                            s.active = s.active.max(1);
                            s.zero_since = None;
                            logi!("туннель установлен (профиль {})", s.prof_id);
                        }
                    }
                    "STATS" => {
                        s.active = data["active"].as_i64().unwrap_or(0) as i32;
                        s.up = data["bytes_up"].as_i64().unwrap_or(s.up);
                        s.down = data["bytes_down"].as_i64().unwrap_or(s.down);
                        if s.active > 0 {
                            s.zero_since = None;
                            if s.connected_at.is_none() {
                                s.connected_at = Some(Instant::now());
                            }
                        }
                    }
                    "ACTIVE_ZERO" => {
                        s.active = 0;
                        if s.zero_since.is_none() {
                            s.zero_since = Some(Instant::now());
                        }
                        logw!("активных воркеров нет");
                    }
                    "ERROR" => {
                        let code = data["code"].as_str().unwrap_or("").to_string();
                        let msg = data["message"].as_str().unwrap_or("").to_string();
                        let fatal = data["fatal"].as_bool().unwrap_or(false);
                        loge!("ядро: [{}] {}{}", code, msg, if fatal { " (фатально)" } else { "" });
                        if fatal && fail.is_none() {
                            let l = format!("{} {}", code, msg).to_lowercase();
                            let kind = if l.contains("auth") || l.contains("password") || l.contains("401") || l.contains("forbidden") { "auth" } else { "fail" };
                            fail = Some((format!("{}: {}", code, msg), kind));
                        }
                    }
                    "CONFIG" => {
                        if let Some((ip, dns)) = data["config"].as_str().and_then(tun::parse_tunconf) {
                            logi!("сервер выдал адрес туннеля {} (DNS {})", ip, if dns.is_empty() { "—" } else { &dns });
                            s.client_ip = Some(ip);
                            s.dns = dns;
                            if server_addr {
                                // как Android-клиент: адрес /32; маршрутов не добавляем (interface-only)
                                match tun::set_addr(&ifname_cfg, ip, 32) {
                                    Ok(()) => logi!("адрес {}/32 назначен на {}", ip, ifname_cfg),
                                    Err(e) => logw!("не удалось назначить {} на {}: {}", ip, ifname_cfg, e),
                                }
                            }
                        } else {
                            logd!("ядро: CONFIG {}", data);
                        }
                    }
                    "STOPPED" => logi!("ядро сообщило STOPPED"),
                    "SERVER_RESTART" | "NETWORK_SUSPECT" | "PROGRESS" | "PROCESS" => logd!("ядро: {} {}", kind, data),
                    _ => logd!("ядро: событие {} {}", kind, data),
                },
                Msg::Captcha { mode, uri, session: _ } => {
                    if s.captcha.is_some() {
                        s.core.send_line("CAPTCHA_RESULT|error:busy");
                        continue;
                    }
                    if mode == "auto" {
                        // headless-WebView на роутере недоступен: отдаём управление цепочке ядра
                        s.core.send_line("CAPTCHA_RESULT|error:headless-unsupported");
                        continue;
                    }
                    let ttl = if mode == "manual" { 60 } else { 120 };
                    let pid = s.prof_id.clone();
                    match self.helper.new_challenge(&pid, &mode, &uri, ttl) {
                        Ok(cid) => {
                            logi!("[CAPTCHA] требуется ручное решение (challenge {}, режим {}); откройте страницу CAPTCHA в панели", cid, mode);
                            s.captcha = Some(cid);
                            self.set_pool_state(&pid, "captcha_required");
                        }
                        Err(e) => {
                            logw!("[CAPTCHA] {}", e);
                            s.core.send_line(&format!("CAPTCHA_RESULT|error:{}", e));
                        }
                    }
                }
                Msg::HashCheck(_) => {}
                Msg::Log { stderr: _, line } => {
                    let l = line.trim();
                    if l.is_empty() {
                        continue;
                    }
                    if l.contains("[ОШИБКА]") || l.contains("[ФАТАЛ]") || l.contains("[PANIC]") {
                        loge!("core: {}", l);
                    } else if l.contains("[КАПЧА]") {
                        logi!("core: {}", l);
                    } else {
                        logd!("core: {}", l);
                    }
                }
                Msg::StdoutClosed => {}
            }
        }
        if let Some((why, kind)) = fail {
            return self.fail_session(why, kind);
        }
        // исход CAPTCHA
        let outcome = self.sess.as_ref().and_then(|s| s.captcha.clone()).and_then(|cid| self.helper.outcome(&cid).map(|o| (cid, o)));
        if let Some((_cid, o)) = outcome {
            let (pid, policy_failover) = {
                let s = self.sess.as_mut().unwrap();
                s.captcha = None;
                (s.prof_id.clone(), self.set.captcha_policy == "failover")
            };
            match o {
                Ok(tok) => {
                    let s = self.sess.as_mut().unwrap();
                    s.core.send_line(&format!("CAPTCHA_RESULT|{}", tok));
                    self.set_pool_state(&pid, "");
                    logi!("[CAPTCHA] решение передано ядру");
                }
                Err(reason) => {
                    let s = self.sess.as_mut().unwrap();
                    s.core.send_line(&format!("CAPTCHA_RESULT|error:{}", reason));
                    logw!("[CAPTCHA] не решена: {}", reason);
                    if policy_failover && self.others_available(&pid) {
                        return self.fail_session(format!("CAPTCHA не решена ({})", reason), "captcha");
                    }
                    self.set_pool_state(&pid, "");
                }
            }
        }
    }

    fn check_requests(&mut self) {
        let (acc, hsh) = self.status_dir_files();
        let m = util::file_mtime(&acc);
        if m > self.access_req_seen {
            self.access_req_seen = m;
            if let Some(s) = self.sess.as_mut() {
                s.last_probe = Instant::now() - Duration::from_secs(3600); // проба сразу
                logi!("запрошена ручная проверка доступа");
            }
        }
        let m = util::file_mtime(&hsh);
        if m > self.hash_req_seen {
            self.hash_req_seen = m;
            self.start_hash_check();
        }
    }

    fn start_hash_check(&mut self) {
        let Some(s) = self.sess.as_ref() else { return };
        let Some(sec) = self.cfg.server(&s.prof_id) else { return };
        let vk = normalize_hashes(&self.cfg.shared(&sec, "vk"));
        if vk.is_empty() || self.hashes.lock().unwrap().checking {
            return;
        }
        let fp = self.cfg.shared(&sec, "fingerprint");
        let ids = self.cfg.shared(&sec, "client_ids");
        let num = s.num;
        let hashes = self.hashes.clone();
        {
            let mut h = hashes.lock().unwrap();
            h.checking = true;
        }
        std::thread::spawn(move || {
            let res = validate_hashes(&vk, if fp.is_empty() { "chrome" } else { &fp }, &ids);
            let mut h = hashes.lock().unwrap();
            h.checking = false;
            h.session = num;
            h.set_fp = vk;
            h.results = res.into_iter().map(|(st, _)| st).collect();
        });
    }

    fn check_health(&mut self) {
        let interval = self.set.health_interval;
        let thr = self.set.fail_threshold;
        let succ = self.set.success_threshold;
        let health_mode = self.set.health_mode.clone();
        let target = self.set.health_target.clone();
        let ifname = self.set.ifname.clone();
        let failback = self.set.failback && self.set.mode == "priority";
        let stable = self.set.failback_stable;
        let mut fail: Option<(String, &'static str)> = None;
        let mut do_failback = false;

        // ядро завершилось: даём stdout-потоку доставить последние события (ERROR fatal и т.п.)
        let exited = self.sess.as_mut().and_then(|s| s.core.exit_code());
        if let Some(code) = exited {
            std::thread::sleep(Duration::from_millis(150));
            self.pump_messages();
            if self.sess.is_none() {
                return;
            }
            return self.fail_session(format!("ядро завершилось (код {})", code), "fail");
        }
        // неблокирующая передача дескриптора TUN: повторяем, пока ядро не откроет сокет
        let pending = self.sess.as_ref().filter(|s| !s.tun_sent).map(|s| (s.uds.clone(), s.tun_deadline));
        if let Some((uds, deadline)) = pending {
            let Some(fd) = self.tun.as_ref().map(|t| t.fd.as_raw_fd()) else { return };
            match tun::try_send(&uds, fd) {
                Ok(()) => {
                    if let Some(s) = self.sess.as_mut() {
                        s.tun_sent = true;
                    }
                    logd!("дескриптор TUN передан ядру");
                }
                Err(e) => {
                    let retry = matches!(e.raw_os_error(), Some(libc::ECONNREFUSED) | Some(libc::ENOENT));
                    if !(retry && Instant::now() < deadline) {
                        return self.fail_session(format!("передача TUN ядру не удалась: {}", e), "fail");
                    }
                }
            }
            return;
        }

        let Some(s) = self.sess.as_mut() else { return };
        let now = Instant::now();
        let dt = now.duration_since(s.tick_prev);
        s.tick_prev = now;
        if s.captcha.is_some() && s.connected_at.is_none() {
            s.deadline += dt; // время ручной капчи не считаем
        }
        if s.connected_at.is_none() {
            if now >= s.deadline {
                fail = Some(("таймаут установки соединения".into(), "fail"));
            }
        } else {
            if let Some(z) = s.zero_since {
                if now.duration_since(z) >= Duration::from_secs(interval * thr) {
                    fail = Some((format!("нет активных воркеров {} с", now.duration_since(z).as_secs()), "fail"));
                }
            }
            // активная проба доступности через интерфейс
            if let Some(rx) = &s.probe_rx {
                if let Ok(ok) = rx.try_recv() {
                    s.probe_rx = None;
                    s.last_probe = Instant::now(); // следующая проба — через interval после завершения этой
                    s.access_checked_at = util::now_secs();
                    if ok {
                        s.probe_ok += 1;
                        if s.probe_ok >= succ {
                            s.probe_fail = 0; // гистерезис: счётчик сбоев сбрасывается после success_threshold удач подряд
                        }
                        s.access = "ok";
                    } else {
                        s.probe_fail += 1;
                        s.probe_ok = 0;
                        s.access = "failed";
                    }
                }
            }
            // Явный health_target (TCP) участвует в failover. Если он не задан, используется цель по
            // умолчанию — DNS-запрос к DNS, выданному сервером, через интерфейс туннеля: только
            // информация (access_state), без failover — внешние причины не должны ронять рабочий профиль.
            let mode_probe = health_mode == "both" || health_mode == "probe" || health_mode == "access";
            let explicit = !target.is_empty();
            let default_dns = if explicit { None } else { first_dns_ip(&s.dns) };
            let probing = mode_probe && (explicit || default_dns.is_some());
            if probing && s.probe_rx.is_none() && now.duration_since(s.last_probe) >= Duration::from_secs(interval) {
                s.last_probe = now;
                // прошлый результат (ok/failed) остаётся видимым, пока идёт новая проба
                if matches!(s.access, "waiting" | "skipped") {
                    s.access = "checking";
                }
                let (tx, rx) = mpsc::channel();
                let (t, i, d) = (target.clone(), ifname.clone(), default_dns.clone());
                std::thread::spawn(move || {
                    let ok = match d {
                        Some(ip) if t.is_empty() => dns_probe(&ip, 53, &i),
                        _ => tcp_probe(&t, &i),
                    };
                    let _ = tx.send(ok);
                });
                s.probe_rx = Some(rx);
            } else if !probing {
                s.access = "skipped";
            }
            if explicit && probing && s.probe_fail >= thr && fail.is_none() {
                fail = Some((format!("проверка доступа {} не проходит ({} раз подряд)", target, s.probe_fail), "fail"));
            }
            if failback && fail.is_none() {
                if let Some(c) = s.connected_at {
                    if now.duration_since(c) >= Duration::from_secs(stable) {
                        do_failback = true;
                    }
                }
            }
        }
        if let Some((why, kind)) = fail {
            return self.fail_session(why, kind);
        }
        if do_failback {
            let cur = self.sess.as_ref().map(|s| s.prof_id.clone()).unwrap_or_default();
            let cur_prio = self.pool.iter().find(|p| p.id == cur).map(|p| p.priority).unwrap_or(i64::MAX);
            if let Some(best) = self.pick(false) {
                let best_prio = self.pool.iter().find(|p| p.id == best).map(|p| p.priority).unwrap_or(i64::MAX);
                if best != cur && best_prio < cur_prio {
                    logi!("failback: возврат на профиль {}", best);
                    self.restart_session("failback");
                }
            }
        }
    }

    // -------- status.json
    fn proc_rss_kb(pid: u32) -> Option<u64> {
        let t = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
        t.lines().find(|l| l.starts_with("VmRSS:"))?.split_whitespace().nth(1)?.parse().ok()
    }
    fn proc_ticks(pid: u32) -> Option<u64> {
        let t = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        let rest = &t[t.rfind(')')? + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
    }

    fn profile_state(&self, p: &Prof) -> &'static str {
        if !p.enabled {
            return "disabled";
        }
        if let Some(s) = &self.sess {
            if s.prof_id == p.id {
                if p.state_override == "captcha_required" {
                    return "captcha_required";
                }
                return if s.connected_at.is_some() { "active" } else { "connecting" };
            }
        }
        if !p.complete {
            return "failed";
        }
        if p.state_override == "cooldown" || (p.cooldown_until > util::mono_secs() && p.state_override != "") {
            return "cooldown";
        }
        match p.state_override {
            "" => "standby",
            "failed" => "failed",
            "auth_failed" => "auth_failed",
            "captcha_required" => "captcha_required",
            _ => "standby",
        }
    }

    fn write_status(&mut self) {
        let now = util::now_secs();
        let pid = std::process::id();
        let (connected, session_obj, active_profile, workers_active, core_pid) = match &self.sess {
            Some(s) => (
                s.connected_at.is_some() && s.active > 0,
                json!({
                    "session": s.num,
                    "session_age_secs": s.connected_at.map(|c| c.elapsed().as_secs()).unwrap_or(0),
                    "session_established": s.connected_at.is_some(),
                    "process_running": true,
                    "tun_present": tun::exists(&self.set.ifname),
                    "transfer_observed": (s.up + s.down) > 0,
                    "stale": false,
                    "access_state": s.access,
                    "access_checked_at": s.access_checked_at,
                    "access_target": if !self.set.health_target.is_empty() { self.set.health_target.clone() }
                        else { first_dns_ip(&s.dns).map(|ip| format!("{}:53", ip)).unwrap_or_default() },
                    "access_target_default": self.set.health_target.is_empty() && first_dns_ip(&s.dns).is_some(),
                }),
                s.prof_id.clone(),
                s.active.max(0),
                Some(s.core.pid),
            ),
            None => (
                false,
                json!({"session_established": false, "process_running": false, "tun_present": tun::exists(&self.set.ifname),
                       "transfer_observed": false, "stale": false, "access_state": "waiting"}),
                String::new(),
                0,
                None,
            ),
        };
        // CPU/RSS ядра + супервизора
        let mut rss = Self::proc_rss_kb(pid).unwrap_or(0);
        let mut ticks = Self::proc_ticks(pid).unwrap_or(0);
        if let Some(cp) = core_pid {
            rss += Self::proc_rss_kb(cp).unwrap_or(0);
            ticks += Self::proc_ticks(cp).unwrap_or(0);
        }
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
        if let Some((pt, pi)) = self.cpu_prev {
            let dt = pi.elapsed().as_secs_f64();
            if dt >= 0.5 {
                self.cpu_pct = ((ticks.saturating_sub(pt)) as f64 / hz / dt * 100.0 * 10.0).round() / 10.0;
                self.cpu_prev = Some((ticks, Instant::now()));
            }
        } else {
            self.cpu_prev = Some((ticks, Instant::now()));
        }
        let (up, down) = match &self.sess {
            Some(s) => (self.total_up + s.up, self.total_down + s.down),
            None => (self.total_up, self.total_down),
        };
        let configured_workers = self
            .pool
            .iter()
            .find(|p| p.id == active_profile)
            .and_then(|p| self.cfg.server(&p.id))
            .map(|sec| self.cfg.shared(&sec, "workers").parse::<i64>().unwrap_or(18))
            .unwrap_or(0);
        let profiles: Vec<Value> = self
            .pool
            .iter()
            .map(|p| json!({"id": p.id, "name": p.name, "state": self.profile_state(p), "priority": p.priority, "fails": p.fails,
                            "last_error": if p.problem.is_empty() { p.last_error.clone() } else { p.problem.clone() }}))
            .collect();
        let mut st = json!({
            "schema": 1,
            "pid": pid,
            "version": version_string(),
            "generated_at": now,
            "started_at": self.started_at,
            "running": true,
            "connected": connected,
            "enabled": self.set.enabled,
            "active_profile": active_profile,
            "selection_mode": self.set.mode,
            "tunnel": {"interface": self.set.ifname, "present": tun::exists(&self.set.ifname),
                       "mtu": iface_mtu(&self.set.ifname),
                       "client_ip": self.sess.as_ref().and_then(|s| s.client_ip).map(|i| i.to_string()),
                       "dns": self.sess.as_ref().map(|s| s.dns.clone()).filter(|d| !d.is_empty())},
            "connectivity": session_obj,
            "tx_bytes": up,
            "rx_bytes": down,
            "reconnects": self.reconnects,
            "workers": {"active": workers_active, "configured": configured_workers},
            "resources": {"process_rss_kb": rss, "process_cpu_percent": self.cpu_pct},
            "switch_history": self.history.iter().rev().cloned().collect::<Vec<_>>(),
            "profiles": profiles,
            "captcha_pending": self.helper.pending(),
            "captcha_challenges": self.helper.snapshot(),
            "last_error": if !self.last_error.is_empty() { Value::String(self.last_error.clone()) } else { Value::Null },
        });
        if let Some(s) = &self.sess {
            st["auto_api"] = if s.auto_js { json!({"state": if s.connected_at.is_some() {"active"} else {"starting"}}) } else { Value::Null };
        }
        if let Some(sec) = self.sess.as_ref().and_then(|s| self.cfg.server(&s.prof_id)) {
            st["vk_hashes"] = self.vk_hashes_json(&sec);
            let (transport, obfs) = effective_settings(&self.cfg, &sec);
            st["effective"] = json!({"turn_transport": transport, "obfs": obfs});
        }
        if st["auto_api"].is_null() {
            st.as_object_mut().unwrap().remove("auto_api");
        }
        if let Err(e) = util::write_atomic(&self.opts.status, st.to_string().as_bytes(), 0o644) {
            logw!("не удалось записать {}: {}", self.opts.status, e);
        }
    }

    fn vk_hashes_json(&self, sec: &Section) -> Value {
        let mode = { let m = self.cfg.shared(sec, "vk_hash_mode"); if m.is_empty() { "manual".to_string() } else { m } };
        let list: Vec<String> = normalize_hashes(&self.cfg.shared(sec, "vk")).split(',').filter(|x| !x.is_empty()).map(String::from).collect();
        let h = self.hashes.lock().unwrap().clone();
        let cur_set = list.join(",");
        let sess_num = self.sess.as_ref().map(|s| s.num).unwrap_or(0);
        let connected = self.sess.as_ref().map(|s| s.connected_at.is_some()).unwrap_or(false);
        let have = !h.results.is_empty();
        let stale_reason = if !have { None } else if h.set_fp != cur_set { Some("set_changed") } else if h.session != sess_num { Some("session") } else { None };
        let entries: Vec<Value> = list
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let state = if have && stale_reason.is_none() { h.results.get(i).cloned().unwrap_or_else(|| "not_checked".into()) } else { "not_checked".into() };
                json!({"index": i + 1, "state": state, "source": "manual"})
            })
            .collect();
        let mut v = json!({
            "mode": mode,
            "state": if connected { "connected_unverified" } else { "unverified" },
            "manual_saved": list.len(),
            "hashes": entries,
            "hashes_truncated": false,
            "check_state": if h.checking { "checking" } else if stale_reason.is_some() { "stale" } else if have { "done" } else { "idle" },
        });
        if let Some(r) = stale_reason {
            v["check_stale_reason"] = json!(r);
        }
        v
    }
}

/// Проверка хешей VK через ядро: [(status, message)] в порядке хешей.
pub fn validate_hashes(vk: &str, fingerprint: &str, client_ids: &str) -> Vec<(String, String)> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let mut out = Vec::new();
    let child = Command::new(core_bin())
        .args(["--validate-vk-hashes", "--vk", vk, "--fingerprint", fingerprint, "--client-ids", client_ids])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return out };
    if let Some(so) = child.stdout.take() {
        for line in BufReader::new(so).lines().map_while(Result::ok) {
            if let Some(js) = line.strip_prefix("HASH_CHECK:") {
                if let Ok(v) = serde_json::from_str::<Value>(js) {
                    let status = v["status"].as_str().unwrap_or("unavailable");
                    let msg = v["message"].as_str().unwrap_or("").to_string();
                    let st = match status {
                        "valid" => "verified",
                        "invalid" if msg.to_lowercase().contains("captcha") => "captcha",
                        "invalid" => "invalid",
                        _ => "unavailable",
                    };
                    out.push((st.to_string(), msg));
                }
            }
        }
    }
    let _ = child.wait();
    out
}

/// Первый IPv4-адрес из списка DNS ("1.1.1.1,8.8.8.8").
pub fn first_dns_ip(dns: &str) -> Option<String> {
    dns.split(',').map(str::trim).find_map(|x| x.parse::<std::net::Ipv4Addr>().ok()).map(|ip| ip.to_string())
}

/// Минимальный DNS-запрос A для example.com (id 0x4351).
pub fn dns_query() -> Vec<u8> {
    let mut q = vec![0x43, 0x51, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// Ответ на наш запрос: тот же id и бит QR.
pub fn is_dns_response(resp: &[u8]) -> bool {
    resp.len() >= 12 && resp[0] == 0x43 && resp[1] == 0x51 && resp[2] & 0x80 != 0
}

/// DNS-проба через интерфейс туннеля (SO_BINDTODEVICE): подтверждает сквозной путь «туннель → сервер → интернет».
pub fn dns_probe(ip: &str, port: u16, ifname: &str) -> bool {
    use std::net::UdpSocket;
    let Ok(addr) = format!("{}:{}", ip, port).parse::<SocketAddr>() else { return false };
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { return false };
    let name = std::ffi::CString::new(ifname).unwrap_or_default();
    let r = unsafe { libc::setsockopt(sock.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr() as *const _, ifname.len() as libc::socklen_t) };
    if r < 0 {
        return false; // без привязки к туннелю проба была бы ложной (ушла бы через WAN)
    }
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    if sock.connect(addr).is_err() || sock.send(&dns_query()).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(sock.recv(&mut buf), Ok(n) if is_dns_response(&buf[..n]))
}

/// TCP-проба "host:port" с привязкой сокета к интерфейсу туннеля.
pub fn tcp_probe(target: &str, ifname: &str) -> bool {
    let Some(addr) = target.to_socket_addrs().ok().and_then(|mut a| a.next()) else { return false };
    probe_addr(addr, ifname)
}

fn probe_addr(addr: SocketAddr, ifname: &str) -> bool {
    match raw_connect(addr, ifname) {
        Some(ok) => ok,
        None => {
            logd!("SO_BINDTODEVICE {} недоступен — проба без привязки", ifname);
            TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok()
        }
    }
}

/// None — привязка к интерфейсу невозможна; Some(ok) — результат соединения.
fn raw_connect(addr: SocketAddr, ifname: &str) -> Option<bool> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return None;
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let name = std::ffi::CString::new(ifname).unwrap_or_default();
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr() as *const _, ifname.len() as libc::socklen_t) } < 0 {
        return None;
    }
    let (ss, len): (libc::sockaddr_storage, libc::socklen_t) = unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        match addr {
            SocketAddr::V4(a) => {
                let sin = &mut ss as *mut _ as *mut libc::sockaddr_in;
                (*sin).sin_family = libc::AF_INET as _;
                (*sin).sin_port = a.port().to_be();
                (*sin).sin_addr = libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) };
                (ss, std::mem::size_of::<libc::sockaddr_in>() as _)
            }
            SocketAddr::V6(a) => {
                let sin6 = &mut ss as *mut _ as *mut libc::sockaddr_in6;
                (*sin6).sin6_family = libc::AF_INET6 as _;
                (*sin6).sin6_port = a.port().to_be();
                (*sin6).sin6_addr = libc::in6_addr { s6_addr: a.ip().octets() };
                (ss, std::mem::size_of::<libc::sockaddr_in6>() as _)
            }
        }
    };
    let r = unsafe { libc::connect(fd, &ss as *const _ as *const libc::sockaddr, len) };
    if r == 0 {
        return Some(true);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
        return Some(false);
    }
    let mut pfd = libc::pollfd { fd: owned.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
    if unsafe { libc::poll(&mut pfd, 1, 3000) } <= 0 {
        return Some(false);
    }
    let mut err: libc::c_int = 0;
    let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut _, &mut l) };
    Some(err == 0)
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        o.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "config csqtt 'main'\n\toption enabled '1'\n\toption vk 'h1,h2'\n\toption device_id 'dev-1'\n\toption workers '12'\n\nconfig server 'p1'\n\toption name 'A'\n\toption enabled '1'\n\toption priority '10'\n\toption peer '203.0.113.7:46000'\n\toption password 'secret'\n\nconfig server 'p2'\n\toption enabled '1'\n\toption priority '20'\n\toption peer '203.0.113.8:46000'\n";

    #[test]
    fn args_ok_and_errors() {
        let cfg = Config::parse(CFG);
        let a = core_args(&cfg, &cfg.server("p1").unwrap(), "u").unwrap();
        let s = a.join(" ");
        assert!(s.contains("--peer 203.0.113.7:46000"));
        assert!(s.contains("--vk h1,h2"));
        assert!(s.contains("--device-id dev-1"));
        assert!(s.contains("-n 12"));
        assert!(s.contains("--captcha-mode auto"));
        assert!(s.ends_with("--tun-uds u"));
        assert!(core_args(&cfg, &cfg.server("p2").unwrap(), "u").unwrap_err().contains("password"));
    }

    #[test]
    fn auto_js_requires_token() {
        let t = CFG.replace("option vk 'h1,h2'", "option vk_hash_mode 'auto_js'");
        let cfg = Config::parse(&t);
        assert!(core_args(&cfg, &cfg.server("p1").unwrap(), "u").unwrap_err().contains("vk_js_token"));
        let t2 = t.replace("option device_id", "option vk_js_token 'T'\n\toption device_id");
        let cfg2 = Config::parse(&t2);
        assert!(core_args(&cfg2, &cfg2.server("p1").unwrap(), "u").is_ok());
    }

    #[test]
    fn effective_defaults_and_overrides() {
        let cfg = Config::parse(CFG);
        let sec = cfg.server("p1").unwrap();
        assert_eq!(effective_settings(&cfg, &sec), ("udp".to_string(), "audio".to_string()));
        let a = core_args(&cfg, &sec, "u").unwrap().join(" ");
        assert!(a.contains("--turn-transport udp") && a.contains("--obfs audio"));
        let t = CFG.replace("option workers '12'", "option workers '12'\n\toption turn_transport 'tcp'");
        let cfg2 = Config::parse(&t);
        assert_eq!(effective_settings(&cfg2, &cfg2.server("p1").unwrap()).0, "tcp");
        let t3 = t.replace("option password 'secret'", "option password 'secret'\n\toption obfs 'none'");
        let cfg3 = Config::parse(&t3);
        assert_eq!(effective_settings(&cfg3, &cfg3.server("p1").unwrap()), ("tcp".to_string(), "none".to_string()));
    }

    #[test]
    fn hashes_normalized() {
        assert_eq!(normalize_hashes(" a, b;c+d  e "), "a,b,c,d,e");
    }

    #[test]
    fn base64_matches() {
        assert_eq!(b64(b"{\"token\":\"x\"}"), "eyJ0b2tlbiI6IngifQ==");
        assert_eq!(b64(b"ab"), "YWI=");
    }

    #[test]
    fn dns_helpers() {
        assert_eq!(first_dns_ip("1.1.1.1,8.8.8.8").as_deref(), Some("1.1.1.1"));
        assert_eq!(first_dns_ip(" x, 9.9.9.9").as_deref(), Some("9.9.9.9"));
        assert_eq!(first_dns_ip(""), None);
        let q = dns_query();
        assert_eq!(q.len(), 12 + 1 + 7 + 1 + 3 + 1 + 4);
        let mut resp = q.clone();
        resp[2] |= 0x80;
        assert!(is_dns_response(&resp) && !is_dns_response(&q) && !is_dns_response(&[0u8; 4]));
    }

    /// root (SO_BINDTODEVICE): cargo test -- --ignored
    #[test]
    #[ignore]
    fn dns_probe_loopback() {
        let srv = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut b = [0u8; 512];
            if let Ok((n, from)) = srv.recv_from(&mut b) {
                let mut r = b[..n].to_vec();
                r[2] |= 0x80;
                let _ = srv.send_to(&r, from);
            }
        });
        assert!(dns_probe("127.0.0.1", port, "lo"));
        assert!(!dns_probe("127.0.0.1", port.wrapping_add(1), "lo")); // порт молчит → таймаут
    }

    #[test]
    fn settings_defaults() {
        let cfg = Config::parse(CFG);
        let s = Settings::from(&cfg.main());
        assert_eq!(s.mode, "priority");
        assert_eq!(s.tun_mtu, 1280);
        assert!(s.failover && !s.failback);
    }
}
