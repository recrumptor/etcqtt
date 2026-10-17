//! Журнал: файл (с ротацией по размеру) + stdout (procd → syslog/logread).
use crate::util;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

struct State {
    file: Option<File>,
    path: String,
    max_bytes: u64,
    level: u8,
    echo: bool,
}

static LOG: OnceLock<Mutex<State>> = OnceLock::new();

pub fn level_num(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "debug" => 0,
        "info" => 1,
        "warn" | "warning" => 2,
        "error" => 3,
        _ => 1,
    }
}

pub fn init(path: &str, max_kb: u64, level: &str, echo: bool) {
    let file = if path.is_empty() { None } else { OpenOptions::new().create(true).append(true).open(path).ok() };
    let st = State { file, path: path.to_string(), max_bytes: max_kb.max(32) * 1024, level: level_num(level), echo };
    if let Some(m) = LOG.get() {
        *m.lock().unwrap() = st;
    } else {
        let _ = LOG.set(Mutex::new(st));
    }
}

pub fn set_level(level: &str) {
    if let Some(m) = LOG.get() {
        m.lock().unwrap().level = level_num(level);
    }
}

fn stamp() -> String {
    let t = util::now_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)
}

pub fn write(lvl: u8, tag: &str, msg: &str) {
    let msg = util::redact(msg);
    let Some(m) = LOG.get() else {
        eprintln!("[{}] {}", tag, msg);
        return;
    };
    let mut st = m.lock().unwrap();
    if lvl < st.level {
        return;
    }
    let line = format!("{} [{}] {}\n", stamp(), tag, msg);
    if st.echo {
        print!("{}", line);
        let _ = std::io::stdout().flush();
    }
    if st.file.is_some() {
        let over = st.file.as_ref().and_then(|f| f.metadata().ok()).map(|md| md.len() > st.max_bytes).unwrap_or(false);
        if over {
            let bak = format!("{}.1", st.path);
            let _ = fs::rename(&st.path, &bak);
            st.file = OpenOptions::new().create(true).append(true).open(&st.path).ok();
        }
        if let Some(f) = st.file.as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[macro_export]
macro_rules! logd { ($($a:tt)*) => { $crate::log::write(0, "DEBUG", &format!($($a)*)) } }
#[macro_export]
macro_rules! logi { ($($a:tt)*) => { $crate::log::write(1, "INFO", &format!($($a)*)) } }
#[macro_export]
macro_rules! logw { ($($a:tt)*) => { $crate::log::write(2, "WARN", &format!($($a)*)) } }
#[macro_export]
macro_rules! loge { ($($a:tt)*) => { $crate::log::write(3, "ERROR", &format!($($a)*)) } }
