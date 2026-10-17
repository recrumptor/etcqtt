//! Запуск и управление процессом ядра (upstream `client`) через stdin/stdout.
//! Протокол ядра: события `__CSQTT_EVENT__|KIND|{json}`, `CAPTCHA_SOLVE|mode|uri|session`,
//! `HASH_CHECK:{json}`; команды в stdin: STOP, PAUSE, RESUME, FINISH_VK_CALLS,
//! `CAPTCHA_RESULT|<token|error:..>`, `VK_JS_BOOTSTRAP:<base64>`.
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

pub const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";

#[derive(Debug)]
#[allow(dead_code)]
pub enum Msg {
    Event { kind: String, data: Value },
    Captcha { mode: String, uri: String, session: String },
    HashCheck(Value),
    Log { stderr: bool, line: String },
    StdoutClosed,
}

pub fn parse_stdout_line(line: &str) -> Msg {
    if let Some(rest) = line.strip_prefix(EVENT_PREFIX) {
        let (kind, json) = rest.split_once('|').unwrap_or((rest, "{}"));
        let data = serde_json::from_str(json).unwrap_or(Value::Null);
        return Msg::Event { kind: kind.to_string(), data };
    }
    if let Some(rest) = line.strip_prefix("CAPTCHA_SOLVE|") {
        let mut p = rest.splitn(3, '|');
        let mode = p.next().unwrap_or("").to_string();
        let uri = p.next().unwrap_or("").to_string();
        let session = p.next().unwrap_or("").to_string();
        return Msg::Captcha { mode, uri, session };
    }
    if let Some(rest) = line.strip_prefix("HASH_CHECK:") {
        if let Ok(v) = serde_json::from_str(rest) {
            return Msg::HashCheck(v);
        }
    }
    Msg::Log { stderr: false, line: line.to_string() }
}

pub struct Core {
    pub child: Child,
    stdin: Option<ChildStdin>,
    pub rx: Receiver<Msg>,
    pub pid: u32,
    #[allow(dead_code)]
    pub started: Instant,
}

impl Core {
    pub fn spawn(bin: &str, args: &[String], events: bool) -> std::io::Result<Core> {
        let mut cmd = Command::new(bin);
        cmd.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if events {
            cmd.env("CSQTT_EVENTS", "1");
        }
        let mut child = cmd.spawn()?;
        let pid = child.id();
        let stdin = child.stdin.take();
        let (tx, rx) = mpsc::channel();
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(parse_stdout_line(line.trim_end())).is_err() {
                        return;
                    }
                }
                let _ = tx.send(Msg::StdoutClosed);
            });
        }
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(Msg::Log { stderr: true, line }).is_err() {
                        return;
                    }
                }
            });
        }
        Ok(Core { child, stdin, rx, pid, started: Instant::now() })
    }

    pub fn send_line(&mut self, line: &str) -> bool {
        if let Some(si) = self.stdin.as_mut() {
            if si.write_all(line.as_bytes()).is_ok() && si.write_all(b"\n").is_ok() && si.flush().is_ok() {
                return true;
            }
        }
        false
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn exit_code(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(st)) => Some(st.code().unwrap_or(-1)),
            _ => None,
        }
    }

    /// Мягкая остановка: STOP в stdin, ожидание grace, затем SIGKILL.
    pub fn stop(&mut self, finish_vk_calls: bool, grace: Duration) {
        if finish_vk_calls {
            self.send_line("FINISH_VK_CALLS");
        }
        self.send_line("STOP");
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if !self.alive() {
                self.stdin = None;
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stdin = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_lines() {
        match parse_stdout_line("__CSQTT_EVENT__|READY|{\"worker\":3}") {
            Msg::Event { kind, data } => {
                assert_eq!(kind, "READY");
                assert_eq!(data["worker"], 3);
            }
            _ => panic!(),
        }
        match parse_stdout_line("CAPTCHA_SOLVE|manual|https://id.vk.com/captcha?x=1|abc") {
            Msg::Captcha { mode, uri, session } => {
                assert_eq!((mode.as_str(), uri.as_str(), session.as_str()), ("manual", "https://id.vk.com/captcha?x=1", "abc"));
            }
            _ => panic!(),
        }
        assert!(matches!(parse_stdout_line("HASH_CHECK:{\"status\":\"valid\"}"), Msg::HashCheck(_)));
        assert!(matches!(parse_stdout_line("hello"), Msg::Log { .. }));
    }
}
