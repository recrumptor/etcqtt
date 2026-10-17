//! CAPTCHA-помощник.
//!
//! Два слушателя:
//!  * API (127.0.0.1:helper_port) — контракт rpcd/LuCI: GET /api/challenges,
//!    GET /api/challenge/<id>/helper-url, POST /api/challenge/<id>/cancel;
//!  * страница решения (0.0.0.0:solve_port) — доступна по одноразовой capability-ссылке
//!    /c/<cap>/: проксирует страницу VK-капчи (только домены vk.com/vk.ru/ok.ru/okcdn.ru),
//!    внедряет тот же перехватчик `captchaNotRobot.check`, что и Android-клиент, и по
//!    получении success_token отдаёт его ядру.
use crate::{https, logd, logi, logw, util};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const ALLOWED: &[&str] = &["vk.com", "vk.ru", "ok.ru", "okcdn.ru"];
const MAX_CONN: usize = 48;
const MAX_REQ_BODY: usize = 256 * 1024;

pub fn host_allowed(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    !h.is_empty() && ALLOWED.iter().any(|d| h == *d || h.ends_with(&format!(".{}", d)))
}

fn domain_of(h: &str) -> &'static str {
    let h = h.to_ascii_lowercase();
    ALLOWED.iter().find(|d| h == **d || h.ends_with(&format!(".{}", d))).copied().unwrap_or("")
}

/// https-URI капчи → (host, path+query), только allowlist.
pub fn split_uri(u: &str) -> Option<(String, String)> {
    let rest = u.strip_prefix("https://")?;
    let (hostport, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.contains(['@', ':']) || !host_allowed(hostport) {
        return None;
    }
    let path = if path.starts_with('?') { format!("/{}", path) } else { path.to_string() };
    Some((hostport.to_ascii_lowercase(), path))
}

#[derive(Clone, Debug)]
pub struct Challenge {
    pub id: String,
    pub profile_id: String,
    pub mode: String,
    pub uri: String,
    pub state: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub cap: Option<String>,
    pub result: Option<String>,
    pub reason: String,
    cookies: HashMap<String, HashMap<String, String>>,
}

impl Challenge {
    fn closed(&self) -> bool {
        matches!(self.state.as_str(), "solved" | "failed" | "expired" | "cancelled")
    }
    fn open_state(&self) -> bool {
        !self.closed()
    }
}

pub struct Helper {
    st: Mutex<Vec<Challenge>>,
    pub api_port: u16,
    pub solve_port: u16,
    host_override: Mutex<String>,
    conns: AtomicUsize,
}

impl Helper {
    pub fn new(api_port: u16, solve_port: u16) -> Arc<Helper> {
        Arc::new(Helper { st: Mutex::new(Vec::new()), api_port, solve_port, host_override: Mutex::new(String::new()), conns: AtomicUsize::new(0) })
    }

    pub fn set_public_host(&self, h: &str) {
        *self.host_override.lock().unwrap() = h.trim().to_string();
    }

    pub fn new_challenge(&self, profile: &str, mode: &str, uri: &str, ttl: u64) -> Result<String, String> {
        if split_uri(uri).is_none() {
            return Err("redirect_uri вне allowlist VK/OK".into());
        }
        let now = util::now_secs();
        let id = format!("c{}", util::random_hex(4));
        let mut st = self.st.lock().unwrap();
        st.retain(|c| c.open_state() || now.saturating_sub(c.expires_at.max(c.created_at)) < 120);
        st.push(Challenge {
            id: id.clone(),
            profile_id: profile.to_string(),
            mode: mode.to_string(),
            uri: uri.to_string(),
            state: "pending".into(),
            created_at: now,
            expires_at: now + ttl,
            cap: None,
            result: None,
            reason: String::new(),
            cookies: HashMap::new(),
        });
        Ok(id)
    }

    /// Помечает просроченные; вызывается из цикла супервизора.
    pub fn tick(&self) {
        let now = util::now_secs();
        for c in self.st.lock().unwrap().iter_mut() {
            if c.open_state() && now >= c.expires_at {
                c.state = "expired".into();
                c.reason = "timeout".into();
            }
        }
    }

    /// Некэшируемый исход: Some(Ok(token)) / Some(Err(reason)) / None (ещё ждём).
    pub fn outcome(&self, id: &str) -> Option<Result<String, String>> {
        let st = self.st.lock().unwrap();
        let c = st.iter().find(|c| c.id == id)?;
        match c.state.as_str() {
            "solved" => Some(Ok(c.result.clone().unwrap_or_default())),
            "failed" | "expired" | "cancelled" => Some(Err(if c.reason.is_empty() { c.state.clone() } else { c.reason.clone() })),
            _ => None,
        }
    }

    pub fn cancel_all(&self, reason: &str) {
        for c in self.st.lock().unwrap().iter_mut() {
            if c.open_state() {
                c.state = "cancelled".into();
                c.reason = reason.into();
            }
        }
    }

    pub fn cancel(&self, id: &str) -> u16 {
        let mut st = self.st.lock().unwrap();
        match st.iter_mut().find(|c| c.id == id) {
            None => 404,
            Some(c) if c.closed() => 409,
            Some(c) => {
                c.state = "cancelled".into();
                c.reason = "cancelled".into();
                200
            }
        }
    }

    pub fn pending(&self) -> usize {
        self.st.lock().unwrap().iter().filter(|c| c.open_state()).count()
    }

    pub fn snapshot(&self) -> Vec<Value> {
        self.st
            .lock()
            .unwrap()
            .iter()
            .map(|c| json!({"id": c.id, "profile_id": c.profile_id, "mode": c.mode, "state": c.state, "created_at": c.created_at, "expires_at": c.expires_at}))
            .collect()
    }

    fn public_host(&self) -> String {
        let o = self.host_override.lock().unwrap().clone();
        if !o.is_empty() {
            return o;
        }
        lan_ip().unwrap_or_else(|| "192.168.1.1".into())
    }

    fn helper_url(&self, id: &str) -> Option<String> {
        let mut st = self.st.lock().unwrap();
        let c = st.iter_mut().find(|c| c.id == id)?;
        if c.closed() {
            return None;
        }
        let cap = c.cap.get_or_insert_with(|| util::random_hex(16)).clone();
        drop(st);
        Some(format!("http://{}:{}/c/{}/", self.public_host(), self.solve_port, cap))
    }

    fn with_cap<R>(&self, cap: &str, f: impl FnOnce(&mut Challenge) -> R) -> Option<R> {
        let mut st = self.st.lock().unwrap();
        st.iter_mut().find(|c| c.cap.as_deref() == Some(cap) && c.open_state()).map(f)
    }
}

/// IPv4 LAN-интерфейса: br-lan, иначе первый частный адрес.
pub fn lan_ip() -> Option<String> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }
    let mut best: Option<String> = None;
    let mut p = ifap;
    while !p.is_null() {
        let ifa = unsafe { &*p };
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET {
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().to_string();
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let o = sin.sin_addr.s_addr.to_ne_bytes();
            let ip = std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            if name == "lo" || name.starts_with("csqtt") {
                p = ifa.ifa_next;
                continue;
            }
            if name == "br-lan" {
                best = Some(ip.to_string());
                break;
            }
            if best.is_none() && ip.is_private() {
                best = Some(ip.to_string());
            }
        }
        p = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    best
}

// ---------------------------------------------------------------- HTTP-сервер

struct Req {
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_req(s: &mut TcpStream) -> Option<Req> {
    s.set_read_timeout(Some(Duration::from_secs(15))).ok()?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 32 * 1024 {
            return None;
        }
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut rl = lines.next()?.split_whitespace();
    let method = rl.next()?.to_string();
    let target = rl.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let cl: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if cl > MAX_REQ_BODY {
        return None;
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < cl {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(cl);
    Some(Req { method, path, query, headers, body })
}

fn respond(s: &mut TcpStream, status: u16, headers: &[(String, String)], body: &[u8]) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let mut h = format!("HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n", status, reason, body.len());
    for (k, v) in headers {
        h.push_str(&format!("{}: {}\r\n", k, v));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn json_resp(s: &mut TcpStream, status: u16, v: Value) {
    respond(s, status, &[("Content-Type".into(), "application/json".into())], v.to_string().as_bytes());
}

fn text_resp(s: &mut TcpStream, status: u16, t: &str) {
    respond(s, status, &[("Content-Type".into(), "text/plain; charset=utf-8".into())], t.as_bytes());
}

fn id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn start(h: &Arc<Helper>, bind_api: &str, bind_solve: &str) -> Result<(), String> {
    let api = TcpListener::bind((bind_api, h.api_port)).map_err(|e| format!("helper API {}:{}: {}", bind_api, h.api_port, e))?;
    let solve = TcpListener::bind((bind_solve, h.solve_port)).map_err(|e| format!("helper solve {}:{}: {}", bind_solve, h.solve_port, e))?;
    for (listener, is_api) in [(api, true), (solve, false)] {
        let h = h.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                if h.conns.load(Ordering::Relaxed) >= MAX_CONN {
                    continue;
                }
                h.conns.fetch_add(1, Ordering::Relaxed);
                let h2 = h.clone();
                std::thread::spawn(move || {
                    let mut conn = conn;
                    if let Some(req) = read_req(&mut conn) {
                        if is_api { handle_api(&h2, &mut conn, req) } else { handle_solve(&h2, &mut conn, req) }
                    }
                    h2.conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }
    Ok(())
}

// ------------------------------------------------------------------- API

fn handle_api(h: &Helper, s: &mut TcpStream, r: Req) {
    let parts: Vec<&str> = r.path.trim_matches('/').split('/').collect();
    match (r.method.as_str(), parts.as_slice()) {
        ("GET", ["api", "challenges"]) => json_resp(s, 200, json!({"challenges": h.snapshot(), "pending": h.pending()})),
        ("GET", ["api", "challenge", id, "helper-url"]) if id_ok(id) => match h.helper_url(id) {
            Some(url) => json_resp(s, 200, json!({"id": id, "url": url})),
            None => json_resp(s, 404, json!({"error": "not found"})),
        },
        ("POST", ["api", "challenge", id, "cancel"]) if id_ok(id) => match h.cancel(id) {
            200 => {
                logi!("[CAPTCHA] challenge {} отменён из панели", id);
                json_resp(s, 200, json!({"cancelled": true}))
            }
            c => json_resp(s, c, json!({"cancelled": false})),
        },
        _ => json_resp(s, 404, json!({"error": "unknown endpoint"})),
    }
}

// ------------------------------------------------------- страница решения + прокси

const PAGE_DONE: &str = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><body style='font:18px sans-serif;padding:2em;text-align:center'>Готово — можно закрыть страницу.</body>";

fn handle_solve(h: &Helper, s: &mut TcpStream, r: Req) {
    let rest = match r.path.strip_prefix("/c/") {
        Some(x) => x,
        None => return text_resp(s, 404, "not found"),
    };
    let (cap, sub) = match rest.split_once('/') {
        Some((c, sub)) => (c.to_string(), format!("/{}", sub)),
        None => (rest.to_string(), "/".to_string()),
    };
    if cap.len() != 32 || !cap.bytes().all(|b| b.is_ascii_hexdigit()) {
        return text_resp(s, 404, "not found");
    }
    // сначала убеждаемся, что capability жива
    let Some(uri) = h.with_cap(&cap, |c| c.uri.clone()) else {
        return text_resp(s, 404, "Ссылка недействительна или просрочена.");
    };
    let pfx = format!("/c/{}", cap);
    if sub == "/" {
        h.with_cap(&cap, |c| {
            if c.state == "pending" {
                c.state = "opened".into();
            }
        });
        let Some((host, path)) = split_uri(&uri) else { return text_resp(s, 400, "bad uri") };
        return respond(s, 302, &[("Location".into(), format!("{}/p/{}{}", pfx, host, path))], b"");
    }
    if sub == "/status" {
        let st = h.with_cap(&cap, |c| c.state.clone()).unwrap_or_default();
        return json_resp(s, 200, json!({"state": st}));
    }
    if sub == "/result" && r.method == "POST" {
        let token = String::from_utf8_lossy(&r.body).trim().to_string();
        if token.is_empty() || token.len() > 4096 || token.contains(['\r', '\n', '|']) {
            return text_resp(s, 400, "bad token");
        }
        h.with_cap(&cap, |c| {
            c.result = Some(token);
            c.state = "solved".into();
        });
        logi!("[CAPTCHA] получен success_token из браузера");
        return respond(s, 200, &[("Content-Type".into(), "text/html; charset=utf-8".into())], PAGE_DONE.as_bytes());
    }
    if let Some(p) = sub.strip_prefix("/p/") {
        let (host, path) = match p.split_once('/') {
            Some((hst, rest)) => (hst.to_ascii_lowercase(), format!("/{}", rest)),
            None => (p.to_ascii_lowercase(), "/".to_string()),
        };
        if !host_allowed(&host) {
            return text_resp(s, 403, "host not allowed");
        }
        return proxy(h, s, &cap, &pfx, &host, &path, &r, &uri);
    }
    text_resp(s, 404, "not found")
}

fn proxy(h: &Helper, s: &mut TcpStream, cap: &str, pfx: &str, host: &str, path: &str, r: &Req, entry_uri: &str) {
    if !matches!(r.method.as_str(), "GET" | "POST" | "HEAD") {
        return text_resp(s, 405, "method not allowed");
    }
    let path_q = if r.query.is_empty() { path.to_string() } else { format!("{}?{}", path, r.query) };
    let origin = split_uri(entry_uri).map(|(hh, _)| format!("https://{}", hh)).unwrap_or_else(|| format!("https://{}", host));
    let dom = domain_of(host);
    let cookie_hdr = h
        .with_cap(cap, |c| c.cookies.get(dom).map(|m| m.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ")))
        .flatten()
        .unwrap_or_default();

    let mut hdrs: Vec<(String, String)> = Vec::new();
    for k in ["user-agent", "accept", "accept-language", "content-type"] {
        if let Some(v) = r.headers.get(k) {
            hdrs.push((k.to_string(), v.clone()));
        }
    }
    hdrs.push(("Origin".into(), origin.clone()));
    hdrs.push(("Referer".into(), format!("{}/", origin)));
    if !cookie_hdr.is_empty() {
        hdrs.push(("Cookie".into(), cookie_hdr));
    }
    logd!("[CAPTCHA] proxy {} {}{}", r.method, host, path);
    let resp = match https::request(&r.method, host, &path_q, &hdrs, &r.body) {
        Ok(x) => x,
        Err(e) => {
            logw!("[CAPTCHA] proxy {}: {}", host, e);
            return text_resp(s, 502, &format!("Ошибка обращения к VK: {}", e));
        }
    };
    // Set-Cookie → jar
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            let first = v.split(';').next().unwrap_or("");
            if let Some((n, val)) = first.split_once('=') {
                let (n, val) = (n.trim().to_string(), val.trim().to_string());
                h.with_cap(cap, |c| {
                    let jar = c.cookies.entry(dom.to_string()).or_default();
                    if val.is_empty() { jar.remove(&n); } else { jar.insert(n, val); }
                });
            }
        }
    }
    let ctype = resp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default();
    let ctl = ctype.to_ascii_lowercase();
    let textual = ["text/html", "javascript", "json", "text/css", "text/plain", "xml"].iter().any(|t| ctl.contains(t));
    let mut out_headers: Vec<(String, String)> = Vec::new();
    for (k, v) in &resp.headers {
        let kl = k.to_ascii_lowercase();
        match kl.as_str() {
            "content-length" | "content-encoding" | "transfer-encoding" | "connection" | "set-cookie" | "content-security-policy"
            | "content-security-policy-report-only" | "x-frame-options" | "strict-transport-security" | "cache-control"
            | "referrer-policy" | "report-to" | "nel" => {}
            "location" => out_headers.push((k.clone(), rewrite_location(v, pfx, host))),
            _ => out_headers.push((k.clone(), v.clone())),
        }
    }
    let mut body = resp.body;
    if textual {
        let text = String::from_utf8_lossy(&body).to_string();
        let mut t = rewrite_text(&text, pfx);
        if ctl.contains("text/html") {
            t = rewrite_html_attrs(&t, &format!("{}/p/{}", pfx, host));
            t = inject_interceptor(&t, pfx);
        }
        body = t.into_bytes();
    }
    respond(s, resp.status, &out_headers, if r.method == "HEAD" { b"" } else { &body });
}

fn rewrite_location(loc: &str, pfx: &str, cur_host: &str) -> String {
    if let Some(rest) = loc.strip_prefix("https://").or_else(|| loc.strip_prefix("http://")) {
        let (hp, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if host_allowed(hp) {
            return format!("{}/p/{}{}", pfx, hp.to_ascii_lowercase(), path);
        }
        return loc.to_string();
    }
    if loc.starts_with('/') && !loc.starts_with("//") {
        return format!("{}/p/{}{}", pfx, cur_host, loc);
    }
    loc.to_string()
}

/// Подмена абсолютных ссылок на allowlist-хосты внутри текстовых ответов.
pub fn rewrite_text(s: &str, pfx: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 256);
    let mut i = 0;
    let escaped_pfx = pfx.replace('/', "\\/");
    while i < b.len() {
        let rest = &s[i..];
        // варианты: https://h, http://h, https:\/\/h, //h, \/\/h
        let (skip, esc, ok_prefix) = if rest.starts_with("https://") { (8, false, true) }
            else if rest.starts_with("http://") { (7, false, true) }
            else if rest.starts_with("https:\\/\\/") { (10, true, true) }
            else if rest.starts_with("http:\\/\\/") { (9, true, true) }
            else if rest.starts_with("//") { (2, false, i > 0 && matches!(b[i - 1], b'"' | b'\'' | b'(' | b'=' | b' ' | b',')) }
            else if rest.starts_with("\\/\\/") { (4, true, i > 0 && matches!(b[i - 1], b'"' | b'\'' | b'(' | b'=' | b' ' | b',')) }
            else { (0, false, false) };
        if skip > 0 && ok_prefix {
            let hs = &rest[skip..];
            let end = hs.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).unwrap_or(hs.len());
            let host = &hs[..end];
            if host_allowed(host) {
                if esc {
                    out.push_str(&format!("{}\\/p\\/{}", escaped_pfx, host.to_ascii_lowercase()));
                } else {
                    out.push_str(&format!("{}/p/{}", pfx, host.to_ascii_lowercase()));
                }
                i += skip + end;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// src="/x" href="/x" action="/x" → префикс текущего хоста (корневые относительные пути).
pub fn rewrite_html_attrs(s: &str, host_pfx: &str) -> String {
    let mut out = String::with_capacity(s.len() + 128);
    let mut rest = s;
    'outer: while !rest.is_empty() {
        for attr in ["src=", "href=", "action="] {
            if rest.len() > attr.len() + 2 && rest[..attr.len()].eq_ignore_ascii_case(attr) {
                let q = rest.as_bytes()[attr.len()];
                if (q == b'"' || q == b'\'') && rest.as_bytes()[attr.len() + 1] == b'/' && rest.as_bytes()[attr.len() + 2] != b'/' {
                    out.push_str(&rest[..attr.len() + 1]);
                    out.push_str(host_pfx);
                    rest = &rest[attr.len() + 1..];
                    continue 'outer;
                }
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

const INTERCEPTOR: &str = r#"<script>(function(){var P='__PFX__',OK=/(^|\.)(vk\.com|vk\.ru|ok\.ru|okcdn\.ru)$/i;
var cur=(location.pathname.match(/\/p\/([^\/]+)/)||[])[1]||'';
function fix(u){try{if(typeof u!=='string')return u;if(u.indexOf(P+'/')===0)return u;
var m=u.match(/^(?:https?:)?\/\/([^\/?#:]+)(?::\d+)?([\s\S]*)$/i);
if(m){return OK.test(m[1])?P+'/p/'+m[1].toLowerCase()+(m[2]||'/'):u}
if(u.charAt(0)==='/'&&u.charAt(1)!=='/'&&cur)return P+'/p/'+cur+u;return u}catch(e){return u}}
var sent=false;
function send(t){if(sent)return;sent=true;fetch(P+'/result',{method:'POST',headers:{'Content-Type':'text/plain'},body:t}).then(function(){document.body.innerHTML='<div style="font:20px sans-serif;padding:2em;text-align:center">Готово. Можно закрыть страницу.</div>'}).catch(function(){sent=false})}
function scan(d){if(d&&d.response&&d.response.success_token)send(d.response.success_token)}
var of=window.fetch;
window.fetch=function(a,b){var orig=(typeof a==='string')?a:(a&&a.url)||'';if(typeof a==='string')a=fix(a);else if(a&&a.url){try{a=new Request(fix(a.url),a)}catch(e){}}
var p=of.call(this,a,b);if(String(orig).indexOf('captchaNotRobot.check')>=0){p.then(function(r){try{r.clone().json().then(scan).catch(function(){})}catch(e){}}).catch(function(){})}return p};
var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){this.__u=u;arguments[1]=fix(u);return xo.apply(this,arguments)};
var xs=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(){var x=this;if(String(x.__u||'').indexOf('captchaNotRobot.check')>=0)x.addEventListener('load',function(){try{scan(JSON.parse(x.responseText))}catch(e){}});return xs.apply(this,arguments)};
function patch(pr,n){var d=Object.getOwnPropertyDescriptor(pr,n);if(!d||!d.set)return;Object.defineProperty(pr,n,{get:d.get,set:function(v){d.set.call(this,fix(v))},configurable:true})}
patch(HTMLScriptElement.prototype,'src');patch(HTMLLinkElement.prototype,'href');patch(HTMLImageElement.prototype,'src');patch(HTMLIFrameElement.prototype,'src');
var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(typeof v==='string'&&/^(src|href|action)$/i.test(n))v=fix(v);return sa.call(this,n,v)};
})();</script>"#;

pub fn inject_interceptor(html: &str, pfx: &str) -> String {
    let script = INTERCEPTOR.replace("__PFX__", pfx);
    let lower = html.to_ascii_lowercase();
    if let Some(p) = lower.find("<head") {
        if let Some(e) = lower[p..].find('>') {
            let at = p + e + 1;
            return format!("{}{}{}", &html[..at], script, &html[at..]);
        }
    }
    format!("{}{}", script, html)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        write!(s, "{} {} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", method, path, body.len(), body).unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        let st: u16 = buf.split_whitespace().nth(1).unwrap().parse().unwrap();
        let b = buf.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default();
        (st, b)
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn allowlist() {
        assert!(host_allowed("id.vk.com"));
        assert!(host_allowed("api.vk.ru"));
        assert!(!host_allowed("evil-vk.com"));
        assert!(!host_allowed("vk.com.evil.net"));
        assert!(split_uri("https://id.vk.com/captcha?session_token=abc").is_some());
        assert!(split_uri("http://id.vk.com/captcha").is_none());
        assert!(split_uri("https://id.vk.com@evil.net/").is_none());
        assert!(split_uri("https://evil.net/").is_none());
    }

    #[test]
    fn rewriting() {
        let t = rewrite_text("a=\"https://api.vk.ru/method/x\" b='//st.vk.com/a.js' c=https://evil.net/z d=\"https:\\/\\/id.vk.com\\/x\"", "/c/AA");
        assert!(t.contains("\"/c/AA/p/api.vk.ru/method/x\""), "{}", t);
        assert!(t.contains("'/c/AA/p/st.vk.com/a.js'"), "{}", t);
        assert!(t.contains("https://evil.net/z"));
        assert!(t.contains("\"\\/c\\/AA\\/p\\/id.vk.com\\/x\""), "{}", t);
        let h = rewrite_html_attrs("<script src=\"/js/a.js\"></script><a href='//x'>", "/c/AA/p/id.vk.com");
        assert!(h.contains("src=\"/c/AA/p/id.vk.com/js/a.js\""), "{}", h);
        assert!(h.contains("href='//x'"));
        assert!(inject_interceptor("<html><head><title>x</title>", "/c/AA").contains("captchaNotRobot.check"));
    }

    #[test]
    fn api_and_solve_flow() {
        let (ap, sp) = (free_port(), free_port());
        let h = Helper::new(ap, sp);
        h.set_public_host("192.0.2.1");
        start(&h, "127.0.0.1", "127.0.0.1").unwrap();
        assert!(h.new_challenge("p1", "manual", "https://evil.net/x", 60).is_err());
        let id = h.new_challenge("p1", "manual", "https://id.vk.com/captcha?session_token=abc", 60).unwrap();
        assert_eq!(h.pending(), 1);
        let (st, body) = http(ap, "GET", "/api/challenges", "");
        assert_eq!(st, 200);
        assert!(body.contains(&id));
        let (st, body) = http(ap, "GET", &format!("/api/challenge/{}/helper-url", id), "");
        assert_eq!(st, 200);
        let v: Value = serde_json::from_str(&body).unwrap();
        let url = v["url"].as_str().unwrap().to_string();
        assert!(url.starts_with("http://192.0.2.1:"));
        let cap = url.trim_end_matches('/').rsplit('/').next().unwrap().to_string();
        // страница → редирект на прокси
        let (st, _) = http(sp, "GET", &format!("/c/{}/", cap), "");
        assert_eq!(st, 302);
        // чужая/кривая capability
        assert_eq!(http(sp, "GET", "/c/00000000000000000000000000000000/", "").0, 404);
        assert_eq!(http(sp, "GET", &format!("/c/{}/p/evil.net/x", cap), "").0, 403);
        // результат
        assert_eq!(http(sp, "POST", &format!("/c/{}/result", cap), "bad|token").0, 400);
        assert_eq!(http(sp, "POST", &format!("/c/{}/result", cap), "TOKEN123").0, 200);
        assert_eq!(h.outcome(&id), Some(Ok("TOKEN123".to_string())));
        // повторно: закрыт
        assert_eq!(http(ap, "POST", &format!("/api/challenge/{}/cancel", id), "").0, 409);
        assert_eq!(http(ap, "POST", "/api/challenge/nope/cancel", "").0, 404);
        // отмена
        let id2 = h.new_challenge("p1", "manual", "https://id.vk.com/c?s=1", 60).unwrap();
        assert_eq!(http(ap, "POST", &format!("/api/challenge/{}/cancel", id2), "").0, 200);
        assert_eq!(h.outcome(&id2), Some(Err("cancelled".to_string())));
    }

    #[test]
    fn expiry() {
        let h = Helper::new(1, 2);
        let id = h.new_challenge("p", "manual", "https://id.vk.com/c?s=1", 0).unwrap();
        h.tick();
        assert_eq!(h.outcome(&id), Some(Err("timeout".to_string())));
    }
}
