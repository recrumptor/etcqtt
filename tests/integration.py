#!/usr/bin/env python3
"""Сквозной тест службы `csqtt run` с поддельным ядром. Нужен root и /dev/net/tun."""
import json, os, signal, subprocess, sys, tempfile, time, urllib.request, shutil

BIN = os.environ.get("CSQTT_BIN", os.path.join(os.path.dirname(__file__), "..", "wrapper", "target", "release", "csqtt"))
HERE = os.path.dirname(os.path.abspath(__file__))
d = tempfile.mkdtemp(prefix="csqtt-it-")
cfgp, stp, logp, flog = f"{d}/csqtt", f"{d}/run/status.json", f"{d}/csqtt.log", f"{d}/fake.log"
os.makedirs(f"{d}/run")
PORT = 18443

def write_cfg(extra_main="", profiles=None):
    profiles = profiles if profiles is not None else [("p1", 10, "good1.example:46000"), ("p2", 20, "good2.example:46000")]
    t = f"""config csqtt 'main'
\toption enabled '1'
\toption ifname 'csqtt_it0'
\toption selection_mode 'priority'
\toption active_profile ''
\toption failover '1'
\toption failback '0'
\toption cooldown '60'
\toption reconnect_delay '1'
\toption tun_mtu '1280'
\toption tun_address '10.255.88.1/30'
\toption helper_bind '127.0.0.1'
\toption log_level 'debug'
\toption vk 'hashA,hashB'
\toption device_id 'dev-it-1'
\toption workers '6'
{extra_main}
"""
    for pid, prio, peer in profiles:
        t += f"\nconfig server '{pid}'\n\toption name 'Name {pid}'\n\toption enabled '1'\n\toption priority '{prio}'\n\toption peer '{peer}'\n\toption password 'pw-{pid}'\n"
    open(cfgp, "w").write(t)

def status():
    try:
        return json.load(open(stp))
    except Exception:
        return None

def wait(cond, what, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = status()
        if s is not None and cond(s):
            return s
        time.sleep(0.2)
    print("TIMEOUT:", what, json.dumps(status(), ensure_ascii=False)[:800]); dump(); sys.exit(1)

def dump():
    for f in (logp, flog):
        if os.path.exists(f):
            print(f"--- {f}"); print(open(f).read()[-3000:])

def api(path, method="GET"):
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method)
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def ok(msg): print("OK  ", msg)
def check(cond, msg):
    if not cond:
        print("FAIL", msg); dump(); sys.exit(1)
    ok(msg)

env = dict(os.environ, CSQTT_CORE=f"{HERE}/fake_core.py", FAKE_LOG=flog, TUN_NAME="csqtt_it0")
proc = None
def start():
    global proc
    proc = subprocess.Popen([BIN, "run", "--config", cfgp, "--status", stp, "--log", logp, "--helper-port", str(PORT)],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

try:
    # ---- 1. обычное подключение по приоритету
    write_cfg(); start()
    s = wait(lambda s: s.get("connected"), "подключение p1")
    check(s["active_profile"] == "p1", "выбран профиль с наименьшим priority (p1)")
    check(s["tunnel"]["present"] and s["connectivity"]["tun_present"], "TUN csqtt_it0 создан")
    check(open("/sys/class/net/csqtt_it0/mtu").read().strip() == "1280", "MTU 1280 применён")
    wait(lambda s: s["tx_bytes"] > 0, "счётчики")
    check(s["workers"]["configured"] == 6, "workers.configured из конфига")
    check(any(p["id"] == "p1" and p["state"] == "active" for p in s["profiles"]), "p1 в состоянии active")
    check("got tun fd, ifname_ok=True" in open(flog).read(), "ядро получило дескриптор TUN")
    check("dev=dev-it-1" in open(flog).read() and "vk=hashA,hashB" in open(flog).read(), "общие настройки переданы ядру")
    r = subprocess.run([BIN, "status", "--status-path", stp], capture_output=True, text=True)
    check(r.returncode == 0, f"csqtt status → 0 (подключён): {r.stdout.strip()[:60]}")

    # ---- 2. failover: p1 помечаем «плохим» (ядро падает с auth), p2 рабочий
    write_cfg(profiles=[("p1", 10, "bad1.example:46000"), ("p2", 20, "good2.example:46000")])
    proc.send_signal(signal.SIGHUP)
    s = wait(lambda s: s.get("connected") and s["active_profile"] == "p2", "failover на p2", 25)
    check(any(h["reason"] == "auth" and h["to"] == "p2" for h in s["switch_history"]) or any(h["to"] == "p2" for h in s["switch_history"]), "switch_history содержит переход на p2")
    states = {p["id"]: p["state"] for p in s["profiles"]}
    check(states["p1"] in ("cooldown", "auth_failed"), f"p1 после сбоя: {states['p1']}")
    check(s["reconnects"] >= 1, "счётчик переподключений растёт")

    # ---- 3. ручной выбор через profile use + reload
    write_cfg(profiles=[("p1", 10, "good1.example:46000"), ("p2", 20, "good2.example:46000")])
    r = subprocess.run([BIN, "profile", "use", "p2", "--config", cfgp], capture_output=True, text=True)
    check(r.returncode == 0, "profile use p2")
    proc.send_signal(signal.SIGHUP)
    time.sleep(1.5)
    s = wait(lambda s: s.get("connected") and s["active_profile"] == "p2" and s["selection_mode"] == "manual", "manual p2")
    ok("режим manual, активен p2")

    # ---- 4. CAPTCHA: ядро просит ручное решение, решаем через helper
    write_cfg(profiles=[("p1", 10, "captcha1.example:46000")])
    proc.send_signal(signal.SIGHUP)
    s = wait(lambda s: s.get("captcha_pending", 0) >= 1, "challenge создан", 25)
    ch = [c for c in s["captcha_challenges"] if c["state"] in ("pending", "opened")][0]
    check(ch["profile_id"] == "p1" and ch["mode"] == "manual", "challenge в status.json (profile_id/mode)")
    check(any(p["id"] == "p1" and p["state"] == "captcha_required" for p in s["profiles"]), "профиль в captcha_required")
    st, body = api(f"/api/challenge/{ch['id']}/helper-url")
    check(st == 200 and "/c/" in body["url"], f"helper-url выдан: {body['url'][:40]}…")
    cap = body["url"].rstrip("/").rsplit("/", 1)[1]
    solve_port = PORT + 1
    # страница решения редиректит на прокси VK
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", solve_port, timeout=5); c.request("GET", f"/c/{cap}/")
    resp = c.getresponse(); loc = resp.getheader("Location")
    check(resp.status == 302 and "/p/id.vk.com/captcha?session_token=tok123" in loc, f"страница → прокси VK: {loc}")
    # «браузер» присылает success_token
    c = http.client.HTTPConnection("127.0.0.1", solve_port, timeout=5)
    c.request("POST", f"/c/{cap}/result", body="SUCCESS_TOKEN_XYZ"); resp = c.getresponse()
    check(resp.status == 200, "success_token принят")
    s = wait(lambda s: s.get("connected") and s["active_profile"] == "p1", "подключение после капчи", 25)
    check("captcha_result=['SUCCESS_TOKEN_XYZ']" in open(flog).read(), "ядро получило CAPTCHA_RESULT|<token>")
    check(s["captcha_pending"] == 0, "captcha_pending сброшен")

    # ---- 5. check вызовов CLI
    r = subprocess.run([BIN, "doctor", "--json", "--config", cfgp, "--status-path", stp], capture_output=True, text=True, env=env)
    rep = json.loads(r.stdout)
    check(any(c["name"] == "config" and c["status"] == "ok" for c in rep["checks"]), f"doctor --json: {rep['summary']}")
    vf = f"{d}/vk.tmp"; open(vf, "w").write("good1,badX")
    r = subprocess.run([BIN, "--validate-vk-hashes", "--vk-file", vf, "--config", cfgp], capture_output=True, text=True, env=env)
    lines = [l for l in r.stdout.splitlines() if l.startswith("HASH_CHECK:")]
    check(len(lines) == 2 and '"valid"' in lines[0] and '"invalid"' in lines[1], "--validate-vk-hashes проксирует вывод ядра")
    r = subprocess.run([BIN, "profile", "export", "p1", "--config", cfgp], capture_output=True, text=True)
    check(r.stdout.startswith("csqtt://connect?v=2&host=captcha1.example&peer=46000"), "profile export")

    # ---- 6. корректная остановка
    proc.send_signal(signal.SIGTERM)
    check(proc.wait(timeout=15) == 0, "SIGTERM → код 0")
    check(not os.path.exists(stp), "status.json удалён при остановке")
    check("stopped cleanly" in open(flog).read(), "ядру отправлен STOP, остановлено штатно")
    check(not os.path.exists("/sys/class/net/csqtt_it0"), "TUN исчез после остановки")
    r = subprocess.run([BIN, "status", "--status-path", stp], capture_output=True, text=True)
    check(r.returncode == 2, "csqtt status → 2 (не запущена)")
    print("\nВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")
finally:
    if proc and proc.poll() is None:
        proc.kill()
    shutil.rmtree(d, ignore_errors=True)
