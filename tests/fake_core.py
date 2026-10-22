#!/usr/bin/env python3
"""Поддельное ядро CSQTT с тем же внешним контрактом, что у upstream `client`:
--tun-uds (абстрактный сокет, SCM_RIGHTS, ack=1), события __CSQTT_EVENT__, CAPTCHA_SOLVE,
команды STOP/CAPTCHA_RESULT в stdin. Поведение выбирается по значению --peer."""
import os, socket, sys, threading, time, json, array

args = sys.argv[1:]
def opt(name, default=""):
    return args[args.index(name) + 1] if name in args else default

LOG = os.environ.get("FAKE_LOG", "/dev/null")
def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{os.getpid()} {msg}\n")

def ev(kind, **payload):
    sys.stdout.write(f"__CSQTT_EVENT__|{kind}|{json.dumps(payload)}\n"); sys.stdout.flush()

if "--validate-vk-hashes" in args:
    for i, h in enumerate(opt("--vk").split(",")):
        st = "valid" if not h.startswith("bad") else "invalid"
        print("HASH_CHECK:" + json.dumps({"hash": h, "status": st, "message": "x"}), flush=True)
    sys.exit(0)

peer, uds, vk = opt("--peer"), opt("--tun-uds"), opt("--vk")
MODE = os.environ.get("FAKE_MODE", "legacy")   # modern = ядро 2.5.0+: пароль только в окружении
pw_env = os.environ.get("CSQTT_PASSWORD", "")
pw = pw_env or opt("--password")
log(f"start peer={peer} captcha_mode={opt('--captcha-mode')} vk={vk} dev={opt('--device-id')} n={opt('-n')} pw={pw} pwenv={1 if pw_env else 0} devarg={1 if '--device-id' in args else 0} obfs={opt('--obfs')} srtp={opt('--srtp-mode')}")
if MODE == "modern" and ("--password" in args or "--device-id" in args):
    # как clap в ядре 2.5.0: таких аргументов больше нет
    sys.stderr.write("error: unexpected argument '--password' found\n"); sys.exit(2)
if MODE == "modern" and not pw_env:
    sys.stderr.write("[ФАТАЛ] [КЛИЕНТ] Нужен пароль в переменной CSQTT_PASSWORD\n"); sys.exit(1)
stop = threading.Event()
captcha_result = []
bootstrap = []

def reader():
    for line in sys.stdin:
        line = line.strip()
        log(f"stdin {line[:60]}")
        if line == "STOP":
            stop.set(); return
        if line.startswith("CAPTCHA_RESULT|"):
            captcha_result.append(line.split("|", 1)[1])
        if line.startswith("VK_JS_BOOTSTRAP:"):
            bootstrap.append(line)
    stop.set()
threading.Thread(target=reader, daemon=True).start()

if "bad" in peer:
    ev("ERROR", code="E_AUTH", message="authentication failed", fatal=True)
    sys.exit(1)

srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind("\0" + uds); srv.listen(1); srv.settimeout(10)
conn, _ = srv.accept()
msg, anc, flags, addr = conn.recvmsg(1, socket.CMSG_LEN(array.array("i").itemsize))
fds = array.array("i")
for lvl, typ, data in anc:
    if lvl == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
        fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
assert len(fds) == 1, "fd не получен"
tunfd = fds[0]
conn.send(b"\x01")
log(f"got tun fd, ifname_ok={os.path.exists('/sys/class/net/' + os.environ.get('TUN_NAME','csqtt_it0'))}")

if "captcha" in peer:
    sys.stdout.write(f"CAPTCHA_SOLVE|manual|https://id.vk.com/captcha?session_token=tok123|tok123\n"); sys.stdout.flush()
    t0 = time.time()
    while not captcha_result and time.time() - t0 < 30 and not stop.is_set():
        time.sleep(0.1)
    log(f"captcha_result={captcha_result}")
    if not captcha_result or captcha_result[0].startswith("error:"):
        ev("ERROR", code="E_CAPTCHA", message="captcha failed", fatal=True); sys.exit(1)

# как настоящее ядро: сервер выдаёт клиенту адрес туннеля (TUNCONF) до начала передачи данных
ev("CONFIG", config="TUNCONF:10.255.88.9:1.1.1.1")
if MODE == "modern":
    ev("WORKERS", workers=10)   # ядро 2.5.0 само округляет число воркеров до групп по 10
ev("READY", worker=1)
if "tunlost" in peer:
    mark = os.environ.get("FAKE_MARK", "/tmp/fake_tunlost.mark")
    if not os.path.exists(mark):
        open(mark, "w").close()
        time.sleep(1.0)
        ev("TUN_LOST"); log("tun lost -> exit 3"); sys.exit(3)
sent = 0
while not stop.is_set():
    sent += 1000
    ev("STATS", active=1, bytes_up=sent, bytes_down=sent * 2)
    time.sleep(0.5)
ev("STOPPED"); log("stopped cleanly")
