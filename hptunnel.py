#!/usr/bin/env python3
"""HomePi Tunnel - share this Home Pi's console over a free Cloudflare
quick tunnel. No Cloudflare account, no keys, nothing secret in the repo.

Run it on the Pi (from the App Store or: python3 hptunnel.py). It shows a
https://....trycloudflare.com URL and a 6-digit PIN on the Pi's own screen.
Open the URL anywhere, type the PIN, and you see the Pi's console and can
send keys. q on the Pi kills the tunnel and every session.

Safety: the web side is localhost-only; the tunnel is the only way in;
the PIN is random every run, valid 10 minutes, 5 tries then a 5-minute
lockout; sessions are per-boot HMAC cookies; no password or token is ever
stored or printed anywhere but the Pi's own screen.

Console reading and key injection reuse Home Pi's hpremote (same machine,
/usr/bin/hpremote). Falls back to a built-in reader/injector when hpremote
is not installed, so the app also works on plain Raspberry Pi OS.
"""
import hashlib, hmac, http.server, json, os, re, secrets, shutil, socketserver
import subprocess, sys, threading, time, urllib.request

VERSION = "1.0.0"
CLOUDFLARED_VERSION = "2026.10.3"
CLOUDFLARED_URL = "https://github.com/cloudflare/cloudflared/releases/download/%s/cloudflared-linux-arm64" % CLOUDFLARED_VERSION
CLOUDFLARED_SHA256 = "89297ebfb9e8c99c0dc013a1140601453cf3798d8306c5591651f4a3f5210be8"
APP_DIR = os.path.expanduser("~/.local/share/homepi-tunnel")
CLOUDFLARED = os.environ.get("HPTUNNEL_CLOUDFLARED") or os.path.join(APP_DIR, "cloudflared")
PORT = int(os.environ.get("HPTUNNEL_PORT", "18765"))
PIN_TTL = 600
PIN_TRIES = 5
LOCKOUT = 300
LOG = os.environ.get("HPTUNNEL_LOG", "/tmp/hptunnel.log")

DEMO = os.environ.get("HPTUNNEL_DEMO") == "1"

SECRET = secrets.token_bytes(32)

# --- hpremote reuse -------------------------------------------------------

_hp = None
def load_hpremote():
    global _hp
    if _hp is not None:
        return _hp or None
    for p in ("/usr/bin", os.path.dirname(os.path.abspath(__file__))):
        if p not in sys.path:
            sys.path.insert(0, p)
    try:
        import hpremote
        _hp = hpremote
    except Exception:
        _hp = False
    return _hp or None


def read_console_text():
    hp = load_hpremote()
    if hp:
        try:
            data = hp.read_console()
            rows, cols, (cx, cy), lines = hp.parse_vcsa(data)
            return "\n".join(lines)
        except Exception:
            pass
    # fallback: read the vcsa device directly, no attributes
    try:
        with open("/dev/vcsa", "rb") as f:
            data = f.read()
        rows, cols = data[0], data[1]
        out = []
        for r in range(rows):
            line = data[4 + r * cols * 2: 4 + (r + 1) * cols * 2: 2]
            out.append(line.decode("utf-8", "replace").rstrip())
        return "\n".join(out)
    except Exception as e:
        return "(console not readable: %s)" % e


NAMED_KEYS = {"ENTER": 343, "ESC": 27, "TAB": 9, "BACKSPACE": 263,
              "UP": 259, "DOWN": 258, "LEFT": 260, "RIGHT": 261,
              "DEL": 330, "HOME": 262, "END": 358, "PGUP": 339, "PGDN": 338}


def inject_codes(codes):
    """Inject a list of curses-style key codes. Returns (ok, backend)."""
    hp = load_hpremote()
    if not hp:
        return False, "hpremote not installed"
    inj, backend = hp.open_injector(watch=False)
    if inj is None:
        return False, "no injection backend (view-only)"
    try:
        for code in codes:
            events = hp.map_key(code)
            if events:
                inj.inject(events)
        return True, backend
    finally:
        try:
            inj.close()
        except Exception:
            pass


def inject_payload(body):
    """Body is 'K:NAME' for a named key, or literal text to type."""
    if body.startswith("K:"):
        name = body[2:].strip().upper()
        if name not in NAMED_KEYS:
            return False, "unknown key"
        return inject_codes([NAMED_KEYS[name]])
    codes = []
    for ch in body:
        if ch == "\n" or ch == "\r":
            codes.append(343)
        elif ch == "\t":
            codes.append(9)
        elif ord(ch) < 256:
            codes.append(ord(ch))
    if not codes:
        return False, "empty"
    return inject_codes(codes)


# --- PIN + sessions -------------------------------------------------------

class Gate:
    def __init__(self, pin=None):
        self.pin = pin or "%06d" % secrets.randbelow(1000000)
        self.made = time.time()
        self.tries = 0
        self.locked_until = 0
        self.lock = threading.Lock()

    def fresh(self):
        return time.time() - self.made < PIN_TTL

    def check(self, candidate):
        with self.lock:
            now = time.time()
            if now < self.locked_until:
                return "locked"
            if not self.fresh():
                return "expired"
            ok = hmac.compare_digest(candidate.strip(), self.pin)
            if ok:
                self.tries = 0
                return True
            self.tries += 1
            if self.tries >= PIN_TRIES:
                self.locked_until = now + LOCKOUT
                self.tries = 0
                return "locked"
            return False

    def new_session(self):
        return hmac.new(SECRET, ("session:" + self.pin).encode(), hashlib.sha256).hexdigest()

    def session_ok(self, tok):
        if not tok or not self.fresh():
            return False
        return hmac.compare_digest(tok, self.new_session())


PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>HomePi Tunnel</title>
<body style="background:#111;color:#eee;font-family:monospace;margin:1em">
<h3>HomePi Tunnel</h3>
<form method=post action=/pin>
PIN from the Pi screen: <input name=pin inputmode=numeric autocomplete=off autofocus>
<button>Open</button></form>
<p style=color:#888>%s</p></body>"""

CONSOLE_PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Home Pi console</title>
<body style="background:#111;color:#eee;font-family:monospace;margin:0">
<pre id=scr style="font-size:14px;line-height:1.1;padding:8px;margin:0;white-space:pre">loading...</pre>
<div style="position:fixed;bottom:0;left:0;right:0;background:#222;padding:8px">
<form id=f style="display:flex;gap:6px">
<input id=k autocomplete=off placeholder="type here, Enter sends" style="flex:1">
<button>Send</button></form>
<div id=keys></div></div>
<script>
async function poll(){try{let r=await fetch('/console.txt');document.getElementById('scr').textContent=await r.text()}catch(e){}setTimeout(poll,1000)}
poll();
document.getElementById('f').onsubmit=async e=>{e.preventDefault();let k=document.getElementById('k');
if(k.value){await fetch('/key',{method:'POST',body:k.value});}
await fetch('/key',{method:'POST',body:'K:ENTER'});k.value='';};
for(const [label,key] of [['Enter','K:ENTER'],['Esc','K:ESC'],['Tab','K:TAB'],['Bksp','K:BACKSPACE'],['Up','K:UP'],['Down','K:DOWN'],['Right','K:RIGHT'],['Left','K:LEFT']){
 let b=document.createElement('button');b.textContent=label;
 b.onclick=async()=>{await fetch('/key',{method:'POST',body:key})};
 document.getElementById('keys').appendChild(b);}
</script></body>"""


class Handler(http.server.BaseHTTPRequestHandler):
    gate = None

    def log_message(self, *a):
        pass

    def _cookie(self):
        for h in self.headers.get_all("Cookie", []):
            for part in h.split(";"):
                part = part.strip()
                if part.startswith("hpt="):
                    return part[4:]
        return None

    def _auth(self):
        return self.gate.session_ok(self._cookie())

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, PAGE % ("Tunnel is up. The PIN is on the Pi's screen.",))
        elif self.path == "/console":
            if not self._auth():
                self._send(403, PAGE % "Bad or missing PIN. Open / first.")
            else:
                self._send(200, CONSOLE_PAGE)
        elif self.path == "/console.txt":
            if not self._auth():
                self._send(403, "no", "text/plain")
            else:
                self._send(200, read_console_text(), "text/plain; charset=utf-8")
        elif self.path == "/healthz":
            self._send(200, "ok", "text/plain")
        else:
            self._send(404, "nope", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n > 4096:
            self._send(413, "too big", "text/plain")
            return
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.path == "/pin":
            pin = ""
            for part in body.split("&"):
                if part.startswith("pin="):
                    pin = part[4:]
            r = self.gate.check(pin)
            if r is True:
                self._send(303, "", extra=[("Location", "/console"),
                                           ("Set-Cookie", "hpt=%s; HttpOnly; Secure; SameSite=Strict" % self.gate.new_session())])
            elif r == "locked":
                self._send(403, PAGE % "Too many wrong tries. Locked for 5 minutes.")
            elif r == "expired":
                self._send(403, PAGE % "PIN expired. Check the Pi screen for a fresh one.")
            else:
                self._send(403, PAGE % "Wrong PIN.")
        elif self.path == "/key":
            if not self._auth():
                self._send(403, "no", "text/plain")
                return
            ok, why = inject_payload(body)
            self._send(200 if ok else 500, "ok" if ok else why, "text/plain")
        else:
            self._send(404, "nope", "text/plain")


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --- cloudflared ----------------------------------------------------------

def ensure_cloudflared(log=print):
    path = CLOUDFLARED
    if os.path.exists(path) and os.access(path, os.X_OK):
        return path
    found = shutil.which("cloudflared")
    if found:
        return found
    os.makedirs(APP_DIR, exist_ok=True)
    log("Downloading cloudflared %s (one time, ~38 MB)..." % CLOUDFLARED_VERSION)
    tmp = path + ".download"
    urllib.request.urlretrieve(CLOUDFLARED_URL, tmp)
    got = hashlib.sha256(open(tmp, "rb").read()).hexdigest()
    if got != CLOUDFLARED_SHA256:
        os.unlink(tmp)
        raise RuntimeError("cloudflared download hash mismatch - not installing it.")
    os.rename(tmp, path)
    os.chmod(path, 0o755)
    return path


URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

def start_tunnel(log=print):
    binpath = ensure_cloudflared(log)
    proc = subprocess.Popen([binpath, "tunnel", "--url", "http://localhost:%d" % PORT,
                             "--no-autoupdate", "--loglevel", "info"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    url = None
    deadline = time.time() + 60
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            break
        m = URL_RE.search(line)
        if m:
            url = m.group(0)
            break
    return proc, url
# --- Pi screen UI ---------------------------------------------------------

def run_ui(gate, url, proc):
    """Fullscreen curses display on the Pi's own screen. q kills everything."""
    import curses

    def draw(stdscr):
        try:
            curses.curs_set(0)
        except Exception:
            pass
        stdscr.timeout(250)
        while True:
            if not gate.fresh():
                gate.pin = "%06d" % secrets.randbelow(1000000)
                gate.made = time.time()
                gate.tries = 0
                gate.locked_until = 0
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            def put(r, s, attr=0):
                if 0 <= r < h and s:
                    stdscr.addnstr(r, 0, s.ljust(w - 1), w - 1, attr)
            left = max(0, int(PIN_TTL - (time.time() - gate.made)))
            tunnel = "up" if (proc is None or proc.poll() is None) else "DIED - press q"
            put(0, "=" * (w - 1), curses.A_BOLD)
            put(1, "  HomePi Tunnel  v%s" % VERSION, curses.A_BOLD)
            put(2, "=" * (w - 1), curses.A_BOLD)
            put(4, "  From any phone or computer, open:")
            put(5, "    " + url, curses.A_BOLD)
            put(7, "  PIN (valid %d:%02d more):" % (left // 60, left % 60))
            put(8, "    " + gate.pin, curses.A_BOLD)
            r = 10
            if time.time() < gate.locked_until:
                put(r, "  Locked from too many wrong tries; clears soon."); r += 1
            put(r, "  Web console shows this Pi's screen live."); r += 1
            put(r, "  Typing there types on this Pi."); r += 2
            put(r, "  Tunnel: %s   |   Listening on localhost only" % tunnel); r += 2
            put(r, "  Press  q  here to close the tunnel and every session.", curses.A_BOLD)
            put(h - 1, "=" * (w - 1), curses.A_BOLD)
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q")):
                break
            if proc is not None and proc.poll() is not None:
                # keep showing the dead-tunnel notice until q
                pass

    import curses as _c
    _c.wrapper(draw)


def main():
    logf = open(LOG, "a", buffering=1)
    def log(*a):
        msg = " ".join(str(x) for x in a)
        logf.write(time.strftime("%H:%M:%S ") + msg + "\n")

    gate = Gate()
    Handler.gate = gate
    server = Server(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log("web on 127.0.0.1:%d" % PORT)

    proc = None
    if DEMO:
        url = "https://demo-%s.trycloudflare.com" % secrets.token_hex(4)
        log("demo mode, fake url %s" % url)
    else:
        try:
            proc, url = start_tunnel(log)
        except Exception as e:
            print("Could not start cloudflared: %s" % e)
            print("Full log: %s" % LOG)
            server.shutdown()
            return 1
        if not url:
            print("cloudflared started but gave no address. Log: %s" % LOG)
            try:
                proc.terminate()
            except Exception:
                pass
            server.shutdown()
            return 1
        log("tunnel %s" % url)

    try:
        run_ui(gate, url, proc)
    except KeyboardInterrupt:
        pass
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except Exception:
                proc.kill()
        server.shutdown()
        server.server_close()
    print("Tunnel closed. No sessions remain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
