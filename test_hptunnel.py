#!/usr/bin/env python3
"""Unit + PTY tests for hptunnel. Run: python3 test_hptunnel.py"""
import hashlib, hmac, http.client, os, pty, re, select, subprocess, sys, tempfile, time, unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist"))
import hptunnel as T


class TestGate(unittest.TestCase):
    def test_pin_shape(self):
        for _ in range(20):
            g = T.Gate()
            self.assertRegex(g.pin, r"^\d{6}$")

    def test_correct_pin(self):
        g = T.Gate(pin="123456")
        self.assertTrue(g.check("123456"))

    def test_wrong_pin_then_lockout(self):
        g = T.Gate(pin="123456")
        for _ in range(T.PIN_TRIES - 1):
            self.assertFalse(g.check("000000"))
        self.assertEqual(g.check("000000"), "locked")
        self.assertEqual(g.check("123456"), "locked")  # right pin still locked
        g.locked_until = 0  # simulate lockout elapsed
        self.assertTrue(g.check("123456"))

    def test_expiry(self):
        g = T.Gate(pin="123456")
        g.made = time.time() - T.PIN_TTL - 1
        self.assertEqual(g.check("123456"), "expired")

    def test_session_hmac(self):
        g = T.Gate(pin="123456")
        tok = g.new_session()
        self.assertTrue(g.session_ok(tok))
        self.assertFalse(g.session_ok(tok[:-1] + "0" if tok[-1] != "0" else tok[:-1] + "1"))
        self.assertFalse(g.session_ok(""))
        self.assertFalse(g.session_ok(None))
        # session dies with the PIN
        g.made = time.time() - T.PIN_TTL - 1
        self.assertFalse(g.session_ok(tok))


class TestEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = T.Gate(pin="654321")
        T.Handler.gate = cls.gate
        cls.server = T.Server(("127.0.0.1", 0), T.Handler)
        cls.port = cls.server.server_address[1]
        import threading
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        hs = dict(r.getheaders())
        c.close()
        return r.status, data, hs

    def test_root_page(self):
        s, d, _ = self.req("GET", "/")
        self.assertEqual(s, 200)
        self.assertIn(b"PIN", d)

    def test_console_requires_auth(self):
        s, d, _ = self.req("GET", "/console.txt")
        self.assertEqual(s, 403)

    def test_pin_flow_and_console(self):
        s, d, h = self.req("POST", "/pin", body="pin=000000")
        self.assertEqual(s, 403)
        s, d, h = self.req("POST", "/pin", body="pin=654321")
        self.assertEqual(s, 303)
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertTrue(cookie.startswith("hpt="))
        self.assertIn("Secure", h["Set-Cookie"])
        s, d, _ = self.req("GET", "/console", headers={"Cookie": cookie})
        self.assertEqual(s, 200)
        self.assertIn(b"scr", d)
        # console.txt reads the console (vcsa missing in this container -> graceful text)
        s, d, _ = self.req("GET", "/console.txt", headers={"Cookie": cookie})
        self.assertEqual(s, 200)
        # key injection fails cleanly without hpremote
        s, d, _ = self.req("POST", "/key", body="K:ENTER", headers={"Cookie": cookie})
        self.assertIn(s, (200, 500))
        if s == 500:
            self.assertTrue(b"view-only" in d or b"hpremote not installed" in d)
        # bad session rejected
        s, d, _ = self.req("GET", "/console", headers={"Cookie": "hpt=deadbeef"})
        self.assertEqual(s, 403)

    def test_body_cap(self):
        s, d, _ = self.req("POST", "/pin", body="x" * 5000)
        self.assertEqual(s, 413)

    def test_404(self):
        s, _, _ = self.req("GET", "/admin")
        self.assertEqual(s, 404)


class TestInjectPayload(unittest.TestCase):
    def test_unknown_named_key(self):
        ok, why = T.inject_payload("K:NOPE")
        self.assertFalse(ok)
        self.assertIn("unknown", why)

    def test_text_maps_to_codes(self):
        seen = {}
        real = T.inject_codes
        def fake(codes):
            seen["codes"] = codes
            return True, "fake"
        T.inject_codes = fake
        try:
            ok, _ = T.inject_payload("hi\n")
            self.assertTrue(ok)
            self.assertEqual(seen["codes"], [ord("h"), ord("i"), 343])
            ok, _ = T.inject_payload("K:ENTER")
            self.assertTrue(ok)
            self.assertEqual(seen["codes"], [343])
        finally:
            T.inject_codes = real


class TestPTYUI(unittest.TestCase):
    """Run the real app in a PTY with a stub cloudflared; check the screen."""

    def test_ui_shows_url_and_pin_then_quits(self):
        stub = os.path.join(tempfile.mkdtemp(), "cloudflared")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\necho 'INF https://unit-test-abc.trycloudflare.com registered' >&2\nsleep 600\n")
        os.chmod(stub, 0o755)
        env = dict(os.environ)
        env.update({"HPTUNNEL_CLOUDFLARED": stub, "HPTUNNEL_PORT": "18766",
                    "HPTUNNEL_LOG": "/tmp/hptunnel-test.log", "TERM": "xterm",
                    "LINES": "30", "COLUMNS": "100"})
        master, slave = pty.openpty()
        p = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "hptunnel.py")],
                             stdin=slave, stdout=slave, stderr=slave, env=env, close_fds=True)
        os.close(slave)
        buf = b""
        deadline = time.time() + 30
        try:
            while time.time() < deadline:
                r, _, _ = select.select([master], [], [], 1)
                if r:
                    try:
                        buf += os.read(master, 65536)
                    except OSError:
                        break
                if b"Press  q" in buf:
                    break
            self.assertIn(b"unit-test-abc.trycloudflare.com", buf, "URL not on screen")
            self.assertRegex(buf, rb"\b\d{6}\b", "no 6-digit PIN on screen")
            self.assertIn(b"Press  q", buf)
            os.write(master, b"q")
            p.wait(10)
            self.assertEqual(p.returncode, 0)
            # stub process must be dead
            time.sleep(0.5)
            r = subprocess.run(["pgrep", "-f", stub], capture_output=True)
            self.assertNotEqual(r.returncode, 0, "stub cloudflared still running after q")
        finally:
            try:
                os.write(master, b"q")
            except OSError:
                pass
            if p.poll() is None:
                p.kill()
            subprocess.run(["pkill", "-f", stub], capture_output=True)
            os.close(master)


if __name__ == "__main__":
    unittest.main(verbosity=2)
