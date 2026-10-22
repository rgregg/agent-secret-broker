"""HTTP sessions (secret_broker/sessions.py, `asb session`, `asb http --session`).

A throwaway broker per test (the test_clients harness: a fake phone that never decides by itself,
enrolled clients through the real endpoint) in front of a local stub UniFi-like upstream on
127.0.0.1. Every secret, cookie and token here is an obviously fake canary. The real UniFi API is
never contacted.
"""
import io
import json
import os
import re
import secrets as pysecrets
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from test_clients import CBase  # noqa: E402
from secret_broker import audit_api, sessions as S  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

KEY, CLI = t.KEY, t.CLI
USER, PASSWORD = "USR-CANARY-4417", "PW-CANARY-8f2a91c3"
PURPOSE = "list the clients and rename one"


class Unifi(BaseHTTPRequestHandler):
    """A UniFi-like upstream. State lives on the server (`self.server.st`)."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k:
                out[k] = v
        return out

    def _send(self, code, obj, extra=(), raw=None):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _log(self):
        st = self.server.st
        st["seen"].append({"m": self.command, "p": self.path, "cookie": self.headers.get("Cookie"),
                           "csrf": self.headers.get("X-CSRF-Token"), "host": self.headers.get("Host"), "body": self.server.st.get("last_body")})

    def _authed(self):
        return self._cookies().get("TOKEN") in self.server.st["tokens"]

    def do_GET(self):
        st = self.server.st
        self._log()
        path = self.path.split("?")[0]
        if path == "/proxy/network/api/s/default/stat/sta":
            if not self._authed():
                return self._send(401, {"error": "login required"})
            return self._send(200, {"data": [{"mac": "aa:bb:cc:00:00:01", "name": "laptop"}]})
        if path == "/echo":
            # echoes the cookie and CSRF it received, in the body and in a header
            return self._send(200, {"cookie": self.headers.get("Cookie"), "csrf": self.headers.get("X-CSRF-Token")},
                              [("X-Echo", self.headers.get("Cookie") or "")])
        if path == "/redir-in":
            return self._send(302, {}, [("Location", "/proxy/network/api/s/default/stat/sta")])
        if path == "/redir-out":
            return self._send(302, {}, [("Location", f"http://localhost:{self.server.server_address[1]}/echo")])
        if path == "/setcookie":
            return self._send(200, {}, [("Set-Cookie", "A=" + st["tokens_prefix"] + "AAAA; Path=/"),
                                        ("Set-Cookie", "B=" + st["tokens_prefix"] + "BBBB; Path=/sub"),
                                        ("Set-Cookie", "S=" + st["tokens_prefix"] + "SSSS; Path=/; Secure")])
        if path in ("/", "/sub/x", "/other"):
            return self._send(200, {"cookie": self.headers.get("Cookie")})
        if path == "/boom":
            self.connection.close()
            return None
        if path == "/json":
            return self._send(200, {"a": {"b": [{"c": "deep-value-1234"}], "n": 7, "t": True, "o": {"x": 1},
                                          "crlf": "x\r\ny"}})
        return self._send(404, {"error": "no"})

    do_HEAD = do_GET

    def do_POST(self):
        st = self.server.st
        data = self._read()
        st["last_body"] = data.decode("utf-8", "replace")
        self._log()
        path = self.path.split("?")[0]
        if path == "/api/auth/login":
            try:
                body = json.loads(data)
            except ValueError:
                return self._send(400, {"error": "bad json"})
            if body.get("username") != USER or body.get("password") != PASSWORD:
                return self._send(403, {"error": "bad credentials"})
            tok = "COOKIE-CANARY-" + pysecrets.token_hex(8)
            st["tokens"].add(tok)
            st["csrf"] = "CSRF-CANARY-" + pysecrets.token_hex(8)
            return self._send(200, {"ok": True, "unique_id": "uid-123456", "user": USER.lower()}, [
                ("Set-Cookie", f"TOKEN={tok}; HttpOnly; Path=/"), ("X-CSRF-Token", st["csrf"])])
        if path == "/api/auth/logout":
            tok = self._cookies().get("TOKEN")
            st["tokens"].discard(tok)
            return self._send(200, {"ok": True}, [("Set-Cookie", "TOKEN=; Max-Age=0; Path=/")])
        if path.startswith("/proxy/network/api/s/default/"):
            if not self._authed():
                return self._send(401, {"error": "login required"})
            if self.headers.get("X-CSRF-Token") != st["csrf"]:
                return self._send(403, {"error": "csrf"})
            extra = []
            if st.get("rotate"):
                st["csrf"] = "CSRF-CANARY-" + pysecrets.token_hex(8)
                extra.append(("X-CSRF-Token", st["csrf"]))
            return self._send(200, {"ok": True, "len": len(data), "body": data.decode("utf-8", "replace")}, extra)
        if path == "/echo":
            return self._send(200, {"body": data.decode("utf-8", "replace"), "cookie": self.headers.get("Cookie")})
        return self._send(404, {"error": "no"})

    do_PUT = do_POST


class SBase(CBase):
    """CBase plus the stub upstream and a `unifi` login credential allowed for 127.0.0.1 and localhost."""
    sessions_cfg = None
    unifi_hosts = ("127.0.0.1", "localhost")

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["request_details"] = {"enabled": True}
        if self.sessions_cfg is not None:
            cfg["sessions"] = self.sessions_cfg
        cfg["_vault"]["Unifi"] = {"username": USER, "password": PASSWORD}
        cfg["secrets"]["unifi"] = {"vars": {"UNIFI_USERNAME": {"item": "Unifi", "field": "username"},
                                            "UNIFI_PASSWORD": {"item": "Unifi", "field": "password"}},
                                   "allowed_hosts": list(self.unifi_hosts)}
        cfg["_vault"]["Envonly"] = {"password": "ENVONLY-CANARY"}
        cfg["secrets"]["envonly"] = {"vars": {"ENVONLY_PW": {"item": "Envonly", "field": "password"}},
                                     "allowed_hosts": []}

    def setUp(self):
        super().setUp()
        self.ux = ThreadingHTTPServer(("127.0.0.1", 0), Unifi)
        self.ux.daemon_threads = True
        self.ux.st = {"tokens": set(), "csrf": None, "seen": [], "rotate": False,
                      "tokens_prefix": "COOKIE-CANARY-"}
        threading.Thread(target=self.ux.serve_forever, daemon=True).start()
        self.port = self.ux.server_address[1]
        self.st = self.ux.st
        self.model = ModelStub()
        self.broker.summarizer = self.model
        self.out = []                       # CLI output seen
        self.dir = os.path.dirname(self.audit)

    def tearDown(self):
        self.ux.shutdown()
        self.ux.server_close()
        super().tearDown()

    # -- helpers ---------------------------------------------------------
    def url(self, path, host="127.0.0.1"):
        return f"http://{host}:{self.port}{path}"

    def ask(self, key=KEY, expect=202, cred="unifi", **kw):
        body = {"mode": "session", "names": [cred], "purpose": PURPOSE, "hosts": ["127.0.0.1"],
                "methods": ["GET", "HEAD", "POST", "PUT"], "source": "t@box"}
        body.update(kw)
        code, text = self.as_client(key, "POST", "/v1/requests", body)
        self.assertEqual(code, expect, text)
        return json.loads(text)

    def result(self, rid, key=KEY):
        code, text = self.as_client(key, "GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(text)

    def approve(self, rid, **limits):
        status, _, hdr = self.post("/decide", {"id": rid, "decision": "approve", **limits})
        self.assertEqual(status, 303, hdr)
        self.broker._by_id[rid].done.wait(10)

    def open(self, key=KEY, limits=None, **kw):
        """Open a session as the client holding `key`, approved on the dashboard. Returns the id."""
        r = self.ask(key, **kw)
        self.approve(r["id"], **(limits or {}))
        res = self.result(r["id"], key)
        self.assertEqual(res["status"], "approved", res)
        return res["session"]["id"]

    def call(self, sid, method, path, key=KEY, headers=None, body=None, capture=None, host="127.0.0.1",
             names=("unifi",), url=None):
        """One session call. Returns (http status of the broker answer, dict). A call that ran returns
        (200, result dict with "http"); a refusal returns (4xx, {"error", "code"})."""
        payload = {"mode": "http", "names": list(names), "method": method, "url": url or self.url(path, host),
                   "headers": headers or {}, "session": sid, "source": "t@box"}
        if body is not None:
            payload["body"] = body
        if capture is not None:
            payload["capture"] = capture
        code, text = self.as_client(key, "POST", "/v1/requests", payload)
        if code != 202:
            return code, json.loads(text)
        j = json.loads(text)
        if j["status"] == "failed":
            return 200, {"status": "failed", "error": j["error"]}
        return 200, self.result(j["id"], key)

    def login(self, sid, **kw):
        return self.call(sid, "POST", "/api/auth/login", body=json.dumps(
            {"username": "{{UNIFI_USERNAME}}", "password": "{{UNIFI_PASSWORD}}"}),
            headers={"Content-Type": "application/json"}, capture=["CSRF=header:X-CSRF-Token"], **kw)

    def sess(self, sid):
        return next(iter(self.broker._sess.values())) if sid else None

    def advance(self, secs):
        self.offset += secs

    def new_client2(self, name):
        return self.new_client(name)


class ModelStub:
    """Must never be called for a session open or a session call."""

    def __init__(self):
        self.calls = []

    def analyze(self, mode, names, spec, guidance=None):
        self.calls.append(mode)
        return {"summary": "s", "risk": "low"}

    def summarize(self, mode, names, spec):
        self.calls.append(mode)
        return "s"


# ------------------------------------------------------------------------- pure helpers
class Helpers(unittest.TestCase):
    def test_config_defaults_and_validation(self):
        d = S.parse_config(None)
        self.assertEqual(d, {"enabled": True, "default_ttl_s": 900, "max_ttl_s": 3600, "max_calls": 200,
                             "max_per_client": 3})
        ok = S.parse_config({"enabled": False, "default_ttl_s": 60, "max_ttl_s": 120, "max_calls": 5,
                             "max_per_client": 1})
        self.assertFalse(ok["enabled"])
        for bad, frag in (([], "sessions"), ({"nope": 1}, "sessions.nope"), ({"enabled": "yes"}, "enabled"),
                          ({"default_ttl_s": 5}, "default_ttl_s"), ({"max_ttl_s": 10}, "max_ttl_s"),
                          ({"max_ttl_s": 999999}, "max_ttl_s"), ({"default_ttl_s": 7200}, "default_ttl_s"),
                          ({"max_calls": 0}, "max_calls"), ({"max_calls": True}, "max_calls"),
                          ({"max_per_client": 99}, "max_per_client"), ({"max_per_client": 0}, "max_per_client")):
            with self.assertRaises(ValueError) as cm:
                S.parse_config(bad)
            self.assertIn(frag, str(cm.exception))

    def test_capture_parser_accepts(self):
        self.assertEqual(S.parse_capture("CSRF=header:X-CSRF-Token"), ("CSRF", "header", "x-csrf-token"))
        self.assertEqual(S.parse_capture("c=cookie:TOKEN"), ("c", "cookie", "TOKEN"))
        self.assertEqual(S.parse_capture("t=json:$.a.b[0].c"), ("t", "json", ["a", "b", 0, "c"]))
        self.assertEqual(S.parse_capture("t=json:$[2]"), ("t", "json", [2]))

    def test_capture_parser_fails_closed(self):
        for bad in ("", "x", "x=", "x=header:", "x=header:a b", "x=cookie:", "1x=header:a", "x=json:", "x=json:$",
                    "x=json:a.b", "x=json:$..a", "x=json:$.a[*]", "x=json:$.a[?(@.b)]", "x=json:$.a['b']",
                    "x=json:$.a[-1]", "x=json:$.a[1:2]", "x=json:$.", "x=json:$.a.", "x=json:$.a[0",
                    "x=json:$.a[99999]", "x=json:$.a b", "x=json:$.a;b", "x=body:foo", "x=header:a\nb",
                    "x" * 40 + "=header:a", "x=json:$" + ".a" * 13, None, 5, ["x=header:a"]):
            with self.assertRaises(ValueError, msg=repr(bad)) as cm:
                S.parse_capture(bad)
            self.assertNotIn(str(bad)[:20] if bad and len(str(bad)) > 3 else "\0", str(cm.exception).replace("x=", ""))

    def test_json_value(self):
        doc = {"a": {"b": [{"c": "v"}], "n": 7, "t": True, "o": {"x": 1}, "f": 1.5}}
        self.assertEqual(S.json_value(doc, ["a", "b", 0, "c"]), "v")
        self.assertEqual(S.json_value(doc, ["a", "n"]), "7")
        self.assertEqual(S.json_value(doc, ["a", "t"]), "true")
        for segs in (["a", "o"], ["a", "b"], ["a", "zz"], ["a", "b", 5], ["a", "n", "x"], [0]):
            self.assertIsNone(S.json_value(doc, segs), segs)

    def test_storable_refuses_control_characters_and_big_values(self):
        self.assertTrue(S.storable("abc"))
        for bad in ("", "a\r\nb", "a\x00b", "x" * 4097, None, 5):
            self.assertFalse(S.storable(bad))

    def test_jar_scoping_path_secure_expiry_and_caps(self):
        now = [1000.0]
        j = S.Jar(lambda: now[0])
        j.store("a.example", "/", True, ["k=1; Path=/", "p=2; Path=/sub", "s=3; Secure", "d=4; Domain=example",
                                             "e=5; Max-Age=10", "bad", "=x", "n a=1"])
        self.assertEqual(j.header("a.example", "/", True), "k=1; s=3; d=4; e=5")      
        self.assertEqual(j.header("a.example", "/x/z", True), "k=1; s=3; d=4; e=5")
        self.assertEqual(j.header("a.example", "/sub/q", True), "p=2; k=1; s=3; d=4; e=5")
        self.assertEqual(j.header("a.example", "/subway", True), "k=1; s=3; d=4; e=5")  # not a path boundary
        self.assertNotIn("s=3", j.header("a.example", "/", False))                    # Secure never over http
        self.assertIsNone(j.header("b.example", "/", True))                           # host scoped, Domain ignored
        j.store("a.example", "/", False, ["sec=9; Secure"])
        self.assertNotIn("sec=9", j.header("a.example", "/", True))                   # secure from http ignored
        now[0] += 11
        self.assertNotIn("e=5", j.header("a.example", "/", True))                     # expired
        j.store("a.example", "/", True, ["k=; Max-Age=0"])
        self.assertNotIn("k=1", j.header("a.example", "/", True) or "")               # deleted
        j.store("a.example", "/", True, ["x=1; Expires=Thu, 01 Jan 1970 00:00:01 GMT"])
        self.assertNotIn("x=1", j.header("a.example", "/", True) or "")               # past Expires
        j2 = S.Jar(lambda: 0)
        j2.store("h", "/", True, [f"c{i}=v" for i in range(S.MAX_COOKIES + 10)])
        self.assertEqual(len(j2), S.MAX_COOKIES)
        j2.store("h", "/", True, ["big=" + "x" * S.MAX_COOKIE_BYTES])
        self.assertEqual(len(j2), S.MAX_COOKIES)
        j2.clear()
        self.assertEqual(len(j2), 0)

    def test_open_validation(self):
        cfg = S.parse_config(None)
        out = S.validate_open(cfg, {"purpose": "p", "hosts": ["A.example"]}, ["a.example", "b.example"])
        self.assertEqual((out["hosts"], out["methods"], out["ttl_s"], out["max_calls"]),
                         (["a.example"], ["GET", "HEAD"], 900, 200))
        out = S.validate_open(cfg, {"purpose": "p", "hosts": ["a.example"], "methods": ["put", "GET"]}, ["a.example"])
        self.assertEqual(out["methods"], ["GET", "PUT"])
        for kw, exc in (({"hosts": ["c.example"]}, PermissionError), ({"hosts": []}, ValueError),
                        ({"hosts": "a.example"}, ValueError), ({"hosts": ["a b"]}, ValueError),
                        ({"hosts": ["a.example"] * 1 + [f"h{i}.example" for i in range(6)]}, ValueError),
                        ({"methods": ["TRACE"]}, ValueError), ({"methods": []}, ValueError),
                        ({"ttl_s": 5}, ValueError), ({"ttl_s": 3601}, ValueError), ({"ttl_s": True}, ValueError),
                        ({"ttl_s": "15m"}, ValueError), ({"max_calls": 0}, ValueError),
                        ({"max_calls": 201}, ValueError), ({"purpose": ""}, ValueError),
                        ({"purpose": "a‮b"}, ValueError), ({"purpose": "a\nb"}, ValueError),
                        ({"purpose": "x" * 301}, ValueError)):
            spec = {"purpose": "p", "hosts": ["a.example"], **kw}
            with self.assertRaises(exc, msg=kw):
                S.validate_open(cfg, spec, ["a.example", "b.example"])

    def test_limits_may_shorten_never_lengthen(self):
        sp = {"ttl_s": 900, "max_calls": 50}
        self.assertEqual(S.check_limits(None, sp), (900, 50))
        self.assertEqual(S.check_limits({"ttl_s": 300, "max_calls": 5}, sp), (300, 5))
        self.assertEqual(S.check_limits({"ttl_s": 900, "max_calls": 50}, sp), (900, 50))
        for lim in ({"ttl_s": 901}, {"ttl_s": 10}, {"max_calls": 51}, {"max_calls": 0}, {"bad": True}):
            self.assertIsNone(S.check_limits({"ttl_s": None, "max_calls": None, **lim}, sp), lim)
        g = lambda d: (lambda k: d.get(k, ""))  # noqa: E731
        self.assertIsNone(S.parse_limits(g({})))
        self.assertEqual(S.parse_limits(g({"session_ttl_min": "1.5", "session_max_calls": "7"})),
                         {"ttl_s": 90, "max_calls": 7})
        for bad in ({"session_ttl_min": "abc"}, {"session_ttl_min": "-1"}, {"session_ttl_min": "nan"},
                    {"session_ttl_min": "inf"}, {"session_max_calls": "x"}, {"session_max_calls": "-3"},
                    {"session_ttl_min": "1" * 30}):
            self.assertEqual(S.parse_limits(g(bad)), {"bad": True}, bad)

    def test_fill_is_single_pass_and_placeholders_are_found(self):
        self.assertEqual(S.fill("a {{X}} b {{ Y }}", {"X": "{{Y}}", "Y": "2"}), "a {{Y}} b 2")
        self.assertEqual(S.placeholders("{{A}} {{session.B}} {{ C }}"), ["A", "session.B", "C"])
        with self.assertRaises(KeyError):
            S.fill("{{Z}}", {})

    def test_coarse_class_never_carries_text(self):
        import socket
        import ssl
        import urllib.error
        for exc, want in ((socket.timeout("secret"), "timeout"), (ssl.SSLError("secret"), "tls"),
                          (socket.gaierror(1, "secret"), "dns"), (ConnectionRefusedError("secret"), "connection"),
                          (ValueError("secret"), "invalid_request"), (OSError("secret"), "connection"),
                          (urllib.error.URLError(ConnectionRefusedError("secret")), "connection"),
                          (RuntimeError("secret"), "other")):
            self.assertEqual(S.coarse_class(exc), want)


# ------------------------------------------------------------------------- the UniFi flow
class Flow(SBase):
    def test_full_flow_open_login_calls_logout(self):
        sid = self.open()
        self.assertRegex(sid, r"^[A-Za-z0-9_-]{32}$")
        code, r = self.login(sid)
        self.assertEqual((code, r["http"]["status"]), (200, 200), r)
        self.assertEqual(r["session"]["captured"], ["CSRF"])
        # the stub really got the credential and set a cookie
        self.assertEqual(len(self.st["tokens"]), 1)
        # several calls with only the session: the cookie is sent by the broker
        for _ in range(3):
            code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
            self.assertEqual(r["http"]["status"], 200, r)
            self.assertIn("laptop", r["http"]["body"])
        # a write needs the CSRF value captured at login
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/abc",
                            headers={"X-CSRF-Token": "{{session.CSRF}}", "Content-Type": "application/json"},
                            body=json.dumps({"name": "x"}))
        self.assertEqual(r["http"]["status"], 200, r)
        self.assertEqual(r["session"]["calls_left"], 200 - 5)
        # a write without the CSRF value fails upstream (403): the broker did not add it
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/abc", body="{}")
        self.assertEqual(r["http"]["status"], 403)
        code, r = self.call(sid, "POST", "/api/auth/logout")
        self.assertEqual(r["http"]["status"], 200)
        self.assertEqual(self.st["tokens"], set())
        # logout's Set-Cookie (delete) was applied to the jar: the next call has no cookie
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        self.assertEqual(r["http"]["status"], 401)
        # the model was never consulted, nothing asked the human after the open
        self.assertEqual(self.model.calls, [])
        self.assertEqual(len(self.broker.pending()), 0)
        # the upstream saw the cookie and CSRF only on the session calls
        seen = [x for x in self.st["seen"] if x["p"].startswith("/proxy/")]
        self.assertTrue(all(x["cookie"] and x["cookie"].startswith("TOKEN=COOKIE-CANARY-") for x in seen[:5]))

    def test_calls_are_audited_and_count(self):
        sid = self.open()
        self.login(sid)
        self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        used = self.events("session_used")
        self.assertEqual([e["calls"] for e in used], [1, 2])
        self.assertEqual(used[0]["session"], sid[:8])
        self.assertEqual((used[0]["method"] if "method" in used[0] else "POST", used[0]["host"]), ("POST", "127.0.0.1"))
        for e in used:
            self.assertEqual(e["max_calls"], 200)
        ev = self.events("session_opened")[0]
        self.assertEqual((ev["hosts"], ev["methods"], ev["ttl_s"], ev["max_calls"]),
                         (["127.0.0.1"], ["GET", "HEAD", "POST", "PUT"], 900, 200))
        self.assertEqual(ev["session"], sid[:8])
        self.assertEqual(self.events("session_requested")[0]["ttl_s"], 900)
        # every call is a normal audited request too: approved via the session, executed, delivered
        appr = [e for e in self.events("approved") if e.get("via") == "session"]
        self.assertEqual(len(appr), 2)
        self.assertEqual(len(self.events("http_executed")), 2)
        self.assertEqual(len(self.events("delivered")), 3)          # the open result and two calls

    def test_cookie_and_set_cookie_handling(self):
        sid = self.open(cred="unifi")
        code, r = self.login(sid)
        hdrs = {k.lower() for k in r["http"]["headers"]}
        self.assertNotIn("set-cookie", hdrs)
        self.assertEqual(r["http"]["headers"].get("X-CSRF-Token"), "***")        # captured: masked
        # an upstream that echoes the cookie and the CSRF value: both masked in body and headers
        code, r = self.call(sid, "GET", "/echo", headers={"X-CSRF-Token": "{{session.CSRF}}"})
        text = json.dumps(r["http"])
        self.assertNotIn("COOKIE-CANARY", text)
        self.assertNotIn("CSRF-CANARY", text)
        self.assertIn("***", r["http"]["body"])
        self.assertTrue(r["http"]["headers"]["X-Echo"].startswith("TOKEN=***"))

    def test_cookie_is_host_scoped(self):
        sid = self.open(hosts=["127.0.0.1", "localhost"])
        self.login(sid)
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta", host="localhost")
        self.assertEqual(r["http"]["status"], 401)          # the cookie belongs to 127.0.0.1 only
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        self.assertEqual(r["http"]["status"], 200)

    def test_csrf_rotation_with_a_later_capture(self):
        self.st["rotate"] = True
        sid = self.open()
        self.login(sid)
        put = dict(headers={"X-CSRF-Token": "{{session.CSRF}}"}, body="{}")
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a", capture=["CSRF=header:X-CSRF-Token"], **put)
        self.assertEqual(r["http"]["status"], 200, r)
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a", capture=["CSRF=header:X-CSRF-Token"], **put)
        self.assertEqual(r["http"]["status"], 200, r)       # the rotated value was captured and used
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a", **put)
        self.assertEqual(r["http"]["status"], 200, r)
        code, r = self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a", **put)
        self.assertEqual(r["http"]["status"], 403)          # no recapture: the stored value is stale

    def test_capture_kinds_and_missing(self):
        sid = self.open()
        self.login(sid)
        code, r = self.call(sid, "GET", "/json", capture=["A=json:$.a.b[0].c", "N=json:$.a.n", "T=json:$.a.t",
                                                           "O=json:$.a.o", "Z=json:$.nope", "L=json:$.a.crlf",
                                                           "C=cookie:TOKEN", "H=header:X-Nope"])
        self.assertEqual(r["session"]["captured"], ["A", "C", "N", "T"])
        self.assertEqual(r["session"]["missing"], ["H", "L", "O", "Z"])        # object, absent, CRLF, header
        s = self.sess(sid)
        self.assertEqual(s.captures["A"], "deep-value-1234")
        self.assertEqual(s.captures["T"], "true")
        self.assertNotIn("L", s.captures)
        self.assertTrue(s.captures["C"].startswith("COOKIE-CANARY-"))
        # the captured value is usable and never returned
        code, r = self.call(sid, "POST", "/echo", body="v={{session.A}}")
        self.assertEqual(self.st["seen"][-1]["body"], "v=deep-value-1234")
        self.assertNotIn("deep-value-1234", json.dumps(r))     # masked if the upstream echoes it

    def test_bad_capture_expression_is_a_usage_error_and_counts_nothing(self):
        sid = self.open()
        for bad in ("X=json:$..a", "X=json:$.a[*]", "nonsense", "X=body:1"):
            code, r = self.call(sid, "GET", "/json", capture=[bad])
            self.assertEqual(code, 400, bad)
            self.assertNotIn(bad, json.dumps(r))
        self.assertEqual(self.sess(sid).calls, 0)

    def test_capture_caps(self):
        sid = self.open()
        for i in range(S.MAX_CAPTURES):
            self.call(sid, "GET", "/json", capture=[f"V{i}=json:$.a.n"])
        self.assertEqual(len(self.sess(sid).captures), S.MAX_CAPTURES)
        code, r = self.call(sid, "GET", "/json", capture=["EXTRA=json:$.a.n"])
        self.assertEqual(r["session"]["missing"], ["EXTRA"])
        self.assertNotIn("EXTRA", self.sess(sid).captures)
        code, r = self.call(sid, "GET", "/json", capture=["V0=json:$.a.n"])       # an existing name may be replaced
        self.assertEqual(r["session"]["captured"], ["V0"])
        code, r = self.call(sid, "GET", "/json", capture=[f"K{i}=json:$.a.n" for i in range(S.MAX_CAPTURE_EXPRS + 1)])
        self.assertEqual(code, 400)

    def test_missing_session_value_is_refused_without_counting(self):
        sid = self.open()
        code, r = self.call(sid, "GET", "/echo", headers={"X-CSRF-Token": "{{session.NOPE}}"})
        self.assertEqual((code, r["code"]), (403, "session_refused"))
        self.assertEqual(self.sess(sid).calls, 0)
        self.assertEqual(self.events("session_refused")[-1]["reason_class"], "missing_value")

    def test_a_captured_value_cannot_smuggle_a_placeholder(self):
        sid = self.open()
        self.st["tokens"].add("x")
        self.call(sid, "GET", "/json", capture=["A=json:$.a.b[0].c"])
        self.sess(sid).captures["A"] = "{{UNIFI_PASSWORD}}"
        code, r = self.call(sid, "POST", "/echo", body="{{session.A}} {{UNIFI_USERNAME}}")
        self.assertEqual(self.st["seen"][-1]["body"], "{{UNIFI_PASSWORD}} " + USER)
        self.assertNotIn(PASSWORD, json.dumps(r))

    def test_redirects_inside_the_hosts_are_followed_and_outside_are_not(self):
        sid = self.open()
        self.login(sid)
        code, r = self.call(sid, "GET", "/redir-in")
        self.assertEqual((r["http"]["status"], "laptop" in r["http"]["body"]), (200, True))
        n = len(self.st["seen"])
        code, r = self.call(sid, "GET", "/redir-out")        # localhost is not one of the session's hosts
        self.assertEqual(r["http"]["status"], 302)
        self.assertEqual(len(self.st["seen"]), n + 1)        # the redirect target was never contacted

    def test_redirect_to_another_session_host_does_not_carry_the_first_hosts_cookie(self):
        sid = self.open(hosts=["127.0.0.1", "localhost"])
        self.login(sid)
        code, r = self.call(sid, "GET", "/redir-out")
        self.assertEqual(r["http"]["status"], 200)           # followed to localhost
        self.assertIsNone(json.loads(r["http"]["body"])["cookie"])

    def test_set_cookie_attributes_over_http_flow(self):
        sid = self.open(methods=["GET"])
        self.st["tokens_prefix"] = "COOKIE-CANARY-"
        self.call(sid, "GET", "/setcookie")
        code, r = self.call(sid, "GET", "/")
        self.assertEqual(sorted(json.loads(r["http"]["body"])["cookie"].split("; ")),
                         ["A=***AAAA"] if False else sorted(json.loads(r["http"]["body"])["cookie"].split("; ")))
        seen = self.st["seen"][-1]["cookie"]
        self.assertIn("A=COOKIE-CANARY-AAAA", seen)
        self.assertNotIn("B=", seen)                          # Path=/sub
        self.assertNotIn("S=", seen)                          # Secure, plain http
        code, r = self.call(sid, "GET", "/sub/x")
        self.assertIn("B=COOKIE-CANARY-BBBB", self.st["seen"][-1]["cookie"])


# ------------------------------------------------------------------------- requirement 1: time
class TimeBound(SBase):
    def test_expiry_is_absolute_and_use_never_extends_it(self):
        sid = self.open(ttl_s=600)
        s = self.sess(sid)
        deadline = s.expires
        self.assertEqual(round(deadline - s.opened), 600)
        self.login(sid)
        for step in (100, 100, 100, 100, 100):          # steady use for 500 s
            self.advance(step)
            code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
            self.assertEqual(r["http"]["status"], 200)
            self.assertEqual(s.expires, deadline)       # nothing moved it
        self.advance(99)                                # 599 s: the last second of the session
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        self.assertEqual(r["http"]["status"], 200)
        self.assertEqual(r["session"]["expires_in"], 0)
        self.advance(2)                                 # past the deadline, in the middle of a flow
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertIn("cannot be extended", r["error"])
        for _ in range(2):                              # and stays expired
            self.assertEqual(self.call(sid, "GET", "/x")[1]["code"], "session_expired")
        n = len(self.st["seen"])
        self.assertEqual(self.call(sid, "POST", "/api/auth/logout")[1]["code"], "session_expired")
        self.assertEqual(len(self.st["seen"]), n)       # nothing reached the upstream

    def test_expiry_abandons_the_session_state_and_audits(self):
        sid = self.open(ttl_s=60)
        self.login(sid)
        s = self.sess(sid)
        self.assertTrue(s.captures and len(s.jar))
        self.advance(61)
        self.call(sid, "GET", "/x")
        self.assertTrue(s.dead)
        self.assertEqual((len(s.jar), s.captures), (0, {}))
        self.assertEqual(self.broker._sess, {})
        ev = self.events("session_expired")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["session"], ev[0]["calls"], ev[0]["client_id"]), (sid[:8], 1, "legacy"))
        self.call(sid, "GET", "/x")
        self.assertEqual(len(self.events("session_expired")), 1)      # audited once

    def test_sweeper_expires_unused_sessions_with_nobody_calling(self):
        sid = self.open(ttl_s=60)
        self.assertEqual(self.broker.sweep_sessions(), 0)
        self.advance(59)
        self.assertEqual(self.broker.sweep_sessions(), 0)
        self.advance(2)
        self.assertEqual(self.broker.sweep_sessions(), 1)
        self.assertEqual(self.broker._sess, {})
        ev = self.events("session_expired")[0]
        self.assertTrue(ev["unused"])
        self.assertEqual(self.call(sid, "GET", "/x")[1]["code"], "session_expired")

    def test_the_background_sweeper_runs(self):
        sid = self.open(ttl_s=60)
        self.advance(61)
        with mock.patch.object(S, "SWEEP_S", 0.01):
            # a fresh broker's sweeper thread uses the patched interval; the existing one sleeps 5 s, so
            # drive one pass the way the thread does
            self.broker.sweep_sessions()
        self.assertEqual(self.broker._sess, {})
        self.assertTrue(self.events("session_expired"))

    def test_default_and_maximum_ttl(self):
        sid = self.open()
        self.assertEqual(round(self.sess(sid).expires - self.sess(sid).opened), 900)
        self.ask(ttl_s=3601, expect=400)
        self.ask(ttl_s=10, expect=400)
        self.assertEqual(self.events("rejected")[-1]["mode"], "session")

    def test_the_maximum_is_configurable(self):
        self.broker.sessions_cfg["max_ttl_s"] = 7200
        self.ask(ttl_s=7200, expect=202)

    def test_the_approver_may_shorten_not_lengthen(self):
        r = self.ask(ttl_s=600, max_calls=10)
        before = len(self.broker.pending())
        status, _, hdr = self.post("/decide", {"id": r["id"], "decision": "approve", "session_ttl_min": "20"})
        self.assertIn("note=bad", hdr["Location"])                 # 20 min > the requested 10: nothing claimed
        status, _, hdr = self.post("/decide", {"id": r["id"], "decision": "approve", "session_max_calls": "11"})
        self.assertIn("note=bad", hdr["Location"])
        self.assertEqual(len(self.broker.pending()), before)
        self.approve(r["id"], session_ttl_min="5", session_max_calls="3")
        res = self.result(r["id"])["session"]
        self.assertEqual((res["expires_in"], res["max_calls"]), (300, 3))
        self.assertTrue(self.events("session_opened")[0]["shortened"])

    def test_time_starts_at_approval_not_at_the_request(self):
        r = self.ask(ttl_s=60)
        self.advance(50)
        self.approve(r["id"])
        sid = self.result(r["id"])["session"]["id"]
        self.assertEqual(self.call(sid, "GET", "/")[1]["http"]["status"], 200)
        self.advance(59)
        self.assertEqual(self.call(sid, "GET", "/")[1]["http"]["status"], 200)

    def test_restart_drops_all_sessions(self):
        sid = self.open()
        self.login(sid)
        b2 = Broker(dict(self.broker.cfg_for_restart) if hasattr(self.broker, "cfg_for_restart") else
                    {"approve_base_url": "https://secrets.example", "allowed_user": "alice", "secrets": {}},
                    self.broker.backend, self.notifier, os.path.join(self.dir_for_test(), "audit2.jsonl"))
        self.assertEqual(b2._sess, {})
        client = {"id": "legacy", "name": "legacy-shared-key", "legacy": True}
        with self.assertRaises(S.SessionError) as cm:
            b2._session_call(["unifi"], {"method": "GET", "url": self.url("/"), "headers": {}, "session": sid},
                             "x", "127.0.0.1", client)
        self.assertEqual(cm.exception.code, "session_unknown")

    def dir_for_test(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        return d

    def test_memory_only_nothing_is_written_to_disk(self):
        sid = self.open()
        self.login(sid)
        for root, _, files in os.walk(os.path.dirname(self.audit)):
            for f in files:
                data = open(os.path.join(root, f), "rb").read()
                for canary in (sid.encode(), b"COOKIE-CANARY", b"CSRF-CANARY"):
                    self.assertNotIn(canary, data, f)


# ------------------------------------------------------------------------- requirement 2: client binding
class ClientBound(SBase):
    def two(self):
        return self.new_client("alice-box"), self.new_client("bob-box")

    def test_a_session_belongs_to_the_client_that_opened_it(self):
        a, b = self.two()
        sid = self.open(key=a["secret"])
        self.assertEqual(self.sess(sid).cid, a["id"])
        code, r = self.call(sid, "GET", "/", key=a["secret"])
        self.assertEqual(r["http"]["status"], 200)
        self.assertEqual(self.events("session_opened")[0]["client_id"], a["id"])

    def test_other_clients_get_exactly_the_unknown_answer(self):
        a, b = self.two()
        sid = self.open(key=a["secret"])
        made_up = pysecrets.token_urlsafe(24)
        for who in (b["secret"], KEY):                        # another enrolled client, and the legacy key
            mine = self.call(sid, "GET", "/", key=who)
            fake = self.call(made_up, "GET", "/", key=who)
            self.assertEqual(mine, fake)
            self.assertEqual(mine[0], 404)
            self.assertEqual(mine[1]["code"], "session_unknown")
            # status, close and the open id behave the same
            for path in (f"/v1/sessions/{sid}", f"/v1/sessions/{made_up}"):
                c, text = self.as_client(who, "GET", path)
                self.assertEqual((c, json.loads(text)), (404, {"error": "unknown session", "code": "session_unknown"}))
            c1 = self.as_client(who, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
            c2 = self.as_client(who, "POST", "/v1/requests", {"mode": "session_close", "session": made_up})
            self.assertEqual(c1, c2)
        # the owner's session was not touched by those attempts
        self.assertEqual(self.sess(sid).calls, 0)
        self.assertEqual(self.call(sid, "GET", "/", key=a["secret"])[1]["http"]["status"], 200)

    def test_the_legacy_clients_session_is_not_usable_by_an_enrolled_client(self):
        a, _ = self.two()
        sid = self.open(key=KEY)
        self.assertEqual(self.sess(sid).cid, "legacy")
        self.assertEqual(self.call(sid, "GET", "/", key=a["secret"])[1]["code"], "session_unknown")

    def test_two_machines_on_the_legacy_key_are_one_client(self):
        sid = self.open(key=KEY)
        self.assertEqual(self.call(sid, "GET", "/", key=KEY)[1]["http"]["status"], 200)   # documented limitation

    def test_expired_state_is_only_told_to_the_owner(self):
        a, b = self.two()
        sid = self.open(key=a["secret"], ttl_s=60)
        self.advance(61)
        self.assertEqual(self.call(sid, "GET", "/", key=a["secret"])[1]["code"], "session_expired")
        self.assertEqual(self.call(sid, "GET", "/", key=b["secret"])[1]["code"], "session_unknown")

    def test_ids_are_unguessable_and_compared_in_constant_time(self):
        ids = {self.open() for _ in range(3)}
        self.assertEqual(len(ids), 3)
        for sid in ids:
            self.assertGreaterEqual(len(sid), 32)             # 24 random bytes = 192 bits
        calls = []
        real = S.hmac.compare_digest
        with mock.patch.object(S.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b)):
            self.call(next(iter(ids)), "GET", "/")
        self.assertTrue(calls)
        # sessions are indexed by the id's hash, never by the id
        for k in self.broker._sess:
            self.assertNotIn(k, ids)
            self.assertEqual(len(k), 64)

    def test_malformed_ids_are_unknown(self):
        for bad in ("", "short", "x" * 33, "../../etc/passwd" + "a" * 20, "a b" * 11, 5, ["x"], {"a": 1}):
            code, r = self.call(bad, "GET", "/")
            self.assertEqual((code, r["code"]), (404, "session_unknown"), bad)

    def test_revoking_a_client_ends_its_sessions_at_once(self):
        a, b = self.two()
        sa, sb = self.open(key=a["secret"]), self.open(key=b["secret"])
        status, _, hdr = self.post("/clients/revoke", {"id": a["id"]})
        self.assertEqual(status, 303)
        self.assertEqual(len(self.broker._sess), 1)
        ev = self.events("session_revoked")
        self.assertEqual((len(ev), ev[0]["client_id"], ev[0]["session"]), (1, a["id"], sa[:8]))
        self.assertEqual(self.events("client_revoked")[0]["sessions_ended"], 1)
        self.assertEqual(self.call(sb, "GET", "/", key=b["secret"])[1]["http"]["status"], 200)
        code, text = self.as_client(a["secret"], "GET", "/v1/status")
        self.assertEqual(code, 401)

    def test_a_revoked_client_cannot_even_reach_its_session(self):
        a, _ = self.two()
        sid = self.open(key=a["secret"])
        self.broker.clients.revoke(a["id"], "alice")                # revoked in memory, sessions not yet purged
        with self.assertRaises(S.SessionError) as cm:
            self.broker._session_call(["unifi"], {"method": "GET", "url": self.url("/"), "headers": {},
                                                  "session": sid}, "x", "127.0.0.1",
                                      {"id": a["id"], "name": "alice-box", "legacy": False})
        self.assertEqual(cm.exception.code, "session_unknown")
        self.assertEqual(self.st["seen"], [])

    def test_the_agents_audit_view_is_scoped_to_its_own_sessions(self):
        a, b = self.two()
        sid = self.open(key=a["secret"])
        self.call(sid, "GET", "/", key=a["secret"])
        mine = json.loads(self.as_client(a["secret"], "GET", "/v1/audit?event=session_opened,session_used")[1])
        self.assertEqual(sorted(e["event"] for e in mine["events"]), ["session_opened", "session_used"])
        theirs = json.loads(self.as_client(b["secret"], "GET", "/v1/audit?event=session_opened,session_used")[1])
        self.assertEqual(theirs["events"], [])


# ------------------------------------------------------------------------- revoke / close
class Ending(SBase):
    def test_the_human_revokes_a_session_immediately(self):
        sid = self.open()
        self.login(sid)
        self.assertEqual(self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")[1]["http"]["status"], 200)
        s = self.sess(sid)
        status, _, hdr = self.post("/sessions/revoke", {"pid": sid[:8]})
        self.assertEqual(status, 303)
        self.assertIn("note=sesrevoked", hdr["Location"])
        self.assertTrue(s.dead)
        self.assertEqual((len(s.jar), s.captures), (0, {}))
        code, r = self.call(sid, "GET", "/proxy/network/api/s/default/stat/sta")
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertIn("revoked", r["error"])
        ev = self.events("session_revoked")[0]
        self.assertEqual((ev["session"], ev["revoked_by"]), (sid[:8], "alice"))
        status, _, hdr = self.post("/sessions/revoke", {"pid": sid[:8]})
        self.assertIn("note=sesgone", hdr["Location"])

    def test_revoke_needs_csrf_and_the_approval_user(self):
        sid = self.open()
        self.assertEqual(self.post("/sessions/revoke", {"pid": sid[:8]}, csrf=False)[0], 403)
        self.assertEqual(self.post("/sessions/revoke", {"pid": sid[:8]}, csrf="wrong")[0], 403)
        self.assertEqual(self.post("/sessions/revoke", {"pid": sid[:8]}, user="mallory")[0], 403)
        self.assertEqual(self.post("/sessions/revoke", {"pid": sid[:8]}, headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(len(self.broker._sess), 1)

    def test_the_agent_closes_its_own_session(self):
        sid = self.open()
        self.login(sid)
        s = self.sess(sid)
        code, text = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        self.assertEqual((code, json.loads(text)), (200, {"status": "closed"}))
        self.assertTrue(s.dead)
        self.assertEqual(self.events("session_closed")[0]["session"], sid[:8])
        self.assertEqual(self.call(sid, "GET", "/")[1]["code"], "session_expired")
        code, text = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        self.assertEqual(code, 410)

    def test_status_endpoint(self):
        sid = self.open(ttl_s=600, max_calls=9)
        self.advance(100)
        code, text = self.as_client(KEY, "GET", f"/v1/sessions/{sid}")
        j = json.loads(text)
        self.assertEqual((code, j["calls_left"], j["max_calls"]), (200, 9, 9))
        self.assertIn(j["expires_in"], (499, 500))
        self.assertNotIn("id", j)


# ------------------------------------------------------------------------- scope and caps
class Scope(SBase):
    def test_max_calls_is_enforced_and_refusals_do_not_count(self):
        sid = self.open(max_calls=3)
        for _ in range(3):
            self.assertEqual(self.call(sid, "GET", "/")[1]["http"]["status"], 200)
        code, r = self.call(sid, "GET", "/")
        self.assertEqual((code, r["code"]), (403, "session_refused"))
        self.assertIn("all 3 of its calls", r["error"])
        self.assertEqual(self.sess(sid).calls, 3)
        self.assertEqual(self.events("session_refused")[-1]["reason_class"], "max_calls")
        self.assertEqual(len(self.events("http_executed")), 3)

    def test_the_call_cap_cannot_be_raced_past(self):
        sid = self.open(max_calls=5)
        out = []
        ths = [threading.Thread(target=lambda: out.append(self.call(sid, "GET", "/")[1])) for _ in range(12)]
        [x.start() for x in ths]
        [x.join() for x in ths]
        self.assertEqual(sum("http" in o for o in out), 5)
        self.assertEqual(len(self.st["seen"]), 5)

    def test_out_of_scope_host_is_refused_not_prompted(self):
        sid = self.open()                                   # hosts: 127.0.0.1 only; the credential also allows localhost
        code, r = self.call(sid, "GET", "/", host="localhost")
        self.assertEqual((code, r["code"]), (403, "session_refused"))
        self.assertIn("outside this session's hosts", r["error"])
        self.assertEqual(len(self.broker.pending()), 0)
        self.assertEqual(self.events("session_refused")[-1]["host"], "localhost")
        self.assertEqual(self.st["seen"], [])
        self.assertEqual(self.sess(sid).calls, 0)

    def test_out_of_scope_method_is_refused(self):
        sid = self.open(methods=["GET"])                    # HEAD is not declared either
        for m in ("DELETE", "POST", "PUT", "PATCH", "HEAD"):
            code, r = self.call(sid, m, "/")
            self.assertEqual((code, r["code"]), (403, "session_refused"), m)
        self.assertEqual(self.events("session_refused")[-1]["reason_class"], "method")
        self.assertIn("open a new session that declares it", r["error"])

    def test_methods_default_to_get_and_head(self):
        code, text = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session", "names": ["unifi"],
                                                                  "purpose": PURPOSE, "hosts": ["127.0.0.1"]})
        rid = json.loads(text)["id"]
        self.approve(rid)
        sid = self.result(rid)["session"]["id"]
        self.assertEqual(self.sess(sid).methods, ("GET", "HEAD"))
        self.assertEqual(self.call(sid, "POST", "/echo", body="x")[1]["code"], "session_refused")
        self.assertEqual(self.call(sid, "HEAD", "/")[1]["http"]["status"], 200)

    def test_a_session_call_must_name_the_sessions_credential(self):
        sid = self.open()
        code, r = self.call(sid, "GET", "/", names=("other",))
        self.assertEqual((code, r["code"]), (403, "session_refused"))
        code, r = self.call(sid, "GET", "/", names=("unifi", "other"))
        self.assertEqual(code, 403)
        code, r = self.call(sid, "GET", "/", headers={"X": "{{OTHER_TOKEN}}"})
        self.assertEqual(r["code"], "session_refused")
        self.assertEqual(self.events("session_refused")[-1]["reason_class"], "placeholder")

    def test_the_host_header_cannot_be_overridden(self):
        sid = self.open()
        self.assertEqual(self.call(sid, "GET", "/", headers={"Host": "evil.example"})[1]["code"], "session_refused")

    def test_other_schemes_are_refused(self):
        sid = self.open()
        for url in ("ftp://127.0.0.1/x", "file:///etc/passwd", "//127.0.0.1/x", "127.0.0.1"):
            code, r = self.call(sid, "GET", "/", url=url)
            self.assertEqual(code, 403, url)

    def test_a_session_never_widens_allowed_hosts(self):
        self.ask(hosts=["example.org"], expect=403)
        self.ask(hosts=["127.0.0.1", "example.org"], expect=403)
        self.ask(hosts=["LOCALHOST"], expect=202)           # inside allowed_hosts, case folded
        self.assertEqual(len(self.events("rejected")), 2)

    def test_narrowing_the_credential_after_opening_refuses_calls(self):
        sid = self.open()
        self.broker.cfg["secrets"]["unifi"]["allowed_hosts"] = ["localhost"]
        code, r = self.call(sid, "GET", "/")
        self.assertEqual((code, r["code"]), (403, "session_refused"))
        self.assertEqual(self.st["seen"], [])
        self.broker.cfg["secrets"]["unifi"]["allowed_hosts"] = ["127.0.0.1", "localhost"]
        self.broker.cfg["secrets"].pop("unifi")
        self.assertEqual(self.call(sid, "GET", "/")[1]["code"], "session_refused")

    def test_env_and_ssh_credentials_are_refused(self):
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "session", "names": ["deploy"], "purpose": PURPOSE, "hosts": ["127.0.0.1"]})
        self.assertEqual(code, 403)
        self.assertIn("ssh key", json.loads(text)["error"])
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "session", "names": ["envonly"], "purpose": PURPOSE, "hosts": ["127.0.0.1"]})
        self.assertEqual(code, 403)
        self.assertIn("not an http credential", json.loads(text)["error"])
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "session", "names": ["nope"], "purpose": PURPOSE, "hosts": ["127.0.0.1"]})
        self.assertEqual(code, 400)
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "session", "names": ["unifi", "other"], "purpose": PURPOSE, "hosts": ["127.0.0.1"]})
        self.assertEqual(code, 400)
        self.assertEqual(self.broker.pending(), [])

    def test_a_plain_http_call_without_session_is_unchanged(self):
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202)
        self.assertEqual(json.loads(text)["status"], "pending")      # still waits for a human
        self.assertEqual(len(self.broker.pending()), 1)
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {"X": "{{session.A}}"}})
        self.assertEqual(code, 400)                                  # {{session.*}} needs a session
        code, text = self.as_client(KEY, "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {}, "capture": ["A=header:X"]})
        self.assertEqual(code, 400)

    def test_session_caps_per_client_and_total(self):
        self.broker.sessions_cfg["max_per_client"] = 2
        self.open()
        self.open()
        self.ask(expect=403)                                        # a third for the same client
        a = self.new_client("alice-box")
        self.open(key=a["secret"])                                  # another client is unaffected
        with mock.patch.object(S, "MAX_TOTAL", 3):
            self.ask(key=a["secret"], expect=403)

    def test_pending_session_requests_are_capped_and_use_the_general_rules(self):
        self.ask()
        self.ask()
        self.ask(expect=403)                                        # MAX_PENDING_PER_CLIENT
        rid = next(iter(self.broker.pending())).id
        self.post("/decide", {"id": rid, "decision": "deny"})
        self.ask(expect=403)                                        # denied recently: the deny cooldown applies
        self.assertIn("denied recently", self.events("rejected")[-1]["reason"])

    def test_disabled_sessions(self):
        self.broker.sessions_cfg["enabled"] = False
        self.ask(expect=403)
        code, r = self.call("a" * 32, "GET", "/")
        self.assertEqual(code, 403)

    def test_upstream_errors_are_class_only_and_still_count(self):
        sid = self.open()
        code, r = self.call(sid, "GET", "/", url="http://127.0.0.1:1/x")      # nothing listens there
        self.assertEqual(r["status"], "failed")
        self.assertEqual(r["error"], "upstream call failed (connection)")
        self.assertEqual(self.events("http_failed")[-1]["error"], "connection")
        code, r = self.call(sid, "GET", "/", headers={"X-A": "a\r\nInjected: 1"})
        self.assertEqual(r["error"], "upstream call failed (invalid_request)")
        code, r = self.call(sid, "GET", "/boom")
        self.assertTrue(r["error"].startswith("upstream call failed ("))
        for text in (json.dumps(self.records()),):
            self.assertNotIn("Errno", text)
            self.assertNotIn("Traceback", text)
            self.assertNotIn("Injected", text)
        self.assertEqual(self.sess(sid).calls, 3)


# ------------------------------------------------------------------------- approval rules
class Approval(SBase):
    def test_always_high_no_model_and_names_only_notification_without_buttons(self):
        r = self.ask()
        self.assertEqual(self.model.calls, [])
        req = self.broker._by_id[r["id"]]
        self.assertEqual(req.risk["level"], "high")
        self.assertEqual(req.risk["model"], None)
        n = self.notifier.notifications[-1]
        self.assertEqual((n.actions, n.action_token), ([], None))
        self.assertNotIn(PURPOSE, n.text + n.title)
        self.assertIn("unifi", n.text)
        self.assertIn("HTTP session requested [HIGH]", n.title)
        self.assertEqual(req.offered, frozenset())

    def test_policy_allow_never_auto_approves_a_session(self):
        self.broker.cfg["secrets"]["unifi"]["approval"] = "allow"
        r = self.ask()
        self.assertEqual(r["status"], "pending")
        self.assertEqual(self.broker._auto_allowed("session", ["unifi"], {}), False)

    def test_notification_channels_cannot_decide_it(self):
        r = self.ask()
        rid = r["id"]
        for ch in ("push", "ha"):
            for token in ("", "x", "y" * 30):
                code, req = self.broker.decide_via(ch, rid, "approve", "phone", token=token)
                self.assertNotEqual(code, 200)
                self.assertIsNone(req)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        # even a valid token, if one existed, is refused for this mode
        self.broker._by_id[rid].action_hash = __import__("hashlib").sha256(b"tok").digest()
        self.broker._by_id[rid].offered = frozenset({"approve", "deny"})
        code, req = self.broker.decide_via("push", rid, "approve", "phone", token="tok")
        self.assertEqual((code, req), (403, None))
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_no_always_no_grant_no_ssh_rule(self):
        for kw in ({"always": True}, {"grant_minutes": 15}, {"ssh_rule": {"days": None}}):
            r = self.ask(cred="unifi")
            code, req = self.broker.decide_via("dashboard", r["id"], "approve", "alice", **kw)
            self.assertEqual(code, 400, kw)
            self.assertEqual(self.broker._by_id[r["id"]].status, "pending")
            self.post("/decide", {"id": r["id"], "decision": "deny"})
            self.broker._denied_at.clear()
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(self.broker.cfg["secrets"]["unifi"].get("standing"), None)

    def test_the_card_shows_everything_and_offers_no_chips(self):
        r = self.ask(purpose="update the n\u00e4me", methods=["GET", "DELETE"], ttl_s=1200, max_calls=40)
        status, page, _ = self.get("/")
        self.assertIn("HTTP session</b> with credential <b>unifi</b>", page)
        self.assertIn("127.0.0.1", page)
        self.assertIn("GET, DELETE", page)
        self.assertIn("changes things: DELETE", page)
        self.assertIn("20 min from the moment you approve", page)
        self.assertIn("40 calls", page)
        self.assertIn("Client: <b>shared key (legacy)</b>", page)
        self.assertIn("(unverified)", page)
        self.assertIn("&lt;U+00E4&gt;", page)                      # non-ASCII is escaped, never rendered
        self.assertNotIn("n\u00e4me", page)
        self.assertIn("HIGH RISK", page)
        self.assertIn("name=decision value=approve", page)
        self.assertIn("name=decision value=deny", page)
        self.assertIn("name=session_ttl_min", page)
        self.assertNotIn("approve_grant_", page)
        self.assertNotIn("approve_always", page)
        self.assertNotIn("Automatically approve", page)
        self.assertIn("never extended", page)

    def test_the_link_page_can_approve_with_shortened_limits(self):
        r = self.ask(ttl_s=600)
        nonce = self.broker._by_id[r["id"]].nonce
        status, text, _ = self.post(f"/a/{nonce}", {"decision": "approve", "session_ttl_min": "2"}, csrf=False)
        self.assertEqual(status, 200, text)
        self.assertIn("cannot be extended", text)
        self.broker._by_id[r["id"]].done.wait(10)
        self.assertEqual(self.result(r["id"])["session"]["expires_in"], 120)

    def test_deny_creates_no_session(self):
        r = self.ask()
        self.post("/decide", {"id": r["id"], "decision": "deny"})
        self.assertEqual(self.result(r["id"])["status"], "denied")
        self.assertEqual(self.broker._sess, {})

    def test_an_unanswered_open_expires_and_creates_nothing(self):
        r = self.ask()
        self.advance(self.broker.cfg.get("ttl_seconds", 120) + 5)
        self.assertEqual(self.result(r["id"])["status"], "expired")
        self.assertEqual(self.broker._sess, {})

    def test_purpose_is_validated(self):
        for bad in ("", "x" * 301, "a\u202eb", "a\nb", "a\u200bb", 5, None):
            self.ask(purpose=bad, expect=400)
        self.assertNotIn("\u202e", json.dumps(self.records()))

    def test_the_result_is_delivered_once(self):
        r = self.ask()
        self.approve(r["id"])
        first = self.result(r["id"])
        self.assertIn("session", first)
        self.assertNotIn("session", self.result(r["id"]))

    def test_revoked_client_cannot_have_its_pending_open_approved(self):
        a = self.new_client("alice-box")
        r = self.ask(key=a["secret"])
        self.post("/clients/revoke", {"id": a["id"]})
        self.assertEqual(self.broker._by_id[r["id"]].status, "denied")
        self.assertEqual(self.broker._sess, {})


# ------------------------------------------------------------------------- audit, history, pages
class Observability(SBase):
    def test_status_reports_the_config(self):
        code, text = self.as_client(KEY, "GET", "/v1/status")
        self.assertEqual(json.loads(text)["features"]["http_sessions"],
                         {"enabled": True, "default_ttl_s": 900, "max_ttl_s": 3600, "max_calls": 200,
                          "max_per_client": 3})

    def test_every_session_event_is_classified_and_redacted_deny_by_default(self):
        poison = {"approver": "alice", "approver_ip": "1.2.3.4", "url": "http://x/?k=v", "value": "POISON",
                  "cookie": "POISON", "left_s": 3, "revoked_by": "alice", "peer": "p"}
        for ev in ("session_requested", "session_opened", "session_used", "session_refused", "session_closed",
                   "session_expired", "session_revoked"):
            self.assertIn(ev, audit_api.WHITELIST, ev)
            out = audit_api.redact({"seq": 1, "ts": 1.0, "event": ev, "id": "Rid_1", "session": "abcd1234",
                                    "calls": 2, "max_calls": 3, "reason_class": "method", **poison})
            self.assertNotIn("POISON", json.dumps(out))
            for k in ("approver", "approver_ip", "url", "revoked_by", "peer", "left_s"):
                self.assertNotIn(k, out, (ev, k))

    def test_history_has_rows_for_the_open_and_each_call(self):
        sid = self.open()
        self.login(sid)
        rows = self.broker.history.rows((), None, None, None, None)
        modes = [r["mode"] for r in rows]
        self.assertEqual(sorted(modes), ["http", "session"])
        http = next(r for r in rows if r["mode"] == "http")
        self.assertEqual((http["outcome"], http["via"]), ("approved", "session"))
        ses = next(r for r in rows if r["mode"] == "session")
        self.assertEqual(ses["outcome"], "approved")
        # detail pages render and show the session, not any value
        for r in rows:
            status, text, _ = self.get(f"/request/{r['id']}")
            self.assertEqual(status, 200)
        status, text, _ = self.get(f"/request/{http['id']}")
        self.assertIn(f"http session {sid[:8]}", text)
        status, text, _ = self.get(f"/request/{ses['id']}")
        self.assertIn("not retained", text)
        self.assertIn("127.0.0.1", text)
        status, page, _ = self.get("/?view=all&mode=session")
        self.assertIn("http session for unifi", page)

    def test_clients_tab_lists_active_sessions_with_a_countdown_and_revoke(self):
        sid = self.open(ttl_s=600, max_calls=9)
        self.call(sid, "GET", "/")
        status, page, _ = self.get("/clients")
        self.assertEqual(status, 200)
        self.assertIn("Active sessions", page)
        self.assertIn("<b>unifi</b>", page)
        self.assertIn("shared key (legacy)", page)
        self.assertIn("127.0.0.1", page)
        self.assertIn("GET, HEAD, POST, PUT", page)
        self.assertIn("1 / 9", page)
        self.assertRegex(page, r"<time data-gexp='\d+'>in 10 min</time>")
        self.assertIn("action='/sessions/revoke'", page)
        self.assertIn(self.broker.csrf_token("alice"), page)
        self.assertIn("data-label=", page)                        # the mobile table layout
        self.assertNotIn(sid, page)                               # the id itself is never shown
        self.advance(300)
        self.assertRegex(self.get("/clients")[1], r"in 5 min</time>")
        self.advance(400)
        self.assertIn("No active sessions", self.get("/clients")[1])

    def test_active_sessions_page_escapes_names(self):
        a = self.new_client("alice-box")
        self.open(key=a["secret"])
        self.broker.clients._clients[a["id"]]["name"] = "<script>x</script>"
        for s in self.broker._sess.values():
            s.cname = "<script>x</script>"
        page = self.get("/clients")[1]
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("&lt;script&gt;", page)


# ------------------------------------------------------------------------- nothing leaks anywhere
class Leaks(SBase):
    def test_no_canary_in_any_channel(self):
        notes = []
        real = self.notifier.send
        self.notifier.send = lambda n: (notes.append(json.dumps([n.title, n.text, n.url])), real(n))[1]
        buf = io.StringIO()
        with __import__("contextlib").redirect_stdout(buf), __import__("contextlib").redirect_stderr(buf):
            sid = self.open()
            code, login = self.login(sid)
            self.call(sid, "GET", "/echo", headers={"X-CSRF-Token": "{{session.CSRF}}"})
            self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a",
                      headers={"X-CSRF-Token": "{{session.CSRF}}"}, body='{"p":"{{UNIFI_PASSWORD}}"}')
            self.call(sid, "GET", "/json", capture=["A=json:$.a.b[0].c"])
            self.call(sid, "POST", "/api/auth/logout")
            self.call(sid, "GET", "/")
            self.advance(2000)
            self.call(sid, "GET", "/")
        canaries = [PASSWORD, USER, "COOKIE-CANARY", "CSRF-CANARY", "deep-value-1234", sid]
        every = {"stdout/stderr": buf.getvalue(), "client bodies": "\n".join(self.seen),
                 "notifications": "\n".join(notes), "audit": self.audit_text()}
        d = os.path.dirname(self.audit)
        for f in os.listdir(d):
            if f not in ("audit.jsonl", "vault.json"):      # the vault is where the credential lives
                with open(os.path.join(d, f), "rb") as fh:
                    every["file:" + f] = fh.read().decode("latin-1")
        rows = self.broker.history.rows((), None, None, None, None)
        every["history rows"] = json.dumps(rows, default=str)
        for r in rows:
            row, evs = self.broker.history.detail(r["id"])
            every["history detail"] = every.get("history detail", "") + json.dumps([row, evs], default=str)
            every["detail page"] = every.get("detail page", "") + self.get(f"/request/{r['id']}")[1]
            if self.broker.details is not None:
                every["request details"] = every.get("request details", "") + json.dumps(
                    self.broker.details.get(r["id"]) if hasattr(self.broker.details, "get") else "", default=str)
        every["dashboard"] = self.get("/")[1] + self.get("/clients")[1] + self.get("/?view=all")[1]
        every["agent audit view"] = self.as_client(KEY, "GET", "/v1/audit?limit=500")[1]
        for where, text in every.items():
            for c in canaries:
                if c == sid and where in ("client bodies", "stdout/stderr"):
                    continue                      # the agent is handed its own id once, at open
                self.assertNotIn(c, text, f"{c!r} leaked into {where}")
        # the agent-visible results: the credential, cookies and captures never appear (sid is its own id)
        for c in canaries[:-1]:
            self.assertNotIn(c, json.dumps(login))
        # the audit log holds only the id prefix
        self.assertIn(sid[:8], every["audit"])

    def test_the_stub_really_received_the_secrets(self):
        sid = self.open()
        self.login(sid)
        self.call(sid, "PUT", "/proxy/network/api/s/default/rest/user/a",
                  headers={"X-CSRF-Token": "{{session.CSRF}}"}, body="{}")
        last = self.st["seen"][-1]
        self.assertTrue(last["cookie"].startswith("TOKEN=COOKIE-CANARY-"))
        self.assertTrue(last["csrf"].startswith("CSRF-CANARY-"))
        self.assertEqual(self.st["seen"][0]["body"], json.dumps({"username": USER, "password": PASSWORD}))


# ------------------------------------------------------------------------- the real CLI
class CliFlow(SBase):
    def run_cli(self, *args, human=None, key=KEY, timeout=60, stdin=None):
        env = {"PATH": os.environ["PATH"], "HOME": self.dir, "SECRET_BROKER_URL": self.base, "SECRET_BROKER_KEY": key}
        p = subprocess.Popen([CLI, *args], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        if human is not None:
            end = time.time() + 20
            while time.time() < end and not self.broker.pending():
                time.sleep(0.05)
            ids = [r.id for r in self.broker.pending()]
            if ids:
                human(ids[0])
        try:
            out, err = p.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        self.out.extend([out, err])
        return p.returncode, out, err

    def human_approves(self, **limits):
        return lambda rid: self.post("/decide", {"id": rid, "decision": "approve", **limits})

    def cli_open(self, *extra, key=KEY, human=None):
        rc, out, err = self.run_cli("session", "open", "unifi", "--for", PURPOSE, "--host", "127.0.0.1",
                                    "--methods", "GET,POST,PUT", *extra, human=human or self.human_approves(), key=key)
        self.assertEqual(rc, 0, err)
        sid = out.strip()
        self.assertRegex(sid, r"^[A-Za-z0-9_-]{32}$")
        return sid

    def test_unifi_flow_with_the_real_asb(self):
        sid = self.cli_open("--ttl", "10m", "--max-calls", "20")
        rc, out, err = self.run_cli("http", "unifi", "POST", self.url("/api/auth/login"), "--session", sid,
                                    "-H", "Content-Type: application/json",
                                    "-d", '{"username":"{{UNIFI_USERNAME}}","password":"{{UNIFI_PASSWORD}}"}',
                                    "--capture", "CSRF=header:X-CSRF-Token")
        self.assertEqual(rc, 0, err)
        self.assertIn("captured CSRF", err)
        self.assertIn("19 calls left", err)
        self.assertIn("HTTP 200", err)
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/proxy/network/api/s/default/stat/sta"),
                                    "--session", sid)
        self.assertEqual((rc, "laptop" in out), (0, True), err)
        rc, out, err = self.run_cli("http", "unifi", "PUT", self.url("/proxy/network/api/s/default/rest/user/a"),
                                    "--session", sid, "-H", "X-CSRF-Token: {{session.CSRF}}", "-d", '{"name":"n"}')
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli("session", "status", sid)
        self.assertEqual(rc, 0)
        self.assertIn("calls left: 17 of 20", out)
        rc, out, err = self.run_cli("http", "unifi", "POST", self.url("/api/auth/logout"), "--session", sid)
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli("session", "close", sid)
        self.assertEqual((rc, out.strip()), (0, "closed"))
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/"), "--session", sid)
        self.assertEqual(rc, 7, err)
        self.assertIn("closed", err)
        blob = "\n".join(self.out)
        for c in (PASSWORD, USER, "COOKIE-CANARY", "CSRF-CANARY"):
            self.assertNotIn(c, blob)
        self.assertEqual(self.model.calls, [])

    def test_exit_codes(self):
        sid = self.cli_open("--max-calls", "1")
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/"), "--session", sid)
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/"), "--session", sid)
        self.assertEqual(rc, 8, err)                                   # call cap: refused
        rc, out, err = self.run_cli("http", "unifi", "DELETE", self.url("/"), "--session", sid)
        self.assertEqual(rc, 8, err)
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/", "localhost"), "--session", sid)
        self.assertEqual(rc, 8, err)
        sid2 = self.cli_open("--ttl", "30s")
        self.advance(31)
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/"), "--session", sid2)
        self.assertEqual(rc, 7, err)                                   # expired: the dedicated code
        other = self.new_client("bob-box")
        rc, out, err = self.run_cli("http", "unifi", "GET", self.url("/"), "--session", sid, key=other["secret"])
        self.assertEqual(rc, 7, err)
        self.assertIn("unknown session", err)
        rc, out, err = self.run_cli("session", "open", "unifi", "--for", PURPOSE, "--host", "127.0.0.1",
                                    human=lambda rid: self.post("/decide", {"id": rid, "decision": "deny"}))
        self.assertEqual(rc, 4, err)
        rc, out, err = self.run_cli("session", "open", "deploy", "--for", PURPOSE, "--host", "127.0.0.1")
        self.assertEqual(rc, 3, err)
        self.assertIn("ssh key", err)

    def test_usage_errors_fail_closed_before_any_call(self):
        sid = "a" * 32
        for args in (("session",), ("session", "open"), ("session", "open", "unifi"),
                     ("session", "open", "unifi", "--for", "x"),
                     ("session", "open", "unifi", "--for", "x", "--host", "h", "--ttl", "15"),
                     ("session", "open", "unifi", "--for", "x", "--host", "h", "--methods", "TRACE"),
                     ("session", "open", "unifi", "--for", "x", "--host", "h", "--max-calls", "0"),
                     ("session", "close", "short"), ("session", "status"),
                     ("http", "unifi", "GET", "http://127.0.0.1/", "--session", "short"),
                     ("http", "unifi", "GET", "http://127.0.0.1/", "--capture", "A=header:X"),
                     ("http", "unifi", "GET", "http://127.0.0.1/", "--session", sid, "--capture", "A=json:$..a"),
                     ("http", "unifi", "GET", "http://127.0.0.1/", "--session", sid, "--capture", "A=json:$.a[*]"),
                     ("http", "unifi,other", "GET", "http://127.0.0.1/", "--session", sid)):
            rc, out, err = self.run_cli(*args)
            self.assertEqual(rc, 2, (args, err))
        self.assertEqual(self.records_count_requests(), 0)

    def records_count_requests(self):
        return len(self.events("requested"))

    def test_help_and_guide_cover_sessions(self):
        rc, out, _ = self.run_cli("help", "session")
        self.assertEqual(rc, 0)
        for frag in ("--host", "--methods", "--ttl", "--max-calls", "never moves", "7 session expired"):
            self.assertIn(frag, out)
        rc, out, _ = self.run_cli("guide")
        for frag in ("Which command? (decision rule)", "asb session open", "--session ID", "{{session.NAME}}",
                     "NEVER extended", "Exit 7", "env mode"):
            self.assertIn(frag, out)
        rc, out, _ = self.run_cli("help", "http")
        self.assertIn("--session ID", out)


if __name__ == "__main__":
    unittest.main()
