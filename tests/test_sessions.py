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


if __name__ == "__main__":
    unittest.main()
