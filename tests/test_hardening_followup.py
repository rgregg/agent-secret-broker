"""Second-round hardening (independent review findings): fail-closed approval listener, proxy secret,
Origin on the JSON endpoints, own_ports, header rules, collapsed guard refusals, extra blocked ranges,
one masker (encoded echoes and the cut), newline stripping, Set-Cookie, sanitised error text,
operator-client proxy handling.

Every secret, address and name here is fake; every server is a loopback stub or an in-process fake.
"""
import base64
import email.message
import io
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
import test_destination_guard as tdg  # noqa: E402
import test_e2e as t  # noqa: E402
import test_leak_regression as lr  # noqa: E402
import test_sessions as ts  # noqa: E402
import plan_base as pb  # noqa: E402
from secret_broker import destguard, masking  # noqa: E402
from secret_broker import request_details as details_mod  # noqa: E402
from secret_broker.destguard import DestGuard, DestinationRefused  # noqa: E402

SECRET = "ab/cd+ef=gh-Token-8f3a21"


class Resp:
    def __init__(self, body=b"", status=200, headers=()):
        self.status = status
        self.headers = email.message.Message()
        for k, v in headers:
            self.headers.add_header(k, v)
        self._b = io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    read1 = read

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class FakeOpener:
    def __init__(self, make):
        self.make, self.seen = make, []

    def open(self, req, timeout=None):
        self.seen.append(req)
        return self.make(req)


def patched(fo):
    return mock.patch("secret_broker.broker._opener_for", lambda tls, *a, **k: fo)


# ---------------------------------------------------------------------------------------- masker
class MaskerUnit(unittest.TestCase):
    def test_every_spelling_is_masked(self):
        v = SECRET
        spellings = {
            "raw": v, "json": json.dumps(v)[1:-1].replace("/", "\\/"), "quote": urllib.parse.quote(v, safe=""),
            "quote_plus": urllib.parse.quote_plus(v), "lower": v.lower(), "upper": v.upper(),
            "hex": v.encode().hex(), "b64": base64.b64encode(v.encode()).decode(),
            "b64 no pad": base64.b64encode(v.encode()).decode().rstrip("="),
            "b64 url": base64.urlsafe_b64encode(v.encode()).decode(),
            "b64 bearer": base64.b64encode(b"Bearer " + v.encode()).decode(),
        }
        m = masking.Masker([v])
        for name, text in spellings.items():
            out = m.mask("before " + text + " after")
            self.assertEqual(out, "before *** after", name)

    def test_each_line_of_a_multi_line_value(self):
        pem = "-----BEGIN KEY-----\nMIIEvQIBADANBgkq\nhkiG9w0BAQEFAASC\n-----END KEY-----\n"
        m = masking.Masker([pem])
        for line in ("MIIEvQIBADANBgkq", "hkiG9w0BAQEFAASC"):
            self.assertNotIn(line, m.mask("x " + line + " y"))

    def test_short_values_are_not_masked(self):
        self.assertEqual(masking.Masker(["abc", "", None]).mask("abc abc"), "abc abc")
        self.assertIn("***", masking.Masker(["abcd"]).mask("xx abcd"))

    def test_tail_prefix(self):
        m = masking.Masker([SECRET])
        self.assertEqual(m.mask_tail("AAAA " + SECRET[:7]), "AAAA ***")
        self.assertEqual(m.mask_tail("AAAA " + SECRET[:3]), "AAAA " + SECRET[:3])     # under 4: left alone

    def test_one_trailing_newline(self):
        f = masking.strip_one_newline
        self.assertEqual((f("tok\n"), f("tok\r\n"), f("tok\n\n"), f("tok")), ("tok", "tok", "tok\n", "tok"))


# ---------------------------------------------------------------------------- plain http mode
class HttpMasking(lr.HttpBase):
    value = SECRET

    def reply(self, body, headers=()):
        fo = FakeOpener(lambda req: Resp(body, 200, headers))
        with patched(fo):
            code, got, rid = self.go()
        return got, fo

    def test_echoed_spellings_never_reach_the_agent(self):
        v = SECRET
        for name, text in {"json": json.dumps(v)[1:-1].replace("/", "\\/"), "quote": urllib.parse.quote(v, safe=""),
                           "b64": base64.b64encode(("Bearer " + v).encode()).decode(), "hex": v.encode().hex(),
                           "upper": v.upper()}.items():
            got, _ = self.reply(("echo:" + text).encode())
            self.assertEqual(got["http"]["body"], "echo:***", name)
        self.assert_no_leak(SECRET)

    def test_padded_echo_at_every_offset_around_the_cut(self):
        cut = 3000
        with mock.patch("secret_broker.broker.MAX_RESPONSE_BYTES", cut):
            for k in range(-3, len(SECRET) + 4):
                got, _ = self.reply(b"A" * (cut - k) + SECRET.encode() + b"B" * 40)
                body = got["http"]["body"]
                self.assertNotIn(SECRET[:4], body, k)
                self.assertLessEqual(len(body.encode()), cut, k)

    def test_set_cookie_is_not_returned_in_plain_http_mode(self):
        got, _ = self.reply(b"ok", [("Set-Cookie", "sid=cookie-canary-1; Path=/"), ("X-Other", "yes")])
        self.assertEqual({k.lower() for k in got["http"]["headers"]}, {"x-other"})

    def test_a_trailing_newline_is_not_sent(self):
        self.broker.backend._data["Svc"]["token"] = SECRET + "\n"
        got, fo = self.reply(b"ok")
        self.assertEqual(fo.seen[0].get_header("Authorization"), "Bearer " + SECRET)
        # env mode keeps the stored value exactly
        code, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["env"]["SVC_TOKEN"], SECRET + "\n")

    def test_a_multi_line_value_is_masked_per_line_in_a_body_echo(self):
        self.broker.backend._data["Svc"]["token"] = "first-line-secret-AAAA\nsecond-line-secret-BBBB"
        fo = FakeOpener(lambda req: Resp(b"saw second-line-secret-BBBB here"))
        with patched(fo):
            code, got, rid = self.go(headers={}, **{"body": "{{SVC_TOKEN}}", "method": "POST"})
        self.assertEqual(got["http"]["body"], "saw *** here")


# --------------------------------------------------------------------------------- header rules
class HeaderRules(tdg.StrictHarness):
    names = {"lan.example": ["10.9.8.7"], "pub.example": ["93.184.216.34"]}

    def route(self):
        return {("10.9.8.7", 80): self.sport, ("93.184.216.34", 80): self.sport}

    def refused(self, headers, url="http://lan.example/x"):
        code, body = self.call(url, headers=headers)
        self.assertEqual(code, 400, (headers, body))

    def test_forbidden_headers(self):
        for h in ("Content-Length", "transfer-encoding", "Connection", "Cookie", "Upgrade", "TE", "Proxy-Authorization",
                  "proxy-connection", "X-Secret-Broker-Egress", "x-secret-broker-anything", "Trailer", "Expect"):
            self.refused({h: "1"})

    def test_host_must_equal_the_url_authority(self):
        self.refused({"Host": "evil.example"})
        self.refused({"Host": "lan.example:8080"})
        self.refused({"Host": "lan.example@evil"})
        self.refused({"Host": "{{SVC_TOKEN}}"})
        for ok in ("lan.example", "LAN.Example", "lan.example:80"):
            code, body = self.call("http://lan.example/x", headers={"Host": ok})
            self.assertEqual(code, 202, (ok, body))
            self.drop_pending()
        code, body = self.call("https://lan.example:443/x", headers={"host": "lan.example"})
        self.assertEqual(code, 202)

    def drop_pending(self):
        for r in self.broker._by_id.values():
            if r.status == "pending":
                r.status = "expired"

    def test_case_insensitive_duplicates(self):
        self.refused({"X-A": "1", "x-a": "2"})

    def test_error_text_is_clipped_and_ascii(self):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "POST", "url": "http://lan.example/x", "headers": {},
            "body": "{{" + "\x1b[31m‮" + "Z" * 500 + "}}"})
        self.assertEqual(code, 400)
        err = json.loads(body)["error"]
        self.assertTrue(err.isascii() and err.isprintable() and len(err) <= 200, err)
        rej = self.events("rejected")[-1]["reason"]
        self.assertTrue(rej.isascii() and rej.isprintable() and len(rej) <= 200, rej)


class SessionAndPlanHostHeader(ts.SBase):
    def test_session_refuses_host_and_framing_headers(self):
        sid = self.open()
        for h in ("Host", "Content-Length", "Transfer-Encoding", "Connection", "Cookie", "X-Secret-Broker-Egress"):
            code, r = self.call(sid, "GET", "/x", headers={h: "x"})
            self.assertNotEqual(r.get("status"), "approved", h)
            self.assertIn("error", r, h)
        self.assertEqual(self.st["seen"], [])


class PlanHostHeader(pb.PBase):
    def test_plan_refuses_host_header(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        for h in ("Host", "Content-Length", "Connection", "Cookie", "X-Secret-Broker-Egress"):
            code, r = self.call(pid, "svc", "GET", "/v1/accounts/1", headers={h: "x"})
            self.assertNotEqual((r or {}).get("status"), "approved", h)
        self.assertEqual(self.upstream(), [])


# ------------------------------------------------------------------- sessions and plans: the cut
class SessionCut(ts.SBase):
    def test_padded_echo_and_encoded_echo(self):
        sid = self.open()
        cut = 4000
        secret = ts.PASSWORD
        with mock.patch("secret_broker.sessions.READ_LIMIT", cut):
            for k in range(-3, len(secret) + 4):
                fo = FakeOpener(lambda req, k=k: Resp(b"A" * (cut - k) + secret.encode() + b"B" * 40))
                with patched(fo):
                    code, r = self.call(sid, "GET", "/echo")
                body = r["http"]["body"]
                self.assertNotIn(secret[:4], body, k)
        fo = FakeOpener(lambda req: Resp(urllib.parse.quote(secret, safe="").encode() + b" " + secret.upper().encode()))
        with patched(fo):
            code, r = self.call(sid, "GET", "/echo")
        self.assertEqual(r["http"]["body"], "*** ***")

    def test_trailing_newline_is_not_sent_in_a_session(self):
        self.broker.backend._data["Spacecred"]["token"] = "tok-session-newline\n"
        sid = self.open(cred="spacecred")
        fo = FakeOpener(lambda req: Resp(b"ok"))
        with patched(fo):
            self.call(sid, "GET", "/echo", names=("spacecred",), headers={"X-CSRF-Token": "{{SPACECRED_TOKEN}}"})
        self.assertEqual(fo.seen[0].get_header("X-csrf-token"), "tok-session-newline")


class PlanCut(pb.PBase):
    def test_padded_echo_at_every_offset(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        cut = 3000
        secret = pb.SVC_VALUE
        with mock.patch("secret_broker.broker.MAX_RESPONSE_BYTES", cut):
            for k in range(-3, len(secret) + 4):
                fo = FakeOpener(lambda req, k=k: Resp(b"A" * (cut - k) + secret.encode() + b"B" * 40))
                with patched(fo):
                    code, r = self.call(pid, "svc", "GET", "/v1/accounts/1")
                self.assertNotIn(secret[:4], json.dumps(r), k)

    def test_set_cookie_not_returned(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        fo = FakeOpener(lambda req: Resp(b"ok", 200, [("Set-Cookie", "a=b-canary-cookie")]))
        with patched(fo):
            code, r = self.call(pid, "svc", "GET", "/v1/accounts/1")
        self.assertNotIn("canary-cookie", json.dumps(r))


# ------------------------------------------------------------------ guard refusals look like failures
class CollapsedRefusals(ts.SBase):
    def test_session_refusal_is_a_plain_connection_failure(self):
        sid = self.open()
        self.broker.dest_guard.deny = [ipaddress.ip_network("127.0.0.0/8")]
        code, r = self.call(sid, "GET", "/")
        self.assertEqual(r["error"], "upstream call failed (connection)")
        ev = [e for e in self.audit_events() if e["event"] == "http_failed"][-1]
        self.assertEqual((ev["error"], ev["reason_class"]), ("connection", "destination not allowed"))
        agent = self.as_client(ts.KEY, "GET", "/v1/audit?limit=500")[1]
        self.assertNotIn("destination", agent)

    def audit_events(self):
        return [json.loads(line) for line in open(self.audit) if line.strip()]


class CollapsedPlanRefusals(pb.PBase):
    def test_plan_refusal_is_a_plain_connection_failure(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        self.broker.dest_guard.deny = [ipaddress.ip_network("127.0.0.0/8")]
        code, r = self.call(pid, "svc", "GET", "/v1/accounts/1")
        self.assertEqual(r["error"], "release failed: connection")


class GuardRanges(unittest.TestCase):
    def test_extra_blocked_ranges(self):
        g = tdg.strict_guard()
        for a in ("0:0:0:0:ffff:0:102:304", "64:ff9b:1::1", "64:ff9b:1:ffff::1",
                  "::5efe:7f00:1", "fe80::200:5efe:7f00:1", "2001:db8::200:5efe:a9fe:a9fe",
                  "192.0.0.192", "168.63.129.16", "::ffff:8.8.8.8"):
            with self.assertRaises(DestinationRefused, msg=a):
                g.resolve(a, 80)
        self.assertEqual(g.resolve("2001:db8::1", 80), ["2001:db8::1"])

    def test_own_ports_config(self):
        g = DestGuard.from_config({"own_ports": [9443]}, resolver=tdg.no_dns, local_addrs=lambda: set())
        for ip in ("10.1.2.3", "172.17.0.1", "192.168.5.5"):
            with self.assertRaises(DestinationRefused):
                g.resolve(ip, 9443)
        self.assertEqual(g.resolve("8.8.8.8", 9443), ["8.8.8.8"])
        for bad in ([0], [70000], ["80"], [True], "8801", [1] * 40):
            with self.assertRaises(ValueError, msg=str(bad)):
                DestGuard.from_config({"own_ports": bad})
        DestGuard.from_config({"own_ports": None})

    def test_null_ports_in_the_config_are_defaults(self):
        from secret_broker.broker import Broker
        from secret_broker.backends import MemoryBackend
        from secret_broker.notify import FakeNotifier
        b = Broker({"client_port": None, "approval_port": None, "allowed_user": "a", "approve_base_url": "https://x"},
                   MemoryBackend(), FakeNotifier(on_send=lambda u: None),
                   os.path.join(tempfile.mkdtemp(), "a.jsonl"))
        self.assertTrue({8800, 8801} <= b.dest_guard.own_ports)

    def test_serve_registers_the_real_bound_ports(self):
        # (StrictHarness does not register them by hand any more)
        pass


class BoundPorts(tdg.StrictHarness):
    def test_the_real_ports_are_own_ports(self):
        self.assertTrue({self.a.server_address[1], self.c.server_address[1]} <= self.guard.own_ports)


# ------------------------------------------------------------------------ the approval listener
class ListenerSecret(tdg.StrictHarness):
    def setUp(self):
        self.secret_file = os.path.join(tempfile.mkdtemp(), "s")
        with open(self.secret_file, "w") as f:
            f.write("proxy-secret-0123456789abcdef\n")
        self.cfg_extra = {"approval_trust_any_peer": True, "approval_proxy_secret_file": self.secret_file}
        super().setUp()

    def hit(self, headers=None, path="/", base=None):
        r = urllib.request.Request((base or self.abase) + path, headers={"X-authentik-username": "alice",
                                                                         **(headers or {})})
        try:
            return urllib.request.urlopen(r, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_every_request_needs_the_secret(self):
        self.assertEqual(self.hit(), 403)
        self.assertEqual(self.hit({"X-ASB-Proxy-Secret": "wrong-secret-0123456789"}), 403)
        self.assertEqual(self.hit({"X-ASB-Proxy-Secret": "proxy-secret-0123456789abcdef"}), 200)
        self.assertEqual(self.hit(path="/manifest.webmanifest"), 403)

    def test_the_secret_never_appears_anywhere(self):
        self.hit({"X-ASB-Proxy-Secret": "wrong-guess"})
        self.assertNotIn("proxy-secret-0123456789abcdef", open(self.audit).read())
        self.assertNotIn("proxy-secret", json.dumps(self.broker.status()))
        self.assertTrue(self.events("approval_forbidden"))

    def test_secret_alone_is_valid_for_a_non_loopback_peer(self):
        self.broker.cfg.pop("approval_trust_any_peer")
        self.assertTrue(self.broker.peer_trusted("10.1.2.3"))
        self.assertTrue(self.broker.peer_trusted("100.64.1.2"))
        self.assertFalse(self.broker.peer_trusted("127.0.0.1"))
        self.assertFalse(self.broker.peer_trusted(tdg.OWN))
        self.assertTrue(self.broker.listener_open())

    def test_secret_plus_peer_list_needs_both(self):
        self.broker.cfg.pop("approval_trust_any_peer")
        self.broker.cfg["approval_trusted_peers"] = ["100.64.0.0/10"]
        self.assertTrue(self.broker.peer_trusted("100.64.1.2"))
        self.assertFalse(self.broker.peer_trusted("10.1.2.3"))
        self.assertTrue(self.broker.proxy_secret_ok({"X-ASB-Proxy-Secret": "proxy-secret-0123456789abcdef"}))
        self.assertFalse(self.broker.proxy_secret_ok({}))

    def test_an_agent_cannot_send_or_read_it(self):
        # an agent-supplied header of that name is dropped on the way out, and any echo is masked
        sent = []

        def make(req):
            sent.append({k.lower(): v for k, v in req.header_items()})
            return Resp(b"echo proxy-secret-0123456789abcdef " + base64.b64encode(b"proxy-secret-0123456789abcdef"))
        guard = self.broker.dest_guard
        self.assertEqual(guard.strip_headers, ("X-ASB-Proxy-Secret",))
        self.guard._resolver = lambda h, p: ["93.184.216.34"]
        from secret_broker import broker as bm
        req = urllib.request.Request("http://pub.example/x", headers={"X-ASB-Proxy-Secret": "guess"})
        fo = FakeOpener(make)
        out = None
        with patched(fo):
            out = bm._exchange(req, [], None, guard=guard)
        self.assertNotIn("proxy-secret-0123456789abcdef", out["body"])
        self.assertEqual(out["body"].count("***"), 2)
        # the real opener removes the header before connecting
        op = guard.opener()
        names = []
        for h in op.handlers:
            if hasattr(h, "http_open"):
                real = h

        class Probe(urllib.request.Request):
            pass
        r2 = urllib.request.Request("http://pub.example/x", headers={"X-asb-proxy-secret": "guess"})
        destguard._mark(r2, guard.strip_headers)
        self.assertNotIn("x-asb-proxy-secret", {k.lower() for k in r2.headers})
        self.assertEqual(r2.unredirected_hdrs.get("X-secret-broker-egress"), "1")


class ListenerSecretBad(tdg.StrictHarness):
    def setUp(self):
        d = tempfile.mkdtemp()
        short = os.path.join(d, "short")
        open(short, "w").write("tiny\n")
        self.cfg_extra = {"approval_proxy_secret_file": short}
        super().setUp()

    def test_a_bad_secret_is_an_error_not_a_crash_and_the_listener_stays_closed(self):
        self.assertTrue([e for e in self.events("config_error") if "approval_proxy_secret_file" in e["error"]])
        self.assertFalse(self.broker.listener_open())
        self.assertFalse(self.broker.peer_trusted("10.1.2.3"))

    def test_missing_file(self):
        secret, header, errs = self.broker._load_proxy_secret({"approval_proxy_secret_file": "/nonexistent/x",
                                                               "approval_proxy_secret_header": "bad header"})
        self.assertIsNone(secret)
        self.assertEqual(len(errs), 2)


class OriginRequired(tdg.StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True}

    def post(self, path, body, headers=None):
        h = {"X-authentik-username": "alice", "X-Requested-With": "asb", "Content-Type": "application/json",
             **(headers or {})}
        r = urllib.request.Request(self.abase + path, data=json.dumps(body).encode(), headers=h, method="POST")
        try:
            return urllib.request.urlopen(r, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_missing_origin_is_refused_on_all_three(self):
        for path, body in (("/presence", {"v": True, "tab": "abc"}), ("/push/event", {"event": "x"}),
                           ("/push/decide", {"decision": "approve", "token": "x", "rid": "y"})):
            self.assertEqual(self.post(path, body), 403, path)
            self.assertNotEqual(self.post(path, body, {"Origin": "https://secrets.example"}), 403, path)
            self.assertEqual(self.post(path, body, {"Origin": "https://evil.example"}), 403, path)
            self.assertEqual(self.post(path, body, {"Origin": "null"}), 403, path)

    def test_service_worker_and_page_posts_are_same_origin_fetches(self):
        # the page and the worker post with fetch(..., {method:'POST', credentials:'same-origin'}): a browser
        # always attaches Origin to a same-origin POST. None of them uses mode:'no-cors' or omits credentials.
        src = open(os.path.join(os.path.dirname(__file__), "..", "secret_broker", "broker.py")).read()
        for m in re.finditer(r"fetch\('(/push/decide|/presence|/push/event)'[^;]{0,200}", src):
            self.assertNotIn("no-cors", m.group(0))
            self.assertIn("method:'POST'", m.group(0))


class CookieSecure(tdg.StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True, "approve_base_url": "http://secrets.example"}

    def cookie(self, headers=None):
        self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["true"]})
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice", **(headers or {})})
        return urllib.request.urlopen(r, timeout=10).headers.get_all("Set-Cookie")[0]

    def test_secure_follows_the_forwarded_proto_from_a_trusted_peer(self):
        self.assertNotIn("Secure", self.cookie())
        self.assertIn("Secure", self.cookie({"X-Forwarded-Proto": "https"}))
        self.assertNotIn("Secure", self.cookie({"X-Forwarded-Proto": "http"}))


# ------------------------------------------------------------------- operator-configured clients
class OperatorClients(unittest.TestCase):
    def test_no_client_uses_the_environment_proxy(self):
        import secret_broker as pkg
        root = os.path.dirname(pkg.__file__)
        for f in ("description.py", "summarize.py", "notify.py", "riskmodel.py", os.path.join("backends", "bitwarden.py")):
            self.assertNotIn("urllib.request.urlopen(", open(os.path.join(root, f)).read(), f)

    def test_operator_urlopen_ignores_proxy_env_and_marks_the_call(self):
        seen = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        env = {"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9", "NO_PROXY": ""}
        with mock.patch.dict(os.environ, env):
            r = destguard.operator_urlopen(urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/x"),
                                           timeout=5)
            self.assertEqual(r.read(), b"ok")
        self.assertEqual({k.lower(): v for k, v in seen[0].items()}["x-secret-broker-egress"], "1")


class DisplaySanitising(unittest.TestCase):
    def test_bidi_and_zero_width_are_replaced_in_the_card(self):
        v = details_mod.build_view({"method": "POST", "url": "http://127.0.0.1/x",
                                    "headers": {"X-A": "a‮b​c⁦d"},
                                    "body": "txt ‮ evil ​ zero ⁠ joiner", "body_b64": None})
        page = details_mod.html(v)
        for ch in ("‮", "​", "⁦", "⁠"):
            self.assertNotIn(ch, page)
        self.assertEqual(v["headers"][0][1].count("?"), 3)


# ------------------------------------------------------------------------------ trusted_proxies
def broker_with(proxies, local=(tdg.OWN,), **extra):
    from secret_broker.broker import Broker
    from secret_broker.backends import MemoryBackend
    from secret_broker.notify import FakeNotifier
    g = tdg.strict_guard(local=local)
    cfg = {"allowed_user": "a", "approve_base_url": "https://x", "trusted_proxies": proxies, **extra}
    return Broker(cfg, MemoryBackend(), FakeNotifier(on_send=lambda u: None),
                  os.path.join(tempfile.mkdtemp(), "a.jsonl"), dest_guard=g)


class EffectiveAddress(unittest.TestCase):
    def test_off_by_default_and_untrusted_peers_are_never_believed(self):
        b = broker_with(None)
        self.assertEqual(b.effective_addr("10.0.0.100", "1.2.3.4"), "10.0.0.100")
        b = broker_with(["10.0.0.100/32"])
        self.assertEqual(b.effective_addr("10.0.0.7", "1.2.3.4"), "10.0.0.7")      # spoof from an untrusted peer
        self.assertEqual(b.effective_addr("8.8.8.8", "1.2.3.4"), "8.8.8.8")

    def test_single_client(self):
        b = broker_with(["10.0.0.100/32"])
        self.assertEqual(b.effective_addr("10.0.0.100", "10.0.1.77"), "10.0.1.77")

    def test_walks_from_the_right_and_skips_trusted_hops(self):
        b = broker_with(["10.0.0.0/24"])
        self.assertEqual(b.effective_addr("10.0.0.100", "9.9.9.9, 1.2.3.4, 10.0.0.101"), "1.2.3.4")
        self.assertEqual(b.effective_addr("10.0.0.100", "1.2.3.4, 10.0.0.101, 10.0.0.102"), "1.2.3.4")
        # the leftmost value is never taken when something untrusted sits to its right
        self.assertEqual(b.effective_addr("10.0.0.100", "6.6.6.6, 7.7.7.7"), "7.7.7.7")

    def test_garbage_falls_back_to_the_socket_peer(self):
        b = broker_with(["10.0.0.100/32"])
        for xff in ("", "garbage", "1.2.3.4, garbage", "999.1.1.1", "1.2.3.4:80", "-", "1.2.3.4/32", None):
            self.assertEqual(b.effective_addr("10.0.0.100", xff), "10.0.0.100", xff)
        b = broker_with(["10.0.0.0/24"])
        self.assertEqual(b.effective_addr("10.0.0.100", "10.0.0.5, 10.0.0.6"), "10.0.0.100")   # nothing untrusted

    def test_ipv6_and_mapped_forms(self):
        b = broker_with(["10.0.0.100/32", "2001:db8:1::/48"])
        self.assertEqual(b.effective_addr("10.0.0.100", "2001:db8::5"), "2001:db8::5")
        self.assertEqual(b.effective_addr("10.0.0.100", "[2001:db8::5]"), "2001:db8::5")
        self.assertEqual(b.effective_addr("10.0.0.100", "::ffff:1.2.3.4"), "1.2.3.4")
        self.assertEqual(b.effective_addr("::ffff:10.0.0.100", "1.2.3.4"), "1.2.3.4")        # mapped peer
        self.assertEqual(b.effective_addr("2001:db8:1::9", "1.2.3.4, 2001:db8:1::8"), "1.2.3.4")

    def test_loopback_and_own_peers_are_ignored_in_strict_mode(self):
        b = broker_with(["127.0.0.1/32", tdg.OWN + "/32", "::1/128"])
        for peer in ("127.0.0.1", tdg.OWN, "::1"):
            self.assertEqual(b.effective_addr(peer, "1.2.3.4"), peer)
        self.assertTrue([w for w in b.trust_warnings() if "trusted_proxies" in w])

    def test_config_validation(self):
        from secret_broker.broker import parse_trusted_proxies
        self.assertEqual(parse_trusted_proxies({}), [])
        self.assertEqual(len(parse_trusted_proxies({"trusted_proxies": ["10.0.0.100/32", "fd00::/8"]})), 2)
        for bad in ("10.0.0.1", ["nope"], [5], [None], ["10.0.0.1/99"], ["10.0.0.1"] * 40):
            if bad == ["10.0.0.1"] * 40 or isinstance(bad, (str, list)):
                if bad == ["10.0.0.1/99"] or bad == ["nope"] or bad == [5] or bad == [None] or isinstance(bad, str) or len(bad) > 32:
                    with self.assertRaises(ValueError, msg=str(bad)[:30]):
                        parse_trusted_proxies({"trusted_proxies": bad})

    def test_it_never_feeds_a_trust_decision(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "secret_broker", "broker.py")).read()
        for m in re.finditer(r"peer_trusted\(([^)]*)\)", src):
            if "def " in src[max(0, m.start() - 10):m.start()]:
                continue
            self.assertIn("client_address", m.group(1), m.group(0))      # the real socket peer, never _ip
        b = broker_with(["10.0.0.100/32"], approval_trusted_peers=["203.0.113.0/24"])
        self.assertFalse(b.peer_trusted("10.0.0.100"))      # whatever X-Forwarded-For said, only the socket counts


class PerClientLimits(tc.CBase):
    extra = {"trusted_proxies": ["127.0.0.1/32"]}

    def enrol(self, n, xff):
        h = {"X-Forwarded-For": xff} if xff else {}
        body = {"name": f"box{n}", "hash": tc.clients_mod.hash_secret("asbc1_" + str(n) * 40), "claim": f"u@box{n}"}
        return self.raw("POST", "/v1/enroll", body, h)[0]

    def test_limits_follow_the_real_client(self):
        codes = [self.enrol(i, f"198.51.100.{i}") for i in range(1, 4)]      # (3 pending overall is the global cap)
        self.assertEqual(codes, [202, 202, 202])
        self.assertTrue([e for e in self.records_of("enroll_requested") if e["peer"] == "198.51.100.1"])

    def test_the_same_client_is_still_limited(self):
        codes = [self.enrol(i, "198.51.100.9") for i in range(10, 13)]       # 2 pending per source
        self.assertEqual(codes, [202, 202, 429])

    def records_of(self, name):
        return [json.loads(line) for line in open(self.audit) if line.strip() and json.loads(line)["event"] == name]


class PerClientLimitsOff(tc.CBase):
    def test_header_is_ignored_without_trusted_proxies(self):
        codes = []
        for i in range(1, 4):
            body = {"name": f"box{i}", "hash": tc.clients_mod.hash_secret("asbc1_" + str(i) * 40), "claim": f"u@box{i}"}
            codes.append(self.raw("POST", "/v1/enroll", body, {"X-Forwarded-For": f"198.51.100.{i}"})[0])
        self.assertEqual(codes, [202, 202, 429])         # one real source: the header was not believed


class ApprovalListenerIgnoresIt(t.Harness):
    def tweak(self, cfg):
        cfg["approval_trusted_proxies"] = ["127.0.0.1/32"]
        cfg["approval_trusted_peers"] = ["203.0.113.0/24"]

    def test_forwarded_for_cannot_make_a_peer_trusted(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice",
                                                              "X-Forwarded-For": "203.0.113.5"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(cm.exception.code, 403)
        ev = [e for e in self.events("approval_forbidden")][-1]
        self.assertEqual(ev["client_ip"], "203.0.113.5")        # logged as the real client, decided on the socket


class ClientApiGate(tdg.StrictHarness):
    cfg_extra = {"trusted_proxies": ["10.0.0.100/32", "10.0.1.0/24"]}

    def raw(self, path, method="GET", headers=None, data=None):
        r = urllib.request.Request(self.base + path, headers=headers or {}, data=data, method=method)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_untrusted_peer_is_refused_before_authentication(self):
        code, body = self.raw("/v1/status", headers={"X-Client-Key": tdg.KEY})
        self.assertEqual((code, json.loads(body)), (403, {"error": "forbidden"}))
        code, body = self.raw("/v1/status", headers={"X-Client-Key": "wrong"})
        self.assertEqual(code, 403)                             # not 401: authentication is never reached
        self.assertEqual(self.raw("/v1/enroll", "POST", data=b"{}", headers={"Content-Type": "application/json"})[0], 403)
        self.assertEqual(self.raw("/v1/enroll/abc")[0], 403)
        self.assertEqual(self.raw("/v1/hooks/ha/decide", "POST", data=b"{}")[0], 403)

    def test_forged_forwarded_for_does_not_help(self):
        for xff in ("10.0.0.100", "10.0.1.5, 10.0.0.100", "::ffff:10.0.0.100"):
            code, _ = self.raw("/v1/status", headers={"X-Client-Key": tdg.KEY, "X-Forwarded-For": xff})
            self.assertEqual(code, 403, xff)

    def test_the_refusal_is_audited_once_a_minute_and_hidden_from_agents(self):
        for _ in range(5):
            self.raw("/v1/status", headers={"X-Client-Key": tdg.KEY})
        ev = self.events("client_peer_refused")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["peer"], "127.0.0.1")
        from secret_broker import audit_api
        self.assertIn("client_peer_refused", audit_api.HIDDEN)

    def test_loopback_health_check_works_and_says_nothing(self):
        self.assertEqual(self.raw("/healthz"), (200, "ok"))
        self.assertEqual(self.raw("/healthz", "POST")[0], 403)

    def test_peer_rules(self):
        b = self.broker
        for peer in ("10.0.0.100", "::ffff:10.0.0.100", "10.0.1.77"):             # a proxy chain: either hop
            self.assertTrue(b.client_peer_allowed(peer, "POST", "/v1/requests"), peer)
        for peer in ("10.0.0.7", "8.8.8.8", "127.0.0.1", tdg.OWN, "garbage"):
            self.assertFalse(b.client_peer_allowed(peer, "POST", "/v1/requests"), peer)
        self.assertTrue(b.client_peer_allowed("127.0.0.1", "GET", "/healthz"))
        self.assertTrue(b.client_peer_allowed(tdg.OWN, "GET", "/healthz"))
        self.assertFalse(b.client_peer_allowed("10.0.0.7", "GET", "/healthz"))

    def test_the_approval_listener_is_not_affected(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(cm.exception.code, 403)             # (its own rule: fail closed here, not the client gate)
        self.assertEqual(self.events("client_peer_refused"), [])


class ClientApiOptOut(tdg.StrictHarness):
    cfg_extra = {"trusted_proxies": ["10.0.0.100/32"], "client_api_allow_direct": True}

    def test_direct_access_with_a_warning(self):
        r = urllib.request.Request(self.base + "/v1/status", headers={"X-Client-Key": tdg.KEY})
        self.assertEqual(urllib.request.urlopen(r, timeout=10).status, 200)
        self.assertTrue([e for e in self.events("config_warning") if "client_api_allow_direct" in e["warning"]])


class ClientApiDefault(tdg.StrictHarness):
    def test_no_trusted_proxies_means_no_gate(self):
        r = urllib.request.Request(self.base + "/v1/status", headers={"X-Client-Key": tdg.KEY})
        self.assertEqual(urllib.request.urlopen(r, timeout=10).status, 200)
        self.assertEqual(urllib.request.urlopen(self.base + "/healthz", timeout=10).read(), b"ok")


class SecretNeverSkipped(unittest.TestCase):
    def write(self, text):
        p = os.path.join(tempfile.mkdtemp(), "s")
        open(p, "w").write(text)
        return p

    def broker(self, path, **extra):
        return broker_with(None, approval_proxy_secret_file=path, approval_trusted_peers=["10.9.0.5/32"], **extra)

    def test_unusable_secrets_close_the_listener_whatever_else_is_set(self):
        d = tempfile.mkdtemp()
        cases = {"unreadable": os.path.join(d, "missing"), "directory": d, "empty": self.write(""),
                 "short": self.write("abc123\n"), "placeholder": self.write("changeme-changeme-changeme\n"),
                 "repeated": self.write("aaaaaaaaaaaaaaaaaaaaaaaa\n"), "spaces": self.write("two words in here 123456\n"),
                 "empty key": ""}
        for name, path in cases.items():
            for extra in ({}, {"approval_trust_any_peer": True}):
                b = self.broker(path, **extra)
                self.assertFalse(b.listener_open(), name)
                self.assertFalse(b.peer_trusted("10.9.0.5"), name)
                self.assertTrue([e for e in b.trust_errors() if "approval_proxy_secret_file" in e], name)

    def test_a_valid_secret_opens_it(self):
        b = self.broker(self.write("0123456789abcdef0123456789abcdef\n"))
        self.assertTrue(b.listener_open())
        self.assertTrue(b.peer_trusted("10.9.0.5"))
        self.assertEqual(b.trust_errors(), [])

    def test_listener_answers_403_to_everything_with_a_broken_secret(self):
        h = tdg.StrictHarness
        # (real listener, trust-any-peer set, secret file missing)
        class T(h):
            cfg_extra = {"approval_trust_any_peer": True, "approval_proxy_secret_file": "/nonexistent/secret"}

            def runTest(self):
                for hdr in ({}, {"X-ASB-Proxy-Secret": "anything-at-all-1234567890"}):
                    r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice", **hdr})
                    with self.assertRaises(urllib.error.HTTPError) as cm:
                        urllib.request.urlopen(r, timeout=10)
                    self.assertEqual(cm.exception.code, 403)
        res = unittest.TextTestRunner(stream=io.StringIO()).run(T())
        self.assertTrue(res.wasSuccessful(), res.failures + res.errors)

    def test_broad_peer_prefixes_warn(self):
        for cidr in ("172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16", "fd00::/48"):
            b = broker_with(None, approval_trusted_peers=[cidr])
            self.assertTrue([w for w in b.trust_warnings() if "broader than" in w], cidr)
        b = broker_with(None, approval_trusted_peers=["172.30.50.10/32", "172.30.50.0/24", "fd00::/64"])
        self.assertFalse([w for w in b.trust_warnings() if "broader than" in w])


if __name__ == "__main__":
    unittest.main()
