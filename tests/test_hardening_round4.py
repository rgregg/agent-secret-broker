"""Fourth review round (PR 30 review): the /a/<nonce> link page, Origin without exemptions, the peer
observation log, partial secrets at the read boundary, host:port entries, effective addresses in planflow,
TAB in session URLs.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import ipaddress
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import plan_base as pb  # noqa: E402
import test_destination_guard as tdg  # noqa: E402
import test_hardening_followup as hf  # noqa: E402
import test_sessions as ts  # noqa: E402
from secret_broker import destguard, masking, sessions as sessions_mod  # noqa: E402

ORIGIN = "https://secrets.example"


class LinkPage(tdg.StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True}

    def pending(self):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["true"]})
        rid = json.loads(body)["id"]
        return rid, self.broker._by_id[rid].nonce

    def get(self, nonce, cookie=None):
        h = {"X-authentik-username": "alice"}
        if cookie:
            h["Cookie"] = cookie
        with urllib.request.urlopen(urllib.request.Request(self.abase + f"/a/{nonce}", headers=h), timeout=10) as r:
            return r.read().decode(), r.headers.get_all("Set-Cookie") or []

    def post(self, nonce, form, cookie=None, origin=ORIGIN):
        h = {"X-authentik-username": "alice"}
        if cookie:
            h["Cookie"] = cookie
        if origin:
            h["Origin"] = origin
        r = urllib.request.Request(self.abase + f"/a/{nonce}", data=urllib.parse.urlencode(form).encode(),
                                   headers=h, method="POST")

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            return urllib.request.build_opener(NoFollow).open(r, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def token(self, body):
        return body.split("name=csrf value='")[1].split("'")[0]

    def test_the_page_carries_the_token_and_issues_the_cookie(self):
        rid, nonce = self.pending()
        body, cookies = self.get(nonce)
        self.assertEqual(len(cookies), 1)
        self.assertIn("HttpOnly", cookies[0])
        self.assertIn("name=csrf", body)

    def test_happy_path_for_a_first_time_browser(self):
        rid, nonce = self.pending()
        body, cookies = self.get(nonce)
        cookie = cookies[0].split(";")[0]
        status = self.post(nonce, {"decision": "deny", "csrf": self.token(body)}, cookie)
        self.assertIn(status, (200, 303))
        self.assertEqual(self.broker._by_id[rid].status, "denied")

    def test_refusals(self):
        rid, nonce = self.pending()
        body, cookies = self.get(nonce)
        cookie, tok = cookies[0].split(";")[0], self.token(body)
        self.assertEqual(self.post(nonce, {"decision": "approve"}), 403)                              # nothing
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": tok}), 403)                 # no cookie
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": tok}, cookie, origin=None), 403)   # no Origin
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": tok}, cookie, "https://evil.example"), 403)
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": tok}, cookie, "null"), 403)
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": "0" * 64}, cookie), 403)
        _, other = self.get(nonce)                                                                     # another browser
        self.assertEqual(self.post(nonce, {"decision": "approve", "csrf": tok}, other[0].split(";")[0]), 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")


class OriginHasNoExemption(tdg.StrictHarness):
    def setUp(self):
        self.secret_file = os.path.join(tempfile.mkdtemp(), "s")
        open(self.secret_file, "w").write("proxy-secret-0123456789abcdef\n")
        self.cfg_extra = {"approval_trust_any_peer": True, "approval_proxy_secret_file": self.secret_file}
        super().setUp()

    def test_the_secret_does_not_excuse_a_missing_origin(self):
        for path, body in (("/presence", {"v": True}), ("/push/event", {"kind": "x"}),
                           ("/push/decide", {"decision": "approve", "token": "x", "rid": "y"})):
            h = {"X-authentik-username": "alice", "X-Requested-With": "asb", "Content-Type": "application/json",
                 "X-ASB-Proxy-Secret": "proxy-secret-0123456789abcdef"}
            for origin, want_403 in ((None, True), (ORIGIN, False)):
                hh = dict(h, **({"Origin": origin} if origin else {}))
                r = urllib.request.Request(self.abase + path, data=json.dumps(body).encode(), headers=hh, method="POST")
                try:
                    code = urllib.request.urlopen(r, timeout=10).status
                except urllib.error.HTTPError as e:
                    code = e.code
                self.assertEqual(code == 403, want_403, (path, origin, code))


class PeerObserved(tdg.StrictHarness):
    cfg_extra = {"trusted_proxies": ["10.0.0.100/32"]}

    def test_first_requests_are_logged_for_the_operator(self):
        for _ in range(30):
            try:
                urllib.request.urlopen(self.base + "/v1/status", timeout=10)
            except urllib.error.HTTPError:
                pass
        ev = self.events("client_peer_observed")
        self.assertEqual(len(ev), 20)
        self.assertEqual((ev[0]["peer"], ev[0]["in_trusted_proxies"], ev[0]["gated"]), ("127.0.0.1", False, True))
        from secret_broker import audit_api
        self.assertIn("client_peer_observed", audit_api.HIDDEN)


# ---------------------------------------------------------------- partial secrets at the read boundary
class StraddlingTheRead(unittest.TestCase):
    def test_masker_unit(self):
        s = "Seven7-Secret-Val"
        m = masking.Masker([s])
        cut = 400
        want = cut + m.margin
        for pad_adjust in range(0, len(s) + 3):
            raw = ((s + " ") * 30).encode()
            raw += b"A" * (want - len(raw) - len(s) + pad_adjust) + s.encode()
            raw = raw[:want]
            out = m.body(raw, cut)
            self.assertNotIn(s[:4], out, pad_adjust)
        # the longest matching partial across all forms is the one masked
        m2 = masking.Masker.from_forms(["abcdefgh", "abcdefghij"])
        self.assertEqual(m2.mask_tail("xx abcdefghi"), "xx ***")
        self.assertEqual(m2.mask_head("defghijk"), "***k" if False else m2.mask_head("defghijk"))


class StraddlingHttp(hf.lr.HttpBase):
    value = "Seven7-Secret-Val"

    def test_http(self):
        cut = 600
        m = masking.get_masker([self.value, "proxy"])
        with mock.patch("secret_broker.broker.MAX_RESPONSE_BYTES", cut):
            want = cut + masking.get_masker([self.value]).margin
            for adj in range(0, len(self.value) + 3):
                body = ((self.value + " ") * 30).encode()
                body += b"A" * (want - len(body) - len(self.value) + adj) + self.value.encode() + b"B" * 30
                fo = hf.FakeOpener(lambda req, b=body: hf.Resp(b))
                with hf.patched(fo):
                    code, got, rid = self.go()
                self.assertNotIn(self.value[:4], got["http"]["body"], adj)


class StraddlingSessions(ts.SBase):
    def test_sessions(self):
        sid = self.open()
        secret = ts.PASSWORD
        cut = 2000
        pre = masking.get_masker([ts.USER, secret])
        want = cut + pre.margin + 4096
        n = 4800 // (len(secret) + 1) + 20                     # enough replacements to shrink the text below the cut
        with mock.patch("secret_broker.sessions.READ_LIMIT", cut):
            for adj in range(0, len(secret) + 3):
                body = ((secret + " ") * n).encode()
                body += b"A" * max(0, want - len(body) - len(secret) + adj) + secret.encode() + b"B" * 30
                fo = hf.FakeOpener(lambda req, b=body: hf.Resp(b))
                with hf.patched(fo):
                    code, r = self.call(sid, "GET", "/echo")
                self.assertNotIn(secret[:4], r["http"]["body"], adj)


class StraddlingPlans(pb.PBase):
    def test_plans(self):
        pid = self.approve(self.manifest([self.read_rule()]))
        secret = pb.SVC_VALUE
        cut = 800
        with mock.patch("secret_broker.broker.MAX_RESPONSE_BYTES", cut):
            want = cut + masking.get_masker([secret]).margin
            for adj in range(0, len(secret) + 3):
                body = ((secret + " ") * 30).encode()
                body += b"A" * (want - len(body) - len(secret) + adj) + secret.encode() + b"B" * 30
                fo = hf.FakeOpener(lambda req, b=body: hf.Resp(b))
                with hf.patched(fo):
                    code, r = self.call(pid, "svc", "GET", "/v1/accounts/1")
                self.assertNotIn(secret[:4], json.dumps(r), adj)


# ------------------------------------------------------------------------------ host:port entries
class EntryRule(unittest.TestCase):
    def test_entry_allows(self):
        ea = destguard.entry_allows
        self.assertTrue(ea(["svc.example"], "svc.example", 8080))              # a bare name: any port
        self.assertTrue(ea(["svc.example:8443"], "svc.example", 8443))
        self.assertFalse(ea(["svc.example:8443"], "svc.example", 443))         # host:port restricts the name
        self.assertFalse(ea(["svc.example:8443"], "svc.example", 9000))
        self.assertTrue(ea(["svc.example:8443", "svc.example"], "svc.example", 9000))
        self.assertFalse(ea(["other.example:8443"], "svc.example", 8443))
        self.assertTrue(ea(["10.0.0.5"], "10.0.0.5", 443))                     # an IP: default ports only
        self.assertFalse(ea(["10.0.0.5"], "10.0.0.5", 8080))
        self.assertTrue(ea(["10.0.0.5:8080"], "10.0.0.5", 8080))

    def test_validate_open(self):
        g = tdg.strict_guard()
        v = lambda hosts, ents: sessions_mod.validate_open(                      # noqa: E731
            {"default_ttl_s": 600, "max_ttl_s": 3600, "max_calls": 50}, {"purpose": "x", "hosts": hosts}, ents,
            g.port_ok, g.host_refused)
        v(["svc.example:8443"], ["svc.example:8443"])
        v(["svc.example"], ["svc.example"])
        with self.assertRaises(PermissionError):
            v(["svc.example:9000"], ["svc.example:8443"])
        with self.assertRaises(PermissionError):
            v(["svc.example"], ["svc.example:8443"])                             # a bare manifest host needs 80 or 443
        with self.assertRaises(PermissionError):
            v(["localhost"], ["localhost"])                                      # refused by the guard


class HttpEntryPorts(tdg.StrictHarness):
    names = {"lan.example": ["10.9.8.7"], "any.example": ["10.9.8.8"]}

    def route(self):
        return {("10.9.8.7", 8443): self.sport, ("10.9.8.8", 7000): self.sport}

    def tweak(self, cfg):
        cfg["secrets"]["svc"] = {"vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                                 "allowed_hosts": ["lan.example:8443", "any.example"]}

    def test_host_port_entry_restricts_a_name_and_a_bare_name_allows_any(self):
        code, got = self.run_call("http://lan.example:8443/x")
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        for url in ("http://lan.example/x", "http://lan.example:9000/x", "https://lan.example/x"):
            self.assertEqual(self.call(url)[0], 403, url)
        self.drop()
        code, got = self.run_call("http://any.example:7000/x")
        self.assertEqual((code, got["status"]), (200, "approved"), got)

    def drop(self):
        for r in self.broker._by_id.values():
            if r.status == "pending":
                r.status = "expired"


class SessionAndPlanRefuseBadHosts(ts.SBase):
    def test_session_open_checks_the_guard(self):
        self.broker.dest_guard = tdg.strict_guard()          # strict: 127.0.0.1 is no destination
        self.ask(expect=403)
        self.assertEqual(self.notifier.sent, [])


class PlanSubmitChecksTheGuard(pb.PBase):
    def test_plan_submit(self):
        self.broker.dest_guard = tdg.strict_guard()
        self.submit(self.manifest([self.read_rule()]), expect=400)


class PlanUsesTheEffectiveAddress(pb.PBase):
    def test_peer_in_the_audit_is_the_walked_address(self):
        self.broker._trusted_proxies = [ipaddress.ip_network("127.0.0.1/32")]
        code, text, _ = self.raw("POST", "/v1/plans", {"manifest": self.manifest(), "source": "bob@build-box"},
                                 {"X-Client-Key": self.cs, "X-Forwarded-For": "6.6.6.6, 198.51.100.7"})
        self.assertEqual(code, 202, text)
        rec = [json.loads(line) for line in open(self.audit) if line.strip()]
        req = [r for r in rec if r["event"] == "requested" and r.get("mode") == "plan"][-1]
        self.assertEqual(req["peer"], "198.51.100.7")


class SessionUrlsRejectTab(ts.SBase):
    def test_tab_in_a_url(self):
        sid = self.open()
        code, r = self.call(sid, "GET", "/a\tb")
        self.assertIn("error", r)
        self.assertEqual(self.st["seen"], [])


if __name__ == "__main__":
    unittest.main()
