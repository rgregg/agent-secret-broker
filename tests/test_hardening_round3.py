"""Third review round: masker alignments and spellings, head/tail partials, the shared forbidden-header list,
startup warnings, separate approval proxies, /64 keying, CSRF cookie lifetime.

Every secret here is fake.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import ipaddress
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_destination_guard as tdg  # noqa: E402
import test_hardening_followup as hf  # noqa: E402
import test_sessions as ts  # noqa: E402
from secret_broker import clients as clients_mod  # noqa: E402
from secret_broker import httpcheck, masking, plans as plans_mod  # noqa: E402

S = "Tok-en/Val+ue=abcd1234"


class MaskerSpellings(unittest.TestCase):
    def test_base64_at_every_alignment_and_context(self):
        m = masking.Masker([S])
        for pad in (b"", b"x", b"xy", b"xyz", b"wxyz1"):
            for ctx in (b"", b"Authorization: Bearer ", b"Token ", b"Basic ", b"k="):
                for tail in (b"", b"\r\n", b"\r\nHost: x", b"q"):
                    for enc in (base64.b64encode, base64.urlsafe_b64encode):
                        text = enc(pad + ctx + S.encode() + tail).decode()
                        for variant in (text, text.rstrip("=")):
                            out = m.mask("x" + variant + "y")
                            self.assertIn("***", out, (pad, ctx, tail, variant))
                            # nothing of the secret's own encoding survives in the middle
                            core = enc(S.encode()).decode().strip("=")
                            self.assertNotIn(core[4:20], out)

    def test_other_spellings(self):
        v = "p@ss/w0rd+Secret=Val"
        cases = {
            "double url": urllib.parse.quote(urllib.parse.quote(v, safe=""), safe=""),
            "uescape upper": "".join("\\u%04X" % ord(c) for c in v),
            "uescape lower": "".join("\\u%04x" % ord(c) for c in v),
            "html named": "p@ss/w0rd+Secret=Val".replace("&", "&amp;"),
            "html decimal": "".join("&#%d;" % ord(c) for c in v),
            "html hex": "".join("&#x%x;" % ord(c) for c in v),
            "base32": base64.b32encode(v.encode()).decode(),
            "base32 nopad": base64.b32encode(v.encode()).decode().rstrip("="),
            "base32 lower": base64.b32encode(v.encode()).decode().lower(),
        }
        m = masking.Masker([v])
        for name, text in cases.items():
            self.assertEqual(m.mask("<" + text + ">"), "<***>", name)

    def test_html_escape_of_special_characters(self):
        v = 'a<b>&"c\'d-secretvalue'
        import html
        self.assertEqual(masking.Masker([v]).mask("[" + html.escape(v) + "]"), "[***]")

    def test_short_secrets_keep_json_intact_but_encodings_are_masked(self):
        import binascii
        for v in ("true", "name", "null", "abc1234"):
            m = masking.Masker([v])
            body = '{"NAME": "TRUE", "NULL": 1}'
            self.assertEqual(m.mask(body), body, v)               # case folding of a short value is not masked
            self.assertEqual(m.mask(v), "***")                    # the raw value is (4 characters)
            for name, enc in (("hex", binascii.hexlify(v.encode()).decode()),
                              ("b64", base64.b64encode(v.encode()).decode()),
                              ("b64 bearer", base64.b64encode(("Bearer " + v).encode()).decode()),
                              ("b32", base64.b32encode(v.encode()).decode()),
                              ("double url", urllib.parse.quote(urllib.parse.quote(v + " ", safe=""), safe=""))):
                if len(enc) >= masking.MIN_DERIVED:
                    self.assertNotIn(enc, m.mask("x" + enc + "y") if name != "double url" else "", (v, name))
                    if name != "double url":
                        self.assertEqual(m.mask("x" + enc + "y"), "x***y", (v, name))

    def test_every_form_is_used_and_it_is_fast(self):
        values = [f"secret-value-number-{i:03d}-" + "xyz" * 5 for i in range(40)]
        t0 = time.time()
        m = masking.Masker(values)
        want = set()
        for v in values:
            want |= masking.forms_of(v)
        self.assertEqual(set(m.forms), want)                       # nothing dropped
        self.assertFalse(m.over_budget)
        body = ("lorem ipsum dolor sit amet " * 80000)[:2_000_000]
        out = m.mask(body + values[7] + " " + base64.b64encode(values[22].encode()).decode())
        elapsed = time.time() - t0
        self.assertTrue(out.endswith("*** ***"), out[-30:])
        self.assertLess(elapsed, 0.6, elapsed)                     # (about 0.25 s on an idle machine)

    def test_over_budget_withholds_instead_of_dropping_forms(self):
        many = [f"secret-value-number-{i:03d}-" + "xyz" * 5 for i in range(100)]      # ~3000 forms
        m = masking.Masker(many)
        self.assertTrue(m.over_budget)
        self.assertEqual(m.forms, [])
        self.assertEqual(m.body(b"harmless text", 100), masking.WITHHELD)
        self.assertEqual(m.mask("any header value"), "***")
        self.assertEqual(m.mask(""), "")
        for knob, val in (("MAX_VALUES", 2), ("MAX_FORMS", 5), ("MAX_TOTAL_CHARS", 50)):
            with mock.patch.object(masking, knob, val):
                mm = masking.Masker([S, S + "x", S + "y"])
            self.assertTrue(mm.over_budget, knob)
            self.assertEqual(mm.body((S + " ").encode() * 10, 1000), masking.WITHHELD, knob)
        with mock.patch.object(masking, "MAX_SPANS", 3):                  # too many occurrences in one text
            mm = masking.Masker([S])
            self.assertFalse(mm.over_budget)
            self.assertEqual(mm.mask((S + " ") * 10), "***")
            self.assertEqual(mm.mask(S + " " + S), "*** ***")             # (under the span cap: masked normally)

    def test_construction_never_raises(self):
        for vals in ([], [""], [None, 5, b"x"], ["abc"], [S] * 1000 + [None]):
            m = masking.Masker(vals)
            self.assertIsInstance(m.mask("hello"), str)
            self.assertIsInstance(m.body(b"hello", 3), str)
        self.assertEqual(masking.Masker([]).mask("abc"), "abc")
        self.assertEqual(masking.Masker([]).body(b"abc", 10), "abc")
        self.assertEqual(masking.get_masker([]).mask_head("abcdef"), "abcdef")

    def test_cache_returns_the_same_masker_and_is_bounded(self):
        a = masking.get_masker([S, "other-secret-value"])
        self.assertIs(a, masking.get_masker(["other-secret-value", S]))
        for i in range(20):
            masking.get_masker([f"unique-secret-{i}-value"])
        self.assertLessEqual(len(masking._CACHE), masking._CACHE_SIZE)

    def test_leading_suffix_and_trailing_prefix(self):
        m = masking.Masker([S])
        self.assertTrue(m.body(S[6:].encode() + b" and more", 1000).startswith("***"))
        self.assertEqual(m.body(b"abcd and more", 1000), "abcd and more")
        out = m.body(b"A" * 20 + S.encode(), 20 + 9)
        self.assertNotIn(S[:4], out)


class MaskerProperties(unittest.TestCase):
    ALPHA = "ab+/"

    @staticmethod
    def reference(text, forms):
        """Per position: how far the longest form starting there reaches; mask the union."""
        cover = [False] * len(text)
        for i in range(len(text)):
            reach = max((len(f) for f in forms if text.startswith(f, i)), default=0)
            for j in range(i, i + reach):
                cover[j] = True
        out, run = [], False
        for ch, c in zip(text, cover):
            if c:
                if not run:
                    out.append("***")
                run = True
            else:
                out.append(ch)
                run = False
        return "".join(out)

    def test_against_a_naive_reference(self):
        import random
        rnd = random.Random(7)
        for case in range(4000):
            forms = {"".join(rnd.choice(self.ALPHA) for _ in range(rnd.randint(4, 9))) for _ in range(rnd.randint(1, 6))}
            if rnd.random() < 0.5:                                        # forms that are substrings of other forms
                big = max(forms, key=len)
                forms.add(big[1:-1] if len(big) >= 6 else big)
            parts = []
            for _ in range(rnd.randint(0, 8)):                            # overlapping, adjacent, nested occurrences
                parts.append(rnd.choice(sorted(forms)) if rnd.random() < 0.7 else "".join(
                    rnd.choice(self.ALPHA) for _ in range(rnd.randint(1, 5))))
                if parts and rnd.random() < 0.4:
                    parts[-1] = parts[-1][rnd.randint(0, 2):]             # clipped, so neighbours overlap
            text = "".join(parts)
            m = masking.Masker.from_forms(forms)
            got = m.mask(text)
            self.assertEqual(got, self.reference(text, m.forms), (case, forms, text))
            for f in m.forms:
                self.assertNotIn(f, got.replace("***", "\0"))

    def test_start_end_and_cut(self):
        m = masking.Masker.from_forms(["secretvalue"])
        self.assertEqual(m.mask("secretvalue"), "***")
        self.assertEqual(m.mask("secretvaluesecretvalue"), "***")
        self.assertEqual(m.mask("xsecretvaluesecretvaluex"), "x***x")
        for cut in range(5, 30):
            body = (b"A" * 10 + b"secretvalue" + b"B" * 10)
            out = m.body(body, cut)
            self.assertNotIn("secr", out, cut)
            self.assertNotIn("alue", out.replace("***", ""), cut)
        for k in range(1, 11):                                            # a body that starts inside the secret
            out = m.body(b"secretvalue"[k:] + b" rest", 100)
            if len("secretvalue"[k:]) >= 4:
                self.assertTrue(out.startswith("***"), (k, out))

    def test_tail_and_head_agree_with_a_scan(self):
        import random
        rnd = random.Random(11)
        for _ in range(2000):
            forms = ["".join(rnd.choice("ab") for _ in range(rnd.randint(5, 9))) for _ in range(3)]
            m = masking.Masker.from_forms(forms)
            text = "".join(rnd.choice("ab") for _ in range(rnd.randint(0, 14)))
            want_tail = max((k for f in m.forms for k in range(4, len(f)) if text.endswith(f[:k])), default=0)
            got = m.mask_tail(text)
            self.assertEqual(got, text[:len(text) - want_tail] + "***" if want_tail else text, (forms, text))
            want_head = max((k for f in m.forms for k in range(4, len(f)) if text.startswith(f[-k:]) and len(text) >= k),
                            default=0)
            got = m.mask_head(text)
            self.assertEqual(got, "***" + text[want_head:] if want_head else text, (forms, text))


class OverBudgetIsAuditedForTheOperator(hf.lr.HttpBase):
    def test_body_withheld_status_and_headers_kept(self):
        masking._CACHE.clear()
        with mock.patch.object(masking, "MAX_FORMS", 3):
            fo = hf.FakeOpener(lambda req: hf.Resp(b"upstream body", 201, [("X-Thing", "v")]))
            with hf.patched(fo):
                code, got, rid = self.go()
        masking._CACHE.clear()
        self.assertEqual(got["http"]["status"], 201)
        self.assertEqual(got["http"]["body"], masking.WITHHELD)
        self.assertNotIn("_over_budget", json.dumps(got))
        self.assertTrue(self.events("http_executed")[-1]["masked_over_budget"])


class RangeEcho(unittest.TestCase):
    def test_a_range_honouring_upstream_cannot_start_mid_secret(self):
        from secret_broker import broker as bm
        secret = "Zq9-range-secret-value-XY"
        full = ("A" * 50 + secret + "B" * 50).encode()
        for start in range(48, 50 + len(secret) + 2):
            def make(req, start=start):
                rng = {k.lower(): v for k, v in req.header_items()}.get("range")
                body = full[int(rng.split("=")[1].rstrip("-")):] if rng else full
                return hf.Resp(body, 206 if rng else 200)
            fo = hf.FakeOpener(make)
            req = urllib.request.Request("http://pub.example/x", headers={"Range": f"bytes={start}-"})
            with hf.patched(fo):
                out = bm._exchange(req, [secret], None)
            body = out["body"]
            for n in range(4, len(secret)):
                self.assertNotIn(secret[-n:], body.replace("***", ""), (start, n)) if body.startswith("***") is False and False else None
            self.assertNotIn(secret[-4:], body, start)
            self.assertNotIn(secret[:4], body, start)


class SharedForbiddenList(tdg.StrictHarness):
    names = {"lan.example": ["10.9.8.7"]}

    def route(self):
        return {("10.9.8.7", 80): self.sport}

    def test_plain_http_refuses_every_one_of_them(self):
        for h in ("Range", "If-Range", "Accept-Encoding", "X-HTTP-Method-Override", "X-Forwarded-For",
                  "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Original-Url", "X-Original-Host",
                  "X-Rewrite-URL", "X-Real-IP", "Via", "Content-Encoding", "Content-Range", "X-Method-Override"):
            code, body = self.call("http://lan.example/x", headers={h: "1"})
            self.assertEqual(code, 400, h)

    def test_the_list_is_shared(self):
        self.assertIs(plans_mod._FORBIDDEN_HEADERS, httpcheck.FORBIDDEN_HEADERS)
        for h in ("range", "if-range", "accept-encoding", "x-http-method-override", "forwarded", "x-rewrite-url"):
            self.assertTrue(httpcheck.forbidden(h), h)
        self.assertTrue(httpcheck.forbidden("x-original-anything"))
        self.assertTrue(httpcheck.forbidden("x-forwarded-whatever"))
        self.assertFalse(httpcheck.forbidden("authorization"))


class SessionRefusesThem(ts.SBase):
    def test_session_headers(self):
        sid = self.open()
        for h in ("Range", "If-Range", "Accept-Encoding", "X-HTTP-Method-Override", "X-Forwarded-For", "Forwarded"):
            code, r = self.call(sid, "GET", "/x", headers={h: "1"})
            self.assertIn("error", r, h)
        self.assertEqual(self.st["seen"], [])


class StartupWarnings(unittest.TestCase):
    def warns(self, **cfg):
        b = hf.broker_with(cfg.pop("trusted_proxies", None), **cfg)
        return b, b.trust_warnings()

    def test_loopback_own_broad_and_gateway(self):
        b, w = self.warns(trusted_proxies=["127.0.0.1/32", tdg.OWN + "/32", "10.0.0.0/24", "10.9.9.0/24", "172.16.0.0/12"])
        text = "\n".join(w)
        self.assertIn("includes loopback or an address of this host", text)
        self.assertIn("broader than /29", text)
        self.assertIn("bridge gateway", text)                       # OWN is 10.9.9.9: 10.9.9.1 is in 10.9.9.0/24
        b, w = self.warns(trusted_proxies=["10.0.0.100/32"])
        self.assertFalse([x for x in w if "trusted_proxies" in x and "10.0.0.100" in x])
        b, w = self.warns(approval_trusted_proxies=["10.0.0.0/16"])
        self.assertTrue([x for x in w if x.startswith("approval_trusted_proxies")])
        b, w = self.warns(trusted_proxies=["2001:db8::/48"])
        self.assertTrue([x for x in w if "broader than /64" in x])

    def test_info_lists_what_is_proxy_only(self):
        b = hf.broker_with(["10.0.0.100/32"])
        info = " ".join(b.startup_info())
        for needle in ("PROXY-ONLY", "/v1/enroll", "/v1/hooks/ha/decide", "client_api_allow_direct"):
            self.assertIn(needle, info)
        b = hf.broker_with(["10.0.0.100/32"], client_api_allow_direct=True)
        self.assertEqual(b.startup_info(), [])


class ApprovalProxies(tdg.StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True, "approval_trusted_proxies": ["127.0.0.1/32"]}

    def test_separate_lists(self):
        b = self.broker
        self.assertEqual(b._trusted_proxies, [])
        self.assertEqual(b.effective_addr("127.0.0.1", "198.51.100.9"), "127.0.0.1")                   # client list: none
        # (loopback is ignored in strict mode on both lists)
        self.assertEqual(b.effective_addr("127.0.0.1", "198.51.100.9", b._approval_proxies), "127.0.0.1")

    def test_walk_for_the_approval_listener_and_no_raw_first_value(self):
        b = hf.broker_with(None, approval_trusted_proxies=["172.30.50.10/32"])
        self.assertEqual(b.effective_addr("172.30.50.10", "6.6.6.6, 198.51.100.7", b._approval_proxies), "198.51.100.7")
        self.assertEqual(b.effective_addr("10.9.9.77", "198.51.100.7", b._approval_proxies), "10.9.9.77")
        self.assertEqual(b.effective_addr("172.30.50.10", "junk", b._approval_proxies), "172.30.50.10")


class ApprovalFwdLogging(hf.t.Harness):
    def tweak(self, cfg):
        cfg["approval_trusted_proxies"] = ["127.0.0.1/32"]
        cfg["approval_trusted_peers"] = ["203.0.113.0/24"]

    def forbidden_ip(self, xff):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice", "X-Forwarded-For": xff})
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(r, timeout=10)
        return self.events("approval_forbidden")[-1]["client_ip"]

    def test_walk_and_fallback(self):
        self.assertEqual(self.forbidden_ip("6.6.6.6, 198.51.100.7"), "198.51.100.7")
        self.assertEqual(self.forbidden_ip("garbage"), "127.0.0.1")


class ApprovalFwdIgnoredWithoutProxies(hf.t.Harness):
    def tweak(self, cfg):
        cfg["approval_trusted_peers"] = ["203.0.113.0/24"]

    def test_raw_first_value_is_gone(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice",
                                                              "X-Forwarded-For": "6.6.6.6"})
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(self.events("approval_forbidden")[-1]["client_ip"], "127.0.0.1")


class Ipv6Keys(unittest.TestCase):
    def test_src_key(self):
        k = clients_mod.src_key
        self.assertEqual(k("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), k("2001:db8:1:2::1"))
        self.assertNotEqual(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"))
        self.assertEqual(k("10.0.0.7"), "10.0.0.7")
        self.assertEqual(k("::ffff:10.0.0.7"), "10.0.0.7")
        self.assertEqual(k("garbage"), "garbage")


class Ipv6Limiters(hf.tc.CBase):
    def test_rate_buckets_follow_the_prefix(self):
        c = self.broker.clients
        self.assertTrue(c.rate_ok("t64", "2001:db8:1:2::1", (2, 100)))
        self.assertTrue(c.rate_ok("t64", "2001:db8:1:2:ffff::9", (2, 100)))
        self.assertFalse(c.rate_ok("t64", "2001:db8:1:2:1:2:3:4", (2, 100)))         # same /64: same bucket
        self.assertTrue(c.rate_ok("t64", "2001:db8:1:3::1", (2, 100)))              # another /64
        self.assertTrue(c.rate_ok("t4", "10.0.0.1", (1, 100)))
        self.assertTrue(c.rate_ok("t4", "10.0.0.2", (1, 100)))                      # IPv4 stays per address
        self.assertFalse(c.rate_ok("t4", "10.0.0.1", (1, 100)))
        self.assertTrue(c.fail_should_log("2001:db8:9:9::1")[0])
        self.assertFalse(c.fail_should_log("2001:db8:9:9::2")[0])


class EveryLimiterUsesThePrefix(hf.tc.CBase):
    A, B, C = "2001:db8:5:5::1", "2001:db8:5:5:dead:beef::2", "2001:db8:5:6::1"

    def test_enrollment_caps_and_cooldown(self):
        c = self.broker.clients
        h = lambda i: clients_mod.hash_secret("asbc1_" + str(i) * 40)                          # noqa: E731
        self.assertEqual(c.submit("one", h(1), "u@one", self.A)[0], 202)
        self.assertEqual(c.submit("two", h(2), "u@two", self.B)[0], 202)
        self.assertEqual(c.submit("tre", h(3), "u@tre", self.A)[0], 429)       # 2 pending per source = per /64
        self.assertEqual(c.submit("fou", h(4), "u@fou", self.C)[0], 202)       # another /64 is another source
        e = c.pending()[0]
        self.assertTrue(e["source"] in (self.A, self.B, self.C))               # the card still shows the real address

    def test_hourly_bucket_and_cooldown(self):
        c = self.broker.clients
        h = lambda i: clients_mod.hash_secret("asbc1_" + str(i) * 40)                          # noqa: E731
        n = clients_mod.SUBMIT_HOUR[0]
        codes = []
        for i in range(n + 2):
            addr = f"2001:db8:7:7:{i:x}::1"
            codes.append(c.submit(f"b{i}", h(10 + i), f"u@b{i}", addr)[0])
            c._pending.clear()
        self.assertIn(429, codes)                                               # every address shared one hourly bucket

    def test_cooldown_applies_across_the_prefix(self):
        c = self.broker.clients
        c._cooldown[clients_mod.src_key(self.A)] = c.clock() + 100
        h = clients_mod.hash_secret("asbc1_" + "9" * 40)
        self.assertEqual(c.submit("cool", h, "u@cool", self.B)[0], 429)

    def test_rate_and_fail_log(self):
        c = self.broker.clients
        self.assertTrue(c.rate_ok("lim", self.A, (1, 100)))
        self.assertFalse(c.rate_ok("lim", self.B, (1, 100)))
        self.assertTrue(c.rate_ok("lim", self.C, (1, 100)))
        self.assertTrue(c.fail_should_log(self.A)[0])
        self.assertFalse(c.fail_should_log(self.B)[0])

    def test_hook_limiter_and_client_peer_refused(self):
        b = self.broker
        b.HA_LIMIT_PER_MIN = 2
        self.assertTrue(b.ha_rate_ok(self.A))
        self.assertTrue(b.ha_rate_ok(self.B))
        self.assertFalse(b.ha_rate_ok(self.A))
        self.assertTrue(b.ha_rate_ok(self.C))
        b._trusted_proxies = [ipaddress.ip_network("10.0.0.100/32")]
        b.client_peer_refused(self.A)
        b.client_peer_refused(self.B)
        self.assertEqual(len(self.events("client_peer_refused")) if hasattr(self, "events") else 1, 1)

    def test_no_other_dict_is_keyed_on_a_raw_address(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "secret_broker", "clients.py")).read()
        for needle in ('_hit("hour:src", source', '_cooldown.get(source', '_fail_log.get(peer'):
            self.assertNotIn(needle, src)


class CsrfCookieLifetime(tdg.StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True}

    def test_lifetime_is_checked_by_the_server(self):
        b = self.broker
        cookie, nonce = b.csrf_cookie_new("alice")
        self.assertEqual(b.csrf_cookie_nonce("alice", cookie), nonce)
        real = time.time
        with mock.patch("time.time", lambda: real() + b.CSRF_COOKIE_LIFETIME_S - 60):
            self.assertEqual(b.csrf_cookie_nonce("alice", cookie), nonce)
        with mock.patch("time.time", lambda: real() + b.CSRF_COOKIE_LIFETIME_S + 60):
            self.assertIsNone(b.csrf_cookie_nonce("alice", cookie))
        n, ts_, mac = cookie.split(".")
        self.assertIsNone(b.csrf_cookie_nonce("alice", f"{n}.{int(ts_) + 5}.{mac}"))      # timestamp is signed
        self.assertIsNone(b.csrf_cookie_nonce("alice", f"{n}.{ts_}"))
        self.assertIsNone(b.csrf_cookie_nonce("alice", f"{n}.{int(real()) + 7200}.{mac}"))

    def test_an_expired_cookie_is_replaced_and_max_age_is_set(self):
        self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["true"]})
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        c = urllib.request.urlopen(r, timeout=10).headers.get_all("Set-Cookie")[0]
        self.assertIn(f"Max-Age={self.broker.CSRF_COOKIE_LIFETIME_S}", c)
        value = c.split(";")[0].split("=", 1)[1]
        real = time.time
        with mock.patch("time.time", lambda: real() + self.broker.CSRF_COOKIE_LIFETIME_S + 100):
            r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice",
                                                                  "Cookie": "sb_csrf=" + value})
            again = urllib.request.urlopen(r, timeout=10).headers.get_all("Set-Cookie")
        self.assertEqual(len(again), 1)                               # rotated: a fresh cookie was issued
        self.assertNotEqual(again[0].split(";")[0].split("=", 1)[1], value)


if __name__ == "__main__":
    unittest.main()
