"""Per-client credentials and human-approved enrollment (secret_broker/clients.py, `asb enroll`).

A throwaway broker per test (the shared test_grants.Base harness: a fake phone that never decides
by itself, a stub upstream, an SSH key, a second credential). Clients are enrolled through the real
endpoint and approved on the real approval listener. Every secret and value here is fake.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import secrets as pysecrets
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402  (Base only)
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api  # noqa: E402
from secret_broker import clients as clients_mod  # noqa: E402
from secret_broker.broker import Broker, serve  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

KEY, CLI = t.KEY, t.CLI
ALICE = {"X-authentik-username": "alice"}


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def load_asb():
    loader = importlib.machinery.SourceFileLoader("asb_under_test", CLI)
    spec = importlib.util.spec_from_loader("asb_under_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class CBase(tg.Base):
    """tg.Base plus helpers to enroll, approve and call as a client."""
    enroll_cfg = None
    legacy = None
    extra = None

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.enroll_cfg is not None:
            cfg["enrollment"] = self.enroll_cfg
        if self.legacy is not None:
            cfg["legacy_client_key"] = self.legacy
        cfg.update(self.extra or {})

    def setUp(self):
        super().setUp()
        self.opener = urllib.request.build_opener(NoFollow)
        self.seen = []                  # every body this test saw, for the leak checks

    # -- raw http ----------------------------------------------------------
    def raw(self, method, path, body=None, headers=None, base=None, data=None):
        h = dict(headers or {})
        if data is None and body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        r = urllib.request.Request((base or self.base) + path, data=data, headers=h, method=method)
        try:
            resp = self.opener.open(r, timeout=15)
            out = (resp.status, resp.read().decode(), resp.headers)
        except urllib.error.HTTPError as e:
            out = (e.code, e.read().decode(), e.headers)
        self.seen.append(out[1])
        if out[2].get("Location"):
            self.seen.append(out[2]["Location"])
        return out

    def as_client(self, secret, method, path, body=None):
        code, text, _ = self.raw(method, path, body, {"X-Client-Key": secret})
        if method == "POST" and path == "/v1/requests":
            self.broker.flush_notifications(10)
        return code, text

    def enr(self, name="laptop", claim="bob@laptop", secret=None, extra=None):
        """POST /v1/enroll; returns (status, body dict, secret, hash)."""
        secret = secret or "asbc1_" + pysecrets.token_urlsafe(32)
        h = clients_mod.hash_secret(secret)
        code, text, _ = self.raw("POST", "/v1/enroll", {"name": name, "hash": h, "claim": claim, **(extra or {})})
        return code, json.loads(text), secret, h

    def get(self, path, user="alice"):
        return self.raw("GET", path, headers={"X-authentik-username": user}, base=self.abase)

    def post(self, path, form, user="alice", headers=None, csrf=True):
        form = dict(form)
        if csrf is True:
            form["csrf"] = self.broker.csrf_token(user)
        elif csrf:
            form["csrf"] = csrf
        return self.raw("POST", path, data=urllib.parse.urlencode(form, doseq=True).encode(),
                        headers={"X-authentik-username": user, **(headers or {})}, base=self.abase)

    def decide_enroll(self, eid, decision="approve", name=None, **kw):
        form = {"id": eid, "decision": decision}
        if name is not None:
            form["name"] = name
        return self.post("/enroll/decide", form, **kw)

    def new_client(self, name="laptop", **kw):
        """Enroll and approve through the real endpoints. Returns {"secret", "id", "hash", "name"}."""
        code, body, secret, h = self.enr(name, **kw)
        self.assertEqual(code, 202, body)
        status, _, hdr = self.decide_enroll(body["id"], "approve", name=name)
        self.assertEqual(status, 303)
        self.assertIn("note=enrolled", hdr["Location"])
        st = self.raw("GET", "/v1/enroll/" + body["id"])
        self.assertEqual(json.loads(st[1])["status"], "approved")
        return {"secret": secret, "hash": h, "name": name, **{"id": json.loads(st[1])["client_id"]}}

    def audit_text(self):
        return _fast.read_audit_text(self.audit)

    def tearDown(self):
        super().tearDown()


# ---------------------------------------------------------------------------- pure helpers
class Helpers(unittest.TestCase):
    def test_hash_and_code_vector(self):
        h = clients_mod.hash_secret("asbc1_test")
        self.assertEqual(h, hashlib.sha256(b"asb-client-secret-v1\0asbc1_test").hexdigest())
        self.assertRegex(clients_mod.confirm_code(h), r"^[A-Z2-7]{4}-[A-Z2-7]{4}$")
        self.assertEqual(clients_mod.confirm_code(h), "TTUZ-BFPY")
        # domain separation: the code is not a slice of the stored hash
        self.assertNotIn(clients_mod.confirm_code(h).replace("-", "").lower(), h)

    def test_client_script_computes_the_same_hash_and_code(self):
        asb = load_asb()
        for s in ("asbc1_test", "asbc1_" + "x" * 43, "plain"):
            self.assertEqual(asb.enroll_hash(s), clients_mod.hash_secret(s))
            self.assertEqual(asb.enroll_code(asb.enroll_hash(s)), clients_mod.confirm_code(clients_mod.hash_secret(s)))

    def test_names(self):
        for ok in ("laptop", "a", "build-box.1", "x_y", "0day"):
            self.assertTrue(clients_mod.valid_name(ok), ok)
        for bad in ("", "-x", ".x", "UPPER", "has space", "a" * 33, "c-1a2b3c4d", "legacy", "ünï", "a/b",
                    "<b>", None, 5):
            self.assertFalse(clients_mod.valid_name(bad), bad)

    def test_scope_parser(self):
        self.assertEqual(clients_mod.parse_scope(None), "*")
        self.assertEqual(clients_mod.parse_scope("c-0a1b2c3d"), "c-0a1b2c3d")
        self.assertEqual(clients_mod.parse_scope("legacy"), "legacy")
        for bad in ("", "any", "c-xyz", "C-0A1B2C3D", 7, ["*"], "*,c-0a1b2c3d"):
            with self.assertRaises(ValueError):
                clients_mod.parse_scope(bad)

    def test_config_parser(self):
        d = clients_mod.parse_config({})
        self.assertEqual((d["legacy"], d["enrollment"]["ttl_s"], d["enrollment"]["max_pending"], d["overrides"]),
                         ("allow", 600, 3, {}))
        ok = clients_mod.parse_config({"legacy_client_key": "deny", "enrollment": {"ttl_s": 120, "max_pending": 2},
                                       "clients": {"c-0a1b2c3d": {"risk": {"auto_approve_max": "none"}},
                                                   "legacy": {"risk": {"auto_modes": ["http"]}}}})
        self.assertEqual(ok["overrides"]["c-0a1b2c3d"], {"auto_approve_max": "none"})
        self.assertEqual(ok["overrides"]["legacy"], {"auto_modes": ["http"]})
        for bad, frag in (({"legacy_client_key": "maybe"}, "legacy_client_key"),
                          ({"enrollment": []}, "enrollment"),
                          ({"enrollment": {"nope": 1}}, "enrollment.nope"),
                          ({"enrollment": {"ttl_s": 5}}, "enrollment.ttl_s"),
                          ({"enrollment": {"ttl_s": True}}, "enrollment.ttl_s"),
                          ({"enrollment": {"max_pending": 0}}, "enrollment.max_pending"),
                          ({"enrollment": {"enabled": "yes"}}, "enrollment.enabled"),
                          ({"clients": {"laptop": {}}}, "clients.laptop"),
                          ({"clients": {"c-0a1b2c3d": {"risk": {"auto_approve_max": "sure"}}}}, "auto_approve_max"),
                          ({"clients": {"c-0a1b2c3d": {"risk": {"auto_modes": ["ssh"]}}}}, "auto_modes"),
                          ({"clients": {"c-0a1b2c3d": {"rules": []}}}, "rules")):
            with self.assertRaises(ValueError) as cm:
                clients_mod.parse_config(bad)
            self.assertIn(frag, str(cm.exception))


# ---------------------------------------------------------------------------- the endpoint
class Enrollment(CBase):
    def test_happy_path_end_to_end(self):
        code, body, secret, h = self.enr("laptop", claim="bob@laptop")
        self.assertEqual(code, 202)
        self.assertEqual(set(body), {"id", "code", "expires_in", "interval"})
        self.assertEqual(body["code"], clients_mod.confirm_code(h))
        # pending: the poll says so; the secret does not work yet
        self.assertEqual(json.loads(self.raw("GET", "/v1/enroll/" + body["id"])[1]), {"status": "pending"})
        self.assertEqual(self.as_client(secret, "GET", "/v1/status")[0], 401)
        # the card: name, claim marked unverified, source address, the code, Approve/Deny and a CSRF token
        status, page, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Client enrollment: laptop", page)
        self.assertIn(body["code"], page)
        self.assertIn("bob@laptop", page)
        self.assertIn("unverified", page)
        self.assertIn("127.0.0.1", page)
        self.assertIn("name=decision value=approve", page)
        self.assertIn("name=decision value=deny", page)
        self.assertIn(self.broker.csrf_token("alice"), page)
        self.assertNotIn(secret, page)
        self.assertNotIn(h, page)
        self.assertEqual(self.broker.attention(), 1)
        # approve
        status, _, hdr = self.decide_enroll(body["id"])
        self.assertEqual(status, 303)
        st = json.loads(self.raw("GET", "/v1/enroll/" + body["id"])[1])
        self.assertEqual((st["status"], st["name"]), ("approved", "laptop"))
        self.assertRegex(st["client_id"], r"^c-[0-9a-f]{8}$")
        # the new credential works, and the card is gone
        code, text = self.as_client(secret, "GET", "/v1/status")
        self.assertEqual(code, 200, text)
        self.assertNotIn("Client enrollment", self.get("/")[1])
        # attribution: the request, the audit log and the card name the client; user@host is extra
        rid = self.client_http(secret)
        req = self.broker._by_id[rid]
        self.assertEqual((req.client["id"], req.client["name"]), (st["client_id"], "laptop"))
        rec = self.events("requested")[-1]
        self.assertEqual((rec["client_id"], rec["client_name"]), (st["client_id"], "laptop"))
        card = self.get("/")[1]
        self.assertIn("Client: <b>laptop</b>", card)
        self.assertIn("Claimed source (unverified)", card)
        ev = self.events("enroll_decided")[-1]
        self.assertEqual((ev["decision"], ev["name"], ev["client_name"], ev["approver"]),
                         ("approved", "laptop", "laptop", "alice"))
        self.assertEqual(self.events("enroll_requested")[0]["name"], "laptop")

    def client_http(self, secret, names=("svc",), path="/x", method="GET"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        code, body = self.as_client(secret, "POST", "/v1/requests", {
            "mode": "http", "names": list(names), "method": method, "url": url, "source": "bob@laptop",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_deny(self):
        code, body, secret, _ = self.enr("laptop")
        status, _, hdr = self.decide_enroll(body["id"], "deny")
        self.assertIn("note=enrolldeny", hdr["Location"])
        self.assertEqual(json.loads(self.raw("GET", "/v1/enroll/" + body["id"])[1]), {"status": "denied"})
        self.assertEqual(self.as_client(secret, "GET", "/v1/status")[0], 401)
        self.assertEqual(self.broker.clients.rows(), [])
        self.assertEqual(self.events("enroll_decided")[-1]["decision"], "denied")
        # the same source waits before the next try
        code2, body2, _, _ = self.enr("laptop")
        self.assertEqual(code2, 429)

    def test_expire(self):
        code, body, secret, _ = self.enr("laptop")
        self.broker.clients.clock = lambda: time.time()          # follows the patched clock
        self.offset += 601
        self.assertEqual(json.loads(self.raw("GET", "/v1/enroll/" + body["id"])[1]), {"status": "expired"})
        self.assertNotIn("Client enrollment", self.get("/")[1])
        self.assertEqual(self.as_client(secret, "GET", "/v1/status")[0], 401)
        status, _, hdr = self.decide_enroll(body["id"])
        self.assertIn("note=stale", hdr["Location"])             # too late to approve
        self.broker.sweep_enrollments()
        self.assertEqual(self.events("enroll_decided")[-1]["decision"], "expired")
        self.assertEqual(self.broker.clients.rows(), [])

    def test_configurable_ttl(self):
        self.broker.clients.cfg["enrollment"]["ttl_s"] = 45
        code, body, _, _ = self.enr("laptop")
        self.assertEqual(body["expires_in"], 45)

    def test_duplicate_pending_name_is_refused(self):
        self.assertEqual(self.enr("laptop")[0], 202)
        code, body, _, _ = self.enr("laptop")
        self.assertEqual(code, 409)
        self.assertEqual(len(self.broker.clients.pending()), 1)

    def test_same_request_twice_is_idempotent(self):
        secret = "asbc1_" + pysecrets.token_urlsafe(32)
        a = self.enr("laptop", secret=secret)
        b = self.enr("laptop", secret=secret)
        self.assertEqual((a[0], b[0], a[1]["id"]), (202, 202, b[1]["id"]))
        self.assertEqual(len(self.broker.clients.pending()), 1)
        self.broker.flush_notifications(5)
        self.assertEqual(len(self.notifier.sent), 1)             # and one notification

    def test_name_of_an_existing_client_is_not_an_oracle(self):
        self.new_client("laptop")
        code, body, _, _ = self.enr("laptop")                    # accepted exactly like a fresh name
        self.assertEqual(code, 202)
        fresh = self.enr("other-box")
        self.assertEqual(set(body), set(fresh[1]))
        # the human sees the clash and must pick another name; the request stays pending
        self.assertIn("already used by another client", self.get("/")[1])
        status, _, hdr = self.decide_enroll(body["id"], name="laptop")
        self.assertIn("note=enrollname", hdr["Location"])
        self.assertEqual(len(self.broker.clients.pending()), 2)
        status, _, hdr = self.decide_enroll(body["id"], name="laptop-2")
        self.assertIn("note=enrolled", hdr["Location"])
        self.assertEqual(sorted(c["name"] for c in self.broker.clients.rows()), ["laptop", "laptop-2"])

    def test_invalid_input(self):
        good = clients_mod.hash_secret("x")
        cases = [{"name": "UPPER", "hash": good, "claim": "a@b"},
                 {"name": "", "hash": good, "claim": "a@b"},
                 {"name": "c-0a1b2c3d", "hash": good, "claim": "a@b"},
                 {"name": "ok", "hash": "short", "claim": "a@b"},
                 {"name": "ok", "hash": good.upper(), "claim": "a@b"},
                 {"name": "ok", "hash": good, "claim": "bad claim <x>"},
                 {"name": "ok", "hash": good, "claim": "a" * 200},
                 {"name": "ok", "hash": good},
                 {"name": "ok", "hash": good, "claim": "a@b", "extra": 1},
                 {"name": 5, "hash": good, "claim": "a@b"},
                 {"name": "ok", "hash": [good], "claim": "a@b"}]
        with mock.patch.object(clients_mod, "SUBMIT_MIN", (999, 999)):
            for body in cases:
                code, text, _ = self.raw("POST", "/v1/enroll", body)
                self.assertEqual(code, 400, body)
                self.assertNotIn("Traceback", text)
            for data in (b"not json", b"[]", b'"x"', b"null", b"\xff\xfe"):
                self.assertEqual(self.raw("POST", "/v1/enroll", data=data,
                                          headers={"Content-Type": "application/json"})[0], 400, data)
        self.assertEqual(self.broker.clients.pending(), [])

    def test_oversize_body_and_missing_length(self):
        big = json.dumps({"name": "ok", "hash": "0" * 64, "claim": "a@b", "pad": "x" * 2000}).encode()
        self.assertEqual(self.raw("POST", "/v1/enroll", data=big)[0], 413)
        # no Content-Length at all
        import socket
        with socket.create_connection(("127.0.0.1", self.c.server_address[1]), timeout=5) as s:
            s.sendall(b"POST /v1/enroll HTTP/1.0\r\nHost: x\r\n\r\n")
            self.assertIn(b" 411 ", s.recv(200))
        self.assertEqual(self.broker.clients.pending(), [])

    def test_pending_cap_and_notifications(self):
        with mock.patch.object(clients_mod, "SOURCE_PENDING", 99), \
                mock.patch.object(clients_mod, "SUBMIT_MIN", (99, 99)), \
                mock.patch.object(clients_mod, "SUBMIT_HOUR", (99, 99)):
            codes = [self.enr(f"box{i}")[0] for i in range(6)]
        self.assertEqual(codes, [202, 202, 202, 429, 429, 429])
        self.broker.flush_notifications(5)
        self.assertEqual(len(self.notifier.sent), 3)             # spam cannot notify beyond the cap
        self.assertEqual(len(self.broker.clients.pending()), 3)
        self.assertEqual(self.get("/")[1].count("Client enrollment:"), 3)

    def test_per_source_pending_cap(self):
        with mock.patch.object(clients_mod, "SUBMIT_MIN", (99, 99)):
            codes = [self.enr(f"box{i}")[0] for i in range(4)]
        self.assertEqual(codes, [202, 202, 429, 429])

    def test_per_source_and_global_rate_limits(self):
        with mock.patch.object(clients_mod, "SOURCE_PENDING", 99), mock.patch.object(
                clients_mod, "SUBMIT_HOUR", (99, 99)), mock.patch.object(clients_mod, "SUBMIT_MIN", (3, 99)):
            codes = [self.enr(f"b{i}", extra=None)[0] for i in range(6)]
            self.assertEqual(codes[:3], [202, 202, 202])
            self.assertTrue(all(c == 429 for c in codes[3:]), codes)
        self.broker.clients._rates.clear()
        self.broker.clients.cfg["enrollment"]["max_pending"] = 10
        with mock.patch.object(clients_mod, "SOURCE_PENDING", 99), mock.patch.object(
                clients_mod, "SUBMIT_HOUR", (99, 99)), mock.patch.object(clients_mod, "SUBMIT_MIN", (99, 2)):
            codes = [self.enr(f"g{i}")[0] for i in range(4)]
            self.assertEqual(codes, [202, 202, 429, 429])
        # a refusal explains itself without naming anything
        code, text, hdr = self.raw("POST", "/v1/enroll", {"name": "x", "hash": "0" * 64, "claim": "a@b"})
        self.assertEqual(code, 429)
        self.assertEqual(hdr["Retry-After"], "60")

    def test_hourly_budget(self):
        with mock.patch.object(clients_mod, "SOURCE_PENDING", 99), mock.patch.object(
                clients_mod, "SUBMIT_MIN", (99, 99)), mock.patch.object(clients_mod, "SUBMIT_HOUR", (2, 99)):
            self.broker.clients.cfg["enrollment"]["max_pending"] = 10
            codes = [self.enr(f"h{i}")[0] for i in range(4)]
        self.assertEqual(codes, [202, 202, 429, 429])

    def test_rate_limit_maps_stay_bounded(self):
        st = self.broker.clients
        for i in range(clients_mod.RATE_MAP_CAP + 500):
            st.rate_ok("enroll", f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", (99, 10 ** 9))
        self.assertLessEqual(len(st._rates[("enroll:src", 60)]), clients_mod.RATE_MAP_CAP)

    def test_disabled(self):
        self.broker.clients.cfg["enrollment"]["enabled"] = False
        code, body, _, _ = self.enr("laptop")
        self.assertEqual(code, 403)
        self.assertEqual(self.broker.clients.pending(), [])

    def test_unknown_enrollment_ids(self):
        for eid in ("x", "A" * 22, "../v1/status", "A" * 64, ""):
            self.assertEqual(self.raw("GET", "/v1/enroll/" + eid)[0], 404, eid)
        # a decided enrollment keeps its answer for a while, then the id is simply unknown
        code, body, _, _ = self.enr("laptop")
        self.decide_enroll(body["id"], "deny")
        self.broker.clients.clock = lambda: time.time()
        self.offset += clients_mod.RESOLVED_KEEP_S + 5
        self.assertEqual(self.raw("GET", "/v1/enroll/" + body["id"])[0], 404)

    def test_poll_rate_limit(self):
        with mock.patch.object(clients_mod, "POLL_MIN", (3, 99)):
            codes = [self.raw("GET", "/v1/enroll/" + "A" * 22)[0] for _ in range(5)]
        self.assertEqual(codes, [404, 404, 404, 429, 429])

    def test_code_clash_is_refused(self):
        code, body, _, h = self.enr("one")
        self.assertEqual(code, 202)
        with mock.patch.object(clients_mod, "confirm_code", lambda x: body["code"]):
            code, text, _ = self.raw("POST", "/v1/enroll", {"name": "two", "hash": "1" * 64, "claim": "a@b"})
        self.assertEqual(code, 409)

    def test_already_enrolled_hash_is_refused(self):
        c = self.new_client("laptop")
        code, body, _, _ = self.enr("again", secret=c["secret"])
        self.assertEqual(code, 409)

    def test_client_list_cap(self):
        with mock.patch.object(clients_mod, "MAX_CLIENTS", 2):
            self.new_client("one")
            self.new_client("two")
            self.assertEqual(self.enr("three")[0], 429)


class EndpointIsolation(CBase):
    """The new endpoint is the only unauthenticated path and reaches nothing else."""

    def test_everything_else_still_needs_a_key(self):
        for method, path in (("GET", "/v1/status"), ("GET", "/v1/secrets"), ("GET", "/v1/audit"),
                             ("GET", "/v1/audit/verify"), ("GET", "/v1/requests/abc"),
                             ("POST", "/v1/requests"), ("PUT", "/v1/enroll"), ("DELETE", "/v1/enroll"),
                             ("POST", "/v1/enroll/x"), ("POST", "/v1/enroll/"), ("GET", "/v1/enroll"),
                             ("GET", "/v1/enrollx")):
            code, text, _ = self.raw(method, path, {"mode": "env", "names": ["svc"], "argv": ["echo"]}
                                     if method == "POST" else None)
            self.assertIn(code, (401, 404), (method, path, code))
            self.assertNotIn("svc", text)
        self.assertEqual(self.raw("GET", "/v1/secrets")[0], 401)
        self.assertEqual(self.raw("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})[0], 401)
        self.assertEqual(self.notifier.sent, [])

    def test_the_endpoint_cannot_create_a_request_or_change_a_policy(self):
        before = (len(self.broker._by_id), dict(self.broker.cfg["secrets"]["svc"]).get("approval"),
                  len(self.broker.grants.active()), len(self.broker.clients.rows()))
        self.raw("POST", "/v1/enroll", {"mode": "env", "names": ["svc"], "argv": ["echo"]})
        self.raw("POST", "/v1/enroll", {"name": "x", "hash": "0" * 64, "claim": "a@b", "mode": "env"})
        self.enr("laptop")
        after = (len(self.broker._by_id), dict(self.broker.cfg["secrets"]["svc"]).get("approval"),
                 len(self.broker.grants.active()), len(self.broker.clients.rows()))
        self.assertEqual(before, after)
        self.assertEqual(len(self.broker.clients.pending()), 1)          # and nothing but a pending card
        self.assertEqual(self.broker.pending(), [])

    def test_the_poll_returns_only_its_own_status(self):
        a = self.enr("one")[1]
        b = self.enr("two")[1]
        sa = json.loads(self.raw("GET", "/v1/enroll/" + a["id"])[1])
        self.assertEqual(sa, {"status": "pending"})              # no name, code, hash, source, other ids

    def test_enrollment_is_not_a_request_and_no_token_channel_reaches_it(self):
        code, body, secret, h = self.enr("laptop")
        eid = body["id"]
        self.assertEqual(self.broker._by_id, {})
        self.assertEqual(self.broker._by_nonce, {})
        self.broker.flush_notifications(5)
        n = self.notifier.notifications[-1]
        self.assertEqual((n.actions, n.action_token), ([], None))
        self.assertEqual(n.names, ["laptop"])
        self.assertNotIn(body["code"], n.text + n.title)
        self.assertNotIn(h, n.text)
        # every decision channel answers "unknown", and nothing changes
        for ch in ("dashboard", "link", "push", "ha"):
            self.assertEqual(self.broker.decide_via(ch, eid, "approve", "alice", token="x" * 22)[0] in (403, 404, 410), True)
            self.assertEqual(self.broker.decide_via(ch, None, "approve", "alice", nonce=eid)[0] in (403, 404, 410), True)
        self.assertEqual(self.raw("POST", "/a/" + eid, data=b"decision=approve", base=self.abase,
                                  headers=ALICE)[0], 404)
        self.assertEqual(self.raw("POST", "/push/decide", data=urllib.parse.urlencode(
            {"rid": eid, "token": "t", "decision": "approve"}).encode(), base=self.abase, headers=ALICE)[0] >= 400, True)
        self.assertEqual(self.raw("POST", "/v1/hooks/ha/decide", {"rid": eid, "decision": "approve", "token": "x"},
                                  {"Authorization": "Bearer nope"})[0] in (403, 404), True)
        self.assertEqual(len(self.broker.clients.pending()), 1)
        self.assertEqual(self.broker.clients.rows(), [])

    def test_approval_actions_need_the_human_identity_and_csrf(self):
        code, body, _, _ = self.enr("laptop")
        eid = body["id"]
        self.assertEqual(self.decide_enroll(eid, user="mallory")[0], 403)
        self.assertEqual(self.decide_enroll(eid, csrf=False)[0], 403)
        self.assertEqual(self.decide_enroll(eid, csrf="wrong")[0], 403)
        self.assertEqual(self.decide_enroll(eid, headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.raw("POST", "/enroll/decide", data=urllib.parse.urlencode(
            {"id": eid, "decision": "approve", "csrf": self.broker.csrf_token("alice")}).encode(),
            base=self.abase)[0], 403)                            # no identity header
        self.assertEqual(len(self.broker.clients.pending()), 1)
        self.assertEqual(self.broker.clients.rows(), [])
        self.assertEqual(self.decide_enroll(eid)[0], 303)

    def test_unknown_decision_or_id_changes_nothing(self):
        code, body, _, _ = self.enr("laptop")
        for form in ({"id": body["id"], "decision": "maybe"}, {"id": "nope", "decision": "approve"},
                     {"id": "", "decision": "approve"}, {"decision": "approve"}):
            status, _, hdr = self.post("/enroll/decide", form)
            self.assertIn("note=stale", hdr["Location"])
        self.assertEqual(len(self.broker.clients.pending()), 1)


# ---------------------------------------------------------------------------- authentication
class Auth(CBase):
    def test_per_client_secrets_authenticate_and_are_attributed(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        for c in (a, b):
            self.assertEqual(self.as_client(c["secret"], "GET", "/v1/status")[0], 200)
        self.assertEqual(self.as_client("asbc1_wrong", "GET", "/v1/status")[0], 401)
        self.assertEqual(self.as_client("", "GET", "/v1/status")[0], 401)
        self.assertEqual(self.as_client("x" * 5000, "GET", "/v1/status")[0], 401)
        rid = self.http_as(a["secret"])
        self.assertEqual(self.broker._by_id[rid].client["name"], "alpha")
        rid2 = self.http_as(b["secret"])
        self.assertEqual(self.broker._by_id[rid2].client["id"], b["id"])
        ids = {self.events("requested")[-2]["client_id"], self.events("requested")[-1]["client_id"]}
        self.assertEqual(ids, {a["id"], b["id"]})

    def http_as(self, secret, path="/x"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        code, body = self.as_client(secret, "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_legacy_key_is_one_client(self):
        rid = self.http()
        req = self.broker._by_id[rid]
        self.assertEqual((req.client["id"], req.client["name"], req.client["legacy"]),
                         ("legacy", "shared key (legacy)", True))
        rec = self.events("requested")[-1]
        self.assertEqual((rec["client_id"], rec["client_name"]), ("legacy", "shared key (legacy)"))
        self.assertIn("shared key (legacy)", self.get("/")[1])
        self.assertIn("shared key (legacy)", self.get("/clients")[1])
        self.assertEqual(self.broker.clients.legacy_row()["requests"], 1)

    def test_a_client_cannot_poll_another_clients_request(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        rid = self.http_as(a["secret"])
        self.assertEqual(self.as_client(b["secret"], "GET", f"/v1/requests/{rid}?wait=0")[0], 404)
        self.assertEqual(self.as_client(KEY, "GET", f"/v1/requests/{rid}?wait=0")[0], 404)
        self.assertEqual(self.as_client(a["secret"], "GET", f"/v1/requests/{rid}?wait=0")[0], 200)

    def test_failures_are_audited_rate_limited_and_secret_free(self):
        for i in range(40):
            self.as_client(f"asbc1_guess{i}", "GET", "/v1/status")
        recs = self.events("client_auth_failed")
        self.assertEqual(len(recs), 1)                           # one record per source per window
        self.assertEqual((recs[0]["reason"], recs[0]["peer"]), ("bad_key", "127.0.0.1"))
        self.assertNotIn("guess", self.audit_text())
        self.broker.clients.clock = lambda: time.time()
        self.offset += clients_mod.FAIL_LOG_S + 1
        self.as_client("asbc1_again", "GET", "/v1/status")
        recs = self.events("client_auth_failed")
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[1]["suppressed"], 39)
        self.assertNotIn("again", self.audit_text())

    def test_compare_digest_is_used_for_every_stored_hash(self):
        self.new_client("alpha")
        self.new_client("bravo")
        calls = []
        real = clients_mod.hmac.compare_digest

        def spy(a, b):
            calls.append(1)
            return real(a, b)
        with mock.patch.object(clients_mod.hmac, "compare_digest", spy):
            view, why = self.broker.clients.authenticate("asbc1_nope", KEY)
            self.assertEqual((view, why), (None, "bad_key"))
            first = len(calls)
            view, why = self.broker.clients.authenticate(KEY, KEY)
            self.assertEqual((view["id"], why), ("legacy", "ok"))
        self.assertEqual(first, 3)                               # two clients + the legacy key, no early exit
        self.assertEqual(len(calls), 6)
        src = open(os.path.join(os.path.dirname(__file__), "..", "secret_broker", "clients.py")).read()
        body = src[src.index("def authenticate"):src.index("def touch")]
        self.assertNotRegex(body, r"\bhash\b\s*==|==\s*\w*hash|\[\"hash\"\]\s*==")

    def test_last_seen_and_request_counts(self):
        a = self.new_client("alpha")
        for _ in range(3):
            self.as_client(a["secret"], "GET", "/v1/status")
        row = self.broker.clients.get(a["id"])
        self.assertEqual((row["requests"], row["last_source"]), (3, "127.0.0.1"))
        self.assertGreater(row["last_seen"], 0)
        page = self.get("/clients")[1]
        self.assertIn("alpha", page)
        self.assertIn("ago", page)


class Legacy(CBase):
    legacy = "deny"

    def test_deny_refuses_the_shared_key_with_a_clear_error(self):
        code, text = self.as_client(KEY, "GET", "/v1/status")
        self.assertEqual(code, 401)
        self.assertIn("asb enroll", text)
        c = self.new_client("alpha")
        self.assertEqual(self.as_client(c["secret"], "GET", "/v1/status")[0], 200)
        self.assertEqual(self.events("client_auth_failed")[-1]["reason"], "legacy_denied")
        self.assertIn("denied", self.get("/clients")[1])
        self.assertEqual(json.loads(self.as_client(c["secret"], "GET", "/v1/status")[1])["features"]["legacy_client_key"],
                         "deny")


class LegacyAllowDefault(CBase):
    def test_default_allow_keeps_everything_working(self):
        self.assertEqual(self.broker.clients_cfg["legacy"], "allow")
        self.assertEqual(self.api("GET", "/v1/status")[0], 200)
        self.assertEqual(self.api("GET", "/v1/secrets")[0], 200)
        rid = self.http()
        self.assertEqual(self.broker._by_id[rid].status, "pending")


# ---------------------------------------------------------------------------- revoke, rename, remove
class Administration(CBase):
    def test_revoke_takes_effect_on_the_next_request_and_others_are_unaffected(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        self.assertEqual(self.as_client(a["secret"], "GET", "/v1/status")[0], 200)
        status, _, hdr = self.post("/clients/revoke", {"id": a["id"]})
        self.assertEqual(status, 303)
        self.assertIn("note=revoked", hdr["Location"])
        code, text = self.as_client(a["secret"], "GET", "/v1/status")
        self.assertEqual(code, 401)
        self.assertIn("revoked", text)
        self.assertIn("asb enroll", text)
        self.assertEqual(self.as_client(b["secret"], "GET", "/v1/status")[0], 200)
        self.assertEqual(self.api("GET", "/v1/status")[0], 200)
        ev = self.events("client_revoked")[0]
        self.assertEqual((ev["client_id"], ev["client_name"], ev["revoked_by"]), (a["id"], "alpha", "alice"))
        self.assertEqual(self.events("client_auth_failed")[-1]["reason"], "revoked")
        self.assertIn("revoked", self.get("/clients")[1])

    def test_revoke_mid_pending_denies_the_clients_open_requests_only(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        ra, rb = TestAuthHelper.http_as(self, a["secret"]), TestAuthHelper.http_as(self, b["secret"], "/y")
        rl = self.http(path="/z")
        self.assertEqual(len(self.broker.pending()), 3)
        self.post("/clients/revoke", {"id": a["id"]})
        self.assertEqual(self.broker._by_id[ra].status, "denied")
        self.assertIn("revoked", self.broker._by_id[ra].error)
        self.assertEqual(self.broker._by_id[rb].status, "pending")
        self.assertEqual(self.broker._by_id[rl].status, "pending")
        self.assertEqual(self.events("client_revoked")[0]["denied_pending"], 1)
        self.assertEqual(self.events("denied")[-1]["via"], "client_revoked")
        # a revoked client's denial does not start a cooldown for everyone else
        self.assertEqual(self.broker._denied_at, {})
        # the decision for a request that was denied by revoke finds nothing to approve
        self.assertEqual(self.broker.decide_via("dashboard", ra, "approve", "alice")[0], 410)

    def test_revoke_is_audited_and_idempotent(self):
        a = self.new_client("alpha")
        self.assertEqual(self.broker.revoke_client(a["id"], "alice"), "revoked")
        self.assertEqual(self.broker.revoke_client(a["id"], "alice"), "already")
        self.assertEqual(self.broker.revoke_client("c-00000000", "alice"), "missing")
        self.assertEqual(len(self.events("client_revoked")), 1)

    def test_rename(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        status, _, hdr = self.post("/clients/rename", {"id": a["id"], "name": "alpha-2"})
        self.assertIn("note=renamed", hdr["Location"])
        self.assertEqual(self.broker.clients.get(a["id"])["name"], "alpha-2")
        ev = self.events("client_renamed")[0]
        self.assertEqual((ev["client_id"], ev["old_name"], ev["new_name"]), (a["id"], "alpha", "alpha-2"))
        for bad in ("bravo", "BAD NAME", "", "c-0a1b2c3d", "legacy"):
            status, _, hdr = self.post("/clients/rename", {"id": a["id"], "name": bad})
            self.assertIn("note=taken", hdr["Location"], bad)
        self.assertEqual(self.broker.clients.get(a["id"])["name"], "alpha-2")
        # the id is stable; later requests carry the new name
        rid = TestAuthHelper.http_as(self, a["secret"])
        self.assertEqual(self.events("requested")[-1]["client_name"], "alpha-2")
        self.assertEqual(self.events("requested")[-1]["client_id"], a["id"])

    def test_actions_need_csrf_and_the_human_identity(self):
        a = self.new_client("alpha")
        for path, form in (("/clients/revoke", {"id": a["id"]}), ("/clients/rename", {"id": a["id"], "name": "zed"}),
                           ("/clients/remove", {"id": a["id"]})):
            self.assertEqual(self.post(path, form, csrf=False)[0], 403, path)
            self.assertEqual(self.post(path, form, csrf="bad")[0], 403, path)
            self.assertEqual(self.post(path, form, user="mallory")[0], 403, path)
            self.assertEqual(self.post(path, form, headers={"Sec-Fetch-Site": "cross-site"})[0], 403, path)
        self.assertEqual(self.broker.clients.get(a["id"])["state"], "active")
        self.assertEqual(self.broker.clients.get(a["id"])["name"], "alpha")
        self.assertEqual(self.as_client(a["secret"], "GET", "/v1/status")[0], 200)

    def test_remove_only_forgets_revoked_rows(self):
        a = self.new_client("alpha")
        self.assertIn("note=active", self.post("/clients/remove", {"id": a["id"]})[2]["Location"])
        self.post("/clients/revoke", {"id": a["id"]})
        self.assertIn("note=removed", self.post("/clients/remove", {"id": a["id"]})[2]["Location"])
        self.assertIsNone(self.broker.clients.get(a["id"]))
        self.assertEqual(self.as_client(a["secret"], "GET", "/v1/status")[0], 401)
        self.assertEqual(self.events("client_removed")[0]["client_id"], a["id"])

    def test_clients_page(self):
        a = self.new_client("alpha", claim="bob@laptop")
        page = self.get("/clients")[1]
        for needle in ("Clients", "alpha", a["id"], "bob@laptop", "unverified", "shared key (legacy)",
                       "Revoke...", "Rename", "data-label=Name", "data-label='Last seen'", "data-label=Requests",
                       "data-label=State", "data-label=Ceiling", "Effective ceiling", "asb enroll"):
            self.assertIn(needle, page, needle)
        self.assertIn(self.broker.csrf_token("alice"), page)
        self.assertNotIn(a["secret"], page)
        self.assertNotIn(a["hash"], page)
        self.assertIn("<a href='/clients' class=on>Clients", page)
        self.assertEqual(self.get("/clients", user="mallory")[0], 403)


class TestAuthHelper:
    """http_as() usable from other classes in this file."""
    http_as = Auth.http_as


# ---------------------------------------------------------------------------- persistence
class Persistence(CBase):
    def restart(self):
        """A second broker over the same state directory (the first keeps running; tests only read)."""
        b = Broker(dict(approve_base_url="https://secrets.example", allowed_user="alice", ttl_seconds=60,
                        secrets={}), self.broker.backend, FakeNotifier(), self.audit)
        self.addCleanup(lambda: None)
        return b

    def test_clients_survive_a_restart(self):
        a, b = self.new_client("alpha"), self.new_client("bravo")
        self.as_client(a["secret"], "GET", "/v1/status")
        self.post("/clients/rename", {"id": b["id"], "name": "bravo-2"})
        self.post("/clients/revoke", {"id": a["id"]})
        self.broker.clients.flush()
        b2 = self.restart()
        self.assertEqual({c["name"]: c["state"] for c in b2.clients.rows()}, {"alpha": "revoked", "bravo-2": "active"})
        view, why = b2.clients.authenticate(b["secret"], KEY)
        self.assertEqual((view["id"], view["name"], why), (b["id"], "bravo-2", "ok"))
        self.assertEqual(b2.clients.authenticate(a["secret"], KEY)[1], "revoked")
        self.assertEqual(b2.clients.get(a["id"])["requests"], 1)

    def test_the_file_holds_hashes_only_and_is_private(self):
        c = self.new_client("alpha")
        path = os.path.join(os.path.dirname(self.audit), "clients.json")
        text = open(path).read()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn(c["hash"], text)
        self.assertNotIn(c["secret"], text)
        data = json.loads(text)
        self.assertEqual(set(data["clients"][0]), {"id", "name", "hash", "state", "created", "last_seen",
                                                   "requests", "last_source", "approved_by", "claim",
                                                   "enrolled_from", "revoked_at", "revoked_by"})

    def test_pending_enrollments_do_not_survive_a_restart(self):
        self.enr("laptop")
        self.assertEqual(self.restart().clients.pending(), [])

    def test_corrupt_file_fails_closed_and_is_left_alone(self):
        path = os.path.join(os.path.dirname(self.audit), "clients.json")
        junk = '{"clients": [ {"id": "nope"} ]}'
        with open(path, "w") as f:
            f.write(junk)
        b2 = self.restart()
        self.assertTrue(b2.clients.broken)
        self.assertEqual(b2.clients.rows(), [])
        self.assertEqual(b2.clients.submit("x", "0" * 64, "a@b", "1.2.3.4")[0], 503)
        self.assertEqual(b2.clients.authenticate(KEY, KEY)[1], "ok")         # the legacy key still works
        self.assertEqual(open(path).read(), junk)                            # never overwritten
        ev = [r for r in _fast.read_jsonl(self.audit) if r["event"] == "clients_file_corrupt"]
        self.assertEqual(len(ev), 1)
        self.assertNotIn("nope", json.dumps(ev))

    def test_a_failed_write_refuses_the_approval_and_leaks_nothing(self):
        code, body, secret, _ = self.enr("laptop")
        real = os.replace

        def boom(src, dst):
            if str(dst).endswith("clients.json"):
                raise OSError("LEAKY-PATH-TEXT /secret/place")
            return real(src, dst)
        buf = io.StringIO()
        with mock.patch("os.replace", boom), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            status, page, hdr = self.decide_enroll(body["id"])
        self.assertIn("note=enrollsave", hdr["Location"])
        self.assertEqual(self.broker.clients.rows(), [])                   # nothing half-enrolled
        self.assertEqual(len(self.broker.clients.pending()), 1)            # still waiting for another try
        self.assertEqual(self.as_client(secret, "GET", "/v1/status")[0], 401)
        for text in (self.audit_text(), buf.getvalue(), page, *self.seen):
            self.assertNotIn("LEAKY", text)
            self.assertNotIn("/secret/place", text)
        self.assertEqual(self.decide_enroll(body["id"])[0], 303)           # and it works once the disk does

    def test_a_failed_save_never_leaves_a_revoked_client_active(self):
        c = self.new_client("alpha")
        real = os.replace

        def boom(src, dst):
            if str(dst).endswith("clients.json"):
                raise OSError("LEAKY-PATH-TEXT")
            return real(src, dst)
        with mock.patch("os.replace", boom):
            status, _, hdr = self.post("/clients/revoke", {"id": c["id"]})
            self.assertIn("note=revokedmem", hdr["Location"])
            self.assertEqual(self.as_client(c["secret"], "GET", "/v1/status")[0], 401)   # effective now
        self.assertNotIn("LEAKY", self.audit_text())
        self.assertFalse(self.events("client_revoked")[0]["saved"])
        self.broker.clients.flush()                                         # the retry persists it
        self.assertEqual(self.restart().clients.get(c["id"])["state"], "revoked")


# ---------------------------------------------------------------------------- audit surface
class AuditSurface(CBase):
    def test_new_events_are_classified_for_the_agent_audit_view(self):
        a = self.new_client("alpha")
        self.post("/clients/rename", {"id": a["id"], "name": "alpha-2"})
        self.as_client("bad", "GET", "/v1/status")
        self.post("/clients/revoke", {"id": a["id"]})
        names = {r["event"] for r in self.records()}
        for ev in ("enroll_requested", "enroll_decided", "client_renamed", "client_revoked", "client_auth_failed"):
            self.assertIn(ev, names)
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertNotIn(ev, audit_api.WHITELIST)
        for ev in ("enroll_refused", "client_rename_refused", "client_removed", "clients_file_corrupt",
                   "clients_file_write_failed", "enroll_notify_failed"):
            self.assertIn(ev, audit_api.HIDDEN)

    def test_the_agent_sees_its_client_name_and_nothing_about_enrollment(self):
        a = self.new_client("alpha")
        rid = Auth.http_as(self, a["secret"])
        code, text = self.as_client(a["secret"], "GET", "/v1/audit?limit=500")
        self.assertEqual(code, 200)
        evs = json.loads(text)["events"]
        req = next(e for e in evs if e["event"] == "requested")
        self.assertEqual(req["client"], "alpha")
        self.assertNotIn("enroll", text)
        self.assertNotIn(a["hash"], text)
        self.assertNotIn(a["id"], text)

    def test_history_and_detail_show_the_client(self):
        a = self.new_client("alpha")
        rid = Auth.http_as(self, a["secret"])
        self.broker.decide_via("dashboard", rid, "deny", "alice")
        self.broker._by_id[rid].done.wait(5)
        row, evs = self.broker.history.detail(rid)
        self.assertEqual((row["client_id"], row["client_name"]), (a["id"], "alpha"))
        status, page, _ = self.get("/request/" + rid)
        self.assertEqual(status, 200)
        self.assertIn("alpha", page)
        self.assertIn("claimed by the client, unverified", page)


# ---------------------------------------------------------------------------- the real client
class CliEnroll(CBase):
    """`asb enroll` against the throwaway broker in a scratch HOME. The human is simulated by posting
    to the approval page after reading the pending card."""
    ttl = 600

    def setUp(self):
        super().setUp()
        self.home = tempfile.mkdtemp()
        self.cfgdir = os.path.join(self.home, ".config", "secret-broker")
        self.cfgfile = os.path.join(self.cfgdir, "client.json")

    def run_cli(self, *args, human=None, timeout=60, env_extra=None, snapshot_ps=False, on_request=None):
        env = {"PATH": os.environ["PATH"], "HOME": self.home, "USER": "bob"}
        env.update(env_extra or {})
        p = subprocess.Popen([*_fast.FAST_CLI, *args], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)           # the real client, poll sleeps capped
        ps = ""
        if human is not None:
            end = time.time() + 20
            while time.time() < end and not self.broker.clients.pending():
                time.sleep(0.05)
            if snapshot_ps:
                ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
            pend = self.broker.clients.pending()
            if pend:
                human(pend[0])
        if on_request is not None:              # a request the client made is waiting for a human
            _fast.wait_until(self.broker.pending, 20, "the client's request to be pending")
            on_request(self.broker.pending()[0].id)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        self.seen.extend([out, err])
        return p.returncode, out, err, ps

    def approve(self, e):
        self.assertIn(self.decide_enroll(e["id"], "approve")[0], (303,))

    def test_happy_path(self):
        rc, out, err, ps = self.run_cli("enroll", "--name", "build-box", "--url", self.base,
                                        human=self.approve, snapshot_ps=True)
        self.assertEqual(rc, 0, err)
        row = self.broker.clients.rows()[0]
        self.assertEqual(out.strip(), f"enrolled: build-box ({row['id']})")
        cfg = json.load(open(self.cfgfile))
        self.assertEqual(cfg["url"], self.base)
        self.assertTrue(cfg["key"].startswith("asbc1_"))
        self.assertEqual(len(cfg["key"]), 6 + 43)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfgfile).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfgdir).st_mode), 0o700)
        # the code on the terminal is the code on the card
        m = re.search(r"confirmation code: ([A-Z2-7]{4}-[A-Z2-7]{4})", err)
        self.assertTrue(m, err)
        self.assertEqual(m.group(1), clients_mod.confirm_code(clients_mod.hash_secret(cfg["key"])))
        self.assertEqual(self.events("enroll_requested")[0]["code"], m.group(1))
        # the secret is nowhere it should not be
        self.assertNotIn(cfg["key"], out + err + ps + self.audit_text())
        self.assertEqual(row["hash"], clients_mod.hash_secret(cfg["key"]))
        self.assertEqual(row["claim"].split("@")[0], "bob")
        # and the written config is a working credential for every other command
        rc, out, err, _ = self.run_cli("status", "--json")
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["features"]["client_enrollment"], True)
        rc, out, err, _ = self.run_cli("list")
        self.assertEqual(rc, 0, err)
        self.assertIn("svc", out)

    def test_default_name_is_the_host_name(self):
        rc, out, err, _ = self.run_cli("enroll", "--url", self.base, human=self.approve)
        self.assertEqual(rc, 0, err)
        import socket
        want = re.sub(r"[^a-z0-9_.-]+", "-", socket.gethostname().split(".")[0].lower()).strip("-.")[:32] or "client"
        self.assertEqual(self.broker.clients.rows()[0]["name"], want)

    def test_denied_exit_4_and_nothing_written(self):
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--url", self.base,
                                       human=lambda e: self.decide_enroll(e["id"], "deny"))
        self.assertEqual(rc, 4, err)
        self.assertIn("denied", err)
        self.assertEqual(out, "")
        self.assertFalse(os.path.exists(self.cfgfile))

    def test_expired_exit_5(self):
        self.broker.clients.cfg["enrollment"]["ttl_s"] = 2
        skew = [0]
        self.broker.clients.clock = lambda: time.time() + skew[0]
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--url", self.base,
                                       human=lambda e: skew.__setitem__(0, 10))      # the 2 s ttl passes
        self.assertEqual(rc, 5, err)
        self.assertIn("expired", err)
        self.assertFalse(os.path.exists(self.cfgfile))

    def test_refused_and_unreachable_exit_3(self):
        self.enr("box")                                          # a pending card with that name
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--url", self.base)
        self.assertEqual(rc, 3, err)
        self.assertIn("refused", err)
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--url", "http://127.0.0.1:9")
        self.assertEqual(rc, 3, err)
        self.assertIn("cannot reach", err)
        self.assertNotIn("Errno", err)                           # a class name at most, never exception text
        self.assertFalse(os.path.exists(self.cfgfile))

    def test_usage_errors_exit_2(self):
        for args in (["enroll", "--name"], ["enroll", "--bogus"], ["enroll", "--name", "BAD NAME", "--url", self.base],
                     ["enroll", "--name", "x" * 40, "--url", self.base], ["enroll"]):
            rc, out, err, _ = self.run_cli(*args)
            self.assertEqual(rc, 2, (args, err))
        self.assertEqual(self.broker.clients.pending(), [])

    def test_existing_config_needs_force_and_is_backed_up(self):
        os.makedirs(self.cfgdir, mode=0o700)
        old = {"url": self.base, "key": KEY, "extra": "kept"}
        with open(self.cfgfile, "w") as f:
            json.dump(old, f)
        rc, out, err, _ = self.run_cli("enroll", "--name", "box")
        self.assertEqual(rc, 2, err)
        self.assertIn("--force", err)
        self.assertEqual(json.load(open(self.cfgfile)), old)     # untouched
        self.assertEqual(self.broker.clients.pending(), [])
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--force", human=self.approve)
        self.assertEqual(rc, 0, err)
        baks = [f for f in os.listdir(self.cfgdir) if f.startswith("client.json.bak-")]
        self.assertEqual(len(baks), 1)
        self.assertEqual(json.load(open(os.path.join(self.cfgdir, baks[0]))), old)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.cfgdir, baks[0])).st_mode), 0o600)
        new = json.load(open(self.cfgfile))
        self.assertEqual((new["url"], new["extra"]), (self.base, "kept"))
        self.assertNotEqual(new["key"], KEY)
        self.assertIn("previous file is saved", err)
        self.assertNotIn(KEY, out + err)

    def test_url_comes_from_the_environment_or_the_existing_config(self):
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", human=self.approve,
                                       env_extra={"SECRET_BROKER_URL": self.base})
        self.assertEqual(rc, 0, err)

    def test_environment_key_override_is_flagged(self):
        rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--url", self.base, human=self.approve,
                                       env_extra={"SECRET_BROKER_KEY": "other"})
        self.assertEqual(rc, 0, err)
        self.assertIn("SECRET_BROKER_KEY", err)

    def test_a_key_the_broker_rejects_restores_the_old_file(self):
        os.makedirs(self.cfgdir, mode=0o700)
        old = {"url": self.base, "key": KEY}
        with open(self.cfgfile, "w") as f:
            json.dump(old, f)
        real = self.broker.clients.decide

        def approve_then_forget(eid, approve, name, actor):
            out = real(eid, approve, name, actor)
            if out[2]:
                self.broker.clients._clients.clear()             # the broker "loses" it before the check
            return out
        with mock.patch.object(self.broker.clients, "decide", approve_then_forget):
            rc, out, err, _ = self.run_cli("enroll", "--name", "box", "--force", human=self.approve)
        self.assertEqual(rc, 3, err)
        self.assertIn("rejected the new key", err)
        self.assertEqual(json.load(open(self.cfgfile)), old)

    def test_leak_check_after_a_full_lifecycle(self):
        """Secret, its hash and exception text appear in no log, audit record, history row, request
        detail, notification, page, CLI output or process list."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc, out, err, ps = self.run_cli("enroll", "--name", "leaky", "--url", self.base,
                                            human=self.approve, snapshot_ps=True)
            self.assertEqual(rc, 0, err)
            secret = json.load(open(self.cfgfile))["key"]
            cid = self.broker.clients.rows()[0]["id"]
            h = clients_mod.hash_secret(secret)
            rc, o2, e2, ps2 = self.run_cli("http", "svc", "GET", f"http://127.0.0.1:{self.up.server_address[1]}/x",
                                           "-H", "Authorization: Bearer {{SVC_TOKEN}}",
                                           on_request=lambda rid: self.broker.decide_via(
                                               "dashboard", rid, "deny", "alice"))
            self.post("/clients/rename", {"id": cid, "name": "leaky2"})
            self.as_client("asbc1_wrongwrong", "GET", "/v1/status")
            self.post("/clients/revoke", {"id": cid})
            self.as_client(secret, "GET", "/v1/status")
        self.broker.flush_notifications(5)
        pages = [self.get(p)[1] for p in ("/", "/clients", "/policies", "/settings")]
        details = ""
        det = os.path.join(os.path.dirname(self.audit), "request_details.db")
        if os.path.exists(det):
            details = open(det, "rb").read().decode("latin-1")
        notes = json.dumps([(n.title, n.text, n.names, n.url) for n in self.notifier.notifications])
        hist = json.dumps(self.broker.history.rows())
        blob = "\n".join([out, err, o2, e2, ps, ps2, buf.getvalue(), self.audit_text(), notes, hist, details,
                          *pages, *self.seen])
        for canary in (secret, h):
            self.assertNotIn(canary, blob)
        self.assertNotIn(h[:12], blob)
        self.assertIn(h, open(os.path.join(os.path.dirname(self.audit), "clients.json")).read())
        self.assertNotIn("Traceback", "\n".join([out, err, o2, e2, self.audit_text(), *pages]))

    def test_server_text_cannot_inject_terminal_control_characters(self):
        asb = load_asb()
        self.assertEqual(asb._safe_text("ok\x1b[31mred\x07\n"), "ok?[31mred??")


if __name__ == "__main__":
    unittest.main()
