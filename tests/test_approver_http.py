"""The approver API's HTTP routes on the client listener (/v1/approver/*): OIDC bearer auth,
rate limits, coalesced refusal audit, body caps, the long poll, decide and app presence.
A local stub issuer serves the discovery document and JWKS; tokens are signed with real keys."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)
from test_approver_oidc import Key  # noqa: E402  (signing helper only)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # the stub issuer lives on 127.0.0.1; no config key does this
from secret_broker import approver_api, audit_api, notify, presence  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

CLIENT = "asb-app"
P = "/v1/approver"


class Issuer:
    """An in-process OIDC issuer: discovery + JWKS over plain http on loopback."""

    def __init__(self, *keys):
        self.keys, self.down = list(keys), False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if outer.down:
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    return self.end_headers()
                if self.path.endswith("/.well-known/openid-configuration"):
                    body = {"issuer": outer.url, "jwks_uri": outer.url + "/jwks"}
                elif self.path.endswith("/jwks"):
                    body = {"keys": [k.jwk for k in outer.keys]}
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    return self.end_headers()
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/realms/home"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


_KEY = Key("k1")            # RSA key generation is slow: one for the whole module


class Base(t.Dashboard):
    configured = True
    issuer_down = False

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.configured:
            cfg["approver_api"] = {"issuer": self.issuer.url, "client_id": CLIENT}

    def setUp(self):
        self.key = _KEY
        self.issuer = Issuer(self.key)
        self.issuer.down = self.issuer_down
        self.addCleanup(self.issuer.close)
        super().setUp()

    def token(self, **claims):
        c = {"iss": self.issuer.url, "aud": CLIENT, "preferred_username": "alice",
             "exp": time.time() + 600, "iat": time.time()}
        c.update(claims)
        return self.key.token(c)

    def app(self, method, path, body=None, token="valid", headers=None, raw=None):
        """-> (status, headers, parsed JSON or None)."""
        h = {"Content-Type": "application/json"}
        if token == "valid":
            token = self.token()
        if token is not None:
            h["Authorization"] = "Bearer " + token
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                code, hdrs, text = resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            code, hdrs, text = e.code, e.headers, e.read()
        try:
            return code, hdrs, json.loads(text)
        except ValueError:
            return code, hdrs, None

    def audit_text(self):
        with open(self.audit) as f:
            return f.read()


for _n in dir(t.Dashboard):         # reuse its helpers, not its tests
    if _n.startswith("test"):
        setattr(Base, _n, None)


class NoConfig(Base):
    configured = False

    def test_all_paths_404_without_config(self):
        self.assertIsNone(self.broker.approver)
        for method, path, body in (("GET", P + "/config", None), ("GET", P + "/pending", None),
                                   ("GET", P + "/pending?since=0&wait=5", None),
                                   ("POST", P + "/decide", {"id": "x", "decision": "deny"}),
                                   ("POST", P + "/presence", {"active": True}),
                                   ("GET", P, None), ("GET", P + "/nope", None),
                                   ("PUT", P + "/config", {}), ("DELETE", P + "/pending", None)):
            for tok in (None, "valid"):
                code, _, got = self.app(method, path, body, token=tok)
                self.assertEqual((code, got), (404, {"error": "not found"}), (method, path, tok))
        self.assertEqual(self.events("approver_auth_refused"), [])


class Routes(Base):
    def test_config_unauthenticated(self):
        code, hdrs, got = self.app("GET", P + "/config", token=None)
        self.assertEqual(code, 200)
        self.assertEqual(got, {"issuer": self.issuer.url, "client_id": CLIENT,
                               "scopes": ["openid", "profile", "offline_access"], "api_version": 1})
        self.assertEqual(hdrs.get("Content-Type"), "application/json")

    def test_unknown_path_404_and_wrong_method_405(self):
        self.assertEqual(self.app("GET", P + "/nope")[0], 404)
        self.assertEqual(self.app("POST", P + "/pending", {})[0], 405)
        self.assertEqual(self.app("GET", P + "/decide")[0], 405)
        self.assertEqual(self.app("PUT", P + "/presence", {})[0], 405)

    def test_client_key_refused_on_approver(self):
        for tok in (None, "valid"):
            code, _, got = self.app("GET", P + "/pending", token=tok, headers={"X-Client-Key": t.KEY})
            self.assertEqual((code, got), (401, {"error": "unauthorized"}), tok)
        code, _, _ = self.app("POST", P + "/presence", {"active": True}, token=None,
                              headers={"X-Client-Key": t.KEY})
        self.assertEqual(code, 401)
        self.assertEqual(self.broker.presence._users, {})

    def test_jwt_refused_on_v1_requests(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, _, _ = self.app("POST", "/v1/requests", {"mode": "http", "names": ["svc"],
                                                        "method": "GET", "url": url})
        self.assertEqual(code, 401)
        self.assertEqual(self.broker._by_id, {})
        self.assertEqual(self.app("GET", "/v1/status")[0], 401)

    def test_each_refusal_audited_without_token(self):
        bad = {"expired": self.token(exp=time.time() - 3600),
               "user": self.token(preferred_username="mallory"),
               "audience": self.token(aud="someone-else"),
               "issuer": self.token(iss="https://evil.example"),
               "malformed": "not.a.jwt",
               "signature": self.token()[:-6] + "AAAAAA"}
        for reason, tok in bad.items():
            code, hdrs, got = self.app("GET", P + "/pending", token=tok)
            self.assertEqual((code, got), (401, {"error": "unauthorized"}), reason)
            self.assertEqual(hdrs.get("WWW-Authenticate"), "Bearer")
        self.assertEqual(self.app("GET", P + "/pending", token=None)[0], 401)
        evs = self.events("approver_auth_refused")
        self.assertEqual(sorted(e["reason"] for e in evs), sorted(list(bad) + ["missing"]))
        for e in evs:
            self.assertEqual(set(e) - {"time", "ts", "seq", "prev", "event"}, {"reason", "peer"})
            self.assertIn(e["reason"], approver_api.oidc.REASONS)
            self.assertIsNone(audit_api.redact(e))          # never in the agent's audit view
        text = self.audit_text()
        for tok in bad.values():
            self.assertNotIn(tok, text)
            self.assertNotIn(tok.split(".")[-1], text)
        self.assertNotIn("mallory", text)

    def test_refusals_coalesced_per_window(self):
        clock = [1000.0]
        self.broker.approver.clock = lambda: clock[0]
        tok = self.token(exp=time.time() - 3600)
        for _ in range(3):
            self.assertEqual(self.app("GET", P + "/pending", token=tok)[0], 401)
        self.assertEqual(self.app("GET", P + "/pending", token="x")[0], 401)    # another reason: own line
        evs = self.events("approver_auth_refused")
        self.assertEqual([(e["reason"], e.get("suppressed")) for e in evs],
                         [("expired", None), ("malformed", None)])
        clock[0] += 61
        self.assertEqual(self.app("GET", P + "/pending", token=tok)[0], 401)
        evs = self.events("approver_auth_refused")
        self.assertEqual((evs[-1]["reason"], evs[-1]["suppressed"]), ("expired", 2))

    def test_body_over_4k_is_413(self):
        for path in ("/decide", "/presence"):
            code, _, got = self.app("POST", P + path, raw=b'{"a": "' + b"x" * 5000 + b'"}')
            self.assertEqual((code, got), (413, {"error": "request too large"}), path)
        code, _, _ = self.app("POST", P + "/presence", raw=b"not json")
        self.assertEqual(code, 400)

    def test_rate_limit_valid_and_shared_invalid_bucket(self):
        bad = self.token(preferred_username="mallory")
        limit = self.broker.APP_UNAUTH_LIMIT_PER_MIN
        for _ in range(limit):
            self.assertEqual(self.app("GET", P + "/pending", token=bad)[0], 401)
        code, _, got = self.app("GET", P + "/pending", token="garbage")       # the shared bucket
        self.assertEqual(code, 429)
        self.assertEqual(self.app("GET", P + "/pending", token=None)[0], 429)
        self.assertEqual(self.broker._app_rate, {})          # bad tokens made no per-source state
        tok = self.token()
        for i in range(self.broker.APP_LIMIT_PER_MIN):       # a valid token still works
            self.assertEqual(self.app("GET", P + "/pending", token=tok)[0], 200, i)
        code, hdrs, got = self.app("GET", P + "/pending", token=tok)
        self.assertEqual((code, got), (429, {"error": "rate limited"}))
        self.assertEqual(hdrs.get("Retry-After"), "60")
        self.assertEqual(len(self.events("approver_rate_limited")), 2)      # first drop per bucket


class Unavailable(Base):
    issuer_down = True

    def test_503_when_jwks_unavailable(self):
        self.assertEqual(len(self.events("approver_api_discovery_failed")), 1)
        code, _, got = self.app("GET", P + "/pending")
        self.assertEqual((code, got), (503, {"error": "identity provider unavailable"}))
        self.assertEqual([e["reason"] for e in self.events("approver_auth_refused")],
                         ["jwks_unavailable"])
        self.assertEqual(self.app("GET", P + "/config", token=None)[0], 200)
        self.issuer.down = False
        self.broker.approver.verifier._last_fetch = None        # the once-a-minute refetch is due
        self.assertEqual(self.app("GET", P + "/pending")[0], 200)


class Pending(Base):
    def test_pending_lists_and_long_polls(self):
        code, hdrs, got = self.app("GET", P + "/pending")
        self.assertEqual((code, got["requests"]), (200, []))
        self.assertIsNone(hdrs.get("Retry-After"))
        v0 = got["version"]
        out = {}

        def poll():
            t0 = time.time()
            out["r"] = self.app("GET", f"{P}/pending?since={v0}&wait=5")
            out["dt"] = time.time() - t0
        th = threading.Thread(target=poll)
        th.start()
        time.sleep(0.3)
        rid = self.ask()
        self.broker.flush_notifications(10)
        th.join(10)
        code, hdrs, got = out["r"]
        self.assertEqual(code, 200)
        self.assertGreater(got["version"], v0)
        self.assertLess(out["dt"], 4.5)
        self.assertIsNone(hdrs.get("Retry-After"))
        _, _, got = self.app("GET", P + "/pending")
        self.assertEqual([r["id"] for r in got["requests"]], [rid])
        self.assertEqual(got["requests"][0]["actions"][0], "deny")
        rid2 = self.ask("/y")
        _, _, got = self.app("GET", P + "/pending")
        self.assertEqual([r["id"] for r in got["requests"]], [rid, rid2])     # oldest first

    def test_wait_capped_at_25(self):
        feed = self.broker.approver.feed
        seen = []

        def fake_wait(since, timeout, fp):
            seen.append(timeout)
            return feed.version + 1
        with mock.patch.object(feed, "wait", fake_wait):
            self.assertEqual(self.app("GET", f"{P}/pending?since=0&wait=600")[0], 200)
            self.assertEqual(self.app("GET", f"{P}/pending?since=0&wait=3")[0], 200)
            self.assertEqual(self.app("GET", f"{P}/pending")[0], 200)
        self.assertEqual(seen, [25, 3, 0])

    def test_bad_query_is_400(self):
        for q in ("since=x", "wait=-1", "wait=1.5", "since=" + "9" * 30):
            self.assertEqual(self.app("GET", f"{P}/pending?{q}")[0], 400, q)

    def test_waiter_cap_answers_at_once_with_retry_after(self):
        feed = self.broker.approver.feed
        feed.max_waiters = 0
        v = self.app("GET", P + "/pending")[2]["version"]
        t0 = time.time()
        code, hdrs, got = self.app("GET", f"{P}/pending?since={v}&wait=5")
        self.assertLess(time.time() - t0, 2)
        self.assertEqual((code, got["version"]), (200, v))
        self.assertEqual(hdrs.get("Retry-After"), "2")
        # an unknown `since` (broker restarted) answers at once without asking the app to back off
        code, hdrs, _ = self.app("GET", f"{P}/pending?since={v + 100}&wait=5")
        self.assertEqual(code, 200)
        self.assertIsNone(hdrs.get("Retry-After"))


class Decide(Base):
    def test_decide_approves_once(self):
        rid = self.ask()
        self.broker.flush_notifications(10)
        code, _, got = self.app("POST", P + "/decide", {"id": rid, "decision": "approve"})
        self.assertEqual((code, got), (200, {"ok": True}))
        self.assertEqual(self.result(rid)["status"], "approved")
        code, _, got = self.app("POST", P + "/decide", {"id": rid, "decision": "deny"})
        self.assertEqual((code, got), (410, {"ok": False}))
        self.assertEqual(self.app("POST", P + "/decide", {"id": "nope", "decision": "deny"})[0], 404)
        self.assertEqual(self.app("POST", P + "/decide", {"id": rid, "decision": "maybe"})[0], 400)
        self.assertEqual(self.app("POST", P + "/decide", ["x"])[0], 400)
        text = self.audit_text()
        self.assertIn("app:alice", text)
        self.assertNotIn(self.token().split(".")[-1], text)


class AppPresence(Base):
    ttl = 300

    def setUp(self):
        super().setUp()
        self.wp = FakeNotifier(type_name="webpush")
        self.broker.notifier = notify.MultiNotifier([self.wp])
        self.broker._presence_autostart = False

    def test_presence_active_holds_phone_and_inactive_releases(self):
        code, _, got = self.app("POST", P + "/presence", {"active": True, "device": "ryans-mac.local:1"})
        self.assertEqual((code, got), (200, {"ok": True}))
        self.assertEqual(list(self.broker.presence._users["alice"]), ["app-ryans-mac_local_1"])
        rid = self.ask()
        self.broker.flush_notifications(10)
        self.assertEqual(self.wp.sent, [])
        self.assertIn(rid, self.broker._held)
        self.broker.presence_tick()
        self.assertEqual(self.wp.sent, [])
        code, _, got = self.app("POST", P + "/presence", {"active": False, "device": "ryans-mac.local:1"})
        self.assertEqual((code, got), (200, {"ok": True}))
        self.broker.presence_tick()
        self.assertEqual(len(self.wp.sent), 1)
        self.assertNotIn(rid, self.broker._held)

    def test_presence_tab_ids(self):
        self.assertEqual(approver_api.presence_tab(None), "app-unknown")
        self.assertEqual(approver_api.presence_tab("a.b:c"), "app-a_b_c")
        tab = approver_api.presence_tab("x" * 64)
        self.assertEqual(tab, ("app-" + "x" * 64)[:32])
        self.assertTrue(presence.TAB_RE.match(tab))

    def test_presence_rejects_bad_bodies(self):
        for body in ({}, {"active": "yes"}, {"active": True, "device": "bad device!"},
                     {"active": True, "extra": 1}, {"active": True, "device": "x" * 65}, [True]):
            self.assertEqual(self.app("POST", P + "/presence", body)[0], 400, body)
        self.assertEqual(self.broker.presence._users, {})


if __name__ == "__main__":
    unittest.main()
