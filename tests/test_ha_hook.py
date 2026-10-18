"""Home Assistant actionable-notification hook: ticker action payloads,
POST /v1/hooks/ha/decide on the client listener, channel `ha`."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import notify  # noqa: E402
from secret_broker.broker import CHANNELS, Broker, serve  # noqa: E402

HOOK = "h" * 40
PATH = "/v1/hooks/ha/decide"


def note(risk="low", policy=None, rid="Rid_abc-123", token="Tok_xyz-789"):
    t_ = notify.TickerNotifier("http://ha.example", "tok", actions_enabled=True)
    return t_, notify.make_notification(
        rid=rid, tag="secret-x", title="T", text="body", names=["svc"], risk=risk,
        url="https://x/a/n", source="host", summary=None, expires_at=1.0, transport=t_,
        default_policy=policy)


class FakeHA(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *a):
        pass

    def _reply(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        FakeHA.calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self._reply([])

    def do_GET(self):
        self._reply({"attributes": {"notifications": [{"delivered": True}]}})


class TickerActions(unittest.TestCase):
    def setUp(self):
        FakeHA.calls.clear()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeHA)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self._sleep, time.sleep = time.sleep, lambda s: None

    def tearDown(self):
        time.sleep = self._sleep
        self.srv.shutdown()
        self.srv.server_close()

    def send(self, enabled=True, risk="low", policy=None):
        tk = notify.TickerNotifier(self.url, "tok", actions_enabled=enabled)
        n = notify.make_notification(
            rid="Rid_abc-123", tag="secret-x", title="T", text="body", names=["svc"], risk=risk,
            url="https://x/a/n", source="host", summary=None, expires_at=1.0, transport=tk,
            default_policy=policy)
        tk.send(n.for_transport(tk))
        return n, FakeHA.calls[-1]

    def test_payload_shape_and_order(self):
        n, body = self.send()
        self.assertNotIn("actions", body)              # top-level is Ticker's switch only
        self.assertEqual(body["data"]["actions"], [
            {"action": f"ASB|deny|Rid_abc-123|{n.action_token}", "title": "Deny"},
            {"action": f"ASB|approve|Rid_abc-123|{n.action_token}", "title": "Approve"}])
        self.assertEqual((body["title"], body["message"]), ("T", "body"))     # text unchanged
        for a in body["data"]["actions"]:
            self.assertLess(len(a["action"]), 100)
            self.assertRegex(a["action"], r"^ASB\|(approve|deny)\|[A-Za-z0-9_-]+\|[A-Za-z0-9_-]+$")

    def test_no_actions_without_hook(self):
        n, body = self.send(enabled=False)
        self.assertNotIn("actions", body)
        self.assertNotIn("actions", body["data"])
        self.assertIsNone(n.action_token)

    def test_policy_applies(self):
        pol = notify.parse_action_policy({"approve_max_risk": "low", "deny": True}, "x")
        _, body = self.send(risk="medium", policy=pol)
        self.assertEqual([a["title"] for a in body["data"]["actions"]], ["Deny"])
        none = notify.parse_action_policy({"approve_max_risk": "none", "deny": False}, "x")
        n, body = self.send(policy=none)
        self.assertNotIn("actions", body)
        self.assertNotIn("actions", body["data"])
        self.assertIsNone(n.action_token)

    def test_unsafe_ids_drop_buttons(self):
        tk, n = note(rid="a|b")
        self.assertEqual(tk.action_list(n), [])

    def test_build_enables_only_with_hook(self):
        rd = {"ha": "x"}.__getitem__
        base = {"ha_url": "http://ha", "ha_token_file": "ha"}
        self.assertEqual(notify.build(dict(base), rd).supports_actions, ())
        self.assertEqual(notify.build({**base, "ha_hook": {"key": HOOK}}, rd).supports_actions,
                         ("approve", "deny"))


class Validation(unittest.TestCase):
    def check(self, raw, field, rd=lambda p: "k" * 40):
        with self.assertRaises(ValueError) as cm:
            notify.parse_ha_hook(raw, rd)
        self.assertIn(field, str(cm.exception))

    def test_startup_validation(self):
        self.assertIsNone(notify.parse_ha_hook(None, None))
        self.check("x", "ha_hook")
        self.check({"key": "short"}, "ha_hook.key")
        self.check({"key_file": "/nope"}, "ha_hook.key_file", rd=lambda p: open(p).read())
        self.check({"key_file": "/f"}, "ha_hook.key_file", rd=lambda p: "short")
        self.check({"key": HOOK, "key_file": "/f"}, "ha_hook")
        self.check({}, "ha_hook")
        self.check({"key": HOOK, "allowed_devices": "phone"}, "ha_hook.allowed_devices")
        self.check({"key": HOOK, "allowed_devices": [1]}, "ha_hook.allowed_devices")
        self.check({"key": HOOK, "nope": 1}, "ha_hook.nope")
        ok = notify.parse_ha_hook({"key_file": "/f", "allowed_devices": ["a"]}, lambda p: HOOK)
        self.assertEqual(ok, {"key": HOOK, "allowed_devices": ["a"]})

    def test_broker_refuses_bad_hook_and_equal_keys(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "v.json")
        with open(p, "w") as f:
            json.dump({}, f)
        with self.assertRaises(ValueError):
            Broker({"approve_base_url": "https://s", "ha_hook": {"key": "x"}},
                   t.FileBackend(p), t.FakeNotifier(), None)
        b = Broker({"approve_base_url": "https://s", "ha_hook": {"key": t.KEY + "x" * 40}},
                   t.FileBackend(p), t.FakeNotifier(), None)
        with self.assertRaises(ValueError):
            b.ha_hook = {"key": t.KEY, "allowed_devices": []}
            serve(b, ("127.0.0.1", 0), ("127.0.0.1", 0), t.KEY)


class Hook(t.Dashboard):
    hook_cfg = {"key": HOOK, "allowed_devices": ["phone-1"]}

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.hook_cfg is not None:
            cfg["ha_hook"] = dict(self.hook_cfg)

    def setUp(self):
        super().setUp()
        self.notifier.supports_actions = ("approve", "deny")

    def asked(self, path="/x"):
        rid = self.ask(path)
        end = time.time() + 5
        while not any(x.rid == rid for x in self.notifier.notifications) and time.time() < end:
            time.sleep(0.05)
        return rid, next(x for x in self.notifier.notifications if x.rid == rid)

    def hook(self, body, key=HOOK, raw=None, headers=None, path=PATH):
        h = {"Content-Type": "application/json"}
        if key is not None:
            h["Authorization"] = f"Bearer {key}"
        h.update(headers or {})
        data = raw if raw is not None else json.dumps(body).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.base + path, data=data, headers=h, method="POST"), timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def good(self, rid, n, decision="approve", device="phone-1"):
        return {"rid": rid, "token": n.action_token, "decision": decision, "device": device}


class HookEndpoint(Hook):
    def test_hook_key_decides_with_ha_channel(self):
        rid, n = self.asked()
        code, body = self.hook(self.good(rid, n))
        self.assertEqual((code, json.loads(body)), (200, {"ok": True, "decision": "approve"}))
        self.assertEqual(self.result(rid)["status"], "approved")
        (d,) = self.events("decided")
        self.assertEqual((d["channel"], d["approver"], d["via"], d["decision"], d["always_requested"]),
                         ("ha", "ha:phone-1", "user", "approve", False))
        self.assertEqual(self.events("policy_change"), [])

    def test_deny_and_unknown_device_label(self):
        rid, n = self.asked()
        g = self.good(rid, n, "deny")
        del g["device"]
        self.broker.ha_hook["allowed_devices"] = []
        self.assertEqual(self.hook(g)[0], 200)
        self.assertEqual(self.events("decided")[0]["approver"], "ha:unknown")
        self.assertEqual(self.events("denied")[0]["channel"], "ha")

    def test_auth_matrix(self):
        rid, n = self.asked()
        g = self.good(rid, n)
        self.assertEqual(self.hook(g, key=t.KEY)[0], 403)                      # agent key as bearer
        self.assertEqual(self.hook(g, key=None, headers={"X-Client-Key": t.KEY})[0], 403)
        self.assertEqual(self.hook(g, key=None)[0], 403)
        self.assertEqual(self.hook(g, key="w" * 40)[0], 403)
        self.assertEqual(self.hook(g, key=HOOK[:-1])[0], 403)
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.hook(g)[0], 200)

    def test_hook_key_rejected_elsewhere(self):
        for method, path in (("POST", "/v1/requests"), ("GET", "/v1/secrets"),
                             ("GET", "/v1/requests/abc")):
            code, _ = t.req(self.base + path, method,
                            {"mode": "env", "names": ["svc"]} if method == "POST" else None,
                            {"X-Client-Key": HOOK, "Authorization": f"Bearer {HOOK}"})
            self.assertEqual(code, 401, path)
        self.assertEqual(self.api("GET", "/v1/secrets")[0], 200)               # client key still fine

    def test_status_codes(self):
        rid, n = self.asked()
        g = self.good(rid, n)
        self.assertEqual(self.hook({**g, "token": "x" * 22})[0], 403)          # wrong token
        self.assertEqual(self.hook({**g, "rid": "nope"})[0], 404)
        self.assertEqual(self.hook(g)[0], 200)
        self.assertEqual(self.hook(g)[0], 410)                                 # replay
        self.assertEqual(self.hook({**g, "decision": "deny"})[0], 410)
        self.assertEqual(len(self.events("decided")), 1)
        self.assertIsNone(self.broker._by_id[rid].action_hash)

    def test_decision_elsewhere_spends_token(self):
        rid, n = self.asked()
        self.broker.decide_via("dashboard", rid, "deny", "alice")
        self.assertEqual(self.hook(self.good(rid, n))[0], 410)

    def test_malformed_and_oversize(self):
        rid, n = self.asked()
        g = self.good(rid, n)
        for bad in ({**g, "decision": "maybe"}, {**g, "rid": 5}, {**g, "rid": "a b"},
                    {**g, "token": ""}, {**g, "device": "x" * 65}, {**g, "device": "a b"},
                    {**g, "device": 3}, [1]):
            self.assertEqual(self.hook(bad)[0], 400, bad)
        self.assertEqual(self.hook(None, raw=b"{nope")[0], 400)
        self.assertEqual(self.hook(None, raw=b"x" * 3000)[0], 413)
        self.assertEqual(self.events("decided"), [])

    def test_responses_have_no_request_details(self):
        rid, n = self.asked()
        for code, body in (self.hook({**self.good(rid, n), "token": "x" * 22}), self.hook(self.good(rid, n))):
            for s in ("svc", "127.0.0.1", rid, n.action_token, "Reads"):
                self.assertNotIn(s, body)

    def test_empty_device_is_unknown(self):
        rid, n = self.asked()
        self.assertEqual(self.hook(self.good(rid, n, device=""))[0], 403)   # allow-list set
        self.broker.ha_hook["allowed_devices"] = []
        self.assertEqual(self.hook(self.good(rid, n, device=""))[0], 200)
        self.assertEqual(self.events("decided")[0]["approver"], "ha:unknown")

    def test_allowed_devices(self):
        rid, n = self.asked()
        self.assertEqual(self.hook(self.good(rid, n, device="evil"))[0], 403)
        d = self.good(rid, n)
        del d["device"]
        self.assertEqual(self.hook(d)[0], 403)
        self.assertEqual(self.events("decided"), [])
        refused = self.events("ha_decide_refused")
        self.assertEqual(len(refused), 2)
        self.assertEqual(refused[0]["user"], "ha:evil")
        self.assertEqual(self.hook(self.good(rid, n))[0], 200)                 # token not burned

    def test_rate_limit(self):
        codes = [self.hook({"rid": "r", "token": "t", "decision": "deny", "device": "phone-1"})[0]
                 for _ in range(65)]
        self.assertEqual(codes[:60].count(404), 60)
        self.assertEqual(set(codes[60:]), {429})
        self.assertEqual(len(self.events("ha_decide_dropped")), 1)

    def test_token_never_in_audit_or_history(self):
        rid, n = self.asked()
        self.hook(self.good(rid, n))
        self.hook({**self.good(rid, n), "token": "S" * 22})
        self.result(rid)
        with open(self.audit) as f:
            self.assertNotIn(n.action_token, f.read())
        self.assertNotIn(n.action_token, json.dumps(self.broker.history.__dict__, default=str))
        with open(self.audit) as f:
            self.assertNotIn("S" * 22, f.read())

    def test_channel_registry(self):
        self.assertTrue(CHANNELS["ha"].token_required)
        self.assertFalse(CHANNELS["ha"].may_create_always)


class ActionPolicyAtDecision(Hook):
    """The token only authorises the actions that were actually offered."""
    policy = {"approve_max_risk": "low", "deny": True}
    risk = "high"

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["notify_actions"] = dict(self.policy)

    def setUp(self):
        super().setUp()
        self.broker.summarizer = t._Stub("Reads things", self.risk)

    def test_unoffered_approve_refused_on_ha_and_push_token_not_spent(self):
        rid, n = self.asked()
        self.assertEqual([a.id for a in n.actions], ["deny"])
        self.assertEqual(self.broker._by_id[rid].offered, frozenset({"deny"}))
        self.assertEqual(self.hook(self.good(rid, n, "approve"))[0], 403)
        code, req = self.broker.decide_via("push", rid, "approve", "u", token=n.action_token)
        self.assertEqual((code, req), (403, None))
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertIsNotNone(self.broker._by_id[rid].action_hash)
        self.assertEqual(self.events("decided"), [])
        ref = self.events("decision_refused")
        self.assertEqual([(e["channel"], e["decision"]) for e in ref],
                         [("ha", "approve"), ("push", "approve")])
        with open(self.audit) as f:
            self.assertNotIn(n.action_token, f.read())
        self.assertEqual(self.hook(self.good(rid, n, "deny"))[0], 200)       # token still works
        self.assertEqual(self.result(rid)["status"], "denied")

    def test_dashboard_approve_unaffected(self):
        rid, n = self.asked()
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice")[0], 200)
        self.assertEqual(self.result(rid)["status"], "approved")

    def test_offered_approve_and_deny_work(self):
        self.broker.summarizer = t._Stub("Reads things", "low")
        rid, n = self.asked()
        self.assertEqual(self.broker._by_id[rid].offered, frozenset({"approve", "deny"}))
        self.assertEqual(self.hook(self.good(rid, n, "approve"))[0], 200)
        rid2, n2 = self.asked("/y")
        self.assertEqual(self.broker.decide_via("push", rid2, "deny", "u", token=n2.action_token)[0], 200)

    def test_no_token_means_token_channels_refused(self):
        rid, n = self.asked()
        self.broker._by_id[rid].offered = frozenset()
        self.assertEqual(self.broker.decide_via("push", rid, "deny", "u", token=n.action_token)[0], 403)

    def test_union_across_transports(self):
        a = t.FakeNotifier(supports_actions=("approve", "deny"))
        a.action_policy = {"approve_max_risk": "none", "deny": True}
        b = t.FakeNotifier(supports_actions=("approve", "deny"))
        b.action_policy = {"approve_max_risk": "high", "deny": False}
        self.broker.notifier = notify.MultiNotifier([a, b])
        rid = self.ask("/u")
        end = time.time() + 5
        while not a.notifications and time.time() < end:
            time.sleep(0.05)
        n = a.notifications[0]
        self.assertEqual(self.broker._by_id[rid].offered, frozenset({"approve", "deny"}))
        self.assertEqual(self.broker.decide_via("push", rid, "approve", "u", token=n.action_token)[0], 200)

    def test_union_when_only_one_transport_denies(self):
        a = t.FakeNotifier(supports_actions=("approve", "deny"))
        a.action_policy = {"approve_max_risk": "none", "deny": True}
        b = t.FakeNotifier(supports_actions=())
        self.broker.notifier = notify.MultiNotifier([a, b])
        rid = self.ask("/v")
        end = time.time() + 5
        while not a.notifications and time.time() < end:
            time.sleep(0.05)
        n = a.notifications[0]
        self.assertEqual(self.broker._by_id[rid].offered, frozenset({"deny"}))
        self.assertEqual(self.broker.decide_via("push", rid, "approve", "u", token=n.action_token)[0], 403)


def ipn(i):
    return f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"


class RateMapBound(Hook):
    def test_valid_key_map_capped_evicts_oldest_serves_newest(self):
        b, cap = self.broker, self.broker.RATE_MAP_CAP
        self.assertEqual(cap, 4096)
        for i in range(10000):
            self.assertTrue(b.ha_rate_ok(ipn(i)), i)            # never refused for being full
            self.assertLessEqual(len(b._ha_rate), cap)
            b._ha_rate[ipn(i)]["t"] += i * 1e-6                 # strictly increasing window starts
        self.assertEqual(len(b._ha_rate), cap)
        self.assertIn(ipn(9999), b._ha_rate)                    # newest served and tracked
        self.assertNotIn(ipn(0), b._ha_rate)                    # oldest evicted
        self.assertIn(ipn(10000 - cap), b._ha_rate)
        self.assertNotIn(ipn(10000 - cap - 1), b._ha_rate)
        res = [b.ha_rate_ok("192.0.2.2") for _ in range(65)]
        self.assertEqual((res[:60].count(True), res[60:].count(True)), (60, 0))
        self.assertLessEqual(len(b._ha_rate), cap)

    def test_window_expiry_still_works(self):
        b = self.broker
        for _ in range(60):
            self.assertTrue(b.ha_rate_ok("192.0.2.9"))
        self.assertFalse(b.ha_rate_ok("192.0.2.9"))
        b._ha_rate["192.0.2.9"]["t"] -= 120
        self.assertTrue(b.ha_rate_ok("192.0.2.9"))

    def test_make_room_prunes_expired_before_evicting(self):
        now = time.time()
        cap = self.broker.RATE_MAP_CAP
        m = {i: {"t": now - (120 if i % 2 else 0)} for i in range(cap)}
        self.broker.rate_map_make_room(m, now)
        self.assertEqual(len(m), cap // 2)
        m = {i: {"t": now - i * 0.001} for i in range(cap)}      # all live: evict oldest only
        self.broker.rate_map_make_room(m, now)
        self.assertEqual(len(m), cap - 1)
        self.assertNotIn(cap - 1, m)

    def test_bad_key_flood_creates_no_state_and_cannot_lock_out_ha(self):
        b = self.broker
        for i in range(10000):
            b.ha_unauth_ok(ipn(i))
        self.assertEqual(len(b._ha_rate), 0)
        # shared bucket exhausted (429 for bad key), yet the keyed caller is served
        self.assertFalse(b.ha_unauth_ok("203.0.113.5"))
        self.assertEqual(len(b._ha_rate), 0)
        res = [b.ha_rate_ok("198.51.100.7") for _ in range(65)]
        self.assertEqual((res[:60].count(True), res[60:].count(True)), (60, 0))

    def test_bad_key_http_flood_shared_bucket_429_and_valid_key_still_ok(self):
        b, lim = self.broker, self.broker.HA_UNAUTH_LIMIT_PER_MIN
        self.assertEqual(lim, 120)
        codes = [self.hook({"rid": "r"}, key="w" * 40)[0] for _ in range(lim + 5)]
        self.assertEqual(codes[:lim].count(403), lim)
        self.assertEqual(set(codes[lim:]), {429})
        self.assertEqual(len(b._ha_rate), 0)                    # no per-IP state for bad keys
        self.assertEqual(len(self.events("ha_decide_dropped")), 1)
        code, _ = self.hook({"rid": "r", "token": "t", "decision": "deny", "device": "phone-1"})
        self.assertEqual(code, 404)                             # valid key passes the limiter
        self.assertEqual(len(b._ha_rate), 1)
        self.assertEqual(self.hook({"rid": "r"}, key=None)[0], 429)   # missing key: same bucket
        b._ha_unauth["t"] -= 120                                # window expiry resets the bucket
        self.assertEqual(self.hook({"rid": "r"}, key="w" * 40)[0], 403)

    def test_ha_http_valid_key_limited_per_ip(self):
        b = self.broker
        for i in range(500):
            b.ha_unauth_ok(ipn(i))
        codes = [self.hook({"rid": "r", "token": "t", "decision": "deny", "device": "phone-1"})[0]
                 for _ in range(62)]
        self.assertEqual((codes[:60].count(404), set(codes[60:])), (60, {429}))

    def test_push_event_map_bounded_serves_new_users(self):
        m, cap, now = {}, Broker.RATE_MAP_CAP, time.time()
        for i in range(10000):
            Broker.rate_map_make_room(m, now)
            m[f"u{i}"] = {"t": now + i * 1e-6, "n": 0, "drop": 0}
            self.assertLessEqual(len(m), cap)
        self.assertEqual(len(m), cap)
        self.assertIn("u9999", m)
        self.assertNotIn("u0", m)


class HookEmptyDevices(Hook):
    hook_cfg = {"key": HOOK}

    def test_warning_logged_once_and_any_device_accepted(self):
        self.assertEqual(len(self.events("ha_hook_any_device")), 1)
        rid, n = self.asked()
        self.assertEqual(self.hook(self.good(rid, n, device="whatever"))[0], 200)
        self.assertEqual(self.events("decided")[0]["approver"], "ha:whatever")


class HookNotConfigured(Hook):
    hook_cfg = None

    def test_404_and_no_hook_key_acceptance(self):
        self.assertEqual(self.hook({"rid": "r"})[0], 404)
        self.assertEqual(self.hook({"rid": "r"}, key=t.KEY)[0], 404)
        self.assertEqual(self.events("ha_hook_any_device"), [])


def load_tests(loader, tests, pattern):
    """The hook harness extends t.Dashboard; do not re-run its inherited tests."""
    def walk(suite):
        for x in suite:
            if isinstance(x, unittest.TestSuite):
                yield from walk(x)
            else:
                yield x
    out = unittest.TestSuite()
    for c in walk(tests):
        fn = getattr(type(c), c._testMethodName, None)
        if getattr(fn, "__module__", __name__) == __name__:
            out.addTest(c)
    return out


if __name__ == "__main__":
    unittest.main()
