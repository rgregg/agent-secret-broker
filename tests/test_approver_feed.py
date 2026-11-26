"""Approver API, broker side: the `app` notify leaf, the long-poll feed, request views and
the `app` decision channel (secret_broker/approver_api.py). No HTTP routes here."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import approver_api, notify  # noqa: E402
from secret_broker.broker import CHANNELS  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

ISSUER = "https://idp.example/application/o/asb-app/"
BROWSER_ONLY = ("guidance", "credential", "plan", "session", "sudo")


def fake_fetch(url):
    if url.endswith("/.well-known/openid-configuration"):
        return {"jwks_uri": "https://idp.example/jwks"}
    return {"keys": []}


def failing_fetch(url):
    raise OSError("unreachable")


class Base(t.Dashboard):
    approver_cfg = {"issuer": ISSUER, "client_id": "asb-app"}
    grants = None
    fetch = staticmethod(fake_fetch)

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.approver_cfg is not None:
            cfg["approver_api"] = json.loads(json.dumps(self.approver_cfg))
        if self.grants is not None:
            cfg["timed_grants"] = dict(self.grants)

    def setUp(self):
        with mock.patch.object(approver_api, "FETCH_JSON", self.fetch):
            super().setUp()

    def pushed(self, path="/x", headers=None):
        """A pending http request that has been through _push (and its sends)."""
        if headers is None:
            rid = self.ask(path)
        else:
            url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
            body = {"mode": "http", "names": ["svc"], "method": "GET", "url": url, "headers": headers}
            _, body = self.api("POST", "/v1/requests", body)
            rid = json.loads(body)["id"]
        self.broker.flush_notifications(10)
        return self.broker._by_id[rid]

    def view(self, req):
        return approver_api.request_view(self.broker, req)


for _n in dir(t.Dashboard):         # reuse its helpers, not its tests
    if _n.startswith("test"):
        setattr(Base, _n, None)


class NoConfig(Base):
    approver_cfg = None

    def test_no_config_no_app_leaf(self):
        self.assertIsNone(self.broker.approver)
        self.assertEqual(list(notify.leaves(self.broker.notifier)), [self.notifier])
        self.broker.notifier = notify.MultiNotifier([self.notifier])
        self.assertEqual(list(notify.leaves(self.broker.notifier)), [self.notifier])


class Startup(Base):
    fetch = staticmethod(failing_fetch)

    def test_discovery_failure_logs_one_warning_and_starts(self):
        self.assertIsNotNone(self.broker.approver)
        (ev,) = self.events("approver_api_discovery_failed")
        self.assertIn("warning", ev)
        self.assertEqual(self.pushed().status, "pending")      # the broker works

    def test_bad_config_names_the_field(self):
        cfg = {"approve_base_url": "https://s", "allowed_user": "alice",
               "approver_api": {"issuer": "http://idp.example/", "client_id": "x"}}
        with self.assertRaises(ValueError) as cm:
            t.Broker(cfg, t.MemoryBackend(), FakeNotifier(), None)
        self.assertIn("approver_api.issuer", str(cm.exception))


class Leaf(Base):
    ttl = 300               # long enough for the presence fallback to apply

    def app_leaf(self):
        (leaf,) = [x for x in notify.leaves(self.broker.notifier) if notify.transport_type(x) == "app"]
        return leaf

    def test_app_leaf_added_and_never_held(self):
        self.assertTrue(self.broker.approver.verifier is not None)
        self.assertIs(self.app_leaf().feed, self.broker.approver.feed)
        tick = FakeNotifier(type_name="ticker")
        self.broker.notifier = notify.MultiNotifier([tick])         # a replaced notifier keeps the leaf
        leaf = self.app_leaf()
        self.assertEqual(len(list(notify.leaves(self.broker.notifier))), 2)
        self.broker._presence_autostart = False
        self.broker.presence.beat("alice", True, "t1")
        req = self.pushed()
        held = self.broker._presence_hold_set(req)
        self.assertIn(tick, held)
        self.assertFalse(any(x is leaf for x in held))
        self.assertTrue(self.view(req)["notified"])                 # sent at once, not held
        self.assertEqual(tick.sent, [])                             # the phone transport is held
        self.assertIn(req.id, self.broker._held)

    def test_notified_only_after_push(self):
        gate, orig = threading.Event(), self.broker._push
        self.broker._push = lambda r: (gate.wait(10), orig(r))
        th = threading.Thread(target=self.ask, daemon=True)
        th.start()
        end = time.time() + 5
        while not self.broker.pending() and time.time() < end:
            time.sleep(0.02)
        (req,) = self.broker.pending()
        v = self.view(req)
        self.assertEqual((v["notified"], v["banner_actions"]), (False, []))
        gate.set()
        th.join(10)
        self.broker.flush_notifications(10)
        v = self.view(req)
        self.assertEqual((v["notified"], v["banner_actions"]), (True, ["deny", "approve"]))
        # the app never uses the shared action token: its actions do not widen it, and with no
        # action-capable real transport no token is minted at all
        self.assertEqual(req.offered, frozenset())
        self.assertIsNone(req.notification.action_token)
        self.assertIsNone(req.action_hash)

    def test_app_leaf_does_not_widen_push_token(self):
        wp = FakeNotifier(type_name="webpush", supports_actions=("approve", "deny"))
        wp.action_policy = notify.parse_action_policy({"approve_max_risk": "none"}, "x")
        self.broker.notifier = notify.MultiNotifier([wp])
        req = self.pushed()
        (n,) = wp.notifications
        self.assertEqual([a.id for a in n.actions], ["deny"])
        self.assertIsNotNone(n.action_token)
        self.assertEqual(req.offered, frozenset({"deny"}))
        self.assertEqual(self.view(req)["banner_actions"], ["deny", "approve"])    # the app's own entry
        code, _ = self.broker.decide_via("push", req.id, "approve", "push:alice", token=n.action_token)
        self.assertEqual(code, 403)
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.broker.decide_via("push", req.id, "deny", "push:alice", token=n.action_token)[0],
                         200)

    def test_real_transport_failure_is_logged_and_request_waits(self):
        class Boom(FakeNotifier):
            def send(self, n):
                raise notify.NotifyError("secret detail must not be logged")
        self.broker.notifier = notify.MultiNotifier([Boom(type_name="ticker")])
        req = self.pushed()
        self.assertEqual(req.status, "pending")
        self.assertTrue(self.view(req)["notified"])
        (ev,) = self.events("notify_failed")
        self.assertEqual((ev["id"], ev["transports"], ev["errors"]), (req.id, ["ticker"], ["NotifyError"]))
        self.assertIn("warning", ev)
        self.assertNotIn("secret detail", json.dumps(ev))
        ok = FakeNotifier(type_name="telegram")
        self.broker.notifier = notify.MultiNotifier([Boom(type_name="ticker"), ok])
        self.pushed("/two")
        self.assertEqual(len(self.events("notify_failed")), 1)          # one real transport delivered

    def test_failure_of_released_held_transport_is_logged(self):
        class Boom(FakeNotifier):
            def send(self, n):
                raise notify.NotifyError("down")
        self.broker.notifier = notify.MultiNotifier([Boom(type_name="ticker")])
        self.broker._presence_autostart = False
        self.broker.presence.beat("alice", True, "t1")
        req = self.pushed()
        self.assertIn(req.id, self.broker._held)
        self.assertEqual(self.events("notify_failed"), [])
        self.broker._release_held(req, "presence_lapsed")
        self.assertEqual(req.status, "pending")
        (ev,) = self.events("notify_failed")
        self.assertEqual((ev["transports"], ev["errors"]), (["ticker"], ["NotifyError"]))

    def test_channel_registry(self):
        ch = CHANNELS["app"]
        self.assertEqual((ch.token_required, ch.may_create_always, ch.may_create_grant, ch.may_create_ssh_rule),
                         (False, True, True, False))


class Override(Base):
    approver_cfg = {"issuer": ISSUER, "client_id": "asb-app", "actions": {"approve_max_risk": "low"}}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = t._Stub("Reads things", "medium")

    def test_banner_actions_follow_override(self):
        v = self.view(self.pushed())
        self.assertEqual(v["risk"]["level"], "medium")
        self.assertEqual(v["banner_actions"], ["deny"])
        self.assertIn("approve", v["actions"])                      # the popover is independent


class Views(Base):
    grants = {"durations": [15, 60]}

    def browser_only(self, req, mode):
        req.mode = mode
        req.spec = {"guidance": {}, "credential": {}, "plan": {"rules": [{}]},
                    "session": {"hosts": ["h.example"], "methods": ["GET"], "ttl_s": 600, "max_calls": 5},
                    "sudo": {"argv": ["ls", "/root"], "user": "root"}}[mode]

    def test_browser_only_modes(self):
        for mode in BROWSER_ONLY:
            with self.subTest(mode=mode):
                req = self.pushed()
                self.browser_only(req, mode)
                self.broker._push(req)
                self.broker.flush_notifications(10)
                v = self.view(req)
                self.assertEqual(v["actions"], ["deny"])
                self.assertEqual(v["banner_actions"], [])
                self.assertTrue(v["notified"])
                self.assertTrue(v["browser_url"].startswith("https://secrets.example/a/"))
                self.assertIsNone(v["details"])

    def test_offered_actions_grants_and_always(self):
        req = self.pushed()
        acts = approver_api.offered_actions(self.broker, req)
        self.assertEqual(acts[:2], ["deny", "approve"])
        self.assertIn("grant:15", acts)
        self.assertIn("grant:60", acts)
        ok, _ = self.broker.always_allow_eligibility(req)
        self.assertTrue(ok)
        self.assertIn("always", acts)
        self.assertNotIn("always_script", acts)                     # http: no script to bind
        self.broker.summarizer = t._Stub("Deletes things", "high")
        high = self.pushed("/y")
        self.assertFalse(self.broker.always_allow_eligibility(high)[0])
        self.assertNotIn("always", approver_api.offered_actions(self.broker, high))
        self.broker.grants_cfg["enabled"] = False
        self.assertFalse([a for a in approver_api.offered_actions(self.broker, req) if a.startswith("grant:")])

    def test_view_shape(self):
        req = self.pushed()
        v = self.view(req)
        self.assertEqual(set(v), {"id", "mode", "created", "expires", "credentials", "client", "summary",
                                  "summary_source", "risk", "target", "details", "notified", "banner_actions",
                                  "actions", "browser_url"})
        self.assertEqual((v["id"], v["mode"], v["credentials"]), (req.id, "http", ["svc"]))
        self.assertEqual(v["client"], {"name": req.client["name"], "id": req.client["id"]})
        self.assertEqual(v["target"], self.broker._what(req))
        self.assertTrue(v["target"].startswith("GET http://127.0.0.1:"))
        self.assertEqual(v["browser_url"], f"https://secrets.example/a/{req.nonce}")
        json.dumps(v)                                               # serialisable as is
        self.assertNotIn(t.SECRET, json.dumps(v))

    def test_view_caps_summary_and_strips_controls(self):
        req = self.pushed()
        req.summary = "\x1b[31mred\x07\x9b " + "y" * 10240 + "‮"
        req.risk = {"level": "low", "model": "m", "reasons": ["a\x1b]8;;http://evil\x07b"]}
        v = self.view(req)
        self.assertEqual(len(v["summary"]), 500)
        self.assertTrue(v["summary"].startswith("[31mred "))
        self.assertFalse(any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f for c in v["summary"]))
        self.assertFalse(any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f for c in v["risk"]["reasons"][0]))

    def test_view_masks_details(self):
        req = self.pushed(headers={"Authorization": "Bearer literal-abc123", "X-Note": "plain"})
        v = self.view(req)
        hdrs = {h[0] if isinstance(h, (list, tuple)) else h["name"]: h for h in v["details"]["headers"]}
        self.assertIn("[masked]", json.dumps(hdrs["Authorization"]))
        self.assertNotIn("literal-abc123", json.dumps(v))


class Feed(unittest.TestCase):
    def test_wait_returns_at_once_when_since_unknown(self):
        f = approver_api.AppFeed()
        f.bump()
        t0 = time.time()
        self.assertEqual(f.wait(f.version + 5, 25, lambda: ()), f.version)
        self.assertLess(time.time() - t0, 0.5)

    def test_wait_wakes_on_fingerprint_change(self):
        f, fp = approver_api.AppFeed(), [("a",)]
        v0 = f.wait(f.version, 0, lambda: tuple(fp))
        out = []
        th = threading.Thread(target=lambda: out.append(f.wait(v0, 10, lambda: tuple(fp))), daemon=True)
        th.start()
        time.sleep(0.2)
        fp.append(("b",))
        th.join(3)
        self.assertEqual(len(out), 1)
        self.assertGreater(out[0], v0)

    def test_change_between_calls_is_not_missed(self):
        f, fp = approver_api.AppFeed(), [("a",)]
        v0 = f.wait(f.version, 0, lambda: tuple(fp))
        fp.append(("b",))                       # changes while no one waits
        t0 = time.time()
        self.assertGreater(f.wait(v0, 10, lambda: tuple(fp)), v0)
        self.assertLess(time.time() - t0, 0.5)

    def test_wait_times_out(self):
        f = approver_api.AppFeed()
        t0 = time.time()
        self.assertEqual(f.wait(f.version, 0.3, lambda: ()), f.version)
        self.assertGreater(time.time() - t0, 0.25)

    def test_waiter_cap(self):
        f = approver_api.AppFeed(max_waiters=8)
        v = f.version
        ths = [threading.Thread(target=f.wait, args=(v, 10, lambda: ()), daemon=True) for _ in range(8)]
        for th in ths:
            th.start()
        end = time.time() + 5
        while f.waiting < 8 and time.time() < end:
            time.sleep(0.02)
        self.assertEqual(f.waiting, 8)
        t0 = time.time()
        self.assertEqual(f.wait(v, 10, lambda: ()), v)               # 9th: answered at once
        self.assertLess(time.time() - t0, 0.5)
        f.bump()
        for th in ths:
            th.join(3)
        self.assertEqual(f.waiting, 0)

    def test_notified_and_forget(self):
        f = approver_api.AppFeed()
        self.assertIsNone(f.notified("r1"))
        v = f.version
        f.mark_notified("r1", ["deny"])
        self.assertEqual((f.notified("r1"), f.version), (["deny"], v + 1))
        f.forget("r1")
        self.assertIsNone(f.notified("r1"))

    def test_notifier_never_raises(self):
        class Bad:
            def mark_notified(self, *a):
                raise RuntimeError("x")

            def bump(self):
                raise RuntimeError("x")

            def forget(self, rid):
                raise RuntimeError("x")
        leaf = approver_api.AppNotifier(Bad())
        n = t.N("T", "x", "u", "tag")
        leaf.send(n)
        leaf.resolved(n, "approved")
        self.assertEqual(notify.transport_type(leaf), "app")
        self.assertEqual(leaf.supports_actions, ("approve", "deny"))


class Wait(Base):
    def test_wait_wakes_on_new_request(self):
        feed = self.broker.approver.feed
        v = feed.wait(feed.version, 0, lambda: approver_api.fingerprint(self.broker))
        out = []
        th = threading.Thread(target=lambda: out.append(
            feed.wait(v, 20, lambda: approver_api.fingerprint(self.broker))), daemon=True)
        th.start()
        time.sleep(0.1)
        t0 = time.time()
        self.ask()
        th.join(2)
        self.assertLess(time.time() - t0, 2.5)
        self.assertEqual(len(out), 1)
        self.assertNotEqual(out[0], v)

    def test_fingerprint(self):
        req = self.pushed()
        self.assertEqual(approver_api.fingerprint(self.broker), ((req.id, True, "low", True),))

    def test_finish_bumps(self):
        req = self.pushed()
        feed = self.broker.approver.feed
        v = feed.version
        self.broker.decide_via("dashboard", req.id, "deny", "alice")
        self.assertGreater(feed.version, v)


class Decide(Base):
    grants = {"durations": [15, 60]}

    def decide(self, rid, body, token_id="jti-1"):
        return approver_api.decide(self.broker, rid, body, "alice", "127.0.0.1", token_id)

    def test_decide_app_channel_audit(self):
        req = self.pushed()
        self.assertEqual(self.decide(req.id, {"id": req.id, "decision": "approve", "device": "mac-1"}),
                         (200, {"ok": True}))
        self.assertEqual(self.result(req.id)["status"], "approved")
        (d,) = self.events("decided")
        self.assertEqual((d["channel"], d["approver"], d["device"], d["token_id"], d["approver_peer"]),
                         ("app", "app:alice", "mac-1", "jti-1", "127.0.0.1"))
        self.assertFalse(d["always_requested"])

    def test_deny(self):
        req = self.pushed()
        self.assertEqual(self.decide(req.id, {"decision": "deny"}), (200, {"ok": True}))
        self.assertEqual(self.events("denied")[0]["channel"], "app")

    def test_decide_grant_and_always(self):
        req, req2 = self.pushed(), self.pushed("/other")         # both pending before either is decided
        self.assertEqual(self.decide(req.id, {"decision": "approve", "grant_minutes": 15}), (200, {"ok": True}))
        self.assertEqual(self.decide(req2.id, {"decision": "approve", "always": True, "rule_scope": "any"}),
                         (200, {"ok": True}))
        self.result(req.id)
        self.result(req2.id)
        g, a = self.events("decided")
        self.assertEqual((g["grant_minutes"], g["channel"]), (15, "app"))
        self.assertTrue(a["always_requested"])
        self.assertTrue(self.events("grant_created"))
        self.assertEqual(req2.always, "applied")

    def test_always_on_fresh_request(self):
        req = self.pushed()
        self.assertEqual(self.decide(req.id, {"decision": "approve", "always": True}), (200, {"ok": True}))
        self.result(req.id)
        self.assertEqual(req.always, "applied")
        self.assertTrue(self.events("decided")[0]["always_requested"])

    def test_decide_refuses_unoffered(self):
        code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["newapi"], "kind": "token",
                                                       "purpose": "for the build", "hosts": ["127.0.0.1"]})
        self.assertEqual(code, 202, text)
        rid = json.loads(text)["id"]
        self.broker.flush_notifications(10)
        req = self.broker._by_id[rid]
        self.assertEqual(req.mode, "credential")
        self.assertEqual(self.decide(rid, {"decision": "approve"})[0], 400)
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.events("decided"), [])
        http = self.pushed()
        for bad in ({"decision": "maybe"}, {"decision": "approve", "grant_minutes": 7},
                    {"decision": "approve", "grant_minutes": "15"}, {"decision": "approve", "always": "x"},
                    {"decision": "approve", "always": "script"},     # not offered for http
                    {"decision": "deny", "always": True}, {"decision": "deny", "grant_minutes": 15},
                    {"decision": "approve", "always": True, "grant_minutes": 15},
                    {"decision": "approve", "rule_scope": "everyone"},
                    {"decision": "approve", "device": "a b"}, {"decision": "approve", "device": "x" * 65},
                    {"decision": "approve", "device": 3}, {"decision": "approve", "extra": 1},
                    {"decision": "approve", "id": "someone-else"}, [1], None):
            with self.subTest(bad=bad):
                self.assertEqual(self.decide(http.id, bad), (400, {"ok": False}))
        self.assertEqual(http.status, "pending")
        self.assertEqual(self.decide(rid, {"decision": "deny"}), (200, {"ok": True}))

    def test_decide_ssh_rule_never_created(self):
        req = self.pushed()
        self.assertEqual(self.decide(req.id, {"decision": "approve", "ssh_rule": {"days": None}})[0], 400)
        self.assertEqual(self.broker.decide_via("app", req.id, "approve", "app:alice", ssh_rule={"days": None})[0],
                         403)
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.events("decided"), [])

    def test_decide_410_after_dashboard_decision(self):
        req = self.pushed()
        self.broker.decide_via("dashboard", req.id, "deny", "alice")
        self.assertEqual(self.decide(req.id, {"decision": "approve"}), (410, {"ok": False}))
        self.assertEqual(self.decide("no-such-id", {"decision": "deny"}), (404, {"ok": False}))
        self.assertEqual(len(self.events("decided")), 1)

    def test_token_id(self):
        self.assertEqual(approver_api.token_id({"jti": "abc"}, "tok"), "abc")
        import hashlib
        self.assertEqual(approver_api.token_id({}, "tok"), hashlib.sha256(b"tok").hexdigest()[:16])
        self.assertEqual(approver_api.token_id({"jti": 5}, "tok"), hashlib.sha256(b"tok").hexdigest()[:16])


if __name__ == "__main__":
    unittest.main()
