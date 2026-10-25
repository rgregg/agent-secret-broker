"""Notification pipeline (one Notification, per-transport actions), the legacy
transport adapter, and the single decision entry Broker.decide_via."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import notify  # noqa: E402
from secret_broker import webpush  # noqa: E402
from secret_broker.broker import CHANNELS, Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402


def build(transport, risk="low", default=None):
    return notify.make_notification(
        rid="r1", tag="secret-r1", title="T", text="body", names=["svc"], risk=risk,
        url="https://x/a/n", source="host", summary=None, expires_at=1.0, transport=transport,
        default_policy=default)


def ids(n):
    return [a.id for a in n.actions]


class Builder(unittest.TestCase):
    def test_fields(self):
        f = FakeNotifier(supports_actions=("approve", "deny"))
        n = build(f, "medium")
        self.assertEqual((n.rid, n.tag, n.title, n.text, n.names, n.risk, n.url, n.source,
                          n.summary, n.expires_at), ("r1", "secret-r1", "T", "body", ["svc"],
                                                     "medium", "https://x/a/n", "host", None, 1.0))
        self.assertEqual([(a.id, a.label) for a in n.actions], [("deny", "Deny"), ("approve", "Approve")])
        self.assertGreaterEqual(len(n.action_token), 22)

    def test_policy_per_risk(self):
        f = FakeNotifier(supports_actions=("approve", "deny"))
        pol = notify.parse_action_policy({"approve_max_risk": "low", "deny": True}, "x")
        self.assertEqual(ids(build(f, "low", pol)), ["deny", "approve"])
        self.assertEqual(ids(build(f, "medium", pol)), ["deny"])
        self.assertEqual(ids(build(f, None, pol)), ["deny"])
        self.assertEqual(ids(build(f, "high")), ["deny", "approve"])     # defaults
        none = notify.parse_action_policy({"approve_max_risk": "none", "deny": False}, "x")
        n = build(f, "low", none)
        self.assertEqual((n.actions, n.action_token), ([], None))

    def test_no_supporting_transport_means_no_actions_and_no_token(self):
        n = build(FakeNotifier())
        self.assertEqual((n.actions, n.action_token), ([], None))

    def test_per_transport_actions_and_one_token(self):
        pushy = FakeNotifier(supports_actions=("approve", "deny"))
        denyonly = FakeNotifier(supports_actions=("deny",))
        plain = FakeNotifier()
        multi = notify.MultiNotifier([pushy, denyonly, plain])
        n = build(multi)
        self.assertEqual(ids(n), ["deny", "approve"])
        multi.send(n)
        got = [x.notifications[0] for x in (pushy, denyonly, plain)]
        self.assertEqual([ids(g) for g in got], [["deny", "approve"], ["deny"], []])
        self.assertEqual([g.action_token for g in got], [n.action_token, n.action_token, None])

    def test_transport_override_beats_global(self):
        a = FakeNotifier(supports_actions=("approve", "deny"))
        b = FakeNotifier(supports_actions=("approve", "deny"))
        b.action_policy = notify.parse_action_policy({"approve_max_risk": "none"}, "x")
        glob = notify.parse_action_policy({"approve_max_risk": "low", "deny": False}, "x")
        multi = notify.MultiNotifier([a, b])
        multi.send(build(multi, "low", glob))
        self.assertEqual(ids(a.notifications[0]), ["approve"])
        self.assertEqual(ids(b.notifications[0]), ["deny"])

    def test_build_config_override_and_webpush_block(self):
        store = webpush.PushStore("/nonexistent/x.json", "/nonexistent/v.pem", "mailto:a@b.c")
        rd = lambda p: "x"  # noqa: E731
        m = notify.build({"notify": [
            {"type": "webpush", "actions": {"approve_max_risk": "low"}},
            {"type": "telegram", "bot_token_file": "t", "chat_id": 1,
             "actions": {"deny": False}}]}, rd, push_store=store)
        wp, tg = m.transports
        self.assertEqual(wp.action_policy, {"approve_max_risk": "low", "deny": True})
        self.assertEqual(tg.action_policy, {"approve_max_risk": "high", "deny": False})
        old = notify.build({"notify": [{"type": "webpush"}],
                            "webpush": {"actions": {"deny": False}}}, rd, push_store=store)
        self.assertEqual(old.action_policy, {"approve_max_risk": "high", "deny": False})
        live = notify.build({"notify": [{"type": "webpush"}]}, rd, push_store=store)
        self.assertIsNone(live.action_policy)           # global notify_actions applies
        for bad, field in (({"type": "webpush", "actions": {"approve_max_risk": "x"}},
                            "notify[0].actions.approve_max_risk"),
                           ({"type": "webpush", "actions": {"nope": 1}}, "notify[0].actions.nope")):
            with self.assertRaises(ValueError) as cm:
                notify.build({"notify": [bad]}, rd, push_store=store)
            self.assertIn(field, str(cm.exception))

    def test_bad_notify_actions_name_the_field(self):
        for bad, field in (({"approve_max_risk": "urgent"}, "notify_actions.approve_max_risk"),
                           ({"deny": "yes"}, "notify_actions.deny"),
                           ({"nope": 1}, "notify_actions.nope"),
                           ("x", "notify_actions")):
            with self.assertRaises(ValueError) as cm:
                Broker({"approve_base_url": "https://s.example", "notify_actions": bad},
                       t.FileBackend(self._vault()), FakeNotifier(), None)
            self.assertIn(field, str(cm.exception))

    def _vault(self):
        import tempfile
        import json
        d = tempfile.mkdtemp()
        p = os.path.join(d, "v.json")
        with open(p, "w") as f:
            f.write(json.dumps({}))
        return p


class Legacy(unittest.TestCase):
    def test_legacy_signature_is_detected_once_and_called(self):
        got = []

        class Old:
            def send(self, title, message, url, tag, names=None, context=None):
                got.append((title, message, url, tag, names, context))

            def resolved(self, tag, status):
                got.append(("resolved", tag, status))
        a = notify.adapt(Old())
        self.assertIsInstance(a, notify.LegacyAdapter)
        self.assertIs(notify.adapt(a), a)
        n = build(a)
        a.send(n)
        a.resolved(n, "approved")
        self.assertEqual(got[0][:5], ("T", "body", "https://x/a/n", "secret-r1", ["svc"]))
        self.assertEqual(got[0][5], {"rid": "r1", "risk": "low", "action_token": n.action_token})
        self.assertEqual(got[1], ("resolved", "secret-r1", "approved"))

    def test_new_style_is_not_wrapped_and_broker_adapts_on_assignment(self):
        f = FakeNotifier()
        self.assertIs(notify.adapt(f), f)

        class Old:
            def send(self, title, message, url, tag):
                pass
        b = Broker({"approve_base_url": "https://s.example"}, t.FileBackend(Legacy._vault(self)),
                   Old(), None)
        self.assertIsInstance(b.notifier, notify.LegacyAdapter)
        b.notifier = f
        self.assertIs(b.notifier, f)

    _vault = Builder._vault


class Pipeline(t.Dashboard):
    """Through a real Broker: one Notification, resolved gets it, decide_via parity."""

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["notify_actions"] = {"approve_max_risk": "medium", "deny": True}

    def setUp(self):
        super().setUp()
        self.notifier.supports_actions = ("approve", "deny")

    def asked(self, path="/x"):
        rid = self.ask(path)
        end = time.time() + 5
        while not any(x.rid == rid for x in self.notifier.notifications) and time.time() < end:
            time.sleep(0.05)
        return rid, next(x for x in self.notifier.notifications if x.rid == rid)

    def test_broker_builds_notification_once_with_policy(self):
        rid, n = self.asked()
        self.assertEqual((n.rid, n.risk, n.source, n.summary), (rid, "low", n.source, "Reads things"))
        self.assertEqual(n.names, ["svc"])
        self.assertTrue(n.url.endswith(self.broker._by_id[rid].nonce))
        self.assertIn("[LOW]", n.title)
        self.assertEqual(n.expires_at, self.broker._by_id[rid].expires)
        self.assertEqual(ids(n), ["deny", "approve"])
        self.assertEqual(self.broker._by_id[rid].action_hash is not None, True)
        self.broker.summarizer = t._Stub("Writes things", "high")
        _, n2 = self.asked("/y")
        self.assertEqual(ids(n2), ["deny"])

    def test_no_supporting_transport_creates_no_token(self):
        self.notifier.supports_actions = ()
        rid, n = self.asked()
        self.assertIsNone(n.action_token)
        self.assertIsNone(self.broker._by_id[rid].action_hash)

    def test_resolved_receives_the_notification(self):
        rid, n = self.asked()
        self.decide(rid, "deny")
        end = time.time() + 5
        while not self.notifier.resolved_notifications and time.time() < end:
            time.sleep(0.05)
        (got, status), = self.notifier.resolved_notifications
        self.assertEqual((got.rid, got.names, status), (rid, ["svc"], "denied"))
        self.assertIs(got, n)

    def audit_of(self, name, rid):
        (e,) = [r for r in self.events(name) if r.get("id") == rid or r.get("rid") == rid]
        return e

    def test_decide_via_parity_dashboard_vs_push(self):
        rid1, _ = self.asked("/a")
        rid2, n2 = self.asked("/b")
        c1, r1 = self.broker.decide_via("dashboard", rid1, "approve", "alice", peer="10.0.0.1",
                                        client_ip="1.2.3.4")
        c2, r2 = self.broker.decide_via("push", rid2, "approve", "alice", token=n2.action_token,
                                        peer="10.0.0.1", client_ip="1.2.3.4")
        self.assertEqual((c1, c2), (200, 200))
        self.result(rid1)
        self.result(rid2)
        d = {e["channel"]: e for e in self.events("decided")}
        self.assertEqual(set(d), {"dashboard", "push"})
        keys = lambda e: {k for k in e if k not in ("ts", "id", "rid", "time")}  # noqa: E731
        self.assertEqual(keys(d["dashboard"]), keys(d["push"]))
        for e in d.values():
            self.assertEqual((e["approver"], e["approver_peer"], e["approver_ip"], e["via"],
                              e["decision"]), ("alice", "10.0.0.1", "1.2.3.4", "user", "approve"))
        # token spent / request decided: a replay changes nothing
        self.assertEqual(self.broker.decide_via("push", rid2, "deny", "alice",
                                                token=n2.action_token)[0], 410)
        self.assertEqual(self.broker.decide_via("dashboard", rid1, "deny", "alice")[0], 410)
        self.assertEqual(len(self.events("decided")), 2)

    def test_push_wrong_token_403_missing_token_403_and_untouched(self):
        rid, n = self.asked()
        self.assertEqual(self.broker.decide_via("push", rid, "approve", "a", token="x" * 22)[0], 403)
        self.assertEqual(self.broker.decide_via("push", rid, "approve", "a")[0], 403)
        self.assertEqual(self.broker.decide_via("push", "nope", "approve", "a", token="x")[0], 404)
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.broker.decide_via("push", None, "deny", "a", token=n.action_token)[0], 200)

    def test_decision_by_other_channel_kills_token(self):
        rid, n = self.asked()
        self.assertEqual(self.broker.decide_via("dashboard", rid, "deny", "a")[0], 200)
        self.assertEqual(self.broker.decide_via("push", rid, "approve", "a",
                                                token=n.action_token)[0], 410)

    def test_always_only_for_channels_that_may_create_it(self):
        self.assertFalse(CHANNELS["push"].may_create_always)
        self.assertTrue(CHANNELS["dashboard"].may_create_always)
        rid, n = self.asked()
        self.broker.decide_via("push", rid, "approve", "a", token=n.action_token, always=True)
        self.result(rid)
        self.assertFalse(self.events("decided")[0]["always_requested"])
        self.assertEqual(self.events("policy_change"), [])
        rid2, _ = self.asked("/z")
        self.broker.decide_via("dashboard", rid2, "approve", "a", always=True)
        self.assertTrue(self.events("decided")[1]["always_requested"])

    def test_unknown_channel_and_decision_rejected(self):
        rid, _ = self.asked()
        with self.assertRaises(ValueError):
            self.broker.decide_via("carrier-pigeon", rid, "approve", "a")
        with self.assertRaises(ValueError):
            self.broker.decide_via("dashboard", rid, "maybe", "a")
        self.assertEqual(self.events("decided"), [])

    def test_audit_extra_is_recorded(self):
        rid, _ = self.asked()
        self.broker.decide_via("dashboard", rid, "deny", "a", note="hook")
        self.assertEqual(self.events("decided")[0]["note"], "hook")


if __name__ == "__main__":
    unittest.main()
