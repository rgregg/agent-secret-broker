"""Approver presence: heartbeat endpoint, hold/release of phone notifications."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api, notify, presence  # noqa: E402
from secret_broker import broker as bmod  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier, NotifyError  # noqa: E402


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


class Boom(FakeNotifier):
    def send(self, n):
        raise NotifyError("down")


class Base(t.Dashboard):
    ttl = 300
    presence_cfg = None
    with_actions = False

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.presence_cfg is not None:
            cfg["notify_presence"] = dict(self.presence_cfg)
        if self.with_actions:
            cfg["ha_hook"] = {"key": "k" * 40, "allowed_devices": []}

    def setUp(self):
        super().setUp()
        acts = ("approve", "deny") if self.with_actions else ()
        self.tick = FakeNotifier(type_name="ticker", supports_actions=acts)
        self.tele = FakeNotifier(type_name="telegram")
        self.wp = FakeNotifier(type_name="webpush", supports_actions=acts)
        self.other = FakeNotifier(type_name=None)
        self.install([self.tick, self.tele, self.wp])
        self.clock = Clock()
        self.broker.presence_clock = self.clock
        self.broker._presence_autostart = False

    def install(self, ts):
        self.broker.notifier = notify.MultiNotifier(ts)

    def here(self, user="alice", tab="t1", v=True):
        self.broker.presence.beat(user, v, tab)

    def counts(self):
        return [len(x.sent) for x in (self.tick, self.tele, self.wp)]

    def ev(self, name):
        return self.events(name)

    def beat(self, body=None, user="alice", headers=None, raw=None, path="/presence"):
        h = {"X-authentik-username": user, "Content-Type": "application/json",
             "X-Requested-With": "asb", "Origin": self.broker.cfg["approve_base_url"].rstrip("/"),}
        if headers is not None:
            h = {k: v for k, v in {**h, **headers}.items() if v is not None}
        data = raw if raw is not None else json.dumps(body).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + path, data=data, headers=h, method="POST"), timeout=10)
            return r.status
        except urllib.error.HTTPError as e:
            return e.code


for _n in dir(t.Dashboard):         # reuse its helpers, not its tests
    if _n.startswith("test"):
        setattr(Base, _n, None)


class Config(unittest.TestCase):
    def bad(self, raw, field):
        with self.assertRaises(ValueError) as cm:
            presence.parse_config(raw)
        self.assertIn(field, str(cm.exception))

    def test_defaults(self):
        self.assertEqual(presence.parse_config(None), {
            "enabled": True, "ttl_s": 25, "fallback_s": 60,
            "transports": ["ticker", "telegram", "webpush"], "require_focus": False})
        self.assertEqual(presence.parse_config({"fallback_s": None})["fallback_s"], None)
        self.assertEqual(presence.parse_config({"transports": []})["transports"], [])

    def test_validation_names_the_field(self):
        self.bad("x", "notify_presence")
        self.bad({"nope": 1}, "notify_presence.nope")
        self.bad({"enabled": "yes"}, "notify_presence.enabled")
        self.bad({"require_focus": 1}, "notify_presence.require_focus")
        for v in (9, 121, "25", 2.5, True):
            self.bad({"ttl_s": v}, "notify_presence.ttl_s")
        for v in (4, 3601, "60", 1.5, False):
            self.bad({"fallback_s": v}, "notify_presence.fallback_s")
        for v in ("ticker", ["sms"], [1], None):
            self.bad({"transports": v}, "notify_presence.transports")
        for ok in ({"ttl_s": 10}, {"ttl_s": 120}, {"fallback_s": 5}, {"fallback_s": 3600}):
            presence.parse_config(ok)

    def test_broker_refuses_bad_config(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "v.json")
        with open(p, "w") as f:
            json.dump({}, f)
        with self.assertRaises(ValueError) as cm:
            Broker({"approve_base_url": "https://s", "notify_presence": {"fallback_s": 1}},
                   t.FileBackend(p), FakeNotifier(), None)
        self.assertIn("notify_presence.fallback_s", str(cm.exception))

    def test_main_validates_at_startup(self):
        src = open(os.path.join(os.path.dirname(bmod.__file__), "__main__.py")).read()
        self.assertIn('presence.parse_config(cfg.get("notify_presence"))', src)


class PresenceState(unittest.TestCase):
    def test_ttl_and_hidden_beat(self):
        c = Clock()
        p = presence.Presence(25, c)
        self.assertFalse(p.present("a"))
        p.beat("a", True, "x")
        self.assertTrue(p.present("a"))
        c.t += 25
        self.assertTrue(p.present("a"))
        c.t += 0.1
        self.assertFalse(p.present("a"))
        p.beat("a", True, "x")
        p.beat("a", False, "x")
        self.assertFalse(p.present("a"))
        self.assertFalse(p.present("b"))

    def test_other_tab_still_visible(self):
        p = presence.Presence(25, Clock())
        p.beat("a", True, "x")
        p.beat("a", True, "y")
        p.beat("a", False, "x")
        self.assertTrue(p.present("a"))
        p.beat("a", False, "y")
        self.assertFalse(p.present("a"))

    def test_maps_are_bounded(self):
        c = Clock()
        p = presence.Presence(25, c)
        for i in range(presence.Presence.MAX_USERS + 20):
            c.t += 0.001
            p.beat(f"u{i}", True, "x")
        self.assertLessEqual(len(p._users), presence.Presence.MAX_USERS)
        self.assertTrue(p.present(f"u{presence.Presence.MAX_USERS + 19}"))
        for i in range(presence.Presence.MAX_TABS + 10):
            c.t += 0.001
            p.beat("one", True, f"t{i}")
        self.assertLessEqual(len(p._users["one"]), presence.Presence.MAX_TABS)


class Endpoint(Base):
    def test_accepts_and_records(self):
        self.assertEqual(self.beat({"v": True, "tab": "abc_1"}), 204)
        self.assertTrue(self.broker.presence.present("alice"))
        self.assertEqual(self.beat({"v": False, "tab": "abc_1"}), 204)
        self.assertFalse(self.broker.presence.present("alice"))
        self.assertEqual(self.beat({"v": True}), 204)             # tab is optional
        self.assertTrue(self.broker.presence.present("alice"))

    def test_guard_matrix(self):
        ok = {"v": True}
        self.assertEqual(self.beat(ok, headers={"X-Requested-With": None}), 403)
        self.assertEqual(self.beat(ok, headers={"X-Requested-With": "x"}), 403)
        self.assertEqual(self.beat(ok, headers={"Content-Type": "text/plain"}), 403)
        self.assertEqual(self.beat(ok, headers={"Content-Type": "application/x-www-form-urlencoded"}), 403)
        self.assertEqual(self.beat(ok, headers={"Sec-Fetch-Site": "cross-site"}), 403)
        self.assertEqual(self.beat(ok, headers={"Origin": "https://evil.example"}), 403)
        self.assertEqual(self.beat(ok, user="mallory"), 403)
        self.assertEqual(self.beat(ok, user=""), 403)
        self.assertEqual(self.beat({"v": True, "tab": "a" * 300}), 413)
        self.assertEqual(self.beat(None, raw=b"not json"), 400)
        self.assertEqual(self.beat({"v": "yes"}), 400)
        self.assertEqual(self.beat({"v": 1}), 400)
        self.assertEqual(self.beat({}), 400)
        self.assertEqual(self.beat([True]), 400)
        self.assertEqual(self.beat({"v": True, "tab": "bad tab!"}), 400)
        self.assertEqual(self.beat({"v": True, "tab": 5}), 400)
        self.assertFalse(self.broker.presence.present("alice"))
        self.assertFalse(self.broker.presence.present("mallory"))

    def test_untrusted_peer_refused(self):
        self.broker.cfg["approval_trusted_peers"] = ["10.9.9.0/24"]
        self.assertEqual(self.beat({"v": True}), 403)
        self.assertFalse(self.broker.presence.present("alice"))

    def test_client_api_port_cannot_post_presence(self):
        for key in (t.KEY, "wrong"):
            try:
                code, _ = t.req(self.base + "/presence", "POST", {"v": True},
                                {"X-Requested-With": "asb", "Content-Type": "application/json",
                                 "X-authentik-username": "alice", "X-Client-Key": key})
            except OSError:
                code = None             # the client API just drops unknown POST paths
            self.assertNotEqual(code, 204)
        self.assertFalse(self.broker.presence.present("alice"))

    def test_rate_limit_and_bounded_map(self):
        for _ in range(Broker.PRESENCE_LIMIT_PER_MIN):
            self.assertEqual(self.beat({"v": True}), 204)
        self.assertEqual(self.beat({"v": True}), 429)
        for i in range(Broker.RATE_MAP_CAP + 5):
            self.broker.presence_beat(f"u{i}", True, "", None)
        self.assertLessEqual(len(self.broker._presence_rate), Broker.RATE_MAP_CAP)

    def test_beats_are_not_audited(self):
        self.beat({"v": True})
        self.beat({"v": False})
        self.assertFalse([r for r in self.records() if "presence" in r["event"]])
        self.assertEqual(self.events("client_event"), [])


class Hold(Base):
    def test_not_present_sends_everything(self):
        self.ask()
        self.assertEqual(self.counts(), [1, 1, 1])
        self.assertEqual(self.ev("notify_held"), [])
        self.assertEqual(len(self.ev("notified")), 1)

    def test_present_holds_listed_transports(self):
        self.here()
        rid = self.ask()
        self.assertEqual(self.counts(), [0, 0, 0])
        self.assertIn(rid, self.broker._held)
        (h,) = self.ev("notify_held")
        self.assertEqual((h["id"], h["reason"], h["transports"]), (rid, "presence", ["telegram", "ticker", "webpush"]))
        self.assertEqual(self.ev("notified"), [])
        # the request is still created and appears on the page at once
        self.assertIn(rid, self.get("/?fragment=1")[1])

    def test_transports_not_listed_are_sent_immediately(self):
        self.broker.presence_cfg["transports"] = ["ticker", "webpush"]
        self.here()
        self.ask()
        self.assertEqual(self.counts(), [0, 1, 0])
        self.assertEqual(self.ev("notify_held")[0]["transports"], ["ticker", "webpush"])
        self.assertEqual(len(self.ev("notified")), 1)

    def test_unlisted_type_or_empty_list_holds_nothing(self):
        self.here()
        self.broker.presence_cfg["transports"] = []
        self.ask()
        self.assertEqual(self.counts(), [1, 1, 1])
        self.install([self.other])
        self.broker.presence_cfg["transports"] = ["ticker"]
        self.ask()
        self.assertEqual(len(self.other.sent), 1)

    def test_single_transport_notifier(self):
        self.install([self.tick])
        self.broker.notifier = self.tick
        self.here()
        self.ask()
        self.assertEqual(len(self.tick.sent), 0)
        self.assertEqual(len(self.broker._held), 1)

    def test_all_requests_alike_ssh_and_high_risk(self):
        self.here()
        self.broker.summarizer = t._Stub("Does a thing", "high")
        self.ask()
        self.assertEqual(self.counts(), [0, 0, 0])

    def test_short_lived_request_sends_immediately(self):
        self.here()
        self.broker.cfg["ttl_seconds"] = 69          # fallback 60 + 10 margin = 70
        self.ask()
        self.assertEqual(self.counts(), [1, 1, 1])
        self.broker.cfg["ttl_seconds"] = 71
        self.ask()
        self.assertEqual(self.counts(), [1, 1, 1])   # held
        self.assertEqual(len(self.broker._held), 1)

    def test_null_fallback_ignores_lifetime_margin(self):
        self.broker.presence_cfg["fallback_s"] = None
        self.here()
        self.broker.cfg["ttl_seconds"] = 20
        self.ask()
        self.assertEqual(self.counts(), [0, 0, 0])

    def test_disabled_restores_old_behavior(self):
        self.broker.presence_cfg["enabled"] = False
        self.here()
        self.ask()
        self.assertEqual(self.counts(), [1, 1, 1])
        self.assertEqual(self.broker._held, {})
        self.assertEqual(self.beat({"v": True}), 204)    # still answers

    def test_agent_create_does_not_wait_on_held_sends(self):
        gate = threading.Event()                         # the slow transport's send blocks until the test opens it
        self.addCleanup(gate.set)
        slow = FakeNotifier(type_name="telegram", on_send=lambda u: gate.wait(10))
        self.install([self.tick, slow])
        self.here()
        t0 = time.time()
        self.ask()
        self.assertLess(time.time() - t0, 5)             # create returned while the send was still blocked
        self.assertFalse(gate.is_set())
        self.assertEqual(len(slow.sent), 0)              # the slow transport was held


class Release(Base):
    def held(self):
        self.here()
        rid = self.ask()
        self.assertEqual(self.counts(), [0, 0, 0])
        return rid

    def test_release_on_presence_lapse(self):
        rid = self.held()
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [0, 0, 0])       # still here
        self.clock.t += 26
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [1, 1, 1])
        (r,) = self.ev("notify_released")
        self.assertEqual((r["id"], r["reason"], r["transports"]),
                         (rid, "presence_lapsed", ["telegram", "ticker", "webpush"]))
        self.assertEqual(len(self.ev("notified")), 1)
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [1, 1, 1])       # once only

    def test_release_on_hidden_beat(self):
        self.held()
        self.here(v=False)
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [1, 1, 1])

    def test_hidden_beat_in_one_tab_but_other_tab_visible_keeps_holding(self):
        self.held()
        self.here(tab="t2")
        self.here(tab="t1", v=False)
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [0, 0, 0])

    def test_release_on_fallback_exactly(self):
        rid = self.held()
        req = self.broker._by_id[rid]
        for dt in (30, 59.9):
            self.clock.t = req.created + dt
            self.here()
            self.broker.presence_tick()
            self.assertEqual(self.counts(), [0, 0, 0], dt)
        self.clock.t = req.created + 60
        self.here()
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [1, 1, 1])
        self.assertEqual(self.ev("notify_released")[0]["reason"], "fallback")

    def test_configurable_fallback(self):
        self.broker.presence_cfg["fallback_s"] = 5
        self.broker.cfg["ttl_seconds"] = 15
        rid = self.held()
        self.clock.t = self.broker._by_id[rid].created + 5
        self.here()
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [1, 1, 1])

    def test_null_fallback_never_sends(self):
        self.broker.presence_cfg["fallback_s"] = None
        rid = self.held()
        req = self.broker._by_id[rid]
        for dt in (60, 600, 3000):
            self.clock.t = req.created + dt
            self.here()
            self.broker.presence_tick()
        self.assertEqual(self.counts(), [0, 0, 0])
        self.assertEqual(self.ev("notify_released"), [])

    def test_decided_while_held_drops_and_never_sends_late(self):
        rid = self.held()
        code, _, _ = self.decide(rid, "approve")
        self.assertEqual(code, 303)
        self.assertEqual(self.broker._by_id[rid].done.wait(5), True)
        _fast.quiesce(self.broker)
        self.assertNotIn(rid, self.broker._held)
        (d,) = self.ev("notify_dropped")
        self.assertEqual((d["id"], d["outcome"]), (rid, "approved"))
        self.clock.t += 500
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [0, 0, 0])
        for x in (self.tick, self.tele, self.wp):
            self.assertEqual(x.resolutions, [])           # never sent: never resolved

    def test_denied_while_held(self):
        rid = self.held()
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        self.assertEqual(self.ev("notify_dropped")[0]["outcome"], "denied")
        self.assertEqual([len(x.resolutions) for x in (self.tick, self.tele, self.wp)], [0, 0, 0])

    def test_expired_while_held_drops(self):
        rid = self.held()
        self.broker._by_id[rid].expires = time.time() - 1
        self.clock.t = time.time()
        self.broker.presence_tick()
        self.assertEqual(self.counts(), [0, 0, 0])
        self.assertEqual(self.ev("notify_dropped")[0]["outcome"], "expired")

    def test_partial_hold_resolves_only_transports_that_sent(self):
        self.broker.presence_cfg["transports"] = ["ticker"]
        self.here()
        rid = self.ask()
        self.assertEqual(self.counts(), [0, 1, 1])
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        self.assertEqual([len(x.resolutions) for x in (self.tick, self.tele, self.wp)], [0, 1, 1])

    def test_resolved_flows_after_release(self):
        rid = self.held()
        self.clock.t += 30
        self.broker.presence_tick()
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        self.assertEqual([len(x.resolutions) for x in (self.tick, self.tele, self.wp)], [1, 1, 1])

    def test_one_failing_transport_does_not_block_others(self):
        boom = Boom(type_name="ticker")
        self.install([boom, self.tele, self.wp])
        rid = self.held()
        self.clock.t += 30
        self.broker.presence_tick()
        self.assertEqual(self.counts()[1:], [1, 1])
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_all_failing_on_release_fails_the_request_like_today(self):
        self.install([Boom(type_name="ticker")])
        rid = self.held()
        self.clock.t += 30
        self.broker.presence_tick()
        self.assertEqual(self.broker._by_id[rid].status, "failed")

    def test_tick_tolerates_exceptions(self):
        self.held()
        self.ask()
        self.broker.presence.present = None           # break the state object
        self.broker.presence_tick()                   # must not raise
        self.broker.presence = None
        self.broker.presence_tick()

    def test_monitor_thread_runs(self):
        self.broker._presence_autostart = True
        self.broker.presence_tick_s = 0.05
        self.held()
        self.here(v=False)
        end = time.time() + 5
        while self.counts() != [1, 1, 1] and time.time() < end:
            time.sleep(0.05)
        self.assertEqual(self.counts(), [1, 1, 1])
        self.assertTrue(self.broker._presence_thread.daemon)

    def test_restart_holds_nothing(self):
        self.held()
        self.assertTrue(self.broker._held)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "v.json")
        with open(p, "w") as f:
            json.dump({}, f)
        b2 = Broker({"approve_base_url": "https://s"}, t.FileBackend(p), FakeNotifier(), None)
        self.assertEqual(b2._held, {})


class Slow(FakeNotifier):
    """Sends take `delay` seconds (or wait for `gate`); the end of a send is recorded in `log`."""

    def __init__(self, delay=0.5, gate=None, log=None, **kw):
        super().__init__(**kw)
        self.delay, self.gate, self.log = delay, gate, log if log is not None else []
        self.started = threading.Event()

    def send(self, n):
        self.started.set()
        if self.gate is not None:
            self.gate.wait(10)
        else:
            time.sleep(self.delay)
        super().send(n)
        self.log.append(("sent", self.type_name))

    def resolved(self, n, status):
        super().resolved(n, status)
        self.log.append(("resolved", status))


class AsyncDispatch(Base):
    def setUp(self):
        super().setUp()
        old = bmod.MAX_PENDING
        bmod.MAX_PENDING = 50
        self.addCleanup(setattr, bmod, "MAX_PENDING", old)

    def raw_create(self):
        t0 = time.time()
        code, body = t.req(self.base + "/v1/requests", "POST",
                           {"mode": "env", "names": ["svc"], "argv": ["x"]},
                           {"X-Client-Key": t.KEY, "Content-Type": "application/json"})
        return code, json.loads(body), time.time() - t0

    def test_create_latency_does_not_depend_on_presence(self):
        gate = threading.Event()                                   # every send blocks until the test opens the gate
        self.addCleanup(gate.set)
        slow = [Slow(gate=gate, type_name="ticker"), Slow(gate=gate, type_name="telegram")]
        self.install(slow)
        lat = {}
        lat["absent"] = self.raw_create()[2]                       # sent at once, slowly
        self.here()
        lat["held"] = self.raw_create()[2]                         # everything held
        self.broker.presence_cfg["transports"] = ["ticker"]
        lat["partial"] = self.raw_create()[2]                      # one held, one slow immediate
        self.broker.presence_cfg["transports"] = []
        lat["unheld"] = self.raw_create()[2]
        for k, v in lat.items():
            self.assertLess(v, 5, k)                               # returned long before the 10 s the sends block
        self.assertFalse(gate.is_set())
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual([len(x.sent) for x in slow], [2, 3])      # absent, partial(tele), unheld

    def test_response_shape_is_the_same_held_or_not(self):
        a = self.raw_create()
        self.here()
        b = self.raw_create()
        self.assertEqual(a[0], b[0])
        self.assertEqual(sorted(a[1]), sorted(b[1]))
        self.assertEqual(a[1].get("status"), b[1].get("status"))
        self.assertTrue(self.broker.flush_notifications(10))

    def test_failure_after_async_dispatch_fails_and_audits(self):
        self.install([Boom(type_name="ticker")])
        code, body, _ = self.raw_create()
        self.assertEqual(code, 202)
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(self.broker._by_id[body["id"]].status, "failed")
        (f,) = self.ev("failed")
        self.assertIn("could not notify", f["error"])
        self.assertEqual(self.ev("notified"), [])
        _, b = self.api("GET", f"/v1/requests/{body['id']}?wait=0")
        self.assertEqual(json.loads(b)["status"], "failed")
        self.assertEqual(audit_api.error_class(f["error"]), "other")

    def test_notified_audited_after_success(self):
        self.raw_create()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(len(self.ev("notified")), 1)

    def test_decision_before_slow_send_finishes_resolves_after_the_send(self):
        gate, log = threading.Event(), []
        slow = Slow(gate=gate, log=log, type_name="ticker")
        self.install([slow])
        rid = self.raw_create()[1]["id"]
        self.assertTrue(slow.started.wait(5))
        self.decide(rid, "deny")
        self.assertEqual(self.broker._by_id[rid].status, "denied")
        _fast.quiesce()                                            # nothing may be mid-flight but the held send
        self.assertEqual(slow.resolutions, [])                     # send still in flight
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(log, [("sent", "ticker"), ("resolved", "denied")])

    def test_failure_racing_a_decision_never_overrides_it(self):
        gate = threading.Event()

        class FailLate(Slow):
            def send(self, n):
                self.started.set()
                self.gate.wait(10)
                raise NotifyError("late failure")
        slow = FailLate(gate=gate, type_name="ticker")
        self.install([slow])
        rid = self.raw_create()[1]["id"]
        self.assertTrue(slow.started.wait(5))
        self.decide(rid, "deny")
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(self.broker._by_id[rid].status, "denied")
        self.assertEqual(self.ev("failed"), [])

    def test_queued_send_for_a_settled_request_never_goes_out(self):
        jobs = []
        self.broker._notify_submit = jobs.append
        rid = self.raw_create()[1]["id"]
        self.assertEqual(len(jobs), 1)
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        jobs[0]()
        self.assertEqual(self.counts(), [0, 0, 0])
        self.assertEqual([len(x.resolutions) for x in (self.tick, self.tele, self.wp)], [0, 0, 0])

    def test_held_request_decided_during_partial_send(self):
        gate, log = threading.Event(), []
        slow = Slow(gate=gate, log=log, type_name="telegram")
        self.install([self.tick, slow])
        self.broker.presence_cfg["transports"] = ["ticker"]
        self.here()
        rid = self.raw_create()[1]["id"]
        self.assertTrue(slow.started.wait(5))
        self.decide(rid, "deny")
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(self.tick.sent, [])
        self.assertEqual(self.tick.resolutions, [])
        self.assertEqual(log, [("sent", "telegram"), ("resolved", "denied")])

    def test_concurrent_requests(self):
        gate = threading.Event()
        self.addCleanup(gate.set)
        slow = [Slow(gate=gate, type_name="ticker")]
        self.install(slow)
        out = []
        ts = [threading.Thread(target=lambda: out.append(self.raw_create())) for _ in range(6)]
        t0 = time.time()
        for x in ts:
            x.start()
        for x in ts:
            x.join(10)
        self.assertLess(time.time() - t0, 5)                     # all six returned while every send is blocked
        self.assertFalse(gate.is_set())
        self.assertEqual(len({o[1]["id"] for o in out}), 6)
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))
        self.assertEqual(len(slow[0].sent), 6)
        self.assertEqual(len(self.ev("notified")), 6)

    def test_pending_work_does_not_block_shutdown(self):
        gate = threading.Event()
        slow = Slow(gate=gate, type_name="ticker")
        self.install([slow])
        self.raw_create()
        self.assertTrue(slow.started.wait(5))
        t0 = time.time()
        self.assertFalse(self.broker.flush_notifications(0.2))     # gives up, does not hang
        self.assertLess(time.time() - t0, 2)
        workers = [x for x in threading.enumerate() if x.name.startswith("Thread") and x.daemon]
        self.assertTrue(workers)
        gate.set()
        self.assertTrue(self.broker.flush_notifications(10))


class ActionToken(Base):
    with_actions = True

    def test_token_works_after_delayed_release(self):
        self.here()
        rid = self.ask()
        self.assertEqual(self.counts(), [0, 0, 0])
        self.clock.t += 30
        self.broker.presence_tick()
        n = self.tick.notifications[0]
        self.assertTrue(n.action_token)
        self.assertEqual(n.rid, rid)
        h = {"X-authentik-username": "alice", "Content-Type": "application/json",
             "X-Requested-With": "asb", "Origin": self.broker.cfg["approve_base_url"].rstrip("/"),}
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/push/decide", method="POST", headers=h,
            data=json.dumps({"rid": rid, "token": n.action_token, "decision": "approve"}).encode()))
        self.assertEqual(r.status, 200)
        self.assertEqual(self.result(rid)["status"], "approved")

    def test_token_is_the_same_one_built_at_creation(self):
        self.here()
        rid = self.ask()
        req = self.broker._by_id[rid]
        held_n = self.broker._held[rid]["n"]
        self.assertIs(held_n, req.notification)
        import hashlib
        self.assertEqual(req.action_hash, hashlib.sha256(held_n.action_token.encode()).digest())


class Visibility(Base):
    def test_audit_events_in_history_timeline(self):
        self.here()
        rid = self.ask()
        self.clock.t += 30
        self.broker.presence_tick()
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        body = self.get(f"/request/{rid}?fragment=1")[1]
        self.assertIn("notify_held", body)
        self.assertIn("notify_released", body)
        self.assertIn("presence_lapsed", body)

    def test_events_are_hidden_from_the_agent_audit_api(self):
        for ev in ("notify_held", "notify_released", "notify_dropped"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertIsNone(audit_api.redact({"event": ev, "id": "r", "ts": 1.0, "seq": 1,
                                                "reason": "presence", "transports": ["ticker"]}))

    def test_nothing_presence_related_reaches_agent_surfaces(self):
        self.here()
        rid = self.ask()
        _, created = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})
        surfaces = [created]

        def sweep():
            for path in (f"/v1/requests/{rid}?wait=0", "/v1/secrets", "/v1/status", "/v1/audit",
                         "/v1/audit?limit=100"):
                surfaces.append(self.api("GET", path)[1])
        sweep()
        self.clock.t += 30
        self.broker.presence_tick()
        sweep()
        self.decide(rid, "deny")
        _fast.quiesce(self.broker)
        sweep()
        for s in surfaces:
            low = s.lower()
            for word in ("presence", "held", "notify_", "fallback", "heartbeat", "released"):
                self.assertNotIn(word, low, word)

    def test_event_names_are_all_classified(self):
        for ev in ("notify_held", "notify_released", "notify_dropped"):
            self.assertIn(ev, __import__("test_audit_api").event_names_in_broker())

    def test_settings_row(self):
        body = self.get("/settings")[1]
        self.assertIn("held while an approval page is open", body)
        self.assertIn("sent after 60 s if still waiting", body)
        self.broker.presence_cfg["enabled"] = False
        self.assertIn("always sent immediately", self.get("/settings")[1])
        self.broker.presence_cfg.update(enabled=True, fallback_s=None)
        self.assertIn("never sent as a fallback", self.get("/settings")[1])

    def test_pages_carry_the_heartbeat_script_only_when_enabled(self):
        for path in ("/", "/settings", "/policies"):
            body = self.get(path)[1]
            self.assertIn("/presence", body, path)
            self.assertIn("visibilityState", body)
            self.assertIn("ASB_PRESENCE", body)
        self.broker.presence_cfg["enabled"] = False
        self.assertNotIn("ASB_PRESENCE", self.get("/settings")[1])

    def test_require_focus_is_passed_to_the_page(self):
        self.assertIn('"focus": false', self.get("/")[1])
        self.broker.presence_cfg["require_focus"] = True
        self.assertIn('"focus": true', self.get("/")[1])
        self.assertIn("document.hasFocus()", self.get("/")[1])

    def test_server_records_what_js_sends(self):
        self.broker.presence_cfg["require_focus"] = True
        self.assertEqual(self.beat({"v": False}), 204)     # JS: not focused -> hidden beat
        self.assertFalse(self.broker.presence.present("alice"))


NODE_HARNESS = r"""
const fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const cfg=JSON.parse(process.argv[3]);
const state=JSON.parse(process.argv[4]);          // {visible, focus}
const calls=[], L={}, W={};
let intervals=[];
global.window={ASB_PRESENCE:cfg,addEventListener:(e,f)=>{W[e]=f;}};
global.document={get visibilityState(){return state.visible?'visible':'hidden';},
  hasFocus(){ if(state.throwFocus) throw new Error('x'); return state.focus;},
  addEventListener:(e,f)=>{L[e]=f;}};
global.fetch=(u,o)=>{calls.push({u,o,b:JSON.parse(o.body)});
  return state.status?Promise.resolve({status:state.status}):Promise.reject(new Error('net'));};
global.setInterval=(f,ms)=>{intervals.push({f,ms});return intervals.length;};
global.clearInterval=()=>{};
new Function('window','document','fetch','setInterval','clearInterval',src)(window,document,fetch,setInterval,clearInterval);
const out=[];
const mark=(l)=>{out.push([l,calls.splice(0).map(c=>[c.u,c.b.v,c.o.keepalive,c.o.headers['X-Requested-With'],c.o.headers['Content-Type'],typeof c.b.tab])]);};
(async()=>{
  mark('load'); await new Promise(r=>setTimeout(r,5));
  intervals[0].f(); mark('tick');
  state.visible=false; L.visibilitychange(); mark('hidden');
  intervals[0].f(); mark('tick-hidden');
  state.visible=true; L.visibilitychange(); mark('visible');
  state.focus=false; W.blur(); mark('blur');
  state.focus=true; W.focus(); mark('focus');
  W.pagehide(); mark('pagehide');
  console.log(JSON.stringify({out,every:intervals[0].ms}));
})();
"""


class JsHeartbeat(unittest.TestCase):
    def run_js(self, cfg, state):
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "p.js"), "w") as f:
            f.write(bmod._PRESENCE_JS)
        with open(os.path.join(d, "h.js"), "w") as f:
            f.write(NODE_HARNESS)
        chk = subprocess.run([node, "--check", os.path.join(d, "p.js")], capture_output=True, text=True)
        self.assertEqual(chk.returncode, 0, chk.stderr)
        r = subprocess.run([node, os.path.join(d, "h.js"), os.path.join(d, "p.js"),
                            json.dumps(cfg), json.dumps(state)], capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(r.stdout.strip().splitlines()[-1])
        return {k: v for k, v in res["out"]}, res["every"]

    def vs(self, out, k):
        return [c[1] for c in out[k]]

    def test_visible_only_without_focus_requirement(self):
        out, every = self.run_js({"every": 10000, "focus": False}, {"visible": True, "focus": False})
        self.assertEqual(every, 10000)
        self.assertEqual(self.vs(out, "load"), [True])
        self.assertEqual(self.vs(out, "tick"), [True])
        self.assertEqual(self.vs(out, "hidden"), [False])          # final hidden beat
        self.assertEqual(out["tick-hidden"], [])                   # nothing while hidden
        self.assertEqual(self.vs(out, "visible"), [True])
        self.assertEqual(self.vs(out, "blur"), [True])             # focus not required
        c = out["load"][0]
        self.assertEqual(c[:2], ["/presence", True])
        self.assertEqual(c[2:], [True, "asb", "application/json", "string"])

    def test_require_focus(self):
        out, _ = self.run_js({"every": 10000, "focus": True}, {"visible": True, "focus": False})
        self.assertEqual(out["load"], [])                          # visible but unfocused: no beat
        out, _ = self.run_js({"every": 10000, "focus": True}, {"visible": True, "focus": True})
        self.assertEqual(self.vs(out, "load"), [True])
        self.assertEqual(self.vs(out, "blur"), [False])            # losing focus sends hidden
        self.assertEqual(self.vs(out, "focus"), [True])

    def test_never_throws_and_stops_on_404(self):
        out, _ = self.run_js({"every": 10000, "focus": True},
                             {"visible": True, "focus": True, "throwFocus": True})
        self.assertEqual(out["load"], [])
        out, _ = self.run_js({"every": 10000, "focus": False}, {"visible": True, "focus": True, "status": 404})
        self.assertEqual(self.vs(out, "load"), [True])
        self.assertEqual(self.vs(out, "tick"), [])                 # dead after a 404


if __name__ == "__main__":
    unittest.main()
