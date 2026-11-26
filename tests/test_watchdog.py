"""Watchdog: a lock that every request needs and that stays taken is a hung broker. /healthz turns 503 and,
past `stuck_s`, the process exits so the container's restart policy brings it back."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import watchdog  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Parse(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(watchdog.parse_config(None), {"enabled": True, "stuck_s": 120})

    def test_bad_values_name_the_field(self):
        for bad in ("x", {"nope": 1}, {"enabled": "yes"}, {"stuck_s": 10}, {"stuck_s": 5000},
                    {"stuck_s": 60.5}, {"stuck_s": True}):
            with self.subTest(bad), self.assertRaises(ValueError) as cm:
                watchdog.parse_config(bad)
            self.assertTrue(str(cm.exception).startswith("watchdog"), str(cm.exception))

    def test_a_valid_override(self):
        self.assertEqual(watchdog.parse_config({"enabled": False, "stuck_s": 300}),
                         {"enabled": False, "stuck_s": 300})


class Detect(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.a, self.b = threading.Lock(), threading.Lock()
        self.fired = []
        self.wd = watchdog.Watchdog({"a": self.a, "b": self.b}, lambda n, s: self.fired.append((n, s)),
                                    stuck_s=120, probe_s=0.01, mono=self.clock)

    def step(self, secs):
        self.clock.t += secs
        self.wd.check()

    def test_free_locks_are_healthy_and_never_fire(self):
        for _ in range(50):
            self.step(10)
        self.assertTrue(self.wd.healthy())
        self.assertEqual(self.fired, [])

    def test_a_briefly_held_lock_is_not_a_hang(self):
        self.a.acquire()
        self.step(10)
        self.assertTrue(self.wd.healthy())              # one missed probe is a busy broker, not a hung one
        self.a.release()
        self.step(10)
        self.assertTrue(self.wd.healthy())
        self.assertEqual(self.wd.stuck(), {})

    def test_a_stuck_lock_turns_unhealthy_then_fires_once(self):
        self.b.acquire()
        self.step(0)
        self.step(watchdog.UNHEALTHY_S)
        self.assertFalse(self.wd.healthy())
        self.assertEqual(self.fired, [])
        self.step(120 - watchdog.UNHEALTHY_S)
        self.assertEqual(self.fired, [("b", 120)])
        self.step(10)
        self.assertEqual(len(self.fired), 1)

    def test_release_before_the_limit_resets_the_count(self):
        self.a.acquire()
        self.step(0)
        self.step(100)
        self.a.release()
        self.step(10)
        self.a.acquire()
        self.step(10)
        self.step(100)
        self.assertEqual(self.fired, [])

    def test_the_probe_leaves_the_lock_free(self):
        self.step(10)
        self.assertFalse(self.a.locked())
        self.assertFalse(self.b.locked())


class OnStuck(unittest.TestCase):
    def test_logs_then_exits_even_if_the_log_hangs(self):
        exits, logged = [], []
        hang = threading.Event()

        def log(ev, **kw):
            logged.append((ev, kw))
            hang.wait(5)                                # a log write stuck behind the same hang

        fn = watchdog.exit_on_stuck(log, exit_fn=exits.append, log_timeout_s=0.05)
        fn("cfg", 125.4)
        hang.set()
        self.assertEqual(exits, [watchdog.EXIT_CODE])
        self.assertEqual(logged, [("watchdog_restart", {"lock": "cfg", "stuck_s": 125})])


class Healthz(t.Harness):
    """/healthz reports the watchdog's view: a hung broker must not answer `ok`."""

    def get(self):
        url = f"http://127.0.0.1:{self.c.server_address[1]}/healthz"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_ok_without_and_with_a_healthy_watchdog(self):
        self.assertEqual(self.get(), (200, b"ok"))
        clock = Clock()
        self.broker.watchdog = watchdog.Watchdog(self.broker.watched_locks(), lambda n, s: None,
                                                 probe_s=0.01, mono=clock)
        self.broker.watchdog.check()
        self.assertEqual(self.get(), (200, b"ok"))

    def test_unhealthy_while_the_catalog_lock_is_stuck(self):
        clock = Clock()
        self.broker.watchdog = wd = watchdog.Watchdog(self.broker.watched_locks(), lambda n, s: None,
                                                      probe_s=0.01, mono=clock)
        self.assertEqual(set(self.broker.watched_locks()), {"cfg", "state"})
        with self.broker._cfg_lock:
            wd.check()
            clock.t += watchdog.UNHEALTHY_S
            wd.check()
            self.assertEqual(self.get()[0], 503)       # healthz itself must not need the stuck lock
        wd.check()
        self.assertEqual(self.get(), (200, b"ok"))


if __name__ == "__main__":
    unittest.main()
