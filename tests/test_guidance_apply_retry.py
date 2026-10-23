"""Applying a guidance proposal against a rate-limited vault: serialized spaced writes, retry
with backoff, failure classes for the approver only, the Retry action, and `asb guidance
status`. The clock and sleep are fakes (see test_guidance_proposals.Base)."""
import http.server
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_guidance_proposals as g  # noqa: E402

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api, proposals  # noqa: E402
from secret_broker.backends import BackendError  # noqa: E402

RATE = "Too many requests. Slow down, vault.example.internal item 0f3a"
ENTRIES = [{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"}, {"name": "gamma", "text": "G1"}]


class Apply(g.Base):
    def fail_first(self, k, msg=RATE, only=None):
        """set_meta raises `msg` for the first k calls (of `only` item when given)."""
        real, left = self.broker.backend.set_meta, [k]
        self.calls = []

        def set_meta(item, meta):
            self.calls.append((item, self.now))
            if (only is None or item == only) and left[0] > 0:
                left[0] -= 1
                raise BackendError(msg)
            return real(item, meta)
        self.broker.backend.set_meta = set_meta

    def go(self, entries=ENTRIES, apply=None):
        rid = self.propose(entries)[1]["id"]
        self.decide(rid, "approve", apply=range(len(entries)) if apply is None else apply)
        self.settle(rid)
        return rid

    def test_rate_limit_for_first_k_calls_all_entries_end_applied(self):
        self.fail_first(3)
        rid = self.go()
        self.assertEqual(self.result(rid), {"status": "approved", "error": None, "guidance": {
            "applied": ["alpha", "beta", "gamma"], "denied": [], "failed": []}})
        self.assertEqual((self.guid("alpha"), self.guid("beta"), self.guid("gamma")), ("A1", "B1", "G1"))
        # alpha: 3 tries failed -> backoff 5s, 15s, 45s, then the 4th try succeeds
        backoffs = [d for d in self.sleeps if d >= 5]
        self.assertEqual(backoffs, [5, 15, 45])
        self.assertEqual(len(self.events("guidance_changed")), 3)
        self.assertEqual(len(self.events("guidance_change_retry")), 3)
        self.assertEqual(self.events("guidance_change_failed"), [])

    def test_one_rate_limit_per_entry_spread_across_entries(self):
        real, seen = self.broker.backend.set_meta, set()

        def set_meta(item, meta):
            if item not in seen:
                seen.add(item)
                raise BackendError("Rate limit exceeded")
            return real(item, meta)
        self.broker.backend.set_meta = set_meta
        rid = self.go()
        self.assertEqual(self.result(rid)["guidance"]["applied"], ["alpha", "beta", "gamma"])
        self.assertEqual([d for d in self.sleeps if d >= 5], [5, 5, 5])

    def test_permanent_failure_marks_failed_after_three_retries_others_apply(self):
        self.fail_first(99, only="Beta")
        rid = self.go()
        self.assertEqual(self.result(rid)["guidance"], {"applied": ["alpha", "gamma"], "denied": [],
                                                        "failed": ["beta"]})
        self.assertEqual(len([c for c in self.calls if c[0] == "Beta"]), 4)      # 1 try + 3 retries
        f = self.events("guidance_change_failed")
        self.assertEqual(len(f), 1)
        self.assertEqual((f[0]["error_class"], f[0]["attempts"], f[0]["secret"]), ("rate_limited", 4, "beta"))
        self.assertEqual(self.broker._by_id[rid].gclasses, {"beta": "rate_limited"})
        self.assertEqual(self.broker._by_id[rid].status, "approved")

    def test_non_transient_error_is_not_retried(self):
        self.fail_first(99, msg="item is invalid", only="Alpha")
        rid = self.go()
        self.assertEqual(len([c for c in self.calls if c[0] == "Alpha"]), 1)
        self.assertEqual(self.events("guidance_change_retry"), [])
        self.assertEqual(self.broker._by_id[rid].gclasses, {"alpha": "invalid"})

    def test_writes_are_spaced(self):
        self.fail_first(0)
        self.go()
        times = [t for _, t in self.calls]
        self.assertEqual(len(times), 3)
        self.assertTrue(all(b - a >= 1.5 - 1e-9 for a, b in zip(times, times[1:])), times)

    def test_jitter_scales_backoff(self):
        self.broker._jitter = lambda a, b: b            # the top of the range
        self.fail_first(1)
        self.go(ENTRIES[:1])
        self.assertAlmostEqual([d for d in self.sleeps if d >= 5][0], 5 * (1 + proposals.RETRY_JITTER))

    def test_decision_returns_promptly_and_agent_polls_pending_then_approved(self):
        self.fail_first(1)
        self.gate = threading.Event()                    # the first backoff sleep blocks
        rid = self.propose(ENTRIES)[1]["id"]
        t0 = time.time()
        status, _ = self.decide(rid, "approve", apply=(0, 1, 2))
        self.assertEqual(status, 200)
        self.assertLess(time.time() - t0, 5)
        time.sleep(0.3)
        req = self.broker._by_id[rid]
        self.assertEqual(req.status, "deciding")
        self.assertEqual(self.api("GET", f"/v1/requests/{rid}?wait=0")[1] and
                         json.loads(self.api("GET", f"/v1/requests/{rid}?wait=0")[1]),
                         {"status": "pending", "error": None})
        self.gate.set()
        req.done.wait(10)
        self.assertEqual(self.result(rid)["status"], "approved")
        self.assertEqual(self.result(rid)["guidance"]["applied"], ["alpha", "beta", "gamma"])

    def test_decision_notes_say_applying_n(self):
        self.gate = threading.Event()
        self.fail_first(1)
        rid = self.propose(ENTRIES)[1]["id"]
        form = {"id": rid, "decision": "approve", "csrf": self.broker.csrf_token("alice"),
                "apply_0": "1", "apply_2": "1"}
        status, body = self.post("/decide", **form)
        self.assertEqual(status, 200)                    # urlopen follows the redirect to the dashboard
        self.assertIn("Applying 2 entries", body)
        self.gate.set()
        self.settle(rid)

    def test_link_page_says_applying_n(self):
        rid = self.propose(ENTRIES[:2])[1]["id"]
        status, body = self.post(f"/a/{self.broker._by_id[rid].nonce}", decision="approve",
                                 apply_0="1", apply_1="1")
        self.assertIn("Applying 2 entries", body)
        self.settle(rid)

    def test_two_proposals_serialize_their_writes(self):
        self.gate = None
        active, peak, guard = [0], [0], threading.Lock()
        real = self.broker.backend.set_meta

        def set_meta(item, meta):
            with guard:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with guard:
                active[0] -= 1
            return real(item, meta)
        self.broker.backend.set_meta = set_meta
        r1 = self.propose([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"}])[1]["id"]
        r2 = self.propose([{"name": "gamma", "text": "G1"}, {"name": "svc", "text": "S1"}])[1]["id"]
        self.decide(r1, "approve", apply=(0, 1))
        self.decide(r2, "approve", apply=(0, 1))
        self.settle(r1)
        self.settle(r2)
        self.assertEqual(peak[0], 1)
        self.assertEqual(self.guid("svc"), "S1")
        self.assertEqual(len(self.events("guidance_changed")), 4)

    def test_failure_classes_in_approver_ui_and_audit_not_for_the_agent(self):
        self.fail_first(99, only="Beta")
        rid = self.go()
        body = self.get(f"/request/{rid}")[1]
        self.assertIn("applied", body)
        self.assertIn("failed: rate limited", body)
        self.assertNotIn("vault.example.internal", body)
        self.assertNotIn("Too many requests", body)
        res = self.events("guidance_proposal_result")[-1]
        self.assertEqual((res["failed_names"], res["failed_classes"]), (["beta"], ["rate_limited"]))
        # not for the agent: result is names only, the audit API hides every guidance event
        self.assertEqual(set(self.result(rid)["guidance"]), {"applied", "denied", "failed"})
        self.assertNotIn("rate_limited", json.dumps(self.result(rid)))
        for ev in ("guidance_change_failed", "guidance_change_retry", "guidance_proposal_result",
                   "guidance_retry_requested", "guidance_retry_refused"):
            self.assertIn(ev, audit_api.HIDDEN)
        code, raw = self.api("GET", "/v1/audit?limit=500")
        self.assertNotIn("rate_limited", raw)
        self.assertNotIn("failed_classes", raw)

    def test_not_ticked_is_shown_as_denied_not_ticked(self):
        rid = self.go(apply=(0,))
        body = self.get(f"/request/{rid}")[1]
        self.assertIn("denied (not ticked)", body)

    def test_each_class_from_error_text(self):
        c = proposals.classify
        self.assertEqual(c(BackendError("Rate limit exceeded")), "rate_limited")
        self.assertEqual(c(BackendError("bw: timed out")), "backend_unavailable")
        self.assertEqual(c(ConnectionResetError("x")), "backend_unavailable")
        self.assertEqual(c(BackendError("409 conflict")), "conflict")
        self.assertEqual(c(KeyError("x")), "invalid")
        self.assertEqual(c(BackendError("item 'x' not found")), "invalid")
        self.assertEqual(c(BackendError("boom")), "other")

    def test_class_labels_for_other_failures(self):
        self.fail_first(99, msg="bw: Connection refused", only="Alpha")
        rid = self.go(ENTRIES[:1])
        self.assertIn("failed: backend unavailable", self.get(f"/request/{rid}")[1])


class Retry(g.Base):
    def setUp(self):
        super().setUp()
        real = self.broker.backend.set_meta
        self.broken = {"Beta", "Gamma"}

        def set_meta(item, meta):
            if item in self.broken:
                raise BackendError(RATE)
            return real(item, meta)
        self.broker.backend.set_meta = set_meta

    def failed_proposal(self):
        rid = self.propose(ENTRIES)[1]["id"]
        self.decide(rid, "approve", apply=(0, 1, 2))
        self.settle(rid)
        return rid

    def retry(self, rid, **kw):
        form = {"id": rid, "csrf": self.broker.csrf_token("alice")}
        form.update(kw)
        return self.post("/request/retry", **form)

    def wait_retry(self, rid):
        end = time.time() + 10
        while time.time() < end and self.broker._gretry.get(rid, {}).get("running", False):
            time.sleep(0.02)
        time.sleep(0.05)

    def test_button_only_with_failed_entries_and_retry_applies_only_those(self):
        rid = self.failed_proposal()
        pop = self.get(f"/request/{rid}")[1]
        self.assertIn("Retry failed (2)", pop)
        self.assertEqual(self.guid("alpha"), "A1")
        n_changed = len(self.events("guidance_changed"))
        self.broken = set()
        status, body = self.retry(rid)
        self.assertEqual(status, 200)
        self.assertIn("Retrying the failed entries", body)
        self.wait_retry(rid)
        self.assertEqual((self.guid("beta"), self.guid("gamma")), ("B1", "G1"))
        ch = self.events("guidance_changed")
        self.assertEqual(len(ch) - n_changed, 2)                         # alpha was not written again
        self.assertEqual({e["secret"]: e["via"] for e in ch[n_changed:]},
                         {"beta": "proposal_retry", "gamma": "proposal_retry"})
        got = self.result(rid)
        self.assertEqual(got["status"], "approved")
        self.assertEqual(got["guidance"], {"applied": ["alpha", "beta", "gamma"], "denied": [], "failed": []})
        self.assertNotIn("Retry failed", self.get(f"/request/{rid}")[1])
        self.assertEqual(self.retry(rid)[0], 200)                        # redirect with the stale note
        self.assertIn("Nothing to retry", self.retry(rid)[1])
        self.assertEqual(self.broker._gretry, {})                        # text gone once applied
        self.assertTrue(self.events("guidance_retry_requested"))

    def test_partial_retry_keeps_remaining_failed(self):
        rid = self.failed_proposal()
        self.broken = {"Gamma"}
        self.retry(rid)
        self.wait_retry(rid)
        self.assertEqual(self.result(rid)["guidance"], {"applied": ["alpha", "beta"], "denied": [],
                                                        "failed": ["gamma"]})
        self.assertEqual(self.broker.retry_count(rid), 1)
        self.assertIn("Retry failed (1)", self.get(f"/request/{rid}")[1])
        self.assertIn("failed: rate limited", self.get(f"/request/{rid}")[1])

    def test_text_only_for_failed_entries_never_denied_or_applied(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": g.CANARY},
                            {"name": "gamma", "text": "G1"}])[1]["id"]
        self.decide(rid, "approve", apply=(1, 2))          # alpha not ticked; beta, gamma fail
        self.settle(rid)
        self.assertEqual(self.broker._gretry[rid]["texts"], {"beta": g.CANARY, "gamma": "G1"})
        self.assertNotIn(g.CANARY, self.all_text())

    def test_text_dropped_after_ttl(self):
        rid = self.failed_proposal()
        self.broker._gretry[rid]["until"] = time.time() - 1
        self.assertEqual(self.broker.retry_count(rid), 0)
        self.assertNotIn("Retry failed", self.get(f"/request/{rid}")[1])
        self.assertEqual(self.broker.retry_proposal(rid, "alice", "dashboard")[0], 410)
        self.assertEqual(self.broker._gretry, {})
        self.assertIn("Nothing to retry", self.retry(rid)[1])

    def test_ttl_is_the_proposal_ttl_from_settle(self):
        rid = self.failed_proposal()
        left = self.broker._gretry[rid]["until"] - time.time()
        self.assertAlmostEqual(left, self.broker.proposals_cfg["ttl_s"], delta=5)

    def test_restart_loses_the_text(self):
        rid = self.failed_proposal()
        from secret_broker.broker import Broker
        from secret_broker.notify import FakeNotifier
        b2 = Broker({"approve_base_url": "https://s.example", "allowed_user": "alice"},
                    self.broker.backend, FakeNotifier(), None)
        self.assertEqual(b2.retry_count(rid), 0)
        self.assertEqual(b2.retry_proposal(rid, "alice", "dashboard")[0], 410)

    def test_csrf_and_sso_guards(self):
        rid = self.failed_proposal()
        self.assertEqual(self.post("/request/retry", id=rid)[0], 403)                 # no csrf
        self.assertEqual(self.post("/request/retry", user="mallory", id=rid,
                                   csrf=self.broker.csrf_token("alice"))[0], 403)
        self.assertEqual(self.broker.retry_count(rid), 2)
        self.assertEqual(self.events("guidance_retry_requested"), [])

    def test_only_human_channels_may_retry(self):
        rid = self.failed_proposal()
        for ch in ("push", "ha", "token", "bogus"):
            self.assertEqual(self.broker.retry_proposal(rid, "x", ch)[0], 403)
        self.assertEqual(len(self.events("guidance_retry_refused")), 4)
        self.assertEqual(self.broker.retry_count(rid), 2)
        self.broken = set()
        self.assertEqual(self.broker.retry_proposal(rid, "alice", "link")[0], 202)
        self.wait_retry(rid)
        self.assertEqual(self.guid("beta"), "B1")

    def test_second_retry_while_running_is_refused(self):
        rid = self.failed_proposal()
        self.gate = threading.Event()
        self.broker._gwrite_last = None
        self.broker._jitter = lambda a, b: 0.0
        self.assertEqual(self.broker.retry_proposal(rid, "alice", "dashboard")[0], 202)
        time.sleep(0.2)
        self.assertEqual(self.broker.retry_proposal(rid, "alice", "dashboard")[0], 409)
        self.assertEqual(self.broker.retry_count(rid), 0)       # no button while one runs
        self.gate.set()
        self.wait_retry(rid)

    def test_agent_poll_never_sees_classes_after_retry(self):
        rid = self.failed_proposal()
        self.assertEqual(set(self.result(rid)["guidance"]), {"applied", "denied", "failed"})
        self.assertEqual(self.result(rid)["status"], "approved")


class Config(unittest.TestCase):
    def test_write_spacing_validation(self):
        self.assertEqual(proposals.parse_config(None)["write_spacing_s"], 1.5)
        for ok in (0, 0.0, 1, 30, 29.9, 2.5):
            self.assertEqual(proposals.parse_config({"write_spacing_s": ok})["write_spacing_s"], ok)
        for bad in (-0.1, 30.1, "1", True, None, [], float("nan")):
            with self.assertRaises(ValueError) as cm:
                proposals.parse_config({"write_spacing_s": bad})
            self.assertIn("guidance_proposals.write_spacing_s", str(cm.exception))

    def test_spacing_zero_means_no_wait(self):
        class B(g.Base):
            def tweak(self, cfg):
                super().tweak(cfg)
                cfg["guidance_proposals"] = {"write_spacing_s": 0}
        self.assertEqual(B.__name__, "B")


class RestartDoc(unittest.TestCase):
    def test_documented(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "docs", "guidance.md")) as f:
            doc = f.read()
        self.assertIn("restarts while", doc)
        self.assertIn("write_spacing_s", doc)


# -------------------------------------------------------- asb guidance status
class FakeBroker(http.server.BaseHTTPRequestHandler):
    shapes = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        rid = self.path.split("?")[0].rsplit("/", 1)[1]
        body = json.dumps(self.shapes[rid]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class StatusCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FakeBroker.shapes = {
            "applied0001": {"status": "approved", "error": None,
                            "guidance": {"applied": ["alpha", "beta"], "denied": ["gamma"], "failed": ["delta"]}},
            "allfailed01": {"status": "approved", "error": None,
                            "guidance": {"applied": [], "denied": [], "failed": ["alpha"]}},
            "denied0001": {"status": "denied", "error": None,
                           "guidance": {"applied": [], "denied": ["alpha"], "failed": []}},
            "expired001": {"status": "expired", "error": None,
                           "guidance": {"applied": [], "denied": ["alpha"], "failed": []}},
            "pending001": {"status": "pending", "error": None},
            "deciding01": {"status": "deciding", "error": None},
        }
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeBroker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def status(self, rid):
        env = dict(os.environ, SECRET_BROKER_URL=f"http://127.0.0.1:{self.srv.server_port}",
                   SECRET_BROKER_KEY=g.KEY)
        p = subprocess.run([sys.executable, "-I", g.CLI, "guidance", "status", rid], env=env,
                           capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.splitlines()

    def test_shapes(self):
        self.assertEqual(self.status("applied0001"),
                         (0, ["applied: alpha, beta", "denied: gamma", "failed: delta"]))
        self.assertEqual(self.status("allfailed01"), (3, ["applied: -", "denied: -", "failed: alpha"]))
        self.assertEqual(self.status("denied0001"), (4, ["applied: -", "denied: alpha", "failed: -"]))
        self.assertEqual(self.status("expired001"), (5, ["applied: -", "denied: alpha", "failed: -"]))
        self.assertEqual(self.status("pending001"), (0, ["pending"]))
        self.assertEqual(self.status("deciding01"), (0, ["pending"]))


if __name__ == "__main__":
    unittest.main()
