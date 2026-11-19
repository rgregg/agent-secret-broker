"""An auto-approved request must not hold its `POST /v1/requests` open while the upstream call runs.

A request approved by policy (an `auto_approve` rule, a standing approval, `approval: allow`) used to be released on
the very thread that answers the agent's POST, so the POST returned only after the upstream call did. A slow upstream
(an LLM call of 79 s) outran the client's 40 to 60 s wait and the client reported a connection error while the
broker went on to finish the call. A human-approved request never had the problem: it is released on its own thread
and the client collects the result with a poll. Auto-approved ones now work the same way.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import autorules  # noqa: E402
from secret_broker.backends import BackendError  # noqa: E402
from test_auto_rules import Enrolled  # noqa: E402


class SlowRelease(Enrolled, t.Harness):
    """`_release` (the upstream call) blocks on `self.gate` until the test lets it go."""
    risk = "low"
    settle_auto = False         # the whole point: the POST must return before the release has finished

    def setUp(self):
        super().setUp()
        self.port = self.up.server_address[1]
        self.broker.summarizer = t._Stub("Reads", "low")                 # an Always approval needs a low rating
        self.gate = threading.Event()
        self.fail_with = None
        real = self.broker._release

        def slow(req):
            self.gate.wait(8)
            if self.fail_with:
                raise self.fail_with
            return real(req)
        self.broker._release = slow
        self.addCleanup(self.gate.set)

    def post(self):
        """POST the request; returns (seconds it took, status code, body)."""
        t0 = time.time()
        code, raw = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{self.port}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        return time.time() - t0, code, json.loads(raw)

    def poll(self, rid, wait):
        return json.loads(self.api("GET", f"/v1/requests/{rid}?wait={wait}")[1])

    def check_returns_at_once_and_delivers_later(self):
        took, code, body = self.post()
        self.assertEqual(code, 202)
        self.assertLess(took, 3, "the POST waited for the upstream call")
        self.assertEqual(body["status"], "approved")                     # approved by policy: nobody is being waited for
        rid = body["id"]
        self.assertEqual(self.broker.pending(), [])                      # not offered to a human while it runs
        running = self.poll(rid, 0)
        self.assertNotIn(running["status"], ("pending", "denied", "failed"))     # still running, not final
        self.assertNotIn("http", running)                                # and no result yet
        self.gate.set()
        done = self.poll(rid, 8)
        self.assertEqual(done["status"], "approved")
        self.assertEqual(done["http"]["status"], 200)                    # the call ran and its result was delivered
        return rid, done


class ByRule(SlowRelease):
    def setUp(self):
        super().setUp()
        self.broker.auto_rules = autorules.parse([
            {"name": "reads", "mode": "http", "secret": "svc", "scheme": "http", "host": "127.0.0.1",
             "path_prefix": "/x", "clients": [self.client.id]}])

    def test_a_config_rule_returns_at_once_and_delivers_through_the_poll(self):
        self.check_returns_at_once_and_delivers_later()
        approved = self.events("approved")[-1]
        self.assertEqual((approved["via"], approved["decision_source"], approved["rule_name"]),
                         ("policy", "config_rule", "reads"))

    def test_a_failing_release_is_delivered_by_the_poll_as_a_fixed_failure(self):
        self.fail_with = BackendError("S3CR3T-vault-detail")
        took, code, body = self.post()
        self.assertEqual((code, body["status"]), (202, "approved"))
        self.assertLess(took, 3)
        self.gate.set()
        done = self.poll(body["id"], 8)
        self.assertEqual(done["status"], "failed")
        self.assertNotIn("S3CR3T", json.dumps(done))                     # no exception text reaches the agent
        self.assertTrue(done["error"])                                   # but there is a fixed one


class ByStanding(SlowRelease):
    def test_an_always_approval_returns_at_once(self):
        self.broker._add_always("svc", "http", "any", "alice", "*")
        self.check_returns_at_once_and_delivers_later()
        self.assertEqual(self.events("approved")[-1]["via"], "policy")

    def test_a_timed_grant_returns_at_once(self):
        self.broker.grants.add(["svc"], 5, "any", "alice", "dashboard", "r", mode="http")
        self.check_returns_at_once_and_delivers_later()
        self.assertEqual(self.events("grant_used")[-1]["kind"], "timed")


class ByAllow(SlowRelease):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"

    def setUp(self):
        super().setUp()

    def test_approval_allow_returns_at_once(self):
        self.check_returns_at_once_and_delivers_later()
        self.assertEqual(self.events("approved")[-1]["via"], "policy")

    def test_a_human_cannot_decide_a_request_that_is_already_being_released(self):
        took, code, body = self.post()
        self.assertEqual(code, 202)
        self.assertLess(took, 3)                                         # the release is still running (the gate is shut)
        rid = body["id"]
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice")[0], 410)   # not pending any more
        self.gate.set()
        self.assertEqual(self.poll(rid, 8)["http"]["status"], 200)       # released exactly once, by policy
        self.assertEqual(len(self.events("approved")), 1)


if __name__ == "__main__":
    unittest.main()
