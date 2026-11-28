"""A request gets a card on the requests page only once it has been handed to a human.

While the broker is still deciding (the risk model rating it, then rules, policy and grants), the request is
`pending` but must not be listed: one that is then released by policy used to flash up as a card for the few
seconds the rating took, and briefly raised the attention badge.
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


class _SlowStub:
    """A summarizer whose rating waits on `gate`; `entered` is set once a rating has started."""

    def __init__(self, risk):
        self.risk, self.gate, self.entered = risk, threading.Event(), threading.Event()

    def analyze(self, mode, names, spec):
        self.entered.set()
        self.gate.wait(8)
        return {"summary": "Reads things", "risk": self.risk}


class RoutingHidden(t.Harness):
    risk = "low"

    def setUp(self):
        super().setUp()
        self.stub = _SlowStub(self.risk)
        self.broker.summarizer = self.stub
        self.addCleanup(self.stub.gate.set)
        self.result = {}

    def post_in_background(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"

        def go():
            code, raw = self.api("POST", "/v1/requests", {
                "mode": "http", "names": ["svc"], "method": "GET", "url": url,
                "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
            self.result.update(code=code, body=json.loads(raw))
        th = threading.Thread(target=go, daemon=True)
        th.start()
        self.assertTrue(self.stub.entered.wait(5), "the rating never started")
        return th

    def dash(self):
        return t.req(self.abase + "/", headers={"X-authentik-username": "alice"})[1]

    def assert_no_card(self):
        rid = next(iter(self.broker._by_id))
        self.assertEqual(self.broker._by_id[rid].status, "pending")    # it is open, just not shown yet
        self.assertEqual(self.broker.pending(), [])
        self.assertEqual(self.broker.attention(), 0)
        self.assertNotIn(f"<article class=req data-id='{rid}'", self.dash())
        return rid


class PolicyReleased(RoutingHidden):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"

    def test_an_auto_approved_request_never_has_a_card(self):
        th = self.post_in_background()
        self.assert_no_card()
        self.stub.gate.set()
        th.join(5)
        self.assertEqual(self.result["body"]["status"], "approved")
        self.assertEqual(self.broker.pending(), [])


class HumanDecided(RoutingHidden):
    risk = "high"
    decision = None             # nobody taps the notification: the request stays with the human

    def test_a_request_for_the_human_gets_its_card_once_it_is_routed(self):
        th = self.post_in_background()
        rid = self.assert_no_card()
        self.stub.gate.set()
        th.join(5)
        self.assertEqual(self.result["body"]["status"], "pending")
        deadline = time.time() + 5
        while not self.broker.pending() and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual([r.id for r in self.broker.pending()], [rid])
        self.assertIn(f"<article class=req data-id='{rid}'", self.dash())


if __name__ == "__main__":
    unittest.main()
