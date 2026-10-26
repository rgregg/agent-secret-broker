"""Progressive description and rating: the card is drawn at summary_timeout with the plain line and
swaps in the model's answer when it arrives; a late rating is shown but never decides anything."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as E  # noqa: E402
from secret_broker import description as D, riskmodel  # noqa: E402

LOW = {"answers": {"risk": {"choice": "low", "probabilities": {"low": .9, "medium": .05, "high": .05}}}}


def chat(text):
    return {"choices": [{"message": {"content": text}, "finish_reason": "stop"}], "usage": {"cost": 0.0001}}


class Late(E.Harness):
    ttl = 4
    decision = None                       # nobody answers on the phone
    soft, hard = 0.3, 20.0
    release_rating = None                 # Event: the decision call waits for it
    release_text = None                   # Event: the description call waits for it
    text = "Retrieving the list of things from the test service. It is a plain lookup of what exists."

    def tweak(self, cfg):
        cfg["risk"] = {"auto_approve_max": "high"}      # even a HIGH request would auto-release
        cfg["secrets"]["svc"]["approval"] = "prompt"

    def setUp(self):
        super().setUp()
        self.release_rating, self.release_text = threading.Event(), threading.Event()
        self.rating_timeouts, self.chat_timeouts = [], []

        def post(url, key, payload, timeout):
            if "decisions" in url:
                self.rating_timeouts.append(timeout)
                if not self.release_rating.wait(timeout):
                    raise TimeoutError("timed out")
                return LOW
            self.chat_timeouts.append(timeout)
            if not self.release_text.wait(timeout):
                raise TimeoutError("timed out")
            return chat(self.text)
        self.patches = [mock.patch.object(riskmodel, "_post_json", post), mock.patch.object(D, "_post_json", post)]
        [p.start() for p in self.patches]
        d = D.Describer("k", timeout=self.soft, hard_timeout=self.hard)
        self.broker.summarizer = riskmodel.FloorAnalyzer(
            riskmodel.JevAnalyzer("k", timeout=self.soft, hard_timeout=self.hard, describer=d))

    def tearDown(self):
        self.release_rating.set()
        self.release_text.set()
        [p.stop() for p in self.patches]
        super().tearDown()

    def make(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def cards(self):
        code, page = E.req(self.abase + "/?fragment=1", headers={"X-authentik-username": "alice"})
        self.assertEqual(code, 200)
        import re
        return re.search(r"data-version='([0-9a-f]+)'", page).group(1), page

    def until(self, fn, what, secs=5):
        end = time.time() + secs
        while time.time() < end:
            if fn():
                return
            time.sleep(0.02)
        self.fail(what)

    def req_obj(self, rid):
        return self.broker._by_id[rid]

    def status(self, rid):
        return json.loads(self.api("GET", f"/v1/requests/{rid}?wait=0")[1])["status"]

    def test_late_description_swaps_into_the_card(self):
        t0 = time.time()
        rid = self.make()
        self.assertLess(time.time() - t0, 2.5)          # the card did not wait for the model
        v1, page = self.cards()
        self.assertIn("auto: GET", page)
        self.assertIn("model description pending", page)
        self.release_rating.set()
        self.release_text.set()
        self.until(lambda: self.req_obj(rid).summary_source == "model", "description did not arrive")
        v2, page = self.cards()
        self.assertNotEqual(v1, v2)
        self.assertIn("Retrieving the list of things", page)
        self.assertNotIn("model description pending", page)
        self.assertEqual(self.chat_timeouts, [self.hard])          # the call itself ran to the hard ceiling
        self.assertEqual(len(self.events("description_updated")), 1)
        self.assertEqual(self.events("description_updated")[0]["summary_source"], "model")
        v3, _ = self.cards()
        self.assertEqual(v2, v3)                                    # unchanged page: no card redraw

    def test_late_rating_refreshes_the_card_but_never_decides(self):
        rid = self.make()
        self.assertEqual(self.req_obj(rid).risk["level"], "high")   # no verdict in time: treated as high
        self.assertEqual(self.status(rid), "pending")
        v1, page = self.cards()
        self.assertNotIn("rated later", page)
        self.release_rating.set()
        self.until(lambda: self.req_obj(rid).late_rating == "low", "late rating did not arrive")
        v2, page = self.cards()
        self.assertNotEqual(v1, v2)
        self.assertIn("rated later", page)
        self.assertIn("still handled as HIGH", page)
        self.assertEqual(self.req_obj(rid).risk["level"], "high")   # the gate's view is unchanged
        self.assertEqual(self.status(rid), "pending")               # and it was not released
        self.assertEqual(self.events("rated_late")[0]["late_level"], "low")
        self.assertFalse(self.events("approved") or self.events("auto_approved"))

    def test_late_reply_for_a_settled_request_only_reaches_history(self):
        rid = self.make()
        _fast.expire(self.broker, rid)                      # its ttl passes
        self.assertEqual(self.status(rid), "expired")
        before = (self.req_obj(rid).status, self.req_obj(rid).risk, len(self.records()))
        self.release_rating.set()
        self.release_text.set()
        # the description and the late rating come from two threads: wait for BOTH records
        self.until(lambda: self.req_obj(rid).summary_source == "model"
                   and {"description_updated", "rated_late"} <= {e["event"] for e in self.records()[before[2]:]},
                   "description and late rating did not both arrive")
        r = self.req_obj(rid)
        self.assertEqual((r.status, r.risk), before[:2])
        self.assertEqual({e["event"] for e in self.records()[before[2]:]}, {"description_updated", "rated_late"})
        code, d = E.req(self.abase + f"/request/{rid}?fragment=1", headers={"X-authentik-username": "alice"})
        self.assertEqual(code, 200)
        self.assertIn("Retrieving the list of things", d)
        self.assertIn("rated later: LOW", d)
        _, lst = self.cards()
        self.assertNotIn("Retrieving the list", lst)                # nothing pending is touched

    def test_hard_ceiling_gives_one_permanent_fallback_with_its_reason(self):
        self.broker.summarizer = riskmodel.FloorAnalyzer(riskmodel.JevAnalyzer(
            "k", timeout=0.2, hard_timeout=0.2, describer=D.Describer("k", timeout=0.2, hard_timeout=0.8)))
        rid = self.make()
        self.assertTrue(self.req_obj(rid).summary_pending)
        self.until(lambda: not self.req_obj(rid).summary_pending, "ceiling did not pass", secs=6)
        r = self.req_obj(rid)
        self.assertEqual((r.summary_source, r.summary_reason), ("deterministic", "timeout"))
        self.assertTrue(r.summary.startswith("auto:"))
        ev = self.events("description_updated")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["summary_reason"], "timeout")
        _, page = self.cards()
        self.assertNotIn("model description pending", page)

    def test_rejected_late_reply_is_final_with_its_rule(self):
        self.text = "Searching for approved things"
        rid = self.make()
        self.release_text.set()
        self.until(lambda: not self.req_obj(rid).summary_pending, "no final state")
        r = self.req_obj(rid)
        self.assertEqual((r.summary_source, r.summary_reason, r.summary_rule),
                         ("deterministic", "rejected", "forbidden_word"))
        self.assertTrue(r.summary.startswith("auto:"))

    def test_poll_keeps_typed_state_and_agent_views_stay_blind(self):
        src = E.Broker.__module__
        import secret_broker.broker as B
        js = B._DASH_JS
        # the version-change path restores open sections and checkboxes, as for an arriving assessment
        for frag in ("asbOpenKeys(cards)", "asbChecked(cards)", "asbReopen(cards,wasopen)",
                     "asbRecheck(cards,wasck)", "refreshdetail();"):
            self.assertIn(frag, js)
        rid = self.make()
        self.release_text.set()
        self.until(lambda: self.req_obj(rid).summary_source == "model", "description did not arrive")
        code, body = self.api("GET", f"/v1/audit?request={rid}")
        for leak in ("description_updated", "rated_late", "late_level", "summary_reason", "pending"):
            self.assertNotIn(leak, body)
        code, body = self.api("GET", f"/v1/requests/{rid}?wait=0")
        for leak in ("summary", "late", "reason"):
            self.assertNotIn(leak, body.replace("rate", ""))


if __name__ == "__main__":
    unittest.main()
