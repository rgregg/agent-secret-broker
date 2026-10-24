"""The report-2 exploit chain, written against the public interfaces only (so it runs, and FAILS,
on a tree without the fixes):

  1. the agent creates a credential for 127.0.0.1 without a tap;
  2. the approval listener on the same host believes the identity header of any peer;
  3. one approved http call to the listener (with the approver's username header, which the agent can
     read in /v1/audit) returns the CSRF token, after which the agent can decide anything.

Every value is fake; the broker is in-process and the only server is the broker's own listener.
"""
import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from secret_broker import destguard as _dg  # noqa: E402
except ImportError:
    _dg = None
import test_e2e as t  # noqa: E402


class Strict(t.Harness):
    """The Harness with the production rules (no test-only loopback switch)."""
    decision = None
    peers_cfg = None

    def setUp(self):
        self._prior = _dg.test_loopback_allowed() if _dg else None
        if _dg:
            _dg.allow_loopback_for_tests(False)
        super().setUp()

    def tearDown(self):
        super().tearDown()
        if _dg:
            _dg.allow_loopback_for_tests(self._prior)

    def tweak(self, cfg):
        cfg.update(self.peers_cfg or {})
        cfg["secrets"]["svc"]["allowed_hosts"] = ["127.0.0.1"]


class AgentCannotMakeALoopbackCredential(Strict):
    def test_store_create_for_loopback_is_refused(self):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["selfapprove"], "op": "create", "value": "x",
            "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual(code, 400, body)
        self.assertNotIn("selfapprove", self.broker.cfg["secrets"])
        self.assertEqual(self.notifier.sent, [])


class ListenerDoesNotTrustItself(Strict):
    def test_loopback_peer_with_the_identity_header_is_refused_by_default(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(cm.exception.code, 403)


class ChainEndsAtTheDestination(Strict):
    decision = "approve"            # the human taps approve on the (innocent-looking) card
    peers_cfg = {"approval_trust_any_peer": True}   # (ignored by a tree without the setting: it trusts everyone)

    def test_call_to_the_approval_listener_never_returns_a_token(self):
        url = f"http://127.0.0.1:{self.a.server_address[1]}/"
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"X-authentik-username": "alice"}})
        if code != 202:
            return                  # refused at creation: the chain is already broken
        rid = json.loads(body)["id"]
        _, got = self.api("GET", f"/v1/requests/{rid}?wait=5")
        got = json.loads(got)
        self.assertNotEqual(got["status"], "approved", got)
        self.assertNotIn("name=csrf", json.dumps(got))
        self.assertNotIn("csrf", json.dumps(got).lower())


if __name__ == "__main__":
    unittest.main()
