"""The broker half of the client update notice: one validated version string in two answers, nothing else.

See docs/superpowers/specs/2026-11-19-client-update-notice-design.md. The client half is in
test_client_update_notice_cli.py.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
from secret_broker import clients as clients_mod, clientver  # noqa: E402


class Expected(unittest.TestCase):
    """clientver.expected: the one place that decides what the broker tells clients."""

    def test_default_is_the_newest_known(self):
        self.assertEqual(clientver.expected(None, True), clientver.LATEST_CLIENT_VERSION)

    def test_configured_minimum_wins(self):
        self.assertEqual(clientver.expected("1.7", True), "1.7")

    def test_none_and_the_switch_send_nothing(self):
        self.assertIsNone(clientver.expected("none", True))
        self.assertIsNone(clientver.expected(None, False))
        self.assertIsNone(clientver.expected("1.7", False))
        self.assertEqual(clientver.expected("1.7", True), "1.7")            # positive control for the three above

    def test_an_invalid_value_is_never_sent(self):
        self.assertEqual(clientver.expected("1.2.3.4", True), "1.2.3.4")    # control: the longest valid one passes
        for bad in ("", "x", "1.", "1.2.3.4.5", "1.1\x1b[31m", "https://evil.example/x", "9" * 40):
            self.assertIsNone(clientver.expected(bad, True), repr(bad))


class Config(unittest.TestCase):
    def test_update_notice_key(self):
        self.assertIs(clients_mod.parse_config({})["update_notice"], True)
        self.assertIs(clients_mod.parse_config({"clients": {"update_notice": False}})["update_notice"], False)
        self.assertIs(clients_mod.parse_config({"clients": {"update_notice": True}})["update_notice"], True)
        for bad in ("no", 0, 1, None, []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                clients_mod.parse_config({"clients": {"update_notice": bad}})
        # a client id key still works beside it
        d = clients_mod.parse_config({"clients": {"update_notice": False,
                                                  "legacy": {"risk": {"auto_approve_max": "none"}}}})
        self.assertEqual(d["overrides"]["legacy"], {"auto_approve_max": "none"})


class OnTheWire(tc.CBase):
    legacy = "allow"

    def status(self, secret=None):
        code, text = self.as_client(secret or tc.KEY, "GET", "/v1/status")
        self.assertEqual(code, 200, text)
        return json.loads(text)

    def post_request(self, secret=None):
        code, text = self.as_client(secret or tc.KEY, "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": "http://127.0.0.1:9/x", "source": "t@h",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, text)
        return json.loads(text)

    def test_status_and_a_new_request_carry_the_version(self):
        want = clientver.LATEST_CLIENT_VERSION
        self.assertEqual(self.status()["latest_client_version"], want)
        self.assertEqual(self.post_request()["latest_client_version"], want)

    def test_the_configured_minimum_is_what_is_sent(self):
        self.broker.clients.cfg["min_version"] = "1.9"
        self.assertEqual(self.status()["latest_client_version"], "1.9")
        self.assertEqual(self.post_request()["latest_client_version"], "1.9")

    def test_none_and_the_switch_leave_the_field_out(self):
        self.assertIn("latest_client_version", self.status())               # control: present before the change
        self.broker.clients.cfg["min_version"] = "none"
        self.assertNotIn("latest_client_version", self.status())
        self.assertNotIn("latest_client_version", self.post_request())
        self.broker.clients.cfg["min_version"] = None
        self.broker.clients.cfg["update_notice"] = False
        self.assertNotIn("latest_client_version", self.status())
        self.assertNotIn("latest_client_version", self.post_request())

    def test_it_is_a_bare_version_and_the_same_for_every_client(self):
        c = self.new_client("alpha")
        a, b = self.status(), self.status(c["secret"])
        self.assertEqual(a["latest_client_version"], b["latest_client_version"])
        self.assertRegex(a["latest_client_version"], r"^[0-9]{1,4}(\.[0-9]{1,4}){0,3}$")
        # the answer to a request carries the id, status, expiry and the version, and no new key besides
        self.assertEqual(sorted(self.post_request()), ["error", "expires_in", "id", "latest_client_version", "status"])

    def test_an_unauthenticated_caller_gets_no_version(self):
        code, text, _ = self.raw("GET", "/v1/status")
        self.assertEqual(code, 401)
        self.assertNotIn("latest_client_version", text)


if __name__ == "__main__":
    unittest.main()
