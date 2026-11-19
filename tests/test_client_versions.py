"""Which version of `asb` a client runs, and when to recommend an upgrade (secret_broker/clientver.py).

The version arrives in the client's own `User-Agent`, so it is untrusted text: only a bounded, digits-and-dots
version is ever kept; anything else is "unknown", which is shown as such and never flagged as outdated.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import clientver  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


class Parse(unittest.TestCase):
    def test_reads_the_version_the_cli_sends(self):
        for ua, want in (("asb/1.1 (+https://github.com/rgregg/agent-secret-broker)", "1.1"),
                         ("asb/1 (+https://example.com)", "1"), ("asb/2.10.3", "2.10.3"), ("asb/1.2.3.4 x", "1.2.3.4")):
            self.assertEqual(clientver.parse_user_agent(ua), want, ua)

    def test_anything_else_is_unknown(self):
        for ua in (None, "", 5, b"asb/1", "curl/8.0", "Mozilla/5.0 asb/1.1", "asb/", "asb/x", "asb/1.", "asb/1..2",
                   "asb/1.2.3.4.5", "asb/99999", "asb/1.1<script>", "asb/1.1\x00", "ASB/1.1", " asb/1.1",
                   "asb/" + "9" * 5, "asb/1." + "9" * 5, "asb/1" + "." * 500):
            self.assertEqual(clientver.parse_user_agent(ua), "", repr(ua))

    def test_what_is_kept_is_digits_dots_and_short(self):
        for ua in ("asb/1.1 " + "A" * 5000, "asb/1.1 " + "<b>" * 100):
            v = clientver.parse_user_agent(ua)
            self.assertEqual(v, "1.1")
            self.assertRegex(v, r"^[0-9.]{1,24}$")


class Compare(unittest.TestCase):
    def test_ordering_is_numeric_not_textual(self):
        self.assertTrue(clientver.outdated("1.9", "1.10"))
        self.assertFalse(clientver.outdated("1.10", "1.9"))
        self.assertTrue(clientver.outdated("1", "1.1"))
        self.assertFalse(clientver.outdated("1.1", "1.1"))
        self.assertFalse(clientver.outdated("1.1.0", "1.1"))
        self.assertFalse(clientver.outdated("2", "1.1"))
        self.assertTrue(clientver.outdated("0.9.9", "1"))

    def test_unknown_is_never_outdated(self):
        for v in ("", None, "dev", "1.x", "abc", "1..2"):
            self.assertIsNone(clientver.outdated(v, "1.1"), v)

    def test_no_threshold_means_no_flag(self):
        self.assertIsNone(clientver.outdated("0.1", None))
        self.assertIsNone(clientver.outdated("0.1", ""))
        self.assertIsNone(clientver.outdated("0.1", "none"))

    def test_label(self):
        self.assertEqual(clientver.label(""), "unknown")
        self.assertEqual(clientver.label("1.1"), "1.1")


class ConfigKey(unittest.TestCase):
    def test_min_version_parses(self):
        from secret_broker import clients as clients_mod
        self.assertEqual(clients_mod.parse_config({})["min_version"], None)
        self.assertEqual(clients_mod.parse_config({"clients": {"min_version": "1.2"}})["min_version"], "1.2")
        self.assertEqual(clients_mod.parse_config({"clients": {"min_version": "none"}})["min_version"], "none")
        for bad in (5, "x", "1.", "", None, ["1"], "1.2.3.4.5", "v1.2"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                clients_mod.parse_config({"clients": {"min_version": bad}})
        # a client id key still works beside it
        d = clients_mod.parse_config({"clients": {"min_version": "1.2", "legacy": {"risk": {"auto_approve_max": "none"}}}})
        self.assertEqual(d["overrides"]["legacy"], {"auto_approve_max": "none"})

    def test_threshold_is_config_else_newest_known(self):
        from secret_broker import clients as clients_mod
        self.assertEqual(clientver.threshold(None), clients_mod.LATEST_CLIENT_VERSION)
        self.assertEqual(clientver.threshold("1.5"), "1.5")
        self.assertIsNone(clientver.threshold("none"))


class SendersAgree(unittest.TestCase):
    """The Python CLI, the Rust CLI and the broker's idea of the newest client carry the same number."""

    def test_both_clis_send_the_version_the_broker_knows(self):
        from secret_broker import clients as clients_mod
        py = open(os.path.join(ROOT, "client", "asb")).read()
        rs = open(os.path.join(ROOT, "crates", "asb-cli", "src", "broker.rs")).read()
        v = clients_mod.LATEST_CLIENT_VERSION
        self.assertRegex(v, r"^\d+(\.\d+)*$")
        self.assertIn(f'CLI_VERSION = "{v}"', py)
        self.assertRegex(py, r'USER_AGENT = f"asb/\{CLI_VERSION\} ')
        m = re.search(r'pub const USER_AGENT: &str = "(asb/[^"]*)";', rs)
        self.assertIsNotNone(m)                                 # premise: the Rust constant was found
        self.assertTrue(m.group(1).startswith(f"asb/{v} "), m.group(1))
        # and what each sends parses back to exactly that version
        self.assertEqual(clientver.parse_user_agent(m.group(1)), v)


if __name__ == "__main__":
    unittest.main()
