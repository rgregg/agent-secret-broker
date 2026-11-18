"""Auto-approve rules kept in a credential's vault metadata (`auto_rules`) and managed from the Policies tab.

The properties: one validator for config rules and stored rules (so the form and the matcher cannot disagree);
a stored rule belongs to the one credential it is stored on; expired rules never match; creating or revoking a
rule needs the approver's authenticated session, a confirmation tick and a valid shape, and every refusal is a
fixed reason; nothing typed into the form reaches an agent response or the audit log.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import autorules, sshrules  # noqa: E402

FUTURE = sshrules.iso(time.time() + 86400 * 30)
PAST = sshrules.iso(time.time() - 3600)
BOX = "c-0a0b0c0d"


def http_rule(**kw):
    return {"id": "r0001", "name": "news", "mode": "http", "host": "api.example.com", "methods": ["GET", "POST"],
            "path_prefix": "/v1", "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None, **kw}


def env_rule(**kw):
    return {"id": "r0002", "name": "nightly", "mode": "env", "argv": ["python3", "report.py"],
            "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None, **kw}


class Parse(unittest.TestCase):
    def test_config_parse_is_unchanged(self):
        r = autorules.parse([{"name": "h", "mode": "http", "secret": "a", "host": "H.example.com"}])[0]
        self.assertEqual((r["host"], r["methods"], r["path_prefix"], r["source"]),
                         ("h.example.com", frozenset({"GET", "HEAD"}), "/", "config"))
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "sudo", "secret": "a"}])
        self.assertIn("auto_approve[0].mode 'sudo' always needs a human", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "http", "host": "h.example.com"}])
        self.assertIn("exactly one of secret", str(cm.exception))

    def test_stored_http_rule_round_trips(self):
        raw = [http_rule()]
        rules = autorules.parse_stored(raw, "news-key")
        self.assertEqual(rules[0]["source"], "ui")
        self.assertEqual(rules[0]["secrets"], frozenset({"news-key"}))
        self.assertEqual(rules[0]["clients"], frozenset())
        self.assertEqual(autorules.serialize_stored(rules), raw)

    def test_stored_client_list_round_trips_sorted(self):
        raw = [http_rule(clients=[BOX])]
        self.assertEqual(autorules.serialize_stored(autorules.parse_stored(raw, "k")), raw)

    def test_stored_env_rule_round_trips(self):
        raw = [env_rule(expires_at=FUTURE)]
        rules = autorules.parse_stored(raw, "k")
        self.assertEqual(rules[0]["argv"], ("python3", "report.py"))
        self.assertEqual(autorules.serialize_stored(rules), raw)

    def test_stored_rejects_secret_and_secrets(self):
        for key, val in (("secret", "other"), ("secrets", ["other"])):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(**{key: val})], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_rejects_ssh_sign_and_human_only_modes(self):
        for mode in ("ssh_sign", "sudo", "plan", "bogus"):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(mode=mode)], "k")
            self.assertIn("auto_rules[0].mode", str(cm.exception), mode)
        self.assertEqual(len(autorules.parse_stored([http_rule()], "k")), 1)     # positive control

    def test_stored_requires_id_by_and_at(self):
        for key in ("id", "by", "at"):
            raw = http_rule()
            del raw[key]
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([raw], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_bad_times_are_refused(self):
        for key, val in (("at", "yesterday"), ("expires_at", "2026-13-99")):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(**{key: val})], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_duplicate_name_and_id(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(), http_rule(id="r0009", name="NEWS")], "k")
        self.assertIn("used twice", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(), http_rule(name="other")], "k")
        self.assertIn("auto_rules[1].id", str(cm.exception))

    def test_stored_cap_is_50(self):
        many = [http_rule(id=f"r{i:04d}", name=f"n{i}") for i in range(50)]
        self.assertEqual(len(autorules.parse_stored(many, "k")), 50)
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored(many + [http_rule(id="r9999", name="n50")], "k")
        self.assertIn("more than 50", str(cm.exception))

    def test_unknown_key_names_the_field(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(account="ryan")], "k")
        self.assertIn("auto_rules[0].account", str(cm.exception))

    def test_stored_must_be_a_list(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored({"id": "x"}, "k")
        self.assertIn("auto_rules must be a list", str(cm.exception))
        self.assertEqual(autorules.parse_stored(None, "k"), [])


class Expiry(unittest.TestCase):
    SPEC = {"url": "https://api.example.com/v1/x", "method": "GET", "headers": {}}

    def find(self, rule, now=None):
        rules = autorules.parse_stored([rule], "k")
        return autorules.find(rules, "http", ["k"], self.SPEC, {"id": BOX}, now)

    def test_find_skips_expired_and_keeps_unexpired(self):
        self.assertIsNotNone(self.find(http_rule(expires_at=FUTURE)))
        self.assertIsNone(self.find(http_rule(expires_at=PAST)))

    def test_find_uses_the_given_clock(self):
        far = sshrules.to_epoch(FUTURE) + 1
        self.assertIsNone(self.find(http_rule(expires_at=FUTURE), now=far))

    def test_is_expired_ignores_config_rules_and_none(self):
        cfg = autorules.parse([{"name": "h", "mode": "http", "secret": "k", "host": "api.example.com"}])[0]
        self.assertFalse(autorules.is_expired(cfg, time.time() + 10 ** 9))
        stored = autorules.parse_stored([http_rule()], "k")[0]
        self.assertFalse(autorules.is_expired(stored, time.time() + 10 ** 9))


if __name__ == "__main__":
    unittest.main()
