"""Credential values on the Credentials tab: show, replace, add and remove a credential's values."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_credential_editor as ed  # noqa: E402
from secret_broker import crededitor  # noqa: E402
from secret_broker.backends import BackendError, BackendNotFound  # noqa: E402
from secret_broker.broker import MAX_STORE_VALUE  # noqa: E402

NEW_VALUE = "S3CR3T-new-value-9f1"
EXTRA = "S3CR3T-extra-77a"
MULTI_ID, MULTI_SEC = "S3CR3T-id-31", "S3CR3T-sec-32"


def _ssh_pair():
    k = ed25519.Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return priv, pub


SSH_PRIV, SSH_PUB = _ssh_pair()


class Base(ed.Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["multi"] = {"vars": {"M_ID": {"item": "Multi", "field": "notes", "key": "ID"},
                                            "M_SEC": {"item": "Multi", "field": "notes", "key": "SECRET"}},
                                   "allowed_hosts": ["127.0.0.1"]}
        cfg["secrets"]["sshk"] = {"vars": {"SSHK_KEY": {"item": "Sshk", "field": "private_key"}},
                                  "ssh": True, "ssh_public_key": SSH_PUB}
        cfg["_vault"] = {"Multi": {"notes": json.dumps({"ID": MULTI_ID, "SECRET": MULTI_SEC})},
                         "Sshk": {"private_key": SSH_PRIV}}

    def vault(self, item, field):
        return self.broker.backend.get(item, field)

    def audit_text(self):
        with open(self.audit) as f:
            return f.read()

    def assert_no_values_in_audit(self):
        text = self.audit_text()
        self.assertIn("credential_value", text)                          # positive control: events were written
        for v in (t.SECRET, NEW_VALUE, EXTRA, MULTI_ID, MULTI_SEC):
            self.assertNotIn(v, text)

    def sha(self, name):
        return crededitor.digest(self.broker.credential_stored_meta(name))


class Reveal(Base):
    def test_reveals_a_plain_and_a_keyed_value(self):
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["value"], t.SECRET)
        r = self.broker.reveal_value("multi", "M_SEC", "alice")
        self.assertEqual((r["status"], r["value"]), ("ok", MULTI_SEC))
        ev = self.events("credential_value_revealed")
        self.assertEqual([(e["secret"], e["var"], e["user"]) for e in ev],
                         [("svc", "SVC_TOKEN", "alice"), ("multi", "M_SEC", "alice")])
        self.assert_no_values_in_audit()

    def test_refusals_are_closed_labels(self):
        cases = {("svc", "NOPE"): "unknown_var", ("sshk", "SSHK_KEY"): "ssh"}
        for (name, var), reason in cases.items():
            with self.subTest(reason):
                r = self.broker.reveal_value(name, var, "alice")
                self.assertEqual((r["status"], r["reason"]), ("refused", reason))
                self.assertNotIn("value", r)
        self.assertEqual([e["reason"] for e in self.events("credential_value_refused")], ["unknown_var", "ssh"])
        self.assertEqual(self.events("credential_value_revealed"), [])

    def test_a_key_on_a_field_that_is_not_structured_is_invalid(self):
        self.broker.backend.put("Multi", "notes", "plain text, not structured")
        r = self.broker.reveal_value("multi", "M_ID", "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "invalid"))
        self.assertEqual(r["message"], self.broker._VALUE_TEXT["invalid"])

    def test_a_vault_failure_is_a_fixed_label(self):
        with mock.patch.object(self.broker.backend, "get", side_effect=BackendError("boom " + t.SECRET)):
            r = self.broker.reveal_value("svc", "SVC_TOKEN", "alice")
        self.assertEqual((r["status"], r["reason"], r["message"]), ("failed", "vault_read", "Could not read the vault"))
        self.assertNotIn(t.SECRET, self.audit_text())

    def test_rate_limited_per_user(self):
        for _ in range(self.broker.VALUE_RATE[0]):
            self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["status"], "ok")
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["reason"], "rate_limited")
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "bob")["status"], "ok")   # per user

    def test_internal_key_is_refused(self):
        with mock.patch.object(self.broker, "is_internal_secret", side_effect=lambda n: n == "svc"):
            r = self.broker.reveal_value("svc", "SVC_TOKEN", "alice")
        self.assertEqual(r["reason"], "internal")


class Replace(Base):
    def test_replaces_and_keeps_the_previous_value(self):
        r = self.broker.replace_value("svc", "SVC_TOKEN", NEW_VALUE, "alice")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.vault("Svc", "token"), NEW_VALUE)
        self.assertEqual(self.vault("Svc", "previous_value"), t.SECRET)
        ev = self.events("credential_value_changed")
        self.assertEqual([(e["secret"], e["var"], e["value_bytes"]) for e in ev],
                         [("svc", "SVC_TOKEN", len(NEW_VALUE))])
        self.assert_no_values_in_audit()

    def test_a_keyed_value_changes_only_its_key(self):
        self.assertEqual(self.broker.replace_value("multi", "M_ID", NEW_VALUE, "alice")["status"], "ok")
        self.assertEqual(json.loads(self.vault("Multi", "notes")), {"ID": NEW_VALUE, "SECRET": MULTI_SEC})

    def test_refusals_write_nothing(self):
        cases = [("svc", "SVC_TOKEN", "", "empty"), ("svc", "SVC_TOKEN", "a\x00b", "bad_value"),
                 ("svc", "SVC_TOKEN", "a\x1bb", "bad_value"),
                 ("svc", "SVC_TOKEN", "x" * (MAX_STORE_VALUE + 1), "too_large"),
                 ("svc", "NOPE", NEW_VALUE, "unknown_var"), ("sshk", "SSHK_KEY", NEW_VALUE, "ssh")]
        for name, var, value, reason in cases:
            with self.subTest(reason):
                r = self.broker.replace_value(name, var, value, "alice")
                self.assertEqual((r["status"], r["reason"]), ("refused", reason))
        self.assertEqual(self.vault("Svc", "token"), t.SECRET)
        self.assertEqual(self.vault("Sshk", "private_key"), SSH_PRIV)
        self.assertEqual(self.events("credential_value_changed"), [])

    def test_a_vault_failure_keeps_no_text(self):
        with mock.patch.object(self.broker.backend, "put", side_effect=BackendError("write failed " + NEW_VALUE)):
            r = self.broker.replace_value("svc", "SVC_TOKEN", NEW_VALUE, "alice")
        self.assertEqual((r["status"], r["reason"]), ("failed", "vault_write"))
        self.assertIn("credential_value_refused", self.audit_text())
        self.assertNotIn(NEW_VALUE, self.audit_text())


class Add(Base):
    def test_adds_the_field_and_the_variable_in_one_write(self):
        r = self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice", confirm=True)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        self.assertEqual(self.stored()["vars"]["SVC_EXTRA"], {"field": "SVC_EXTRA"})
        self.assertEqual(self.stored()["custom"], {"keep": "me"})        # the rest of the metadata kept
        self.assertIn("SVC_EXTRA", self.broker.cfg["secrets"]["svc"]["vars"])   # live
        self.assertEqual([(e["var"], e["value_bytes"]) for e in self.events("credential_value_added")],
                         [("SVC_EXTRA", len(EXTRA))])
        self.assertEqual(self.broker.reveal_value("svc", "SVC_EXTRA", "alice")["value"], EXTRA)
        self.assert_no_values_in_audit()

    def test_needs_the_tick(self):
        before = self.stored()
        r = self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "needs_confirmation"))
        self.assertEqual(self.stored(), before)
        with self.assertRaises(BackendNotFound):
            self.vault("Svc", "SVC_EXTRA")

    def test_refusals(self):
        sha = self.sha("svc")
        self.broker.backend.put("Svc", "TAKEN", "S3CR3T-taken", add_field=True)
        cases = [("SVC_TOKEN", EXTRA, sha, "exists"), ("TAKEN", EXTRA, sha, "field_exists"),
                 ("bad name", EXTRA, sha, "invalid_name"), ("LD_PRELOAD", EXTRA, sha, "invalid_name"),
                 ("SVC_EXTRA", "", sha, "empty"), ("SVC_EXTRA", EXTRA, "0" * 64, "conflict")]
        for var, value, s, reason in cases:
            with self.subTest(reason=reason, var=var):
                r = self.broker.add_value("svc", var, value, s, "alice", confirm=True)
                self.assertEqual(r["reason"], reason)
                self.assertNotIn(EXTRA, r["message"])
        self.assertEqual(set(self.stored()["vars"]), {"SVC_TOKEN"})
        self.assertEqual(self.events("credential_value_added"), [])
        r = self.broker.add_value("sshk", "X", EXTRA, self.sha("sshk"), "alice", confirm=True)
        self.assertEqual(r["reason"], "ssh")

    def test_adopted_item_is_refused(self):
        self.broker.cfg["secrets"]["svc"]["auto"] = True
        r = self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice", confirm=True)
        self.assertEqual(r["reason"], "adopted")
        # an adopted item's values can still be shown and replaced
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["value"], t.SECRET)


class Remove(Base):
    def test_removes_the_variable_and_keeps_the_field(self):
        r = self.broker.remove_value("multi", "M_SEC", self.sha("multi"), "alice")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(set(self.broker.credential_stored_meta("multi")["vars"]), {"M_ID"})
        self.assertNotIn("M_SEC", self.broker.cfg["secrets"]["multi"]["vars"])
        self.assertEqual(json.loads(self.vault("Multi", "notes"))["SECRET"], MULTI_SEC)   # nothing destroyed
        self.assertEqual([e["var"] for e in self.events("credential_value_removed")], ["M_SEC"])

    def test_refusals(self):
        self.assertEqual(self.broker.remove_value("svc", "SVC_TOKEN", self.sha("svc"), "alice")["reason"], "last")
        self.assertEqual(self.broker.remove_value("multi", "NOPE", self.sha("multi"), "alice")["reason"],
                         "unknown_var")
        self.assertEqual(self.broker.remove_value("multi", "M_ID", "0" * 64, "alice")["reason"], "conflict")
        self.assertEqual(self.broker.remove_value("sshk", "SSHK_KEY", self.sha("sshk"), "alice")["reason"], "ssh")
        self.assertEqual(set(self.broker.credential_stored_meta("multi")["vars"]), {"M_ID", "M_SEC"})
        self.assertEqual(self.events("credential_value_removed"), [])


class Hidden(unittest.TestCase):
    def test_value_events_are_hidden_from_the_agent_audit_api(self):
        from secret_broker import audit_api
        for ev in ("credential_value_revealed", "credential_value_changed", "credential_value_added",
                   "credential_value_removed", "credential_value_refused"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertIsNone(audit_api.redact({"seq": 1, "ts": 1.0, "event": ev, "secret": "svc", "var": "V"}))


if __name__ == "__main__":
    unittest.main()
