"""`asb update NAME --add-host / --remove-host`: an agent asks to change which hosts a credential may be used
against. It is a metadata-only update: always a human decision (never auto-approved, whatever the credential's
`approval` says), rated high, applied only if the credential is as it was when asked, and for a Login it also
keeps the vault item's websites in step.
"""
import _fast  # noqa: F401
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
from secret_broker.backends.base import LOGIN, merge_uri_hosts  # noqa: E402
from secret_broker.backends.memory import MemoryBackend  # noqa: E402
_destguard.allow_loopback_for_tests()
CLI = os.environ.get("ASB_CLI") or os.path.join(os.path.dirname(__file__), "..", "client", "asb")


class Base(t.Harness):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["allowed_hosts"] = ["a.example.com", "b.example.com"]

    def ask(self, **body):
        code, out = self.api("POST", "/v1/requests", {"mode": "store", "names": ["svc"], "op": "update", **body})
        return code, json.loads(out)

    def settle(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)


class Change(Base):
    def test_approved_change_updates_the_catalog_and_the_vault(self):
        code, r = self.ask(add_hosts=["C.example.com"], remove_hosts=["b.example.com"])
        self.assertEqual(code, 202)
        done = self.settle(r["id"])
        self.assertEqual(done["status"], "approved")
        self.assertEqual(done["stored"]["hosts"], ["a.example.com", "c.example.com"])
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "c.example.com"])
        self.assertEqual(self.disk()["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "c.example.com"])
        ev = self.events("stored")[-1]
        self.assertEqual((ev["hosts_added"], ev["hosts_removed"]), (["c.example.com"], ["b.example.com"]))
        self.assertEqual(self.broker.backend._data["Svc"]["token"], t.SECRET)       # the value never moved

    def test_a_vault_that_survives_a_restart_keeps_the_change(self):
        _, r = self.ask(add_hosts=["c.example.com"])
        self.settle(r["id"])
        self.assertIn("c.example.com", self.disk()["secrets"]["svc"]["allowed_hosts"])

    def test_it_is_rated_high(self):
        _, r = self.ask(add_hosts=["c.example.com"])
        self.settle(r["id"])
        self.assertEqual(self.broker._by_id[r["id"]].risk["level"], "high")

    def test_refusals(self):
        bad = {
            "empty change": {},
            "remove an unknown host": {"remove_hosts": ["z.example.com"]},
            "add one already there": {"add_hosts": ["a.example.com"]},
            "add and remove one": {"add_hosts": ["c.example.com"], "remove_hosts": ["c.example.com"]},
            "remove them all": {"remove_hosts": ["a.example.com", "b.example.com"]},
            "a value with a host change": {"add_hosts": ["c.example.com"], "value": "x"},
            "a variable with a host change": {"add_hosts": ["c.example.com"], "var": "SVC_TOKEN"},
            "not a host": {"add_hosts": ["http://evil.example.com/x"]},
            "a link-local host": {"add_hosts": ["169.254.169.254"]},
            "too many": {"add_hosts": [f"h{i}.example.com" for i in range(11)]},
            "not a list": {"add_hosts": "c.example.com"},
        }
        for label, body in bad.items():
            code, out = self.ask(**body)
            self.assertEqual(code, 400, f"{label}: {out}")
        code, _ = self.api("POST", "/v1/requests", {"mode": "store", "names": ["nope"], "op": "update",
                                                    "add_hosts": ["c.example.com"]})
        self.assertEqual(code, 400)
        code, _ = self.api("POST", "/v1/requests", {"mode": "store", "names": ["svc"], "op": "create",
                                                    "value": "v", "allowed_hosts": ["c.example.com"],
                                                    "add_hosts": ["d.example.com"]})
        self.assertEqual(code, 400)
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "b.example.com"])

    def test_it_applies_only_if_the_credential_is_as_it_was_asked(self):
        self.decision = None
        _, r = self.ask(add_hosts=["c.example.com"])
        self.broker.cfg["secrets"]["svc"]["allowed_hosts"] = ["a.example.com"]     # changed under the request
        self.broker.decide_via("dashboard", r["id"], "approve", "alice")
        done = self.settle(r["id"])
        self.assertEqual(done["status"], "failed")
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com"])


class Cli(Base):
    """The real client/asb: no value is read from stdin, the human decides, the hosts change."""

    def run_cli(self, *args):
        env = {"PATH": os.environ["PATH"], "HOME": self.tmp, "SECRET_BROKER_URL": self.base,
               "SECRET_BROKER_KEY": t.KEY}
        return subprocess.run([CLI, *args], env=env, capture_output=True, text=True, timeout=60,
                              input="THE-STDIN-MUST-NOT-BE-READ")

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()

    def test_add_and_remove_hosts(self):
        r = self.run_cli("update", "svc", "--add-host", "c.example.com", "--remove-host", "b.example.com")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(),
                         "updated: svc may now be used against a.example.com, c.example.com")
        self.assertEqual(self.broker.backend._data["Svc"]["token"], t.SECRET)

    def test_usage_errors(self):
        for args in (("--add-host", ""), ("--add-host", "c.example.com", "--var", "SVC_TOKEN")):
            r = self.run_cli("update", "svc", *args)
            self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "b.example.com"])


class Denied(Base):
    decision = "deny"

    def test_denied_changes_nothing(self):
        _, r = self.ask(add_hosts=["c.example.com"])
        self.assertEqual(self.settle(r["id"])["status"], "denied")
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "b.example.com"])
        self.assertEqual(self.disk()["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "b.example.com"])


class NeverAuto(Base):
    """A credential that auto-approves everything, a store that auto-creates, an auto_approve rule for the
    secret: a host change still waits for a person."""
    decision = None

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["approval"] = "allow"
        cfg["secrets"]["svc"]["auto_modes"] = ["http", "env", "store"]
        cfg["risk"] = {"auto_approve_max": "high"}

    def test_waits_for_a_human(self):
        _, r = self.ask(add_hosts=["c.example.com"])
        self.assertEqual(self.broker._by_id[r["id"]].status, "pending")
        self.assertEqual(self.settle(r["id"])["status"], "pending")
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["a.example.com", "b.example.com"])

    def test_the_always_button_is_not_offered(self):
        _, r = self.ask(add_hosts=["c.example.com"])
        ok, _ = self.broker.always_allow_eligibility(self.broker._by_id[r["id"]])
        self.assertFalse(ok)


class Websites(unittest.TestCase):
    def test_merge_adds_and_removes_by_host_and_keeps_the_rest(self):
        self.assertEqual(merge_uri_hosts(["https://a.com/login", "b.com:8443", "https://keep.me"],
                                         ["c.com", "a.com"], ["b.com:8443"]),
                         ["https://a.com/login", "https://keep.me", "https://c.com"])
        self.assertEqual(merge_uri_hosts(None, ["x.com"]), ["https://x.com"])
        self.assertEqual(merge_uri_hosts(["https://A.com"], None, ["a.com"]), [])

    def test_edit_item_changes_a_logins_websites_only(self):
        b = MemoryBackend()
        b.create_login("site", "u", "p", uri=["https://a.com", "https://keep.me"])
        b.put("note", "notes", "n", create=True)
        b.edit_item("site", add_hosts=["c.com"], remove_hosts=["a.com"])
        b.edit_item("note", add_hosts=["c.com"])
        self.assertEqual(b._items["site"].uris, ["https://keep.me", "https://c.com"])
        self.assertEqual(b._items["note"].uris, [])
        self.assertEqual(b._items["site"].kind, LOGIN)


if __name__ == "__main__":
    unittest.main()
