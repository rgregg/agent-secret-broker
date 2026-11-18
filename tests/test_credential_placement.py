"""Which standing approvals and config rules belong on a credential's page, and which stay on the Policies tab.

An entry is per-credential only when its set of secret names is exactly one credential that exists in the catalog.
Everything else (two or more names, or a name that is gone) stays shared, so nothing is ever shown in neither place.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_grants as tg  # noqa: E402
from secret_broker import autorules  # noqa: E402

BOX = "c-0a0b0c0d"


class Placement(tg.Base):
    def grant(self, names, client="*"):
        return self.broker.grants.add(names, 5, "any", "alice", "dashboard", "r", client=client)["id"]

    def ids(self, rows):
        return sorted(r["id"] for r in rows)

    def test_single_secret_timed_grant_is_per_credential(self):
        gid = self.grant(["svc"])
        per, shared = self.broker.standing_by_credential()
        self.assertEqual(self.ids(per["svc"]), [gid])
        self.assertEqual(shared, [])
        self.assertEqual(per["svc"][0]["names"], ["svc"])

    def test_two_secret_timed_grant_is_shared_and_not_per_credential(self):
        gid = self.grant(["svc", "other"])
        per, shared = self.broker.standing_by_credential()
        self.assertEqual(self.ids(shared), [gid])
        self.assertEqual(per, {})
        self.assertFalse(shared[0]["orphan"])
        solo = self.grant(["svc"])                                                    # control: one name is per-credential
        per, shared = self.broker.standing_by_credential()
        self.assertEqual(self.ids(per["svc"]), [solo])
        self.assertEqual(self.ids(shared), [gid])

    def test_always_approval_is_per_credential(self):
        self.broker.cfg["secrets"]["svc"]["standing"] = [{
            "id": "s0001", "mode": "http", "scope": "read", "created_by": "alice",
            "created_at": "2026-11-18T00:00:00Z", "client": "*"}]
        per, shared = self.broker.standing_by_credential()
        self.assertEqual([(r["kind"], r["id"]) for r in per["svc"]], [("always", "s0001")])
        self.assertEqual(shared, [])

    def test_legacy_allow_is_per_credential(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        per, shared = self.broker.standing_by_credential()
        self.assertEqual([r["kind"] for r in per["svc"]], ["legacy"])
        self.assertEqual(per["svc"][0]["names"], ["svc"])
        self.assertEqual(shared, [])

    def test_duplicate_names_count_as_one(self):
        row = {"kind": "timed", "id": "d0001", "secrets": ["svc", "svc"], "names": ["svc", "svc"]}
        self.broker.standing_rows = lambda: [row]
        per, shared = self.broker.standing_by_credential()
        self.assertEqual(self.ids(per["svc"]), ["d0001"])
        self.assertEqual(shared, [])

    def test_a_grant_for_a_deleted_credential_is_a_shared_orphan(self):
        gid = self.grant(["svc"])
        other = self.grant(["other"])
        del self.broker.cfg["secrets"]["svc"]
        per, shared = self.broker.standing_by_credential()
        self.assertEqual(self.ids(shared), [gid])
        self.assertTrue(shared[0]["orphan"])
        self.assertEqual(self.ids(per["other"]), [other])                             # control: the living one stays
        pair = self.grant(["svc", "other"])                                           # a pair with one name gone is an orphan too
        _, shared = self.broker.standing_by_credential()
        self.assertTrue(next(r for r in shared if r["id"] == pair)["orphan"])

    def test_the_internal_key_keeps_its_page_and_names_have_no_tag(self):
        self.broker._internal_secrets = lambda: (frozenset({"other"}), frozenset())
        self.broker.cfg["secrets"]["other"]["approval"] = "allow"
        per, _ = self.broker.standing_by_credential()
        row = per["other"][0]
        self.assertEqual(row["names"], ["other"])
        self.assertIn("internal", row["secrets"][0])                                  # the display name keeps its tag

    def test_client_scope_does_not_change_placement(self):
        gid = self.grant(["svc"], client=BOX)
        per, _ = self.broker.standing_by_credential()
        self.assertEqual(self.ids(per["svc"]), [gid])
        self.assertEqual(per["svc"][0]["client"], BOX)

    def test_config_rule_placement(self):
        self.broker.auto_rules = autorules.parse([
            {"name": "one", "mode": "env", "secret": "svc", "argv": ["echo"]},
            {"name": "pair", "mode": "env", "secrets": ["svc", "other"], "argv": ["echo"]},
            {"name": "gone", "mode": "env", "secret": "missing", "argv": ["echo"]}])
        self.assertEqual([r["name"] for r in self.broker.config_rules_for("svc")], ["one", "pair"])
        self.assertEqual([r["name"] for r in self.broker.config_rules_for("other")], ["pair"])
        self.assertEqual(self.broker.config_rules_for("deploy"), [])
        shared = self.broker.shared_config_rules()
        self.assertEqual([(r["name"], r["orphan"]) for r in shared], [("pair", False), ("gone", True)])

    def test_nothing_is_lost(self):
        solo = self.grant(["svc"])
        self.grant(["svc"], client=BOX)                                               # a different client: a distinct grant
        self.grant(["svc", "other"])
        self.grant(["other"], client=BOX)
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.broker.cfg["secrets"]["other"]["standing"] = [{
            "id": "s0002", "mode": "env", "scope": "any", "created_by": "alice",
            "created_at": "2026-11-18T00:00:00Z", "client": "*"}]
        del self.broker.cfg["secrets"]["deploy"]                                      # unrelated deletion changes nothing
        per, shared = self.broker.standing_by_credential()
        every = self.broker.standing_rows()
        self.assertEqual(len(every), 6)                                               # the premise: four timed, one always, one legacy
        self.assertEqual(sum(len(v) for v in per.values()) + len(shared), len(every))
        self.assertEqual(len(shared), 1)
        self.assertIn(solo, self.ids(per["svc"]))
