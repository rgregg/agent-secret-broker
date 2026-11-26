"""Aliases: a credential's former names. An alias resolves to the canonical name before any check, is flagged
wherever it is used, and is never part of what an agent can discover."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_credential_editor as ed  # noqa: E402
import plan_base as pb  # noqa: E402
from secret_broker import aliases as aliases_mod  # noqa: E402
from secret_broker import crededitor  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

OLD = "old-svc"


class Parse(unittest.TestCase):
    def meta(self, **kw):
        return {"name": "svc", "vars": {"SVC_TOKEN": {"field": "token"}}, "allowed_hosts": ["127.0.0.1"], **kw}

    def entry(self, **kw):
        return Broker._entry("Svc", self.meta(**kw))[1]

    def test_a_valid_list_is_kept_as_a_tuple(self):
        e = self.entry(aliases=["old-svc", "older_svc"])
        self.assertEqual(e["aliases"], ("old-svc", "older_svc"))

    def test_no_aliases_leaves_no_key(self):
        self.assertNotIn("aliases", self.entry())
        self.assertNotIn("aliases", self.entry(aliases=[]))

    def test_bad_aliases_are_refused_with_a_fixed_text(self):
        cases = {"not a list": "old-svc", "bad characters": ["Old Svc"], "upper case": ["OLD"],
                 "too long": ["a" * 42], "the credential's own name": ["svc"], "reserved": ["new"],
                 "repeated": ["a1", "a1"], "not a string": [3], "too many": [f"a{i}" for i in range(11)]}
        for why, bad in cases.items():
            with self.subTest(why), self.assertRaises(ValueError) as cm:
                self.entry(aliases=bad)
            self.assertTrue(str(cm.exception).startswith("aliases "), str(cm.exception))
            self.assertNotIn("S3CR3T", str(cm.exception))

    def test_the_pure_map_drops_a_name_that_is_also_a_credential_and_an_alias_two_claim(self):
        entries = {"a": {"aliases": ("x", "b", "y")}, "b": {}, "c": {"aliases": ("y", "z")}}
        amap, dropped = aliases_mod.build_map(entries)
        self.assertEqual(amap, {"x": "a", "z": "c"})
        self.assertEqual(sorted(dropped), ["b", "y"])

    def test_resolve_leaves_canonical_and_foreign_values_alone(self):
        amap = {"x": "a"}
        self.assertEqual(aliases_mod.resolve(amap, ["x", "a", "zz"]), (["a", "a", "zz"], {"x": "a"}))
        self.assertEqual(aliases_mod.resolve(amap, "x"), ("x", {}))        # not a list: untouched
        self.assertEqual(aliases_mod.resolve(amap, [3, None]), ([3, None], {}))


class Base(ed.Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["aliases"] = [OLD]
        cfg["_vault"] = {"Other": {"token": "S3CR3T-other"}}
        cfg["secrets"]["other"] = {"vars": {"OTHER_TOKEN": {"item": "Other", "field": "token"}},
                                   "allowed_hosts": ["127.0.0.1"]}

    def env_request(self, names):
        return self.api("POST", "/v1/requests", {"mode": "env", "names": list(names), "argv": ["echo", "hi"]})


class Resolution(Base):
    decision = None             # leave requests pending: the card is what we look at

    def test_the_catalog_maps_the_alias(self):
        self.assertEqual(self.broker.cfg["aliases"], {OLD: "svc"})
        self.assertEqual(self.broker.resolve_names([OLD, "other"]), (["svc", "other"], {OLD: "svc"}))

    def test_a_request_by_alias_is_a_request_for_the_canonical_name(self):
        code, body = self.env_request([OLD])
        self.assertEqual(code, 202, body)
        req = self.broker._by_id[json.loads(body)["id"]]
        self.assertEqual(req.names, ["svc"])
        self.assertEqual(req.aliases_used, {OLD: "svc"})
        ev = self.events("requested")[-1]
        self.assertEqual((ev["names"], ev["aliases_used"]), (["svc"], {OLD: "svc"}))
        used = self.events("alias_used")
        self.assertEqual([(e["alias"], e["secret"], e["mode"]) for e in used], [(OLD, "svc", "env")])

    def test_a_request_by_the_real_name_is_not_flagged(self):
        code, body = self.env_request(["svc"])
        self.assertEqual(code, 202, body)
        self.assertEqual(self.broker._by_id[json.loads(body)["id"]].aliases_used, {})
        self.assertNotIn("aliases_used", self.events("requested")[-1])
        self.assertEqual(self.events("alias_used"), [])

    def test_the_card_and_the_approval_page_say_the_old_name_was_used(self):
        _, body = self.env_request([OLD])
        req = self.broker._by_id[json.loads(body)["id"]]
        for what, path in (("dashboard", "/"), ("approval page", "/a/" + req.nonce)):
            with self.subTest(what):
                code, page = self.get(path)
                self.assertEqual(code, 200)
                self.assertIn("Requested as", page)
                self.assertIn(f"<code>{OLD}</code>", page)
        code, page = self.get("/")
        self.assertIn("svc", page)                                           # positive control: the card is there
        _, body = self.env_request(["svc"])
        self.assertEqual(self.get("/a/" + self.broker._by_id[json.loads(body)["id"]].nonce)[1].count("Requested as"), 0)
        self.assertEqual(aliases_mod.note_html({}), "")

    def test_the_history_details_say_which_name_the_agent_used(self):
        self.decision = "approve"
        _, body = self.env_request([OLD])
        rid = json.loads(body)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        code, frag = self.get(f"/request/{rid}?fragment=1")
        self.assertEqual(code, 200)
        self.assertIn("Requested as", frag)
        self.assertIn(OLD, frag)

    def test_a_denial_cooldown_on_the_name_covers_its_alias(self):
        self.broker._denied_at["svc"] = __import__("time").time()
        code, body = self.env_request([OLD])
        self.assertEqual(code, 403, body)
        self.assertIn("svc was denied recently", body)

    def test_an_unknown_name_stays_unknown_and_removed_aliases_stop_working(self):
        self.assertEqual(self.env_request(["nope"])[0], 400)
        res = self.broker.remove_alias("svc", OLD, crededitor.digest(self.broker.credential_stored_meta("svc")),
                                       "alice")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(self.env_request([OLD])[0], 400)
        self.assertNotIn(OLD, self.broker.cfg["aliases"])

    def test_the_internal_key_cannot_be_reached_through_an_alias(self):
        self.broker.summarizer = types.SimpleNamespace(key_providers=[types.SimpleNamespace(name="svc")])
        self.assertTrue(self.broker.is_internal_secret("svc"))             # premise
        code, body = self.env_request([OLD])
        self.assertEqual(code, 400)
        self.assertIn("unknown secret name", body)
        self.assertEqual(self.events("requested"), [])


class Discovery(Base):
    def test_an_alias_is_in_no_agent_facing_output(self):
        code, secrets_body = self.api("GET", "/v1/secrets")
        _, status_body = self.api("GET", "/v1/status")
        _, host_body = self.api("GET", "/v1/secrets?host=127.0.0.1")
        for what, text in (("secrets", secrets_body), ("status", status_body), ("by host", host_body)):
            with self.subTest(what):
                self.assertNotIn(OLD, text)
        self.assertEqual(code, 200)
        self.assertIn('"svc"', secrets_body)                                 # positive control: the credential is listed
        self.assertNotIn(OLD, json.dumps(self.broker.available()))
        found = [e for e in self.events("discovery")]
        self.assertTrue(found)
        self.assertNotIn(OLD, json.dumps(found))

    def test_asking_for_the_alias_as_a_host_or_secret_finds_nothing_new(self):
        self.assertEqual([f["name"] for f in self.broker.available("127.0.0.1")], ["other", "svc"])


class Catalog(Base):
    def test_a_name_that_is_also_a_credential_wins_over_the_alias(self):
        meta = self.broker.credential_stored_meta("svc")
        meta["aliases"] = ["other", OLD]
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)
        self.assertEqual(self.broker.cfg["aliases"], {OLD: "svc"})
        self.assertEqual(self.broker.resolve_names(["other"])[0], ["other"])

    def test_an_alias_two_credentials_claim_belongs_to_neither(self):
        meta = self.broker.credential_stored_meta("other")
        meta["aliases"] = [OLD]
        self.broker.backend.set_meta("Other", meta)
        self.broker._refresh_if(0)
        self.assertEqual(self.broker.cfg["aliases"], {})
        self.assertEqual(self.broker.resolve_names([OLD]), ([OLD], {}))

    def test_creating_a_credential_named_like_an_alias_is_refused(self):
        r = self.broker.create_credential(OLD, "127.0.0.1", "S3CR3T-x", "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "exists"))
        self.assertNotIn(OLD, self.broker.cfg["secrets"])
        code, body = self.api("POST", "/v1/requests", {"mode": "store", "names": [OLD], "op": "create",
                                                       "value": "S3CR3T-x", "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual(code, 400, body)
        self.assertIn("already exists", body)

    def test_the_editor_save_refuses_an_alias_another_credential_owns(self):
        meta = self.broker.credential_stored_meta("other")
        sha = crededitor.digest(meta)
        for taken in ("svc", OLD):
            with self.subTest(taken):
                r = self.broker.set_credential_meta("other", {**meta, "aliases": [taken]}, sha, "alice")
                self.assertEqual((r["status"], r["reason"]), ("refused", "alias_taken"))
        self.assertNotIn("aliases", self.broker.credential_stored_meta("other"))
        ok = self.broker.set_credential_meta("other", {**meta, "aliases": ["other-old"]}, sha, "alice")
        self.assertEqual(ok["status"], "saved")                              # premise: a free alias is fine


class Rename(Base):
    def rename(self, new, keep=False, name="svc"):
        sha = crededitor.digest(self.broker.credential_stored_meta(name))
        return self.broker.rename_credential(name, new, sha, "alice", keep_alias=keep)

    def test_keeping_the_old_name_adds_it_as_an_alias_in_the_same_write(self):
        r = self.rename("svc-new", keep=True)
        self.assertEqual(r["status"], "renamed")
        meta = self.broker.credential_stored_meta("svc-new")
        self.assertEqual((meta["name"], meta["aliases"]), ("svc-new", [OLD, "svc"]))
        self.assertEqual(self.broker.cfg["aliases"], {OLD: "svc-new", "svc": "svc-new"})
        self.assertEqual(self.broker.resolve_names(["svc"])[0], ["svc-new"])
        ev = self.events("credential_renamed")[-1]
        self.assertEqual((ev["secret"], ev["new_secret"], ev["alias_kept"]), ("svc", "svc-new", True))

    def test_without_the_box_the_old_name_is_gone_but_existing_aliases_stay(self):
        r = self.rename("svc-new")
        self.assertEqual(r["status"], "renamed")
        self.assertEqual(self.broker.credential_stored_meta("svc-new")["aliases"], [OLD])
        self.assertNotIn("svc", self.broker.cfg["aliases"])
        self.assertEqual(self.broker.resolve_names(["svc"])[0], ["svc"])     # and it is simply unknown now

    def test_a_new_name_that_is_anyones_alias_is_refused(self):
        r = self.rename(OLD, name="other")
        self.assertEqual((r["status"], r["reason"]), ("refused", "exists"))
        self.assertNotIn("aliases", self.broker.credential_stored_meta("other"))

    def test_renaming_back_to_one_of_its_own_aliases_takes_it_over(self):
        self.assertEqual(self.rename("svc-new", keep=True)["status"], "renamed")
        r = self.rename("svc", keep=True, name="svc-new")
        self.assertEqual(r["status"], "renamed")
        meta = self.broker.credential_stored_meta("svc")
        self.assertEqual((meta["name"], sorted(meta["aliases"])), ("svc", [OLD, "svc-new"]))

    def test_the_alias_limit_is_a_refusal_not_a_truncation(self):
        meta = self.broker.credential_stored_meta("svc")
        meta["aliases"] = [f"a{i}" for i in range(aliases_mod.MAX_ALIASES)]
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)
        r = self.rename("svc-new", keep=True)
        self.assertEqual((r["status"], r["reason"]), ("refused", "invalid"))
        self.assertEqual(self.broker.credential_stored_meta("svc")["name"], "svc")

    def test_refusals_still_apply_with_the_box_ticked(self):
        self.broker.plans_cfg["deny_secrets"] = ["svc"]
        r = self.rename("svc-new", keep=True)
        self.assertEqual((r["status"], r["reason"]), ("refused", "denied_by_name"))
        self.assertEqual(self.broker.credential_stored_meta("svc")["name"], "svc")


class WithASummaryKey(Base):
    """A summary key provider is configured (the normal production setup): _internal_secrets takes the
    catalog lock, so rename and delete must not reach it while holding that lock (they once deadlocked
    there, hanging every later request that needed the catalog)."""

    def setUp(self):
        super().setUp()
        self.broker.summarizer = types.SimpleNamespace(key_providers=[types.SimpleNamespace(name="other")])
        self.assertTrue(self.broker.is_internal_secret("other"))          # premise: real lookup, not a mock

    def run_bounded(self, fn):
        import threading
        out = {}
        th = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
        th.start()
        th.join(10)                                                      # returns at once unless it deadlocks
        self.assertFalse(th.is_alive(), "the credential action deadlocked on the catalog lock")
        self.assertFalse(self.broker._cfg_lock.locked())
        return out["r"]

    def test_rename_with_and_without_alias_finishes(self):
        for keep, new in ((True, "svc-new"), (False, "svc-newer")):
            name = "svc" if keep else "svc-new"
            sha = crededitor.digest(self.broker.credential_stored_meta(name))
            r = self.run_bounded(lambda: self.broker.rename_credential(name, new, sha, "alice", keep_alias=keep))
            self.assertEqual(r["status"], "renamed", r)

    def test_rename_of_the_internal_key_is_still_refused(self):
        sha = crededitor.digest(self.broker.credential_stored_meta("other"))
        r = self.run_bounded(lambda: self.broker.rename_credential("other", "other2", sha, "alice"))
        self.assertEqual((r["status"], r["reason"]), ("refused", "internal"))

    def test_delete_finishes(self):
        r = self.run_bounded(lambda: self.broker.delete_credential("svc", "svc", "alice"))
        self.assertEqual(r["status"], "deleted", r)


class RemoveAlias(Base):
    def test_removal_is_audited_by_name_and_other_aliases_stay(self):
        meta = self.broker.credential_stored_meta("svc")
        meta["aliases"] = [OLD, "older-svc"]
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)
        r = self.broker.remove_alias("svc", OLD, crededitor.digest(meta), "alice")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.broker.credential_stored_meta("svc")["aliases"], ["older-svc"])
        self.assertEqual([(e["secret"], e["alias"], e["user"]) for e in self.events("credential_alias_removed")],
                         [("svc", OLD, "alice")])

    def test_removing_the_last_alias_drops_the_key(self):
        sha = crededitor.digest(self.broker.credential_stored_meta("svc"))
        self.assertEqual(self.broker.remove_alias("svc", OLD, sha, "alice")["status"], "ok")
        self.assertNotIn("aliases", self.broker.credential_stored_meta("svc"))

    def test_refusals_change_nothing(self):
        meta = self.broker.credential_stored_meta("svc")
        sha = crededitor.digest(meta)
        self.assertEqual(self.broker.remove_alias("svc", "nope", sha, "alice")["reason"], "unknown_alias")
        self.assertEqual(self.broker.remove_alias("svc", OLD, "0" * 64, "alice")["reason"], "conflict")
        self.assertEqual(self.broker.credential_stored_meta("svc"), meta)
        self.assertEqual(self.events("credential_alias_removed"), [])
        self.assertEqual([e["reason"] for e in self.events("credential_change_refused")],
                         ["unknown_alias", "conflict"])


class Plans(pb.PBase):
    plans_cfg = {}

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["aliases"] = [OLD]

    def test_a_manifest_naming_the_alias_is_a_plan_for_the_credential(self):
        r = self.submit(self.manifest([self.read_rule(secret=OLD)]))
        req = self.card(r["id"])
        self.assertEqual(req.names, ["svc"])
        self.assertEqual([x["secret"] for x in req.spec["rules"]], ["svc"])
        self.assertEqual(req.aliases_used, {OLD: "svc"})
        self.assertEqual([(e["alias"], e["secret"]) for e in self.events("alias_used")], [(OLD, "svc")])

    def test_the_deny_list_covers_the_name_and_the_alias_both_ways(self):
        for denied in ("svc", OLD):
            with self.subTest(denied):
                self.broker.plans_cfg["deny_secrets"] = [denied]
                code, body = self.api("POST", "/v1/plans", {"manifest": self.manifest([self.read_rule(secret=OLD)]),
                                                            "source": "bob@build-box"})
                self.assertEqual(code, 403, body)
                self.assertIn("does not allow plans", body["error"])
                code, body = self.api("POST", "/v1/plans", {"manifest": self.manifest([self.read_rule()]),
                                                            "source": "bob@build-box"})
                self.assertEqual(code, 403, body)
        self.broker.plans_cfg["deny_secrets"] = []
        self.submit(self.manifest([self.read_rule(secret=OLD)]))             # premise: allowed when not denied

    def test_a_plan_call_by_alias_uses_the_plan_made_for_the_credential(self):
        plan_id = self.approve(self.manifest([self.read_rule()]))
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": [OLD], "method": "GET", "plan": plan_id,
            "url": f"http://127.0.0.1:{self.port}/v1/accounts/1",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, body)
        self.assertEqual([(e["alias"], e["secret"], e["mode"]) for e in self.events("alias_used")],
                         [(OLD, "svc", "http")])


if __name__ == "__main__":
    unittest.main()
