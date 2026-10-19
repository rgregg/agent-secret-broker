"""Standing approvals: 'Always' and time-boxed grants as one feature."""
import json
import os
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import audit_api  # noqa: E402
from secret_broker import grants as grants_mod  # noqa: E402
from secret_broker import standing as standing_mod  # noqa: E402
from secret_broker.backends import BackendError  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
from test_e2e import _Stub  # noqa: E402
import test_grants as tg  # noqa: E402  (Base only; its tests are not re-collected here)
from test_audit_api import event_names_in_broker  # noqa: E402

H = {"X-authentik-username": "alice"}


class Base(tg.Base):
    risk = "low"

    def env(self, names=("svc",), scripts=None):
        body = {"mode": "env", "names": list(names),
                "argv": ["bash", "run.sh"] if scripts else ["echo", "hi"]}
        if scripts is not None:
            body["scripts"] = scripts
        code, b = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def always_it(self, method="GET", mode="http", path="/x"):
        rid = self.env() if mode == "env" else self.http(method=method, path=path)
        self.assertEqual(self.approve(rid, "approve_always"), 303)
        self.broker._by_id[rid].done.wait(10)
        return rid

    def both(self, method="POST", minutes=15):
        """An Always and a timed grant for svc, made from two requests pending at once."""
        a, b = self.http(method=method, path="/ba"), self.http(method=method, path="/bb")
        self.assertEqual(self.approve(a, "approve_always"), 303)
        self.assertEqual(self.approve(b, f"approve_grant_{minutes}"), 303)
        for r in (a, b):
            self.broker._by_id[r].done.wait(10)
        self.assertEqual((len(self.standing()), len(self.broker.active_grants())), (1, 1))

    def standing(self, name="svc"):
        return list(self.broker.cfg["secrets"][name].get("standing") or [])

    def disk_standing(self, name="svc"):
        return self.disk()["secrets"][name].get("standing")

    def pushes(self):
        return len(self.notifier.sent)

    def post_revoke(self, gid, csrf="ok"):
        form = {"grant": gid, "csrf": self.broker.csrf_token("alice") if csrf == "ok" else csrf}
        try:
            return urllib.request.urlopen(urllib.request.Request(
                self.abase + "/grants/revoke", data=urllib.parse.urlencode(form).encode(),
                headers=H, method="POST"), timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def card(self, rid=None):
        r = self.broker._by_id[rid] if rid else list(self.broker._by_id.values())[-1]
        return req_text(self, f"/a/{r.nonce}")


def req_text(t, path):
    from test_e2e import req
    return req(t.abase + path, headers=H)[1]


class AlwaysScope(Base):
    def test_get_creates_a_reads_only_always(self):
        self.always_it("GET")
        self.assertEqual([(e["mode"], e["scope"], e["secrets"], e["expires_at"]) for e in self.standing()],
                         [("http", "read", ["svc"], None)])
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("approval", "prompt"), "prompt")
        n = self.pushes()
        self.assertEqual(self.result(self.http(path="/again"))["status"], "approved")
        self.assertEqual(self.pushes(), n)
        for m in ("POST", "DELETE", "PUT"):
            self.http(method=m)
            self.assertEqual(self.pushes(), n + 1, m)
            self.assertEqual(self.events("grant_skipped")[-1]["reason"], "method")
            self.broker.decide_via("dashboard", self.pending_id(), "deny", "alice")
            self.broker._denied_at.clear()
            n = self.pushes()

    def test_post_creates_an_any_method_always(self):
        self.always_it("POST")
        self.assertEqual([(e["mode"], e["scope"]) for e in self.standing()], [("http", "any")])
        n = self.pushes()
        for m in ("GET", "DELETE", "POST"):
            self.assertEqual(self.result(self.http(method=m, path="/" + m))["status"], "approved", m)
        self.assertEqual(self.pushes(), n)

    def test_env_always_covers_env_only_and_web_always_does_not_cover_env(self):
        self.always_it(mode="env")
        self.assertEqual([(e["mode"], e["scope"]) for e in self.standing()], [("env", "any")])
        n = self.pushes()
        self.assertEqual(self.result(self.env())["status"], "approved")
        self.assertEqual(self.pushes(), n)
        self.http()                                              # web is not covered
        self.assertEqual(self.pushes(), n + 1)
        self.broker.decide_via("dashboard", self.pending_id(), "approve", "alice")
        self.always_it("POST", path="/w")                        # a web any-method Always
        self.assertEqual(sorted((e["mode"], e["scope"]) for e in self.standing()),
                         [("env", "any"), ("http", "any")])
        self.broker.revoke_grant(next(e["id"] for e in self.standing() if e["mode"] == "env"), "alice")
        n = self.pushes()
        self.env()
        self.assertEqual(self.pushes(), n + 1)                   # web Always never covers env

    def test_other_secret_and_other_set_prompt(self):
        self.always_it("POST")
        n = self.pushes()
        self.http(("other",))
        self.http(("svc", "other"))
        self.assertEqual(self.pushes(), n + 2)

    def test_duplicate_is_a_noop_that_still_approves(self):
        a, b = self.http(path="/a"), self.http(path="/b")
        self.assertEqual(self.approve(a, "approve_always"), 303)
        self.assertEqual(self.approve(b, "approve_always"), 303)
        self.broker._by_id[b].done.wait(10)
        self.assertEqual(self.broker._by_id[b].always, "exists")
        self.assertEqual(len(self.standing()), 1)
        self.assertEqual(len(self.events("grant_created")), 1)
        self.assertEqual(self.status_of(b), "approved")

    def test_broader_replaces_narrower_and_narrower_is_covered(self):
        r1, r2 = self.http(path="/a"), self.http(method="POST", path="/b")
        self.approve(r1, "approve_always")
        self.approve(r2, "approve_always")
        self.assertEqual([(e["mode"], e["scope"]) for e in self.standing()], [("http", "any")])
        r3 = self.http(path="/c", method="POST")           # covered now: nothing pending
        self.assertEqual(self.status_of(r3), "approved")
        self.assertEqual([(e["mode"], e["scope"]) for e in self.disk_standing()], [("http", "any")])

    def test_cap_is_enforced(self):
        full = [{"id": f"id{i:04d}", "secrets": ["svc"], "mode": "http", "scope": "read",
                 "expires_at": None, "created_by": "a", "created_at": "2026-10-19T00:00:00Z"}
                for i in range(standing_mod.MAX_STANDING)]
        self.broker._persist_standing("svc", full, "alice")
        rid = self.env()
        self.assertEqual(self.approve(rid, "approve_always"), 303)
        self.broker._by_id[rid].done.wait(10)
        self.assertIn("maximum", self.broker._by_id[rid].always)
        self.assertEqual(len(self.standing()), standing_mod.MAX_STANDING)
        self.assertEqual(self.events("grant_refused")[-1]["reason"], "cap")
        self.assertEqual(self.status_of(rid), "approved")

    def test_never_from_push_or_ha_channels(self):
        import hashlib
        for ch in ("push", "ha"):
            rid = self.http(path="/" + ch)
            r = self.broker._by_id[rid]
            r.action_hash = hashlib.sha256(b"t").digest()
            r.offered = frozenset(("approve", "deny"))
            self.broker.decide_via(ch, rid, "approve", "alice", token="t", always=True)
        self.assertEqual(self.standing(), [])

    def test_ssh_has_no_always_and_creates_none(self):
        rid = self.sign()
        page = self.card(rid)
        self.assertNotIn("approve_always", page)
        self.assertNotIn("Always approve", page)
        code, _ = self.broker.decide_via("dashboard", rid, "approve", "alice", always=True)
        self.assertEqual(code, 200)
        self.assertEqual(self.standing("deploy"), [])
        self.assertIn("not applied", self.broker._by_id[rid].always)

    def test_old_post_values_still_work(self):
        self.always_it("GET", path="/2")
        self.assertEqual(len(self.standing()), 1)
        self.assertEqual(self.approve(self.http(("other",), path="/1"), "approve_grant_15"), 303)
        self.assertEqual(len(self.broker.active_grants()), 1)

    def test_not_offered_when_rated_high_or_above_ceiling(self):
        self.broker.summarizer = _Stub("x", "high")
        rid = self.http(method="DELETE")
        self.assertNotIn("value=approve_always", self.card(rid))
        self.broker.decide_via("dashboard", rid, "approve", "alice", always=True)
        self.assertEqual(self.standing(), [])
        self.broker.summarizer = _Stub("x", "medium")            # above auto_approve_max low
        self.broker._denied_at.clear()
        rid = self.http(path="/m")
        self.assertNotIn("value=approve_always", self.card(rid))


class ChipText(Base):
    def test_confirm_text_per_mode_and_scope(self):
        rid = self.http(method="GET")
        page = self.card(rid)
        self.assertIn("Always approve reads-only requests for svc? The secret will be used for "
                      "matching requests without asking again when the request is rated low or lower.", page)
        self.assertIn("value=approve_always", page)
        self.assertIn(">5 min<", page)
        self.assertIn(">30 min<", page)
        rid = self.http(method="POST", path="/p")
        self.assertIn("Always approve any-method requests for svc?", self.card(rid))
        rid = self.env()
        self.assertIn("Always approve run-with-secret requests for svc? The secret value will be "
                      "released to the requesting machine without asking again when the request is "
                      "rated low or lower.", self.card(rid))

    def test_chip_not_offered_for_several_secrets_or_invisible_scripts(self):
        rid = self.http(("svc", "other"))
        self.assertNotIn("value=approve_always", self.card(rid))
        rid = self.env(scripts=[{"stdin": True}])
        self.assertNotIn("value=approve_always", self.card(rid))


class Persistence(Base):
    def reload(self):
        return Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)

    def test_survives_a_new_broker_and_is_in_vault_metadata(self):
        self.always_it("GET")
        self.always_it(mode="env")
        d = self.disk_standing()
        self.assertEqual(sorted((e["mode"], e["scope"]) for e in d), [("env", "any"), ("http", "read")])
        self.assertEqual(set(d[0]), set(standing_mod.KEYS))
        self.assertEqual(self.disk()["secrets"]["svc"]["standing_changed"]["by"], "alice")
        self.assertEqual(self.disk()["secrets"]["svc"]["allowed_hosts"], ["127.0.0.1"])
        b = self.reload()
        self.assertEqual(sorted((e["mode"], e["scope"]) for e in b.cfg["secrets"]["svc"]["standing"]),
                         [("env", "any"), ("http", "read")])
        self.assertEqual([r["kind"] for r in b.standing_rows()], ["always", "always"])

    def test_revoke_removes_it_from_the_metadata(self):
        self.always_it("GET")
        self.always_it(mode="env")
        gid = next(e["id"] for e in self.standing() if e["mode"] == "http")
        self.assertTrue(self.broker.revoke_grant(gid, "alice"))
        self.assertEqual([e["mode"] for e in self.disk_standing()], ["env"])
        self.assertEqual([e["mode"] for e in self.reload().cfg["secrets"]["svc"]["standing"]], ["env"])
        ev = self.events("grant_revoked")[-1]
        self.assertEqual((ev["kind"], ev["grant_id"], ev["revoked_by"]), ("always", gid, "alice"))
        self.assertTrue(self.broker.revoke_grant(self.standing()[0]["id"], "alice"))
        self.assertIsNone(self.disk_standing())
        self.assertNotIn("standing", self.broker.cfg["secrets"]["svc"])
        self.assertFalse(self.broker.revoke_grant(gid, "alice"))

    def test_revoke_failure_keeps_the_entry(self):
        self.always_it("GET")
        gid = self.standing()[0]["id"]

        def boom(*a, **k):
            raise BackendError("locked")
        orig = self.broker.backend.set_meta
        self.broker.backend.set_meta = boom
        try:
            self.assertIsNone(self.broker.revoke_grant(gid, "alice"))
        finally:
            self.broker.backend.set_meta = orig
        self.assertEqual(len(self.standing()), 1)
        self.assertEqual(self.events("standing_change_failed")[-1]["op"], "revoke")

    def test_always_does_not_expire(self):
        self.always_it("GET")
        self.offset += 30 * 86400
        self.assertEqual(self.result(self.http(path="/later"))["status"], "approved")


class Validation(unittest.TestCase):
    GOOD = {"id": "abcd1234", "secrets": ["svc"], "mode": "http", "scope": "read", "expires_at": None,
            "created_by": "alice", "created_at": "2026-10-19T12:00:00Z"}

    def bad(self, raw, field, name="svc"):
        with self.assertRaises(ValueError) as cm:
            standing_mod.parse(raw, name)
        self.assertIn(field, str(cm.exception))

    def one(self, **kw):
        e = {**self.GOOD, **kw}
        return [e]

    def test_good_entry_and_defaults(self):
        out = standing_mod.parse([{k: v for k, v in self.GOOD.items() if k not in ("secrets", "expires_at")}],
                                 "svc")
        self.assertEqual(out, [self.GOOD])

    def test_table(self):
        self.bad("x", "standing must be a list")
        self.bad({}, "standing must be a list")
        self.bad(["x"], "standing[0] must be an object")
        self.bad(self.one(bogus=1), "standing[0].bogus")
        for k in ("id", "mode", "scope", "created_by", "created_at"):
            e = dict(self.GOOD)
            del e[k]
            self.bad([e], f"standing[0].{k} is required")
        self.bad(self.one(id="a"), "standing[0].id")
        self.bad(self.one(id="has space"), "standing[0].id")
        self.bad(self.one(id=5), "standing[0].id")
        self.bad([self.GOOD, self.GOOD], "standing[1].id")
        self.bad(self.one(secrets=["other"]), "standing[0].secrets")
        self.bad(self.one(secrets=["svc", "other"]), "standing[0].secrets")
        self.bad(self.one(mode="ssh_sign"), "standing[0].mode")
        self.bad(self.one(mode="store"), "standing[0].mode")
        self.bad(self.one(scope="write"), "standing[0].scope")
        self.bad(self.one(mode="env", scope="read"), "standing[0].scope")
        self.bad(self.one(expires_at=1.0), "standing[0].expires_at")
        self.bad(self.one(created_by=""), "standing[0].created_by")
        self.bad(self.one(created_by="x" * 121), "standing[0].created_by")
        self.bad(self.one(created_by=7), "standing[0].created_by")
        self.bad(self.one(created_at="yesterday"), "standing[0].created_at")
        self.bad(self.one(created_at=5), "standing[0].created_at")
        many = [{**self.GOOD, "id": f"id{i:04d}"} for i in range(standing_mod.MAX_STANDING + 1)]
        self.bad(many, "more than 50")
        self.bad([{**self.GOOD, "id": "okok"}, {**self.GOOD, "id": "okay", "mode": "x"}], "standing[1].mode")

    def test_max_entries_ok(self):
        many = [{**self.GOOD, "id": f"id{i:04d}"} for i in range(standing_mod.MAX_STANDING)]
        self.assertEqual(len(standing_mod.parse(many, "svc")), 50)

    def test_catalog_entry_rejects_bad_metadata_and_keeps_good(self):
        meta = {"name": "svc", "vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                "allowed_hosts": ["127.0.0.1"], "standing": [{**self.GOOD, "scope": "nope"}]}
        with self.assertRaises(ValueError) as cm:
            Broker._entry("Svc", meta)
        self.assertIn("standing[0].scope", str(cm.exception))
        meta["standing"] = [self.GOOD]
        name, entry = Broker._entry("Svc", meta)
        self.assertEqual(entry["standing"], [self.GOOD])

    def test_labels(self):
        self.assertEqual(standing_mod.covers_label("http", "read"), "web reads only")
        self.assertEqual(standing_mod.covers_label("http", "any"), "web any method")
        self.assertEqual(standing_mod.covers_label("env", "any"), "run-with-secret")
        self.assertEqual(standing_mod.covers_label("ssh_sign", "any"), "ssh")
        self.assertEqual(standing_mod.decided_by("always", None, "http", "read"),
                         "standing approval (always, reads only)")
        self.assertEqual(standing_mod.decided_by("timed", 15, "http", "any"),
                         "standing approval (15 min, any method)")


class Ceilings(Base):
    risk = "low"

    def test_always_above_the_ceiling_prompts_and_audits_skip(self):
        self.always_it("GET")
        self.broker.summarizer = _Stub("x", "medium")
        n = self.pushes()
        rid = self.http(path="/m")
        self.assertEqual(self.pushes(), n + 1)
        sk = self.events("grant_skipped")[-1]
        self.assertEqual((sk["id"], sk["kind"], sk["reason"], sk["max_risk"], sk["risk_level"]),
                         (rid, "always", "risk", "low", "medium"))
        self.assertEqual(self.events("grant_used"), [])

    def test_missing_verdict_counts_as_high_for_always_only(self):
        self.both("POST")
        self.broker.summarizer = None
        n = self.pushes()
        # an Always alone would prompt; a timed grant (below) releases with no verdict
        self.assertEqual(self.result(self.http(path="/nv", method="POST"))["status"], "approved")
        self.assertEqual(self.pushes(), n)
        self.broker.revoke_grant(self.broker.active_grants()[0]["id"], "alice")
        self.http(path="/nv2", method="POST")
        self.assertEqual(self.pushes(), n + 1)
        self.assertEqual(self.events("grant_skipped")[-1]["kind"], "always")

    def test_auto_approve_max_none_never_uses_always(self):
        self.always_it("GET")
        self.broker._auto_max = "none"
        n = self.pushes()
        self.http(path="/n")
        self.assertEqual(self.pushes(), n + 1)

    def test_raising_the_ceiling_allows_it(self):
        self.always_it("GET")
        self.broker.summarizer = _Stub("x", "medium")
        self.broker._auto_max = "medium"
        n = self.pushes()
        self.assertEqual(self.result(self.http(path="/n"))["status"], "approved")
        self.assertEqual(self.pushes(), n)

    def test_timed_grant_at_high_risk_releases_with_no_ceiling(self):
        self.grant_it(("svc",), 15, method="POST")
        self.broker.summarizer = _Stub("x", "high")
        n = self.pushes()
        self.assertEqual(self.result(self.http(path="/h", method="DELETE"))["status"], "approved")
        self.assertEqual(self.pushes(), n)
        u = self.events("grant_used")[-1]
        self.assertEqual((u["kind"], u["grant_minutes"]), ("timed", 15))

    def test_timed_still_skipped_for_method_and_invisible_script(self):
        self.grant_it(("svc",), 15, method="GET")
        n = self.pushes()
        self.http(method="DELETE")
        self.assertEqual(self.pushes(), n + 1)
        sk = self.events("grant_skipped")[-1]
        self.assertEqual((sk["kind"], sk["reason"]), ("timed", "method"))
        rid = self.env()
        self.broker.decide_via("dashboard", rid, "approve", "alice", grant_minutes=15)
        n = self.pushes()
        self.env(scripts=[{"stdin": True}])
        self.assertEqual(self.pushes(), n + 1)
        self.assertEqual(self.events("grant_skipped")[-1]["reason"], "script_not_visible")

    def test_always_env_skipped_for_invisible_script(self):
        self.always_it(mode="env")
        n = self.pushes()
        self.env(scripts=[{"stdin": True}])
        self.assertEqual(self.pushes(), n + 1)
        sk = self.events("grant_skipped")[-1]
        self.assertEqual((sk["kind"], sk["reason"]), ("always", "script_not_visible"))


class Order(Base):
    def test_legacy_allow_first(self):
        self.both("POST")
        self.broker.set_approval("svc", "allow", "alice")
        rid = self.http(path="/l")
        self.result(rid)
        ap = [e for e in self.events("approved") if e["id"] == rid][0]
        self.assertEqual(ap["via"], "policy")
        self.assertNotIn("grant_id", ap)
        self.assertEqual([e for e in self.events("grant_used")
                          if e["id"] == rid], [])

    def test_always_before_timed(self):
        self.both("POST")
        rid = self.http(path="/o")
        self.result(rid)
        used = [e for e in self.events("grant_used") if e["id"] == rid]
        self.assertEqual([u["kind"] for u in used], ["always"])

    def test_timed_after_always_skipped_for_risk(self):
        self.both("POST")
        self.broker.summarizer = _Stub("x", "medium")
        n = self.pushes()
        rid = self.http(path="/o")
        self.assertEqual(self.result(rid)["status"], "approved")
        self.assertEqual(self.pushes(), n)
        ev = [e for e in self.records() if e.get("id") == rid and e["event"].startswith("grant_")]
        self.assertEqual([(e["event"], e["kind"]) for e in ev],
                         [("grant_skipped", "always"), ("grant_used", "timed")])

    def test_legacy_escalated_falls_through_to_standing(self):
        self.grant_it(("svc",), 15, method="POST")
        self.broker.set_approval("svc", "allow", "alice")
        self.broker.summarizer = _Stub("x", "medium")          # above the ceiling: legacy escalates
        n = self.pushes()
        rid = self.http(path="/e")
        self.assertEqual(self.result(rid)["status"], "approved")
        self.assertEqual(self.pushes(), n)
        self.assertEqual(self.events("grant_used")[-1]["kind"], "timed")

    def test_prompt_when_nothing_applies(self):
        n = self.pushes()
        self.http()
        self.assertEqual(self.pushes(), n + 1)


class Revocation(Base):
    def test_always_timed_and_legacy_revoke_through_the_page(self):
        self.always_it("GET")
        self.grant_it(("other",), 15, method="POST")
        self.broker.set_approval("svc", "allow", "alice")
        rows = {r["kind"]: r for r in self.broker.standing_rows()}
        self.assertEqual(sorted(rows), ["always", "legacy", "timed"])
        self.assertEqual(self.post_revoke(rows["always"]["id"], csrf="bad"), 403)
        self.assertEqual(len(self.standing()), 1)
        self.assertEqual(self.post_revoke(rows["always"]["id"]), 200)
        self.assertEqual(self.standing(), [])
        self.assertEqual(self.post_revoke(rows["timed"]["id"]), 200)
        self.assertEqual(self.broker.active_grants(), [])
        # a stale id is reported, not an error
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/grants/revoke", headers=H, method="POST",
            data=urllib.parse.urlencode({"grant": "nope", "csrf": self.broker.csrf_token("alice")}).encode()),
            timeout=10)
        self.assertIn("no longer active", r.read().decode())
        form = {"name": "svc", "approval": "prompt", "csrf": self.broker.csrf_token("alice")}
        urllib.request.urlopen(urllib.request.Request(
            self.abase + "/policies", data=urllib.parse.urlencode(form).encode(), headers=H, method="POST"),
            timeout=10)
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["approval"], "prompt")
        self.assertEqual(self.broker.standing_rows(), [])

    def test_revoked_always_prompts_again(self):
        self.always_it("GET")
        self.broker.revoke_grant(self.standing()[0]["id"], "alice")
        n = self.pushes()
        self.http(path="/r")
        self.assertEqual(self.pushes(), n + 1)

    def test_timed_expiry_and_sweep(self):
        self.both("GET", minutes=5)
        self.offset += 400
        self.broker.grants.sweep()
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(self.events("grant_expired")[0]["secrets"], ["svc"])
        self.assertEqual(len(self.standing()), 1)

    def test_timed_revoke_audits_kind(self):
        self.grant_it(("svc",), 5)
        self.assertTrue(self.broker.revoke_grant(self.broker.active_grants()[0]["id"], "alice"))
        self.assertEqual(self.events("grant_revoked")[-1]["kind"], "timed")


class MaxRiskIgnored(Base):
    grants_cfg = {"max_risk": "none"}

    def test_accepted_ignored_and_warned(self):
        out = grants_mod.parse_config({"max_risk": "low"})
        self.assertNotIn("max_risk", out)
        warns = [e["warning"] for e in self.events("config_warning")]
        self.assertTrue(any("timed_grants.max_risk is ignored" in w for w in warns), warns)
        self.grant_it()
        self.broker.summarizer = _Stub("x", "high")
        self.assertEqual(self.result(self.http(path="/y"))["status"], "approved")

    def test_describe(self):
        self.assertEqual(grants_mod.describe(grants_mod.parse_config(None), "low"),
                         "Standing approvals: timed grants (no ceiling) 5/15/30 min; Always up to low risk")
        self.assertIn("timed grants off", grants_mod.describe(grants_mod.parse_config({"enabled": False}), "high"))
        self.assertIn("Always off", grants_mod.describe(grants_mod.parse_config(None), "none"))


class Pages(Base):
    def test_empty_state_and_single_section(self):
        pol = req_text(self, "/policies")
        self.assertIn("Standing approvals", pol)
        self.assertIn("No standing approvals", pol)
        self.assertNotIn("Active grants", pol)
        self.assertNotIn("Always allowed", pol)
        self.assertEqual(pol.count("<h3 style='margin-top:0'>"), 1)

    def test_one_table_for_all_three_kinds_with_escaping(self):
        self.always_it("GET")
        evil = "<script>x</script>"
        self.broker._persist_standing(
            "svc", self.standing() + [{"id": "evil1234", "secrets": ["svc"], "mode": "env", "scope": "any",
                                       "expires_at": None, "created_by": evil,
                                       "created_at": "2026-10-19T12:00:00Z"}], evil)
        self.broker.grants.add(["other"], 15, "any", evil, "dashboard", "r", mode="http")
        self.broker.set_approval("other", "allow", evil)
        pol = req_text(self, "/policies")
        self.assertNotIn("<script>x", pol)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", pol)
        self.assertIn("<td data-label=Covers>web reads only</td>", pol)
        self.assertIn("<td data-label=Covers>run-with-secret</td>", pol)
        self.assertIn("<td data-label=Covers>web any method</td>", pol)
        self.assertIn("whole credential, any method, any covered mode (web, run-with-secret)", pol)
        self.assertEqual(pol.count("<td data-label=Expires>never</td>"), 3)
        self.assertRegex(pol, r"<td data-label=Expires><time data-gexp='\d+'>in 15 min</time></td>")
        self.assertEqual(pol.count(">Revoke</button>"), 4)
        self.assertEqual(pol.count("action='/grants/revoke'"), 3)
        self.assertIn("name=approval value=prompt>Revoke", pol)
        self.assertIn("<th>Secrets</th><th>Covers</th><th>Expires</th><th>Created by</th>", pol)

    def test_settings_line(self):
        s = req_text(self, "/settings")
        self.assertIn("Standing approvals: timed grants (no ceiling) 5/15/30 min; Always up to low risk", s)
        self.assertNotIn("Time-boxed grants", s)

    def test_history_wording(self):
        self.always_it("GET")
        rid = self.http(path="/h")
        self.result(rid)
        self.assertIn("standing approval (always, reads only) (auto-approved), grant ",
                      req_text(self, f"/request/{rid}?fragment=1"))
        self.broker.revoke_grant(self.standing()[0]["id"], "alice")
        self.always_it("POST", path="/h2")
        rid = self.http(method="PUT", path="/h3")
        self.result(rid)
        self.assertIn("standing approval (always, any method)", req_text(self, f"/request/{rid}?fragment=1"))
        self.broker.revoke_grant(self.standing()[0]["id"], "alice")
        self.always_it(mode="env")
        rid = self.env()
        self.result(rid)
        self.assertIn("standing approval (always, run-with-secret)", req_text(self, f"/request/{rid}?fragment=1"))

    def test_policies_page_requires_identity(self):
        from test_e2e import req
        self.assertEqual(req(self.abase + "/policies", headers={"X-authentik-username": "mallory"})[0], 403)


class AgentCanary(Base):
    def test_nothing_about_standing_approvals_reaches_the_agent(self):
        self.always_it("GET")
        self.grant_it(("other",), 15)
        rid = self.http(path="/c")
        got = self.result(rid)
        self.assertEqual(got["status"], "approved")
        blob = json.dumps(got)
        for path in ("/v1/secrets", "/v1/secrets?host=127.0.0.1", "/v1/status"):
            blob += self.api("GET", path)[1]
        blob = blob.replace("timed_grants", "")
        for word in ("standing", "grant", "always", "Always", "expires", "created_by", "scope"):
            self.assertNotIn(word, blob, word)
        for n in self.notifier.sent:
            self.assertNotIn("standing", json.dumps(n, default=str).lower())
        # the redacted audit view shows a plain approval and none of the policy events
        code, body = self.api("GET", "/v1/audit?limit=200")[0], self.api("GET", "/v1/audit?limit=200")[1]
        self.assertEqual(code, 200)
        low = body.lower()
        for word in ("grant", "standing", "always", "policy_changed"):
            self.assertNotIn(word, low.replace("always_requested", ""), word)
        self.assertIn('"approved"', body)

    def test_hidden_events_are_classified(self):
        names = event_names_in_broker()
        for ev in ("grant_created", "grant_used", "grant_skipped", "grant_revoked", "grant_refused",
                   "standing_change_failed"):
            self.assertIn(ev, names)
            self.assertIn(ev, audit_api.HIDDEN)
        self.assertEqual(names - set(audit_api.WHITELIST) - audit_api.HIDDEN, set())
        for ev in ("grant_created", "grant_used", "grant_skipped", "grant_revoked", "standing_change_failed"):
            self.assertIsNone(audit_api.redact({"event": ev, "seq": 1, "ts": 1.0, "kind": "always"}))


class SshUnaffected(Base):
    def test_ssh_card_chips_and_no_always(self):
        rid = self.sign()
        page = self.card(rid)
        self.assertIn("approve_grant_", page)                    # timed chips remain
        self.assertNotIn("value=approve_always", page)
        self.assertRegex(page, r"<span class='chip off'[^>]*>Always</span>")


if __name__ == "__main__":
    unittest.main()
