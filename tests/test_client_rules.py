"""Per-client auto-approval rules (GitHub issue #15, "Per-client auto-approval rules").

Every Always approval, timed grant and SSH host rule carries a client scope (`*` = any client, or one
client id). A rule made from a card defaults to the requesting client; a rule for client A never
applies to client B; a rule for any client applies to all. Ceilings (`auto_approve_max`,
`auto_modes`) have global defaults and per-client overrides. Rules saved before this existed are
global, so nothing changes on upgrade. Revoking a client removes its own rules.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import sys
import time
import unittest
import urllib.parse
import secrets as pysecrets
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
import test_ssh_rules as sr  # noqa: E402
from test_e2e import _Stub  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import clients as clients_mod  # noqa: E402
from secret_broker import grants as grants_mod  # noqa: E402
from secret_broker import sshrules, standing as standing_mod  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

KEY = t.KEY
ANY = clients_mod.ANY


class ClientMixin:
    """Enroll clients directly through the broker API (the HTTP path is covered in test_clients)."""

    def mk(self, name):
        secret = "asbc1_" + pysecrets.token_urlsafe(32)
        with mock.patch.object(clients_mod, "SUBMIT_HOUR", (999, 999)):
            code, out, e = self.broker.clients.submit(name, clients_mod.hash_secret(secret), "u@h", "127.0.0.1")
        assert code == 202, (code, out)
        status, _ = self.broker.decide_enrollment(out["id"], "approve", name, "alice")
        assert status == "approved", status
        cid = next(c["id"] for c in self.broker.clients.rows() if c["name"] == name)
        return type("C", (), {"secret": secret, "id": cid, "name": name})

    def http_as(self, c, path="/x", method="GET", names=("svc",)):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        key = c if isinstance(c, str) else c.secret
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": list(names), "method": method, "url": url,
            "headers": {**({"Authorization": "Bearer {{SVC_TOKEN}}"} if "svc" in names else {}),
                        **({"X-Other": "{{OTHER_TOKEN}}"} if "other" in names else {})}}, key=key)
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def env_as(self, c, names=("svc",)):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": list(names),
                                                      "argv": ["echo", "hi"]}, key=c.secret)
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def card(self, rid, decision, scope=None, user="alice"):
        form = {"id": rid, "decision": decision, "csrf": self.broker.csrf_token(user)}
        if scope is not None:
            form["rule_scope"] = scope
        import urllib.request
        import urllib.error

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            r = urllib.request.build_opener(NoFollow).open(urllib.request.Request(
                self.abase + "/decide", data=urllib.parse.urlencode(form).encode(),
                headers={"X-authentik-username": user}, method="POST"), timeout=10)
            return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def settle(self, rid):
        self.broker._by_id[rid].done.wait(10)
        return self.broker._by_id[rid].status

    def pushes(self):
        self.broker.flush_notifications(5)
        return len(self.notifier.sent)

    def stored_standing(self, name="svc"):
        return self.disk()["secrets"][name].get("standing") or []

    def live_standing(self, name="svc"):
        return list(self.broker.cfg["secrets"][name].get("standing") or [])

    def assert_auto(self, c, **kw):
        n = self.pushes()
        rid = self.http_as(c, **kw)
        self.assertEqual(self.settle(rid), "approved", c.name)
        self.assertEqual(self.pushes(), n, f"{c.name} should not have been asked")
        return rid

    def assert_asked(self, c, **kw):
        n = self.pushes()
        rid = self.http_as(c, **kw)
        self.assertEqual(self.broker._by_id[rid].status, "pending", c.name)
        self.assertEqual(self.pushes(), n + 1, f"{c.name} should have been asked")
        self.broker.decide_via("dashboard", rid, "deny", "alice")
        self.broker._denied_at.clear()
        return rid


class Legacy:
    """A stand-in client for the shared key."""
    secret, id, name = KEY, "legacy", "shared key (legacy)"


# ---------------------------------------------------------------------------- Always and timed grants
class StandingScope(ClientMixin, tg.Base):
    risk = "low"

    def test_always_defaults_to_the_requesting_client(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        rid = self.http_as(a, method="GET")
        self.assertEqual(self.card(rid, "approve_always"), 303)
        self.settle(rid)
        (e,) = self.live_standing()
        self.assertEqual((e["mode"], e["scope"], e["client"]), ("http", "read", a.id))
        self.assertEqual(self.stored_standing()[0]["client"], a.id)            # persisted in the vault metadata
        self.assertEqual(self.events("grant_created")[0]["rule_client"], a.id)
        self.assert_auto(a, path="/again")
        self.assert_asked(b)                                                    # A's Always never applies to B
        self.assert_asked(Legacy)                                               # nor to the shared key
        self.assert_auto(a, path="/third")

    def test_any_client_is_an_explicit_choice(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        rid = self.http_as(a)
        self.assertEqual(self.card(rid, "approve_always", scope="any"), 303)
        self.settle(rid)
        (e,) = self.live_standing()
        self.assertNotIn("client", e)                                           # global rules keep the old shape
        self.assertNotIn("client", self.stored_standing()[0])
        for c in (a, b, Legacy):
            self.assert_auto(c)

    def test_unrecognised_scope_values_fall_back_to_the_requesting_client(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        for bad in ("*", "all", "c-00000000", "ANY", ""):
            self.broker.revoke_grant(self.live_standing()[0]["id"], "alice") if self.live_standing() else None
            rid = self.http_as(a, path="/" + (bad or "empty"))
            self.assertEqual(self.card(rid, "approve_always", scope=bad), 303)
            self.settle(rid)
            self.assertEqual([e.get("client") for e in self.live_standing()], [a.id], bad)
            self.assert_asked(b)

    def test_timed_grants_are_scoped_the_same_way(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        rid = self.http_as(a)
        self.assertEqual(self.card(rid, "approve_grant_15"), 303)
        self.settle(rid)
        (g,) = self.broker.active_grants()
        self.assertEqual(g["client"], a.id)
        self.assert_auto(a, path="/y")
        self.assert_asked(b)
        self.assert_asked(Legacy)
        rid = self.http_as(b, path="/z")
        self.assertEqual(self.card(rid, "approve_grant_15", scope="any"), 303)
        self.settle(rid)
        self.assertEqual(sorted(g["client"] for g in self.broker.active_grants()), [ANY, a.id])
        self.assert_auto(Legacy)
        self.assert_auto(b)

    def test_scoped_and_global_grants_for_one_set_coexist(self):
        a = self.mk("alpha")
        self.broker.grants.add(["svc"], 15, "read", "alice", "dashboard", "r", mode="http", client=a.id)
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http")
        self.assertEqual(len(self.broker.active_grants()), 2)
        self.assertEqual(self.broker.grants.find(["svc"], "http", a.id)["client"], a.id)    # its own wins
        self.assertEqual(self.broker.grants.find(["svc"], "http", "c-ffffffff")["client"], ANY)
        self.assertEqual(self.broker.grants.find(["svc"], "http")["client"], ANY)
        # a read-only client grant plus a global any-method grant: a POST from A is covered by the global one
        self.assert_auto(a, method="POST", path="/p")

    def test_a_grant_for_one_client_does_not_cover_another_even_for_the_same_set(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http", client=a.id)
        self.assertIsNone(self.broker.grants.find(["svc"], "http", b.id))
        self.assertIsNone(self.broker.grants.find(["svc"], "http", "legacy"))
        self.assertIsNone(self.broker.grants.find(["svc"], "http"))
        self.assertIsNotNone(self.broker.grants.find(["svc"], "http", a.id))

    def test_resolution_order_for_always(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        # client rule reads-only, global rule any method: A's POST is covered by the global rule
        self.broker._add_always("svc", "http", "read", "alice", a.id)
        self.broker._add_always("svc", "http", "any", "alice", ANY)
        self.assert_auto(a, method="POST", path="/p")
        self.assert_auto(b, method="POST", path="/p2")
        # drop the global rule: A keeps GET only; B and legacy keep nothing
        gid = next(e["id"] for e in self.live_standing() if "client" not in e)
        self.assertTrue(self.broker.revoke_grant(gid, "alice"))
        self.assert_auto(a, method="GET", path="/g")
        self.assert_asked(a, method="POST", path="/p3")
        self.assert_asked(b, method="GET", path="/g2")

    def test_creating_a_client_rule_when_a_global_one_covers_it_is_a_noop(self):
        a = self.mk("alpha")
        self.broker._add_always("svc", "http", "any", "alice", ANY)
        status, e = self.broker._add_always("svc", "http", "read", "alice", a.id)
        self.assertEqual(status, "exists")
        self.assertEqual(len(self.live_standing()), 1)
        # but a global rule is still created when only a client rule exists
        b = self.mk("bravo")
        self.broker.revoke_grant(self.live_standing()[0]["id"], "alice")
        self.broker._add_always("svc", "http", "any", "alice", b.id)
        status, e = self.broker._add_always("svc", "http", "any", "alice", ANY)
        self.assertEqual(status, "created")
        self.assertEqual(sorted(x.get("client", ANY) for x in self.live_standing()), sorted([ANY, b.id]))

    def test_a_new_client_inherits_only_global_rules(self):
        a = self.mk("alpha")
        self.broker._add_always("svc", "http", "any", "alice", a.id)             # alpha's own
        self.broker._add_always("other", "http", "any", "alice", ANY)             # everyone's
        c = self.mk("charlie")
        self.assert_asked(c)                                                      # nothing of alpha's
        rid = self.http_as(c, names=("other",))
        self.assertEqual(self.settle(rid), "approved")                           # the global rule only
        self.assertEqual([e.get("client") for e in self.live_standing()], [a.id])

    def test_revoking_a_client_removes_exactly_its_rules(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker._add_always("svc", "http", "any", "alice", a.id)
        self.broker._add_always("svc", "env", "any", "alice", b.id)
        self.broker._add_always("other", "http", "any", "alice", ANY)
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http", client=a.id)
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="env", client=b.id)
        self.broker.grants.add(["other"], 15, "any", "alice", "dashboard", "r", mode="http")
        self.assertEqual(self.broker.revoke_client(a.id, "alice"), "revoked")
        self.assertEqual([e.get("client") for e in self.live_standing()], [b.id])
        self.assertEqual([e.get("client") for e in self.stored_standing()], [b.id])         # in the vault too
        self.assertEqual(len(self.live_standing("other")), 1)
        self.assertEqual(sorted(g["client"] for g in self.broker.active_grants()), [ANY, b.id])
        ev = self.events("client_revoked")[0]
        self.assertEqual(ev["rules_removed"], {"timed": 1, "always": 1, "ssh": 0})
        self.assertEqual(ev["rules_failed"], 0)
        # B and the global rule still work
        rid = self.http_as(b, names=("other",))
        self.assertEqual(self.settle(rid), "approved")

    def test_a_vault_write_failure_during_revoke_is_reported_and_harmless(self):
        a = self.mk("alpha")
        self.broker._add_always("svc", "http", "any", "alice", a.id)
        real = self.broker.backend.set_meta

        def boom(*args, **kw):
            raise OSError("LEAKY-VAULT-TEXT")
        self.broker.backend.set_meta = boom
        try:
            self.assertEqual(self.broker.revoke_client(a.id, "alice"), "revoked")
        finally:
            self.broker.backend.set_meta = real
        ev = self.events("client_revoked")[0]
        self.assertEqual(ev["rules_failed"], 1)
        self.assertNotIn("LEAKY", open(self.audit).read())
        # the rule remains but can never match: the client is revoked and its id is never reused
        self.assertEqual(self.api("GET", "/v1/status", key=a.secret)[0], 401)

    def test_ids_are_never_reused(self):
        seen = set()
        for i in range(12):
            c = self.mk(f"box{i}")
            self.assertNotIn(c.id, seen)
            seen.add(c.id)
            self.broker.revoke_client(c.id, "alice")
            self.broker.clients.remove(c.id)

    def test_policies_page_shows_who_a_rule_applies_to(self):
        a = self.mk("alpha")
        self.broker._add_always("svc", "http", "any", "alice", a.id)
        self.broker._add_always("svc", "env", "any", "alice", ANY)
        self.broker.grants.add(["other"], 15, "any", "alice", "dashboard", "r", mode="http", client="legacy")
        pol = self.get("/policies")[1]
        self.assertIn("<th>Applies to</th>", pol)
        self.assertIn("<td data-label='Applies to'>alpha</td>", pol)
        self.assertIn("<td data-label='Applies to'>any client</td>", pol)
        self.assertIn("<td data-label='Applies to'>shared key (legacy)</td>", pol)
        self.broker.revoke_client(a.id, "alice")
        self.assertNotIn("<td data-label='Applies to'>alpha</td>", self.get("/policies")[1])

    def test_card_offers_the_choice_with_the_client_name(self):
        a = self.mk("alpha")
        rid = self.http_as(a)
        page = self.get("/")[1]
        self.assertIn("name=rule_scope", page)
        self.assertIn("<option value=client selected>only this client (alpha)</option>", page)
        self.assertIn("<option value=any>any client (every machine)</option>", page)
        self.assertNotIn("<option value=any selected", page)
        link = t.req(self.abase + f"/a/{self.broker._by_id[rid].nonce}", headers={"X-authentik-username": "alice"})[1]
        self.assertIn("only this client (alpha)", link)

    def test_clients_page_lists_each_clients_own_rules(self):
        a = self.mk("alpha")
        self.broker._add_always("svc", "http", "any", "alice", a.id)
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http", client=a.id)
        page = self.get("/clients")[1]
        self.assertIn("2 rules", page)
        self.assertIn("always: svc", page)
        self.assertIn("timed: svc", page)

    def get(self, path, user="alice"):
        return t.req(self.abase + path, headers={"X-authentik-username": user})


# ---------------------------------------------------------------------------- migration
class Migration(ClientMixin, tg.Base):
    """Rules saved by a broker that knew nothing about clients are global, byte for byte."""
    OLD_STANDING = [{"id": "old11111", "secrets": ["svc"], "mode": "http", "scope": "any", "expires_at": None,
                     "created_by": "alice", "created_at": "2026-10-01T00:00:00Z"}]

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["standing"] = [dict(e) for e in self.OLD_STANDING]

    def test_old_always_entries_load_as_global_and_apply_to_everyone(self):
        (e,) = self.broker.cfg["secrets"]["svc"]["standing"]
        self.assertNotIn("client", e)
        a = self.mk("alpha")
        for c in (a, Legacy, self.mk("bravo")):
            self.assert_auto(c)
        row = [r for r in self.broker.standing_rows() if r["kind"] == "always"][0]
        self.assertEqual(row["client"], ANY)

    def test_the_old_file_formats_stay_byte_identical_when_only_global_rules_exist(self):
        before = json.loads(json.dumps(self.disk()["secrets"]["svc"]["standing"]))
        self.assertEqual(before, self.OLD_STANDING)
        self.broker._add_always("svc", "env", "any", "alice", ANY)            # a new GLOBAL rule
        after = self.disk()["secrets"]["svc"]["standing"]
        self.assertEqual(after[0], self.OLD_STANDING[0])
        self.assertNotIn("client", json.dumps(after))                          # no new field anywhere

    def test_standing_parse_accepts_old_entries_and_the_new_field(self):
        old = standing_mod.parse([dict(e) for e in self.OLD_STANDING], "svc")
        self.assertNotIn("client", old[0])
        new = standing_mod.parse([{**self.OLD_STANDING[0], "client": "c-0a1b2c3d"}], "svc")
        self.assertEqual(new[0]["client"], "c-0a1b2c3d")
        for bad in ("nope", "", 5, "c-XYZ"):
            with self.assertRaises(ValueError):
                standing_mod.parse([{**self.OLD_STANDING[0], "client": bad}], "svc")
        self.assertEqual(standing_mod.serialize(new), [{**self.OLD_STANDING[0], "client": "c-0a1b2c3d"}])
        self.assertEqual(standing_mod.serialize(old), self.OLD_STANDING)

    def test_a_version_3_grants_file_loads_as_global_grants(self):
        path = os.path.join(os.path.dirname(self.audit), "grants.json")
        now = time.time()
        with open(path, "w") as f:
            json.dump({"version": 3, "grants": [{
                "id": "g1", "secrets": ["svc"], "scope": "any", "minutes": 15, "created_at": now,
                "expires_at": now + 600, "created_by": "alice", "channel": "dashboard", "request_id": "r",
                "mode": "http"}]}, f)
        b = Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)
        (g,) = b.active_grants()
        self.assertEqual(g["client"], ANY)
        a = self.mk("alpha")
        self.assertEqual(b.grants.find(["svc"], "http", a.id)["id"], "g1")
        self.assertEqual(b.grants.find(["svc"], "http", "legacy")["id"], "g1")

    def test_client_grants_are_stored_where_an_older_broker_will_not_read_them(self):
        a = self.mk("alpha")
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http", client=a.id)
        self.broker.grants.add(["other"], 15, "any", "alice", "dashboard", "r", mode="http")
        data = json.load(open(os.path.join(os.path.dirname(self.audit), "grants.json")))
        self.assertEqual([g["secrets"] for g in data["grants"]], [["other"]])
        self.assertEqual([g["client"] for g in data["client_grants"]], [a.id])
        self.assertNotIn("client", data["grants"][0])
        b = Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)
        self.assertEqual(sorted(g["client"] for g in b.active_grants()), [ANY, a.id])

    def test_a_malformed_scope_in_the_grants_file_drops_the_grant(self):
        path = os.path.join(os.path.dirname(self.audit), "grants.json")
        now = time.time()
        with open(path, "w") as f:
            json.dump({"version": 4, "grants": [], "client_grants": [{
                "id": "g1", "secrets": ["svc"], "scope": "any", "minutes": 15, "created_at": now,
                "expires_at": now + 600, "created_by": "alice", "mode": "http", "client": "everyone"}]}, f)
        b = Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)
        self.assertEqual(b.active_grants(), [])


# ---------------------------------------------------------------------------- ceilings
class Ceilings(ClientMixin, tg.Base):
    risk = "low"

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["approval"] = "allow"
        cfg["risk"] = {"auto_approve_max": "low"}

    def override(self, c, **risk):
        self.broker.clients_cfg["overrides"][c.id] = dict(risk)

    def test_global_default_applies_to_everyone_without_an_override(self):
        a = self.mk("alpha")
        self.assert_auto(a)
        self.assert_auto(Legacy)

    def test_a_client_set_to_never_auto_approve_always_prompts(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.override(a, auto_approve_max="none")
        rid = self.http_as(a)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.events("escalated")[-1]["reason"], "this client is set to never auto-approve")
        self.broker.decide_via("dashboard", rid, "deny", "alice")
        self.broker._denied_at.clear()
        self.assert_auto(b)
        self.assert_auto(Legacy)

    def test_never_blocks_always_grants_and_ssh_rules_for_that_client_only(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.broker._add_always("svc", "http", "any", "alice", ANY)
        self.assert_auto(a)
        self.override(a, auto_approve_max="none")
        self.assert_asked(a)                                   # the global Always no longer applies to A
        self.assert_auto(b)
        self.broker.grants.add(["svc"], 15, "any", "alice", "dashboard", "r", mode="http", client=a.id)
        self.broker.revoke_grant(next(e["id"] for e in self.live_standing()), "alice")
        self.assert_asked(a)
        self.assertEqual(self.broker.auto_max_for(a.id), "none")
        self.assertTrue(self.broker.client_never_auto(a.id))
        self.assertFalse(self.broker.client_never_auto(b.id))

    def test_a_client_can_be_loosened_above_the_global_default(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker.summarizer = _Stub("Writes", "medium")
        self.assert_asked(a)
        self.assert_asked(b)
        self.override(a, auto_approve_max="medium")
        self.assert_auto(a)
        self.assert_asked(b)
        self.assert_asked(Legacy)

    def test_a_client_can_be_tightened_below_the_global_default(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker.summarizer = _Stub("Reads", "low")
        self.override(a, auto_approve_max="none")
        self.assert_asked(a)
        self.assert_auto(b)

    def test_auto_modes_override_replaces_the_global_default_for_that_client(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.override(a, auto_modes=["http"])
        rid = self.env_as(a)
        self.assertEqual(self.broker._by_id[rid].status, "pending")      # env is not auto for A
        self.broker.decide_via("dashboard", rid, "deny", "alice")
        self.broker._denied_at.clear()
        rid = self.env_as(b)
        self.assertEqual(self.settle(rid), "approved")                     # but it is for B (global http+env)
        self.assert_auto(a)                                                # and http still is for A

    def test_a_credentials_own_auto_modes_still_win(self):
        a = self.mk("alpha")
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http"]
        self.override(a, auto_modes=["http", "env"])
        rid = self.env_as(a)
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_always_is_not_offered_when_the_clients_ceiling_forbids_it(self):
        a = self.mk("alpha")
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.override(a, auto_approve_max="none")
        rid = self.http_as(a)
        ok, why = self.broker.always_allow_eligibility(self.broker._by_id[rid])
        self.assertFalse(ok)
        self.assertIn("never auto-approve", why)
        self.override(a, auto_approve_max="high")
        self.assertTrue(self.broker.always_allow_eligibility(self.broker._by_id[rid])[0])

    def test_a_clients_always_is_checked_against_its_own_ceiling(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.broker._add_always("svc", "http", "any", "alice", ANY)
        self.broker.summarizer = _Stub("Writes", "medium")
        self.assert_asked(a)                                               # medium > low
        self.override(b, auto_approve_max="medium")
        self.assert_auto(b)
        self.assertEqual(self.events("grant_skipped")[0]["reason"], "risk")

    def test_the_clients_page_shows_the_effective_ceiling(self):
        a = self.mk("alpha")
        page = t.req(self.abase + "/clients", headers={"X-authentik-username": "alice"})[1]
        self.assertIn("up to low risk; modes http, env - the global default", page)
        self.override(a, auto_approve_max="none")
        page = t.req(self.abase + "/clients", headers={"X-authentik-username": "alice"})[1]
        self.assertIn("never auto-approves (every request asks) - its own setting", page)

    def test_overrides_for_clients_that_do_not_exist_are_harmless(self):
        self.broker.clients_cfg["overrides"]["c-00000000"] = {"auto_approve_max": "none"}
        self.assert_auto(self.mk("alpha"))


# ---------------------------------------------------------------------------- SSH host rules
class SshScope(ClientMixin, sr.Base):
    ssh_hosts = sr.KNOWN

    def ask_as(self, c, data, binds=None):
        for r in self.broker._by_id.values():
            if r.status == "pending":
                r.status = "expired"
        body = {"mode": "ssh_sign", "names": ["deploy"], "flags": 0, "data_b64": base64.b64encode(data).decode()}
        if binds is not None:
            body["binds"] = binds
        code, raw = self.api("POST", "/v1/requests", body, key=c.secret)
        self.assertEqual(code, 202, raw)
        rid = json.loads(raw)["id"]
        self.keys[rid] = c.secret
        return rid

    keys = {}

    def result(self, rid, wait=5):
        # a request can only be polled by the client that made it
        return json.loads(self.api("GET", f"/v1/requests/{rid}?wait={wait}", key=self.keys.get(rid, KEY))[1])

    def login(self):
        return sr.login(sr.SID_A), [sr.HOST.bind(sr.SID_A)]

    def make_rule(self, c, **extra):
        rid = self.ask_as(c, *self.login())
        self.assertEqual(self.decide(rid, "approve_ssh_rule", extra=extra)[0], 303)
        self.assertTrue(self.released(rid))
        return rid

    def test_rule_from_a_card_defaults_to_the_requesting_client(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.make_rule(a)
        (rule,) = self.stored_rules()
        self.assertEqual(rule["client"], a.id)
        self.assertEqual(self.events("ssh_rule_created")[0]["rule_client"], a.id)
        n = self.sent()
        rid = self.ask_as(a, *self.login())
        self.assertTrue(self.released(rid))
        self.assertEqual(self.sent(), n)                                   # A: no prompt
        rid = self.ask_as(b, *self.login())
        self.assertEqual(self.r(rid).status, "pending")                    # B: asked
        rid = self.ask_as(Legacy, *self.login())
        self.assertEqual(self.r(rid).status, "pending")                    # shared key: asked

    def test_any_client_is_an_explicit_choice_and_keeps_the_old_shape(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.make_rule(a, rule_scope="any")
        (rule,) = self.stored_rules()
        self.assertNotIn("client", rule)
        self.assertEqual(set(rule), set(sshrules.RULE_KEYS) - {"client"})
        for c in (b, Legacy):
            self.assertTrue(self.released(self.ask_as(c, *self.login())))

    def test_global_and_client_rules_resolution(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        found, _ = sshrules.find([{"id": "x", "fp": sr.HOST.fp, "user": "deploy", "client": a.id, "expires_at": None},
                                  {"id": "y", "fp": sr.HOST.fp, "user": "deploy", "expires_at": None}],
                                 sr.HOST.fp, "deploy", time.time(), a.id)
        self.assertEqual(found["id"], "x")                                  # its own wins
        found, _ = sshrules.find([{"id": "x", "fp": sr.HOST.fp, "user": "deploy", "client": a.id,
                                   "expires_at": None}], sr.HOST.fp, "deploy", time.time(), b.id)
        self.assertIsNone(found)                                            # another client's: never
        found, _ = sshrules.find([{"id": "x", "fp": sr.HOST.fp, "user": "deploy", "client": a.id,
                                   "expires_at": None}], sr.HOST.fp, "deploy", time.time())
        self.assertIsNone(found)                                            # no client: only global

    def test_a_client_rule_is_a_noop_when_a_global_one_exists(self):
        a = self.mk("alpha")
        status, _ = self.broker._add_rule("deploy", sr.HOST.fp, "deploy", "web", "alice", None, ANY)
        self.assertEqual(status, "created")
        status, _ = self.broker._add_rule("deploy", sr.HOST.fp, "deploy", "web", "alice", None, a.id)
        self.assertEqual(status, "exists")
        self.assertEqual(len(self.live_rules()), 1)

    def test_old_rules_without_a_client_are_global(self):
        a = self.mk("alpha")
        rules = sshrules.parse([sr.R(sr.HOST, label="web")], "ssh_rules")
        self.assertNotIn("client", rules[0])
        self.broker.cfg["secrets"]["deploy"]["ssh_rules"] = rules
        for c in (a, Legacy):
            self.assertTrue(self.released(self.ask_as(c, *self.login())))
        self.assertEqual(sshrules.serialize(rules), rules)

    def test_revoking_a_client_removes_its_ssh_rules_only(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        self.make_rule(a)
        self.broker._add_rule("deploy", sr.OTHER.fp, "deploy", "other", "alice", None, ANY)
        self.broker._add_rule("deploy", sr.THIRD.fp, "deploy", "third", "alice", None, b.id)
        self.assertEqual(len(self.live_rules()), 3)
        self.broker.revoke_client(a.id, "alice")
        self.assertEqual(sorted(r.get("client", ANY) for r in self.live_rules()), sorted([ANY, b.id]))
        self.assertEqual(sorted(r.get("client", ANY) for r in self.stored_rules()), sorted([ANY, b.id]))
        self.assertEqual(self.events("client_revoked")[0]["rules_removed"]["ssh"], 1)

    def test_manual_add_takes_a_client_and_refuses_unknown_ones(self):
        a = self.mk("alpha")
        res = self.broker.add_ssh_rule("deploy", sr.HOST.fp, "deploy", "never", True, "alice", client=a.id)
        self.assertEqual(res["status"], "created")
        self.assertEqual(self.live_rules()[0]["client"], a.id)
        for bad in ("c-00000000", "everyone", "legacy-ish", ""):
            res = self.broker.add_ssh_rule("deploy", sr.OTHER.fp, "deploy", "never", True, "alice", client=bad)
            self.assertEqual(res["status"], "refused", bad)
        res = self.broker.add_ssh_rule("deploy", sr.OTHER.fp, "deploy", "never", True, "alice", client="legacy")
        self.assertEqual(res["status"], "created")
        res = self.broker.add_ssh_rule("deploy", sr.THIRD.fp, "deploy", "never", True, "alice", client=ANY)
        self.assertEqual(res["status"], "created")
        self.broker.revoke_client(a.id, "alice")
        self.assertEqual(self.broker.add_ssh_rule("deploy", sr.THIRD.fp, "deploy2", "never", True, "alice",
                                                  client=a.id)["status"], "refused")      # revoked: not a valid scope

    def test_policies_page_has_the_client_column_and_choice(self):
        a = self.mk("alpha")
        self.broker._add_rule("deploy", sr.HOST.fp, "deploy", "web", "alice", None, a.id)
        page = t.req(self.abase + "/policies", headers={"X-authentik-username": "alice"})[1]
        self.assertIn("<th>Account</th><th>Client</th>", page)
        self.assertIn("<td data-label=Client>alpha</td>", page)
        self.assertIn("name=client", page)
        self.assertIn("Any client (every machine)", page)
        self.assertIn(f"<option value='{a.id}'>Only alpha</option>", page)
        self.assertIn("<option value='legacy'>Only shared key (legacy)</option>", page)

    def test_manual_add_through_the_page_posts_the_client(self):
        a = self.mk("alpha")
        import urllib.request
        form = {"secret": "deploy", "host": sr.HOST.fp, "account": "deploy", "expires": "never",
                "confirm": "1", "client": a.id, "csrf": self.broker.csrf_token("alice")}
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/policies/ssh_rules/add", data=urllib.parse.urlencode(form).encode(),
            headers={"X-authentik-username": "alice"}, method="POST"), timeout=10)
        self.assertEqual(r.status, 200)
        self.assertEqual(self.live_rules()[0]["client"], a.id)

    def test_never_auto_blocks_the_clients_ssh_rules_too(self):
        a = self.mk("alpha")
        self.broker._add_rule("deploy", sr.HOST.fp, "deploy", "web", "alice", None, ANY)
        self.assertTrue(self.released(self.ask_as(a, *self.login())))
        self.broker.clients_cfg["overrides"][a.id] = {"auto_approve_max": "none"}
        self.assertEqual(self.r(self.ask_as(a, *self.login())).status, "pending")


if __name__ == "__main__":
    unittest.main()
