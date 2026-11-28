"""Timed grants for remote commands (`exec`): "approve for N minutes" from a pinned command's card.

An exec grant is pinned to the key, the host, the port, the account and the client scope of the command it was made
from, and it carries that command's risk level as its ceiling: a later command is covered while it is rated at or
below it, and asks again when it is rated higher. A host the key does not pin (new or changed) is never covered.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_exec_intake as ti  # noqa: E402
from secret_broker import broker as broker_mod  # noqa: E402
from secret_broker import grants as grants_mod  # noqa: E402

RESTART = "systemctl restart nginx"     # not on the read-only table: the model rates it


class ExecGrantBase(ti.ExecBase):
    def setUp(self):
        super().setUp()
        self.enable(max_pending_per_client=20)

    def granted(self, risk="medium", minutes=15, command=RESTART, **body):
        """A pinned command rated `risk`, approved with a timed grant. Returns the grant."""
        self.model.risk = risk
        rid = self.pending(command=command, **body)
        req = self.broker._by_id[rid]
        code, _ = self.broker.decide_via("dashboard", rid, "approve", "alice", grant_minutes=minutes)
        self.assertEqual(code, 200)
        self.assertTrue(req.done.wait(10))
        self.assertEqual(self.ran, [rid])
        [g] = [g for g in self.broker.active_grants() if g["mode"] == "exec"]
        return g

    def later(self, risk="medium", command=RESTART, c=None, **body):
        """A later command: the request once its host check and any policy have acted."""
        self.model.risk = risk
        code, b = self.ask(c=c, command=command, **body)
        self.assertEqual(code, 202, b)
        req = self.broker._by_id[json.loads(b)["id"]]
        if req.auto:
            self.assertTrue(req.done.wait(10))
        return req


class Coverage(ExecGrantBase):
    def test_the_grant_is_pinned_to_host_port_account_and_the_approved_risk(self):
        g = self.granted("medium")
        self.assertEqual((g["target"], g["max_risk"], g["client"], g["scope"]),
                         (["nas.example.com", 22, "ryan"], "medium", self.agent.id, "any"))
        made = self.events("grant_created")[-1]
        self.assertEqual((made["grant_target"], made["grant_max_risk"]), (["nas.example.com", 22, "ryan"], "medium"))

    def test_a_command_rated_the_same_or_lower_is_approved_without_asking(self):
        self.granted("medium")
        sent = len(self.notifier.sent)
        for risk, command in (("medium", "systemctl reload nginx"), ("low", "uptime"), ("low", "ls /tmp")):
            req = self.later(risk, command)
            self.assertEqual(req.status, "approved", command)
            self.assertIn(req.id, self.ran)
        self.assertEqual(len(self.notifier.sent), sent)                 # nobody was asked
        used = self.events("grant_used")[-1]
        self.assertEqual(used["kind"], "timed")

    def test_a_command_rated_higher_asks_again(self):
        self.granted("medium")
        req = self.later("high", "rm -rf /var/lib/app")
        self.assertEqual(req.status, "pending")
        self.assertNotIn(req.id, self.ran)
        skip = self.events("grant_skipped")[-1]
        self.assertEqual((skip["reason"], skip["risk_level"], skip["max_risk"]), ("risk", "high", "medium"))
        self.assertEqual(self.later("medium").status, "approved")       # control: the grant still stands

    def test_a_command_with_no_model_verdict_counts_as_high(self):
        self.granted("medium")
        self.assertEqual(self.later(None, "systemctl stop nginx").status, "pending")

    def test_a_low_grant_does_not_cover_medium(self):
        self.granted("low", command="uptime")
        self.assertEqual(self.later("medium").status, "pending")
        self.assertEqual(self.later("low", "df -h").status, "approved")

    def test_another_host_port_or_account_asks(self):
        self.granted("medium")
        for body in ({"user": "root"}, {"host": "127.0.0.1"}, {"host": "port.example.com", "port": 2222}):
            req = self.later("low", "uptime", **body)
            self.assertEqual(req.status, "pending", body)
            req.status = "expired"                                      # keep under the broker's pending cap
        self.assertEqual(self.later("low", "uptime", host="NAS.example.com").status, "approved")  # same host, any case

    def test_another_key_asks(self):
        sc = dict(self.broker.cfg["secrets"]["deploy"])
        self.broker.cfg["secrets"]["deploy2"] = sc
        self.granted("medium")
        self.assertEqual(self.later("low", "uptime", names=["deploy2"]).status, "pending")

    def test_another_client_asks_unless_the_grant_was_for_any_client(self):
        self.enable(clients=[self.agent.id, self.other.id], max_pending_per_client=20)
        self.granted("medium")
        self.assertEqual(self.later("low", "uptime", c=self.other).status, "pending")
        for g in self.broker.active_grants():
            self.broker.grants.revoke(g["id"])
        self.model.risk = "medium"
        rid = self.pending(command=RESTART)
        self.broker.decide_via("dashboard", rid, "approve", "alice", grant_minutes=15, rule_scope="any")
        self.broker._by_id[rid].done.wait(10)
        self.assertEqual(self.later("low", "uptime", c=self.other).status, "approved")

    def test_a_changed_host_key_is_never_covered(self):
        self.granted("medium")
        self.servers.table[("nas.example.com", 22)] = ti.FRESH
        req = self.later("low", "uptime")
        self.assertEqual(req.status, "pending")
        self.assertEqual(req.spec.get("host_state"), "changed")
        self.assertNotIn(req.id, self.ran)

    def test_a_grant_never_covers_another_mode_and_another_modes_grant_never_covers_exec(self):
        g = self.granted("medium")
        self.assertFalse(grants_mod.covers(g, "ssh_sign", {}))
        self.assertFalse(grants_mod.covers(g, "http", {"method": "GET"}))
        self.broker.grants.add(["deploy"], 15, "any", "alice", "dashboard", "x", mode="ssh_sign", client=self.agent.id)
        for gg in self.broker.active_grants():
            if gg["mode"] == "exec":
                self.broker.grants.revoke(gg["id"])
        self.assertEqual(self.later("low", "uptime").status, "pending")

    def test_revoke_and_expiry_end_it(self):
        g = self.granted("medium")
        self.broker.revoke_grant(g["id"], "alice")
        self.assertEqual(self.later("low", "uptime").status, "pending")
        for r in self.broker._by_id.values():
            r.status = "expired"
        self.ran.clear()
        self.granted("medium")
        self.offset += 16 * 60
        self.assertEqual(self.later("low", "uptime").status, "pending")

    def test_a_client_set_to_never_auto_approve_still_prompts(self):
        self.granted("medium")
        self.broker.client_never_auto = lambda cid: True
        self.assertEqual(self.later("low", "uptime").status, "pending")

    def test_the_operator_ceiling_caps_the_grant(self):
        self.broker.grants_cfg = {**self.broker.grants_cfg, "max_risk": "low"}
        g = self.granted("high", command="rm -rf /tmp/x")
        self.assertEqual(g["max_risk"], "low")
        self.assertEqual(self.later("medium").status, "pending")
        self.assertEqual(self.later("low", "uptime").status, "approved")


class Refusals(ExecGrantBase):
    def test_an_unpinned_host_cannot_make_one_and_the_decision_claims_nothing(self):
        rid = self.pending(host="nas.example.com", port=2200)
        req = self.broker._by_id[rid]
        self.assertEqual(req.spec.get("host_state"), "new")
        self.assertFalse(self.broker.grant_eligibility(req)[0])
        code, got = self.broker.decide_via("dashboard", rid, "approve", "alice", grant_minutes=15)
        self.assertEqual((code, got), (400, None))
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.broker.active_grants(), [])

    def test_a_plain_approve_makes_none_and_token_channels_cannot_make_one(self):
        for ch in ("push", "ha", "telegram"):
            self.assertFalse(broker_mod.CHANNELS[ch].may_create_grant, ch)
        self.model.risk = "medium"
        rid = self.pending(command=RESTART)
        code, _ = self.broker.decide_via("dashboard", rid, "approve", "alice")
        self.assertEqual(code, 200)
        self.assertEqual(self.broker.active_grants(), [])

    def test_always_is_still_refused(self):
        self.model.risk = "low"
        rid = self.pending(command=RESTART)
        code, got = self.broker.decide_via("dashboard", rid, "approve", "alice", always=True, grant_minutes=15)
        self.assertEqual((code, got), (400, None))
        self.assertEqual(self.broker._by_id[rid].status, "pending")


class CardAndPages(ExecGrantBase):
    def test_the_card_chip_makes_the_grant_and_the_policies_page_lists_it(self):
        self.model.risk = "medium"
        rid = self.pending(command=RESTART)
        card = self.get(f"/a/{self.broker._by_id[rid].nonce}")[1]
        self.assertIn("approve_grant_15", card)
        self.assertIn("rated <b>MEDIUM</b> or lower", card)
        self.decide(rid, "approve_grant_15")
        self.assertTrue(self.broker._by_id[rid].done.wait(10))
        [g] = self.broker.active_grants()
        self.assertEqual(g["max_risk"], "medium")
        rows = [r for r in self.broker.standing_rows() if r["kind"] == "timed"]
        self.assertEqual(rows[0]["covers"], "remote commands on ryan@nas.example.com rated medium or lower")


class Persistence(ExecGrantBase):
    def test_saved_apart_so_an_older_broker_drops_it_and_reloaded_intact(self):
        g = self.granted("medium")
        path = self.broker.grants._path
        data = json.load(open(path))
        self.assertEqual([x["id"] for x in data["exec_grants"]], [g["id"]])
        self.assertEqual(data["grants"] + data["client_grants"], [])     # nothing an older broker would read
        fresh = grants_mod.GrantStore(path, lambda *a, **k: None)
        fresh.load()
        [back] = fresh.active()
        self.assertEqual((back["target"], back["max_risk"], back["mode"]), (g["target"], "medium", "exec"))

    def test_a_malformed_exec_entry_is_skipped(self):
        g = self.granted("medium")
        path = self.broker.grants._path
        data = json.load(open(path))
        for bad in ({"max_risk": "none"}, {"target": ["nas.example.com", 22]}, {"target": None}, {"scope": "read"},
                    {"target": ["", 22, "ryan"]}, {"target": ["h", True, "ryan"]}):
            data["exec_grants"] = [{**data["exec_grants"][0], **bad}]
            with open(path, "w") as f:
                json.dump(data, f)
            logged = []
            fresh = grants_mod.GrantStore(path, lambda n, **k: logged.append(n))
            fresh.load()
            self.assertEqual(fresh.active(), [], bad)
            self.assertIn("grants_file_corrupt", logged, bad)
        self.assertTrue(g)


if __name__ == "__main__":
    unittest.main()
