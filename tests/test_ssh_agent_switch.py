"""Key metadata `ssh_agent` (allow | ask | off): the switch that stops the agent-signing path for a key once a
host has moved to `asb exec`, so the exec vetting cannot be walked around.

The properties: the default (allow) is today's behavior, unchanged; `ask` sends every ssh_sign for the key to a
human and neither uses nor offers a timed grant, Always, an SSH host rule or a configuration rule; `off` refuses
ssh_sign for the key with a fixed label and audits it; the value is validated; widening it needs the editor's tick;
`exec` on the same key is unaffected by either value.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_exec_intake as ti  # noqa: E402
import test_ssh_rules as tr  # noqa: E402
from test_client_rules import ClientMixin  # noqa: E402
from test_ssh_rules import HOST, KNOWN, R, SID_A, login  # noqa: E402
from secret_broker import autorules, crededitor, sshkey  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

BIND = [HOST.bind(SID_A)]


class SwitchBase(tr.Base):
    ssh_hosts = KNOWN
    ssh_agent = None
    rules = [R(HOST, user="deploy")]
    auto_max = "high"

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.ssh_agent is not None:
            cfg["secrets"]["deploy"]["ssh_agent"] = self.ssh_agent

    def sign(self):
        return self.ask(login(SID_A), BIND)


class Allow(SwitchBase):
    """The default: nothing changes."""

    def test_a_standing_rule_still_releases_without_a_prompt(self):
        self.assertNotIn("ssh_agent", self.broker.cfg["secrets"]["deploy"].get("_meta", {}))
        code, body = self.sign()
        self.assertEqual(code, 202, body)
        self.assertEqual(self.r(body["id"]).status, "approved")
        self.assertEqual(self.sent(), 0)
        self.assertTrue(self.events("ssh_sign_refused") == [] and self.events("ssh_rule_used"))

    def test_chips_are_offered(self):
        self.rules = None
        self.broker.cfg["secrets"]["deploy"].pop("ssh_rules")
        rid = self.ask_ok(login(SID_A), BIND)
        self.assertIn("approve_ssh_rule", self.link_page(rid))


class Ask(SwitchBase):
    ssh_agent = "ask"

    def test_the_value_is_live(self):
        self.assertEqual(self.broker.cfg["secrets"]["deploy"]["ssh_agent"], "ask")

    def test_a_standing_rule_is_not_used(self):
        code, body = self.sign()
        self.assertEqual(code, 202, body)
        self.assertEqual(self.r(body["id"]).status, "pending")
        self.assertEqual(self.sent(), 1)                                    # a human is asked
        self.assertEqual(self.events("ssh_rule_used"), [])
        self.assertEqual(self.events("approved"), [])

    def test_a_configuration_rule_is_not_used(self):
        agent = ClientMixin.mk(self, "ssh-agent-box")           # a rule never matches the legacy key: enroll a client
        plain = self.api
        self.api = lambda m, p, b=None, key=None: plain(m, p, b, key=agent.secret)
        self.broker.cfg["secrets"]["deploy"].pop("ssh_rules")
        self.broker.auto_rules = autorules.parse([{"name": "cfg", "mode": "ssh_sign", "secret": "deploy",
                                                  "host": "web.example.com", "account": "deploy"}])
        code, body = self.sign()
        self.assertEqual(code, 202, body)
        self.assertEqual(self.r(body["id"]).status, "pending")
        self.assertEqual(self.events("auto_rule_used"), [])
        self.broker.cfg["secrets"]["deploy"]["ssh_agent"] = "allow"          # control: the same rule works when allowed
        code, body = self.sign()
        self.assertEqual(self.r(body["id"]).status, "approved")
        self.assertTrue(self.events("auto_rule_used"))

    def test_approval_allow_does_not_release_it(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc.pop("ssh_rules")
        sc.update(approval="allow", auto_modes=["ssh_sign"])
        code, body = self.sign()
        self.assertEqual(self.r(body["id"]).status, "pending")
        sc["ssh_agent"] = "allow"                                            # control
        code, body = self.sign()
        self.assertEqual(self.r(body["id"]).status, "approved")

    def test_an_existing_timed_grant_is_not_used(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc.pop("ssh_rules")
        sc["ssh_agent"] = "allow"
        rid = self.ask_ok(login(SID_A), BIND)
        self.assertEqual(self.decide(rid, "approve_grant_5")[0], 303)
        self.assertTrue(self.broker.active_grants())                          # the grant exists
        rid = self.ask_ok(login(SID_A), BIND)
        self.assertEqual(self.r(rid).status, "approved")                      # control: it covers the next one
        sc["ssh_agent"] = "ask"
        rid = self.ask_ok(login(SID_A), BIND)
        self.assertEqual(self.r(rid).status, "pending")

    def test_no_chip_is_offered_and_a_form_post_for_one_claims_nothing(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc.pop("ssh_rules")
        stored_before = self.stored_rules()
        rid = self.ask_ok(login(SID_A), BIND)
        card = self.link_page(rid)
        for chip in ("approve_ssh_rule", "approve_grant_", "approve_always", "Automatically approve..."):
            self.assertNotIn(chip, card, chip)
        self.assertIn("value=approve>", card)
        req = self.r(rid)
        self.assertFalse(self.broker.grant_eligibility(req)[0])
        self.assertFalse(self.broker.always_allow_eligibility(req)[0])
        self.assertIsNone(self.broker.ssh_rule_chip(req))
        for kw in ({"always": True}, {"grant_minutes": 5}, {"ssh_rule": {"days": None}}):
            code, got = self.broker.decide_via("dashboard", rid, "approve", "alice", **kw)
            self.assertIn(code, (400, 403, 409), kw)
            self.assertIsNone(got)
            self.assertEqual(req.status, "pending", kw)
        self.assertEqual(self.stored_rules(), stored_before)
        self.assertEqual(self.broker.active_grants(), [])
        code, _ = self.broker.decide_via("dashboard", rid, "approve", "alice")    # control: a plain approve
        self.assertEqual(code, 200)

    def test_a_human_can_still_approve_it_once(self):
        rid = self.ask_ok(login(SID_A), BIND)
        self.assertEqual(self.decide(rid, "approve")[0], 303)
        self.assertTrue(self.released(rid))


class Off(SwitchBase):
    ssh_agent = "off"

    def test_ssh_sign_is_refused_with_a_fixed_label_and_nothing_is_asked(self):
        code, body = self.sign()
        self.assertEqual(code, 403, body)
        self.assertEqual(json.loads(body)["error"], "ssh signing is turned off for this key")
        ev = self.events("ssh_sign_refused")[-1]
        self.assertEqual((ev["reason"], ev["names"]), ("ssh_agent_off", ["deploy"]))
        self.assertEqual(self.sent(), 0)
        self.assertEqual(self.events("requested"), [])
        self.assertEqual([r for r in self.broker._by_id.values()], [])

    def test_another_key_is_unaffected_and_so_is_switching_back(self):
        self.assertEqual(self.ask(login(SID_A), BIND, name="deploy2")[0], 202)        # control
        self.broker.cfg["secrets"]["deploy"]["ssh_agent"] = "allow"
        self.assertEqual(self.sign()[0], 202)

    def test_the_refusal_comes_before_the_host_policy(self):
        # even a login that the host policy would also refuse says why it was really refused
        code, body = self.ask(login(SID_A), [HOST.bind(b"z" * 32)])
        self.assertEqual(self.events("ssh_sign_refused")[-1]["reason"], "ssh_agent_off")


class Validation(unittest.TestCase):
    def meta(self, **kw):
        pub = sshkey.public_line(sshkey.load_private(tr.ts._openssh(tr.ed25519.Ed25519PrivateKey.generate())))
        return {"name": "k", "ssh": True, "ssh_public_key": pub, "vars": {"K": {"field": "private_key"}}, **kw}

    def test_values(self):
        for v in ("allow", "ask", "off"):
            _, e = Broker._entry("k", self.meta(ssh_agent=v))
            self.assertEqual(e["ssh_agent"], v)
        _, e = Broker._entry("k", self.meta())
        self.assertNotIn("ssh_agent", e)                                    # absent means allow

    def test_bad_values_invalidate_the_credential_naming_the_field(self):
        for v in ("deny", "", None, True, 1, ["off"], "Off"):
            with self.assertRaises(ValueError) as cm:
                Broker._entry("k", self.meta(ssh_agent=v))
            self.assertIn("ssh_agent must be one of allow, ask, off", str(cm.exception), repr(v))

    def test_only_an_ssh_key_has_it(self):
        with self.assertRaises(ValueError) as cm:
            Broker._entry("p", {"name": "p", "vars": {"P": {"field": "token"}}, "allowed_hosts": ["a.example.com"],
                                "ssh_agent": "off"})
        self.assertIn("ssh_agent only applies to an ssh key", str(cm.exception))


class Editor(unittest.TestCase):
    def test_widening_needs_the_tick_and_narrowing_does_not(self):
        base = {"ssh": True}
        for old, new, widens in (("off", "allow", True), ("ask", "allow", True), ("off", "ask", True),
                                 ("allow", "ask", False), ("allow", "off", False), ("ask", "off", False),
                                 ("allow", "allow", False)):
            got = crededitor.widened({**base, "ssh_agent": old}, {**base, "ssh_agent": new})
            self.assertEqual("ssh_agent_widened" in got, widens, (old, new))
        self.assertIn("ssh_agent_widened", crededitor.WIDEN_TEXT)
        # a key that never had the field is "allow": removing a restriction widens, adding one narrows
        self.assertIn("ssh_agent_widened", crededitor.widened({**base, "ssh_agent": "off"}, dict(base)))
        self.assertNotIn("ssh_agent_widened", crededitor.widened(dict(base), {**base, "ssh_agent": "off"}))

    def test_the_form_writes_it_only_for_an_ssh_key(self):
        old = {"ssh": True, "ssh_public_key": "x"}
        self.assertEqual(crededitor.build(old, {"ssh_agent": "off"})["ssh_agent"], "off")
        self.assertNotIn("ssh_agent", crededitor.build(old, {"ssh_agent": "allow"}))        # an untouched default is no write
        self.assertNotIn("ssh_agent", crededitor.build({"allowed_hosts": ["a.example.com"]}, {"ssh_agent": "off"}))
        with self.assertRaises(ValueError):
            crededitor.build(old, {"ssh_agent": "deny"})
        self.assertEqual(crededitor.build({**old, "ssh_agent": "off"}, {"ssh_agent": "allow"}).get("ssh_agent"), "allow")


class ExecUnaffected(ti.ExecBase):
    def test_exec_on_the_same_key_works_for_every_value(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        for value in ("allow", "ask", "off"):
            sc["ssh_agent"] = value
            for r in self.broker._by_id.values():
                r.status = "expired"
            self.assertEqual(self.ask()[0], 202, value)


if __name__ == "__main__":
    unittest.main()
