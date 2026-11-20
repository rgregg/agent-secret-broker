"""Auto-approve rules for `exec`: the shared matcher (config rules and rules stored on the ssh key), the
properties that a rule never matches a script or shell syntax, never crosses credentials, and that stored
rules need the confirmation tick and honor expiry and revocation.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_exec_intake as ti  # noqa: E402
from test_exec_intake import _OMIT, SSH_HOSTS  # noqa: E402
from test_ssh import _openssh  # noqa: E402
from secret_broker import autorules, sshkey  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

AGENT = "c-1a2b3c4d"
H, A = "nas.example.com", "ryan"
AT = "2026-11-18T00:00:00Z"


def cfg_rule(**kw):
    return {"name": "status", "mode": "exec", "secret": "deploy", "host": H, "account": A,
            "argv": ["systemctl", "status"], **kw}


def stored_rule(**kw):
    return {"id": "x0001", "name": "status", "mode": "exec", "host": H, "account": A,
            "argv": ["systemctl", "status"], "by": "alice", "at": AT, "expires_at": None, **kw}


def spec(command="systemctl status nginx", host=H, user=A, **kw):
    s = {"host": host, "user": user, "port": 22, "timeout_s": 60, **kw}
    if "script" not in kw:
        s["command"] = command
    return s


CLIENT = {"id": AGENT, "name": "agent", "legacy": False}


def find(rules, s, names=("deploy",), client=CLIENT):
    return autorules.find(rules, "exec", list(names), s, client)


class Parse(unittest.TestCase):
    def test_config_rule(self):
        [r] = autorules.parse([cfg_rule(host="NAS.Example.com")])
        self.assertEqual((r["mode"], r["host"], r["account"], r["argv"], r["secrets"]),
                         ("exec", H, A, ("systemctl", "status"), frozenset({"deploy"})))

    def test_bad_rules_name_the_field(self):
        for kw, field in (({"host": "a b"}, "host"), ({"host": None}, "host"), ({"account": "-x"}, "account"),
                          ({"account": ""}, "account"), ({"argv": []}, "argv"), ({"argv": [""]}, "argv"),
                          ({"argv": "ls"}, "argv"), ({"argv": ["a", 3]}, "argv"), ({"secrets": ["a"]}, "secrets"),
                          ({"methods": ["GET"]}, "methods"), ({"path_prefix": "/"}, "path_prefix")):
            raw = cfg_rule(**kw)
            if "secrets" in kw:
                del raw["secret"]
            with self.assertRaises(ValueError) as cm:
                autorules.parse([raw])
            self.assertIn(f"auto_approve[0].{field}", str(cm.exception), kw)
        self.assertEqual(len(autorules.parse([cfg_rule()])), 1)             # positive control

    def test_stored_round_trip_and_where_it_may_live(self):
        raw = [stored_rule(clients=[AGENT], expires_at="2099-01-01T00:00:00Z")]
        rules = autorules.parse_stored(raw, "deploy", ssh=True)
        self.assertEqual(autorules.serialize_stored(rules), raw)
        with self.assertRaises(ValueError) as cm:                           # not on a credential that is not an ssh key
            autorules.parse_stored(raw, "svc", ssh=False)
        self.assertIn("auto_rules[0].mode", str(cm.exception))
        with self.assertRaises(ValueError) as cm:                           # an ssh key holds nothing else
            autorules.parse_stored([{"id": "r0001", "name": "n", "mode": "http", "host": "a.example.com",
                                     "by": "a", "at": AT}], "deploy", ssh=True)
        self.assertIn("auto_rules[0].mode", str(cm.exception))

    def test_a_malformed_stored_rule_invalidates_the_credential_naming_the_field(self):
        pub = sshkey.public_line(sshkey.load_private(_openssh(ed25519.Ed25519PrivateKey.generate())))
        meta = {"name": "k", "ssh": True, "ssh_public_key": pub, "vars": {"K": {"field": "private_key"}}}
        Broker._entry("k", {**meta, "auto_rules": [stored_rule()]})         # positive control
        for bad, field in (({"argv": []}, "argv"), ({"host": "a b"}, "host"), ({"account": 5}, "account")):
            with self.assertRaises(ValueError) as cm:
                Broker._entry("k", {**meta, "auto_rules": [stored_rule(**bad)]})
            self.assertIn(f"auto_rules[0].{field}", str(cm.exception))
        with self.assertRaises(ValueError):                                 # exec rules on a plain credential
            Broker._entry("p", {"name": "p", "vars": {"P": {"field": "token"}}, "allowed_hosts": ["a.example.com"],
                                "auto_rules": [stored_rule()]})


class Matcher(unittest.TestCase):
    """One table, run over the config form and the stored form of the same rule."""

    def both(self):
        return {"config": autorules.parse([cfg_rule()]),
                "stored": autorules.parse_stored([stored_rule()], "deploy", ssh=True)}

    def test_prefix_match_and_non_match(self):
        cases = [("systemctl status nginx", True), ("systemctl status", True), ("systemctl status -l nginx", True),
                 ("systemctl  status   'nginx'", True), ("systemctl restart nginx", False), ("systemctl", False),
                 ("systemctl statusx", False), ("/usr/bin/systemctl status x", False), ("echo systemctl status", False),
                 # shell syntax never matches, even with the right words in front
                 ("systemctl status; reboot", False), ("systemctl status nginx | sh", False),
                 ("systemctl status $(id)", False), ("systemctl status `id`", False), ("systemctl status *", False),
                 ("systemctl status\nreboot", False), ("systemctl status 'a b", False), ("FOO=1 systemctl status x", False)]
        for name, rules in self.both().items():
            for cmd, want in cases:
                self.assertEqual(find(rules, spec(cmd)) is not None, want, (name, cmd))

    def test_a_script_never_matches(self):
        for name, rules in self.both().items():
            self.assertIsNotNone(find(rules, spec()), name)                  # control: the command form matches
            self.assertIsNone(find(rules, spec(script={"text": "systemctl status nginx", "interpreter": "sh"})), name)

    def test_host_account_client_and_legacy(self):
        for name, rules in self.both().items():
            self.assertIsNotNone(find(rules, spec()), name)
            self.assertIsNone(find(rules, spec(host="other.example.com")), name)
            self.assertIsNone(find(rules, spec(user="root")), name)
            self.assertIsNone(find(rules, spec(user="Ryan")), name)
            self.assertIsNone(find(rules, spec(), client={"id": AGENT, "name": "legacy", "legacy": True}), name)
        scoped = autorules.parse([cfg_rule(clients=[AGENT])])
        self.assertIsNotNone(find(scoped, spec()))
        self.assertIsNone(find(scoped, spec(), client={"id": "c-00000000", "name": "o", "legacy": False}))

    def test_a_rule_on_one_credential_never_approves_another(self):
        for name, rules in self.both().items():
            self.assertIsNotNone(find(rules, spec(), names=("deploy",)), name)
            self.assertIsNone(find(rules, spec(), names=("deploy2",)), name)
            self.assertIsNone(find(rules, spec(), names=("deploy", "deploy2")), name)

    def test_other_modes_never_match_an_exec_rule(self):
        rules = autorules.parse([cfg_rule()])
        for mode in ("http", "env", "ssh_sign"):
            self.assertIsNone(autorules.find(rules, mode, ["deploy"], spec(), CLIENT), mode)

    def test_expired_stored_rule_never_matches(self):
        past = autorules.parse_stored([stored_rule(expires_at="2020-01-01T00:00:00Z")], "deploy", ssh=True)
        live = autorules.parse_stored([stored_rule(expires_at="2099-01-01T00:00:00Z")], "deploy", ssh=True)
        self.assertIsNotNone(find(live, spec()))
        self.assertIsNone(find(past, spec()))


class RulesBase(ti.ExecBase):
    def tweak(self, cfg):
        super().tweak(cfg)
        pem = _openssh(ed25519.Ed25519PrivateKey.generate())
        cfg["_vault"]["Deploykey2"] = {"private_key": pem}
        cfg["secrets"]["deploy2"] = {
            "vars": {"DEPLOY2_SSH_KEY": {"item": "Deploykey2", "field": "private_key"}},
            "allowed_hosts": [], "ssh": True, "ssh_hosts": SSH_HOSTS,
            "ssh_public_key": sshkey.public_line(sshkey.load_private(pem))}

    def setUp(self):
        super().setUp()
        self.broker.auto_rules = autorules.parse([cfg_rule(clients=[self.agent.id])])

    def ask_done(self, wait=True, **body):
        body.setdefault("command", "systemctl status nginx")
        code, b = self.ask(**body)
        self.assertEqual(code, 202, b)
        req = self.broker._by_id[json.loads(b)["id"]]
        if wait and req.auto:
            req.done.wait(10)
        return req


class ConfigRules(RulesBase):
    def test_a_matching_command_is_released_without_a_prompt(self):
        req = self.ask_done(command="systemctl status nginx")
        self.assertEqual(self.ran, [req.id])
        self.assertEqual(self.notifier.sent, [])
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["source"], used["rule_name"], used["id"]), ("config", "status", req.id))
        fin = self.events("approved")[-1]
        self.assertEqual((fin["via"], fin["decision_source"]), ("policy", "config_rule"))

    def test_the_rule_does_not_lower_what_it_does_not_match(self):
        before = len(self.ran)
        for body in ({"command": "systemctl restart nginx"}, {"command": "systemctl status nginx; reboot"},
                     {"command": _OMIT, "script": {"text": "systemctl status nginx"}}, {"user": "root", "port": 22},
                     {"host": "127.0.0.1"}):
            for r in self.broker._by_id.values():
                r.status = "expired"
            req = self.ask_done(wait=False, **body)
            self.assertEqual(req.status, "pending", body)                   # a human is asked instead
        self.assertEqual(len(self.ran), before)
        self.assertEqual(self.events("auto_rule_used"), [])

    def test_a_rule_on_one_key_does_not_approve_the_other(self):
        req = self.ask_done(names=["deploy2"], wait=False)
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.ran, [])
        self.assertEqual(self.ask_done(names=["deploy"]).status, "approved")        # control

    def test_a_client_set_to_never_auto_approve_still_prompts(self):
        self.assertEqual(self.ask_done().status, "approved")                         # control: the rule applies
        self.assertEqual(len(self.ran), 1)
        self.broker.client_never_auto = lambda cid: True
        req = self.ask_done(wait=False)
        self.assertEqual(req.status, "pending")
        self.assertEqual(len(self.ran), 1)

    def test_a_rule_for_another_client_does_not_apply(self):
        self.enable(clients=[self.agent.id, self.other.id])
        req = self.ask_done(wait=False, c=self.other)
        self.assertEqual(req.status, "pending")
        self.assertEqual(self.ask_done().status, "approved")                         # control: the named client


class StoredRules(RulesBase):
    def setUp(self):
        super().setUp()
        self.broker.auto_rules = []

    def add(self, confirm=True, expiry="never", **kw):
        fields = {"name": "status", "mode": "exec", "host": H, "account": A, "argv": ["systemctl", "status"],
                  "client": self.agent.id, **kw}
        return self.broker.add_auto_rule("deploy", fields, expiry, confirm, "alice")

    def test_needs_the_confirmation_tick(self):
        res = self.add(confirm=False)
        self.assertEqual(res["status"], "refused")
        self.assertIn("Tick the box", res["message"])
        self.assertEqual(self.broker.auto_rules_of("deploy"), [])
        self.assertEqual(self.events("auto_rule_refused")[-1]["reason"], "not_confirmed")
        self.assertEqual(self.add()["status"], "created")                           # control

    def test_a_stored_rule_releases_a_matching_command_and_is_audited(self):
        rid = self.add()["rule_id"]
        self.assertEqual(self.events("auto_rule_created")[-1]["rule_mode"], "exec")
        req = self.ask_done(command="systemctl status nginx")
        self.assertEqual(self.ran, [req.id])
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["source"], used["rule_id"]), ("ui", rid))
        self.assertEqual(self.events("approved")[-1]["decision_source"], "ui_rule")
        self.assertEqual(self.broker.auto_rule_usage.get("deploy", rid)["uses"], 1)

    def test_it_survives_a_reload_of_the_catalog(self):
        self.add()
        self.broker._refresh_if(0)
        self.assertEqual([r["name"] for r in self.broker.auto_rules_of("deploy")], ["status"])
        self.assertEqual(self.ask_done().status, "approved")

    def test_expiry_stops_it_matching(self):
        self.add(expiry="30")
        self.assertEqual(self.ask_done().status, "approved")
        self.offset = 31 * 86400
        req = self.ask_done(wait=False)
        self.assertEqual(req.status, "pending")

    def test_revoke_stops_it(self):
        rid = self.add()["rule_id"]
        self.assertEqual(self.broker.revoke_auto_rule("deploy", rid, "alice"), "revoked")
        self.assertEqual(self.ask_done(wait=False).status, "pending")
        self.assertEqual(self.broker.revoke_auto_rule("deploy", rid, "alice"), "missing")

    def test_a_rule_on_one_key_does_not_approve_the_other(self):
        self.add()
        self.assertEqual(self.ask_done(names=["deploy2"], wait=False).status, "pending")
        self.assertEqual(self.ran, [])

    def test_bad_input_is_refused_with_a_fixed_message_that_does_not_echo_it(self):
        for kw in ({"argv": []}, {"host": "a b"}, {"account": "-x"}, {"name": ""}):
            res = self.add(**{**kw, "name": kw.get("name", "S3CR3T-n"), "argv": kw.get("argv", ["S3CR3T-w"])})
            self.assertEqual(res["status"], "refused", kw)
            self.assertNotIn("S3CR3T", res["message"])
        self.assertEqual(self.broker.auto_rules_of("deploy"), [])

    def test_kinds_are_not_interchangeable(self):
        with self.assertRaises(ValueError):                                          # http rule on an ssh key
            self.broker.add_auto_rule("deploy", {"name": "n", "mode": "http", "host": "a.example.com",
                                                 "methods": ["GET"]}, "never", True, "alice")
        with self.assertRaises(ValueError):                                          # exec rule on a plain credential
            self.broker.add_auto_rule("svc", {"name": "n", "mode": "exec", "host": H, "account": A,
                                              "argv": ["x"]}, "never", True, "alice")
        self.assertEqual(self.broker.auto_rules_of("svc"), [])

    def test_the_ssh_keys_policies_page_lists_and_offers_exec_rules_and_a_plain_credential_does_not(self):
        page = self.get("/credentials/deploy?tab=policies")[1]
        self.assertIn("Add rule for remote commands", page)                 # the form is there with no rule yet
        self.assertIn("No rules", page)
        self.add()
        page = self.get("/credentials/deploy?tab=policies")[1]
        self.assertIn("run on nas.example.com as ryan: systemctl status ...", page)
        self.assertIn("/policies/auto_rules/revoke", page)
        self.assertNotIn("Add rule for remote commands", self.get("/credentials/svc?tab=policies")[1])

    def test_the_form_route_adds_and_revokes_on_an_ssh_key(self):
        hdr = {"X-authentik-username": "alice"}
        csrf = self.broker.csrf_token("alice")
        form = {"csrf": csrf, "secret": "deploy", "mode": "exec", "name": "status", "host": H, "account": A,
                "argv": "systemctl\nstatus", "client": self.agent.id, "expires": "never", "confirm": "1"}
        r = urllib.request.Request(self.abase + "/policies/auto_rules/add", data=urllib.parse.urlencode(form).encode(),
                                   headers=hdr, method="POST")
        self.assertEqual(urllib.request.urlopen(r, timeout=10).status, 200)
        [rule] = self.broker.auto_rules_of("deploy")
        self.assertEqual((rule["mode"], rule["argv"]), ("exec", ("systemctl", "status")))
        bad = urllib.request.Request(self.abase + "/policies/auto_rules/add", method="POST", headers=hdr,
                                     data=urllib.parse.urlencode({**form, "mode": "http"}).encode())
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(bad, timeout=10)
        self.assertEqual(cm.exception.code, 400)
        form_r = urllib.parse.urlencode({"csrf": csrf, "secret": "deploy", "rule": rule["id"]}).encode()
        r = urllib.request.Request(self.abase + "/policies/auto_rules/revoke", data=form_r, headers=hdr, method="POST")
        self.assertEqual(urllib.request.urlopen(r, timeout=10).status, 200)
        self.assertEqual(self.broker.auto_rules_of("deploy"), [])


if __name__ == "__main__":
    unittest.main()
