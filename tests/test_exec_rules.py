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
    return {"id": "x0001", "name": "status", "mode": "exec", "host": H, "account": A, "port": 22,
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
        self.assertEqual((r["mode"], r["hosts"], r["account"], r["argv"], r["secrets"]),
                         ("exec", (H,), A, ("systemctl", "status"), frozenset({"deploy"})))

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


class RulePort(unittest.TestCase):
    def rules(self, port=None):
        kw = {} if port is None else {"port": port}
        return {"config": autorules.parse([cfg_rule(**kw)]),
                "stored": autorules.parse_stored([stored_rule(**({"port": 22} if port is None else kw))], "deploy", ssh=True)}

    def test_the_default_is_22_and_a_rule_for_22_does_not_approve_2222(self):
        for name, rules in self.rules().items():
            self.assertEqual(rules[0]["ports"], (22,), name)
            self.assertIsNotNone(find(rules, spec(port=22)), name)                    # positive control
            self.assertIsNone(find(rules, spec(port=2222)), name)

    def test_a_rule_for_another_port_approves_only_that_port(self):
        for name, rules in self.rules(2222).items():
            self.assertIsNotNone(find(rules, spec(port=2222)), name)
            self.assertIsNone(find(rules, spec(port=22)), name)
            self.assertIsNone(find(rules, spec(port=2223)), name)

    def test_a_stored_rule_with_no_port_is_a_port_22_rule(self):
        raw = stored_rule()
        del raw["port"]
        [r] = autorules.parse_stored([raw], "deploy", ssh=True)
        self.assertEqual(r["ports"], (22,))
        self.assertEqual(autorules.serialize_stored([r])[0]["port"], 22)

    def test_a_bad_port_names_the_field(self):
        for bad in (0, 65536, -1, "22", True, 22.0, None, []):
            with self.assertRaises(ValueError) as cm:
                autorules.parse([cfg_rule(port=bad)])
            self.assertIn("auto_approve[0].port", str(cm.exception), repr(bad))
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([stored_rule(port=bad)], "deploy", ssh=True)
            self.assertIn("auto_rules[0].port", str(cm.exception), repr(bad))


class RuleWords(unittest.TestCase):
    def test_hidden_and_look_alike_characters_in_a_rule_are_refused(self):
        for word in ("systemctl\u202e", "syst\u0435mctl", "a\u200bb", "caf\u00e9"):
            with self.assertRaises(ValueError) as cm:
                autorules.parse([cfg_rule(argv=[word, "status"])])
            self.assertIn("auto_approve[0].argv", str(cm.exception), word)
            with self.assertRaises(ValueError):
                autorules.parse_stored([stored_rule(argv=[word])], "deploy", ssh=True)
        self.assertEqual(len(autorules.parse([cfg_rule()])), 1)                 # positive control


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

    def test_rule_approved_runs_count_against_the_per_client_cap_while_they_run(self):
        import threading
        gate = threading.Event()
        self.broker._exec_run = lambda req: gate.wait(20) and {"exit_code": 0, "stdout": "", "stderr": "",
                                                              "truncated": False, "label": None}
        self.enable(clients=[self.agent.id], max_pending_per_client=2)
        self.settle_auto = False
        try:
            reqs = [self.ask_done(wait=False) for _ in range(2)]
            self.assertEqual([r.status for r in reqs], ["deciding", "deciding"])      # running, not pending
            code, b = self.ask()
            self.assertEqual((code, json.loads(b)["error"]), (403, "too many pending remote command requests"))
        finally:
            gate.set()
        for r in reqs:
            r.done.wait(10)
        self.assertEqual(self.ask_done().status, "approved")                          # control: room again

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

    def test_a_port_on_the_form_is_stored_and_only_that_port_is_approved(self):
        self.add(exec_port="2222", name="alt", host="port.example.com")
        [rule] = self.broker.auto_rules_of("deploy")
        self.assertEqual(rule["ports"], (2222,))
        self.assertEqual(self.events("auto_rule_created")[-1]["rule_port"], 2222)
        self.assertEqual(self.ask_done(host="port.example.com", port=2222).status, "approved")
        self.assertEqual(self.ask_done(wait=False, host="nas.example.com", port=22).status, "pending")   # a port-22 request is not covered
        self.assertEqual(self.add(exec_port="70000", name="bad")["status"], "refused")
        self.assertEqual(self.add(exec_port="", name="dflt", host="nas.example.com")["status"], "created")        # blank means 22
        self.assertEqual([r["ports"][0] for r in self.broker.auto_rules_of("deploy")], [2222, 22])

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
        self.assertIn("run on nas.example.com:22 as ryan: systemctl status ...", page)
        self.assertIn("name=xport", page)
        self.assertIn("/policies/auto_rules/revoke", page)
        self.assertNotIn("Add rule for remote commands", self.get("/credentials/svc?tab=policies")[1])

    def test_the_form_route_adds_and_revokes_on_an_ssh_key(self):
        hdr = {"X-authentik-username": "alice"}
        csrf = self.broker.csrf_token("alice")
        form = {"csrf": csrf, "secret": "deploy", "mode": "exec", "name": "status", "host": H, "account": A,
                "argv": "systemctl\nstatus", "xport": "22", "client": self.agent.id, "expires": "never", "confirm": "1"}
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


class Lists(RulesBase):
    """`host` and `port` of an exec rule may be lists; one entry is exactly the old single value."""
    LISTED = cfg_rule(host=[H, "port.example.com", "NEW.example.com"], port=[22, 2222], clients=[AGENT])

    def test_a_list_matches_exactly_the_listed_hosts_and_ports(self):
        rules = autorules.parse([self.LISTED])
        for host in (H, "port.example.com", "new.example.com"):
            for port in (22, 2222):
                self.assertIsNotNone(find(rules, spec(host=host, port=port)), (host, port))
        for host, port in (("other.example.com", 22), (H, 2223), (H, 23), ("nas.example.com.", 22), ("nas2.example.com", 22),
                           ("127.0.0.1", 22)):
            self.assertIsNone(find(rules, spec(host=host, port=port)), (host, port))
        self.assertEqual(rules[0]["hosts"], (H, "port.example.com", "new.example.com"))   # lower-cased, order kept

    def test_a_one_element_list_is_the_old_single_value(self):
        single = autorules.parse([cfg_rule()])[0]
        one = autorules.parse([cfg_rule(host=[H], port=[22])])[0]
        self.assertEqual((single["hosts"], single["ports"]), (one["hosts"], one["ports"]))
        for s in (spec(), spec(host="x.example.com"), spec(port=2222)):
            self.assertEqual(find([single], s) is not None, find([one], s) is not None)
        stored = stored_rule(host=[H], port=[22])
        [r] = autorules.parse_stored([stored], "deploy", ssh=True)
        self.assertEqual(autorules.serialize_stored([r])[0]["host"], H)             # written back as the bare value
        self.assertEqual(autorules.serialize_stored([r])[0]["port"], 22)
        [m] = autorules.parse_stored([stored_rule(host=[H, "b.example.com"], port=[22, 23])], "deploy", ssh=True)
        out = autorules.serialize_stored([m])[0]
        self.assertEqual((out["host"], out["port"]), ([H, "b.example.com"], [22, 23]))
        self.assertEqual(autorules.parse_stored([out], "deploy", ssh=True)[0]["hosts"], m["hosts"])   # round trip

    def test_duplicates_collapse_and_bad_lists_are_refused_by_field(self):
        [r] = autorules.parse([cfg_rule(host=[H, H.upper()], port=[22, 22])])
        self.assertEqual((r["hosts"], r["ports"]), ((H,), (22,)))
        too_many = [f"h{i}.example.com" for i in range(autorules.MAX_EXEC_LIST + 1)]
        for kw, field in (({"host": []}, "host"), ({"host": too_many}, "host"), ({"host": [H, 3]}, "host"),
                          ({"host": [H, "a b"]}, "host"), ({"host": [H, None]}, "host"), ({"host": {"a": 1}}, "host"),
                          ({"port": []}, "port"), ({"port": [22, 0]}, "port"), ({"port": [22, 70000]}, "port"),
                          ({"port": [22, True]}, "port"), ({"port": [22, "23"]}, "port"), ({"port": list(range(1, 22))}, "port")):
            with self.assertRaises(ValueError) as cm:
                autorules.parse([cfg_rule(**kw)])
            self.assertIn(f"auto_approve[0].{field}", str(cm.exception), kw)
        self.assertEqual(len(autorules.parse([cfg_rule(host=too_many[:-1])])), 1)      # control: exactly the cap is fine

    def test_a_listed_rule_never_approves_a_host_the_key_does_not_pin(self):
        self.broker.auto_rules = autorules.parse([cfg_rule(host=[H, "new.example.com"], port=[22, 2222],
                                                           clients=[self.agent.id])])
        self.enable(max_pending_per_client=20)
        req = self.ask_done(command="systemctl status nginx")                  # control: listed and pinned
        self.assertEqual((req.status, self.ran), ("approved", [req.id]))
        before = len(self.ran)
        for body in ({"host": "new.example.com"}, {"host": H, "port": 2222}):  # listed, but the key pins neither
            for r in self.broker._by_id.values():
                r.status = "expired"
            req = self.ask_done(wait=False, **body)
            self.assertEqual(req.status, "pending", body)
            self.assertIn("host_state", req.spec)
        self.assertEqual(len(self.ran), before)

    def test_the_form_takes_comma_separated_lists(self):
        add = lambda **kw: self.broker.add_auto_rule("deploy", {"name": "l", "mode": "exec", "account": A,   # noqa: E731
                                                                "argv": ["uptime"], "client": self.agent.id, **kw},
                                                     "never", True, "alice")
        self.assertEqual(add(host="nas.example.com, port.example.com", exec_port="22, 2222")["status"], "created")
        [rule] = self.broker.auto_rules_of("deploy")
        self.assertEqual((rule["hosts"], rule["ports"]), ((H, "port.example.com"), (22, 2222)))
        ev = self.events("auto_rule_created")[-1]
        self.assertEqual((ev["rule_host"], ev["rule_port"]), ([H, "port.example.com"], [22, 2222]))
        stored = self.broker.cfg["secrets"]["deploy"]["_meta"]["auto_rules"][0]
        self.assertEqual((stored["host"], stored["port"]), ([H, "port.example.com"], [22, 2222]))
        for name, kw in (("a", {"host": "nas.example.com,,x.example.com"}), ("b", {"host": "nas.example.com,"}),
                         ("c", {"exec_port": "22,x"}), ("d", {"exec_port": "22,,23"}), ("e", {"exec_port": "22, 70000"})):
            self.assertEqual(add(name=name, **kw)["status"], "refused", kw)
        self.assertEqual(len(self.broker.auto_rules_of("deploy")), 1)
        self.assertEqual(add(name="single", host="nas.example.com")["status"], "created")    # control
        self.assertEqual(self.broker.cfg["secrets"]["deploy"]["_meta"]["auto_rules"][1]["host"], H)   # bare value for one
        self.assertIn("nas.example.com,port.example.com:22,2222", autorules_text(self.broker))


def autorules_text(broker):
    from secret_broker import uirules
    return uirules.describe(broker.auto_rules_of("deploy")[0])


if __name__ == "__main__":
    unittest.main()
