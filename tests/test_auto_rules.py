"""`auto_approve` rules in the broker config: requests that match one are released without a human.

The properties: strict parsing (a typo is an error, human-only modes are refused at load); a rule matches only
on facts the broker verified; it approves at any risk and whatever the secret's `approval` says; it never
reaches a client set to never auto-approve or the legacy shared key; everything that does not match prompts
exactly as before; and the audit log records the rule's name, which the agent never sees.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
import test_ssh_host as th  # noqa: E402
from secret_broker import audit_api, autorules  # noqa: E402
from test_client_rules import ClientMixin  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this

FP = "SHA256:" + "A" * 43


class Enrolled(ClientMixin):
    """Requests are made by an enrolled client named `box`; the harness's default key is the legacy shared key,
    which no rule ever matches."""

    def setUp(self):
        super().setUp()
        self.client = self.mk("box")

    def api(self, method, path, body=None, key=None):
        return super().api(method, path, body, key=key or self.client.secret)

    def get(self, path, user="alice"):
        return t.req(self.abase + path, headers={"X-authentik-username": user})


def ssh_rule(**kw):
    return {"name": "r", "mode": "ssh_sign", "secret": "deploy", "host": "web.example.com", "account": "deploy", **kw}


BOX = "c-0a0b0c0d"


class Parse(unittest.TestCase):
    def test_nothing_means_no_rules(self):
        self.assertEqual(autorules.parse(None), [])
        self.assertEqual(autorules.parse([]), [])

    def test_a_full_set_parses(self):
        rules = autorules.parse([
            ssh_rule(clients=[BOX]),
            {"name": "h", "mode": "http", "secrets": ["a", "b"], "host": "API.Example.com", "methods": ["GET"],
             "path_prefix": "/v1"},
            {"name": "e", "mode": "env", "secret": "svc", "argv": ["python3", "send.py"]},
            {"name": "by fp", "mode": "ssh_sign", "secret": "deploy", "host_fp": FP, "account": "ryan"}])
        self.assertEqual([r["mode"] for r in rules], ["ssh_sign", "http", "env", "ssh_sign"])
        self.assertEqual(rules[1]["host"], "api.example.com")
        self.assertEqual(rules[1]["methods"], frozenset({"GET"}))

    def test_http_defaults_to_reads(self):
        r = autorules.parse([{"name": "h", "mode": "http", "secret": "a", "host": "h.example.com"}])[0]
        self.assertEqual(r["methods"], frozenset({"GET", "HEAD"}))
        self.assertEqual(r["path_prefix"], "/")

    def test_human_only_modes_are_refused_at_load(self):
        for mode in ("sudo", "credential", "guidance", "plan", "session", "store"):
            with self.assertRaises(ValueError) as cm:
                autorules.parse([{"name": "x", "mode": mode, "secret": "a"}])
            self.assertIn("always needs a human", str(cm.exception), mode)
        with self.assertRaises(ValueError):
            autorules.parse([{"name": "x", "mode": "nonsense", "secret": "a"}])

    def test_every_mistake_is_an_error_naming_the_field(self):
        bad = {
            "not a list": ("auto_approve", {"name": "x"}),
            "not an object": ("auto_approve[0]", ["x"]),
            "no name": ("auto_approve[0].name", {"mode": "env", "secret": "a", "argv": ["x"]}),
            "client by name": ("auto_approve[0].clients", {"name": "x", "mode": "env", "secret": "a", "argv": ["x"],
                                                          "clients": ["sheridan-dev-box"]}),
            "http bad scheme": ("auto_approve[0].scheme", {"name": "x", "mode": "http", "secret": "a",
                                                           "host": "h.example.com", "scheme": "ftp"}),
            "unknown key": ("auto_approve[0].path", {"name": "x", "mode": "env", "secret": "a", "argv": ["x"],
                                                     "path": "/"}),
            "both secret forms": ("auto_approve[0]", {"name": "x", "mode": "env", "secret": "a", "secrets": ["a"],
                                                      "argv": ["x"]}),
            "no secret": ("auto_approve[0]", {"name": "x", "mode": "env", "argv": ["x"]}),
            "empty argv": ("auto_approve[0].argv", {"name": "x", "mode": "env", "secret": "a", "argv": []}),
            "argv not strings": ("auto_approve[0].argv", {"name": "x", "mode": "env", "secret": "a", "argv": [1]}),
            "ssh no account": ("auto_approve[0].account", {"name": "x", "mode": "ssh_sign", "secret": "a",
                                                           "host": "h.example.com"}),
            "ssh no server": ("auto_approve[0]", {"name": "x", "mode": "ssh_sign", "secret": "a", "account": "u"}),
            "ssh both servers": ("auto_approve[0]", {"name": "x", "mode": "ssh_sign", "secret": "a", "account": "u",
                                                     "host": "h.example.com", "host_fp": FP}),
            "ssh bad fp": ("auto_approve[0].host_fp", {"name": "x", "mode": "ssh_sign", "secret": "a",
                                                       "account": "u", "host_fp": "SHA256:short"}),
            "http no host": ("auto_approve[0].host", {"name": "x", "mode": "http", "secret": "a"}),
            "http host with scheme": ("auto_approve[0].host", {"name": "x", "mode": "http", "secret": "a",
                                                               "host": "https://h.example.com"}),
            "http lower-case method": ("auto_approve[0].methods", {"name": "x", "mode": "http", "secret": "a",
                                                                   "host": "h.example.com", "methods": ["get"]}),
            "http dotdot": ("auto_approve[0].path_prefix", {"name": "x", "mode": "http", "secret": "a",
                                                            "host": "h.example.com", "path_prefix": "/a/../b"}),
            "http relative prefix": ("auto_approve[0].path_prefix", {"name": "x", "mode": "http", "secret": "a",
                                                                     "host": "h.example.com", "path_prefix": "a"}),
        }
        for label, (where, rule) in bad.items():
            with self.assertRaises(ValueError, msg=label) as cm:
                autorules.parse(rule if label == "not a list" else [rule])
            self.assertIn(where, str(cm.exception), label)

    def test_names_must_be_unique(self):
        r = {"name": "same", "mode": "env", "secret": "a", "argv": ["x"]}
        with self.assertRaises(ValueError):
            autorules.parse([r, dict(r, name="SAME")])


class Match(unittest.TestCase):
    CLIENT = {"id": BOX, "name": "box", "legacy": False}

    def rules(self, *r):
        return autorules.parse(list(r))

    def test_http_matches_host_method_and_path_prefix_exactly(self):
        rules = self.rules({"name": "h", "mode": "http", "secret": "a", "host": "api.example.com",
                            "methods": ["GET", "POST"], "path_prefix": "/v1"})
        find = lambda method, url, names=("a",), **spec: autorules.find(  # noqa: E731
            rules, "http", list(names), {"method": method, "url": url, **spec}, self.CLIENT)
        self.assertIsNotNone(find("GET", "https://API.example.com/v1"))
        self.assertIsNotNone(find("POST", "https://api.example.com/v1/things?x=1"))
        self.assertIsNone(find("DELETE", "https://api.example.com/v1/things"))
        self.assertIsNone(find("GET", "https://api.example.com/v10"))          # not a path-segment prefix
        self.assertIsNone(find("GET", "https://api.example.com/v1/../admin"))
        self.assertIsNone(find("GET", "https://api.example.com/v1/%2e%2e/admin"))
        self.assertIsNone(find("GET", "https://api.example.com/v1/a%2fb"))        # any escape: the plain path only
        self.assertIsNone(find("GET", "https://api.example.com/v1;x=1/y"))
        self.assertIsNone(find("GET", "https://api.example.com/v1/./y"))
        self.assertIsNone(find("GET", "https://api.example.com/v1\\..\\admin"))
        self.assertIsNone(find("GET", "http://api.example.com/v1"))               # plain http: the rule says https
        self.assertIsNone(find("POST", "https://api.example.com/v1", headers={"X-HTTP-Method-Override": "DELETE"}))
        self.assertIsNone(find("POST", "https://api.example.com/v1?_method=DELETE"))
        self.assertIsNone(find("POST", "https://api.example.com/v1?a=1;_method=DELETE"))
        self.assertIsNone(find("POST", "https://api.example.com/v1?%5Fmethod=DELETE"))
        self.assertIsNone(find("POST", "https://api.example.com/v1", body="a=1&_method=DELETE"))
        self.assertIsNone(find("POST", "https://api.example.com/v1", body='{"_method": "DELETE"}'))
        self.assertIsNone(find("POST", "https://api.example.com/v1", body_b64="X21ldGhvZD1ERUxFVEU="))   # _method=DELETE
        self.assertIsNone(find("POST", "https://api.example.com/v1", body_b64="***not base64***"))
        for h in ("X-Original-URL", "X-Rewrite-URL", "x-forwarded-path", "X-Forwarded-Method"):
            self.assertIsNone(find("POST", "https://api.example.com/v1", headers={h: "/admin"}), h)
        self.assertIsNone(find("POST", "https://api.example.com/v1", body='{"\\u005fmethod": "DELETE"}'))   # JSON escape
        self.assertIsNone(find("POST", "https://api.example.com/v1", body="%255fmethod=DELETE"))          # double encoding
        self.assertIsNone(find("POST", "https://api.example.com/v1?%255fmethod=DELETE"))
        self.assertIsNone(find("POST", "https://api.example.com/v1", body="caf\u00e9"))                    # not plain ASCII
        self.assertIsNone(find("POST", "https://api.example.com/v1", headers={"Content-Encoding": "gzip"}, body="x"))
        self.assertIsNotNone(find("POST", "https://api.example.com/v1?q=a%20b", body="a=1&b=2"))   # ordinary escapes are fine
        self.assertIsNone(find("GET", "https://api.example.com/v1", body="x"))    # a read with a body is not a read
        self.assertIsNotNone(find("POST", "https://api.example.com/v1", body="x"))
        self.assertIsNone(find("GET", "https://other.example.com/v1"))
        self.assertIsNone(find("GET", "https://api.example.com.evil.net/v1"))
        self.assertIsNone(find("GET", "https://api.example.com/v1", names=("a", "b")))   # b is not covered
        self.assertIsNone(autorules.find(rules, "env", ["a"], {"argv": ["x"]}, self.CLIENT))   # wrong mode

    def test_env_needs_the_exact_argv_and_readable_scripts(self):
        rules = self.rules({"name": "e", "mode": "env", "secret": "a", "argv": ["echo", "hi"]})
        find = lambda argv, **kw: autorules.find(rules, "env", ["a"], {"argv": argv, **kw}, self.CLIENT)  # noqa: E731
        self.assertIsNotNone(find(["echo", "hi"]))
        self.assertIsNone(find(["echo", "hi", "there"]))
        self.assertIsNone(find(["echo"]))
        self.assertIsNone(find(["echo", "hi;", "rm"]))

    def test_a_request_for_several_secrets_needs_a_rule_that_covers_all_of_them(self):
        both = self.rules({"name": "both", "mode": "env", "secrets": ["a", "b"], "argv": ["echo"]})
        one = self.rules({"name": "one", "mode": "env", "secret": "a", "argv": ["echo"]})
        spec = {"argv": ["echo"]}
        self.assertIsNotNone(autorules.find(both, "env", ["a", "b"], spec, self.CLIENT))
        self.assertIsNotNone(autorules.find(both, "env", ["b", "a"], spec, self.CLIENT))     # order does not matter
        self.assertIsNotNone(autorules.find(both, "env", ["a"], spec, self.CLIENT))          # fewer is still covered
        self.assertIsNone(autorules.find(one, "env", ["a", "b"], spec, self.CLIENT))         # b is not covered
        self.assertIsNone(autorules.find(both, "env", ["a", "b", "c"], spec, self.CLIENT))   # neither is c

    def test_clients_limit_a_rule_and_the_legacy_key_never_matches(self):
        spec = {"argv": ["echo"]}
        open_rule = self.rules({"name": "e", "mode": "env", "secret": "a", "argv": ["echo"]})
        scoped = self.rules({"name": "e", "mode": "env", "secret": "a", "argv": ["echo"],
                             "clients": [BOX, "c-99999999"]})
        legacy = {"id": "legacy", "name": "legacy", "legacy": True}
        self.assertIsNotNone(autorules.find(open_rule, "env", ["a"], spec, self.CLIENT))
        self.assertIsNone(autorules.find(open_rule, "env", ["a"], spec, legacy))
        self.assertIsNotNone(autorules.find(scoped, "env", ["a"], spec, self.CLIENT))
        self.assertIsNotNone(autorules.find(scoped, "env", ["a"], spec,
                                            {"id": "c-99999999", "name": "z", "legacy": False}))
        self.assertIsNone(autorules.find(scoped, "env", ["a"], spec,
                                         {"id": "c-22222222", "name": "box", "legacy": False}))   # same name, other id
        self.assertIsNone(autorules.find(scoped, "env", ["a"], spec, legacy))


class SshRules(Enrolled, th.HostBase):
    host = th.Host()
    ssh_hosts = {"known_hosts": [host.line("web.example.com,10.0.0.5")]}
    rules = [ssh_rule()]

    def setUp(self):
        super().setUp()
        self.broker.auto_rules = autorules.parse(self.rules)

    def login(self, user="deploy", host=None, forwarding=False):
        host = host or self.host
        return self.sign(th.hostbound(th.SID_A, host, user=user), [host.bind(th.SID_A, forwarding=forwarding)])

    def test_a_matching_login_is_approved_without_anyone(self):
        code, body = self.login()
        self.assertEqual(code, 202)
        rid = json.loads(body)["id"]
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
        self.assertEqual(json.loads(b)["status"], "approved")
        self.assertEqual(self.notifier.sent, [])
        ap = self.events("approved")[-1]
        self.assertEqual((ap["via"], ap["decision_source"], ap["rule_name"]), ("policy", "config_rule", "r"))
        self.assertEqual(self.events("auto_rule_used")[-1]["rule_name"], "r")

    def test_the_history_says_which_rule_decided(self):
        code, body = self.login()
        rid = json.loads(body)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=3")
        row, _ = self.broker.history.detail(rid)
        self.assertEqual((row["outcome"], row["rule_name"]), ("auto-approved", "r"))
        page = self.get(f"/request/{rid}?fragment=1")[1]
        self.assertIn("configuration rule \"r\" (auto-approved)", page)
        self.assertIn("Log in to web.example.com (10.0.0.5) as &#x27;deploy&#x27;", page)     # the readable headline

    def test_another_account_another_host_or_a_forwarded_login_still_prompts(self):
        other = th.Host()
        for label, make in {
                "account": lambda: self.login(user="root"),
                "host": lambda: self.login(host=other),
                "forwarded": lambda: self.login(forwarding=True)}.items():
            code, body = make()
            if code != 202:
                continue                # refused outright (e.g. forwarding policy) is also fine
            rid = json.loads(body)["id"]
            self.assertEqual(self.result_status(rid), "pending", label)
        self.assertEqual(self.events("approved"), [])

    def result_status(self, rid):
        return json.loads(self.api("GET", f"/v1/requests/{rid}?wait=0")[1])["status"]

    def test_a_login_with_no_verified_server_never_matches(self):
        code, body = self.sign(th.login(th.SID_A))          # no bind, no host key in the data
        self.assertEqual(code, 202)
        self.assertEqual(self.result_status(json.loads(body)["id"]), "pending")

    def test_the_legacy_shared_key_never_matches_a_rule(self):
        for r in self.broker._by_id.values():
            r.status = "expired"
        body = {"mode": "ssh_sign", "names": ["deploy"], "flags": 0,
                "data_b64": base64.b64encode(th.hostbound(th.SID_A, self.host)).decode(),
                "binds": [self.host.bind(th.SID_A)]}
        code, out = self.api("POST", "/v1/requests", body, key=t.KEY)
        self.assertEqual(code, 202, out)
        _, b = self.api("GET", f"/v1/requests/{json.loads(out)['id']}?wait=0", key=t.KEY)
        self.assertEqual(json.loads(b)["status"], "pending")
        self.assertEqual(self.events("auto_rule_used"), [])

    def test_a_client_set_to_never_auto_approve_still_prompts(self):
        self.broker.client_never_auto = lambda cid: True
        code, body = self.login()
        self.assertEqual(self.result_status(json.loads(body)["id"]), "pending")
        self.assertEqual(self.events("auto_rule_used"), [])


class SshRulesByFingerprint(SshRules):
    rules = [{"name": "r", "mode": "ssh_sign", "secret": "deploy", "host_fp": SshRules.host.fp, "account": "deploy"}]


class SshRuleForAnotherSecret(SshRules):
    rules = [ssh_rule(secret="someone-else")]

    def test_a_matching_login_is_approved_without_anyone(self):
        code, body = self.login()
        self.assertEqual(self.result_status(json.loads(body)["id"]), "pending")

    test_the_history_says_which_rule_decided = None


class HttpRules(Enrolled, t.Harness):
    def setUp(self):
        super().setUp()
        self.port = self.up.server_address[1]
        self.broker.auto_rules = autorules.parse([
            {"name": "reads", "mode": "http", "secret": "svc", "scheme": "http", "host": "127.0.0.1",
             "path_prefix": "/x", "clients": [self.client.id]}])

    def call(self, method="GET", path="/x"):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": method, "url": f"http://127.0.0.1:{self.port}{path}",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_a_matching_call_runs_without_a_prompt_even_at_high_risk(self):
        self.broker.summarizer = t._Stub("Reads a thing", "high")
        rid = self.call()
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        self.assertEqual(json.loads(b)["http"]["status"], 200)
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("approved")[-1]["rule_name"], "reads")

    def test_a_call_outside_the_rule_prompts(self):
        for method, path in (("POST", "/x"), ("GET", "/y"), ("GET", "/xy")):
            self.call(method, path)
        self.assertEqual(len(self.notifier.sent), 3)             # a human was asked each time
        self.assertEqual(self.events("auto_rule_used"), [])
        self.assertTrue(all(e["via"] == "user" for e in self.events("approved")))


class EnvRules(Enrolled, t.Harness):
    def setUp(self):
        super().setUp()
        self.broker.auto_rules = autorules.parse([
            {"name": "greet", "mode": "env", "secret": "svc", "argv": ["echo", "hi"]}])

    def env(self, argv):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": argv})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_the_exact_command_is_released_and_a_variant_prompts(self):
        rid = self.env(["echo", "hi"])
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
        self.assertEqual(json.loads(b)["env"], {"SVC_TOKEN": t.SECRET})
        self.assertEqual(self.notifier.sent, [])
        self.env(["echo", "hi", "there"])
        self.assertEqual(len(self.notifier.sent), 1)


class MultiSecretRules(Enrolled, tg.Base):
    """A request that names two credentials (a script that needs both) is approved by one rule listing both."""

    def env(self, names):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": names, "argv": ["echo", "hi"]})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_one_rule_covers_the_pair_and_nothing_wider(self):
        self.broker.auto_rules = autorules.parse([
            {"name": "pair", "mode": "env", "secrets": ["svc", "other"], "argv": ["echo", "hi"]}])
        rid = self.env(["svc", "other"])
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
        self.assertEqual(sorted(json.loads(b)["env"]), ["OTHER_TOKEN", "SVC_TOKEN"])
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("approved")[-1]["rule_name"], "pair")

    def test_a_rule_for_one_of_them_does_not_cover_the_pair(self):
        self.broker.auto_rules = autorules.parse([
            {"name": "just svc", "mode": "env", "secret": "svc", "argv": ["echo", "hi"]}])
        self.env(["svc", "other"])
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("auto_rule_used"), [])


class AgentCannotSeeRules(unittest.TestCase):
    def test_rule_fields_are_not_in_what_the_audit_api_shows(self):
        shown = {k for spec in audit_api.WHITELIST.values() for k in spec}
        for field in ("rule_name", "decision_source"):
            self.assertNotIn(field, shown)
        self.assertNotIn("auto_rule_used", audit_api.WHITELIST)


if __name__ == "__main__":
    unittest.main()
