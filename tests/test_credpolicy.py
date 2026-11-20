"""The per-credential policy cards and the body of a credential's Policies sub-tab."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import html as _html  # noqa: E402
from secret_broker import autorules, credlinks, credpolicy, guidance, sshhosts, sshrules, standing, uirules  # noqa: E402

CSRF = "tok-123"
NOW = time.time()


def stored(**kw):
    return {"id": "r0001", "name": "news", "mode": "http", "host": "api.example.com", "methods": ["GET"],
            "path_prefix": "/v1", "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None, **kw}


def http_cred(**kw):
    sc = {"allowed_hosts": ["api.example.com"], "_meta": {}, "auto_rules": autorules.parse_stored([stored()], "svc"),
          "guidance": "Reads are fine"}
    sc.update(kw)
    return sc


SSH_CRED = {"ssh": True, "allowed_hosts": [], "_meta": {}}


def timed(**kw):
    return {"kind": "timed", "id": "g0000001", "secrets": ["svc"], "names": ["svc"], "mode": "http", "client": "*",
            "scope": "any", "covers": "any method", "expires_at": NOW + 300, "left_s": 300, "created_by": "alice",
            "created_at": "2026-11-18 00:00:00 UTC", **kw}


def legacy(**kw):
    return {"kind": "legacy", "id": "", "name": "svc", "secrets": ["svc"], "names": ["svc"], "mode": None,
            "client": "*", "scope": "any", "covers": "whole credential, any method", "expires_at": None,
            "left_s": None, "created_by": "alice", "created_at": ""}


def ctx(**kw):
    base = dict(csrf=CSRF, usage_ssh=sshrules.Usage(None), usage_auto=sshrules.Usage(None), client_names={},
                client_choices=[("legacy", "legacy")], standing_rows=[], config_rules=[], states={})
    base.update(kw)
    return credpolicy.PolicyCtx(**base)


class Cards(unittest.TestCase):
    def test_each_card_keeps_its_form_fields_and_names_the_credential(self):
        g = guidance.card("svc", http_cred(), CSRF)
        self.assertIn("action='/policies/guidance'", g)
        self.assertIn("name=name value='svc'", g)
        h = sshhosts.card("deploy", SSH_CRED, CSRF)
        self.assertIn("action='/policies/ssh_hosts'", h)
        self.assertIn("name=secret value='deploy'", h)
        r = sshrules.card("deploy", SSH_CRED, CSRF, sshrules.Usage(None))
        self.assertIn("action='/policies/ssh_rules/add'", r)
        self.assertIn("name=secret value='deploy'", r)
        a = uirules.card("svc", http_cred(), [], CSRF, sshrules.Usage(None))
        self.assertIn("action='/policies/auto_rules/add'", a)
        self.assertIn("name=secret value='svc'", a)

    def test_open_renders_expanded(self):
        self.assertNotIn(" open>", guidance.card("svc", http_cred(), CSRF))
        self.assertIn("gbox' open>", guidance.card("svc", http_cred(), CSRF, open_=True))
        self.assertIn(" open>", uirules.card("svc", http_cred(), [], CSRF, sshrules.Usage(None), open_=True))
        self.assertIn(" open>", sshhosts.card("deploy", SSH_CRED, CSRF, open_=True))
        self.assertIn(" open>", sshrules.card("deploy", SSH_CRED, CSRF, sshrules.Usage(None), open_=True))

    def test_cards_do_not_apply_to_the_wrong_kind(self):
        self.assertEqual(sshhosts.card("svc", http_cred(), CSRF), "")
        self.assertEqual(sshrules.card("svc", http_cred(), CSRF, sshrules.Usage(None)), "")
        # an ssh key's card holds remote-command (exec) rules only: no web, run-with-secret or session forms
        ssh_card = uirules.card("deploy", SSH_CRED, [], CSRF, sshrules.Usage(None))
        self.assertIn("Add rule for remote commands", ssh_card)
        for kind in ("value=http", "value=env", "value=http_session", "value=ws_session"):
            self.assertNotIn(kind, ssh_card)
        self.assertIn("value=http selected", uirules.card("svc", http_cred(), [], CSRF, sshrules.Usage(None)))   # control
        self.assertNotEqual(sshhosts.card("deploy", SSH_CRED, CSRF), "")                    # controls
        self.assertNotEqual(uirules.card("svc", http_cred(), [], CSRF, sshrules.Usage(None)), "")

    def test_a_config_rule_on_an_ssh_key_is_shown_read_only(self):
        cfg = autorules.parse([{"name": "cfg-ssh", "mode": "ssh_sign", "secret": "deploy",
                                "host": "web.example.com", "account": "deploy"}])
        out = credpolicy.body("deploy", dict(SSH_CRED), ctx(config_rules=cfg))
        self.assertIn("cfg-ssh", out)
        self.assertIn("sign in as deploy on web.example.com", out)
        self.assertIn("<h3>Auto-approve rules (1)", out)
        self.assertNotIn("value=http", out)                 # an ssh key takes only remote-command rules, never a web or env one
        self.assertIn("Add rule for remote commands", out)
        self.assertNotIn("Auto-approve rules", credpolicy.body("deploy", dict(SSH_CRED), ctx()))   # none, no section

    def test_a_pair_config_rule_is_marked(self):
        pair = autorules.parse([{"name": "pair", "mode": "env", "secrets": ["svc", "other"], "argv": ["echo"]}])
        one = autorules.parse([{"name": "one", "mode": "env", "secret": "svc", "argv": ["echo"]}])
        self.assertIn("covers several credentials", uirules.card("svc", http_cred(), pair, CSRF, sshrules.Usage(None)))
        self.assertNotIn("covers several credentials", uirules.card("svc", http_cred(), one, CSRF, sshrules.Usage(None)))


class Standing(unittest.TestCase):
    def test_forms_carry_the_grant_and_where_to_come_back_to(self):
        out = credpolicy.standing_card("svc", [timed()], CSRF, {})
        self.assertIn("action='/grants/revoke'", out)
        self.assertIn("name=grant value='g0000001'", out)
        self.assertIn("name=back value='svc'", out)
        self.assertIn(f"name=csrf value='{CSRF}'", out)

    def test_legacy_allow_is_a_read_only_line_with_a_settings_link(self):
        out = credpolicy.standing_card("svc", [legacy()], CSRF, {})
        self.assertIn("approval: allow", out)
        self.assertIn("href='/credentials/svc'", out)
        self.assertNotIn("/grants/revoke", out)
        self.assertNotIn("Revoke", out)

    def test_an_empty_list_says_so(self):
        self.assertIn("No standing approvals", credpolicy.standing_card("svc", [], CSRF, {}))


class Body(unittest.TestCase):
    def pos(self, html_, needle):
        self.assertIn(needle, html_)
        return html_.index(needle)

    def test_http_credential_sections_and_order(self):
        out = credpolicy.body("svc", http_cred(), ctx(standing_rows=[timed()]))
        self.assertLess(self.pos(out, "<h3>Standing approvals"), self.pos(out, "<h3>Auto-approve rules"))
        self.assertLess(self.pos(out, "<h3>Auto-approve rules"), self.pos(out, "<h3>Risk guidance"))
        self.assertNotIn("SSH host", out)

    def test_ssh_credential_sections_and_order(self):
        out = credpolicy.body("deploy", dict(SSH_CRED), ctx())
        self.assertLess(self.pos(out, "<h3>Standing approvals"), self.pos(out, "<h3>Risk guidance"))
        self.assertLess(self.pos(out, "<h3>Risk guidance"), self.pos(out, "<h3>SSH host policy"))
        self.assertLess(self.pos(out, "<h3>SSH host policy"), self.pos(out, "<h3>SSH host rules"))
        self.assertNotIn("Auto-approve rules", out)

    def test_every_value_is_escaped(self):
        evil = "<img/src=x/onerror=alert(1)>"
        sc = http_cred(guidance=evil,
                       auto_rules=autorules.parse_stored([stored(name=evil, by="<b>bob</b>")], "svc"))
        out = credpolicy.body("svc", sc, ctx(standing_rows=[timed(created_by="<i>x</i>", client="c-0a0b0c0d")],
                                             client_names={"c-0a0b0c0d": "<u>box</u>"}))
        for raw in ("<img/src", "<b>bob", "<i>x", "<u>box"):
            self.assertNotIn(raw, out)
        self.assertIn("&lt;img/src=x/onerror=alert(1)&gt;", out)
        self.assertIn("&lt;u&gt;box&lt;/u&gt;", out)                                        # the client label is shown, escaped
        self.assertIn("&lt;i&gt;x&lt;/i&gt;", out)


class Counts(unittest.TestCase):
    def test_counts_exclude_guidance_from_the_total(self):
        cfg = autorules.parse([{"name": "c", "mode": "env", "secret": "svc", "argv": ["echo"]}])
        c = credpolicy.counts("svc", http_cred(), [timed(), legacy()], cfg)
        self.assertEqual(c, {"standing": 2, "rules": 2, "ssh_rules": 0, "guidance": True, "total": 4})
        c = credpolicy.counts("svc", http_cred(guidance="", auto_rules=[]), [], [])
        self.assertEqual(c, {"standing": 0, "rules": 0, "ssh_rules": 0, "guidance": False, "total": 0})

    def test_ssh_host_rules_count_for_an_ssh_key(self):
        rules = sshrules.parse([{"id": "sr0001", "fp": "SHA256:" + "A" * 43, "user": "deploy", "host": "web",
                                 "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None},
                                {"id": "sr0002", "fp": "SHA256:" + "B" * 43, "user": "root", "host": "db",
                                 "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None}])
        cfg = autorules.parse([{"name": "c", "mode": "ssh_sign", "secret": "deploy", "host": "web.example.com",
                                "account": "deploy"}])
        c = credpolicy.counts("deploy", {"ssh": True, "ssh_rules": rules, "_meta": {}}, [timed()], cfg)
        self.assertEqual(c, {"standing": 1, "rules": 1, "ssh_rules": 2, "guidance": False, "total": 4})


class Link(unittest.TestCase):
    def test_text_labels_the_anchor_and_is_escaped(self):
        out = credlinks.link("svc", text="<Settings>")
        self.assertEqual(out, "<a class=clink href='/credentials/svc'>&lt;Settings&gt;</a>")
        self.assertEqual(credlinks.link("<x>", text="Settings"), "Settings")             # invalid name: plain label


class ConfirmHtml(unittest.TestCase):
    def test_it_is_the_plain_question_with_only_the_name_swapped_for_html(self):
        for mode, scope in (("http", "read"), ("http", "any"), ("env", "any")):
            plain = standing.confirm_text("svc", mode, scope, "low")
            self.assertEqual(standing.confirm_html("svc", mode, scope, "low"), _html.escape(plain), (mode, scope))
            linked = standing.confirm_html("<a href='x'>svc</a>", mode, scope, "low")
            self.assertIn("<a href='x'>svc</a>", linked)                                   # the name HTML goes in verbatim
            self.assertEqual(linked.replace("<a href='x'>svc</a>", "svc"), _html.escape(plain))   # and nothing else changed

    def test_everything_but_the_name_is_escaped(self):
        out = standing.confirm_html("N", "http", "read", "<low>")
        self.assertIn("rated &lt;low&gt; or lower", out)
        self.assertNotIn("<low>", out)


if __name__ == "__main__":
    unittest.main()
