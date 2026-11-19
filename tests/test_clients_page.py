"""The Clients tab (secret_broker/clientspage.py) and the email-shaped text on every approval page.

Part 1 scans rendered pages: an edge proxy rewrites `user@host` in HTML text into `[email protected]`, so no page may
put such text in a text node. Every scan first asserts the identity is on the page (a scan of an empty page passes).
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
import test_ssh_rules as sr  # noqa: E402
from test_emailsafe import raw_email_shapes, visible  # noqa: E402

OWNER = "ryan@example.com"


class EmailBase(tc.CBase):
    """The approval-site user is an email-shaped SSO identity, as it is behind most SSO proxies."""

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["allowed_user"] = OWNER

    def get(self, path, user=OWNER):
        return super().get(path, user=user)

    def post(self, path, form, user=OWNER, **kw):
        return super().post(path, form, user=user, **kw)


class EmailOnPages(EmailBase):
    def assert_safe(self, page, *identities):
        text = visible(page)
        for ident in identities:
            self.assertIn(ident, text, ident)                 # premise: the identity is on the page, as typed
        self.assertEqual(raw_email_shapes(page), [])
        self.assertIn("<!--email_off-->", page)               # and it went through the helper

    def test_clients_tab(self):
        self.new_client("alpha", claim="build@host-01.example")
        status, page, _ = self.get("/clients")
        self.assertEqual(status, 200)
        self.assert_safe(page, "build@host-01.example", OWNER)

    def test_enrollment_card_and_header(self):
        code, body, _s, _h = self.enr("laptop", claim="bob@laptop.example")
        self.assertEqual(code, 202)
        status, page, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("Client enrollment: laptop", page)
        self.assert_safe(page, "bob@laptop.example", OWNER)

    def test_request_card_and_history_from_line(self):
        c = self.new_client("alpha")
        code, text, _ = self.raw("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "source": "carol@workstation.example",
            "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}}, {"X-Client-Key": c["secret"]})
        self.assertEqual(code, 202, text)
        self.broker.flush_notifications(10)
        status, page, _ = self.get("/")
        self.assertEqual(status, 200)
        self.assert_safe(page, "carol@workstation.example")
        rid = json.loads(text)["id"]
        self.broker.decide_via("dashboard", rid, "deny", OWNER)
        status, frag, _ = self.get(f"/request/{rid}?fragment=1")
        self.assertEqual(status, 200)
        self.assertEqual(raw_email_shapes(frag), [])

    def test_the_signed_in_identity_in_the_header_of_any_page(self):
        status, page, _ = self.get("/settings")
        self.assertEqual(status, 200)
        self.assert_safe(page, OWNER)


class EmailOnSshPages(sr.Base):
    """The SSH rule chip names `account@server`; the card, the dashboard and the credential's Policies page show it."""
    ssh_hosts = sr.KNOWN

    def test_chip_on_card_and_dashboard(self):
        rid = self.ask_ok(sr.login(sr.SID_A), [sr.HOST.bind(sr.SID_A)])
        for page in (self.link_page(rid), self.dashboard()):
            text = visible(page)
            self.assertIn("Always approve deploy@web.example.com with this key?", text)
            self.assertEqual(raw_email_shapes(page), [])

    def test_ssh_rule_in_the_request_detail(self):
        rid = self.ask_ok(sr.login(sr.SID_A), [sr.HOST.bind(sr.SID_A)])
        self.assertEqual(self.decide(rid, "approve_ssh_rule")[0], 303)
        self.assertTrue(self.released(rid))
        rid2 = self.ask_ok(sr.login(sr.SID_A), [sr.HOST.bind(sr.SID_A)])
        self.assertTrue(self.released(rid2))                   # auto-approved by the rule
        status, frag = sr.t.req(self.abase + f"/request/{rid2}?fragment=1", headers=self.H)[:2]
        self.assertEqual(status, 200)
        self.assertIn("standing SSH rule (auto-approved)", frag)
        self.assertIn("deploy@web.example.com", visible(frag))
        self.assertEqual(raw_email_shapes(frag), [])


if __name__ == "__main__":
    unittest.main()
