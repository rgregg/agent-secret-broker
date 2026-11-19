"""The Clients tab (secret_broker/clientspage.py) and the email-shaped text on every approval page.

Part 1 scans rendered pages: an edge proxy rewrites `user@host` in HTML text into `[email protected]`, so no page may
put such text in a text node. Every scan first asserts the identity is on the page (a scan of an empty page passes).
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import html as htmlmod
import json
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
import test_client_rules as tcr  # noqa: E402
from secret_broker import autorules, clients as clients_mod  # noqa: E402
import test_ssh_rules as sr  # noqa: E402
from _pagetext import raw_email_shapes, visible  # noqa: E402

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


def rows_of(page):
    """{client name: the row's <li> html} for the compact list (not its dialogs)."""
    out = {}
    for m in re.finditer(r"<li class='crow [^']*' id='cl-[^']*'>.*?</li>", page, re.S):
        out[re.search(r"class=cname[^>]*>([^<]*)<", m.group(0)).group(1)] = m.group(0)
    return out


def dialog(page, did):
    m = re.search(r"<dialog id='%s'.*?</dialog>" % re.escape(did), page, re.S)
    return m.group(0) if m else None


def text_of(markup):
    return htmlmod.unescape(re.sub(r"<[^>]*>", "", markup))


class Layout(tc.CBase):
    def setUp(self):
        super().setUp()
        self.ca = self.new_client("alpha", claim="build@host-01.example")
        self.cb = self.new_client("bravo")

    def page(self):
        status, page, _ = self.get("/clients")
        self.assertEqual(status, 200)
        return page

    def test_one_compact_row_per_client_and_the_rest_is_in_dialogs(self):
        page = self.page()
        rows = rows_of(page)
        self.assertEqual(sorted(rows), ["alpha", "bravo", "shared key (legacy)"])        # premise: all three rows found
        for name, row in rows.items():
            for detail in ("unverified", "approved by", "Enrolled", "Effective ceiling", "type=text", "host-01"):
                self.assertNotIn(detail, row, (name, detail))
            self.assertIn("seen", row)                                                    # last seen
            self.assertIn("version unknown", row)                                          # version (none sent yet)
            self.assertIn("class=cnt", row)                                                # the one-glance rules count
        self.assertNotIn("<details", page.split("<ul class=cl-list>")[1].split("</ul>")[0])   # no tiny expander
        det = text_of(dialog(page, "cd-" + self.ca["id"]))
        for want in ("build@host-01.example", "unverified", "approved by", "Effective ceiling", self.ca["id"]):
            self.assertIn(want, det, want)

    def test_the_list_renders_without_script_and_dialogs_open_by_target(self):
        page = self.page()
        row = rows_of(page)["alpha"]
        for part in ("href='#cd-", "href='#cr-", "href='#cn-", "href='#cv-"):
            self.assertIn(part, row)                                                      # real links: they work with no JS
        for did in ("cd-", "cr-", "cn-", "cv-"):
            self.assertIsNotNone(dialog(page, did + self.ca["id"]), did)
        self.assertIn("dialog.cdlg:target", page)                                         # shown in place without script
        self.assertIn("showModal", page)                                                  # and modal with it

    def test_every_icon_has_an_accessible_name_and_a_focus_state(self):
        page = self.page()
        ctl = re.findall(r"<(?:a|button) class='ib[^']*'[^>]*>", page)
        self.assertGreaterEqual(len(ctl), 9)                                              # premise: controls were found
        for tag in ctl:
            self.assertRegex(tag, r"aria-label='[^']{4,}'", tag)
            self.assertRegex(tag, r"title='[^']{4,}'", tag)
        imgs = re.findall(r"<span class='cx[^']*'[^>]*>", page)
        self.assertGreaterEqual(len(imgs), 3)
        for tag in imgs:
            self.assertIn("role=img", tag)
            self.assertRegex(tag, r"aria-label='[^']{3,}'")
        self.assertNotIn("<svg viewBox='0 0 24 24'>", page)                               # every svg is hidden from readers
        self.assertRegex(page, r"\.ib:focus-visible[^{]*\{outline:")
        self.assertIn("var(--accent)", page)                                              # theme variables

    def test_status_icons_follow_the_state(self):
        self.post("/clients/disable", {"id": self.ca["id"]})
        self.post("/clients/revoke", {"id": self.cb["id"]})
        page = self.page()
        rows = rows_of(page)
        self.assertIn("aria-label='Disabled", rows["alpha"])
        self.assertIn("st-disabled", rows["alpha"])
        self.assertIn("aria-label='Revoked'", rows["bravo"])
        self.assertIn("aria-label='Allowed (shared key)'", rows["shared key (legacy)"])
        # a disabled row offers enable, an active one disable, a revoked one only removal
        self.assertIn("action='/clients/enable'", rows["alpha"])
        self.assertNotIn("action='/clients/disable'", rows["alpha"])
        self.assertIn("action='/clients/remove'", rows["bravo"])
        for gone in ("/clients/enable", "/clients/disable", "href='#cn-", "href='#cv-"):
            self.assertNotIn(gone, rows["bravo"], gone)
        self.assertIsNone(dialog(page, "cn-" + self.cb["id"]))
        self.assertIsNone(dialog(page, "cv-" + self.cb["id"]))

    def test_legacy_row_has_no_state_controls(self):
        row = rows_of(self.page())["shared key (legacy)"]
        for gone in ("/clients/", "href='#cn-", "href='#cv-"):
            self.assertNotIn(gone, row)
        self.assertIn("href='#cr-legacy'", row)

    def test_rename_is_a_dialog_not_an_always_visible_box(self):
        page = self.page()
        self.assertNotIn("name=name", "".join(rows_of(page).values()))
        d = dialog(page, "cn-" + self.ca["id"])
        self.assertIn("action='/clients/rename'", d)
        self.assertRegex(d, r"<input id='rn-c-[0-9a-f]{8}' type=text name=name value='alpha' maxlength=32 required")
        self.assertIn(self.broker.csrf_token("alice"), d)
        self.assertIn("aria-label='Rename alpha'", rows_of(page)["alpha"])
        status, _, hdr = self.post("/clients/rename", {"id": self.ca["id"], "name": "alpha-2"})
        self.assertIn("note=renamed", hdr["Location"])
        self.assertIn("alpha-2", rows_of(self.page()))

    def test_revoke_asks_for_confirmation_in_a_dialog(self):
        page = self.page()
        d = dialog(page, "cv-" + self.ca["id"])
        self.assertIn("action='/clients/revoke'", d)
        self.assertIn("cannot be undone", d)
        self.assertNotIn("action='/clients/revoke'", rows_of(page)["alpha"])               # the row never revokes in one click

    def test_dialog_script_gives_focus_escape_and_return(self):
        page = self.page()
        js = "".join(re.findall(r"<script[^>]*>(.*?)</script>", page, re.S))
        for needle in ("showModal", "data-autofocus", "opener.focus()", "'close'", "data-dclose"):
            self.assertIn(needle, js, needle)
        scripts = re.findall(r"<script[^>]*>", page)
        self.assertGreaterEqual(len(scripts), 2)
        for tag in scripts:
            self.assertRegex(tag, r"^<script nonce='[^']+'>$")                            # only nonced scripts run

    def test_pending_enrollment_is_flagged_on_the_tab_and_has_its_icon_on_the_card(self):
        code, body, _s, _h = self.enr("gamma", claim="g@h")
        self.assertEqual(code, 202)
        self.assertRegex(self.page(), r"aria-label='Enrollment waiting'.*?1 enrollment is waiting")
        status, home, _ = self.get("/")
        self.assertIn("aria-label='Enrollment pending'", home)
        self.assertIn("Client enrollment: gamma", home)

    def test_active_plans_stay_below_the_list(self):
        page = self.page()
        self.assertIn("Active plans", page)
        self.assertLess(page.index("cl-list"), page.index("Active plans"))

    def test_version_is_shown_and_an_old_one_is_flagged(self):
        newest = clients_mod.LATEST_CLIENT_VERSION
        self.raw("GET", "/v1/status", headers={"X-Client-Key": self.ca["secret"], "User-Agent": f"asb/{newest} (+x)"})
        self.raw("GET", "/v1/status", headers={"X-Client-Key": self.cb["secret"], "User-Agent": "asb/1.0 (+x)"})
        rows = rows_of(self.page())
        self.assertIn(f"asb {newest}", rows["alpha"])
        self.assertNotIn("Upgrade recommended", rows["alpha"])
        self.assertIn("asb 1.0", rows["bravo"])
        self.assertIn("aria-label='Upgrade recommended", rows["bravo"])
        self.assertIn("version unknown", rows["shared key (legacy)"])
        self.assertNotIn("Upgrade recommended", rows["shared key (legacy)"])               # unknown is never flagged

    def test_min_version_config_moves_the_threshold(self):
        self.raw("GET", "/v1/status", headers={"X-Client-Key": self.ca["secret"], "User-Agent": "asb/1.1"})
        self.assertNotIn("Upgrade recommended", rows_of(self.page())["alpha"])
        self.broker.clients.cfg["min_version"] = "1.5"
        self.assertIn("Upgrade recommended", rows_of(self.page())["alpha"])
        self.broker.clients.cfg["min_version"] = "none"
        self.assertNotIn("Upgrade recommended", rows_of(self.page())["alpha"])

    def test_client_chosen_text_is_escaped(self):
        # a claim cannot hold markup (validated), and a source is shown only inside the details dialog, escaped
        det = dialog(self.page(), "cd-" + self.ca["id"])
        self.assertNotIn("<script", det)
        self.assertIn("<code>" + self.ca["id"] + "</code>", det)


class RulesDialog(tcr.ClientMixin, tc.CBase):
    def test_lists_every_kind_of_rule_with_links_and_revokes_through_the_existing_endpoints(self):
        a = tc.CBase.new_client(self, "alpha")
        b = tc.CBase.new_client(self, "bravo")
        cid = a["id"]
        self.broker._add_always("svc", "http", "read", "alice", client=cid)
        self.broker._add_always("other", "http", "read", "alice", client=b["id"])         # another client's rule
        self.assertEqual(self.broker.add_ssh_rule("deploy", tcr.sr.HOST.fp, "deploy", "never", True, "alice",
                                                  client=cid)["status"], "created")
        self.broker.auto_rules = autorules.parse([{"name": "cfgrule", "mode": "http", "secret": "other",
                                                   "host": "api.example.com", "methods": ["GET"], "clients": [cid]}])
        plan = {"id": "p1234567", "client_id": cid, "names": ["svc"], "uses": 1, "uses_max": 3, "left_s": 600,
                "task": "t", "client_name": "alpha", "expires_at": 0, "state": "active"}
        with mock.patch.object(self.broker, "active_plans", return_value=[plan]):
            page = self.get("/clients")[1]
        d = dialog(page, "cr-" + cid)
        self.assertIsNotNone(d)
        rule_items = re.findall(r"<li class=rrow>.*?</li>", d, re.S)
        kinds = [re.search(r"class=rkind>([^<]*)<", li).group(1) for li in rule_items]
        self.assertEqual(sorted(kinds), ["Always approval", "Auto-approve rule (configuration)", "Plan", "SSH host rule"])
        self.assertIn("<a class=clink href='/credentials/svc?tab=policies'>svc</a>", d)    # credential names link (credlinks)
        self.assertIn("<a class=clink href='/credentials/deploy?tab=policies'>deploy</a>", d)
        row = rows_of(page)["alpha"]
        self.assertRegex(row, r"<span class=cnt>4</span>")
        self.assertIn("aria-label='4 rules for alpha: view'", row)
        # each revocable rule posts to an existing endpoint with the CSRF token and returns to the tab
        self.assertEqual(sorted(re.findall(r"action='([^']+)'", d)),
                         ["/grants/revoke", "/plans/revoke", "/policies/ssh_rules/revoke"])
        for li in rule_items:
            if "(configuration)" in li:
                self.assertNotIn("<form", li)
                self.assertIn("set in the configuration file", li)
            else:
                self.assertIn(self.broker.csrf_token("alice"), li)
                self.assertIn("aria-label='Revoke", li)
        grant = re.search(r"action='/grants/revoke'.*?name='grant' value='([^']+)'", d, re.S).group(1)
        ssh = re.search(r"action='/policies/ssh_rules/revoke'.*?name='rule' value='([^']+)'", d, re.S).group(1)
        self.assertIn("name='back' value='clients'", d)
        status, _, hdr = self.post("/grants/revoke", {"grant": grant, "back": "clients"})
        self.assertEqual((status, hdr["Location"]), (303, "/clients?note=rulerevoked"))
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("standing") or [], [])
        status, _, hdr = self.post("/policies/ssh_rules/revoke", {"secret": "deploy", "rule": ssh, "back": "clients"})
        self.assertEqual((status, hdr["Location"]), (303, "/clients?note=rulerevoked"))
        self.assertEqual(self.broker.cfg["secrets"]["deploy"].get("ssh_rules") or [], [])
        self.assertEqual(self.post("/grants/revoke", {"grant": grant, "back": "clients"})[2]["Location"],
                         "/clients?note=rulegone")
        # the other client's rule is untouched, and the guards stay on
        self.assertEqual(len(self.broker.cfg["secrets"]["other"]["standing"]), 1)
        for path, form in (("/grants/revoke", {"grant": "x", "back": "clients"}),
                           ("/policies/ssh_rules/revoke", {"secret": "deploy", "rule": ssh, "back": "clients"})):
            self.assertEqual(self.post(path, form, csrf=False)[0], 403, path)
            self.assertEqual(self.post(path, form, user="mallory")[0], 403, path)

    def test_a_rule_of_another_client_or_for_any_client_is_not_listed(self):
        a = tc.CBase.new_client(self, "alpha")
        b = tc.CBase.new_client(self, "bravo")
        self.broker._add_always("svc", "http", "read", "alice", client="*")
        self.broker._add_always("other", "http", "read", "alice", client=b["id"])
        page = self.get("/clients")[1]
        self.assertIn("No rules of its own", dialog(page, "cr-" + a["id"]))
        self.assertRegex(rows_of(page)["alpha"], r"<span class=cnt>0</span>")
        self.assertIn("aria-label='No rules of its own for alpha'", rows_of(page)["alpha"])
        self.assertRegex(rows_of(page)["bravo"], r"<span class=cnt>1</span>")
        self.assertIn("/credentials/other", dialog(page, "cr-" + b["id"]))


if __name__ == "__main__":
    unittest.main()
