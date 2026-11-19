"""The credential Settings page after the editor rework: values edited in place, a per-value multi-line toggle,
collapsible TLS / Approval / WebSocket sections, and Rename / Delete / Remove in pop-over dialogs."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import html
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_credential_values as tv  # noqa: E402
from secret_broker import crededitor  # noqa: E402

SENT = crededitor.SENTINEL
FP_A, FP_B = "sha256:" + "ab" * 32, "sha256:" + "cd" * 32


class Base(tv.Base):
    decision = None

    def page(self, name="svc"):
        code, body = self.get(f"/credentials/{name}")
        self.assertEqual(code, 200)
        return body

    def section(self, body, title):
        """The `<details class=cfold>` block whose summary starts with `title`."""
        m = re.search(r"<details class=cfold[^>]*>\s*<summary><span class=ft>" + re.escape(title) + r"</span>.*?</details>",
                      body, re.S)
        self.assertIsNotNone(m, f"no section {title}")
        return m.group(0)


class InPlaceValues(Base):
    def test_each_value_is_one_password_input_showing_the_sentinel_and_never_the_value(self):
        body = self.page()
        self.assertRegex(body, r"<input type=password name=value id='val-SVC_TOKEN' form='sv-SVC_TOKEN' "
                               r"value='" + SENT + "'")
        self.assertIn("form='sv-SVC_TOKEN'", body)
        self.assertNotIn(t.SECRET, body)                                  # nothing but a reveal may carry it
        self.assertNotIn("Replace the value", body)                       # no separate box to type into
        self.assertNotIn("placeholder='new value'", body)
        self.assertIn("action='/credentials/svc/value'", body)
        self.assertIn("action='/credentials/svc/reveal'", body)           # Show keeps the reveal flow

    def test_the_sentinel_is_a_non_ascii_marker_a_value_cannot_be_confused_with(self):
        self.assertNotEqual(SENT.encode("ascii", "ignore").decode(), SENT)
        self.assertRegex(SENT, r"^•+$")

    def test_posting_the_sentinel_changes_nothing(self):
        before = json.dumps(self.broker.backend._data["Svc"], sort_keys=True)
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=SENT)
        self.assertEqual(code, 200)
        self.assertIn("No change: SVC_TOKEN", body)                         # positive control: the page answered
        self.assertEqual(json.dumps(self.broker.backend._data["Svc"], sort_keys=True), before)
        self.assertNotIn("previous_value", self.broker.backend._data["Svc"])
        self.assertEqual(self.events("credential_value_changed"), [])

    def test_posting_the_sentinel_in_the_multi_line_box_changes_nothing_either(self):
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value="", value_ml=SENT)
        self.assertEqual(code, 200)
        self.assertIn("No change: SVC_TOKEN", body)
        self.assertEqual(self.vault("Svc", "token"), t.SECRET)

    def test_saving_the_value_that_is_already_stored_is_no_change_and_keeps_no_previous_copy(self):
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=t.SECRET)
        self.assertEqual(code, 200)
        self.assertIn("No change: SVC_TOKEN", body)
        self.assertNotIn("previous_value", self.broker.backend._data["Svc"])
        self.assertEqual(self.events("credential_value_changed"), [])
        self.assertNotIn(t.SECRET, body)

    def test_typing_a_new_value_replaces_it_and_keeps_the_previous_one(self):
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=tv.NEW_VALUE)
        self.assertEqual(code, 200)
        self.assertIn("Value replaced: SVC_TOKEN", body)
        self.assertEqual(self.vault("Svc", "token"), tv.NEW_VALUE)
        self.assertEqual(self.vault("Svc", "previous_value"), t.SECRET)
        self.assertEqual(len(self.events("credential_value_changed")), 1)
        self.assertNotIn(tv.NEW_VALUE, body)

    def test_show_without_script_puts_the_value_in_the_same_input_escaped(self):
        tricky = "S3CR3T-'<b>x</b></script>"
        self.broker.backend.put("Svc", "token", tricky)
        code, hdr, body = self.raw_post("/credentials/svc/reveal", var="SVC_TOKEN")
        self.assertEqual(code, 200)
        self.assertEqual(hdr["Cache-Control"], "no-store")
        esc = "S3CR3T-&#x27;&lt;b&gt;x&lt;/b&gt;&lt;/script&gt;"
        self.assertEqual(body.count(esc), 1)
        self.assertRegex(body, r"<input type=text name=value id='val-SVC_TOKEN' form='sv-SVC_TOKEN' value='"
                         + re.escape(esc) + "'")
        self.assertNotIn(tricky, body)
        self.assertNotIn("<textarea readonly", body)

    def test_show_without_script_uses_a_textarea_for_a_value_with_newlines(self):
        pem = "-----BEGIN KEY-----\nS3CR3T-line-one\n-----END KEY-----\n"
        self.broker.backend.put("Svc", "token", pem)
        code, _, body = self.raw_post("/credentials/svc/reveal", var="SVC_TOKEN")
        self.assertEqual(code, 200)
        self.assertRegex(body, r"<textarea name=value_ml id='ml-SVC_TOKEN' form='sv-SVC_TOKEN' [^>]*>\n"
                               r"-----BEGIN KEY-----\nS3CR3T-line-one\n")
        self.assertIn("S3CR3T-line-one", body)                            # exactly one place carries it

    def test_the_sentinel_never_becomes_a_stored_value_via_add(self):
        code, _, body = self.raw_post("/credentials/svc/value/add", var="SVC_X", value=SENT,
                                      old_sha=self.sha("svc"), confirm="1")
        self.assertEqual(code, 400)
        self.assertIn(self.broker._VALUE_TEXT["placeholder"], body)
        self.assertNotIn("SVC_X", self.stored()["vars"])
        self.assertNotIn("SVC_X", self.broker.backend._data["Svc"])


class MultiLineToggle(Base):
    def test_there_is_no_always_present_multi_line_box(self):
        body = self.page()
        self.assertEqual(body.count("<textarea name=value_ml"), 2)        # one per value box (svc has 1) + Add
        for ta in re.findall(r"<textarea name=value_ml[^>]*>", body):
            self.assertIn(" hidden", ta)                                  # off by default
            self.assertIn(" disabled", ta)                                # and not submitted while off
        self.assertNotIn("Multi-line value (PEM, JSON)", body)           # the old always-there <details>

    def test_each_value_has_its_own_toggle(self):
        body = self.page("multi")
        for v in ("M_ID", "M_SEC"):
            self.assertRegex(body, r"<button type=button class='btn sm' data-ml='" + v + "'[^>]* hidden>")
        self.assertIn("data-ml='ADD'", body)

    def test_the_script_wires_the_toggle(self):
        self.assertIn("data-ml", crededitor.JS)
        self.assertIn("disabled", crededitor.JS)

    def test_the_server_still_takes_a_multi_line_value(self):
        pem = "-----BEGIN KEY-----\nS3CR3T-line-one\n-----END KEY-----\n"
        code, _, _ = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value="",
                                   value_ml=pem.replace("\n", "\r\n"))
        self.assertEqual(code, 200)
        self.assertEqual(self.vault("Svc", "token"), pem)


class Folds(Base):
    def test_sections_are_closed_by_default_with_a_one_line_summary(self):
        body = self.page()
        for title, summary in (("TLS", "verify the certificate"), ("Approval", "ask on my phone"),
                               ("WebSocket", "off")):
            with self.subTest(title):
                sec = self.section(body, title)
                self.assertNotRegex(sec.split(">", 1)[0], r"\bopen\b")
                self.assertRegex(sec, r"<span class=fs[^>]*>" + re.escape(summary))
        self.assertIn("<h2>Allowed hosts</h2>", body)                      # the host list stays open

    def test_the_inputs_stay_in_the_form_so_nothing_about_saving_changed(self):
        body = self.page()
        form = body.split("id=cedit", 1)[1].split("</form>", 1)[0]
        for needle in ("name=tls value=verify", "name=tls value=pin", "name=tls value=skip",
                       "name=tls_fingerprint", "name=approval", "name=plans", "name=ws value=off",
                       "name=ws value=home-assistant", "id=cdirty"):
            with self.subTest(needle):
                self.assertIn(needle, form)

    def test_the_summaries_follow_the_stored_settings(self):
        meta = self.broker.credential_stored_meta("svc")
        cases = [({"tls_fingerprint": [FP_A, FP_B]}, "TLS", "pinned: 2 fingerprints"),
                 ({"tls_fingerprint": FP_A}, "TLS", "pinned: 1 fingerprint"),
                 ({"tls_verify": False}, "TLS", "not verified"),
                 ({"approval": "allow"}, "Approval", "allowed without asking"),
                 ({"plans": True}, "Approval", "plans allowed"),
                 ({"ws": {"handshake": "home-assistant"}}, "WebSocket", "Home Assistant"),
                 ({"ws": {"origin": "http://x.example"}}, "WebSocket", "custom")]
        for extra, title, want in cases:
            with self.subTest(want):
                self.reset_to({**meta, **extra})
                sec = self.section(self.page(), title)
                self.assertRegex(sec, r"<span class=fs[^>]*>[^<]*" + re.escape(want))
        self.reset_to(meta)

    def test_a_section_that_differs_from_the_stored_settings_opens_itself(self):
        # a refused save re-renders the human's candidate; the sections they changed must not be hidden
        code, body = self.post("/credentials/svc/save", **self.form(tls="pin", tls_fingerprint="not a fingerprint"))
        self.assertEqual(code, 400)
        self.assertRegex(self.section(body, "TLS").split(">", 1)[0], r"\bopen\b")
        self.assertNotRegex(self.section(body, "Approval").split(">", 1)[0], r"\bopen\b")

    def test_widening_still_goes_through_the_review_step(self):
        before = self.stored()
        pc, sc, body = self.save(approval="allow")
        self.assertEqual((pc, sc), (200, 400))                            # reviewed, then refused without the tick
        self.assertIn("Tick the box", body)
        self.assertEqual(self.stored(), before)
        pc, sc, _ = self.save(approval="allow", confirm=True)
        self.assertEqual((pc, sc), (200, 200))
        self.assertEqual(self.stored()["approval"], "allow")

    def test_the_summary_text_is_a_pure_function_of_the_metadata(self):
        self.assertEqual(crededitor.tls_line({}), "verify the certificate")
        self.assertEqual(crededitor.tls_line({"tls_fingerprint": [FP_A, FP_B]}), "pinned: 2 fingerprints")
        self.assertEqual(crededitor.tls_line({"tls_verify": False}), "not verified")
        self.assertEqual(crededitor.approval_line({}), "ask on my phone for each use")
        self.assertEqual(crededitor.approval_line({"approval": "allow", "plans": True}),
                         "allowed without asking, plans allowed")
        self.assertEqual(crededitor.ws_line({}), "off")
        self.assertEqual(crededitor.ws_line({"ws": {"handshake": "home-assistant"}}), "Home Assistant")


class Dialogs(Base):
    def test_rename_delete_and_remove_are_buttons_that_open_dialogs(self):
        body = self.page()
        for which in ("rename", "delete"):
            with self.subTest(which):
                self.assertRegex(body, r"<button type=button class='btn[^']*' data-dlg-open='dlg-" + which + "' hidden")
                m = re.search(r"<dialog id='dlg-" + which + r"' class='dlg cdlg' aria-labelledby='dlg-" + which
                              + r"-t'>", body)
                self.assertIsNotNone(m)
        self.assertNotIn("Rename or delete", body)                          # the always-visible section is gone
        self.assertIn("Renaming, deleting and removing a value need JavaScript", body)

    def test_the_rename_dialog_has_the_name_field_and_the_alias_tick_off_by_default(self):
        dlg = self.page().split("id='dlg-rename'", 1)[1].split("</dialog>", 1)[0]
        self.assertIn("action='/credentials/svc/rename'", dlg)
        self.assertIn("name=new_name", dlg)
        self.assertRegex(dlg, r"<input type=checkbox name=keep_alias value=1>")
        self.assertIn("Keep the old name as an alias", dlg)
        self.assertIn(f"name=old_sha value='{self.sha('svc')}'", dlg)
        self.assertIn("data-dlg-focus", dlg)

    def test_the_delete_dialog_asks_for_the_name_and_the_server_still_checks_it(self):
        dlg = self.page().split("id='dlg-delete'", 1)[1].split("</dialog>", 1)[0]
        self.assertIn("action='/credentials/svc/delete'", dlg)
        self.assertIn("name=typed", dlg)
        self.assertIn("data-expect='svc'", dlg)
        self.assertIn("cannot be undone", dlg)
        code, body = self.post("/credentials/svc/delete", typed="nope")
        self.assertEqual(code, 400)
        self.assertIn("Type the credential&#x27;s name to confirm", body)
        self.assertIn("Svc", self.broker.backend._data)

    def test_the_remove_dialog_says_it_is_irreversible_and_posts_the_confirmation(self):
        self.assertEqual(self.broker.add_value("svc", "SVC_EXTRA", tv.EXTRA, self.sha("svc"), "alice",
                                               confirm=True)["status"], "ok")
        body = self.page()
        dlg = body.split("id='dlg-rm-SVC_EXTRA'", 1)[1].split("</dialog>", 1)[0]
        self.assertIn("action='/credentials/svc/value/remove'", dlg)
        self.assertIn("name=confirm value=1", dlg)
        self.assertIn("name=var value='SVC_EXTRA'", dlg)
        self.assertIn("deleted from the vault", dlg)
        self.assertIn("cannot be undone", dlg)
        self.assertRegex(body, r"data-dlg-open='dlg-rm-SVC_EXTRA'")
        self.assertNotIn("data-confirm=", body)                             # the browser confirm() is gone
        self.assertEqual(body.count("<dialog id='dlg-rm-"), 2)             # one dialog per removable value

    def test_a_credential_with_one_value_offers_no_remove(self):
        self.assertNotIn("dlg-rm-", self.page())

    def test_dialogs_are_driven_by_the_nonced_script_and_the_csp_allows_only_that(self):
        r = t.urllib.request.Request(self.abase + "/credentials/svc", headers={"X-authentik-username": "alice"})
        with t.urllib.request.urlopen(r, timeout=10) as resp:
            csp, body = resp.headers["Content-Security-Policy"], resp.read().decode()
        nonce = re.search(r"script-src 'nonce-([^']+)'", csp).group(1)
        self.assertIn(f"<script nonce='{nonce}'>", body)
        self.assertNotRegex(body, r"\son(click|submit|change)=")           # no inline handlers: the CSP would block them
        for needle in ("showModal", "data-dlg-open", "data-dlg-close", "data-expect", "isConnected"):
            self.assertIn(needle, crededitor.JS)

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_the_page_script_is_valid_javascript(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(crededitor.JS)
        self.addCleanup(os.unlink, f.name)
        r = subprocess.run(["node", "--check", f.name], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_refused_rename_reopens_its_dialog_with_the_fixed_message_inside(self):
        code, body = self.post("/credentials/svc/rename", new_name="Not A Name", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)
        dlg = body.split("id='dlg-rename'", 1)[1].split("</dialog>", 1)[0]
        self.assertIn("secret name must be 1-41 chars", dlg)
        self.assertRegex(body, r"<dialog id='dlg-rename' class='dlg cdlg' aria-labelledby='dlg-rename-t' open>")
        self.assertNotRegex(body, r"<dialog id='dlg-delete'[^>]* open>")
        self.assertIn("value='Not A Name'", dlg.replace("&#x27;", "'"))     # what they typed is kept (names are not secret)

    def test_every_refusal_keeps_its_message_in_the_dialog(self):
        cases = [("exists", {"new_name": "svc"}, "That is already its name"),
                 ("denied", None, "plans.deny_secrets names this credential")]
        self.broker.plans_cfg["deny_secrets"] = ["svc"]
        code, body = self.post("/credentials/svc/rename", new_name="svc2", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)
        self.assertIn(cases[1][2], body.split("id='dlg-rename'", 1)[1].split("</dialog>", 1)[0])
        self.broker.plans_cfg["deny_secrets"] = []
        code, body = self.post("/credentials/svc/rename", new_name="svc", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)
        self.assertIn(cases[0][2], body.split("id='dlg-rename'", 1)[1].split("</dialog>", 1)[0])

    def test_a_refused_delete_reopens_the_delete_dialog(self):
        code, body = self.post("/credentials/svc/delete", typed="nope")
        self.assertEqual(code, 400)
        self.assertRegex(body, r"<dialog id='dlg-delete' class='dlg cdlg' aria-labelledby='dlg-delete-t' open>")
        self.assertIn("Type the credential&#x27;s name to confirm",
                      body.split("id='dlg-delete'", 1)[1].split("</dialog>", 1)[0])

    def test_a_refused_remove_reopens_its_dialog(self):
        self.broker.add_value("svc", "SVC_EXTRA", tv.EXTRA, self.sha("svc"), "alice", confirm=True)
        code, _, body = self.raw_post("/credentials/svc/value/remove", var="SVC_EXTRA", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)
        self.assertRegex(body, r"<dialog id='dlg-rm-SVC_EXTRA' class='dlg cdlg' aria-labelledby='dlg-rm-SVC_EXTRA-t' open>")
        self.assertIn(self.broker._VALUE_TEXT["confirm_delete"],
                      body.split("id='dlg-rm-SVC_EXTRA'", 1)[1].split("</dialog>", 1)[0])
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), tv.EXTRA)

    def test_a_bound_credential_disables_both_buttons_and_says_why(self):
        self.assertEqual(self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["echo"]})[0], 202)
        body = self.page()
        self.assertIn("Rename and delete are unavailable while this credential is in use", body)
        self.assertRegex(body, r"data-dlg-open='dlg-rename' disabled")
        self.assertRegex(body, r"data-dlg-open='dlg-delete' disabled")
        code, body = self.post("/credentials/svc/rename", new_name="svc2", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)                                        # the server refuses too
        self.assertIn("Still in use by 1 pending", body)

    def test_a_dialog_holds_no_value(self):
        self.broker.add_value("svc", "SVC_EXTRA", tv.EXTRA, self.sha("svc"), "alice", confirm=True)
        body = self.page()
        self.assertIn("dlg-rm-SVC_EXTRA", body)                            # positive control
        for v in (t.SECRET, tv.EXTRA):
            self.assertNotIn(v, body)

    def test_rename_with_the_tick_keeps_the_old_name_as_an_alias(self):
        code, body = self.post("/credentials/svc/rename", new_name="svc2", old_sha=self.sha("svc"), keep_alias="1")
        self.assertEqual(code, 200)
        self.assertIn("Renamed svc to svc2", body)
        self.assertEqual(self.broker.credential_stored_meta("svc2")["aliases"], ["svc"])
        self.assertTrue(self.events("credential_renamed")[-1]["alias_kept"])

    def test_rename_without_the_tick_keeps_no_alias(self):
        code, _ = self.post("/credentials/svc/rename", new_name="svc2", old_sha=self.sha("svc"))
        self.assertEqual(code, 200)
        self.assertNotIn("aliases", self.broker.credential_stored_meta("svc2"))
        self.assertFalse(self.events("credential_renamed")[-1]["alias_kept"])


class AliasesLine(Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["aliases"] = ["old-svc", "older-svc"]

    def test_the_page_lists_aliases_with_a_remove_button_each(self):
        body = self.page()
        self.assertIn("Aliases", body)
        for a in ("old-svc", "older-svc"):
            self.assertIn(f"<code>{a}</code>", body)
            self.assertRegex(body, r"action='/credentials/svc/alias/remove'[^>]*>(?:(?!</form>).)*name=alias value='"
                             + a + "'")

    def test_removing_one_is_audited_and_the_other_stays(self):
        code, body = self.post("/credentials/svc/alias/remove", old_sha=self.sha("svc"), alias="old-svc")
        self.assertEqual(code, 200)
        self.assertIn("Alias removed: old-svc", body)
        self.assertEqual(self.broker.credential_stored_meta("svc")["aliases"], ["older-svc"])
        self.assertEqual([e["alias"] for e in self.events("credential_alias_removed")], ["old-svc"])

    def test_a_refused_removal_is_a_fixed_message(self):
        code, body = self.post("/credentials/svc/alias/remove", old_sha=self.sha("svc"), alias="nope")
        self.assertEqual(code, 400)
        self.assertIn("That is not an alias of this credential", body)
        code, _ = self.post("/credentials/svc/alias/remove", old_sha="0" * 64, alias="old-svc")
        self.assertEqual(code, 409)
        self.assertEqual(self.broker.credential_stored_meta("svc")["aliases"], ["old-svc", "older-svc"])

    def test_the_route_needs_csrf_and_the_human(self):
        code, _ = self.post("/credentials/svc/alias/remove", csrf=False, old_sha=self.sha("svc"), alias="old-svc")
        self.assertEqual(code, 403)
        code, _ = self.post("/credentials/svc/alias/remove", user="mallory", old_sha=self.sha("svc"), alias="old-svc")
        self.assertEqual(code, 403)
        self.assertEqual(self.broker.credential_stored_meta("svc")["aliases"], ["old-svc", "older-svc"])

    def test_a_credential_without_aliases_shows_no_line(self):
        self.assertNotIn("Aliases", self.page("multi"))


if __name__ == "__main__":
    unittest.main()
