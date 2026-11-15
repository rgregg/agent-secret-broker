"""The Credentials-tab editor: change a credential's broker metadata from the approval site."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import html
import json
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
from secret_broker import crededitor  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

NEW_HOST = "canary-edit-5d2.example.com"
PIN_A = "sha256:" + "ab" * 32
PIN_B = "sha256:" + "cd" * 32
HDR = {"X-authentik-username": "alice"}


class Base(t.Harness):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["allowed_hosts"] = ["127.0.0.1", "localhost"]
        cfg["secrets"]["svc"]["custom"] = {"keep": "me"}      # a key the form does not know

    def post(self, path, csrf=True, user="alice", **form):
        if csrf is True:
            form["csrf"] = self.broker.csrf_token("alice")
        elif isinstance(csrf, str):
            form["csrf"] = csrf
        r = t.urllib.request.Request(self.abase + path, data=urllib.parse.urlencode(form).encode(),
                                     headers={"X-authentik-username": user}, method="POST")
        try:
            with t.urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, resp.read().decode()
        except t.urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def get(self, path, headers=HDR):
        return t.req(self.abase + path, headers=headers)

    def stored(self):
        return self.disk()["secrets"]["svc"]

    def reset_to(self, meta):
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)

    def stored_sha(self):
        return crededitor.digest(self.stored())

    def form(self, **over):
        s = self.stored()
        f = {"old_sha": self.stored_sha(), "advanced_orig": crededitor.pretty(s), "advanced": crededitor.pretty(s),
             "allowed_hosts": "\n".join(s["allowed_hosts"]), "tls": "verify", "approval": "prompt"}
        f.update(over)
        return f

    def save(self, confirm=False, **over):
        """preview -> save, the way the browser does it; returns (preview status, save status, save body)."""
        pc, body = self.post("/credentials/svc/preview", **self.form(**over))
        if pc != 200:
            return pc, None, body
        meta_json = html.unescape(body.split("name=meta_json value='")[1].split("'>")[0])
        extra = {"confirm_widen": "1"} if confirm else {}
        sc, sbody = self.post("/credentials/svc/save", old_sha=self.form()["old_sha"], meta_json=meta_json, **extra)
        return pc, sc, sbody


class Pages(Base):
    def test_list_shows_credentials_and_the_tab(self):
        code, body = self.get("/credentials")
        self.assertEqual(code, 200)
        self.assertIn("href='/credentials/svc'", body)
        self.assertIn("127.0.0.1, localhost", body)
        self.assertIn("href='/credentials' class=on", body)

    def test_edit_page_shows_stored_values_and_hash(self):
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertIn("127.0.0.1\nlocalhost</textarea>", body)
        self.assertIn(self.stored_sha(), body)
        self.assertIn("&quot;keep&quot;: &quot;me&quot;", body)         # the unknown key is in the advanced box

    def test_unknown_credential_is_404(self):
        self.assertEqual(self.get("/credentials/nope")[0], 404)

    def test_only_the_human_session_reaches_it(self):
        self.assertEqual(self.get("/credentials", headers={})[0], 403)
        self.assertEqual(self.get("/credentials", headers={"X-authentik-username": "mallory"})[0], 403)
        # the agent-facing port has no such route, and a client key does not open one
        code, _ = t.req(self.base + "/credentials", headers={"X-Client-Key": t.KEY})
        self.assertEqual(code, 404)
        code, _ = t.req(self.base + "/credentials/svc/save", "POST", {}, {"X-Client-Key": t.KEY})
        self.assertEqual(code, 404)


class Editing(Base):
    def test_preview_writes_nothing_and_shows_the_diff(self):
        before = self.stored()
        code, body = self.post("/credentials/svc/preview", **self.form(allowed_hosts="127.0.0.1\n" + NEW_HOST))
        self.assertEqual(code, 200)
        self.assertIn(NEW_HOST, body)
        self.assertIn("class='df add'", body)
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.events("credential_changed"), [])

    def test_narrowing_saves_without_a_tick_and_keeps_unknown_keys(self):
        pc, sc, body = self.save(allowed_hosts="127.0.0.1")
        self.assertEqual((pc, sc), (200, 200))
        self.assertEqual(self.stored()["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(self.stored()["custom"], {"keep": "me"})
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["127.0.0.1"])   # live, not just stored
        ev = self.events("credential_changed")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["widened"], ev[0]["changed_keys"], ev[0]["user"]), ([], 1, "alice"))

    def test_every_widening_needs_the_tick_and_saves_with_it(self):
        cases = {
            "host_added": dict(allowed_hosts="127.0.0.1\nlocalhost\n" + NEW_HOST),
            "pin_added": dict(tls="pin", tls_fingerprint=PIN_A),
            "tls_unverified": dict(tls="skip"),
            "approval_allow": dict(approval="allow"),
            "plans_enabled": dict(plans="1"),
        }
        for label, over in cases.items():
            with self.subTest(label):
                before = self.stored()
                pc, sc, body = self.save(**over)
                self.assertEqual((pc, sc), (200, 400))
                self.assertIn("This change widens access", body)
                self.assertEqual(self.stored(), before)                      # refused: nothing written
                self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "needs_confirmation")
                pc, sc, body = self.save(confirm=True, **over)
                self.assertEqual(sc, 200)
                self.assertNotEqual(self.stored(), before)
                self.assertIn(label, self.events("credential_changed")[-1]["widened"])
                self.reset_to(before)

    def test_removing_a_pin_is_a_widening_and_the_unpinned_credential_then_verifies(self):
        self.reset_to({**self.stored(), "tls_fingerprint": PIN_A})
        pc, sc, body = self.save(tls="verify")
        self.assertEqual((pc, sc), (200, 400))
        self.assertIn("removes a TLS fingerprint pin", body)
        self.assertEqual(self.stored()["tls_fingerprint"], PIN_A)
        self.assertEqual(self.save(confirm=True, tls="verify")[1], 200)
        self.assertNotIn("tls_fingerprint", self.stored())
        self.assertEqual(self.broker._tls_policy(["svc"]), {"fingerprint": None, "verify": True})

    def test_a_saved_edit_loads_again_from_the_vault(self):
        self.assertEqual(self.save(allowed_hosts="localhost")[1], 200)
        fresh = Broker({"approve_base_url": "https://s.example"}, self.broker.backend, FakeNotifier(), None)
        fresh.refresh_catalog(fresh=True)
        self.assertEqual(fresh.cfg["secrets"]["svc"]["allowed_hosts"], ["localhost"])

    def test_invalid_input_is_refused_with_the_loaders_own_rule(self):
        before = self.stored()
        code, body = self.post("/credentials/svc/preview", **self.form(allowed_hosts="not a host!"))
        self.assertEqual(code, 400)
        self.assertIn("allowed_hosts must be up to 10 plain hostnames", body)
        self.assertEqual(self.stored(), before)
        code, body = self.post("/credentials/svc/preview", **self.form(advanced="{not json"))
        self.assertEqual(code, 400)
        self.assertIn("not valid JSON", body)
        # the loader's rule on its own, applied to a save that skips the preview step
        code, body = self.post("/credentials/svc/save", old_sha=self.stored_sha(),
                               meta_json=json.dumps({**before, "approval": "bogus"}), confirm_widen="1")
        self.assertEqual(code, 400)
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "invalid")

    def test_the_advanced_box_replaces_the_form_when_edited(self):
        s = self.stored()
        adv = crededitor.pretty({**s, "custom": {"keep": "changed"}})
        pc, sc, _ = self.save(advanced=adv)
        self.assertEqual((pc, sc), (200, 200))
        self.assertEqual(self.stored()["custom"], {"keep": "changed"})

    def test_rename_is_refused(self):
        before = self.stored()
        pc, sc, body = self.save(advanced=crededitor.pretty({**before, "name": "other"}))
        self.assertEqual(pc, 400)
        self.assertIn("name must stay the same", body)
        self.assertEqual(self.stored(), before)

    def test_rename_is_refused_on_save_too(self):
        before = self.stored()
        code, body = self.post("/credentials/svc/save", old_sha=self.stored_sha(), confirm_widen="1",
                               meta_json=json.dumps({**before, "name": "other"}))
        self.assertEqual(code, 400)
        self.assertIn("name must stay the same", body)
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "rename")

    def test_a_change_in_the_vault_after_opening_is_not_overwritten(self):
        opened_sha = self.stored_sha()
        self.reset_to({**self.stored(), "approval": "allow"})          # someone edits it in Bitwarden
        theirs = self.stored()
        code, body = self.post("/credentials/svc/save", old_sha=opened_sha,
                               meta_json=json.dumps({**theirs, "allowed_hosts": ["127.0.0.1"]}))
        self.assertEqual(code, 409)
        self.assertIn("changed in the vault after you opened it", body)
        self.assertEqual(self.stored(), theirs)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "conflict")
        # the same on the preview step
        code, _ = self.post("/credentials/svc/preview", **{**self.form(), "old_sha": opened_sha})
        self.assertEqual(code, 409)

    def test_no_change_is_reported_as_such(self):
        pc, sc, body = self.save()
        self.assertEqual((pc, sc), (200, 200))
        self.assertIn("No changes", body)
        self.assertEqual(self.events("credential_changed"), [])


class Guards(Base):
    def attempt(self, **kw):
        before = self.stored()
        meta = json.dumps({**before, "allowed_hosts": ["127.0.0.1"]})
        code, _ = self.post("/credentials/svc/save", old_sha=self.stored_sha(), meta_json=meta, **kw)
        return code, before

    def test_csrf_is_required(self):
        code, before = self.attempt(csrf=False)
        self.assertEqual(code, 403)
        code2, _ = self.attempt(csrf="wrong")
        self.assertEqual(code2, 403)
        self.assertEqual(self.stored(), before)
        self.assertGreaterEqual(len(self.events("csrf_refused")), 2)
        code3, _ = self.attempt()               # positive control: the same request with the token is accepted
        self.assertEqual(code3, 200)
        self.assertEqual(self.stored()["allowed_hosts"], ["127.0.0.1"])

    def test_another_identity_is_refused_even_with_a_token(self):
        before = self.stored()
        code, _ = self.post("/credentials/svc/save", user="mallory", old_sha=self.stored_sha(),
                            meta_json=json.dumps({**before, "approval": "allow"}), confirm_widen="1")
        self.assertEqual(code, 403)
        self.assertEqual(self.stored(), before)

    def test_oversized_form_is_refused(self):
        code, _ = self.post("/credentials/svc/preview", advanced="x" * (crededitor.FORM_LIMIT + 10))
        self.assertEqual(code, 413)

    def test_backend_without_set_meta_cannot_edit(self):
        before = self.stored()
        self.broker.backend.capabilities = frozenset()
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertIn("cannot store metadata", body)
        self.assertIn("<textarea name=allowed_hosts rows=4 disabled>", body)
        code, body = self.post("/credentials/svc/save", old_sha=self.stored_sha(),
                               meta_json=json.dumps({**before, "allowed_hosts": ["127.0.0.1"]}))
        self.assertEqual(code, 400)
        self.assertEqual(self.stored(), before)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "unsupported")

    def test_pages_escape_the_metadata_and_audit_keeps_no_names(self):
        evil = "<img src=x onerror=alert(1)>"
        self.reset_to({**self.stored(), "note_to_self": evil})
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertNotIn(evil, body)
        self.assertIn(html.escape(evil), body)                      # positive control: it is shown, escaped
        pc, sc, _ = self.save(confirm=True, allowed_hosts=f"127.0.0.1\n{NEW_HOST}")
        self.assertEqual(sc, 200)
        self.assertEqual(len(self.events("credential_changed")), 1)  # positive control: the event exists
        with open(self.audit) as f:
            text = f.read()
        self.assertNotIn(NEW_HOST, text)
        self.assertNotIn(evil, text)


class Secrecy(Base):
    def test_editor_events_are_hidden_from_the_agent_audit_api(self):
        from secret_broker import audit_api
        for ev in ("credentials_viewed", "credential_changed", "credential_change_refused",
                   "credential_change_failed"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertIsNone(audit_api.redact({"seq": 1, "ts": 1.0, "event": ev, "secret": "svc",
                                                "new_sha256": "ab", "request": "r"}), ev)

    def test_the_events_the_editor_really_writes_are_all_hidden(self):
        from secret_broker import audit_api
        self.get("/credentials")
        self.save(allowed_hosts="127.0.0.1")                         # changed
        self.save(approval="allow")                                  # refused: needs the tick
        written = {r["event"] for r in self.records()} & {
            "credentials_viewed", "credential_changed", "credential_change_refused"}
        self.assertEqual(written, {"credentials_viewed", "credential_changed", "credential_change_refused"})
        for ev in written:
            self.assertIn(ev, audit_api.HIDDEN)


class Units(unittest.TestCase):
    def test_widened_is_empty_for_narrowing(self):
        old = {"allowed_hosts": ["a.example.com", "b.example.com"], "tls_verify": False}
        self.assertEqual(crededitor.widened(old, {"allowed_hosts": ["a.example.com"]}), [])
        self.assertEqual(crededitor.widened({}, {"allowed_hosts": ["a.example.com"]}), ["host_added"])

    def test_pin_normalisation_does_not_count_as_a_change(self):
        a = {"tls_fingerprint": PIN_A}
        b = {"tls_fingerprint": PIN_A.replace("sha256:", "SHA256:").upper().replace("SHA256:", "sha256:")}
        self.assertEqual(crededitor.widened(a, b), [])

    def test_build_rejects_control_characters_and_bad_modes(self):
        with self.assertRaises(ValueError):
            crededitor.build({}, {"allowed_hosts": "a.example.com\x00"})
        with self.assertRaises(ValueError):
            crededitor.build({}, {"tls": "sideways"})
        with self.assertRaises(ValueError):
            crededitor.build({}, {"tls": "pin", "tls_fingerprint": ""})


if __name__ == "__main__":
    unittest.main()
