"""The Credentials-tab editor: change a credential's broker metadata from the approval site."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import html
import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock

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


class Create(Base):
    VALUE = "S3CR3T-created-value-7f3a"
    HOST = "api.example.com"

    def create(self, **over):
        f = {"name": "fresh", "allowed_hosts": self.HOST, "value": self.VALUE}
        f.update(over)
        return self.post("/credentials/new", **f)

    def vault_items(self):
        return set(self.broker.backend._data)

    def test_the_form_has_a_password_box_and_never_a_value(self):
        code, body = self.get("/credentials/new")
        self.assertEqual(code, 200)
        self.assertIn("<input type=password name=value", body)
        self.assertIn("action='/credentials/new'", body)
        self.assertIn("href='/credentials/new'", self.get("/credentials")[1])

    def test_creates_the_item_its_metadata_and_the_live_entry_like_asb_store(self):
        code, body = self.create()
        self.assertEqual(code, 200)
        self.assertIn("Created: fresh", body)
        rec = self.broker.backend._data["fresh"]
        self.assertEqual(rec["notes"], self.VALUE)                       # the value was stored
        meta = json.loads(rec["broker"])
        self.assertEqual(set(meta), {"name", "vars", "allowed_hosts", "approval", "created"})
        self.assertEqual((meta["name"], meta["allowed_hosts"], meta["approval"], meta["created"]["by"]),
                         ("fresh", [self.HOST], "prompt", "alice"))
        self.assertEqual(meta["vars"], {"FRESH_TOKEN": {"field": "notes"}})
        live = self.broker.cfg["secrets"]["fresh"]
        self.assertEqual((live["allowed_hosts"], live["_item"]), ([self.HOST], "fresh"))
        self.assertEqual(self.events("credential_created")[0]["hosts"], 1)

    def test_the_value_reaches_no_page_log_or_audit_event(self):
        code, body = self.create()
        self.assertEqual(code, 200)
        self.assertIn("Created: fresh", body)                             # positive control: it ran
        code, body = self.create(name="fresh", value=self.VALUE)           # refused: it exists
        self.assertEqual(code, 400)
        self.assertIn("already exists", body)                              # positive control: the error shows
        self.assertNotIn(self.VALUE, body)
        self.assertNotIn(self.VALUE, self.get("/credentials/fresh")[1])
        self.assertNotIn(self.VALUE, self.get("/credentials")[1])
        with open(self.audit) as f:
            text = f.read()
        self.assertIn('"credential_created"', text)
        self.assertNotIn(self.VALUE, text)
        self.assertNotIn(self.HOST, text)

    def test_refusals_write_nothing_and_say_why(self):
        before = self.vault_items()
        cases = [
            ("exists", dict(name="svc")),
            ("invalid", dict(name="new")),                                # reserved: it is a route
            ("invalid", dict(name="Bad Name")),
            ("invalid", dict(value="")),
            ("invalid", dict(allowed_hosts="")),
            ("invalid", dict(allowed_hosts="169.254.169.254")),           # a metadata address, as for asb store
            ("invalid", dict(allowed_hosts="not a host!")),
        ]
        for reason, over in cases:
            with self.subTest(over=sorted(over)):
                code, _ = self.create(**over)
                self.assertEqual(code, 400)
                self.assertEqual(self.events("credential_change_refused")[-1]["reason"], reason)
                self.assertEqual(self.vault_items(), before)
        self.assertEqual(self.events("credential_created"), [])

    def test_the_item_of_another_credential_cannot_be_taken(self):
        # the default item is the name; "svc" the credential lives in the vault item "Svc"
        code, _ = self.create(name="Svc".lower(), allowed_hosts=self.HOST)
        self.assertEqual(code, 400)
        self.assertEqual(self.broker.backend._data["Svc"]["token"], t.SECRET)

    def test_needs_the_human_session_and_a_token(self):
        before = self.vault_items()
        self.assertEqual(self.create(csrf=False)[0], 403)
        self.assertEqual(self.create(user="mallory")[0], 403)
        self.assertEqual(self.vault_items(), before)
        self.assertEqual(t.req(self.base + "/credentials/new", "POST", {}, {"X-Client-Key": t.KEY})[0], 404)
        self.assertEqual(self.create()[0], 200)                            # positive control

    def test_backend_without_set_meta_cannot_create(self):
        self.broker.backend.capabilities = frozenset()
        code, body = self.get("/credentials/new")
        self.assertIn("cannot store metadata", body)
        before = self.vault_items()
        self.assertEqual(self.create()[0], 400)
        self.assertEqual(self.vault_items(), before)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "unsupported")

    def test_the_summary_keys_vault_item_cannot_be_taken(self):
        with mock.patch.object(self.broker, "_deny_internal", side_effect=ValueError("refused")):
            code, _ = self.create()
        self.assertEqual(code, 400)
        self.assertNotIn("fresh", self.vault_items())


class Manage(Base):
    decision = None             # nobody answers: a request stays pending

    def rename(self, new_name, sha=None, **kw):
        return self.post("/credentials/svc/rename", new_name=new_name, old_sha=sha or self.stored_sha(), **kw)

    def delete(self, typed="svc", **kw):
        return self.post("/credentials/svc/delete", typed=typed, **kw)

    def last_reason(self):
        return self.events("credential_change_refused")[-1]["reason"]

    def test_the_edit_page_offers_rename_and_delete(self):
        code, body = self.get("/credentials/svc")
        self.assertIn("action='/credentials/svc/rename'", body)
        self.assertIn("action='/credentials/svc/delete'", body)
        self.assertNotIn("disabled", body.split("Rename or delete")[1])

    def test_rename_changes_the_name_and_leaves_the_item_and_value(self):
        code, body = self.rename("svc2")
        self.assertEqual(code, 200)
        self.assertIn("Renamed svc to svc2", body)
        self.assertEqual(self.disk()["secrets"]["svc2"]["allowed_hosts"], ["127.0.0.1", "localhost"])
        self.assertNotIn("svc", self.disk()["secrets"])
        self.assertIn("svc2", self.broker.cfg["secrets"])
        self.assertNotIn("svc", self.broker.cfg["secrets"])               # live, not just stored
        self.assertEqual(self.broker.backend._data["Svc"]["token"], t.SECRET)   # the value is untouched
        self.assertEqual(self.get("/credentials/svc")[0], 404)
        self.assertEqual(self.get("/credentials/svc2")[0], 200)
        self.assertEqual(self.events("credential_renamed")[0]["new_secret"], "svc2")

    def test_rename_refusals(self):
        before = self.stored()
        for reason, new in (("invalid", "svc"), ("invalid", "new"), ("invalid", "Bad Name"), ("invalid", ""),
                            ("exists", "other")):
            with self.subTest(new=new):
                if reason == "exists":
                    self.broker.cfg["secrets"]["other"] = dict(self.broker.cfg["secrets"]["svc"])
                code, _ = self.rename(new)
                self.assertEqual(code, 400)
                self.assertEqual(self.last_reason(), reason)
                self.assertEqual(self.stored(), before)

    def test_rename_and_delete_refuse_while_something_is_bound_to_the_name(self):
        before = self.stored()
        self.assertEqual(self.create_env()[0], 202)                       # a pending request names it
        self.assertEqual(self.broker.credential_bindings("svc")["pending"], 1)   # the premise took effect
        code, body = self.rename("svc2")
        self.assertEqual((code, self.last_reason()), (400, "bound"))
        self.assertIn("1 pending", body)
        code, body = self.delete()
        self.assertEqual((code, self.last_reason()), (400, "bound"))
        self.assertIn("Still in use by 1 pending", body)
        self.assertEqual(self.stored(), before)
        self.assertIn("Svc", self.broker.backend._data)
        self.assertIn("disabled", self.get("/credentials/svc")[1].split("Rename or delete")[1])

    def test_each_kind_of_binding_is_counted_and_blocks_rename_and_delete(self):
        b = self.broker
        sc = b.cfg["secrets"]["svc"]
        self.assertEqual(b.credential_bindings("svc"), {"timed_grants": 0, "always": 0, "plans": 0,
                                                        "sessions": 0, "pending": 0})     # nothing bound yet
        kinds = {
            "timed_grants": mock.patch.object(b, "active_grants", return_value=[{"secrets": ["svc", "x"]}]),
            "plans": mock.patch.object(b, "active_plans", return_value=[{"names": ["svc"]}]),
            "sessions": mock.patch.object(b, "active_sessions", return_value=[{"cred": "svc"}]),
        }
        others = {                                                    # rows for ANOTHER credential never block
            "timed_grants": mock.patch.object(b, "active_grants", return_value=[{"secrets": ["other"]}]),
            "plans": mock.patch.object(b, "active_plans", return_value=[{"names": ["other"]}]),
            "sessions": mock.patch.object(b, "active_sessions", return_value=[{"cred": "other"}]),
        }
        for kind, patch in kinds.items():
            with self.subTest(kind=kind):
                with others[kind]:
                    self.assertEqual(b.credential_bindings("svc")[kind], 0)
                with patch:
                    self.assertEqual(b.credential_bindings("svc")[kind], 1)
                    self.assertEqual(self.rename("svc2")[0], 400)
                    self.assertEqual(self.last_reason(), "bound")
                    self.assertEqual(self.delete()[0], 400)
                    self.assertEqual(self.last_reason(), "bound")
        with self.subTest(kind="always"):
            sc["standing"] = [{"id": "a1"}]
            self.assertEqual(b.credential_bindings("svc")["always"], 1)
            self.assertEqual(self.rename("svc2")[0], 400)
            self.assertEqual(self.last_reason(), "bound")
            del sc["standing"]
        self.assertIn("Svc", b.backend._data)
        self.assertEqual(self.events("credential_renamed") + self.events("credential_deleted"), [])

    def test_a_deny_rule_on_the_name_blocks_rename(self):
        self.broker.plans_cfg["deny_secrets"] = ["svc"]
        before = self.stored()
        code, body = self.rename("svc2")
        self.assertEqual((code, self.last_reason()), (400, "denied_by_name"))
        self.assertIn("deny", body)
        self.assertEqual(self.stored(), before)

    def test_internal_and_adopted_credentials_cannot_be_renamed_or_deleted(self):
        before = self.stored()
        with mock.patch.object(self.broker, "_internal_secrets", return_value=(frozenset({"svc"}), frozenset())):
            self.assertEqual(self.rename("svc2")[0], 400)
            self.assertEqual(self.last_reason(), "internal")
            self.assertEqual(self.delete()[0], 400)
            self.assertEqual(self.last_reason(), "internal")
        self.broker.cfg["secrets"]["svc"]["auto"] = True
        self.assertEqual(self.rename("svc2")[0], 400)
        self.assertEqual(self.last_reason(), "adopted")
        self.assertEqual(self.delete()[0], 400)
        self.assertEqual(self.last_reason(), "adopted")
        self.assertEqual(self.stored(), before)
        self.assertIn("Svc", self.broker.backend._data)

    def test_rename_is_refused_after_a_vault_change(self):
        opened = self.stored_sha()
        self.reset_to({**self.stored(), "approval": "allow"})
        theirs = self.stored()
        code, body = self.rename("svc2", sha=opened)
        self.assertEqual(code, 409)
        self.assertEqual(self.stored(), theirs)
        self.assertEqual(self.last_reason(), "conflict")

    def test_delete_needs_the_name_typed(self):
        code, body = self.delete(typed="nope")
        self.assertEqual((code, self.last_reason()), (400, "confirm"))
        self.assertIn("Type the credential", body)
        self.assertIn("Svc", self.broker.backend._data)
        self.assertEqual(self.events("credential_deleted"), [])

    def test_delete_removes_the_item_and_the_entry(self):
        code, body = self.delete()
        self.assertEqual(code, 200)
        self.assertIn("Deleted svc", body)
        self.assertNotIn("Svc", self.broker.backend._data)
        self.assertNotIn("svc", self.broker.cfg["secrets"])
        self.assertEqual(len(self.events("credential_deleted")), 1)
        self.assertEqual(self.get("/credentials/svc")[0], 404)

    def test_csrf_and_identity_are_required(self):
        before = self.stored()
        for kw in ({"csrf": False}, {"csrf": "wrong"}, {"user": "mallory"}):
            self.assertEqual(self.rename("svc2", **kw)[0], 403)
            self.assertEqual(self.delete(**kw)[0], 403)
        self.assertEqual(self.stored(), before)
        self.assertIn("Svc", self.broker.backend._data)
        self.assertEqual(t.req(self.base + "/credentials/svc/delete", "POST", {}, {"X-Client-Key": t.KEY})[0], 404)
        self.assertEqual(self.rename("svc2")[0], 200)                      # positive control

    def test_backend_without_set_meta_cannot_rename_or_delete(self):
        self.broker.backend.capabilities = frozenset()
        self.assertEqual(self.rename("svc2")[0], 400)
        self.assertEqual(self.last_reason(), "unsupported")
        self.assertEqual(self.delete()[0], 400)
        self.assertIn("Svc", self.broker.backend._data)


class Secrecy(Base):
    def test_editor_events_are_hidden_from_the_agent_audit_api(self):
        from secret_broker import audit_api
        for ev in ("credentials_viewed", "credential_changed", "credential_change_refused",
                   "credential_change_failed", "credential_created", "credential_renamed", "credential_deleted"):
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
