"""The Credentials-tab editor: change a credential's broker metadata from the approval site."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import datetime
import hashlib
import html
import json
import os
import re
import socket
import ssl
import tempfile
import threading
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
        self.assertIn("<code class=hchip title='127.0.0.1'>127.0.0.1</code><code class=hchip title='localhost'>", body)
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

    def test_a_rejected_candidate_keeps_its_keys_when_the_form_is_then_fixed(self):
        s = self.stored()
        bad = crededitor.pretty({**s, "custom2": {"added": 1}, "allowed_hosts": ["not a host!"]})
        code, body = self.post("/credentials/svc/preview", **self.form(advanced=bad))
        self.assertEqual(code, 400)                                      # rejected: the bad host
        orig = html.unescape(re.search(r"name=advanced_orig value='(.*?)'>", body, re.S).group(1))
        self.assertIn("custom2", orig)                                   # premise: the page shows the candidate
        pc, pbody = self.post("/credentials/svc/preview", **self.form(advanced=orig, advanced_orig=orig,
                                                                     allowed_hosts="127.0.0.1"))
        self.assertEqual(pc, 200)
        meta = json.loads(html.unescape(pbody.split("name=meta_json value='")[1].split("'>")[0]))
        self.assertEqual((meta["custom2"], meta["allowed_hosts"]), ({"added": 1}, ["127.0.0.1"]))

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


def _self_signed(cn):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("device.example.com")]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert.public_bytes(serialization.Encoding.DER), cp, kp


class TlsDevice:
    """A TLS server on 127.0.0.1 that completes a handshake and counts connections."""
    def __init__(self, cn):
        self.der, cp, kp = _self_signed(cn)
        self.fp = "sha256:" + hashlib.sha256(self.der).hexdigest()
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.load_cert_chain(cp, kp)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            try:
                with self.ctx.wrap_socket(c, server_side=True) as t:
                    t.recv(1)
            except OSError:
                pass

    def close(self):
        self.sock.close()


def _closed_port():
    s = socket.create_server(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Fingerprint(Base):
    CN = "dev<i>x</i>.example.com"

    @classmethod
    def setUpClass(cls):
        cls.dev = TlsDevice(cls.CN)
        cls.entry = f"127.0.0.1:{cls.dev.port}"

    @classmethod
    def tearDownClass(cls):
        cls.dev.close()

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["allowed_hosts"] = [self.entry]

    def fetch(self, fp_host=None, **over):
        return self.post("/credentials/svc/fingerprint", **self.form(fp_host=fp_host or self.entry, **over))

    def fields(self, body):
        """The form fields of a re-rendered edit page, the way a browser would submit them."""
        tx = lambda n: html.unescape(re.search(rf"<textarea name={n} rows=\d+>(.*?)</textarea>", body, re.S).group(1))  # noqa: E731
        orig = html.unescape(re.search(r"name=advanced_orig value='(.*?)'>", body, re.S).group(1))
        sha = re.search(r"name=old_sha value='([0-9a-f]{64})'", body).group(1)
        tls = re.search(r"name=tls value=(\w+) checked", body).group(1)
        return {"allowed_hosts": tx("allowed_hosts"), "tls_fingerprint": tx("tls_fingerprint"), "tls": tls,
                "advanced": tx("advanced"), "advanced_orig": orig, "old_sha": sha, "approval": "prompt"}

    def test_fetch_shows_the_certificate_and_adds_the_pin_without_saving(self):
        before = self.stored()
        code, body = self.fetch()
        self.assertEqual(code, 200)
        self.assertIn(self.dev.fp, body)
        self.assertIn("(self-signed)", body)
        self.assertIn("device.example.com", body)
        f = self.fields(body)
        self.assertEqual((f["tls"], f["tls_fingerprint"]), ("pin", self.dev.fp))
        self.assertEqual(self.stored(), before)                          # a fetch writes nothing
        self.assertEqual(self.events("credential_changed"), [])
        ev = self.events("credential_fingerprint_fetched")
        self.assertEqual([e["result"] for e in ev], ["ok"])
        self.assertGreaterEqual(self.dev.accepted, 1)

    def test_the_fetched_pin_saves_through_review_with_the_widening_tick(self):
        code, body = self.fetch()
        self.assertEqual(code, 200)
        pc, pbody = self.post("/credentials/svc/preview", **self.fields(body))
        self.assertEqual(pc, 200)
        self.assertIn("adds a trusted TLS fingerprint", pbody)
        meta_json = html.unescape(pbody.split("name=meta_json value='")[1].split("'>")[0])
        sc, _ = self.post("/credentials/svc/save", old_sha=self.stored_sha(), meta_json=meta_json)
        self.assertEqual(sc, 400)                                        # not without the tick
        self.assertNotIn("tls_fingerprint", self.stored())
        sc, _ = self.post("/credentials/svc/save", old_sha=self.stored_sha(), meta_json=meta_json, confirm_widen="1")
        self.assertEqual(sc, 200)
        self.assertEqual(self.stored()["tls_fingerprint"], self.dev.fp)
        self.assertEqual(self.stored()["custom"], {"keep": "me"})        # the rest of the metadata survived the round trip
        self.assertEqual(self.broker._tls_policy(["svc"])["fingerprint"], (self.dev.fp.split(":")[1],))

    def test_certificate_text_is_escaped(self):
        code, body = self.fetch()
        self.assertEqual(code, 200)
        # the certificate library writes the subject as CN=dev\<i\>x\</i\>...; the page must escape what it gets
        self.assertIn("CN=dev\\&lt;i\\&gt;x", body)                     # positive control: the subject is shown
        self.assertNotIn("\\<i\\>", body)

    def test_only_a_listed_host_and_port_is_fetched(self):
        before = self.dev.accepted
        for reason, fp_host, hosts in (("not_listed", "other.example.com", self.entry),
                                       ("not_listed", "127.0.0.1:1", self.entry),
                                       ("invalid", "bad host!", self.entry),
                                       ("destination", "169.254.169.254", "169.254.169.254")):
            with self.subTest(fp_host=fp_host):
                code, body = self.fetch(fp_host=fp_host, allowed_hosts=hosts)
                self.assertEqual(code, 400)
                self.assertIn("Could not fetch a certificate", body)
                self.assertEqual(self.events("credential_fingerprint_fetched")[-1]["result"], reason)
        self.assertEqual(self.dev.accepted, before)                      # nothing was dialled
        self.assertEqual(self.fetch()[0], 200)                           # positive control

    def test_a_failure_is_a_closed_label(self):
        port = _closed_port()
        code, body = self.fetch(fp_host=f"127.0.0.1:{port}", allowed_hosts=f"127.0.0.1:{port}")
        self.assertEqual(code, 400)
        self.assertIn("Could not fetch a certificate: connection", body)
        self.assertNotIn("Errno", body)
        self.assertEqual(self.events("credential_fingerprint_fetched")[-1]["result"], "connection")

    def test_fetches_are_rate_limited(self):
        self.broker.FP_RATE = (1, 60)
        self.assertEqual(self.fetch()[0], 200)
        code, body = self.fetch()
        self.assertEqual(code, 400)
        self.assertEqual(self.events("credential_fingerprint_fetched")[-1]["result"], "rate_limited")

    def test_needs_the_human_session_and_a_token(self):
        before = self.dev.accepted
        self.assertEqual(self.post("/credentials/svc/fingerprint", csrf=False, fp_host=self.entry,
                                   allowed_hosts=self.entry)[0], 403)
        self.assertEqual(self.post("/credentials/svc/fingerprint", user="mallory", fp_host=self.entry,
                                   allowed_hosts=self.entry)[0], 403)
        self.assertEqual(self.dev.accepted, before)

    def test_the_audit_names_no_host(self):
        self.assertEqual(self.fetch()[0], 200)
        ev = self.events("credential_fingerprint_fetched")
        self.assertEqual(len(ev), 1)                                     # positive control
        self.assertEqual(len(ev[0]["host_sha256"]), 12)
        with open(self.audit) as f:
            self.assertNotIn(self.entry, f.read())


class Secrecy(Base):
    def test_editor_events_are_hidden_from_the_agent_audit_api(self):
        from secret_broker import audit_api
        for ev in ("credentials_viewed", "credential_changed", "credential_change_refused",
                   "credential_change_failed", "credential_created", "credential_renamed", "credential_deleted",
                   "credential_fingerprint_fetched"):
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


class SaveFromForm(Base):
    """The edit form's own Save button: posts the form fields to /save (no meta_json)."""

    def direct(self, **over):
        return self.post("/credentials/svc/save", **self.form(**over))

    def test_the_edit_page_has_save_and_close(self):
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertIn("<form class=cred-form id=cedit method=post action='/credentials/svc/save'>", body)
        self.assertIn("<button type=submit class='btn approve'>Save</button>", body)
        self.assertIn("formaction='/credentials/svc/preview'>Review changes</button>", body)
        self.assertIn("<a class=btn id=cclose href='/credentials'>Close</a>", body)
        self.assertRegex(body, r"<script nonce='[^']+'>\s*\(function\(\)\{\s*var q=document.getElementById\('cq'\)")

    def test_a_narrowing_change_saves_and_returns_to_the_list(self):
        code, body = self.direct(allowed_hosts="127.0.0.1")
        self.assertEqual(code, 200)
        self.assertIn("<div class=flash>Saved: svc</div>", body)
        self.assertIn("id=ctbl", body)                                   # back on the list
        self.assertEqual(self.stored()["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(self.stored()["custom"], {"keep": "me"})
        self.assertEqual(len(self.events("credential_changed")), 1)

    def test_a_widening_change_goes_to_review_even_with_a_tick_in_the_form(self):
        cases = {"host_added": dict(allowed_hosts="127.0.0.1\nlocalhost\n" + NEW_HOST),
                 "approval_allow": dict(approval="allow"), "tls_unverified": dict(tls="skip")}
        for label, over in cases.items():
            with self.subTest(label):
                before = self.stored()
                code, body = self.direct(confirm_widen="1", **over)
                self.assertEqual(code, 200)
                self.assertIn("Review changes to svc", body)
                self.assertIn("This change widens access", body)
                self.assertIn(crededitor.WIDEN_TEXT[label], body)
                self.assertIn("name=meta_json value=", body)
                self.assertEqual(self.stored(), before)                  # nothing written from the form
                self.assertEqual(self.events("credential_changed"), [])
        # the review page's own Save, with the tick, does write (the path above was not simply broken)
        self.assertEqual(self.save(confirm=True, approval="allow")[1], 200)
        self.assertEqual(self.stored()["approval"], "allow")

    def test_a_stale_form_is_refused(self):
        opened = self.form(allowed_hosts="127.0.0.1")
        self.reset_to({**self.stored(), "approval": "allow"})
        theirs = self.stored()
        code, body = self.post("/credentials/svc/save", **opened)
        self.assertEqual(code, 409)
        self.assertIn("changed in the vault after you opened it", body)
        self.assertEqual(self.stored(), theirs)
        self.assertEqual(self.events("credential_change_refused")[-1]["reason"], "conflict")

    def test_invalid_form_input_is_refused(self):
        before = self.stored()
        code, body = self.direct(allowed_hosts="not a host!")
        self.assertEqual(code, 400)
        self.assertIn("allowed_hosts must be up to 10 plain hostnames", body)
        self.assertEqual(self.stored(), before)

    def test_no_change_is_reported(self):
        code, body = self.direct()
        self.assertEqual(code, 200)
        self.assertIn("No changes: svc", body)
        self.assertEqual(self.events("credential_changed"), [])


class ListPage(Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["shell"] = {"vars": {"SHELL_KEY": {"item": "Shell", "field": "token"}},
                                   "allowed_hosts": ["10.9.8.7"], "approval": "allow",
                                   "tls_verify": False}
        cfg["_vault"] = {"Shell": {"token": "S3CR3T-shell"}}

    def visible(self, body):
        return sorted(n for h, n in (
            (m.group(1), m.group(2)) for m in re.finditer(
                r"<tr class=r data-s='[^']*'( hidden)?>.*?href='/credentials/(\w+)'", body)) if not h)

    def test_icons_say_what_each_credential_is(self):
        code, body = self.get("/credentials")
        self.assertEqual(code, 200)
        self.assertEqual(self.visible(body), ["shell", "svc"])
        shell = body[body.index("href='/credentials/shell'"):]
        self.assertIn("aria-label='Approval: allowed without asking'", shell)
        self.assertIn("aria-label='TLS: NOT verified'", shell)
        svc = body[body.index("href='/credentials/svc'"):body.index("href='/credentials/shell'")] \
            if body.index("href='/credentials/svc'") < body.index("href='/credentials/shell'") \
            else body[body.index("href='/credentials/svc'"):]
        self.assertIn("aria-label='Approval: asks on your phone'", svc)
        self.assertIn("aria-label='TLS: verified'", svc)
        self.assertIn("2 credentials", body)

    def test_search_hides_rows_that_do_not_match(self):
        code, body = self.get("/credentials?q=10.9.8")
        self.assertEqual(code, 200)
        self.assertEqual(self.visible(body), ["shell"])
        self.assertIn("href='/credentials/svc'", body)                   # rendered, only hidden
        self.assertIn("1 of 2 credentials", body)
        self.assertIn("<p id=cnone hidden>", body)
        code, body = self.get("/credentials?q=allow+unverified")         # every word must match
        self.assertEqual(self.visible(body), ["shell"])
        code, body = self.get("/credentials?q=nothing-like-this")
        self.assertEqual(self.visible(body), [])
        self.assertIn("0 of 2 credentials", body)
        self.assertIn("<p id=cnone>", body)

    def test_the_query_is_escaped(self):
        evil = "<script>alert(1)</script>'"
        code, body = self.get("/credentials?q=" + urllib.parse.quote(evil))
        self.assertEqual(code, 200)
        self.assertIn("value='&lt;script&gt;alert(1)&lt;/script&gt;&#x27;'", body)
        self.assertNotIn(evil, body)

    def test_the_list_shows_no_value(self):
        code, body = self.get("/credentials")
        self.assertIn("href='/credentials/shell'", body)
        self.assertNotIn("S3CR3T-shell", body)
        self.assertNotIn(t.SECRET, body)


class Units(unittest.TestCase):
    def test_kind_of(self):
        self.assertEqual(crededitor.kind_of({"ssh": True, "vars": {"K": {"field": "private_key"}}}), "ssh")
        self.assertEqual(crededitor.kind_of({"vars": {"U": {"field": "username"}, "P": {"field": "password"}}}),
                         "login")
        self.assertEqual(crededitor.kind_of({"vars": {"U": {"field": "notes", "key": "username"}}}), "login")
        self.assertEqual(crededitor.kind_of({"vars": {"T": {"field": "notes"}}}), "token")

    def test_matches_needs_every_word(self):
        self.assertTrue(crededitor.matches("svc token 127.0.0.1", "SVC  127"))
        self.assertFalse(crededitor.matches("svc token 127.0.0.1", "svc login"))
        self.assertTrue(crededitor.matches("anything", ""))

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
