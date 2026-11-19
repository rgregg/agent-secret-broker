"""Credential values on the Credentials tab: show, replace, add and remove a credential's values."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import re
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_credential_editor as ed  # noqa: E402
from secret_broker import crededitor  # noqa: E402
from secret_broker.backends import BackendError, BackendNotFound  # noqa: E402
from secret_broker.broker import MAX_STORE_VALUE  # noqa: E402

NEW_VALUE = "S3CR3T-new-value-9f1"
EXTRA = "S3CR3T-extra-77a"
MULTI_ID, MULTI_SEC = "S3CR3T-id-31", "S3CR3T-sec-32"


def _ssh_pair():
    k = ed25519.Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return priv, pub


SSH_PRIV, SSH_PUB = _ssh_pair()


class Base(ed.Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["multi"] = {"vars": {"M_ID": {"item": "Multi", "field": "notes", "key": "ID"},
                                            "M_SEC": {"item": "Multi", "field": "notes", "key": "SECRET"}},
                                   "allowed_hosts": ["127.0.0.1"]}
        cfg["secrets"]["sshk"] = {"vars": {"SSHK_KEY": {"item": "Sshk", "field": "private_key"}},
                                  "ssh": True, "ssh_public_key": SSH_PUB}
        cfg["_vault"] = {"Multi": {"notes": json.dumps({"ID": MULTI_ID, "SECRET": MULTI_SEC})},
                         "Sshk": {"private_key": SSH_PRIV}}

    def vault(self, item, field):
        return self.broker.backend.get(item, field)

    def audit_text(self):
        with open(self.audit) as f:
            return f.read()

    def assert_no_values_in_audit(self):
        text = self.audit_text()
        self.assertIn("credential_value", text)                          # positive control: events were written
        for v in (t.SECRET, NEW_VALUE, EXTRA, MULTI_ID, MULTI_SEC):
            self.assertNotIn(v, text)

    def raw_post(self, path, accept=None, csrf=True, user="alice", **form):
        if csrf:
            form["csrf"] = self.broker.csrf_token("alice")
        hdr = {"X-authentik-username": user}
        if accept:
            hdr["Accept"] = accept
        r = t.urllib.request.Request(self.abase + path, data=ed.urllib.parse.urlencode(form).encode(),
                                     headers=hdr, method="POST")
        try:
            with t.urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except t.urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def sha(self, name):
        return crededitor.digest(self.broker.credential_stored_meta(name))


class Reveal(Base):
    def test_reveals_a_plain_and_a_keyed_value(self):
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["value"], t.SECRET)
        r = self.broker.reveal_value("multi", "M_SEC", "alice")
        self.assertEqual((r["status"], r["value"]), ("ok", MULTI_SEC))
        ev = self.events("credential_value_revealed")
        self.assertEqual([(e["secret"], e["var"], e["user"]) for e in ev],
                         [("svc", "SVC_TOKEN", "alice"), ("multi", "M_SEC", "alice")])
        self.assert_no_values_in_audit()

    def test_refusals_are_closed_labels(self):
        cases = {("svc", "NOPE"): "unknown_var", ("sshk", "SSHK_KEY"): "ssh"}
        for (name, var), reason in cases.items():
            with self.subTest(reason):
                r = self.broker.reveal_value(name, var, "alice")
                self.assertEqual((r["status"], r["reason"]), ("refused", reason))
                self.assertNotIn("value", r)
        self.assertEqual([e["reason"] for e in self.events("credential_value_refused")], ["unknown_var", "ssh"])
        self.assertEqual(self.events("credential_value_revealed"), [])

    def test_a_key_on_a_field_that_is_not_structured_is_invalid(self):
        self.broker.backend.put("Multi", "notes", "plain text, not structured")
        r = self.broker.reveal_value("multi", "M_ID", "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "invalid"))
        self.assertEqual(r["message"], self.broker._VALUE_TEXT["invalid"])

    def test_a_vault_failure_is_a_fixed_label(self):
        with mock.patch.object(self.broker.backend, "get", side_effect=BackendError("boom " + t.SECRET)):
            r = self.broker.reveal_value("svc", "SVC_TOKEN", "alice")
        self.assertEqual((r["status"], r["reason"], r["message"]), ("failed", "vault_read", "Could not read the vault"))
        self.assertNotIn(t.SECRET, self.audit_text())

    def test_rate_limited_per_user(self):
        for _ in range(self.broker.VALUE_RATE[0]):
            self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["status"], "ok")
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "alice")["reason"], "rate_limited")
        self.assertEqual(self.broker.reveal_value("svc", "SVC_TOKEN", "bob")["status"], "ok")   # per user

    def test_internal_key_is_refused(self):
        with mock.patch.object(self.broker, "is_internal_secret", side_effect=lambda n: n == "svc"):
            r = self.broker.reveal_value("svc", "SVC_TOKEN", "alice")
        self.assertEqual(r["reason"], "internal")


class Replace(Base):
    def test_replaces_and_keeps_the_previous_value(self):
        r = self.broker.replace_value("svc", "SVC_TOKEN", NEW_VALUE, "alice")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.vault("Svc", "token"), NEW_VALUE)
        self.assertEqual(self.vault("Svc", "previous_value"), t.SECRET)
        ev = self.events("credential_value_changed")
        self.assertEqual([(e["secret"], e["var"], e["value_bytes"]) for e in ev],
                         [("svc", "SVC_TOKEN", len(NEW_VALUE))])
        self.assert_no_values_in_audit()

    def test_a_keyed_value_changes_only_its_key(self):
        self.assertEqual(self.broker.replace_value("multi", "M_ID", NEW_VALUE, "alice")["status"], "ok")
        self.assertEqual(json.loads(self.vault("Multi", "notes")), {"ID": NEW_VALUE, "SECRET": MULTI_SEC})

    def test_refusals_write_nothing(self):
        cases = [("svc", "SVC_TOKEN", "", "empty"), ("svc", "SVC_TOKEN", "a\x00b", "bad_value"),
                 ("svc", "SVC_TOKEN", "a\x1bb", "bad_value"),
                 ("svc", "SVC_TOKEN", "x" * (MAX_STORE_VALUE + 1), "too_large"),
                 ("svc", "NOPE", NEW_VALUE, "unknown_var"), ("sshk", "SSHK_KEY", NEW_VALUE, "ssh")]
        for name, var, value, reason in cases:
            with self.subTest(reason):
                r = self.broker.replace_value(name, var, value, "alice")
                self.assertEqual((r["status"], r["reason"]), ("refused", reason))
        self.assertEqual(self.vault("Svc", "token"), t.SECRET)
        self.assertEqual(self.vault("Sshk", "private_key"), SSH_PRIV)
        self.assertEqual(self.events("credential_value_changed"), [])

    def test_a_vault_failure_keeps_no_text(self):
        with mock.patch.object(self.broker.backend, "put", side_effect=BackendError("write failed " + NEW_VALUE)):
            r = self.broker.replace_value("svc", "SVC_TOKEN", NEW_VALUE, "alice")
        self.assertEqual((r["status"], r["reason"]), ("failed", "vault_write"))
        self.assertIn("credential_value_refused", self.audit_text())
        self.assertNotIn(NEW_VALUE, self.audit_text())


class Add(Base):
    def test_adds_the_field_and_the_variable_in_one_write(self):
        r = self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice", confirm=True)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        self.assertEqual(self.stored()["vars"]["SVC_EXTRA"], {"field": "SVC_EXTRA"})
        self.assertEqual(self.stored()["custom"], {"keep": "me"})        # the rest of the metadata kept
        self.assertIn("SVC_EXTRA", self.broker.cfg["secrets"]["svc"]["vars"])   # live
        self.assertEqual([(e["var"], e["value_bytes"]) for e in self.events("credential_value_added")],
                         [("SVC_EXTRA", len(EXTRA))])
        self.assertEqual(self.broker.reveal_value("svc", "SVC_EXTRA", "alice")["value"], EXTRA)
        self.assert_no_values_in_audit()

    def test_needs_the_tick(self):
        before = self.stored()
        r = self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "needs_confirmation"))
        self.assertEqual(self.stored(), before)
        with self.assertRaises(BackendNotFound):
            self.vault("Svc", "SVC_EXTRA")

    def test_refusals(self):
        sha = self.sha("svc")
        self.broker.backend.put("Svc", "TAKEN", "S3CR3T-taken", add_field=True)
        cases = [("SVC_TOKEN", EXTRA, sha, "exists"), ("TAKEN", EXTRA, sha, "field_exists"),
                 ("bad name", EXTRA, sha, "invalid_name"), ("LD_PRELOAD", EXTRA, sha, "invalid_name"),
                 ("SVC_EXTRA", "", sha, "empty"), ("SVC_EXTRA", EXTRA, "0" * 64, "conflict")]
        for var, value, s, reason in cases:
            with self.subTest(reason=reason, var=var):
                r = self.broker.add_value("svc", var, value, s, "alice", confirm=True)
                self.assertEqual(r["reason"], reason)
                self.assertNotIn(EXTRA, r["message"])
        self.assertEqual(set(self.stored()["vars"]), {"SVC_TOKEN"})
        self.assertEqual(self.events("credential_value_added"), [])
        r = self.broker.add_value("sshk", "X", EXTRA, self.sha("sshk"), "alice", confirm=True)
        self.assertEqual(r["reason"], "ssh")



class Remove(Base):
    """Removing a variable deletes its value from the vault (it is irreversible, so it needs `confirm`)."""

    def remove(self, name, var, **kw):
        kw.setdefault("confirm", True)
        return self.broker.remove_value(name, var, self.sha(name), "alice", **kw)

    def add_extra(self):
        self.assertEqual(self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice",
                                               confirm=True)["status"], "ok")

    def test_deletes_the_vault_field_and_its_previous_value(self):
        self.add_extra()
        self.assertEqual(self.broker.replace_value("svc", "SVC_EXTRA", NEW_VALUE, "alice")["status"], "ok")
        self.assertEqual(self.vault("Svc", "previous_value"), EXTRA)          # premise: a previous copy exists
        r = self.remove("svc", "SVC_EXTRA")
        self.assertEqual((r["status"], r["outcome"]), ("ok", "field_deleted"))
        for f in ("SVC_EXTRA", "previous_value", "previous_replaced_at"):
            with self.subTest(f), self.assertRaises(BackendNotFound):
                self.vault("Svc", f)
        self.assertEqual(self.vault("Svc", "token"), t.SECRET)                # the other value is untouched
        self.assertNotIn("SVC_EXTRA", self.stored()["vars"])
        self.assertNotIn("SVC_EXTRA", self.broker.cfg["secrets"]["svc"]["vars"])
        raw = json.dumps(self.broker.backend._data["Svc"])
        self.assertNotIn(EXTRA, raw)
        self.assertNotIn(NEW_VALUE, raw)

    def test_the_audit_event_names_the_variable_and_never_a_value(self):
        self.add_extra()
        self.remove("svc", "SVC_EXTRA")
        ev = self.events("credential_value_removed")
        self.assertEqual([(e["secret"], e["var"], e["outcome"], e["previous_dropped"]) for e in ev],
                         [("svc", "SVC_EXTRA", "field_deleted", True)])
        self.assert_no_values_in_audit()

    def test_a_keyed_variable_drops_only_its_key_and_the_previous_copy(self):
        self.assertEqual(self.broker.replace_value("multi", "M_ID", NEW_VALUE, "alice")["status"], "ok")
        self.assertIn(MULTI_SEC, self.vault("Multi", "previous_value"))        # premise: it holds the whole blob
        r = self.remove("multi", "M_SEC")
        self.assertEqual((r["status"], r["outcome"]), ("ok", "key_dropped"))
        self.assertEqual(json.loads(self.vault("Multi", "notes")), {"ID": NEW_VALUE})
        with self.assertRaises(BackendNotFound):
            self.vault("Multi", "previous_value")
        self.assertNotIn(MULTI_SEC, json.dumps(self.broker.backend._data["Multi"]))
        self.assertEqual(set(self.stored_of("multi")["vars"]), {"M_ID"})

    def stored_of(self, name):
        return self.broker.credential_stored_meta(name)

    def test_a_field_another_variable_still_uses_is_kept(self):
        meta = self.broker.credential_stored_meta("svc")
        meta["vars"]["SVC_ALIAS"] = {"field": "token"}
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)
        self.assertEqual(self.broker.replace_value("svc", "SVC_TOKEN", NEW_VALUE, "alice")["status"], "ok")
        r = self.remove("svc", "SVC_ALIAS")
        self.assertEqual((r["status"], r["outcome"]), ("ok", "field_kept"))
        self.assertEqual(self.vault("Svc", "token"), NEW_VALUE)               # still there: SVC_TOKEN uses it
        self.assertEqual(self.vault("Svc", "previous_value"), t.SECRET)       # untouched: nothing destructive
        self.assertEqual(set(self.stored()["vars"]), {"SVC_TOKEN"})
        self.assertFalse(self.events("credential_value_removed")[0]["previous_dropped"])

    def test_a_built_in_field_is_cleared(self):
        self.broker.backend._data["Svc"]["notes"] = EXTRA
        meta = self.broker.credential_stored_meta("svc")
        meta["vars"]["SVC_NOTE"] = {"field": "notes"}
        self.broker.backend.set_meta("Svc", meta)
        self.broker._refresh_if(0)
        self.assertEqual(self.vault("Svc", "notes"), EXTRA)                  # premise
        r = self.remove("svc", "SVC_NOTE")
        self.assertEqual((r["status"], r["outcome"]), ("ok", "field_deleted"))
        self.assertEqual(self.vault("Svc", "notes"), "")
        self.assertNotIn(EXTRA, json.dumps(self.broker.backend._data["Svc"]))

    def test_without_the_capability_nothing_changes(self):
        self.add_extra()
        before_vault, before_meta = json.dumps(self.broker.backend._data["Svc"]), self.stored()
        with mock.patch.object(type(self.broker.backend), "capabilities",
                               self.broker.backend.capabilities - {"delete_field"}):
            r = self.remove("svc", "SVC_EXTRA")
        self.assertEqual((r["status"], r["reason"]), ("refused", "no_delete"))
        self.assertEqual(r["message"], self.broker._VALUE_TEXT["no_delete"])
        self.assertEqual(json.dumps(self.broker.backend._data["Svc"]), before_vault)   # no fallback: nothing written
        self.assertEqual(self.stored(), before_meta)
        self.assertEqual(self.events("credential_value_removed"), [])
        self.assertEqual([e["reason"] for e in self.events("credential_value_refused")], ["no_delete"])

    def test_it_needs_the_confirmation(self):
        self.add_extra()
        r = self.remove("svc", "SVC_EXTRA", confirm=False)
        self.assertEqual((r["status"], r["reason"]), ("refused", "confirm_delete"))
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        self.assertIn("SVC_EXTRA", self.stored()["vars"])

    def test_a_vault_failure_changes_nothing_and_leaks_nothing(self):
        self.add_extra()
        with mock.patch.object(self.broker.backend, "delete_field", side_effect=BackendError("boom " + EXTRA)):
            r = self.remove("svc", "SVC_EXTRA")
        self.assertEqual((r["status"], r["reason"], r["message"]),
                         ("failed", "vault_write", "Could not save to the vault"))
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        self.assertIn("SVC_EXTRA", self.stored()["vars"])
        self.assertNotIn(EXTRA, self.audit_text())

    def test_refusals(self):
        self.assertEqual(self.remove("svc", "SVC_TOKEN")["reason"], "last")
        self.assertEqual(self.remove("multi", "NOPE")["reason"], "unknown_var")
        self.assertEqual(self.broker.remove_value("multi", "M_ID", "0" * 64, "alice", confirm=True)["reason"],
                         "conflict")
        self.assertEqual(self.remove("sshk", "SSHK_KEY")["reason"], "ssh")
        self.assertEqual(set(self.broker.credential_stored_meta("multi")["vars"]), {"M_ID", "M_SEC"})
        self.assertEqual(json.loads(self.vault("Multi", "notes")), {"ID": MULTI_ID, "SECRET": MULTI_SEC})
        self.assertEqual(self.events("credential_value_removed"), [])


class Hidden(unittest.TestCase):
    def test_value_events_are_hidden_from_the_agent_audit_api(self):
        from secret_broker import audit_api
        for ev in ("credential_value_revealed", "credential_value_changed", "credential_value_added",
                   "credential_value_removed", "credential_value_refused"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertIsNone(audit_api.redact({"seq": 1, "ts": 1.0, "event": ev, "secret": "svc", "var": "V"}))


class Pages(Base):
    """The Values card and its routes on the approval site."""

    def test_the_edit_page_lists_variables_and_holds_no_value(self):
        code, body = self.get("/credentials/multi")
        self.assertEqual(code, 200)
        self.assertIn("<code>M_ID</code>", body)                         # positive control
        self.assertIn("<code>M_SEC</code>", body)
        self.assertIn("field <code>notes</code>, key <code>SECRET</code>", body)
        self.assertIn("action='/credentials/multi/reveal'", body)
        for v in (MULTI_ID, MULTI_SEC, t.SECRET):
            self.assertNotIn(v, body)

    def test_reveal_json(self):
        code, hdr, body = self.raw_post("/credentials/svc/reveal", accept="application/json", var="SVC_TOKEN")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"value": t.SECRET})
        self.assertEqual(hdr["Cache-Control"], "no-store")
        code, _, body = self.raw_post("/credentials/svc/reveal", accept="application/json", var="NOPE")
        self.assertEqual(code, 400)
        self.assertEqual(json.loads(body), {"error": self.broker._VALUE_TEXT["unknown_var"]})

    def test_reveal_without_script_renders_the_one_value_escaped(self):
        tricky = "S3CR3T-'<b>x</b></script>"
        self.broker.backend.put("Multi", "notes", json.dumps({"ID": tricky, "SECRET": MULTI_SEC}))
        code, hdr, body = self.raw_post("/credentials/multi/reveal", var="M_ID")
        self.assertEqual(code, 200)
        self.assertEqual(hdr["Cache-Control"], "no-store")
        esc = "S3CR3T-&#x27;&lt;b&gt;x&lt;/b&gt;&lt;/script&gt;"
        self.assertEqual(body.count(esc), 1)                             # in one box: M_ID's
        self.assertRegex(body, r"<input type=text name=value id='val-M_ID' form='sv-M_ID' value='" + re.escape(esc) + "'")
        self.assertNotIn(tricky, body)
        self.assertNotIn(MULTI_SEC, body)                                # only the one asked for

    def test_reveal_needs_csrf_and_the_human(self):
        code, _, _ = self.raw_post("/credentials/svc/reveal", csrf=False, var="SVC_TOKEN")
        self.assertEqual(code, 403)
        code, _, _ = self.raw_post("/credentials/svc/reveal", user="mallory", var="SVC_TOKEN")
        self.assertEqual(code, 403)
        self.assertEqual(self.events("credential_value_revealed"), [])
        code, _ = t.req(self.base + "/credentials/svc/reveal", "POST", {"var": "SVC_TOKEN"}, {"X-Client-Key": t.KEY})
        self.assertEqual(code, 404)
        # positive control: the same request with the token works
        self.assertEqual(self.raw_post("/credentials/svc/reveal", var="SVC_TOKEN")[0], 200)

    def test_replace_never_echoes_the_value(self):
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=NEW_VALUE)
        self.assertEqual(code, 200)
        self.assertIn("Value replaced: SVC_TOKEN", body)
        self.assertNotIn(NEW_VALUE, body)
        self.assertEqual(self.vault("Svc", "token"), NEW_VALUE)

    def test_a_failed_replace_re_renders_without_the_value(self):
        with mock.patch.object(self.broker.backend, "put", side_effect=BackendError("x")):
            code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=NEW_VALUE)
        self.assertEqual(code, 500)
        self.assertIn("Could not save to the vault", body)
        self.assertNotIn(NEW_VALUE, body)

    def test_add_and_remove(self):
        sha = self.sha("svc")
        code, _, body = self.raw_post("/credentials/svc/value/add", var="SVC_EXTRA", value=EXTRA, old_sha=sha)
        self.assertEqual(code, 400)                                      # no tick
        self.assertIn("Tick the box", body)
        self.assertNotIn(EXTRA, body)
        code, _, body = self.raw_post("/credentials/svc/value/add", var="SVC_EXTRA", value=EXTRA, old_sha=sha,
                                      confirm="1")
        self.assertEqual(code, 200)
        self.assertIn("Value added: SVC_EXTRA", body)
        self.assertNotIn(EXTRA, body)
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        code, _, body = self.raw_post("/credentials/svc/value/remove", var="SVC_EXTRA", old_sha=self.sha("svc"))
        self.assertEqual(code, 400)                                      # no confirmation: nothing is deleted
        self.assertIn(self.broker._VALUE_TEXT["confirm_delete"], body)
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        code, _, body = self.raw_post("/credentials/svc/value/remove", var="SVC_EXTRA", old_sha=self.sha("svc"),
                                      confirm="1")
        self.assertEqual(code, 200)
        self.assertIn("Removed from the vault: SVC_EXTRA", body)
        self.assertNotIn("SVC_EXTRA", self.stored()["vars"])
        with self.assertRaises(BackendNotFound):
            self.vault("Svc", "SVC_EXTRA")
        code, _, _ = self.raw_post("/credentials/svc/value/remove", var="SVC_TOKEN", old_sha="0" * 64)
        self.assertEqual(code, 409)

    def test_ssh_shows_the_public_key_and_no_show_button(self):
        code, body = self.get("/credentials/sshk")
        self.assertEqual(code, 200)
        self.assertIn(SSH_PUB.split()[1][:40], body)
        self.assertNotIn("action='/credentials/sshk/reveal'", body)
        self.assertNotIn(SSH_PRIV.splitlines()[1], body)
        self.assertEqual(self.raw_post("/credentials/sshk/reveal", var="SSHK_KEY")[0], 400)

    def test_page_script_wires_the_buttons(self):
        code, body = self.get("/credentials/svc")
        self.assertIn("data-reveal", body)
        self.assertIn("'Accept':'application/json'", body)


class Peek(Base):
    def test_every_box_that_takes_a_new_value_has_the_toggle(self):
        # the in-place editor of an existing value holds only the placeholder dots (its Show button is the
        # reveal flow, not this toggle); the Add box and the New credential box take typed text and keep it
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertEqual(body.count("type=password name=value"), 2)       # the in-place box (one variable) and Add
        self.assertEqual(body.count("<span class=peek><input type=password name=value"), 1)
        self.assertIn("<span class=peek><input type=password name=value id='val-ADD'", body)
        self.assertIn("querySelectorAll('button[data-peek]')", body)
        code, body = self.get("/credentials/new")
        self.assertIn("<span class=peek><input type=password name=value", body)
        self.assertIn("querySelectorAll('button[data-peek]')", body)

    def test_the_toggle_never_carries_a_value(self):
        from secret_broker import peek
        out = peek.wrap("<input type=password name=x>")
        self.assertTrue(out.startswith("<span class=peek><input type=password name=x><button type=button"))
        self.assertNotIn("value=", out)


class WithASummaryKey(Base):
    """A summary key provider is configured (the normal production setup): is_internal_secret takes the
    catalog lock, so a value action must not call it while holding that lock."""

    def setUp(self):
        super().setUp()
        import types
        self.broker.summarizer = types.SimpleNamespace(key_providers=[types.SimpleNamespace(name="multi")])
        self.assertTrue(self.broker.is_internal_secret("multi"))          # premise: real lookup, not a mock

    def run_bounded(self, fn):
        import threading
        out = {}
        th = threading.Thread(target=lambda: out.setdefault("r", fn()), daemon=True)
        th.start()
        th.join(10)                                                      # returns at once unless it deadlocks
        self.assertFalse(th.is_alive(), "the value action deadlocked on the catalog lock")
        self.assertFalse(self.broker._cfg_lock.locked())
        return out["r"]

    def test_add_and_remove_finish_and_work(self):
        r = self.run_bounded(lambda: self.broker.add_value("svc", "SVC_EXTRA", EXTRA, self.sha("svc"), "alice",
                                                           confirm=True))
        self.assertEqual(r["status"], "ok")
        self.assertEqual(self.vault("Svc", "SVC_EXTRA"), EXTRA)
        r = self.run_bounded(lambda: self.broker.remove_value("svc", "SVC_EXTRA", self.sha("svc"), "alice",
                                                                            confirm=True))
        self.assertEqual(r["status"], "ok")
        self.assertNotIn("SVC_EXTRA", self.stored()["vars"])

    def test_the_internal_key_itself_is_refused_for_every_action(self):
        sha = self.sha("multi")
        self.assertEqual(self.run_bounded(lambda: self.broker.reveal_value("multi", "M_ID", "alice"))["reason"],
                         "internal")
        self.assertEqual(self.run_bounded(lambda: self.broker.replace_value("multi", "M_ID", NEW_VALUE,
                                                                            "alice"))["reason"], "internal")
        self.assertEqual(self.run_bounded(lambda: self.broker.add_value("multi", "M_X", EXTRA, sha, "alice",
                                                                        confirm=True))["reason"], "internal")
        self.assertEqual(self.run_bounded(lambda: self.broker.remove_value("multi", "M_ID", sha,
                                                                           "alice", confirm=True))["reason"], "internal")
        self.assertEqual(json.loads(self.vault("Multi", "notes")), {"ID": MULTI_ID, "SECRET": MULTI_SEC})


class MultiLine(Base):
    PEM = "-----BEGIN KEY-----\nS3CR3T-line-one\nS3CR3T-line-two\n-----END KEY-----\n"

    def test_reveal_keeps_newlines_in_both_paths(self):
        self.broker.backend.put("Svc", "token", self.PEM)
        code, _, body = self.raw_post("/credentials/svc/reveal", accept="application/json", var="SVC_TOKEN")
        self.assertEqual(json.loads(body)["value"], self.PEM)
        code, _, body = self.raw_post("/credentials/svc/reveal", var="SVC_TOKEN")
        self.assertEqual(code, 200)
        # a textarea, with the leading newline the HTML parser drops, so the value's own first line survives
        self.assertIn("rows=4 spellcheck=false autocomplete=off aria-label='Value of SVC_TOKEN'>\n"
                      "-----BEGIN KEY-----\nS3CR3T-line-one\n", body)

    def test_replace_and_add_take_a_multi_line_value_with_lf_line_ends(self):
        crlf = self.PEM.replace("\n", "\r\n")                           # what a browser submits from a textarea
        code, _, body = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value="", value_ml=crlf)
        self.assertEqual(code, 200)
        self.assertNotIn("S3CR3T-line-one", body)
        self.assertEqual(self.vault("Svc", "token"), self.PEM)            # LF line ends, nothing else changed
        code, _, _ = self.raw_post("/credentials/svc/value/add", var="SVC_PEM", value="", value_ml=crlf,
                                   old_sha=self.sha("svc"), confirm="1")
        self.assertEqual(code, 200)
        self.assertEqual(self.vault("Svc", "SVC_PEM"), self.PEM)

    def test_the_single_line_box_still_wins_when_the_multi_line_one_is_empty(self):
        code, _, _ = self.raw_post("/credentials/svc/value", var="SVC_TOKEN", value=NEW_VALUE, value_ml="")
        self.assertEqual(code, 200)
        self.assertEqual(self.vault("Svc", "token"), NEW_VALUE)

    def test_the_page_offers_the_multi_line_toggle_not_an_open_box(self):
        code, body = self.get("/credentials/svc")
        self.assertEqual(body.count("<textarea name=value_ml"), 2)       # one per value box and Add, both off
        self.assertEqual(body.count("data-ml="), 2)
        self.assertEqual(len(re.findall(r"<textarea name=value_ml[^>]* hidden disabled", body)), 2)


class Adopted(unittest.TestCase):
    """A vault item with no `broker` field, adopted with defaults (a real one: the memory backend adopts)."""

    def setUp(self):
        import tempfile
        from secret_broker.backends import MemoryBackend
        from secret_broker.broker import Broker
        from secret_broker.notify import FakeNotifier
        self.b = MemoryBackend()
        self.b.put("Plain Note", "notes", t.SECRET, create=True)
        self.broker = Broker({"approve_base_url": "https://s.example"}, self.b, FakeNotifier(),
                             os.path.join(tempfile.mkdtemp(), "audit.jsonl"))
        self.broker.refresh_catalog(fresh=True)
        sc = self.broker.cfg["secrets"]["plain-note"]
        self.assertTrue(sc["auto"])                                       # premise: adopted, no metadata
        self.assertIsNone(self.b.catalog()[0]["meta"])
        self.sha = crededitor.digest(self.broker.credential_stored_meta("plain-note"))

    def test_show_and_replace_work(self):
        self.assertEqual(self.broker.reveal_value("plain-note", "PLAIN_NOTE_NOTE", "alice")["value"], t.SECRET)
        self.assertEqual(self.broker.replace_value("plain-note", "PLAIN_NOTE_NOTE", NEW_VALUE, "alice")["status"], "ok")
        self.assertEqual(self.b.get("Plain Note", "notes"), NEW_VALUE)

    def test_add_and_remove_are_refused_and_write_no_metadata(self):
        r = self.broker.add_value("plain-note", "EXTRA", EXTRA, self.sha, "alice", confirm=True)
        self.assertEqual((r["status"], r["reason"]), ("refused", "adopted"))
        r = self.broker.remove_value("plain-note", "PLAIN_NOTE_NOTE", self.sha, "alice")
        self.assertEqual((r["status"], r["reason"]), ("refused", "adopted"))
        self.assertIsNone(self.b.catalog()[0]["meta"])                    # still no metadata written
        with self.assertRaises(BackendNotFound):
            self.b.get("Plain Note", "EXTRA")

    def test_replace_on_an_unstructured_key_field_is_invalid(self):
        self.b.put("Plain Note", "notes", "not structured")
        self.broker.cfg["secrets"]["plain-note"]["vars"]["K"] = {"item": "Plain Note", "field": "notes", "key": "X"}
        r = self.broker.replace_value("plain-note", "K", NEW_VALUE, "alice")
        self.assertEqual((r["status"], r["reason"], r["message"]), ("refused", "invalid",
                                                                    self.broker._VALUE_TEXT["invalid"]))
        self.assertEqual(self.b.get("Plain Note", "notes"), "not structured")


if __name__ == "__main__":
    unittest.main()
