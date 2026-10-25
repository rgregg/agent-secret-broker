"""The backend conformance suite: the acceptance test for any `VaultBackend`.

Subclass `BackendContract` together with `unittest.TestCase`, implement `make()`
(and, for persistent backends, `reopen()`), and the whole contract in
`secret_broker/backends/base.py` / docs/reference.md is checked:

    class MyBackendContract(BackendContract, unittest.TestCase):
        def make(self, **kw):
            return MyBackend(tempfile.mkdtemp())

Hooks (all optional, each has a safe default):

    make(idle_timeout=None)   a NEW, EMPTY, independent backend. `idle_timeout` (seconds)
                              is passed only when `supports_idle` is True.
    reopen(backend)           a fresh object over the SAME storage (a "restart");
                              leave unimplemented for non-persistent backends
                              (`persistent = False`).
    seed(backend, kind, name) put a native item the contract cannot create: kind is
                              "card", "identity" or "duplicate" (an item whose name
                              differs from `name` only by case, in scope). Return
                              False when impossible; the dependent tests are then skipped.
    ci_lookup                 True (default): a name also matches case-insensitively.

Values in tests are obviously fake. Run with:  python -m unittest tests.test_backends
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from secret_broker import sshkey
from secret_broker.backends import (BackendConflict, BackendError, BackendInvalid, BackendNotFound,
                                    Item, MemoryBackend, NotSupported, VaultBackend, error_class)
from secret_broker.backends.base import KNOWN_CAPABILITIES

SECRET = "s3cr3t-value-DO-NOT-LEAK-7731"
OTHER = "0ther-s3cr3t-value-5512"


def _ssh_pair():
    k = ed25519.Ed25519PrivateKey.generate()
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                          serialization.NoEncryption()).decode()
    return pem, sshkey.public_line(sshkey.load_private(pem))


class BackendContract:
    persistent = False
    supports_idle = False
    ci_lookup = True
    sees_external_writes = True       # a second instance's write shows up in catalog()

    # -- hooks ---------------------------------------------------------------
    def make(self, **kw):
        raise NotImplementedError

    def reopen(self, backend):
        raise NotImplementedError

    def seed(self, backend, kind, name):
        return False

    # -- helpers ---------------------------------------------------------------
    def setUp(self):
        self.b = self.make()
        self.addCleanup(self.b.close)

    def caps(self, b=None):
        return (b or self.b).capabilities

    def need(self, cap):
        if cap not in self.caps():
            self.skipTest(f"backend does not declare {cap!r}")

    def row(self, name, b=None):
        rows = [r for r in (b or self.b).catalog() if r["item"] == name]
        self.assertLessEqual(len(rows), 1)
        return rows[0] if rows else None

    def errors(self, *calls):
        """Run each callable, return the exceptions raised (None for no error)."""
        out = []
        for c in calls:
            try:
                c()
                out.append(None)
            except Exception as e:  # noqa: BLE001
                out.append(e)
        return out

    # == 1. the type itself =======================================================
    def test_is_a_vault_backend(self):
        self.assertIsInstance(self.b, VaultBackend)
        self.assertIsInstance(self.b.kind, str)
        self.assertTrue(self.b.kind)

    def test_capabilities_are_a_frozenset_of_known_names(self):
        self.assertIsInstance(self.b.capabilities, frozenset)
        self.assertLessEqual(self.b.capabilities, KNOWN_CAPABILITIES)

    def test_undeclared_optional_methods_raise_not_supported(self):
        calls = {"create_login": lambda: self.b.create_login("x", "u", "p"),
                 "edit_item": lambda: self.b.edit_item("x", new_name="y"),
                 "warm": lambda: self.b.warm(),
                 "export_items": lambda: self.b.export_items(),
                 "import_items": lambda: self.b.import_items([Item("x", "note", notes="n")])}
        for cap, call in calls.items():
            if cap not in self.caps():
                with self.assertRaises(NotSupported, msg=cap):
                    call()

    def test_set_meta_without_capability_raises_not_supported(self):
        if "set_meta" in self.caps():
            self.skipTest("declares set_meta")
        with self.assertRaises(NotSupported):
            self.b.set_meta("x", {"a": 1})

    def test_close_is_idempotent_and_the_backend_reopens(self):
        self.b.put("C", "notes", "c-val", create=True)
        self.b.close()
        self.b.close()
        self.assertEqual(self.b.get("C", "notes"), "c-val")
        self.b.close()

    # == 2. create and read =========================================================
    def test_create_note_and_read_it(self):
        self.b.put("Note", "notes", "note-value", create=True)
        self.assertEqual(self.b.get("Note", "notes"), "note-value")

    def test_create_login_password_and_read_it(self):
        self.b.put("Login", "password", "pw-value", create=True)
        self.assertEqual(self.b.get("Login", "password"), "pw-value")

    def test_create_custom_field_and_read_it(self):
        self.b.put("Multi", "api_key", "key-value", create=True)
        self.assertEqual(self.b.get("Multi", "api_key"), "key-value")

    def test_auto_alias_follows_item_kind(self):
        self.b.put("N", "notes", "n-val", create=True)
        self.b.put("L", "password", "p-val", create=True)
        for alias in ("auto", None, ""):
            self.assertEqual(self.b.get("N", alias), "n-val")
            self.assertEqual(self.b.get("L", alias), "p-val")

    def test_auto_alias_on_create_means_notes(self):
        self.b.put("A", "auto", "a-val", create=True)
        self.assertEqual(self.b.get("A", "notes"), "a-val")

    def test_ssh_key_item_uses_private_key_field(self):
        pem, pub = _ssh_pair()
        self.b.put("Deploy", "private_key", pem, create=True,
                   meta={"ssh": True, "ssh_public_key": pub})
        self.assertEqual(self.b.get("Deploy", "private_key"), pem)
        self.assertEqual(self.b.get("Deploy", "auto"), pem)
        pem2, _ = _ssh_pair()
        self.b.put("Deploy", "auto", pem2, keep_previous=True)
        self.assertEqual(self.b.get("Deploy", "private_key"), pem2)
        self.assertEqual(self.b.get("Deploy", "previous_value"), pem)

    def test_ssh_key_create_needs_the_public_key(self):
        pem, _ = _ssh_pair()
        with self.assertRaises(BackendInvalid):
            self.b.put("NoPub", "private_key", pem, create=True)
        self.assertIsNone(self.row("NoPub"))

    def test_create_existing_item_is_a_conflict(self):
        self.b.put("Dup", "notes", "one", create=True)
        with self.assertRaises(BackendConflict):
            self.b.put("Dup", "notes", "two", create=True)
        self.assertEqual(self.b.get("Dup", "notes"), "one")

    def test_create_conflict_is_case_insensitive(self):
        if not self.ci_lookup:
            self.skipTest("backend matches names exactly")
        self.b.put("MixedCase", "notes", "one", create=True)
        with self.assertRaises(BackendConflict):
            self.b.put("mixedcase", "notes", "two", create=True)

    def test_values_are_independent_per_item(self):
        self.b.put("A", "notes", "a", create=True)
        self.b.put("B", "notes", "b", create=True)
        self.assertEqual((self.b.get("A", "notes"), self.b.get("B", "notes")), ("a", "b"))

    # == 3. update and previous values ================================================
    def test_update_replaces_the_value(self):
        self.b.put("U", "notes", "old", create=True)
        self.b.put("U", "notes", "new")
        self.assertEqual(self.b.get("U", "notes"), "new")

    def test_update_password_and_custom_field(self):
        self.b.put("P", "password", "p1", create=True)
        self.b.put("P", "password", "p2")
        self.assertEqual(self.b.get("P", "password"), "p2")
        self.b.put("K", "api_key", "k1", create=True)
        self.b.put("K", "api_key", "k2")
        self.assertEqual(self.b.get("K", "api_key"), "k2")

    def test_update_through_the_auto_alias(self):
        self.b.put("N", "notes", "n1", create=True)
        self.b.put("L", "password", "p1", create=True)
        self.b.put("N", "auto", "n2")
        self.b.put("L", None, "p2")
        self.assertEqual((self.b.get("N", "notes"), self.b.get("L", "password")), ("n2", "p2"))

    def test_update_missing_item_is_not_found(self):
        with self.assertRaises(BackendNotFound):
            self.b.put("Nope", "notes", "v")

    def test_update_missing_field_is_not_found(self):
        self.b.put("U", "notes", "n", create=True)
        with self.assertRaises(BackendNotFound):
            self.b.put("U", "no_such_field", "v")
        with self.assertRaises(BackendNotFound):
            self.b.get("U", "no_such_field")

    def test_keep_previous_stores_the_old_value_and_time(self):
        self.b.put("R", "notes", "old-value", create=True)
        self.b.put("R", "notes", "new-value", keep_previous=True)
        self.assertEqual(self.b.get("R", "previous_value"), "old-value")
        stamp = self.b.get("R", "previous_replaced_at")
        self.assertRegex(stamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(self.b.get("R", "notes"), "new-value")

    def test_keep_previous_on_a_login_password(self):
        self.b.put("R", "password", "pw-old", create=True)
        self.b.put("R", "password", "pw-new", keep_previous=True)
        self.assertEqual(self.b.get("R", "previous_value"), "pw-old")

    def test_keep_previous_keeps_only_the_latest(self):
        self.b.put("R", "notes", "v1", create=True)
        self.b.put("R", "notes", "v2", keep_previous=True)
        self.b.put("R", "notes", "v3", keep_previous=True)
        self.assertEqual(self.b.get("R", "previous_value"), "v2")

    def test_no_previous_value_unless_asked(self):
        self.b.put("R", "notes", "v1", create=True)
        self.b.put("R", "notes", "v2")
        with self.assertRaises(BackendNotFound):
            self.b.get("R", "previous_value")

    def test_previous_value_not_stored_when_the_old_value_was_empty(self):
        self.b.put("R", "notes", "", create=True)
        self.b.put("R", "notes", "v2", keep_previous=True)
        with self.assertRaises(BackendNotFound):
            self.b.get("R", "previous_value")

    def test_update_with_meta_replaces_the_metadata(self):
        self.b.put("M", "notes", "v", create=True, meta={"approval": "prompt"})
        self.b.put("M", "notes", "v2", meta={"approval": "allow"})
        self.assertEqual(self.row("M")["meta"], {"approval": "allow"})

    # == 4. reserved names, bad arguments ================================================
    def test_the_metadata_field_is_not_readable(self):
        self.b.put("M", "notes", "v", create=True, meta={"a": 1})
        with self.assertRaises(BackendInvalid):
            self.b.get("M", "broker")

    def test_the_metadata_field_is_not_writable(self):
        self.b.put("M", "notes", "v", create=True)
        with self.assertRaises(BackendInvalid):
            self.b.put("M", "broker", SECRET)
        with self.assertRaises(BackendInvalid):
            self.b.put("Fresh", "broker", SECRET, create=True)
        self.assertIsNone(self.row("Fresh"))

    def test_previous_fields_are_not_writable(self):
        self.b.put("M", "notes", "v", create=True)
        for f in ("previous_value", "previous_replaced_at"):
            with self.assertRaises(BackendInvalid):
                self.b.put("M", f, SECRET)
            with self.assertRaises(BackendInvalid):
                self.b.put("New-" + f, f, SECRET, create=True)

    def test_non_string_values_are_invalid(self):
        self.b.put("V", "notes", "v", create=True)
        for bad in (None, 5, b"bytes", ["x"]):
            with self.assertRaises(BackendInvalid):
                self.b.put("V", "notes", bad)
            with self.assertRaises(BackendInvalid):
                self.b.put("V2", "notes", bad, create=True)
        self.assertEqual(self.b.get("V", "notes"), "v")

    def test_bad_item_names_are_invalid(self):
        for bad in (None, "", 7):
            with self.assertRaises(BackendInvalid):
                self.b.put(bad, "notes", "v", create=True)
            with self.assertRaises(BackendInvalid):
                self.b.get(bad, "notes")

    def test_a_failed_create_leaves_nothing_behind(self):
        with self.assertRaises(BackendError):
            self.b.put("Half", "broker", "x", create=True)
        with self.assertRaises(BackendNotFound):
            self.b.get("Half", "notes")

    # == 5. lookup rules ====================================================================
    def test_missing_item_is_not_found(self):
        with self.assertRaises(BackendNotFound):
            self.b.get("Nope", "notes")

    def test_lookup_is_case_insensitive_when_unique(self):
        if not self.ci_lookup:
            self.skipTest("backend matches names exactly")
        self.b.put("Grafana", "notes", "g-val", create=True)
        self.assertEqual(self.b.get("grafana", "notes"), "g-val")
        self.assertEqual(self.b.get("GRAFANA", "notes"), "g-val")

    def test_a_name_is_not_a_substring_search(self):
        self.b.put("OpenAI Backup", "notes", "long", create=True)
        self.b.put("openai", "notes", "short", create=True)
        self.assertEqual(self.b.get("openai", "notes"), "short")
        self.assertEqual(self.b.get("OpenAI Backup", "notes"), "long")
        with self.assertRaises(BackendNotFound):
            self.b.get("Open", "notes")

    def test_exact_name_beats_a_case_insensitive_match(self):
        self.b.put("Dup", "notes", "exact", create=True)
        if not self.seed(self.b, "duplicate", "Dup"):
            self.skipTest("cannot seed a case-variant duplicate")
        self.assertEqual(self.b.get("Dup", "notes"), "exact")

    def test_two_case_variants_without_an_exact_match_are_ambiguous(self):
        if not self.ci_lookup:
            self.skipTest("backend matches names exactly")
        self.b.put("Amb", "notes", "one", create=True)
        if not self.seed(self.b, "duplicate", "Amb"):
            self.skipTest("cannot seed a case-variant duplicate")
        with self.assertRaises(BackendInvalid):
            self.b.get("AMB", "notes")

    def test_unusual_item_names_round_trip(self):
        for name in ("with space", "a/b", "q?x=1&y=2", "caf\u00e9 \u2615", "100% done"):
            self.b.put(name, "notes", "v-" + name, create=True)
            self.assertEqual(self.b.get(name, "notes"), "v-" + name)

    # == 6. metadata ===========================================================================
    def test_create_with_meta_appears_in_the_catalog(self):
        meta = {"name": "svc", "allowed_hosts": ["api.example.com"], "approval": "prompt"}
        self.b.put("Svc", "notes", "v", create=True, meta=meta)
        self.assertEqual(self.row("Svc"), {"item": "Svc", "meta": meta})

    def test_credential_request_item_shapes_round_trip(self):
        """What a human-supplied credential (docs/reference.md, credential requests) stores: a token
        in `notes`, and a login as ONE JSON note read back by key. Value and metadata survive exactly."""
        tok = {"name": "tokcred", "allowed_hosts": ["api.example.com"], "approval": "prompt",
               "vars": {"TOKCRED_TOKEN": {"field": "notes"}},
               "created": {"by": "alice", "at": "2026-01-02T03:04:05Z"}}
        self.b.put("tokcred", "notes", SECRET, create=True, meta=tok)
        self.assertEqual(self.b.get("tokcred", "notes"), SECRET)
        self.assertEqual(self.row("tokcred"), {"item": "tokcred", "meta": tok})
        login = json.dumps({"username": "u s\u00e9r", "password": 'p"w\\ \n' + OTHER})
        lm = {"name": "logcred", "allowed_hosts": ["x.example.com"], "approval": "prompt",
              "vars": {"LOGCRED_USERNAME": {"field": "notes", "key": "username"},
                       "LOGCRED_PASSWORD": {"field": "notes", "key": "password"}}}
        self.b.put("logcred", "notes", login, create=True, meta=lm)
        self.assertEqual(json.loads(self.b.get("logcred", "notes")), json.loads(login))
        self.assertEqual(self.row("logcred")["meta"], lm)
        with self.assertRaises(BackendConflict):
            self.b.put("logcred", "notes", "again", create=True, meta=lm)
        self.assertEqual(json.loads(self.b.get("logcred", "notes")), json.loads(login))

    def test_nested_meta_round_trips_exactly(self):
        meta = {"vars": {"T": {"field": "notes", "key": "a.b"}}, "ssh_hosts": {"allowed": ["fp1"]},
                "list": [1, 2.5, True, None, {"x": ["y"]}], "text": "caf\u00e9 \"quoted\" \\ n",
                "empty": {}, "guidance": "line1\nline2"}
        self.b.put("N", "notes", "v", create=True, meta=meta)
        self.assertEqual(self.row("N")["meta"], meta)
        meta["vars"]["T"]["field"] = "mutated after the call"
        self.assertNotEqual(self.row("N")["meta"], meta)         # the backend kept its own copy

    def test_set_meta_replaces_the_metadata(self):
        self.need("set_meta")
        self.b.put("S", "notes", "v", create=True, meta={"a": 1})
        self.b.set_meta("S", {"b": {"c": [1, 2]}})
        self.assertEqual(self.row("S")["meta"], {"b": {"c": [1, 2]}})
        self.assertEqual(self.b.get("S", "notes"), "v")

    def test_set_meta_adds_metadata_to_an_item_without_any(self):
        self.need("set_meta")
        self.b.put("S", "notes", "v", create=True)
        self.b.set_meta("S", {"approval": "allow"})
        self.assertEqual(self.row("S"), {"item": "S", "meta": {"approval": "allow"}})

    def test_set_meta_on_a_missing_item_is_not_found(self):
        self.need("set_meta")
        with self.assertRaises(BackendNotFound):
            self.b.set_meta("Nope", {"a": 1})

    def test_set_meta_needs_an_object(self):
        self.need("set_meta")
        self.b.put("S", "notes", "v", create=True, meta={"a": 1})
        for bad in (None, "text", [1], 3):
            with self.assertRaises(BackendInvalid):
                self.b.set_meta("S", bad)
        self.assertEqual(self.row("S")["meta"], {"a": 1})

    def test_meta_needs_an_object_on_put(self):
        with self.assertRaises(BackendInvalid):
            self.b.put("S", "notes", "v", create=True, meta="not an object")
        self.assertIsNone(self.row("S"))

    def test_disabled_metadata_is_still_reported(self):
        self.b.put("Off", "notes", "v", create=True, meta={"disabled": True})
        self.assertEqual(self.row("Off")["meta"], {"disabled": True})

    def test_set_meta_leaves_secrets_untouched(self):
        self.need("set_meta")
        self.b.put("L", "password", "pw", create=True)
        self.b.put("L", "password", "pw2", keep_previous=True)
        self.b.set_meta("L", {"approval": "prompt"})
        self.assertEqual((self.b.get("L", "password"), self.b.get("L", "previous_value")), ("pw2", "pw"))

    # == 7. the catalog ===========================================================================
    def test_empty_backend_has_an_empty_catalog(self):
        self.assertEqual(self.b.catalog(), [])

    def test_catalog_rows_have_the_documented_shape(self):
        self.b.put("A", "notes", "v", create=True, meta={"x": 1})
        self.b.put("B", "password", "v", create=True)
        for r in self.b.catalog():
            self.assertIn(r["item"], ("A", "B"))
            self.assertLessEqual(set(r), {"item", "meta", "auto"})
            self.assertTrue(r["meta"] is None or isinstance(r["meta"], dict))
            if "auto" in r:
                self.assertIsNone(r["meta"])
                self.assertIsInstance(r["auto"], dict)

    def test_adopted_login_row(self):
        self.need("adopts")
        self.b.put("Login", "password", SECRET, create=True)
        self.assertEqual(self.row("Login"), {"item": "Login", "meta": None, "auto": {
            "login": True, "username": False, "password": True, "notes": False,
            "fields": [], "uris": []}})

    def test_adopted_note_row(self):
        self.need("adopts")
        self.b.put("Note", "notes", SECRET, create=True)
        self.assertEqual(self.row("Note"), {"item": "Note", "meta": None, "auto": {
            "login": False, "username": False, "password": False, "notes": True,
            "fields": [], "uris": []}})

    def test_adopted_custom_field_row(self):
        self.need("adopts")
        self.b.put("Multi", "api_key", SECRET, create=True)
        auto = self.row("Multi")["auto"]
        self.assertEqual((auto["login"], auto["notes"], auto["fields"]), (False, False, ["api_key"]))

    def test_adopted_ssh_key_row_carries_only_the_public_half(self):
        self.need("adopts")
        pem, pub = _ssh_pair()
        self.b.put("Key", "private_key", pem, create=True, meta={"ssh": True, "ssh_public_key": pub})
        # an ssh key WITHOUT metadata: made by the backend's own import path
        if "import_items" in self.caps():
            self.b.import_items([Item("Bare Key", "ssh_key", private_key=pem, public_key=pub)])
            self.assertEqual(self.row("Bare Key"), {"item": "Bare Key", "meta": None,
                                                    "auto": {"ssh_public_key": pub}})
            self.assertNotIn("PRIVATE", json.dumps(self.b.catalog()))

    def test_adoption_never_carries_values(self):
        self.need("adopts")
        self.b.put("A", "password", SECRET, create=True)
        self.b.put("B", "notes", OTHER, create=True)
        self.b.put("C", "api_key", SECRET + OTHER, create=True)
        text = json.dumps(self.b.catalog())
        for v in (SECRET, OTHER):
            self.assertNotIn(v, text)

    def test_empty_items_are_not_adopted(self):
        self.need("adopts")
        self.b.put("EmptyNote", "notes", "", create=True)
        self.b.put("EmptyLogin", "password", "", create=True)
        self.assertIsNone(self.row("EmptyNote"))
        self.assertIsNone(self.row("EmptyLogin"))

    def test_items_without_metadata_are_not_listed_unless_adopted(self):
        if "adopts" in self.caps():
            self.skipTest("backend adopts")
        self.b.put("Bare", "notes", "v", create=True)
        self.assertIsNone(self.row("Bare"))
        self.assertEqual(self.b.get("Bare", "notes"), "v")

    def test_reserved_fields_never_count_as_adopted_fields(self):
        self.need("adopts")
        self.b.put("X", "api_key", "k1", create=True)
        self.b.put("X", "api_key", "k2", keep_previous=True)
        self.assertEqual(self.row("X")["auto"]["fields"], ["api_key"])

    def test_explicit_metadata_wins_over_adoption(self):
        self.b.put("Both", "notes", "v", create=True, meta={"approval": "allow"})
        rows = [r for r in self.b.catalog() if r["item"] == "Both"]
        self.assertEqual(rows, [{"item": "Both", "meta": {"approval": "allow"}}])

    def test_cards_and_identities_are_ignored(self):
        for kind in ("card", "identity"):
            if not self.seed(self.b, kind, "Native " + kind):
                self.skipTest("backend has no such item kinds")
        self.assertEqual([r for r in self.b.catalog() if r["item"].startswith("Native")], [])

    def test_catalog_sees_writes_immediately(self):
        self.b.put("A", "notes", "v", create=True, meta={"n": 1})
        self.assertEqual(self.row("A")["meta"], {"n": 1})
        self.b.delete("A")
        self.assertIsNone(self.row("A"))

    def test_catalog_lists_each_item_once(self):
        for i in range(5):
            self.b.put(f"I{i}", "notes", "v", create=True, meta={"i": i})
        names = [r["item"] for r in self.b.catalog()]
        self.assertEqual(sorted(names), [f"I{i}" for i in range(5)])

    # == 8. delete =================================================================================
    def test_delete_removes_the_item(self):
        self.b.put("D", "notes", "v", create=True, meta={"a": 1})
        self.b.delete("D")
        with self.assertRaises(BackendNotFound):
            self.b.get("D", "notes")
        self.assertIsNone(self.row("D"))

    def test_delete_missing_item_is_not_an_error(self):
        self.b.delete("Never existed")

    def test_an_item_can_be_recreated_after_delete(self):
        self.b.put("D", "notes", "first", create=True)
        self.b.put("D", "notes", "second", keep_previous=True)
        self.b.delete("D")
        self.b.put("D", "notes", "again", create=True)
        self.assertEqual(self.b.get("D", "notes"), "again")
        with self.assertRaises(BackendNotFound):
            self.b.get("D", "previous_value")                  # history died with the item

    def test_delete_only_removes_the_named_item(self):
        self.b.put("Keep", "notes", "k", create=True)
        self.b.put("Drop", "notes", "d", create=True)
        self.b.delete("Drop")
        self.assertEqual(self.b.get("Keep", "notes"), "k")

    # == 9. values ===================================================================================
    def test_unicode_values_round_trip(self):
        vals = {"notes": "caf\u00e9 \u2603 \u65e5\u672c\u8a9e \U0001f511", "password": "p\u00e4ss\u00f6rd\u2713",
                "api_key": "\u00fc\u00f1\u00ee\u00e7\u00f8d\u00e9"}
        for field, v in vals.items():
            self.b.put("U-" + field, field, v, create=True)
            self.assertEqual(self.b.get("U-" + field, field), v)

    def test_multiline_values_keep_interior_newlines(self):
        v = "line one\nline two\r\nline three\n\nlast"
        self.b.put("ML", "notes", v, create=True)
        self.assertEqual(self.b.get("ML", "notes"), v)
        self.b.put("MK", "api_key", v, create=True)
        self.assertEqual(self.b.get("MK", "api_key"), v)

    def test_special_characters_are_not_interpreted(self):
        v = "\"quotes\" 'single' \\ back $(cmd) `tick` {{VAR}} %s <b>&amp;</b> ; -- \t tab"
        self.b.put("SP", "notes", v, create=True)
        self.assertEqual(self.b.get("SP", "notes"), v)

    def test_a_64k_value_round_trips(self):
        v = ("0123456789abcdef" * 4096)
        self.b.put("Big", "notes", v, create=True)
        self.assertEqual(self.b.get("Big", "notes"), v)
        self.b.put("Big", "notes", v[::-1], keep_previous=True)
        self.assertEqual(self.b.get("Big", "previous_value"), v)

    def test_an_empty_value_round_trips(self):
        self.b.put("E", "password", "", create=True)
        self.assertEqual(self.b.get("E", "password"), "")

    def test_many_items(self):
        for i in range(40):
            self.b.put(f"item-{i:03d}", "notes", f"value-{i}", create=True, meta={"i": i})
        self.assertEqual(len(self.b.catalog()), 40)
        self.assertEqual(self.b.get("item-017", "notes"), "value-17")

    # == 10. errors never carry secrets ==============================================================
    def _failing_calls(self):
        b = self.b
        b.put("Exists", "notes", "kept", create=True)
        return [
            lambda: b.put("Exists", "notes", SECRET, create=True),
            lambda: b.put("Missing", "notes", SECRET),
            lambda: b.put("Exists", "no_such_field", SECRET),
            lambda: b.put("Exists", "broker", SECRET),
            lambda: b.put("Exists", "previous_value", SECRET),
            lambda: b.put("New", "broker", SECRET, create=True),
            lambda: b.put("New", "private_key", SECRET, create=True),
            lambda: b.put("Exists", "notes", SECRET, meta="bad"),
            lambda: b.put("Exists", "notes", 12345),
            lambda: b.get("Missing", "notes"),
            lambda: b.get("Exists", "no_such_field"),
            lambda: b.get("Exists", "broker"),
            lambda: b.set_meta("Missing", {"k": SECRET}),
            lambda: b.set_meta("Exists", "bad"),
        ]

    def test_failures_are_backend_errors(self):
        for exc in self.errors(*self._failing_calls()):
            self.assertIsNotNone(exc)
            self.assertIsInstance(exc, BackendError, repr(exc))

    def test_no_exception_text_contains_a_secret_value(self):
        for exc in self.errors(*self._failing_calls()):
            seen = []
            while exc is not None and exc not in seen:
                seen.append(exc)
                for text in (str(exc), repr(exc), " ".join(map(repr, exc.args))):
                    self.assertNotIn(SECRET, text)
                exc = exc.__cause__ or exc.__context__

    def test_failed_calls_do_not_modify_state(self):
        self.errors(*self._failing_calls())
        self.assertEqual(self.b.get("Exists", "notes"), "kept")
        self.assertEqual([r["item"] for r in self.b.catalog() if r["item"] != "Exists"
                          and r["item"] in ("Missing", "New")], [])

    def test_error_classes_map_to_the_documented_classes(self):
        errs = self.errors(lambda: self.b.get("Missing", "notes"),
                           lambda: self.b.get("Missing", "broker"))
        self.assertEqual([error_class(e) for e in errs], ["invalid", "invalid"])
        self.b.put("X", "notes", "v", create=True)
        e = self.errors(lambda: self.b.put("X", "notes", "w", create=True))[0]
        self.assertEqual(error_class(e), "conflict")

    # == 11. concurrency ===============================================================================
    def _run_threads(self, fns):
        errs, threads = [], []

        def wrap(fn):
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        for fn in fns:
            t = threading.Thread(target=wrap, args=(fn,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join(120)
        self.assertFalse([t for t in threads if t.is_alive()], "a thread hung")
        return errs

    def test_concurrent_creates_of_different_items_all_land(self):
        n = 6
        errs = self._run_threads([lambda i=i: self.b.put(f"T{i}", "notes", f"v{i}", create=True,
                                                         meta={"i": i}) for i in range(n)])
        self.assertEqual(errs, [])
        self.assertEqual(sorted(r["item"] for r in self.b.catalog()), sorted(f"T{i}" for i in range(n)))
        for i in range(n):
            self.assertEqual(self.b.get(f"T{i}", "notes"), f"v{i}")

    def test_concurrent_create_of_one_name_has_exactly_one_winner(self):
        errs = self._run_threads([lambda i=i: self.b.put("Race", "notes", f"v{i}", create=True)
                                  for i in range(5)])
        self.assertEqual(len(errs), 4)
        self.assertTrue(all(isinstance(e, BackendConflict) for e in errs), errs)
        self.assertIn(self.b.get("Race", "notes"), {f"v{i}" for i in range(5)})

    def test_concurrent_updates_of_one_item_do_not_corrupt_it(self):
        self.b.put("Hot", "notes", "v-start", create=True)
        errs = self._run_threads([lambda i=i: self.b.put("Hot", "notes", f"v{i}", keep_previous=True)
                                  for i in range(5)])
        self.assertEqual(errs, [])
        self.assertIn(self.b.get("Hot", "notes"), {f"v{i}" for i in range(5)})
        self.assertIn(self.b.get("Hot", "previous_value"), {"v-start"} | {f"v{i}" for i in range(5)})

    def test_concurrent_set_meta_and_put_do_not_lose_either(self):
        self.need("set_meta")
        self.b.put("Both", "notes", "v0", create=True)
        errs = self._run_threads([lambda: self.b.set_meta("Both", {"m": 1}),
                                  lambda: self.b.put("Both", "notes", "v1")])
        self.assertEqual(errs, [])
        self.assertEqual(self.b.get("Both", "notes"), "v1")
        self.assertEqual(self.row("Both")["meta"], {"m": 1})

    def test_readers_see_a_whole_value_while_a_writer_updates(self):
        self.b.put("RW", "notes", "A" * 200, create=True)
        stop, bad = threading.Event(), []

        def reader():
            while not stop.is_set():
                try:
                    v = self.b.get("RW", "notes")
                    if v not in ("A" * 200, "B" * 200):
                        bad.append(v[:10])
                except Exception as e:  # noqa: BLE001
                    bad.append(repr(e))

        t = threading.Thread(target=reader)
        t.start()
        try:
            for i in range(6):
                self.b.put("RW", "notes", ("B" if i % 2 == 0 else "A") * 200)
        finally:
            stop.set()
            t.join(30)
        self.assertEqual(bad, [])

    # == 12. persistence ================================================================================
    def test_a_reopened_backend_sees_everything(self):
        if not self.persistent:
            self.skipTest("not a persistent backend")
        meta = {"vars": {"T": {"field": "notes"}}, "n": {"deep": [1, 2]}}
        self.b.put("P", "notes", "v1", create=True, meta=meta)
        self.b.put("P", "notes", "v2", keep_previous=True)
        self.b.put("Q", "password", "pw", create=True)
        again = self.reopen(self.b)
        self.addCleanup(again.close)
        self.assertEqual(again.get("P", "notes"), "v2")
        self.assertEqual(again.get("P", "previous_value"), "v1")
        self.assertEqual(again.get("Q", "password"), "pw")
        self.assertEqual(self.row("P", again)["meta"], meta)

    def test_deletes_persist(self):
        if not self.persistent:
            self.skipTest("not a persistent backend")
        self.b.put("Gone", "notes", "v", create=True)
        self.b.delete("Gone")
        again = self.reopen(self.b)
        self.addCleanup(again.close)
        with self.assertRaises(BackendNotFound):
            again.get("Gone", "notes")

    def test_a_write_through_another_instance_is_seen(self):
        if not self.persistent or not self.sees_external_writes:
            self.skipTest("needs a persistent backend that notices outside changes")
        self.b.put("Shared", "notes", "v1", create=True, meta={"a": 1})
        other = self.reopen(self.b)
        self.addCleanup(other.close)
        other.put("Shared", "notes", "v2")
        other.put("Added", "notes", "x", create=True, meta={"b": 2})
        self.assertEqual(self.b.get("Shared", "notes"), "v2")
        self.assertEqual(sorted(r["item"] for r in self.b.catalog()), ["Added", "Shared"])

    # == 13. idle lock ====================================================================================
    IDLE = 0.3          # idle_timeout the idle test asks for; fake-clock backends override it (see lapse)

    def lapse(self, b, seconds):
        """Let `seconds` of idle time pass for `b` and run its idle expiry. Default: really wait (a backend
        that can be driven by a fake clock overrides this)."""
        time.sleep(seconds)

    def test_the_backend_works_again_after_its_idle_timeout(self):
        if not self.supports_idle:
            self.skipTest("no idle lock")
        b = self.make(idle_timeout=self.IDLE)
        self.addCleanup(b.close)
        b.put("Idle", "notes", "v", create=True, meta={"a": 1})
        self.lapse(b, 0.9)                                # locked / logged out by now
        self.assertEqual(b.get("Idle", "notes"), "v")
        self.lapse(b, 0.9)
        self.assertEqual(self.row("Idle", b)["meta"], {"a": 1})
        b.put("Idle", "notes", "v2")
        self.assertEqual(b.get("Idle", "notes"), "v2")

    # == 14. optional capabilities ==========================================================================
    def test_create_login_sets_username_password_and_uri(self):
        self.need("create_login")
        self.b.create_login("Site", "alice", "pw-1", uri="https://x.example", notes="a note",
                            meta={"allowed_hosts": ["x.example"]})
        self.assertEqual(self.b.get("Site", "username"), "alice")
        self.assertEqual(self.b.get("Site", "password"), "pw-1")
        self.assertEqual(self.b.get("Site", "auto"), "pw-1")
        self.assertEqual(self.b.get("Site", "notes"), "a note")
        self.assertEqual(self.row("Site")["meta"], {"allowed_hosts": ["x.example"]})

    def test_create_login_without_meta_is_adopted_with_its_shape(self):
        self.need("create_login")
        self.need("adopts")
        self.b.create_login("Site", "alice", "pw-1", uri="https://x.example")
        auto = self.row("Site")["auto"]
        self.assertEqual((auto["login"], auto["username"], auto["password"], auto["uris"]),
                         (True, True, True, ["https://x.example"]))

    def test_create_login_on_an_existing_name_is_a_conflict(self):
        self.need("create_login")
        self.b.put("Site", "notes", "n", create=True)
        with self.assertRaises(BackendConflict):
            self.b.create_login("Site", "u", "p")

    def test_edit_item_renames_and_keeps_values(self):
        self.need("edit_item")
        self.b.put("Old", "notes", "v", create=True, meta={"a": 1})
        self.b.edit_item("Old", new_name="New")
        self.assertEqual(self.b.get("New", "notes"), "v")
        self.assertEqual(self.row("New")["meta"], {"a": 1})
        with self.assertRaises(BackendNotFound):
            self.b.get("Old", "notes")

    def test_edit_item_replaces_and_drops_metadata(self):
        self.need("edit_item")
        self.b.put("E", "notes", "v", create=True, meta={"a": 1})
        self.b.edit_item("E", meta={"b": {"c": 2}})
        self.assertEqual(self.row("E")["meta"], {"b": {"c": 2}})
        self.b.edit_item("E", drop_meta=True)
        row = self.row("E")
        self.assertTrue(row is None or row["meta"] is None)
        self.assertEqual(self.b.get("E", "notes"), "v")

    def test_edit_item_conflicts_and_misses(self):
        self.need("edit_item")
        self.b.put("A", "notes", "a", create=True)
        self.b.put("B", "notes", "b", create=True)
        with self.assertRaises(BackendConflict):
            self.b.edit_item("A", new_name="B")
        with self.assertRaises(BackendNotFound):
            self.b.edit_item("Nope", new_name="Z")
        self.assertEqual((self.b.get("A", "notes"), self.b.get("B", "notes")), ("a", "b"))

    def test_warm_then_read(self):
        self.need("warm")
        self.b.warm()
        self.b.put("W", "notes", "v", create=True)
        self.b.warm()
        self.assertEqual(self.b.get("W", "notes"), "v")

    def test_event_callback_is_optional_and_never_breaks_calls(self):
        self.need("on_event")
        seen = []
        self.b.on_event = lambda name, **f: seen.append((name, f))
        self.b.put("Ev", "notes", SECRET, create=True)
        self.b.get("Ev", "notes")
        for name, fields in seen:
            self.assertIsInstance(name, str)
            self.assertNotIn(SECRET, json.dumps([name, fields], default=str))

        def boom(name, **f):
            raise RuntimeError("callback failure")
        self.b.on_event = boom
        self.assertEqual(self.b.get("Ev", "notes"), SECRET)
        self.b.put("Ev", "notes", "x")
        self.b.on_event = None
        self.assertEqual(self.b.get("Ev", "notes"), "x")

    def test_export_items_returns_whole_items_with_values(self):
        self.need("export_items")
        self.b.put("N", "notes", "n-val", create=True, meta={"m": {"d": 1}})
        self.b.put("L", "password", "p-val", create=True)
        self.b.put("C", "api_key", "c-val", create=True)
        got = {i.name: i for i in self.b.export_items()}
        self.assertEqual(sorted(got), ["C", "L", "N"])
        self.assertEqual((got["N"].kind, got["N"].notes, got["N"].meta), ("note", "n-val", {"m": {"d": 1}}))
        self.assertEqual((got["L"].kind, got["L"].password), ("login", "p-val"))
        self.assertEqual(got["C"].fields, {"api_key": "c-val"})
        self.assertNotIn("n-val", repr(got["N"]))                # repr never shows values

    def test_export_then_import_into_another_backend(self):
        self.need("export_items")
        self.b.put("N", "notes", "n-val", create=True, meta={"m": [1]})
        self.b.create_login("Lg", "alice", "pw", uri="https://u.example") if "create_login" in self.caps() \
            else self.b.put("Lg", "password", "pw", create=True)
        target = MemoryBackend()
        target.import_items(self.b.export_items())
        self.assertEqual(target.get("N", "notes"), "n-val")
        self.assertEqual(target.get("Lg", "password"), "pw")
        self.assertEqual({r["item"]: r["meta"] for r in target.catalog() if r["meta"]}, {"N": {"m": [1]}})

    def test_import_items_writes_whole_items(self):
        self.need("import_items")
        items = [Item("N", "note", notes="n-val", meta={"m": 1}),
                 Item("L", "login", username="alice", password="pw", uris=["https://u.example"],
                      notes="c", fields={"pin": "1234"}),
                 Item("F", "note", fields={"api_key": "k"})]
        self.assertEqual(sorted(self.b.import_items(items)), ["F", "L", "N"])
        self.assertEqual(self.b.get("N", "notes"), "n-val")
        self.assertEqual([self.b.get("L", f) for f in ("username", "password", "notes", "pin")],
                         ["alice", "pw", "c", "1234"])
        self.assertEqual(self.b.get("F", "api_key"), "k")
        self.assertEqual(self.row("N")["meta"], {"m": 1})

    def test_import_items_conflicts_unless_overwrite(self):
        self.need("import_items")
        self.b.put("Have", "notes", "old", create=True)
        with self.assertRaises(BackendConflict):
            self.b.import_items([Item("New", "note", notes="x"), Item("Have", "note", notes="new")])
        with self.assertRaises(BackendNotFound):
            self.b.get("New", "notes")                           # all or nothing
        self.b.import_items([Item("Have", "note", notes="new")], overwrite=True)
        self.assertEqual(self.b.get("Have", "notes"), "new")

    def test_import_items_rejects_malformed_items(self):
        self.need("import_items")
        for bad in (Item("", "note", notes="x"), Item("x", "card"), Item("x", "note", notes=5),
                    Item("x", "note", fields={"broker": "no"}), Item("x", "note", meta="str")):
            with self.assertRaises(BackendInvalid):
                self.b.import_items([bad])
