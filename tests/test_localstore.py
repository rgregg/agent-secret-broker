import base64
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from secret_broker import localstore as ls  # noqa: E402
from secret_broker.__main__ import build_backend  # noqa: E402
from secret_broker.backends import BackendError, FileBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.localstore import BackendConfigError, LocalBackend, StoreError  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
import test_e2e as e2e  # noqa: E402

RAW = base64.b64encode(bytes(range(32))).decode()       # a fake raw 32-byte key
PASS = "correct horse battery staple (fake)"
VAL = "fake-secret-value-0001"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "store.enc")
        self.keyfile = os.path.join(self.dir, "key")
        self.write_key(RAW)
        self.events = []

    def write_key(self, text, nl="\n"):
        with open(self.keyfile, "w") as f:
            f.write(text + nl)
        os.chmod(self.keyfile, 0o600)

    def init(self, key=RAW, doc=None, **kw):
        ls.create_store(self.path, ls.Key(key), doc, **kw)

    def backend(self, idle=300, key_source=None):
        b = LocalBackend(self.path, key_source or ls.FileKeySource(self.keyfile), idle)
        b.on_event = lambda name, **f: self.events.append((name, f))
        return b

    def names(self):
        return [n for n, _ in self.events]

    def raw(self):
        with open(self.path, "rb") as f:
            return f.read()

    def put_raw(self, data):
        with open(self.path, "wb") as f:
            f.write(data)


class RoundTrip(Base):
    def test_create_get_catalog_roundtrip(self):
        self.init()
        b = self.backend()
        meta = {"name": "svc", "allowed_hosts": ["api.example.com"], "vars": {"T": {"field": "notes"}}}
        b.put("Svc", "notes", VAL, create=True, meta=meta)
        b.put("Pw", "password", "pw-1", create=True)
        b.put("Multi", "API Key", "k-1", create=True)
        self.assertEqual(b.get("Svc", "notes"), VAL)
        self.assertEqual(b.get("Pw", "password"), "pw-1")
        self.assertEqual(b.get("Multi", "API Key"), "k-1")
        # a fresh backend (new process) reads the same file
        b2 = self.backend()
        self.assertEqual(b2.get("Svc", "auto"), VAL)
        self.assertEqual(b2.catalog()[0], {"item": "Svc", "meta": meta})

    def test_file_is_ciphertext_and_private(self):
        self.init()
        b = self.backend()
        b.put("Svc", "notes", VAL, create=True, meta={"name": "hiddenname"})
        raw = self.raw()
        for needle in (VAL.encode(), b"Svc", b"hiddenname"):
            self.assertNotIn(needle, raw)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_metadata_field_refused(self):
        self.init()
        b = self.backend()
        b.put("Svc", "notes", VAL, create=True, meta={"name": "x"})
        with self.assertRaises(BackendError):
            b.get("Svc", "broker")
        with self.assertRaises(BackendError):
            b.put("Svc", "broker", "x")

    def test_field_resolution_matches_bw(self):
        self.init()
        b = self.backend()
        b.create_login("Router", "admin", "pw-2", uri="http://192.168.1.1/", notes="  note text\n")
        b.put("Plain", "notes", "free text\n", create=True)
        self.assertEqual(b.get("Router", "auto"), "pw-2")
        self.assertEqual(b.get("Router", None), "pw-2")
        self.assertEqual(b.get("Router", "username"), "admin")
        self.assertEqual(b.get("Router", "notes"), "note text")       # trimmed like Bw
        self.assertEqual(b.get("Plain", "auto"), "free text")
        for item, field in (("Plain", "password"), ("Plain", "username"), ("Router", "nope"),
                            ("Missing", "notes")):
            with self.assertRaises(BackendError):
                b.get(item, field)

    def test_case_insensitive_fallback_and_ambiguity(self):
        self.init()
        b = self.backend()
        b.put("Grafana", "notes", "a", create=True)
        self.assertEqual(b.get("grafana", "notes"), "a")
        with self.assertRaises(BackendError):
            b.put("grafana", "notes", "x", create=True)               # collides case-insensitively

    def test_create_existing_and_update_missing(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        with self.assertRaises(BackendError):
            b.put("A", "notes", "2", create=True)
        with self.assertRaises(BackendError):
            b.put("B", "notes", "2")
        with self.assertRaises(BackendError):
            b.put("A", "nofield", "2")
        self.assertEqual(b.get("A", "notes"), "1")

    def test_set_meta_edit_item_delete(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        b.put("Z", "notes", "2", create=True)
        b.set_meta("A", {"name": "a"})
        self.assertEqual(b.catalog()[0]["meta"], {"name": "a"})
        b.edit_item("A", new_name="A2", meta={"name": "a2"})
        self.assertEqual([r["item"] for r in b.catalog()], ["A2", "Z"])     # order kept
        b.edit_item("A2", drop_meta=True)
        self.assertEqual(b.catalog()[0].get("meta"), None)
        with self.assertRaises(BackendError):
            b.edit_item("A2", new_name="Z")
        with self.assertRaises(BackendError):
            b.set_meta("Nope", {})
        b.delete("Z")
        b.delete("Z")                                                       # idempotent
        self.assertEqual([r["item"] for r in b.catalog()], ["A2"])

    def test_non_string_value_rejected(self):
        self.init()
        with self.assertRaises(BackendError):
            self.backend().put("A", "notes", 12, create=True)


class PreviousValue(Base):
    def test_keep_previous(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "old-value", create=True, meta={"name": "a"})
        b.put("A", "notes", "new-value", keep_previous=True)
        self.assertEqual(b.get("A", "notes"), "new-value")
        self.assertEqual(b.get("A", "previous_value"), "old-value")
        self.assertRegex(b.get("A", "previous_replaced_at"), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        b.put("A", "notes", "newer", keep_previous=True)
        self.assertEqual(b.get("A", "previous_value"), "new-value")

    def test_without_keep_previous_nothing_kept(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "old", create=True)
        b.put("A", "notes", "new")
        with self.assertRaises(BackendError):
            b.get("A", "previous_value")

    def test_previous_value_is_not_an_adoptable_field(self):
        self.init()
        b = self.backend()
        b.create_login("L", "u", "old")
        b.put("L", "password", "new", keep_previous=True)
        self.assertEqual(b.catalog()[0]["auto"]["fields"], [])
        with self.assertRaises(BackendError):
            b.put("L", "previous_value", "x")                              # not a writable field


class Adoption(Base):
    def test_auto_rows(self):
        self.init()
        b = self.backend()
        b.create_login("Cable Modem", "admin", "pw", uri="http://192.168.100.1/login")
        b.put("Wifi", "notes", "ssid-pass", create=True)
        b.put("Keys", "API Key", "k", create=True)
        b.put("Explicit", "notes", "v", create=True, meta={"name": "e"})
        b.put("Empty", "notes", "", create=True)
        rows = {r["item"]: r for r in b.catalog()}
        self.assertEqual(rows["Cable Modem"], {"item": "Cable Modem", "meta": None, "auto": {
            "login": True, "username": True, "password": True, "notes": False, "fields": [],
            "uris": ["http://192.168.100.1/login"]}})
        self.assertEqual(rows["Wifi"]["auto"], {"login": False, "username": False, "password": False,
                                                "notes": True, "fields": [], "uris": []})
        self.assertEqual(rows["Keys"]["auto"]["fields"], ["API Key"])
        self.assertEqual(rows["Explicit"], {"item": "Explicit", "meta": {"name": "e"}})
        self.assertNotIn("Empty", rows)                                    # nothing usable
        self.assertNotIn(VAL, json.dumps(rows))

    def test_broker_metadata_that_is_not_an_object_is_a_bad_row(self):
        self.init(doc={"items": {"Bad": {"type": "note", "notes": "x", "broker": "oops"}}})
        self.assertEqual(self.backend().catalog(), [{"item": "Bad", "meta": None}])

    def test_catalog_drives_broker(self):
        self.init()
        b = self.backend()
        b.create_login("Cable Modem", "admin", "pw", uri="http://192.168.100.1/")
        b.put("Svc", "notes", VAL, create=True,
              meta={"allowed_hosts": ["api.example.com"], "vars": {"T_TOKEN": {"field": "notes"}}})
        br = Broker({"approve_base_url": "https://s.example"}, b, FakeNotifier(), None)
        self.assertEqual(sorted(br.cfg["secrets"]), ["cable-modem", "svc"])
        self.assertTrue(br.cfg["secrets"]["cable-modem"]["auto"])
        self.assertEqual(br.cfg["secrets"]["svc"]["_item"], "Svc")


class Tamper(Base):
    def setUp(self):
        super().setUp()
        self.init(doc={"items": {"A": {"type": "note", "notes": VAL}}})
        self.good = self.raw()

    def expect(self, data, reason):
        self.put_raw(data)
        b = self.backend()
        with self.assertRaises(StoreError) as cm:
            b.get("A", "notes")
        self.assertEqual(cm.exception.reason, reason)
        self.assertNotIn(VAL, str(cm.exception))
        self.assertIn(("store_unlock_failed", {"reason": reason}), self.events)
        return b

    def flip(self, data, i):
        return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]

    def test_flip_in_body(self):
        head_end = self.good.index(b"\n") + 1
        self.expect(self.flip(self.good, head_end + 20), "corrupt")
        self.expect(self.flip(self.good, head_end + 3), "corrupt")         # the nonce
        self.expect(self.flip(self.good, len(self.good) - 1), "corrupt")   # the tag

    def test_truncated_body(self):
        self.expect(self.good[:-5], "corrupt")
        self.expect(self.good[:self.good.index(b"\n") + 8], "corrupt")

    def test_header_changes_fail(self):
        head, _, body = self.good.partition(b"\n")
        h = json.loads(head)
        h["extra"] = 1                                                      # authenticated: any edit fails
        self.expect(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body, "corrupt")

    def test_flip_in_wraps(self):
        head, _, body = self.good.partition(b"\n")
        h = json.loads(head)
        w = h["wraps"][0]
        raw = bytearray(base64.b64decode(w["wrapped_dek"]))
        raw[0] ^= 1
        w["wrapped_dek"] = base64.b64encode(bytes(raw)).decode()
        self.expect(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body, "wrong_key")

    def test_downgrade_of_version_and_cipher(self):
        head, _, body = self.good.partition(b"\n")
        for field, val in (("v", 0), ("v", 2), ("cipher", "aes-128-gcm"), ("cipher", "none")):
            h = json.loads(head)
            h[field] = val
            self.expect(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body,
                        "unsupported")

    def test_wrap_swapped_in_from_another_store(self):
        other = os.path.join(self.dir, "other.enc")
        ls.create_store(other, ls.Key(RAW), {"items": {}})
        with open(other, "rb") as f:
            oh = json.loads(f.read().partition(b"\n")[0])
        head, _, body = self.good.partition(b"\n")
        h = json.loads(head)
        h["wraps"] = oh["wraps"]
        self.expect(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body, "corrupt")

    def test_garbage_file(self):
        self.expect(b"not an encrypted store", "corrupt")
        self.expect(b"{bad json}\nxxxx", "corrupt")

    def test_corrupt_file_is_never_overwritten(self):
        bad = self.flip(self.good, len(self.good) - 1)
        self.put_raw(bad)
        b = self.backend()
        with self.assertRaises(StoreError) as cm:
            b.put("B", "notes", "x", create=True)
        self.assertIn(".bak", str(cm.exception))
        self.assertEqual(self.raw(), bad)

    def test_unknown_kdf_and_low_scrypt_n_refused(self):
        head, _, body = self.good.partition(b"\n")
        h = json.loads(head)
        h["wraps"][0]["kdf"] = {"alg": "scrypt", "n": 2 ** 10, "r": 8, "p": 1, "salt": "AAAA"}
        self.put_raw(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body)
        with self.assertRaises(StoreError):
            self.backend().get("A", "notes")


class Keys(Base):
    def test_wrong_key(self):
        self.init(doc={"items": {"A": {"type": "note", "notes": VAL}}})
        self.write_key(base64.b64encode(b"\x01" * 32).decode())
        b = self.backend()
        with self.assertRaises(StoreError) as cm:
            b.catalog()
        self.assertEqual(cm.exception.reason, "wrong_key")
        self.assertEqual(self.names(), ["store_unlock_failed"])
        self.write_key(RAW)                                                # fixing the key recovers
        self.assertEqual(len(b.catalog()), 1)
        self.assertEqual(self.names(), ["store_unlock_failed", "store_unlocked"])

    def test_missing_key_file_and_env(self):
        self.init()
        os.unlink(self.keyfile)
        b = self.backend()
        with self.assertRaises(StoreError) as cm:
            b.catalog()
        self.assertEqual(cm.exception.reason, "key_missing")
        with mock.patch.dict(os.environ, clear=False):
            os.environ.pop("ASB_TEST_KEY", None)
            b2 = self.backend(key_source=ls.EnvKeySource("ASB_TEST_KEY"))
            with self.assertRaises(StoreError) as cm:
                b2.catalog()
            self.assertEqual(cm.exception.reason, "key_missing")
            self.assertIn("ASB_TEST_KEY", str(cm.exception))

    def test_empty_key_is_missing(self):
        self.init()
        self.write_key("", nl="\n")
        with self.assertRaises(StoreError) as cm:
            self.backend().catalog()
        self.assertEqual(cm.exception.reason, "key_missing")

    def test_missing_store_file(self):
        with self.assertRaises(StoreError) as cm:
            self.backend().catalog()
        self.assertEqual(cm.exception.reason, "not_found")

    def test_passphrase_via_file_strips_one_newline(self):
        self.init(key=PASS)
        for nl in ("\n", "\r\n", ""):
            self.write_key(PASS, nl=nl)
            self.assertEqual(self.backend().catalog(), [])
        self.write_key(PASS, nl="\n\n")                                     # only ONE newline is trimmed
        with self.assertRaises(StoreError):
            self.backend().catalog()

    def test_passphrase_uses_scrypt_wrap(self):
        self.init(key=PASS)
        h = json.loads(self.raw().partition(b"\n")[0])
        kdf = h["wraps"][0]["kdf"]
        self.assertEqual(kdf["alg"], "scrypt")
        self.assertGreaterEqual(kdf["n"], 2 ** 15)
        self.assertEqual(len(base64.b64decode(kdf["salt"])), 16)
        with self.assertRaises(StoreError):
            ls.create_store(os.path.join(self.dir, "weak"), ls.Key(PASS), kdf={"n": 2 ** 10, "r": 8, "p": 1})

    def test_raw_key_skips_kdf(self):
        self.init(key=RAW)
        h = json.loads(self.raw().partition(b"\n")[0])
        self.assertEqual(h["wraps"][0]["kdf"], {"alg": "raw"})

    def test_env_source(self):
        self.init(key=PASS)
        with mock.patch.dict(os.environ, {"ASB_TEST_KEY": PASS + "\n"}):
            b = self.backend(key_source=ls.EnvKeySource("ASB_TEST_KEY"))
            self.assertEqual(b.catalog(), [])

    def test_env_raw_key(self):
        path2 = os.path.join(self.dir, "s2.enc")
        ls.create_store(path2, ls.Key(RAW), {"items": {"A": {"type": "note", "notes": VAL}}})
        with mock.patch.dict(os.environ, {"ASB_TEST_KEY": RAW}):
            b = LocalBackend(path2, ls.EnvKeySource("ASB_TEST_KEY"))
            self.assertEqual(b.get("A", "notes"), VAL)

    def test_recovery_wrap_opens_the_store(self):
        self.init(recovery_key=ls.Key(PASS))
        self.write_key(PASS)
        self.assertEqual(self.backend().catalog(), [])

    def test_loose_key_file_mode_warns_once_not_fails(self):
        self.init()
        os.chmod(self.keyfile, 0o644)
        ls.FileKeySource._warned.clear()
        with self.assertLogs("secret_broker.localstore", "WARNING") as cm:
            self.backend().catalog()
        self.assertEqual(len(cm.output), 1)
        self.assertNotIn(RAW, cm.output[0])

    def test_key_never_in_errors_or_events(self):
        self.init()
        self.write_key(PASS)
        b = self.backend()
        with self.assertRaises(StoreError) as cm:
            b.catalog()
        self.assertNotIn(PASS, str(cm.exception) + json.dumps(self.events))


class Durability(Base):
    def test_failed_write_leaves_old_file_and_memory(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        before = self.raw()
        with mock.patch("secret_broker.localstore.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                b.put("B", "notes", "2", create=True)
        self.assertEqual(self.raw(), before)
        self.assertEqual([f for f in os.listdir(self.dir) if ".tmp." in f], [])      # temp cleaned up
        self.assertEqual([r["item"] for r in b.catalog()], ["A"])
        self.assertEqual([r["item"] for r in self.backend().catalog()], ["A"])
        b.put("B", "notes", "2", create=True)                                        # and it recovers

    def test_failure_before_rename_after_fsync(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        before = self.raw()
        with mock.patch("secret_broker.localstore.os.fsync", side_effect=OSError("io error")):
            with self.assertRaises(OSError):
                b.put("B", "notes", "2", create=True)
        self.assertEqual(self.raw(), before)

    def test_error_in_change_writes_nothing(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        before = self.raw()
        with self.assertRaises(BackendError):
            b.put("A", "notes", "again", create=True)
        self.assertEqual(self.raw(), before)

    def test_one_bak_generation(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        v1 = self.raw()
        b.put("B", "notes", "2", create=True)
        with open(self.path + ".bak", "rb") as f:
            self.assertEqual(f.read(), v1)
        b.put("C", "notes", "3", create=True)
        bak = LocalBackend(self.path + ".bak", ls.FileKeySource(self.keyfile))
        self.assertEqual([r["item"] for r in bak.catalog()], ["A", "B"])
        self.assertEqual(stat.S_IMODE(os.stat(self.path + ".bak").st_mode), 0o600)

    def test_fresh_nonce_each_write(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        n1 = self.raw().partition(b"\n")[2][:12]
        b.put("A", "notes", "1")
        self.assertNotEqual(self.raw().partition(b"\n")[2][:12], n1)

    def test_concurrent_writers_lose_nothing(self):
        self.init()
        errs = []

        def work(k):
            try:
                b = self.backend()                          # separate instance = separate "process"
                for i in range(5):
                    b.put(f"item-{k}-{i}", "notes", f"v{k}{i}", create=True)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=work, args=(k,)) for k in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        names = {r["item"] for r in self.backend().catalog()}
        self.assertEqual(names, {f"item-{k}-{i}" for k in range(4) for i in range(5)})

    def test_create_store_refuses_to_overwrite(self):
        self.init()
        with self.assertRaises(StoreError):
            self.init()


class Reload(Base):
    def test_external_change_is_picked_up_and_audited(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        self.assertEqual(len(b.catalog()), 1)
        self.events.clear()
        other = self.backend()                              # the admin CLI, say
        other.put("B", "notes", "2", create=True)
        self.events.clear()
        self.assertEqual(len(b.catalog()), 2)
        self.assertEqual(self.names(), ["store_reloaded"])
        self.assertEqual(self.events[0][1], {"items": 2})
        self.events.clear()
        b.catalog()
        self.assertEqual(self.events, [])                   # unchanged: no re-read, no event

    def test_restored_backup_is_picked_up(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        b.put("B", "notes", "2", create=True)
        os.replace(self.path + ".bak", self.path)
        self.assertEqual([r["item"] for r in b.catalog()], ["A"])

    def test_own_write_does_not_report_reload(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", "1", create=True)
        b.catalog()
        self.assertNotIn("store_reloaded", self.names())


class Events(Base):
    def test_unlocked_and_written_events_carry_no_values(self):
        self.init()
        b = self.backend()
        b.put("A", "notes", VAL, create=True, meta={"name": "a"})
        self.assertEqual(self.names(), ["store_unlocked", "store_written"])
        self.assertNotIn(VAL, json.dumps(self.events))
        self.assertNotIn("A", json.dumps(self.events))

    def test_broker_receives_events_in_audit_log(self):
        self.init()
        b = self.backend()
        audit = os.path.join(self.dir, "audit.jsonl")
        Broker({"approve_base_url": "https://s.example"}, b, FakeNotifier(), audit)
        b.put("A", "notes", VAL, create=True, meta={"vars": {"T": {"field": "notes"}}})
        with open(audit) as f:
            text = f.read()
        self.assertIn("store_written", text)
        self.assertNotIn(VAL, text)

    def test_emit_errors_are_swallowed(self):
        self.init()
        b = LocalBackend(self.path, ls.FileKeySource(self.keyfile))
        b.on_event = mock.Mock(side_effect=RuntimeError("boom"))
        b.put("A", "notes", "1", create=True)


class IdleLock(Base):
    def test_idle_drops_state_and_next_use_redecrypts(self):
        self.init()
        b = self.backend(idle=0.2)
        b.put("A", "notes", VAL, create=True)
        store = b._store
        self.assertIsNotNone(store._doc)
        deadline = time.time() + 5
        while store._doc is not None and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNone(store._doc)
        self.assertIsNone(store._dek)
        self.assertIn("store_locked", self.names())
        self.assertEqual(self.names().count("store_unlocked"), 1)
        self.assertEqual(b.get("A", "notes"), VAL)                  # decrypts again from the key source
        self.assertEqual(self.names().count("store_unlocked"), 2)

    def test_locked_store_cannot_be_read_when_key_gone(self):
        self.init()
        b = self.backend(idle=0.2)
        b.put("A", "notes", VAL, create=True)
        while b._store._doc is not None:
            time.sleep(0.05)
        os.unlink(self.keyfile)
        with self.assertRaises(StoreError):
            b.get("A", "notes")

    def test_use_extends_the_window(self):
        self.init()
        b = self.backend(idle=0.6)
        b.put("A", "notes", VAL, create=True)
        for _ in range(4):
            time.sleep(0.25)
            b.get("A", "notes")
        self.assertIsNotNone(b._store._doc)
        b.close()
        self.assertIsNone(b._store._doc)

    def test_zero_means_never(self):
        self.init()
        b = self.backend(idle=0)
        b.put("A", "notes", "1", create=True)
        self.assertIsNone(b._store._timer)


class Config(unittest.TestCase):
    def cfg(self, **over):
        b = {"type": "local", "path": "/nonexistent/store.enc",
             "key_source": {"type": "file", "path": "/nonexistent/key"}, "idle_timeout": 60}
        b.update(over)
        return {"backend": b}

    def bad(self, cfg, field):
        with self.assertRaises(BackendConfigError) as cm:
            build_backend(cfg)
        self.assertIn(field, str(cm.exception))

    def test_valid_config_builds_without_touching_disk(self):
        self.assertIsInstance(build_backend(self.cfg()), LocalBackend)
        env = self.cfg(key_source={"type": "env", "name": "X"})
        self.assertIsInstance(build_backend(env), LocalBackend)

    def test_missing_and_unknown_fields_name_the_field(self):
        c = self.cfg()
        del c["backend"]["path"]
        self.bad(c, "backend.path")
        c = self.cfg()
        del c["backend"]["key_source"]
        self.bad(c, "backend.key_source")
        self.bad(self.cfg(key_source={"type": "keychain"}), "backend.key_source.type")
        self.bad(self.cfg(key_source={"type": "file"}), "backend.key_source.path")
        self.bad(self.cfg(key_source={"type": "env"}), "backend.key_source.name")
        self.bad(self.cfg(key_source={"type": "env", "name": "X", "path": "/x"}), "backend.key_source.path")
        self.bad(self.cfg(bogus=1), "backend.bogus")
        self.bad(self.cfg(idle_timeout="soon"), "backend.idle_timeout")
        self.bad(self.cfg(idle_timeout=-1), "backend.idle_timeout")
        self.bad(self.cfg(path=""), "backend.path")

    def test_unknown_type_and_missing_backend(self):
        self.bad({"backend": {"type": "nope"}}, "backend.type")
        self.bad({}, "backend")

    def test_legacy_file_backend_unchanged(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "v.json")
        with open(p, "w") as f:
            json.dump({"A": {"notes": "x"}}, f)
        b = build_backend({"backend": {"type": "file", "path": p}})
        self.assertIsInstance(b, FileBackend)
        self.assertEqual(b.get("A", "notes"), "x")

    def test_bw_still_built(self):
        d = tempfile.mkdtemp()
        pw = os.path.join(d, "pw")
        with open(pw, "w") as f:
            f.write("fake\n")
        from secret_broker.backends import BwBackend, BwServeBackend
        b = {"type": "bw", "server_url": "https://v.example", "master_password_file": pw}
        self.assertIs(type(build_backend({"backend": b})), BwBackend)
        self.assertIs(type(build_backend({"backend": {**b, "serve": True}})), BwServeBackend)


class LocalHarness(e2e.Harness):
    """The broker's own end-to-end harness, with the vault replaced by a LocalBackend
    holding the same items."""
    decision = None

    def setUp(self):
        super().setUp()
        old = self.broker.backend._data
        items = {}
        for name, rec in old.items():
            it = {"type": "note", "notes": rec.get("notes"), "uris": [],
                  "fields": {k: v for k, v in rec.items() if k not in ("notes", "broker")}}
            if "broker" in rec:
                it["broker"] = json.loads(rec["broker"])
            items[name] = it
        self.dir = tempfile.mkdtemp()
        self.keyfile = os.path.join(self.dir, "key")
        with open(self.keyfile, "w") as f:
            f.write(RAW)
        os.chmod(self.keyfile, 0o600)
        path = os.path.join(self.dir, "store.enc")
        ls.create_store(path, ls.Key(RAW), {"items": items})
        self.broker.backend = LocalBackend(path, ls.FileKeySource(self.keyfile))
        self.broker.backend.on_event = self.broker.log
        self.broker.refresh_catalog()

    def stored_meta(self):
        return self.broker.backend._store.read(
            lambda items: {n: i.get("broker") for n, i in items.items() if i.get("broker")})


class LocalEndToEnd(LocalHarness):
    NEW = "brand-new-local-VALUE-123"

    def store(self, op="create", name="localapi", value=None, **kw):
        body = {"mode": "store", "names": [name], "op": op, "value": value or self.NEW}
        if op == "create":
            body.setdefault("allowed_hosts", ["127.0.0.1"])
        body.update(kw)
        return self.api("POST", "/v1/requests", body)

    def result(self, body):
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        return json.loads(b)

    def test_http_request_uses_custom_field_from_local_store(self):
        self.decision = "approve"
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        _, b = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        out = self.result(b)
        self.assertEqual(out["status"], "approved")
        self.assertIn("Bearer ***", out["http"]["body"])
        self.assertEqual(self.broker.backend.get("Svc", "token"), e2e.SECRET)

    def test_auto_create_then_use_via_http(self):
        code, body = self.store()
        self.assertEqual(code, 202)
        r = self.result(body)
        self.assertEqual(r["stored"]["name"], "localapi")
        self.assertEqual(self.broker.backend.get("localapi", "notes"), self.NEW)
        self.assertIn("localapi", self.stored_meta())
        # the value is in neither the audit log nor the metadata
        with open(self.audit) as f:
            text = f.read()
        self.assertNotIn(self.NEW, text)
        self.assertIn("store_written", text)
        self.assertNotIn(self.NEW, json.dumps(self.stored_meta()))
        self.decision = "approve"
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        _, b2 = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["localapi"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{LOCALAPI_TOKEN}}"}})
        out = self.result(b2)["http"]["body"]
        self.assertIn("Bearer ***", out)
        self.assertNotIn(self.NEW, out)

    def test_update_needs_approval_and_keeps_previous(self):
        self.store()
        self.decision = "approve"
        code, body = self.store("update", "localapi", value="rotated-local-VALUE-9")
        self.assertEqual(code, 202)
        self.assertEqual(self.result(body)["status"], "approved")
        self.assertEqual(self.broker.backend.get("localapi", "notes"), "rotated-local-VALUE-9")
        self.assertEqual(self.broker.backend.get("localapi", "previous_value"), self.NEW)

    def test_update_denied_changes_nothing(self):
        self.store()
        self.decision = "deny"
        _, body = self.store("update", "localapi", value="rotated-local-VALUE-9")
        self.assertEqual(self.result(body)["status"], "denied")
        self.assertEqual(self.broker.backend.get("localapi", "notes"), self.NEW)

    def test_wrong_key_keeps_broker_up_and_audits(self):
        with open(self.keyfile, "w") as f:
            f.write(base64.b64encode(b"\x07" * 32).decode())
        self.broker.backend.close()
        with self.assertRaises(StoreError):
            self.broker.refresh_catalog()
        self.assertTrue(any(r["reason"] == "wrong_key" for r in self.events("store_unlock_failed")))
        code, _ = self.api("GET", "/v1/secrets")
        self.assertEqual(code, 200)                          # previous catalog still served


if __name__ == "__main__":
    unittest.main()
