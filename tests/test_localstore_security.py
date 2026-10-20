"""Hardening tests for the encrypted local store, beyond tests/test_localstore.py:
permissions, wrap identity binding, crash safety at every write step, key material
and values never in logs, errors or audit events."""
import base64
import glob
import json
import logging
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import localstore_cli as cli  # noqa: E402
from secret_broker.backends import BackendError, BackendUnavailable, LocalBackend  # noqa: E402
from secret_broker.backends import localstore as ls  # noqa: E402

RAW = base64.b64encode(bytes(range(32))).decode()
PASS = "hunter2-passphrase-DO-NOT-LOG-5521"
VAL = "fake-secret-value-DO-NOT-LEAK-0042"
VAL2 = "fake-secret-value-DO-NOT-LEAK-0043"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "sub", "store.enc")
        self.keyfile = os.path.join(self.dir, "key")
        with open(self.keyfile, "w") as f:
            f.write(PASS)
        os.chmod(self.keyfile, 0o600)
        self.events = []
        ls.FileKeySource._warned.clear()
        ls.LocalStore._warned.clear()

    def make(self, doc=None, idle=300, **kw):
        ls.create_store(self.path, ls.Key(PASS), doc, **kw)
        return self.open(idle)

    def open(self, idle=300):
        b = LocalBackend(self.path, ls.FileKeySource(self.keyfile), idle)
        b.on_event = lambda name, **f: self.events.append((name, f))
        self.addCleanup(b.close)
        return b

    def raw(self):
        with open(self.path, "rb") as f:
            return f.read()

    def leftovers(self):
        return [p for p in glob.glob(self.path + ".*") if p.endswith(".lock") is False
                and not p.endswith(".bak")]


class Permissions(Base):
    def test_files_are_private_even_with_a_permissive_umask(self):
        old = os.umask(0)
        self.addCleanup(os.umask, old)
        b = self.make()
        b.put("A", "notes", VAL, create=True)
        b.put("A", "notes", VAL2)                      # second write makes the .bak
        for p in (self.path, self.path + ".bak", self.path + ".lock"):
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600, p)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode), 0o700)

    def test_a_loose_store_warns_once_but_still_works(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL}}})
        os.chmod(self.path, 0o644)
        with self.assertLogs("secret_broker.localstore", "WARNING") as cm:
            self.assertEqual(b.get("A", "notes"), VAL)
            b.close()
            self.assertEqual(b.get("A", "notes"), VAL)
        self.assertEqual(len([m for m in cm.output if "accessible by other users" in m]), 1)
        self.assertNotIn(VAL, "\n".join(cm.output))

    def test_the_backup_is_not_readable_by_others_either(self):
        b = self.make()
        os.chmod(self.path, 0o600)
        b.put("A", "notes", VAL, create=True)
        self.assertEqual(stat.S_IMODE(os.stat(self.path + ".bak").st_mode), 0o600)


class WrapBinding(Base):
    def rewrite(self, mutate):
        head, _, body = self.raw().partition(b"\n")
        h = json.loads(head)
        mutate(h)
        with open(self.path, "wb") as f:
            f.write(json.dumps(h, sort_keys=True, separators=(",", ":")).encode() + b"\n" + body)

    def test_a_wrap_cannot_be_renamed(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL}}}, recovery_key=ls.Key(RAW))
        b.close()

        def rename(h):
            for w in h["wraps"]:
                w["id"] = "x-" + w["id"]
        self.rewrite(rename)
        with self.assertRaises(BackendUnavailable):
            self.open().get("A", "notes")

    def test_wraps_cannot_be_reordered_or_dropped_silently(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL}}}, recovery_key=ls.Key(RAW))
        b.close()
        self.rewrite(lambda h: h["wraps"].reverse())            # header is AAD: the body fails
        with self.assertRaises(BackendUnavailable):
            self.open().get("A", "notes")

    def test_an_absurd_scrypt_cost_is_refused_before_it_is_computed(self):
        b = self.make({"items": {}})
        b.close()

        def evil(h):
            h["wraps"][0]["kdf"].update(n=2 ** 30)
        self.rewrite(evil)
        with mock.patch.object(ls, "Scrypt", side_effect=AssertionError("derived")):
            with self.assertRaises(ls.StoreError) as cm:
                self.open().get("A", "notes")
        self.assertEqual(cm.exception.reason, "corrupt")

    def test_two_stores_never_share_wrap_material(self):
        a = os.path.join(self.dir, "a.enc")
        c = os.path.join(self.dir, "c.enc")
        ls.create_store(a, ls.Key(PASS))
        ls.create_store(c, ls.Key(PASS))
        ha = json.loads(open(a, "rb").read().partition(b"\n")[0])["wraps"][0]
        hc = json.loads(open(c, "rb").read().partition(b"\n")[0])["wraps"][0]
        self.assertNotEqual(ha["wrapped_dek"], hc["wrapped_dek"])
        self.assertNotEqual(ha["kdf"]["salt"], hc["kdf"]["salt"])


class CrashSafety(Base):
    def test_a_failure_at_any_step_of_a_write_keeps_the_old_file(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL, "uris": [], "fields": {}}}})
        b.get("A", "notes")
        before = self.raw()
        steps = {"fsync": 1, "link": 1, "replace_bak": 1, "replace_final": 2, "fsync_dir": 2}
        for name, nth in steps.items():
            calls = []
            target = {"fsync": "os.fsync", "link": "os.link", "replace_bak": "os.replace",
                      "replace_final": "os.replace", "fsync_dir": "os.fsync"}[name]
            real = {"os.fsync": os.fsync, "os.link": os.link, "os.replace": os.replace}[target]

            def failing(*a, _real=real, _calls=calls, _nth=nth, **k):
                _calls.append(1)
                if len(_calls) == _nth:
                    raise OSError(28, "No space left on device")
                return _real(*a, **k)
            with mock.patch(target, failing):
                with self.assertRaises(OSError) if name == "fsync_dir" else self.assertRaises(Exception):
                    b.put("A", "notes", VAL2)
            if name != "fsync_dir":                       # the directory fsync happens after the rename
                self.assertEqual(self.raw(), before, name)
            self.assertEqual(self.leftovers(), [], name)
            fresh = self.open()
            self.assertIn(fresh.get("A", "notes"), (VAL, VAL2), name)
            # the failed write also left no half state in the running backend
            self.assertIn(b.get("A", "notes"), (VAL, VAL2), name)
            b.put("A", "notes", VAL)                      # and the store is still writable
            before = self.raw()

    def test_a_crash_between_bak_and_rename_leaves_a_valid_file_and_backup(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL, "uris": [], "fields": {}}}})
        b.get("A", "notes")
        before = self.raw()
        real = os.replace
        calls = []

        def die_on_final(src, dst):
            calls.append(dst)
            if len(calls) == 2:
                raise KeyboardInterrupt("simulated kill")
            return real(src, dst)
        with mock.patch("os.replace", die_on_final):
            with self.assertRaises(KeyboardInterrupt):
                b.put("A", "notes", VAL2)
        self.assertEqual(self.raw(), before)
        with open(self.path + ".bak", "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.open().get("A", "notes"), VAL)
        self.assertEqual(self.leftovers(), [])

    def test_a_failed_change_function_writes_nothing(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL, "uris": [], "fields": {}}}})
        before = self.raw()
        with self.assertRaises(BackendError):
            b.put("Nope", "notes", VAL2)
        self.assertEqual(self.raw(), before)
        self.assertFalse(os.path.exists(self.path + ".bak"))


class NoLeaks(Base):
    def test_neither_values_nor_keys_reach_logs_during_a_whole_session(self):
        records = []

        class Grab(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage() + " " + str(record.args))
        h = Grab(level=logging.DEBUG)
        root = logging.getLogger()
        old = root.level
        root.addHandler(h)
        root.setLevel(logging.DEBUG)
        self.addCleanup(lambda: (root.removeHandler(h), root.setLevel(old)))
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        os.chmod(os.path.dirname(self.path), 0o700)
        os.chmod(self.keyfile, 0o644)                    # provoke the key file warning
        b = self.make({"items": {}}, recovery_key=ls.Key(RAW))
        b.put("A", "notes", VAL, create=True, meta={"a": 1})
        b.put("A", "notes", VAL2, keep_previous=True)
        b.catalog()
        with open(self.keyfile, "w") as f:
            f.write("a wrong passphrase DO-NOT-LOG")
        b.close()
        with self.assertRaises(BackendUnavailable):
            b.get("A", "notes")
        text = "\n".join(records) + json.dumps(self.events, default=str)
        for secret in (VAL, VAL2, PASS, RAW, "wrong passphrase DO-NOT-LOG"):
            self.assertNotIn(secret, text)

    def test_exceptions_do_not_carry_keys_or_values(self):
        b = self.make({"items": {"A": {"type": "note", "notes": VAL, "uris": [], "fields": {}}}})
        b.close()
        with open(self.keyfile, "w") as f:
            f.write(PASS + "-wrong")
        errors = []
        for call in (lambda: b.get("A", "notes"), lambda: b.catalog(),
                     lambda: b.put("A", "notes", VAL2), lambda: b.set_meta("A", {"k": VAL2})):
            try:
                call()
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        self.assertEqual(len(errors), 4)
        for e in errors:
            text = f"{e!s} {e!r} {e.args}"
            for secret in (VAL, VAL2, PASS, PASS + "-wrong"):
                self.assertNotIn(secret, text)

    def test_key_objects_never_print_their_material(self):
        k = ls.Key(PASS)
        self.assertNotIn(PASS, repr(k))
        self.assertNotIn(PASS, str(k))
        src = ls.FileKeySource(self.keyfile)
        self.assertNotIn(PASS, repr(src) + str(src))
        self.assertNotIn(RAW, repr(ls.Key(RAW)))

    def test_audit_events_carry_only_names_counts_and_reasons(self):
        b = self.make({"items": {}}, idle=0.2)
        b.put("A", "notes", VAL, create=True)
        b.get("A", "notes")
        import time
        time.sleep(0.5)
        with open(self.path, "ab"):
            pass
        os.utime(self.path, None)
        b.get("A", "notes")
        with open(self.keyfile, "w") as f:
            f.write("wrong")
        b.close()
        with self.assertRaises(BackendUnavailable):
            b.get("A", "notes")
        names = {n for n, _ in self.events}
        self.assertLessEqual(names, {"store_unlocked", "store_locked", "store_written",
                                     "store_reloaded", "store_unlock_failed", "store_rekeyed"})
        for _, fields in self.events:
            for k, v in fields.items():
                self.assertIn(k, {"items", "idle_seconds", "reason", "wraps"})
                self.assertIsInstance(v, (int, float, str))
        self.assertNotIn(VAL, json.dumps(self.events))

    def test_the_cli_never_prints_values_or_keys_in_any_command(self):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()

        def run(*argv, stdin=""):
            class In(io.StringIO):
                def isatty(self):
                    return False
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    mock.patch("sys.stdin", In(stdin)):
                return cli.main(list(argv) + ["--store", self.path, "--key-file", self.keyfile])
        self.assertEqual(run("init", "--no-recovery"), 0)
        self.assertEqual(run("add", "A", stdin=VAL), 0)
        self.assertEqual(run("add", "L", "--json", "--kind", "login",
                             stdin=json.dumps({"username": "u", "password": VAL2})), 0)
        for cmd in (["list"], ["show", "A"], ["show", "L"], ["export-names"]):
            self.assertEqual(run(*cmd), 0)
        self.assertEqual(run("add", "A", stdin=VAL2), 1)                   # conflict
        self.assertEqual(run("show", "missing"), 1)
        for secret in (VAL, VAL2, PASS):
            self.assertNotIn(secret, out.getvalue() + err.getvalue())


if __name__ == "__main__":
    unittest.main()
