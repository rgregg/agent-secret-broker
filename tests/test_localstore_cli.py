import base64
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from secret_broker import localstore_cli as cli  # noqa: E402
from secret_broker.backends import Item, LocalBackend, MemoryBackend  # noqa: E402
from secret_broker.backends import localstore as ls  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

PASS = "correct horse battery staple (fake)"
SECRET = "s3cr3t-value-DO-NOT-LEAK-4821"
SECRET2 = "0ther-s3cr3t-DO-NOT-LEAK-9930"


class FakeStdin(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self._tty = tty

    def isatty(self):
        return self._tty


class CliBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = os.path.join(self.dir, "store.enc")
        self.keyfile = os.path.join(self.dir, "key")
        with open(self.keyfile, "w") as f:
            f.write(PASS + "\n")
        os.chmod(self.keyfile, 0o600)
        self.outputs = []

    def run_cli(self, *argv, stdin="", tty=False, expect=0, key=True, getpass_values=(), inputs=()):
        args = list(argv)
        if key and "--key-file" not in args and "--key-env" not in args and "--config" not in args:
            args += ["--key-file", self.keyfile]
        if "--store" not in args and "--config" not in args:
            args += ["--store", self.store]
        out, err = io.StringIO(), io.StringIO()
        gp = mock.patch("getpass.getpass", side_effect=list(getpass_values))
        inp = mock.patch("builtins.input", side_effect=list(inputs))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", FakeStdin(stdin, tty)), gp, inp:
            code = cli.main(args)
        self.outputs += [out.getvalue(), err.getvalue()]
        self.assertEqual(code, expect, f"stdout={out.getvalue()!r} stderr={err.getvalue()!r}")
        return out.getvalue(), err.getvalue()

    def init(self, *extra):
        out, _ = self.run_cli("init", *extra)
        return out

    def backend(self):
        return LocalBackend(self.store, ls.FileKeySource(self.keyfile), 0)

    def assertNoSecrets(self, *vals):
        text = "\n".join(self.outputs)
        for v in vals or (SECRET, SECRET2):
            self.assertNotIn(v, text)


class Init(CliBase):
    def test_creates_a_private_store_and_prints_a_recovery_key_once(self):
        out = self.init()
        self.assertEqual(stat.S_IMODE(os.stat(self.store).st_mode), 0o600)
        rec = out.strip().splitlines()[-1]
        self.assertEqual(len(base64.b64decode(rec)), 32)
        self.assertEqual(out.count(rec), 1)
        # the recovery key opens it by itself
        b = LocalBackend(self.store, ls.EnvKeySource("ASB_REC"), 0)
        with mock.patch.dict(os.environ, {"ASB_REC": rec}):
            self.assertEqual(b.catalog(), [])

    def test_no_recovery(self):
        out = self.init("--no-recovery")
        self.assertIn("no recovery key", out)
        self.assertEqual(ls.parse(open(self.store, "rb").read())[0]["wraps"][0]["id"], "primary")
        self.assertEqual(len(ls.parse(open(self.store, "rb").read())[0]["wraps"]), 1)

    def test_refuses_to_overwrite_without_force(self):
        self.init()
        before = open(self.store, "rb").read()
        _, err = self.run_cli("init", expect=1)
        self.assertIn("already exists", err)
        self.assertEqual(open(self.store, "rb").read(), before)

    def test_force_keeps_the_old_file(self):
        self.init()
        before = open(self.store, "rb").read()
        self.run_cli("init", "--force")
        self.assertEqual(open(self.store + ".replaced", "rb").read(), before)
        self.assertNotEqual(open(self.store, "rb").read(), before)

    def test_missing_key_file_needs_generate_key(self):
        kf = os.path.join(self.dir, "new.key")
        _, err = self.run_cli("init", "--key-file", kf, expect=1)
        self.assertIn("--generate-key", err)
        self.run_cli("init", "--key-file", kf, "--generate-key", "--no-recovery")
        self.assertEqual(stat.S_IMODE(os.stat(kf).st_mode), 0o600)
        self.assertEqual(len(base64.b64decode(open(kf).read().strip())), 32)
        b = LocalBackend(self.store, ls.FileKeySource(kf), 0)
        self.assertEqual(b.catalog(), [])

    def test_generate_key_never_overwrites_a_key_file(self):
        _, err = self.run_cli("init", "--generate-key", expect=1)
        self.assertIn("does not exist yet", err)
        self.assertEqual(open(self.keyfile).read().strip(), PASS)

    def test_env_key_source(self):
        with mock.patch.dict(os.environ, {"ASB_K": PASS}):
            self.run_cli("init", "--key-env", "ASB_K", "--no-recovery")
            self.run_cli("list", "--key-env", "ASB_K")

    def test_a_key_source_is_required(self):
        _, err = self.run_cli("init", key=False, expect=1)
        self.assertIn("key source", err)

    def test_loose_key_file_warns(self):
        os.chmod(self.keyfile, 0o644)
        _, err = self.run_cli("init", "--no-recovery")
        self.assertIn("readable by other users", err)

    def test_config_file_supplies_store_and_key(self):
        cfg = os.path.join(self.dir, "broker.json")
        json.dump({"backend": {"type": "local", "path": self.store,
                               "key_source": {"type": "file", "path": self.keyfile}}}, open(cfg, "w"))
        self.run_cli("init", "--config", cfg, "--no-recovery")
        self.assertTrue(os.path.exists(self.store))
        self.run_cli("list", "--config", cfg)

    def test_config_must_be_a_local_backend(self):
        cfg = os.path.join(self.dir, "broker.json")
        json.dump({"backend": {"type": "bw"}}, open(cfg, "w"))
        _, err = self.run_cli("list", "--config", cfg, expect=1)
        self.assertIn("not 'local'", err)


class Safety(CliBase):
    def test_refuses_a_store_other_users_can_read(self):
        self.init("--no-recovery")
        os.chmod(self.store, 0o640)
        for cmd in (["list"], ["export-names"], ["show", "x"], ["delete", "x", "--yes"]):
            _, err = self.run_cli(*cmd, expect=1)
            self.assertIn("accessible by other users", err)
        os.chmod(self.store, 0o600)
        self.run_cli("list")

    def test_missing_store(self):
        _, err = self.run_cli("list", expect=1)
        self.assertIn("run init", err)

    def test_wrong_key_is_a_clean_error(self):
        self.init("--no-recovery")
        with open(self.keyfile, "w") as f:
            f.write("not the key\n")
        _, err = self.run_cli("list", expect=1)
        self.assertIn("wrong_key", err)
        self.assertNotIn("Traceback", err)

    def test_values_cannot_be_given_on_the_command_line(self):
        for flag in ("--password", "--value", "--secret"):
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                cli.main(["add", "x", flag, SECRET, "--store", self.store, "--key-file", self.keyfile])
            self.assertEqual(cm.exception.code, 2)


class Items(CliBase):
    def setUp(self):
        super().setUp()
        self.init("--no-recovery")

    def test_add_a_note_from_stdin(self):
        self.run_cli("add", "Svc Token", stdin=SECRET + "\n")
        self.assertEqual(self.backend().get("Svc Token", "notes"), SECRET)
        self.assertNoSecrets()

    def test_add_a_note_with_hidden_prompt(self):
        self.run_cli("add", "Svc", tty=True, getpass_values=[SECRET + "\n"])
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)

    def test_add_a_login_from_json_and_prompt(self):
        self.run_cli("add", "Modem", "--kind", "login", "--uri", "http://192.0.2.1/",
                     "--json", stdin=json.dumps({"username": "admin", "password": SECRET,
                                                 "uris": ["http://192.0.2.1/"]}))
        b = self.backend()
        self.assertEqual((b.get("Modem", "username"), b.get("Modem", "password")), ("admin", SECRET))
        self.run_cli("add", "Router", "--kind", "login", tty=True, inputs=["root"],
                     getpass_values=[SECRET2])
        self.assertEqual(b.get("Router", "password"), SECRET2)
        self.assertNoSecrets()

    def test_add_custom_fields_by_prompt(self):
        self.run_cli("add", "Multi", "--field", "api_key", "--field", "api_secret", tty=True,
                     getpass_values=[SECRET, SECRET2])
        b = self.backend()
        self.assertEqual((b.get("Multi", "api_key"), b.get("Multi", "api_secret")), (SECRET, SECRET2))

    def test_add_a_login_without_a_terminal_or_json_is_refused(self):
        _, err = self.run_cli("add", "Modem", "--kind", "login", expect=1)
        self.assertIn("terminal", err)

    def test_add_with_metadata_file(self):
        meta = os.path.join(self.dir, "m.json")
        json.dump({"allowed_hosts": ["api.example.com"], "vars": {"T": {"field": "notes"}}},
                  open(meta, "w"))
        self.run_cli("add", "Api", "--meta", meta, stdin=SECRET)
        self.assertEqual(self.backend().catalog()[0]["meta"]["allowed_hosts"], ["api.example.com"])

    def test_add_never_overwrites(self):
        self.run_cli("add", "Svc", stdin=SECRET)
        _, err = self.run_cli("add", "svc", stdin=SECRET2, expect=1)
        self.assertIn("already exists", err)
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)
        self.assertNoSecrets()

    def test_list_shows_names_and_shapes_only(self):
        self.run_cli("add", "Svc", stdin=SECRET)
        self.run_cli("add", "Modem", "--json", "--kind", "login",
                     stdin=json.dumps({"username": "admin", "password": SECRET2, "notes": SECRET}))
        out, _ = self.run_cli("list")
        self.assertIn("Svc\tnote notes no-meta", out)
        self.assertIn("Modem\tlogin username password notes no-meta", out)
        self.assertNoSecrets()

    def test_show_prints_metadata_and_field_names_not_values(self):
        meta = os.path.join(self.dir, "m.json")
        json.dump({"name": "svc", "guidance": "treat as low"}, open(meta, "w"))
        self.run_cli("add", "Svc", "--meta", meta, "--json",
                     stdin=json.dumps({"notes": SECRET, "fields": {"api_key": SECRET2}}))
        out, _ = self.run_cli("show", "svc")
        self.assertIn("api_key", out)
        self.assertIn('"guidance": "treat as low"', out)
        self.assertNoSecrets()
        _, err = self.run_cli("show", "nope", expect=1)
        self.assertIn("not found", err)

    def test_set_meta_from_file_and_stdin(self):
        self.run_cli("add", "Svc", stdin=SECRET)
        meta = os.path.join(self.dir, "m.json")
        json.dump({"a": {"b": [1]}}, open(meta, "w"))
        self.run_cli("set-meta", "Svc", meta)
        self.assertEqual(self.backend().catalog()[0]["meta"], {"a": {"b": [1]}})
        self.run_cli("set-meta", "Svc", "-", stdin='{"c": 2}')
        self.assertEqual(self.backend().catalog()[0]["meta"], {"c": 2})
        self.run_cli("set-meta", "Svc", "-", stdin='[1]', expect=1)
        self.run_cli("set-meta", "Svc", "-", stdin='nope', expect=1)
        self.run_cli("set-meta", "Nope", "-", stdin='{}', expect=1)

    def test_delete_needs_yes_or_confirmation(self):
        self.run_cli("add", "Svc", stdin=SECRET)
        self.run_cli("delete", "Svc", expect=1)
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)
        self.run_cli("delete", "Svc", tty=True, inputs=["wrong"], expect=1)
        self.run_cli("delete", "Svc", tty=True, inputs=["Svc"])
        self.assertEqual(self.backend().export_items(), [])
        self.run_cli("delete", "Svc", "--yes", expect=1)          # already gone

    def test_export_names(self):
        self.run_cli("add", "B", stdin=SECRET)
        self.run_cli("add", "a", stdin=SECRET2)
        out, _ = self.run_cli("export-names")
        self.assertEqual(out.split(), ["a", "B"])
        self.assertNoSecrets()


class KeyManagement(CliBase):
    def newkey(self, text):
        p = os.path.join(self.dir, "new.key")
        with open(p, "w") as f:
            f.write(text + "\n")
        os.chmod(p, 0o600)
        return p

    def test_change_key_rewraps_and_keeps_the_data(self):
        rec = self.init().strip().splitlines()[-1]
        self.run_cli("add", "Svc", stdin=SECRET)
        before_wraps = ls.parse(open(self.store, "rb").read())[0]["wraps"]
        nk = self.newkey("a brand new passphrase")
        self.run_cli("change-key", "--new-key-file", nk)
        b_old = self.backend()
        with self.assertRaises(ls.StoreError):
            b_old.get("Svc", "notes")
        b_new = LocalBackend(self.store, ls.FileKeySource(nk), 0)
        self.assertEqual(b_new.get("Svc", "notes"), SECRET)
        # the recovery wrap is untouched and still opens the store
        after = ls.parse(open(self.store, "rb").read())[0]["wraps"]
        self.assertEqual([w for w in after if w["id"] == "recovery"],
                         [w for w in before_wraps if w["id"] == "recovery"])
        with mock.patch.dict(os.environ, {"R": rec}):
            self.assertEqual(LocalBackend(self.store, ls.EnvKeySource("R"), 0).get("Svc", "notes"), SECRET)
        self.assertNoSecrets()

    def test_change_key_by_prompt(self):
        self.init("--no-recovery")
        self.run_cli("change-key", tty=True, getpass_values=["new pass", "new pass"])
        nk = self.newkey("new pass")
        self.assertEqual(LocalBackend(self.store, ls.FileKeySource(nk), 0).catalog(), [])
        self.run_cli("change-key", "--key-file", nk, tty=True, getpass_values=["a", "b"], expect=1)

    def test_change_key_unknown_wrap(self):
        self.init("--no-recovery")
        _, err = self.run_cli("change-key", "--wrap", "recovery", "--new-key-file", self.newkey("x"),
                              expect=1)
        self.assertIn("no wrap", err)

    def test_change_recovery_wrap(self):
        self.init()
        self.run_cli("add", "Svc", stdin=SECRET)
        nk = self.newkey("replacement recovery passphrase")
        self.run_cli("change-key", "--wrap", "recovery", "--new-key-file", nk)
        self.assertEqual(LocalBackend(self.store, ls.FileKeySource(nk), 0).get("Svc", "notes"), SECRET)
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)       # primary unchanged

    def test_rotate_dek_reencrypts_and_refuses_to_orphan_the_recovery_key(self):
        rec = self.init().strip().splitlines()[-1]
        self.run_cli("add", "Svc", stdin=SECRET)
        raw = open(self.store, "rb").read()
        _, err = self.run_cli("rotate-dek", expect=1)
        self.assertIn("other key wraps", err)
        self.assertEqual(open(self.store, "rb").read(), raw)              # nothing changed
        self.run_cli("rotate-dek", "--drop-other-wraps")
        self.assertNotEqual(open(self.store, "rb").read(), raw)
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)
        with mock.patch.dict(os.environ, {"R": rec}), self.assertRaises(ls.StoreError):
            LocalBackend(self.store, ls.EnvKeySource("R"), 0).get("Svc", "notes")

    def test_rotate_dek_with_a_new_recovery_key(self):
        old_rec = self.init().strip().splitlines()[-1]
        self.run_cli("add", "Svc", stdin=SECRET)
        out, _ = self.run_cli("rotate-dek", "--new-recovery")
        new_rec = out.strip().splitlines()[-1]
        self.assertNotEqual(new_rec, old_rec)
        with mock.patch.dict(os.environ, {"R": new_rec}):
            self.assertEqual(LocalBackend(self.store, ls.EnvKeySource("R"), 0).get("Svc", "notes"), SECRET)
        with mock.patch.dict(os.environ, {"R": old_rec}), self.assertRaises(ls.StoreError):
            LocalBackend(self.store, ls.EnvKeySource("R"), 0).get("Svc", "notes")

    def test_rotate_dek_keeping_the_recovery_key(self):
        rec = self.init().strip().splitlines()[-1]
        self.run_cli("add", "Svc", stdin=SECRET)
        rf = self.newkey(rec)
        self.run_cli("rotate-dek", "--recovery-key-file", rf)
        with mock.patch.dict(os.environ, {"R": rec}):
            self.assertEqual(LocalBackend(self.store, ls.EnvKeySource("R"), 0).get("Svc", "notes"), SECRET)

    def test_a_running_broker_picks_up_a_rotation(self):
        self.init("--no-recovery")
        self.run_cli("add", "Svc", stdin=SECRET)
        live = self.backend()
        live._store._idle_timeout = 300
        self.assertEqual(live.get("Svc", "notes"), SECRET)
        self.run_cli("rotate-dek")
        self.assertEqual(live.get("Svc", "notes"), SECRET)
        self.run_cli("add", "Two", stdin=SECRET2)
        self.assertEqual(live.get("Two", "notes"), SECRET2)


class ImportBw(CliBase):
    def setUp(self):
        super().setUp()
        self.init("--no-recovery")
        self.src = MemoryBackend()
        meta = {"name": "svc", "allowed_hosts": ["api.example.com"],
                "vars": {"T": {"field": "notes", "key": "a.b"}}, "approval": "allow"}
        self.src.import_items([
            Item("Svc", "note", notes=SECRET, meta=meta, fields={"extra": SECRET2}),
            Item("Modem", "login", username="admin", password=SECRET, uris=["http://192.0.2.1/"],
                 notes="n"),
            Item("Plain", "note", fields={"api_key": SECRET2})])
        p = mock.patch.object(cli, "build_source_backend", lambda path: self.src)
        p.start()
        self.addCleanup(p.stop)

    def test_copies_everything_and_verifies(self):
        out, _ = self.run_cli("import-bw", "--bw-config", "ignored.json")
        self.assertIn("3 items imported and verified", out)
        b = self.backend()
        want = {i.name: i.to_dict() for i in self.src.export_items()}
        got = {i.name: i.to_dict() for i in b.export_items()}
        self.assertEqual(got, want)
        self.assertEqual(b.get("Svc", "extra"), SECRET2)
        self.assertEqual({r["item"]: r["meta"] for r in b.catalog() if r["meta"]}["Svc"]["vars"]["T"],
                         {"field": "notes", "key": "a.b"})
        self.assertNoSecrets()

    def test_prints_only_names_and_leaves_the_source_alone(self):
        before = [i.to_dict() for i in self.src.export_items()]
        self.run_cli("import-bw", "--bw-config", "x.json")
        self.assertEqual([i.to_dict() for i in self.src.export_items()], before)
        self.assertNoSecrets()

    def test_existing_items_stop_the_import_unless_told(self):
        self.run_cli("add", "svc", stdin="mine")
        _, err = self.run_cli("import-bw", "--bw-config", "x.json", expect=1)
        self.assertIn("already exist", err)
        self.assertEqual(self.backend().export_items()[0].notes, "mine")        # nothing imported
        out, _ = self.run_cli("import-bw", "--bw-config", "x.json", "--skip-existing")
        self.assertIn("2 items imported", out)
        self.assertEqual(self.backend().get("svc", "notes"), "mine")
        self.run_cli("import-bw", "--bw-config", "x.json", "--overwrite")
        self.assertEqual(self.backend().get("Svc", "notes"), SECRET)

    def test_dry_run_writes_nothing(self):
        out, _ = self.run_cli("import-bw", "--bw-config", "x.json", "--dry-run")
        self.assertIn("would import Svc", out)
        self.assertEqual(self.backend().export_items(), [])

    def test_a_failed_read_back_is_reported(self):
        real = LocalBackend.export_items
        calls = []

        def lossy(self_):
            items = real(self_)
            calls.append(1)
            if len(calls) >= 2:             # the post-import read-back
                items[0].notes = "changed"
                for i in items:
                    i.fields = {}
            return items
        with mock.patch.object(LocalBackend, "export_items", lossy):
            _, err = self.run_cli("import-bw", "--bw-config", "x.json", expect=1)
        self.assertIn("read-back check FAILED", err)

    def test_source_must_export(self):
        class NoExport(MemoryBackend):
            capabilities = frozenset()
        self.src = NoExport()
        _, err = self.run_cli("import-bw", "--bw-config", "x.json", expect=1)
        self.assertIn("cannot export", err)


class ImportBwFakeVault(CliBase):
    """The same through the real BwBackend code path against the fake `bw`."""

    def test_import_from_a_fake_bitwarden_collection(self):
        from test_e2e import FAKE_BW
        from secret_broker.backends import BwBackend
        d = tempfile.mkdtemp()
        state, bw, pw = (os.path.join(d, n) for n in ("state.json", "bw", "pw"))
        open(bw, "w").write(FAKE_BW)
        os.chmod(bw, 0o755)
        open(pw, "w").write("m")
        mine = {"organizationId": "org1", "collectionIds": ["col1"]}
        items = [
            {"id": "1", "name": "Tagged", "type": 2, "notes": SECRET, "secureNote": {"type": 0}, **mine,
             "fields": [{"name": "broker", "type": 0, "value": json.dumps(
                 {"name": "tagged", "vars": {"T": {"field": "notes"}}, "n": {"deep": [1]}})},
                 {"name": "extra", "type": 1, "value": SECRET2},
                 {"name": "flag", "type": 2, "value": "true"},
                 {"name": "previous_value", "type": 1, "value": "old"}]},
            {"id": "2", "name": "Modem", "type": 1, "notes": "n", **mine,
             "login": {"username": "admin", "password": SECRET, "uris": [{"uri": "http://192.0.2.1/"}]}},
            {"id": "3", "name": "Card", "type": 3, **mine, "card": {"number": "4111"}},
            {"id": "4", "name": "Elsewhere", "type": 2, "notes": "x", "organizationId": "org1",
             "collectionIds": ["other"], "secureNote": {"type": 0}},
        ]
        json.dump({"items": items, "in": False, "n": 9}, open(state, "w"))
        self.init("--no-recovery")
        env = {"FAKE_BW_STATE": state}
        cfgpath = os.path.join(d, "broker.json")
        json.dump({"backend": {"type": "bw", "server_url": "https://v.example",
                               "master_password_file": pw, "organization": "Org",
                               "collection": "Shared"}}, open(cfgpath, "w"))

        def build(path):
            return BwBackend("https://v.example", pw, bw=bw, idle_timeout=0, organization="Org",
                             collection="Shared")
        with mock.patch.dict(os.environ, env), mock.patch.object(cli, "build_source_backend", build):
            out, _ = self.run_cli("import-bw", "--bw-config", cfgpath)
        self.assertIn("2 items imported", out)
        b = self.backend()
        got = {i.name: i for i in b.export_items()}
        self.assertEqual(sorted(got), ["Modem", "Tagged"])           # not the card, not other collections
        self.assertEqual(got["Tagged"].meta["n"], {"deep": [1]})      # parsed into a nested object
        self.assertEqual(got["Tagged"].fields, {"extra": SECRET2})    # custom text fields; no flags/history
        self.assertEqual((got["Modem"].username, got["Modem"].uris), ("admin", ["http://192.0.2.1/"]))
        self.assertEqual(json.load(open(state))["items"], items)      # the source is untouched
        self.assertNoSecrets()


class ImportEnv(CliBase):
    def setUp(self):
        super().setUp()
        self.init("--no-recovery")
        self.env = os.path.join(self.dir, "x.env")

    def write(self, text):
        with open(self.env, "w") as f:
            f.write(text)

    def test_each_key_becomes_an_env_mode_item(self):
        self.write(f"# comment\n\nOPENAI_API_KEY={SECRET}\nexport DB_PASS=\"{SECRET2}\"\nQ='single'\n")
        out, _ = self.run_cli("import-env", self.env)
        self.assertIn("3 items imported", out)
        self.assertIn(f"now delete {self.env}", out)
        b = self.backend()
        self.assertEqual(b.get("OPENAI_API_KEY", "notes"), SECRET)
        self.assertEqual(b.get("DB_PASS", "notes"), SECRET2)
        self.assertEqual(b.get("Q", "notes"), "single")
        meta = {r["item"]: r["meta"] for r in b.catalog()}["OPENAI_API_KEY"]
        self.assertEqual(meta, {"name": "openai-api-key", "approval": "prompt",
                                "vars": {"OPENAI_API_KEY": {"field": "notes"}}})
        self.assertNoSecrets()

    def test_the_broker_accepts_the_imported_metadata(self):
        self.write(f"OPENAI_API_KEY={SECRET}\n")
        self.run_cli("import-env", self.env)
        row = self.backend().catalog()[0]
        name, entry = Broker._entry(row["item"], row["meta"])
        self.assertEqual(name, "openai-api-key")
        self.assertEqual(entry["approval"], "prompt")
        self.assertEqual(entry["vars"]["OPENAI_API_KEY"]["field"], "notes")

    def test_existing_items_are_skipped_not_replaced(self):
        self.run_cli("add", "DB_PASS", stdin="mine")
        self.write(f"DB_PASS={SECRET}\nOTHER={SECRET2}\n")
        out, _ = self.run_cli("import-env", self.env)
        self.assertIn("skipped DB_PASS", out)
        self.assertEqual(self.backend().get("DB_PASS", "notes"), "mine")
        self.run_cli("import-env", self.env, "--overwrite")
        self.assertEqual(self.backend().get("DB_PASS", "notes"), SECRET)

    def test_bad_input(self):
        self.write("not a pair\n")
        _, err = self.run_cli("import-env", self.env, expect=1)
        self.assertIn("line 1", err)
        self.assertNotIn("not a pair", err)
        self.write("A=1\nA=2\n")
        _, err = self.run_cli("import-env", self.env, expect=1)
        self.assertIn("more than once", err)
        self.write("# only a comment\n")
        self.run_cli("import-env", self.env, expect=1)
        self.run_cli("import-env", os.path.join(self.dir, "missing.env"), expect=1)

    def test_parse_env_text(self):
        self.assertEqual(cli.parse_env_text('A=1\n  export B = "two words" \n#x\nC=\n'),
                         [("A", "1"), ("B", "two words"), ("C", "")])


class Entry(CliBase):
    def test_python_dash_m_entry_point(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), ".."))
        p = subprocess.run([sys.executable, "-m", "secret_broker.localstore", "init", "--store",
                            self.store, "--key-file", self.keyfile, "--no-recovery"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run([sys.executable, "-m", "secret_broker.localstore", "list", "--store",
                            self.store, "--key-file", self.keyfile],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_help_lists_every_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        for c in ("init", "list", "show", "add", "set-meta", "delete", "change-key", "rotate-dek",
                  "import-bw", "import-env", "export-names"):
            self.assertIn(c, out.getvalue())


if __name__ == "__main__":
    unittest.main()
