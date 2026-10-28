"""Env mode: the script entries the CLI puts in its request are what the Python script detection finds.

Differential and black-box: it runs the CLI as a subprocess against a stub broker and compares the request's `scripts`
with `find_scripts` from the Python client (loaded from client/asb_python when tools/run_tests_against_rust_cli.py has
replaced client/asb with a shim around the Rust binary). The same file therefore checks the Python client against
itself and the Rust client against Python. The commands really run after the stub approves, so every script here is
harmless and the CLI gets no stdin.
"""
import _fast  # noqa: F401
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import test_scripts as ts  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "..", "client", "asb")
PY = os.path.join(HERE, "..", "client", "asb_python")
if not os.path.exists(PY):
    PY = CLI
_loader = importlib.machinery.SourceFileLoader("asb_py_reference", PY)
A = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_py_reference", _loader))
_loader.exec_module(A)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.home = os.path.realpath(tempfile.mkdtemp())
        self.cwd = os.getcwd()
        os.chdir(self.d)
        ts.FakeBroker.seen, ts.FakeBroker.hook = [], None
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), ts.FakeBroker)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.env = dict(os.environ, SECRET_BROKER_URL=f"http://127.0.0.1:{self.srv.server_address[1]}",
                        SECRET_BROKER_KEY="k", HOME=self.home)

    def tearDown(self):
        os.chdir(self.cwd)
        self.srv.shutdown()
        self.srv.server_close()

    def write(self, name, data, mode=0o644):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)
        return p

    def sent(self, argv, env=None):
        """The `scripts` the CLI sends for this command (None when it sends no such key)."""
        ts.FakeBroker.seen = []
        subprocess.run([sys.executable, "-I", CLI, "svc", "--", *argv], env=env or self.env, cwd=self.d,
                       stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        self.assertEqual(len(ts.FakeBroker.seen), 1, argv)
        return ts.FakeBroker.seen[0].get("scripts")

    def same(self, argv, env=None):
        """The CLI and the Python function agree about `argv`; returns what they found."""
        env = env or self.env
        with mock.patch.dict(os.environ, {k: env[k] for k in ("HOME", "PATH")}):
            want = json.loads(json.dumps(A.find_scripts(list(argv))))
        got = self.sent(argv, env)
        self.assertEqual(got, want or None, argv)
        return want


class Parity(Base):
    def test_interpreters_and_their_scripts(self):
        self.write("deploy.sh", "#!/bin/sh\necho hi\n")
        self.write("sync.py", "print(1)\n")
        for argv in (["bash", "deploy.sh"], ["sh", "deploy.sh", "arg"], ["zsh", "-e", "deploy.sh"],
                     ["bash", "-x", "-o", "pipefail", "deploy.sh"], ["/bin/bash", "deploy.sh"],
                     ["dash", "--", "deploy.sh"], ["bash", "-eu", "deploy.sh"], ["python3", "sync.py"],
                     ["python3.12", "-u", "sync.py"], ["python", "-W", "ignore", "sync.py"],
                     ["node", "-r", "dotenv/config", "sync.py"], ["ruby", "sync.py"], ["perl", "-w", "sync.py"],
                     ["php", "sync.py"], ["deno", "run", "-A", "sync.py"], ["bun", "run", "sync.py"],
                     ["bun", "sync.py"], ["awk", "-f", "sync.py", "data"], ["sed", "-f", "sync.py", "data"]):
            self.assertTrue(self.same(argv), argv)

    def test_wrappers_are_skipped(self):
        self.write("deploy.sh", "#!/bin/sh\n")
        for argv in (["env", "A=1", "B=2", "bash", "deploy.sh"], ["env", "-u", "X", "bash", "deploy.sh"],
                     ["nohup", "bash", "deploy.sh"], ["time", "bash", "deploy.sh"], ["timeout", "30", "bash", "deploy.sh"],
                     ["timeout", "-s", "KILL", "30", "bash", "deploy.sh"], ["nice", "-n", "5", "bash", "deploy.sh"],
                     ["nice", "-5", "bash", "deploy.sh"], ["stdbuf", "-oL", "bash", "deploy.sh"],
                     ["exec", "bash", "deploy.sh"], ["command", "bash", "deploy.sh"],
                     ["nohup", "nice", "-n", "5", "env", "A=1", "timeout", "9", "bash", "deploy.sh"]):
            self.assertTrue(self.same(argv), argv)

    def test_inline_code_and_shell_strings(self):
        self.write("deploy.sh", "#!/bin/sh\n", 0o755)
        self.assertTrue(self.same(["bash", "-c", "./deploy.sh"]))
        self.assertTrue(self.same(["sh", "-c", "echo a && bash deploy.sh"]))
        self.assertTrue(self.same(["sh", "-c", "LANG=C bash deploy.sh"]))
        for argv in (["python3", "-c", "import x"], ["python3", "-m", "mod", "deploy.sh"], ["node", "-e", "1"],
                     ["ruby", "-e", "1"], ["perl", "-e", "1"], ["perl", "-ne", "print"], ["php", "-r", "1;"],
                     ["awk", "{print}", "deploy.sh"], ["sed", "s/a/b/", "deploy.sh"], ["sed", "-n", "p"]):
            self.assertEqual(self.same(argv), [], argv)

    def test_scripts_run_directly(self):
        p = self.write("run.sh", "#!/bin/bash\necho\n", 0o755)
        q = self.write("noshebang", "echo hi\n", 0o755)
        self.assertEqual([e["path"] for e in self.same(["./run.sh"])], [p])
        self.assertEqual([e["path"] for e in self.same([p])], [p])
        self.assertEqual([e["path"] for e in self.same(["./noshebang"])], [q])
        self.assertEqual(self.same(["./nothere"]), [])
        self.assertEqual(self.same(["nohup", "./run.sh", "--flag"])[0]["path"], p)

    def test_a_bare_name_on_path_needs_a_shebang(self):
        bindir = os.path.join(self.d, "bin")
        self.write("bin/tool.sh", "#!/bin/sh\necho\n", 0o755)
        self.write("bin/plain", "just text\n", 0o755)
        env = {**self.env, "PATH": bindir + os.pathsep + os.environ["PATH"]}
        self.assertEqual(self.same(["tool.sh"], env)[0]["path"], os.path.join(bindir, "tool.sh"))
        self.assertEqual(self.same(["plain"], env), [])
        self.assertEqual(self.same(["ls", "-l"], env), [])

    def test_unreadable_and_odd_files(self):
        self.write("blob.py", b"\x00\x01\x02binary")
        self.assertEqual(self.same(["python3", "blob.py"])[0]["unreadable"], "binary")
        self.assertEqual(self.same(["bash", "gone.sh"])[0]["unreadable"], "missing")
        self.assertEqual(self.same(["./blob.py"]), [])
        os.mkdir("adir")
        self.assertEqual(self.same(["bash", "adir"]), [])
        if os.getuid() != 0:
            self.write("secret.sh", "x", 0o000)
            self.assertEqual(self.same(["bash", "secret.sh"])[0]["unreadable"], "permission")
        with open("sparse.sh", "wb") as f:
            f.truncate(65 * 1024 * 1024)
        self.assertEqual(self.same(["bash", "sparse.sh"])[0]["unreadable"], "too_large")

    def test_refused_places_are_not_read(self):
        for sub in (".ssh", "tokens", ".config/secret-broker"):
            self.write(os.path.join(self.home, sub, "x.sh"), "TOPSECRET\n")
            for argv in (["bash", os.path.join(self.home, sub, "x.sh")], ["bash", f"~/{sub}/x.sh"]):
                e = self.same(argv)
                self.assertEqual(e[0]["unreadable"], "refused", argv)
                self.assertNotIn("TOPSECRET", json.dumps(e))
        for argv in (["bash", "/proc/version"], ["bash", "/sys/kernel/x"], ["bash", "/dev/zero"]):
            self.assertEqual(self.same(argv)[0]["unreadable"], "refused", argv)

    def test_symlinks_are_resolved_once_and_the_target_decides_refusal(self):
        real = self.write("real.sh", "#!/bin/sh\necho\n")
        os.symlink(real, "link.sh")
        e = self.same(["bash", "link.sh"])
        self.assertEqual((e[0]["path"], e[0]["given"]), (real, os.path.join(self.d, "link.sh")))
        key = self.write(os.path.join(self.home, ".ssh", "id"), "PRIVATE")
        os.symlink(key, "innocent.sh")
        e = self.same(["bash", "innocent.sh"])
        self.assertEqual(e[0]["unreadable"], "refused")
        self.assertNotIn("PRIVATE", json.dumps(e))
        os.symlink("loop2", "loop1")
        os.symlink("loop1", "loop2")
        self.same(["bash", "loop1"])

    def test_sizes_text_and_hash(self):
        body = ("echo line\n" * 5000).encode()
        self.write("big.sh", body)
        e = self.same(["bash", "big.sh"])[0]
        self.assertEqual((e["truncated"], e["size"], e["sha256"]), (True, len(body), hashlib.sha256(body).hexdigest()))
        huge = ("# pad\n" * 60000).encode()
        self.write("huge.sh", huge)
        self.assertEqual(self.same(["bash", "huge.sh"])[0]["sha256"], hashlib.sha256(huge).hexdigest())
        self.write("small.sh", "echo\n")
        self.assertFalse(self.same(["bash", "small.sh"])[0]["truncated"])
        self.write("u.sh", ("é" * 20000).encode())
        self.assertNotIn("�", self.same(["bash", "u.sh"])[0]["text"])
        self.write("bad.sh", b"echo \xff\xfe ok\n")
        self.assertIn("text", self.same(["bash", "bad.sh"])[0])
        for bad in (25, 30, 31, 35):                      # the share of undecodable bytes that makes a file "binary"
            self.write(f"mix{bad}.sh", b"\xff" * bad + b"a" * (100 - bad))
            self.same(["bash", f"mix{bad}.sh"])
        self.assertIn("text", self.same(["bash", "mix30.sh"])[0])
        self.assertEqual(self.same(["bash", "mix31.sh"])[0].get("unreadable"), "binary")
        self.write("fffd.sh", "echo � ok\n".encode())
        self.assertIn("�", self.same(["bash", "fffd.sh"])[0]["text"])
        self.write("cut.sh", b"a" * (32 * 1024 - 1) + "é".encode())     # a character cut by the limit
        self.same(["bash", "cut.sh"])

    def test_stdin_markers(self):
        self.write("x.sh", "echo\n")
        for argv in (["bash", "-s"], ["sh", "-s", "arg"], ["python3", "-"], ["bash", "-"], ["bash"], ["python3"],
                     ["sh", "/dev/stdin"], ["bash", "-s", "--", "x"], ["nohup", "bash", "-s"]):
            self.assertEqual(self.same(argv), [{"stdin": True}], argv)

    def test_three_files_at_most_and_no_repeats(self):
        for n in "abcde":
            self.write(f"{n}.awk", "{print}\n")
        argv = ["awk"]
        for n in "abcde":
            argv += ["-f", f"{n}.awk"]
        self.assertEqual(len(self.same(argv)), 3)
        self.assertEqual(len(self.same(["awk", "-f", "a.awk", "-f", "a.awk"])), 1)

    def test_odd_characters_in_a_path_are_replaced(self):
        self.write("we\x1bird‮.sh", "echo\n")
        e = self.same(["bash", "we\x1bird‮.sh"])
        self.assertNotRegex(e[0]["path"], "[\x00-\x1f‮]")

    def test_relative_and_dotted_paths(self):
        self.write("sub/run.sh", b"#!/bin/sh\necho hi\n")
        os.symlink(os.path.join(self.d, "sub", "run.sh"), os.path.join(self.d, "link.sh"))
        for argv in (["bash", "sub/run.sh"], ["./sub/run.sh"], ["bash", "link.sh"], ["bash", "./sub/../sub/run.sh"],
                     ["env", "-i", "bash", "sub/run.sh"], ["env", "LANG=C", "bash", os.path.join(self.d, "link.sh")],
                     ["nohup", "bash", "link.sh"]):
            self.assertTrue(self.same(argv), argv)

    def test_the_request_also_carries_the_directory(self):
        self.same(["echo", "hi"])
        self.assertEqual(ts.FakeBroker.seen[0]["cwd"], self.d)
        self.assertEqual(ts.FakeBroker.seen[0]["argv"], ["echo", "hi"])
        self.assertEqual(ts.FakeBroker.seen[0]["mode"], "env")


class Running(Base):
    """What happens after the human approves."""

    def run_cli(self, *argv):
        return subprocess.run([sys.executable, "-I", CLI, "svc", "--", *argv], env=self.env, cwd=self.d,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)

    def test_the_values_are_masked_in_both_streams_and_the_exit_code_passes_through(self):
        p = self.run_cli("sh", "-c", 'echo "out=$SVC_TOKEN"; echo "err=$SVC_TOKEN" >&2; exit 3')
        self.assertEqual((p.returncode, p.stdout), (3, "out=***\n"))
        self.assertTrue(p.stderr.endswith("err=***\n"), p.stderr)

    def test_short_values_are_not_masked(self):
        ts.FakeBroker.do_GET = lambda self_: self_._send(200, {"status": "approved", "env": {"SVC_TOKEN": "abc12"}})
        self.addCleanup(lambda: setattr(ts.FakeBroker, "do_GET", _orig_get))
        self.assertEqual(self.run_cli("sh", "-c", 'echo "$SVC_TOKEN"').stdout, "abc12\n")

    def test_the_command_gets_the_rest_of_the_environment_too(self):
        p = self.run_cli("sh", "-c", 'echo "$HOME"')
        self.assertEqual(p.stdout, self.home + "\n")

    def test_a_signal_death_is_a_shell_style_status(self):
        self.assertEqual(self.run_cli("sh", "-c", "kill -9 $$").returncode, 247)

    def test_usage_errors(self):
        for argv in (["--", "ls"], ["a,b"], ["svc", "--"]):
            p = subprocess.run([sys.executable, "-I", CLI, *argv], env=self.env, capture_output=True, text=True,
                               timeout=30, stdin=subprocess.DEVNULL)
            self.assertEqual(p.returncode, 2, argv)
        p = subprocess.run([sys.executable, "-I", CLI, "-x", "--", "ls"], env=self.env, capture_output=True, text=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        self.assertEqual(p.returncode, 2)
        self.assertIn("looks like a flag", p.stderr)


_orig_get = ts.FakeBroker.do_GET

if __name__ == "__main__":
    unittest.main()
