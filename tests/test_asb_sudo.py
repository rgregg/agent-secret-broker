"""`asb sudo NAME -- command`: the broker-approved env release is fed to sudo through an askpass
helper; the password stays out of the output and the helper is cleaned up."""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

CLI = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
PW = "hunter2-pw"

# stands in for sudo: runs askpass the way sudo -A does, and only runs the command if the password matches
FAKE_SUDO = """#!/bin/sh
[ "$1" = "-A" ] || { echo "no -A" >&2; exit 90; }
[ "$2" = "-k" ] || { echo "no -k" >&2; exit 91; }
shift 3
got=$("$SUDO_ASKPASS" "Password: ")
[ "$got" = "hunter2-pw" ] || { echo "sorry" >&2; exit 1; }
echo "askpass said $got"
exec "$@"
"""


def load():
    loader = importlib.machinery.SourceFileLoader("asb_sudo", CLI)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_sudo", loader))
    loader.exec_module(mod)
    return mod


class AsbSudo(unittest.TestCase):
    def setUp(self):
        self.asb = load()
        self.bin = tempfile.mkdtemp()
        fake = os.path.join(self.bin, "sudo")
        with open(fake, "w") as f:
            f.write(FAKE_SUDO)
        os.chmod(fake, 0o755)
        patcher = mock.patch.dict(os.environ, {"PATH": self.bin + os.pathsep + os.environ["PATH"]})
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_sudo(self, argv, env=None):
        sent = []

        def obtain(payload, waiting=""):
            sent.append(payload)
            return {"env": env if env is not None else {"SUDO_PW": PW}}
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.asb, "obtain", obtain), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = self.asb.main(["sudo"] + argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue(), sent

    def test_runs_command_with_password_masked(self):
        rc, out, err, sent = self.run_sudo(["homesudo", "--", "echo", "done"])
        self.assertEqual(rc, 0, err)
        self.assertIn("done", out)
        self.assertNotIn(PW, out + err)
        self.assertIn("askpass said ***", out)

    def test_broker_sees_the_command_under_sudo(self):
        _, _, _, sent = self.run_sudo(["homesudo", "--", "echo", "done"])
        self.assertEqual(sent[0]["mode"], "env")
        self.assertEqual(sent[0]["names"], ["homesudo"])
        self.assertEqual(sent[0]["argv"], ["sudo", "echo", "done"])

    def test_exit_code_passes_through(self):
        rc, *_ = self.run_sudo(["homesudo", "--", "sh", "-c", "exit 7"])
        self.assertEqual(rc, 7)

    def test_helper_removed_and_holds_no_password(self):
        seen = []
        real = tempfile.mkdtemp
        with mock.patch.object(tempfile, "mkdtemp", lambda **k: seen.append(real(**k)) or seen[-1]):
            self.run_sudo(["homesudo", "--", "true"])
        self.assertEqual(len(seen), 1)
        self.assertFalse(os.path.exists(seen[0]))

    def test_without_a_name_it_calls_the_root_helper_through_sudo_n(self):
        log = os.path.join(self.bin, "args.txt")
        with open(os.path.join(self.bin, "sudo"), "w") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > {log}\necho "from helper"\nexit 7\n')
        rc, out, err, sent = self.run_sudo(["--", "systemctl", "restart", "nginx"], env={})
        self.assertEqual(rc, 7)
        self.assertEqual(sent, [])          # no password request: the helper talks to the broker itself
        with open(log) as f:
            self.assertEqual(f.read().split(), ["-n", "/usr/local/sbin/asb-root-exec", "--",
                                                "systemctl", "restart", "nginx"])

    def test_a_help_flag_after_the_dashes_belongs_to_the_command(self):
        rc, out, err, _ = self.run_sudo(["n", "--", "echo", "--help"])
        self.assertEqual(rc, 0, err)
        self.assertIn("--help", out)
        self.assertNotIn("usage: asb sudo", out)

    def test_usage_errors(self):
        for argv in ([], ["n"], ["n", "echo"], ["a,b", "--", "true"], ["-x", "--", "true"]):
            rc, _, err, sent = self.run_sudo(argv)
            self.assertEqual(rc, 2, argv)
            self.assertEqual(sent, [])

    def test_credential_must_have_one_variable(self):
        rc, out, err, _ = self.run_sudo(["n", "--", "true"], env={"A": "x" * 8, "B": "y" * 8})
        self.assertEqual(rc, 3)
        self.assertNotIn("xxxxxxxx", out + err)


if __name__ == "__main__":
    unittest.main()
