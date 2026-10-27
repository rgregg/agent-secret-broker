"""`asb sudo -- command`: the client hands the command to the root helper through the one sudoers rule.
The helper (crates/asb-root-exec) asks the broker itself; the client never requests a credential and no
password exists."""
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import tempfile
import unittest
from unittest import mock

CLI = os.path.join(os.path.dirname(__file__), "..", "client", "asb")


def load():
    loader = importlib.machinery.SourceFileLoader("asb_sudo", CLI)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_sudo", loader))
    loader.exec_module(mod)
    return mod


class AsbSudo(unittest.TestCase):
    def setUp(self):
        self.asb = load()
        self.bin = tempfile.mkdtemp()
        self.log = os.path.join(self.bin, "args.txt")
        self.fake_sudo("exit 0")
        p = mock.patch.dict(os.environ, {"PATH": self.bin + os.pathsep + os.environ["PATH"]})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("ASB_ROOT_EXEC", None)

    def fake_sudo(self, body):
        """A sudo that records its arguments (one per line) and then runs `body`."""
        path = os.path.join(self.bin, "sudo")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > {self.log}\n{body}\n')
        os.chmod(path, 0o755)

    def sudo_args(self):
        with open(self.log) as f:
            return f.read().split("\n")[:-1]

    def run_asb(self, argv):
        out, err = io.StringIO(), io.StringIO()

        def no_broker(*a, **k):
            raise AssertionError("the client must not talk to the broker: the helper does")
        with mock.patch.object(self.asb, "obtain", no_broker), mock.patch.object(self.asb, "call", no_broker), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = self.asb.main(["sudo"] + argv)
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_it_calls_the_root_helper_through_sudo_n(self):
        rc, _, err = self.run_asb(["--", "/usr/bin/systemctl", "restart", "nginx"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.sudo_args(), ["-n", "/usr/local/sbin/asb-root-exec", "--",
                                            "/usr/bin/systemctl", "restart", "nginx"])

    def test_the_commands_exit_code_passes_through(self):
        self.fake_sudo("exit 7")
        self.assertEqual(self.run_asb(["--", "/usr/bin/true"])[0], 7)

    def test_the_helper_path_can_be_overridden_but_only_the_installed_one_is_in_sudoers(self):
        with mock.patch.dict(os.environ, {"ASB_ROOT_EXEC": "/opt/asb/asb-root-exec"}):
            self.run_asb(["--", "/usr/bin/true"])
        self.assertEqual(self.sudo_args()[:3], ["-n", "/opt/asb/asb-root-exec", "--"])

    def test_a_help_flag_after_the_dashes_belongs_to_the_command(self):
        rc, out, err = self.run_asb(["--", "/usr/bin/ls", "--help"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.sudo_args()[-2:], ["/usr/bin/ls", "--help"])
        self.assertNotIn("usage: asb sudo", out)

    def test_usage_errors_exit_2_and_run_nothing(self):
        for argv in ([], ["--"], ["somecommand"], ["-x", "ls"], ["NAME", "--", "ls"]):
            rc, _, err = self.run_asb(argv)
            self.assertEqual(rc, 2, argv)
            self.assertIn("usage: asb sudo", err, argv)
        self.assertFalse(os.path.exists(self.log))

    def test_no_sudo_on_the_machine_is_a_clear_error(self):
        empty = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"PATH": empty}):
            rc, _, err = self.run_asb(["--", "/usr/bin/true"])
        self.assertEqual(rc, 2)
        self.assertIn("sudo is not installed", err)

    def test_help_describes_only_the_helper_form(self):
        text = self.asb.HELP["sudo"]
        self.assertNotIn("NAME", text)
        self.assertIn("allow-list", text)


if __name__ == "__main__":
    unittest.main()
