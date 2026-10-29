"""`asb sudo -- command`: the client hands the command to the root helper through the one sudoers rule.

Black-box: it runs the CLI as a subprocess with a fake `sudo` on PATH, so the same tests check the Python client and,
through tools/run_tests_against_rust_cli.py, the Rust one. The helper (crates/asb-root-exec) asks the broker itself;
the client never requests a credential and no password exists: these runs have no broker config at all.
"""
import os
import subprocess
import sys
import tempfile
import unittest

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "asb")


class AsbSudo(unittest.TestCase):
    def setUp(self):
        self.bin = tempfile.mkdtemp()
        self.home = tempfile.mkdtemp()           # an empty HOME: no client.json, so no broker config
        self.log = os.path.join(self.bin, "args.txt")
        self.fake_sudo("exit 0")

    def fake_sudo(self, body):
        """A sudo that records its arguments (one per line) and then runs `body`."""
        path = os.path.join(self.bin, "sudo")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > {self.log}\n{body}\n')
        os.chmod(path, 0o755)

    def sudo_args(self):
        with open(self.log) as f:
            return f.read().split("\n")[:-1]

    def asb(self, *argv, path=None, extra_env=None):
        env = {"PATH": path if path is not None else self.bin + os.pathsep + os.environ["PATH"], "HOME": self.home,
               **(extra_env or {})}
        return subprocess.run([sys.executable, "-I", CLI, *argv], env=env, capture_output=True, text=True, timeout=60)

    def test_it_calls_the_root_helper_through_sudo_n(self):
        p = self.asb("sudo", "--", "/usr/bin/systemctl", "restart", "nginx")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.sudo_args(), ["-n", "/usr/local/sbin/asb-root-exec", "--",
                                            "/usr/bin/systemctl", "restart", "nginx"])

    def test_the_commands_exit_code_passes_through(self):
        self.fake_sudo("exit 7")
        self.assertEqual(self.asb("sudo", "--", "/usr/bin/true").returncode, 7)

    def test_the_commands_output_passes_through_untouched(self):
        self.fake_sudo('echo "out line"; echo "err line" >&2')
        p = self.asb("sudo", "--", "/usr/bin/true")
        self.assertEqual((p.stdout, p.stderr), ("out line\n", "err line\n"))

    def test_the_helper_path_can_be_overridden_but_only_the_installed_one_is_in_sudoers(self):
        self.asb("sudo", "--", "/usr/bin/true", extra_env={"ASB_ROOT_EXEC": "/opt/asb/asb-root-exec"})
        self.assertEqual(self.sudo_args()[:3], ["-n", "/opt/asb/asb-root-exec", "--"])

    def test_a_help_flag_after_the_dashes_belongs_to_the_command(self):
        p = self.asb("sudo", "--", "/usr/bin/ls", "--help")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.sudo_args()[-2:], ["/usr/bin/ls", "--help"])
        self.assertNotIn("usage: asb sudo", p.stdout)

    def test_a_help_flag_before_the_dashes_is_ours(self):
        p = self.asb("sudo", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: asb sudo -- command", p.stdout)
        self.assertFalse(os.path.exists(self.log))

    def test_usage_errors_exit_2_and_run_nothing(self):
        for argv in ([], ["--"], ["somecommand"], ["-x", "ls"], ["NAME", "--", "ls"]):
            p = self.asb("sudo", *argv)
            self.assertEqual(p.returncode, 2, argv)
            self.assertIn("usage: asb sudo", p.stderr, argv)
        self.assertFalse(os.path.exists(self.log))

    def test_no_sudo_on_the_machine_is_a_clear_error(self):
        p = self.asb("sudo", "--", "/usr/bin/true", path=tempfile.mkdtemp())
        self.assertEqual(p.returncode, 2)
        self.assertIn("sudo is not installed", p.stderr)

    def test_help_describes_only_the_helper_form(self):
        text = self.asb("help", "sudo").stdout
        self.assertNotIn("NAME", text)
        self.assertIn("allow-list", text)


if __name__ == "__main__":
    unittest.main()
