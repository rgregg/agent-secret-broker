"""asb agent-setup: marked instruction block for Claude Code, Codex and Copilot.

Every test runs the CLI with a temporary HOME and a temporary working directory, an
empty PATH directory (so no real agent binary is detected) and no CODEX_HOME or
COPILOT_HOME. Nothing here touches a real agent file or the real client.json.
"""
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "asb")
BEGIN = re.compile(r"<!-- asb:agent-setup begin v\d+ -->")
END = "<!-- asb:agent-setup end -->"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = os.path.join(self.tmp.name, "home")
        self.proj = os.path.join(self.tmp.name, "proj")
        self.bin = os.path.join(self.tmp.name, "bin")
        for d in (self.home, self.proj, self.bin):
            os.makedirs(d)

    def asb(self, *args, env_extra=None):
        env = {"HOME": self.home, "PATH": self.bin, "LANG": "C.UTF-8"}
        env.update(env_extra or {})
        r = subprocess.run([sys.executable, CLI, "agent-setup", *args], cwd=self.proj, env=env,
                           capture_output=True, text=True)
        return r

    def p(self, *parts):
        return os.path.join(self.home, *parts)

    def read(self, path, mode="rb"):
        with open(path, mode) as f:
            return f.read()

    def write(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    def backups(self, d):
        return [n for n in os.listdir(d) if ".asb-bak-" in n]


class Targets(Base):
    def test_each_agent_user_and_project(self):
        cases = [
            ("claude", "user", self.p(".claude", "CLAUDE.md")),
            ("codex", "user", self.p(".codex", "AGENTS.md")),
            ("copilot", "user", self.p(".copilot", "copilot-instructions.md")),
            ("claude", "project", os.path.join(self.proj, "CLAUDE.md")),
            ("codex", "project", os.path.join(self.proj, "AGENTS.md")),
            ("copilot", "project", os.path.join(self.proj, ".github", "copilot-instructions.md")),
        ]
        for agent, scope, path in cases:
            with self.subTest(agent=agent, scope=scope):
                r = self.asb("--agent", agent, "--scope", scope)
                self.assertEqual(r.returncode, 0, r.stderr)
                text = self.read(path, "r")
                self.assertRegex(text, BEGIN)
                self.assertIn(END, text)

    def test_block_content(self):
        self.asb("--agent", "claude")
        text = self.read(self.p(".claude", "CLAUDE.md"), "r")
        for needle in ("asb which", "asb list", "asb http", "asb request-credential",
                       "asb guide", "final", "Never read credential"):
            self.assertIn(needle, text)
        text.encode("ascii")
        self.assertNotIn("ryan", text.lower())
        self.assertNotIn("http://", text)
        self.assertLess(len(text.splitlines()), 20)

    def test_claude_project_prefers_existing_dot_claude_file(self):
        alt = os.path.join(self.proj, ".claude", "CLAUDE.md")
        self.write(alt, "mine\n")
        self.assertEqual(self.asb("--agent", "claude", "--scope", "project").returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.proj, "CLAUDE.md")))
        self.assertRegex(self.read(alt, "r"), BEGIN)

    def test_env_homes_honoured(self):
        ch, cp = os.path.join(self.tmp.name, "ch"), os.path.join(self.tmp.name, "cp")
        r = self.asb("--agent", "all", env_extra={"CODEX_HOME": ch, "COPILOT_HOME": cp})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(ch, "AGENTS.md")))
        self.assertTrue(os.path.exists(os.path.join(cp, "copilot-instructions.md")))
        self.assertFalse(os.path.exists(self.p(".codex")))

    def test_codex_override_note(self):
        self.write(self.p(".codex", "AGENTS.override.md"), "x\n")
        r = self.asb("--agent", "codex")
        self.assertIn("AGENTS.override.md", r.stdout)

    def test_all_creates_everything(self):
        r = self.asb("--agent", "all")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in ((".claude", "CLAUDE.md"), (".codex", "AGENTS.md"),
                    (".copilot", "copilot-instructions.md")):
            self.assertTrue(os.path.exists(self.p(*rel)))


class Detect(Base):
    def test_nothing_found_exit_1(self):
        r = self.asb()
        self.assertEqual(r.returncode, 1)
        self.assertIn("no coding agent found", r.stderr)
        self.assertEqual(os.listdir(self.home), [])

    def test_detects_config_dirs_and_reports(self):
        os.makedirs(self.p(".claude"))
        os.makedirs(self.p(".codex"))
        r = self.asb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("found claude", r.stdout)
        self.assertIn("found codex", r.stdout)
        self.assertNotIn("found copilot", r.stdout)
        self.assertTrue(os.path.exists(self.p(".claude", "CLAUDE.md")))
        self.assertFalse(os.path.exists(self.p(".copilot")))

    def test_detects_binary_but_does_not_create_directory(self):
        exe = os.path.join(self.bin, "copilot")
        self.write(exe, "#!/bin/sh\n")
        os.chmod(exe, 0o755)
        r = self.asb()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("found copilot", r.stdout)
        self.assertIn("skipped", r.stdout)
        self.assertFalse(os.path.exists(self.p(".copilot")))

    def test_project_scope_detects_existing_file(self):
        self.write(os.path.join(self.proj, "AGENTS.md"), "hello\n")
        r = self.asb("--scope", "project")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("found codex", r.stdout)
        self.assertRegex(self.read(os.path.join(self.proj, "AGENTS.md"), "r"), BEGIN)
        self.assertFalse(os.path.exists(os.path.join(self.proj, "CLAUDE.md")))


class Content(Base):
    def setUp(self):
        super().setUp()
        self.f = self.p(".claude", "CLAUDE.md")

    def test_idempotent_and_no_backup_when_unchanged(self):
        self.write(self.f, "# Mine\n\nkeep this\n")
        self.assertEqual(self.asb("--agent", "claude").returncode, 0)
        first = self.read(self.f)
        self.assertEqual(len(self.backups(self.p(".claude"))), 1)
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 0)
        self.assertIn("unchanged", r.stdout)
        self.assertEqual(self.read(self.f), first)
        self.assertEqual(len(self.backups(self.p(".claude"))), 1)

    def test_existing_content_preserved_around_block(self):
        before, after = "# Top\n\nline A\n", "\n## Later\nline B\n"
        self.write(self.f, before)
        self.asb("--agent", "claude")
        text = self.read(self.f, "r")
        self.assertTrue(text.startswith(before))
        # user adds text after the block, then a re-run must keep both sides
        self.write(self.f, text + after)
        self.assertEqual(self.asb("--agent", "claude").returncode, 0)
        text2 = self.read(self.f, "r")
        self.assertTrue(text2.startswith(before))
        self.assertTrue(text2.endswith(after))
        self.assertEqual(text2.count(END), 1)

    def test_old_version_replaced_in_place(self):
        old = "intro\n<!-- asb:agent-setup begin v0 -->\nstale text\n<!-- asb:agent-setup end -->\noutro\n"
        self.write(self.f, old)
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("updated (v0 -> v1)", r.stdout)
        text = self.read(self.f, "r")
        self.assertTrue(text.startswith("intro\n<!-- asb:agent-setup begin v1 -->"))
        self.assertTrue(text.endswith(END + "\noutro\n"))
        self.assertNotIn("stale", text)

    def test_no_trailing_newline(self):
        self.write(self.f, "no newline")
        self.asb("--agent", "claude")
        text = self.read(self.f, "r")
        self.assertTrue(text.startswith("no newline\n\n<!-- asb"))
        self.assertTrue(text.endswith(END + "\n"))
        again = self.read(self.f)
        self.asb("--agent", "claude")
        self.assertEqual(self.read(self.f), again)

    def test_block_at_eof_without_newline_stays_that_way(self):
        self.write(self.f, "top\n")
        self.asb("--agent", "claude")
        body = self.read(self.f, "r").rstrip("\n")
        self.write(self.f, body)
        self.assertEqual(self.asb("--agent", "claude").returncode, 0)
        self.assertEqual(self.read(self.f, "r"), body)

    def test_crlf_file_stays_crlf(self):
        self.write(self.f, b"# Mine\r\nline\r\n")
        self.asb("--agent", "claude")
        raw = self.read(self.f)
        self.assertTrue(raw.startswith(b"# Mine\r\nline\r\n"))
        self.assertNotRegex(raw, rb"(?<!\r)\n")
        again = raw
        self.assertEqual(self.asb("--agent", "claude").returncode, 0)
        self.assertEqual(self.read(self.f), again)
        self.assertEqual(self.asb("--agent", "claude", "--remove").returncode, 0)
        self.assertEqual(self.read(self.f), b"# Mine\r\nline\r\n")

    def test_non_utf8_refused(self):
        self.write(self.f, b"\xff\xfe bad")
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self.read(self.f), b"\xff\xfe bad")

    def test_symlink_written_through(self):
        target = os.path.join(self.tmp.name, "dotfiles", "claude.md")
        self.write(target, "linked\n")
        os.makedirs(self.p(".claude"))
        os.symlink(target, self.f)
        self.assertEqual(self.asb("--agent", "claude").returncode, 0)
        self.assertTrue(os.path.islink(self.f))
        self.assertRegex(self.read(target, "r"), BEGIN)
        self.assertEqual(len(self.backups(os.path.dirname(target))), 1)
        self.assertEqual(self.backups(self.p(".claude")), [])

    def test_dangling_symlink_refused(self):
        os.makedirs(self.p(".claude"))
        os.symlink(os.path.join(self.tmp.name, "nowhere"), self.f)
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 2)
        self.assertIn("dangling", r.stderr)

    def test_file_mode_preserved(self):
        self.write(self.f, "x\n")
        os.chmod(self.f, 0o600)
        self.asb("--agent", "claude")
        self.assertEqual(stat.S_IMODE(os.stat(self.f).st_mode), 0o600)

    def test_backup_is_copy_of_original(self):
        self.write(self.f, "original\n")
        self.asb("--agent", "claude")
        (name,) = self.backups(self.p(".claude"))
        self.assertRegex(name, r"\.asb-bak-\d{14}")
        self.assertEqual(self.read(os.path.join(self.p(".claude"), name)), b"original\n")

    def test_new_file_has_no_backup(self):
        self.asb("--agent", "claude")
        self.assertEqual(self.backups(self.p(".claude")), [])


class Refusals(Base):
    def setUp(self):
        super().setUp()
        self.f = self.p(".claude", "CLAUDE.md")

    def test_marker_corruption(self):
        good = "<!-- asb:agent-setup begin v1 -->\nx\n<!-- asb:agent-setup end -->\n"
        cases = {
            "begin without end": "top\n<!-- asb:agent-setup begin v1 -->\nx\n",
            "end without begin": "top\n<!-- asb:agent-setup end -->\n",
            "end before begin": "<!-- asb:agent-setup end -->\n<!-- asb:agent-setup begin v1 -->\n",
            "duplicated": good + "mid\n" + good,
            "malformed": "<!-- asb:agent-setup begin -->\nx\n<!-- asb:agent-setup end -->\n",
        }
        for name, content in cases.items():
            for extra in ([], ["--remove"]):
                with self.subTest(case=name, extra=extra):
                    self.write(self.f, content)
                    r = self.asb("--agent", "claude", *extra)
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertIn("REFUSED", r.stderr)
                    self.assertIn("marker", r.stderr)
                    self.assertEqual(self.read(self.f, "r"), content)
                    self.assertEqual(self.backups(self.p(".claude")), [])

    def test_corruption_in_one_file_writes_none(self):
        self.write(self.p(".codex", "AGENTS.md"), "<!-- asb:agent-setup begin v1 -->\n")
        r = self.asb("--agent", "all")
        self.assertEqual(r.returncode, 2)
        self.assertIn("nothing was written", r.stderr)
        self.assertFalse(os.path.exists(self.f))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root bypasses file permissions")
    def test_read_only_file(self):
        self.write(self.f, "ro\n")
        os.chmod(self.f, 0o444)
        for extra in ([], ["--remove"]):
            r = self.asb("--agent", "claude", *extra)
            if extra:
                self.assertEqual(r.returncode, 0)  # nothing to remove: no write needed
            else:
                self.assertEqual(r.returncode, 2)
                self.assertIn("read-only", r.stderr)
        self.assertEqual(self.read(self.f), b"ro\n")
        self.assertEqual(self.backups(self.p(".claude")), [])

    def test_read_only_file_with_block_remove_refused(self):
        self.write(self.f, "a\n")
        self.asb("--agent", "claude")
        os.chmod(self.f, 0o444)
        r = self.asb("--agent", "claude", "--remove")
        self.assertEqual(r.returncode, 2)
        self.assertIn(END, self.read(self.f, "r"))

    def test_unwritable_directory_for_new_file(self):
        if os.geteuid() == 0:
            self.skipTest("root")
        os.makedirs(self.p(".claude"))
        os.chmod(self.p(".claude"), 0o555)
        self.addCleanup(os.chmod, self.p(".claude"), 0o755)
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 2)

    def test_path_is_directory(self):
        os.makedirs(self.f)
        r = self.asb("--agent", "claude")
        self.assertEqual(r.returncode, 2)

    def test_usage_errors(self):
        for args in (["--agent", "gemini"], ["--scope", "global"], ["--bogus"], ["--agent"]):
            with self.subTest(args=args):
                self.assertEqual(self.asb(*args).returncode, 2)
        self.assertEqual(os.listdir(self.home), [])


class DryRunAndRemove(Base):
    def setUp(self):
        super().setUp()
        self.f = self.p(".claude", "CLAUDE.md")

    def test_dry_run_new_file_writes_nothing(self):
        r = self.asb("--agent", "claude", "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("+<!-- asb:agent-setup begin v1 -->", r.stdout)
        self.assertIn("/dev/null", r.stdout)
        self.assertEqual(os.listdir(self.home), [])

    def test_dry_run_existing_file_diff_and_no_backup(self):
        self.write(self.f, "keep\n")
        r = self.asb("--agent", "claude", "--dry-run")
        self.assertIn(" keep", r.stdout)
        self.assertIn("+<!-- asb:agent-setup end -->", r.stdout)
        self.assertEqual(self.read(self.f), b"keep\n")
        self.assertEqual(self.backups(self.p(".claude")), [])

    def test_dry_run_unchanged_prints_no_diff(self):
        self.asb("--agent", "claude")
        r = self.asb("--agent", "claude", "--dry-run")
        self.assertIn("unchanged", r.stdout)
        self.assertNotIn("@@", r.stdout)

    def test_dry_run_remove(self):
        self.asb("--agent", "claude")
        before = self.read(self.f)
        r = self.asb("--agent", "claude", "--remove", "--dry-run")
        self.assertIn("-<!-- asb:agent-setup begin v1 -->", r.stdout)
        self.assertEqual(self.read(self.f), before)

    def test_dry_run_autodetect_creates_nothing(self):
        os.makedirs(self.p(".codex"))
        self.asb("--dry-run")
        self.assertEqual(os.listdir(self.p(".codex")), [])

    def test_remove_restores_original_text(self):
        for original in ("# Mine\n\nbody\n", "no newline", "", "# a\n\n\n"):
            with self.subTest(original=original):
                self.write(self.f, original)
                self.asb("--agent", "claude")
                r = self.asb("--agent", "claude", "--remove")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("removed", r.stdout)
                got = self.read(self.f, "r")
                # install adds a newline to a file lacking one; everything else is exact
                self.assertEqual(got, original if original.endswith("\n") or not original
                                 else original + "\n")

    def test_remove_keeps_text_after_block(self):
        self.write(self.f, "a\n<!-- asb:agent-setup begin v1 -->\nx\n<!-- asb:agent-setup end -->\nb\n")
        self.asb("--agent", "claude", "--remove")
        self.assertEqual(self.read(self.f, "r"), "a\nb\n")

    def test_remove_when_absent(self):
        self.write(self.f, "plain\n")
        r = self.asb("--agent", "claude", "--remove")
        self.assertEqual(r.returncode, 0)
        self.assertIn("absent", r.stdout)
        self.assertEqual(self.read(self.f), b"plain\n")
        self.assertEqual(self.backups(self.p(".claude")), [])

    def test_remove_missing_file_creates_nothing(self):
        r = self.asb("--agent", "all", "--remove")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(os.listdir(self.home), [])


class Misc(Base):
    def test_help_and_guide_mention_it(self):
        env = {"HOME": self.home, "PATH": self.bin}
        for argv in (["help", "agent-setup"], ["agent-setup", "--help"]):
            r = subprocess.run([sys.executable, CLI, *argv], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("--dry-run", r.stdout)
        g = subprocess.run([sys.executable, CLI, "guide"], env=env, capture_output=True, text=True)
        self.assertIn("asb agent-setup", g.stdout)

    def test_needs_no_broker_config_and_never_reads_client_json(self):
        cfg = self.p(".config", "secret-broker", "client.json")
        self.write(cfg, '{"url": "http://x", "key": "SENTINEL-KEY-123456"}')
        r = self.asb("--agent", "all")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("SENTINEL", r.stdout + r.stderr)
        for rel in ((".claude", "CLAUDE.md"), (".codex", "AGENTS.md")):
            self.assertNotIn("SENTINEL", self.read(self.p(*rel), "r"))


if __name__ == "__main__":
    unittest.main()
