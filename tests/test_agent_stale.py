"""The stale agent-instructions notice: `asb` tells the human, once a day on stderr, when an instruction file holds a
block that an older asb wrote, and `asb version` always shows the state.

Everything runs the CLI as a subprocess (so tools/run_tests_against_rust_cli.py runs it against the Rust binary too)
with a temporary HOME, project directory and state directory. The broker is a stub (it only has to answer a call: the
notice is local and nothing about it goes to the broker).
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from test_client_update_notice_cli import Stub, LIST_STDOUT, STUB_KEY  # noqa: E402

CLI = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
TAIL = "Ask the human to run `asb agent-setup`; agents: do not edit your own instruction files."
BEGIN, END = "<!-- asb:agent-setup begin v%d -->", "<!-- asb:agent-setup end -->"


def block(version, eol="\n"):
    return eol.join([BEGIN % version, "## Credentials (asb)", "Use asb.", END]) + eol


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="asb-stale-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = os.path.join(self.tmp, "home")
        self.proj = os.path.join(self.tmp, "proj")
        self.state = os.path.join(self.tmp, "state")
        for d in (self.home, self.proj):
            os.makedirs(d)
        self.stub = Stub({})
        self.addCleanup(self.stub.close)
        self.current = self.current_version()
        self.old = self.current - 1

    def env(self, **over):
        env = {"HOME": self.home, "PATH": os.path.join(self.tmp, "nobin"), "LANG": "C.UTF-8",
               "XDG_STATE_HOME": self.state, "SECRET_BROKER_URL": self.stub.url, "SECRET_BROKER_KEY": STUB_KEY}
        env.update(over)
        return {k: v for k, v in env.items() if v is not None}

    def asb(self, *args, cwd=None, **over):
        return subprocess.run([sys.executable, "-I", CLI, *args], env=self.env(**over), cwd=cwd or self.proj,
                              capture_output=True, text=True, timeout=30)

    def current_version(self):
        scratch = tempfile.mkdtemp(prefix="asb-cur-")
        self.addCleanup(shutil.rmtree, scratch, True)
        r = subprocess.run([sys.executable, "-I", CLI, "agent-setup", "--agent", "claude"], cwd=scratch,
                           env={"HOME": scratch, "PATH": scratch}, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(scratch, ".claude", "CLAUDE.md")) as f:
            m = re.search(r"begin v(\d+) -->", f.read())
        self.assertIsNotNone(m)
        return int(m.group(1))

    def put(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return path

    @property
    def claude(self):
        return os.path.join(self.home, ".claude", "CLAUDE.md")

    @property
    def agent_state(self):
        return os.path.join(self.state, "asb", "agent-notice")

    def notice(self, p):
        return [ln for ln in p.stderr.splitlines() if "agent instructions are out of date" in ln]

    def listed(self, **over):
        p = self.asb("list", **over)
        self.assertEqual((p.returncode, p.stdout), (0, LIST_STDOUT), p.stderr)   # stdout and exit code never change
        return p


class Decision(Base):
    def test_an_older_block_is_named_once_with_the_fixed_words(self):
        self.put(self.claude, "# mine\n\n" + block(self.old))
        p = self.listed()
        self.assertEqual(self.notice(p), [f"asb: your agent instructions are out of date ({self.claude} has v{self.old}, "
                                          f"this asb writes v{self.current}). {TAIL}"], p.stderr)
        self.assertNotIn("Use asb.", p.stderr)                                    # no file content is echoed

    def test_the_current_version_is_silent(self):
        self.put(self.claude, block(self.old))
        self.assertEqual(len(self.notice(self.listed())), 1)                      # control: the same file, older, is named
        os.remove(self.agent_state)
        self.put(self.claude, block(self.current))
        self.assertEqual(self.notice(self.listed()), [])

    def test_a_newer_block_than_this_asb_is_not_stale(self):
        self.put(self.claude, block(self.current + 1))
        self.assertEqual(self.notice(self.listed()), [])
        self.assertIn("agent instructions: up to date", self.asb("version").stdout)

    def test_no_file_and_no_block_say_nothing(self):
        self.assertEqual(self.notice(self.listed()), [])
        self.put(self.claude, "# notes with no asb block\n")
        self.assertEqual(self.notice(self.listed()), [])
        self.assertIn("agent instructions: not installed", self.asb("version").stdout)

    def test_a_damaged_block_says_nothing(self):
        damaged = {"begin only": BEGIN % self.old + "\nbody\n",
                   "end only": "body\n" + END + "\n",
                   "twice": block(self.old) + block(self.old),
                   "malformed marker": "<!-- asb:agent-setup begin vX -->\nbody\n" + END + "\n",
                   "end first": END + "\n" + BEGIN % self.old + "\n"}
        for what, text in damaged.items():
            self.put(self.claude, text)
            self.assertEqual(self.notice(self.listed()), [], what)
            self.assertIn("agent instructions: not installed", self.asb("version").stdout, what)
        self.put(self.claude, block(self.old))                                    # control: repaired, it is named
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_an_unreadable_file_or_directory_or_binary_says_nothing(self):
        self.put(self.claude, block(self.old))
        os.chmod(self.claude, 0)
        if os.access(self.claude, os.R_OK):
            self.skipTest("running as root: permissions do not apply")
        self.assertEqual(self.notice(self.listed()), [])
        os.chmod(self.claude, 0o644)
        self.assertEqual(len(self.notice(self.listed())), 1)                      # control: readable again, named
        os.remove(self.agent_state)
        os.remove(self.claude)
        os.mkdir(self.claude)                                                     # not a regular file
        self.assertEqual(self.notice(self.listed()), [])
        os.rmdir(self.claude)
        self.put(self.claude, b"\xff\xfe" + block(self.old).encode())             # not UTF-8
        self.assertEqual(self.notice(self.listed()), [])

    def test_a_huge_file_is_not_read(self):
        self.put(self.claude, block(self.old) + "x" * 400_000)
        self.assertEqual(self.notice(self.listed()), [])
        self.put(self.claude, block(self.old) + "x" * 1000)                       # control: a small one is
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_crlf_files_are_read(self):
        self.put(self.claude, "# mine\r\n\r\n" + block(self.old, "\r\n"))
        self.assertEqual(len(self.notice(self.listed())), 1)
        self.assertIn(f"{self.claude} (v{self.old}, current v{self.current})", self.asb("version").stdout)

    def test_a_user_file_symlinked_to_a_dotfiles_repo_is_followed(self):
        target = self.put(os.path.join(self.tmp, "home", "dotfiles", "CLAUDE.md"), block(self.old))
        os.makedirs(os.path.dirname(self.claude))
        os.symlink(target, self.claude)
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_a_project_file_may_not_lead_outside_the_project(self):
        outside = self.put(os.path.join(self.tmp, "elsewhere", "CLAUDE.md"), block(self.old))
        os.symlink(outside, os.path.join(self.proj, "CLAUDE.md"))
        self.assertEqual(self.notice(self.listed()), [])
        self.assertIn("agent instructions: not installed", self.asb("version").stdout)
        os.remove(os.path.join(self.proj, "CLAUDE.md"))                           # control: inside the project is read
        self.put(os.path.join(self.proj, "CLAUDE.md"), block(self.old))
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_codex_and_copilot_homes_and_the_project_files_are_all_read(self):
        codex = self.put(os.path.join(self.tmp, "cx", "AGENTS.md"), block(self.old))
        copilot = self.put(os.path.join(self.tmp, "cp", "copilot-instructions.md"), block(self.old))
        proj = self.put(os.path.join(self.proj, ".github", "copilot-instructions.md"), block(self.old))
        self.put(os.path.join(self.home, ".codex", "AGENTS.md"), block(self.old))   # the override replaces this one
        out = self.asb("version", CODEX_HOME=os.path.dirname(codex), COPILOT_HOME=os.path.dirname(copilot)).stdout
        for path in (codex, copilot, proj):
            self.assertIn(path, out)
        self.assertNotIn(os.path.join(self.home, ".codex"), out)

    def test_at_most_three_files_are_named_then_a_count(self):
        paths = [self.put(self.claude, block(self.old)),
                 self.put(os.path.join(self.home, ".codex", "AGENTS.md"), block(self.old)),
                 self.put(os.path.join(self.home, ".copilot", "copilot-instructions.md"), block(self.old)),
                 self.put(os.path.join(self.proj, "CLAUDE.md"), block(self.old)),
                 self.put(os.path.join(self.proj, "AGENTS.md"), block(self.old))]
        (line,) = self.notice(self.listed())
        for path in paths[:3]:
            self.assertIn(f"{path} has v{self.old}", line)
        for path in paths[3:]:
            self.assertNotIn(path, line)
        self.assertIn(f", and 2 more, this asb writes v{self.current})", line)

    def test_home_as_the_project_is_not_counted_twice(self):
        self.put(self.claude, block(self.old))
        p = self.asb("version", cwd=self.home)                                    # cwd == HOME: user and project are one file
        self.assertEqual(p.stdout.count(self.claude), 1, p.stdout)

    def test_a_hostile_path_is_printed_with_controls_escaped(self):
        evil = os.path.join(self.tmp, "p\x1b[31mred\x07")
        os.makedirs(evil)
        self.put(os.path.join(evil, "CLAUDE.md"), block(self.old))
        p = self.asb("list", cwd=evil)
        self.assertEqual(p.returncode, 0, p.stderr)
        (line,) = self.notice(p)
        self.assertIn("p\\x1b[31mred\\x07", line)
        self.assertNotIn("\x1b", p.stderr)
        self.assertNotIn("\x07", p.stderr)
        v = self.asb("version", cwd=evil).stdout
        self.assertIn("p\\x1b[31mred\\x07", v)
        self.assertNotIn("\x1b", v)


class Limits(Base):
    def test_once_a_day_and_again_after_a_day(self):
        self.put(self.claude, block(self.old))
        self.assertEqual(len(self.notice(self.listed())), 1)
        self.assertTrue(os.path.isfile(self.agent_state))                         # premise: it was recorded
        self.assertEqual(self.notice(self.listed()), [])
        with open(self.agent_state, "w") as f:
            f.write(str(int(time.time()) - 2 * 86400) + "\n")
        self.assertEqual(len(self.notice(self.listed())), 1)
        with open(self.agent_state, "w") as f:
            f.write("garbage\n")
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_nothing_stale_does_not_use_up_the_day(self):
        self.assertEqual(self.notice(self.listed()), [])
        self.assertFalse(os.path.exists(self.agent_state))
        self.put(self.claude, block(self.old))
        self.assertEqual(len(self.notice(self.listed())), 1)

    def test_it_has_its_own_record_beside_the_update_notice(self):
        self.put(os.path.join(self.state, "asb", "update-notice"), "%d\n" % int(time.time()))
        self.put(self.claude, block(self.old))
        self.assertEqual(len(self.notice(self.listed())), 1)                      # a recent update notice does not hide it

    def test_an_unwritable_record_means_no_notice(self):
        self.put(self.claude, block(self.old))
        self.put(self.state, "a file, so the state directory cannot be made")
        self.assertEqual(self.notice(self.listed()), [])
        os.remove(self.state)
        self.assertEqual(len(self.notice(self.listed())), 1)                      # control

    def test_the_opt_out_is_any_value_but_empty_or_zero(self):
        self.put(self.claude, block(self.old))
        for v, shown in (("1", False), ("yes", False), ("", True), ("0", True)):
            if os.path.exists(self.agent_state):
                os.remove(self.agent_state)
            self.assertEqual(len(self.notice(self.listed(ASB_NO_UPDATE_CHECK=v))), int(shown), v)
        os.remove(self.agent_state)
        self.listed(ASB_NO_UPDATE_CHECK="1")
        self.assertFalse(os.path.exists(self.agent_state))                        # switched off: nothing recorded


class Surfaces(Base):
    def test_version_always_shows_the_state_and_ignores_the_opt_out_and_the_record(self):
        self.assertIn("agent instructions: not installed", self.asb("version").stdout)
        self.put(self.claude, block(self.old))
        want = f"agent instructions: out of date: {self.claude} (v{self.old}, current v{self.current}): run asb agent-setup"
        for _ in range(2):
            p = self.asb("version", ASB_NO_UPDATE_CHECK="1")
            self.assertIn(want, p.stdout.splitlines(), p.stdout)
            self.assertEqual(self.notice(p), [])                                  # it shows the state; no stderr notice
        self.put(self.claude, block(self.current))
        self.assertIn("agent instructions: up to date", self.asb("version").stdout.splitlines())
        self.assertFalse(os.path.exists(self.agent_state))                        # version never touches the daily record

    def test_nothing_is_ever_written_to_an_instruction_file(self):
        files = {self.claude: block(self.old), os.path.join(self.proj, "AGENTS.md"): block(self.old)}
        for path, text in files.items():
            self.put(path, text)
            os.utime(path, (1_000_000, 1_000_000))
        before = {path: (os.stat(path).st_mtime_ns, os.stat(path).st_size) for path in files}
        self.assertEqual(len(self.notice(self.listed())), 1)                      # premise: the notice ran
        self.asb("version")
        for path, text in files.items():
            with open(path) as f:
                self.assertEqual(f.read(), text)
            self.assertEqual((os.stat(path).st_mtime_ns, os.stat(path).st_size), before[path])
        self.assertEqual(sorted(os.listdir(os.path.join(self.home, ".claude"))), ["CLAUDE.md"])   # no backup or temp file
        self.assertEqual(sorted(os.listdir(self.proj)), ["AGENTS.md"])

    def test_agent_setup_refreshes_the_file_without_the_notice(self):
        self.put(self.claude, block(self.old))
        p = self.asb("agent-setup", "--agent", "claude")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"updated (v{self.old} -> v{self.current})", p.stdout)       # premise: it was stale
        self.assertEqual(self.notice(p), [])
        self.assertNotIn("out of date", p.stdout + p.stderr)
        self.assertFalse(os.path.exists(self.agent_state))
        self.assertEqual(self.notice(self.listed()), [])                          # and now there is nothing to say

    def test_status_does_not_print_it(self):
        self.put(self.claude, block(self.old))
        self.assertEqual(self.notice(self.asb("status")), [])
        self.assertEqual(len(self.notice(self.listed())), 1)                      # control: another command does

    def test_help_and_guide_describe_it(self):
        self.assertIn("Stale agent instructions", self.asb("guide").stdout)
        self.assertIn("agent instructions:", self.asb("help", "version").stdout)


if __name__ == "__main__":
    unittest.main()
