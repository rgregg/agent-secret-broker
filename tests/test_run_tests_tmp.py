"""The test runner must not leave the temp directories of the tests it ran behind.

Every test that builds a harness makes a directory with `tempfile.mkdtemp()` and nothing removes it, so a full run
used to leave about 3,300 of them in the temp dir (200,000 after a few weeks, enough to fill a disk). The runner now
gives its test processes a private temp dir and deletes it when it exits.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = "test_ui_auto_rules.Persistence"      # a small class whose tests build a harness (and so a temp dir)


def run(cmd, base, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, env=dict(os.environ, TMPDIR=base), stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=300)


class Leak(unittest.TestCase):
    def test_tests_do_leave_temp_dirs_when_run_directly(self):
        """The premise: without the runner's private dir the probe tests really do leak (so the next test can fail)."""
        with tempfile.TemporaryDirectory() as base:
            p = run([sys.executable, "-m", "unittest", "-q", PROBE], base, cwd=HERE)
            self.assertEqual(p.returncode, 0, p.stdout[-400:])
            self.assertGreater(len(os.listdir(base)), 0)

    def test_the_runner_leaves_nothing_behind(self):
        with tempfile.TemporaryDirectory() as base:
            p = run([sys.executable, os.path.join(HERE, "run_tests.py"), "-j", "2", "-k", PROBE], base)
            self.assertEqual(p.returncode, 0, p.stdout[-400:])
            self.assertRegex(p.stdout, r"\b[1-9]\d* tests, 0 failing")                          # the premise: tests ran
            self.assertEqual(os.listdir(base), [])

    def test_the_runner_cleans_up_when_it_is_terminated(self):
        with tempfile.TemporaryDirectory() as base:
            proc = subprocess.Popen([sys.executable, os.path.join(HERE, "run_tests.py"), "-j", "2"], cwd=ROOT,
                                    env=dict(os.environ, TMPDIR=base), stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            end = time.time() + 60
            while time.time() < end and not any(n.startswith("tmp") for n in os.listdir(base)):
                time.sleep(0.2)
            self.assertTrue(os.listdir(base), "the runner did not start")                         # premise: it was running
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=60)
            end = time.time() + 30
            while time.time() < end and os.listdir(base):
                time.sleep(0.2)
            self.assertEqual(os.listdir(base), [])


if __name__ == "__main__":
    unittest.main()
