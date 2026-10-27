#!/usr/bin/env python3
"""Run the existing test-suite against the Rust `asb` instead of client/asb.

    python tools/run_tests_against_rust_cli.py [-k SUBSTRING] [--release] [--list]

About 18 test files run the CLI as a subprocess (`python -I client/asb ARGS`). In a throwaway copy of the repo this
replaces client/asb with a shim that executes the Rust binary, so those tests run UNMODIFIED against it and every
failure is a real difference in behaviour, down to the exact message. The shim only executes when run as a script, so
the few tests that import client/asb as a module (they exercise Python internals, such as the script analyser) fail
at the attribute they look up: they need golden vectors instead, see docs/proposals/rust-cli.md.

It prints the tests that fail and compares them with tests/rust_cli_known_gaps.txt, the tests that are expected to
fail until their command is ported. It exits non-zero on a failure that is NOT in that list, and on a listed test that
now passes (so the list can only shrink). `--list` prints the failing tests without comparing.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GAPS = os.path.join(ROOT, "tests", "rust_cli_known_gaps.txt")
SHIM = '''#!/usr/bin/env python3
import os, sys
RUST = {rust!r}
if __name__ == "__main__":
    os.execv(RUST, [RUST] + sys.argv[1:])
'''


def build(release):
    cmd = ["cargo", "build", "--locked", "-p", "asb-cli"] + (["--release"] if release else [])
    subprocess.run(cmd, cwd=ROOT, check=True)
    return os.path.join(ROOT, "target", "release" if release else "debug", "asb")


def main():
    args = sys.argv[1:]
    release, list_only = "--release" in args, "--list" in args
    k = args[args.index("-k") + 1] if "-k" in args else None
    rust = build(release)
    tmp = tempfile.mkdtemp(prefix="asb-rust-cli-")
    try:
        tree = os.path.join(tmp, "repo")
        shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(".git", "target", "__pycache__", "*.pyc", ".superpowers"))
        with open(os.path.join(tree, "client", "asb"), "w") as f:
            f.write(SHIM.format(rust=rust))
        cmd = [sys.executable, os.path.join("tests", "run_tests.py"), "-j8"] + (["-k", k] if k else [])
        r = subprocess.run(cmd, cwd=tree, capture_output=True, text=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out = r.stdout + r.stderr
    failing = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\S+) \(([\w.]+)\)", out, re.M)))
    names = sorted({f"{mod_test}" for _, mod_test in failing})
    summary = [l for l in out.splitlines() if re.search(r"\d+ tests, \d+ failing", l)]
    print(summary[-1] if summary else "(no summary line: the run did not finish)")
    if list_only:
        print("\n".join(names))
        return 0
    known = set()
    if os.path.exists(GAPS):
        known = {l.strip() for l in open(GAPS) if l.strip() and not l.startswith("#")}
    new, fixed = sorted(set(names) - known), sorted(known - set(names)) if not k else []
    if new:
        print(f"\n{len(new)} failing test(s) NOT in tests/rust_cli_known_gaps.txt:")
        print("\n".join("  " + n for n in new))
    if fixed:
        print(f"\n{len(fixed)} listed test(s) now pass: remove them from tests/rust_cli_known_gaps.txt:")
        print("\n".join("  " + n for n in fixed))
    if not new and not fixed:
        print(f"as expected: {len(names)} known gap(s), nothing new")
    return 1 if (new or fixed) else 0


if __name__ == "__main__":
    sys.exit(main())
