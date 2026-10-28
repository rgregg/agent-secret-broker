#!/usr/bin/env python3
"""Record what the PYTHON client computes, as golden vectors the Rust CLI's tests must reproduce.

    python tools/gen_cli_golden.py            # rewrite tests/fixtures/cli/*.json
    python tools/gen_cli_golden.py --check    # exit 1 if they are out of date

The Rust port is held to the original's exact output on a deterministic corpus (a fixed seed, plus the edge cases
that matter), so "ported" means "reproduces Python", not "looks right". While both clients exist client/asb is the
source of truth; the files are committed so the Rust tests need no Python.
"""
import difflib
import importlib.machinery
import importlib.util
import json
import os
import random
import shlex
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "fixtures", "cli")


def unified(a, b, fromf, tof):
    return list(difflib.unified_diff(a.splitlines(), b.splitlines(), fromf, tof, lineterm=""))


def difflib_cases():
    rng = random.Random(20261027)
    words = ["alpha", "beta", "gamma", "", "delta", "## Credentials (asb)", "- item", "x", "same", "same"]

    def doc(n):
        return "\n".join(rng.choice(words) + (str(rng.randrange(5)) if rng.random() < 0.3 else "") for _ in range(n))

    cases = [("", "hello\nworld"), ("hello\nworld", ""), ("a\nb\nc", "a\nb\nc"), ("a\nb\nc\n", "a\nb\nc"),
             ("a\r\nb\r\n", "a\nb\n"), ("one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten",
                                      "one\ntwo\nTHREE\nfour\nfive\nsix\nseven\neight\nnine\nTEN"),
             ("x\ny\nz", "x\ninserted\ny\nz\nextra"), ("a\x0bb\x0cc d\x85e", "a\nb\nc\nd\ne")]
    for n in (3, 8, 15, 40, 120):
        a = doc(n)
        lines = a.split("\n")
        b = list(lines)
        for _ in range(max(1, n // 6)):          # a few edits
            op, k = rng.choice("rid"), rng.randrange(len(b)) if b else 0
            if op == "r" and b:
                b[k] = b[k] + " changed"
            elif op == "i":
                b.insert(k, "new line " + str(rng.randrange(99)))
            elif b:
                del b[k]
        cases.append((a, "\n".join(b)))
    # 250 lines with many repeats: exercises the "popular element" heuristic that kicks in at 200 lines
    big = "\n".join(rng.choice(["common", "common", "common", "rare" + str(i)]) for i in range(250))
    cases.append((big, big.replace("rare7", "edited7").replace("rare100", "gone")))
    cases.append((big, "\n".join(reversed(big.split("\n")))))
    out = []
    for a, b in cases:
        out.append({"a": a, "b": b, "from": "a/CLAUDE.md", "to": "b/CLAUDE.md", "diff": unified(a, b, "a/CLAUDE.md", "b/CLAUDE.md")})
        out.append({"a": a, "b": b, "from": "/dev/null", "to": "b/x.md", "diff": unified(a, b, "/dev/null", "b/x.md")})
    return out


def _python_client():
    loader = importlib.machinery.SourceFileLoader("asb_py", os.path.join(ROOT, "client", "asb"))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_py", loader))
    loader.exec_module(mod)
    return mod


def ssh_claim_cases():
    """argv -> the `user@host:port` the Python client says it will connect to (null when it cannot tell)."""
    asb = _python_client()
    table = os.path.join(ROOT, "tests", "test_ssh_host.py")
    src = open(table, encoding="utf-8").read()
    start = src.index("    TABLE = [")
    end = src.index("    ]\n", start)
    # the hand-written table of the Python tests, parsed from its source so the two cannot drift
    pairs = eval("[" + src[start + len("    TABLE = ["):end] + "]")      # noqa: S307 (our own test file)
    argvs = [shlex.split(cmd) for cmd, _ in pairs]
    rng = random.Random(20261028)
    progs = ["ssh", "scp", "sftp", "rsync", "git", "curl", "/usr/bin/ssh", "ssh/"]
    pool = ["-p", "2222", "-l", "bob", "-J", "j1,j2", "u@jump:2222", "-o", "Port=7", "HostName=real.example",
            "User=zed", "ProxyJump=a,b,c", "Port 99", "-P", "-e", "ssh -p 99", "ssh -l z", "u@h", "h", "u@h:/x",
            "h:y", "[::1]", "u@[::1]:x", "u@::1", "ssh://u@h:2200/", "scp://h/x", "sftp://u@h:99/x",
            "rsync://h/m", "h::m", "git@github.com:o/r", "git@h:o/r.git", "--rsh=ssh -l z", "--rsh", "-av", "-ae",
            "--", "-N", "-4", "-6", "-vvv", "-i", "key", "-q", "bad host", "h\n", "host\u202e", "a@b", "-oPort=1",
            "-p22", "-lroot", "x:/y", "/abs:x", "./rel:x", "~/h:x", "@h:x", "u@", "h:", ":x", "-", "'", "\"",
            "ssh 'unterminated", "-e", "ssh -J a@b -p 1", "h:22", "0", "65535", "65536", "+22", " 22 ", "2_2",
            "u@h:2200", "[h]:22", "u\tv@h", "", "é@h", "ünï.example"]
    for _ in range(1500):
        argvs.append([rng.choice(progs)] + [rng.choice(pool) for _ in range(rng.randrange(0, 7))])
    users, hosts = ["", "bob@", "u@", "git@", "a.b@"], ["h", "host.example", "10.0.0.5", "[::1]", "::1", "h_1", "-h", "a b"]
    opts = {"ssh": [["-p", "2222"], ["-p22"], ["-l", "bob"], ["-J", "j1,j2"], ["-o", "Port=7"], ["-oUser=zed"],
                    ["-o", "HostName=real"], ["-i", "k"], ["-N"], ["-vvv"], ["-6"], ["-p", "x"], ["-o", "ProxyJump=j"]],
            "scp": [["-P", "2222"], ["-r"], ["-o", "Port=7"], ["-i", "k"], ["-l", "5"], ["-J", "j"]],
            "sftp": [["-P", "2222"], ["-o", "Port=7"], ["-i", "k"], ["-J", "j"]],
            "rsync": [["-av"], ["-e", "ssh -p 2222"], ["-ae", "ssh"], ["--rsh=ssh -l bob"], ["-e", "ssh -J j -p 1"]],
            "git": [["clone"], ["push"], ["remote", "add", "o"], ["-C", "d"]]}
    for _ in range(1200):
        prog = rng.choice(list(opts))
        argv = [prog]
        for _ in range(rng.randrange(0, 3)):
            argv += rng.choice(opts[prog])
        target = rng.choice(users) + rng.choice(hosts)
        if prog == "ssh":
            argv += [target] + rng.choice([[], ["ls", "-l"], ["--", "ls"]])
        elif prog == "git":
            argv += [rng.choice(["git@h:o/r.git", "ssh://git@h:2222/o/r", "u@h:o/r", "https://h/o/r", target + ":o/r"])]
        else:
            argv += rng.choice([[target + ":/x", "."], ["a.txt", target + ":/tmp"], [target], [target + ":y", "z:q"],
                                ["scp://" + target + "/x", "."], ["a", "b"]])
        argvs.append(argv)
    argvs += [[], [""], ["ssh", ""], ["ssh", "-p"], ["rsync", "-e"], ["git", ""], ["scp", "-P"], ["ssh"] + ["-o"] * 5]
    return [{"argv": a, "claim": asb.claimed_destination(a)} for a in argvs]


def generate():
    return {"difflib.json": json.dumps(difflib_cases(), indent=1, ensure_ascii=True) + "\n",
            "ssh_claim.json": json.dumps(ssh_claim_cases(), indent=0, ensure_ascii=True) + "\n"}


def main():
    files, check, stale = generate(), "--check" in sys.argv[1:], []
    for name, content in files.items():
        path = os.path.join(OUT, name)
        try:
            same = open(path, encoding="utf-8").read() == content
        except OSError:
            same = False
        if not same:
            stale.append(name)
            if not check:
                os.makedirs(OUT, exist_ok=True)
                open(path, "w", encoding="utf-8").write(content)
    if check and stale:
        print("out of date (run tools/gen_cli_golden.py): " + ", ".join(stale))
        sys.exit(1)
    print(("checked" if check else "wrote") + f" {len(files)} file(s)")


if __name__ == "__main__":
    main()
