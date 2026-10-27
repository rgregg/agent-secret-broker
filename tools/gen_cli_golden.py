#!/usr/bin/env python3
"""Record what the PYTHON client computes, as golden vectors the Rust CLI's tests must reproduce.

    python tools/gen_cli_golden.py            # rewrite tests/fixtures/cli/*.json
    python tools/gen_cli_golden.py --check    # exit 1 if they are out of date

The Rust port is held to the original's exact output on a deterministic corpus (a fixed seed, plus the edge cases
that matter), so "ported" means "reproduces Python", not "looks right". While both clients exist client/asb is the
source of truth; the files are committed so the Rust tests need no Python.
"""
import difflib
import json
import os
import random
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


def generate():
    return {"difflib.json": json.dumps(difflib_cases(), indent=1, ensure_ascii=True) + "\n"}


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
