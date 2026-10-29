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


def analyse_cases():
    """argv -> what the Python script analyser (`_analyze`) says: the scripts, whether it is understood, and the command
    left after unwrapping. The corpus is the broker's own detection table plus structured fuzzing around every
    program, wrapper and interpreter the analyser knows."""
    asb = _python_client()
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    sys.path.insert(0, ROOT)
    import test_scripts                                                 # for its table of known commands
    argvs = [list(a) for a, _, _ in test_scripts.DETECT_TABLE] + [list(test_scripts.NEST5)]
    rng = random.Random(20261029)
    plains = sorted(asb.PLAIN_PROGRAMS)
    wrappers = sorted(asb.SCRIPT_WRAPPERS) + ["env", "env", "xargs", "su", "busybox"]
    interps = ["sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh", "fish", "python", "python3", "python3.11",
               "node", "nodejs", "ruby", "perl", "php", "pwsh", "powershell", "lua", "luajit", "Rscript", "deno",
               "bun", "awk", "gawk", "mawk", "sed", "cat"]
    prefixes = ["", "", "", "/usr/bin/", "/bin/", "/usr/sbin/", "/opt/x/", "./", "../", "~/", "/usr/local/bin/",
                "//bin/", "/usr/bin/../bin/", "/usr/bin/*"]
    flags = ["-n", "-c", "-e", "-E", "-r", "-m", "-", "--", "-i", "-u", "-o", "-s", "-l", "-la", "-vvv", "--version",
             "--help", "--rcfile", "--init-file", "-I", "-M", "-d", "-f", "--file", "--expression", "--source", "-x",
             "-h", "-p", "-H", "-X", "-W", "-A5", "-n5", "-5", "-n", "--max-time", "--max-time=5", "--silent",
             "--header", "--request=GET", "-XGET", "-XPOST", "+%Y", "+x", "--non-interactive", "--user", "--user=bob",
             "--adj", "--adjustment=5", "--ignore-environment", "--null", "--unset", "--unset=X", "--sig",
             "--signal", "-k", "-kill", "-k5", "-s9", "-nH", "-Hn", "-ii", "-i0", "--preserve-status", "-o0",
             "-B", "--import", "--require=x", "--input-type=module", "-lm", "-Mstrict", "-Ilib", "-rfoo", "-ce",
             "-cs", "-se", "-ec", "-sc", "-C", "-z", "-Command", "-encodedcommand", "-File", "-EncodedCommand",
             "--eval", "--print", "-pe", "-ne", "-lane"]
    operands = ["foo.sh", "script.py", "x.js", "run.rb", "a.pl", "b.php", "c.ps1", "d.lua", "e.R", "/tmp/x.sh",
                "./run", "../up.sh", "~/bin/x", "dir/script", "/usr/bin/python3", "x", "5", "10", "1.5", "GET",
                "POST", "X: y", "a@b", "http://h/x", "https://h:8/p", "http://u@h/x", "example.com", "8.8.8.8",
                "A", "pid", "a b", "", "\0".replace("\\0", "\x00"), "line\nbreak", "-5", "+5", "k", ".", "..",
                "1,2", "1n", ".x", "f.txt", "-", "LANG=C", "FOO=1", "TZ=UTC", "LC_ALL=C", "A=b/c", "A=$x", "A=b c",
                "A=", "=x", "1A=x", "env", "sh", "bash", "python3", "echo", "ls"]
    shells = ["echo hi", "ls -l | grep x", "cat f && rm g", "env LANG=C cat f", "sh -c 'echo hi'", "a;b",
              "echo $HOME", "echo `x`", "cat <<EOF", "x > y", "cat f 2>&1", "(ls)", "{ ls; }", "if true; then ls; fi",
              "ls &", "ls & ls", "a || b", "a ;; b", "python3 s.py", "bash x.sh && echo ok", "'unterminated",
              "\"q\" 'r'", "ls ''", "echo \"a b\"", "VAR=1 ls", "LANG=C ls", "FOO=x ls", "./run.sh a", "/tmp/x.sh",
              "rm -rf /", "", " ", "ls | | ls", "echo a#b", "echo a\\b", "cat <(x)", "ls |& cat", "time ls",
              "ls; ", "; ls", "ls &&", "echo '' x", "2>&1", "echo 2>&1", "echo 2>&1 x", "echo 2>&1|cat", "echo 2>&1;ls",
              "echo 2>&1&&ls", "echo 1>&2", "ls\tl", "ls\nl", "python3 -c 'print(1)'", "sh -c \"sh -c 'ls'\"",
              "node a.js | python3 b.py", "perl -e 1", "awk '{print}' f", "sed s/a/b/ f", "curl http://h/x",
              "curl -s https://h/x | jq .", "jq .a f", "jq env f", "head -5 f", "tail -n +5 f", "stat -c %s f"]

    def pick(pool, lo, hi):
        return [rng.choice(pool) for _ in range(rng.randrange(lo, hi + 1))]
    def prog():
        return rng.choice(prefixes) + rng.choice(plains + interps + wrappers)
    def spec_args(name):
        sp = asb.PLAIN_PROGRAMS.get(name)
        out = []
        if sp:
            for _ in range(rng.randrange(0, 4)):
                kind = rng.randrange(4)
                if kind == 0 and sp["short"]:
                    out.append("-" + "".join(rng.choice(sp["short"]) for _ in range(rng.randrange(1, 4))))
                elif kind == 1 and sp["valued"]:
                    c = rng.choice(sorted(sp["valued"]))
                    out += ["-" + c, rng.choice(["5", "1.5", "+5", "x", "GET", "a b", "1,2", "-"])]
                elif kind == 2 and (sp["long"] or sp["longv"]):
                    out.append(rng.choice(sorted(sp["long"] | set(sp["longv"]))) + rng.choice(["", "", "=5"]))
                else:
                    out.append(rng.choice(operands))
        return out
    for _ in range(2600):
        shape = rng.randrange(7)
        chain = []
        for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
            w = rng.choice(wrappers)
            chain += [rng.choice(prefixes[:5]) + w] + pick(flags, 0, 2) + (["5"] if w == "timeout" and rng.random() < 0.8 else [])
        if shape == 0:
            name = rng.choice(plains)
            argv = chain + [rng.choice(prefixes[:4]) + name] + spec_args(name)
        elif shape == 1:
            argv = chain + [rng.choice(prefixes) + rng.choice(interps)] + pick(flags, 0, 3) + pick(operands, 0, 2)
        elif shape == 2:
            argv = chain + [rng.choice(prefixes[:4]) + rng.choice(["sh", "bash", "zsh", "dash", "fish"]), "-c", rng.choice(shells)] + pick(operands, 0, 1)
        elif shape == 3:
            argv = chain + [prog()] + pick(flags + operands, 0, 5)
        elif shape == 4:
            argv = pick(flags + operands + wrappers + plains + interps, 0, 6)
        elif shape == 5:
            argv = chain + [rng.choice(["bash", "sh"]), "-c", rng.choice(shells)]
        else:
            argv = [rng.choice(["env"] * 4 + ["/usr/bin/env"])] + pick(["-i", "-u", "X", "-S", "--ignore-environment", "-0", "-", "--", "A=b", "LANG=C", "FOO=1", "-C", "x/y"], 0, 4) + [rng.choice(plains + interps), *pick(flags + operands, 0, 2)]
        argvs.append(argv)
    # every option of every program the analyser knows, written each way it can be written
    tails = [[], ["x"], ["x", "y"], ["--", "-x"], ["5\n"], ["http://h/x"], ["http://h/x\n"], ["+%Y"], ["a.b"], ["1,2"]]
    for name, sp in sorted(asb.PLAIN_PROGRAMS.items()):
        toks = []
        for c in sp["short"]:
            toks.append(["-" + c])
        for c in sorted(sp["valued"]):
            toks += [["-" + c, "5"], ["-" + c + "5"], ["-" + c, "x"], ["-" + c], ["-" + c, "5\n"], ["-" + c, "GET"],
                     ["-" + c, "1,2"], ["-" + c, "+5"], ["-" + c, "1.5"], ["-" + c, "a\x00b"]]
        for l in sorted(sp["long"]):
            toks += [[l], [l + "=1"]]
        for l in sorted(sp["longv"]):
            toks += [[l, "5"], [l + "=5"], [l], [l, "x"], [l, "GET"], [l + "=GET"], [l, "5\n"], [l, "a\nb"]]
        for e in sorted(sp["exact"]):
            toks += [[e]]
        toks += [["-5"], ["-12"], ["-x"], ["--bogus"], ["-"], ["--"], ["-" + sp["short"][:2]] if sp["short"] else []]
        for t in toks:
            argvs.append([name] + t + rng.choice(tails))
        for t in tails:
            argvs.append([name] + t)
    for w, sp in sorted(asb.SCRIPT_WRAPPERS.items()):
        toks = [["-" + c] for c in sp["s"] + sp["so"]] + [["-" + c, "5"] for c in sp["sv"]] + [["-" + c + "5"] for c in sp["sv"]]
        toks += [[l] for l in sorted(sp["l"])] + [[l, "5"] for l in sorted(sp["lv"])] + [[l + "=5"] for l in sorted(sp["lv"])]
        toks += [[l[:4]] for l in sorted(sp["l"] | sp["lv"])] + [[l[:3], "5"] for l in sorted(sp["lv"])] + [["-z"], ["--zz"], ["-"], ["--"]]
        for t in toks:
            for cmd in (["ls"], ["bash", "x.sh"], [], ["5", "ls"]):
                argvs.append([w] + t + (["--"] if rng.random() < 0.25 else []) + cmd)
    for opt in (["-i"], ["-0"], ["-u", "X"], ["-uX"], ["--unset", "X"], ["--unset=X"], ["--null"], ["--ignore-environment"],
                ["--ign"], ["-S", "ls"], ["--split-string=ls"], ["-C", "x"], ["-"], ["--"], ["A=b"], ["LANG=C"], ["PATH=x"], ["LANG=a/b"]):
        for cmd in (["ls"], ["bash", "x.sh"], [], ["LANG=C", "ls"]):
            argvs.append(["env"] + opt + cmd)
    for n in range(28, 36):
        argvs.append(["env"] * n + ["cat", "f"])
        argvs.append(["nohup"] * n + ["cat", "f"])
    for n in range(1, 8):
        nested, wrapped = "ls", ["ls"]
        for _ in range(n):
            nested = "sh -c " + shlex.quote(nested)
            wrapped = ["bash", "-c", " ".join(wrapped) if len(wrapped) == 1 else shlex.join(wrapped)]
        argvs += [["sh", "-c", nested], ["bash", "-c", "env " * n + "ls"], wrapped, ["sudo", "-n"] + wrapped,
                  ["sh", "-c", nested + " && " + nested], ["env", "LANG=C"] + wrapped]
    for pat, valued, inline, stdin in [(None, None, None, None)]:
        pass
    for interp in interps:
        flagset = set(flags)
        for spec in asb.SCRIPT_INTERPRETERS:
            if spec[0].match(interp):
                flagset |= set(spec[1]) | set(spec[2]) | set(spec[3]) | {f.upper() for f in spec[2]}
        flagset |= set(asb.SCRIPT_FILE_FLAGS.get(interp, ()))
        for f in sorted(flagset):
            for tail in rng.sample([[], ["x.py"], ["ls"], ["x", "y.sh"], ["-"], ["--"], ["--", "x.sh"], ["echo hi && ls"], ["-c", "ls"]], 3):
                argvs.append([interp, f] + tail)
        for tail in ([], ["x"], ["x.py"], ["-"], ["--"], ["--", "x"], ["run", "x.ts"], ["run", "-"], ["eval", "1"], ["x", "-"], ["-A", "x"]):
            argvs.append([interp] + tail)
            argvs.append(["/usr/bin/" + interp] + tail)
            argvs.append(["./" + interp] + tail)
    for cmdline in ("in x", "case x in", "esac", "coproc ls", "time ls", "! ls", "[[ x ]]", "function f", "select x", "do ls", "done",
                    "if", "then ls", "else ls", "elif x", "fi", "for x", "while x", "until x", "{", "}", "ls | in", "ls && in x"):
        argvs.append(["sh", "-c", cmdline])
    argvs += [[], [""], ["env"], ["env", "-i"], ["env", "A=b"], ["sh", "-c"], ["python3", "-c"], ["python3", "-m"],
              ["sudo"], ["timeout"], ["timeout", "5"], ["nohup"], ["time", "time", "time", "time", "time", "ls"],
              ["env"] * 40 + ["cat"], ["env"] * 3 + ["cat"], ["nice", "-n", "5", "bash", "x.sh"]]
    out, seen = [], set()
    for a in argvs:
        if json.dumps(a) in seen:
            continue
        seen.add(json.dumps(a))
        trace = {}
        items, ok = asb._analyze(a, 0, trace)
        out.append({"argv": a, "items": [[p, bool(st)] for p, st in items], "ok": bool(ok), "cmd": trace.get("cmd") or []})
    return out


def generate():
    return {"analyse.json": json.dumps(analyse_cases(), separators=(",", ":"), ensure_ascii=True) + "\n",
            "difflib.json": json.dumps(difflib_cases(), indent=1, ensure_ascii=True) + "\n",
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
