#!/usr/bin/env python3
"""Stand-in for the OpenSSH programs `ssh`, `ssh-agent` and `ssh-add`, for tests/test_execrun.py.

The test copies this file three times into a throwaway directory, as `ssh`, `ssh-agent` and `ssh-add`; the copy
behaves as its own name says. Behavior comes from `config.json` beside it, and every call is appended to
`calls.jsonl` there (argv, the environment it ran with, stdin, and for ssh the generated known_hosts file), so a
test can assert what the broker really passed. This is test code: it records the key it is given, on purpose,
so a test can prove the key travelled only on stdin.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = os.path.basename(sys.argv[0])


def config():
    try:
        with open(os.path.join(HERE, "config.json")) as f:
            return json.load(f).get(NAME, {})
    except FileNotFoundError:
        return {}


def log(**kw):
    kw.update(tool=NAME, argv=sys.argv[1:], env=dict(os.environ), cwd=os.getcwd())
    with open(os.path.join(HERE, "calls.jsonl"), "a") as f:
        f.write(json.dumps(kw) + "\n")


def agent(cfg):
    """`ssh-agent -D -a SOCK`: stay in the foreground, create the socket, print the first line, run until killed."""
    sock = sys.argv[sys.argv.index("-a") + 1]
    open(sock, "w").close()                         # "listening"
    log(pid=os.getpid(), sock=sock)
    print(f"SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;", flush=True)
    while True:
        time.sleep(0.05)


def add(cfg):
    data = sys.stdin.buffer.read()
    log(stdin=data.decode("utf-8", "replace"), sock_exists=os.path.exists(os.environ.get("SSH_AUTH_SOCK", "")))
    return cfg.get("rc", 0)


def ssh(cfg):
    data = sys.stdin.buffer.read() if not cfg.get("no_stdin") else b""
    known = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("UserKnownHostsFile=")), None)
    kh = None
    if known and os.path.exists(known):
        with open(known) as f:
            kh = f.read()
        kh_mode = oct(os.stat(known).st_mode & 0o777)
    else:
        kh_mode = None
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    d = os.path.dirname(known) if known else None
    listing = sorted(os.listdir(d)) if d and os.path.isdir(d) else None
    secret_in_dir = False
    for fn in listing or []:
        try:
            with open(os.path.join(d, fn), "rb") as f:
                secret_in_dir = secret_in_dir or b"S3CR3T-KEY" in f.read()
        except OSError:
            pass
    t0 = time.time()
    log(dir=d, dir_listing=listing, secret_in_dir=secret_in_dir, stdin=data.decode("utf-8", "replace"), known_hosts=kh, known_hosts_mode=kh_mode,
        dir_mode=oct(os.stat(os.path.dirname(known)).st_mode & 0o777) if known else None,
        sock_exists=os.path.exists(sock), pid=os.getpid())
    if cfg.get("wait_for"):                         # a barrier for the concurrency test: start, then wait for `go`
        open(os.path.join(HERE, f"started-{os.getpid()}"), "w").close()
        while not os.path.exists(os.path.join(HERE, cfg["wait_for"])):
            time.sleep(0.01)
    if cfg.get("sleep"):
        time.sleep(cfg["sleep"])
    if cfg.get("hang"):
        while True:
            time.sleep(0.05)
    if cfg.get("flood_bytes"):
        chunk = b"x" * 4096
        sent = 0
        try:
            while sent < cfg["flood_bytes"]:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                sent += len(chunk)
        except BrokenPipeError:
            pass
    if cfg.get("stdout"):
        sys.stdout.write(cfg["stdout"])
    if cfg.get("stderr"):
        sys.stderr.write(cfg["stderr"])
    sys.stdout.flush()
    sys.stderr.flush()
    if cfg.get("stdout_hex"):
        sys.stdout.buffer.write(bytes.fromhex(cfg["stdout_hex"]))
    if cfg.get("stderr_hex"):
        sys.stderr.buffer.write(bytes.fromhex(cfg["stderr_hex"]))
    sys.stdout.flush()
    sys.stderr.flush()
    log(phase="end", t0=t0, t1=time.time())
    return cfg.get("rc", 0)


if __name__ == "__main__":
    cfg = config()
    if cfg.get("missing"):
        sys.exit(127)
    sys.exit({"ssh-agent": agent, "ssh-add": add, "ssh": ssh}[NAME](cfg))
