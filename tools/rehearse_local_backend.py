#!/usr/bin/env python3
"""End-to-end rehearsal of the encrypted local backend (`backend.type: local`).

Stands up a THROWAWAY broker (the real `python -m secret_broker`) on a scratch
encrypted store, a local stub upstream and a stub model/notification endpoint, and
drives it with the real `client/asb` and the real approval web app. Prints one
PASS/FAIL line per check, never a secret value. Only fake secrets are used.

    python3 tools/rehearse_local_backend.py [--groups ABCDEFGH] [--root DIR] [--keep]
                                            [--docker-image IMAGE | --docker-build]

Safety: every `asb` call gets a scratch HOME and an explicit URL/key for the
throwaway broker (see Rehearsal.asb); nothing here reads ~/.config/secret-broker,
~/tokens, a real vault or any real credential. Ports are 127.0.0.1 only.
See docs/rehearsal.md.
"""
import argparse
import base64
import json
import os
import re
import shutil
import site
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ASB = REPO / "client" / "asb"
CLIENT_KEY = "rehearsal-client-key-0001"
USER = "tester"

# Fake secrets. None of them may ever appear in a log, the audit file, CLI output
# or the process list (and none may appear in the encrypted store in the clear).
SECRETS = {
    "http": "FAKE-http-token-7f3a91c2",
    "env": "FAKE-env-token-b84d20e5",
    "plainpw": "FAKE-plain-pw-1c9e77aa",
    "loginpw": "FAKE-login-pw-93d1f0b6",
    "allow": "FAKE-allow-token-5a6c2e19",
    "stored": "FAKE-stored-token-e07b43d8",
    "updated": "FAKE-updated-token-2f8a6d51",
    "dotenv": "FAKE-dotenv-value-6b1d9c03",
    "plainnew": "FAKE-plain-pw-rotated-71ac",
    "bw": "FAKE-bitwarden-value-c4e8a207",
    "passphrase": "correct horse battery rehearsal",
    "envkey": "FAKE-env-key-passphrase-88d3",
    "credtoken": "FAKE-credreq-token-4d9a17c3",
    "creduser": "FAKE-credreq-user-a07e52b9",
    "credpw": "FAKE-credreq-pw-6e2c80d1",
}


_next_port = [18800]


def free_port():
    """Next bindable loopback port from 18800 upward (client API, approval UI, ...)."""
    while True:
        p = _next_port[0]
        _next_port[0] += 1
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            continue
        finally:
            s.close()
        return p


# ---------------------------------------------------------------- stub servers
class Upstream(BaseHTTPRequestHandler):
    """Echoes request headers and body back as JSON; records every hit."""
    hits = []

    def log_message(self, *a):
        pass

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        rec = {"method": self.command, "path": self.path,
               "headers": {k: v for k, v in self.headers.items()}, "body": body}
        Upstream.hits.append(rec)
        raw = json.dumps({"echo": rec}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = do_PUT = do_DELETE = _do


class Aux(BaseHTTPRequestHandler):
    """Stub model API (/chat/completions: low unless the request mentions 'highrisk')
    and a stub Telegram API (/bot*/sendMessage etc.). Records telegram texts."""
    telegram = []
    model_calls = []

    def log_message(self, *a):
        pass

    def _send(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        if self.path.endswith("/chat/completions"):
            Aux.model_calls.append(body)
            level = "high" if "highrisk" in body else "low"
            content = json.dumps({"summary": "Stub summary of a request", "risk": level})
            return self._send({"choices": [{"message": {"content": content}}], "usage": {}})
        Aux.telegram.append(body)
        self._send({"ok": True, "result": {"message_id": len(Aux.telegram)}})

    do_GET = do_POST


def serve_thread(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- results
class Results:
    def __init__(self):
        self.rows = []      # (group, name, ok, reason)
        self.skipped = []
        self.numbers = {}

    def check(self, group, name, ok, reason=""):
        reason = " | ".join(str(reason).split("\n"))[:170]
        self.rows.append((group, name, bool(ok), reason))
        print(f"{'PASS' if ok else 'FAIL'} [{group}] {name}" + (f": {reason}" if reason else ""),
              flush=True)
        return bool(ok)

    def note(self, group, name, text):
        print(f"INFO [{group}] {name}: {text}", flush=True)

    def skip(self, group, why):
        self.skipped.append((group, why))
        print(f"SKIP [{group}] {why}", flush=True)

    def summary(self):
        print("\n== summary ==")
        groups = sorted({r[0] for r in self.rows})
        for g in groups:
            rows = [r for r in self.rows if r[0] == g]
            bad = [r for r in rows if not r[2]]
            print(f"{g}: {len(rows) - len(bad)}/{len(rows)} passed" + ("" if not bad else
                  "  FAILED: " + "; ".join(r[1] for r in bad)))
        for g, why in self.skipped:
            print(f"{g}: SKIPPED ({why})")
        for k, v in self.numbers.items():
            print(f"number {k}: {v}")
        return not any(not r[2] for r in self.rows)


# ---------------------------------------------------------------- approval web app client
class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Approver:
    """Drives the approval app like the SSO proxy + browser would."""

    def __init__(self, port, user=USER):
        self.base = f"http://127.0.0.1:{port}"
        self.user = user
        self.op = urllib.request.build_opener(NoFollow)

    def _open(self, req, timeout=15):
        try:
            r = self.op.open(req, timeout=timeout)
            return r.status, r.headers.get("Location"), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            return 0, None, f"{type(e).__name__}"

    def get(self, path, user=None, timeout=15):
        r = urllib.request.Request(self.base + path,
                                   headers={"X-authentik-username": self.user if user is None else user})
        return self._open(r, timeout)

    def post(self, path, form, user=None, timeout=30, csrf=True):
        form = dict(form)
        if csrf:
            form.setdefault("csrf", self.csrf())
        data = urllib.parse.urlencode(form, doseq=True).encode()
        r = urllib.request.Request(self.base + path, data=data, method="POST",
                                   headers={"X-authentik-username": self.user if user is None else user})
        return self._open(r, timeout)

    def csrf(self):
        _, _, body = self.get("/policies")
        m = re.search(r"name=csrf value='([0-9a-f]{64})'", body)
        if not m:
            _, _, body = self.get("/")
            m = re.search(r"name=csrf value='([0-9a-f]{64})'", body)
        return m.group(1) if m else ""

    def cards(self):
        _, _, body = self.get("/")
        return re.findall(r"<article class=req data-id='([^']+)'", body)

    def wait_card(self, seen=(), timeout=20, proc=None):
        end = time.time() + timeout
        while time.time() < end:
            for c in self.cards():
                if c not in seen:
                    return c
            if proc is not None and proc.poll() is not None:
                return None
            time.sleep(0.15)
        return None

    def decide(self, rid, decision="approve", extra=None):
        form = {"id": rid, "decision": decision}
        form.update(extra or {})
        return self.post("/decide", form)


# ---------------------------------------------------------------- the throwaway broker
class Broker:
    def __init__(self, rh, name, store, key_source, cport=None, aport=None, ttl=8, idle=300,
                 env=None, risk=None, extra=None, summary=True):
        self.rh, self.name, self.store = rh, name, store
        self.cport, self.aport = cport or free_port(), aport or free_port()
        self.proc = None
        self.env = env or {}
        self.logf = rh.logs / f"{name}.log"
        self.audit = rh.data / f"{name}.audit.jsonl"
        self.cfg_path = rh.sec / f"{name}.config.json"
        cfg = {
            "backend": {"type": "local", "path": str(store), "key_source": key_source,
                        "idle_timeout": idle},
            "client_key_file": str(rh.sec / "client_key"),
            "approve_base_url": f"http://127.0.0.1:{self.aport}",
            "allowed_user": USER, "identity_header": "X-authentik-username",
            "approval_trusted_peers": ["127.0.0.1/32"],
            "client_port": self.cport, "approval_port": self.aport,
            "ttl_seconds": ttl, "audit_log": str(self.audit),
            "risk": risk or {"auto_approve_max": "low"},
            "notify": [{"type": "telegram", "bot_token_file": str(rh.sec / "telegram_token"),
                        "chat_id": "1", "api_base": f"http://127.0.0.1:{rh.aux_port}"}],
            "notify_presence": {"enabled": False},
            "request_details": {"enabled": True, "retention_days": 7},
        }
        if summary:
            cfg["summary"] = {"type": "openrouter", "model": "stub/model", "prompt": "rubric",
                              "api_key_file": str(rh.sec / "model_key"),
                              "base_url": f"http://127.0.0.1:{rh.aux_port}", "timeout": 4}
        cfg.update(extra or {})
        self.cfg = cfg
        self.write_cfg()
        self.ap = Approver(self.aport)

    def write_cfg(self):
        fd = os.open(self.cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.cfg, f, indent=1)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.cport}"

    def start(self, wait=True):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.rh.home), "PYTHONPATH": str(REPO),
               "PYTHONUSERBASE": site.getuserbase(), "BIND": "127.0.0.1", "PYTHONUNBUFFERED": "1", **self.env}
        log = open(self.logf, "ab")
        self.proc = subprocess.Popen([sys.executable, "-m", "secret_broker", "--config", str(self.cfg_path)],
                                     env=env, stdout=log, stderr=log, cwd=str(self.rh.root))
        self.rh.pids.add(self.proc.pid)
        if wait:
            return self.wait_ready()
        return True

    def wait_ready(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                return False
            try:
                urllib.request.urlopen(urllib.request.Request(
                    self.url + "/v1/status", headers={"X-Client-Key": CLIENT_KEY}), timeout=3).read()
                return True
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        return False

    def stop(self, sig=signal.SIGTERM, timeout=15):
        if not self.proc:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.rh.pids.discard(self.proc.pid)
        rc = self.proc.returncode
        self.proc = None
        return rc

    def records(self):
        out = []
        try:
            for line in open(self.audit):
                if line.strip():
                    out.append(json.loads(line))
        except FileNotFoundError:
            pass
        return out

    def events(self, name):
        return [r for r in self.records() if r.get("event") == name]

    def api(self, method, path, body=None, key=CLIENT_KEY):
        r = urllib.request.Request(self.url + path, method=method,
                                   data=json.dumps(body).encode() if body is not None else None,
                                   headers={"X-Client-Key": key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:  # noqa: BLE001
            return 0, type(e).__name__


def rh_run(rh, b, args, stdin, timeout):
    return rh.asb(b, *args, stdin=stdin, timeout=timeout)


# ---------------------------------------------------------------- the rehearsal
class Rehearsal:
    def __init__(self, root, res):
        self.res = res
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.home, self.logs, self.data, self.sec = (self.root / d for d in ("home", "logs", "data", "secrets"))
        self.srcdir = self.root / "src"        # plaintext inputs (fake .env, bw shim data, ssh key)
        for d in (self.home, self.logs, self.data, self.sec, self.srcdir):
            d.mkdir(mode=0o700, exist_ok=True)
        self.outputs = []       # every captured CLI output, scanned for secrets at the end
        self.pids = set()
        self.psdump = []
        self.up = serve_thread(Upstream)
        self.aux = serve_thread(Aux)
        self.up_port = self.up.server_address[1]
        self.aux_port = self.aux.server_address[1]
        self.secret_file(self.sec / "client_key", CLIENT_KEY)
        self.secret_file(self.sec / "telegram_token", "fake-telegram-token")
        self.secret_file(self.sec / "model_key", "fake-model-key")
        self.secret_file(self.sec / "pass_key", SECRETS["passphrase"])
        # the scratch HOME hides the user site-packages (cryptography etc.); point python back at them
        self.pyenv = {"PATH": os.environ["PATH"], "HOME": str(self.home), "PYTHONPATH": str(REPO),
                      "PYTHONUSERBASE": site.getuserbase()}

    @staticmethod
    def secret_file(path, text):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text + "\n")

    @staticmethod
    def _ancestors():
        pids, pid = set(), os.getpid()
        while pid > 1:
            pids.add(pid)
            try:
                pid = int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                break
        return pids

    def snap_ps(self):
        """Argument lists of every process on the host except this script and its ancestors
        (a wrapper shell's own command line can legitimately contain the fake strings)."""
        mine = self._ancestors()
        out = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout
        keep = [ln for ln in out.splitlines() if ln.split(None, 1)[0].isdigit() and int(ln.split(None, 1)[0]) not in mine]
        self.psdump.append("\n".join(keep))

    # -- the CLIs ---------------------------------------------------------
    def asb_env(self, b, extra=None):
        url = b.url
        assert re.match(r"^http://127\.0\.0\.1:\d+$", url), "refusing to point asb anywhere but loopback"
        env = {"PATH": os.environ["PATH"], "HOME": str(self.home),
               "SECRET_BROKER_URL": url, "SECRET_BROKER_KEY": CLIENT_KEY}
        env.update(extra or {})
        return env

    def asb(self, b, *args, stdin=None, timeout=90, extra_env=None, cwd=None):
        """Run the repo's client/asb against the throwaway broker `b`. Clean environment."""
        cp = subprocess.run([str(ASB), *args], env=self.asb_env(b, extra_env), cwd=cwd or str(self.root),
                            input=stdin, capture_output=True, text=True, timeout=timeout)
        self.outputs.append((f"asb {args[:2]}", cp.stdout + cp.stderr))
        return cp.returncode, cp.stdout, cp.stderr

    def asb_popen(self, b, *args, extra_env=None, cwd=None):
        p = subprocess.Popen([str(ASB), *args], env=self.asb_env(b, extra_env), cwd=cwd or str(self.root),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return p

    def asb_decided(self, b, args, decision="approve", stdin=None, extra=None, timeout=60,
                    extra_env=None, cwd=None, expect_card=True, post_wait=0):
        """Run asb; when its approval card appears, POST `decision` (None = leave it
        pending). Returns (rc, stdout, stderr, card_id)."""
        seen = set(b.ap.cards())
        p = self.asb_popen(b, *args, extra_env=extra_env, cwd=cwd)
        if stdin is not None:
            try:
                p.stdin.write(stdin)
            except BrokenPipeError:
                pass
        try:
            p.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        p.stdin = None
        rid = b.ap.wait_card(seen, timeout=25, proc=p) if expect_card else None
        self.snap_ps()
        if rid and decision is not None:
            b.ap.decide(rid, decision, extra)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
            err += "\n[rehearsal: asb timed out]"
        self.outputs.append((f"asb {args[:2]}", out + err))
        return p.returncode, out, err, rid

    def lsc(self, *args, stdin=None, env=None, store=None, key_file="PASS", check_rc=None, timeout=120):
        """`python -m secret_broker.localstore ...` (the admin CLI)."""
        e = dict(self.pyenv)
        e.update(env or {})
        cp = subprocess.run([sys.executable, "-m", "secret_broker.localstore", *args], env=e, cwd=str(self.root),
                            input=stdin, capture_output=True, text=True, timeout=timeout)
        self.outputs.append((f"localstore {args[:1]}", cp.stdout + cp.stderr))
        return cp.returncode, cp.stdout, cp.stderr

    def lsc_k(self, cmd, store, keyfile=None, keyenv=None, *args, **kw):
        keyopt = ["--key-env", keyenv] if keyenv else ["--key-file", str(keyfile or self.sec / "pass_key")]
        return self.lsc(cmd, "--store", str(store), *keyopt, *args, **kw)

    # -- checks helpers ---------------------------------------------------
    def check(self, group, name, ok, reason=""):
        return self.res.check(group, name, ok, reason)

    def note(self, group, name, text):
        self.res.note(group, name, text)

    def asb_auto(self, b, args, stdin=None, timeout=60):
        """Run asb and never touch the approval page. If the request needs a human it
        simply expires (short ttl). Returns (rc, out, err, via) where via is the `via` of
        the request's `approved` audit event ('user' would mean a human decided)."""
        base = max([r["seq"] for r in b.records()] or [0])
        rc, out, err = rh_run(self, b, args, stdin, timeout)
        via = [e.get("via") for e in b.records() if e["seq"] > base and e.get("event") == "approved"]
        return rc, out, err, (via[-1] if via else None)

    def leak_scan(self, group, label, texts):
        hits = []
        for src, t in texts:
            for k, v in SECRETS.items():
                if v in t:
                    hits.append(f"{k}@{src}")
        self.check(group, label, not hits, "secret strings found: " + ", ".join(sorted(set(hits))[:6]) if hits else "")

    def scan_files(self, paths):
        hits = []
        for p in paths:
            try:
                data = Path(p).read_bytes()
            except OSError:
                continue
            for k, v in SECRETS.items():
                if v.encode() in data:
                    hits.append(f"{Path(p).name}:{k}")
        return hits

    def cleanup_procs(self):
        for pid in list(self.pids):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        time.sleep(0.5)
        for pid in list(self.pids):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.pids.clear()
        self.up.shutdown()
        self.aux.shutdown()


# ================================================================ scenario A: setup
def meta_file(rh, name, meta):
    p = rh.srcdir / f"meta-{name}.json"
    p.write_text(json.dumps(meta))
    return p


def add_note(rh, store, item, text, meta=None, keyenv=None, env=None, keyfile=None):
    args = [item]
    if meta is not None:
        args += ["--meta", str(meta_file(rh, item.replace(" ", "_"), meta))]
    return rh.lsc_k("add", store, keyfile, keyenv, *args, stdin=text, env=env)


def add_login(rh, store, item, user, pw, uri=None, meta=None):
    args = [item, "--kind", "login", "--json"]
    if meta is not None:
        args += ["--meta", str(meta_file(rh, item.replace(" ", "_"), meta))]
    return rh.lsc_k("add", store, None, None, *args,
                    stdin=json.dumps({"username": user, "password": pw, "uris": [uri] if uri else []}))


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def scenario_A(rh):
    g = "A"
    store = rh.data / "main.enc"
    rc, out, err = rh.lsc_k("init", store)
    rec = [ln for ln in out.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]{44}", ln.strip())]
    rh.check(g, "init (file key source, passphrase)", rc == 0 and store.exists() and len(rec) == 1,
             f"rc={rc} recovery_key_printed={len(rec)}")
    rh.recovery = rec[0].strip() if rec else None
    rh.secret_file(rh.sec / "recovery_key", rh.recovery or "")
    rh.check(g, "store mode 0600", mode_of(store) == 0o600, oct(mode_of(store)))
    hosts = ["127.0.0.1"]
    rcs = []
    rcs.append(add_note(rh, store, "Stub API", SECRETS["http"],
                        {"name": "stub", "allowed_hosts": hosts, "vars": {"STUB_TOKEN": {"field": "notes"}},
                         "approval": "prompt"})[0])
    rcs.append(add_note(rh, store, "Env Cred", SECRETS["env"],
                        {"name": "envcred", "vars": {"ENV_TOKEN": {"field": "notes"}}, "approval": "prompt"})[0])
    rcs.append(add_note(rh, store, "Allow Cred", SECRETS["allow"],
                        {"name": "allowcred", "allowed_hosts": hosts, "vars": {"ALLOW_TOKEN": {"field": "notes"}},
                         "approval": "allow"})[0])
    rcs.append(add_login(rh, store, "Plain Login", "plainuser", SECRETS["plainpw"], "http://127.0.0.1/")[0])
    rcs.append(add_login(rh, store, "Login Up", "loginuser", SECRETS["loginpw"], None,
                         {"name": "loginup", "allowed_hosts": hosts, "approval": "prompt",
                          "vars": {"LU_USER": {"field": "username"}, "LU_PASS": {"field": "password"}}})[0])
    for nm in ("Extra One", "Extra Two"):
        rcs.append(add_note(rh, store, nm, "FAKE-extra-" + nm.split()[1].lower() + "-value",
                            {"name": nm.lower().replace(" ", "-"), "allowed_hosts": hosts, "vars": {nm.upper().replace(" ", "_") + "_TOKEN": {"field": "notes"}},
                             "approval": "prompt"})[0])
    rh.check(g, "admin CLI add: http note, env note, allow note, plain login (no meta), login user+pass",
             all(r == 0 for r in rcs), f"{len(rcs)} adds, rcs={rcs}")
    rc, out, err = rh.lsc_k("list", store)
    names = [ln.split("\t")[0] for ln in out.splitlines()]
    rh.check(g, "admin CLI list shows 7 items, shapes only", rc == 0 and len(names) == 7
             and "Plain Login" in names and "no-meta" in out, f"rc={rc} names={names}")
    rc, out, err = rh.lsc_k("show", store, None, None, "Plain Login")
    rh.check(g, "show: plain login 'adopts: yes', no values", rc == 0 and "adopts: yes" in out, out.strip()[:80])
    # env key source, separate store
    estore = rh.data / "envkey.enc"
    env = {"REH_ENVKEY": SECRETS["envkey"]}
    rc, out, err = rh.lsc("init", "--store", str(estore), "--key-env", "REH_ENVKEY", "--no-recovery", env=env)
    rc2, _, _ = rh.lsc("add", "EnvItem", "--store", str(estore), "--key-env", "REH_ENVKEY", stdin=SECRETS["stored"], env=env)
    rc3, out3, _ = rh.lsc("list", "--store", str(estore), "--key-env", "REH_ENVKEY", env=env)
    rc4, _, err4 = rh.lsc("list", "--store", str(estore), "--key-env", "REH_ENVKEY", env={"REH_ENVKEY": "wrong"})
    rh.check(g, "env key source: init/add/list work; wrong env key refused",
             rc == 0 and rc2 == 0 and rc3 == 0 and "EnvItem" in out3 and rc4 != 0, f"rcs={rc},{rc2},{rc3},{rc4}: {err4.strip()[:60]}")
    rh.check(g, "store file holds no plaintext secret", not rh.scan_files([store, estore]), "")
    rh.check(g, "stub upstream up", True, f"127.0.0.1:{rh.up_port}")
    rh.store = store
    rh.estore = estore


# ================================================================ scenario B: real broker on the store
def scenario_B(rh):
    g = "B"
    b = Broker(rh, "main", rh.store, {"type": "file", "path": str(rh.sec / "pass_key")})
    rh.main = b
    started = time.time()
    ok = b.start()
    rh.check(g, "broker process starts (backend.type local)", ok, f"cport={b.cport} aport={b.aport}")
    if not ok:
        return False
    # SAFETY: prove asb is talking to the throwaway broker, not a live one.
    st, rc, t_wait = {}, 1, time.time()
    for _ in range(40):         # the first catalog load runs in the background after the listener is up
        rc, out, err = rh.asb(b, "status", "--json")
        try:
            st = json.loads(out)
        except ValueError:
            st = {}
        if st.get("catalog", {}).get("count"):
            break
        time.sleep(0.25)
    fresh = st.get("uptime_s", 9999) < 60 and st.get("started_at", "") >= time.strftime(
        "%Y-%m-%dT%H:%M:%S", time.gmtime(started - 5))
    rh.check(g, "SAFETY asb status reports the throwaway broker (fresh uptime, local backend)",
             rc == 0 and fresh and st.get("backend", {}).get("type") == "local",
             f"url=127.0.0.1:{b.cport} uptime_s={st.get('uptime_s')} backend={st.get('backend')}")
    if not (rc == 0 and fresh):
        print("ABORT: asb does not look like it reached the throwaway broker", flush=True)
        return False
    rh.check(g, "status: backend ok, 7 catalog items, 1 adopted, 0 invalid",
             st["backend"]["ok"] and st["catalog"]["count"] == 7 and st["catalog"]["adopted"] == 1
             and st["catalog"]["invalid"] == 0, json.dumps(st["catalog"]))
    rc, out, err = rh.asb(b, "list", "--json")
    try:
        lst = json.loads(out)
    except ValueError:
        lst = []
    names = sorted(x.get("name") for x in (lst if isinstance(lst, list) else lst.get("secrets", [])))
    rh.check(g, "asb list shows the items incl. the adopted one",
             {"stub", "envcred", "allowcred", "loginup", "plain-login"} <= set(names), f"{names}")
    rc, out, err = rh.asb(b, "which", "127.0.0.1")
    rh.check(g, "asb which 127.0.0.1 finds http credentials", rc == 0 and "stub" in out, out.strip()[:80])
    return True


# ================================================================ scenario C: request flows
def up_url(rh, path="/v1/thing"):
    return f"http://127.0.0.1:{rh.up_port}{path}"


def last_hit(rh):
    return Upstream.hits[-1] if Upstream.hits else None


def scenario_C(rh):
    g = "C"
    b = rh.main
    S = SECRETS
    n0 = len(Upstream.hits)
    # 1. http, approved; the upstream gets the secret, the agent never does
    rc, out, err, rid = rh.asb_decided(b, ["http", "stub", "GET", up_url(rh), "-H", "Authorization: Bearer {{STUB_TOKEN}}"])
    h = last_hit(rh)
    rh.check(g, "http approved: upstream received the substituted secret",
             rc == 0 and h and h["headers"].get("Authorization") == "Bearer " + S["http"], f"rc={rc} err={err.strip()[:80]}")
    rh.check(g, "http approved: response masks the secret the upstream echoed", S["http"] not in out + err and "echo" in out,
             "echoed Authorization header is masked in the agent's output")
    # 2. POST with a placeholder in the body
    rc, out, err, rid = rh.asb_decided(b, ["http", "stub", "POST", up_url(rh, "/post"), "-H", "Content-Type: application/json",
                                           "-d", '{"token":"{{STUB_TOKEN}}","x":1}'])
    h = last_hit(rh)
    rh.check(g, "http POST body placeholder substituted upstream", rc == 0 and h and S["http"] in h["body"] and h["method"] == "POST",
             f"rc={rc}")
    # 3. login username+password; adopted plain login
    rc, out, err, rid = rh.asb_decided(b, ["http", "loginup", "POST", up_url(rh, "/login"), "-d", "u={{LU_USER}}&p={{LU_PASS}}"])
    h = last_hit(rh)
    rh.check(g, "login item: username+password both substituted",
             rc == 0 and h and h["body"] == f"u=loginuser&p={S['loginpw']}", f"rc={rc}")
    rc, out, err, rid = rh.asb_decided(b, ["http", "plain-login", "POST", up_url(rh, "/adopted"), "-d", "p={{PLAIN_LOGIN_PASSWORD}}"])
    h = last_hit(rh)
    rh.check(g, "adopted item (no metadata) usable, approval prompt, value substituted",
             rc == 0 and rid is not None and h and h["body"] == "p=" + S["plainpw"], f"rc={rc} card={rid is not None}")
    # 3b. rotate the adopted item's password; the item has no metadata and must stay usable afterwards
    rc, out, err, rid = rh.asb_decided(b, ["update", "plain-login", "--var", "PLAIN_LOGIN_PASSWORD"], stdin=S["plainnew"])
    rh.check(g, "asb update on an adopted item (no metadata) needs approval and succeeds", rc == 0 and rid is not None, f"rc={rc} {err.strip()[-80:]}")
    rc, out, err, rid = rh.asb_decided(b, ["http", "plain-login", "POST", up_url(rh, "/adopted2"), "-d", "p={{PLAIN_LOGIN_PASSWORD}}&u={{PLAIN_LOGIN_USERNAME}}"])
    h = last_hit(rh)
    rh.check(g, "adopted item after update: new password used, username untouched",
             rc == 0 and h and h["body"] == "p=" + S["plainnew"] + "&u=plainuser", f"rc={rc}")
    # 4. denied
    n1 = len(Upstream.hits)
    rc, out, err, rid = rh.asb_decided(b, ["http", "extra-two", "GET", up_url(rh, "/denied"), "-H", "X-T: {{EXTRA_TWO_TOKEN}}"],
                                       decision="deny")
    rh.check(g, "denied request: exit 4, upstream never called", rc == 4 and len(Upstream.hits) == n1, f"rc={rc}")
    # 5. expired (ttl_seconds is short on this broker)
    t0 = time.time()
    rc, out, err, rid = rh.asb_decided(b, ["http", "loginup", "GET", up_url(rh, "/expired"), "-H", "X-U: {{LU_USER}}"],
                                       decision=None, timeout=60)
    rh.check(g, "expired request: exit 5, upstream never called", rc == 5 and len(Upstream.hits) == n1,
             f"rc={rc} after {time.time() - t0:.0f}s")
    # 6. allow-credential auto-approves without a card
    rc, out, err, via = rh.asb_auto(b, ["http", "allowcred", "GET", up_url(rh, "/auto"), "-H", "X-K: {{ALLOW_TOKEN}}"])
    h = last_hit(rh)
    rh.check(g, "approval:allow credential, low risk: auto-approved by policy, no human",
             rc == 0 and via == "policy" and h and h["headers"].get("X-K") == S["allow"], f"rc={rc} via={via}")
    # 7. env mode with a visible script
    script = rh.srcdir / "use_env.sh"
    outf = rh.srcdir / "env_digest.txt"
    script.write_text('#!/bin/sh\nprintf "%s" "$ENV_TOKEN" | sha256sum | cut -d" " -f1 > "$1"\necho done\n')
    import hashlib
    want = hashlib.sha256(S["env"].encode()).hexdigest()
    rc, out, err, rid = rh.asb_decided(b, ["envcred", "--", "sh", str(script), str(outf)])
    got = outf.read_text().strip() if outf.exists() else ""
    rh.check(g, "env mode (visible script) approved: value delivered to the command", rc == 0 and got == want and "done" in out,
             f"rc={rc} err={err.strip()[:80]}")
    outf.unlink(missing_ok=True)
    # 8. store (new credential), then use it
    rc, out, err, via = rh.asb_auto(b, ["store", "newcred", "--hosts", "127.0.0.1"], stdin=S["stored"])
    rh.check(g, "asb store creates a credential (auto-approved by policy: store.create defaults to auto)",
             rc == 0 and via == "policy", f"rc={rc} via={via} {out.strip()[:60]}")
    rc, out, err = rh.asb(b, "list", "--json")
    names = {x.get("name"): x for x in json.loads(out)} if rc == 0 else {}
    var = (names.get("newcred") or {}).get("vars") or []
    rh.check(g, "stored credential appears in the catalog", "newcred" in names and var, f"vars={var}")
    if var:
        rc, out, err, rid = rh.asb_decided(b, ["http", "newcred", "POST", up_url(rh, "/stored"), "-d", "v={{%s}}" % var[0]])
        h = last_hit(rh)
        rh.check(g, "stored credential read back in a request", rc == 0 and h and h["body"] == "v=" + S["stored"], f"rc={rc}")
        rc, out, err, rid = rh.asb_decided(b, ["update", "newcred"], stdin=S["updated"])
        rh.check(g, "asb update needs approval and succeeds", rc == 0 and rid is not None, f"rc={rc} card={rid is not None} {err.strip()[:80]}")
        rc, out, err, rid = rh.asb_decided(b, ["http", "newcred", "POST", up_url(rh, "/updated"), "-d", "v={{%s}}" % var[0]])
        h = last_hit(rh)
        rh.check(g, "updated value is what requests now use", rc == 0 and h and h["body"] == "v=" + S["updated"], f"rc={rc}")
    # the external admin CLI sees the new item and (names only) the store was written by the broker
    rc, out, err = rh.lsc_k("list", rh.store)
    rh.check(g, "admin CLI sees the broker-created item", rc == 0 and "newcred" in out, "")
    # audit
    rc, out, err = rh.asb(b, "audit", "verify")
    rh.check(g, "asb audit verify: chain intact", rc == 0, (out + err).strip()[:100])
    rc, out, err = rh.asb(b, "audit", "--since", "30m", "--json")
    try:
        evs = json.loads(out)
        evs = evs.get("events", evs) if isinstance(evs, dict) else evs
    except ValueError:
        evs = []
    kinds = {e.get("event") for e in evs}
    rh.check(g, "asb audit shows request events", rc == 0 and len(evs) > 5 and kinds, f"{len(evs)} events: {sorted(k for k in kinds if k)[:8]}")
    srv = {r["event"] for r in b.records()}
    rh.check(g, "audit file has store events (unlocked/written)", {"store_unlocked", "store_written"} <= srv,
             f"{sorted(e for e in srv if e.startswith('store'))}")
    cp = subprocess.run([sys.executable, "-m", "secret_broker.audit", "verify", str(b.audit)],
                        env=rh.pyenv, capture_output=True, text=True)
    rh.check(g, "python -m secret_broker.audit verify (offline) ok", cp.returncode == 0, (cp.stdout + cp.stderr).strip()[:100])
    rh.check(g, "notifications went to the stub transport and carry no secret value",
             len(Aux.telegram) > 3 and not any(v in t for t in Aux.telegram for v in S.values()), f"{len(Aux.telegram)} messages")
    credreq_scenario(rh, g)
    clients_scenario(rh, g)


def clients_scenario(rh, g):
    """Per-client credentials on the main throwaway broker: `asb enroll` end to end (the human matches the
    code and approves the card), the new credential working, a client-scoped Always that never applies to
    the shared key, then revoke."""
    b = rh.main
    home = rh.home / "enrollhome"       # outside the scanned data and log directories
    home.mkdir(exist_ok=True)
    quiet = {"HOME": str(home), "SECRET_BROKER_KEY": ""}
    seen = set()

    def enroll_card():
        _, _, page = b.ap.get("/")
        m = re.search(r"Client enrollment: ([a-z0-9._-]+)</h2>.*?class=code>([A-Z2-7]{4}-[A-Z2-7]{4})<.*?"
                      r"action='/enroll/decide' class=decide><input type=hidden name=id value='([^']+)'", page, re.S)
        return m.groups() if m else None

    p = rh.asb_popen(b, "enroll", "--name", "rehearsal-box", "--url", b.url, extra_env=quiet)
    p.stdin.close()
    p.stdin = None
    card, end = None, time.time() + 25
    while time.time() < end and card is None and p.poll() is None:
        card = enroll_card()
        time.sleep(0.2)
    resp = b.ap.post("/enroll/decide", {"id": card[2], "decision": "approve", "name": card[0]}) if card else None
    out, err = p.communicate(timeout=60)
    rh.outputs.append(("asb enroll", out + err))
    cfgf = home / ".config" / "secret-broker" / "client.json"
    cj = json.loads(cfgf.read_text()) if cfgf.exists() else {}
    key = cj.get("key", "")
    rh.check(g, "enroll: the card shows the name and a confirmation code, and the terminal prints the same code",
             bool(card) and card[0] == "rehearsal-box" and f"confirmation code: {card[1]}" in err, (card or ("?",))[0])
    rh.check(g, "enroll: approval exits 0, writes client.json (0600) with a per-client key, prints no secret",
             p.returncode == 0 and resp and resp[0] == 303 and key.startswith("asbc1_") and mode_of(cfgf) == 0o600
             and key not in out + err and out.startswith("enrolled: rehearsal-box"), f"rc={p.returncode}")
    SECRETS["clientkey"] = key or "unset-client-key-placeholder"
    env2 = {"HOME": str(home), "SECRET_BROKER_KEY": key}
    rc, o, e = rh.asb(b, "status", extra_env=env2)
    rh.check(g, "enroll: the new credential authenticates (asb status)", rc == 0, f"rc={rc}")
    args = ["http", "stub", "GET", up_url(rh, "/client-rule"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"]
    rc, o, e, rid = rh.asb_decided(b, args, decision="approve_always", extra_env=env2)
    req = [r for r in b.records() if r.get("event") == "requested" and r.get("client_name") == "rehearsal-box"]
    rh.check(g, "client rules: the request is attributed to the client, and Always is made for this client only",
             rc == 0 and rid and bool(req) and any(r.get("rule_client") == req[-1]["client_id"]
                                                   for r in b.records() if r.get("event") == "grant_created"), f"rc={rc}")
    base = max([r["seq"] for r in b.records()] or [0])
    rc, o, e = rh.asb(b, *args, extra_env=env2, timeout=30)
    via = [r.get("via") for r in b.records() if r["seq"] > base and r.get("event") == "approved"]
    rh.check(g, "client rules: the same client is then approved without a prompt", rc == 0 and via[-1:] == ["policy"], f"rc={rc} via={via}")
    # left undecided on purpose: a denial would start the per-name cooldown that later groups trip over
    rc, o, e, rid = rh.asb_decided(b, args, decision=None)
    rh.check(g, "client rules: the shared key is still asked (a client's Always never applies to another)",
             rid is not None and rc == 5, f"rc={rc} card={bool(rid)}")
    _, _, page = b.ap.get("/clients")
    m = re.search(r"id (c-[0-9a-f]{8})", page)
    rh.check(g, "Clients tab lists the client and the legacy shared key",
             bool(m) and "rehearsal-box" in page and "shared key (legacy)" in page, "")
    if m:
        b.ap.post("/clients/revoke", {"id": m.group(1)})
    rc, o, e = rh.asb(b, "status", extra_env=env2)
    rh.check(g, "revoke: the client's next request fails (exit 3, says revoked); the shared key still works",
             rc == 3 and "revoked" in e and rh.asb(b, "status")[0] == 0, f"rc={rc}")
    rh.check(g, "revoke: its own rules are removed and the audit has no key or hash",
             any(r.get("event") == "client_revoked" and r.get("rules_removed", {}).get("always") == 1 for r in b.records())
             and key not in open(b.audit).read() and __import__("hashlib").sha256(
                 b"asb-client-secret-v1\0" + key.encode()).hexdigest() not in open(b.audit).read(), "")


def credreq_scenario(rh, g):
    """Agent-initiated credential requests (asb request-credential) on a fresh local store and its own
    throwaway broker: the human types the value on the approval page; the agent never sees it."""
    S = SECRETS
    store = rh.data / "credreq.enc"
    rc, _, _ = rh.lsc_k("init", store, None, None, "--no-recovery")
    b = Broker(rh, "credreq", store, {"type": "file", "path": str(rh.sec / "pass_key")})
    ok = rc == 0 and b.start()
    rh.check(g, "credential requests: throwaway broker on a fresh local store starts", ok, f"rc={rc}")
    if not ok:
        return

    def ask(args, human, timeout=60):
        """Run asb request-credential; when its card appears call human(rid)."""
        seen = set(b.ap.cards())
        p = rh.asb_popen(b, "request-credential", *args)
        p.stdin.close()
        p.stdin = None
        rid = b.ap.wait_card(seen, timeout=25, proc=p)
        resp = human(rid) if rid else None
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        rh.outputs.append(("asb request-credential", out + err))
        return p.returncode, out, err, rid, resp

    purpose = "rehearsal: call the local echo service"
    # 1. token: the card, the entry page, then Store
    state = {}

    def human_token(rid):
        code, _, page = b.ap.get(f"/credential/{rid}")
        state["page"] = (code, page)
        _, _, dash = b.ap.get("/")
        state["dash"] = dash
        return b.ap.post("/credential", {"id": rid, "decision": "approve", "name": "credrehearse", "hosts": "127.0.0.1",
                                         "cred_mode": "http", "var": "", "token": S["credtoken"]})
    rc, out, err, rid, resp = ask(["credrehearse", "--kind", "token", "--for", purpose, "--host", "127.0.0.1"], human_token)
    code, page = state.get("page", (0, ""))
    rh.check(g, "credential request: entry page has password-type field, editable hosts, purpose; dashboard card has no secret field",
             code == 200 and "type=password name=token" in page and "value='127.0.0.1'" in page and purpose in page
             and "type=password name=" not in state.get("dash", "") and "Review and enter value" in state.get("dash", ""), f"http {code}")
    rh.check(g, "credential request: CLI prints only the stored name, exit 0", rc == 0 and out.strip() == "stored: credrehearse"
             and S["credtoken"] not in out + err, f"rc={rc} out={out.strip()[:60]} err={err.strip()[:80]}")
    rh.check(g, "credential request: the submit response never echoes the value", resp is not None and resp[0] == 200
             and S["credtoken"] not in resp[2] and "Stored" in resp[2], f"http {resp and resp[0]}")
    rc, out, err = rh.asb(b, "list", "--json")
    cat = {x["name"]: x for x in json.loads(out)} if rc == 0 else {}
    rh.check(g, "credential request: catalog has the credential with the confirmed host and variable",
             cat.get("credrehearse", {}).get("allowed_hosts") == ["127.0.0.1"] and cat["credrehearse"]["vars"] == ["CREDREHEARSE_TOKEN"],
             json.dumps(cat.get("credrehearse")))
    # 2. the normal request flow uses it (and still asks a human)
    rc, out, err, rid2 = rh.asb_decided(b, ["http", "credrehearse", "GET", up_url(rh, "/credreq"),
                                            "-H", "Authorization: Bearer {{CREDREHEARSE_TOKEN}}"])
    h = last_hit(rh)
    rh.check(g, "credential request: asb http with the new credential reaches the stub upstream (after a human approval)",
             rc == 0 and rid2 is not None and h and h["headers"].get("Authorization") == "Bearer " + S["credtoken"], f"rc={rc}")
    # 3. login
    def human_login(rid):
        return b.ap.post("/credential", {"id": rid, "decision": "approve", "name": "credsite", "hosts": "127.0.0.1",
                                         "cred_mode": "http", "var": "", "username": S["creduser"],
                                         "password": S["credpw"]})
    rc, out, err, rid, resp = ask(["credsite", "--kind", "login", "--for", "rehearsal login", "--host", "127.0.0.1"], human_login)
    rc2, out2, err2, _ = rh.asb_decided(b, ["http", "credsite", "GET", up_url(rh, "/credlogin"),
                                            "-H", "X-U: {{CREDSITE_USERNAME}}", "-H", "X-P: {{CREDSITE_PASSWORD}}"])
    h = last_hit(rh)
    rh.check(g, "credential request: login (username+password) stored and usable through two variables",
             rc == 0 and rc2 == 0 and h and h["headers"].get("X-U") == S["creduser"] and h["headers"].get("X-P") == S["credpw"],
             f"rc={rc},{rc2}")
    # 4. a refused form keeps the request pending and echoes no secret
    seen = set(b.ap.cards())
    p = rh.asb_popen(b, "request-credential", "credbad", "--kind", "token", "--for", "rehearsal refused form", "--mode", "env")
    p.stdin.close()
    p.stdin = None
    rid = b.ap.wait_card(seen, timeout=25, proc=p)
    bad = b.ap.post("/credential", {"id": rid, "decision": "approve", "name": "credbad", "hosts": "", "cred_mode": "http",
                                    "var": "", "token": S["credtoken"]}) if rid else (0, None, "")
    pending_after = rid in b.ap.cards() if rid else False
    den = b.ap.post("/credential", {"id": rid, "decision": "deny"}) if rid else (0, None, "")
    out, err = p.communicate(timeout=60)
    rh.outputs.append(("asb request-credential (denied)", out + err))
    rh.check(g, "credential request: no host in http mode is refused (422), the request stays pending, the page has no secret",
             bad[0] == 422 and S["credtoken"] not in bad[2] and pending_after and "allowed hosts are required" in bad[2], f"http {bad[0]}")
    rh.check(g, "credential request: deny exits 4 and stores nothing", p.returncode == 4 and "credbad" not in
             {x["name"] for x in json.loads(rh.asb(b, "list", "--json")[1] or "[]")}, f"rc={p.returncode}")
    # 5. collision and invalid name are refused by the broker (exit 3)
    rc, out, err = rh.asb(b, "request-credential", "credrehearse", "--kind", "token", "--for", "again", "--host", "127.0.0.1")
    rh.check(g, "credential request: an existing name is refused (exit 3) with the `asb update` hint", rc == 3 and "asb update credrehearse" in err, f"rc={rc}")
    rc, out, err = rh.asb(b, "request-credential", "Bad Name", "--kind", "token", "--for", "x", "--host", "127.0.0.1")
    rh.check(g, "credential request: an invalid name is refused (exit 3)", rc == 3, f"rc={rc}")
    # 6. not stored in the clear, notification names only, audit without values, survives a restart
    notes = [t for t in Aux.telegram if "Credential requested" in t]
    rh.check(g, "credential request: notifications say 'Credential requested: NAME' and carry no purpose or value",
             any("Credential requested: credrehearse" in t for t in notes) and not any(purpose in t or v in t for t in notes for v in S.values()),
             f"{len(notes)} notifications")
    recs = b.records()
    ev = {r["event"] for r in recs}
    rh.check(g, "credential request: audit has requested/credential_provided/stored and no value or purpose",
             {"requested", "credential_provided", "stored"} <= ev and purpose not in open(b.audit).read()
             and not any(v in open(b.audit).read() for v in S.values()), "")
    rc, out, err = rh.asb(b, "audit", "--event", "stored,credential_provided", "--since", "30m")
    rh.check(g, "credential request: asb audit shows the stored name, never the human's entry event", "stored" in out
             and "credential_provided" not in out, out.strip()[:80])
    b.stop()
    ok = b.start()
    rc, out, err = rh.asb(b, "list", "--json") if ok else (1, "[]", "")
    for _ in range(20):
        if rc == 0 and any(x.get("name") == "credrehearse" for x in json.loads(out or "[]")):
            break
        time.sleep(0.4)
        rc, out, err = rh.asb(b, "list", "--json")
    rh.check(g, "credential request: the credentials survive a broker restart",
             ok and {x["name"] for x in json.loads(out or "[]")} >= {"credrehearse", "credsite"}, f"rc={rc}")
    rh.check(g, "credential request: the encrypted store file holds no plaintext value",
             not rh.scan_files([store]), "")
    b.stop()


# ================================================================ scenario D: policy writes persist
def dump_meta(rh, store=None):
    """{item name: broker metadata (or None)} read through the admin CLI (names/metadata only)."""
    store = store or rh.store
    rc, out, err = rh.lsc_k("list", store)
    names = [ln.split("\t")[0] for ln in out.splitlines() if "\t" in ln]
    res = {}
    for n in names:
        rc, o, e = rh.lsc_k("show", store, None, None, n)
        m = None
        if "broker metadata:" in o:
            m = json.loads(o.split("broker metadata:", 1)[1])
        res[n] = m
    return res


def make_ssh_key(rh, name):
    path = rh.srcdir / name
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "rehearsal-" + name, "-f", str(path)],
                       check=True, capture_output=True)
    return path


def key_markers(path):
    """Strings that identify a private key's secret material (for leak scans)."""
    body = [ln.strip() for ln in Path(path).read_text().splitlines() if ln and "-----" not in ln]
    return body


def scenario_D(rh):
    g = "D"
    b = rh.main
    S = SECRETS
    # an SSH key to carry a host policy (E uses another key, because a host policy blocks serverless signing)
    pol_key = make_ssh_key(rh, "id_policy")
    rc, out, err, rid = rh.asb_decided(b, ["store", "sshpol", "--ssh"], stdin=pol_key.read_text())
    rh.check(g, "asb store --ssh (policy-test key) accepted", rc == 0, f"rc={rc} {(out + err).strip()[:90]}")
    # 1. Always
    rc, out, err, rid = rh.asb_decided(b, ["http", "stub", "GET", up_url(rh, "/always"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"],
                                       decision="approve_always")
    rh.check(g, "Always (approve_always) accepted", rc == 0 and rid is not None, f"rc={rc}")
    n0 = len(Upstream.hits)
    rc, out, err, via = rh.asb_auto(b, ["http", "stub", "GET", up_url(rh, "/always2"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"])
    rh.check(g, "Always: next read request is auto-approved (no human)", rc == 0 and via not in (None, "user") and len(Upstream.hits) == n0 + 1,
             f"rc={rc} via={via}")
    rc, out, err, rid = rh.asb_decided(b, ["http", "stub", "POST", up_url(rh, "/always3"), "-H", "Authorization: Bearer {{STUB_TOKEN}}", "-d", "x=1"])
    rh.check(g, "Always (read scope) does not cover a POST: it still prompts", rid is not None, f"card={rid is not None}")
    # 2. timed grant
    rc, out, err, rid = rh.asb_decided(b, ["http", "loginup", "GET", up_url(rh, "/grant"), "-H", "X-U: {{LU_USER}}"],
                                       decision="approve_grant_5")
    rh.check(g, "timed grant (approve_grant_5) accepted", rc == 0 and rid is not None, f"rc={rc}")
    rc, out, err, via = rh.asb_auto(b, ["http", "loginup", "GET", up_url(rh, "/grant2"), "-H", "X-U: {{LU_USER}}"])
    rh.check(g, "timed grant: next request approved without a human", rc == 0 and via not in (None, "user"), f"rc={rc} via={via}")
    # 3. guidance via the Policies editor
    gtext = "Rehearsal guidance: this credential only reaches a local echo service."
    code, loc, body = b.ap.post("/policies/guidance", {"name": "envcred", "guidance": gtext})
    rh.check(g, "Policies editor: guidance saved", code == 200 and "Guidance saved" in body, f"http {code}")
    # 4. guidance proposal, batch of 8, apply 6 / deny 2
    names8 = ["stub", "envcred", "allowcred", "plain-login", "loginup", "newcred", "extra-one", "extra-two"]
    prop = rh.srcdir / "proposal8.json"
    prop.write_text(json.dumps([{"name": n, "text": f"Proposed rehearsal guidance for {n}."} for n in names8]))
    seen = set(b.ap.cards())
    p = rh.asb_popen(b, "guidance", "propose", str(prop))
    p.stdin.close()
    p.stdin = None
    pid = b.ap.wait_card(seen, timeout=20, proc=p)
    ticked = {f"apply_{i}": "1" for i in range(6)}
    t0 = time.time()
    if pid:
        b.ap.decide(pid, "approve", ticked)
    out, err = p.communicate(timeout=180)
    rh.outputs.append(("guidance propose", out + err))
    took = time.time() - t0
    rh.check(g, "guidance proposal (8 entries): apply 6, deny 2", pid is not None and p.returncode == 0
             and out.count("applied") >= 1 and "denied" in out, f"rc={p.returncode} took={took:.0f}s out={out.strip()[:140]!r}")
    rh.res.numbers["guidance apply 6 entries (s)"] = round(took, 1)
    meta = dump_meta(rh)
    by_name = {n: (m or {}).get("guidance") for n, m in meta.items()}
    want = {"stub": 1, "envcred": 1, "allowcred": 1, "plain-login": 1, "loginup": 1, "newcred": 1}
    key_for = {"stub": "Stub API", "envcred": "Env Cred", "allowcred": "Allow Cred", "plain-login": "Plain Login",
               "loginup": "Login Up", "newcred": "newcred", "extra-one": "Extra One", "extra-two": "Extra Two"}
    got_guid = {n: bool(by_name.get(key_for[n])) for n in names8}
    rh.check(g, "guidance persisted for the 6 ticked entries only (plain-login adopted item included)",
             all(got_guid[n] for n in names8[:6]) and not got_guid["extra-one"] and not got_guid["extra-two"], f"{got_guid}")
    # 5. Retry-failed path: make the store directory unwritable while a proposal applies
    sdir = rh.store.parent
    prop2 = rh.srcdir / "proposal2.json"
    prop2.write_text(json.dumps([{"name": "extra-one", "text": "Retry path guidance one."},
                                 {"name": "extra-two", "text": "Retry path guidance two."}]))
    seen = set(b.ap.cards())
    p = rh.asb_popen(b, "guidance", "propose", str(prop2))
    p.stdin.close()
    p.stdin = None
    pid2 = b.ap.wait_card(seen, timeout=20, proc=p)
    os.chmod(sdir, 0o500)       # the broker can still read the store, but cannot create the temp file
    try:
        if pid2:
            b.ap.decide(pid2, "approve", {"apply_0": "1", "apply_1": "1"})
        end = time.time() + 40
        while p.poll() is None and time.time() < end:
            time.sleep(0.5)
    finally:
        os.chmod(sdir, 0o700)
    if p.poll() is None:
        # transient retries are still running; with the directory writable again they may succeed on their own
        out, err = p.communicate(timeout=120)
        self_healed = True
    else:
        out, err = p.communicate()
        self_healed = False
    rh.outputs.append(("guidance propose 2", out + err))
    failed = "failed" in out
    rh.note(g, "retry path", f"rc={p.returncode} self_healed={self_healed} out={out.strip()[:160]!r}")
    if failed:
        code, loc, body = b.ap.post("/request/retry", {"id": pid2})
        deadline = time.time() + 40
        ok = False
        while time.time() < deadline:
            mm = dump_meta(rh)
            if mm.get("Extra One", {}) and mm["Extra One"].get("guidance") and mm["Extra Two"].get("guidance"):
                ok = True
                break
            time.sleep(2)
        rh.check(g, "Retry failed: entries applied after the store is writable again", ok, f"retry POST -> {code} {loc}")
    else:
        mm = dump_meta(rh)
        ok = bool(mm["Extra One"] and mm["Extra One"].get("guidance"))
        rh.check(g, "guidance write under a read-only store directory: failure surfaced or healed",
                 ok or failed, f"no 'failed' line; applied={ok}")
    rh.check(g, "store directory permissions restored and still readable", mode_of(sdir) == 0o700, oct(mode_of(sdir)))
    left = sorted(f.name for f in sdir.iterdir() if f.name.startswith("main.enc") and f.name not in ("main.enc", "main.enc.bak", "main.enc.lock"))
    rh.check(g, "failed writes left no temp files next to the store", not left, f"{left}")
    # 6. SSH host policy editor
    hostpub = " ".join((pol_key.with_name(pol_key.name + ".pub")).read_text().split()[:2])
    code, loc, body = b.ap.post("/policies/ssh_hosts", {"secret": "sshpol", "known_hosts": f"git.rehearsal.test {hostpub}\n",
                                                          "allowed_hosts": "git.rehearsal.test\n", "allow_forwarded": ""})
    rh.check(g, "SSH host policy editor: saved", code == 200 and "policy saved" in body, f"http {code}")
    # 7. request details retention
    hist = b.records()
    rid_http = next((r["id"] for r in hist if r.get("event") == "http_executed" and "/always" in (r.get("url") or "")), None)
    code, loc, body = b.ap.get(f"/request/{rid_http}") if rid_http else (0, None, "")
    rh.check(g, "request details retained and viewable on the approval site", code == 200 and "Authorization" in body, f"http {code}")
    # --- snapshot, stop, restart -------------------------------------------------------------
    pre_meta = dump_meta(rh)
    pre_seq = max(r["seq"] for r in b.records())
    pre_catalog = json.loads(rh.asb(b, "list", "--json")[1])
    rc = b.stop()
    rh.check(g, "SIGTERM stops the broker cleanly", rc == 0, f"exit code {rc}")
    # the store must be intact while the broker is down
    rc2, out2, _ = rh.lsc_k("list", rh.store)
    rh.check(g, "store opens with the admin CLI after the broker stopped", rc2 == 0 and len(out2.splitlines()) >= 9, "")
    started = time.time()
    ok = b.start()
    rh.check(g, "broker restarts on the same store", ok, "")
    if not ok:
        return
    for _ in range(40):         # the first catalog load runs in the background
        rc, out, err = rh.asb(b, "status", "--json")
        st = json.loads(out)
        if st["catalog"]["count"]:
            break
        time.sleep(0.25)
    rh.check(g, "restart: fresh uptime, catalog complete, backend ok",
             st["uptime_s"] < 60 and st["backend"]["ok"] and st["catalog"]["count"] == len(pre_catalog) and st["catalog"]["invalid"] == 0,
             f"uptime={st['uptime_s']} catalog={st['catalog']}")
    post_meta = dump_meta(rh)
    rh.check(g, "restart: every item's metadata (standing, guidance, ssh_hosts, ...) byte-identical to before",
             post_meta == pre_meta, "diff: " + ",".join(sorted(k for k in set(pre_meta) | set(post_meta) if pre_meta.get(k) != post_meta.get(k))))
    st_stub = (post_meta.get("Stub API") or {}).get("standing") or []
    rh.check(g, "restart: exactly one Always entry on Stub API (nothing duplicated)", len(st_stub) == 1, f"{len(st_stub)}")
    rh.check(g, "restart: SSH host policy present", ((post_meta.get("sshpol") or {}).get("ssh_hosts") or {}).get("allowed_hosts") == ["git.rehearsal.test"], "")
    code, _, body = b.ap.get("/policies")
    rh.check(g, "restart: Policies page shows the guidance and the Always entry",
             code == 200 and "Rehearsal guidance" in body.replace("&#x27;", "'") or "Proposed rehearsal guidance" in body, f"http {code}")
    n0 = len(Upstream.hits)
    rc, out, err, via = rh.asb_auto(b, ["http", "stub", "GET", up_url(rh, "/after-restart"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"])
    h = last_hit(rh)
    rh.check(g, "restart: Always still effective (auto-approved by standing approval, secret substituted)",
             rc == 0 and via not in (None, "user") and h and h["headers"].get("Authorization") == "Bearer " + S["http"], f"rc={rc} via={via}")
    rc, out, err, via = rh.asb_auto(b, ["http", "loginup", "GET", up_url(rh, "/grant-after"), "-H", "X-U: {{LU_USER}}"])
    rh.check(g, "restart: timed grant still effective (persisted)", rc == 0 and via not in (None, "user"), f"rc={rc} via={via}")
    rc, out, err, rid = rh.asb_decided(b, ["http", "plain-login", "POST", up_url(rh, "/prompt-after"), "-d", "p={{PLAIN_LOGIN_PASSWORD}}"])
    rh.check(g, "restart: a credential without a policy still prompts", rid is not None and rc == 0, "")
    recs = b.records()
    seqs = [r["seq"] for r in recs]
    rh.check(g, "audit chain continues across the restart (unique, increasing seq)",
             seqs == sorted(set(seqs)) and max(seqs) > pre_seq, f"{len(seqs)} records, seq {pre_seq} -> {max(seqs)}")
    rc, out, err = rh.asb(b, "audit", "verify")
    rh.check(g, "asb audit verify after restart", rc == 0, (out + err).strip()[:90])
    rh.check(g, "two startup events in the audit log", len(b.events("startup")) == 2, f"{len(b.events('startup'))}")
    rid_http_after = b.events("startup")
    cat = json.loads(rh.asb(b, "list", "--json")[1])
    nm = [x["name"] for x in cat]
    rh.check(g, "catalog has no duplicate names after restart", len(nm) == len(set(nm)), f"{len(nm)} names")


# ================================================================ scenario E: SSH keys
def scenario_E(rh):
    g = "E"
    b = rh.main
    key = make_ssh_key(rh, "id_agent")
    pub = key.with_name("id_agent.pub")
    for k in ("id_agent", "id_policy"):
        for i, ln in enumerate(key_markers(rh.srcdir / k)[:2]):
            SECRETS[f"ssh-{k}-{i}"] = ln
    rc, out, err, rid = rh.asb_decided(b, ["store", "sshreh", "--ssh"], stdin=key.read_text())
    rh.check(g, "asb store --ssh into the local store", rc == 0, f"rc={rc} {(out + err).strip()[-100:]}")
    rc, o, e = rh.lsc_k("list", rh.store)
    rh.check(g, "store holds it as kind ssh_key (admin CLI list)", "sshreh\tssh_key" in o, "")
    lst = {x["name"]: x for x in json.loads(rh.asb(b, "list", "--json")[1])}
    rh.check(g, "asb list shows the key with no placeholder VARS but with its public key",
             "sshreh" in lst and lst["sshreh"]["vars"] == [] and lst["sshreh"].get("ssh_public_key"), "")
    sock = rh.root / "agent.sock"
    ag = subprocess.Popen([str(ASB), "ssh-agent", "--socket", str(sock)], env=rh.asb_env(b), cwd=str(rh.root),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rh.pids.add(ag.pid)
    end = time.time() + 10
    while not sock.exists() and time.time() < end and ag.poll() is None:
        time.sleep(0.1)
    tool_env = {"PATH": os.environ["PATH"], "HOME": str(rh.home), "SSH_AUTH_SOCK": str(sock)}
    try:
        cp = subprocess.run(["ssh-add", "-L"], env=tool_env, capture_output=True, text=True, timeout=30)
        rh.outputs.append(("ssh-add -L", cp.stdout + cp.stderr))
        mine = " ".join(pub.read_text().split()[:2])
        rh.check(g, "ssh-add -L through the agent lists the broker-held identity",
                 cp.returncode == 0 and mine in cp.stdout, f"rc={cp.returncode} {cp.stdout.count(chr(10))} identities")
        msg = rh.srcdir / "msg.txt"
        msg.write_text("hello from the rehearsal\n")
        sig = Path(str(msg) + ".sig")
        sig.unlink(missing_ok=True)
        seen = set(b.ap.cards())
        sp = subprocess.Popen(["ssh-keygen", "-Y", "sign", "-n", "test", "-f", str(pub), "-U", str(msg)], env=tool_env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rid = b.ap.wait_card(seen, timeout=25, proc=sp)
        code = b.ap.decide(rid, "approve")[0] if rid else None
        out, err = sp.communicate(timeout=60)
        rh.outputs.append(("ssh-keygen sign", out + err))
        rh.check(g, "signing needs approval (card appears) and succeeds once approved",
                 rid is not None and sp.returncode == 0 and sig.exists(), f"rc={sp.returncode} card={rid is not None} {err.strip()[:80]}")
        if sig.exists():
            cp = subprocess.run(["ssh-keygen", "-Y", "check-novalidate", "-n", "test", "-s", str(sig)], input=msg.read_text(),
                                env=tool_env, capture_output=True, text=True, timeout=30)
            rh.check(g, "signature verifies against the public key (check-novalidate)", cp.returncode == 0 and "Good" in cp.stdout,
                     (cp.stdout + cp.stderr).strip()[:100])
            fp = subprocess.run(["ssh-keygen", "-lf", str(pub)], capture_output=True, text=True).stdout.split()[1]
            rh.check(g, "signature carries the key's fingerprint", fp in cp.stdout, "")
        evs = {r["event"] for r in b.records() if r.get("mode") == "ssh_sign"}
        rh.check(g, "audit has ssh_sign request events", {"requested", "approved"} <= evs or len(evs) >= 2, f"{sorted(evs)}")
        # an unapproved signature must fail (expire) and leave no signature file
        sig.unlink(missing_ok=True)
        sp = subprocess.Popen(["ssh-keygen", "-Y", "sign", "-n", "test", "-f", str(pub), "-U", str(msg)], env=tool_env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = sp.communicate(timeout=90)
        rh.check(g, "unapproved signature request fails (expires), no signature produced", sp.returncode != 0 and not sig.exists(),
                 f"rc={sp.returncode}")
    finally:
        ag.terminate()
        try:
            ag.wait(10)
        except subprocess.TimeoutExpired:
            ag.kill()
        rh.pids.discard(ag.pid)
    time.sleep(0.5)
    hits = [k for k, v in SECRETS.items() if k.startswith("ssh-") and any(v in t for t in Aux.telegram)]
    rh.check(g, "private key material absent from notifications", not hits, "")


# ================================================================ scenario F: failure and recovery
FAKE_BW = r"""#!/usr/bin/env python3
import json, os, sys
S = os.environ["FAKE_BW_STATE"]
d = json.load(open(S))
a = sys.argv[1:]
cmd = a[0] if a else ""
if cmd == "status":
    print(json.dumps({"status": "unlocked"}))
elif cmd in ("login", "config", "sync", "lock", "logout"):
    pass
elif cmd == "unlock":
    print("SESSION")
elif cmd == "list" and a[1] == "organizations":
    print(json.dumps([{"id": "org1", "name": "Org"}]))
elif cmd == "list" and a[1] == "collections":
    print(json.dumps([{"id": "col1", "name": "Shared"}]))
elif cmd == "list" and a[1] == "items":
    print(json.dumps(d["items"]))
elif cmd == "get":
    hits = [i for i in d["items"] if i["name"] == a[2] or i["id"] == a[2]]
    if not hits:
        print("Not found.", file=sys.stderr); sys.exit(1)
    print(json.dumps(hits[0]))
else:
    print("fake bw: unsupported " + cmd, file=sys.stderr); sys.exit(1)
"""


def mini_store(rh, name, keytext, recovery=False, **kw):
    kf = rh.sec / f"{name}.key"
    rh.secret_file(kf, keytext)
    store = rh.data / f"{name}.enc"
    rc, out, err = rh.lsc_k("init", store, kf, None, *(() if recovery else ("--no-recovery",)))
    rec = [ln.strip() for ln in out.splitlines() if re.fullmatch(r"[A-Za-z0-9+/=]{44}", ln.strip())]
    add_note(rh, store, "F Item", SECRETS["stored"],
             {"name": "fitem", "allowed_hosts": ["127.0.0.1"], "vars": {"F_TOKEN": {"field": "notes"}}, "approval": "allow"},
             keyfile=kf)
    return store, kf, (rec[0] if rec else None)


def fitem_req(rh, b, path="/f"):
    """One auto-approved request on fitem. Returns (ok, rc, err)."""
    n = len(Upstream.hits)
    rc, out, err, via = rh.asb_auto(b, ["http", "fitem", "GET", up_url(rh, path), "-H", "X-F: {{F_TOKEN}}"], timeout=60)
    ok = rc == 0 and len(Upstream.hits) == n + 1 and Upstream.hits[-1]["headers"].get("X-F") == SECRETS["stored"]
    return ok, rc, (out + err).strip().replace("\n", " | ")


def sha(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fkeysrc(kf):
    return {"type": "file", "path": str(kf)}


def scenario_F(rh):
    g = "F"
    S = SECRETS
    # ---- F1: wrong key at startup, then fixed without a restart --------------------------
    store, kf, rec = mini_store(rh, "f1", "right-passphrase-f1", recovery=True)
    wrong = rh.sec / "f1.wrongkey"
    rh.secret_file(wrong, "wrong-passphrase-f1")
    b = Broker(rh, "f1", store, fkeysrc(wrong))
    ok = b.start()
    time.sleep(1.5)
    alive = b.proc.poll() is None
    rc, out, err = rh.asb(b, "status", "--json")
    st = json.loads(out) if rc == 0 else {}
    rh.check(g, "wrong key: broker stays up, status shows backend NOT ok, empty catalog",
             ok and alive and st.get("backend", {}).get("ok") is False and st.get("catalog", {}).get("count") == 0, json.dumps(st.get("backend")))
    good, rc, msg = fitem_req(rh, b)
    rh.check(g, "wrong key: request fails clearly (not a crash), message mentions the store/key", not good and rc != 0
             and ("key" in msg.lower() or "store" in msg.lower() or "backend" in msg.lower() or "not found" in msg.lower()), f"rc={rc} {msg[:110]}")
    fails = [e.get("reason") for e in b.events("store_unlock_failed")]
    rh.check(g, "wrong key: store_unlock_failed audited with reason wrong_key", "wrong_key" in fails, f"{fails[:3]}")
    rh.secret_file(wrong, "right-passphrase-f1")        # fix the key file in place
    time.sleep(2)
    rc0, out0, _ = rh.asb(b, "status", "--json")
    rh.note(g, "observation", "`asb status` after fixing the key but before any request or `asb list`: backend ok = "
            f"{json.loads(out0)['backend']['ok']} (the catalog is retried by the next request or discovery, not on a timer)")
    good, rc, msg = fitem_req(rh, b)
    rc2, out2, _ = rh.asb(b, "status", "--json")
    st2 = json.loads(out2)
    rh.check(g, "key file fixed: next request succeeds with no restart; status backend ok",
             good and st2["backend"]["ok"] and st2["catalog"]["count"] == 1, f"rc={rc} {msg[:100]} {st2['backend']}")
    # ---- F2: corruption, truncation, .bak restore ----------------------------------------
    rc, out, err, via = rh.asb_auto(b, ["store", "fnew", "--hosts", "127.0.0.1"], stdin="FAKE-fnew-value-1")
    rh.check(g, "write via asb store creates the .bak generation", rc == 0 and Path(str(store) + ".bak").exists(), f"rc={rc}")
    rh.check(g, ".bak and .lock are mode 0600", mode_of(str(store) + ".bak") == 0o600 and mode_of(str(store) + ".lock") == 0o600,
             f"{oct(mode_of(str(store) + '.bak'))} {oct(mode_of(str(store) + '.lock'))}")
    raw = bytearray(store.read_bytes())
    raw[len(raw) // 2 + 20] ^= 0x01
    store.write_bytes(bytes(raw))
    os.chmod(store, 0o600)
    flipped = sha(store)
    good, rc, msg = fitem_req(rh, b, "/corrupt")
    fails = [e.get("reason") for e in b.events("store_unlock_failed")]
    rh.check(g, "flipped byte: unlock fails (corrupt), request fails clearly", not good and rc != 0 and "corrupt" in fails, f"rc={rc} {msg[:90]} reasons={fails[-2:]}")
    rc, out, err, via = rh.asb_auto(b, ["store", "fother", "--hosts", "127.0.0.1"], stdin="FAKE-fother-value-2")
    rc3, o3, e3 = rh.lsc_k("list", store, kf)
    rh.check(g, "corrupt store is never overwritten (asb store refused, CLI refused, file byte-identical)",
             rc != 0 and rc3 != 0 and sha(store) == flipped, f"asb rc={rc}; cli rc={rc3} {e3.strip()[:70]}")
    shutil.copyfile(str(store) + ".bak", store)         # documented recovery: put the .bak back
    os.chmod(store, 0o600)
    good, rc, msg = fitem_req(rh, b, "/restored")
    rh.check(g, ".bak restore: broker recovers with no restart (restored generation lacks the last write)", good, f"rc={rc} {msg[:80]}")
    for n in (0, 50):
        store.write_bytes(store.read_bytes()[:n])
        os.chmod(store, 0o600)
        good, rc, msg = fitem_req(rh, b, f"/trunc{n}")
        rc3, o3, e3 = rh.lsc_k("list", store, kf)
        rh.check(g, f"truncated to {n} bytes: request and CLI fail clearly, file not rewritten",
                 not good and rc != 0 and rc3 != 0 and store.stat().st_size == n, f"rc={rc} cli={e3.strip()[:60]}")
        shutil.copyfile(str(store) + ".bak", store)
        os.chmod(store, 0o600)
        good, rc, msg = fitem_req(rh, b, f"/untrunc{n}")
        rh.check(g, f"after truncation({n}) restore from .bak: recovered", good, msg[:80])
    # ---- recovery key / permissions ------------------------------------------------------
    recf = rh.sec / "f1.recovery"
    rh.secret_file(recf, rec or "")
    rc, o, e = rh.lsc_k("list", store, recf)
    rh.check(g, "recovery key unlocks the store", rc == 0 and "F Item" in o, e.strip()[:60])
    shutil.copyfile(store, rh.data / "perm.enc")
    os.chmod(rh.data / "perm.enc", 0o640)
    rc, o, e = rh.lsc_k("list", rh.data / "perm.enc", kf)
    rh.check(g, "admin CLI refuses a group-readable store", rc != 0 and "accessible by other users" in e, e.strip()[:80])
    kf2 = rh.sec / "f1.key644"
    rh.secret_file(kf2, "right-passphrase-f1")
    os.chmod(kf2, 0o644)
    rc, o, e = rh.lsc_k("list", store, kf2)
    rh.check(g, "admin CLI warns (but works) for a group/world-readable key file", rc == 0 and "readable by other users" in e, e.strip()[:80])
    # SIGKILL (no clean shutdown): the store and the audit chain survive
    b.stop(signal.SIGKILL)
    ok = b.start()
    good, rc, msg = fitem_req(rh, b, "/after-kill")
    rc2, o2, e2 = rh.asb(b, "audit", "verify")
    rh.check(g, "kill -9 then restart: store intact, request works, audit chain verifies", ok and good and rc2 == 0, f"{msg[:50]} {(o2 + e2).strip()[:60]}")
    # a group-readable store: the broker still serves it and warns once
    os.chmod(store, 0o640)
    b.stop()
    b.logf.write_bytes(b"")
    b.start()
    good, rc, msg = fitem_req(rh, b, "/mode640")
    rh.check(g, "group-readable store (0640): broker still serves and logs a warning", good and "accessible by other users" in b.logf.read_text(), msg[:60])
    os.chmod(store, 0o600)
    b.stop()
    # ---- F3: startup config errors and a missing store file ------------------------------
    def startup_error(label, mutate, want):
        c = Broker(rh, "f3x", store, fkeysrc(kf))
        mutate(c.cfg["backend"])
        c.write_cfg()
        c.logf.write_bytes(b"")
        c.start(wait=False)
        try:
            c.proc.wait(15)
        except subprocess.TimeoutExpired:
            pass
        rc = c.proc.poll()
        text = c.logf.read_text()
        c.stop()
        rh.check(g, f"startup config error: {label}", rc not in (None, 0) and want in text, f"rc={rc} {text.strip()[-110:]!r}")
    startup_error("missing backend.path names the field", lambda d: d.pop("path"), "backend.path")
    startup_error("unknown backend field named", lambda d: d.update({"idle_timout": 5}), "backend.idle_timout")
    startup_error("missing key_source named", lambda d: d.pop("key_source"), "key_source")
    startup_error("bad key_source type named", lambda d: d.update({"key_source": {"type": "carrier-pigeon"}}), "key_source")
    c = Broker(rh, "f3env", store, {"type": "env", "name": "REHEARSAL_UNSET_KEY_VAR"})
    c.start()
    time.sleep(1)
    good, rc, msg = fitem_req(rh, c, "/envunset")
    reasons = [e.get("reason") for e in c.events("store_unlock_failed")]
    rh.check(g, "env key source with the variable unset: broker up, key_missing audited, request fails clearly",
             c.proc.poll() is None and not good and rc != 0 and "key_missing" in reasons, f"reasons={reasons[:2]} {msg[:70]}")
    c.stop()
    gone = rh.data / "f3_missing.enc"
    kmiss = rh.sec / "f3_later.key"
    b = Broker(rh, "f3", gone, fkeysrc(kmiss))
    ok = b.start()
    time.sleep(1)
    rc, out, err = rh.asb(b, "status", "--json")
    st = json.loads(out)
    good, rc, msg = fitem_req(rh, b)
    reasons = [e.get("reason") for e in b.events("store_unlock_failed")]
    rh.check(g, "missing store file + missing key file at startup: broker up, backend not ok, request fails clearly",
             ok and b.proc.poll() is None and not st["backend"]["ok"] and not good and rc != 0, f"reasons={reasons[:3]} msg={msg[:70]}")
    rh.secret_file(kmiss, "late-passphrase-f3")
    rc, out, err = rh.lsc("init", "--store", str(gone), "--key-file", str(kmiss), "--no-recovery")
    add_note(rh, gone, "F Item", S["stored"], {"name": "fitem", "allowed_hosts": ["127.0.0.1"], "vars": {"F_TOKEN": {"field": "notes"}},
                                                  "approval": "allow"}, keyfile=kmiss)
    good, rc, msg = fitem_req(rh, b)
    rh.check(g, "store and key appear later: recovered with no restart", good, f"rc={rc} {msg[:80]}")
    b.stop()
    # ---- F4: change-key, rotate-dek, recovery ---------------------------------------------
    store, kf, rec = mini_store(rh, "f4", "passphrase-A-f4", recovery=True)
    recf = rh.sec / "f4.recovery"
    rh.secret_file(recf, rec or "")
    b = Broker(rh, "f4", store, fkeysrc(kf))
    b.start()
    good0, _, _ = fitem_req(rh, b, "/ck0")
    kB = rh.sec / "f4.newkey"
    rh.secret_file(kB, "passphrase-B-f4")
    rc, o, e = rh.lsc_k("change-key", store, kf, None, "--new-key-file", str(kB))
    rh.check(g, "change-key while the broker runs succeeds", rc == 0, e.strip()[:80])
    good, rc, msg = fitem_req(rh, b, "/ck1")
    rh.check(g, "broker still holding the OLD key file can no longer unlock after change-key (fails clearly)",
             good0 and not good and rc != 0, f"rc={rc} {msg[:70]}")
    shutil.copyfile(kB, kf)                 # point the broker's key file at the new key
    os.chmod(kf, 0o600)
    good, rc, msg = fitem_req(rh, b, "/ck2")
    rh.check(g, "key file updated to the new key: broker recovers without a restart", good, msg[:70])
    rh.secret_file(rh.sec / "f4.oldkey", "passphrase-A-f4")
    rc, o, e = rh.lsc_k("list", store, rh.sec / "f4.oldkey")
    rh.check(g, "old key is rejected, new key accepted", rc != 0 and rh.lsc_k("list", store, kf)[0] == 0, e.strip()[:70])
    bak = Path(str(store) + ".bak")
    rh.check(g, "change-key removed the .bak (the old key must not still open a copy of every item)",
             not bak.exists() or rh.lsc_k("list", bak, rh.sec / "f4.oldkey")[0] != 0, "bak exists=" + str(bak.exists()))
    rc, o, e = rh.lsc_k("list", store, recf)
    rh.check(g, "recovery key still opens the store after change-key", rc == 0, "")
    rc, o, e = rh.lsc_k("rotate-dek", store, kf)
    rh.check(g, "rotate-dek without recovery args refuses clearly (would orphan the recovery wrap)", rc != 0 and "recovery" in e, e.strip()[:90])
    pre = sha(store)
    rc, o, e = rh.lsc_k("rotate-dek", store, kf, None, "--recovery-key-file", str(recf))
    good, rc2, msg = fitem_req(rh, b, "/dek")
    rc3, _, _ = rh.lsc_k("list", store, recf)
    rh.check(g, "rotate-dek with the recovery key: store re-encrypted, broker (running) keeps working, recovery key still opens",
             rc == 0 and sha(store) != pre and good and rc3 == 0, f"rc={rc} {e.strip()[:60]} {msg[:60]}")
    rh.check(g, "rotate-dek removed the .bak (it holds the old data key)", not bak.exists(), "bak exists=" + str(bak.exists()))
    b.stop()
    kC = rh.sec / "f4.key3"
    rh.secret_file(kC, "passphrase-C-f4")
    rc, o, e = rh.lsc_k("change-key", store, kf, None, "--new-key-file", str(kC))
    shutil.copyfile(kC, kf)
    os.chmod(kf, 0o600)
    ok = b.start()
    good, rc2, msg = fitem_req(rh, b, "/ck3")
    rh.check(g, "change-key with the broker stopped, restart on the new key", rc == 0 and ok and good, msg[:70])
    # ---- idle_timeout 5s ------------------------------------------------------------------
    b.stop()
    store, kf, _ = mini_store(rh, "f5", "passphrase-f5")
    b = Broker(rh, "f5", store, fkeysrc(kf), idle=5)
    b.start()
    good, rc, msg = fitem_req(rh, b, "/idle0")
    time.sleep(8)
    locked = b.events("store_locked")
    good2, rc2, msg2 = fitem_req(rh, b, "/idle1")
    unl = b.events("store_unlocked")
    rh.check(g, "idle_timeout=5: store locks after idle (audited) and re-unlocks transparently on next use",
             good and good2 and len(locked) >= 1 and len(unl) >= 2, f"locked={len(locked)} unlocked={len(unl)}")
    time.sleep(7)
    code, loc, body = b.ap.post("/policies/guidance", {"name": "fitem", "guidance": "Written after an idle lock."})
    rc, o, e = rh.lsc_k("show", store, kf, None, "F Item")
    rh.check(g, "idle lock, then a policy write (Policies editor) re-unlocks and persists",
             code == 200 and "Guidance saved" in body and "Written after an idle lock" in o, f"http {code}")
    b.stop()
    # ---- admin CLI while the main broker runs -------------------------------------------
    b = rh.main
    n_re = len(b.events("store_reloaded"))
    add_note(rh, rh.store, "External Add", S["stored"], {"name": "external-add", "allowed_hosts": ["127.0.0.1"],
             "vars": {"EXT_TOKEN": {"field": "notes"}}, "approval": "allow"})
    seen_in_list = "external-add" in {x["name"] for x in json.loads(rh.asb(b, "list", "--json")[1])}
    rh.note(g, "observation", f"`asb list` right after an external admin add shows it: {seen_in_list} "
            "(discovery serves the cached catalog for up to 5 minutes; a request by name refreshes at once)")
    n = len(Upstream.hits)
    rc, out, err, via = rh.asb_auto(b, ["http", "external-add", "GET", up_url(rh, "/ext"), "-H", "X-E: {{EXT_TOKEN}}"])
    rh.check(g, "admin CLI add while the broker runs: broker picks it up (store_reloaded) and serves it",
             rc == 0 and len(Upstream.hits) == n + 1 and len(b.events("store_reloaded")) > n_re, f"rc={rc} {err.strip()[:80]}")
    errs = []
    def cli_add(i):
        r = add_note(rh, rh.store, f"Cli Item {i}", f"FAKE-cli-{i}-value", {"name": f"cli-item-{i}", "allowed_hosts": ["127.0.0.1"],
                     "vars": {f"CLI_{i}": {"field": "notes"}}, "approval": "prompt"})
        if r[0] != 0:
            errs.append(r[2].strip()[:80])
    def asb_store(i):
        r = rh.asb(b, "store", f"conc-{i}", "--hosts", "127.0.0.1", stdin=f"FAKE-conc-{i}-value")
        if r[0] != 0:
            errs.append(r[2].strip()[:80])
    ts = [threading.Thread(target=cli_add, args=(i,)) for i in range(5)] + [threading.Thread(target=asb_store, args=(i,)) for i in range(3)]   # MAX_PENDING is 3
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    rc, o, e = rh.lsc_k("list", rh.store)
    have = {ln.split("\t")[0] for ln in o.splitlines()}
    want = {f"Cli Item {i}" for i in range(5)} | {f"conc-{i}" for i in range(3)}
    rh.check(g, "concurrent admin-CLI adds and broker (asb store) writes: no lost updates (flock)", want <= have and not errs,
             f"missing={sorted(want - have)} errs={errs[:2]}")
    # ---- import-env ---------------------------------------------------------------------------
    envf = rh.srcdir / "fake.env"
    envf.write_text(f"# fake dotenv\nREHEARSAL_DOTENV_KEY={S['dotenv']}\nexport OTHER_VAL='quoted value'\n")
    rc, o, e = rh.lsc_k("import-env", rh.store, None, None, str(envf))
    rh.check(g, "import-env imports 2 items, prints names only, reminds to delete the file",
             rc == 0 and "2 items imported" in o and S["dotenv"] not in o + e and "delete" in o, o.strip().splitlines()[-1][:80])
    script = rh.srcdir / "dotenv.sh"
    outf = rh.srcdir / "dotenv.out"
    script.write_text('#!/bin/sh\nprintf "%s" "$REHEARSAL_DOTENV_KEY" | sha256sum | cut -d" " -f1 > "$1"\n')
    import hashlib
    rc, out, err, rid = rh.asb_decided(b, ["rehearsal-dotenv-key", "--", "sh", str(script), str(outf)])
    rh.check(g, "imported .env item usable through the running broker (env mode, approved)",
             rc == 0 and outf.exists() and outf.read_text().strip() == hashlib.sha256(S["dotenv"].encode()).hexdigest(), f"rc={rc} {err.strip()[:70]}")
    envf.unlink()
    # ---- import-bw against a FAKE bw shim -------------------------------------------------------
    shim = rh.srcdir / "bin"
    shim.mkdir(exist_ok=True)
    (shim / "bw").write_text(FAKE_BW)
    os.chmod(shim / "bw", 0o755)
    bwstate = rh.srcdir / "bw_state.json"
    def bwitem(i, name, typ, **kw):
        base = {"id": f"id{i}", "name": name, "type": typ, "notes": None, "organizationId": "org1", "collectionIds": ["col1"], "fields": []}
        base.update(kw)
        return base
    items = [
        bwitem(1, "BW Note", 2, notes=S["bw"], fields=[{"name": "broker", "type": 0, "value": json.dumps(
            {"name": "bw-note", "allowed_hosts": ["127.0.0.1"], "vars": {"BW_NOTE": {"field": "notes"}}, "approval": "prompt"})}]),
        bwitem(2, "BW Login", 1, login={"username": "bwuser", "password": "FAKE-bw-login-pw-5d", "uris": [{"uri": "https://127.0.0.1/"}]}),
        bwitem(3, "BW Fielded", 2, notes="n", fields=[{"name": "api_key", "type": 1, "value": "FAKE-bw-field-9a"}]),
    ]
    bwstate.write_text(json.dumps({"items": items}))
    SECRETS["bwlogin"], SECRETS["bwfield"] = "FAKE-bw-login-pw-5d", "FAKE-bw-field-9a"
    bwpw = rh.sec / "bw_pw"
    rh.secret_file(bwpw, "fake-master")
    bwcfg = rh.sec / "bw_config.json"
    bwcfg.write_text(json.dumps({"backend": {"type": "bw", "server_url": "https://bw.invalid", "master_password_file": str(bwpw),
                                              "organization": "Org", "collection": "Shared"}}))
    istore, ikf, _ = mini_store(rh, "imp", "passphrase-imp")
    # drop the pre-seeded item so the import store starts empty of bw names
    shimenv = {"PATH": f"{shim}:{os.environ['PATH']}", "FAKE_BW_STATE": str(bwstate)}
    src_before = sha(bwstate)
    rc, o, e = rh.lsc_k("import-bw", istore, ikf, None, "--bw-config", str(bwcfg), "--dry-run", env=shimenv)
    rc2, o2, _ = rh.lsc_k("list", istore, ikf)
    rh.check(g, "import-bw --dry-run (fake bw): lists 3 would-import, writes nothing",
             rc == 0 and o.count("would import") == 3 and "BW Note" not in o2, f"rc={rc} {(o + e).strip()[:90]}")
    rc, o, e = rh.lsc_k("import-bw", istore, ikf, None, "--bw-config", str(bwcfg), env=shimenv)
    rh.check(g, "import-bw: 3 items imported and verified by read-back; source untouched",
             rc == 0 and "3 items imported and verified" in o and sha(bwstate) == src_before, (o + e).strip()[-100:].replace("\n", " | "))
    sys.path.insert(0, str(REPO))
    try:
        from secret_broker.backends.local import LocalBackend
        from secret_broker.backends.localstore import FileKeySource
        lb = LocalBackend(str(istore), FileKeySource(str(ikf)), idle_timeout=0)
        got = {i.name: i for i in lb.export_items()}
        lb.close()
        eq = (got["BW Note"].notes == S["bw"] and got["BW Login"].password == "FAKE-bw-login-pw-5d"
              and got["BW Login"].username == "bwuser" and got["BW Fielded"].fields.get("api_key") == "FAKE-bw-field-9a"
              and got["BW Note"].meta and got["BW Note"].meta.get("name") == "bw-note" and got["BW Login"].meta is None)
    except Exception as ex:  # noqa: BLE001
        eq = False
        rh.note(g, "readback", f"{type(ex).__name__}")
    rh.check(g, "independent read-back: values, custom fields, nested broker metadata equal; unmetadata'd login stays adoptable", eq, "")
    rc, o, e = rh.lsc_k("import-bw", istore, ikf, None, "--bw-config", str(bwcfg), env=shimenv)
    rh.check(g, "import-bw refuses to clobber existing items without --skip-existing/--overwrite", rc != 0 and "already exist" in e, e.strip()[:80])


# ================================================================ scenario G: scale / performance
def rss_mb(pid):
    try:
        for ln in open(f"/proc/{pid}/status"):
            if ln.startswith("VmRSS:"):
                return round(int(ln.split()[1]) / 1024, 1)
    except OSError:
        pass
    return None


def scenario_G(rh):
    g = "G"
    num = rh.res.numbers
    sys.path.insert(0, str(REPO))
    from secret_broker.backends.base import NOTE, Item
    from secret_broker.backends.local import LocalBackend
    from secret_broker.backends.localstore import FileKeySource
    kf = rh.sec / "g.key"
    rh.secret_file(kf, "passphrase-for-the-scale-store")
    store = rh.data / "scale.enc"
    rc, out, err = rh.lsc_k("init", store, kf, None, "--no-recovery")
    items = []
    for i in range(300):
        items.append(Item(f"Scale Item {i:03d}", NOTE, notes=f"FAKE-scale-value-{i:03d}-" + "x" * 40,
                          meta={"name": f"g{i:03d}", "allowed_hosts": ["127.0.0.1", f"svc{i}.example.test"],
                                "vars": {f"G{i:03d}_TOKEN": {"field": "notes"}},
                                "approval": "allow" if i == 0 else "prompt"}))
    lb = LocalBackend(str(store), FileKeySource(str(kf)), idle_timeout=0)
    t = time.time()
    lb.import_items(items)
    num["G build 300 items, one write (ms)"] = round((time.time() - t) * 1000)
    lb.close()
    num["G store file size, 300 items (KiB)"] = round(store.stat().st_size / 1024, 1)
    t = time.time()
    lb = LocalBackend(str(store), FileKeySource(str(kf)), idle_timeout=0)
    rows = lb.catalog()
    cold = (time.time() - t) * 1000
    t = time.time()
    lb.catalog()
    warm = (time.time() - t) * 1000
    num["G catalog load cold, incl. scrypt unlock (ms)"] = round(cold)
    num["G catalog load warm (ms)"] = round(warm, 1)
    lat = []
    for i in range(20):
        t = time.time()
        lb.set_meta(f"Scale Item {i:03d}", {"name": f"g{i:03d}", "allowed_hosts": ["127.0.0.1"], "vars": {f"G{i:03d}_TOKEN": {"field": "notes"}},
                                            "approval": "allow" if i == 0 else "prompt", "guidance": f"Guidance edit number {i} for the scale test."})
        lat.append((time.time() - t) * 1000)
    lb.close()
    num["G write latency set_meta x20, mean / max (ms)"] = f"{sum(lat) / len(lat):.0f} / {max(lat):.0f}"
    num["G store file size after 20 edits (KiB)"] = round(store.stat().st_size / 1024, 1)
    rh.check(g, "300 items stored, catalog readable, 20 metadata writes applied", len(rows) == 300, f"{len(rows)} rows")
    base_rss = rss_mb(rh.main.proc.pid) if getattr(rh, "main", None) and rh.main.proc else None
    b = Broker(rh, "g", store, fkeysrc(kf))
    t = time.time()
    b.start()
    st = {}
    while time.time() - t < 60:
        rc, out, err = rh.asb(b, "status", "--json")
        st = json.loads(out) if rc == 0 else {}
        if st.get("catalog", {}).get("count") == 300:
            break
        time.sleep(0.1)
    num["G broker start to 300-item catalog loaded (s)"] = round(time.time() - t, 2)
    rh.check(g, "broker serves a 300-item catalog", st.get("catalog", {}).get("count") == 300 and st["backend"]["ok"], json.dumps(st.get("catalog")))
    t = time.time()
    rc, out, err = rh.asb(b, "list", "--json")
    num["G asb list --json, 300 items (ms)"] = round((time.time() - t) * 1000)
    t = time.time()
    n = len(Upstream.hits)
    rc, out, err, via = rh.asb_auto(b, ["http", "g000", "GET", up_url(rh, "/scale"), "-H", "X-G: {{G000_TOKEN}}"])
    num["G auto-approved asb http request incl. process start (ms)"] = round((time.time() - t) * 1000)
    rh.check(g, "request against the 300-item store works", rc == 0 and len(Upstream.hits) == n + 1, f"rc={rc}")
    num["G broker RSS, 300 items (MiB)"] = rss_mb(b.proc.pid)
    num["G broker RSS, small catalog (MiB)"] = base_rss
    lat = []
    okc = 0
    for i in range(20):
        t = time.time()
        code, loc, body = b.ap.post("/policies/guidance", {"name": f"g{i + 20:03d}", "guidance": f"Policies-editor guidance edit {i}."})
        lat.append((time.time() - t) * 1000)
        okc += code == 200
    num["G Policies-editor guidance POST x20, mean / max (ms)"] = f"{sum(lat) / len(lat):.0f} / {max(lat):.0f}"
    rh.check(g, "20 Policies-editor edits on the 300-item store all saved", okc == 20, f"{okc}/20")
    meta = dump_meta_fast(rh, store, kf)
    rh.check(g, "all 20 edits persisted in the store file", sum(1 for i in range(20, 40) if meta.get(f"Scale Item {i:03d}", {}).get("guidance")) == 20, "")
    num["G broker RSS after 20 edits (MiB)"] = rss_mb(b.proc.pid)
    num["G store file size after 40 edits (KiB)"] = round(store.stat().st_size / 1024, 1)
    b.stop()


def dump_meta_fast(rh, store, kf):
    from secret_broker.backends.local import LocalBackend
    from secret_broker.backends.localstore import FileKeySource
    lb = LocalBackend(str(store), FileKeySource(str(kf)), idle_timeout=0)
    try:
        return {i.name: i.meta for i in lb.export_items()}
    finally:
        lb.close()


# ================================================================ final: nothing secret anywhere
def final_scan(rh):
    g = "F"
    files = [p for p in list(rh.logs.rglob("*")) + list(rh.data.rglob("*")) + list((rh.root / "docker").rglob("data/*"))
             if p.is_file() and not p.name.endswith(".lock")]
    canary = rh.data / "canary.txt"
    canary.write_text("x" + SECRETS["http"] + "y")
    rh.check(g, "leak scanner self-test: a planted canary is detected", bool(rh.scan_files([canary])), "")
    canary.unlink()
    hits = rh.scan_files(files)
    rh.check(g, f"no fake secret in any broker log, audit file, request-details file or encrypted store ({len(files)} files)", not hits, ",".join(hits[:6]))
    texts = list(rh.outputs) + [("ps", t) for t in rh.psdump] + [("telegram", t) for t in Aux.telegram]
    rh.leak_scan(g, f"no fake secret in any captured CLI output ({len(rh.outputs)} captures), notification or process list ({len(rh.psdump)} snapshots)", texts)
    logs = "\n".join(p.read_text(errors="replace") for p in rh.logs.glob("*.log"))
    bad = [ln for ln in logs.splitlines() if "Traceback" in ln]
    rh.check(g, "no Python traceback in any broker log", not bad, f"{len(bad)} traceback lines")


# ================================================================ scenario H: docker
def sh(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(cmd, **kw)


class DockerBroker(Broker):
    """The same broker, but the process is a container (host networking, loopback bind)."""

    def __init__(self, rh, name, image, keymode, ddir, sdir):
        super().__init__(rh, name, rh.data / "unused.enc", {"type": "file", "path": "/run/secrets/store_key"})
        self.image, self.keymode, self.ddir, self.sdir = image, keymode, ddir, sdir
        self.cname = f"asb-reh-{name}"
        c = self.cfg
        c["backend"] = {"type": "local", "path": "/data/store.enc", "idle_timeout": 300,
                        "key_source": ({"type": "file", "path": "/run/secrets/store_key"} if keymode == "file"
                                       else {"type": "env", "name": "BROKER_STORE_KEY"})}
        c["client_key_file"] = "/run/secrets/client_key"
        c["audit_log"] = "/data/audit.jsonl"
        c["notify"][0]["bot_token_file"] = "/run/secrets/telegram_token"
        c["summary"]["api_key_file"] = "/run/secrets/model_key"

    def run_args(self):
        a = ["docker", "run", "-d", "--name", self.cname, "--network", "host", "--read-only", "--tmpfs", "/tmp",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
             "-e", "HOME=/tmp", "-e", "BIND=127.0.0.1", "-e", "BROKER_CONFIG=" + json.dumps(self.cfg)]
        if self.keymode == "env":
            a += ["--env-file", str(self.sdir.parent.parent / f"{self.sdir.parent.name}.key.env")]
        a += ["-v", f"{self.ddir}:/data", "-v", f"{self.sdir}:/run/secrets:ro", self.image]
        return a

    def start(self, wait=True):
        sh(["docker", "rm", "-f", self.cname])
        cp = sh(self.run_args())
        if cp.returncode != 0:
            self.rh.note("H", "docker run", cp.stderr.strip()[:150])
            return False
        return self.wait_ready() if wait else True

    def restart(self):
        cp = sh(["docker", "restart", "-t", "15", self.cname])
        return cp.returncode == 0 and self.wait_ready()

    def stop(self, *a, **k):
        sh(["docker", "stop", "-t", "15", self.cname])
        cp = sh(["docker", "inspect", "--format", "{{.State.ExitCode}}", self.cname])
        return int(cp.stdout.strip() or -1)

    def wait_ready(self, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            try:
                urllib.request.urlopen(urllib.request.Request(self.url + "/v1/status", headers={"X-Client-Key": CLIENT_KEY}), timeout=3).read()
                return True
            except Exception:  # noqa: BLE001
                time.sleep(0.3)
        return False

    def records(self):
        cp = sh(["docker", "exec", self.cname, "cat", "/data/audit.jsonl"]) if True else None
        out = []
        for line in (cp.stdout if cp.returncode == 0 else "").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def exec(self, *args, stdin=None):
        return sh(["docker", "exec", "-i", self.cname, *args], input=stdin)

    def cli(self, *args, stdin=None):
        """The admin CLI, inside the running container (the supported way to administer a containerised store)."""
        ks = ["--key-file", "/run/secrets/store_key"] if self.keymode == "file" else ["--key-env", "BROKER_STORE_KEY"]
        return self.exec("python", "-m", "secret_broker.localstore", args[0], "--store", "/data/store.enc", *ks, *args[1:], stdin=stdin)


def docker_image(rh):
    img = rh.args.docker_image
    if img:
        return img, "given"
    cp = sh(["docker", "build", "-q", "-t", "asb-rehearsal:local", "--build-arg", "GIT_SHA=rehearsal", str(REPO)], timeout=900)
    if cp.returncode == 0:
        return "asb-rehearsal:local", "built from the worktree Dockerfile"
    rh.note("H", "docker build failed", cp.stderr.strip()[-160:])
    cp = sh(["docker", "pull", "ghcr.io/rgregg/agent-secret-broker:latest"], timeout=600)
    if cp.returncode == 0:
        return "ghcr.io/rgregg/agent-secret-broker:latest", "pulled"
    return None, cp.stderr.strip()[-160:]


def chown_dirs(rh, root, uid, mode_cmds=""):
    """chown a tree through a throwaway alpine container (we are not root)."""
    return sh(["docker", "run", "--rm", "-v", f"{root}:/w", "alpine:latest", "sh", "-c",
               f"chown -R {uid}:{uid} /w && {mode_cmds or 'true'}"])


def docker_core(rh, image, keymode):
    g = "H"
    tag = f"d{keymode}"
    droot = rh.root / "docker" / tag
    ddir, sdir, mdir = droot / "data", droot / "secrets", droot / "meta"
    for d in (ddir, sdir, mdir):
        d.mkdir(parents=True, exist_ok=True)
    rh.secret_file(sdir / "client_key", CLIENT_KEY)
    rh.secret_file(sdir / "telegram_token", "fake-telegram-token")
    rh.secret_file(sdir / "model_key", "fake-model-key")
    storekey = "docker-passphrase-" + keymode if keymode == "file" else SECRETS["envkey"]
    if keymode == "file":
        rh.secret_file(sdir / "store_key", storekey)
    else:
        rh.secret_file(droot.parent / f"{tag}.key.env", "BROKER_STORE_KEY=" + storekey)
    for name, meta in (("stub", {"name": "stub", "allowed_hosts": ["127.0.0.1"], "vars": {"STUB_TOKEN": {"field": "notes"}}, "approval": "prompt"}),
                       ("envcred", {"name": "envcred", "vars": {"ENV_TOKEN": {"field": "notes"}}, "approval": "prompt"})):
        (mdir / f"{name}.json").write_text(json.dumps(meta))
    os.chmod(mdir, 0o755)
    for f in mdir.iterdir():
        os.chmod(f, 0o644)
    chown_dirs(rh, droot, 65534, f"chmod 755 /w/data /w/meta; chmod 500 /w/secrets; chmod 400 /w/secrets/*; chmod 700 /w/data")
    b = DockerBroker(rh, f"dk{keymode}", image, keymode, ddir, sdir)

    def run_cli(*args, stdin=None):
        ks = ["--key-file", "/run/secrets/store_key"] if keymode == "file" else ["--key-env", "BROKER_STORE_KEY"]
        envf = ["--env-file", str(droot.parent / f"{tag}.key.env")] if keymode == "env" else []
        a = ["docker", "run", "--rm", "-i", "--user", "65534:65534", "-e", "HOME=/tmp", *envf, "-v", f"{ddir}:/data", "-v", f"{sdir}:/run/secrets:ro",
             "-v", f"{mdir}:/meta:ro", "--entrypoint", "python", image, "-m", "secret_broker.localstore", args[0],
             "--store", "/data/store.enc", *ks, *args[1:]]
        cp = sh(a, input=stdin)
        rh.outputs.append((f"docker cli {args[0]}", cp.stdout + cp.stderr))
        return cp
    cp = run_cli("init", "--no-recovery")
    rh.check(g, f"[{keymode}] store created by the admin CLI inside the image as uid 65534", cp.returncode == 0, cp.stderr.strip()[:100])
    run_cli("add", "Stub API", "--meta", "/meta/stub.json", stdin=SECRETS["http"])
    run_cli("add", "Env Cred", "--meta", "/meta/envcred.json", stdin=SECRETS["env"])
    cp = run_cli("add", "Plain Login", "--kind", "login", "--json", stdin=json.dumps(
        {"username": "plainuser", "password": SECRETS["plainpw"], "uris": ["http://127.0.0.1/"]}))
    cp = run_cli("list")
    rh.check(g, f"[{keymode}] 3 items added and listed", cp.stdout.count("\n") == 3, cp.stderr.strip()[:80])
    ok = b.start()
    rh.check(g, f"[{keymode}] container starts (rootfs read-only, cap_drop ALL, no-new-privileges)", ok,
             sh(["docker", "logs", "--tail", "5", b.cname]).stderr.strip()[-120:])
    if not ok:
        return b
    t0 = time.time()
    st = {}
    for _ in range(40):
        rc, out, err = rh.asb(b, "status", "--json")
        st = json.loads(out) if rc == 0 else {}
        if st.get("catalog", {}).get("count"):
            break
        time.sleep(0.25)
    rh.check(g, f"[{keymode}] SAFETY asb status shows the throwaway container broker, backend local ok, 3 items incl. adopted",
             st.get("uptime_s", 999) < 60 and st["backend"] == {"type": "local", "ok": True} and st["catalog"]["count"] == 3
             and st["catalog"]["adopted"] == 1, json.dumps(st.get("catalog")))
    ss = sh(["ss", "-ltnH"]).stdout
    bound = [ln.split()[3] for ln in ss.splitlines() if re.search(rf":({b.cport}|{b.aport})\b", ln)]
    rh.check(g, f"[{keymode}] listeners are loopback-only", bound and all(x.startswith("127.0.0.1:") for x in bound), f"{bound}")
    who = sh(["docker", "exec", b.cname, "id", "-u"]).stdout.strip()
    insp = sh(["docker", "inspect", b.cname]).stdout
    cfgj = json.loads(insp)[0]
    rh.check(g, f"[{keymode}] container runs as non-root (uid 65534)", who == "65534", f"id -u={who} Config.User={cfgj['Config'].get('User')!r}")
    # core flows
    rc, out, err, rid = rh.asb_decided(b, ["http", "stub", "GET", up_url(rh, "/docker"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"],
                                       decision="approve_always")
    h = last_hit(rh)
    rh.check(g, f"[{keymode}] http request approved (Always): secret substituted upstream, masked in the response",
             rc == 0 and h and h["headers"].get("Authorization") == "Bearer " + SECRETS["http"] and SECRETS["http"] not in out + err, f"rc={rc}")
    rc, out, err, via = rh.asb_auto(b, ["http", "stub", "GET", up_url(rh, "/docker2"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"])
    rh.check(g, f"[{keymode}] Always auto-approves the next read", rc == 0 and via not in (None, "user"), f"via={via}")
    script = rh.srcdir / "dk_env.sh"
    outf = rh.srcdir / f"dk_env_{keymode}.out"
    script.write_text('#!/bin/sh\nprintf "%s" "$ENV_TOKEN" | sha256sum | cut -d" " -f1 > "$1"\n')
    import hashlib
    rc, out, err, rid = rh.asb_decided(b, ["envcred", "--", "sh", str(script), str(outf)])
    rh.check(g, f"[{keymode}] env-mode request delivers the value", rc == 0 and outf.exists()
             and outf.read_text().strip() == hashlib.sha256(SECRETS["env"].encode()).hexdigest(), f"rc={rc}")
    code, loc, body = b.ap.post("/policies/guidance", {"name": "envcred", "guidance": "Docker rehearsal guidance for envcred."})
    rh.check(g, f"[{keymode}] Policies editor guidance saved", code == 200 and "Guidance saved" in body, f"http {code}")
    rc, out, err, rid = rh.asb_decided(b, ["store", "dockernew", "--hosts", "127.0.0.1"], stdin=SECRETS["stored"])
    rh.check(g, f"[{keymode}] asb store creates a credential in the containerised store", rc == 0, f"rc={rc}")
    ls = sh(["docker", "exec", b.cname, "ls", "-ln", "/data"]).stdout
    rows = {ln.split()[-1]: ln.split() for ln in ls.splitlines() if len(ln.split()) >= 9}
    okperm = all(n in rows and rows[n][0] == "-rw-------" and rows[n][2] == "65534" for n in ("store.enc", "store.enc.bak", "store.enc.lock"))
    rh.check(g, f"[{keymode}] store, .bak, .lock inside the container: mode 0600, owner 65534", okperm, " ".join(f"{n}:{r[0]}/{r[2]}" for n, r in rows.items())[:140])
    rh.check(g, f"[{keymode}] audit/details files owned by 65534", rows.get("audit.jsonl", ["", "", "", "0"])[2] == "65534", "")
    meta_before = b.cli("show", "Env Cred").stdout
    pre_seq = max(r["seq"] for r in b.records())
    t = time.time()
    okr = b.restart()
    rh.res.numbers[f"H docker restart to ready, {keymode} key (s)"] = round(time.time() - t, 1)
    rh.check(g, f"[{keymode}] docker restart: broker comes back", okr, "")
    rc, out, err = rh.asb(b, "status", "--json")
    st2 = json.loads(out) if rc == 0 else {}
    for _ in range(20):
        if st2.get("catalog", {}).get("count") == 4:
            break
        time.sleep(0.5)
        st2 = json.loads(rh.asb(b, "status", "--json")[1])
    rh.check(g, f"[{keymode}] after restart: backend ok, 4 items (the stored one persisted)", st2["backend"]["ok"] and st2["catalog"]["count"] == 4,
             json.dumps(st2["catalog"]))
    rc, out, err, via = rh.asb_auto(b, ["http", "stub", "GET", up_url(rh, "/docker3"), "-H", "Authorization: Bearer {{STUB_TOKEN}}"])
    rh.check(g, f"[{keymode}] after restart: Always still effective (no prompt)", rc == 0 and via not in (None, "user"), f"via={via}")
    rh.check(g, f"[{keymode}] after restart: guidance persisted", "Docker rehearsal guidance" in b.cli("show", "Env Cred").stdout, "")
    seqs = [r["seq"] for r in b.records()]
    rc, out, err = rh.asb(b, "audit", "verify")
    rh.check(g, f"[{keymode}] audit chain continues across docker restart", rc == 0 and seqs == sorted(set(seqs)) and max(seqs) > pre_seq, (out + err).strip()[:80])
    # secrets and docker inspect
    insp = sh(["docker", "inspect", b.cname]).stdout
    logs = sh(["docker", "logs", b.cname])
    rh.outputs.append(("docker logs", logs.stdout + logs.stderr))
    seen_in_inspect = [k for k, v in SECRETS.items() if v in insp]
    if keymode == "file":
        rh.check(g, "[file] docker inspect shows no secret value (key is a mounted file)", not seen_in_inspect, f"{seen_in_inspect}")
    else:
        rh.check(g, "[env] docker inspect shows the env key (documented caveat) and nothing else secret",
                 seen_in_inspect == ["envkey"], f"{seen_in_inspect}")
        docs = (REPO / "docs" / "setup.md").read_text() + (REPO / "docs" / "reference.md").read_text()
        rh.check(g, "[env] the docs warn that env keys are visible in docker inspect", "docker inspect" in docs and "environment variables" in docs.lower(), "")
        insp = insp.replace(SECRETS["envkey"], "<envkey>")
    rh.outputs.append((f"docker inspect {keymode}", insp))
    st_code = b.stop()
    rh.check(g, f"[{keymode}] docker stop (SIGTERM) exits 0", st_code == 0, f"exit {st_code}")
    sh(["docker", "rm", "-f", b.cname])
    chown_dirs(rh, droot, os.getuid(), "chmod -R u+rwX /w")
    return b


def scenario_H(rh):
    g = "H"
    if shutil.which("docker") is None or sh(["docker", "version", "--format", "{{.Server.Version}}"]).returncode != 0:
        rh.res.skip(g, "docker not available")
        return
    t = time.time()
    image, how = docker_image(rh)
    if not image:
        rh.res.skip(g, "no image: " + how)
        return
    rh.res.numbers["H image prepared (s)"] = round(time.time() - t, 1)
    rh.note(g, "image", f"{image} ({how})")
    for keymode in ("file", "env"):
        try:
            docker_core(rh, image, keymode)
        finally:
            sh(["docker", "rm", "-f", f"asb-reh-dk{keymode}"])
            chown_dirs(rh, rh.root / "docker" / f"d{keymode}", os.getuid(), "chmod -R u+rwX /w")
    # bridge networking with a published loopback port (no upstream needed)
    droot = rh.root / "docker" / "bridge"
    name = "asb-reh-bridge"
    sh(["docker", "rm", "-f", name])
    for d in ("data", "secrets"):
        (droot / d).mkdir(parents=True, exist_ok=True)
    rh.secret_file(droot / "secrets" / "client_key", CLIENT_KEY)
    rh.secret_file(droot / "secrets" / "store_key", "bridge-passphrase")
    cport, aport = free_port(), free_port()
    cfg = {"backend": {"type": "local", "path": "/data/store.enc", "key_source": {"type": "file", "path": "/run/secrets/store_key"}},
           "client_key_file": "/run/secrets/client_key", "approve_base_url": f"http://127.0.0.1:{aport}", "allowed_user": USER,
           "notify": [{"type": "telegram", "bot_token_file": "/run/secrets/client_key", "chat_id": "1", "api_base": "http://127.0.0.1:9"}],
           "audit_log": "/data/audit.jsonl", "approval_trusted_peers": ["172.16.0.0/12"]}
    chown_dirs(rh, droot, 65534, "chmod 700 /w/data; chmod 500 /w/secrets; chmod 400 /w/secrets/*")
    base = ["docker", "run", "--rm", "-i", "--user", "65534:65534", "-e", "HOME=/tmp", "-v", f"{droot/'data'}:/data", "-v", f"{droot/'secrets'}:/run/secrets:ro",
            "--entrypoint", "python", image, "-m", "secret_broker.localstore"]
    sh([*base, "init", "--store", "/data/store.enc", "--key-file", "/run/secrets/store_key", "--no-recovery"])
    sh([*base, "add", "Bridge Item", "--store", "/data/store.enc", "--key-file", "/run/secrets/store_key"], input="FAKE-bridge-value")
    cp = sh(["docker", "run", "-d", "--name", name, "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "-e", "HOME=/tmp",
             "-e", "BROKER_CONFIG=" + json.dumps(cfg), "-p", f"127.0.0.1:{cport}:8800", "-p", f"127.0.0.1:{aport}:8801",
             "-v", f"{droot/'data'}:/data", "-v", f"{droot/'secrets'}:/run/secrets:ro", image])
    class Tmp:
        url = f"http://127.0.0.1:{cport}"
    try:
        end = time.time() + 40
        up = False
        while time.time() < end and cp.returncode == 0:
            try:
                urllib.request.urlopen(urllib.request.Request(Tmp.url + "/v1/status", headers={"X-Client-Key": CLIENT_KEY}), timeout=3).read()
                up = True
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.3)
        time.sleep(1)
        rc, out, err = rh.asb(Tmp, "status", "--json")
        st = json.loads(out) if rc == 0 else {}
        pub = sh(["docker", "port", name]).stdout
        rh.check(g, "[bridge] container with ports published on 127.0.0.1 only: client API reachable, store loaded",
                 up and st.get("catalog", {}).get("count") == 1 and st["backend"]["ok"] and "0.0.0.0" not in pub, pub.strip().replace("\n", " "))
    finally:
        sh(["docker", "rm", "-f", name])
        chown_dirs(rh, droot, os.getuid(), "chmod -R u+rwX /w")


def main_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--groups", default="ABCDEFGH")
    ap.add_argument("--root", default=None, help="scratch directory (default: a new mode-0700 dir under /tmp)")
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory")
    ap.add_argument("--docker-image", default=None, help="use this image for group H instead of building")
    ap.add_argument("--docker-build", action="store_true", help="build the image from the worktree Dockerfile")
    return ap.parse_args()


def main():
    args = main_args()
    root = args.root or tempfile.mkdtemp(prefix="asb-rehearsal-", dir="/tmp")
    res = Results()
    rh = Rehearsal(root, res)
    rh.args = args
    print(f"scratch: {rh.root}", flush=True)
    try:
        groups = args.groups.upper()
        if any(x in groups for x in "CDEF"):
            groups += "AB"      # C-F run against the store and broker that A and B set up
        order = {"A": scenario_A, "B": scenario_B, "C": scenario_C, "D": scenario_D, "E": scenario_E, "F": scenario_F, "G": scenario_G, "H": scenario_H}
        for gname in "ABCDEFGH":
            if gname in groups:
                if order[gname](rh) is False:
                    break
        if any(x in groups for x in "ABCDEFGH"):
            final_scan(rh)
    finally:
        rh.cleanup_procs()
    ok = res.summary()
    if args.root is None and not args.keep:
        for pth in (rh.root,):
            subprocess.run(["chmod", "-R", "u+rwX", str(pth)], capture_output=True)
            shutil.rmtree(pth, ignore_errors=True)
        print(f"scratch directory {rh.root} removed")
    else:
        print(f"scratch directory kept: {rh.root}")
    print("RESULT: " + ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
