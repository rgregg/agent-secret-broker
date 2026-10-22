"""Shared harness for the plan-mode tests (not a test module).

A throwaway broker per test (the test_grants/test_clients harness: a fake phone that never decides
by itself, a recording stub upstream on a loopback port), per-client credentials enrolled through
the real endpoint, plans submitted and approved through the real endpoints, and a fake clock that
moves both the wall clock and the monotonic clock. Every secret and value here is fake.
"""
import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
import test_e2e as t  # noqa: E402

KEY, CLI = t.KEY, t.CLI
LEDGER_VALUE = "LEDGER-CANARY-value-77c1d0"
SVC_VALUE = t.SECRET            # "s3cr3t-token-value"
NOPLAN_VALUE = "NOPLAN-CANARY-value-5e5e5e"
TASK_CANARY = "TASK-CANARY-nightly-8a8a8a"
DESC_CANARY = "DESC-CANARY-because-6b6b6b"
BODY_CANARY = "BODY-CANARY-text-3c3c3c"
DOC_CANARY = "DocCanary9d9d9d"


class Stub(BaseHTTPRequestHandler):
    """The upstream. Records every request it receives (method, path, headers, body)."""
    seen = []
    lock = threading.Lock()
    delay = 0.0
    gate = None                     # an Event a handler waits on before answering (in-flight tests)

    def log_message(self, *a):
        pass

    def _reply(self, code, obj, extra=None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n) if n else b""
        with Stub.lock:
            Stub.seen.append({"method": self.command, "path": self.path, "headers": dict(self.headers),
                              "body": data})
        if Stub.gate is not None:
            Stub.gate.wait(10)
        if Stub.delay:
            time.sleep(Stub.delay)
        if self.path.startswith("/redir"):
            return self._reply(302, {}, {"Location": "/landed", "Set-Cookie": "sid=COOKIE-CANARY"})
        if self.path.startswith("/fail"):
            return self._reply(500, {"error": "boom"})
        self._reply(200, {"ok": True, "echo_auth": self.headers.get("Authorization"), "len": len(data)})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle


class PBase(tc.CBase):
    """CBase plus a stub upstream, three extra credentials, a fake clock and plan helpers."""
    ttl = 600
    plans_cfg = None

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.plans_cfg is not None:
            cfg["plans"] = self.plans_cfg
        cfg["_vault"]["Ledger"] = {"token": LEDGER_VALUE}
        cfg["secrets"]["ledger"] = {"vars": {"LEDGER_TOKEN": {"item": "Ledger", "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"]}
        cfg["_vault"]["Noplan"] = {"token": NOPLAN_VALUE}
        cfg["secrets"]["noplan"] = {"vars": {"NOPLAN_TOKEN": {"item": "Noplan", "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"], "plans": False}

    def setUp(self):
        super().setUp()
        Stub.seen, Stub.delay, Stub.gate = [], 0.0, None
        self.stub = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=self.stub.serve_forever, daemon=True).start()
        self.port = self.stub.server_address[1]
        real_mono = time.monotonic
        p = mock.patch("time.monotonic", lambda: real_mono() + self.offset)
        p.start()
        self.addCleanup(p.stop)
        self.client = self.new_client("build-box")
        self.cs = self.client["secret"]
        self.logs = []                  # every text this test produced, for the leak checks

    def tearDown(self):
        self.stub.shutdown()
        self.stub.server_close()
        super().tearDown()

    # -- manifests -------------------------------------------------------------------
    def rule(self, **kw):
        r = {"secret": "ledger", "method": "POST", "host": "127.0.0.1", "port": self.port, "scheme": "http",
             "path_prefix": "/v1/notes", "max_uses": 5,
             "body": {"json": {"keys": ["text", "kind"], "pin": {"kind": "reconcile"}}}}
        r.update(kw)
        return {k: v for k, v in r.items() if v is not None}

    def read_rule(self, **kw):
        r = {"secret": "svc", "method": "GET", "host": "127.0.0.1", "port": self.port, "scheme": "http",
             "path_prefix": "/v1/accounts", "max_uses": 5}
        r.update(kw)
        return {k: v for k, v in r.items() if v is not None}

    def manifest(self, rules=None, **kw):
        m = {"v": 1, "task": "nightly finance sync", "description": "pull balances, post a note",
             "ttl_seconds": 3600, "rules": rules if rules is not None else [self.read_rule(), self.rule()]}
        m.update(kw)
        return m

    # -- API ---------------------------------------------------------------------------
    def api(self, method, path, body=None, secret=None):
        code, text = self.as_client(secret or self.cs, method, path, body)
        self.logs.append(text)
        return code, (json.loads(text) if text.startswith("{") else text)

    def submit(self, manifest=None, secret=None, source="bob@build-box", expect=202):
        m = self.manifest() if manifest is None else manifest
        code, r = self.api("POST", "/v1/plans", {"manifest": m, "source": source}, secret)
        self.assertEqual(code, expect, r)
        return r

    def card(self, rid):
        return self.broker._by_id[rid]

    def decide(self, rid, decision="approve", granted=None, user="alice", csrf=True, **kw):
        req = self.card(rid)
        form = {"id": rid, "decision": decision,
                "granted": granted if granted is not None else req.spec["requested_s"]}
        form.update(kw)
        out = self.post("/plans/decide", form, user=user, csrf=csrf)
        self.logs.append(out[1])
        return out

    def approve(self, manifest=None, granted=None, secret=None, **kw):
        """Submit, then approve on the approval page (confirming a high plan). Returns the plan id."""
        r = self.submit(manifest, secret)
        req = self.card(r["id"])
        dec = "approve_confirmed" if req.spec["tier"] == "high" else "approve"
        st, body, hdr = self.decide(r["id"], dec, granted, **kw)
        self.assertEqual(st, 303, body)
        self.assertIn("note=planok", hdr["Location"])
        req.done.wait(10)
        self.assertEqual(req.status, "approved", req.error)
        return r["plan"]

    def call(self, plan, name="ledger", method="POST", path="/v1/notes", body=None, headers=None,
             url=None, secret=None, expect=None, no_plan_key=False, raw_body=None, extra=None):
        """One plan call through the API: returns (http code of the POST, parsed body or the result)."""
        h = {"Authorization": "Bearer {{" + name.upper() + "_TOKEN}}"}
        if method not in ("GET", "HEAD", "OPTIONS", "DELETE"):
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        payload = {"mode": "http", "names": [name], "method": method,
                   "url": url or f"http://127.0.0.1:{self.port}{path}", "headers": h}
        if not no_plan_key:
            payload["plan"] = plan
        if raw_body is not None:
            payload["body"] = raw_body
        elif body is not None:
            payload["body"] = json.dumps(body)
        payload.update(extra or {})
        code, r = self.api("POST", "/v1/requests", payload, secret)
        self.broker.flush_notifications(10)
        if code == 202 and r.get("status") == "approved":
            res = self.api("GET", f"/v1/requests/{r['id']}?wait=5", None, secret)[1]
            return code, res
        return code, r

    def ok_note(self, **kw):
        b = {"text": "reconciled", "kind": "reconcile"}
        b.update(kw)
        return b

    def upstream(self):
        with Stub.lock:
            return list(Stub.seen)

    def tick(self, seconds):
        self.offset += seconds

    def plan_view(self, pid):
        return self.broker.plans.get_view(pid)

    def everything(self):
        """Every text channel this test produced, for the leak checks."""
        return "\n".join(self.seen + self.logs + [self.audit_text()])

    # -- real CLI ---------------------------------------------------------------------------
    def cli(self, *args, secret=None, env_extra=None, timeout=60, stdin=None, human=None):
        self.home = getattr(self, "home", None) or tempfile.mkdtemp()
        env = {"PATH": os.environ["PATH"], "HOME": self.home, "USER": "bob",
               "SECRET_BROKER_URL": self.base, "SECRET_BROKER_KEY": secret or self.cs}
        env.update(env_extra or {})
        p = subprocess.Popen([CLI, *args], env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ps = ""
        if human is not None:
            end = time.time() + 20
            while time.time() < end and not self.broker.pending():
                time.sleep(0.05)
            ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
            pend = self.broker.pending()
            if pend:
                human(pend[0])
        try:
            out, err = p.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        self.logs.extend([out, err])
        return p.returncode, out, err, ps

    def write_manifest(self, manifest=None):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "manifest.json")
        with open(path, "w") as f:
            json.dump(self.manifest() if manifest is None else manifest, f)
        return path
