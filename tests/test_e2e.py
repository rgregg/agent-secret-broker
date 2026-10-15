import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import audit as audit_mod  # noqa: E402
from secret_broker import risk as risk_mod  # noqa: E402
from secret_broker.backends import BackendError, BwBackend, FileBackend  # noqa: E402
from secret_broker.broker import Broker, serve  # noqa: E402
from secret_broker import notify as notify_mod  # noqa: E402
from secret_broker.notify import FakeNotifier, NotifyError  # noqa: E402
from secret_broker.summarize import OpenRouterSummarizer  # noqa: E402

SECRET = "s3cr3t-token-value"
CLI = os.path.join(os.path.dirname(__file__), "..", "client", "secret-run")
KEY = "client-key"


class Echo(BaseHTTPRequestHandler):
    """Upstream API: echoes the Authorization header back in the body."""

    def log_message(self, *a):
        pass

    hits = []

    def _reply(self, code, obj, extra=None):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        Echo.hits.append(self.path)
        if self.path == "/redir":
            return self._reply(302, {}, {"Location": "/landed"})
        self._reply(200, {"auth": self.headers.get("Authorization")})

    def do_POST(self):
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            text = data.decode()
        except UnicodeDecodeError:
            text = None
        self._reply(200, {"auth": self.headers.get("Authorization"), "len": len(data),
                          "text": text, "head": data[:4].hex()})


def req(url, method="GET", body=None, headers=None):
    r = urllib.request.Request(url, method=method, headers=headers or {},
                               data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class Harness(unittest.TestCase):
    ttl = 30
    decision = "approve"       # what the fake "phone" does
    user = "alice"

    def setUp(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "vault.json"), "w") as f:
            json.dump({"Svc": {"token": SECRET}}, f)
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        cfg = {
            "approve_base_url": "https://secrets.example", "allowed_user": "alice", "ttl_seconds": self.ttl,
            "secrets": {"svc": {"vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                                "allowed_hosts": ["127.0.0.1"]}},
        }
        self.tweak(cfg)
        self.notifier = FakeNotifier(on_send=self._phone)
        self.audit = os.path.join(d, "audit.jsonl")
        self.broker = Broker(cfg, FileBackend(os.path.join(d, "vault.json")), self.notifier, self.audit)
        self.c, self.a = serve(self.broker, ("127.0.0.1", 0), ("127.0.0.1", 0), KEY)
        self.base = f"http://127.0.0.1:{self.c.server_address[1]}"
        self.abase = f"http://127.0.0.1:{self.a.server_address[1]}"

    def tweak(self, cfg):
        """Subclass hook to adjust the broker config before it starts."""

    def tearDown(self):
        for s in (self.c, self.a, self.up):
            s.shutdown()
            s.server_close()

    def records(self):
        with open(self.audit) as f:
            return [json.loads(line) for line in f if line.strip()]

    def events(self, name):
        return [r for r in self.records() if r["event"] == name]

    def _phone(self, url):
        """Simulates tapping the push, then the button, via the approval page."""
        if self.decision is None:
            return
        path = urllib.parse.urlsplit(url).path
        hdr = {"X-authentik-username": self.user}
        data = urllib.parse.urlencode({"decision": self.decision}).encode()
        r = urllib.request.Request(self.abase + path, data=data, headers=hdr, method="POST")
        try:
            urllib.request.urlopen(r, timeout=10).read()
        except urllib.error.HTTPError:
            return                      # rejected: nothing will be released
        req_ = self.broker._by_nonce.get(path.rsplit("/", 1)[1])
        if req_ is not None:
            req_.done.wait(10)          # accepted: release runs asynchronously

    def api(self, method, path, body=None, key=KEY):
        return req(self.base + path, method, body, {"X-Client-Key": key, "Content-Type": "application/json"})

    def create_env(self, names=("svc",)):
        return self.api("POST", "/v1/requests", {"mode": "env", "names": list(names), "argv": ["echo", "hi"]})


class EnvMode(Harness):
    def test_approve_releases_once(self):
        code, body = self.create_env()
        rid = json.loads(body)["id"]
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        got = json.loads(b)
        self.assertEqual(got["status"], "approved")
        self.assertEqual(got["env"], {"SVC_TOKEN": SECRET})
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=1")
        self.assertEqual(json.loads(b), {"status": "released"})

    def test_client_never_sees_nonce(self):
        _, body = self.create_env()
        nonce = urllib.parse.urlsplit(self.notifier.sent[0]["url"]).path.rsplit("/", 1)[1]
        self.assertNotIn(nonce, body)

    def test_unknown_secret_and_bad_key(self):
        self.assertEqual(self.create_env(["nope"])[0], 400)
        self.assertEqual(self.api("POST", "/v1/requests", {}, key="wrong")[0], 401)

    def test_audit_has_no_values(self):
        _, body = self.create_env()
        self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        with open(self.audit) as f:
            text = f.read()
        self.assertIn('"event": "approved"', text)
        self.assertNotIn(SECRET, text)


class Denied(Harness):
    decision = "deny"

    def test_deny_then_cooldown(self):
        _, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "denied")
        d = self.events("denied")[0]
        self.assertEqual((d["via"], d["approver"]), ("user", "alice"))
        self.assertEqual(self.create_env()[0], 403)
        self.assertIn("denied recently", self.events("rejected")[-1]["reason"])


class WrongUser(Harness):
    user = "mallory"

    def test_other_identity_cannot_approve(self):
        _, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=1")
        self.assertEqual(json.loads(b)["status"], "pending")


class Expiry(Harness):
    ttl = 1
    decision = None

    def test_expires(self):
        _, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=3")
        self.assertEqual(json.loads(b)["status"], "expired")
        self.assertEqual(len(self.events("expired")), 1)


class NotifyFailure(Harness):
    def test_undeliverable_push_fails_request(self):
        def boom(*a):
            raise NotifyError("no device")
        self.notifier.send = boom
        code, body = self.create_env()
        self.assertEqual(json.loads(body)["status"], "failed")


class HttpMode(Harness):
    def test_broker_makes_call_and_masks(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        r = json.loads(b)
        self.assertEqual(r["http"]["status"], 200)
        self.assertNotIn(SECRET, r["http"]["body"])
        self.assertIn("Bearer ***", r["http"]["body"])
        self.assertNotIn("env", r)

    def test_host_not_allowed(self):
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": "http://evil.example/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 403)
        self.assertEqual(self.notifier.sent, [])


class Redirects(Harness):
    def test_redirect_is_not_followed(self):
        Echo.hits.clear()
        url = f"http://127.0.0.1:{self.up.server_address[1]}/redir"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        r = json.loads(b)["http"]
        self.assertEqual(r["status"], 302)
        self.assertEqual(Echo.hits, ["/redir"])


class FakeOpenRouter(BaseHTTPRequestHandler):
    seen = []
    reply = "List servers on Komodo"
    status = 200

    def log_message(self, *a):
        pass

    def do_POST(self):
        FakeOpenRouter.seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        raw = json.dumps({"choices": [{"message": {"content": FakeOpenRouter.reply}}]}).encode()
        self.send_response(FakeOpenRouter.status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Summary(Harness):
    def setUp(self):
        super().setUp()
        FakeOpenRouter.seen.clear()
        FakeOpenRouter.reply, FakeOpenRouter.status = "List servers on Komodo", 200
        self.or_srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenRouter)
        threading.Thread(target=self.or_srv.serve_forever, daemon=True).start()
        self.base_or = f"http://127.0.0.1:{self.or_srv.server_address[1]}"
        self.broker.summarizer = OpenRouterSummarizer("k", "m", timeout=2, base_url=self.base_or)

    def tearDown(self):
        self.or_srv.shutdown()
        self.or_srv.server_close()
        super().tearDown()

    def http_req(self, **kw):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x?token=SHOULD-NOT-LEAK"
        body = {"mode": "http", "names": ["svc"], "method": "POST", "url": url,
                "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}, "body": '{"type":"ListServers"}'}
        body.update(kw)
        return self.api("POST", "/v1/requests", body)

    def test_summary_in_push_and_audit_and_input_has_no_values(self):
        code, _ = self.http_req()
        self.assertEqual(code, 202)
        self.assertIn("List servers on Komodo (unverified)", self.notifier.sent[0]["message"])
        sent = json.dumps(FakeOpenRouter.seen[0])
        self.assertNotIn(SECRET, sent)
        self.assertNotIn("SHOULD-NOT-LEAK", sent)        # query string stripped
        self.assertNotIn("Bearer", sent)                  # header values never sent
        self.assertIn("Authorization", sent)              # header names are
        self.assertIn("ListServers", sent)
        with open(self.audit) as f:
            self.assertIn("List servers on Komodo", f.read())

    def test_send_content_false_withholds_body_and_command(self):
        self.broker.summarizer = OpenRouterSummarizer("k", "m", timeout=2, send_content=False, base_url=self.base_or)
        self.http_req()
        self.assertNotIn("ListServers", json.dumps(FakeOpenRouter.seen[0]))

    def test_model_failure_does_not_block_request(self):
        FakeOpenRouter.status = 500
        code, body = self.http_req()
        self.assertEqual(code, 202)
        self.assertNotIn("unverified", self.notifier.sent[0]["message"])
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "approved")

    def test_summary_is_length_capped_and_escaped_on_page(self):
        FakeOpenRouter.reply = "<script>alert(1)</script> " + "x" * 500
        self.decision = None
        self.http_req()
        nonce = None
        for r in self.broker._by_id.values():
            nonce = r.nonce
            self.assertLessEqual(len(r.summary), 100)
        status, page = req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})
        self.assertEqual(status, 200)
        self.assertNotIn("<script>", page)
        self.assertIn("unverified", page)


class Discovery(Harness):
    def test_lists_without_approval_or_values(self):
        code, body = self.api("GET", "/v1/secrets?host=127.0.0.1")
        r = json.loads(body)
        self.assertEqual(code, 200)
        self.assertEqual([s["name"] for s in r["secrets"]], ["svc"])
        self.assertEqual(r["secrets"][0]["vars"], ["SVC_TOKEN"])
        self.assertNotIn(SECRET, body)
        self.assertEqual(self.notifier.sent, [])          # no push
        self.assertEqual(self.broker._by_id, {})          # no request created

    def test_no_match_and_url_form(self):
        _, body = self.api("GET", "/v1/secrets?host=other.example")
        self.assertEqual(json.loads(body)["secrets"], [])
        _, body = self.api("GET", "/v1/secrets?url=" + urllib.parse.quote("http://127.0.0.1:9/x?y=1"))
        self.assertEqual(len(json.loads(body)["secrets"]), 1)

    def test_requires_client_key(self):
        self.assertEqual(self.api("GET", "/v1/secrets", key="wrong")[0], 401)


class AutoAllowHttp(Harness):
    decision = None   # the phone does nothing; policy must decide

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"

    def http_body(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        return {"mode": "http", "names": ["svc"], "method": "GET", "url": url,
                "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}}

    def test_http_released_without_prompt_and_audited(self):
        code, body = self.api("POST", "/v1/requests", self.http_body())
        self.assertEqual(code, 202)
        self.assertEqual(self.notifier.sent, [])
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=2")
        self.assertEqual(json.loads(b)["http"]["status"], 200)
        approved = self.events("approved")[0]
        self.assertEqual(approved["via"], "policy")
        self.assertIsNone(approved.get("approver"))
        self.assertEqual(self.events("http_executed")[0]["upstream_status"], 200)
        self.assertEqual(self.events("secret_read")[0]["secret"], "svc")

    def test_env_mode_still_prompts_by_default(self):
        self.create_env()
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("approved"), [])


class AutoAllowEnvExplicit(Harness):
    decision = None

    def tweak(self, cfg):
        cfg["secrets"]["svc"].update(approval="allow", auto_modes=["http", "env"])

    def test_env_auto_when_opted_in(self):
        _, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=2")
        self.assertEqual(json.loads(b)["env"], {"SVC_TOKEN": SECRET})
        self.assertEqual(self.notifier.sent, [])


class MixedPolicy(Harness):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"
        cfg["secrets"]["locked"] = {"vars": {"LOCKED": {"item": "Svc", "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"]}

    def test_any_prompt_secret_forces_prompt(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc", "locked"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("approved")[0]["via"], "user")

    def test_discovery_reports_policy(self):
        _, body = self.api("GET", "/v1/secrets?host=127.0.0.1")
        pol = {s["name"]: s["approval"] for s in json.loads(body)["secrets"]}
        self.assertEqual(pol, {"locked": "prompt", "svc": "allow"})


class BadPolicy(unittest.TestCase):
    def test_unknown_approval_value_refuses_to_start(self):
        cfg = {"secrets": {"x": {"vars": {}, "approval": "sometimes"}}}
        with self.assertRaises(ValueError):
            Broker(cfg, None, FakeNotifier())


class AuditTrail(Harness):
    def test_chain_verifies_and_has_no_values(self):
        _, body = self.create_env()
        self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        ok, msg = audit_mod.verify(self.audit)
        self.assertTrue(ok, msg)
        names = [r["event"] for r in self.records()]
        for want in ("startup", "requested", "notified", "secret_read", "approved", "delivered"):
            self.assertIn(want, names)
        with open(self.audit) as f:
            self.assertNotIn(SECRET, f.read())
        d = self.events("delivered")[0]
        self.assertEqual(d["to_peer"], "127.0.0.1")
        a = self.events("approved")[0]
        self.assertEqual((a["via"], a["approver"]), ("user", "alice"))
        self.assertEqual(oct(os.stat(self.audit).st_mode & 0o777), "0o600")

    def test_tampering_is_detected(self):
        self.create_env()
        with open(self.audit) as f:
            lines = f.read().splitlines()
        edited = [l.replace('"approved"', '"denied__"') if '"event": "approved"' in l else l for l in lines]
        path = self.audit + ".edited"
        with open(path, "w") as f:
            f.write("\n".join(edited) + "\n")
        self.assertFalse(audit_mod.verify(path)[0])
        path2 = self.audit + ".deleted"
        with open(path2, "w") as f:
            f.write("\n".join(lines[:2] + lines[3:]) + "\n")
        self.assertFalse(audit_mod.verify(path2)[0])

    def test_page_views_and_forwarded_ip_are_recorded(self):
        self.decision = None
        self.create_env()
        nonce = next(iter(self.broker._by_id.values())).nonce
        hdr = {"X-authentik-username": "alice", "X-Forwarded-For": "203.0.113.9, 198.51.100.1"}
        status, _ = req(self.abase + f"/a/{nonce}", headers=hdr)
        self.assertEqual(status, 200)
        v = self.events("approval_viewed")[0]
        self.assertEqual((v["user"], v["client_ip"], v["found"]), ("alice", "203.0.113.9", True))
        data = urllib.parse.urlencode({"decision": "approve"}).encode()
        urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{nonce}", data=data, headers=hdr, method="POST"), timeout=10).read()
        next(iter(self.broker._by_id.values())).done.wait(10)
        self.assertEqual(self.events("approved")[0]["approver_ip"], "203.0.113.9")
        self.assertNotIn(nonce, open(self.audit).read())

    def test_chain_continues_across_restart(self):
        self.create_env()
        again = Broker(self.broker.cfg, self.broker.backend, self.notifier, self.audit)
        again.log("probe")
        self.assertTrue(audit_mod.verify(self.audit)[0])

    def test_security_events_are_recorded(self):
        self.api("POST", "/v1/requests", {}, key="wrong")
        self.api("POST", "/v1/requests", {"mode": "http", "names": ["svc"], "method": "GET",
                                           "url": "http://evil.example/x", "headers": {}})
        self.create_env(["nope"])
        r = urllib.request.Request(self.abase + "/a/whatever", headers={"X-authentik-username": "mallory"})
        try:
            urllib.request.urlopen(r, timeout=5)
        except urllib.error.HTTPError:
            pass
        self.assertEqual(self.events("auth_failed")[0]["peer"], "127.0.0.1")
        reasons = " ".join(r["reason"] for r in self.events("rejected"))
        self.assertIn("evil.example", reasons)
        self.assertIn("unknown secret", reasons)
        self.assertEqual(self.events("approval_forbidden")[0]["claimed_user"], "mallory")


class RiskBaseline(unittest.TestCase):
    CFG = {"lo": {"vars": {}, "sensitivity": "low"}, "hi": {"vars": {}, "sensitivity": "high"},
           "unset": {"vars": {}}}

    def b(self, mode, names, **spec):
        return risk_mod.baseline(mode, names, spec, self.CFG)

    def http(self, names, method="GET", url="https://h.example/api/things", **kw):
        return self.b("http", names, method=method, url=url, headers={}, **kw)

    def test_levels(self):
        self.assertEqual(self.http(["lo"])[0], "low")
        self.assertEqual(self.http(["lo"], "POST")[0], "medium")
        self.assertEqual(self.http(["lo"], "DELETE")[0], "high")
        self.assertEqual(self.http(["hi"])[0], "high")
        self.assertEqual(self.http(["unset"])[0], "medium")          # unlabelled is not low

    def test_destructive_keywords_and_privilege_paths(self):
        self.assertEqual(self.http(["lo"], "POST", body='{"type":"DeleteStack"}')[0], "high")
        self.assertEqual(self.http(["lo"], url="https://h.example/api/stack/restart")[0], "high")
        self.assertEqual(self.http(["lo"], url="https://h.example/admin/x")[0], "medium")

    def test_env_mode(self):
        self.assertEqual(self.b("env", ["lo"], argv=["curl", "-s", "https://x"])[0], "medium")
        self.assertEqual(self.b("env", ["lo"], argv=["sh", "-c", "curl $T"])[0], "high")
        self.assertEqual(self.b("env", ["lo"], argv=["printenv"])[0], "high")

    def test_model_can_only_raise(self):
        a = risk_mod.assess("http", ["lo"], {"method": "DELETE", "url": "https://h.example/x", "headers": {}},
                            self.CFG, _Stub("harmless", "low"))
        self.assertEqual((a["level"], a["model"]), ("high", "low"))
        a = risk_mod.assess("http", ["lo"], {"method": "GET", "url": "https://h.example/x", "headers": {}},
                            self.CFG, _Stub("scary", "high"))
        self.assertEqual(a["level"], "high")
        self.assertIn("model rated it high", a["reasons"])

    def test_garbage_model_output_is_ignored(self):
        a = risk_mod.assess("http", ["lo"], {"method": "GET", "url": "https://h.example/x", "headers": {}},
                            self.CFG, _Stub("x", "catastrophic"))
        self.assertEqual((a["level"], a["model"]), ("low", None))


class _Stub:
    def __init__(self, summary, risk):
        self.s, self.r = summary, risk

    def analyze(self, mode, names, spec):
        return {"summary": self.s, "risk": self.r}


class RiskFlow(Harness):
    decision = None
    model_risk = "low"

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["sensitivity"] = "low"
        cfg["risk"] = {"escalate_auto_at": "high"}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("List things", self.model_risk)

    def http(self, method="GET", path="/x", **kw):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        return self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": method, "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}, **kw})

    def test_risk_in_title_page_and_audit(self):
        self.http("DELETE")
        self.assertIn("[HIGH]", self.notifier.sent[0]["title"])
        self.assertIn("DELETE request", self.notifier.sent[0]["message"])
        a = self.events("assessed")[0]
        self.assertEqual((a["baseline"], a["risk"]), ("high", "high"))
        nonce = next(iter(self.broker._by_id.values())).nonce
        _, page = req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})
        self.assertIn("HIGH RISK", page)

    def test_low_risk_allow_secret_is_auto_released(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.http("GET")
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("approved")[0]["risk"], "low")

    def test_high_risk_overrides_allow_and_prompts(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.http("DELETE")
        self.assertEqual(len(self.notifier.sent), 1)               # prompted despite allow
        self.assertEqual(self.events("approved"), [])
        self.assertEqual(len(self.events("escalated")), 1)


class RiskFlowModelRaises(RiskFlow):
    model_risk = "high"

    def test_model_high_escalates_a_get(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.http("GET")
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("assessed")[0]["model"], "high")

    # parent tests assume a low model verdict
    test_low_risk_allow_secret_is_auto_released = None


class FakeTelegram(BaseHTTPRequestHandler):
    calls = []
    fail = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeTelegram.calls.append((self.path, body))
        if FakeTelegram.fail:
            raw = json.dumps({"ok": False, "description": "Unauthorized"}).encode()
            code = FakeTelegram.fail
        else:
            raw = json.dumps({"ok": True, "result": {"message_id": 77}}).encode()
            code = 200
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Transports(unittest.TestCase):
    TOKEN = "123456:SECRET-BOT-TOKEN"

    def setUp(self):
        FakeTelegram.calls.clear()
        FakeTelegram.fail = None
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeTelegram)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def tg(self):
        return notify_mod.TelegramNotifier(self.TOKEN, 4242, api_base=self.api)

    def test_telegram_sends_url_button_only(self):
        n = self.tg()
        n.send("Secret request [LOW]", "svc from host", "https://secrets.example/a/NONCE", "secret-abc")
        path, body = FakeTelegram.calls[0]
        self.assertEqual(path, f"/bot{self.TOKEN}/sendMessage")
        self.assertEqual(body["chat_id"], "4242")
        kb = body["reply_markup"]["inline_keyboard"][0][0]
        self.assertEqual(kb["url"], "https://secrets.example/a/NONCE")
        self.assertNotIn("callback_data", kb)             # approval cannot happen in-chat

    def test_resolved_edits_message(self):
        n = self.tg()
        n.send("t", "m", "https://x.example/a/n", "tag1")
        n.resolved("tag1", "approved")
        path, body = FakeTelegram.calls[-1]
        self.assertTrue(path.endswith("/editMessageText"))
        self.assertEqual(body["message_id"], 77)
        self.assertIn("APPROVED", body["text"])

    def test_error_never_contains_bot_token(self):
        FakeTelegram.fail = 401
        with self.assertRaises(NotifyError) as cm:
            self.tg().send("t", "m", "https://x.example/a/n", "tag")
        self.assertNotIn("SECRET-BOT-TOKEN", str(cm.exception))
        self.assertIn("401", str(cm.exception))

    def test_multi_delivers_if_any_succeeds(self):
        class Boom:
            def send(self, *a):
                raise NotifyError("down")
        ok = FakeNotifier()
        multi = notify_mod.MultiNotifier([Boom(), ok])
        multi.send("t", "m", "u", "tag")
        self.assertEqual(len(ok.sent), 1)
        with self.assertRaises(NotifyError):
            notify_mod.MultiNotifier([Boom(), Boom()]).send("t", "m", "u", "tag")

    def test_build_from_config(self):
        files = {"ha": "hatok", "bot": self.TOKEN}
        rd = files.__getitem__
        legacy = notify_mod.build({"ha_url": "http://ha", "ha_token_file": "ha"}, rd)
        self.assertIsInstance(legacy, notify_mod.TickerNotifier)
        both = notify_mod.build({"notify": [
            {"type": "ticker", "ha_url": "http://ha", "ha_token_file": "ha"},
            {"type": "telegram", "bot_token_file": "bot", "chat_id": 1}]}, rd)
        self.assertIsInstance(both, notify_mod.MultiNotifier)
        with self.assertRaises(ValueError):
            notify_mod.build({"notify": [{"type": "carrier-pigeon"}]}, rd)


class ResolvedHook(Harness):
    def test_transport_told_when_settled(self):
        _, body = self.create_env()
        self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        for _ in range(50):
            if getattr(self.notifier, "resolutions", None):
                break
            time.sleep(0.05)
        self.assertEqual([s for _, s in self.notifier.resolutions], ["approved"])


class BwBackendState(unittest.TestCase):
    """The real CLI refuses `config server` once logged in; the backend must cope."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.state = os.path.join(d, "state")
        os.mkdir(self.state)
        item = {"name": "Thing", "notes": "tok\n"}
        self.bw = os.path.join(d, "bw")
        with open(self.bw, "w") as f:
            f.write(f"""#!/bin/sh
S={self.state}
case "$1" in
  status) if [ -e $S/in ]; then if [ -e $S/unlocked ]; then echo '{{"status":"unlocked"}}'; else echo '{{"status":"locked"}}'; fi
          else echo '{{"status":"unauthenticated"}}'; fi;;
  config) if [ -e $S/in ]; then echo "Logout required before server config update." >&2; exit 1; fi;;
  login) touch $S/in;;
  lock) rm -f $S/unlocked;;
  unlock) if [ ! -e $S/in ]; then echo "not logged in" >&2; exit 1; fi; sleep 0.2; touch $S/unlocked; echo SESSION;;
  sync) ;;
  get) cat <<'EOF'
{json.dumps(item)}
EOF
;;
esac
""")
        os.chmod(self.bw, 0o755)
        self.pw = os.path.join(d, "pw")
        open(self.pw, "w").write("master")

    def backend(self):
        return BwBackend("https://vault.example", self.pw, bw=self.bw)

    def test_new_process_with_existing_login_state(self):
        self.assertEqual(self.backend().get("Thing", "notes"), "tok")
        # second "process" (new object) sees an already logged-in, unlocked CLI
        self.assertEqual(self.backend().get("Thing", "notes"), "tok")

    def test_concurrent_gets_on_one_backend(self):
        b, out, errs = self.backend(), [], []

        def go():
            try:
                out.append(b.get("Thing", "notes"))
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual((errs, out), ([], ["tok"] * 6))


class BwBackendParsing(unittest.TestCase):
    """BwBackend against a fake `bw` executable (no network, no real vault)."""

    def setUp(self):
        d = tempfile.mkdtemp()
        item = {"name": "Thing", "notes": "tok-value\n\n",
                "login": {"username": "u", "password": "p4ss"},
                "fields": [{"name": "key", "value": "custom-val", "type": 1}]}
        self.bw = os.path.join(d, "bw")
        with open(self.bw, "w") as f:
            f.write("#!/bin/sh\n"
                    'case "$1" in\n'
                    '  status) echo \'{"status":"unauthenticated"}\';;\n'
                    '  unlock) echo SESSIONKEY;;\n'
                    "  get) cat <<'EOF'\n" + json.dumps(item) + "\nEOF\n;;\n"
                    "  *) ;;\n"
                    "esac\n")
        os.chmod(self.bw, 0o755)
        self.pw = os.path.join(d, "pw")
        with open(self.pw, "w") as f:
            f.write("master\n")
        self.b = BwBackend("https://vault.example", self.pw, bw=self.bw)

    def test_fields(self):
        self.assertEqual(self.b.get("Thing", "notes"), "tok-value")      # trailing newlines stripped
        self.assertEqual(self.b.get("Thing", "password"), "p4ss")
        self.assertEqual(self.b.get("Thing", "username"), "u")
        self.assertEqual(self.b.get("Thing", "key"), "custom-val")
        with self.assertRaises(BackendError):
            self.b.get("Thing", "nope")


class SlowBackend(FileBackend):
    reads = 0

    def get(self, item, field):
        SlowBackend.reads += 1
        time.sleep(0.6)
        return super().get(item, field)


class DoubleSubmit(Harness):
    decision = None

    def setUp(self):
        super().setUp()
        SlowBackend.reads = 0
        self.broker.backend = SlowBackend(os.path.join(os.path.dirname(self.audit), "vault.json"))

    def test_concurrent_approvals_release_once(self):
        self.create_env()
        nonce = next(iter(self.broker._by_id.values())).nonce
        hdr = {"X-authentik-username": "alice"}
        data = urllib.parse.urlencode({"decision": "approve"}).encode()
        codes = []

        def post():
            try:
                r = urllib.request.urlopen(urllib.request.Request(
                    self.abase + f"/a/{nonce}", data=data, headers=hdr, method="POST"), timeout=10)
                codes.append(r.status)
            except urllib.error.HTTPError as e:
                codes.append(e.code)
        ts = [threading.Thread(target=post) for _ in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(sorted(codes), [200, 404])
        next(iter(self.broker._by_id.values())).done.wait(10)
        self.assertEqual(SlowBackend.reads, 1)
        self.assertEqual(len(self.events("approved")), 1)
        self.assertEqual(self.events("failed"), [])
        self.assertEqual(len(self.events("approval_stale")), 1)


class AsyncApproval(Harness):
    decision = None

    def setUp(self):
        super().setUp()
        SlowBackend.reads = 0
        self.broker.backend = SlowBackend(os.path.join(os.path.dirname(self.audit), "vault.json"))

    def test_page_answers_before_release_finishes(self):
        _, body = self.create_env()
        nonce = next(iter(self.broker._by_id.values())).nonce
        data = urllib.parse.urlencode({"decision": "approve"}).encode()
        t0 = time.time()
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{nonce}", data=data, headers={"X-authentik-username": "alice"},
            method="POST"), timeout=10)
        page, took = r.read().decode(), time.time() - t0
        self.assertIn("Approved", page)
        self.assertLess(took, 0.4)                       # backend sleeps 0.6s per read
        # the decision is on record immediately; the release outcome is not yet
        self.assertEqual(self.events("decided")[0]["decision"], "approve")
        self.assertEqual(self.events("approved"), [])
        self.assertEqual([s for _, s in getattr(self.notifier, "resolutions", [])], ["approved"])
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["env"], {"SVC_TOKEN": SECRET})
        self.assertEqual(len(self.events("approved")), 1)

    def test_deny_is_immediate_and_recorded(self):
        _, body = self.create_env()
        nonce = next(iter(self.broker._by_id.values())).nonce
        data = urllib.parse.urlencode({"decision": "deny"}).encode()
        t0 = time.time()
        page = urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{nonce}", data=data, headers={"X-authentik-username": "alice"},
            method="POST"), timeout=10).read().decode()
        self.assertIn("Denied", page)
        self.assertLess(time.time() - t0, 0.4)
        self.assertEqual(self.events("decided")[0]["decision"], "deny")
        self.assertEqual(len(self.events("denied")), 1)
        self.assertEqual(SlowBackend.reads, 0)           # nothing was ever read

    def test_release_failure_is_audited_not_shown_to_approver(self):
        self.broker.backend = FileBackend.__new__(FileBackend)
        self.broker.backend._data = {}                   # every lookup raises BackendError
        _, body = self.create_env()
        nonce = next(iter(self.broker._by_id.values())).nonce
        data = urllib.parse.urlencode({"decision": "approve"}).encode()
        urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{nonce}", data=data, headers={"X-authentik-username": "alice"},
            method="POST"), timeout=10).read()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "failed")
        self.assertIn("release failed", self.events("failed")[0]["error"])


class BwBackendWarm(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.log = os.path.join(d, "calls")
        self.bw = os.path.join(d, "bw")
        with open(self.bw, "w") as f:
            f.write(f"""#!/bin/sh
echo "$1" >> {self.log}
case "$1" in
  status) echo '{{"status":"unauthenticated"}}';;
  unlock) echo SESSION;;
  get) echo '{{"name":"T","notes":"v"}}';;
esac
""")
        os.chmod(self.bw, 0o755)
        self.pw = os.path.join(d, "pw")
        open(self.pw, "w").write("m")

    def calls(self):
        with open(self.log) as f:
            return f.read().split()

    def test_warm_then_get_does_not_unlock_or_resync(self):
        b = BwBackend("https://v.example", self.pw, bw=self.bw)
        b.warm()
        before = self.calls()
        self.assertEqual(b.get("T", "notes"), "v")
        self.assertEqual(b.get("T", "notes"), "v")
        after = self.calls()[len(before):]
        self.assertEqual(after, ["get", "get"])          # no status/login/unlock/sync

    def test_resync_after_interval(self):
        b = BwBackend("https://v.example", self.pw, bw=self.bw, sync_interval=0)
        b.get("T", "notes")
        b.get("T", "notes")
        self.assertEqual(self.calls().count("sync"), 2)


class BwIdleLogout(BwBackendWarm):
    """Session is kept for idle_timeout after last use, then logged out."""

    def backend(self, idle):
        b = BwBackend("https://v.example", self.pw, bw=self.bw, idle_timeout=idle)
        self.addCleanup(b.close)
        self.events = []
        b.on_event = lambda name, **kw: self.events.append(name)
        return b

    def test_logs_out_after_idle_then_recovers(self):
        b = self.backend(0.4)
        self.assertEqual(b.get("T", "notes"), "v")
        self.assertNotIn("logout", self.calls())
        time.sleep(1.0)
        self.assertEqual(self.calls().count("logout"), 1)
        self.assertEqual(self.events, ["backend_closed"])
        self.assertEqual(b.get("T", "notes"), "v")        # transparently logs in again
        self.assertEqual(self.calls().count("login"), 2)

    def test_use_extends_the_window(self):
        b = self.backend(0.8)
        b.get("T", "notes")
        time.sleep(0.5)
        b.get("T", "notes")                               # re-arms the timer
        time.sleep(0.5)                                   # 1.0s since first use, 0.5s since last
        self.assertNotIn("logout", self.calls())
        time.sleep(0.8)
        self.assertEqual(self.calls().count("logout"), 1)

    def test_idle_timeout_zero_disables_logout(self):
        b = self.backend(0)
        b.get("T", "notes")
        time.sleep(0.4)
        self.assertNotIn("logout", self.calls())

    # inherited warm/resync tests don't depend on idle behaviour
    test_warm_then_get_does_not_unlock_or_resync = None
    test_resync_after_interval = None


class PrewarmStub:
    def __init__(self):
        self.warmed = threading.Event()
        self.count = 0

    def warm(self):
        self.count += 1
        self.warmed.set()

    def get(self, item, field):
        return "v"


class Prewarm(Harness):
    decision = None

    def setUp(self):
        super().setUp()
        self.stub = PrewarmStub()
        self.broker.backend = self.stub

    def test_request_creation_warms_backend(self):
        self.create_env()
        self.assertTrue(self.stub.warmed.wait(3))
        for _ in range(50):
            if self.events("backend_ready"):
                break
            time.sleep(0.05)
        self.assertEqual(len(self.events("backend_ready")), 1)

    def test_prewarm_can_be_disabled(self):
        self.broker.cfg["backend"] = {"prewarm": False}
        self.create_env()
        time.sleep(0.3)
        self.assertEqual(self.stub.count, 0)


class Cli(Harness):
    def run_cli(self, *args):
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY)
        return subprocess.run([sys.executable, "-I", CLI, *args], env=env,
                              capture_output=True, text=True, timeout=30)

    def test_env_mode_masks_output(self):
        p = self.run_cli("svc", "--", "sh", "-c", 'echo "tok=$SVC_TOKEN"')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "tok=***")

    def test_file_body_with_placeholder(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "body.json")
        with open(path, "w") as f:
            f.write('{"token": "{{SVC_TOKEN}}"}')
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        p = self.run_cli("http", "svc", "POST", url, "-d", f"@{path}")
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        self.assertEqual(json.loads(got["text"]), {"token": "***"})   # real value reached upstream, masked back

    def test_binary_file_body_passthrough(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "blob.bin")
        with open(path, "wb") as f:
            f.write(b"\xff\xfe\x00\x01" + b"{{SVC_TOKEN}}")
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        p = self.run_cli("http", "svc", "POST", url, "-d", f"@{path}")
        got = json.loads(p.stdout)
        self.assertEqual(got["head"], "fffe0001")
        self.assertEqual(got["len"], 4 + len("{{SVC_TOKEN}}"))   # not substituted

    def test_list_text_and_json(self):
        p = self.run_cli("list")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "svc\tSVC_TOKEN\t127.0.0.1\tprompt")
        pj = self.run_cli("list", "--json")
        self.assertEqual(json.loads(pj.stdout), [
            {"name": "svc", "vars": ["SVC_TOKEN"], "allowed_hosts": ["127.0.0.1"], "approval": "prompt"}])
        self.assertNotIn(SECRET, p.stdout + pj.stdout)
        self.assertEqual(self.notifier.sent, [])           # no push, no request
        self.assertEqual(self.broker._by_id, {})
        self.assertEqual(self.run_cli("list", "--bogus").returncode, 2)

    def test_list_empty_exit_codes(self):
        self.broker.cfg["secrets"] = {}
        self.assertEqual(self.run_cli("list").returncode, 1)
        pj = self.run_cli("list", "--json")
        self.assertEqual((pj.returncode, json.loads(pj.stdout)), (0, []))

    def test_which_exit_codes(self):
        ok = self.run_cli("which", "http://127.0.0.1:8080/api")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(ok.stdout.strip(), "svc\tSVC_TOKEN")
        none = self.run_cli("which", "nothing.example")
        self.assertEqual(none.returncode, 1)
        self.assertEqual(self.notifier.sent, [])

    def test_http_mode(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        p = self.run_cli("http", "svc", "GET", url, "-H", "Authorization: Bearer {{SVC_TOKEN}}")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn(SECRET, p.stdout)


if __name__ == "__main__":
    unittest.main()
