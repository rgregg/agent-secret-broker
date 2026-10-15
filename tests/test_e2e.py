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
from secret_broker.backends import BwServeBackend  # noqa: E402
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
        # The vault is the catalog: each configured secret becomes broker
        # metadata on the vault item that holds its value.
        vault_path = os.path.join(d, "vault.json")
        with open(vault_path) as f:
            vault = json.load(f)
        for item, rec in cfg.pop("_vault", {}).items():
            vault.setdefault(item, {}).update(rec)
        for name, sc in cfg.pop("secrets").items():
            carrier = next(iter(sc["vars"].values()))["item"]
            assert "broker" not in vault.get(carrier, {}), "one secret per vault item"
            vault.setdefault(carrier, {})["broker"] = json.dumps({"name": name, **sc})
        with open(vault_path, "w") as f:
            json.dump(vault, f)
        self.notifier = FakeNotifier(on_send=self._phone)
        self.audit = os.path.join(d, "audit.jsonl")
        self.broker = Broker(cfg, FileBackend(vault_path), self.notifier, self.audit)
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

    def disk(self):
        """The catalog as persisted in the vault (broker metadata of each item)."""
        out = {}
        for item, rec in self.broker.backend._data.items():
            if "broker" in rec:
                m = json.loads(rec["broker"])
                out[m.get("name") or item.lower()] = m
        return {"secrets": out}

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

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Reads", "low")   # only a low verdict auto-releases

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

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Reads", "low")   # only a low verdict auto-releases

    def test_env_auto_when_opted_in(self):
        _, body = self.create_env()
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=2")
        self.assertEqual(json.loads(b)["env"], {"SVC_TOKEN": SECRET})
        self.assertEqual(self.notifier.sent, [])


class NoVerdictFailsClosed(Harness):
    decision = None

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"       # note: no risk.escalate_auto_at set

    def test_allow_secret_still_prompts_without_a_model_verdict(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202)
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("approved"), [])
        self.assertEqual(len(self.events("escalated")), 1)

    def test_medium_verdict_also_prompts_by_default(self):
        self.broker.summarizer = _Stub("Changes a thing", "medium")
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(len(self.notifier.sent), 1)


class MixedPolicy(Harness):
    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"
        cfg["_vault"] = {"Locked": {"token": SECRET}}
        cfg["secrets"]["locked"] = {"vars": {"LOCKED": {"item": "Locked", "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"]}

    def test_any_prompt_secret_forces_prompt(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc", "locked"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.events("approved")[0]["via"], "user")

    def test_discovery_does_not_reveal_policy(self):
        # whether a credential prompts must not influence which one is chosen
        for path in ("/v1/secrets", "/v1/secrets?host=127.0.0.1"):
            _, body = self.api("GET", path)
            names = {s["name"] for s in json.loads(body)["secrets"]}
            self.assertEqual(names, {"locked", "svc"})
            for s in json.loads(body)["secrets"]:
                self.assertEqual(set(s), {"name", "vars", "allowed_hosts"})
            self.assertNotIn("approval", body)
            self.assertNotIn('"allow"', body)
            self.assertNotIn("sensitivity", body)


class CatalogFromVault(unittest.TestCase):
    """The catalog is read from the vault; bad entries are skipped, not trusted."""

    def make(self, vault):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "vault.json")
        with open(path, "w") as f:
            json.dump(vault, f)
        audit = os.path.join(d, "audit.jsonl")
        return Broker({"approve_base_url": "https://s.example"}, FileBackend(path), FakeNotifier(), audit), audit

    def meta(self, **kw):
        return json.dumps({"vars": {"T_TOKEN": {"field": "notes"}}, "allowed_hosts": ["api.example.com"], **kw})

    def test_only_items_with_metadata_are_secrets(self):
        b, _ = self.make({"Plain": {"notes": "x"}, "My API": {"notes": "y", "broker": self.meta()}})
        self.assertEqual(sorted(b.cfg["secrets"]), ["my-api"])      # name derived from the item
        self.assertEqual(b.cfg["secrets"]["my-api"]["vars"]["T_TOKEN"]["item"], "My API")

    def test_invalid_metadata_is_skipped_and_audited_fail_closed(self):
        b, audit = self.make({
            "Bad approval": {"notes": "x", "broker": self.meta(approval="sometimes")},
            "No hosts": {"notes": "x", "broker": json.dumps({"vars": {"T": {}}})},
            "Wild": {"notes": "x", "broker": self.meta(allowed_hosts=["*.example.com"])},
            "Garbage": {"notes": "x", "broker": "not json"},
            "Good": {"notes": "x", "broker": self.meta()}})
        self.assertEqual(sorted(b.cfg["secrets"]), ["good"])
        with open(audit) as f:
            ev = [json.loads(line) for line in f if '"catalog_loaded"' in line][0]
        self.assertEqual(len(ev["invalid"]), 4)

    def test_duplicate_names_keep_the_first_only(self):
        b, _ = self.make({"A": {"notes": "x", "broker": self.meta(name="same")},
                          "B": {"notes": "x", "broker": self.meta(name="same")}})
        self.assertEqual(list(b.cfg["secrets"]), ["same"])

    def test_a_vault_that_cannot_be_read_does_not_stop_startup(self):
        class Down:
            def catalog(self):
                raise BackendError("vault down")
        b = Broker({"approve_base_url": "https://s.example"}, Down(), FakeNotifier(), None)
        self.assertEqual(b.cfg["secrets"], {})

    def test_new_item_appears_without_restart(self):
        b, _ = self.make({"Old": {"notes": "x", "broker": self.meta()}})
        b.backend._data["Fresh"] = {"notes": "z", "broker": self.meta()}
        b._catalog_at = 0
        b._refresh_if(0)
        self.assertEqual(sorted(b.cfg["secrets"]), ["fresh", "old"])


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


class RiskModelOnly(unittest.TestCase):
    SPEC = {"method": "GET", "url": "https://h.example/x", "headers": {}}

    def test_level_is_the_model_verdict_in_both_directions(self):
        for v in ("low", "medium", "high"):
            a = risk_mod.assess("http", ["s"], self.SPEC, _Stub("x", v))
            self.assertEqual((a["level"], a["model"]), (v, v))
        a = risk_mod.assess("http", ["s"], dict(self.SPEC, method="DELETE"), _Stub("x", "low"))
        self.assertEqual(a["level"], "low")               # no rule overrides the model

    def test_no_or_bad_verdict_fails_closed_to_high(self):
        for analyzer in (None, _Stub("x", "catastrophic"), _Stub("x", None), _Boom()):
            a = risk_mod.assess("http", ["s"], self.SPEC, analyzer)
            self.assertEqual((a["level"], a["model"]), ("high", None))
            self.assertIn("no model verdict", a["reasons"][0])


class _Boom:
    def analyze(self, mode, names, spec):
        raise RuntimeError("model down")


class _Stub:
    def __init__(self, summary, risk):
        self.s, self.r = summary, risk

    def analyze(self, mode, names, spec):
        return {"summary": self.s, "risk": self.r}


class RiskFlow(Harness):
    decision = None
    model_risk = "low"

    def tweak(self, cfg):
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
        self.broker.summarizer = _Stub("Deletes things", "high")
        self.http("DELETE")
        self.assertIn("[HIGH]", self.notifier.sent[0]["title"])
        self.assertIn("model rated it high", self.notifier.sent[0]["message"])
        a = self.events("assessed")[0]
        self.assertEqual((a["model"], a["risk"]), ("high", "high"))
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
        self.broker.summarizer = _Stub("Deletes things", "high")
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


class AlwaysAllow(Harness):
    decision = None

    def tweak(self, cfg):
        cfg["risk"] = {"escalate_auto_at": "high"}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("List things", "low")

    def http_req(self, method="GET", path="/x"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        return self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": method, "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})

    def nonce(self):
        return list(self.broker._by_id.values())[-1].nonce

    def page(self, nonce=None):
        return req(self.abase + f"/a/{nonce or self.nonce()}", headers={"X-authentik-username": "alice"})[1]

    def post(self, path, **form):
        data = urllib.parse.urlencode(form).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + path, data=data, headers={"X-authentik-username": "alice"}, method="POST"),
                timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def finish(self):
        list(self.broker._by_id.values())[-1].done.wait(10)

    def test_button_persists_policy_and_takes_effect(self):
        self.http_req()
        self.assertIn("approve_always", self.page())
        status, body = self.post(f"/a/{self.nonce()}", decision="approve_always")
        self.assertEqual(status, 200)
        self.assertIn("Always allow saved", body)
        self.finish()
        d = self.disk()
        self.assertEqual(d["secrets"]["svc"]["approval"], "allow")        # written to the vault item
        self.assertEqual(d["secrets"]["svc"]["approval_changed"]["by"], "alice")
        self.assertEqual(d["secrets"]["svc"]["allowed_hosts"], ["127.0.0.1"])   # rest untouched
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["approval"], "allow")
        ch = self.events("policy_changed")[0]
        self.assertEqual((ch["secret"], ch["from"], ch["to"], ch["user"]), ("svc", "prompt", "allow", "alice"))
        self.assertTrue(self.events("decided")[0]["always_requested"])
        pushes = len(self.notifier.sent)
        _, b = self.http_req()                                       # next call: no prompt
        self.assertEqual(len(self.notifier.sent), pushes)
        _, r = self.api("GET", f"/v1/requests/{json.loads(b)['id']}?wait=3")
        self.assertEqual(json.loads(r)["http"]["status"], 200)
        self.assertEqual(self.events("approved")[-1]["via"], "policy")

    def test_not_offered_and_refused_for_env_mode(self):
        self.create_env()
        page = self.page()
        self.assertNotIn("value=approve_always", page)
        self.assertIn("Always allow not offered", page)
        status, body = self.post(f"/a/{self.nonce()}", decision="approve_always")   # forged
        self.assertEqual(status, 200)
        self.assertIn("not applied", body)
        self.finish()
        self.assertEqual(self.disk()["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertEqual(len(self.events("policy_change_refused")), 1)
        self.assertEqual(self.events("approved")[0]["via"], "user")   # this request still approved

    def test_high_risk_request_cannot_establish_standing_allow(self):
        self.broker.summarizer = _Stub("Deletes things", "high")
        self.http_req("DELETE")
        self.assertNotIn("value=approve_always", self.page())
        self.post(f"/a/{self.nonce()}", decision="approve_always")
        self.finish()
        self.assertEqual(self.disk()["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertIn("rated high", self.events("policy_change_refused")[0]["reason"])

    def test_write_failure_leaves_policy_unchanged_but_approves(self):
        self.http_req()
        orig = self.broker._persist_approval

        def boom(*a, **k):
            raise OSError("disk full")
        self.broker._persist_approval = boom
        status, body = self.post(f"/a/{self.nonce()}", decision="approve_always")
        self.broker._persist_approval = orig
        self.assertEqual(status, 200)
        self.assertIn("could not write", body)
        self.finish()
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertEqual(len(self.events("policy_change_failed")), 1)
        self.assertEqual(len(self.events("approved")), 1)

    def test_policies_page_can_only_tighten(self):
        self.assertTrue(self.broker.set_approval("svc", "allow", "alice"))
        status, body = req(self.abase + "/policies", headers={"X-authentik-username": "alice"})
        self.assertEqual(status, 200)
        self.assertIn("Require approval again", body)
        # granting is refused here
        self.assertEqual(self.post("/policies", name="svc", approval="allow")[0], 400)
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "allow")
        status, body = self.post("/policies", name="svc", approval="prompt")
        self.assertEqual(status, 200)
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "prompt")
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["approval"], "prompt")
        self.assertEqual(self.post("/policies", name="nope", approval="prompt")[0], 400)

    def test_policies_page_requires_identity(self):
        r = req(self.abase + "/policies", headers={"X-authentik-username": "mallory"})
        self.assertEqual(r[0], 403)


FAKE_BW = r"""#!/usr/bin/env python3
import base64, json, os, sys
S = os.environ["FAKE_BW_STATE"]
def load():
    return json.load(open(S)) if os.path.exists(S) else {"items": [], "in": False, "n": 0}
def save(d):
    json.dump(d, open(S, "w"))
a = sys.argv[1:]
d = load()
cmd = a[0] if a else ""
if cmd == "status":
    print(json.dumps({"status": "locked" if d["in"] else "unauthenticated"}))
elif cmd == "login":
    d["in"] = True; save(d)
elif cmd in ("config", "sync", "lock", "logout"):
    pass
elif cmd == "unlock":
    print("SESSION")
elif cmd == "encode":
    print(base64.b64encode(sys.stdin.read().encode()).decode())
elif cmd == "list" and a[1] == "organizations":
    print(json.dumps(d.get("orgs", [{"id": "org1", "name": "Org"}])))
elif cmd == "list" and a[1] == "collections":
    print(json.dumps(d.get("colls", [{"id": "col1", "name": "Shared"}])))
elif cmd == "get":
    hits = [i for i in d["items"] if i["name"] == a[2] or i["id"] == a[2]]
    if not hits:
        print("Not found.", file=sys.stderr); sys.exit(1)
    if len(hits) > 1:
        print("More than one result was found.", file=sys.stderr); sys.exit(1)
    print(json.dumps(hits[0]))
elif cmd in ("create", "edit"):
    obj = json.loads(base64.b64decode(sys.stdin.read().strip()))
    if cmd == "create":
        d["n"] += 1; obj["id"] = f"id{d['n']}"; d["items"].append(obj)
    else:
        d["items"] = [obj if i["id"] == a[2] else i for i in d["items"]]
    save(d)
elif cmd == "delete":
    d["items"] = [i for i in d["items"] if i["id"] != a[2]]; save(d)
elif cmd == "serve":
    import urllib.parse
    from http.server import BaseHTTPRequestHandler, HTTPServer
    port = int(a[a.index("--port") + 1])
    log = os.environ.get("FAKE_BW_SERVE_LOG")
    if log:
        open(log, "a").write("start\n")
    st = {"unlocked": bool(os.environ.get("BW_SESSION"))}
    class H(BaseHTTPRequestHandler):
        def log_message(self, *x): pass
        def reply(self, ok, data=None, msg=None, code=200):
            body = json.dumps({"success": ok, "data": data, "message": msg}).encode()
            self.send_response(code if ok else 400); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n)) if n else None
        def route(self, method):
            u = urllib.parse.urlsplit(self.path); q = urllib.parse.parse_qs(u.query)
            p = u.path; dd = load()
            if p == "/status": return self.reply(True, {"status": "unlocked" if st["unlocked"] else "locked"})
            if p == "/unlock":
                self.body(); st["unlocked"] = True; return self.reply(True, {"raw": "S"})
            if not st["unlocked"]: return self.reply(False, msg="Vault is locked.")
            if p == "/lock": st["unlocked"] = False; return self.reply(True, {})
            if p == "/sync": return self.reply(True, {})
            if p == "/list/object/organizations":
                return self.reply(True, {"data": dd.get("orgs", [{"id": "org1", "name": "Org"}])})
            if p == "/list/object/collections":
                return self.reply(True, {"data": dd.get("colls", [{"id": "col1", "name": "Shared"}])})
            if p == "/list/object/items":
                t = (q.get("search") or [""])[0].lower()
                return self.reply(True, {"data": [i for i in dd["items"] if t in i["name"].lower()]})
            if p.startswith("/object/item"):
                iid = p[len("/object/item/"):]
                if method == "POST":
                    obj = self.body(); dd["n"] += 1; obj["id"] = f"id{dd['n']}"; dd["items"].append(obj)
                    save(dd); return self.reply(True, obj)
                hit = [i for i in dd["items"] if i["id"] == iid]
                if not hit: return self.reply(False, msg="Not found.")
                if method == "GET": return self.reply(True, hit[0])
                if method == "PUT":
                    obj = self.body(); dd["items"] = [obj if i["id"] == iid else i for i in dd["items"]]
                    save(dd); return self.reply(True, obj)
                if method == "DELETE":
                    dd["items"] = [i for i in dd["items"] if i["id"] != iid]; save(dd)
                    return self.reply(True, {})
            self.reply(False, msg="unknown route")
        def do_GET(self): self.route("GET")
        def do_POST(self): self.route("POST")
        def do_PUT(self): self.route("PUT")
        def do_DELETE(self): self.route("DELETE")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
"""


class BwBackendWrites(unittest.TestCase):
    backend_class = BwBackend

    def setUp(self):
        d = tempfile.mkdtemp()
        self.state = os.path.join(d, "state.json")
        self.bw = os.path.join(d, "bw")
        with open(self.bw, "w") as f:
            f.write(FAKE_BW)
        os.chmod(self.bw, 0o755)
        os.environ["FAKE_BW_STATE"] = self.state
        self.addCleanup(os.environ.pop, "FAKE_BW_STATE", None)
        pw = os.path.join(d, "pw")
        open(pw, "w").write("m")
        self.b = self.backend_class("https://v.example", pw, bw=self.bw, idle_timeout=0)
        self.addCleanup(self.b.close)

    def items(self):
        return {i["name"]: i for i in json.load(open(self.state))["items"]}

    def test_create_each_field_kind_in_org_collection(self):
        self.b.put("A", "notes", "n-val", create=True)
        self.b.put("B", "password", "p-val", create=True)
        self.b.put("C", "api_key", "c-val", create=True)
        it = self.items()
        self.assertEqual((it["A"]["type"], it["A"]["notes"]), (2, "n-val"))
        self.assertEqual(it["B"]["login"]["password"], "p-val")
        self.assertEqual(it["C"]["fields"][0], {"name": "api_key", "value": "c-val", "type": 1})
        for k in "ABC":
            self.assertEqual((it[k]["organizationId"], it[k]["collectionIds"]), ("org1", ["col1"]))
        self.assertEqual(self.b.get("C", "api_key"), "c-val")           # readable straight away

    def test_auto_field_follows_item_type(self):
        self.b.put("Note", "notes", "n-val", create=True)
        self.b.put("Login", "password", "p-val", create=True)
        for f in ("auto", None, ""):
            self.assertEqual(self.b.get("Note", f), "n-val")
            self.assertEqual(self.b.get("Login", f), "p-val")
        self.b.put("Note", "auto", "n2", create=False)
        self.b.put("Login", "auto", "p2", create=False, keep_previous=True)
        it = self.items()
        self.assertEqual(it["Note"]["notes"], "n2")
        self.assertEqual(it["Login"]["login"]["password"], "p2")
        self.assertEqual({f["name"]: f["value"] for f in it["Login"]["fields"]}["previous_value"], "p-val")

    def test_create_recovers_from_an_invalidated_session(self):
        real, calls = self.b._resolve_target, []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise BackendError("Expecting value: line 1 column 1 (char 0)")
            return real()
        self.b._resolve_target = flaky
        self.b.put("Recovered", "notes", "v", create=True)
        self.assertEqual(self.items()["Recovered"]["notes"], "v")
        self.assertEqual(len(calls), 2)

    def test_duplicate_create_refused(self):
        self.b.put("A", "notes", "1", create=True)
        with self.assertRaises(BackendError):
            self.b.put("A", "notes", "2", create=True)
        self.assertEqual(self.items()["A"]["notes"], "1")

    def test_update_replaces_and_keeps_previous(self):
        self.b.put("A", "notes", "old", create=True)
        self.b.put("A", "notes", "new", create=False, keep_previous=True)
        a = self.items()["A"]
        self.assertEqual(a["notes"], "new")
        fields = {f["name"]: f["value"] for f in a["fields"]}
        self.assertEqual(fields["previous_value"], "old")
        self.assertIn("previous_replaced_at", fields)
        self.b.put("A", "notes", "newer", create=False, keep_previous=True)   # no field pile-up
        a = self.items()["A"]
        self.assertEqual(len([f for f in a["fields"] if f["name"] == "previous_value"]), 1)
        self.assertEqual({f["name"]: f["value"] for f in a["fields"]}["previous_value"], "new")

    def test_update_missing_item_and_missing_field(self):
        with self.assertRaises(BackendError):
            self.b.put("Nope", "notes", "x", create=False)
        self.b.put("C", "api_key", "v", create=True)
        with self.assertRaises(BackendError):
            self.b.put("C", "other", "x", create=False)

    def test_ambiguous_target_requires_config(self):
        with open(self.state, "w") as f:
            json.dump({"items": [], "in": False, "n": 0,
                       "orgs": [{"id": "o1", "name": "One"}, {"id": "o2", "name": "Two"}]}, f)
        with self.assertRaises(BackendError):
            self.b.put("A", "notes", "x", create=True)

    def test_delete_rolls_back(self):
        self.b.put("A", "notes", "x", create=True)
        self.b.delete("A")
        self.assertNotIn("A", self.items())
        self.b.delete("A")                                              # idempotent


class AutoCreate(Harness):
    """Creating a credential needs no tap by default; updating still does."""
    decision = None
    NEW = "auto-created-credential-VALUE-987"

    def store(self, op="create", name="autoapi", **kw):
        body = {"mode": "store", "names": [name], "op": op, "value": self.NEW}
        if op == "create":
            body["allowed_hosts"] = ["127.0.0.1"]
        body.update(kw)
        return self.api("POST", "/v1/requests", body)

    def test_create_is_stored_without_a_prompt_and_audited(self):
        code, body = self.store()
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        r = json.loads(b)
        self.assertEqual((r["status"], r["stored"]["name"]), ("approved", "autoapi"))
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.broker.backend._data["autoapi"]["notes"], self.NEW)
        sec = self.disk()["secrets"]["autoapi"]
        self.assertEqual(sec.get("approval", "prompt"), "prompt")        # use still prompts
        self.assertEqual(sec["created"]["by"], "policy:auto-create")
        a = self.events("approved")[0]
        self.assertEqual(a["via"], "policy")
        with open(self.audit) as f:
            self.assertNotIn(self.NEW, f.read())

    def test_update_still_needs_a_human(self):
        self.store()
        self.store("update", "svc", value="rotated-value-1234")
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertEqual(self.broker.backend._data["Svc"]["token"], SECRET)

    def test_opt_out_restores_the_prompt(self):
        self.broker.cfg["store"] = {"create": "prompt"}
        self.store()
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertNotIn("autoapi", self.broker.backend._data)


class MultiValue(Harness):
    """Several values in one vault field, selected with a `key` on the var."""
    DOTENV = "# creds\nCLIENT_ID=abc\nCLIENT_SECRET: \"s3cr3t\"\nREGION=us-east-1\n"

    def tweak(self, cfg):
        cfg["secrets"]["multi"] = {
            "vars": {"M_ID": {"item": "Multi", "field": "notes", "key": "CLIENT_ID"},
                     "M_SECRET": {"item": "Multi", "key": "CLIENT_SECRET"},
                     "M_REGION": {"item": "Multi", "field": "notes", "key": "REGION"}},
            "allowed_hosts": ["127.0.0.1"]}

    def setUp(self):
        super().setUp()
        self.broker.backend._data["Multi"]["notes"] = self.DOTENV

    def test_keys_split_one_field_into_vars(self):
        code, body = self.create_env(("multi",))
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["env"], {
            "M_ID": "abc", "M_SECRET": "s3cr3t", "M_REGION": "us-east-1"})

    def test_json_field_and_missing_key(self):
        self.broker.backend._data["Multi"]["notes"] = json.dumps(
            {"CLIENT_ID": "j1", "CLIENT_SECRET": "j2", "REGION": "eu", "NOPE": 5})
        code, body = self.create_env(("multi",))
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["env"]["M_SECRET"], "j2")
        self.broker.backend._data["Multi"]["notes"] = "CLIENT_ID=only"
        code, body = self.create_env(("multi",))
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "failed")
        self.assertNotIn("only", self.events("failed")[-1].get("error", ""))

    def test_update_one_key_keeps_the_rest(self):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["multi"], "op": "update", "var": "M_SECRET",
            "value": "rotated"})
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "approved")
        rec = self.broker.backend._data["Multi"]
        self.assertEqual(rec["notes"], self.DOTENV.replace('"s3cr3t"', "rotated"))
        self.assertEqual(rec["previous_value"], self.DOTENV)


class BwServeWrites(BwBackendWrites):
    """Everything the CLI backend does, through one long-lived `bw serve`."""
    backend_class = BwServeBackend

    def alive(self):
        return self.b._proc is not None and self.b._proc.poll() is None

    def test_one_server_for_many_operations(self):
        log = os.path.join(os.path.dirname(self.state), "serve.log")
        os.environ["FAKE_BW_SERVE_LOG"] = log
        self.addCleanup(os.environ.pop, "FAKE_BW_SERVE_LOG", None)
        for n in "ABC":
            self.b.put(n, "notes", n.lower(), create=True)
            self.assertEqual(self.b.get(n, "notes"), n.lower())
        self.assertEqual(open(log).read().count("start"), 1)
        self.assertTrue(self.alive())

    def test_exact_name_not_substring(self):
        self.b.put("OpenAI Backup", "notes", "b", create=True)
        self.b.put("openai", "notes", "o", create=True)        # not a collision with the longer name
        self.assertEqual(self.b.get("openai", "notes"), "o")
        self.assertEqual(self.b.get("OPENAI BACKUP", "notes"), "b")   # case-insensitive fallback
        with self.assertRaises(BackendError):
            self.b.put("openai", "notes", "x", create=True)           # exact name exists

    def test_secrets_never_travel_over_the_http_port(self):
        seen = []
        orig = self.b._http

        def spy(method, path, body=None, timeout=60):
            seen.append((method, path, json.dumps(body)))
            return orig(method, path, body, timeout)
        self.b._http = spy
        self.b.put("A", "notes", "a", create=True)
        self.assertNotIn("/unlock", [p for _, p, _ in seen])
        self.assertNotIn('"m"', " ".join(b for _, _, b in seen))        # master password is "m"

    def test_refuses_a_port_it_does_not_own(self):
        self.b._owns_port = lambda: False
        self.b._startup_timeout = 1.5
        with self.assertRaises(BackendError):
            self.b.put("A", "notes", "a", create=True)
        self.assertIsNone(self.b._proc)

    def test_close_stops_the_server(self):
        self.b.put("A", "notes", "a", create=True)
        proc = self.b._proc
        self.assertTrue(self.alive())
        self.b.close()
        self.assertIsNotNone(proc.poll())
        self.assertIsNone(self.b._session)

    def test_restarts_if_the_server_dies(self):
        self.b.put("A", "notes", "a", create=True)
        self.b._proc.kill()
        self.b._proc.wait()
        self.assertEqual(self.b.get("A", "notes"), "a")           # one retry restarts it
        self.assertTrue(self.alive())


class StructuredParsing(unittest.TestCase):
    def test_parse_forms(self):
        from secret_broker import structured as st
        self.assertEqual(st.parse("export A=1\nB = two words\n#C=3\nD='q'"),
                         {"A": "1", "B": "two words", "D": "q"})
        with self.assertRaises(st.StructuredError):
            st.parse("just a bare token")
        with self.assertRaises(st.StructuredError):
            st.set_key("A=1", "B", "x")

    def test_set_key_round_trips_and_targets_the_right_span(self):
        from secret_broker import structured as st
        t = "export port=1\nPORT=2\nB=3 # keep\n"
        self.assertEqual(st.parse(st.set_key(t, "port", "9")), {"port": "9", "PORT": "2", "B": "3 # keep"})
        self.assertEqual(st.set_key(t, "port", "9").splitlines()[0], "export port=9")
        for v in (" lead", "trail ", '"quoted"', "'q'", "a b", "x#y", "=eq", ""):
            self.assertEqual(st.get(st.set_key("K=old", "K", v), "K"), v, v)
        with self.assertRaises(st.StructuredError):
            st.set_key("K=old", "K", "x\nINJECT=1")
        with self.assertRaises(st.StructuredError):
            st.set_key("K=old", "K", " \"'")


class StoreFlow(Harness):
    NEW = "brand-new-credential-VALUE-123"

    def tweak(self, cfg):
        cfg["store"] = {"create": "prompt"}     # these tests cover the human-approval path

    def store(self, op="create", name="newapi", value=None, **kw):
        body = {"mode": "store", "names": [name], "op": op,
                "value": self.NEW if value is None else value}
        if op == "create":
            body.setdefault("allowed_hosts", ["127.0.0.1"])
        body.update(kw)
        return self.api("POST", "/v1/requests", body)

    def result(self, body):
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        return json.loads(b)

    def test_create_maps_secret_and_is_immediately_usable(self):
        code, body = self.store()
        self.assertEqual(code, 202)
        r = self.result(body)
        self.assertEqual(r["stored"], {"name": "newapi", "op": "create", "item": "newapi", "field": "notes"})
        sec = self.disk()["secrets"]["newapi"]
        self.assertEqual(sec["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(sec["vars"], {"NEWAPI_TOKEN": {"field": "notes"}})   # item = the carrier
        self.assertEqual((sec["approval"], sec["created"]["by"]), ("prompt", "alice"))
        self.assertEqual(self.broker.backend._data["newapi"]["notes"], self.NEW)
        _, lst = self.api("GET", "/v1/secrets")
        self.assertIn("newapi", [x["name"] for x in json.loads(lst)["secrets"]])
        # and it works for a real, approved call
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        _, b2 = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["newapi"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{NEWAPI_TOKEN}}"}})
        out = self.result(b2)["http"]["body"]
        self.assertIn("Bearer ***", out)
        self.assertNotIn(self.NEW, out)

    def test_value_never_appears_anywhere_but_the_vault(self):
        self.decision = None
        _, body = self.store()
        req_ = next(iter(self.broker._by_id.values()))
        page = req(self.abase + f"/a/{req_.nonce}", headers={"X-authentik-username": "alice"})[1]
        self.assertNotIn(self.NEW, page)
        self.assertIn("never displayed", page)
        self.assertNotIn(self.NEW, json.dumps(self.notifier.sent))
        self.assertNotIn("approve_always", page)
        self.decision = "approve"
        urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{req_.nonce}", data=b"decision=approve",
            headers={"X-authentication-username": "x", "X-authentik-username": "alice"}, method="POST"),
            timeout=10).read()
        req_.done.wait(10)
        first = self.result(body)
        self.assertEqual((first["status"], first["stored"]["name"]), ("approved", "newapi"))
        self.assertEqual(self.result(body)["status"], "released")      # results are handed out once
        with open(self.audit) as f:
            self.assertNotIn(self.NEW, f.read())
        self.assertNotIn(self.NEW, json.dumps(self.disk()))               # metadata never holds a value
        self.assertIsNone(req_.spec["value"])                           # wiped once settled
        st = self.events("stored")[0]
        self.assertEqual((st["op"], st["value_bytes"]), ("create", len(self.NEW)))

    def test_never_auto_approved_even_for_allow_secrets(self):
        self.decision = None
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.store("update", "svc", value="rotated-value-1234")
        self.assertEqual(len(self.notifier.sent), 1)                     # still asked
        self.assertEqual(self.events("approved"), [])

    def test_update_keeps_mapping_and_previous_value(self):
        before = json.dumps(self.broker.cfg["secrets"]["svc"], sort_keys=True)
        r = self.result(self.store("update", "svc", value="rotated-value-1234")[1])
        self.assertEqual(r["stored"]["op"], "update")
        rec = self.broker.backend._data["Svc"]
        self.assertEqual((rec["token"], rec["previous_value"]), ("rotated-value-1234", SECRET))
        self.assertEqual(json.dumps(self.broker.cfg["secrets"]["svc"], sort_keys=True), before)

    def test_update_cannot_change_hosts_or_item(self):
        self.assertEqual(self.store("update", "svc", allowed_hosts=["evil.example"])[0], 400)
        self.assertEqual(self.store("update", "svc", item="Other")[0], 400)
        self.assertEqual(self.notifier.sent, [])

    def test_validation_rejects_before_any_prompt(self):
        bad = [
            dict(name="Bad Name"), dict(name="x" * 60), dict(value=""),
            dict(value="v" * 70000), dict(name="svc"),                       # create over existing
            dict(allowed_hosts=[]), dict(allowed_hosts=["*.example.com"]),
            dict(allowed_hosts=["evil.com/path"]), dict(allowed_hosts=["a b"]),
            dict(field="previous_value"), dict(var="lower"), dict(item="Svc"),  # item already used
        ]
        for kw in bad:
            kw = dict(kw)
            name = kw.pop("name", "newapi")
            value = kw.pop("value", None)
            code, body = self.store("create", name, value, **kw)
            self.assertEqual(code in (400, 403), True, (kw, code, body))
        self.assertEqual(self.store("update", "ghost")[0], 400)
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("approved"), [])

    def test_store_risk_is_the_model_verdict_or_high(self):
        self.decision = None
        self.broker.summarizer = _Stub("Creates a credential", "high")
        self.store()                                       # create is low, whatever the model says
        self.broker.summarizer = None                      # no verdict: fail closed
        self.store("update", "svc", value="rotated-value-1234")
        levels = [e["risk"] for e in self.events("assessed")]
        self.assertEqual(levels, ["low", "high"])
        self.assertIn("[LOW]", self.notifier.sent[0]["title"])
        self.assertIn("[HIGH]", self.notifier.sent[1]["title"])

    def test_vault_failure_leaves_no_catalog_entry(self):
        def boom(*a, **k):
            raise BackendError("vault down")
        self.broker.backend.put = boom
        _, body = self.store()
        r = self.result(body)
        self.assertEqual(r["status"], "failed")
        self.assertNotIn("newapi", self.broker.cfg["secrets"])
        self.assertNotIn("newapi", self.disk()["secrets"])

    def test_denied_writes_nothing(self):
        self.decision = "deny"
        _, body = self.store()
        self.assertEqual(self.result(body)["status"], "denied")
        self.assertNotIn("newapi", self.broker.backend._data)
        self.assertNotIn("newapi", self.disk()["secrets"])

    def test_create_refused_when_the_backend_has_no_catalog(self):
        class NoCatalog:
            def put(self, *a, **k): pass
            def get(self, *a, **k): return ""
        self.broker.backend = NoCatalog()
        self.assertEqual(self.store()[0], 403)


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
        self.assertEqual(p.stdout.strip(), "svc\tSVC_TOKEN\t127.0.0.1")
        pj = self.run_cli("list", "--json")
        self.assertEqual(json.loads(pj.stdout), [
            {"name": "svc", "vars": ["SVC_TOKEN"], "allowed_hosts": ["127.0.0.1"]}])
        self.assertNotIn(SECRET, p.stdout + pj.stdout)
        self.assertEqual(self.notifier.sent, [])           # no push, no request
        self.assertEqual(self.broker._by_id, {})
        self.assertEqual(self.run_cli("list", "--bogus").returncode, 2)

    def test_list_empty_exit_codes(self):
        self.broker.cfg["secrets"] = {}
        self.assertEqual(self.run_cli("list").returncode, 1)
        pj = self.run_cli("list", "--json")
        self.assertEqual((pj.returncode, json.loads(pj.stdout)), (0, []))

    def test_store_value_from_stdin_never_argv(self):
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY)
        p = subprocess.run([sys.executable, "-I", CLI, "store", "cliapi", "--hosts", "127.0.0.1"],
                           env=env, input="cli-supplied-value-XYZ\n", capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("stored: cliapi (create)", p.stdout)
        self.assertEqual(self.broker.backend._data["cliapi"]["notes"], "cli-supplied-value-XYZ")
        self.assertNotIn("cli-supplied-value-XYZ", p.stdout + p.stderr)
        # a value flag does not exist
        q = subprocess.run([sys.executable, "-I", CLI, "update", "svc", "--value", "x"],
                           env=env, input="y", capture_output=True, text=True, timeout=30)
        self.assertEqual(q.returncode, 2)

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
