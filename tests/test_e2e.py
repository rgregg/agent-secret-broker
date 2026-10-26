import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
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
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit as audit_mod  # noqa: E402
from secret_broker import risk as risk_mod  # noqa: E402
from secret_broker.backends import BwServeBackend  # noqa: E402
from secret_broker.backends import BackendError, BwBackend, FileBackend, MemoryBackend  # noqa: E402
from secret_broker.broker import Broker, serve  # noqa: E402
from secret_broker import notify as notify_mod  # noqa: E402
from secret_broker.notify import FakeNotifier, NotifyError  # noqa: E402


def N(title, text, url, tag, names=(), risk=None, actions=(), token=None):
    """A Notification for tests that drive a transport directly."""
    return notify_mod.Notification(
        rid="rid1", tag=tag, title=title, text=text, names=list(names), risk=risk, url=url,
        source="host", summary=None, expires_at=0,
        actions=[notify_mod.Action(a, a.title()) for a in actions], action_token=token)
from secret_broker.summarize import OpenRouterSummarizer  # noqa: E402

SECRET = "s3cr3t-token-value"
CLI = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
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
        # name resolution must not depend on the machine running the tests (CI resolves `localhost` to ::1 first,
        # and the stubs listen on 127.0.0.1 only): `localhost` is 127.0.0.1 here
        real_resolver = self.broker.dest_guard._resolver
        self.broker.dest_guard._resolver = lambda h, p: ["127.0.0.1"] if h.lower() == "localhost" else real_resolver(h, p)

    def tweak(self, cfg):
        """Subclass hook to adjust the broker config before it starts."""

    def tearDown(self):
        for s in (self.c, self.a, self.up):
            s.shutdown()
            s.server_close()

    def records(self):
        return _fast.read_jsonl(self.audit)

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
        out = req(self.base + path, method, body, {"X-Client-Key": key, "Content-Type": "application/json"})
        if method == "POST" and path == "/v1/requests":
            self.broker.flush_notifications(10)     # sends run on a worker, not the request thread
        return out

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
        rid = json.loads(body)["id"]
        req = self.broker._by_id[rid]
        self.assertAlmostEqual(req.expires - req.created, 1, delta=0.5)      # the ttl is one second
        _fast.expire(self.broker, rid)                                       # ...and it has passed
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
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
            self.assertLessEqual(len(r.summary), 320)
        status, page = req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})
        self.assertEqual(status, 200)
        self.assertNotIn("<script>", page)
        self.assertIn("Generated by", page)                  # the (i) tooltip names the source
        self.assertIn("based on the request.", page)
        self.assertNotIn("client-supplied text", page)


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

    def test_env_mode_prompts_when_the_credential_opts_out(self):
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http"]    # env is auto by default now
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

    def adopt(self, rows, explicit=None):
        class Rows(MemoryBackend):
            def catalog(self_inner):
                return (explicit or []) + rows
        b = Broker({"approve_base_url": "https://s.example"}, Rows(), FakeNotifier(), None)
        return b

    def test_items_without_metadata_are_adopted_with_defaults(self):
        modem = {"item": "Cable Modem", "meta": None, "auto": {
            "login": True, "username": True, "password": True, "notes": True, "fields": [],
            "uris": ["http://192.168.100.1/login", "https://192.168.100.1:8443/"]}}
        b = self.adopt([modem])
        sc = b.cfg["secrets"]["cable-modem"]
        self.assertEqual(sorted(sc["vars"]), ["CABLE_MODEM_PASSWORD", "CABLE_MODEM_USERNAME"])
        self.assertEqual(sc["vars"]["CABLE_MODEM_PASSWORD"]["field"], "password")
        self.assertEqual(sc["allowed_hosts"], ["192.168.100.1"])
        self.assertEqual(sc["approval"], "prompt")          # always asks until told otherwise
        self.assertTrue(sc["auto"])

    def test_adopted_notes_and_custom_fields_and_no_url(self):
        note = {"item": "Wifi 2.4", "meta": None, "auto": {
            "login": False, "username": False, "password": False, "notes": True,
            "fields": ["API Key"], "uris": []}}
        sc = self.adopt([note]).cfg["secrets"]["wifi-2-4"]
        self.assertEqual(sorted(sc["vars"]), ["WIFI_2_4_API_KEY", "WIFI_2_4_NOTE"])
        self.assertEqual(sc["allowed_hosts"], [])           # no URL: env mode only, never http

    def test_explicit_secret_wins_a_name_over_an_adopted_item(self):
        explicit = [{"item": "Real", "meta": json.loads(self.meta(name="grafana"))}]
        stray = {"item": "Grafana", "meta": None, "auto": {
            "login": True, "username": False, "password": True, "notes": False, "fields": [],
            "uris": ["https://evil.example/"]}}
        b = self.adopt([stray], explicit)
        self.assertEqual(b.cfg["secrets"]["grafana"]["_item"], "Real")
        self.assertNotIn("auto", b.cfg["secrets"]["grafana"])

    def test_two_adopted_items_with_one_name_drop_each_other(self):
        one = {"login": True, "username": False, "password": True, "notes": False, "fields": [], "uris": []}
        b = self.adopt([{"item": "Router", "meta": None, "auto": one},
                        {"item": "router", "meta": None, "auto": one}])
        self.assertEqual(b.cfg["secrets"], {})

    def test_dangerous_variable_names_are_rejected(self):
        for var in ("LD_PRELOAD", "PATH", "PYTHONPATH", "NODE_OPTIONS", "GIT_SSH_COMMAND", "BASH_ENV",
                    "CLASSPATH", "OPENSSL_CONF", "HTTPS_PROXY", "SSL_CERT_FILE", "KUBECONFIG",
                    "SECRET_BROKER_URL", "ZDOTDIR", "CURL_HOME"):
            with self.assertRaises(ValueError, msg=var):
                Broker._entry("Item", {"vars": {var: {"field": "notes"}}})
        Broker._entry("Item", {"vars": {"MY_TOKEN": {"field": "notes"}}})   # ordinary names still fine

    def test_adopted_item_cannot_produce_a_dangerous_name(self):
        row = {"item": "LD", "meta": None, "auto": {
            "login": False, "username": False, "password": False, "notes": False,
            "fields": ["PRELOAD"], "uris": []}}
        self.assertEqual(self.adopt([row]).cfg["secrets"], {})

    def test_request_for_secrets_sharing_a_variable_is_rejected(self):
        meta = {"vars": {"SAME_TOKEN": {"field": "notes"}}, "allowed_hosts": ["a.example.com"]}
        b = self.adopt([], [{"item": "One", "meta": meta}, {"item": "Two", "meta": meta}])
        with self.assertRaises(ValueError):
            b.create("env", ["one", "two"], {}, "test")
        b.create("env", ["one"], {}, "test")                # each alone is fine

    def test_disabled_metadata_hides_an_item(self):
        b = self.adopt([], [{"item": "Hidden", "meta": {"disabled": True}}])
        self.assertEqual(b.cfg["secrets"], {})

    def test_bw_backend_adopts_only_its_own_collection(self):
        from secret_broker.backends import BwBackend
        bw = BwBackend("https://v.example", "/dev/null", organization="Org", collection="Coll")
        login = {"type": 1, "name": "In coll", "organizationId": "o1", "collectionIds": ["c1"],
                 "login": {"username": "u", "password": "p", "uris": [{"uri": "https://x.example"}]}}
        other = {**login, "name": "Other coll", "collectionIds": ["c2"]}
        mine = {**login, "name": "Personal", "organizationId": None, "collectionIds": []}
        card = {**login, "name": "A card", "type": 3}
        tagged = {**login, "name": "Tagged", "fields": [{"name": "broker", "type": 0,
                  "value": json.dumps({"vars": {"T": {}}})}]}
        bw._session, bw._synced = "s", time.time()
        bw._list_items = lambda: [login, other, mine, card, tagged]
        bw._resolve_target = lambda: ("o1", "c1")
        rows = bw.catalog()
        self.assertEqual(sorted(r["item"] for r in rows), ["In coll", "Tagged"])
        self.assertTrue(next(r for r in rows if r["item"] == "In coll")["auto"]["password"])
        bw._org_want = None                                   # cannot scope: adopt nothing
        self.assertEqual([r["item"] for r in bw.catalog()], ["Tagged"])

    def test_invalid_metadata_is_skipped_and_audited_fail_closed(self):
        b, audit = self.make({
            "Bad approval": {"notes": "x", "broker": self.meta(approval="sometimes")},
            "Bad var": {"notes": "x", "broker": json.dumps({"vars": {"lower": {}}, "allowed_hosts": []})},
            "Wild": {"notes": "x", "broker": self.meta(allowed_hosts=["*.example.com"])},
            "Garbage": {"notes": "x", "broker": "not json"},
            "Good": {"notes": "x", "broker": self.meta()}})
        self.assertEqual(sorted(b.cfg["secrets"]), ["good"])
        ev = [r for r in _fast.read_jsonl(audit) if r["event"] == "catalog_loaded"][0]
        self.assertEqual(len(ev["invalid"]), 4)

    def test_no_hosts_means_env_only_never_http(self):
        b, _ = self.make({"Wifi": {"notes": "pw", "broker": json.dumps({"vars": {"WIFI_PW": {}}})}})
        self.assertEqual(b.cfg["secrets"]["wifi"]["allowed_hosts"], [])
        with self.assertRaises(PermissionError):
            b.create("http", ["wifi"], {"method": "GET", "url": "https://x.example/", "headers": {},
                                       "body": None}, "t")

    def test_duplicate_names_drop_every_claimant(self):
        # first-wins would let a look-alike item shadow a real secret
        b, _ = self.make({"A": {"notes": "x", "broker": self.meta(name="same")},
                          "B": {"notes": "x", "broker": self.meta(name="same")},
                          "C": {"notes": "x", "broker": self.meta(name="other")}})
        self.assertEqual(list(b.cfg["secrets"]), ["other"])

    def test_metadata_cannot_reach_other_items_or_itself(self):
        b, audit = self.make({
            "Victim": {"notes": "admin-token", "broker": self.meta(name="victim")},
            "Thief": {"notes": "x", "broker": json.dumps({
                "vars": {"T": {"item": "Victim", "field": "notes"}}, "allowed_hosts": ["evil.example"]})},
            "Self": {"notes": "x", "broker": json.dumps({
                "vars": {"T": {"field": "broker"}}, "allowed_hosts": ["evil.example"]})}})
        self.assertEqual(list(b.cfg["secrets"]), ["victim"])

    def test_metadata_field_is_never_read_or_written_as_a_secret(self):
        b, _ = self.make({"A": {"notes": "x", "broker": self.meta()}})
        with self.assertRaises(BackendError):
            b.backend.get("A", "broker")
        with self.assertRaises(BackendError):
            b.backend.put("A", "broker", "{}", create=False)

    def test_a_vault_that_cannot_be_read_does_not_stop_startup(self):
        class Down(MemoryBackend):
            def catalog(self):
                raise BackendError("vault down")
        b = Broker({"approve_base_url": "https://s.example"}, Down(), FakeNotifier(), None)
        self.assertEqual(b.cfg["secrets"], {})

    def test_background_load_returns_at_once_and_requests_wait_for_it(self):
        import threading, time as _t
        gate = threading.Event()

        class Slow(MemoryBackend):
            def catalog(self):
                gate.wait(5)
                return [{"item": "A", "meta": {"name": "a", "allowed_hosts": ["h.example"],
                                               "vars": {"V": {"field": "notes"}}}}]
        t0 = _t.time()
        b = Broker({"approve_base_url": "https://s.example"}, Slow(), FakeNotifier(), None,
                   background_load=True)
        self.assertLess(_t.time() - t0, 1)          # constructor did not wait for the vault
        out = []
        th = threading.Thread(target=lambda: out.append(b.available("h.example")))
        th.start()
        _t.sleep(0.2)
        self.assertTrue(th.is_alive())              # discovery waits instead of answering []
        gate.set()
        th.join(5)
        self.assertEqual([r["name"] for r in out[0]], ["a"])

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
        import ipaddress
        self.broker._approval_proxies = [ipaddress.ip_network("127.0.0.1/32")]    # approval_trusted_proxies
        hdr = {"X-authentik-username": "alice", "X-Forwarded-For": "203.0.113.9, 198.51.100.1"}
        status, _ = req(self.abase + f"/a/{nonce}", headers=hdr)
        self.assertEqual(status, 200)
        v = self.events("approval_viewed")[0]
        # the walk takes the rightmost untrusted hop, never the (spoofable) leftmost value
        self.assertEqual((v["user"], v["client_ip"], v["found"]), ("alice", "198.51.100.1", True))
        data = urllib.parse.urlencode({"decision": "approve"}).encode()
        urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{nonce}", data=data, headers=hdr, method="POST"), timeout=10).read()
        next(iter(self.broker._by_id.values())).done.wait(10)
        self.assertEqual(self.events("approved")[0]["approver_ip"], "198.51.100.1")
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
        self.assertEqual(self.events("client_auth_failed")[0]["peer"], "127.0.0.1")
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
        cfg["risk"] = {"auto_approve_max": "medium"}

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


class AutoApproveMax(Harness):
    """risk.auto_approve_max: the highest model risk at which an eligible request skips the prompt."""
    decision = None

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = "allow"

    def http(self, name="svc"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        return self.api("POST", "/v1/requests", {
            "mode": "http", "names": [name], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})

    def test_every_setting_against_every_verdict(self):
        for setting in risk_mod.AUTO_MAX:
            for verdict in ("low", "medium", "high", None):
                with self.subTest(setting=setting, verdict=verdict):
                    self.broker._auto_max = setting
                    self.broker.summarizer = _Stub("x", verdict) if verdict else None
                    self.broker._by_id.clear()          # keep under MAX_PENDING
                    before = (len(self.notifier.sent), len(self.events("approved")))
                    self.http()
                    want_auto = setting != "none" and risk_mod.rank(verdict or "high") <= (
                        risk_mod.rank(setting) if setting != "none" else -1)
                    self.assertEqual(len(self.events("approved")) - before[1], 1 if want_auto else 0)
                    self.assertEqual(len(self.notifier.sent) - before[0], 0 if want_auto else 1)
                    if want_auto:
                        self.assertEqual(self.events("approved")[-1]["auto_max"], setting)
                    else:
                        self.assertEqual(self.events("escalated")[-1]["auto_max"], setting)

    def test_none_blocks_even_allow_secrets_and_store_create(self):
        self.broker._auto_max = "none"
        self.broker.summarizer = _Stub("x", "low")
        self.http()
        self.assertEqual(len(self.notifier.sent), 1)
        self.assertIn("auto-approve is off", self.events("escalated")[-1]["reason"])
        self.api("POST", "/v1/requests", {"mode": "store", "names": ["new-one"], "op": "create",
                                          "value": "v", "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual(len(self.notifier.sent), 2)

    def test_high_opens_risk_only_for_eligible_secrets_and_modes(self):
        self.broker._auto_max = "high"
        self.broker.summarizer = None                      # no verdict counts as high
        self.http()
        self.assertEqual(len(self.events("approved")), 1)
        self.assertEqual(self.notifier.sent, [])
        # approval: prompt stays a prompt at any setting
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.http()
        self.assertEqual(len(self.notifier.sent), 1)
        # an allow secret is auto for env too by default; auto_modes ["http"] opts out
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http"]
        self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["true"]})
        self.assertEqual(len(self.notifier.sent), 2)
        self.assertEqual(len(self.events("approved")), 1)

    def test_default_is_low_and_status_reports_it(self):
        self.assertEqual(self.broker.auto_approve_max(), "low")
        _, b = self.api("GET", "/v1/status")
        self.assertEqual(json.loads(b)["features"]["auto_approve_max"], "low")
        self.assertNotIn("escalate", b)

    def test_settings_page_shows_the_line(self):
        for setting, text in (("none", "Off (every request asks a human)"), ("low", "Up to low risk"),
                              ("medium", "Up to medium risk"), ("high", "Any risk level")):
            self.broker._auto_max = setting
            _, body = req(self.abase + "/settings", headers={"X-authentik-username": "alice"})
            self.assertIn("<b>Auto-approve</b>", body)
            self.assertIn(text, body)
            self.assertIn("risk.auto_approve_max", body)

    def test_always_allow_is_not_offered_when_the_setting_would_block_it(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.broker.summarizer = _Stub("x", "medium")
        for setting, offered in (("none", False), ("low", False), ("medium", True), ("high", True)):
            self.broker._auto_max = setting
            self.broker._by_id.clear()
            self.http()
            r = list(self.broker._by_id.values())[-1]
            self.assertEqual(self.broker.always_allow_eligibility(r)[0], offered, setting)
        self.broker.summarizer = _Stub("x", "high")
        self.broker._by_id.clear()
        self.http()
        self.assertFalse(self.broker.always_allow_eligibility(list(self.broker._by_id.values())[-1])[0])


class AutoApproveConfig(unittest.TestCase):
    parse = staticmethod(risk_mod.parse_auto_approve_max)

    def test_default_and_explicit_values(self):
        self.assertEqual(self.parse(None), ("low", None))
        self.assertEqual(self.parse({}), ("low", None))
        for v in ("none", "low", "medium", "high"):
            self.assertEqual(self.parse({"auto_approve_max": v}), (v, None))

    def test_legacy_escalate_auto_at_maps_one_level_down(self):
        for old, new in (("low", "none"), ("medium", "low"), ("high", "medium")):
            self.assertEqual(self.parse({"escalate_auto_at": old}), (new, None))

    def test_both_present_new_wins_and_warns(self):
        got, warn = self.parse({"auto_approve_max": "high", "escalate_auto_at": "low"})
        self.assertEqual(got, "high")
        self.assertIn("escalate_auto_at is ignored", warn)

    def test_invalid_values_name_the_field(self):
        for raw, field in (({"auto_approve_max": "all"}, "risk.auto_approve_max"),
                           ({"auto_approve_max": 3}, "risk.auto_approve_max"),
                           ({"escalate_auto_at": "none"}, "risk.escalate_auto_at"),
                           ({"escalate_auto_at": "bogus"}, "risk.escalate_auto_at"), ("high", "risk")):
            with self.assertRaises(ValueError) as cm:
                self.parse(raw)
            self.assertIn(field, str(cm.exception))

    def test_auto_ok_treats_a_missing_level_as_high(self):
        for mx, want in (("none", False), ("low", False), ("medium", False), ("high", True)):
            self.assertEqual(risk_mod.auto_ok(None, mx), want)
            self.assertEqual(risk_mod.auto_ok("bogus", mx), want)

    def _broker(self, risk):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "v.json")
        with open(path, "w") as f:
            json.dump({}, f)
        cfg = {"approve_base_url": "https://s.example", "allowed_user": "a", "ttl_seconds": 5}
        if risk is not None:
            cfg["risk"] = risk
        return Broker(cfg, FileBackend(path), FakeNotifier(), os.path.join(d, "audit.jsonl")), d

    def test_broker_validates_at_startup_and_logs_the_warning(self):
        with self.assertRaises(ValueError) as cm:
            self._broker({"auto_approve_max": "everything"})
        self.assertIn("risk.auto_approve_max", str(cm.exception))
        b, d = self._broker({"auto_approve_max": "medium", "escalate_auto_at": "high"})
        self.assertEqual(b.auto_approve_max(), "medium")
        warns = [r for r in _fast.read_jsonl(os.path.join(d, "audit.jsonl")) if r["event"] == "config_warning"]
        self.assertEqual(len(warns), 1)
        self.assertEqual(self._broker({"escalate_auto_at": "high"})[0].auto_approve_max(), "medium")
        self.assertEqual(self._broker(None)[0].auto_approve_max(), "low")

    def test_main_rejects_a_bad_value_before_starting(self):
        r = subprocess.run([sys.executable, "-m", "secret_broker"], capture_output=True, text=True,
                           cwd=os.path.join(os.path.dirname(__file__), ".."),
                           env={**os.environ, "BROKER_CONFIG": json.dumps(
                               {"backend": {"type": "file", "path": "/nonexistent"},
                                "risk": {"auto_approve_max": "bogus"}})})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("risk.auto_approve_max", r.stderr)


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
        n.send(N("Secret request [LOW]", "svc from host", "https://secrets.example/a/NONCE", "secret-abc"))
        path, body = FakeTelegram.calls[0]
        self.assertEqual(path, f"/bot{self.TOKEN}/sendMessage")
        self.assertEqual(body["chat_id"], "4242")
        kb = body["reply_markup"]["inline_keyboard"][0][0]
        self.assertEqual(kb["url"], "https://secrets.example/a/NONCE")
        self.assertNotIn("callback_data", kb)             # approval cannot happen in-chat

    def test_resolved_edits_message(self):
        n = self.tg()
        note = N("t", "m", "https://x.example/a/n", "tag1")
        n.send(note)
        n.resolved(note, "approved")
        path, body = FakeTelegram.calls[-1]
        self.assertTrue(path.endswith("/editMessageText"))
        self.assertEqual(body["message_id"], 77)
        self.assertIn("APPROVED", body["text"])

    def test_error_never_contains_bot_token(self):
        FakeTelegram.fail = 401
        with self.assertRaises(NotifyError) as cm:
            self.tg().send(N("t", "m", "https://x.example/a/n", "tag"))
        self.assertNotIn("SECRET-BOT-TOKEN", str(cm.exception))
        self.assertIn("401", str(cm.exception))

    def test_multi_delivers_if_any_succeeds(self):
        class Boom:
            def send(self, *a, **k):
                raise NotifyError("down")
        ok = FakeNotifier()
        multi = notify_mod.MultiNotifier([Boom(), ok])
        multi.send(N("t", "m", "u", "tag"))
        self.assertEqual(len(ok.sent), 1)
        with self.assertRaises(NotifyError):
            notify_mod.MultiNotifier([Boom(), Boom()]).send(N("t", "m", "u", "tag"))

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
    """A vault read that blocks until the test opens `gate` (so a release can be held mid-flight); `entered`
    is set when a read has started."""
    reads = 0

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.gate, self.entered = threading.Event(), threading.Event()

    def get(self, item, field):
        SlowBackend.reads += 1
        self.entered.set()
        self.gate.wait(10)
        return super().get(item, field)


class DoubleSubmit(Harness):
    decision = None

    def setUp(self):
        super().setUp()
        SlowBackend.reads = 0
        self.broker.backend = self.slow = SlowBackend(os.path.join(os.path.dirname(self.audit), "vault.json"))
        self.addCleanup(self.slow.gate.set)

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
        first = threading.Thread(target=post)
        first.start()
        self.assertTrue(self.slow.entered.wait(10))        # the first release is inside the vault read...
        second = threading.Thread(target=post)
        second.start()                                     # ...when the second approval arrives
        second.join()
        self.slow.gate.set()
        first.join()
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
        self.broker.backend = self.slow = SlowBackend(os.path.join(os.path.dirname(self.audit), "vault.json"))
        self.addCleanup(self.slow.gate.set)

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
        self.assertFalse(self.slow.gate.is_set())        # the page answered while the vault read is still blocked
        # the decision is on record immediately; the release outcome is not yet
        self.assertEqual(self.events("decided")[0]["decision"], "approve")
        self.assertEqual(self.events("approved"), [])
        self.assertEqual([s for _, s in getattr(self.notifier, "resolutions", [])], ["approved"])
        self.slow.gate.set()                             # let the release finish
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
    """Session is kept for idle_timeout after last use, then logged out.

    The idle timer is driven by a fake monotonic clock: `idle` is armed with a long real timer that never
    fires, `lapse` moves the clock and runs the callback the timer would run."""

    def setUp(self):
        super().setUp()
        from secret_broker.backends import bitwarden as bw_mod
        self.mono = _fast.patch_mono(self, bw_mod)

    def backend(self, idle):
        b = BwBackend("https://v.example", self.pw, bw=self.bw, idle_timeout=idle)
        self.addCleanup(b.close)
        self.events = []
        b.on_event = lambda name, **kw: self.events.append(name)
        return b

    def lapse(self, b, seconds):
        self.mono.advance(seconds)
        if b._idle_timeout:
            b._idle_logout()                              # what the timer calls when it fires

    def test_logs_out_after_idle_then_recovers(self):
        b = self.backend(300)
        self.assertEqual(b.get("T", "notes"), "v")
        self.assertNotIn("logout", self.calls())
        self.lapse(b, 301)
        self.assertEqual(self.calls().count("logout"), 1)
        self.assertEqual(self.events, ["backend_closed"])
        self.assertEqual(b.get("T", "notes"), "v")        # transparently logs in again
        self.assertEqual(self.calls().count("login"), 2)

    def test_use_extends_the_window(self):
        b = self.backend(300)
        b.get("T", "notes")
        self.lapse(b, 200)                                # not yet idle for 300 s
        self.assertNotIn("logout", self.calls())
        b.get("T", "notes")                               # re-arms the timer
        self.lapse(b, 200)                                # 400 s since first use, 200 s since last
        self.assertNotIn("logout", self.calls())
        self.lapse(b, 101)                                # 301 s since the last use
        self.assertEqual(self.calls().count("logout"), 1)

    def test_idle_timeout_zero_disables_logout(self):
        b = self.backend(0)
        b.get("T", "notes")
        self.lapse(b, 100000)
        self.assertNotIn("logout", self.calls())
        self.assertIsNone(b._timer)

    # inherited warm/resync tests don't depend on idle behaviour
    test_warm_then_get_does_not_unlock_or_resync = None
    test_resync_after_interval = None


class PrewarmStub(MemoryBackend):
    capabilities = frozenset({"warm"})

    def __init__(self):
        super().__init__()
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
        self.stub.capabilities = frozenset()      # a backend that does not declare "warm"
        self.create_env()
        _fast.quiesce(self.broker)                # any warm-up thread has run by now
        self.assertEqual(self.stub.count, 0)


class AlwaysAllow(Harness):
    decision = None

    def tweak(self, cfg):
        cfg["risk"] = {"auto_approve_max": "medium"}

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
        self.assertEqual(d["secrets"]["svc"].get("approval", "prompt"), "prompt")   # narrow, not credential-wide
        st = d["secrets"]["svc"]["standing"]                             # written to the vault item
        self.assertEqual([(e["mode"], e["scope"], e["created_by"], e["expires_at"]) for e in st],
                         [("http", "read", "alice", None)])             # a GET: reads only
        self.assertEqual(d["secrets"]["svc"]["allowed_hosts"], ["127.0.0.1"])   # rest untouched
        self.assertEqual(self.events("policy_changed"), [])
        ch = self.events("grant_created")[0]
        self.assertEqual((ch["kind"], ch["scope"], ch["expires_at"], ch["created_by"]), ("always", "read", None, "alice"))
        self.assertTrue(self.events("decided")[0]["always_requested"])
        pushes = len(self.notifier.sent)
        _, b = self.http_req()                                       # next call: no prompt
        self.assertEqual(len(self.notifier.sent), pushes)
        _, r = self.api("GET", f"/v1/requests/{json.loads(b)['id']}?wait=3")
        self.assertEqual(json.loads(r)["http"]["status"], 200)
        self.assertEqual(self.events("approved")[-1]["via"], "policy")
        self.http_req("DELETE")                                      # a reads-only Always never covers this
        self.assertEqual(len(self.notifier.sent), pushes + 1)
        self.assertEqual(self.events("grant_skipped")[-1]["reason"], "method")

    def test_env_mode_is_offered_the_stronger_confirm_and_applies(self):
        self.create_env()
        page = self.page()
        self.assertIn("value=approve_always", page)
        self.assertIn("released to the requesting machine without asking again", page)
        status, body = self.post(f"/a/{self.nonce()}", decision="approve_always")
        self.assertEqual(status, 200)
        self.assertIn("Always allow saved", body)
        self.finish()
        self.assertEqual([(e["mode"], e["scope"]) for e in self.disk()["secrets"]["svc"]["standing"]],
                         [("env", "any")])

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
        orig = self.broker._persist_standing

        def boom(*a, **k):
            raise OSError("disk full")
        self.broker._persist_standing = boom
        status, body = self.post(f"/a/{self.nonce()}", decision="approve_always")
        self.broker._persist_standing = orig
        self.assertEqual(status, 200)
        self.assertIn("could not write", body)
        self.finish()
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertEqual(len(self.events("standing_change_failed")), 1)
        self.assertNotIn("standing", self.broker.cfg["secrets"]["svc"])
        self.assertEqual(len(self.events("approved")), 1)

    def test_policies_page_can_only_tighten(self):
        self.assertTrue(self.broker.set_approval("svc", "allow", "alice"))
        status, body = req(self.abase + "/policies", headers={"X-authentik-username": "alice"})
        self.assertEqual(status, 200)
        self.assertIn("Revoke", body)
        self.assertNotIn("Nothing is always allowed", body)
        # granting is refused here
        tok = self.broker.csrf_token("alice")
        self.assertEqual(self.post("/policies", name="svc", approval="allow", csrf=tok)[0], 400)
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "allow")
        self.assertEqual(self.post("/policies", name="svc", approval="prompt")[0], 403)   # no csrf token
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "allow")
        status, body = self.post("/policies", name="svc", approval="prompt", csrf=tok)
        self.assertEqual(status, 200)
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "prompt")
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["approval"], "prompt")
        self.assertEqual(self.post("/policies", name="nope", approval="prompt", csrf=tok)[0], 400)

    def test_policies_page_requires_identity(self):
        r = req(self.abase + "/policies", headers={"X-authentik-username": "mallory"})
        self.assertEqual(r[0], 403)


FAKE_BW = r"""#!/bin/sh
# A fake `bw`. It is started for every vault call, so interpreter start-up is the cost: commands that need no
# state are answered by the shell, and the rest run the Python below (started with -I -S, base64 imported lazily).
case "$1" in
  config|sync|lock|logout) exit 0;;
  unlock) echo SESSION; exit 0;;
  status)
    if [ -f "$FAKE_BW_STATE" ] && grep -q '"in": true' "$FAKE_BW_STATE"; then
      echo '{"status": "locked"}'
    else
      echo '{"status": "unauthenticated"}'
    fi
    exit 0;;
esac
PY=$(cat <<'PYEOF'
import json, os, sys
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
    import base64
    print(base64.b64encode(sys.stdin.read().encode()).decode())
elif cmd == "list" and a[1] == "organizations":
    print(json.dumps(d.get("orgs", [{"id": "org1", "name": "Org"}])))
elif cmd == "list" and a[1] == "collections":
    print(json.dumps(d.get("colls", [{"id": "col1", "name": "Shared"}])))
elif cmd == "list" and a[1] == "items":
    print(json.dumps(d["items"]))
elif cmd == "get":
    hits = [i for i in d["items"] if i["name"] == a[2] or i["id"] == a[2]]
    if not hits:
        print("Not found.", file=sys.stderr); sys.exit(1)
    if len(hits) > 1:
        print("More than one result was found.", file=sys.stderr); sys.exit(1)
    print(json.dumps(hits[0]))
elif cmd in ("create", "edit"):
    import base64
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
PYEOF
)
exec python3 -I -S -c "$PY" "$@"
"""


class BwBackendWrites(unittest.TestCase):
    backend_class = BwBackend

    def setUp(self):
        from secret_broker.backends import bitwarden as bw_mod
        _fast.patch_mono(self, bw_mod)       # start-up polling inside the backend does not sleep for real
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


def _self_signed(tmp):
    """(certfile, keyfile, sha256 hex) for a throwaway self-signed certificate."""
    import hashlib
    import shutil
    import ssl
    import subprocess
    if shutil.which("openssl") is None:
        raise unittest.SkipTest("openssl not available")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", cert, "-subj", "/CN=device.lan", "-days", "2"],
                   check=True, capture_output=True)
    der = ssl.PEM_cert_to_DER_cert(open(cert).read())
    return cert, key, hashlib.sha256(der).hexdigest()


class TlsModes(Harness):
    """Self-signed devices: pinned fingerprint, or verification off (private only)."""
    decision = "approve"
    pin = None

    def tweak(self, cfg):
        self.tls_dir = tempfile.mkdtemp()
        self.cert, self.key, self.fp = _self_signed(self.tls_dir)
        sc = cfg["secrets"]["svc"]
        if self.pin == "good":
            sc["tls_fingerprint"] = "sha256:" + self.fp
        elif self.pin == "bad":
            sc["tls_fingerprint"] = "sha256:" + "0" * 64
        elif self.pin == "noverify":
            sc["tls_verify"] = False

    def setUp(self):
        super().setUp()
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.tls_up = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        self.tls_up.socket = ctx.wrap_socket(self.tls_up.socket, server_side=True)
        threading.Thread(target=self.tls_up.serve_forever, daemon=True).start()
        self.addCleanup(self.tls_up.shutdown)

    def go(self):
        url = f"https://127.0.0.1:{self.tls_up.server_address[1]}/x"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=8")
        return json.loads(b)

class TlsDefault(TlsModes):
    def test_default_rejects_a_self_signed_certificate(self):
        self.assertEqual(self.go()["status"], "failed")


class TlsPinned(TlsModes):
    pin = "good"

    def test_matching_fingerprint_is_accepted(self):
        r = self.go()
        self.assertEqual((r["status"], r["http"]["status"]), ("approved", 200))
        self.assertNotIn(SECRET, json.dumps(r))


class TlsPinnedList(TlsModes):
    pin = "list"

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["tls_fingerprint"] = ["sha256:" + "1" * 64, "sha256:" + self.fp]

    def test_any_listed_fingerprint_matches(self):
        r = self.go()
        self.assertEqual((r["status"], r["http"]["status"]), ("approved", 200))


class TlsPinnedWrong(TlsModes):
    pin = "bad"

    def test_wrong_fingerprint_is_refused(self):
        r = self.go()
        self.assertEqual(r["status"], "failed")
        self.assertIn("release failed: tls", " ".join(e.get("error", "") for e in self.events("failed")))   # a label, never the library's text


class TlsNoVerifyPrivate(TlsModes):
    pin = "noverify"

    def test_unverified_tls_is_allowed_for_a_private_host(self):
        r = self.go()
        self.assertEqual((r["status"], r["http"]["status"]), ("approved", 200))


class TlsPolicyRules(unittest.TestCase):
    def entry(self, **kw):
        meta = {"vars": {"T": {}}, "allowed_hosts": ["api.example.com"], **kw}
        return Broker._entry("Item", meta)[1]

    def test_unverified_tls_refused_for_public_hosts(self):
        with self.assertRaises(ValueError):
            self.entry(tls_verify=False)
        with self.assertRaises(ValueError):
            self.entry(tls_verify=False, allowed_hosts=["10.0.0.5", "api.example.com"])
        self.assertEqual(self.entry(tls_verify=False, allowed_hosts=["10.0.0.5", "pikvm.lan"])["_tls"],
                         {"fingerprint": None, "verify": False})

    def test_several_fingerprints_are_all_accepted_and_normalised(self):
        a, b = "ab" * 32, "cd" * 32
        t = self.entry(tls_fingerprint=["sha256:" + b, a, a])["_tls"]
        self.assertEqual(t["fingerprint"], (a, b))                 # sorted, de-duplicated
        with self.assertRaises(ValueError):
            self.entry(tls_fingerprint=[a, "nope"])
        with self.assertRaises(ValueError):
            self.entry(tls_fingerprint=[])

    def test_fingerprint_forms_and_validation(self):
        h = "ab" * 32
        for form in (h, "sha256:" + h, "SHA256:" + ":".join(h[i:i + 2] for i in range(0, 64, 2)).upper()):
            self.assertEqual(self.entry(tls_fingerprint=form)["_tls"]["fingerprint"], (h,))
        with self.assertRaises(ValueError):
            self.entry(tls_fingerprint="sha256:1234")
        # a pin makes tls_verify=false unnecessary even for public names
        self.assertEqual(self.entry(tls_fingerprint=h, tls_verify=False)["_tls"]["fingerprint"], (h,))


class HistoryPage(Harness):
    """The history list lives on the Requests tab (`/`); rows open a detail view."""
    ttl = 1

    def tweak(self, cfg):
        cfg["risk"] = {"auto_approve_max": "medium"}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Reads things", "low")

    def call(self, path="/x?token=QUERYSECRET", decision="approve", wait=5, **extra):
        self.decision = decision
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}, **extra})
        rid = json.loads(body)["id"]
        if decision is None:
            _fast.expire(self.broker, rid)              # nobody answers: the 1 s ttl passes
        _, b = self.api("GET", f"/v1/requests/{rid}?wait={wait}")
        return rid, json.loads(b)

    def page(self, query="?view=all", user="alice"):
        return req(self.abase + "/" + query, headers={"X-authentik-username": user})

    def result(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)

    def detail(self, rid, user="alice", frag=True):
        return req(self.abase + f"/request/{rid}" + ("?fragment=1" if frag else ""),
                   headers={"X-authentik-username": user})

    def test_every_outcome_is_listed_and_nothing_sensitive_is(self):
        self.call(decision="approve")
        self.call(path="/y", decision=None, wait=3)                          # nobody answers: expires
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.call(decision=None)                                              # policy releases it
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.call(decision="deny")                                            # last: denial starts a cooldown
        code, body = self.page()
        self.assertEqual(code, 200)
        for label in ("approved", "denied", "expired", "auto-approved"):
            self.assertRegex(body, rf"<span class='pill \w+'>{label}</span>")
        self.assertIn("svc", body)
        self.assertIn("/x?...", body)                                         # query string hidden
        for secret in (SECRET, "QUERYSECRET"):
            self.assertNotIn(secret, body)

    def test_rows_are_buttons_with_request_ids_and_the_page_has_the_dialog(self):
        rid, _ = self.call()
        _, body = self.page("")
        self.assertIn(f"<button type=button class=hrow data-id='{rid}'", body)
        for want in ("<dialog id=hdlg", "id=hclose", "id=hbody", "showModal", "/request/", "data-hact=all",
                     "id=hform", "id=hlist"):
            self.assertIn(want, body)
        self.assertNotIn("<table", body)                                      # one list, no table layout
        self.assertNotIn("Back to Requests", body)
        # collapsed: the filter form is present but hidden
        self.assertIn("id=hform class=hfilters method=get action='/' hidden", body)
        self.assertNotIn(" hidden", self.page("?view=all")[1].split("id=hform")[1].split(">")[0])

    def test_old_history_url_redirects(self):
        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        op = urllib.request.build_opener(NoFollow)
        for path, want in (("/history", "/?view=all"), ("/history?outcome=denied&page=3", "/?view=all&outcome=denied")):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                op.open(urllib.request.Request(self.abase + path,
                                               headers={"X-authentik-username": "alice"}), timeout=10)
            self.assertEqual((cm.exception.code, cm.exception.headers["Location"]), (303, want))
        self.assertEqual(req(self.abase + "/history", headers={"X-authentik-username": "mallory"})[0], 403)

    def test_filters_search_and_paging_return_the_same_row_markup(self):
        rids = [self.call(path=f"/p{i}")[0] for i in range(3)]
        self.call(path="/needle", decision="deny")
        _, full = self.page("?view=all")
        _, frag = self.page("?fragment=1&view=all")
        self.assertNotIn("<nav", frag)
        self.assertIn(frag[frag.index("<div id=hlist"):frag.index("</main>")], full)               # identical list block
        for rid in rids:
            self.assertIn(f"data-id='{rid}'", frag)
        # outcome filter and search return list rows only, in the same markup
        _, f1 = self.page("?fragment=1&view=all&outcome=denied")
        self.assertIn("<button type=button class=hrow", f1)
        self.assertEqual(f1.count("class=hrow"), 1)
        self.assertEqual(self.page("?fragment=1&view=all&q=needle")[1].count("class=hrow"), 1)
        self.assertEqual(self.page("?fragment=1&view=all&q=NEEDLE")[1].count("class=hrow"), 1)
        self.assertIn("No requests match", self.page("?fragment=1&view=all&q=zzz-none")[1])
        # paging: "show more" extends the same list; limit is clamped
        _, collapsed = self.page("?fragment=1")
        self.assertEqual(collapsed.count("class=hrow"), 4)
        self.assertIn("data-hact=all", collapsed)
        _, p1 = self.page("?fragment=1&view=all&limit=2")
        self.assertEqual(p1.count("class=hrow"), 4)                           # floor is one page
        self.assertIn("4 requests", p1)
        _, evil = self.page("?view=all&q=<script>&outcome=bogus&limit=zzz&mode=<b>")
        self.assertNotIn("<script>", evil)
        self.assertNotIn("<b>&", evil.split("id=hform")[1].split("</form>")[0])

    def test_show_more_link_appears_when_rows_remain(self):
        from secret_broker import broker as bmod
        old = bmod.HIST_PAGE
        bmod.HIST_PAGE = 2
        try:
            for i in range(3):
                self.call(path=f"/m{i}")
            _, body = self.page("?fragment=1&view=all")
            self.assertEqual(body.count("class=hrow"), 2)
            self.assertIn("data-hact=more", body)
            self.assertIn("Show more (1 older)", body)
            self.assertIn("limit=4", body)
            self.assertEqual(self.page("?fragment=1&view=all&limit=4")[1].count("class=hrow"), 3)
        finally:
            bmod.HIST_PAGE = old

    def test_forbidden_identity(self):
        self.call(decision="approve")
        self.assertEqual(self.page(user="mallory")[0], 403)
        self.assertEqual(self.page("?fragment=1&view=all", user="")[0], 403)

    def test_pages_are_responsive_and_not_frameable(self):
        self.call(decision="approve")
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/?view=all", headers={"X-authentik-username": "alice"}), timeout=10)
        body = r.read().decode() + r.headers.get("Content-Security-Policy")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", r.headers.get("Content-Security-Policy"))
        for want in ("width=device-width", "color-scheme", "@media (max-width:42rem)",
                     "dialog.dlg", "prefers-color-scheme:dark", "<nav class=tabs>", "Agent Secret Broker",
                     "rel=icon", "img-src data:"):
            self.assertIn(want, body)
        # the decision page uses the same shell and big tap targets
        self.decision = None
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        _, b = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        nonce = self.broker._by_id[json.loads(b)["id"]].nonce
        _, page = req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})
        for want in ("class='btn approve'", "class='btn deny'", "width=device-width"):
            self.assertIn(want, page)

    def test_store_requests_show_the_operation_not_the_value(self):
        self.decision = "approve"
        self.api("POST", "/v1/requests", {"mode": "store", "names": ["hist-new"], "op": "create",
                                          "value": "the-new-credential-VALUE", "allowed_hosts": ["127.0.0.1"]})
        _, body = self.page()
        self.assertIn("create credential", body)
        self.assertNotIn("the-new-credential-VALUE", body)
        rid = self.events("requested")[0]["id"]
        code, d = self.detail(rid)
        self.assertEqual(code, 200)
        self.assertIn("create credential", d)
        self.assertIn("hist-new", d)
        self.assertNotIn("the-new-credential-VALUE", d)

    def test_rows_survive_a_new_history_object_and_follow_the_log(self):
        from secret_broker.history import History
        self.call(decision="approve")
        h = History(self.audit)
        first = h.rows()
        self.assertEqual([r["outcome"] for r in first], ["approved"])
        self.call(decision="deny")                                            # log grows after the index was built
        self.assertEqual([r["outcome"] for r in h.rows()], ["denied", "approved"])

    # -- detail view ---------------------------------------------------------
    def test_detail_for_an_approved_http_request(self):
        rid, _ = self.call("/x?token=QUERYSECRET")
        code, d = self.detail(rid)
        self.assertEqual(code, 200)
        self.assertNotIn("<html", d)                                          # a fragment, not a page
        for want in (rid, "svc", "GET http://127.0.0.1:", "/x?...", "alice", "approval link",
                     "Reads things", "Generated by", "LOW", "model rated it low", "approved",
                     "Upstream HTTP status", ">200<", "Response size", "Timeline", "requested", "assessed",
                     "notified", "decided", "secret_read", "http_executed", "delivered", "Source",
                     "Peer", "Time to decision"):
            self.assertIn(want, d)
        for bad in (SECRET, "QUERYSECRET", self.events("requested")[0]["prev"]):
            self.assertNotIn(bad, d)
        order = [d.index(f"<b>{ev}</b>") for ev in ("requested", "assessed", "decided",
                                                    "secret_read", "http_executed", "approved", "delivered")]
        self.assertEqual(order, sorted(order))
        # the full page (no fragment) renders the same content in the shell
        code, page = self.detail(rid, frag=False)
        self.assertEqual(code, 200)
        self.assertIn("<nav class=tabs>", page)
        self.assertIn(rid, page)

    def test_detail_for_denied_expired_and_policy_requests(self):
        exp, _ = self.call(path="/e", decision=None, wait=3)
        _, d = self.detail(exp)
        self.assertIn("expired", d)
        self.assertIn("nobody", d)
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        auto, _ = self.call(decision=None)
        _, d = self.detail(auto)
        self.assertIn("policy (auto-approved)", d)
        self.assertIn("auto-approve limit: medium", d)
        self.assertIn("auto_max=medium", d)                                   # why, on the timeline
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        den, _ = self.call(decision="deny")
        _, d = self.detail(den)
        self.assertIn("denied", d)
        self.assertIn("deny", d)
        self.assertIn("approval link", d)

    def test_detail_for_escalated_and_env_requests(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.broker.summarizer = _Stub("Dangerous", "high")
        self.decision = "approve"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "DELETE",
            "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        rid = json.loads(body)["id"]
        self.result(rid)
        _, d = self.detail(rid)
        self.assertIn("Auto-approve", d)
        self.assertIn("above auto_approve_max medium", d)
        self.assertIn("HIGH", d)
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "env", "names": ["svc"], "argv": ["echo", "<script>alert(1)</script>"]})
        rid = json.loads(body)["id"]
        self.result(rid)
        _, d = self.detail(rid)
        self.assertIn("<code>echo &lt;script&gt;alert(1)&lt;/script&gt;</code>", d)
        self.assertNotIn("<script>", d)
        self.assertIn("env", d)
        self.assertNotIn(SECRET, d)

    def test_detail_escapes_hostile_strings(self):
        evil = "<script>alert(1)</script>"
        self.broker.summarizer = _Stub(evil, "low")
        self.decision = "approve"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "source": evil + "<img src=x onerror=1>",
            "url": f"http://127.0.0.1:{self.up.server_address[1]}/<script>x</script>",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        rid = json.loads(body)["id"]
        self.result(rid)
        for frag in (True, False):
            _, d = self.detail(rid, frag=frag)
            self.assertNotIn("<script>alert", d.replace("<script nonce", ""))
            self.assertNotIn("<img src=x", d)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", d)
        _, lst = self.page()
        self.assertNotIn("<script>x", lst)
        self.assertNotIn("<img src=x", lst)

    def test_plain_line_reason_is_for_the_human_only(self):
        class Plain:
            def analyze(self, mode, names, spec):
                return {"summary": "auto: GET 127.0.0.1/x", "risk": "low", "summary_source": "deterministic",
                        "summary_reason": "rejected", "summary_rule": "read_word"}
        self.broker.summarizer = Plain()
        rid, _ = self.call()
        for frag in (True, False):
            _, d = self.detail(rid, frag=frag)
            self.assertIn("check: read_word", d)
            self.assertIn("the AI reply failed a safety or consistency check", d)
        # the aggregated numbers: names and counts only
        code, body = self.api("GET", "/v1/status")
        for leak in ("descriptions", "read_word", "rejected", "by_reason", "by_rule"):
            self.assertNotIn(leak, body)           # agent-readable: no counters, no reason classes
        code, page = req(self.abase + "/settings", headers={"X-authentik-username": "alice"})
        self.assertEqual(code, 200)
        self.assertIn("0 written by the AI model, 1 plain auto lines", page)
        self.assertIn("rejected 1", page)
        self.assertIn("read_word 1", page)
        code, _ = req(self.abase + "/settings", headers={"Authorization": "Bearer " + KEY})
        self.assertNotEqual(code, 200)
        # the agent's audit view never carries the reason, the rule or the assessment
        code, body = self.api("GET", f"/v1/audit?request={rid}")
        self.assertEqual(code, 200)
        for leak in ("read_word", "summary_reason", "summary_rule", "assessed", "check:"):
            self.assertNotIn(leak, body)

    def test_detail_unknown_malformed_and_pending(self):
        self.call()
        for bad in ("nosuchid12345678", "../../etc/passwd", "a", "x" * 200, "%2e%2e%2fsecret", "id%3Brm",
                    "id%20with%20space", "..%5C..%5Cwin", "abc/def"):
            code, d = self.detail(bad)
            self.assertEqual(code, 404, bad)
            self.assertNotIn("Traceback", d)
        self.assertEqual(self.detail("")[0], 404)
        self.decision = None
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        _, b = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        pend = json.loads(b)["id"]
        code, d = self.detail(pend)
        self.assertEqual(code, 409)
        self.assertNotIn(self.broker._by_id[pend].nonce, d)
        self.assertNotIn(pend, self.page("?view=all")[1].split("id=hlist")[1])  # not in the list either

    def test_detail_never_exposes_nonce_or_tokens(self):
        rid, _ = self.call()
        r = self.broker._by_id[rid]
        _, d = self.detail(rid)
        _, lst = self.page("?view=all")
        for blob in (d, lst):
            self.assertNotIn(r.nonce, blob)
            self.assertNotIn(self.broker.csrf_token("alice"), d)
        with open(self.audit) as f:
            self.assertNotIn(r.nonce, f.read())

    def test_detail_requires_the_same_auth_as_other_pages(self):
        rid, _ = self.call()
        for user in ("mallory", ""):
            code, d = self.detail(rid, user=user)
            self.assertEqual(code, 403)
            self.assertNotIn(rid, d)
        code, _ = req(self.abase + f"/request/{rid}?fragment=1")
        self.assertEqual(code, 403)
        self.broker.cfg["approval_trusted_peers"] = ["10.9.9.0/24"]
        self.assertEqual(self.detail(rid)[0], 403)

    def test_detail_does_not_rescan_the_log(self):
        rid, _ = self.call()
        self.detail(rid)
        folded = []
        orig = self.broker.history._fold
        self.broker.history._fold = lambda rec: (folded.append(rec), orig(rec))[1]
        try:
            self.detail(rid)
            self.detail(rid)
            self.assertEqual([r["event"] for r in folded if r.get("id") == rid], [])
        finally:
            self.broker.history._fold = orig


class Dashboard(Harness):
    """Approve/deny from the web UI: same decision path, plus CSRF protection."""
    decision = None
    ttl = 60

    def tweak(self, cfg):
        cfg["risk"] = {"auto_approve_max": "medium"}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Reads things", "low")

    def ask(self, path="/x", method="GET", name="svc"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": [name], "method": method, "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        return json.loads(body)["id"]

    def get(self, path="/", user="alice"):
        return req(self.abase + path, headers={"X-authentik-username": user})

    def decide(self, rid, decision, csrf="ok", user="alice", extra=None):
        form = {"id": rid, "decision": decision}
        if csrf is not None:
            form["csrf"] = self.broker.csrf_token(user) if csrf == "ok" else csrf
        hdr = {"X-authentik-username": user, **(extra or {})}

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        op = urllib.request.build_opener(NoFollow)
        try:
            r = op.open(urllib.request.Request(
                self.abase + "/decide", data=urllib.parse.urlencode(form).encode(),
                headers=hdr, method="POST"), timeout=10)
            return r.status, r.headers.get("Location"), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode()

    def result(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)

    def cev(self, body, user="alice", headers=None, raw=None):
        h = {"X-authentik-username": user, "Content-Type": "application/json",
             "X-Requested-With": "asb", "Origin": self.broker.cfg["approve_base_url"].rstrip("/"),}
        if headers is not None:
            h = {k: v for k, v in {**h, **headers}.items() if v is not None}
        data = raw if raw is not None else json.dumps(body).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + "/push/event", data=data, headers=h, method="POST"), timeout=10)
            return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_client_event_rejects_bad_requests(self):
        ok = {"kind": "push"}
        self.assertEqual(self.cev(ok, headers={"X-Requested-With": None}), 403)
        self.assertEqual(self.cev(ok, headers={"X-Requested-With": "x"}), 403)
        self.assertEqual(self.cev(ok, headers={"Content-Type": "text/plain"}), 403)
        self.assertEqual(self.cev(ok, headers={"Content-Type": "application/x-www-form-urlencoded"}), 403)
        self.assertEqual(self.cev({"kind": "x", "note": "a" * 3000}), 413)
        self.assertEqual(self.cev(ok, user="mallory"), 403)
        self.assertEqual(self.cev(ok, user=""), 403)
        self.assertEqual(self.cev(None, raw=b"not json"), 400)
        self.assertEqual(self.cev({"nokind": 1}), 400)
        self.assertEqual(self.events("client_event"), [])

    def test_client_event_is_sanitized_and_audited(self):
        self.assertEqual(self.cev({
            "kind": "notificationclick", "v": "5", "tag": "t" * 100, "action": "open",
            "clients": 2, "client_paths": ["https://h.example/settings?token=SEKRIT#f", "/", "/a",
                                           "/b", "/c", "/dropped"],
            "ok": True, "err": "e" * 500, "ms": 12, "state": "s" * 99, "visible": False,
            "note": "n" * 200, "queued": 3, "title": "SECRET TITLE", "body": "SECRET BODY",
            "url": "https://x/?a=b", "evil": {"a": 1}}), 204)
        (ev,) = self.events("client_event")
        self.assertEqual(ev["user"], "alice")
        self.assertIn("peer", ev)
        self.assertIn("client_ip", ev)
        self.assertEqual((ev["kind"], ev["v"], ev["action"], ev["clients"], ev["ok"], ev["ms"],
                          ev["visible"], ev["queued"]),
                         ("notificationclick", "5", "open", 2, True, 12, False, 3))
        self.assertEqual(len(ev["tag"]), 40)
        self.assertEqual(len(ev["err"]), 120)
        self.assertEqual(len(ev["note"]), 80)
        self.assertEqual(len(ev["state"]), 24)
        self.assertEqual(ev["client_paths"], ["/settings", "/", "/a", "/b", "/c"])
        for k in ("title", "body", "url", "evil"):
            self.assertNotIn(k, ev)
        with open(self.audit) as f:
            blob = f.read()
        for bad in ("SEKRIT", "SECRET TITLE", "SECRET BODY"):
            self.assertNotIn(bad, blob)

    def test_client_event_rate_limit_drops_and_audits_once(self):
        from secret_broker import broker as bmod
        for _ in range(bmod._CE_LIMIT):
            self.assertEqual(self.cev({"kind": "visibility"}), 204)
        for _ in range(5):
            self.assertEqual(self.cev({"kind": "visibility"}), 204)
        self.assertEqual(len(self.events("client_event")), bmod._CE_LIMIT)
        (d,) = self.events("client_event_dropped")
        self.assertEqual((d["user"], d["dropped"], d["limit_per_min"]), ("alice", 1, bmod._CE_LIMIT))

    def test_dashboard_js_reports_page_steps(self):
        body = self.get()[1]
        for needle in ("/push/event", "X-Requested-With", "page_load", "sw_message",
                       "poll_requested", "visibility"):
            self.assertIn(needle, body)
        self.assertIn("connect-src 'self'", self.get_headers()["Content-Security-Policy"])

    def get_headers(self, path="/"):
        return urllib.request.urlopen(urllib.request.Request(
            self.abase + path, headers={"X-authentik-username": "alice"})).headers

    def test_card_says_assessing_until_the_rating_arrives_and_then_refreshes(self):
        import re
        rid = self.ask("/api/health")
        r = self.broker._by_id[rid]
        keep, r.risk = r.risk, None                      # drawn before the assessment landed
        _, body = self.get("/?fragment=1")
        self.assertIn("ASSESSING", body)
        self.assertNotIn("MEDIUM RISK", body)
        v1 = re.search(r"data-version='([0-9a-f]+)'", body).group(1)
        r.risk = keep                                    # the assessment arrives
        _, body = self.get("/?fragment=1")
        self.assertNotIn("ASSESSING", body)
        v2 = re.search(r"data-version='([0-9a-f]+)'", body).group(1)
        self.assertNotEqual(v1, v2)                      # so the page swaps the card in

    def test_requests_tab_count_follows_the_poll_and_clears_when_nothing_waits(self):
        import re
        # nothing waiting: no count in the page chrome and the polled fragment says 0
        page = self.get("/")[1]
        self.assertNotRegex(page, r"<span class=count>")
        self.assertIn("data-attention='0'", self.get("/?fragment=1")[1])
        rid = self.ask("/api/health")
        # one waiting: the full page badge and the polled fragment agree
        page = self.get("/")[1]
        self.assertIn("<span class=count>1</span>", page)
        self.assertIn("data-attention='1'", self.get("/?fragment=1")[1])
        # the request settles elsewhere: the next poll carries 0, which is what clears the badge
        self.decide(rid, "deny")
        frag = self.get("/?fragment=1")[1]
        self.assertEqual(re.search(r"data-attention='(\d+)'", frag).group(1), "0")
        self.assertNotRegex(self.get("/")[1], r"<span class=count>")
        # the page script applies that number to the tab on every poll, not only when the cards change
        self.assertIn("badge(c.getAttribute('data-attention'))", page)
        self.assertIn("function badge(n)", page)

    def test_notification_toggle_is_present_and_text_is_names_only(self):
        self.ask("/secret-looking-path?token=abc123")
        code, body = self.get()
        self.assertEqual(code, 200)
        self.assertIn("id=notify", self.get("/settings")[1])
        self.assertNotIn("id=notify", body)      # the controls live on Settings
        # The browser notification body is built from the card heading (secret
        # names) only: never from the request description, URL or source.
        js = body[body.index("function announce"):body.index("function track")]
        self.assertIn("querySelector('h2')", body)
        self.assertNotIn("class=box", js)
        self.assertNotIn("data-url", js)
        self.assertNotIn("secret-looking-path", js)
        # Nothing about the request is placed in an attribute the script reads.
        self.assertNotIn("data-body", body)

    def test_lists_pending_without_exposing_the_nonce(self):
        rid = self.ask("/<img/src=x/onerror=alert(1)>")      # (a space in a URL is refused at creation)
        code, body = self.get()
        self.assertEqual(code, 200)
        self.assertIn("svc", body)
        self.assertIn("name=csrf", body)
        self.assertIn(f"data-id='{rid}'", body)
        self.assertNotIn(self.broker._by_id[rid].nonce, body)         # ids, never the capability URL
        self.assertNotIn("<img/src=x", body)                          # escaped
        self.assertIn("script-src 'nonce-", urllib.request.urlopen(urllib.request.Request(
            self.abase + "/", headers={"X-authentik-username": "alice"})).headers["Content-Security-Policy"])

    def test_approve_from_the_dashboard_releases_to_the_client(self):
        rid = self.ask()
        code, loc, _ = self.decide(rid, "approve")
        self.assertEqual((code, loc), (303, "/?note=approved"))
        r = self.result(rid)
        self.assertEqual((r["status"], r["http"]["status"]), ("approved", 200))
        d = self.events("decided")[0]
        self.assertEqual((d["channel"], d["approver"], d["decision"]), ("dashboard", "alice", "approve"))
        self.assertNotIn("name=csrf", self.get()[1].split("id=cards")[1].split("</div>")[0])  # nothing pending now

    def test_deny_from_the_dashboard(self):
        rid = self.ask()
        self.assertEqual(self.decide(rid, "deny")[1], "/?note=denied")
        self.assertEqual(self.result(rid)["status"], "denied")

    def test_csrf_and_origin_protections(self):
        rid = self.ask()
        for kw in (dict(csrf=None), dict(csrf="wrong"),
                   dict(extra={"Origin": "https://evil.example"}),
                   dict(extra={"Sec-Fetch-Site": "cross-site"}),
                   dict(extra={"Origin": "null"})):
            code, _, _ = self.decide(rid, "approve", **kw)
            self.assertEqual(code, 403, kw)
        self.assertEqual(self.broker._by_id[rid].status, "pending")     # nothing was decided
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(len(self.events("csrf_refused")), 5)
        # a token minted for another identity does not work
        tok = self.broker.csrf_token("mallory")
        self.assertEqual(self.decide(rid, "approve", csrf=tok)[0], 403)
        # the legitimate browser path (same-origin) is accepted
        ok = self.decide(rid, "approve", extra={"Origin": "https://secrets.example",
                                                "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(ok[0], 303)

    def test_wrong_user_is_forbidden(self):
        rid = self.ask()
        self.assertEqual(self.get(user="mallory")[0], 403)
        self.assertEqual(self.decide(rid, "approve", user="mallory", csrf=self.broker.csrf_token("alice"))[0], 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_double_decision_is_one_decision(self):
        rid = self.ask()
        self.assertEqual(self.decide(rid, "approve")[1], "/?note=approved")
        self.assertEqual(self.decide(rid, "deny")[1], "/?note=stale")
        self.assertEqual(self.decide("no-such-id", "approve")[1], "/?note=stale")
        self.assertEqual(self.decide(rid, "maybe")[1], "/?note=stale")
        self.assertEqual(len(self.events("decided")), 1)

    def test_always_allow_from_the_dashboard_follows_the_same_rules(self):
        rid = self.ask()
        self.assertIn("approve_always", self.get()[1])
        self.assertEqual(self.decide(rid, "approve_always")[1], "/?note=always")
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertEqual([(e["mode"], e["scope"]) for e in self.broker.cfg["secrets"]["svc"]["standing"]],
                         [("http", "read")])
        self.assertEqual(len(self.disk()["secrets"]["svc"]["standing"]), 1)

    def test_fragment_version_changes_when_the_queue_changes(self):
        def version():
            return self.get("/?fragment=1")[1].split("data-version='")[1].split("'")[0]
        empty = version()
        rid = self.ask()
        one = version()
        self.assertNotEqual(empty, one)
        self.decide(rid, "deny")
        self.assertEqual(version(), empty)
        self.assertNotIn("<nav>", self.get("/?fragment=1")[1])        # fragment only, no page shell


class TrustedPeers(Harness):
    decision = None

    def test_untrusted_peer_gets_nothing_even_with_the_right_identity(self):
        self.broker.cfg["approval_trusted_peers"] = ["10.9.9.0/24"]
        for path in ("/", "/history", "/policies"):
            self.assertEqual(req(self.abase + path, headers={"X-authentik-username": "alice"})[0], 403)
        rid = json.loads(self.create_env()[1])["id"]
        nonce = self.broker._by_id[rid].nonce
        self.assertEqual(req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})[0], 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.events("approval_forbidden")[0]["reason"], "peer is not a trusted proxy")

    def test_trusted_peer_and_default(self):
        self.assertEqual(req(self.abase + "/", headers={"X-authentik-username": "alice"})[0], 200)  # unset
        self.broker.cfg["approval_trusted_peers"] = ["127.0.0.0/8"]
        self.assertEqual(req(self.abase + "/", headers={"X-authentik-username": "alice"})[0], 200)
        self.broker.cfg["approval_trusted_peers"] = ["not-a-cidr"]
        self.assertEqual(req(self.abase + "/", headers={"X-authentik-username": "alice"})[0], 403)


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
        self.b._startup_timeout = 0.3        # the port is never ours: give up quickly
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


class StatusEndpoint(Harness):
    """GET /v1/status: deploy verification without shell access to the host."""

    def tweak(self, cfg):
        cfg["ha_hook"] = {"key": "h" * 40}
        cfg["notify"] = [{"type": "ticker", "ha_url": "http://ha.internal.example:8123"}]
        cfg["_vault"] = {"BadItem": {"notes": "x", "broker": json.dumps({
            "name": "badname-secret", "vars": {"B_T": {"field": "notes"}},
            "allowed_hosts": ["bad host!"]})}}

    def status(self):
        code, body = self.api("GET", "/v1/status")
        self.assertEqual(code, 200, body)
        return json.loads(body), body

    def test_requires_the_client_key(self):
        self.assertEqual(self.api("GET", "/v1/status", key="wrong")[0], 401)
        code, _ = req(self.base + "/v1/status")
        self.assertEqual(code, 401)
        code, _ = req(self.base + "/v1/status", headers={"Authorization": "Bearer " + "h" * 40})
        self.assertEqual(code, 401)
        code, _ = req(self.base + "/v1/status", headers={"X-Client-Key": "h" * 40})
        self.assertEqual(code, 401)
        self.assertNotEqual(self.api("GET", "/v1/status")[0], 401)

    def test_shape_and_values(self):
        st, _ = self.status()
        self.assertEqual(set(st), {"version", "build_time", "started_at", "uptime_s", "catalog",
                                   "backend", "notifiers", "features"})
        self.assertEqual(set(st["catalog"]), {"count", "invalid", "adopted", "loaded_at"})
        self.assertEqual(st["catalog"]["count"], 1)
        self.assertEqual(st["catalog"]["invalid"], 1)
        self.assertEqual(st["catalog"]["adopted"], 0)
        self.assertRegex(st["catalog"]["loaded_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(st["started_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsInstance(st["uptime_s"], int)
        self.assertEqual(st["backend"], {"type": "file", "ok": True})
        self.assertEqual(st["notifiers"], ["ticker"])
        self.assertEqual(st["features"], {"ha_hook": True, "ssh": False, "webpush_actions": False,
                                         "auto_approve_max": "low", "timed_grants": True,
                                         "guidance_proposals": True, "credential_requests": True,
                                         "plans": True, "client_enrollment": True, "legacy_client_key": "allow",
                                         "client_list": "ok",
                                         "http_sessions": {"enabled": True, "default_ttl_s": 900,
                                                           "max_ttl_s": 3600, "max_calls": 200,
                                                           "max_per_client": 3},
                                         "ws_sessions": {"enabled": True, "default_ttl_s": 900,
                                                         "max_ttl_s": 3600, "max_frames": 1000,
                                                         "max_per_client": 2}})

    def test_leaks_no_names_hosts_or_config(self):
        _, body = self.status()
        for leak in ("svc", "SVC_TOKEN", "127.0.0.1", "Svc", "BadItem", "badname", "bad host",
                     SECRET, "h" * 40, "ha.internal.example", "secrets.example", "alice", KEY):
            self.assertNotIn(leak, body)

    def test_does_not_read_the_vault(self):
        calls = []
        orig = self.broker.backend.catalog
        self.broker.backend.catalog = lambda: calls.append(1) or orig()
        self.broker._catalog_at = 0.0           # stale: a request would refresh
        self.status()
        self.assertEqual(calls, [])

    def test_version_unknown_without_env_and_from_env_when_set(self):
        old = {k: os.environ.pop(k, None) for k in ("BROKER_GIT_SHA", "BROKER_BUILD_TIME")}
        try:
            st, _ = self.status()
            self.assertEqual((st["version"], st["build_time"]), ("unknown", "unknown"))
            os.environ["BROKER_GIT_SHA"] = "abc1234def"
            os.environ["BROKER_BUILD_TIME"] = "2026-10-18T01:02:03Z"
            st, _ = self.status()
            self.assertEqual((st["version"], st["build_time"]), ("abc1234def", "2026-10-18T01:02:03Z"))
        finally:
            for k, v in old.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v

    def test_backend_failure_is_reported(self):
        def boom():
            raise BackendError("vault down")
        self.broker.backend.catalog = boom
        self.broker._refresh_if(-1)
        self.assertFalse(self.status()[0]["backend"]["ok"])

    def test_cli_status_text_json_and_exit_codes(self):
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY,
                   BROKER_GIT_SHA="abc1234def")
        run = lambda *a, e=env: subprocess.run(  # noqa: E731
            [sys.executable, "-I", CLI, *a], env=e, capture_output=True, text=True, timeout=30)
        p = run("status")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("catalog:  1 secrets, 1 invalid, 0 adopted", p.stdout)
        self.assertIn("backend:  file ok", p.stdout)
        self.assertNotIn(SECRET, p.stdout)
        pj = run("status", "--json")
        self.assertEqual(json.loads(pj.stdout)["catalog"]["invalid"], 1)
        self.assertEqual(run("status", "--bogus").returncode, 2)
        self.assertIn("usage: asb status", run("help", "status").stdout)
        self.assertIn("asb status", run("guide").stdout)
        self.assertEqual(run("status", e=dict(env, SECRET_BROKER_KEY="bad")).returncode, 3)
        dead = dict(env, SECRET_BROKER_URL="http://127.0.0.1:1")
        self.assertEqual(run("status", e=dead).returncode, 3)


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

    def test_every_command_has_help_and_flags_are_never_names(self):
        for cmd in ("list", "which", "http", "store", "update", "fingerprint"):
            p = self.run_cli(cmd, "--help")
            self.assertEqual(p.returncode, 0, (cmd, p.stderr))
            self.assertIn(f"usage: asb", p.stdout)
        self.assertIn("{{GRAFANA_TOKEN}}", self.run_cli("help", "http").stdout)
        self.assertEqual(self.run_cli("help", "nope").returncode, 2)
        # a flag piped to store must not create an item called "--help"
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY)
        q = subprocess.run([sys.executable, "-I", CLI, "store", "--help"], env=env,
                           input="v", capture_output=True, text=True, timeout=30)
        self.assertEqual(q.returncode, 0)
        self.assertNotIn("--help", self.broker.backend._data)
        for argv in (["store", "-x", "--hosts", "h"], ["http", "-x", "GET", "http://h/"],
                     ["which", "-x"], ["-x", "--", "true"]):
            r = subprocess.run([sys.executable, "-I", CLI, *argv], env=env, input="v",
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 2, argv)
            self.assertIn("flag", r.stderr)
        self.assertEqual(self.broker._by_id, {})

    def test_guide_explains_the_workflow(self):
        p = self.run_cli("guide")
        self.assertEqual(p.returncode, 0)
        for needle in ("{{VAR}}", "asb which", "approve", "Exit codes", "stdin"):
            self.assertIn(needle, p.stdout)
        self.assertIn("asb guide", self.run_cli().stdout)

    def test_errors_say_what_to_do_next(self):
        none = self.run_cli("which", "nothing.example")
        self.assertIn("asb list", none.stderr)
        bad = self.run_cli("frobnicate")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("asb guide", bad.stderr)

    def test_list_has_a_labelled_header_on_stderr(self):
        p = self.run_cli("list")
        self.assertIn("NAME", p.stderr)
        self.assertEqual(p.stdout.strip(), "svc\tSVC_TOKEN\t127.0.0.1")

    def test_exit_codes_are_distinct(self):
        self.decision = "deny"
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        self.assertEqual(self.run_cli("http", "svc", "GET", url).returncode, 4)
        self.assertEqual(self.run_cli("http", "nosuch", "GET", url).returncode, 3)
        env = dict(os.environ, SECRET_BROKER_URL="http://127.0.0.1:9", SECRET_BROKER_KEY=KEY)
        r = subprocess.run([sys.executable, "-I", CLI, "list"], env=env, capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(r.returncode, 3)


if __name__ == "__main__":
    unittest.main()
