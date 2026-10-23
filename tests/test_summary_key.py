"""summary.api_key_secret: the OpenRouter key read from the broker's own vault."""
import json
import logging
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from secret_broker import audit_api, keyprovider, risk, riskmodel  # noqa: E402
from secret_broker import broker as broker_mod  # noqa: E402
from secret_broker.backends import BackendUnavailable, MemoryBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
import test_e2e as e2e  # noqa: E402

NAME, VAR = "openrouter-secret-broker", "OPENROUTER_KEY"
K1, K2 = "sk-or-FAKE-KEY-ONE-9f3a", "sk-or-FAKE-KEY-TWO-77be"
SPEC = {"method": "DELETE", "url": "https://target.invalid/v1/x", "headers": {}, "body": "hello"}


class Fake(BaseHTTPRequestHandler):
    """A fake OpenRouter: records every request, answers jev and chat calls."""
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        Fake.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        if self.path.endswith("/alpha/decisions"):
            out = {"answers": {"risk": {"type": "choice", "choice": "low",
                                        "probabilities": {"low": 0.9, "medium": 0.07, "high": 0.03}}},
                   "usage": {"cost": 0.0}}
        else:
            out = {"choices": [{"message": {"content": "Deletes a thing on target.invalid"}}],
                   "usage": {"cost": 0.0}}
        raw = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Base(unittest.TestCase):
    def setUp(self):
        Fake.seen = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.now = [1000.0]
        self.backend = MemoryBackend()
        self.put(K1, create=True)
        self.audit = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
        self.sc = {"type": "jev", "api_key_secret": {"name": NAME, "var": VAR},
                   "base_url": self.url, "summary_base_url": self.url}
        self.fa = riskmodel.build(self.sc, None, clock=lambda: self.now[0])
        self.notifier = FakeNotifier()
        self.broker = Broker({"approve_base_url": "https://s.example"}, self.backend, self.notifier,
                             self.audit)
        self.broker.summarizer = self.fa                    # attached by hand: no start-up warm-up read
        for kp in self.fa.key_providers:
            kp.attach(self.broker._summary_key_read, self.broker.log)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def put(self, value, create=False):
        meta = {"name": NAME, "vars": {VAR: {"item": "OR", "field": "notes"}},
                "allowed_hosts": ["openrouter.ai"]}
        self.backend.put("OR", "notes", value, create=create, meta=meta if create else None)

    def records(self):
        with open(self.audit) as f:
            return [json.loads(x) for x in f if x.strip()]

    def analyze(self, prime=True):
        """prime: let the background key read finish first (the first request after the TTL
        or at start-up otherwise sees no key / the stale key, by design)."""
        if prime:
            for kp in self.fa.key_providers:
                kp.get()
                kp.wait()
        return self.fa.analyze("http", ["x"], dict(SPEC))

    def gate_vault(self):
        """Make vault reads block until the returned event is set."""
        gate, real = threading.Event(), self.backend.get

        def slow(*a):
            gate.wait(10)
            return real(*a)
        self.backend.get = slow
        return gate

    def auths(self):
        return [s["auth"] for s in Fake.seen]


class Lazy(Base):
    def test_resolved_lazily_cached_and_rotated(self):
        self.assertEqual(Fake.seen, [])
        reads = lambda: [r for r in self.records() if r["event"] == "summary_key_read"]
        self.assertEqual(reads(), [])                       # nothing read at startup
        self.analyze()
        self.assertTrue(Fake.seen)
        self.assertEqual(set(self.auths()), {"Bearer " + K1})
        self.assertEqual(len(reads()), 1)
        self.put(K2)                                        # rotate in the vault
        n = len(Fake.seen)
        self.now[0] += 299
        self.analyze(prime=False)
        self.assertEqual(set(self.auths()[n:]), {"Bearer " + K1})   # still cached
        self.assertEqual(len(reads()), 1)
        self.now[0] += 2                                    # past the 300 s default TTL
        n = len(Fake.seen)
        gate = self.gate_vault()
        self.analyze(prime=False)                           # stale key while the one refresh runs
        self.assertEqual(set(self.auths()[n:]), {"Bearer " + K1})
        gate.set()
        self.fa.key_providers[0].wait()
        n = len(Fake.seen)
        self.analyze(prime=False)
        self.assertEqual(set(self.auths()[n:]), {"Bearer " + K2})
        self.assertEqual(len(reads()), 2)

    def test_first_use_does_not_wait_for_the_vault(self):
        gate = self.gate_vault()
        got = self.analyze(prime=False)                     # no key yet: auto: line, rated HIGH
        self.assertIsNone(got["risk"])
        self.assertEqual(got["summary_source"], "deterministic")
        self.assertEqual(Fake.seen, [])
        gate.set()
        self.fa.key_providers[0].wait()
        self.assertEqual(self.fa.key_providers[0].get(), K1)

    def test_custom_ttl(self):
        sc = dict(self.sc, api_key_ttl_s=30)
        fa = riskmodel.build(sc, None, clock=lambda: self.now[0])
        self.assertEqual(fa.key_providers[0].ttl, 30)
        fa.key_providers[0].attach(self.broker._summary_key_read, self.broker.log)
        kp = fa.key_providers[0]
        kp.get()
        kp.wait()
        self.assertEqual(kp.get(), K1)
        self.put(K2)
        self.now[0] += 31
        kp.get()
        kp.wait()
        self.assertEqual(kp.get(), K2)

    def test_file_key_still_a_plain_constant(self):
        fa = riskmodel.build({"type": "jev", "api_key_file": "/k"}, lambda p: "FILEKEY")
        self.assertEqual(fa.key_providers, ())
        self.assertEqual(fa.inner._key.get(), "FILEKEY")
        old = riskmodel.JevAnalyzer("PLAIN")                 # a plain string still works
        self.assertEqual(old._key.get(), "PLAIN")

    def test_jev_describer_and_decision_share_the_provider(self):
        self.assertIs(self.fa.inner._key, self.fa.inner._describer._key)
        self.assertIs(self.fa.inner._key, self.fa.key_providers[0])


class Failures(Base):
    def degraded(self):
        got = self.analyze()
        self.assertIsNone(got["risk"])
        self.assertEqual(got["summary_source"], "deterministic")
        self.assertTrue(got["summary"].startswith("auto:"), got["summary"])
        self.assertEqual(Fake.seen, [])                      # nothing sent without a key
        a = risk.assess("http", ["x"], dict(SPEC), self.fa)
        self.assertEqual(a["level"], "high")                 # the existing fail-safe rating

    def test_missing_item(self):
        self.backend.delete("OR")
        self.broker.refresh_catalog()
        self.degraded()

    def test_missing_var(self):
        fa = riskmodel.build(dict(self.sc, api_key_secret={"name": NAME, "var": "OTHER_VAR"}), None,
                             clock=lambda: self.now[0])
        fa.key_providers[0].attach(self.broker._summary_key_read, self.broker.log)
        self.fa = fa
        self.degraded()

    def test_backend_down(self):
        def boom(*a):
            raise BackendUnavailable("connection refused to https://vault.secret-host.invalid " + K1)
        self.backend.get = boom
        self.degraded()
        recs = [r for r in self.records() if r["event"] == "summary_key_read"]
        self.assertEqual(recs[-1]["result"], "backend_unavailable")

    def test_empty_and_malformed_values(self):
        for bad, why in (("", "empty"), ("   \n", "empty"), ("sk bad\nkey", "invalid")):
            self.put(bad)
            self.now[0] += 400
            self.degraded()
            last = [r for r in self.records() if r["event"] == "summary_key_read"][-1]
            self.assertEqual(last["result"], why)

    def test_recovers_after_failure_ttl(self):
        self.put("")
        self.degraded()
        self.put(K2)
        self.now[0] += keyprovider.FAIL_TTL + 1
        self.analyze()
        self.assertEqual(set(self.auths()), {"Bearer " + K2})

    def test_get_never_raises(self):
        kp = keyprovider.VaultKey("x", "Y", clock=lambda: 0.0)
        self.assertIsNone(kp.get())                          # not attached
        kp.wait()
        kp.attach(lambda n, v: 1 / 0, lambda *a, **k: 1 / 0)
        kp.invalidate()
        self.assertIsNone(kp.get())
        kp.wait()
        self.assertIsNone(kp.get())

    def test_failure_line_is_rate_limited_and_quiet(self):
        self.put("")
        with self.assertLogs("secret_broker", level="WARNING") as cm:
            for _ in range(5):
                self.now[0] += keyprovider.FAIL_TTL + 1
                self.analyze()
        lines = [x for x in cm.output if "summary key unavailable" in x]
        self.assertEqual(len(lines), 1)
        self.assertIn("reason=empty", lines[0])
        self.assertNotIn(NAME, "\n".join(cm.output))
        self.assertEqual(len([r for r in self.records() if r["event"] == "summary_key_read"]), 1)
        self.now[0] += keyprovider.LOG_EVERY + 1
        with self.assertLogs("secret_broker", level="WARNING"):
            self.analyze()


class Validation(unittest.TestCase):
    base = {"type": "jev"}
    good = {"name": NAME, "var": VAR}

    def bad(self, sc, field):
        with self.assertRaises(ValueError) as cm:
            riskmodel.validate_config(sc)
        self.assertIn(field, str(cm.exception))

    def test_exactly_one_of(self):
        self.bad({**self.base}, "summary.api_key_file")
        self.bad({**self.base, "api_key_file": "/k", "api_key_secret": self.good}, "exactly one")
        riskmodel.validate_config({**self.base, "api_key_secret": self.good})
        riskmodel.validate_config({**self.base, "api_key_file": "/k"})
        riskmodel.validate_config({"model": "m", "api_key_secret": self.good})      # legacy block, no type

    def test_secret_shape(self):
        for v in (None, "x", [], {}, {"name": NAME}, {"name": NAME, "var": VAR, "extra": 1},
                  {"name": "Bad Name", "var": VAR}, {"name": "", "var": VAR}, {"name": 5, "var": VAR},
                  {"name": NAME, "var": "lower"}, {"name": NAME, "var": 5}, {"name": "-x", "var": VAR}):
            self.bad({**self.base, "api_key_secret": v}, "summary.api_key_secret")

    def test_ttl_range(self):
        for v in (29, 3601, 0, -1, 60.5, "300", True, None):
            self.bad({**self.base, "api_key_secret": self.good, "api_key_ttl_s": v}, "api_key_ttl_s")
        for v in (30, 300, 3600):
            riskmodel.validate_config({**self.base, "api_key_secret": self.good, "api_key_ttl_s": v})
        self.bad({**self.base, "api_key_file": "/k", "api_key_ttl_s": 60}, "api_key_ttl_s")

    def test_build_does_not_read_a_file(self):
        def nope(p):
            raise AssertionError("read a file")
        riskmodel.build({**self.base, "api_key_secret": self.good}, nope)

    def test_patterns_match_the_catalog(self):
        self.assertEqual(keyprovider.NAME_RE.pattern, broker_mod._NAME_RE.pattern)
        self.assertEqual(keyprovider.VAR_RE.pattern, broker_mod._VAR_RE.pattern)

    def test_startup_warning_when_not_in_catalog_yet(self):
        sc = {"type": "jev", "api_key_secret": {"name": "not-there-yet", "var": VAR}}
        fa = riskmodel.build(sc, None)
        audit = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        with self.assertLogs("secret_broker", level="WARNING") as cm:
            Broker({"approve_base_url": "https://s.example"}, MemoryBackend(), FakeNotifier(), audit,
                   summarizer=fa)
        self.assertTrue(any("not in the catalog yet" in x for x in cm.output))
        self.assertNotIn("not-there-yet", "\n".join(cm.output))
        with open(audit) as f:
            self.assertIn("config_warning", f.read())


class NoLeaks(Base):
    def test_key_only_in_authorization_header_of_configured_urls(self):
        self.analyze()
        risk.assess("http", ["x"], dict(SPEC), self.fa)
        self.assertTrue(Fake.seen)
        for s in Fake.seen:
            self.assertEqual(s["auth"], "Bearer " + K1)
            self.assertNotIn(K1, s["body"])
            self.assertNotIn(K1, s["path"])
            self.assertTrue(s["path"].startswith("/alpha/decisions") or s["path"].startswith("/chat/completions"))

    def test_key_in_no_log_audit_status_or_exception(self):
        outputs = []
        with self.assertLogs("secret_broker", level="DEBUG") as cm:
            logging.getLogger("secret_broker").debug("probe")
            self.analyze()
            self.backend.get = lambda *a: (_ for _ in ()).throw(BackendUnavailable("down " + K1))
            self.now[0] += 400
            self.analyze()
            outputs.append("\n".join(cm.output))
        with open(self.audit) as f:
            outputs.append(f.read())
        outputs.append(json.dumps(self.broker.status()))
        outputs.append(repr(self.fa.key_providers[0]) + repr(self.fa) + repr(self.fa.inner._key))
        outputs.append(json.dumps([audit_api.redact(r) for r in self.records()]))
        for o in outputs:
            self.assertNotIn(K1, o)
            self.assertNotIn(K2, o)

    def test_internal_read_is_hidden_and_not_a_request(self):
        self.analyze()
        evs = {r["event"] for r in self.records()}
        self.assertIn("summary_key_read", evs)
        self.assertNotIn("secret_read", evs)
        self.assertIn("summary_key_read", audit_api.HIDDEN)
        self.assertNotIn("summary_key_read", audit_api.WHITELIST)
        self.assertEqual(self.notifier.sent, [])             # no card, no notification
        self.assertEqual(self.broker._by_id, {})             # no request object
        rec = [r for r in self.records() if r["event"] == "summary_key_read"][0]
        self.assertEqual(set(rec) - {"seq", "ts", "time", "event", "prev"}, {"secret", "result"})
        self.assertEqual((rec["secret"], rec["result"]), (NAME, "ok"))
        self.assertIsNone(audit_api.redact(rec))


class AgentPath(e2e.Harness):
    """The key credential is internal: an agent can never request, list or change it, and
    every other credential still works as before."""

    def tweak(self, cfg):
        cfg["secrets"][NAME] = {"vars": {VAR: {"item": "OR", "field": "key"}}, "allowed_hosts": ["127.0.0.1"],
                                "approval": "allow"}
        cfg["secrets"]["alias"] = {"vars": {"A1": {"item": "AL", "field": "x"},
                                           "ALIAS_TOKEN": {"item": "OR", "field": "other"}},
                                   "allowed_hosts": ["127.0.0.1"]}
        cfg["_vault"] = {"OR": {"key": K1, "other": "x"}, "AL": {"x": "y"}}
        cfg["credential_requests"] = {"enabled": True}

    def setUp(self):
        super().setUp()
        self.fa = riskmodel.build({"type": "jev", "api_key_secret": {"name": NAME, "var": VAR}}, None)
        self.broker.summarizer = self.fa
        self.kp = self.fa.key_providers[0]
        self.kp.attach(self.broker._summary_key_read, self.broker.log)

    def refused(self, body, unknown_like="unknown secret name"):
        code, out = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 400, out)
        self.assertEqual(json.loads(out), {"error": unknown_like})
        return out

    def test_key_read_works_and_is_not_a_request(self):
        self.kp.get()
        self.kp.wait()
        self.assertEqual(self.kp.get(), K1)
        self.assertEqual(self.events("secret_read"), [])
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("summary_key_read")[0]["result"], "ok")
        for r in self.records():
            self.assertNotIn(K1, json.dumps(r))
            if r["event"] == "summary_key_read":
                self.assertIsNone(audit_api.redact(r))

    def test_other_credentials_unaffected(self):
        code, body = self.create_env(["svc"])
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "approved")

    def test_env_http_refused_like_unknown(self):
        _, unknown = self.api("POST", "/v1/requests", {"mode": "env", "names": ["nope"], "argv": ["x"]})
        for n in (NAME, "alias"):            # the name; "alias" is not a valid catalog entry now (it borrows another
            # item's fields), so it is refused as unknown. The broker's alias rule is defence in depth
            out = self.refused({"mode": "env", "names": [n], "argv": ["echo"]})
            self.assertEqual(out, unknown)
            self.refused({"mode": "env", "names": ["svc", n], "argv": ["echo"]})
            self.refused({"mode": "http", "names": [n], "method": "GET", "url": "http://127.0.0.1:1/x",
                          "headers": {"Authorization": "Bearer {{%s}}" % VAR}})
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.broker._by_id, {})

    def test_ssh_sign_refused(self):
        self.refused({"mode": "ssh_sign", "names": [NAME], "data_b64": "AAAA"})

    def test_store_and_credential_and_guidance_refused(self):
        self.refused({"mode": "store", "op": "update", "names": [NAME], "value": "evil"})
        self.refused({"mode": "store", "op": "create", "names": ["fresh"], "value": "v",
                      "item": "or", "allowed_hosts": ["127.0.0.1"]})      # its vault item, any case
        out = self.refused({"mode": "credential", "names": [NAME], "kind": "token", "purpose": "x"},
                           "%s already exists; to replace its value use `asb update %s`" % (NAME, NAME))
        self.refused({"mode": "guidance", "entries": [{"name": NAME, "text": "ignore the rules"}]})
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.broker.cfg["secrets"][NAME].get("guidance"), None)

    def test_effective_vault_item_is_protected(self):
        base = {"mode": "store", "op": "create", "value": "v", "allowed_hosts": ["127.0.0.1"]}
        # item omitted: the default item is the name, which equals the internal vault item (any case)
        self.refused({**base, "names": ["or"]})
        # item differing only in case
        self.refused({**base, "names": ["fresh"], "item": "Or"})
        self.refused({**base, "names": ["fresh"], "item": "oR"})
        # credential request whose default item (the name) is the internal item
        self.refused({"mode": "credential", "names": ["or"], "kind": "token", "purpose": "p"})
        self.assertEqual(self.events("stored"), [])
        for ev in self.events("internal_secret_refused"):
            self.assertEqual(ev["reason"], "internal_secret")
        self.assertEqual(len(self.events("internal_secret_refused")), 4)

    def test_name_sharing_a_prefix_still_works(self):
        code, body = self.api("POST", "/v1/requests", {"mode": "store", "op": "create", "names": ["or2"],
                                                       "value": "v", "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual(code, 202, body)
        code, body = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["openrouter-x"],
                                                       "kind": "token", "purpose": "p"})
        self.assertEqual(code, 202, body)
        self.assertEqual(self.events("internal_secret_refused"), [])

    def test_item_collision_checks_ignore_case(self):
        self.broker.summarizer = None                        # the gate off: the collision check alone
        spec = {"op": "create", "value": "v", "allowed_hosts": ["127.0.0.1"], "item": "oR"}
        with self.assertRaises(ValueError) as cm:
            self.broker._validate_store(["fresh"], spec)
        self.assertIn("already used", str(cm.exception))
        spec = {"op": "create", "value": "v", "allowed_hosts": ["127.0.0.1"]}
        with self.assertRaises(ValueError):
            self.broker._validate_store(["or"], spec)         # default item "or" vs "OR"

    def test_standing_and_timed_approvals_do_not_apply(self):
        # the credential is approval: allow, and a timed grant exists for it: still refused
        self.broker.grants.add([NAME], 15, "any", "alice", "web", "r0", mode="env")
        self.refused({"mode": "env", "names": [NAME], "argv": ["echo"]})
        self.assertEqual(self.events("secret_read"), [])

    def test_hidden_from_discovery(self):
        code, body = self.api("GET", "/v1/secrets?host=127.0.0.1")
        names = [x["name"] for x in json.loads(body)["secrets"]]
        self.assertEqual(names, ["svc"])
        code, body = self.api("GET", "/v1/secrets")
        self.assertNotIn(NAME, body)
        self.assertNotIn("alias", body)

    def test_audited_as_a_hidden_event_with_reason_class(self):
        self.refused({"mode": "env", "names": [NAME], "argv": ["echo"]})
        ev = self.events("internal_secret_refused")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["secret"], ev[0]["reason"]), (NAME, "internal_secret"))
        self.assertIn("internal_secret_refused", audit_api.HIDDEN)
        self.assertIsNone(audit_api.redact(ev[0]))
        # the agent-visible `rejected` event carries only the generic wording
        rej = [r for r in self.events("rejected") if r["names"] == [NAME]]
        self.assertEqual(rej[0]["reason"], "unknown secret name")

    def test_approver_pages_still_list_it_marked_internal(self):
        rows = self.broker.standing_rows()
        mine = [r for r in rows if r["secrets"] and r["secrets"][0].startswith(NAME)]
        self.assertTrue(mine)
        self.assertIn("(internal: summary key)", mine[0]["secrets"][0])
        self.assertIn(NAME, self.broker.cfg["secrets"])

    def test_catalog_change_invalidates_the_cached_key(self):
        self.broker.refresh_catalog()                        # records the source of the key
        self.kp.get()
        self.kp.wait()
        self.assertEqual(self.kp.get(), K1)
        self.broker.backend._data["OR"]["key2"] = K2
        meta = json.loads(self.broker.backend._data["OR"]["broker"])
        meta["vars"][VAR]["field"] = "key2"
        self.broker.backend._data["OR"]["broker"] = json.dumps(meta)
        self.broker.refresh_catalog()
        self.assertIsNone(self.kp.get())                     # dropped: re-read in the background
        self.kp.wait()
        self.assertEqual(self.kp.get(), K2)
        self.broker.refresh_catalog()                        # unchanged source: kept
        self.assertEqual(self.kp.get(), K2)


class Oracles(AgentPath):
    """An internal name answers exactly like an unknown name (or an existing ordinary credential
    where that is what the mode says): same status, body, visible audit event and code path."""

    def post(self, body):
        return self.api("POST", "/v1/requests", body)

    def same(self, mk, other="nosuch"):
        a, b = self.post(mk(other)), self.post(mk(NAME))
        self.assertEqual(a, b)
        return a

    def test_env_http_ssh_and_bad_scripts(self):
        for mk in (lambda n: {"mode": "env", "names": [n], "argv": ["echo"]},
                   lambda n: {"mode": "env", "names": [n], "argv": ["echo"], "scripts": "nope"},
                   lambda n: {"mode": "env", "names": [n], "argv": ["echo"], "scripts": [{"path": 1}]},
                   lambda n: {"mode": "http", "names": [n], "method": "GET", "url": "http://127.0.0.1:1/x",
                              "headers": {}, "scripts": [{"x": 1}]},
                   lambda n: {"mode": "http", "names": [n], "method": "GET", "url": "http://127.0.0.1:1/x",
                              "headers": {}},
                   lambda n: {"mode": "ssh_sign", "names": [n], "data_b64": "AAAA"}):
            code, body = self.same(mk)
            self.assertEqual(code, 400, body)

    def test_guidance_and_store_update(self):
        self.same(lambda n: {"mode": "guidance", "entries": [{"name": n, "text": "x"}]})
        self.same(lambda n: {"mode": "store", "op": "update", "names": [n], "value": "v"})
        self.same(lambda n: {"mode": "store", "op": "update", "names": [n], "value": ""})   # value error first

    def test_store_and_credential_create_answer_like_an_existing_credential(self):
        code, a = self.post({"mode": "store", "op": "create", "names": ["svc"], "value": "v",
                             "allowed_hosts": ["127.0.0.1"]})
        code2, b = self.post({"mode": "store", "op": "create", "names": [NAME], "value": "v",
                              "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual((code, code2), (400, 400))
        self.assertEqual(a.replace("svc", "X"), b.replace(NAME, "X"))
        code, a = self.post({"mode": "credential", "names": ["svc"], "kind": "token", "purpose": "p"})
        code2, b = self.post({"mode": "credential", "names": [NAME], "kind": "token", "purpose": "p"})
        self.assertEqual((code, code2), (400, 400))
        self.assertEqual(a.replace("svc", "X"), b.replace(NAME, "X"))

    def test_visible_audit_event_is_the_same(self):
        self.post({"mode": "env", "names": ["nosuch"], "argv": ["echo"]})
        self.post({"mode": "env", "names": [NAME], "argv": ["echo"]})
        rej = [r for r in self.events("rejected") if r["mode"] == "env"]
        strip = lambda r: {k: v for k, v in r.items() if k not in ("names", "seq", "ts", "time", "prev")}  # noqa: E731
        self.assertEqual(strip(rej[0]), strip(rej[1]))
        self.assertEqual([audit_api.redact(r) is None for r in self.events("internal_secret_refused")], [True])

    def test_the_same_catalog_refresh_path_is_taken(self):
        calls = []
        real = self.broker._refresh_if
        self.broker._refresh_if = lambda stale, wait=True: (calls.append(stale), real(stale, wait))[1]
        for n in ("nosuch", NAME):
            calls.clear()
            self.post({"mode": "env", "names": [n], "argv": ["echo"]})
            self.assertEqual(calls[0], 0, n)                  # a forced reload, for both
        calls.clear()
        self.post({"mode": "env", "names": ["svc"], "argv": ["echo"]})
        self.assertEqual(calls[0], self.broker.CATALOG_TTL)    # a known name: the cached catalog

    def test_unhealthy_backend_text_applies_to_internal_names_too(self):
        self.broker._refresh_if = lambda *a, **k: None
        self.broker._backend_ok = False
        code, a = self.post({"mode": "env", "names": ["nosuch"], "argv": ["echo"]})
        code2, b = self.post({"mode": "env", "names": [NAME], "argv": ["echo"]})
        self.assertEqual(a, b)
        self.assertIn("not healthy", a)


class KeyItemKnowledge(AgentPath):
    def test_item_stays_protected_while_the_entry_is_missing_from_the_catalog(self):
        self.broker.refresh_catalog()
        self.assertEqual(self.kp.get() is None or True, True)
        self.broker._internal_secrets()                      # learns the item
        self.assertEqual(self.kp.known_items, frozenset({"or"}))
        del self.broker.cfg["secrets"][NAME]                 # a catalog blip
        out = self.refused({"mode": "store", "op": "create", "names": ["fresh"], "value": "v",
                            "allowed_hosts": ["127.0.0.1"], "item": "OR"})
        self.assertEqual(json.loads(out), {"error": "unknown secret name"})

    def test_fails_closed_when_the_item_was_never_seen(self):
        self.kp.known_items = frozenset()
        del self.broker.cfg["secrets"][NAME]
        code, out = self.api("POST", "/v1/requests", {"mode": "store", "op": "create", "names": ["fresh"],
                                                      "value": "v", "allowed_hosts": ["127.0.0.1"]})
        self.assertEqual(code, 400)
        self.assertIn("not healthy", out)

    def test_uuid_looking_items_and_names_are_rejected(self):
        u = "123e4567-e89b-12d3-a456-426614174000"
        code, out = self.api("POST", "/v1/requests", {"mode": "store", "op": "create", "names": ["fresh"],
                                                      "value": "v", "allowed_hosts": ["127.0.0.1"], "item": u})
        self.assertEqual(code, 400)
        self.assertIn("bad item name", out)
        code, out = self.api("POST", "/v1/requests", {"mode": "credential", "names": [u], "kind": "token",
                                                      "purpose": "p"})
        self.assertEqual(code, 400)

    def test_key_is_warmed_at_startup_and_survives_a_catalog_blip(self):
        fa = riskmodel.build({"type": "jev", "api_key_secret": {"name": NAME, "var": VAR}}, None)
        self.broker.summarizer = fa
        kp = fa.key_providers[0]
        kp.attach(self.broker._summary_key_read, self.broker.log)
        self.broker._initial_load(locked=False)              # what start-up does: load, then warm
        kp.wait()
        self.assertEqual(self.events("summary_key_read")[-1]["result"], "ok")
        self.assertEqual(kp.get(), K1)
        del self.broker.cfg["secrets"][NAME]                 # the entry is briefly missing
        kp.invalidate  # (the cache is NOT dropped by a missing entry)
        kp._fresh_until = 0                                  # force a refresh
        kp.get()
        kp.wait()
        self.assertEqual(kp.get(), K1)                       # kept: the blip is transient
        self.assertEqual(self.events("summary_key_read")[-1]["result"], "other")


class Provider(unittest.TestCase):
    """VaultKey on its own, with a scripted reader and a fake clock."""

    def make(self, ttl=60, grace=900, script=None):
        self.now = [0.0]
        self.calls, self.gate = [], threading.Event()
        self.gate.set()
        self.script = list(script or [])

        def reader(name, var):
            self.calls.append(1)
            self.gate.wait(10)
            step = self.script.pop(0) if len(self.script) > 1 else self.script[0]
            self.now[0] += getattr(self, "read_takes", 0)
            if isinstance(step, keyprovider.KeyUnavailable):
                raise step
            return step
        kp = keyprovider.VaultKey("n", "V", ttl, clock=lambda: self.now[0], grace=grace)
        kp.attach(reader, lambda *a, **k: None)
        return kp

    def prime(self, kp):
        kp.get()
        kp.wait()

    def test_twenty_callers_never_queue_and_one_read_happens(self):
        kp = self.make(script=["KEY1"])
        self.gate.clear()                                    # a very slow vault
        out, ths = [], []
        t0 = __import__("time").monotonic()
        for _ in range(20):
            th = threading.Thread(target=lambda: out.append(kp.get()))
            th.start()
            ths.append(th)
        for th in ths:
            th.join(2)
        self.assertLess(__import__("time").monotonic() - t0, 2)
        self.assertEqual(out, [None] * 20)                   # first use: no key, nobody waited
        self.gate.set()
        kp.wait()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(kp.get(), "KEY1")
        # after expiry: 20 more callers all get the stale key, still one read
        self.now[0] += 61
        self.gate.clear()
        out.clear()
        ths = [threading.Thread(target=lambda: out.append(kp.get())) for _ in range(20)]
        [th.start() for th in ths]
        [th.join(2) for th in ths]
        self.assertEqual(out, ["KEY1"] * 20)
        self.gate.set()
        kp.wait()
        self.assertEqual(len(self.calls), 2)

    def test_stale_served_only_up_to_the_grace(self):
        kp = self.make(ttl=60, grace=100, script=["KEY1", keyprovider.KeyUnavailable("backend_unavailable")])
        self.prime(kp)
        self.now[0] = 159                                    # expired 99 s ago, within grace
        self.assertEqual(kp.get(), "KEY1")
        kp.wait()
        self.now[0] = 161                                    # past ttl + grace
        self.assertIsNone(kp.get())

    def test_transient_failure_keeps_last_good_key_for_grace(self):
        down = keyprovider.KeyUnavailable("backend_unavailable")
        kp = self.make(ttl=60, grace=900, script=["KEY1", down])
        self.prime(kp)
        for step in (61, 100, 200, 600):
            self.now[0] = step
            self.assertEqual(kp.get(), "KEY1", step)
            kp.wait()
        self.now[0] = 60 + 900 + 1                           # grace over
        kp.get()
        kp.wait()
        self.assertIsNone(kp.get())

    def test_each_transient_class_keeps_the_key(self):
        for cls in ("backend_unavailable", "rate_limited", "other"):
            kp = self.make(script=["KEY1", keyprovider.KeyUnavailable(cls)])
            self.prime(kp)
            self.now[0] += 61
            kp.get()
            kp.wait()
            self.assertEqual(kp.get(), "KEY1", cls)

    def test_permanent_failure_drops_the_key_at_once(self):
        for bad in (keyprovider.KeyUnavailable("not_found"), "", "  ", "bad key", "k\u00e9y"):
            kp = self.make(script=["KEY1", bad])
            self.prime(kp)
            self.assertEqual(kp.get(), "KEY1")
            self.now[0] += 61
            kp.get()
            kp.wait()
            self.assertIsNone(kp.get(), repr(bad))

    def test_grace_zero_disables_stale(self):
        down = keyprovider.KeyUnavailable("backend_unavailable")
        kp = self.make(ttl=60, grace=0, script=["KEY1", down])
        self.prime(kp)
        self.now[0] = 61
        self.assertIsNone(kp.get())
        kp.wait()
        self.assertIsNone(kp.get())

    def test_expiry_is_measured_after_the_read(self):
        self.read_takes = 50                                 # the read itself takes 50 s
        kp = self.make(ttl=60, script=["KEY1", "KEY2"])
        self.prime(kp)
        self.assertEqual(self.now[0], 50.0)
        self.now[0] = 50 + 59                                # 59 s after the read finished
        kp.get()
        kp.wait()
        self.assertEqual(len(self.calls), 1)                 # still fresh: no second read

    def test_non_ascii_is_invalid(self):
        kp = self.make(script=["k\u00e9y"])
        self.prime(kp)
        self.assertIsNone(kp.get())

    def test_a_hung_vault_read_has_a_deadline_and_does_not_wedge_the_key(self):
        hang = threading.Event()
        kp = keyprovider.VaultKey("n", "V", 60, grace=0, read_timeout=0.2)
        calls = []

        def reader(n, v):
            calls.append(1)
            if len(calls) == 1:
                hang.wait(10)
            return "KEY2"
        kp.attach(reader, lambda *a, **k: None)
        kp.get()
        kp.wait(3)
        self.assertIsNone(kp.get())                          # first read timed out: class backend_unavailable
        kp.wait(3)
        self.assertIsNone(kp._busy)
        kp._fresh_until = 0
        kp.get()
        kp.wait(3)
        self.assertEqual(kp.get(), "KEY2")                   # the next refresh is not blocked
        hang.set()

    def test_grace_config(self):
        ok = {"type": "jev", "api_key_secret": {"name": NAME, "var": VAR}}
        for g in (0, 900, 3600):
            riskmodel.validate_config({**ok, "api_key_grace_s": g})
        for g in (-1, 3601, 1.5, "9", True, None):
            with self.assertRaises(ValueError) as cm:
                riskmodel.validate_config({**ok, "api_key_grace_s": g})
            self.assertIn("api_key_grace_s", str(cm.exception))
        with self.assertRaises(ValueError):
            riskmodel.validate_config({"type": "jev", "api_key_file": "/k", "api_key_grace_s": 5})
        self.assertEqual(riskmodel.build(ok, None).key_providers[0].grace, 900)


if __name__ == "__main__":
    unittest.main()
