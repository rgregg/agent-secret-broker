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
                             self.audit, summarizer=self.fa)

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

    def analyze(self):
        return self.fa.analyze("http", ["x"], dict(SPEC))

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
        self.analyze()
        self.assertEqual(set(self.auths()[n:]), {"Bearer " + K1})   # still cached
        self.assertEqual(len(reads()), 1)
        self.now[0] += 2                                    # past the 300 s default TTL
        n = len(Fake.seen)
        self.analyze()
        self.assertEqual(set(self.auths()[n:]), {"Bearer " + K2})
        self.assertEqual(len(reads()), 2)

    def test_custom_ttl(self):
        sc = dict(self.sc, api_key_ttl_s=30)
        fa = riskmodel.build(sc, None, clock=lambda: self.now[0])
        self.assertEqual(fa.key_providers[0].ttl, 30)
        fa.key_providers[0].attach(self.broker._summary_key_read, self.broker.log)
        self.assertEqual(fa.key_providers[0].get(), K1)
        self.put(K2)
        self.now[0] += 31
        self.assertEqual(fa.key_providers[0].get(), K2)

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
        kp.attach(lambda n, v: 1 / 0, lambda *a, **k: 1 / 0)
        kp._until = 0
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
    """The item stays an ordinary credential: an agent still asks, a human still approves."""

    def tweak(self, cfg):
        cfg["secrets"][NAME] = {"vars": {VAR: {"item": "OR", "field": "key"}}, "allowed_hosts": ["127.0.0.1"]}
        cfg["_vault"] = {"OR": {"key": K1}}

    def test_agent_request_unaffected_and_internal_read_is_not_a_request(self):
        fa = riskmodel.build({"type": "jev", "api_key_secret": {"name": NAME, "var": VAR}}, None)
        self.broker.summarizer = fa
        fa.key_providers[0].attach(self.broker._summary_key_read, self.broker.log)
        self.assertEqual(fa.key_providers[0].get(), K1)
        self.assertEqual(self.events("secret_read"), [])
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.events("summary_key_read")[0]["result"], "ok")
        code, body = self.create_env([NAME])                 # the normal path: prompted, approved
        rid = json.loads(body)["id"]
        self.assertEqual(code, 202)
        self.assertEqual(len(self.notifier.sent), 1)
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        got = json.loads(b)
        self.assertEqual((got["status"], got["env"]), ("approved", {VAR: K1}))
        self.assertEqual(len(self.events("secret_read")), 1)
        self.assertEqual(self.events("secret_read")[0]["id"], rid)
        for r in self.records():                             # the key is in no audit record
            self.assertNotIn(K1, json.dumps(r))
        # the agent-visible audit view never shows the internal read
        for r in self.records():
            if r["event"] == "summary_key_read":
                self.assertIsNone(audit_api.redact(r))


if __name__ == "__main__":
    unittest.main()
