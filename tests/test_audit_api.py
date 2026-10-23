"""GET /v1/audit and /v1/audit/verify (redacted audit view for the agent) and `asb audit`."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit as audit_mod  # noqa: E402
from secret_broker import audit_api  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
ENVELOPE = {"seq", "ts", "event", "request"}
ALLOWED_KEYS = ENVELOPE | {k for spec in audit_api.WHITELIST.values() for k in spec}
POISON = {"risk": "critical", "reasons": ["POISON-REASON"], "summary": "POISON-SUMMARY",
          "token": "POISON-TOKEN", "hash": "POISON-HASH", "value": "POISON-VALUE",
          "prev": "POISON-PREV", "via": "policy", "model": "POISON-MODEL",
          "always_requested": True, "auto_max": 3, "approval": "allow", "adopted": ["POISON-ADOPTED"],
          "policies": {"svc": "allow"}, "nonce": "POISON-NONCE", "previous_value": "POISON-PREVIOUS",
          "action_hash": "POISON-ACTION", "approver_ip": "203.0.113.77", "user": "POISON-USER",
          "client_ip": "203.0.113.78", "to_peer": "203.0.113.79", "names_hidden": ["POISON-NAMES"],
          "latency_ms": 7, "item": "POISON-ITEM", "key": "POISON-KEY", "hosts": ["POISON-HOST"],
          "ssh_what": "POISON-WHAT", "warning": "POISON-WARNING"}


def rec(event, seq=1, **fields):
    return {"seq": seq, "ts": 1760000000.5, "time": "2025-10-09T08:53:20Z", "event": event,
            "prev": "0" * 64, **fields}


def event_names_in_broker():
    """Every audit event name the broker source can emit."""
    src = ""
    for mod in ("broker.py", "sshrules.py", "sessions.py"):         # modules that emit audit events
        with open(os.path.join(ROOT, "secret_broker", mod)) as f:
            src += f.read()
    names = set(re.findall(r'\.(?:log|audit)\(\s*"([a-z_]+)"', src))
    names |= {f"{c}_decide_refused" for c in re.findall(r'self\.log\(f"\{channel\}(_decide_refused)"', src)
              for c in ("dashboard", "push", "ha", "link")}
    names |= set(re.findall(r'self\._finish\(\s*req,\s*"([a-z]+)"', src))
    names |= {"approved", "denied", "expired", "failed"}      # via _finish(status)
    names |= {"session_expired", "session_closed", "session_revoked", "session_ended"}   # sessions.py: "session_" + reason
    return names


class Redaction(unittest.TestCase):
    def test_every_event_the_broker_emits_is_classified(self):
        names = event_names_in_broker()
        self.assertGreater(len(names), 35, names)               # the grep itself works
        for n in ("requested", "approved", "http_executed", "client_event", "ha_decide_refused",
                  "push_decide_refused", "decision_refused", "policy_changed", "assessed"):
            self.assertIn(n, names)
        unknown = names - set(audit_api.WHITELIST) - audit_api.HIDDEN
        self.assertEqual(unknown, set(), "new audit event: add it to WHITELIST or HIDDEN")

    def test_nothing_outside_the_whitelist_leaks_for_any_event(self):
        for ev in sorted(event_names_in_broker() | {"totally_unknown_event"}):
            out = audit_api.redact(rec(ev, id="Rid_1", request_id="Rid_1", **POISON))
            if ev in audit_api.HIDDEN:
                self.assertIsNone(out, ev)
                continue
            if ev not in audit_api.WHITELIST:
                self.assertIsNone(out, ev)                  # deny by default
                continue
            self.assertLessEqual(set(out), ALLOWED_KEYS, ev)
            allowed = ENVELOPE | set(audit_api.WHITELIST.get(ev, {}))
            self.assertLessEqual(set(out), allowed, ev)
            self.assertNotIn("POISON", json.dumps(out), ev)

    def test_poisoned_extra_fields_are_dropped(self):
        out = audit_api.redact(rec("http_executed", id="r1", upstream_status=200, response_bytes=5,
                                   duration_ms=3, **POISON))
        self.assertEqual(out["upstream_status"], 200)
        self.assertEqual(set(out), ENVELOPE | {"upstream_status", "response_bytes", "duration_ms"})
        self.assertIsNone(audit_api.redact(rec("brand_new_event", id="r1", **POISON)))
        out = audit_api.redact(rec("requested", id="r1", names=["svc"], mode="http", method="GET",
                                   url="https://h/p", source="me", peer="1.2.3.4", **POISON))
        self.assertEqual(out["names"], ["svc"])
        self.assertNotIn("POISON", json.dumps(out))
        for k in ("risk", "reasons", "summary", "token", "hash", "value", "via", "prev"):
            self.assertNotIn(k, out)

    def test_wrong_types_are_dropped_not_coerced(self):
        out = audit_api.redact(rec("http_executed", id="r1", upstream_status="200",
                                   response_bytes=True, duration_ms=[1]))
        self.assertEqual(set(out), ENVELOPE)
        out = audit_api.redact(rec("requested", id="r1", names="svc", argv=[1, "ok"]))
        self.assertEqual(out["argv"], ["ok"])
        self.assertNotIn("names", out)
        self.assertIsNone(audit_api.redact(rec("requested", seq="1")))
        self.assertIsNone(audit_api.redact("nope"))
        self.assertIsNone(audit_api.redact({"seq": 1, "event": "requested"}))      # no ts

    def test_policy_approval_looks_like_no_human_decision(self):
        auto = audit_api.redact(rec("approved", id="r1", via="policy", latency_ms=1))
        self.assertEqual(auto["channel"], None)
        self.assertEqual(auto["approver"], None)
        self.assertNotIn("via", auto)
        self.assertNotIn("latency_ms", auto)
        # even a record that carries a channel/approver along with via=policy
        auto2 = audit_api.redact(rec("approved", id="r1", via="policy", channel="push",
                                     approver="policy:auto-create"))
        self.assertEqual((auto2["channel"], auto2["approver"]), (None, None))
        human = audit_api.redact(rec("approved", id="r1", via="user", channel="push",
                                     approver="alice"))
        self.assertEqual((human["channel"], human["approver"]), ("push", "human"))
        self.assertEqual(set(auto), set(human))                                    # same shape
        bad = audit_api.redact(rec("approved", id="r1", via="user", channel="auto", approver="x"))
        self.assertIsNone(bad["channel"])                                          # not an allowed channel

    def test_error_text_is_reduced_to_a_class(self):
        out = audit_api.redact(rec("failed", id="r1", error="release failed: vault item 'Secret Bank' x"))
        self.assertEqual(out["error_class"], "release_failed")
        self.assertNotIn("Bank", json.dumps(out))
        out = audit_api.redact(rec("http_failed", id="r1", error="[Errno 111] Connection refused"))
        self.assertEqual(out["error_class"], "connection")
        out = audit_api.redact(rec("failed", id="r1", error="could not notify: tg 500 token=abc"))
        self.assertEqual(out["error_class"], "other")       # a notify error would mean "a human was asked"
        self.assertNotIn("abc", json.dumps(out))

    def test_catalog_loaded_gives_counts_not_names(self):
        out = audit_api.redact(rec("catalog_loaded", count=3, names=["a", "b", "c"],
                                   invalid=[{"item": "X", "reason": "r"}], adopted=["b"]))
        self.assertEqual((out["count"], out["invalid_count"]), (3, 1))
        self.assertNotIn("names", out)
        self.assertNotIn("adopted", out)

    def test_hidden_events_are_not_returned(self):
        for ev in ("assessed", "escalated", "notified", "decided", "startup", "policy_changed",
                   "approval_viewed", "dashboard_viewed", "client_event_dropped", "push_subscribed",
                   "push_test", "csrf_refused", "ssh_hosts_changed", "ssh_hosts_change_refused",
                   "ssh_hosts_change_failed"):
            self.assertIsNone(audit_api.redact(rec(ev, id="r1")), ev)

    def test_unknown_events_are_dropped_and_not_counted(self):
        self.assertIsNone(audit_api.redact(rec("never_heard_of_it", id="r1")))
        self.assertIn("client_event", audit_api.HIDDEN)
        for ev in ("client_event", "decision_refused", "ha_decide_refused", "push_decide_refused",
                   "dashboard_decide_refused", "link_decide_refused", "config_warning",
                   "request_detail_viewed"):
            self.assertIsNone(audit_api.redact(rec(ev, id="r1", kind="show", ok=True)), ev)
        # nothing outside WHITELIST is ever shown, so the two sets cannot overlap
        self.assertEqual(set(audit_api.WHITELIST) & audit_api.HIDDEN, set())


class Params(unittest.TestCase):
    def p(self, q):
        return audit_api.parse_params(q, now=1_000_000)

    def test_defaults(self):
        p = self.p("")
        self.assertEqual((p["limit"], p["order"]), (100, "desc"))
        self.assertEqual(self.p("request=abc")["order"], "asc")
        self.assertEqual(self.p("after=3")["order"], "asc")
        self.assertEqual(self.p("request=abc&order=desc")["order"], "desc")

    def test_relative_and_iso_times(self):
        self.assertEqual(self.p("since=15m")["since"], 1_000_000 - 900)
        self.assertEqual(self.p("since=3d")["since"], 1_000_000 - 3 * 86400)
        self.assertEqual(self.p("until=2026-10-18T01:02:03Z")["until"], 1792285323.0)
        self.assertEqual(self.p("until=2026-10-18T01:02:03%2B00:00")["until"], 1792285323.0)

    def test_bad_input(self):
        for q in ("limit=0", "limit=501", "limit=abc", "limit=-1", "limit=1&limit=2", "bogus=1",
                  "request=a%20b", "request=" + "a" * 65, "request=", "event=Bad-Name",
                  "event=" + ",".join(["a"] * 21), "event=,", "secret=a/b", "secret=" + "a" * 65,
                  "source=", "source=" + "a" * 81, "since=yesterday", "since=99999999999d",
                  "since=" + "1" * 41, "until=2026-13-45", "before=-1", "before=x", "after=1.5",
                  "before=1&after=2", "order=sideways", "since=1h&until=2h", "source=a%00b",
                  "source=caf%C3%A9", "before=" + "9" * 16):
            with self.assertRaises(audit_api.BadParam, msg=q):
                self.p(q)

    def test_limits_accepted(self):
        self.assertEqual(self.p("limit=500")["limit"], 500)
        self.assertEqual(self.p("event=a_b,c1")["events"], frozenset({"a_b", "c1"}))


class ApiBase(t.Harness):
    """A broker with a real log. Several requests run through approve, deny and auto paths."""
    decision = "approve"

    def tweak(self, cfg):
        cfg["secrets"]["auto"] = {"vars": {"AUTO_TOKEN": {"item": "Auto", "field": "token"}},
                                  "allowed_hosts": ["127.0.0.1"], "approval": "allow"}
        cfg["_vault"] = {"Auto": {"token": "auto-secret-value"}}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = t._Stub("POISON-SUMMARY-TEXT", "low")

    def get(self, q="", key=t.KEY, path="/v1/audit"):
        code, body = self.api("GET", path + (("?" + q) if q else ""), key=key)
        return code, json.loads(body), body

    def run_env(self, decision="approve", names=("svc",)):
        self.decision = decision
        code, b = self.create_env(names)
        rid = json.loads(b)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        return rid

    def run_http(self, name="svc"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, b = self.api("POST", "/v1/requests", {
            "mode": "http", "names": [name], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{%s}}" % ("SVC_TOKEN" if name == "svc" else "AUTO_TOKEN")}})
        rid = json.loads(b)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        return rid


class Api(ApiBase):
    # -- auth --------------------------------------------------------------
    def test_auth_matrix(self):
        for path in ("/v1/audit", "/v1/audit/verify"):
            for key in ("", "wrong", "h" * 40):
                self.assertEqual(self.api("GET", path, key=key)[0], 401, (path, key))
        self.assertEqual(self.get()[0], 200)
        self.assertEqual(self.get(path="/v1/audit/verify")[0], 200)

    def test_hook_key_is_refused(self):
        hook = "h" * 40
        self.broker.ha_hook = {"key": hook, "allowed_devices": []}
        self.assertEqual(self.api("GET", "/v1/audit", key=hook)[0], 401)
        r = t.req(self.base + "/v1/audit", headers={"Authorization": "Bearer " + hook})
        self.assertEqual(r[0], 401)

    # -- filters ------------------------------------------------------------
    def test_request_timeline(self):
        a, b = self.run_env(), self.run_env()
        code, r, _ = self.get(f"request={a}")
        self.assertEqual(code, 200)
        self.assertEqual([e["event"] for e in r["events"]],
                         ["requested", "secret_read", "approved", "delivered"])
        self.assertTrue(all(e["request"] == a for e in r["events"]))
        seqs = [e["seq"] for e in r["events"]]
        self.assertEqual(seqs, sorted(seqs))
        self.assertIsNone(r["next"])
        self.assertFalse(r["truncated"])
        self.assertEqual(r["count"], 4)
        _, d, _ = self.get(f"request={a}&order=desc")
        self.assertEqual([e["seq"] for e in d["events"]], seqs[::-1])
        self.assertEqual(self.get("request=" + "x" * 22)[1]["events"], [])
        self.assertEqual(r["events"][0]["names"], ["svc"])

    def test_event_secret_source_filters(self):
        self.run_env()
        self.run_env(decision="deny")
        _, r, _ = self.get("event=approved,denied")
        self.assertEqual(sorted(e["event"] for e in r["events"]), ["approved", "denied"])
        _, r, _ = self.get("event=requested&secret=svc")
        self.assertEqual(r["count"], 2)
        _, r, _ = self.get("event=requested&secret=nothere")
        self.assertEqual(r["events"], [])
        _, r, _ = self.get("event=secret_read&secret=svc")
        self.assertEqual(r["count"], 1)
        _, r, _ = self.get("event=requested&source=127.0.0.1")
        self.assertEqual(r["count"], 2)
        _, r, _ = self.get("event=requested&source=elsewhere")
        self.assertEqual(r["events"], [])
        _, r, _ = self.get("event=assessed")          # hidden event types never match
        self.assertEqual(r["events"], [])

    def test_time_filters(self):
        self.run_env()
        _, r, _ = self.get("since=1h&event=requested")
        self.assertEqual(r["count"], 1)
        future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
        past = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
        self.assertEqual(self.get(f"since={future}")[1]["events"], [])
        self.assertEqual(self.get(f"until={past}")[1]["events"], [])
        self.assertEqual(self.get(f"until={future}&event=requested")[1]["count"], 1)
        self.assertEqual(self.get(f"since={past}&until={future}&event=requested&order=asc")[1]["count"], 1)

    # -- paging -------------------------------------------------------------
    def test_paging_backward_and_forward(self):
        for _ in range(3):
            self.run_env()
        _, full, _ = self.get("limit=500")
        allseqs = [e["seq"] for e in full["events"]]
        self.assertEqual(allseqs, sorted(allseqs, reverse=True))
        self.assertIsNone(full["next"])
        got, cur = [], None
        for _ in range(50):
            _, r, _ = self.get("limit=3" + (f"&before={cur}" if cur is not None else ""))
            got += [e["seq"] for e in r["events"]]
            cur = r["next"]
            if cur is None:
                break
        self.assertEqual(got, allseqs)
        got, cur = [], None
        for _ in range(50):
            _, r, _ = self.get("order=asc&limit=4" + (f"&after={cur}" if cur is not None else ""))
            got += [e["seq"] for e in r["events"]]
            cur = r["next"]
            if cur is None:
                break
        self.assertEqual(got, allseqs[::-1])
        # tailing: after=<last seq> returns only what is new
        last = allseqs[0]
        self.assertEqual(self.get(f"after={last}")[1]["events"], [])
        self.run_env()
        _, r, _ = self.get(f"after={last}")
        self.assertGreater(r["count"], 0)
        self.assertTrue(all(e["seq"] > last for e in r["events"]))
        self.assertEqual(self.get("before=0")[1]["events"], [])

    def test_limit_and_scan_bound(self):
        for _ in range(2):
            self.run_env()
        self.assertEqual(self.get("limit=2")[1]["count"], 2)
        self.assertIsNotNone(self.get("limit=2")[1]["next"])
        old = audit_api.MAX_SCAN_LINES
        audit_api.MAX_SCAN_LINES = 5
        try:
            _, r, _ = self.get("event=nonexistent_event")
        finally:
            audit_api.MAX_SCAN_LINES = old
        self.assertTrue(r["truncated"])
        self.assertIsNotNone(r["next"])
        self.assertEqual(r["events"], [])

    def test_response_size_cap(self):
        for i in range(30):
            self.broker.log("discovery", peer="p", host="h.example", found=["n" * 40] * 10)
        self.broker.log("client_event", user="u", kind="show", ok=True)       # hidden: not counted
        old = audit_api.MAX_BODY_BYTES
        audit_api.MAX_BODY_BYTES = 2000
        try:
            code, r, raw = self.get("event=discovery&limit=500")
        finally:
            audit_api.MAX_BODY_BYTES = old
        self.assertTrue(r["truncated"])
        self.assertLess(r["count"], 30)
        self.assertIsNotNone(r["next"])
        self.assertEqual(r["next"], r["events"][-1]["seq"])
        _, more, _ = self.get(f"event=discovery&limit=500&before={r['next']}")
        self.assertGreater(more["count"], 0)

    def test_validation_errors_are_400_with_a_short_message(self):
        for q in ("limit=9999", "since=nope", "request=a%20b", "bogus=1", "before=1&after=1"):
            code, r, _ = self.get(q)
            self.assertEqual(code, 400, q)
            self.assertLess(len(r["error"]), 120)

    # -- redaction through the real broker -----------------------------------
    def test_auto_approved_request_shows_no_policy(self):
        self.decision = None
        rid = self.run_http("auto")
        code, r, _ = self.get(f"request={rid}")
        evs = {e["event"]: e for e in r["events"]}
        self.assertEqual([e["event"] for e in r["events"]],
                         ["requested", "secret_read", "http_executed", "approved", "delivered"])
        self.assertIsNone(evs["approved"]["channel"])
        self.assertIsNone(evs["approved"]["approver"])
        self.assertEqual(evs["http_executed"]["upstream_status"], 200)
        for k in ("via", "risk", "reasons", "summary", "latency_ms", "always_requested"):
            self.assertTrue(all(k not in e for e in r["events"]), k)
        self.assertEqual(self.notifier.sent, [])

    def test_no_secret_token_nonce_hash_or_policy_in_any_response(self):
        # approve (link), deny, auto, dashboard and refused paths
        r1 = self.run_env()
        self.decision = None
        r3 = self.run_http("auto")
        code, b = self.create_env()
        r4 = json.loads(b)["id"]
        self.broker.decide_via("dashboard", r4, "approve", "alice")
        self.api("GET", f"/v1/requests/{r4}?wait=5")
        r2 = self.run_env("deny")
        self.broker.log("ha_decide_refused", user="ha:dev1", peer="9.9.9.9", status=403,
                        reason="device not allowed")
        self.broker.log("push_decide_refused", user="alice", peer="9.9.9.9", client_ip="8.8.8.8",
                        status=403, reason="guard")
        self.broker.log("client_event", user="alice", peer="p", client_ip="c", kind="page_load",
                        state="visible", note="/")
        self.broker.log("client_event", user="alice", kind="click_outcome", ok=True, request_id=r4,
                        id=r4)
        self.broker.log("client_event", user="alice", peer="p", client_ip="c", kind="visibility",
                        state="visible", visible=True)
        self.broker.log("client_event", user="alice", peer="p", client_ip="c", kind="show",
                        ok=True, v="7", ms=12, tag="secret-LEAKTAG", note="/LEAKPATH",
                        err="LEAKERR 500", client_paths=["/LEAKPATH"])
        self.broker.log("approval_viewed", user="alice", peer="p", request_id=r4, found=True)
        self.broker.log("push_subscribed", user="alice", device="LEAKDEV", peer="p")
        nonces = [r.nonce for r in self.broker._by_id.values()]
        with open(self.audit) as f:
            raw_log = f.read()
        prevs = re.findall(r'"prev": "([0-9a-f]{64})"', raw_log)
        line_hashes = [hashlib.sha256(l.encode()).hexdigest() for l in raw_log.splitlines()]
        texts = []
        for q in ("limit=500", "limit=500&order=asc", "after=0&limit=500", f"request={r1}", f"request={r2}",
                  f"request={r3}", f"request={r4}", "event=approved,denied,failed,expired",
                  "event=secret_read,delivered,discovery", "secret=svc", "secret=auto"):
            code, r, raw = self.get(q)
            self.assertEqual(code, 200, q)
            texts.append(raw)
        texts.append(self.get(path="/v1/audit/verify")[2])
        blob = "\n".join(texts)
        forbidden = [t.SECRET, "auto-secret-value", t.KEY, "POISON-SUMMARY-TEXT", "approved_always",
                     "alice@", *nonces, *prevs, *line_hashes]
        for f in forbidden:
            self.assertNotIn(f, blob)
        for word in ('"risk"', '"reasons"', '"summary"', '"via"', '"prev"', '"hash"', '"nonce"',
                     '"policy', '"model"', '"approval"', '"adopted"', '"token"', '"value"',
                     "model rated", "treated as high", "policy:", "LEAKTAG", "LEAKPATH", "LEAKERR",
                     "LEAKDEV", "page_load", "visibility", "approval_viewed", "push_subscribed",
                     "client_event", "decide_refused", "decision_refused", "device not allowed"):
            self.assertNotIn(word, blob)
        seen = set()
        for tx in texts[:-1]:
            for e in json.loads(tx)["events"]:
                self.assertLessEqual(set(e), ALLOWED_KEYS)
                seen.add(e["event"])
        for ev in ("requested", "approved", "denied", "secret_read", "delivered"):
            self.assertIn(ev, seen)
        self.assertTrue(seen.isdisjoint(audit_api.HIDDEN), seen & audit_api.HIDDEN)
        dec = [e for e in json.loads(self.get(f"request={r4}")[2])["events"] if e["event"] == "approved"]
        self.assertEqual((dec[0]["channel"], dec[0]["approver"]), ("dashboard", "human"))

    # -- rate limit -----------------------------------------------------------
    def test_rate_limit_per_key(self):
        api = audit_api.AuditApi(self.audit, Broker.rate_map_make_room, rate_per_min=3)
        for _ in range(3):
            self.assertEqual(api.handle("/v1/audit", "limit=1", "k1")[0], 200)
        code, body, hdrs = api.handle("/v1/audit", "limit=1", "k1")
        self.assertEqual(code, 429)
        self.assertIn("Retry-After", hdrs)
        self.assertEqual(api.handle("/v1/audit", "limit=1", "k2")[0], 200)     # other key unaffected
        self.assertEqual(api.handle("/v1/audit/verify", "", "k1")[0], 429)     # shared bucket

    def test_rate_limit_over_http_and_window_reset(self):
        for _ in range(audit_api.RATE_PER_MIN):
            self.assertEqual(self.get("limit=1")[0], 200)
        self.assertEqual(self.get("limit=1")[0], 429)
        api = audit_api.AuditApi(self.audit, Broker.rate_map_make_room, rate_per_min=1)
        self.assertTrue(api.rate_ok("k", now=100.0))
        self.assertFalse(api.rate_ok("k", now=101.0))
        self.assertTrue(api.rate_ok("k", now=161.0))

    def test_rate_map_is_bounded_and_evicts_oldest(self):
        api = audit_api.AuditApi(self.audit, Broker.rate_map_make_room)
        old = Broker.RATE_MAP_CAP
        Broker.RATE_MAP_CAP = 8
        try:
            for i in range(50):
                self.assertTrue(api.rate_ok(f"k{i}", now=1000.0 + i * 0.001))
                self.assertLessEqual(len(api._rate), 8)
            self.assertIn("k49", api._rate)
            self.assertNotIn("k0", api._rate)
        finally:
            Broker.RATE_MAP_CAP = old

    # -- verify ---------------------------------------------------------------
    def test_verify_ok_and_detects_tampering(self):
        self.run_env()
        code, r, _ = self.get(path="/v1/audit/verify")
        self.assertEqual(code, 200)
        self.assertEqual(set(r), {"ok", "events", "first_bad_seq"})
        self.assertEqual((r["ok"], r["first_bad_seq"]), (True, None))
        self.assertEqual(r["events"], len(self.records()))
        self.assertEqual(self.get("x=1", path="/v1/audit/verify")[0], 400)
        with open(self.audit) as f:
            lines = f.read().splitlines()
        i = next(n for n, l in enumerate(lines) if '"event": "approved"' in l)
        lines[i] = lines[i].replace('"approved"', '"denied"')
        with open(self.audit, "w") as f:
            f.write("\n".join(lines) + "\n")
        _, r, _ = self.get(path="/v1/audit/verify")
        self.assertEqual((r["ok"], r["first_bad_seq"]), (False, i + 1))
        # removed line
        del lines[1]
        with open(self.audit, "w") as f:
            f.write("\n".join(lines) + "\n")
        _, r, _ = self.get(path="/v1/audit/verify")
        self.assertFalse(r["ok"])
        self.assertEqual(r["first_bad_seq"], 1)
        # garbage line
        with open(self.audit, "a") as f:
            f.write("not json\n")
        self.assertFalse(self.get(path="/v1/audit/verify")[1]["ok"])

    def test_verify_budget(self):
        self.run_env()
        with self.assertRaises(TimeoutError):
            audit_api.verify_chain(self.audit, budget_s=-1)

    # -- index behavior ---------------------------------------------------------
    def test_index_follows_rotation_and_window(self):
        self.run_env()
        n = self.get("limit=500")[1]["count"]
        self.assertGreater(n, 3)
        # a tiny window: only the tail is indexed, older history is flagged
        view = audit_api.AuditView(self.audit, window=600, stride=4)
        r = view.query(audit_api.parse_params("limit=500"))
        self.assertTrue(r["truncated"])
        self.assertLess(r["count"], n)
        self.assertGreater(r["count"], 0)
        seqs = [e["seq"] for e in r["events"]]
        self.assertEqual(seqs, sorted(seqs, reverse=True))
        # the log is replaced by a shorter file: the index resets
        view2 = audit_api.AuditView(self.audit, stride=4)
        self.assertEqual(view2.query(audit_api.parse_params("limit=500"))["count"], n)
        new = self.audit + ".new"
        with open(self.audit) as f, open(new, "w") as g:
            g.write("".join(f.readlines()[:3]))
        os.replace(new, self.audit)
        self.assertLessEqual(view2.query(audit_api.parse_params("limit=500"))["count"], 3)

    def test_missing_and_empty_log(self):
        view = audit_api.AuditView(os.path.join(tempfile.mkdtemp(), "none.jsonl"))
        self.assertEqual(view.query(audit_api.parse_params(""))["events"], [])
        self.assertEqual(audit_api.verify_chain(os.path.join(tempfile.mkdtemp(), "none")), (True, 0, None))


class Cli(ApiBase):
    def asb(self, *args, key=t.KEY, url=None):
        env = dict(os.environ, SECRET_BROKER_URL=url or self.base, SECRET_BROKER_KEY=key)
        return subprocess.run([sys.executable, "-I", t.CLI, *args], env=env, capture_output=True,
                              text=True, timeout=60)

    def test_formatting_request_and_json(self):
        rid = self.run_env()
        p = self.asb("audit", "--request", rid)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual([l.split()[1] for l in lines],
                         ["requested", "secret_read", "approved", "delivered"])
        self.assertTrue(all(rid[:8] in l for l in lines))
        self.assertTrue(re.match(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  requested ", lines[0]), lines[0])
        self.assertIn("names=svc", lines[0])
        self.assertIn("channel=link approver=human", lines[2])
        for bad in (t.SECRET, "risk", "POISON"):
            self.assertNotIn(bad, p.stdout)
        j = self.asb("audit", "--request", rid, "--json")
        self.assertEqual(json.loads(j.stdout)["count"], 4)
        self.assertEqual(json.loads(j.stdout)["events"][0]["event"], "requested")

    def test_default_list_is_chronological_and_filters(self):
        self.run_env()
        self.run_env("deny")
        p = self.asb("audit", "--since", "1h", "--event", "approved,denied", "--limit", "5")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([l.split()[1] for l in p.stdout.splitlines()], ["approved", "denied"])
        p = self.asb("audit", "--secret", "svc", "--event", "secret_read")
        self.assertEqual(len(p.stdout.splitlines()), 1)
        p = self.asb("audit", "--limit", "2")
        self.assertIn("--before", p.stderr)
        self.assertEqual(len(p.stdout.splitlines()), 2)

    def test_exit_codes(self):
        self.run_env()
        self.assertEqual(self.asb("audit", "--event", "nothing_like_this").returncode, 1)
        self.assertEqual(self.asb("audit", "--bogus").returncode, 2)
        self.assertEqual(self.asb("audit", "--limit").returncode, 2)
        self.assertEqual(self.asb("audit", "--limit", "9999").returncode, 2)       # server says 400
        self.assertEqual(self.asb("audit", "--since", "soon").returncode, 2)
        self.assertEqual(self.asb("audit", "--tail", "--request", "x").returncode, 2)
        self.assertEqual(self.asb("audit", key="bad").returncode, 3)
        self.assertEqual(self.asb("audit", "verify", key="bad").returncode, 3)
        self.assertEqual(self.asb("audit", url="http://127.0.0.1:1").returncode, 3)
        self.assertEqual(self.asb("audit", "verify", "extra").returncode, 2)

    def test_verify_command(self):
        self.run_env()
        p = self.asb("audit", "verify")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("hash chain intact", p.stdout)
        with open(self.audit) as f:
            lines = f.read().splitlines()
        lines[2] = lines[2].replace('"requested"', '"rewritten"')
        with open(self.audit, "w") as f:
            f.write("\n".join(lines) + "\n")
        p = self.asb("audit", "verify")
        self.assertEqual(p.returncode, 1)
        self.assertIn("BROKEN", p.stderr)

    def test_help_guide_and_banner(self):
        p = self.asb("help", "audit")
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: asb audit", p.stdout)
        self.assertIn("--tail", p.stdout)
        self.assertIn("usage: asb audit", self.asb("audit", "--help").stdout)
        g = self.asb("guide").stdout
        self.assertIn("asb audit --request ID", g)
        self.assertIn("Redacted by design", g)
        self.assertIn("asb audit", self.asb().stdout)

    def test_tail_prints_recent_then_new_events(self):
        self.run_env()
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=t.KEY)
        proc = subprocess.Popen([sys.executable, "-I", t.CLI, "audit", "--tail", "--json",
                                 "--event", "requested"], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        try:
            first = json.loads(proc.stdout.readline())
            self.assertEqual(first["event"], "requested")
            rid2 = self.run_env()
            second = json.loads(proc.stdout.readline())
            self.assertEqual(second["request"], rid2)
            self.assertGreater(second["seq"], first["seq"])
        finally:
            proc.send_signal(2)         # Ctrl-C
            proc.wait(timeout=10)
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
