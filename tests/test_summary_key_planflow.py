"""The broker's own summary key stays unusable through plans and sessions too."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import plan_base as pb  # noqa: E402
import test_sessions as ts  # noqa: E402
from secret_broker import audit_api, keyprovider  # noqa: E402

NAME, VAR, KEYVAL = "orkey", "ORKEY_TOKEN", "sk-or-FAKE-planflow-1234"


def add_internal(cfg):
    cfg["_vault"]["OrKey"] = {"token": KEYVAL}
    cfg["secrets"][NAME] = {"vars": {VAR: {"item": "OrKey", "field": "token"}}, "allowed_hosts": ["127.0.0.1"]}
    # (the catalog now refuses a credential that uses another item's fields, so an alias of the
    # internal vault item cannot exist; the broker's alias rule is defence in depth)


def mark_internal(broker, analyzer=None):
    kp = keyprovider.VaultKey(NAME, VAR)
    holder = analyzer or types.SimpleNamespace()
    holder.key_providers = (kp,)
    broker.summarizer = holder
    kp.attach(broker._summary_key_read, broker.log)
    return holder


class Stub:
    key_providers = ()

    def analyze(self, *a, **k):
        return None


class Plans(pb.PBase):
    def tweak(self, cfg):
        super().tweak(cfg)
        add_internal(cfg)

    def setUp(self):
        super().setUp()
        mark_internal(self.broker, Stub())
        self.sent0 = len(self.notifier.sent)

    def refused_events(self):
        return [r for r in self.records() if r["event"] == "internal_secret_refused"]

    def test_submit_refused_like_an_unknown_credential(self):
        code, unknown = self.api("POST", "/v1/plans", {"manifest": self.manifest(
            [self.rule(secret="nosuch")]), "source": "t"})
        self.assertEqual(code, 400)
        for n in (NAME,):
            code, r = self.api("POST", "/v1/plans", {"manifest": self.manifest([self.rule(secret=n)]), "source": "t"})
            self.assertEqual((code, r), (400, unknown))
        self.assertEqual(self.broker.pending(), [])
        self.assertEqual(len(self.notifier.sent), self.sent0)
        self.assertEqual(len(self.refused_events()), 1)
        self.assertEqual({e["reason"] for e in self.refused_events()}, {"internal_secret"})

    def test_one_internal_rule_among_many_refuses_the_whole_manifest(self):
        rules = [self.read_rule(), self.rule(), self.rule(secret=NAME, path_prefix="/v1/other")]
        code, r = self.api("POST", "/v1/plans", {"manifest": self.manifest(rules), "source": "t"})
        self.assertEqual(code, 400)
        self.assertEqual(r, {"error": "rules[2].secret: unknown credential"})
        self.assertEqual(self.broker.pending(), [])
        self.assertEqual(self.broker.active_plans(), [])
        self.assertEqual(KEYVAL in json.dumps(r), False)

    def test_plain_plans_still_work_and_a_plan_call_for_it_is_refused(self):
        pid = self.approve()
        code, r = self.call(pid, "orkey", "GET", "/v1/notes")
        self.assertEqual((code, r["error"], r["reason"]), (403, "outside plan", "no_rule"))
        self.assertEqual(r["why"], "secret")
        self.assertEqual(self.upstream(), [])
        self.assertEqual(len(self.refused_events()), 1)
        self.assertEqual(self.refused_events()[0]["mode"], "plan_call")
        code, r = self.call(pid, body=self.ok_note())        # the ordinary credential is unaffected
        self.assertEqual((code, r["http"]["status"]), (202, 200))

    def test_an_existing_plan_with_a_rule_for_it_stops_working(self):
        # the plan was approved before the credential became internal (or an alias appeared)
        mark_internal(self.broker, Stub())
        self.broker.summarizer.key_providers = ()
        pid = self.approve(self.manifest([self.read_rule(secret=NAME, path_prefix="/v1/n")]))
        self.broker.summarizer.key_providers = (keyprovider.VaultKey(NAME, VAR),)
        code, r = self.call(pid, NAME, "GET", "/v1/n")
        self.assertEqual(code, 403, r)
        self.assertEqual(self.upstream(), [])

    def test_plan_call_miss_is_identical_for_unknown_and_internal_names(self):
        events = lambda: [r for r in self.records() if r["event"] == "plan_miss"]  # noqa: E731
        for plan in ("pl_bogus_id", self.approve()):          # a bogus plan id, then a real plan
            out = []
            for n in ("nosuch", NAME):
                before = len(events())
                out.append(self.call(plan, n, "GET", "/v1/notes"))
                new = events()[before:]
                out.append([{k: v for k, v in e.items() if k not in ("seq", "ts", "time", "prev", "id")}
                            for e in new])
            self.assertEqual(out[0], out[2])
            self.assertEqual(out[1], out[3])
        # and with plans disabled
        self.broker.plans_cfg["enabled"] = False
        a = self.call("pl_bogus_id", "nosuch", "GET", "/v1/notes")
        b = self.call("pl_bogus_id", NAME, "GET", "/v1/notes")
        self.assertEqual(a, b)

    def test_submit_forces_the_same_catalog_reload_for_an_internal_name(self):
        calls = []
        real = self.broker._refresh_if
        self.broker._refresh_if = lambda stale, wait=True: (calls.append(stale), real(stale, wait))[1]
        for n in ("nosuch", NAME):
            calls.clear()
            self.api("POST", "/v1/plans", {"manifest": self.manifest([self.rule(secret=n)]), "source": "t"})
            self.assertEqual(calls[0], 0, n)

    def test_a_reload_that_makes_a_name_internal_still_refuses_the_submit(self):
        state = {"r": False}
        real_refresh = self.broker._refresh_if
        self.broker._refresh_if = lambda stale, wait=True: (state.update(r=True), real_refresh(stale, wait))[1]
        self.broker._internal_secrets = lambda: ((frozenset({"svc"}), frozenset()) if state["r"]
                                                 else (frozenset(), frozenset()))
        code, r = self.api("POST", "/v1/plans", {"manifest": self.manifest([self.read_rule()]), "source": "t"})
        self.assertEqual((code, r), (400, {"error": "rules[0].secret: unknown credential"}))
        self.assertEqual(self.broker.pending(), [])

    def test_prefix_sharing_name_is_unaffected(self):
        self.manifest([self.rule(secret="ledger")])
        self.approve(self.manifest([self.read_rule(), self.rule()]))
        self.assertEqual(self.refused_events(), [])

    def test_no_standing_or_timed_rule_from_a_request_for_it(self):
        req = types.SimpleNamespace(names=[NAME], mode="http", spec={}, risk={"level": "low"},
                                    client={"id": "c1"})
        ok, why = self.broker.grant_eligibility(req)
        self.assertFalse(ok)
        self.assertIn("internal", why)
        ok, why = self.broker.always_allow_eligibility(req)
        self.assertFalse(ok)
        self.assertIn("internal", why)
        req.names = ["svc"]                                  # an ordinary credential is still eligible
        self.assertTrue(self.broker.grant_eligibility(req)[0])

    def records(self):
        return _fast.read_jsonl(self.audit)


class Sessions(ts.SBase):
    def tweak(self, cfg):
        super().tweak(cfg)
        add_internal(cfg)

    def setUp(self):
        super().setUp()
        mark_internal(self.broker, self.model)
        self.sent0 = len(self.notifier.sent)

    def records(self):
        return _fast.read_jsonl(self.audit)

    def test_open_refused_like_an_unknown_credential(self):
        code, text = self.as_client(ts.KEY, "POST", "/v1/requests", {
            "mode": "session", "names": ["nosuch"], "purpose": ts.PURPOSE, "hosts": [self.hp()],
            "methods": ["GET"], "source": "t"})
        self.assertEqual(code, 400)
        for n in (NAME,):
            r = self.ask(cred=n, expect=400)
            self.assertEqual(r, json.loads(text))
        self.assertEqual(self.broker.pending(), [])
        self.assertEqual(len(self.notifier.sent), self.sent0)
        ev = [r for r in self.records() if r["event"] == "internal_secret_refused"]
        self.assertEqual({(e["reason"], e["mode"]) for e in ev}, {("internal_secret", "session")})
        self.assertIn("internal_secret_refused", audit_api.HIDDEN)

    def test_a_call_naming_it_is_refused_like_an_unknown_session(self):
        sid = self.open()                                    # an ordinary session still opens
        code, r = self.call(sid, "GET", "/x", names=(NAME,))
        self.assertEqual(code, 403)
        code, r = self.call(sid, "GET", "/x")                # the real credential: the session works
        self.assertEqual(code, 200, r)

    def test_a_valid_session_call_naming_it_is_the_ordinary_scope_miss(self):
        sid = self.open()
        a = self.call(sid, "GET", "/x", names=("methcred",))        # a credential outside the session
        b = self.call(sid, "GET", "/x", names=(NAME,))
        self.assertEqual(a, b)
        self.assertEqual(a[0], 403)
        self.assertEqual(self.sess(sid).calls, 0)

    def test_open_refresh_and_scripts_order_match_unknown(self):
        calls = []
        real = self.broker._refresh_if
        self.broker._refresh_if = lambda stale, wait=True: (calls.append(stale), real(stale, wait))[1]
        for n in ("nosuch", NAME):
            calls.clear()
            self.ask(cred=n, expect=400)
            self.assertIn(0, calls, n)
        self.assertEqual(self.ask(cred="nosuch", expect=400, hosts=[]), self.ask(cred=NAME, expect=400, hosts=[]))

    def test_a_reload_that_makes_the_name_internal_still_refuses_the_open(self):
        state = {"r": False}
        real_refresh = self.broker._refresh_if
        self.broker._refresh_if = lambda stale, wait=True: (state.update(r=True), real_refresh(stale, wait))[1]
        self.broker._internal_secrets = lambda: ((frozenset({"unifi"}), frozenset()) if state["r"]
                                                 else (frozenset(), frozenset()))
        r = self.ask(cred="unifi", expect=400)
        self.assertEqual(r, {"error": "unknown secret name"})

    def test_unhealthy_backend_open_text(self):
        self.broker._refresh_if = lambda *a, **k: None
        self.broker._backend_ok = False
        self.assertEqual(self.ask(cred="nosuch", expect=400), self.ask(cred=NAME, expect=400))

    def test_a_session_whose_credential_became_internal_is_refused(self):
        sid = self.open()
        self.sess(sid).cred = NAME
        code, r = self.call(sid, "GET", "/x", names=("unifi",))
        self.assertEqual(code, 403)
        self.assertTrue([e for e in self.records() if e["event"] == "internal_secret_refused"
                         and e["mode"] == "session_call"])


if __name__ == "__main__":
    unittest.main()
