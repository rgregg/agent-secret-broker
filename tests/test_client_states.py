"""A client can be disabled (auto-deny, reversible) as well as revoked (permanent), and the broker remembers which
version of `asb` each client runs (secret_broker/clients.py, clientver.py).

Disabled means: the key still identifies the client, so the door answers, but every endpoint returns one fixed label,
nothing is ever evaluated (no standing approval, rule, plan or session applies), nobody is notified, and an audit
event records it. Everything here is fake data.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_clients as tc  # noqa: E402
from secret_broker import audit_api  # noqa: E402
from secret_broker import clients as clients_mod  # noqa: E402

DISABLED_BODY = {"error": "this client is disabled"}


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def store(path=None, clock=None, legacy="allow"):
    logged = []
    cfg = clients_mod.parse_config({"legacy_client_key": legacy})
    s = clients_mod.ClientStore(path, lambda ev, **kw: logged.append((ev, kw)), cfg, clock=clock or Clock())
    s.logged = logged
    return s


def enrol(s, name="alpha", secret="asbc1_" + "a" * 43):
    h = clients_mod.hash_secret(secret)
    code, out, e = s.submit(name, h, "u@h", "127.0.0.1")
    assert code == 202, (code, out)
    st, _e, rec = s.decide(e["id"], True, name, "alice")
    assert st == "approved", st
    return rec["id"], secret


class StoreStates(unittest.TestCase):
    def test_states_and_record_validation(self):
        self.assertEqual(clients_mod.STATES, ("active", "disabled", "revoked"))
        base = {"id": "c-0a1b2c3d", "name": "alpha", "hash": "0" * 64, "state": "disabled", "created": 1}
        self.assertEqual(clients_mod._record(base)["state"], "disabled")
        with self.assertRaises(ValueError):
            clients_mod._record({**base, "state": "paused"})

    def test_an_old_record_loads_with_defaults(self):
        old = {"id": "c-0a1b2c3d", "name": "alpha", "hash": "0" * 64, "state": "active", "created": 5,
               "last_seen": 9, "requests": 3, "last_source": "127.0.0.1", "approved_by": "alice",
               "claim": "u@h", "enrolled_from": "127.0.0.1", "revoked_at": None, "revoked_by": ""}
        rec = clients_mod._record(old)
        self.assertEqual((rec["client_version"], rec["disabled_at"], rec["disabled_by"]), ("", None, ""))
        self.assertEqual((rec["requests"], rec["state"]), (3, "active"))

    def test_an_old_file_loads_and_an_unknown_state_fails_closed(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "clients.json")
        rec = {"id": "c-0a1b2c3d", "name": "alpha", "hash": "0" * 64, "state": "active", "created": 5,
               "last_seen": None, "requests": 0, "last_source": "", "approved_by": "", "claim": "",
               "enrolled_from": "", "revoked_at": None, "revoked_by": ""}
        with open(p, "w") as f:
            json.dump({"version": 1, "clients": [rec], "legacy": {}}, f)
        s = store(p)
        self.assertFalse(s.broken)
        self.assertEqual([c["name"] for c in s.rows()], ["alpha"])
        with open(p, "w") as f:
            json.dump({"version": 1, "clients": [{**rec, "state": "paused"}], "legacy": {}}, f)
        bad = store(p)
        self.assertTrue(bad.broken)
        self.assertEqual(bad.rows(), [])

    def test_disable_and_enable(self):
        s = store()
        cid, secret = enrol(s)
        self.assertEqual(s.authenticate(secret, "k")[1], "ok")
        self.assertTrue(s.is_active(cid))
        st, rec = s.disable(cid, "alice")
        self.assertEqual((st, rec["state"], rec["disabled_by"]), ("disabled", "disabled", "alice"))
        self.assertEqual(s.authenticate(secret, "k"), (None, "disabled"))
        self.assertFalse(s.is_active(cid))
        self.assertEqual(s.disable(cid, "alice")[0], "already")
        self.assertEqual(s.enable(cid)[0], "enabled")
        self.assertEqual(s.authenticate(secret, "k")[1], "ok")
        self.assertTrue(s.is_active(cid))
        self.assertEqual(s.enable(cid)[0], "not_disabled")
        self.assertEqual(s.disable("c-00000000", "alice")[0], "missing")
        self.assertEqual(s.enable("c-00000000")[0], "missing")

    def test_revoke_wins_over_disabled_and_a_revoked_client_cannot_be_enabled(self):
        s = store()
        cid, secret = enrol(s)
        s.disable(cid, "alice")
        self.assertEqual(s.revoke(cid, "alice")[0], "revoked")
        self.assertEqual(s.authenticate(secret, "k"), (None, "revoked"))
        self.assertEqual(s.enable(cid)[0], "not_disabled")
        self.assertEqual(s.disable(cid, "alice")[0], "revoked")
        self.assertEqual(s.get(cid)["state"], "revoked")

    def test_a_disabled_client_keeps_its_name_and_is_not_offered_for_new_rules(self):
        s = store()
        cid, _ = enrol(s)
        self.assertIn((cid, "alpha"), s.active_choices())
        s.disable(cid, "alice")
        self.assertTrue(s.name_in_use("alpha"))
        self.assertNotIn((cid, "alpha"), s.active_choices())
        self.assertEqual(s.names()[cid], "alpha")
        s.enable(cid)
        self.assertIn((cid, "alpha"), s.active_choices())

    def test_the_state_survives_a_restart(self):
        p = os.path.join(tempfile.mkdtemp(), "clients.json")
        s = store(p)
        cid, secret = enrol(s)
        s.disable(cid, "alice")
        again = store(p)
        self.assertEqual(again.get(cid)["state"], "disabled")
        self.assertEqual(again.authenticate(secret, "k"), (None, "disabled"))
        self.assertEqual(json.load(open(p))["version"], 2)
        again.enable(cid)
        self.assertEqual(store(p).get(cid)["state"], "active")

    def test_a_failed_save_keeps_the_disable_in_effect_and_retries(self):
        p = os.path.join(tempfile.mkdtemp(), "clients.json")
        clock = Clock()
        s = store(p, clock)
        cid, secret = enrol(s)
        real = os.replace

        def boom(src, dst):
            if str(dst).endswith("clients.json"):
                raise OSError("no space")
            return real(src, dst)
        with mock.patch("os.replace", boom):
            self.assertEqual(s.disable(cid, "alice")[0], "memory_only")
            self.assertEqual(s.authenticate(secret, "k"), (None, "disabled"))       # effective now
        self.assertTrue(s.unsaved())
        clock.t += 10
        self.assertTrue(s.flush())
        self.assertEqual(store(p).get(cid)["state"], "disabled")


class StoreVersions(unittest.TestCase):
    def view(self, s, cid):
        return s.view(s.get(cid))

    def test_touch_records_a_valid_version_and_keeps_it_when_none_is_sent(self):
        s = store()
        cid, _ = enrol(s)
        s.touch(self.view(s, cid), "127.0.0.1", "1.0")
        self.assertEqual(s.get(cid)["client_version"], "1.0")
        s.touch(self.view(s, cid), "127.0.0.1", "")
        self.assertEqual(s.get(cid)["client_version"], "1.0")          # another tool's request does not erase it
        s.touch(self.view(s, cid), "127.0.0.1", "1.1")
        self.assertEqual(s.get(cid)["client_version"], "1.1")

    def test_touch_ignores_anything_that_is_not_a_version(self):
        s = store()
        cid, _ = enrol(s)
        for bad in ("<script>", "1.1 x", "9" * 40, None, 5):
            s.touch(self.view(s, cid), "127.0.0.1", bad)
            self.assertEqual(s.get(cid)["client_version"], "", repr(bad))
        self.assertEqual(s.get(cid)["requests"], 5)                      # premise: touch ran each time

    def test_writes_are_throttled_but_memory_is_exact(self):
        p = os.path.join(tempfile.mkdtemp(), "clients.json")
        clock = Clock()
        s = store(p, clock)
        cid, _ = enrol(s)
        saved = []
        real = s._save_locked
        s._save_locked = lambda: (saved.append(clock.t), real())[1]
        for i in range(20):
            clock.t += 10                                                # 200 s in all, under the 300 s window
            s.touch(self.view(s, cid), "127.0.0.1", "1.1")
        self.assertEqual(saved, [])                                      # nothing written
        self.assertEqual(s.get(cid)["requests"], 20)                     # but the count and time are current
        self.assertEqual(s.get(cid)["last_seen"], clock.t)
        self.assertEqual(json.load(open(p))["clients"][0]["requests"], 0)
        s.flush_due()
        self.assertEqual(saved, [])
        clock.t += 200
        s.flush_due()
        self.assertEqual(len(saved), 1)
        self.assertEqual(json.load(open(p))["clients"][0]["client_version"], "1.1")
        s.touch(self.view(s, cid), "127.0.0.1", "1.1")
        s.flush_due()
        self.assertEqual(len(saved), 1)                                  # a fresh window again

    def test_legacy_gets_a_version_too(self):
        s = store()
        s.touch(dict(clients_mod.ClientStore.LEGACY_VIEW), "127.0.0.1", "1.0")
        self.assertEqual(s.legacy_row()["client_version"], "1.0")


class Disabled(tc.CBase):
    """The agent API with a disabled client."""

    def setUp(self):
        super().setUp()
        self.ca = self.new_client("alpha")
        self.cb = self.new_client("bravo")

    def disable(self, c):
        status, _, hdr = self.post("/clients/disable", {"id": c["id"]})
        self.assertEqual(status, 303)
        return hdr["Location"]

    def sent(self):
        self.broker.flush_notifications(5)
        return len(self.notifier.sent)

    def test_every_endpoint_answers_one_fixed_label_and_nobody_is_notified(self):
        self.assertIn("note=disabled", self.disable(self.ca))
        before = self.sent()
        for method, path, body in (("GET", "/v1/status", None), ("GET", "/v1/secrets", None),
                                   ("POST", "/v1/requests", {"mode": "http", "names": ["svc"], "method": "GET",
                                                             "url": "http://127.0.0.1:9/x"}),
                                   ("GET", "/v1/requests/0123456789abcdef?wait=0", None)):
            code, text, _ = self.raw(method, path, body, {"X-Client-Key": self.ca["secret"]})
            self.assertEqual(code, 403, path)
            self.assertEqual(json.loads(text), DISABLED_BODY, path)
        self.assertEqual(self.sent(), before)
        self.assertEqual(self.broker.pending(), [])
        # the other client and the shared key are untouched
        self.assertEqual(self.as_client(self.cb["secret"], "GET", "/v1/status")[0], 200)
        self.assertEqual(self.api("GET", "/v1/status")[0], 200)

    def test_nothing_the_client_could_use_applies_while_it_is_disabled(self):
        self.broker._add_always("svc", "http", "read", "alice", client=self.ca["id"])
        rid = tc.TestAuthHelper.http_as(self, self.ca["secret"])
        self.broker._by_id[rid].done.wait(10)
        self.assertEqual(self.broker._by_id[rid].status, "approved")      # premise: the rule does approve it
        self.disable(self.ca)
        code, text = self.as_client(self.ca["secret"], "POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual((code, json.loads(text)), (403, DISABLED_BODY))
        self.assertEqual(len([r for r in self.records() if r["event"] == "requested"]), 1)   # only the first
        self.post("/clients/enable", {"id": self.ca["id"]})
        rid2 = tc.TestAuthHelper.http_as(self, self.ca["secret"], "/again")
        self.broker._by_id[rid2].done.wait(10)
        self.assertEqual(self.broker._by_id[rid2].status, "approved")     # enabling gives the rule back

    def test_disabling_denies_the_clients_open_requests_without_a_cooldown(self):
        ra = tc.TestAuthHelper.http_as(self, self.ca["secret"])
        rb = tc.TestAuthHelper.http_as(self, self.cb["secret"], "/y")
        self.assertEqual(len(self.broker.pending()), 2)
        self.disable(self.ca)
        self.assertEqual(self.broker._by_id[ra].status, "denied")
        self.assertEqual(self.broker._by_id[ra].error, "this client is disabled")
        self.assertEqual(self.broker._by_id[rb].status, "pending")
        self.assertEqual(self.events("denied")[-1]["via"], "client_disabled")
        self.assertEqual(self.broker._denied_at, {})
        self.assertEqual(self.broker.decide_via("dashboard", ra, "approve", "alice")[0], 410)
        ev = self.events("client_disabled")[0]
        self.assertEqual((ev["client_id"], ev["client_name"], ev["user"], ev["denied_pending"]),
                         (self.ca["id"], "alpha", "alice", 1))

    def test_disabling_ends_open_sessions(self):
        with mock.patch.object(self.broker, "revoke_client_sessions", return_value=2) as ended:
            self.disable(self.ca)
        ended.assert_called_once_with(self.ca["id"], "alice")
        self.assertEqual(self.events("client_disabled")[0]["sessions_ended"], 2)

    def test_denials_are_audited_once_per_window_and_hidden_from_agents(self):
        self.disable(self.ca)
        for _ in range(5):
            self.assertEqual(self.as_client(self.ca["secret"], "GET", "/v1/status")[0], 403)
        evs = self.events("client_disabled_denied")
        self.assertEqual(len(evs), 1)                                    # one per window, not per call
        self.assertEqual((evs[0]["client_id"], evs[0]["client_name"], evs[0]["path"]), (self.ca["id"], "alpha", "/v1/status"))
        for ev in ("client_disabled", "client_enabled", "client_disabled_denied"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertNotIn(ev, audit_api.WHITELIST)
        row = self.broker.clients.get(self.ca["id"])
        self.assertEqual(row["requests"], 0)                             # attempts are not served requests ...
        self.assertIsNotNone(row["last_seen"])                           # ... but the owner can see it still tries

    def test_the_agent_learns_nothing_but_the_fixed_label(self):
        self.disable(self.ca)
        code, text, hdr = self.raw("GET", "/v1/status", headers={"X-Client-Key": self.ca["secret"]})
        self.assertEqual(code, 403)
        self.assertEqual(text.strip(), json.dumps(DISABLED_BODY))
        for hidden in ("alpha", self.ca["id"], "alice", "revoked"):
            self.assertNotIn(hidden, text + str(hdr))
        # a wrong key and a revoked client still read exactly as before
        self.assertEqual(self.as_client("asbc1_nope", "GET", "/v1/status")[0], 401)

    def test_enable_restores_service_and_is_audited(self):
        self.disable(self.ca)
        status, _, hdr = self.post("/clients/enable", {"id": self.ca["id"]})
        self.assertIn("note=enabled", hdr["Location"])
        self.assertEqual(self.as_client(self.ca["secret"], "GET", "/v1/status")[0], 200)
        ev = self.events("client_enabled")[0]
        self.assertEqual((ev["client_id"], ev["user"]), (self.ca["id"], "alice"))
        self.assertIn("note=notdisabled", self.post("/clients/enable", {"id": self.ca["id"]})[2]["Location"])

    def test_revoke_still_works_on_a_disabled_client(self):
        self.disable(self.ca)
        self.assertIn("note=revoked", self.post("/clients/revoke", {"id": self.ca["id"]})[2]["Location"])
        code, text = self.as_client(self.ca["secret"], "GET", "/v1/status")
        self.assertEqual(code, 401)
        self.assertIn("revoked", text)

    def test_the_controls_need_csrf_and_the_human_identity(self):
        for path in ("/clients/disable", "/clients/enable"):
            form = {"id": self.ca["id"]}
            self.assertEqual(self.post(path, form, csrf=False)[0], 403, path)
            self.assertEqual(self.post(path, form, csrf="bad")[0], 403, path)
            self.assertEqual(self.post(path, form, user="mallory")[0], 403, path)
            self.assertEqual(self.post(path, form, headers={"Sec-Fetch-Site": "cross-site"})[0], 403, path)
        self.assertEqual(self.broker.clients.get(self.ca["id"])["state"], "active")
        self.assertEqual(self.events("client_disabled"), [])

    def test_a_pending_enrollment_cannot_take_a_disabled_clients_name(self):
        self.disable(self.ca)
        code, body, _s, _h = self.enr("alpha", claim="x@y")
        self.assertEqual(code, 202)                                       # the request is accepted ...
        status, _e = self.broker.decide_enrollment(body["id"], "approve", "alpha", "alice")
        self.assertEqual(status, "name_taken")                            # ... but the name stays reserved

    def test_the_legacy_shared_key_has_no_row_state(self):
        status, _, hdr = self.post("/clients/disable", {"id": "legacy"})
        self.assertIn("note=missing", hdr["Location"])
        self.assertEqual(self.api("GET", "/v1/status")[0], 200)


class VersionsOverHttp(tc.CBase):
    def call(self, secret, ua):
        h = {"X-Client-Key": secret}
        if ua is not None:
            h["User-Agent"] = ua
        return self.raw("GET", "/v1/status", headers=h)[0]

    def test_the_version_comes_from_the_user_agent_of_authenticated_requests(self):
        a = self.new_client("alpha")
        self.assertEqual(self.call(a["secret"], "asb/1.1 (+https://github.com/rgregg/agent-secret-broker)"), 200)
        self.assertEqual(self.broker.clients.get(a["id"])["client_version"], "1.1")
        self.assertEqual(self.call(a["secret"], "curl/8.0"), 200)
        self.assertEqual(self.broker.clients.get(a["id"])["client_version"], "1.1")
        self.assertEqual(self.call(a["secret"], "asb/1.0"), 200)
        self.assertEqual(self.broker.clients.get(a["id"])["client_version"], "1.0")

    def test_a_failed_authentication_records_nothing(self):
        a = self.new_client("alpha")
        self.assertEqual(self.call("asbc1_wrong", "asb/9.9"), 401)
        self.assertEqual(self.broker.clients.get(a["id"])["client_version"], "")
        self.assertEqual(self.broker.clients.legacy_row()["client_version"], "")

    def test_the_shared_key_is_tracked_too(self):
        self.assertEqual(self.call(tc.KEY, "asb/1"), 200)
        self.assertEqual(self.broker.clients.legacy_row()["client_version"], "1")

    def test_a_disabled_client_is_still_seen_and_its_version_kept(self):
        a = self.new_client("alpha")
        self.post("/clients/disable", {"id": a["id"]})
        self.assertEqual(self.call(a["secret"], "asb/1.1 x"), 403)
        self.assertEqual(self.broker.clients.get(a["id"])["client_version"], "1.1")


if __name__ == "__main__":
    unittest.main()
