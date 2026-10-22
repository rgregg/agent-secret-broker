"""Security-review regressions for per-client credentials: audit scoping, the revoke race and
durable (or fail-closed) revocation."""
import builtins
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
from test_client_rules import ClientMixin, Legacy  # noqa: E402
from secret_broker import clients as clients_mod  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

KEY = t.KEY


class AuditScope(ClientMixin, tg.Base):
    def audit_as(self, c, query="", limit=500):
        code, text = self.api("GET", f"/v1/audit?limit={limit}" + query, key=c.secret)
        self.assertEqual(code, 200, text)
        return json.loads(text), text

    def setUp(self):
        super().setUp()
        self.ca, self.cb = self.mk("alpha"), self.mk("bravo")
        self.ra = self.http_as(self.ca, path="/a1")
        self.rb = self.http_as(self.cb, path="/b1")
        self.rl = self.http_as(Legacy, path="/l1")
        for rid in (self.ra, self.rb, self.rl):
            self.broker.decide_via("dashboard", rid, "deny", "alice")
            self.broker._denied_at.clear()
        self.api("GET", "/v1/secrets?host=127.0.0.1", key=self.cb.secret)      # a discovery event of B

    def test_a_client_sees_only_its_own_events_and_never_other_clients_names(self):
        out, text = self.audit_as(self.ca)
        self.assertTrue(out["events"])
        self.assertEqual({e["request"] for e in out["events"] if e["request"]}, {self.ra})
        for needle in ("bravo", self.cb.id, self.rb, self.rl, "shared key", "legacy", self.cb.secret):
            self.assertNotIn(needle, text)
        reqs = [e for e in out["events"] if e["event"] == "requested"]
        self.assertEqual([e["client"] for e in reqs], ["alpha"])
        self.assertNotIn("catalog_loaded", {e["event"] for e in out["events"]})     # system events are not its own

    def test_filters_request_id_and_paging_cannot_reach_another_clients_events(self):
        for q in (f"&request={self.rb}", f"&request={self.rl}", "&event=requested", "&secret=svc",
                  "&source=" + "x", "&order=asc", "&since=1h", f"&after=0", f"&before=99999"):
            out, text = self.audit_as(self.ca, q)
            for e in out["events"]:
                self.assertIn(e["request"], (self.ra, None), q)
            for needle in ("bravo", self.cb.id, self.rb, self.rl):
                self.assertNotIn(needle, text, q)
        out, _ = self.audit_as(self.ca, f"&request={self.rb}")
        self.assertEqual(out["events"], [])
        # tail-style polling: walking forward with `after` never surfaces B's events either
        seen, after = [], 0
        for _ in range(30):
            out, text = self.audit_as(self.ca, f"&after={after}", limit=3)
            seen += out["events"]
            if not out["events"] and out["next"] is None:
                break
            after = out["next"] or out["events"][-1]["seq"]
        self.assertTrue(all(e["request"] in (self.ra, None) for e in seen))

    def test_asb_audit_cli_is_scoped_too(self):
        env = {"PATH": os.environ["PATH"], "HOME": self.dir if hasattr(self, "dir") else "/tmp",
               "SECRET_BROKER_URL": self.base, "SECRET_BROKER_KEY": self.ca.secret}
        for args in (["audit", "--json"], ["audit", "--request", self.rb, "--json"],
                     ["audit", "--event", "requested"], ["audit", "--tail", "--json"]):
            p = subprocess.Popen([t.CLI, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                out, err = p.communicate(timeout=4)
            except subprocess.TimeoutExpired:
                p.kill()
                out, err = p.communicate()
            for needle in ("bravo", self.cb.id, self.rb, "shared key"):
                self.assertNotIn(needle, out + err, args)

    def test_the_legacy_key_keeps_its_view_but_is_told_no_client_names(self):
        out, text = self.audit_as(Legacy)
        self.assertEqual({e["request"] for e in out["events"] if e["request"]}, {self.ra, self.rb, self.rl})
        for needle in ("alpha", "bravo", self.ca.id, self.cb.id, '"client"'):
            self.assertNotIn(needle, text)


class RevokeRace(ClientMixin, tg.Base):
    def test_create_is_refused_once_the_client_is_revoked_and_nothing_is_left_pending(self):
        for round_ in range(4):
            c = self.mk(f"racer{round_}")
            stop, rids, errs = threading.Event(), [], []

            def hammer():
                while not stop.is_set():
                    try:
                        rids.append(self.broker.create("http", ["svc"], {
                            "method": "GET", "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
                            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}, "body": None, "body_b64": None},
                            "src", "127.0.0.1", {"id": c.id, "name": c.name, "legacy": False}).id)
                    except PermissionError:
                        errs.append(1)
                    except Exception:  # noqa: BLE001
                        pass
                    self.broker._denied_at.clear()
                    for r in list(self.broker._by_id.values()):
                        pass
            ths = [threading.Thread(target=hammer) for _ in range(4)]
            for th in ths:
                th.start()
            time.sleep(0.15)
            self.broker.revoke_client(c.id, "alice")
            time.sleep(0.15)
            stop.set()
            for th in ths:
                th.join()
            mine = [r for r in self.broker._by_id.values() if r.client["id"] == c.id]
            self.assertTrue(mine)
            self.assertEqual([r.id for r in mine if r.status in ("pending", "deciding")], [])
            self.assertTrue(errs, "creates after the revoke must be refused")
            for r in mine:
                self.assertEqual(self.broker.decide_via("dashboard", r.id, "approve", "alice")[0] in (404, 410), True)
                self.assertNotEqual(r.status, "approved")

    def test_a_pending_request_of_a_revoked_client_cannot_be_approved(self):
        a = self.mk("alpha")
        rid = self.http_as(a)
        # revoke the store entry only, as if the sweep had not run yet
        self.broker.clients.revoke(a.id, "alice")
        code, req = self.broker.decide_via("dashboard", rid, "approve", "alice")
        self.assertEqual((code, req), (410, None))
        r = self.broker._by_id[rid]
        self.assertEqual(r.status, "denied")
        self.assertEqual(self.broker.take_result(r)["status"], "denied")
        self.assertEqual(self.events("denied")[-1]["via"], "client_revoked")

    def test_dashboard_approve_and_auto_release_are_refused_after_revoke(self):
        a = self.mk("alpha")
        rid = self.http_as(a)
        self.broker.clients.revoke(a.id, "alice")
        self.assertEqual(self.card(rid, "approve"), 303)
        self.assertEqual(self.broker._by_id[rid].status, "denied")
        # an auto path that races the revoke: _release itself refuses
        rid2 = self.http_as(Legacy)
        req = self.broker._by_id[rid2]
        req.client = {"id": a.id, "name": "alpha", "legacy": False}
        from secret_broker.backends import BackendError
        with self.assertRaises(BackendError):
            self.broker._release(req)

    def test_the_legacy_setting_is_checked_at_create_too(self):
        self.broker.clients.cfg["legacy"] = "deny"
        with self.assertRaises(PermissionError):
            self.http_as(Legacy) if False else self.broker.create("env", ["svc"], {"argv": ["x"]}, "s", "127.0.0.1")


class DurableRevoke(ClientMixin, tg.Base):
    def failing_replace(self):
        real = os.replace

        def boom(src, dst):
            if str(dst).endswith("clients.json"):
                raise OSError("LEAKY-DISK-TEXT")
            return real(src, dst)
        return mock.patch("os.replace", boom)

    def restart(self):
        return Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)

    def test_failed_write_is_surfaced_retried_and_then_durable(self):
        a = self.mk("alpha")
        with self.failing_replace():
            self.assertEqual(self.broker.revoke_client(a.id, "alice"), "memory_only")
            self.assertEqual(self.api("GET", "/v1/status", key=a.secret)[0], 401)       # effective now
            self.assertTrue(self.broker.clients.unsaved())
            page = t.req(self.abase + "/clients", headers={"X-authentik-username": "alice"})[1]
            self.assertIn("could not be saved", page)
            self.assertEqual(json.loads(self.api("GET", "/v1/status")[1])["features"]["client_list"], "unsaved")
            # retries while the disk is still bad stay failed and do not spam the audit log
            for _ in range(3):
                self.broker.clients.flush()
            fails = self.events("clients_file_write_failed")
            self.assertEqual(len(fails), 1)
            self.assertEqual(fails[0]["error_class"], "OSError")
            self.assertNotIn("LEAKY", open(self.audit).read())
            self.assertNotIn("LEAKY", page)
        # the disk is back: the timer/next operation persists it
        self.broker.clients._retry_at = 0
        self.assertTrue(self.broker.clients.flush())
        self.assertFalse(self.broker.clients.unsaved())
        self.assertEqual(len(self.events("clients_file_recovered")), 1)
        b2 = self.restart()
        self.assertEqual(b2.clients.get(a.id)["state"], "revoked")
        self.assertEqual(b2.clients.authenticate(a.secret, KEY)[1], "revoked")
        self.assertNotIn("could not be saved", t.req(self.abase + "/clients", headers={"X-authentik-username": "alice"})[1])

    def test_the_next_operation_retries_the_save(self):
        a, b = self.mk("alpha"), self.mk("bravo")
        with self.failing_replace():
            self.broker.revoke_client(a.id, "alice")
        self.broker.clients._retry_at = 0
        self.api("GET", "/v1/status", key=b.secret)              # an ordinary request triggers the retry
        self.assertFalse(self.broker.clients.unsaved())
        self.assertEqual(self.restart().clients.get(a.id)["state"], "revoked")

    def test_an_in_memory_revocation_wins_over_loaded_state(self):
        a = self.mk("alpha")
        with self.failing_replace():
            self.broker.revoke_client(a.id, "alice")
        st = self.broker.clients
        st._clients[a.id]["state"] = "active"                    # e.g. a stale reload
        self.assertEqual(st.authenticate(a.secret, KEY)[1], "revoked")
        self.assertFalse(st.is_active(a.id))
        st.flush()
        self.assertEqual(json.load(open(st._path))["clients"][0]["state"], "revoked")

    def test_the_save_fsyncs_the_file_and_the_directory(self):
        calls = []
        real = os.fsync
        with mock.patch("os.fsync", lambda fd: (calls.append(fd), real(fd))[1]):
            self.mk("alpha")
        self.assertGreaterEqual(len(calls), 2)

    def test_unreadable_state_fails_closed_for_per_client_credentials(self):
        a = self.mk("alpha")
        path = self.broker.clients._path
        real_open = builtins.open

        def deny(file, *args, **kw):
            if str(file) == path:
                raise PermissionError("LEAKY-PERM-TEXT")
            return real_open(file, *args, **kw)
        with mock.patch("builtins.open", deny):
            b2 = self.restart()
        self.assertTrue(b2.clients.unreadable and b2.clients.broken)
        view, why = b2.clients.authenticate(a.secret, KEY)
        self.assertEqual((view, why), (None, "clients_unavailable"))
        self.assertEqual(b2.clients.authenticate(KEY, KEY)[1], "ok")            # legacy follows its setting
        self.assertEqual(b2.clients.submit("x", "0" * 64, "a@b", "1.1.1.1")[0], 503)
        self.assertEqual(b2.status()["features"]["client_list"], "unreadable")
        self.assertNotIn("LEAKY", open(self.audit).read())
        self.assertTrue(os.path.exists(path))                                    # never overwritten

    def test_garbage_state_also_fails_closed(self):
        a = self.mk("alpha")
        with open(self.broker.clients._path, "w") as f:
            f.write("{not json")
        b2 = self.restart()
        self.assertEqual(b2.clients.authenticate(a.secret, KEY)[1], "clients_unavailable")

    def test_http_message_when_the_list_is_unavailable(self):
        self.broker.clients.unreadable = True
        code, text = self.api("GET", "/v1/status", key="asbc1_whatever")
        self.assertEqual(code, 401)
        self.assertIn("unavailable", text)


if __name__ == "__main__":
    unittest.main()
