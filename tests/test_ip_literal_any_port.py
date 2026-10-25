"""The ip_literal_any_port migration flag: human-managed catalog entries only."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_destination_guard as tdg  # noqa: E402


class Base(tdg.StrictHarness):
    names = {}

    def route(self):
        return {("10.9.8.7", 8086): self.sport, ("10.9.8.7", 80): self.sport, ("10.9.8.7", 9999): self.sport}

    def tweak(self, cfg):
        cfg["secrets"]["svc"] = {"vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                                 "allowed_hosts": ["10.9.8.7"]}       # a bare IP literal, as in the live catalog

    def drop(self):
        for r in self.broker._by_id.values():
            if r.status == "pending":
                r.status = "expired"


class FlagOff(Base):
    def test_current_behaviour(self):
        self.assertEqual(self.call("http://10.9.8.7:8086/x")[0], 403)
        code, got = self.run_call("http://10.9.8.7/x")
        self.assertEqual((code, got["status"]), (200, "approved"))

    def test_no_warning(self):
        self.assertFalse([e for e in self.events("config_warning") if "ip_literal_any_port" in e["warning"]])


class FlagOn(Base):
    cfg_extra = {"ip_literal_any_port": True}

    def test_a_catalog_entry_matches_any_port_again(self):
        for url in ("http://10.9.8.7:8086/x", "http://10.9.8.7:9999/x", "http://10.9.8.7/x"):
            code, got = self.run_call(url)
            self.assertEqual((code, got["status"]), (200, "approved"), url)
            self.drop()

    def test_startup_warning(self):
        w = [e for e in self.events("config_warning") if "ip_literal_any_port" in e["warning"]]
        self.assertEqual(len(w), 1)
        self.assertIn("migrate", w[0]["warning"].lower())

    def test_loopback_and_own_listener_ports_stay_refused(self):
        raw = json.loads(self.broker.backend._data["Svc"]["broker"])
        raw["allowed_hosts"] = ["10.9.8.7", "127.0.0.1", tdg.OWN]
        self.broker.backend._data["Svc"]["broker"] = json.dumps(raw)
        self.broker.refresh_catalog()
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["allowed_hosts"], ["10.9.8.7"])   # loopback / own dropped
        for port in (self.a.server_address[1], self.c.server_address[1]):
            code, body = self.call(f"http://10.9.8.7:{port}/x")
            if code == 202:
                got = self.approve_and_get(json.loads(body)["id"])
                self.assertEqual(got["error"], "release failed: connection")
            self.drop()
        self.assertEqual(self.connects, [])

    def test_own_ports_config_stays_refused(self):
        self.guard.register_ports(9999)
        code, body = self.call("http://10.9.8.7:9999/x")
        if code == 202:
            self.assertEqual(self.approve_and_get(json.loads(body)["id"])["error"], "release failed: connection")
        self.assertEqual(self.connects, [])

    def test_a_credential_created_through_a_request_still_needs_host_port(self):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["agentcred"], "op": "create", "value": "agent-made-secret-1234",
            "allowed_hosts": ["10.9.8.7"], "var": "AGENTCRED_TOKEN"})
        self.assertEqual(code, 202, body)
        rid = json.loads(body)["id"]
        req = self.broker._by_id[rid]
        if req.status == "pending":
            self.broker.decide_via("dashboard", rid, "approve", "alice")
        req.done.wait(10)
        sc = self.broker.cfg["secrets"]["agentcred"]
        self.assertFalse(sc["_human"])
        self.assertNotIn("10.9.8.7:*", self.broker.allowed_entries("agentcred"))
        h = {"Authorization": "Bearer {{AGENTCRED_TOKEN}}"}
        self.assertEqual(self.call("http://10.9.8.7:8086/x", h, names=("agentcred",))[0], 403)
        self.assertEqual(self.call("http://10.9.8.7:9999/x", h, names=("agentcred",))[0], 403)
        self.drop()
        # with an explicit host:port it works
        sc["allowed_hosts"] = ["10.9.8.7:8086"]
        code, body = self.call("http://10.9.8.7:8086/x", h, names=("agentcred",))
        self.assertEqual(code, 202, body)
        # while the human-managed credential in the same broker keeps its migration behaviour
        self.assertIn("10.9.8.7:*", self.broker.allowed_entries("svc"))


if __name__ == "__main__":
    unittest.main()
