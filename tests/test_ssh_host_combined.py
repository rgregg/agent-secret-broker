"""SSH host identity composed with grants, guidance, the audit API, env scripts and the card."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import riskmodel  # noqa: E402
from test_grants import Base  # noqa: E402
from test_ssh_host import SID_A, Host, login  # noqa: E402

HOST = Host()
OTHER = Host()


class Recorder:
    """A model stand-in that remembers every call."""
    def __init__(self):
        self.calls = []

    def analyze(self, mode, names, spec, guidance=None):
        self.calls.append((mode, guidance))
        return {"summary": "model summary", "risk": "low", "summary_model": "m"}


class Combined(Base):
    decision = None
    risk = "low"
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com")], "allowed_hosts": ["web.example.com"]}

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["deploy"]["ssh_hosts"] = self.ssh_hosts
        cfg["secrets"]["deploy"]["guidance"] = "OWNER-NOTE-XYZ: signing is fine"

    def sign_to(self, host, claimed="deploy@web.example.com:22"):
        _, body = self.api("POST", "/v1/requests", {
            "mode": "ssh_sign", "names": ["deploy"], "flags": 0,
            "data_b64": base64.b64encode(login(SID_A)).decode(),
            "binds": [host.bind(SID_A)], "claimed_dest": claimed})
        return body

    def test_ssh_with_host_is_high_without_model_or_guidance_and_card_shows_host(self):
        rec = Recorder()
        self.broker.summarizer = riskmodel.FloorAnalyzer(rec)
        body = self.sign_to(HOST)
        r = self.broker._by_id[json.loads(body)["id"]]
        self.assertEqual(r.risk["level"], "high")
        self.assertEqual(rec.calls, [])                       # no model call, so no guidance either
        self.assertIn("server web.example.com", r.summary)
        self.assertIn("destination (claimed) deploy@web.example.com:22", r.summary)
        _, page = self.get("/")
        self.assertIn(HOST.fp, page)
        self.assertIn("Destination (claimed by the client): deploy@web.example.com:22", page)
        self.assertNotIn("OWNER-NOTE-XYZ", page)
        self.assertNotIn("OWNER-NOTE-XYZ", self.notifier.sent[0]["message"])
        _, lp = self.get(f"/a/{r.nonce}")
        self.assertIn(HOST.fp, lp)
        # the guidance hook is never offered to the analyzer for ssh_sign
        self.assertTrue(r.summary_source == "deterministic")

    def test_audit_api_shows_only_the_whitelisted_host_fields(self):
        body = self.sign_to(HOST)
        self.assertEqual(self.approve(json.loads(body)["id"], "approve"), 303)
        self.sign_to(OTHER)                                   # refused by allowed_hosts
        _, out = self.api("GET", "/v1/audit?limit=200")
        evs = json.loads(out)["events"]
        self.assertNotIn("ssh_sign_refused", {e["event"] for e in evs})
        self.assertNotIn("host_not_allowed", out)
        self.assertNotIn(OTHER.fp, out)
        for e in (next(e for e in evs if e["event"] == "requested"),
                  next(e for e in evs if e["event"] == "ssh_signed")):
            self.assertEqual((e["host_fp"], e["host_name"], e["claimed_dest"]),
                             (HOST.fp, "web.example.com", "deploy@web.example.com:22"))
            for hidden in ("host_bound", "host_type", "forwarding", "host_lines"):
                self.assertNotIn(hidden, e)

    def test_env_script_request_and_ssh_request_coexist(self):
        _, b1 = self.api("POST", "/v1/requests", {
            "mode": "env", "names": ["svc"], "argv": ["sh", "run.sh"],
            "scripts": [{"path": "run.sh", "size": 12, "sha256": "a" * 64,
                         "text": "echo hello\n", "truncated": False}]})
        self.assertIn("id", json.loads(b1))
        b2 = self.sign_to(HOST)
        self.assertIn("id", json.loads(b2))
        _, page = self.get("/")
        self.assertIn("run.sh", page)
        self.assertIn(HOST.fp, page)
        req = self.broker._by_id[json.loads(b1)["id"]]
        self.assertEqual(req.spec["scripts"][0]["path"], "run.sh")
        self.assertEqual(self.broker._by_id[json.loads(b2)["id"]].mode, "ssh_sign")

    def test_ssh_card_has_grant_chips_and_a_grant_is_used_for_an_allowed_host(self):
        rid = json.loads(self.sign_to(HOST))["id"]
        _, page = self.get("/")
        self.assertIn("Automatically approve...", page)
        self.assertIn("name=decision value='approve_grant_15'", page)
        self.assertEqual(self.approve(rid, "approve_grant_15"), 303)
        self.broker._by_id[rid].done.wait(10)
        g = self.broker.active_grants()
        self.assertEqual(g[0]["scope"], "any")
        rid2 = json.loads(self.sign_to(HOST))["id"]
        self.assertEqual(self.broker._by_id[rid2].status, "approved")
        self.assertEqual(len(self.events("grant_used")), 1)

    def test_a_grant_never_overrides_the_allowed_hosts_refusals(self):
        rid = json.loads(self.sign_to(HOST))["id"]
        self.assertEqual(self.approve(rid, "approve_grant_15"), 303)
        self.broker._by_id[rid].done.wait(10)
        self.assertTrue(self.broker.active_grants())
        # wrong server, no bind at all, and forwarded use: each is refused despite the active grant
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "ssh_sign", "names": ["deploy"], "flags": 0,
            "data_b64": base64.b64encode(login(SID_A)).decode(), "binds": [OTHER.bind(SID_A)]})
        self.assertEqual(code, 403)
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "ssh_sign", "names": ["deploy"], "flags": 0,
            "data_b64": base64.b64encode(login(SID_A)).decode()})
        self.assertEqual(code, 403)
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "ssh_sign", "names": ["deploy"], "flags": 0,
            "data_b64": base64.b64encode(login(SID_A)).decode(),
            "binds": [HOST.bind(SID_A, forwarding=True)]})
        self.assertEqual(code, 403)
        self.assertEqual([e["reason"] for e in self.events("ssh_sign_refused")],
                         ["host_not_allowed", "host_unverified", "host_forwarded"])
        self.assertEqual(len(self.events("grant_used")), 0)


if __name__ == "__main__":
    unittest.main()
