"""env-mode (run-with-secret) requests are auto-approved under the same rules as web
requests: approval allow + model risk <= risk.auto_approve_max; script text that is
not visible always prompts."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_e2e import SECRET, Harness, _Stub, req  # noqa: E402
from secret_broker import risk as risk_mod  # noqa: E402
from secret_broker.backends import FileBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

VISIBLE = {"path": "run.sh", "size": 12, "sha256": "a" * 64, "text": "echo hello\n", "truncated": False}


class EnvAutoBase(Harness):
    decision = None
    risk_level = "low"
    approval = "allow"
    risk_cfg = {"auto_approve_max": "low"}

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["approval"] = self.approval
        cfg["risk"] = dict(self.risk_cfg)

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Runs a script", self.risk_level)

    def env(self, scripts=None):
        body = {"mode": "env", "names": ["svc"], "argv": ["bash", "run.sh"] if scripts else ["echo", "hi"]}
        if scripts is not None:
            body["scripts"] = scripts
        code, b = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def result(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
        return json.loads(b)

    def assertAuto(self, rid):
        self.assertEqual(self.notifier.sent, [])
        self.assertEqual(self.result(rid)["env"], {"SVC_TOKEN": SECRET})
        ap = self.events("approved")[-1]
        self.assertEqual(ap["via"], "policy")
        self.assertIsNone(ap.get("approver"))

    def assertPrompts(self, n=1):
        self.assertEqual(len(self.notifier.sent), n)
        self.assertEqual(self.events("approved"), [])


class AutoUnderCeiling(EnvAutoBase):
    def test_low_env_auto_approves_and_releases(self):
        self.assertAuto(self.env())

    def test_visible_script_auto_approves(self):
        self.assertAuto(self.env([VISIBLE]))

    def test_delivered_event_is_env(self):
        self.result(self.env())
        self.assertEqual(self.events("delivered")[-1].get("kind"), "env")

    def test_agent_surfaces_do_not_reveal_policy(self):
        rid = self.env()
        for path in ("/v1/secrets", "/v1/status", f"/v1/requests/{rid}?wait=2"):
            _, body = self.api("GET", path)
            self.assertNotIn("auto_modes", body, path)
            self.assertNotIn('"approval"', body, path)
            self.assertNotIn("run-with-secret", body, path)


class AboveCeiling(EnvAutoBase):
    risk_level = "medium"

    def test_prompts_and_audits_escalated(self):
        self.env()
        self.assertPrompts()
        self.assertIn("above auto_approve_max", self.events("escalated")[-1]["reason"])

    def test_medium_ceiling_auto_approves_medium(self):
        self.broker._auto_max = "medium"
        self.assertAuto(self.env())


class MissingVerdict(EnvAutoBase):
    def setUp(self):
        super().setUp()
        self.broker.summarizer = None

    def test_missing_verdict_is_high_and_prompts(self):
        self.env()
        self.assertPrompts()

    def test_missing_verdict_auto_at_high(self):
        self.broker._auto_max = "high"
        self.assertAuto(self.env())


class PromptCredential(EnvAutoBase):
    approval = "prompt"

    def test_still_prompts(self):
        self.env()
        self.assertPrompts()
        self.assertEqual(self.events("escalated"), [])


class CredentialOptOut(EnvAutoBase):
    def test_auto_modes_http_opts_out(self):
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http"]
        self.env()
        self.assertPrompts()


class GlobalModes(EnvAutoBase):
    risk_cfg = {"auto_approve_max": "low", "auto_modes": ["http"]}

    def test_global_http_only_restores_old_behavior(self):
        self.env()
        self.assertPrompts()

    def test_credential_auto_modes_overrides_the_global_list(self):
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http", "env"]
        self.assertAuto(self.env())


class ModeConfig(unittest.TestCase):
    def test_default_and_valid(self):
        self.assertEqual(risk_mod.parse_auto_modes(None), ["http", "env"])
        self.assertEqual(risk_mod.parse_auto_modes({}), ["http", "env"])
        self.assertEqual(risk_mod.parse_auto_modes({"auto_modes": ["http"]}), ["http"])
        self.assertEqual(risk_mod.parse_auto_modes({"auto_modes": []}), [])

    def test_invalid_names_the_field(self):
        for bad in ("http", ["ssh_sign"], ["http", "http"], [1], {"a": 1}, "env"):
            with self.assertRaises(ValueError) as c:
                risk_mod.parse_auto_modes({"auto_modes": bad})
            self.assertIn("risk.auto_modes", str(c.exception))

    def test_broker_rejects_invalid_at_construction(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "v.json")
        with open(path, "w") as f:
            json.dump({}, f)
        cfg = {"approve_base_url": "https://x.example", "allowed_user": "a", "secrets": {},
               "risk": {"auto_modes": ["bogus"]}}
        with self.assertRaises(ValueError) as c:
            Broker(cfg, FileBackend(path), FakeNotifier(), os.path.join(d, "a.jsonl"))
        self.assertIn("risk.auto_modes", str(c.exception))

    def test_empty_list_makes_nothing_default_eligible(self):
        b = object.__new__(Broker)
        b._default_auto_modes = risk_mod.parse_auto_modes({"auto_modes": []})
        self.assertEqual(b._auto_modes({"approval": "allow"}), [])
        self.assertEqual(b._auto_modes({"approval": "allow", "auto_modes": ["env"]}), ["env"])

    def test_ssh_default_unchanged(self):
        b = object.__new__(Broker)
        b._default_auto_modes = ["http", "env"]
        self.assertEqual(b._auto_modes({"approval": "allow", "ssh": True}), ["ssh_sign"])
        self.assertEqual(b._auto_modes({"approval": "prompt"}), [])


class ScriptNotVisible(EnvAutoBase):
    risk_cfg = {"auto_approve_max": "high"}

    def check(self, scripts):
        self.env(scripts)
        self.assertPrompts()
        e = self.events("escalated")[-1]
        self.assertEqual(e["reason"], "script_not_visible")

    def test_unreadable_always_prompts(self):
        self.check([{"path": "gone.sh", "unreadable": "permission"}])

    def test_stdin_always_prompts(self):
        self.check([{"stdin": True}])

    def test_visible_plus_unreadable_prompts(self):
        self.check([VISIBLE, {"path": "b.sh", "unreadable": "binary"}])

    def test_truncated_prompts(self):
        self.check([{**VISIBLE, "truncated": True}])

    def test_the_card_does_not_offer_always(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.env([{"stdin": True}])
        r = list(self.broker._by_id.values())[-1]
        ok, why = self.broker.always_allow_eligibility(r)
        self.assertFalse(ok)
        self.assertIn("not visible", why)

    def test_http_requests_unaffected(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url,
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202)
        self.assertEqual(self.notifier.sent, [])


class AlwaysChip(EnvAutoBase):
    approval = "prompt"
    risk_cfg = {"auto_approve_max": "medium"}

    def page(self):
        r = list(self.broker._by_id.values())[-1]
        return req(self.abase + f"/a/{r.nonce}", headers={"X-authentik-username": "alice"})[1], r

    def post_decision(self, r, decision):
        import urllib.parse
        import urllib.request
        data = urllib.parse.urlencode({"decision": decision}).encode()
        return urllib.request.urlopen(urllib.request.Request(
            self.abase + f"/a/{r.nonce}", data=data, headers={"X-authentik-username": "alice"},
            method="POST"), timeout=10).read().decode()

    def test_chip_text_and_apply(self):
        self.env()
        page, r = self.page()
        self.assertIn("value=approve_always", page)
        self.assertIn("web and run-with-secret requests", page)
        self.assertIn("The secret value will be released to the requesting machine without asking "
                      "again when the request is rated medium or lower.", page)
        body = self.post_decision(r, "approve_always")
        self.assertIn("Always allow saved", body)
        r.done.wait(10)
        sc = self.broker.cfg["secrets"]["svc"]
        self.assertEqual(sc["approval"], "allow")
        self.assertNotIn("auto_modes", sc)
        self.assertEqual(self.events("approved")[0]["via"], "user")
        n = len(self.notifier.sent)
        self.assertEqual(self.result(self.env())["env"], {"SVC_TOKEN": SECRET})
        self.assertEqual(len(self.notifier.sent), n)
        self.assertEqual(self.events("approved")[-1]["via"], "policy")

    def test_http_confirm_text_has_no_release_warning(self):
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x"
        self.api("POST", "/v1/requests", {"mode": "http", "names": ["svc"], "method": "GET", "url": url,
                                          "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        page, _ = self.page()
        self.assertIn("value=approve_always", page)
        self.assertNotIn("released to the requesting machine", page)

    def test_refusal_reasons(self):
        self.env()
        _, r = self.page()
        self.assertEqual(self.broker.always_allow_eligibility(r), (True, ""))
        r.risk = {"level": "high", "model": "high", "reasons": []}
        ok, why = self.broker.always_allow_eligibility(r)
        self.assertFalse(ok)
        self.assertIn("rated high", why)
        self.assertNotIn("requesting host", why)
        r.risk = {"level": "low", "model": "low", "reasons": []}
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        self.assertEqual(self.broker.always_allow_eligibility(r), (False, "already always-allowed"))
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        r2 = type("R", (), {"mode": "store", "names": ["svc"], "spec": {}, "risk": None})()
        self.assertFalse(self.broker.always_allow_eligibility(r2)[0])

    def test_above_ceiling_not_offered(self):
        self.broker.summarizer = _Stub("x", "medium")
        self.broker._auto_max = "low"
        self.env()
        page, r = self.page()
        self.assertNotIn("value=approve_always", page)
        self.assertFalse(self.broker.always_allow_eligibility(r)[0])


class PoliciesList(EnvAutoBase):
    def policies(self):
        return req(self.abase + "/policies", headers={"X-authentik-username": "alice"})[1]

    def test_shows_eligible_modes(self):
        self.assertIn("web, run-with-secret", self.policies())
        self.broker.cfg["secrets"]["svc"]["auto_modes"] = ["http"]
        page = self.policies()
        self.assertNotIn("run-with-secret</td>", page)
        self.assertIn("Auto-approved for", page)


# -- time-boxed grants for env requests ---------------------------------------
import test_grants as tg  # noqa: E402  (Base only; its tests are not re-collected here)


class EnvGrants(tg.Base):
    def env(self, names=("svc",), scripts=None):
        body = {"mode": "env", "names": list(names), "argv": ["bash", "run.sh"] if scripts else ["echo", "hi"]}
        if scripts is not None:
            body["scripts"] = scripts
        code, b = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def grant_env(self, names=("svc",), minutes=15):
        rid = self.env(names)
        self.assertEqual(self.approve(rid, f"approve_grant_{minutes}"), 303)
        self.broker._by_id[rid].done.wait(10)
        return rid

    def test_creation_from_env_request(self):
        self.grant_env()
        g = self.broker.active_grants()[0]
        self.assertEqual((g["secrets"], g["scope"], g["mode"]), (["svc"], "any", "env"))
        ev = self.events("grant_created")[0]
        self.assertEqual((ev["mode"], ev["scope"]), ("env", "any"))
        self.assertEqual(self.events("approved")[0]["via"], "user")

    def test_used_for_the_same_set_and_releases_value(self):
        self.grant_env()
        n = len(self.notifier.sent)
        rid = self.env()
        got = self.result(rid)
        self.assertEqual(got["env"], {"SVC_TOKEN": SECRET})
        self.assertEqual(len(self.notifier.sent), n)
        used = [e for e in self.events("grant_used") if e["id"] == rid][0]
        self.assertEqual(used["mode"], "env")
        self.assertEqual(self.events("approved")[-1]["via"], "policy")

    def test_visible_script_is_covered(self):
        self.grant_env()
        n = len(self.notifier.sent)
        self.assertEqual(self.result(self.env(scripts=[VISIBLE]))["status"], "approved")
        self.assertEqual(len(self.notifier.sent), n)

    def test_not_for_a_different_or_larger_set(self):
        self.grant_env()
        n = len(self.notifier.sent)
        self.env(("other",))
        self.env(("svc", "other"))
        self.assertEqual(len(self.notifier.sent), n + 2)

    def test_modes_do_not_cross(self):
        self.grant_env()
        n = len(self.notifier.sent)
        self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)       # env grant does not cover web
        self.grant_it(("other",), method="POST")              # a web grant (scope any) ...
        n = len(self.notifier.sent)
        self.env(("other",))
        self.assertEqual(len(self.notifier.sent), n + 1)       # ... never covers env
        self.assertEqual(len(self.broker.active_grants()), 2)

    def test_same_set_env_and_web_grants_coexist(self):
        self.grant_env()
        self.grant_it()
        self.assertEqual(sorted(g["mode"] for g in self.broker.active_grants()), ["env", "http"])

    def test_unreadable_and_stdin_scripts_are_never_covered(self):
        self.grant_env()
        for scripts in ([{"path": "x.sh", "unreadable": "permission"}], [{"stdin": True}]):
            n = len(self.notifier.sent)
            self.env(scripts=scripts)
            self.assertEqual(len(self.notifier.sent), n + 1)
            sk = self.events("grant_skipped")[-1]
            self.assertEqual(sk["reason"], "script_not_visible")
            self.assertEqual(sk["mode"], "env")
        self.assertEqual(self.events("grant_used"), [])

    def test_grant_cannot_be_created_from_an_invisible_script(self):
        rid = self.env(scripts=[{"stdin": True}])
        self.assertNotIn("approve_grant_", self.get("/")[1])
        self.assertEqual(self.approve(rid, "approve_grant_15"), 303)
        self.assertEqual(self.broker.active_grants(), [])
        self.assertIn("not visible", self.events("grant_refused")[0]["reason"])

    def test_expiry(self):
        self.grant_env(minutes=5)
        self.offset += 400
        n = len(self.notifier.sent)
        self.env()
        self.assertEqual(len(self.notifier.sent), n + 1)
        self.assertEqual(self.events("grant_expired")[0]["mode"], "env")

    def test_revoke(self):
        self.grant_env()
        gid = self.broker.active_grants()[0]["id"]
        self.assertTrue(self.broker.revoke_grant(gid, "alice"))
        self.assertEqual(self.events("grant_revoked")[0]["mode"], "env")
        n = len(self.notifier.sent)
        self.env()
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_persistence_keeps_the_mode(self):
        from secret_broker import grants as grants_mod
        self.grant_env()
        path = os.path.join(os.path.dirname(self.audit), "grants.json")
        with open(path) as f:
            raw = f.read()
        self.assertIn('"mode": "env"', raw)
        self.assertNotIn(SECRET, raw)
        store = grants_mod.GrantStore(path, lambda *a, **k: None)
        store.load()
        self.assertIsNotNone(store.find(["svc"], "env"))
        self.assertIsNone(store.find(["svc"], "http"))

    def test_legacy_grant_without_mode_never_covers_env(self):
        self.broker.grants.add(["svc"], 5, "any", "alice", "dashboard", "r")     # no mode recorded
        n = len(self.notifier.sent)
        self.env()
        self.assertEqual(len(self.notifier.sent), n + 1)
        self.result(self.http())                               # but it still covers web
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_no_leak_to_the_agent(self):
        self.grant_env()
        rid = self.env()
        for path in ("/v1/secrets", "/v1/status", f"/v1/requests/{rid}?wait=2"):
            _, body = self.api("GET", path)
            self.assertNotIn("grant", body.replace("timed_grants", ""), path)
            self.assertNotIn("run-with-secret", body, path)

    def test_policies_page_lists_the_modes(self):
        self.grant_env()
        self.grant_it(("other",))
        page = self.get("/policies")[1]
        self.assertIn("run-with-secret: all requests", page)
        self.assertIn("web: reads only", page)

    def test_history_wording(self):
        self.grant_env()
        rid = self.env()
        self.result(rid)
        _, frag = self.get(f"/request/{rid}?fragment=1")
        self.assertIn("time-boxed grant (all requests), run-with-secret (auto-approved)", frag)

    def test_ceiling_skip(self):
        self.grant_env()
        self.broker.grants_cfg["max_risk"] = "low"
        self.broker.summarizer = _Stub("x", "medium")
        n = len(self.notifier.sent)
        self.env()
        self.assertEqual(len(self.notifier.sent), n + 1)
        self.assertEqual(self.events("grant_skipped")[-1]["reason"], "risk")


# -- the broker checks argv itself: an omitted `scripts` entry is "not visible" ----
from secret_broker import scripts as scripts_mod  # noqa: E402

FLAGGED = (["bash", "deploy.sh"], ["python3", "x.py"], ["./run.sh"], ["sudo", "-u", "x", "bash", "y.sh"],
           ["env", "A=1", "node", "app.js"], ["/opt/tools/run"], ["deploy.sh"], ["bash"])
NOT_FLAGGED = (["bash", "-c", "echo hi"], ["python3", "-c", "print(1)"], ["python3", "-m", "http.server"],
               ["curl", "-s", "https://example.com"], ["git", "status"], ["docker", "compose", "up"],
               ["/usr/bin/curl", "x"], ["echo", "hi"], ["sed", "s/a/b/"])


class ArgvRunsScript(unittest.TestCase):
    def test_flagged(self):
        for argv in FLAGGED:
            self.assertTrue(scripts_mod.argv_runs_script(argv), argv)

    def test_not_flagged(self):
        for argv in NOT_FLAGGED:
            self.assertEqual(scripts_mod.argv_runs_script(argv), [], argv)

    def test_operands(self):
        self.assertEqual(scripts_mod.argv_runs_script(["sudo", "-u", "x", "bash", "y.sh"]), ["y.sh"])
        self.assertEqual(scripts_mod.argv_runs_script(["./run.sh"]), ["./run.sh"])
        self.assertEqual(scripts_mod.argv_runs_script(["timeout", "5", "python3.12", "-u", "a/b.py"]), ["a/b.py"])

    def test_matching(self):
        ok = [{**VISIBLE, "path": "/home/u/deploy.sh"}]
        self.assertFalse(scripts_mod.script_not_visible(["bash", "deploy.sh"], ok))      # basename
        self.assertFalse(scripts_mod.script_not_visible(["bash", "/home/u/deploy.sh"], ok))
        self.assertTrue(scripts_mod.script_not_visible(["bash", "other.sh"], ok))
        self.assertTrue(scripts_mod.script_not_visible(["bash", "deploy.sh"], []))
        self.assertTrue(scripts_mod.script_not_visible(["bash", "deploy.sh"], None))
        self.assertFalse(scripts_mod.script_not_visible(["curl", "x"], None))


class OmittedScripts(EnvAutoBase):
    risk_cfg = {"auto_approve_max": "high"}

    def post(self, argv, scripts=None):
        body = {"mode": "env", "names": ["svc"], "argv": argv}
        if scripts is not None:
            body["scripts"] = scripts
        code, b = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def test_omitted_list_prompts_even_at_high_with_allow(self):
        for argv in FLAGGED[:5]:
            self.notifier.sent.clear()
            self.broker._by_id.clear()
            self.post(argv)
            self.assertEqual(len(self.notifier.sent), 1, argv)
            self.assertEqual(self.events("escalated")[-1]["reason"], "script_not_visible")
        self.assertEqual(self.events("approved"), [])

    def test_honest_client_with_visible_entry_is_auto(self):
        rid = self.post(["bash", "deploy.sh"], [{**VISIBLE, "path": "deploy.sh"}])
        self.assertAuto(rid)

    def test_path_mismatch_prompts(self):
        self.post(["bash", "deploy.sh"], [VISIBLE])        # entry says run.sh
        self.assertPrompts()
        self.assertEqual(self.events("escalated")[-1]["reason"], "script_not_visible")

    def test_empty_list_does_not_help(self):
        self.post(["bash", "deploy.sh"], [])
        self.assertPrompts()

    def test_inline_and_plain_programs_auto(self):
        for argv in (["bash", "-c", "echo hi"], ["python3", "-c", "print(1)"], ["curl", "-s", "https://x.example"],
                     ["docker", "compose", "up"]):
            rid = self.post(argv)
            self.assertEqual(self.result(rid)["env"], {"SVC_TOKEN": SECRET}, argv)
        self.assertEqual(self.notifier.sent, [])

    def test_always_chip_not_offered_when_omitted(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        self.post(["./run.sh"])
        r = list(self.broker._by_id.values())[-1]
        ok, why = self.broker.always_allow_eligibility(r)
        self.assertFalse(ok)
        self.assertIn("not visible", why)
        self.assertNotIn("value=approve_always", req(self.abase + f"/a/{r.nonce}",
                                                     headers={"X-authentik-username": "alice"})[1])


class OmittedScriptsGrants(tg.Base):
    def grant_env(self):
        rid = self.post(["echo", "hi"])
        self.assertEqual(self.approve(rid, "approve_grant_15"), 303)
        self.broker._by_id[rid].done.wait(10)

    def post(self, argv, scripts=None):
        body = {"mode": "env", "names": ["svc"], "argv": argv}
        if scripts is not None:
            body["scripts"] = scripts
        code, b = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def test_omitted_list_is_not_covered_by_a_grant_and_no_chips(self):
        self.grant_env()
        for argv in (["bash", "deploy.sh"], ["sudo", "-u", "x", "bash", "y.sh"], ["./run.sh"]):
            n = len(self.notifier.sent)
            self.post(argv)
            self.assertEqual(len(self.notifier.sent), n + 1, argv)
            sk = self.events("grant_skipped")[-1]
            self.assertEqual((sk["reason"], sk["mode"]), ("script_not_visible", "env"))
        self.assertEqual(self.events("grant_used"), [])

    def test_no_grant_chips_or_creation_when_omitted(self):
        rid = self.post(["python3", "x.py"])
        self.assertNotIn("approve_grant_", self.get("/")[1])
        self.approve(rid, "approve_grant_15")
        self.assertEqual(self.broker.active_grants(), [])

    def test_grant_covers_inline_and_plain(self):
        self.grant_env()
        n = len(self.notifier.sent)
        for argv in (["bash", "-c", "echo hi"], ["curl", "-s", "https://x.example"]):
            self.assertEqual(self.result(self.post(argv))["status"], "approved")
        self.assertEqual(len(self.notifier.sent), n)
