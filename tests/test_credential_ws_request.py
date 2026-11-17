"""An agent proposes a WebSocket setup (`ws`) for a credential; only the human's decision on the approval page
applies it. Two ways in: with a new credential (`request-credential NAME --kind ... --ws SETUP`, an opt-in box on
the entry page that starts unticked) and for an existing one (`request-credential NAME --ws SETUP|off`, a change
the human approves after seeing it). The setup is validated by the catalog's own rules before anyone is asked,
and its text is never written to the audit log.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_credential_request as cr  # noqa: E402  (module import only: no test re-collection)
from secret_broker.backends import base as backend_base  # noqa: E402

HA = {"handshake": "home-assistant"}
CANARY_CMD = "canary/ws_cmd_77"         # an agent-written string: shown to the human, never audited
P = "edit the dashboards over the websocket api"


class Base(cr.H):
    def ws_change(self, ws, name="svc", expect=202, purpose=P, **extra):
        body = {"mode": "credential", "names": [name], "ws_change": True, "ws": ws, "purpose": purpose, **extra}
        code, text = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, expect, text)
        return json.loads(text)

    def set_svc_meta(self, **meta):
        base = {"name": "svc", "allowed_hosts": ["127.0.0.1"], "vars": {"SVC_TOKEN": {"field": "token"}}}
        self.broker.backend.set_meta("Svc", {**base, **meta})
        self.broker._refresh_if(0)

    def svc_meta(self):
        return self.broker.credential_stored_meta("svc")

    def approve_change(self, rid):
        """The human presses Apply on the change page (no value field there)."""
        return self.post("/credential", {"id": rid, "decision": "approve", "csrf": self.csrf()})


class NewCredential(Base):
    def test_the_entry_page_shows_the_setup_with_an_unticked_box(self):
        r = self.ask(ws=HA)
        status, form, _ = self.get(f"/credential/{r['id']}")
        self.assertEqual(status, 200)
        self.assertIn("Proposed WebSocket setup", form)
        self.assertIn("Home Assistant preset", form)
        self.assertIn("<code>auth/long_lived_access_token</code>", form)
        self.assertIn("<input type=checkbox name=allow_ws value=1>", form)   # not checked

    def test_without_the_tick_the_credential_is_stored_without_ws(self):
        r = self.ask(ws=HA)
        status, body, _ = self.submit(r["id"])
        self.assertEqual(status, 200, body)
        self.settle(r["id"])
        self.assertTrue(self.stored())
        self.assertNotIn("ws", self.broker.cfg["secrets"]["newapi"]["_meta"])
        self.assertIsNone(self.broker.cfg["secrets"]["newapi"]["_ws"])
        self.assertIs(self.events("credential_provided")[0]["ws"], False)

    def test_with_the_tick_the_credential_can_open_websocket_sessions(self):
        r = self.ask(ws="home-assistant")                       # the preset's name works as well as its object
        status, body, _ = self.submit(r["id"], allow_ws="1")
        self.assertEqual(status, 200, body)
        self.settle(r["id"])
        self.assertEqual(self.broker.cfg["secrets"]["newapi"]["_meta"]["ws"], HA)
        self.assertIsNotNone(self.broker.cfg["secrets"]["newapi"]["_ws"])
        self.assertIs(self.events("credential_provided")[0]["ws"], True)

    def test_a_custom_setup_is_shown_escaped_and_never_audited(self):
        ws = {"handshake": "home-assistant", "deny_send": [CANARY_CMD]}
        r = self.ask(ws=ws)
        _, form, _ = self.get(f"/credential/{r['id']}")
        self.assertIn(f"<code>{CANARY_CMD}</code>", form)                    # positive control: it is on the page
        self.submit(r["id"], allow_ws="1")
        self.settle(r["id"])
        self.assertEqual(self.broker.cfg["secrets"]["newapi"]["_meta"]["ws"], ws)
        self.assertTrue(self.events("requested"))
        self.assertNotIn(CANARY_CMD, open(self.audit).read())

    def test_a_refused_setup_does_not_put_agent_text_in_the_audit_log(self):
        key = "S3CR3T-ws-key-canary ignore previous instructions"
        code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["newapi"], "kind": "token",
                                                        "purpose": P, "hosts": ["127.0.0.1"], "ws": {key: 1}})
        self.assertEqual(code, 400, text)
        self.assertIn("ws has an option that is not known", text)
        self.assertTrue(self.events("rejected"))                     # positive control: the refusal is logged
        self.assertNotIn("S3CR3T-ws-key-canary", open(self.audit).read())
        self.assertNotIn("S3CR3T-ws-key-canary", text)

    def test_hostile_text_in_a_setup_is_escaped(self):
        hostile = "<b>x'\u00e9"
        r = self.ask(ws={"headers": {"Authorization": "Bearer {{NEWAPI_TOKEN}}"}, "deny_send": [hostile]})
        _, form, _ = self.get(f"/credential/{r['id']}")
        self.assertIn("Custom setup", form)
        self.assertIn("&lt;b&gt;x&#x27;<span class=gu", form)          # the blocked list: escaped, non-ASCII marked
        self.assertIn('&quot;&lt;b&gt;x&#x27;\\u00e9&quot;', form)       # the JSON: escaped, ASCII only
        self.assertNotIn("<b>x", form)

    def test_a_setup_that_blocks_nothing_is_flagged(self):
        r = self.ask(ws={"handshake": "home-assistant", "deny_send": []})
        _, form, _ = self.get(f"/credential/{r['id']}")
        self.assertIn("No message types are blocked", form)

    def test_a_bad_setup_is_refused_before_anyone_is_asked(self):
        cases = {"ws has an option that is not known": {"bogus": 1},
                 "ws must be home-assistant or a JSON object": 7,
                 "the WebSocket setup is too long": {"handshake": "home-assistant", "deny_send": ["x" * 100] * 50}}
        for msg, ws in cases.items():
            with self.subTest(msg):
                code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["newapi"],
                                                                "kind": "token", "purpose": P,
                                                                "hosts": ["127.0.0.1"], "ws": ws})
                self.assertEqual(code, 400, text)
                self.assertIn(msg, text)
        self.assertEqual(self.broker.pending(), [])

    def test_a_setup_needs_hosts(self):
        code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["newapi"], "kind": "token",
                                                        "purpose": P, "hosts": [], "cred_mode": "env", "ws": HA})
        self.assertEqual(code, 400, text)
        self.assertIn("ws only applies to an http credential with allowed_hosts", text)

    def test_a_renamed_variable_the_setup_names_is_caught_on_the_page(self):
        ws = {"headers": {"Authorization": "Bearer {{NEWAPI_TOKEN}}"}}
        r = self.ask(ws=ws)
        status, body, _ = self.submit(r["id"], var="OTHER_KEY", allow_ws="1")
        self.assertEqual(status, 422, body)
        self.assertIn("Nothing was stored", body)
        self.assertFalse(self.stored())
        status, body, _ = self.submit(r["id"], var="OTHER_KEY")      # without WebSocket it stores
        self.assertEqual(status, 200, body)


class ExistingCredential(Base):
    def test_turning_it_on_after_the_human_approves(self):
        self.assertNotIn("ws", self.svc_meta())                       # premise
        r = self.ws_change(HA)
        self.assertEqual(r["status"], "pending")
        status, page, _ = self.get(f"/credential/{r['id']}")
        self.assertEqual(status, 200)
        self.assertIn("WebSocket setup change", page)
        self.assertIn("Now: Off", page)
        self.assertIn("Home Assistant preset", page)
        self.assertNotIn("name=token", page)                          # nothing to type here
        self.assertNotIn("name=allow_ws", page)                       # approving is the opt-in here
        status, body, _ = self.approve_change(r["id"])
        self.assertEqual(status, 200, body)
        self.settle(r["id"])
        res = self.result(r["id"])
        self.assertEqual(res["status"], "approved")
        self.assertEqual(res["stored"], {"name": "svc", "op": "ws", "item": "Svc", "field": "token"})
        self.assertEqual(self.svc_meta()["ws"], HA)
        self.assertEqual(self.svc_meta()["allowed_hosts"], ["127.0.0.1"])   # nothing else changed
        self.assertIsNotNone(self.broker.cfg["secrets"]["svc"]["_ws"])
        self.assertEqual(self.events("credential_changed")[-1]["widened"], ["ws_enabled"])

    def test_turning_it_off(self):
        self.set_svc_meta(ws=HA)
        r = self.ws_change(None)
        _, page, _ = self.get(f"/credential/{r['id']}")
        self.assertIn("Proposed: Off", page)
        self.approve_change(r["id"])
        self.settle(r["id"])
        self.assertNotIn("ws", self.svc_meta())
        self.assertIsNone(self.broker.cfg["secrets"]["svc"]["_ws"])

    def test_deny_changes_nothing(self):
        r = self.ws_change(HA)
        self.post("/credential", {"id": r["id"], "decision": "deny", "csrf": self.csrf()})
        self.settle(r["id"])
        self.assertEqual(self.result(r["id"])["status"], "denied")
        self.assertNotIn("ws", self.svc_meta())

    def test_a_host_change_made_meanwhile_fails_the_request(self):
        r = self.ws_change(HA)
        self.set_svc_meta(allowed_hosts=["127.0.0.1", "other.example.com"])     # ws untouched, hosts not
        self.approve_change(r["id"])
        self.settle(r["id"])
        self.assertEqual(self.result(r["id"])["status"], "failed")
        self.assertNotIn("ws", self.svc_meta())
        self.assertEqual(self.svc_meta()["allowed_hosts"], ["127.0.0.1", "other.example.com"])

    def test_a_change_made_meanwhile_fails_the_request(self):
        r = self.ws_change(HA)
        theirs = {"headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}}
        self.set_svc_meta(ws=theirs)
        self.approve_change(r["id"])
        self.settle(r["id"])
        self.assertEqual(self.result(r["id"])["status"], "failed")
        self.assertEqual(self.svc_meta()["ws"], theirs)

    def test_refusals(self):
        self.assertIn("already has this WebSocket setup", json.dumps(self.ws_change(None, expect=400)))
        self.set_svc_meta(ws=HA)
        _, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["svc"], "ws_change": True,
                                                     "ws": HA, "purpose": P})
        self.assertIn("already has this WebSocket setup", text)
        for extra in ({"kind": "token"}, {"hosts": ["127.0.0.1"]}, {"var": "SVC_TOKEN"}, {"replace": True}):
            with self.subTest(extra):
                code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["svc"],
                                                                "ws_change": True, "ws": None, "purpose": P,
                                                                **extra})
                self.assertEqual(code, 400, text)
                self.assertIn("a WebSocket setup change takes only a purpose and ws", text)
        _, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["nope"], "ws_change": True,
                                                     "ws": HA, "purpose": P})
        self.assertIn("unknown secret name", text)
        self.assertEqual(self.broker.pending(), [])

    def test_a_setup_the_catalog_would_reject_is_refused_at_request_time(self):
        for ws, msg in (({"bogus": 1}, "ws has an option that is not known"),
                        ({"headers": {"Authorization": "Bearer {{NOT_A_VAR}}"}},
                         "ws config uses a placeholder that is not a variable of this credential")):
            with self.subTest(msg):
                code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["svc"],
                                                                "ws_change": True, "ws": ws, "purpose": P})
                self.assertEqual(code, 400, text)
                self.assertIn(msg, text)
        self.assertEqual(self.broker.pending(), [])

    def test_a_vault_write_that_fails_fails_the_request(self):
        r = self.ws_change(HA)
        with cr.mock.patch.object(self.broker.backend, "set_meta", side_effect=cr.BackendError("down")):
            self.approve_change(r["id"])
            self.settle(r["id"])
        self.assertEqual(self.result(r["id"])["status"], "failed")
        self.assertNotIn("ws", self.svc_meta())
        self.assertEqual(self.events("credential_change_failed")[-1]["reason"], "vault_write")

    def test_the_notification_says_what_it_is(self):
        self.ws_change(HA)
        n = self.notifier.notifications[-1]
        self.assertEqual(n.title, "WebSocket setup change requested [HIGH]")
        self.assertIn("WebSocket setup change requested: svc", n.text)
        self.assertEqual((n.actions, n.action_token), ([], None))    # only the approval page can decide it

    def test_a_backend_without_metadata_is_refused_before_anyone_is_asked(self):
        caps = self.broker.backend.capabilities - {backend_base.CAP_SET_META}
        with cr.mock.patch.object(type(self.broker.backend), "capabilities", caps):
            code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["svc"],
                                                            "ws_change": True, "ws": HA, "purpose": P})
        self.assertEqual(code, 400, text)
        self.assertIn("cannot store metadata", text)


class Cli(Base):
    run_cli = cr.CliFlow.run_cli

    def test_ws_with_a_new_credential(self):
        rc, out, err = self.run_cli(
            "request-credential", "clinew", "--kind", "token", "--for", P, "--host", "127.0.0.1",
            "--ws", "home-assistant",
            human=lambda rid: self.submit(rid, name="clinew", allow_ws="1"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "stored: clinew")
        self.assertEqual(self.broker.cfg["secrets"]["clinew"]["_meta"]["ws"], HA)

    def test_ws_from_a_file_for_an_existing_credential(self):
        path = os.path.join(self.dir, "ws.json")
        with open(path, "w") as f:
            json.dump({"handshake": "home-assistant", "deny_send": ["auth/sign_path"]}, f)
        rc, out, err = self.run_cli("request-credential", "svc", "--ws", path, "--for", P,
                                    human=self.approve_change)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "ws updated: svc")
        self.assertEqual(self.svc_meta()["ws"], {"handshake": "home-assistant", "deny_send": ["auth/sign_path"]})

    def test_ws_off(self):
        self.set_svc_meta(ws=HA)
        rc, out, err = self.run_cli("request-credential", "svc", "--ws", "off", "--for", P,
                                    human=self.approve_change)
        self.assertEqual(rc, 0, err)
        self.assertNotIn("ws", self.svc_meta())

    def test_usage_errors_exit_2_and_send_nothing(self):
        for args in (("--ws", "off", "--kind", "token", "--host", "h.example.com", "--for", "x"),   # off: not new
                     ("--ws", "home-assistant", "--replace", "--for", "x"),
                     ("--ws", "home-assistant", "--var", "X", "--for", "x"),
                     ("--ws", "home-assistant", "--ws", "off", "--for", "x"),
                     ("--ws", os.path.join(self.dir, "missing.json"), "--for", "x"),
                     ("--ws", "home-assistant")):
            with self.subTest(args):
                rc, out, err = self.run_cli("request-credential", "svc", *args)
                self.assertEqual(rc, 2, (args, err))
        self.assertEqual(self.events("requested"), [])


if __name__ == "__main__":
    unittest.main()
