"""Session open requests approved by a rule (`http_session` / `ws_session`), end to end.

A throwaway broker per test (the test_sessions / test_ws_sessions harnesses: a fake phone that never decides by
itself, an enrolled client, stub upstreams on 127.0.0.1). Every negative assertion here sits beside a positive control
in the same test: the matching request in the same setup is approved with no prompt.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from test_sessions import SBase, KEY, PURPOSE  # noqa: E402
from test_ws_sessions import WsBase, TOKEN  # noqa: E402
from secret_broker import audit_api, autorules  # noqa: E402
from test_ui_auto_rules import ManageBase, PoliciesTab  # noqa: E402

STORED = {"id": "r0001", "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None}


class HttpRuleBase(SBase):
    def setUp(self):
        super().setUp()
        self.box = self.new_client("box")
        self.key = self.box["secret"]

    def rule(self, **kw):
        raw = {"name": "unifi reads", "mode": "http_session", "secret": "unifi", "hosts": [self.hp()],
               "methods": ["GET", "HEAD", "POST"], "max_ttl_s": 300, "max_calls": 20, "clients": [self.box["id"]]}
        raw.update(kw)
        return raw

    def use_config_rule(self, **kw):
        self.broker.auto_rules = autorules.parse([self.rule(**kw)])

    def use_stored_rule(self, **kw):
        raw = {k: v for k, v in self.rule(**kw).items() if k != "secret"}
        self.broker.cfg["secrets"]["unifi"]["auto_rules"] = autorules.parse_stored([{**STORED, **raw}], "unifi")

    def asked(self, **kw):
        r = self.ask(self.key, **kw)
        return r, self.broker._by_id[r["id"]]

    def prompted(self, rid):
        return not [e for e in self.events("auto_rule_used") if e.get("id") == rid]

    def assert_prompted_not_approved(self, r, req, why):
        self.assertEqual((r["status"], req.status), ("pending", "pending"), why)
        self.assertTrue(self.prompted(r["id"]), why)
        self.assertEqual(self.events("approved"), [], why)


class HttpAuto(HttpRuleBase):
    def test_a_matching_config_rule_opens_the_session_with_no_prompt_and_the_rule_caps_the_limits(self):
        self.use_config_rule()
        n = len(self.notifier.notifications)
        r = self.ask(self.key, methods=["GET", "POST"], ttl_s=900, max_calls=200)
        self.assertEqual(r["status"], "approved")
        res = self.result(r["id"], self.key)
        self.assertEqual((res["session"]["expires_in"], res["session"]["max_calls"]), (300, 20))
        self.assertEqual(len(self.notifier.notifications), n)                 # nobody was asked
        self.assertEqual(self.model.calls, [])
        ev = self.events("approved")[-1]
        self.assertEqual((ev["via"], ev["decision_source"], ev["rule_name"]), ("policy", "config_rule", "unifi reads"))
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["source"], used["rule_name"], used["ttl_s"], used["max_calls"], used["shortened"]),
                         ("config", "unifi reads", 300, 20, True))
        opened = self.events("session_opened")[-1]
        self.assertEqual((opened["ttl_s"], opened["max_calls"], opened["shortened"]), (300, 20, True))
        code, out = self.call(res["session"]["id"], "GET", "/echo", key=self.key)         # the session works
        self.assertEqual((code, out["http"]["status"]), (200, 200))

    def test_a_request_below_the_rule_caps_keeps_its_own_limits(self):
        self.use_config_rule()
        r = self.ask(self.key, methods=["GET"], ttl_s=60, max_calls=5)
        res = self.result(r["id"], self.key)
        self.assertEqual((res["session"]["expires_in"], res["session"]["max_calls"]), (60, 5))
        self.assertFalse(self.events("auto_rule_used")[-1]["shortened"])

    def test_a_stored_rule_does_the_same_and_is_audited_as_a_ui_rule(self):
        self.use_stored_rule()
        r = self.ask(self.key, methods=["GET"])
        self.assertEqual(r["status"], "approved")
        ev = self.events("approved")[-1]
        self.assertEqual((ev["decision_source"], ev["rule_name"]), ("ui_rule", "unifi reads"))
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["source"], used["rule_id"]), ("ui", "r0001"))
        self.assertEqual(self.broker.auto_rule_usage.get("unifi", "r0001")["uses"], 1)

    def raw_ask(self, **kw):
        """An open request that may be refused outright: (http code, parsed body)."""
        code, text = self.as_client(self.key, "POST", "/v1/requests", {
            "mode": "session", "names": ["unifi"], "purpose": PURPOSE, "hosts": [self.hp()], "source": "t@box", **kw})
        return code, json.loads(text)

    def test_nothing_outside_the_rule_is_approved_and_each_is_asked_as_before(self):
        self.use_config_rule(methods=["GET", "HEAD"])
        ok, req = self.asked(methods=["GET"])                                  # positive control: same setup
        self.assertEqual((ok["status"], req.status), ("approved", "approved"))
        self.broker._sess.clear()
        for label, kw in {
            "extra method": {"methods": ["GET", "POST"]},
            "other method": {"methods": ["DELETE"]},
            "other host": {"hosts": [self.hp("localhost")], "methods": ["GET"]},
            "bare host is wider than the rule's host:port": {"hosts": ["127.0.0.1"], "methods": ["GET"]},
        }.items():
            code, r = self.raw_ask(**kw)
            self.assertEqual((code, r["status"]), (202, "pending"), label)
            self.broker._by_id[r["id"]].status = "denied"                       # free the pending slot
            self.broker._denied_at.clear()
        self.assertEqual(len(self.events("approved")), 1)                       # only the control

    def test_the_rule_never_applies_to_the_legacy_key_an_unlisted_client_or_a_never_auto_client(self):
        self.use_config_rule()
        r, req = self.asked(methods=["GET"])                                    # control
        self.assertEqual(req.status, "approved")
        self.broker._sess.clear()
        r = self.ask(KEY, methods=["GET"])
        self.assertEqual(r["status"], "pending")                                # legacy shared key
        other = self.new_client("other")
        r = self.ask(other["secret"], methods=["GET"])
        self.assertEqual(r["status"], "pending")                                # not in the rule's clients
        self.broker.clients_cfg["overrides"][self.box["id"]] = {"auto_approve_max": "none"}
        r, req = self.asked(methods=["GET"])
        self.assertEqual(req.status, "pending")                                 # set to never auto-approve
        self.assertEqual(len(self.events("approved")), 1)                       # only the control

    def test_a_rule_for_another_credential_or_an_expired_stored_rule_does_not_apply(self):
        self.use_config_rule(secret="methcred")
        r, req = self.asked(methods=["GET"])
        self.assert_prompted_not_approved(r, req, "rule names another credential")
        self.broker.auto_rules = []
        self.use_stored_rule(expires_at="2020-01-01T00:00:00Z")
        r, req = self.asked(methods=["GET"])
        self.assertEqual(req.status, "pending")
        self.use_stored_rule()                                                  # control: unexpired
        self.broker._by_id[r["id"]].status = "denied"
        self.broker._denied_at.clear()
        r, req = self.asked(methods=["GET"])
        self.assertEqual(req.status, "approved")

    def test_request_time_refusals_still_run_before_the_rule(self):
        self.use_config_rule(hosts=["127.0.0.1"], methods=["GET"])             # the rule would admit any port
        r, req = self.asked(hosts=["127.0.0.1"], methods=["GET"])
        self.assertEqual(req.status, "approved")                                # control: both ports 80 and 443 ... allowed here
        self.broker._sess.clear()
        self.broker.cfg["secrets"]["unifi"]["allowed_hosts"] = ["localhost"]    # the credential no longer allows the host
        code, text = self.as_client(self.key, "POST", "/v1/requests", {
            "mode": "session", "names": ["unifi"], "purpose": "p", "hosts": ["127.0.0.1"], "methods": ["GET"],
            "source": "t@box"})
        self.assertEqual(code, 403, text)
        self.assertEqual(len(self.events("approved")), 1)

    def test_the_agent_audit_api_never_shows_the_rule(self):
        self.use_config_rule(name="RULE-NAME-CANARY")
        self.ask(self.key, methods=["GET"])
        visible = json.dumps([audit_api.redact(r) for r in self.records() if audit_api.redact(r)])
        self.assertTrue(self.events("auto_rule_used"))                          # the operator log has it
        self.assertNotIn("RULE-NAME-CANARY", visible)
        self.assertNotIn("config_rule", visible)

    def test_the_history_page_says_a_rule_decided(self):
        self.use_stored_rule()
        r = self.ask(self.key, methods=["GET"])
        self.assertEqual(r["status"], "approved")
        row, _ = self.broker.history.detail(r["id"])
        self.assertEqual((row["outcome"], row["rule_name"], row["decision_source"]),
                         ("auto-approved", "unifi reads", "ui_rule"))
        page = self.get(f"/request/{r['id']}?fragment=1")[1]
        self.assertIn('Policies rule "unifi reads" (auto-approved)', page)
        self.assertIn("http session", page.lower())

    def test_session_close_needs_no_rule(self):
        self.use_config_rule()
        r = self.ask(self.key, methods=["GET"])
        sid = self.result(r["id"], self.key)["session"]["id"]
        code, text = self.as_client(self.key, "POST", "/v1/requests", {
            "mode": "session_close", "names": [], "session": sid, "source": "t@box"})
        self.assertEqual(code, 200, text)
        self.assertEqual(self.broker._sess, {})


class WsAuto(WsBase):
    def setUp(self):
        super().setUp()
        self.box = self.new_client("box")
        self.key = self.box["secret"]

    def rule(self, **kw):
        raw = {"name": "ha stream", "mode": "ws_session", "secret": "ha", "host": "127.0.0.1", "scheme": "ws",
               "port": self.stub.port, "path_prefix": "/api/websocket", "max_ttl_s": 300, "max_frames": 20,
               "clients": [self.box["id"]]}
        raw.update(kw)
        return raw

    def use_config_rule(self, **kw):
        self.broker.auto_rules = autorules.parse([self.rule(**kw)])

    def test_a_matching_rule_opens_a_working_ws_session_with_capped_limits(self):
        self.use_config_rule()
        n = len(self.notifier.notifications)
        r = self.wask(self.key, ttl_s=900, max_frames=500)
        self.assertEqual(r["status"], "approved")
        res = self.result(r["id"], self.key)
        self.assertEqual((res["session"]["expires_in"], res["session"]["max_frames"]), (300, 20))
        self.assertEqual(len(self.notifier.notifications), n)
        ev = self.events("approved")[-1]
        self.assertEqual((ev["via"], ev["decision_source"], ev["rule_name"]), ("policy", "config_rule", "ha stream"))
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["ttl_s"], used["max_calls"], used["shortened"]), (300, 20, True))
        self.assertEqual(self.events("ws_session_opened")[-1]["max_frames"], 20)
        sid = res["session"]["id"]
        self.assertEqual(self.wsend(sid, "hello", self.key)[0], 200)
        self.assertEqual(json.loads(self.frames_until(sid, 1, self.key)[0]["data"]), {"echo": "hello"})
        self.assertEqual(self.stub.auth_msgs, [{"type": "auth", "access_token": TOKEN}])
        self.assertNoSecret()

    def test_a_path_host_port_query_or_scheme_outside_the_rule_is_asked_as_before(self):
        self.use_config_rule()
        ok = self.wask(self.key)                                                # control
        self.assertEqual(ok["status"], "approved")
        self.broker._sess.clear()
        other = self.mkstub()
        for label, url in {
            "other path": self.wurl("/api/other"),
            "parent path": self.wurl("/api"),
            "dot segment": self.wurl("/api/websocket/../admin"),
            "escape": self.wurl("/api/websocket/%2e%2e/x"),
            "query": self.wurl("/api/websocket?x=1"),
            "other port": self.wurl(stub=other),
        }.items():
            n = len(self.events("approved"))
            r = self.wask(self.key, url=url)
            self.assertEqual(r["status"], "pending", label)
            self.assertEqual(len(self.events("approved")), n, label)
            self.broker._by_id[r["id"]].status = "denied"
            self.broker._denied_at.clear()

    def test_a_query_is_approved_only_when_the_rule_allows_one(self):
        self.use_config_rule(allow_query=True)
        r = self.wask(self.key, url=self.wurl("/api/websocket?v=2"))
        self.assertEqual(r["status"], "approved")

    def test_the_legacy_key_and_other_clients_still_ask(self):
        self.use_config_rule()
        self.assertEqual(self.wask(self.key)["status"], "approved")             # control
        self.broker._sess.clear()
        self.assertEqual(self.wask(KEY)["status"], "pending")
        other = self.new_client("other")
        self.assertEqual(self.wask(other["secret"])["status"], "pending")
        self.assertEqual(len(self.events("approved")), 1)


HTTP_FIELDS = dict(name="svc session", mode="http_session", hosts=["127.0.0.1:8080"], methods=["GET", "HEAD"],
                   max_ttl_s=600, max_calls=40)
WS_FIELDS = dict(name="svc stream", mode="ws_session", host="127.0.0.1", scheme="wss", port=443,
                 path_prefix="/api/websocket", allow_query=False, max_ttl_s=600, max_frames=100)


class SessionRuleManage(ManageBase):
    """Adding session rules through the Broker method the Policies page calls: one parser, narrow, confirmed."""

    def test_a_http_session_rule_is_stored_live_audited_and_matches_through_the_shared_check(self):
        res = self.add(**HTTP_FIELDS)
        self.assertEqual((res["status"], res["message"]), ("created", ""))
        [rule] = self.stored()
        self.assertEqual({k: rule[k] for k in ("mode", "hosts", "methods", "max_ttl_s", "max_calls")},
                         {"mode": "http_session", "hosts": ["127.0.0.1:8080"], "methods": ["GET", "HEAD"],
                          "max_ttl_s": 600, "max_calls": 40})
        self.assertNotIn("host", rule)                                      # nothing from the http fieldset leaks in
        live = self.live()[0]
        manifest = {"purpose": "p", "hosts": ["127.0.0.1:8080"], "methods": ["GET"], "ttl_s": 900, "max_calls": 200}
        self.assertEqual(autorules.find([live], "http_session", ["svc"], manifest, {"id": "c-0a0b0c0d"}), live)
        ev = self.events("auto_rule_created")[-1]
        self.assertEqual((ev["rule_mode"], ev["rule_name"]), ("http_session", "svc session"))

    def test_a_ws_session_rule_is_stored_with_its_own_fields(self):
        res = self.add(**WS_FIELDS)
        self.assertEqual(res["status"], "created")
        [rule] = self.stored()
        self.assertEqual({k: rule[k] for k in ("mode", "host", "path_prefix", "max_ttl_s", "max_frames")},
                         {"mode": "ws_session", "host": "127.0.0.1", "path_prefix": "/api/websocket",
                          "max_ttl_s": 600, "max_frames": 100})
        self.assertNotIn("methods", rule)

    def test_refusals_are_fixed_texts_and_write_nothing(self):
        self.assertEqual(self.add(**HTTP_FIELDS)["status"], "created")                 # control: the shape is valid
        before = self.stored()
        cases = {
            "no caps": (dict(HTTP_FIELDS, name="a", max_ttl_s=None), "max_ttl_s"),
            "no calls": (dict(HTTP_FIELDS, name="b", max_calls=None), "max_calls"),
            "caps as text": (dict(HTTP_FIELDS, name="c", max_calls="S3CR3T-many"), "max_calls"),
            "no hosts": (dict(HTTP_FIELDS, name="d", hosts=[]), "hosts"),
            "host with scheme": (dict(HTTP_FIELDS, name="e", hosts=["https://127.0.0.1"]), "hosts"),
            "host the credential does not allow": (dict(HTTP_FIELDS, name="f", hosts=["other.example.com"]), "hosts"),
            "ws without path": (dict(WS_FIELDS, name="g", path_prefix=""), "path_prefix"),
            "ws host the credential does not allow": (dict(WS_FIELDS, name="h", host="other.example.com"), "host"),
        }
        for label, (fields, field) in cases.items():
            res = self.add(**fields)
            self.assertEqual(res["status"], "refused", label)
            self.assertEqual(res["message"], f"Not a valid value for {field}.", label)
            self.assertNotIn("S3CR3T", res["message"], label)
        self.assertEqual(self.add(confirm=False, **dict(HTTP_FIELDS, name="i"))["status"], "refused")
        self.assertEqual(self.stored(), before)

    def test_an_ssh_credential_cannot_get_one(self):
        with self.assertRaises(ValueError):
            self.add(cred="deploy", **HTTP_FIELDS)


class SessionRulePage(PoliciesTab):
    """The Add-rule form on the credential's Policies page."""

    def session_form(self, **over):
        return self.form(**{"name": "svc session", "mode": "http_session", "shosts": "127.0.0.1:8080",
                            "smethods": ["GET", "HEAD"], "ttl_min": "10", "max_calls": "40", **over})

    def test_the_form_text_does_not_promise_https_only_for_an_explicit_port(self):
        """The session's scope check compares host and port, never the scheme of each call, so `host:443` means exactly
        port 443 on any scheme. The form must say that, not that it keeps calls on https."""
        sess = self.section().split("<legend>HTTP session</legend>")[1].split("</fieldset>")[0]
        self.assertNotIn("https only", sess)
        self.assertIn("host:443 allows exactly port 443", sess)
        self.assertIn("does not check the scheme of each call", sess)
        self.assertIn("a bare host allows ports 80 and 443", sess)                    # control: the form still explains it

    def test_the_form_offers_the_session_kinds_with_narrow_defaults_and_a_plain_tick(self):
        sec = self.section()
        self.assertIn("<option value=http_session>", sec)
        self.assertIn("<option value=ws_session>", sec)
        sess = sec.split("<legend>HTTP session</legend>")[1].split("</fieldset>")[0]
        self.assertIn("name=shosts", sess)
        self.assertNotRegex(sess, r"name=shosts[^>]*value=")                          # no default host
        checked = [m for m in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                   if f"name=smethods value='{m}' checked" in sess]
        self.assertEqual(checked, ["GET", "HEAD"])
        limits = sec.split("<legend>Session limits")[1].split("</fieldset>")[0]
        self.assertRegex(limits, r"name=ttl_min[^>]*value=15>")
        self.assertRegex(limits, r"name=max_calls[^>]*value=100>")
        ws = sec.split("<legend>WebSocket session</legend>")[1].split("</fieldset>")[0]
        self.assertIn("<option value=wss selected>", ws)
        self.assertNotIn("name=wquery checked", ws)
        self.assertNotRegex(ws, r"name=whost[^>]*value=")
        self.assertIn("a matching session opens with no approval", sec)
        self.assertIn("at any risk level", sec)

    def test_posting_the_form_adds_a_http_session_rule_and_lists_it(self):
        code, body = self.post(self.ADD, **self.session_form())
        self.assertEqual(code, 200, body)
        [rule] = self.stored()
        self.assertEqual((rule["mode"], rule["hosts"], rule["methods"], rule["max_ttl_s"], rule["max_calls"]),
                         ("http_session", ["127.0.0.1:8080"], ["GET", "HEAD"], 600, 40))
        sec = self.section()
        self.assertIn("HTTP session on 127.0.0.1:8080", sec)
        self.assertIn("up to 10 min and 40 calls", sec)

    def test_posting_the_form_adds_a_ws_session_rule(self):
        code, body = self.post(self.ADD, **self.form(name="svc stream", mode="ws_session", whost="127.0.0.1",
                                                     wscheme="wss", wport="", wpath="/api/websocket", ttl_min="5",
                                                     max_frames="100"))
        self.assertEqual(code, 200, body)
        [rule] = self.stored()
        self.assertEqual((rule["mode"], rule["host"], rule["path_prefix"], rule["max_ttl_s"], rule["max_frames"]),
                         ("ws_session", "127.0.0.1", "/api/websocket", 300, 100))
        self.assertNotIn("allow_query", rule)
        self.assertIn("WebSocket session on wss://127.0.0.1:443/api/websocket", self.section())

    def test_a_blank_cap_or_unticked_box_is_refused_not_defaulted(self):
        self.assertEqual(self.post(self.ADD, **self.session_form())[0], 200)          # control
        before = self.stored()
        for label, over, text in (("no minutes", dict(ttl_min=""), "max_ttl_s"),
                                  ("no calls", dict(max_calls=""), "max_calls"),
                                  ("text minutes", dict(ttl_min="S3CR3T-x"), "max_ttl_s"),
                                  ("no host", dict(shosts=""), "hosts"),
                                  ("not confirmed", dict(confirm="", name="zz"), "Tick the box")):
            code, body = self.post(self.ADD, **self.session_form(**dict({"name": "n-" + label}, **over)))
            self.assertEqual(code, 400, label)
            self.assertIn(text, body, label)
            self.assertNotIn("S3CR3T-x", body, label)
        self.assertEqual(self.stored(), before)


if __name__ == "__main__":
    unittest.main()
