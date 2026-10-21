"""Agent-initiated credential requests (`asb request-credential`, request mode `credential`).

The agent asks, a human types the secret on the approval page, the broker stores it through
the backend create path. The properties: always HIGH by code with no model call, never
auto-approved and never decided from a notification or a link button, the entry form exists
only on the authenticated approval listener behind CSRF, nothing is stored unless the human
submits a complete valid form, and the value appears in no output channel at all.

Every value here is obviously fake.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only: no test re-collection)
from test_guidance_proposals import HIDDEN  # noqa: E402

from secret_broker import audit_api, credreq, risk  # noqa: E402
from secret_broker.backends import (BackendError, BwBackend, FileBackend, LocalBackend,  # noqa: E402
                                    MemoryBackend, NotSupported)
from secret_broker.backends import localstore as ls  # noqa: E402
from secret_broker.broker import Broker, serve  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

KEY, CLI = t.KEY, t.CLI
TOK = "CRED-CANARY-tok-8c1f4e"
USR = "CRED-CANARY-usr-2d7a90"
PW = "CRED-CANARY-pw-91be3c"
ALL_CANARIES = (TOK, USR, PW)
PURPOSE = "read the Example API for the weekly report"


class Rec(t.Echo):
    """Upstream that records the Authorization header it was really sent."""
    seen = []

    def do_GET(self):
        Rec.seen.append(self.headers.get("Authorization"))
        self._reply(200, {"ok": True})


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Stub:
    """An analyzer that must never be called for a credential request."""

    def __init__(self):
        self.calls = []

    def analyze(self, mode, names, spec, guidance=None):
        self.calls.append(("analyze", mode))
        return {"summary": "s", "risk": "low"}

    def summarize(self, mode, names, spec):
        self.calls.append(("summarize", mode))
        return "s"


class H(unittest.TestCase):
    """A broker with a fake phone that never decides on its own, over a pluggable backend."""
    ttl = 30
    user = "alice"

    # -- backends ---------------------------------------------------------
    def make_backend(self, d):
        path = os.path.join(d, "vault.json")
        with open(path, "w") as f:
            json.dump({"Svc": {"token": "existing-svc-value", "broker": json.dumps(
                {"name": "svc", "allowed_hosts": ["127.0.0.1"], "vars": {"SVC_TOKEN": {"field": "token"}}})}}, f)
        return FileBackend(path)

    def extra_cfg(self, cfg):
        pass

    def vault_value(self, item, field="notes"):
        return self.broker.backend.get(item, field)

    # -- lifecycle --------------------------------------------------------
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        Rec.seen = []
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Rec)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        cfg = {"approve_base_url": "https://secrets.example", "allowed_user": "alice",
               "ttl_seconds": self.ttl, "secrets": {}, "request_details": {"enabled": True}}
        self.extra_cfg(cfg)
        self.notifier = FakeNotifier()
        self.audit = os.path.join(self.dir, "audit.jsonl")
        self.backend = self.make_backend(self.dir)
        self.broker = Broker(cfg, self.backend, self.notifier, self.audit)
        self.stub = Stub()
        self.broker.summarizer = self.stub
        self.c, self.a = serve(self.broker, ("127.0.0.1", 0), ("127.0.0.1", 0), KEY)
        self.base = f"http://127.0.0.1:{self.c.server_address[1]}"
        self.abase = f"http://127.0.0.1:{self.a.server_address[1]}"
        self.opener = urllib.request.build_opener(NoFollow)
        self.seen = []              # every HTML body, redirect target and API body this test saw

    def tearDown(self):
        for s in (self.c, self.a, self.up):
            s.shutdown()
            s.server_close()

    # -- helpers ----------------------------------------------------------
    def records(self):
        with open(self.audit) as f:
            return [json.loads(line) for line in f if line.strip()]

    def events(self, name):
        return [r for r in self.records() if r["event"] == name]

    def api(self, method, path, body=None, key=KEY):
        code, text = t.req(self.base + path, method, body,
                           {"X-Client-Key": key, "Content-Type": "application/json"})
        if method == "POST" and path == "/v1/requests":
            self.broker.flush_notifications(10)
        self.seen.append(text)
        return code, text

    def ask(self, name="newapi", kind="token", purpose=PURPOSE, hosts=("127.0.0.1",), expect=202, **extra):
        body = {"mode": "credential", "names": [name], "kind": kind, "purpose": purpose,
                "hosts": list(hosts), **extra}
        code, text = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, expect, text)
        return json.loads(text)

    def open_(self, req):
        try:
            r = self.opener.open(req, timeout=15)
            out = (r.status, r.read().decode(), r.headers)
        except urllib.error.HTTPError as e:
            out = (e.code, e.read().decode(), e.headers)
        self.seen.append(out[1])
        if out[2].get("Location"):
            self.seen.append(out[2]["Location"])
        return out

    def get(self, path, user="alice"):
        return self.open_(urllib.request.Request(self.abase + path, headers={"X-authentik-username": user}))

    def post(self, path, form, user="alice", headers=None):
        data = urllib.parse.urlencode(form, doseq=True).encode()
        h = {"X-authentik-username": user, **(headers or {})}
        return self.open_(urllib.request.Request(self.abase + path, data=data, headers=h, method="POST"))

    def csrf(self, user="alice"):
        return self.broker.csrf_token(user)

    def submit(self, rid, fields=None, user="alice", csrf=True, decision="approve", headers=None, **kw):
        form = {"id": rid, "decision": decision, "name": "newapi", "hosts": "127.0.0.1",
                "cred_mode": "http", "var": "", "token": TOK}
        form.update(fields or {})
        form.update(kw)
        if csrf is True:
            form["csrf"] = self.csrf(user)
        elif csrf:
            form["csrf"] = csrf
        return self.post("/credential", form, user, headers)

    def result(self, rid):
        code, text = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(text)

    def settle(self, rid):
        self.broker._by_id[rid].done.wait(10)
        return self.broker._by_id[rid]

    def stored(self, name="newapi"):
        return name in self.broker.cfg["secrets"]

    def pending_ids(self):
        return [r.id for r in self.broker.pending()]

    def http_with(self, name, var, rid_header="Bearer "):
        """A follow-up http request using the new credential, approved by the human."""
        port = self.up.server_address[1]
        code, text = self.api("POST", "/v1/requests", {
            "mode": "http", "names": [name], "method": "GET", "url": f"http://127.0.0.1:{port}/x",
            "headers": {"Authorization": rid_header + "{{" + var + "}}"}})
        self.assertEqual(code, 202, text)
        rid = json.loads(text)["id"]
        status, _, _ = self.post("/decide", {"id": rid, "decision": "approve", "csrf": self.csrf()})
        self.assertEqual(status, 303)
        self.settle(rid)
        return self.result(rid)


class Happy(H):
    def test_token_request_then_http_with_the_new_credential(self):
        r = self.ask(var="NEWAPI_KEY")
        self.assertEqual(r["status"], "pending")
        # the card is on the dashboard with a link to the entry page, a Deny button and no secret field
        _, page, _ = self.get("/")
        self.assertIn(f"/credential/{r['id']}", page)
        self.assertIn("Review and enter value", page)
        self.assertNotIn("type=password name=", page)
        self.assertNotIn("name=token", page)
        # the entry page has the editable suggestions and a password-type secret input
        status, form, hdr = self.get(f"/credential/{r['id']}")
        self.assertEqual(status, 200)
        self.assertIn("type=password name=token", form)
        self.assertIn("value='newapi'", form)
        self.assertIn("value='127.0.0.1'", form)
        self.assertIn("name=cred_mode", form)
        self.assertIn("value='NEWAPI_KEY'", form)
        self.assertIn("no-store", hdr["Cache-Control"])
        status, body, _ = self.submit(r["id"], var="NEWAPI_KEY")
        self.assertEqual(status, 200, body)
        self.assertIn("Stored", body)
        self.assertNotIn(TOK, body)
        res = self.result(r["id"])
        self.assertEqual(res["status"], "approved")
        self.assertEqual(res["stored"], {"name": "newapi", "op": "create", "item": "newapi", "field": "notes"})
        self.assertNotIn(TOK, json.dumps(res))
        self.assertEqual(self.vault_value("newapi"), TOK)
        meta = self.broker.cfg["secrets"]["newapi"]
        self.assertEqual(meta["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(set(meta["vars"]), {"NEWAPI_KEY"})
        self.assertEqual(meta["approval"], "prompt")
        self.assertEqual(meta["created"]["by"], "alice")
        # the new credential works through the normal request flow (and still asks a human)
        out = self.http_with("newapi", "NEWAPI_KEY")
        self.assertEqual(out["status"], "approved")
        self.assertEqual(out["http"]["status"], 200)
        self.assertEqual(Rec.seen, ["Bearer " + TOK])
        self.assertEqual(self.stub.calls[-1][1], "http")      # the http request, not the credential request
        self.assertNotIn(("analyze", "credential"), self.stub.calls)

    def test_default_variable_name(self):
        r = self.ask("my-svc2")
        self.submit(r["id"], name="my-svc2")
        self.assertEqual(set(self.broker.cfg["secrets"]["my-svc2"]["vars"]), {"MY_SVC2_TOKEN"})

    def test_login_is_stored_as_one_json_note_with_two_variables(self):
        r = self.ask("site", kind="login", hosts=["127.0.0.1"])
        _, form, _ = self.get(f"/credential/{r['id']}")
        self.assertIn("type=text name=username", form)
        self.assertNotIn("type=password name=username", form)
        self.assertIn("type=password name=password", form)
        self.assertNotIn("name=token", form)
        status, body, _ = self.submit(r["id"], name="site", username=USR, password=PW, token="")
        self.assertEqual(status, 200, body)
        sc = self.broker.cfg["secrets"]["site"]
        self.assertEqual(set(sc["vars"]), {"SITE_USERNAME", "SITE_PASSWORD"})
        self.assertEqual({v["key"] for v in sc["vars"].values()}, {"username", "password"})
        self.assertEqual(json.loads(self.vault_value("site")), {"username": USR, "password": PW})
        out = self.http_with("site", "SITE_USERNAME", rid_header="")
        self.assertEqual(out["http"]["status"], 200)
        self.assertEqual(Rec.seen, [USR])
        self.assertEqual(self.events("secret_read")[-1]["vars"], ["SITE_PASSWORD", "SITE_USERNAME"])

    def test_login_with_a_prefix_variable(self):
        r = self.ask("site", kind="login", var="PORTAL")
        self.submit(r["id"], name="site", var="PORTAL", username=USR, password=PW, token="")
        self.assertEqual(set(self.broker.cfg["secrets"]["site"]["vars"]), {"PORTAL_USERNAME", "PORTAL_PASSWORD"})

    def test_the_human_can_edit_name_hosts_mode_and_variable(self):
        r = self.ask(hosts=["old.example.com"])
        status, body, _ = self.submit(r["id"], name="renamed", hosts="a.example.com, https://B.example.com/x c.example.com",
                                      var="my_var", cred_mode="http")
        self.assertEqual(status, 200, body)
        self.assertFalse(self.stored("newapi"))
        sc = self.broker.cfg["secrets"]["renamed"]
        self.assertEqual(sc["allowed_hosts"], ["a.example.com", "b.example.com", "c.example.com"])
        self.assertEqual(set(sc["vars"]), {"MY_VAR"})
        res = self.result(r["id"])
        self.assertEqual(res["stored"]["name"], "renamed")
        prov = self.events("credential_provided")[0]
        self.assertEqual(prov["edited"], ["hosts", "name"])
        self.assertEqual(prov["requested_name"], "newapi")
        # the history row follows the rename
        row = self.broker.history.rows()[0]
        self.assertEqual(row["names"], ["renamed"])

    def test_the_card_shows_name_kind_purpose_and_suggestions(self):
        r = self.ask(hosts=["api.example.com", "b.example.com"], cred_mode="env", var="X_KEY")
        _, page, _ = self.get(f"/credential/{r['id']}")
        for s in ("newapi", "(token)", PURPOSE, "api.example.com", "b.example.com", "Credential request",
                  "unverified", "never sees the value"):
            self.assertIn(s, page)
        self.assertIn("<option value=env selected>", page)

    def test_link_page_shows_the_same_form_and_post_decision_approve_is_refused(self):
        r = self.ask()
        nonce = self.broker._by_id[r["id"]].nonce
        status, page, _ = self.get(f"/a/{nonce}")
        self.assertEqual(status, 200)
        self.assertIn("type=password name=token", page)
        status, body, _ = self.post(f"/a/{nonce}", {"decision": "approve"})
        self.assertEqual(status, 400)
        self.assertIn("form", body)
        self.assertEqual(self.pending_ids(), [r["id"]])
        status, body, _ = self.post(f"/a/{nonce}", {"decision": "deny"})
        self.assertEqual(status, 200)
        self.assertEqual(self.result(r["id"])["status"], "denied")

    def test_audit_events_history_and_agent_redaction(self):
        r = self.ask()
        self.submit(r["id"])
        self.settle(r["id"])
        ev = [e["event"] for e in self.records() if e.get("id") == r["id"]]
        for want in ("requested", "assessed", "notified", "decided", "credential_provided", "stored", "approved"):
            self.assertIn(want, ev)
        req_ev = self.events("requested")[0]
        self.assertEqual((req_ev["mode"], req_ev["cred_kind"], req_ev["names"]), ("credential", "token", ["newapi"]))
        self.assertEqual(req_ev["purpose_length"], len(PURPOSE))
        self.assertNotIn(PURPOSE, json.dumps(self.records()))        # only its length and hash are logged
        self.assertEqual(self.events("assessed")[0]["reasons"], [credreq.REASON])
        stored = self.events("stored")[0]
        self.assertEqual((stored["op"], stored["names"], stored["hosts"]), ("create", ["newapi"], ["127.0.0.1"]))
        self.assertEqual(self.events("approved")[0]["approver"], "alice")
        # history shows it and its detail view says what happened
        row = self.broker.history.rows()[0]
        self.assertEqual((row["mode"], row["outcome"]), ("credential", "approved"))
        status, frag, _ = self.get(f"/request/{r['id']}?fragment=1")
        self.assertEqual(status, 200)
        for s in ("credential request", "Kind", "Purpose", "not retained", "Allowed hosts", "never recorded"):
            self.assertIn(s, frag)
        _, hist, _ = self.get("/?view=all&mode=credential")
        self.assertIn("credential request", hist)
        # the agent's redacted audit view: requested (name, kind) and stored, not the human's entry
        code, text = self.api("GET", f"/v1/audit?request={r['id']}")
        events = {e["event"]: e for e in json.loads(text)["events"]}
        self.assertEqual(events["requested"]["cred_kind"], "token")
        self.assertEqual(events["stored"]["names"], ["newapi"])
        for hidden in ("credential_provided", "decided", "assessed", "notified"):
            self.assertNotIn(hidden, events)
        self.assertNotIn("purpose", text)
        self.assertEqual(audit_api.redact(self.events("credential_provided")[0]), None)

    def test_every_event_is_listed_in_the_agent_whitelist_or_hidden(self):
        r = self.ask()
        self.submit(r["id"], hosts="")      # a refused submission
        self.submit(r["id"])
        self.settle(r["id"])
        for e in {x["event"] for x in self.records()}:
            self.assertTrue(e in audit_api.WHITELIST or e in audit_api.HIDDEN, e)


class Notification(H):
    def test_push_names_only_with_no_buttons(self):
        self.ask(purpose="PURPOSE-CANARY-77 give me " + TOK[:5], hosts=["host-canary.example.com"])
        n = self.notifier.notifications[-1]
        self.assertEqual(n.title, "Credential requested [HIGH]")
        self.assertIn("Credential requested: newapi", n.text)
        self.assertEqual((n.actions, n.action_token), ([], None))
        flat = json.dumps(self.notifier.sent)
        for banned in ("PURPOSE-CANARY", "host-canary", "give me"):
            self.assertNotIn(banned, flat)
        self.assertEqual(n.risk, "high")

    def test_a_token_channel_can_never_decide_it(self):
        r = self.ask()
        for ch in ("push", "ha"):
            for decision in ("approve", "deny"):
                code, req = self.broker.decide_via(ch, r["id"], decision, "x", token="anything")
                self.assertIn(code, (403, 410))
                self.assertIsNone(req)
        self.assertEqual(self.pending_ids(), [r["id"]])
        self.assertEqual(self.notifier.resolutions, [])


class NeverAuto(H):
    def extra_cfg(self, cfg):
        cfg["risk"] = {"auto_approve_max": "high", "auto_modes": ["http", "env"]}
        cfg["timed_grants"] = {"enabled": True}

    def test_pending_high_with_no_model_call_whatever_the_policy(self):
        r = self.ask()
        self.assertEqual(r["status"], "pending")
        self.assertEqual(self.broker._by_id[r["id"]].risk["level"], "high")
        self.assertEqual(self.broker._by_id[r["id"]].risk["model"], None)
        self.assertEqual(self.stub.calls, [])
        self.assertEqual(risk.assess("credential", ["x"], {}, self.stub)["level"], "high")
        evs = {e["event"] for e in self.records()}
        self.assertFalse({"grant_created", "grant_used", "ssh_rule_used", "escalated"} & evs)
        self.assertEqual(self.events("assessed")[0]["model"], None)

    def test_no_always_grant_or_unconfirmed_approval(self):
        r = self.ask()
        card = self.get("/")[1]
        self.assertNotIn("Automatically approve", card)
        self.assertNotIn("Always", card)
        for kw in ({"always": True}, {"grant_minutes": 15}, {}):
            code, req = self.broker.decide_via("dashboard", r["id"], "approve", "alice", **kw)
            self.assertEqual((code, req), (400, None))
        # the dashboard's own Approve value and the grant/always form values cannot approve it either
        for decision in ("approve", "approve_always", "approve_grant_15"):
            status, _, hdr = self.post("/decide", {"id": r["id"], "decision": decision, "csrf": self.csrf()})
            self.assertEqual(status, 303)
            self.assertIn("note=", hdr["Location"])
        self.assertEqual(self.pending_ids(), [r["id"]])
        self.assertFalse(self.stored())
        # credential= is for credential requests only: an env request refuses it
        env = json.loads(self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})[1])
        code, req = self.broker.decide_via("dashboard", env["id"], "approve", "alice", credential=({}, {}))
        self.assertEqual((code, req), (400, None))

    def test_a_legacy_allow_secret_of_the_same_name_does_not_exist_to_auto_approve(self):
        r = self.ask(name="svc2")
        self.assertEqual(r["status"], "pending")


class DenyExpire(H):
    def test_deny_then_cooldown(self):
        r = self.ask()
        status, body, _ = self.submit(r["id"], decision="deny")
        self.assertEqual(status, 200)
        self.assertIn("Nothing was stored", body)
        res = self.result(r["id"])
        self.assertEqual(res["status"], "denied")
        self.assertFalse(self.stored())
        self.assertEqual(self.events("denied")[0]["channel"], "dashboard")
        code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": ["newapi"],
                                                         "kind": "token", "purpose": PURPOSE, "hosts": ["a.example.com"]})
        self.assertEqual(code, 403)
        self.assertIn("denied recently", text)

    def test_deny_from_the_dashboard_card(self):
        r = self.ask()
        status, _, _ = self.post("/decide", {"id": r["id"], "decision": "deny", "csrf": self.csrf()})
        self.assertEqual(status, 303)
        self.assertEqual(self.result(r["id"])["status"], "denied")

    def test_expire(self):
        self.broker.credreq_cfg = dict(self.broker.credreq_cfg, ttl_s=1)
        r = self.ask()
        self.assertLessEqual(r["expires_in"], 1)
        time.sleep(1.4)
        self.assertEqual(self.result(r["id"])["status"], "expired")
        self.assertEqual(self.get(f"/credential/{r['id']}")[0], 404)
        status, _, hdr = self.submit(r["id"])
        self.assertEqual(status, 410)
        self.assertFalse(self.stored())
        self.assertEqual(len(self.events("expired")), 1)
        self.assertEqual(self.broker.history.rows()[0]["outcome"], "expired")
        self.assertNotIn("secret", self.broker._by_id[r["id"]].spec)

    def test_default_ttl_is_longer_than_a_normal_request(self):
        r = self.ask()
        self.assertGreater(r["expires_in"], 800)
        self.assertLessEqual(r["expires_in"], 900)

    def test_ttl_config_is_validated(self):
        self.assertEqual(credreq.parse_config(None), {"enabled": True, "ttl_s": 900})
        for bad in ({"ttl_s": 5}, {"ttl_s": 99999}, {"ttl_s": "x"}, {"enabled": "yes"}, {"nope": 1}, [1]):
            with self.assertRaises(ValueError):
                credreq.parse_config(bad)

    def test_disabled(self):
        self.broker.credreq_cfg = dict(self.broker.credreq_cfg, enabled=False)
        r = self.ask(expect=403)
        self.assertIn("disabled", r["error"])


class Validation(H):
    def test_name_collision_at_request_time(self):
        r = self.ask(name="svc", expect=400)
        self.assertIn("already exists", r["error"])
        self.assertIn("asb update svc", r["error"])
        self.assertEqual(self.pending_ids(), [])

    def test_name_collision_after_the_human_edits_the_name(self):
        r = self.ask()
        status, body, _ = self.submit(r["id"], name="svc")
        self.assertEqual(status, 422)
        self.assertIn("svc already exists", body)
        self.assertEqual(self.pending_ids(), [r["id"]])
        self.assertEqual(self.vault_value("svc", "token"), "existing-svc-value")
        self.assertEqual(self.events("credential_refused")[0]["problems"], 1)

    def test_name_taken_while_the_request_waits(self):
        r = self.ask()
        self.broker.backend.put("newapi", "notes", "other", create=True, meta={
            "name": "newapi", "allowed_hosts": ["x.example.com"], "vars": {"NEWAPI_TOKEN": {"field": "notes"}}})
        self.broker.refresh_catalog()
        status, body, _ = self.submit(r["id"])
        self.assertEqual(status, 422)
        self.assertEqual(self.vault_value("newapi"), "other")

    def test_a_second_pending_request_for_the_same_name_is_refused(self):
        self.ask()
        r = self.ask(expect=403)
        self.assertIn("already waiting", r["error"])

    def test_invalid_names(self):
        for bad in ("Bad Name", "UPPER", "-x", "", "a" * 42, "../etc", "a/b", "x;y", "naïve", "a\nb"):
            code, text = self.api("POST", "/v1/requests", {"mode": "credential", "names": [bad], "kind": "token",
                                                            "purpose": PURPOSE, "hosts": ["a.example.com"]})
            self.assertEqual(code, 400, bad)
            self.assertIn("secret name must be", text)
        for names in ([], ["a", "b"], "newapi", [None], [7]):
            code, _ = self.api("POST", "/v1/requests", {"mode": "credential", "names": names, "kind": "token",
                                                         "purpose": PURPOSE, "hosts": ["a.example.com"]})
            self.assertEqual(code, 400, names)
        self.assertEqual(self.pending_ids(), [])

    def test_bad_kind_mode_host_var_and_purpose(self):
        cases = [{"kind": "ssh"}, {"kind": None}, {"cred_mode": "ssh_sign"}, {"hosts": ["a b"]},
                 {"hosts": ["https://x.example.com"]}, {"hosts": "a.example.com"}, {"hosts": ["h"] * 11},
                 {"var": "lower"}, {"var": "PATH"}, {"var": "LD_PRELOAD"}, {"var": "9X"},
                 {"purpose": ""}, {"purpose": "   "}, {"purpose": "x" * 301}, {"purpose": None},
                 {"purpose": "line one\nline two"}, {"purpose": "tab\there"}, {"purpose": "nul\x00"}]
        for extra in cases:
            body = {"mode": "credential", "names": ["newapi"], "kind": "token", "purpose": PURPOSE,
                    "hosts": ["a.example.com"], **extra}
            code, text = self.api("POST", "/v1/requests", body)
            self.assertEqual(code, 400, extra)
        self.assertEqual(self.pending_ids(), [])

    def test_hidden_unicode_in_the_purpose_is_rejected_without_repeating_it(self):
        for label, ch in HIDDEN.items():
            code, text = self.api("POST", "/v1/requests", {
                "mode": "credential", "names": ["newapi"], "kind": "token", "hosts": ["a.example.com"],
                "purpose": f"read the report{ch} now"})
            self.assertEqual(code, 400, label)
            self.assertIn("hidden characters", text)
            self.assertNotIn(ch, json.loads(text)["error"])
        self.assertEqual(self.pending_ids(), [])
        self.assertTrue(all(r["event"] != "requested" for r in self.records()))

    def test_hostile_purpose_is_escaped_and_non_ascii_is_shown_as_codepoints(self):
        hostile = '<script>alert("x")</script> & <img src=x onerror=1> café аpple'
        r = self.ask(purpose=hostile)
        for path in (f"/credential/{r['id']}", "/"):
            _, page, _ = self.get(path)
            self.assertNotIn("<script>alert", page)
            self.assertNotIn("<img src=x", page)
            self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", page)
            self.assertIn("&lt;U+00E9&gt;", page)
            self.assertIn("&lt;U+0430&gt;", page)        # Cyrillic a is not passed off as ASCII
            self.assertIn("Non-ASCII characters: 2", page)

    def test_hosts_in_the_request_are_lowercased_and_deduplicated_on_the_card(self):
        r = self.ask(hosts=["API.example.com", "api.example.com"])
        self.assertEqual(self.broker._by_id[r["id"]].spec["hosts"], ["api.example.com"])

    def test_a_client_request_can_never_carry_a_value(self):
        for k in ("value", "secret", "token", "password", "username", "credential"):
            code, text = self.api("POST", "/v1/requests", {
                "mode": "credential", "names": ["newapi"], "kind": "token", "purpose": PURPOSE,
                "hosts": ["a.example.com"], k: TOK})
            self.assertEqual(code, 400, k)
            self.assertNotIn(TOK, text)
        self.assertEqual(self.pending_ids(), [])
        self.assertNotIn(TOK, json.dumps(self.records()))

    def test_dangerous_variable_names_and_a_bad_form_are_refused_and_nothing_is_stored(self):
        r = self.ask()
        for var in ("PATH", "ld_preload", "GIT_SSH_COMMAND", "SECRET_BROKER_X", "A B", "1X"):
            status, body, _ = self.submit(r["id"], var=var)
            self.assertEqual(status, 422, var)
            self.assertIn("variable must look like", body)
        self.assertFalse(self.stored())
        self.assertEqual(self.pending_ids(), [r["id"]])

    def test_empty_token_and_login_with_a_missing_half(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"], token="   ")[0], 422)
        self.assertEqual(self.submit(r["id"], token="a\nb")[0], 422)
        self.assertEqual(self.submit(r["id"], token="x" * 16385)[0], 422)
        r2 = self.ask("site", kind="login")
        self.assertEqual(self.submit(r2["id"], name="site", username=USR, password="")[0], 422)
        self.assertEqual(self.submit(r2["id"], name="site", username="", password=PW)[0], 422)
        self.assertFalse(self.stored("newapi") or self.stored("site"))


class HostBinding(H):
    def test_missing_host_is_refused_in_http_mode(self):
        r = self.ask(hosts=())
        for hosts in ("", "  ,  "):
            status, body, _ = self.submit(r["id"], hosts=hosts)
            self.assertEqual(status, 422)
            self.assertIn("allowed hosts are required", body)
        self.assertFalse(self.stored())
        self.assertEqual(self.pending_ids(), [r["id"]])

    def test_the_human_can_add_a_host_the_agent_left_out(self):
        r = self.ask(hosts=())
        self.assertEqual(self.submit(r["id"], hosts="api.example.com")[0], 200)
        self.assertEqual(self.broker.cfg["secrets"]["newapi"]["allowed_hosts"], ["api.example.com"])

    def test_env_mode_without_hosts_needs_the_explicit_box(self):
        r = self.ask(hosts=(), cred_mode="env")
        status, body, _ = self.submit(r["id"], hosts="", cred_mode="env")
        self.assertEqual(status, 422)
        status, body, _ = self.submit(r["id"], hosts="a.example.com", cred_mode="env", no_hosts="1")
        self.assertEqual(status, 422)
        self.assertIn("not both", body)
        status, body, _ = self.submit(r["id"], hosts="", cred_mode="http", no_hosts="1")
        self.assertEqual(status, 422)
        status, body, _ = self.submit(r["id"], hosts="", cred_mode="env", no_hosts="1")
        self.assertEqual(status, 200, body)
        sc = self.broker.cfg["secrets"]["newapi"]
        self.assertEqual(sc["allowed_hosts"], [])
        self.assertEqual(self.events("credential_provided")[0]["no_hosts"], True)
        # with no hosts the credential can never be used by the http command
        code, text = self.api("POST", "/v1/requests", {"mode": "http", "names": ["newapi"], "method": "GET",
                                                         "url": "http://127.0.0.1:1/", "headers": {}})
        self.assertEqual(code, 403)

    def test_bad_hosts_text(self):
        r = self.ask()
        for hosts in ("exa mple!.com", "-bad.example.com", "a.example.com," + ",".join(f"h{i}.example.com" for i in range(10))):
            self.assertEqual(self.submit(r["id"], hosts=hosts)[0], 422, hosts)
        self.assertFalse(self.stored())

    def test_mode_value_is_checked(self):
        r = self.ask()
        status, body, _ = self.submit(r["id"], cred_mode="ssh_sign")
        self.assertEqual(status, 422)
        self.assertIn("mode must be http or env", body)


class Caps(H):
    def test_credential_request_cap_and_the_general_cap(self):
        a = self.ask("one")
        b = self.ask("two")
        c = self.ask("three", expect=403)
        self.assertIn("too many pending credential requests", c["error"])
        self.assertEqual(len(self.pending_ids()), 2)
        self.assertEqual(self.submit(a["id"], name="one")[0], 200)
        d = self.ask("three")
        self.assertEqual(d["status"], "pending")
        rej = [e for e in self.events("rejected") if e["mode"] == "credential"]
        self.assertEqual(len(rej), 1)
        self.assertTrue(b["id"])

    def test_the_general_pending_cap_applies(self):
        for i in range(3):
            code, text = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})
            self.assertEqual(code, 202, text)
        r = self.ask(expect=403)
        self.assertIn("too many pending requests", r["error"])

    def test_a_pending_credential_request_counts_against_the_general_cap(self):
        self.ask("one")
        self.ask("two")
        code, text = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})
        self.assertEqual(code, 202)
        code, text = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["x"]})
        self.assertEqual(code, 403)

    def test_a_credential_request_does_not_use_up_the_guidance_proposal_slots(self):
        self.ask()
        code, text = self.api("POST", "/v1/requests", {"mode": "guidance", "entries": [{"name": "svc", "text": "t"}]})
        self.assertEqual(code, 202, text)


class Csrf(H):
    def test_missing_wrong_and_cross_site_csrf_all_refuse_and_store_nothing(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"], csrf=False)[0], 403)
        self.assertEqual(self.submit(r["id"], csrf="0" * 64)[0], 403)
        self.assertEqual(self.submit(r["id"], csrf=self.csrf("mallory"))[0], 403)     # another user's token
        status, body, _ = self.submit(r["id"], headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        status, body, _ = self.submit(r["id"], headers={"Origin": "https://evil.example"})
        self.assertEqual(status, 403)
        self.assertNotIn(TOK, body)
        self.assertFalse(self.stored())
        self.assertEqual(self.pending_ids(), [r["id"]])
        self.assertEqual(len(self.events("csrf_refused")), 5)
        self.assertEqual(self.events("credential_provided"), [])
        # deny is held to the same token
        self.assertEqual(self.submit(r["id"], csrf=False, decision="deny")[0], 403)
        self.assertEqual(self.pending_ids(), [r["id"]])

    def test_same_origin_with_the_token_works(self):
        r = self.ask()
        status, body, _ = self.submit(r["id"], headers={"Sec-Fetch-Site": "same-origin",
                                                         "Origin": "https://secrets.example"})
        self.assertEqual(status, 200, body)

    def test_only_the_allowed_user_reaches_the_page_and_the_form(self):
        r = self.ask()
        self.assertEqual(self.get(f"/credential/{r['id']}", user="mallory")[0], 403)
        self.assertEqual(self.submit(r["id"], user="mallory", csrf=self.csrf("mallory"))[0], 403)
        self.assertFalse(self.stored())


class DoubleSubmit(H):
    def test_second_submit_finds_it_handled(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"])[0], 200)
        status, body, _ = self.submit(r["id"], token="SECOND-" + TOK)
        self.assertIn(status, (404, 410, 303))
        self.assertEqual(self.vault_value("newapi"), TOK)
        self.assertEqual(len(self.events("stored")), 1)

    def test_concurrent_submits_store_exactly_once(self):
        r = self.ask()
        real = self.broker.backend.put
        calls = []

        def counting(*a, **kw):
            calls.append(a[0])
            time.sleep(0.2)
            return real(*a, **kw)
        out = []
        with mock.patch.object(self.broker.backend, "put", counting):
            ths = [threading.Thread(target=lambda i=i: out.append(self.submit(
                r["id"], token=f"{TOK}-{i}")[0])) for i in range(4)]
            for th in ths:
                th.start()
            for th in ths:
                th.join(20)
        self.assertEqual(sorted(out).count(200), 1, out)
        self.assertEqual(calls, ["newapi"])
        self.assertEqual(len(self.events("stored")), 1)
        self.assertTrue(self.vault_value("newapi").startswith(TOK))

    def test_deny_after_store_does_nothing(self):
        r = self.ask()
        self.submit(r["id"])
        self.assertIn(self.submit(r["id"], decision="deny")[0], (303, 404, 410))
        self.assertTrue(self.stored())
        self.assertEqual(self.result(r["id"])["status"], "approved")
        self.assertEqual(self.result(r["id"])["status"], "released")


class ClientApiSurface(H):
    def test_no_client_endpoint_takes_a_secret(self):
        r = self.ask()
        for method, path, body in (
                ("POST", f"/v1/requests/{r['id']}/secret", {"token": TOK}),
                ("POST", f"/v1/requests/{r['id']}", {"token": TOK}),
                ("POST", "/credential", {"id": r["id"], "token": TOK, "csrf": "x", "decision": "approve"}),
                ("POST", "/v1/credentials", {"name": "newapi", "token": TOK}),
                ("GET", f"/credential/{r['id']}", None),
                ("PUT", f"/v1/requests/{r['id']}", {"token": TOK}),
                ("PATCH", f"/v1/requests/{r['id']}", {"token": TOK}),
                ("DELETE", f"/v1/requests/{r['id']}", None)):
            code, text = self.api(method, path, body)
            self.assertIn(code, (404, 405), (method, path, code))
            self.assertNotIn(TOK, text)
            self.assertNotIn("password", text.lower().replace("passwords", ""))
        self.assertFalse(self.stored())
        self.assertEqual(self.pending_ids(), [r["id"]])
        # the client API also refuses a bad key on every one of them
        code, _ = self.api("POST", f"/v1/requests/{r['id']}/secret", {"token": TOK}, key="wrong")
        self.assertEqual(code, 401)

    def test_a_poll_never_returns_a_value_and_the_result_is_taken_once(self):
        r = self.ask()
        self.submit(r["id"])
        first = self.result(r["id"])
        self.assertEqual(first["stored"]["name"], "newapi")
        self.assertEqual(self.result(r["id"]), {"status": "released"})
        self.assertNotIn(TOK, json.dumps(first))

    def test_discovery_after_storing_lists_names_and_vars_only(self):
        r = self.ask()
        self.submit(r["id"])
        code, text = self.api("GET", "/v1/secrets?host=127.0.0.1")
        self.assertIn("newapi", text)
        self.assertNotIn(TOK, text)


class Failures(H):
    def test_backend_failure_ends_the_request_without_echoing_the_value(self):
        r = self.ask()

        def boom(*a, **kw):
            raise RuntimeError(f"vault said no to {a[2]}")
        with mock.patch.object(self.broker.backend, "put", boom):
            status, body, _ = self.submit(r["id"])
        self.assertEqual(status, 500)
        self.assertIn("Not stored", body)
        self.assertNotIn(TOK, body)
        res = self.result(r["id"])
        self.assertEqual(res["status"], "failed")
        self.assertNotIn(TOK, json.dumps(res))
        self.assertEqual(res["error"], "store failed: RuntimeError")
        self.assertFalse(self.stored())
        self.assertNotIn(TOK, json.dumps(self.records()))
        self.assertEqual(self.events("failed")[0]["names"], ["newapi"])

    def test_exception_text_never_reaches_the_agent_whatever_form_the_value_takes(self):
        """Fail closed: the agent-visible error is the exception class (and coarse backend class) only.
        No exception text is kept anywhere (audit, history, UI, logs), so no encoding of the value can survive."""
        import base64
        r = self.ask("site", kind="login")
        login = json.dumps({"username": USR, "password": PW})
        forms = [PW, USR, json.dumps(PW), json.dumps(PW)[1:-1], urllib.parse.quote(PW, safe=""),
                 urllib.parse.quote_plus(USR), base64.b64encode(PW.encode()).decode(),
                 base64.urlsafe_b64encode(USR.encode()).decode(), login, json.dumps(login),
                 urllib.parse.quote(login, safe=""), repr(PW)]

        def boom(*a, **kw):
            raise RuntimeError("vault exploded: " + " | ".join(forms) + " | secret-in-args=" + a[2])
        with mock.patch.object(self.broker.backend, "put", boom):
            status, body, _ = self.submit(r["id"], name="site", username=USR, password=PW, token="")
        self.assertEqual(status, 500)
        res = self.result(r["id"])
        self.assertEqual(res["error"], "store failed: RuntimeError")
        self.assertIn("store failed: RuntimeError", body)
        self.broker.flush_notifications(10)
        _, frag, _ = self.get(f"/request/{r['id']}?fragment=1")
        _, hist, _ = self.get("/?view=all")
        code, agent_audit = self.api("GET", f"/v1/audit?request={r['id']}")
        everything = "\n".join([body, json.dumps(res), frag, hist, agent_audit, open(self.audit).read(),
                                json.dumps(self.notifier.sent), json.dumps(self.broker.history.rows(), default=str),
                                "\n".join(self.seen)])
        for f in forms:
            self.assertNotIn(f, everything)
        for c in ALL_CANARIES:
            self.assertNotIn(c, everything)
        # no exception text anywhere, not even for the operator: only the class name and category
        self.assertNotIn("vault exploded", everything)
        self.assertEqual(self.events("credential_store_failed"), [])
        self.assertEqual(self.events("failed")[0]["error"], "store failed: RuntimeError")

    def test_a_backend_that_cannot_create(self):
        r = self.ask()
        with mock.patch.object(self.broker.backend, "put", side_effect=NotSupported("no")):
            status, body, _ = self.submit(r["id"])
        self.assertEqual(status, 500)
        self.assertIn("store failed: NotSupported (invalid)", body)
        self.assertEqual(self.result(r["id"])["status"], "failed")
        self.assertFalse(self.stored())

    def test_an_item_that_already_exists_in_the_vault_is_a_conflict_not_an_overwrite(self):
        self.broker.backend.put("newapi", "notes", "keep-me", create=True)     # no metadata: not in the catalog
        r = self.ask()
        status, body, _ = self.submit(r["id"])
        self.assertEqual(status, 500)
        self.assertIn("store failed: BackendConflict (conflict)", body)
        self.assertEqual(self.vault_value("newapi"), "keep-me")

    def test_a_catalog_that_cannot_be_read_still_refuses_a_duplicate_name(self):
        r = self.ask("svc", expect=400)
        self.assertIn("already exists", r["error"])


class SecretNeverLeaks(H):
    """The canaries go in through the form (and once through a refused form) and must come out
    nowhere: log/audit, request details, notifications, CLI output, HTML, redirects, results, history."""

    def collect(self):
        parts = {"audit": open(self.audit).read(), "notifications": json.dumps(self.notifier.sent),
                 "resolutions": json.dumps([(a, b) for a, b in self.notifier.resolutions]),
                 "history": json.dumps(self.broker.history.rows(), default=str),
                 "seen": "\n".join(self.seen), "status": json.dumps(self.broker.status())}
        det = os.path.join(self.dir, "request_details.db")
        parts["details_db"] = open(det, "rb").read().decode("latin-1") if os.path.exists(det) else ""
        for r in list(self.broker._by_id.values()):
            parts[f"spec:{r.id[:6]}"] = repr(r.spec) + repr(r.result) + repr(r.error)
            if self.broker.details:
                parts[f"retained:{r.id[:6]}"] = repr(self.broker.details.get(r.id))
        return parts

    def assertClean(self, parts=None):
        for where, text in (parts or self.collect()).items():
            for c in ALL_CANARIES:
                self.assertNotIn(c, text, f"{c} leaked into {where}")

    def test_token_and_login_leak_nowhere(self):
        a = self.ask("tokcred")
        # a refused submission re-renders the form: no secret, all other fields kept
        status, body, hdr = self.submit(a["id"], name="Bad Name", hosts="keep.example.com", token=TOK)
        self.assertEqual(status, 422)
        for c in ALL_CANARIES:
            self.assertNotIn(c, body)
        self.assertIn("keep.example.com", body)
        self.assertNotRegex(body, r"name=token[^>]*value=")
        self.assertEqual(hdr.get("Location"), None)
        self.assertEqual(self.submit(a["id"], name="tokcred")[0], 200)
        b = self.ask("logcred", kind="login")
        status, body, _ = self.submit(b["id"], name="logcred", hosts="", username=USR, password=PW, token="")
        self.assertEqual(status, 422)
        for c in ALL_CANARIES:
            self.assertNotIn(c, body)
        self.assertEqual(self.submit(b["id"], name="logcred", username=USR, password=PW, token="")[0], 200)
        for rid in (a["id"], b["id"]):
            self.result(rid)
            self.get(f"/request/{rid}?fragment=1")
            self.get(f"/request/{rid}")
        self.get("/")
        self.get("/?view=all")
        self.get("/?fragment=1")
        self.api("GET", "/v1/audit?limit=500")
        self.api("GET", "/v1/status")
        self.api("GET", "/v1/secrets")
        self.http_with("tokcred", "TOKCRED_TOKEN")
        self.broker.flush_notifications(10)
        self.assertClean()
        # the real values did land in the vault (so the scan above is meaningful)
        self.assertEqual(self.vault_value("tokcred"), TOK)
        self.assertEqual(json.loads(self.vault_value("logcred"))["password"], PW)

    def test_a_failing_and_a_denied_request_leak_nothing_either(self):
        a = self.ask("one")
        self.submit(a["id"], name="one", token=TOK, decision="deny")
        b = self.ask("two")
        with mock.patch.object(self.broker.backend, "put", side_effect=RuntimeError(f"nope {TOK}")):
            self.submit(b["id"], name="two", token=TOK)
        self.result(b["id"])
        self.assertClean()

    def test_the_secret_is_dropped_from_memory_once_the_request_settles(self):
        r = self.ask()
        self.submit(r["id"])
        req = self.settle(r["id"])
        self.assertNotIn("secret", req.spec)
        self.assertNotIn(TOK, repr(req.spec))

    def test_the_secret_does_not_appear_in_the_process_log_output(self):
        # everything the broker writes goes through Broker.log -> the audit log; a stray print would not
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            r = self.ask()
            self.submit(r["id"])
            self.settle(r["id"])
        self.assertNotIn(TOK, buf.getvalue())


class CliFlow(H):
    """The real client/asb against the throwaway broker, in a scratch HOME. The human is simulated
    by posting to the approval page; the CLI is never given a value and never reads stdin."""
    ttl = 30

    def run_cli(self, *args, human=None, stdin=None, timeout=60, extra_env=None):
        env = {"PATH": os.environ["PATH"], "HOME": self.dir, "SECRET_BROKER_URL": self.base,
               "SECRET_BROKER_KEY": KEY}
        env.update(extra_env or {})
        p = subprocess.Popen([CLI, *args], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        if human is not None:
            end = time.time() + 20
            while time.time() < end and not self.broker.pending():
                time.sleep(0.05)
            ids = self.pending_ids()
            if ids:
                human(ids[0])
        try:
            out, err = p.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
        self.seen.extend([out, err])
        return p.returncode, out, err

    def test_stored_exit_0_prints_the_name_and_nothing_secret(self):
        rc, out, err = self.run_cli(
            "request-credential", "clinew", "--kind", "token", "--for", PURPOSE, "--host", "127.0.0.1",
            human=lambda rid: self.submit(rid, name="clinew"), stdin=TOK)
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "stored: clinew")
        for c in ALL_CANARIES:
            self.assertNotIn(c, out + err)
        self.assertEqual(self.vault_value("clinew"), TOK)          # the human's value, not stdin's
        self.assertIn("waiting for the human", err)
        # the request carried exactly the metadata the flags gave
        e = self.events("requested")[0]
        self.assertEqual((e["mode"], e["names"], e["cred_kind"], e["hosts"]), ("credential", ["clinew"], "token", ["127.0.0.1"]))

    def test_cli_never_reads_stdin(self):
        # stdin holds a "secret" that would be fatal to read; the CLI must neither read nor send it
        rc, out, err = self.run_cli(
            "request-credential", "clinew", "--kind", "token", "--for", PURPOSE, "--host", "a.example.com",
            human=lambda rid: self.submit(rid, name="clinew", hosts="a.example.com"), stdin=PW)
        self.assertEqual(rc, 0, err)
        self.assertNotIn(PW, open(self.audit).read())
        self.assertNotEqual(self.vault_value("clinew"), PW)

    def test_login_and_repeated_comma_hosts(self):
        rc, out, err = self.run_cli(
            "request-credential", "portal", "--kind", "login", "--for", "log in", "--host", "a.example.com,b.example.com",
            "--host", "c.example.com", "--var", "PORTAL",
            human=lambda rid: self.submit(rid, name="portal", var="PORTAL", hosts="a.example.com b.example.com c.example.com",
                                          username=USR, password=PW, token=""))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.strip(), "stored: portal")
        e = self.events("requested")[0]
        self.assertEqual(e["hosts"], ["a.example.com", "b.example.com", "c.example.com"])
        self.assertEqual(self.broker.cfg["secrets"]["portal"]["vars"].keys(), {"PORTAL_USERNAME", "PORTAL_PASSWORD"})

    def test_denied_exit_4(self):
        rc, out, err = self.run_cli(
            "request-credential", "clinew", "--kind", "token", "--for", PURPOSE, "--host", "a.example.com",
            human=lambda rid: self.submit(rid, decision="deny"))
        self.assertEqual(rc, 4, err)
        self.assertEqual(out, "")
        self.assertFalse(self.stored("clinew"))

    def test_expired_exit_5(self):
        self.broker.credreq_cfg = dict(self.broker.credreq_cfg, ttl_s=1)
        rc, out, err = self.run_cli("request-credential", "clinew", "--kind", "token", "--for", PURPOSE,
                                    "--host", "a.example.com", timeout=60)
        self.assertEqual(rc, 5, err)
        self.assertIn("expired", err)

    def test_name_collision_exit_3_with_the_update_hint(self):
        rc, out, err = self.run_cli("request-credential", "svc", "--kind", "token", "--for", PURPOSE,
                                    "--host", "a.example.com")
        self.assertEqual(rc, 3)
        self.assertIn("asb update svc", err)

    def test_invalid_name_and_cap_exit_3_and_usage_errors_exit_2(self):
        rc, out, err = self.run_cli("request-credential", "Bad_Name", "--kind", "token", "--for", PURPOSE,
                                    "--host", "a.example.com")
        self.assertEqual(rc, 3)
        self.assertIn("secret name must be", err)
        for args in (["request-credential"],
                     ["request-credential", "x"],
                     ["request-credential", "x", "--kind", "ssh", "--for", "p", "--host", "h"],
                     ["request-credential", "x", "--kind", "token", "--host", "h"],
                     ["request-credential", "x", "--kind", "token", "--for", "", "--host", "h"],
                     ["request-credential", "x", "--kind", "token", "--for", "p"],               # http needs a host
                     ["request-credential", "x", "--kind", "token", "--for", "p", "--mode", "ssh", "--host", "h"],
                     ["request-credential", "x", "--kind", "token", "--for", "p" * 301, "--host", "h"],
                     ["request-credential", "x", "--kind", "token", "--for", "p", "--host", "h", "--value", "v"],
                     ["request-credential", "x", "--kind", "token", "--kind", "login", "--for", "p", "--host", "h"],
                     ["request-credential", "--kind", "token", "--for", "p", "--host", "h"]):
            rc, out, err = self.run_cli(*args)
            self.assertEqual(rc, 2, (args, err))
        self.assertEqual(self.pending_ids(), [])

    def test_env_mode_without_host_is_allowed_to_ask(self):
        rc, out, err = self.run_cli(
            "request-credential", "wifi", "--kind", "token", "--for", "join the guest wifi", "--mode", "env",
            human=lambda rid: self.submit(rid, name="wifi", hosts="", cred_mode="env", no_hosts="1"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.broker.cfg["secrets"]["wifi"]["allowed_hosts"], [])

    def test_the_value_is_never_an_argument_and_help_documents_the_command(self):
        rc, out, err = self.run_cli("help", "request-credential")
        self.assertEqual(rc, 0)
        self.assertIn("secret in an argument", out)
        rc, out, err = self.run_cli("guide")
        self.assertIn("request-credential", out)
        rc, out, err = self.run_cli("request-credential", "--help")
        self.assertEqual(rc, 0)

    def test_the_cli_then_uses_the_new_credential(self):
        rc, out, err = self.run_cli(
            "request-credential", "clinew", "--kind", "token", "--for", PURPOSE, "--host", "127.0.0.1",
            human=lambda rid: self.submit(rid, name="clinew"))
        self.assertEqual(rc, 0, err)
        port = self.up.server_address[1]

        def human(rid):
            self.post("/decide", {"id": rid, "decision": "approve", "csrf": self.csrf()})
        rc, out, err = self.run_cli("http", "clinew", "GET", f"http://127.0.0.1:{port}/x",
                                    "-H", "Authorization: Bearer {{CLINEW_TOKEN}}", human=human)
        self.assertEqual(rc, 0, err)
        self.assertEqual(Rec.seen, ["Bearer " + TOK])
        self.assertNotIn(TOK, out + err)


class LocalBackendFlow(H):
    """Restart persistence on the encrypted local backend."""
    PASS = "correct horse battery staple (fake)"

    def make_backend(self, d):
        self.store = os.path.join(d, "store.enc")
        self.keyfile = os.path.join(d, "key")
        with open(self.keyfile, "w") as f:
            f.write(self.PASS + "\n")
        os.chmod(self.keyfile, 0o600)
        ls.create_store(self.store, ls.Key(self.PASS))
        return LocalBackend(self.store, ls.FileKeySource(self.keyfile), 300)

    def reopen(self):
        return LocalBackend(self.store, ls.FileKeySource(self.keyfile), 300)

    def test_stored_credential_survives_a_restart_and_works(self):
        r = self.ask("persist", kind="login")
        self.assertEqual(self.submit(r["id"], name="persist", username=USR, password=PW, token="")[0], 200)
        t0 = self.reopen()
        b2 = Broker({"approve_base_url": "https://secrets.example", "allowed_user": "alice", "secrets": {}},
                    t0, FakeNotifier(), os.path.join(self.dir, "audit2.jsonl"))
        sc = b2.cfg["secrets"]["persist"]
        self.assertEqual(set(sc["vars"]), {"PERSIST_USERNAME", "PERSIST_PASSWORD"})
        self.assertEqual(sc["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(sc["approval"], "prompt")
        self.assertEqual(json.loads(t0.get("persist", "notes")), {"username": USR, "password": PW})
        # the store file holds no plaintext secret
        data = open(self.store, "rb").read()
        for c in ALL_CANARIES:
            self.assertNotIn(c.encode(), data)
        # a second request for the same name is now a collision
        code, text = t.req(self.base + "/v1/requests", "POST", {
            "mode": "credential", "names": ["persist"], "kind": "token", "purpose": PURPOSE, "hosts": ["a.example.com"]},
            {"X-Client-Key": KEY, "Content-Type": "application/json"})
        self.assertEqual(code, 400)

    def test_token_flow_on_local(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"])[0], 200)
        self.assertEqual(self.vault_value("newapi"), TOK)
        self.assertEqual(self.http_with("newapi", "NEWAPI_TOKEN")["http"]["status"], 200)
        self.assertEqual(Rec.seen, ["Bearer " + TOK])


class MemoryBackendFlow(H):
    def make_backend(self, d):
        return MemoryBackend()

    def test_token_and_login_flow(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"])[0], 200)
        self.assertEqual(self.http_with("newapi", "NEWAPI_TOKEN")["http"]["status"], 200)
        r2 = self.ask("site", kind="login")
        self.assertEqual(self.submit(r2["id"], name="site", username=USR, password=PW, token="")[0], 200)
        self.assertEqual(json.loads(self.vault_value("site"))["username"], USR)


class BitwardenFakeFlow(H):
    """Against the fake `bw` of test_e2e (no network, no real vault)."""

    def make_backend(self, d):
        self.state = os.path.join(d, "state.json")
        bw = os.path.join(d, "bw")
        with open(bw, "w") as f:
            f.write(t.FAKE_BW)
        os.chmod(bw, 0o755)
        os.environ["FAKE_BW_STATE"] = self.state
        self.addCleanup(os.environ.pop, "FAKE_BW_STATE", None)
        pw = os.path.join(d, "pw")
        with open(pw, "w") as f:
            f.write("m")
        return BwBackend("https://v.example", pw, bw=bw, idle_timeout=0, organization="Org", collection="Shared")

    def test_token_and_login_flow(self):
        r = self.ask()
        self.assertEqual(self.submit(r["id"])[0], 200)
        self.assertEqual(self.vault_value("newapi"), TOK)
        self.assertEqual(self.http_with("newapi", "NEWAPI_TOKEN")["http"]["status"], 200)
        r2 = self.ask("site", kind="login")
        self.assertEqual(self.submit(r2["id"], name="site", username=USR, password=PW, token="")[0], 200)
        self.assertEqual(json.loads(self.vault_value("site")), {"username": USR, "password": PW})
        self.assertEqual(set(self.broker.cfg["secrets"]["site"]["vars"]), {"SITE_USERNAME", "SITE_PASSWORD"})
        self.assertTrue(self.broker.cfg["secrets"]["newapi"]["allowed_hosts"])
        with open(self.state) as f:
            self.assertNotIn("approval", f.read().replace('\\"approval\\"', ""))     # smoke: state is plain JSON

    def test_conflict_is_reported_not_overwritten(self):
        self.broker.backend.put("newapi", "notes", "keep-me", create=True)
        r = self.ask()
        self.assertEqual(self.submit(r["id"])[0], 500)
        self.assertEqual(self.vault_value("newapi"), "keep-me")


class UnitHelpers(unittest.TestCase):
    def test_purpose_validation(self):
        self.assertEqual(credreq.validate_purpose("  read it  "), "read it")
        for bad in ("", "a\nb", "a" * 301, 5, "x​y"):
            with self.assertRaises(ValueError):
                credreq.validate_purpose(bad)

    def test_default_vars(self):
        self.assertEqual(credreq.default_vars("my-api", "token"), {"token": "MY_API_TOKEN"})
        self.assertEqual(credreq.default_vars("my-api", "token", "KEY"), {"token": "KEY"})
        self.assertEqual(credreq.default_vars("site", "login"), {"username": "SITE_USERNAME", "password": "SITE_PASSWORD"})
        self.assertEqual(credreq.default_vars("site", "login", "X"), {"username": "X_USERNAME", "password": "X_PASSWORD"})

    def test_form_never_fills_in_a_secret(self):
        class R:
            id, names, source, expires = "rid1", ["n"], "src", time.time() + 50
            spec = {"kind": "login", "purpose": "p", "hosts": [], "var": None, "cred_mode": "http"}
        body = credreq.form_html(R, "c" * 64, {"name": "n2", "hosts": "x.example.com", "token": TOK,
                                               "password": PW, "username": USR}, ["bad thing"])
        for c in ALL_CANARIES:
            self.assertNotIn(c, body)
        self.assertIn("bad thing", body)
        self.assertIn("value='n2'", body)


if __name__ == "__main__":
    unittest.main()
