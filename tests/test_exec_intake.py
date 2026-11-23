"""Request mode `exec`, broker side up to the approval: who may ask, which key and host, how it is rated,
what the card, the notification and the audit log show, and what a decision can and cannot do.

The runner itself is replaced by a fake (`Broker._exec_run`); tests/test_execrun.py covers the real one.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import sys
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
from test_client_rules import ClientMixin  # noqa: E402
from secret_broker import audit_api  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import execmode, riskmodel, sshkey  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402


def host_line(names, key=None):
    key = key or ed25519.Ed25519PrivateKey.generate()
    blob = sshkey.public_blob(key)
    return f"{names} ssh-ed25519 {base64.b64encode(blob).decode()}"


FP_ONLY = "SHA256:" + "A" * 43
NAS, PORT, LOCAL, UNLISTED, FRESH = (ed25519.Ed25519PrivateKey.generate() for _ in range(5))
SSH_HOSTS = {"known_hosts": [host_line("nas.example.com", NAS), host_line("[port.example.com]:2222", PORT),
                             host_line("127.0.0.1", LOCAL), host_line("unlisted.example.com", UNLISTED)],
             "allowed_hosts": ["nas.example.com", "port.example.com", "127.0.0.1", "nopin.example.com", FP_ONLY]}


def probe_result(key):
    """What execprobe returns for a server that presents `key` (an ed25519 private key object)."""
    blob = sshkey.public_blob(key)
    line = sshkey.public_line(key)
    k = {"key_type": "ssh-ed25519", "key": line, "fingerprint": sshkey.fingerprint(blob)}
    return {"keys": [k], **k, "address": "93.184.216.34"}


class Servers:
    """A stand-in for the broker's probe: what each (host, port) presents. By default every host in SSH_HOSTS
    presents its pinned key and anything else presents FRESH, so a test changes only what it is about."""

    def __init__(self):
        self.calls = []
        self.table = {("nas.example.com", 22): NAS, ("port.example.com", 2222): PORT, ("127.0.0.1", 22): LOCAL,
                      ("unlisted.example.com", 22): UNLISTED}
        self.default = FRESH

    def __call__(self, host, port, client_id):
        self.calls.append((host, port, client_id))
        got = self.table.get((host, port), self.default)
        return got if isinstance(got, dict) else probe_result(got)


class Model:
    """An analyzer that records what it was asked and what guidance came with it, and answers `risk`."""

    def __init__(self, risk=None):
        self.risk, self.calls = risk, []

    def analyze(self, mode, names, spec, guidance=None):
        self.calls.append((mode, dict(spec), guidance))
        return {"summary": "Does a thing", "risk": self.risk, "cost": None, "summary_source": "model",
                "summary_reason": None, "summary_rule": None, "summary_model": "test-model"}

    summarize = analyze


class ExecBase(ClientMixin, tg.Base):
    guidance_text = None

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["deploy"]["ssh_hosts"] = SSH_HOSTS
        if self.guidance_text:
            cfg["secrets"]["deploy"]["guidance"] = self.guidance_text

    def setUp(self):
        super().setUp()
        self.agent = self.mk("exec-agent")
        self.other = self.mk("someone-else")
        self.model = Model()
        self.broker.summarizer = self.model
        self.servers = Servers()
        self.broker.exec_probe = self.servers
        self.ran = []
        self.broker._exec_run = lambda req: self.ran.append(req.id) or {
            "exit_code": 0, "stdout": "ok\n", "stderr": "", "truncated": False, "label": None}
        self.enable()

    def enable(self, **kw):
        self.broker.exec_cfg = execmode.parse_config({"enabled": True, "clients": [self.agent.id], **kw})

    def ask_raw(self, c=None, **body):
        """The POST alone: what the agent gets back, with the background host check left to finish on its own."""
        body = {"mode": "exec", "names": ["deploy"], "host": "nas.example.com", "user": "ryan",
                "command": "uptime", **body}
        return self.api("POST", "/v1/requests", {k: v for k, v in body.items() if v is not _OMIT},
                        key=(c or self.agent).secret)

    def ask(self, c=None, **body):
        """The POST, then wait for the request's background host check to be fully acted on (the tests that are about
        what happens after it want it done; test_exec_unpinned.Background drives it by hand)."""
        code, b = self.ask_raw(c, **body)
        if code == 202:
            self.assertTrue(self.broker._by_id[json.loads(b)["id"]].exec_settled.wait(20), "the host check never finished")
        return code, b

    def pending(self, **body):
        code, b = self.ask(**body)
        self.assertEqual(code, 202, b)
        rid = json.loads(b)["id"]
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        return rid

    def poll(self, rid, wait=0, c=None):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait={wait}", key=(c or self.agent).secret)
        return json.loads(b)


_OMIT = object()


class Access(ExecBase):
    def test_off_by_default_and_disabled_refuses_a_listed_client(self):
        self.assertEqual(self.ask()[0], 202)                       # positive control: enabled and listed
        self.broker.exec_cfg = execmode.parse_config(None)
        code, b = self.ask()
        self.assertEqual((code, json.loads(b)["error"]), (403, "remote command requests are disabled"))
        self.broker.exec_cfg = execmode.parse_config({"enabled": False, "clients": [self.agent.id]})
        self.assertEqual(self.ask()[0], 403)

    def test_only_listed_clients_and_never_the_legacy_key(self):
        self.assertEqual(self.ask()[0], 202)
        for key in (self.other.secret, t.KEY):
            code, b = self.api("POST", "/v1/requests", {"mode": "exec", "names": ["deploy"], "host": "nas.example.com",
                                                        "user": "ryan", "command": "uptime"}, key=key)
            self.assertEqual((code, json.loads(b)["error"]), (403, "this client may not make remote command requests"))
        # the legacy key is refused even when the list names every id
        self.broker.exec_cfg = execmode.parse_config({"enabled": True, "clients": [self.agent.id, self.other.id]})
        code, _ = self.api("POST", "/v1/requests", {"mode": "exec", "names": ["deploy"], "host": "nas.example.com",
                                                    "user": "ryan", "command": "uptime"}, key=t.KEY)
        self.assertEqual(code, 403)
        self.assertEqual(self.ask(c=self.other)[0], 202)           # control: a listed id passes

    def test_the_names_must_be_exactly_one_ssh_key(self):
        self.assertEqual(self.ask(names=["deploy"])[0], 202)
        for names, want in ((["deploy", "svc"], "exactly one ssh key"), (["svc"], "needs an ssh key credential"),
                            (["nope"], "unknown secret name"), ([], "exactly one ssh key")):
            code, b = self.ask(names=names)
            self.assertEqual(code, 400, (names, b))
            self.assertIn(want, json.loads(b)["error"])

    def test_pending_cap_per_client(self):
        self.enable(max_pending_per_client=2)
        self.pending()
        self.pending()
        code, b = self.ask()
        self.assertEqual((code, json.loads(b)["error"]), (403, "too many pending remote command requests"))
        self.assertEqual(self.ask(c=self.other)[0], 403)           # not listed: still refused, not capped
        self.enable(max_pending_per_client=3, clients=[self.agent.id, self.other.id])
        self.assertEqual(self.ask(c=self.other)[0], 202)           # another client has its own count

    def test_unknown_fields_are_refused(self):
        self.assertEqual(self.ask()[0], 202)
        for extra in ({"ssh_options": ["-oProxyCommand=x"]}, {"env": {"A": "b"}}, {"identity": "/x"}, {"cwd": "/"}):
            code, b = self.ask(**extra)
            self.assertEqual((code, json.loads(b)["error"]), (400, "unknown field in an exec request"), extra)


class Hosts(ExecBase):
    """What a request for a host the key pins does, and that what is NOT pinned is no longer refused here (it goes
    to a human: tests/test_exec_unpinned.py). What is still refused is a host that is not a plain name."""

    def refused(self, code_want, **body):
        before = len(self.events("requested"))
        code, b = self.ask(**body)
        self.assertEqual(code, code_want, (body, b))
        self.assertEqual(len(self.events("requested")), before, "a refused request is never recorded as requested")
        self.assertEqual(self.ran, [])
        self.assertTrue(self.events("rejected"))
        return json.loads(b)["error"]

    def test_a_pinned_named_host_is_accepted_and_is_an_ordinary_request(self):
        self.enable(max_pending_per_client=20)
        for host, port in (("nas.example.com", 22), ("NAS.Example.COM", 22), ("port.example.com", 2222), ("127.0.0.1", 22)):
            for r in self.broker._by_id.values():           # nobody answers here: keep under MAX_PENDING
                r.status = "expired"
            code, b = self.ask(host=host, port=port)
            self.assertEqual(code, 202, (host, b))
            self.assertNotIn("host_state", self.broker._by_id[json.loads(b)["id"]].spec, host)
        sp = self.broker._by_id[json.loads(b)["id"]].spec
        self.assertEqual((sp["host"], sp["port"]), ("127.0.0.1", 22))

    def test_the_host_is_lowercased_before_it_is_compared_and_stored(self):
        rid = json.loads(self.ask(host="NAS.Example.COM")[1])["id"]
        self.assertEqual(self.broker._by_id[rid].spec["host"], "nas.example.com")
        self.assertEqual(self.servers.calls[-1][:2], ("nas.example.com", 22))

    def test_fingerprint_entry_is_not_a_name(self):
        self.assertIn("plain host name", self.refused(400, host=FP_ONLY))   # not even a host name
        self.assertEqual(self.ask()[0], 202)

    def test_syntax_that_is_not_a_host_name_is_refused_before_any_probe(self):
        for host in ("nas.example.com.", "nas.example.com ", " nas.example.com", "nas.example.com\n", "nas.example.com:22",
                     "nas.example.com@x", "nas.example.com/", "nas.example.com%00", "-oProxyCommand=x", "[::1]",
                     "n\u0430s.example.com"):
            self.assertIn("plain host name", self.refused(400, host=host), repr(host))
        self.assertEqual(self.servers.calls, [])                    # nothing odd was ever looked at
        self.assertEqual(self.ask(host="nas.example.com")[0], 202)
        self.assertEqual(len(self.servers.calls), 1)                # positive control: a good one probes

    def test_user_and_port_are_checked(self):
        for body in ({"user": "-oProxyCommand=x"}, {"user": "a b"}, {"port": 0}, {"port": 70000}, {"port": "22"},
                     {"timeout_s": 0}, {"timeout_s": 601}, {"command": "-x"}, {"command": _OMIT}):
            self.refused(400, **body)
        self.assertEqual(self.servers.calls, [])
        self.assertEqual(self.ask(user="ryan", port=22, timeout_s=600)[0], 202)


class Rating(ExecBase):
    def test_simple_read_only_command_is_low_without_a_model_call(self):
        rid = self.pending(command="systemctl status nginx")
        self.assertEqual(self.model.calls, [])
        a = self.events("assessed")[-1]
        self.assertEqual((a["risk"], a["model"]), ("low", None))
        self.assertIn("read-only", a["reasons"][0])
        self.assertEqual(self.broker._by_id[rid].risk["level"], "low")
        self.assertEqual(self.broker._by_id[rid].summary_source, "deterministic")

    def test_non_simple_command_goes_to_the_model_and_defaults_to_high(self):
        rid = self.pending(command="systemctl status nginx; reboot")
        self.assertEqual([c[0] for c in self.model.calls], ["exec"])        # positive control: the model was asked
        self.assertEqual(self.broker._by_id[rid].risk["level"], "high")
        self.assertIn("no model verdict", " ".join(self.broker._by_id[rid].risk["reasons"]))
        self.assertIn("shell syntax", self.broker._by_id[rid].risk["reasons"][0])

    def test_off_the_table_command_goes_to_the_model(self):
        self.model.risk = "medium"
        rid = self.pending(command="systemctl restart nginx")
        self.assertEqual(len(self.model.calls), 1)
        self.assertEqual(self.broker._by_id[rid].risk["level"], "medium")

    def test_a_script_goes_to_the_model_and_the_table_never_lowers_it(self):
        rid = self.pending(command=_OMIT, script={"text": "uptime", "interpreter": "sh"})
        self.assertEqual(len(self.model.calls), 1)
        self.assertIn("script", self.model.calls[0][1])
        self.assertEqual(self.broker._by_id[rid].risk["level"], "high")

    def test_the_model_can_lower_a_non_simple_command(self):
        self.model.risk = "low"
        rid = self.pending(command="ls /tmp | wc -l")
        self.assertEqual(self.broker._by_id[rid].risk["level"], "low")

    def test_the_model_gets_the_credentials_guidance(self):
        self.guidance_text = None
        self.broker.cfg["secrets"]["deploy"]["guidance"] = "S3CR3T-guidance only restart nginx"
        self.pending(command="echo hi | cat")
        self.assertIn("S3CR3T-guidance", json.dumps(self.model.calls[0][2]))

    def test_what_the_model_sees_is_scrubbed_and_lookalikes_are_visible(self):
        secret = "S3CR3T-" + "x" * 40
        spec = {"host": "nas.example.com", "user": "ryan", "port": 22, "timeout_s": 60,
                "command": f"curl -H 'Authorization: Bearer {secret}' http://x/а --data password=hunter2xx"}
        f = riskmodel.request_fields("exec", ["deploy"], spec)
        self.assertEqual((f["host"], f["account"], f["mode"]), ("nas.example.com", "ryan", "exec"))
        self.assertIn("<redacted>", f["command"])                       # the scrubber ran: positive control
        self.assertIn("<U+0430>", f["command"])
        for leak in (secret, "hunter2xx"):
            self.assertNotIn(leak, json.dumps(f))
        sc = {**spec, "script": {"text": f"export TOKEN={secret}\nid", "interpreter": "sh"}}
        sc.pop("command")
        f = riskmodel.request_fields("exec", ["deploy"], sc)
        self.assertIn("<redacted>", f["script_text"])
        self.assertNotIn(secret, json.dumps(f))

    def test_approval_allow_needs_exec_in_the_keys_auto_modes(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc["approval"] = "allow"
        rid = self.pending(command="uptime")                           # an ssh key defaults to ["ssh_sign"]
        self.assertEqual(self.ran, [])
        sc["auto_modes"] = ["ssh_sign", "exec"]
        code, b = self.ask(command="uptime")
        self.assertEqual(code, 202, b)
        rid2 = json.loads(b)["id"]
        self.broker._by_id[rid2].done.wait(10)
        self.assertEqual(self.ran, [rid2])
        self.assertEqual(self.broker._by_id[rid2].risk["level"], "low")
        self.assertNotEqual(rid, rid2)

    def test_approval_allow_respects_the_risk_ceiling(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc.update(approval="allow", auto_modes=["exec"])
        self.model.risk = "medium"
        code, b = self.ask(command="systemctl restart nginx")
        self.assertEqual(code, 202, b)
        self.assertEqual(self.ran, [])                                 # medium is above the default ceiling (low)
        self.assertEqual(self.events("escalated")[-1]["auto_max"], "low")


class Surfaces(ExecBase):
    def card(self, rid):
        nonce = self.broker._by_id[rid].nonce
        return self.get(f"/a/{nonce}")[1]

    def test_card_shows_host_account_and_the_command_that_runs(self):
        rid = self.pending(command="ls '/tmp/a b' \"caf\u00e9\"")
        card = self.card(rid)
        self.assertIn("<b>Run on nas.example.com</b> as <code>ryan</code>", card)
        self.assertIn("<code>ls &#x27;/tmp/a b&#x27; &#x27;caf<span class=gu title=\"\u00e9\">&lt;U+00E9&gt;</span>&#x27;</code>",
                      card)

    def test_card_for_a_script_shows_the_full_text_and_its_hash(self):
        text = "set -e\necho 'hello <b>'\n"
        rid = self.pending(command=_OMIT, script={"text": text, "interpreter": "bash"})
        card = self.card(rid)
        sha = execmode.script_sha256(self.broker._by_id[rid].spec)
        self.assertIn(sha, card)
        self.assertIn("set -e", card)
        self.assertIn("&lt;b&gt;", card)                                # escaped, not markup
        self.assertNotIn("<b>'", card)
        self.assertIn("bash script", card)

    def test_card_shows_the_requoted_command_and_visible_lookalikes(self):
        rid = self.pending(command="echo   'a b'  а")
        card = self.card(rid)
        self.assertIn("echo &#x27;a b&#x27; ", card)                    # rebuilt: single spaces
        self.assertIn("U+0430", card)
        self.assertNotIn("а", card.replace("title=\"а\"", ""))   # only the tooltip carries the real character

    def test_card_offers_approve_and_deny_only(self):
        rid = self.pending()
        card = self.card(rid)
        self.assertIn("value=approve>", card)
        self.assertIn("value=deny>", card)
        for chip in ("approve_always", "approve_grant_", "Automatically approve...", "ssh_rule", "chip always", "class=chip"):
            self.assertNotIn(chip, card, chip)

    def test_notification_carries_host_account_command_and_a_link_but_never_a_script(self):
        self.pending(command="systemctl status nginx")
        n = self.notifier.notifications[-1]
        self.assertIn("run on nas.example.com as ryan: systemctl status nginx", n.text)
        self.assertIn("LOW", n.title)
        self.assertTrue(n.url.startswith("https://secrets.example/a/"))
        body = "echo S3CR3T-script-body"
        self.pending(command=_OMIT, script={"text": body})
        n = self.notifier.notifications[-1]
        self.assertIn("run on nas.example.com as ryan: a script", n.text)
        self.assertNotIn("S3CR3T-script-body", n.text)
        self.assertNotIn("S3CR3T-script-body", json.dumps(self.notifier.sent))

    def test_long_command_is_clipped_in_the_notification(self):
        self.pending(command="echo " + "x" * 3000)
        n = self.notifier.notifications[-1]
        self.assertLess(len(n.text), 900)
        self.assertIn("run on nas.example.com", n.text)

    def test_buttons_follow_the_http_action_policy(self):
        self.broker.notifier = FakeNotifier(supports_actions=("approve", "deny"))
        rid = self.pending()
        req = self.broker._by_id[rid]
        self.assertEqual(req.offered, frozenset({"approve", "deny"}))     # positive control: buttons exist
        self.assertIsNotNone(req.action_hash)

    def test_history_row_names_the_host_and_command(self):
        rid = self.pending(command="uptime")
        self.decide(rid, "deny")
        page = self.get("/history?view=all")[1]
        self.assertIn("run on nas.example.com: uptime", page)


class Decisions(ExecBase):
    def test_always_grant_and_rules_cannot_cover_it_and_claim_nothing(self):
        rid = self.pending()
        req = self.broker._by_id[rid]
        self.assertFalse(self.broker.grant_eligibility(req)[0])
        self.assertFalse(self.broker.always_allow_eligibility(req)[0])
        self.assertEqual(self.broker.ssh_rule_chip(req), None)
        for kw in ({"always": True}, {"always": "script"}, {"grant_minutes": 5}, {"ssh_rule": {"days": 1}},
                   {"rule_scope": "any", "always": True}):
            code, got = self.broker.decide_via("dashboard", rid, "approve", "alice", **kw)
            self.assertIn(code, (400, 403, 409), kw)
            self.assertIsNone(got)
            self.assertEqual(req.status, "pending", kw)
        self.assertEqual(self.events("approved"), [])
        self.assertEqual(self.ran, [])
        code, _ = self.broker.decide_via("dashboard", rid, "approve", "alice")        # positive control: a plain approve
        self.assertEqual(code, 200)
        req.done.wait(10)
        self.assertEqual(self.ran, [rid])

    def test_the_always_form_value_is_refused_on_the_card_post(self):
        rid = self.pending()
        for decision in ("approve_always", "approve_grant_5"):
            self.decide(rid, decision)
            self.assertEqual(self.broker._by_id[rid].status, "pending", decision)
        self.assertEqual(self.events("approved"), [])

    def test_result_is_running_then_released_once_with_the_output(self):
        gate = threading.Event()

        def run(req):
            gate.wait(10)
            return {"exit_code": 3, "stdout": "out\n", "stderr": "err\n", "truncated": False, "label": None}
        self.broker._exec_run = run
        rid = self.pending()
        self.assertEqual(self.poll(rid), {"status": "pending", "error": None})
        self.decide(rid, "approve")
        self.assertEqual(self.poll(rid), {"status": "running"})
        gate.set()
        self.broker._by_id[rid].done.wait(10)
        got = self.poll(rid)
        self.assertEqual(got, {"status": "released", "exit_code": 3, "stdout": "out\n", "stderr": "err\n",
                               "truncated": False, "label": None})
        self.assertEqual(self.poll(rid), {"status": "released"})              # delivered once
        self.assertEqual(self.poll(rid, c=self.other).get("exit_code"), None)  # another client sees nothing

    def test_denial_is_final(self):
        rid = self.pending()
        self.decide(rid, "deny")
        self.assertEqual(self.poll(rid)["status"], "denied")
        self.assertEqual(self.ran, [])


class Audit(ExecBase):
    def test_requested_event_has_the_words_and_where_not_the_script(self):
        self.pending(command="systemctl status " + "/ab" * 140)
        ev = self.events("requested")[-1]
        self.assertEqual((ev["host"], ev["account"], ev["port"]), ("nas.example.com", "ryan", 22))
        self.assertEqual(ev["argv"][:2], ["systemctl", "status"])
        self.assertEqual(len(ev["argv"][2]), 300)
        text = "echo S3CR3T-script-body\n"
        rid = self.pending(command=_OMIT, script={"text": text})
        ev = self.events("requested")[-1]
        self.assertEqual(ev["script_digest"], execmode.script_sha256(self.broker._by_id[rid].spec))
        self.assertEqual(ev["script_len"], len(text))
        self.assertNotIn("argv", ev)
        raw = open(self.audit).read()
        self.assertIn("script_digest", raw)                                    # positive control: the event is there
        self.assertNotIn("S3CR3T-script-body", raw)

    def test_the_agent_audit_view_hides_the_run_and_shows_the_request(self):
        self.assertIn("exec_started", audit_api.HIDDEN)
        self.assertIn("exec_finished", audit_api.HIDDEN)
        self.assertEqual(set(audit_api.WHITELIST) & audit_api.HIDDEN, set())
        for k in ("host", "account", "argv"):
            self.assertIn(k, audit_api.WHITELIST["requested"])

    def test_status_reports_the_feature(self):
        _, b = self.api("GET", "/v1/status", key=self.agent.secret)
        self.assertIs(json.loads(b)["features"]["exec"], True)
        self.broker.exec_cfg = execmode.parse_config(None)
        _, b = self.api("GET", "/v1/status", key=self.agent.secret)
        self.assertIs(json.loads(b)["features"]["exec"], False)


if __name__ == "__main__":
    unittest.main()
