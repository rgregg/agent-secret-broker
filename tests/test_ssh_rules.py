"""Standing per-host SSH rules (GitHub issue #10): a rule is credential + verified
host key fingerprint + account. Creation from the approval card, matching,
refusal ordering, the Policies tab, expiry, audit and hiding."""
import base64
import json
import os
import stat
import sys
import threading
import time
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_ssh as ts  # noqa: E402
import test_ssh_host as th  # noqa: E402
from secret_broker import audit_api, sshkey, sshrules  # noqa: E402
from secret_broker.backends import MemoryBackend  # noqa: E402
from secret_broker.broker import CHANNELS, Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

HOST, OTHER, THIRD = th.Host(), th.Host(), th.Host()
SID_A, SID_B = th.SID_A, th.SID_B
login, hostbound = th.login, th.hostbound
SSHSIG = b"SSHSIG" + ts._s(b"git") + ts._s(b"") + ts._s(b"sha512") + ts._s(b"h" * 64)
FUTURE = sshrules.iso(time.time() + 86400 * 365)
PAST = sshrules.iso(time.time() - 3600)
_n = [0]


def R(host, user="deploy", label=None, expires=None, by="alice"):
    """A stored rule for `host` (a Host or a fingerprint string)."""
    _n[0] += 1
    return {"id": f"r{_n[0]:04d}", "fp": getattr(host, "fp", host), "user": user, "host": label,
            "by": by, "at": "2026-10-01T00:00:00Z", "expires_at": expires}


class NoMeta:
    """A backend that cannot write metadata."""

    def __init__(self, inner):
        self._inner = inner

    @property
    def capabilities(self):
        return self._inner.capabilities - {"set_meta"}

    def __getattr__(self, name):
        return getattr(self._inner, name)


class Base(th.HostBase):
    decision = None
    ttl = 600
    rules = None
    rules2 = None
    auto_max = None

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.rules is not None:
            cfg["secrets"]["deploy"]["ssh_rules"] = self.rules
        if self.auto_max:
            cfg["risk"] = {"auto_approve_max": self.auto_max}
        pem = ts._openssh(ed25519.Ed25519PrivateKey.generate())
        cfg["_vault"]["Deploykey2"] = {"private_key": pem}
        cfg["secrets"]["deploy2"] = {
            "vars": {"DEPLOY2_SSH_KEY": {"item": "Deploykey2", "field": "private_key"}},
            "allowed_hosts": [], "ssh": True,
            "ssh_public_key": sshkey.public_line(sshkey.load_private(pem))}
        if self.rules2 is not None:
            cfg["secrets"]["deploy2"]["ssh_rules"] = self.rules2

    # -- requests
    def ask(self, data, binds=None, name="deploy", claimed=None):
        for r in self.broker._by_id.values():
            if r.status == "pending":
                r.status = "expired"
        body = {"mode": "ssh_sign", "names": [name], "flags": 0, "data_b64": base64.b64encode(data).decode()}
        if binds is not None:
            body["binds"] = binds
        if claimed is not None:
            body["claimed_dest"] = claimed
        code, raw = self.api("POST", "/v1/requests", body)
        return code, (json.loads(raw) if code == 202 else raw)

    def ask_ok(self, *a, **k):
        code, body = self.ask(*a, **k)
        self.assertEqual(code, 202, body)
        return body["id"]

    def result(self, rid, wait=5):
        return json.loads(self.api("GET", f"/v1/requests/{rid}?wait={wait}")[1])

    def released(self, rid):
        return self.result(rid)["status"] in ("approved", "released")

    def r(self, rid):
        return self.broker._by_id[rid]

    # -- pages
    H = {"X-authentik-username": "alice"}

    def link_page(self, rid):
        return t.req(self.abase + f"/a/{self.r(rid).nonce}", headers=self.H)[1]

    def dashboard(self):
        return t.req(self.abase + "/", headers=self.H)[1]

    def decide(self, rid, decision, via="dashboard", expiry=None, extra=None, user="alice"):
        form = {"decision": decision, **(extra or {})}
        if expiry is not None:
            form["ssh_rule_expiry"] = expiry
        if via == "dashboard":
            form.update(id=rid, csrf=self.broker.csrf_token(user))
            url = self.abase + "/decide"
        else:
            url = self.abase + f"/a/{self.r(rid).nonce}"

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            r = urllib.request.build_opener(NoFollow).open(urllib.request.Request(
                url, data=urllib.parse.urlencode(form).encode(), headers={"X-authentik-username": user},
                method="POST"), timeout=10)
            return r.status, r.headers.get("Location"), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode()

    def stored_rules(self, name="deploy"):
        return self.disk()["secrets"][name].get("ssh_rules", [])

    def live_rules(self, name="deploy"):
        return self.broker.cfg["secrets"][name].get("ssh_rules", [])

    def sent(self):
        return len(self.notifier.sent)

    def known(self, host, names):
        self.broker.cfg["secrets"]["deploy"]["ssh_hosts"] = {
            "known": {host.fp: names}, "allowed": None, "allow_forwarded": False}


KNOWN = {"known_hosts": [HOST.line("web.example.com,10.0.0.5")]}


# ------------------------------------------------------------------ creation from the card
class CardChip(Base):
    ssh_hosts = KNOWN

    def test_chip_and_confirm_markup_on_card_and_dashboard(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        for page in (self.link_page(rid), self.dashboard()):
            self.assertEqual(page.count("approve_ssh_rule"), 1)
            self.assertIn("Automatically approve...", page)
            self.assertIn("Always: this host", page)
            self.assertIn("Always approve deploy@web.example.com with this key?", page)
            self.assertIn("name=ssh_rule_expiry", page)
            self.assertIn("Never expires (default)", page)
            self.assertIn("<option value=30>30 days</option>", page)
            self.assertIn("<option value=90>90 days</option>", page)
            self.assertIn(HOST.fp, page)                         # in the tip
        self.assertIn("name=decision value=approve_ssh_rule>Confirm</button>", self.link_page(rid))

    def test_unnamed_server_shows_short_fingerprint(self):
        rid = self.ask_ok(login(SID_A), [OTHER.bind(SID_A)])
        self.assertIn(f"Always approve deploy@{OTHER.fp[:19]} with this key?", self.link_page(rid))

    def test_hostbound_login_data_is_eligible(self):
        rid = self.ask_ok(hostbound(SID_A, HOST))
        self.assertIn("approve_ssh_rule", self.link_page(rid))

    def test_hostile_account_is_escaped(self):
        rid = self.ask_ok(login(SID_A, "<b>x</b>"), [HOST.bind(SID_A)])
        page = self.link_page(rid)
        self.assertIn("approve_ssh_rule", page)
        self.assertNotIn("<b>x</b>@", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;@web.example.com", page)

    def test_ineligible_variants_have_no_chip(self):
        cases = {
            "unbound": (login(SID_A), None),
            "unbound with claim": (login(SID_A), None),
            "forwarded": (login(SID_A), [HOST.bind(SID_A, forwarding=True)]),
            "bind_invalid": (hostbound(SID_A, HOST), [HOST.bind(SID_A, sig=b"x" * 20)]),
            "sshsig": (SSHSIG, None),
            "two hops": (login(SID_A), [OTHER.bind(SID_B), HOST.bind(SID_A)]),
            "chain mismatch": (login(SID_A), [HOST.bind(SID_A), OTHER.bind(SID_B)]),
            "no account (non-ssh-connection service)": (ts.userauth_blob(service="ssh-userauth"), None),
        }
        for label, (data, binds) in cases.items():
            rid = self.ask_ok(data, binds)
            self.assertNotIn("approve_ssh_rule", self.link_page(rid), label)
            self.assertNotIn("Always: this host", self.dashboard(), label)

    def test_host_not_on_allowed_list_no_chip(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.assertIn("approve_ssh_rule", self.link_page(rid))
        self.broker.cfg["secrets"]["deploy"]["ssh_hosts"]["allowed"] = [OTHER.fp]   # edited meanwhile
        self.assertNotIn("approve_ssh_rule", self.link_page(rid))
        self.assertEqual(self.decide(rid, "approve_ssh_rule", "link")[0], 409)
        self.assertEqual(self.r(rid).status, "pending")

    def test_no_set_meta_backend_no_chip(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.broker.backend = NoMeta(self.broker.backend)
        self.assertNotIn("approve_ssh_rule", self.link_page(rid))
        self.decide(rid, "approve_ssh_rule", "dashboard")
        self.assertEqual(self.events("ssh_rule_refused")[-1]["reason"], "backend")
        self.assertEqual(self.r(rid).status, "pending")

    def test_http_requests_never_have_it(self):
        self.api("POST", "/v1/requests", {"mode": "http", "names": ["svc"], "method": "GET",
                                          "url": f"http://127.0.0.1:{self.up.server_address[1]}/x",
                                          "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        dash = self.dashboard()
        self.assertIn("svc", dash)
        self.assertNotIn("approve_ssh_rule", dash)


class CardCap(Base):
    ssh_hosts = KNOWN
    rules = [R(sshkey.fingerprint(os.urandom(32)), user=f"u{i}") for i in range(sshrules.MAX_RULES)]

    def test_cap_reached_no_chip_and_refused(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.assertNotIn("approve_ssh_rule", self.link_page(rid))
        self.assertEqual(self.decide(rid, "approve_ssh_rule")[0], 303)
        self.assertEqual(self.events("ssh_rule_refused")[-1]["reason"], "cap")
        self.assertEqual(self.r(rid).status, "pending")
        self.assertEqual(len(self.stored_rules()), sshrules.MAX_RULES)

    def test_manual_add_at_cap_is_refused(self):
        res = self.broker.add_ssh_rule("deploy", HOST.fp, "deploy", "never", True, "alice")
        self.assertEqual(res["status"], "refused")
        self.assertEqual(len(self.stored_rules()), sshrules.MAX_RULES)


class CardCreate(Base):
    ssh_hosts = KNOWN

    def test_dashboard_creates_rule_and_approves_this_request(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)], claimed="deploy@web.example.com:22")
        status, loc, _ = self.decide(rid, "approve_ssh_rule", extra={"fp": "SHA256:" + "A" * 43, "user": "root"})
        self.assertEqual((status, loc), (303, "/?note=sshrule"))
        self.assertTrue(self.released(rid))
        (rule,) = self.stored_rules()
        self.assertEqual((rule["fp"], rule["user"], rule["host"], rule["by"], rule["expires_at"]),
                         (HOST.fp, "deploy", "web.example.com, 10.0.0.5", "alice", None))
        self.assertRegex(rule["id"], r"^[0-9a-f]{8}$")
        self.assertEqual(self.live_rules(), [rule])
        self.assertEqual(set(rule), set(sshrules.RULE_KEYS))
        ev = self.events("ssh_rule_created")[0]
        self.assertEqual((ev["credential"], ev["host_fp"], ev["account"], ev["rule_id"], ev["created_by"],
                          ev["channel"], ev["id"]), ("deploy", HOST.fp, "deploy", rule["id"], "alice",
                                                     "dashboard", rid))
        self.assertTrue(self.events("decided")[0]["ssh_rule_requested"])
        self.assertNotIn("PRIVATE", json.dumps(ev))
        self.assertEqual(self.events("ssh_rule_refused"), [])

    def test_link_page_creates_rule_with_expiry(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        status, _, body = self.decide(rid, "approve_ssh_rule", "link", expiry="30")
        self.assertEqual(status, 200)
        self.assertIn("Always approved for this account on this server", body)
        (rule,) = self.stored_rules()
        left = sshrules.to_epoch(rule["expires_at"]) - time.time()
        self.assertTrue(29.9 * 86400 < left < 30.1 * 86400, left)
        self.assertEqual(self.events("ssh_rule_created")[0]["channel"], "link")
        for days, want in (("90", 90), ("never", None)):
            other = th.Host()
            rid = self.ask_ok(login(SID_A, "u" + str(days)), [other.bind(SID_A)])
            self.decide(rid, "approve_ssh_rule", "link", expiry=days)
        got = {r["user"]: r["expires_at"] for r in self.stored_rules()}
        self.assertIsNone(got["unever"])
        self.assertTrue(89.9 * 86400 < sshrules.to_epoch(got["u90"]) - time.time() < 90.1 * 86400)

    def test_bad_expiry_changes_nothing(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.assertEqual(self.decide(rid, "approve_ssh_rule", expiry="7")[1], "/?note=stale")
        self.assertEqual(self.decide(rid, "approve_ssh_rule", "link", expiry="7")[0], 404)
        self.assertEqual((self.r(rid).status, self.stored_rules()), ("pending", []))

    def test_duplicate_is_a_noop_that_still_approves(self):
        r1 = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.decide(r1, "approve_ssh_rule")
        self.assertTrue(self.released(r1))
        before = self.stored_rules()
        # a prompt for the same host+account cannot occur now (the rule matches), so ask via a rule-less path:
        self.broker.cfg["secrets"]["deploy"].pop("ssh_rules")
        r2 = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.broker.cfg["secrets"]["deploy"]["ssh_rules"] = list(before)
        self.assertEqual(self.decide(r2, "approve_ssh_rule")[1], "/?note=sshrule")
        self.assertTrue(self.released(r2))
        self.assertEqual(self.stored_rules(), before)
        self.assertEqual(len(self.events("ssh_rule_created")), 1)

    def test_forged_post_for_ineligible_requests_refused_and_pending(self):
        want = {"unbound": ("not_verified", login(SID_A), None),
                "forwarded": ("forwarded", login(SID_A), [HOST.bind(SID_A, forwarding=True)]),
                "sshsig": ("not_eligible", SSHSIG, None),
                "two hops": ("not_eligible", login(SID_A), [OTHER.bind(SID_B), HOST.bind(SID_A)]),
                "bad bind": ("not_verified", hostbound(SID_A, HOST), [HOST.bind(SID_A, sig=b"x")])}
        for label, (cls, data, binds) in want.items():
            rid = self.ask_ok(data, binds)
            for via in ("dashboard", "link"):
                self.decide(rid, "approve_ssh_rule", via)
                self.assertEqual(self.r(rid).status, "pending", label)
            ev = [e for e in self.events("ssh_rule_refused") if e.get("id") == rid]
            self.assertEqual({e["reason"] for e in ev}, {cls}, label)
            self.assertEqual(len(ev), 2, label)
        self.assertEqual(self.stored_rules(), [])
        self.assertEqual(self.events("ssh_rule_created"), [])
        # a plain approve of the same request still works afterwards
        self.decide(rid, "approve")
        self.assertTrue(self.released(rid))

    def test_push_and_ha_channels_cannot_create(self):
        self.assertFalse(CHANNELS["push"].may_create_ssh_rule)
        self.assertFalse(CHANNELS["ha"].may_create_ssh_rule)
        self.assertTrue(CHANNELS["dashboard"].may_create_ssh_rule and CHANNELS["link"].may_create_ssh_rule)
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        for ch in ("push", "ha"):
            code, got = self.broker.decide_via(ch, rid, "approve", "x", token="t", ssh_rule={"days": None})
            self.assertEqual((code, got), (403, None))
        self.assertEqual((self.r(rid).status, self.stored_rules()), ("pending", []))
        self.assertEqual({e["channel"] for e in self.events("ssh_rule_refused")}, {"push", "ha"})

    def test_persists_across_a_new_broker(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.decide(rid, "approve_ssh_rule")
        b = Broker({"approve_base_url": "https://s.example"}, self.broker.backend, FakeNotifier(), None)
        self.assertEqual(b.cfg["secrets"]["deploy"]["ssh_rules"], self.stored_rules())
        self.assertEqual(b.cfg["secrets"]["deploy"]["ssh_rules"][0]["fp"], HOST.fp)

    def test_vault_write_failure_still_approves_once_and_audits(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])

        def boom(*a):
            raise OSError("disk")
        self.broker.backend.set_meta = boom
        self.decide(rid, "approve_ssh_rule")
        self.assertTrue(self.released(rid))
        self.assertEqual(self.live_rules(), [])
        self.assertEqual(self.events("ssh_rule_change_failed")[0]["op"], "create")
        self.assertEqual(self.r(rid).ssh_rule, "failed")

    def test_decision_detail_mentions_the_rule_request(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.decide(rid, "approve_ssh_rule")
        self.assertTrue(self.released(rid))
        body = t.req(self.abase + f"/request/{rid}", headers=self.H)[1]
        self.assertIn("and always allow this host", body)


# ------------------------------------------------------------------ matching
class Match(Base):
    ssh_hosts = KNOWN
    rules = [R(HOST, "deploy", label="web.example.com")]

    def expect(self, label, data, binds, auto, name="deploy", claimed=None):
        before, used = self.sent(), len(self.events("ssh_rule_used"))
        rid = self.ask_ok(data, binds, name=name, claimed=claimed)
        if auto:
            self.assertEqual(self.sent(), before, label)
            res = self.result(rid)
            self.assertEqual(res["status"], "approved", label)
            self.assertIn("ssh_signature", res, label)
            self.assertEqual(len(self.events("ssh_rule_used")), used + 1, label)
        else:
            self.assertEqual(self.sent(), before + 1, label)
            self.assertEqual(self.r(rid).status, "pending", label)
            self.assertEqual(len(self.events("ssh_rule_used")), used, label)
        return rid

    def test_matrix(self):
        cases = [
            ("bound, same host+account", login(SID_A), [HOST.bind(SID_A)], True),
            ("host-bound login data only", hostbound(SID_A, HOST), None, True),
            ("host-bound data and bind", hostbound(SID_A, HOST), [HOST.bind(SID_A)], True),
            ("other host", login(SID_A), [OTHER.bind(SID_A)], False),
            ("other host, host-bound data", hostbound(SID_A, OTHER), None, False),
            ("other account", login(SID_A, "root"), [HOST.bind(SID_A)], False),
            ("account differs in case", login(SID_A, "Deploy"), [HOST.bind(SID_A)], False),
            ("account with suffix", login(SID_A, "deploy2"), [HOST.bind(SID_A)], False),
            ("non-ascii account", login(SID_A, "d\u00e9ploy"), [HOST.bind(SID_A)], False),
            ("unbound plain login", login(SID_A), None, False),
            ("unbound plus a claimed destination", login(SID_A), None, False),
            ("forwarded", login(SID_A), [HOST.bind(SID_A, forwarding=True)], False),
            ("two-hop chain", login(SID_A), [OTHER.bind(SID_B), HOST.bind(SID_A)], False),
            ("bind is for an earlier hop", login(SID_A), [HOST.bind(SID_A), OTHER.bind(SID_B)], False),
            ("invalid bind with matching signed host", hostbound(SID_A, HOST),
             [HOST.bind(SID_A, sig=b"x" * 20)], False),
            ("commit signing", SSHSIG, None, False),
            ("wrong service", ts.userauth_blob(service="ssh-userauth"), None, False),
        ]
        for label, data, binds, auto in cases:
            self.expect(label, data, binds, auto, claimed="deploy@web.example.com:22" if "claimed" in label else None)

    def test_rule_of_another_credential_does_not_match(self):
        self.expect("deploy2 has no rule", login(SID_A), [HOST.bind(SID_A)], False, name="deploy2")
        self.expect("deploy has the rule", login(SID_A), [HOST.bind(SID_A)], True, name="deploy")

    def test_audit_of_a_rule_release(self):
        rid = self.expect("match", login(SID_A), [HOST.bind(SID_A)], True)
        rule = self.stored_rules()[0]
        used = self.events("ssh_rule_used")[0]
        self.assertEqual((used["credential"], used["host_fp"], used["account"], used["rule_id"], used["id"]),
                         ("deploy", HOST.fp, "deploy", rule["id"], rid))
        ap = [e for e in self.events("approved") if e["id"] == rid][0]
        self.assertEqual((ap["via"], ap["rule_id"], ap["decision_source"]), ("policy", rule["id"], "rule"))
        self.assertEqual(self.events("notified"), [])
        self.assertEqual(self.events("escalated"), [])
        self.assertEqual(self.events("assessed")[0]["risk"], "high")      # the HIGH floor did not matter

    def test_last_used_and_counts_and_state_file(self):
        for _ in range(3):
            self.expect("match", login(SID_A), [HOST.bind(SID_A)], True)
        rid = self.live_rules()[0]["id"]
        u = self.broker.ssh_rule_usage.get("deploy", rid)
        self.assertEqual(u["uses"], 3)
        self.assertAlmostEqual(u["last_used"], time.time(), delta=30)
        path = os.path.join(os.path.dirname(self.audit), "ssh_rules_state.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            self.assertEqual(list(json.load(f)["rules"].values())[0]["uses"], 3)
        # nothing about use is written into the vault
        self.assertEqual(self.stored_rules(), self.live_rules())
        self.assertNotIn("last_used", json.dumps(self.stored_rules()))
        page = t.req(self.abase + "/policies", headers=self.H)[1]
        self.assertIn("3 uses", page)

    def test_corrupt_state_file_only_loses_last_used(self):
        self.expect("match", login(SID_A), [HOST.bind(SID_A)], True)
        path = os.path.join(os.path.dirname(self.audit), "ssh_rules_state.json")
        for junk in ("{not json", json.dumps({"rules": {"a": {"uses": "x"}}}), json.dumps([1]), ""):
            with open(path, "w") as f:
                f.write(junk)
            b = Broker({"approve_base_url": "https://s.example"}, self.broker.backend, FakeNotifier(), self.audit)
            self.assertEqual(b.ssh_rule_usage.get("deploy", self.live_rules()[0]["id"]),
                             {"last_used": None, "uses": 0})
            self.assertEqual(len(b.cfg["secrets"]["deploy"]["ssh_rules"]), 1)
        self.assertTrue(self.events("ssh_rules_state_corrupt"))
        self.expect("still matches", login(SID_A), [HOST.bind(SID_A)], True)

    def test_history_detail_shows_the_standing_rule(self):
        rid = self.expect("match", login(SID_A), [HOST.bind(SID_A)], True)
        rule = self.stored_rules()[0]
        body = t.req(self.abase + f"/request/{rid}", headers=self.H)[1]
        self.assertIn(f"standing SSH rule (auto-approved): deploy@web.example.com, rule {rule['id']}", body)
        self.assertIn("ssh_rule_used", body)
        self.assertIn("auto-approved", body)
        self.assertNotIn("time-boxed grant", body)

    def test_rule_beats_a_grant_and_a_grant_still_covers_other_hosts(self):
        # create a grant from a request on another host
        rid = self.ask_ok(login(SID_A), [OTHER.bind(SID_A)])
        self.decide(rid, "approve_grant_15")
        self.assertTrue(self.released(rid))
        # another host: released by the grant, no prompt
        sent = self.sent()
        r2 = self.ask_ok(login(SID_A), [THIRD.bind(SID_A)])
        self.assertTrue(self.released(r2))
        self.assertEqual(self.sent(), sent)
        self.assertEqual(self.events("grant_used")[-1]["id"], r2)
        ap = [e for e in self.events("approved") if e["id"] == r2][0]
        self.assertNotIn("rule_id", ap)
        # the rule host: the audit shows the rule, not the grant
        r3 = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.assertTrue(self.released(r3))
        ap = [e for e in self.events("approved") if e["id"] == r3][0]
        self.assertEqual(ap["decision_source"], "rule")
        self.assertNotIn("grant_id", ap)
        self.assertEqual([e["id"] for e in self.events("grant_used")], [r2])


class MatchOtherCredential(Base):
    rules2 = [R(HOST, "deploy")]

    def test_rule_on_deploy2_does_not_release_deploy(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)], name="deploy")
        self.assertEqual(self.r(rid).status, "pending")
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)], name="deploy2")
        self.assertTrue(self.released(rid))


def _auto_max_class(level):
    class AutoMax(Base):
        ssh_hosts = KNOWN
        rules = [R(HOST, "deploy")]
        auto_max = level

        def test_rule_releases_at_this_limit_and_others_prompt(self):
            self.assertEqual(self.broker.auto_approve_max(), level)
            rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
            self.assertEqual(self.sent(), 0)
            self.assertEqual(self.result(rid)["status"], "approved")
            self.assertEqual(self.events("assessed")[0]["risk"], "high")
            rid = self.ask_ok(login(SID_A), [OTHER.bind(SID_A)])
            rid2 = self.ask_ok(login(SID_A, "root"), [HOST.bind(SID_A)])
            self.assertEqual(self.sent(), 2)
            self.assertEqual({self.r(rid).status, self.r(rid2).status}, {"pending", "expired"})
    AutoMax.__name__ = AutoMax.__qualname__ = f"AutoMax_{level}"
    return AutoMax


for _lvl in ("none", "low", "medium", "high"):
    globals()[f"AutoMax_{_lvl}"] = _auto_max_class(_lvl)
del _lvl


# ------------------------------------------------------------------ refusals first
class RefusalsFirst(Base):
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com"), OTHER.line("db.example.com")],
                 "allowed_hosts": ["db.example.com"]}
    rules = [R(HOST, "deploy"), R(OTHER, "deploy")]

    def test_a_rule_never_overrides_a_refusal(self):
        cases = [("host_not_allowed", login(SID_A), [HOST.bind(SID_A)]),
                 ("host_unverified", login(SID_A), None),
                 ("bind_invalid", hostbound(SID_A, HOST), [HOST.bind(SID_A, sig=b"x" * 20)]),
                 ("session_mismatch", login(SID_A), [OTHER.bind(SID_B)]),
                 ("host_forwarded", login(SID_A), [OTHER.bind(SID_A, forwarding=True)]),
                 ("host_unverified", SSHSIG, None)]
        for reason, data, binds in cases:
            code, _ = self.ask(data, binds)
            self.assertEqual(code, 403, reason)
        self.assertEqual([r["reason"] for r in self.refused()], [c[0] for c in cases])
        self.assertEqual(self.events("ssh_rule_used"), [])
        self.assertEqual(self.events("requested"), [])
        # control: the allowed host with its rule is released
        self.assertTrue(self.released(self.ask_ok(login(SID_A), [OTHER.bind(SID_A)])))

    def test_removing_a_host_from_allowed_hosts_makes_its_rule_ineffective(self):
        self.assertEqual(self.ask(login(SID_A), [HOST.bind(SID_A)])[0], 403)
        res = self.broker.set_ssh_hosts("deploy", "\n".join(self.ssh_hosts["known_hosts"]),
                                        "db.example.com\nweb.example.com", False, "alice")
        self.assertEqual(res["status"], "saved")
        self.assertTrue(self.released(self.ask_ok(login(SID_A), [HOST.bind(SID_A)])))
        res = self.broker.set_ssh_hosts("deploy", "\n".join(self.ssh_hosts["known_hosts"]),
                                        "db.example.com", False, "alice")
        self.assertEqual(res["status"], "saved")
        self.assertEqual(self.ask(login(SID_A), [HOST.bind(SID_A)])[0], 403)
        self.assertEqual(len(self.stored_rules()), 2)                  # the rule is still stored

    def test_policies_page_warns_about_blocked_rules(self):
        page = t.req(self.abase + "/policies", headers=self.H)[1]
        row = [x for x in page.split("<tr>") if HOST.fp[:19] in x and "Revoke" in x][0]
        self.assertIn("blocked by the allowed hosts list", row)
        other = [x for x in page.split("<tr>") if OTHER.fp[:19] in x and "Revoke" in x][0]
        self.assertNotIn("blocked by the allowed hosts list", other)


# ------------------------------------------------------------------ expiry
class Expiry(Base):
    ssh_hosts = KNOWN
    rules = [R(HOST, "deploy", expires=PAST), R(HOST, "root", expires=FUTURE), R(OTHER, "deploy")]

    def test_expired_rule_is_ignored_then_dropped_once(self):
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])
        self.assertEqual(self.r(rid).status, "pending")                # expired rule: prompt
        self.assertTrue(self.released(self.ask_ok(login(SID_A, "root"), [HOST.bind(SID_A)])))
        deadline = time.time() + 5                                     # the lazy drop runs in a thread
        while time.time() < deadline and len(self.stored_rules()) == 3:
            time.sleep(0.05)
        self.assertEqual(sorted(r["user"] for r in self.stored_rules()), ["deploy", "root"])
        self.broker.expire_ssh_rules()
        self.broker.expire_ssh_rules()
        ev = self.events("ssh_rule_expired")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["credential"], ev[0]["host_fp"], ev[0]["account"], ev[0]["expires_at"]),
                         ("deploy", HOST.fp, "deploy", PAST))
        self.assertEqual(len(self.live_rules()), 2)

    def test_sweep_drops_all_keys_and_forgets_usage(self):
        self.broker.expire_ssh_rules()
        self.assertEqual(len(self.stored_rules()), 2)
        self.assertEqual(len(self.events("ssh_rule_expired")), 1)

    def test_expiry_from_a_future_clock(self):
        real = time.time
        orig = time.time
        try:
            time.time = lambda: real() + 400 * 86400
            self.broker.expire_ssh_rules()
        finally:
            time.time = orig
        self.assertEqual([r["user"] for r in self.stored_rules()], ["deploy"])
        self.assertEqual(len(self.events("ssh_rule_expired")), 2)

    def test_sweep_failure_is_audited_once(self):
        def boom(*a):
            raise OSError("disk")
        self.broker.backend.set_meta = boom
        self.broker.expire_ssh_rules()
        self.broker.expire_ssh_rules()
        self.assertEqual(len(self.events("ssh_rule_change_failed")), 1)
        self.assertEqual(self.events("ssh_rule_expired"), [])
        self.assertEqual(len(self.live_rules()), 3)                    # still listed, still ignored at match time


# ------------------------------------------------------------------ metadata validation
class Validation(unittest.TestCase):
    pem = ts._openssh(ed25519.Ed25519PrivateKey.generate())

    def meta(self, **kw):
        m = {"name": "k", "vars": {"K": {"item": "Item", "field": "private_key"}}, "ssh": True,
             "ssh_public_key": sshkey.public_line(sshkey.load_private(self.pem)), "allowed_hosts": []}
        m.update(kw)
        return m

    def good(self, **kw):
        return {"id": "abcd1234", "fp": HOST.fp, "user": "deploy", "by": "alice", "at": "2026-10-01T00:00:00Z", **kw}

    def test_valid_shapes(self):
        _, e = Broker._entry("Item", self.meta(ssh_rules=[self.good(), self.good(
            id="b2c3", user="root", host="web", expires_at="2027-01-01T00:00:00Z")]))
        self.assertEqual(len(e["ssh_rules"]), 2)
        self.assertEqual(e["ssh_rules"][0]["expires_at"], None)
        self.assertEqual(e["ssh_rules"][0]["host"], None)
        _, e = Broker._entry("Item", self.meta(ssh_rules=[self.good(host=None, expires_at=None, fp=HOST.fp + "=")]))
        self.assertEqual(e["ssh_rules"][0]["fp"], HOST.fp)
        _, e = Broker._entry("Item", self.meta(ssh_rules=[]))
        self.assertNotIn("ssh_rules", e)
        _, e = Broker._entry("Item", self.meta(ssh_rules=[self.good(id=f"i{i:03d}", user=f"u{i}") for i in range(100)]))
        self.assertEqual(len(e["ssh_rules"]), 100)

    def test_bad_shapes_name_the_field(self):
        g = self.good
        bad = {
            "not a list": ("ssh_rules", {"a": 1}),
            "too many": ("ssh_rules", [g(id=f"i{i:03d}") for i in range(101)]),
            "not an object": ("ssh_rules[0]", ["x"]),
            "unknown key": ("ssh_rules[0].last_used", [g(last_used="2026-10-01T00:00:00Z")]),
            "missing id": ("ssh_rules[0].id", [{k: v for k, v in g().items() if k != "id"}]),
            "missing fp": ("ssh_rules[0].fp", [{k: v for k, v in g().items() if k != "fp"}]),
            "missing user": ("ssh_rules[0].user", [{k: v for k, v in g().items() if k != "user"}]),
            "bad id": ("ssh_rules[0].id", [g(id="a b")]),
            "duplicate id": ("ssh_rules[1].id", [g(), g(user="x")]),
            "bad fp": ("ssh_rules[0].fp", [g(fp="SHA256:short")]),
            "md5 fp": ("ssh_rules[0].fp", [g(fp="MD5:aa:bb")]),
            "empty user": ("ssh_rules[0].user", [g(user="")]),
            "long user": ("ssh_rules[0].user", [g(user="u" * 65)]),
            "user with space": ("ssh_rules[0].user", [g(user="a b")]),
            "user with newline": ("ssh_rules[0].user", [g(user="a\nb")]),
            "user not text": ("ssh_rules[0].user", [g(user=5)]),
            "long host label": ("ssh_rules[0].host", [g(host="h" * 101)]),
            "host not text": ("ssh_rules[0].host", [g(host=["x"])]),
            "by empty": ("ssh_rules[0].by", [g(by="")]),
            "at bad": ("ssh_rules[0].at", [g(at="yesterday")]),
            "expires bad": ("ssh_rules[0].expires_at", [g(expires_at="2027-01-01")]),
            "expires number": ("ssh_rules[0].expires_at", [g(expires_at=5)]),
        }
        for label, (field, rules) in bad.items():
            with self.assertRaises(ValueError, msg=label) as cm:
                Broker._entry("Item", self.meta(ssh_rules=rules))
            self.assertIn(field, str(cm.exception), label)

    def test_only_for_ssh_keys(self):
        meta = {"name": "k", "vars": {"K": {"item": "Item", "field": "password"}}, "allowed_hosts": ["a.example"],
                "ssh_rules": [self.good()]}
        with self.assertRaises(ValueError) as cm:
            Broker._entry("Item", meta)
        self.assertIn("ssh_rules only applies to an ssh key", str(cm.exception))

    def test_invalid_rules_make_the_secret_invalid_in_the_catalog(self):
        class Rows(MemoryBackend):
            def catalog(self):
                m = Validation.meta(Validation(), ssh_rules=[{"id": "x"}])
                return [{"item": "Item", "meta": m, "auto": {}}]
        b = Broker({"approve_base_url": "https://s.example"}, Rows(), FakeNotifier(), None)
        self.assertNotIn("k", b.cfg["secrets"])


# ------------------------------------------------------------------ Policies tab
class PoliciesBase(Base):
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com"), OTHER.line("db.example.com")]}
    rules = [R(HOST, "deploy", label="web.example.com", by="carol")]

    def post(self, path, user="alice", csrf=True, **form):
        if csrf is True:
            form["csrf"] = self.broker.csrf_token("alice")
        elif isinstance(csrf, str):
            form["csrf"] = csrf
        form.setdefault("secret", "deploy")
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + path, data=urllib.parse.urlencode(form).encode(),
                headers={"X-authentik-username": user}, method="POST"), timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def page(self):
        return t.req(self.abase + "/policies", headers=self.H)[1]

    def section(self):
        return self.page().split("SSH host rules")[1]


class PoliciesTab(PoliciesBase):
    def test_listing(self):
        sec = self.section()
        self.assertIn("web.example.com", sec)
        self.assertIn(HOST.fp[:19], sec)
        self.assertIn("<code>deploy</code>", sec)
        self.assertIn("carol", sec)
        self.assertIn("never", sec)
        self.assertIn("Revoke", sec)
        self.assertIn("0 uses", sec)
        self.assertIn("action='/policies/ssh_rules/add'", sec)
        self.assertIn(f"value='{OTHER.fp}'", sec)                        # host dropdown from known_hosts
        self.assertIn("db.example.com", sec)
        self.assertIn("name=confirm", sec)
        self.assertNotIn("No standing SSH rules", sec.split("deploy2")[0])
        self.assertEqual(sec.count("No standing SSH rules"), 1)           # deploy2 is empty

    def test_empty_state(self):
        self.broker.revoke_ssh_rule("deploy", self.live_rules()[0]["id"], "alice")
        self.assertEqual(self.section().count("No standing SSH rules"), 2)

    def test_revoke(self):
        rid = self.live_rules()[0]["id"]
        self.broker.ssh_rule_usage.record("deploy", rid, time.time())
        status, body = self.post("/policies/ssh_rules/revoke", rule=rid)
        self.assertEqual(status, 200)
        self.assertIn("SSH rule revoked", body)
        self.assertEqual((self.stored_rules(), self.live_rules()), ([], []))
        ev = self.events("ssh_rule_revoked")[0]
        self.assertEqual((ev["credential"], ev["host_fp"], ev["account"], ev["rule_id"], ev["revoked_by"],
                          ev["created_by"], ev["channel"]), ("deploy", HOST.fp, "deploy", rid, "alice", "carol", "policies"))
        self.assertEqual(self.broker.ssh_rule_usage.get("deploy", rid)["uses"], 0)
        self.assertIn("no longer exists", self.post("/policies/ssh_rules/revoke", rule=rid)[1])
        self.assertEqual(self.post("/policies/ssh_rules/revoke", secret="svc", rule=rid)[0], 400)
        self.assertEqual(self.post("/policies/ssh_rules/revoke", secret="nope", rule=rid)[0], 400)
        # after the revoke the request prompts again
        self.assertEqual(self.r(self.ask_ok(login(SID_A), [HOST.bind(SID_A)])).status, "pending")

    def test_revoke_failure_keeps_the_rule(self):
        def boom(*a):
            raise OSError("disk")
        self.broker.backend.set_meta = boom
        status, _ = self.post("/policies/ssh_rules/revoke", rule=self.live_rules()[0]["id"])
        self.assertEqual(status, 500)
        self.assertEqual(len(self.live_rules()), 1)
        self.assertEqual(self.events("ssh_rule_change_failed")[0]["op"], "revoke")

    def test_add_from_known_hosts_and_by_fingerprint(self):
        status, body = self.post("/policies/ssh_rules/add", host=OTHER.fp, account="root", expires="90", confirm="1")
        self.assertEqual(status, 200)
        third = "SHA256:" + "B" * 43
        self.assertEqual(self.post("/policies/ssh_rules/add", host="", fp=third, account="svc", expires="never",
                                   confirm="1")[0], 200)
        by = {(r["fp"], r["user"]): r for r in self.stored_rules()}
        r1 = by[(OTHER.fp, "root")]
        self.assertEqual((r1["host"], r1["by"]), ("db.example.com", "alice"))
        self.assertTrue(89.9 * 86400 < sshrules.to_epoch(r1["expires_at"]) - time.time() < 90.1 * 86400)
        r2 = by[(third, "svc")]
        self.assertEqual((r2["host"], r2["expires_at"]), (None, None))
        self.assertEqual(self.live_rules(), self.stored_rules())
        ev = self.events("ssh_rule_created")
        self.assertEqual([(e["host_fp"], e["account"], e["created_by"], e["channel"]) for e in ev],
                         [(OTHER.fp, "root", "alice", "policies"), (third, "svc", "alice", "policies")])
        # the new rule works for a request
        self.assertTrue(self.released(self.ask_ok(login(SID_A, "root"), [OTHER.bind(SID_A)])))

    def test_add_validation_matches_the_loader(self):
        n = len(self.stored_rules())
        bad = [dict(host="", fp="SHA256:short", account="a", confirm="1"),
               dict(host="", fp="", account="a", confirm="1"),
               dict(host=OTHER.fp, account="", confirm="1"),
               dict(host=OTHER.fp, account="a b", confirm="1"),
               dict(host=OTHER.fp, account="x" * 65, confirm="1"),
               dict(host=OTHER.fp, account="a\nb", confirm="1"),
               dict(host=OTHER.fp, account="a", expires="7", confirm="1"),
               dict(host=OTHER.fp, account="a")]                         # not confirmed
        for form in bad:
            status, body = self.post("/policies/ssh_rules/add", **form)
            self.assertEqual(status, 400, form)
            self.assertIn("Could not add the SSH rule", body)
        self.assertEqual(len(self.stored_rules()), n)
        self.assertEqual(len(self.events("ssh_rule_refused")), len(bad))
        self.assertEqual(self.post("/policies/ssh_rules/add", secret="svc", host=OTHER.fp, account="a",
                                   confirm="1")[0], 400)

    def test_add_duplicate_is_a_noop(self):
        status, body = self.post("/policies/ssh_rules/add", host=HOST.fp, account="deploy", confirm="1")
        self.assertEqual(status, 200)
        self.assertIn("already exists", body)
        self.assertEqual(len(self.stored_rules()), 1)
        self.assertEqual(self.events("ssh_rule_created"), [])

    def test_guards_csrf_origin_identity_and_peer(self):
        before = self.stored_rules()
        rid = before[0]["id"]
        forms = {"/policies/ssh_rules/revoke": dict(rule=rid),
                 "/policies/ssh_rules/add": dict(host=OTHER.fp, account="x", confirm="1")}
        for path, form in forms.items():
            self.assertEqual(self.post(path, csrf=False, **form)[0], 403, path)
            self.assertEqual(self.post(path, csrf="bad", **form)[0], 403, path)
            self.assertEqual(self.post(path, user="mallory", **form)[0], 403, path)
            r = urllib.request.Request(
                self.abase + path, method="POST",
                headers={"X-authentik-username": "alice", "Origin": "https://evil.example"},
                data=urllib.parse.urlencode({"secret": "deploy", "csrf": self.broker.csrf_token("alice"), **form}).encode())
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(r, timeout=10)
            self.assertEqual(cm.exception.code, 403, path)
            self.broker.cfg["approval_trusted_peers"] = ["10.9.9.0/24"]
            self.assertEqual(self.post(path, **form)[0], 403, path)
            del self.broker.cfg["approval_trusted_peers"]
        self.assertEqual(self.stored_rules(), before)

    def test_hostile_labels_and_accounts_are_escaped(self):
        evil = "<img/src=x/onerror=alert(1)>"
        hostile = th.Host()
        self.broker.cfg["secrets"]["deploy"]["ssh_hosts"]["known"][hostile.fp] = [evil]
        self.assertEqual(self.post("/policies/ssh_rules/add", host=hostile.fp, account="<script>x</script>",
                                   confirm="1")[0], 200)
        # a label straight from vault metadata too
        rule = R(THIRD, "a'\"<b>", label="<svg onload=alert(2)>")
        self.broker.cfg["secrets"]["deploy"]["ssh_rules"].append(rule)
        page = self.page()
        for raw in ("<img/src", "<script>x", "<svg onload", "<b>'"):
            self.assertNotIn(raw, page)
        self.assertIn("&lt;img/src=x/onerror=alert(1)&gt;", page)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)
        self.assertIn("&lt;svg onload=alert(2)&gt;", page)

    def test_not_shown_without_ssh_keys(self):
        self.assertEqual(sshrules.policies_section({"svc": {"vars": {}}}, "tok", self.broker.ssh_rule_usage), "")


# ------------------------------------------------------------------ audit and hiding
class AuditHiding(unittest.TestCase):
    EVENTS = ("ssh_rule_created", "ssh_rule_used", "ssh_rule_revoked", "ssh_rule_expired",
              "ssh_rule_refused", "ssh_rule_change_failed", "ssh_rules_state_corrupt",
              "ssh_rules_state_write_failed")

    def test_all_rule_events_are_hidden_from_the_agent(self):
        for ev in self.EVENTS:
            self.assertIn(ev, audit_api.HIDDEN, ev)
            self.assertNotIn(ev, audit_api.WHITELIST, ev)
            out = audit_api.redact({"seq": 1, "ts": 1760000000.5, "event": ev, "id": "r1", "rule_id": "abcd"})
            self.assertIsNone(out, ev)

    def test_coverage_scan_includes_this_module(self):
        from test_audit_api import event_names_in_broker
        names = event_names_in_broker()
        for ev in ("ssh_rule_created", "ssh_rule_used", "ssh_rule_revoked", "ssh_rule_expired",
                   "ssh_rule_refused", "ssh_rule_change_failed"):
            self.assertIn(ev, names)

    def test_rule_approved_looks_like_a_plain_approval(self):
        out = audit_api.redact({"seq": 3, "ts": 1760000000.5, "event": "approved", "id": "r1", "via": "policy",
                                "rule_id": "abcd1234", "decision_source": "rule", "channel": "dashboard",
                                "approver": "alice"})
        self.assertEqual(out["channel"], None)
        self.assertEqual(out["approver"], None)
        self.assertNotIn("abcd1234", json.dumps(out))
        self.assertNotIn("rule", json.dumps(out))


class AgentLeaks(Base):
    """The agent must never learn which servers have rules."""
    LABEL = "canary-rule-host-7c1e.internal"
    ACCT = "canary-acct"
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com"), THIRD.line(LABEL)]}
    rules = [R(HOST, "deploy", label="web.example.com"), R(THIRD, ACCT, label=LABEL)]

    def test_no_agent_facing_output_mentions_rules_or_hosts_with_rules(self):
        canaries = [self.LABEL, self.ACCT, THIRD.fp, THIRD.fp[7:30], "ssh_rule", "standing", "rule_id",
                    "decision_source", "ssh_rules"] + [r["id"] for r in self.live_rules()]
        rid = self.ask_ok(login(SID_A), [HOST.bind(SID_A)])            # rule release
        res_rule = self.result(rid)
        rid2 = self.ask_ok(login(SID_A, "root"), [HOST.bind(SID_A)])   # prompts
        code, pending = self.api("GET", f"/v1/requests/{rid2}?wait=0")
        outputs = [json.dumps(res_rule), pending,
                   self.api("GET", "/v1/status")[1], self.api("GET", "/v1/secrets")[1],
                   self.api("GET", "/v1/secrets?host=web.example.com")[1],
                   self.api("POST", "/v1/requests", {"mode": "ssh_sign", "names": ["deploy"], "flags": 0,
                            "data_b64": base64.b64encode(login(SID_B)).decode()})[1]]
        for q in ("limit=500", f"request={rid}", "event=approved,ssh_rule_used,ssh_rule_created,ssh_rule_refused",
                  "order=asc&limit=500", "secret=deploy"):
            code, body = self.api("GET", "/v1/audit?" + q)
            self.assertEqual(code, 200, q)
            outputs.append(body)
        outputs.append(json.dumps(self.notifier.sent))
        outputs.append(json.dumps([n.text for n in self.notifier.notifications]))
        blob = "\n".join(str(o) for o in outputs)
        for c in canaries:
            self.assertNotIn(c, blob, c)
        # the audit view shows a rule release as a plain approval
        events = json.loads(self.api("GET", f"/v1/audit?request={rid}")[1])["events"]
        ap = [e for e in events if e["event"] == "approved"][0]
        self.assertEqual((ap["channel"], ap["approver"]), (None, None))
        self.assertEqual({e["event"] for e in events} & audit_api.HIDDEN, set())


if __name__ == "__main__":
    unittest.main()
