"""Time-boxed grants: "Approve for N minutes"."""
import base64
import json
import re
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import grants as grants_mod  # noqa: E402
from secret_broker import sshkey  # noqa: E402
from secret_broker.backends import FileBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
from test_e2e import Harness, _Stub, req  # noqa: E402
from test_ssh import _openssh, userauth_blob  # noqa: E402

H = {"X-authentik-username": "alice"}


class Base(Harness):
    decision = None
    ttl = 600
    grants_cfg = None
    risk = "low"

    def tweak(self, cfg):
        if self.grants_cfg is not None:
            cfg["timed_grants"] = self.grants_cfg
        pem = _openssh(ed25519.Ed25519PrivateKey.generate())
        cfg["_vault"] = {"Deploykey": {"private_key": pem}}
        cfg["secrets"]["deploy"] = {
            "vars": {"DEPLOY_SSH_KEY": {"item": "Deploykey", "field": "private_key"}},
            "allowed_hosts": [], "ssh": True,
            "ssh_public_key": sshkey.public_line(sshkey.load_private(pem))}
        vault_other = {"Other": {"token": "other-secret"}}
        cfg["_vault"].update(vault_other)
        cfg["secrets"]["other"] = {"vars": {"OTHER_TOKEN": {"item": "Other", "field": "token"}},
                                   "allowed_hosts": ["127.0.0.1"]}

    def setUp(self):
        super().setUp()
        self.broker.summarizer = _Stub("Reads things", self.risk)
        self.offset = 0
        real = time.time
        p = mock.patch("time.time", lambda: real() + self.offset)
        p.start()
        self.addCleanup(p.stop)

    def get(self, path="/", user="alice"):
        return req(self.abase + path, headers={"X-authentik-username": user})

    def decide(self, rid, decision, csrf="ok", user="alice", extra=None):
        form = {"id": rid, "decision": decision}
        if csrf is not None:
            form["csrf"] = self.broker.csrf_token(user) if csrf == "ok" else csrf
        hdr = {"X-authentik-username": user, **(extra or {})}

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        op = urllib.request.build_opener(NoFollow)
        try:
            r = op.open(urllib.request.Request(
                self.abase + "/decide", data=urllib.parse.urlencode(form).encode(),
                headers=hdr, method="POST"), timeout=10)
            return r.status, r.headers.get("Location"), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode()

    def result(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)

    def http(self, names=("svc",), path="/x", method="GET"):
        url = f"http://127.0.0.1:{self.up.server_address[1]}{path}"
        _, body = self.api("POST", "/v1/requests", {
            "mode": "http", "names": list(names), "method": method, "url": url,
            "headers": {**({"Authorization": "Bearer {{SVC_TOKEN}}"} if "svc" in names else {}),
                        **({"X-Other": "{{OTHER_TOKEN}}"} if "other" in names else {})}})
        return json.loads(body)["id"]

    def sign(self):
        _, body = self.api("POST", "/v1/requests", {
            "mode": "ssh_sign", "names": ["deploy"], "flags": 0,
            "data_b64": base64.b64encode(userauth_blob()).decode()})
        return json.loads(body)["id"]

    def pending_id(self):
        return next(r.id for r in self.broker._by_id.values() if r.status == "pending")

    def approve(self, rid, decision="approve_grant_15", via="dashboard"):
        if via == "link":
            nonce = self.broker._by_id[rid].nonce
            r = urllib.request.Request(
                self.abase + f"/a/{nonce}", headers=H, method="POST",
                data=urllib.parse.urlencode({"decision": decision}).encode())
            try:
                return urllib.request.urlopen(r, timeout=10).status
            except urllib.error.HTTPError as e:
                return e.code
        return self.decide(rid, decision)[0]

    def grant_it(self, names=("svc",), minutes=15, method="GET"):
        rid = self.http(names, method=method)
        self.assertEqual(self.approve(rid, f"approve_grant_{minutes}"), 303)
        self.broker._by_id[rid].done.wait(10)
        return rid

    def auto(self, rid):
        return self.result(rid)

    def status_of(self, rid):
        return self.broker._by_id[rid].status


class Creation(Base):
    def test_dashboard_menu_creates_grant_and_audits(self):
        rid = self.grant_it()
        g = self.broker.active_grants()
        self.assertEqual([x["secrets"] for x in g], [["svc"]])
        self.assertEqual(g[0]["created_by"], "alice")
        self.assertEqual(g[0]["minutes"], 15)
        ev = self.events("grant_created")[0]
        self.assertEqual((ev["id"], ev["grant_minutes"], ev["created_by"], ev["channel"]),
                         (rid, 15, "alice", "dashboard"))
        self.assertIn("expires_at", ev)
        self.assertEqual(self.events("decided")[0]["grant_minutes"], 15)
        self.assertEqual(self.events("approved")[0]["via"], "user")

    def test_link_page_creates_grant(self):
        rid = self.http()
        self.assertEqual(self.approve(rid, "approve_grant_30", via="link"), 200)
        self.broker._by_id[rid].done.wait(10)
        self.assertEqual(self.events("grant_created")[0]["channel"], "link")
        self.assertEqual(self.broker.active_grants()[0]["minutes"], 30)

    def test_csrf_required(self):
        rid = self.http()
        self.assertEqual(self.decide(rid, "approve_grant_15", csrf="bad")[0], 403)
        self.assertEqual(self.decide(rid, "approve_grant_15", csrf=None)[0], 403)
        self.assertEqual(self.decide(rid, "approve_grant_15", extra={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(self.status_of(rid), "pending")

    def test_duration_validation(self):
        rid = self.http()
        for bad in ("approve_grant_7", "approve_grant_61", "approve_grant_0", "approve_grant_",
                    "approve_grant_-5", "approve_grant_x", "approve_grant_9999999999999999999"):
            code, loc, _ = self.decide(rid, bad)
            self.assertEqual(self.status_of(rid), "pending", bad)   # nothing claimed
            self.assertEqual(self.broker.active_grants(), [], bad)
            self.assertIn(loc, ("/?note=bad", "/?note=stale"))

    def test_link_bad_duration_is_400_and_request_stays_pending(self):
        rid = self.http()
        self.assertEqual(self.approve(rid, "approve_grant_7", via="link"), 400)
        self.assertEqual(self.status_of(rid), "pending")

    def test_denied_never_creates(self):
        rid = self.http()
        self.broker.decide_via("dashboard", rid, "deny", "alice", grant_minutes=15)
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(self.events("grant_created"), [])

    def test_decided_request_cannot_grant_and_double_click_safe(self):
        rid = self.http()
        self.assertEqual(self.approve(rid, "approve"), 303)
        self.broker._by_id[rid].done.wait(10)
        code, loc, _ = self.decide(rid, "approve_grant_15")
        self.assertEqual(loc, "/?note=stale")
        self.assertEqual(self.broker.active_grants(), [])
        rid2 = self.http(path="/y")
        self.approve(rid2, "approve_grant_15")
        self.approve(rid2, "approve_grant_15")
        self.assertEqual(len(self.events("grant_created")), 1)

    def test_other_channels_cannot_create(self):
        rid = self.http()
        r = self.broker._by_id[rid]
        tok = "tok"
        import hashlib
        r.action_hash = hashlib.sha256(tok.encode()).digest()
        r.offered = frozenset(("approve", "deny"))
        code, _ = self.broker.decide_via("push", rid, "approve", "alice", token=tok, grant_minutes=15)
        self.assertEqual(code, 200)
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(self.events("grant_created"), [])

    def test_dashboard_card_has_the_chips_only_for_eligible_requests(self):
        self.http()
        _, page = self.get("/")
        self.assertIn("<div class=timed>", page)           # one-tap timed approvals, no label above them
        self.assertNotIn("Automatically approve", page)
        for m in (5, 15, 30):
            self.assertIn(f"name=decision value='approve_grant_{m}'", page)
            self.assertIn(f">{m} min</button>", page)
        self.assertNotIn("approve_grant_60", page)
        self.assertNotIn("Approve for a while", page)
        link_nonce = next(iter(self.broker._by_nonce))
        _, lp = self.get(f"/a/{link_nonce}")
        self.assertIn(">5 min</button>", lp)

    def test_no_menu_for_store(self):
        self.api("POST", "/v1/requests", {"mode": "store", "names": ["svc"], "op": "update", "value": "v"})
        _, page = self.get("/")
        self.assertNotIn("Automatically approve", page)
        self.assertNotIn("approve_grant_", page)
        rid = self.pending_id()
        self.assertEqual(self.decide(rid, "approve_grant_15")[0], 303)
        self.assertEqual(self.broker.active_grants(), [])
        self.assertTrue(self.events("grant_refused")[0]["reason"].startswith("storing"))


class Using(Base):
    def test_same_secret_is_auto_approved_with_audit(self):
        self.grant_it()
        n = len(self.notifier.sent)
        rid = self.http(path="/again")
        self.assertEqual(self.result(rid)["status"], "approved")
        self.assertEqual(len(self.notifier.sent), n)           # no prompt
        ap = [e for e in self.events("approved") if e["id"] == rid][0]
        self.assertEqual(ap["via"], "policy")
        self.assertTrue(ap["grant_id"])
        used = [e for e in self.events("grant_used") if e["id"] == rid][0]
        self.assertTrue(0 < used["grant_left_s"] <= 900)
        self.assertEqual(self.events("http_executed")[-1]["id"], rid)

    def test_history_row_and_popover_show_the_grant(self):
        self.grant_it()
        rid = self.http()
        self.result(rid)
        row, evs = self.broker.history.detail(rid)
        self.assertEqual(row["outcome"], "auto-approved")
        self.assertTrue(row["grant_id"])
        _, frag = self.get(f"/request/{rid}?fragment=1")
        self.assertIn("standing approval (15 min, reads only)", frag)
        self.assertIn("min left when used", frag)
        first = [r for r in self.broker.history.rows() if r["outcome"] == "approved"][-1]
        _, frag2 = self.get(f"/request/{first['id']}?fragment=1")
        self.assertIn("approve for 15 min", frag2)

    def test_other_secret_prompts(self):
        self.grant_it()
        n = len(self.notifier.sent)
        self.http(("other",))
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_set_equality_subset_and_superset_prompt(self):
        self.grant_it(("svc", "other"))
        n = len(self.notifier.sent)
        self.assertEqual(self.result(self.http(("other", "svc")))["status"], "approved")  # same set
        self.assertEqual(len(self.notifier.sent), n)
        self.http(("svc",))                                    # subset prompts
        self.assertEqual(len(self.notifier.sent), n + 1)
        self.broker.decide_via("dashboard", self.pending_id(), "approve", "alice")
        self.grant_it(("svc",), 5)                             # a separate grant for {svc}
        self.assertEqual(len(self.broker.active_grants()), 2)

    def test_superset_prompts(self):
        self.grant_it(("svc",))
        n = len(self.notifier.sent)
        self.http(("svc", "other"))
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_read_grant_does_not_cover_mutating_methods(self):
        self.grant_it(method="GET")
        g = self.broker.active_grants()[0]
        self.assertEqual(g["scope"], "read")
        self.assertEqual(self.events("grant_created")[0]["scope"], "read")
        for m in ("HEAD", "OPTIONS", "GET"):
            self.assertEqual(self.result(self.http(method=m, path="/" + m))["status"], "approved", m)
        n = len(self.notifier.sent)
        rid = self.http(method="DELETE", path="/d")
        self.assertEqual(len(self.notifier.sent), n + 1)
        sk = self.events("grant_skipped")[0]
        self.assertEqual((sk["id"], sk["reason"], sk["scope"]), (rid, "method", "read"))

    def test_write_grant_covers_get_and_other_methods(self):
        self.grant_it(method="POST")
        self.assertEqual(self.broker.active_grants()[0]["scope"], "any")
        n = len(self.notifier.sent)
        for m in ("GET", "DELETE", "PUT"):
            self.assertEqual(self.result(self.http(method=m, path="/" + m))["status"], "approved", m)
        self.assertEqual(len(self.notifier.sent), n)

    def test_ssh_grant_scope_is_any(self):
        rid = self.sign()
        self.approve(rid, "approve_grant_5")
        self.assertEqual(self.broker.active_grants()[0]["scope"], "any")

    def test_env_and_store_always_ask(self):
        self.grant_it()
        n = len(self.notifier.sent)
        self.create_env()
        self.assertEqual(len(self.notifier.sent), n + 1)
        self.api("POST", "/v1/requests", {"mode": "store", "names": ["newone"], "op": "update"})
        # an env request for a granted secret is pending, not approved
        self.assertTrue(all(r.status in ("pending", "failed") for r in self.broker._by_id.values()
                            if r.mode == "env"))

    def test_ssh_sign_uses_grant(self):
        rid = self.sign()
        self.assertEqual(self.approve(rid, "approve_grant_5"), 303)
        self.broker._by_id[rid].done.wait(10)
        n = len(self.notifier.sent)
        rid2 = self.sign()
        got = self.result(rid2)
        self.assertEqual(got["status"], "approved")
        self.assertIn("ssh_signature", got)
        self.assertEqual(len(self.notifier.sent), n)

    def test_expiry_exactly_at_deadline(self):
        self.grant_it()
        exp = self.broker.active_grants()[0]["expires_at"]
        real_now = time.time()
        self.offset += (exp - real_now) - 0.5
        self.assertEqual(len(self.broker.active_grants()), 1)
        self.offset += 0.5 + 0.001
        self.assertEqual(self.broker.active_grants(), [])
        self.assertEqual(len(self.events("grant_expired")), 1)
        n = len(self.notifier.sent)
        self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_expiry_is_audited_by_sweep_and_absolute(self):
        self.grant_it(minutes=5)
        self.offset += 200
        self.http(path="/mid")                          # use does not extend
        self.offset += 200
        self.assertEqual(self.broker.grants.sweep()[0]["secrets"], ["svc"])
        self.assertEqual(len(self.events("grant_expired")), 1)

    def test_revoke(self):
        self.grant_it()
        gid = self.broker.active_grants()[0]["id"]
        self.assertTrue(self.broker.revoke_grant(gid, "alice", "1.2.3.4", None))
        self.assertFalse(self.broker.revoke_grant(gid, "alice"))
        ev = self.events("grant_revoked")[0]
        self.assertEqual((ev["grant_id"], ev["secrets"], ev["revoked_by"], ev["created_by"]),
                         (gid, ["svc"], "alice", "alice"))
        n = len(self.notifier.sent)
        self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)

    def test_concurrent_requests_share_one_grant(self):
        self.grant_it()
        n = len(self.notifier.sent)
        out = []
        ts = [threading.Thread(target=lambda i=i: out.append(self.http(path=f"/c{i}"))) for i in range(2)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual([self.result(r)["status"] for r in out], ["approved", "approved"])
        self.assertEqual(len(self.notifier.sent), n)


class NoCeilingByDefault(Base):
    """`timed_grants.max_risk` defaults to high: a timed grant releases at any risk."""
    risk = "high"

    def test_high_risk_and_missing_verdict_are_released(self):
        self.grant_it()
        n = len(self.notifier.sent)
        self.assertEqual(self.result(self.http())["status"], "approved")
        self.broker.summarizer = None
        self.assertEqual(self.result(self.http(path="/y"))["status"], "approved")
        self.assertEqual(len(self.notifier.sent), n)
        self.assertEqual(self.events("grant_skipped"), [])
        self.assertEqual(self.events("config_warning"), [])


class RiskCeiling(Base):
    """An operator may opt in to a ceiling for timed grants."""
    risk = "medium"
    grants_cfg = {"max_risk": "low"}

    def test_above_ceiling_prompts_and_audits_skip(self):
        self.grant_it()
        n = len(self.notifier.sent)
        rid = self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)
        sk = self.events("grant_skipped")[0]
        self.assertEqual((sk["id"], sk["reason"], sk["max_risk"]), (rid, "risk", "low"))
        self.assertEqual(self.events("grant_used"), [])

    def test_within_ceiling_and_missing_verdict(self):
        self.grant_it()
        self.broker.summarizer = _Stub("x", "low")
        self.assertEqual(self.result(self.http())["status"], "approved")
        self.broker.summarizer = None                    # no verdict counts as high
        n = len(self.notifier.sent)
        self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)


class CeilingNone(Base):
    grants_cfg = {"max_risk": "none"}

    def test_none_never_uses(self):
        self.grant_it()
        n = len(self.notifier.sent)
        self.http()
        self.assertEqual(len(self.notifier.sent), n + 1)


class Disabled(Base):
    grants_cfg = {"enabled": False}

    def test_menu_hidden_and_decision_rejected(self):
        rid = self.http()
        _, page = self.get("/")
        self.assertNotIn("approve_grant_", page)
        self.assertNotIn("Applies to exactly", page)
        self.assertEqual(self.decide(rid, "approve_grant_15")[1], "/?note=bad")
        self.assertEqual(self.status_of(rid), "pending")
        _, pol = self.get("/policies")
        self.assertIn("turned off", pol)
        self.assertFalse(json.loads(self.api("GET", "/v1/status")[1])["features"]["timed_grants"])

    def test_persisted_grants_ignored(self):
        path = os.path.join(os.path.dirname(self.audit), "grants.json")
        with open(path, "w") as f:
            json.dump({"version": 1, "grants": [{
                "id": "ab", "secret": "svc", "minutes": 5, "created_at": time.time(),
                "expires_at": time.time() + 300, "created_by": "alice"}]}, f)
        b = Broker(dict(self.broker.cfg, timed_grants={"enabled": False}), self.broker.backend,
                   FakeNotifier(), self.audit)
        self.assertEqual(b.active_grants(), [])


class Persistence(Base):
    def reload(self):
        return Broker(dict(self.broker.cfg), self.broker.backend, FakeNotifier(), self.audit)

    def path(self):
        return os.path.join(os.path.dirname(self.audit), "grants.json")

    def test_survives_restart_0600_no_secrets(self):
        self.grant_it()
        self.assertEqual(os.stat(self.path()).st_mode & 0o777, 0o600)
        with open(self.path()) as f:
            raw = f.read()
        self.assertNotIn("s3cr3t", raw)
        self.assertNotIn("nonce", raw)
        b = self.reload()
        self.assertEqual([g["secrets"] for g in b.active_grants()], [["svc"]])

    def test_scope_and_set_persist(self):
        self.grant_it(("svc", "other"), method="GET")
        b = self.reload()
        g = b.active_grants()[0]
        self.assertEqual((g["secrets"], g["scope"]), (["other", "svc"], "read"))
        # made from a shared-key request's card: scoped to the legacy client, which is who asked
        self.assertIsNotNone(b.grants.find(["svc", "other"], client="legacy"))
        self.assertIsNone(b.grants.find(["svc", "other"]))
        self.assertIsNone(b.grants.find(["svc"], client="legacy"))

    def test_expired_dropped_on_load_and_audited(self):
        self.grant_it(minutes=5)
        self.offset += 400
        b = self.reload()
        self.assertEqual(b.active_grants(), [])
        self.assertEqual(len(self.events("grant_expired")), 1)

    def test_corrupt_file_fails_closed(self):
        with open(self.path(), "w") as f:
            f.write("{not json")
        b = self.reload()
        self.assertEqual(b.active_grants(), [])
        self.assertEqual(len(self.events("grants_file_corrupt")), 1)

    def test_implausible_deadline_dropped(self):
        with open(self.path(), "w") as f:
            json.dump({"version": 1, "grants": [{
                "id": "ab", "secret": "svc", "minutes": 5, "created_at": time.time(),
                "expires_at": time.time() + 86400, "created_by": "x"}]}, f)
        self.assertEqual(self.reload().active_grants(), [])

    def test_revoke_persists(self):
        self.grant_it()
        self.broker.revoke_grant(self.broker.active_grants()[0]["id"], "alice")
        self.assertEqual(self.reload().active_grants(), [])


class Config(unittest.TestCase):
    def bad(self, raw, field):
        with self.assertRaises(ValueError) as cm:
            grants_mod.parse_config(raw)
        self.assertIn(field, str(cm.exception))

    def test_defaults(self):
        self.assertEqual(grants_mod.parse_config(None), {
            "enabled": True, "durations": [5, 15, 30], "max_minutes": 60, "max_risk": "high"})

    def test_validation_names_fields(self):
        self.bad("x", "timed_grants must")
        self.bad({"enabled": "yes"}, "timed_grants.enabled")
        self.bad({"durations": []}, "timed_grants.durations")
        self.bad({"durations": [0]}, "timed_grants.durations")
        self.bad({"durations": [5, 5]}, "timed_grants.durations")
        self.bad({"durations": [90]}, "timed_grants.durations")
        self.bad({"durations": [1.5]}, "timed_grants.durations")
        self.bad({"durations": [True]}, "timed_grants.durations")
        self.bad({"durations": [1, 2, 3, 4, 5, 6, 7]}, "timed_grants.durations")
        self.bad({"max_minutes": 0}, "timed_grants.max_minutes")
        self.bad({"max_minutes": 99999}, "timed_grants.max_minutes")
        self.bad({"max_risk": "extreme"}, "timed_grants.max_risk")
        self.bad({"bogus": 1}, "timed_grants.bogus")

    def test_sorted_and_cap_raised(self):
        c = grants_mod.parse_config({"durations": [120, 10], "max_minutes": 180})
        self.assertEqual(c["durations"], [10, 120])

    def test_broker_refuses_bad_config(self):
        with self.assertRaises(ValueError):
            import tempfile
            p = os.path.join(tempfile.mkdtemp(), "v.json")
            with open(p, "w") as f:
                f.write("{}")
            Broker({"timed_grants": {"durations": [500]}, "secrets": {}}, FileBackend(p),
                   FakeNotifier(), None)


class CardLayout(Base):
    def card(self, page):
        m = re.search(r"<article class=req.*?</article>", page, re.S)
        self.assertTrue(m)
        return m.group(0)

    def test_approve_and_deny_share_one_row_with_a_filled_danger_deny(self):
        self.http()
        _, page = self.get("/")
        card = self.card(page)
        row = re.search(r"<div class=decide-row>(.*?)</div>", card, re.S).group(1)
        self.assertIn("class='btn approve' name=decision value=approve>Approve once</button>", row)
        self.assertIn("class='btn deny' name=decision value=deny>Deny</button>", row)
        self.assertLess(row.index("Deny"), row.index("Approve once"))      # Deny left, wide Approve once right
        self.assertRegex(page, r"\.btn\.deny\{background:var\(--dnb\);border-color:var\(--dnl\);color:var\(--dnt\)\}")
        self.assertNotIn("<details class=more", page)

    def test_http_card_offers_chips_and_a_confirmed_always(self):
        self.http()
        _, page = self.get("/")
        card = self.card(page)
        self.assertLess(card.index("Approve once</button>"), card.index("<div class=timed>"))
        self.assertLess(card.index(">5 min<"), card.index(">15 min<"))
        self.assertLess(card.index(">30 min<"), card.index(">Always allow this...</summary>"))
        self.assertNotIn("Automatically approve", card)
        # Always is behind a confirmation: the submit button lives inside the opened <details>
        det = re.search(r"<details class=alw>(.*?)</details>", card, re.S).group(1)
        self.assertIn("name=decision value=approve_always>Confirm", det)
        self.assertEqual(card.count("value=approve_always"), 1)
        self.assertNotRegex(card.replace(det, ""), "value=approve_always")
        self.assertIn("Applies to exactly: svc. Reads only (GET, HEAD, OPTIONS).", card)
        self.assertNotIn(" title=", card[card.index("<div class=decide-row>"):])
        for m in re.findall(r"<(?:button|summary|span) class=[^>]*>", card):
            if "chip" in m:
                self.assertIn("aria-label=", m)
        _, lp = self.get(f"/a/{next(iter(self.broker._by_nonce))}")
        self.assertIn("<div class=decide-row>", lp)
        self.assertIn("<div class=timed>", lp)
        self.assertIn("value=approve_always>Confirm", lp)
        self.assertNotIn(" title=", self.card_link(lp))

    def card_link(self, lp):
        return lp[lp.index("<form"):lp.index("</form>")]

    def test_non_read_method_says_any_method(self):
        self.http(method="POST")
        _, page = self.get("/")
        self.assertIn("Applies to exactly: svc. Any method.", page)

    def test_ssh_sign_has_chips_and_a_disabled_always(self):
        self.sign()
        _, page = self.get("/")
        card = self.card(page)
        self.assertIn(">5 min</button>", card)
        self.assertNotIn("approve_always", card)
        m = re.search(r"<span class='chip off linkish'[^>]*>Always allow this...</span>", card)
        self.assertTrue(m)
        self.assertIn("data-tip='Always not offered:", m.group(0))
        self.assertNotIn(" title=", card[card.index("<div class=decide-row>"):])

    def test_env_has_grant_chips_with_release_wording(self):
        self.create_env()
        _, page = self.get("/")
        card = self.card(page)
        self.assertIn("<div class=decide-row>", card)
        self.assertIn("<div class=timed>", card)
        self.assertIn("approve_grant_5", card)
        self.assertIn("released to the requesting machine for the chosen time", card)

    def test_chip_values_are_the_old_contract(self):
        rid = self.http()
        _, page = self.get("/")
        for m in (5, 15, 30):
            self.assertIn(f"value='approve_grant_{m}'", page)
        self.assertEqual(self.approve(rid, "approve_grant_30"), 303)
        self.assertEqual(self.broker.active_grants()[0]["minutes"], 30)

    def test_markup_is_deterministic_for_a_fixed_state(self):
        self.http()
        strip = lambda c: re.sub(r"\d+:\d\d left|data-exp='\d+'", "", c)
        a = strip(self.card(self.get("/")[1]))
        b = strip(self.card(self.get("/")[1]))
        self.assertEqual(a, b)

    def test_names_are_escaped(self):
        self.broker.cfg["secrets"]["<b>x"] = dict(self.broker.cfg["secrets"]["svc"])
        self.http(names=("svc",))
        r = next(iter(self.broker._by_id.values()))
        r.names = ["<b>x"]
        from secret_broker.broker import _approve_actions
        out = _approve_actions(self.broker, r)
        self.assertNotIn("<b>x", out)
        self.assertIn("&lt;b&gt;x", out)


class Pages(Base):
    grants_cfg = {"durations": [10, 60, 120], "max_minutes": 120}

    def test_policies_empty_then_listed_with_revoke(self):
        _, pol = self.get("/policies")
        self.assertIn("No standing approvals", pol)
        self.assertIn("Standing approvals", pol)
        self.assertNotIn("Active grants", pol)
        self.assertNotIn("Always allowed", pol)
        self.grant_it(minutes=60)
        _, pol = self.get("/policies")
        self.assertIn("data-gexp", pol)
        self.assertIn("/grants/revoke", pol)
        self.assertIn("<b>svc</b>", pol)
        self.assertIn("web reads only", pol)
        self.assertRegex(pol, r"<time data-gexp='\d+'>in (59|60) min</time>")
        self.grant_it(("svc", "other"), 10, method="POST")
        _, pol = self.get("/policies")
        self.assertIn("<b>other, svc</b>", pol)
        self.assertIn("web any method", pol)
        gid = next(g["id"] for g in self.broker.active_grants() if g["scope"] == "read")
        form = {"grant": gid, "csrf": "bad"}
        def post(form):
            try:
                return urllib.request.urlopen(urllib.request.Request(
                    self.abase + "/grants/revoke", data=urllib.parse.urlencode(form).encode(),
                    headers=H, method="POST"), timeout=10).status
            except urllib.error.HTTPError as e:
                return e.code
        self.assertEqual(post(form), 403)
        self.assertEqual(len(self.broker.active_grants()), 2)
        self.assertEqual(post({"grant": gid, "csrf": self.broker.csrf_token("alice")}), 200)
        self.assertEqual([g["scope"] for g in self.broker.active_grants()], ["any"])
        self.assertEqual(self.get("/policies", "mallory")[0], 403)

    def test_settings_line_and_card_durations(self):
        _, s = self.get("/settings")
        self.assertIn("Standing approvals: timed grants (no ceiling) 10/60/120 min; Always up to low risk", s)
        self.http()
        _, page = self.get("/")
        self.assertIn(">2 hr</button>", page)
        self.assertIn(">10 min</button>", page)

    def test_creator_name_is_escaped(self):
        self.broker.grants.add(["svc"], 5, "any", "<script>x</script>", "dashboard", "r")
        _, pol = self.get("/policies")
        self.assertNotIn("<script>x", pol)
        self.assertIn("&lt;script&gt;", pol)


class NoLeak(Base):
    def test_agent_surfaces_do_not_reveal_grants(self):
        self.grant_it()
        for path in ("/v1/secrets", "/v1/secrets?host=127.0.0.1", "/v1/status"):
            _, body = self.api("GET", path)
            self.assertNotIn("grant", body.replace("timed_grants", ""), path)
            self.assertNotIn("expires", body, path)
        st = json.loads(self.api("GET", "/v1/status")[1])
        self.assertIs(st["features"]["timed_grants"], True)
        self.assertEqual(sorted(k for k in st["features"] if "grant" in k), ["timed_grants"])
        # the poll result of a grant-approved request looks like any other approval
        rid = self.http(path="/z")
        got = self.result(rid)
        self.assertNotIn("grant", json.dumps(got))


if __name__ == "__main__":
    unittest.main()
