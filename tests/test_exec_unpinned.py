"""Remote exec for a host the key does not fully pin (docs/superpowers/specs/2026-11-20-exec-unpinned-hosts-design.md):
a new host or port, the same key on another port, and a changed key are never refused and never auto-approved; they
reach a human with the fingerprint, a banner for a changed key, and decisions (once, remember, replace) that are
validated on the broker whatever the form says. The probe itself is tests/test_execprobe.py; the runner is
tests/test_execrun.py; the real OpenSSH is tests/e2e_remote_exec/.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_exec_intake as ti  # noqa: E402
from test_exec_intake import FRESH, NAS, PORT, UNLISTED, probe_result  # noqa: E402
from secret_broker import audit_api, autorules, destguard, execmode, execprobe  # noqa: E402
from secret_broker import sshkey  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
from test_execrun import STUB  # noqa: E402

FP = {k: probe_result(v)["fingerprint"] for k, v in (("nas", NAS), ("port", PORT), ("fresh", FRESH),
                                                      ("unlisted", UNLISTED))}
NEW = "new.example.com"          # not on the key at all


class Unpinned(ti.ExecBase):
    def new(self, **kw):
        return {"host": NEW, **kw}

    def changed(self, **kw):                      # nas.example.com:22 is pinned; the server now presents FRESH
        self.servers.table[("nas.example.com", 22)] = FRESH
        return {"host": "nas.example.com", **kw}

    def elsewhere(self, **kw):                    # nas.example.com:22 is pinned; port 2222 presents the same key
        self.servers.table[("nas.example.com", 2222)] = NAS
        return {"host": "nas.example.com", "port": 2222, **kw}

    def post(self, path, form, origin=False):
        form = {**form, "csrf": self.broker.csrf_token("alice")}
        hdr = {"X-authentik-username": "alice"}
        if origin:
            hdr["Origin"] = "https://secrets.example"

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            r = urllib.request.build_opener(NoFollow).open(urllib.request.Request(
                self.abase + path, data=urllib.parse.urlencode(form).encode(), headers=hdr, method="POST"), timeout=10)
            return r.status, r.headers.get("Location"), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode()

    def decide_form(self, rid, decision, **fields):
        return self.post("/decide", {"id": rid, "decision": decision, **fields})

    def req(self, rid):
        return self.broker._by_id[rid]

    def card(self, rid):
        return self.get(f"/a/{self.req(rid).nonce}")[1]

    def states(self):
        return {"new": self.new(), "same_key_elsewhere": self.elsewhere(), "changed": self.changed()}


class Intake(Unpinned):
    def test_each_state_is_a_pending_request_never_a_refusal(self):
        self.enable(max_pending_per_client=20)
        for state, body in self.states().items():
            rid = self.pending(**body)
            sp = self.req(rid).spec
            self.assertEqual(sp["host_state"], state)
            self.assertEqual(sp["presented_fp"], FP["nas"] if state == "same_key_elsewhere" else FP["fresh"])
            self.assertEqual(sp["pinned_fp"], FP["nas"] if state == "changed" else None)
            self.assertEqual(sp["same_as"], "nas.example.com:22" if state == "same_key_elsewhere" else None)
            self.assertEqual(self.req(rid).risk["level"], "high")
        self.assertEqual(self.ran, [])
        self.assertEqual(self.events("rejected"), [])
        self.assertEqual([e["state"] for e in self.events("exec_probe")], ["new", "same_key_elsewhere", "changed"])

    def test_nothing_can_approve_it_but_a_human(self):
        # every rule, policy and standing form that auto-approves an ordinary request
        self.broker.auto_rules = autorules.parse([
            {"name": "up", "mode": "exec", "secret": "deploy", "host": NEW, "account": "ryan", "argv": ["uptime"]},
            {"name": "up2", "mode": "exec", "secret": "deploy", "host": "nas.example.com", "account": "ryan",
             "argv": ["uptime"]}])
        sc = self.broker.cfg["secrets"]["deploy"]
        sc.update(approval="allow", auto_modes=["ssh_sign", "exec"])
        sc["auto_rules"] = autorules.parse_stored(
            [{"id": "x0001", "name": "s", "mode": "exec", "host": NEW, "account": "ryan", "port": 22, "argv": ["uptime"],
              "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None}], "deploy", ssh=True)
        self.broker.set_approval("deploy", "allow", "alice")
        self.enable(max_pending_per_client=20)
        # positive control: the same machinery DOES approve an ordinary request for a pinned host
        code, b = self.ask(command="uptime")
        self.assertEqual(code, 202, b)
        ok = self.req(json.loads(b)["id"])
        ok.done.wait(10)
        self.assertEqual(self.ran, [ok.id])
        self.assertEqual(self.events("approved")[-1]["via"], "policy")
        for state, body in self.states().items():
            before = len(self.ran)
            rid = self.pending(command="uptime", **body)
            self.assertEqual(self.req(rid).status, "pending", state)
            self.assertEqual(len(self.ran), before, state)
        self.assertEqual(len(self.events("auto_rule_used")) + len(self.events("rule_used")), 1)   # only the control

    def test_a_probe_failure_is_one_text_and_the_label_is_only_in_the_audit(self):
        labels = ("unreachable", "not_ssh", "timeout", "refused_destination", "rate_limited", "ssh_unavailable")
        texts = set()
        for label in labels:
            self.servers.table[(NEW, 22)] = {"label": label}
            before = len(self.events("requested"))
            code, b = self.ask(host=NEW)
            self.assertEqual(code, 403, label)
            err = json.loads(b)["error"]
            texts.add(err)
            self.assertNotIn(label, err)
            self.assertEqual(len(self.events("requested")), before)
        self.assertEqual(texts, {"could not read that host's key"})
        self.assertEqual([e["outcome"] for e in self.events("exec_probe")], list(labels))
        self.assertEqual({e["host"] for e in self.events("exec_probe")}, {NEW})
        self.assertEqual(self.ran, [])

    def test_a_probe_that_raises_is_a_failure_with_no_exception_text(self):
        def boom(host, port, cid):
            raise RuntimeError("S3CR3T-probe-exception")
        self.broker.exec_probe = boom
        code, b = self.ask(host=NEW)
        self.assertEqual((code, json.loads(b)["error"]), (403, "could not read that host's key"))
        self.assertNotIn("S3CR3T", open(self.audit).read() + b)
        self.assertEqual(self.events("exec_probe")[-1]["outcome"], "unreachable")

    def test_a_failing_probe_does_not_block_a_host_the_key_already_pins(self):
        self.servers.table[("nas.example.com", 22)] = {"label": "timeout"}
        rid = self.pending()
        self.assertNotIn("host_state", self.req(rid).spec)           # the ordinary flow, as before the probe existed
        self.assertEqual(self.events("exec_probe")[-1]["outcome"], "timeout")
        # but a host that is not pinned and allowed fails
        self.assertEqual(self.ask(host=NEW)[0], 202)                 # control: the stub serves it
        self.servers.table[("nas.example.com", 2222)] = {"label": "timeout"}
        self.assertEqual(self.ask(host="nas.example.com", port=2222)[0], 403)

    def test_the_pending_cap_is_checked_before_any_probe(self):
        self.enable(max_pending_per_client=1)
        self.pending(**self.new())
        n = len(self.servers.calls)
        self.assertEqual(n, 1)                                       # premise: the first one did probe
        code, b = self.ask(host="other-new.example.com")
        self.assertEqual((code, json.loads(b)["error"]), (403, "too many pending remote command requests"))
        self.assertEqual(len(self.servers.calls), n)                 # no probe for a request that is refused anyway

    def test_a_name_that_resolves_to_a_forbidden_address_is_refused_by_the_real_probe(self):
        hit = []
        guard = destguard.DestGuard(resolver=lambda h, p: ["93.184.216.34", "::ffff:10.1.2.3"], local_addrs=lambda: [],
                                    connector=lambda *a, **k: hit.append(a))
        cfg = self.broker.exec_cfg
        self.broker.exec_probe = execprobe.Prober(guard, lambda: cfg).probe
        code, b = self.ask(host=NEW)
        self.assertEqual((code, json.loads(b)["error"]), (403, "could not read that host's key"))
        self.assertEqual(hit, [])                                    # nothing was connected to
        self.assertEqual(self.events("exec_probe")[-1]["outcome"], "refused_destination")

    def test_the_rate_limit_follows_the_config(self):
        self.assertEqual(self.broker._exec_prober.limiter.per_client, 30)
        self.broker.exec_cfg = execmode.parse_config({"enabled": True, "clients": [self.agent.id],
                                                      "probe_per_client": 2, "probe_overall": 3})
        self.assertEqual((self.broker._exec_prober.limiter.per_client, self.broker._exec_prober.limiter.overall), (2, 3))

    def test_the_host_state_cannot_be_sent_by_the_agent(self):
        self.assertEqual(self.ask()[0], 202)
        for extra in ({"host_state": "pinned"}, {"presented_fp": FP["nas"]}, {"presented_key": "x"}, {"pinned_fp": "x"},
                      {"exec_choice": "remember"}, {"probe_address": "127.0.0.1"}):
            code, b = self.ask(**extra)
            self.assertEqual((code, json.loads(b)["error"]), (400, "unknown field in an exec request"), extra)

    def test_the_agent_sees_only_the_status(self):
        code, b = self.ask(**self.new())
        self.assertEqual(code, 202)
        rid = json.loads(b)["id"]
        self.assertEqual(self.poll(rid), {"status": "pending", "error": None})
        for text in (b.decode() if isinstance(b, bytes) else b, json.dumps(self.poll(rid))):
            self.assertNotIn("SHA256", text)
            self.assertNotIn("presented", text)
        self.assertIn("host_state", self.req(rid).spec)               # premise: there was something to hide
        for k in ("host_state", "presented_fp", "pinned_fp", "same_as", "presented_key"):
            self.assertNotIn(k, audit_api.WHITELIST["requested"])
        self.assertIn("exec_probe", audit_api.HIDDEN)

    def test_the_audit_requested_event_has_the_state_and_fingerprints(self):
        self.pending(**self.changed())
        ev = self.events("requested")[-1]
        self.assertEqual((ev["host_state"], ev["presented_fp"], ev["pinned_fp"]), ("changed", FP["fresh"], FP["nas"]))
        self.assertNotIn("presented_key", ev)

    def test_a_key_pinned_under_another_name_is_not_the_same_key(self):
        self.servers.table[("evil.example.com", 22)] = UNLISTED        # pinned, but for unlisted.example.com
        rid = self.pending(host="evil.example.com")
        self.assertEqual(self.req(rid).spec["host_state"], "new")
        self.assertNotIn("Same key", self.card(rid))
        rid = self.pending(**self.elsewhere())                          # positive control: the right name is recognised
        self.assertIn("Same key as nas.example.com:22", self.card(rid))

    def test_a_pinned_line_for_a_host_that_is_not_allowed_is_not_pinned(self):
        self.servers.table[("unlisted.example.com", 22)] = UNLISTED     # line present, name not on allowed_hosts
        rid = self.pending(host="unlisted.example.com")
        self.assertEqual(self.req(rid).spec["host_state"], "new")


class Card(Unpinned):
    def test_a_new_host_shows_host_port_fingerprint_and_the_tofu_limit(self):
        rid = self.pending(**self.new(port=2200))
        card = self.card(rid)
        for want in (f"<b>Run on {NEW}</b>", f"{NEW}, port 2200", FP["fresh"], execmode.FIRST_USE,
                     "value=approve>Approve once", "value=approve_remember>", "value=deny>"):
            self.assertIn(want, card)
        for never in ("approve_replace", "confirm_replace", "HOST KEY CHANGED", "approve_always", "approve_grant_",
                      "Automatically approve...", "ssh_rule"):
            self.assertNotIn(never, card, never)

    def test_the_same_key_elsewhere_says_so(self):
        card = self.card(self.pending(**self.elsewhere()))
        self.assertIn("Same key as nas.example.com:22", card)
        self.assertIn("value=approve_remember>", card)

    def test_a_changed_key_has_the_banner_both_fingerprints_and_no_plain_remember(self):
        card = self.card(self.pending(**self.changed()))
        for want in ("HOST KEY CHANGED", FP["fresh"], FP["nas"], "man-in-the-middle", "value=approve>Approve once",
                     "value=approve_replace>", "name=confirm_replace value=1"):
            self.assertIn(want, card)
        self.assertNotIn("approve_remember", card)
        self.assertLess(card.index("HOST KEY CHANGED"), card.index("<code>uptime</code>"))     # above the command
        self.assertNotIn("approve_always", card)

    def test_the_pinned_card_is_unchanged(self):
        card = self.card(self.pending())
        for never in ("approve_remember", "approve_replace", "hostban", "Approve once"):
            self.assertNotIn(never, card)
        self.assertIn("value=approve>", card)

    def test_remember_is_not_offered_on_a_key_that_does_not_restrict_hosts(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc["ssh_hosts"] = {**sc["ssh_hosts"], "allowed": None}
        card = self.card(self.pending(**self.new()))
        self.assertIn("Not offered: this key has no Allowed hosts list", card)
        self.assertNotIn("approve_remember", card)
        self.assertIn("value=approve>Approve once", card)             # approving once still works

    def test_the_fingerprint_on_the_card_comes_through_the_fixed_escaping(self):
        hostile = {"keys": [], "fingerprint": "SHA256:<script>x</script>", "key_type": "ssh-ed25519",
                   "key": "ssh-ed25519 AAAA", "address": "93.184.216.34"}
        self.assertIn("(unavailable)", execmode.fp_html(hostile["fingerprint"]))
        self.assertNotIn("<script>", execmode.fp_html(hostile["fingerprint"]))
        sp = {"host_state": "changed", "host": "a.example", "port": 22, "presented_fp": "<img src=x>", "pinned_fp": "\"><b>"}
        html_ = execmode.host_html(sp)
        self.assertNotIn("<img", html_)
        self.assertNotIn("\"><b>", html_)
        self.assertIn("HOST KEY CHANGED", html_)                      # premise: the block rendered


class Notification(Unpinned):
    def test_host_and_port_but_no_fingerprint_and_no_buttons(self):
        self.enable(max_pending_per_client=20)
        seen_changed = False
        for state, body in self.states().items():
            self.broker.notifier = FakeNotifier(supports_actions=("approve", "deny"))
            rid = self.pending(**body)
            req = self.req(rid)
            n = req.notification
            self.assertIn(f"{body['host']}:{body.get('port', 22)}", n.text, state)
            self.assertIn("approval page", n.text)
            for fp in FP.values():
                self.assertNotIn(fp, n.text + n.title)
            self.assertEqual((n.actions, n.action_token), ([], None), state)
            self.assertEqual((req.offered, req.action_hash), (frozenset(), None), state)
            self.assertNotIn("SHA256", json.dumps(self.broker.notifier.sent))
            if state == "changed":
                self.assertIn("CHANGED", n.text + n.title)
                seen_changed = True
        self.assertTrue(seen_changed)

    def test_a_pinned_request_keeps_its_buttons(self):
        self.broker.notifier = FakeNotifier(supports_actions=("approve", "deny"))
        req = self.req(self.pending())
        self.assertEqual(req.offered, frozenset({"approve", "deny"}))

    def test_a_token_channel_cannot_decide_it_even_with_a_valid_token(self):
        rid = self.pending(**self.new())
        req = self.req(rid)
        token = "T0KEN-forged"
        req.action_hash, req.offered = hashlib.sha256(token.encode()).digest(), frozenset({"approve", "deny"})
        for channel in ("push", "ha", "telegram"):
            code, got = self.broker.decide_via(channel, rid, "approve", "phone", token=token)
            self.assertEqual((code, got), (403, None), channel)
            self.assertEqual(req.status, "pending", channel)
        self.assertEqual(self.ran, [])
        # positive control: the same forged setup on an ordinary request IS accepted, so the refusal above is about
        # the unpinned state and not about the harness
        req2 = self.req(self.pending())
        req2.action_hash, req2.offered = hashlib.sha256(token.encode()).digest(), frozenset({"approve", "deny"})
        self.assertEqual(self.broker.decide_via("push", req2.id, "approve", "phone", token=token)[0], 200)


class Decisions(Unpinned):
    def test_approve_once_runs_it_and_remembers_nothing(self):
        rid = self.pending(**self.new())
        before = json.dumps(self.broker.cfg["secrets"]["deploy"]["_meta"], sort_keys=True)
        self.assertEqual(self.decide_form(rid, "approve")[0], 303)
        self.req(rid).done.wait(10)
        self.assertEqual(self.ran, [rid])
        self.assertEqual(self.req(rid).exec_choice, "once")
        self.assertEqual(json.dumps(self.broker.cfg["secrets"]["deploy"]["_meta"], sort_keys=True), before)

    def test_deny_is_final_and_runs_nothing(self):
        rid = self.pending(**self.changed())
        self.decide_form(rid, "deny")
        self.assertEqual(self.poll(rid)["status"], "denied")
        self.assertEqual(self.ran, [])

    def test_forged_choices_are_refused_with_400_and_claim_nothing(self):
        cases = [
            ("changed", "approve_remember", {}),                          # remember on a changed key
            ("changed", "approve_replace", {}),                           # replace without the tick
            ("changed", "approve_replace", {"confirm_replace": "0"}),
            ("changed", "approve_replace", {"confirm_replace": "yes"}),
            ("new", "approve_replace", {"confirm_replace": "1"}),         # replace where nothing is pinned
            ("same_key_elsewhere", "approve_replace", {"confirm_replace": "1"}),
            ("changed", "approve_always", {}), ("new", "approve_always", {}), ("new", "approve_grant_5", {}),
            ("new", "approve_always_script", {}),
        ]
        for state, decision, fields in cases:
            rid = self.pending(**self.states()[state])
            code, loc, _ = self.decide_form(rid, decision, **fields)
            self.assertEqual((code, loc), (303, "/?note=bad"), (state, decision, fields))
            self.assertEqual(self.req(rid).status, "pending", (state, decision, fields))
            self.assertIsNone(self.req(rid).exec_choice)
            self.broker._by_id[rid].status = "expired"
        self.assertEqual((self.ran, self.events("approved"), self.events("decided")), ([], [], []))
        # positive control: the allowed forms on the same fixtures are accepted
        for state, decision, fields in (("changed", "approve_replace", {"confirm_replace": "1"}),
                                        ("new", "approve_remember", {}), ("same_key_elsewhere", "approve", {})):
            rid = self.pending(**self.states()[state])
            self.assertEqual(self.decide_form(rid, decision, **fields)[0], 303)
            self.assertEqual(self.req(rid).status in ("approved", "deciding", "released"), True, (state, decision))

    def test_choices_on_the_broker_side_without_the_form(self):
        d = self.broker.decide_via
        for state, kw in (("changed", {"exec_host": "remember"}), ("changed", {"exec_host": "replace"}),
                          ("changed", {"exec_host": "replace", "confirm_replace": 1}),     # truthy is not True
                          ("changed", {"exec_host": "replace", "confirm_replace": "1"}),
                          ("new", {"exec_host": "replace", "confirm_replace": True}),
                          ("new", {"exec_host": "bogus"}), ("new", {"exec_host": ""}),
                          ("new", {"exec_host": "remember", "always": True}),
                          ("new", {"exec_host": "remember", "ssh_rule": {"days": 1}})):
            rid = self.pending(**self.states()[state])
            code, got = d("dashboard", rid, "approve", "alice", **kw)
            self.assertEqual((code, got), (400, None), (state, kw))
            self.assertEqual(self.req(rid).status, "pending")
            self.req(rid).status = "expired"
        for kw in ({"exec_host": "remember"}, {"exec_host": "once"}):                  # a denial carries no choice
            rid = self.pending(**self.new())
            self.assertEqual(d("dashboard", rid, "deny", "alice", **kw)[0], 400)
            self.assertEqual(self.req(rid).status, "pending")
            self.req(rid).status = "expired"
        rid = self.pending(**self.new())
        self.assertEqual(d("dashboard", rid, "deny", "alice")[0], 200)                  # control

    def test_a_host_choice_on_an_ordinary_request_claims_nothing(self):
        for decision, fields in (("approve_remember", {}), ("approve_replace", {"confirm_replace": "1"})):
            rid = self.pending()
            self.decide_form(rid, decision, **fields)
            self.assertEqual(self.req(rid).status, "pending", decision)
            self.req(rid).status = "expired"
        rid = self.pending()
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", exec_host="remember")[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice")[0], 200)     # control

    def test_the_link_page_validates_the_same_way(self):
        rid = self.pending(**self.changed())
        nonce = self.req(rid).nonce
        code, _, body = self.post(f"/a/{nonce}", {"decision": "approve_remember"}, origin=True)
        self.assertEqual(code, 400)
        self.assertIn("That choice is not available", body)
        self.assertEqual(self.req(rid).status, "pending")
        code, _, body = self.post(f"/a/{nonce}", {"decision": "approve_replace"}, origin=True)
        self.assertEqual((code, self.req(rid).status), (400, "pending"))
        code, _, body = self.post(f"/a/{nonce}", {"decision": "approve_replace", "confirm_replace": "1"}, origin=True)
        self.assertEqual(code, 200)                                     # positive control
        self.assertEqual(self.req(rid).exec_choice, "replace")

    def test_remember_is_refused_when_the_key_does_not_restrict_hosts(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        sc["ssh_hosts"] = {**sc["ssh_hosts"], "allowed": None}
        rid = self.pending(**self.new())
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", exec_host="remember")[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", exec_host="once")[0], 200)

    def test_the_run_refuses_an_unpinned_request_no_person_decided(self):
        # defence in depth: even if some path released it, the real runner stops without a human's choice
        rid = self.pending(**self.new())
        req = self.req(rid)
        del self.broker._exec_run                                       # back to the real method
        with self.assertRaises(Exception) as cm:
            self.broker._exec_run(req)
        self.assertIn("needs a person's decision", str(cm.exception))
        spec = dict(req.spec)
        req.exec_choice = "once"
        req.spec["presented_key"] = "not a key"                         # fields not shaped by the probe: also refused
        with self.assertRaises(Exception) as cm:
            self.broker._exec_run(req)
        self.assertIn("needs a person's decision", str(cm.exception))
        req.spec.update(spec)
        self.assertTrue(execmode.host_fields_ok(req.spec))              # premise: the real fields pass the shape check


SSH_BEFORE = ti.SSH_HOSTS


class Run(Unpinned):
    """Decisions through the REAL runner (stub ssh programs): what is persisted, what is connected to."""

    def tweak(self, cfg):
        super().tweak(cfg)
        self.stubs = tempfile.mkdtemp(prefix="stubs-")
        self.addCleanup(shutil.rmtree, self.stubs, True)
        for name in ("ssh", "ssh-agent", "ssh-add"):
            shutil.copy(STUB, os.path.join(self.stubs, name))
            os.chmod(os.path.join(self.stubs, name), 0o755)
        with open(os.path.join(self.stubs, "config.json"), "w") as f:
            json.dump({"ssh": {"stdout": "ran\n", "rc": 0}}, f)

    def setUp(self):
        super().setUp()
        del self.broker._exec_run
        self.enable(ssh_path=self.stubs, max_pending_per_client=20)
        self.broker.dest_guard._resolver = lambda h, p: ["93.184.216.34"]
        self.meta0 = json.dumps(self.meta(), sort_keys=True)

    def meta(self):
        return self.broker.cfg["secrets"]["deploy"]["_meta"].get("ssh_hosts")

    def ssh_calls(self):
        try:
            with open(os.path.join(self.stubs, "calls.jsonl")) as f:
                return [c for c in map(json.loads, f) if c["tool"] == "ssh" and c.get("phase") != "end"]
        except FileNotFoundError:
            return []

    def go(self, decision, state="new", **fields):
        rid = self.pending(**self.states()[state])
        self.assertEqual(self.decide_form(rid, decision, **fields)[0], 303)
        self.req(rid).done.wait(20)
        return self.req(rid)

    def lines(self, host, port=22):
        return sshkey.known_host_lines(self.meta()["known_hosts"], host, port)

    def test_approve_once_connects_to_the_shown_key_and_persists_nothing(self):
        req = self.go("approve")
        self.assertEqual(self.poll(req.id)["exit_code"], 0)                  # premise: it really ran
        [c] = self.ssh_calls()
        self.assertEqual(c["known_hosts"], f"{NEW} {req.spec['presented_key']}\n")
        self.assertIn("HostName=93.184.216.34", c["argv"])                   # connected to the guard-validated address
        self.assertEqual(json.dumps(self.meta(), sort_keys=True), self.meta0)
        self.assertEqual(self.events("exec_host_remembered") + self.events("exec_host_replaced"), [])
        rid = self.pending(host=NEW)                                          # still unpinned next time
        self.assertEqual(self.req(rid).spec["host_state"], "new")

    def test_the_runner_is_given_only_the_fingerprint_shown_never_the_catalogs_lines(self):
        req = self.go("approve", "changed")                                   # the old pinned line must not travel along
        [c] = self.ssh_calls()
        self.assertEqual(c["known_hosts"], f"nas.example.com {req.spec['presented_key']}\n")
        self.assertNotIn(sshkey.public_line(NAS).split()[1], c["known_hosts"])
        self.assertEqual(json.dumps(self.meta(), sort_keys=True), self.meta0)

    def test_a_pinned_request_still_gets_its_catalog_lines_and_no_hostname_override(self):
        self.broker.auto_rules = autorules.parse([{"name": "up", "mode": "exec", "secret": "deploy",
                                                   "host": "nas.example.com", "account": "ryan", "argv": ["uptime"]}])
        rid = json.loads(self.ask(command="uptime")[1])["id"]
        self.req(rid).done.wait(20)
        [c] = self.ssh_calls()
        self.assertEqual(c["known_hosts"], f"nas.example.com {sshkey.public_line(NAS)}\n")
        self.assertFalse([a for a in c["argv"] if a.startswith("HostName=")])

    def test_remember_pins_the_line_and_allows_the_host_and_the_next_call_is_pinned(self):
        req = self.go("approve_remember")
        self.assertEqual(self.poll(req.id)["exit_code"], 0)
        self.assertEqual(self.lines(NEW), [f"{NEW} {req.spec['presented_key']}"])
        self.assertIn(NEW, self.meta()["allowed_hosts"])
        self.assertEqual(self.disk()["secrets"]["deploy"]["ssh_hosts"], self.meta())    # the vault, not just memory
        self.assertIn(NEW, self.broker.cfg["secrets"]["deploy"]["ssh_hosts"]["allowed"])
        for old in SSH_BEFORE["known_hosts"]:                                 # nothing else was touched
            self.assertIn(old, self.meta()["known_hosts"])
        ev = self.events("exec_host_remembered")[-1]
        self.assertEqual((ev["host"], ev["port"], ev["fingerprint"], ev["approver"], ev["channel"], ev["changed"]),
                         (NEW, 22, FP["fresh"], "alice", "dashboard", True))
        self.assertIn(NEW, self.get("/credentials/deploy?tab=policies")[1])    # the credential editor shows it
        rid = self.pending(host=NEW)                                          # now an ordinary pinned request
        self.assertNotIn("host_state", self.req(rid).spec)

    def test_remember_for_another_port_adds_the_bracketed_line(self):
        rid = self.pending(**self.elsewhere())
        self.decide_form(rid, "approve_remember")
        self.req(rid).done.wait(20)
        self.assertEqual(self.lines("nas.example.com", 2222),
                         [f"[nas.example.com]:2222 {self.req(rid).spec['presented_key']}"])
        self.assertEqual(len(self.lines("nas.example.com", 22)), 1)           # the port-22 line is untouched

    def test_remembering_the_same_host_twice_does_not_duplicate_the_line_or_the_allowed_entry(self):
        a, b = self.pending(**self.new()), self.pending(**self.new())         # two cards for one unpinned host
        for rid in (a, b):
            self.assertEqual(self.decide_form(rid, "approve_remember")[0], 303)
            self.req(rid).done.wait(20)
            self.assertEqual(self.req(rid).status, "approved")
        self.assertEqual(len(self.lines(NEW)), 1)
        self.assertEqual(self.meta()["allowed_hosts"].count(NEW), 1)
        self.assertEqual(sum(1 for ln in self.meta()["known_hosts"] if ln.startswith(NEW + " ")), 1)
        self.assertEqual([e["changed"] for e in self.events("exec_host_remembered")], [True, False])

    def test_replace_swaps_the_line_in_place_and_audits_both_fingerprints(self):
        req = self.go("approve_replace", "changed", confirm_replace="1")
        self.assertEqual(self.poll(req.id)["exit_code"], 0)
        self.assertEqual(self.lines("nas.example.com"), [f"nas.example.com {req.spec['presented_key']}"])
        self.assertNotIn(sshkey.public_line(NAS), "\n".join(self.meta()["known_hosts"]))     # the old key is gone
        self.assertEqual(len(self.lines("port.example.com", 2222)), 1)                         # others stay
        ev = self.events("exec_host_replaced")[-1]
        self.assertEqual((ev["fingerprint"], ev["replaced_fingerprint"], ev["approver"], ev["channel"]),
                         (FP["fresh"], FP["nas"], "alice", "dashboard"))
        self.assertEqual(self.events("exec_host_remembered"), [])
        rid = self.pending(host="nas.example.com")                                             # pinned again
        self.assertNotIn("host_state", self.req(rid).spec)

    def test_replace_keeps_other_names_on_a_shared_line(self):
        sc = self.broker.cfg["secrets"]["deploy"]
        shared = f"nas.example.com,backup.example.com {sshkey.public_line(NAS)}"
        raw = {**sc["_meta"]["ssh_hosts"], "known_hosts": [shared] + sc["_meta"]["ssh_hosts"]["known_hosts"][1:]}
        self.broker._persist_ssh_hosts("deploy", raw, "alice")
        self.go("approve_replace", "changed", confirm_replace="1")
        self.assertEqual(len(self.lines("backup.example.com")), 1)
        self.assertEqual(self.lines("backup.example.com")[0].split()[2], sshkey.public_line(NAS).split()[1])

    def test_a_vault_failure_leaves_the_old_metadata_runs_nothing_and_says_so(self):
        with mock.patch.object(self.broker.backend, "set_meta", side_effect=OSError("S3CR3T-vault-path")):
            req = self.go("approve_remember")
        self.assertEqual(req.status, "failed")
        got = self.poll(req.id)
        self.assertEqual(got["status"], "failed")
        self.assertNotIn("S3CR3T", json.dumps(got) + open(self.audit).read())
        self.assertEqual(json.dumps(self.meta(), sort_keys=True), self.meta0)
        self.assertEqual(self.disk()["secrets"]["deploy"]["ssh_hosts"], json.loads(self.meta0))   # nor the vault
        self.assertEqual(self.ssh_calls(), [])                                # the command never ran
        self.assertEqual(len(self.events("exec_host_remember_failed")), 1)
        self.assertEqual(self.events("exec_host_remembered"), [])
        req2 = self.go("approve_remember")                                    # positive control: it works when the vault does
        self.assertEqual(req2.status, "approved")

    def test_a_plain_remember_refuses_to_overwrite_a_different_pinned_key(self):
        # a rekey raced two cards: the second plain remember must never silently replace the first one's line
        a = self.pending(**self.new())
        self.go("approve_remember")
        self.req(a).spec["presented_key"] = sshkey.public_line(UNLISTED)
        self.req(a).spec["presented_fp"] = FP["unlisted"]
        self.decide_form(a, "approve_remember")
        self.req(a).done.wait(20)
        self.assertEqual(self.req(a).status, "failed")
        self.assertEqual(len(self.lines(NEW)), 1)
        self.assertNotIn(sshkey.public_line(UNLISTED).split()[1], " ".join(self.lines(NEW)))

    def test_a_dns_answer_that_became_forbidden_after_the_probe_fails_closed(self):
        self.broker.dest_guard._resolver = lambda h, p: ["169.254.169.254"]
        req = self.go("approve")
        got = self.poll(req.id)
        self.assertEqual((got["status"], got["label"], got["exit_code"]), ("released", "connect_failed", None))
        self.assertEqual(self.ssh_calls(), [])

    def test_a_forbidden_second_address_also_fails_closed(self):
        self.broker.dest_guard._resolver = lambda h, p: ["93.184.216.34", "::ffff:10.0.0.1"]
        req = self.go("approve")
        self.assertEqual(self.poll(req.id)["label"], "connect_failed")
        self.assertEqual(self.ssh_calls(), [])

    def test_the_connect_address_is_the_probed_one_when_it_is_still_valid(self):
        self.broker.dest_guard._resolver = lambda h, p: ["93.184.216.35", "93.184.216.34"]
        self.go("approve")
        [c] = self.ssh_calls()
        self.assertIn("HostName=93.184.216.34", c["argv"])                    # the address the human's key was read from


if __name__ == "__main__":
    unittest.main()
