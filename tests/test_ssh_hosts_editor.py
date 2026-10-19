"""The Policies-page editor for an SSH key's ssh_hosts policy."""
import base64
import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import test_e2e as t  # noqa: E402
import test_ssh_host as th  # noqa: E402
from secret_broker import audit_api, sshhosts  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

CANARY = "canary-7c1e.internal"
CANARY2 = "canary-allowed-93bd.internal"
HOST, OTHER = th.Host(), th.Host()
EC, RSA = th.Host(ec.generate_private_key(ec.SECP256R1())), th.Host(rsa.generate_private_key(65537, 2048))
SID_A = th.SID_A


class Base(th.HostBase):
    ssh_hosts = None

    def post(self, path="/policies/ssh_hosts", user="alice", csrf=True, **form):
        if csrf is True:
            form["csrf"] = self.broker.csrf_token("alice")
        elif isinstance(csrf, str):
            form["csrf"] = csrf
        form.setdefault("secret", "deploy")
        data = urllib.parse.urlencode(form).encode()
        try:
            r = t.urllib.request.urlopen(t.urllib.request.Request(
                self.abase + path, data=data, headers={"X-authentik-username": user}, method="POST"), timeout=10)
            return r.status, r.read().decode()
        except t.urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def page(self):
        return t.req(self.abase + "/policies", headers={"X-authentik-username": "alice"})[1]

    def stored(self):
        return self.disk()["secrets"]["deploy"]

    def live(self):
        return self.broker.cfg["secrets"]["deploy"]

    def audit_text(self):
        with open(self.audit) as f:
            return f.read()

    def reload(self):
        return Broker({"approve_base_url": "https://s.example"}, self.broker.backend, FakeNotifier(), None)

    def bound(self, host):
        return self.sign(th.login(SID_A), [host.bind(SID_A)])


class Editor(Base):
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com,10.0.0.5")], "allowed_hosts": ["web.example.com"]}

    def test_card_only_for_ssh_keys_collapsed_with_badge_and_help(self):
        body = self.page()
        self.assertEqual(body.count("action='/policies/ssh_hosts'"), 1)
        card = body.split("sbox'")[1].split("</details>")[0]
        self.assertNotIn(" open", body.split("sbox")[1].split(">")[0])
        self.assertIn("<b>deploy</b>", card)
        self.assertNotIn("<b>svc</b>", card)                 # the http secret has none
        self.assertIn("Enforcing: 1 allowed hosts", card)
        for want in ("Known hosts", "Allowed hosts", "Allow forwarded agent (every hop must also be allowed)",
                     "Hashed entries", "git commit signing with this key will also be refused because it has no server",
                     "lock this key out of use", "name=secret value='deploy'"):
            self.assertIn(want, card)
        self.assertIn("web.example.com,10.0.0.5 ssh-ed25519", card)
        self.assertIn(HOST.fp, card)                         # parsed table

    def test_not_enforcing_badge(self):
        self.assertEqual(self.post(secret="deploy", known_hosts=HOST.line("w"), allowed_hosts="",
                                   confirm_weaken="1")[0], 200)
        self.assertIn("Not enforcing (any server accepted, identity shown only)", self.page())

    def test_no_card_without_ssh_keys(self):
        cfg = {"svc": {"vars": {}, "allowed_hosts": ["a"]}}
        self.assertEqual(sshhosts.policies_section(cfg, "tok"), "")
        # an adopted item that is not an ssh key
        row = {"item": "Modem", "meta": None, "auto": {
            "login": True, "username": True, "password": True, "notes": False, "fields": [], "uris": []}}

        class Rows:
            def catalog(self):
                return [row]
        b = Broker({"approve_base_url": "https://s.example"}, Rows(), FakeNotifier(), None)
        self.assertEqual(sshhosts.policies_section(b.cfg["secrets"], "tok"), "")
        self.assertEqual(b.set_ssh_hosts("modem", "", "a.example", False, "alice")["status"], "refused")

    def test_http_secret_post_is_refused_400(self):
        status, body = self.post(secret="svc", allowed_hosts="a.example")
        self.assertEqual(status, 400)
        self.assertEqual(self.events("ssh_hosts_change_refused")[0]["reason"], "not_ssh_key")
        self.assertEqual(self.post(secret="nope", allowed_hosts="a")[0], 400)

    def test_csrf_origin_identity_and_peer_are_enforced(self):
        before = self.stored()["ssh_hosts"]
        kw = dict(known_hosts="", allowed_hosts="x.example")
        self.assertEqual(self.post(csrf=False, **kw)[0], 403)
        self.assertEqual(self.post(csrf="bad", **kw)[0], 403)
        self.assertEqual(self.post(user="mallory", **kw)[0], 403)
        r = t.urllib.request.Request(
            self.abase + "/policies/ssh_hosts", method="POST",
            headers={"X-authentik-username": "alice", "Origin": "https://evil.example"},
            data=urllib.parse.urlencode({"secret": "deploy", "allowed_hosts": "x", "csrf": self.broker.csrf_token("alice")}).encode())
        with self.assertRaises(t.urllib.error.HTTPError) as cm:
            t.urllib.request.urlopen(r, timeout=10)
        self.assertEqual(cm.exception.code, 403)
        self.broker.cfg["approval_trusted_peers"] = ["10.9.9.0/24"]
        self.assertEqual(self.post(**kw)[0], 403)
        self.assertEqual(self.stored()["ssh_hosts"], before)

    def test_body_over_the_limit_is_413(self):
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.a.server_address[1], timeout=10)
        c.putrequest("POST", "/policies/ssh_hosts")      # header only: the server answers before reading
        for k, v in (("X-authentik-username", "alice"), ("Content-Length", str(sshhosts.FORM_LIMIT + 10)),
                     ("Content-Type", "application/x-www-form-urlencoded")):
            c.putheader(k, v)
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)
        c.close()


class Hostile(Base):
    ssh_hosts = {"known_hosts": [HOST.line("<script>alert(1)</script>.example")],
                 "allowed_hosts": ["<script>alert(1)</script>.example"]}

    def test_hostile_names_are_escaped_everywhere(self):
        # the loader accepts what the editor refuses, so the page must still escape it
        body = self.page()
        self.assertNotIn("<script>alert(1)", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;.example", body)

    def test_hostile_ignored_line_is_escaped(self):
        bad = '"><img src=x onerror=alert(1)> junk'
        self.post(known_hosts=bad + "\n" + HOST.line("a"), allowed_hosts="a", confirm_weaken="1")
        body = self.page()
        self.assertNotIn("<img", body)
        self.assertIn("&lt;img src=x", body)


class Save(Base):
    ssh_hosts = None

    def test_save_persists_updates_live_and_audits_without_names(self):
        known = "\n".join([HOST.line(f"{CANARY},10.1.1.1"), EC.line("ec.example"), RSA.line("rsa.example")])
        status, body = self.post(known_hosts=known + "\n\n", allowed_hosts=f"{CANARY}\r\n  {EC.fp} \n",
                                 allow_forwarded="1")
        self.assertEqual(status, 200)
        self.assertIn("SSH host policy saved", body)
        self.assertIn("unbound clients (old OpenSSH, git commit signing) will be refused", body)
        want = {"known_hosts": known.split("\n"), "allowed_hosts": [CANARY, EC.fp], "allow_forwarded": True}
        self.assertEqual(self.stored()["ssh_hosts"], want)
        self.assertEqual(self.stored()["ssh_hosts_changed"]["by"], "alice")
        self.assertEqual(self.live()["ssh_hosts"]["allowed"], [CANARY, EC.fp.rstrip("=")])
        self.assertTrue(self.live()["ssh_hosts"]["allow_forwarded"])
        # parity with the loader: a new Broker on the same backend reads the same
        self.assertEqual(self.reload().cfg["secrets"]["deploy"]["ssh_hosts"], self.live()["ssh_hosts"])
        ev = self.events("ssh_hosts_changed")
        self.assertEqual(len(ev), 1)
        e = ev[0]
        self.assertEqual((e["secret"], e["user"], e["known_lines"], e["allowed_entries"]), ("deploy", "alice", 3, 2))
        self.assertEqual((e["allow_forwarded_old"], e["allow_forwarded_new"]), (False, True))
        self.assertEqual((e["enforcing_old"], e["enforcing_new"]), (False, True))
        self.assertIsNone(e["old_sha256"])
        self.assertRegex(e["new_sha256"], "^[0-9a-f]{12}$")
        self.assertIn("peer", e)
        raw = self.audit_text()
        for secret in (CANARY, "10.1.1.1", HOST.fp, EC.fp, "ssh-ed25519 AAAA"[:11] + base64.b64encode(HOST.blob).decode()):
            self.assertNotIn(secret, raw)
        # the saved card shows the parsed table with all three key types
        for fp, typ in ((HOST.fp, "ssh-ed25519"), (EC.fp, "ecdsa-sha2-nistp256"), (RSA.fp, "ssh-rsa")):
            self.assertIn(fp, body)
            self.assertIn(typ, body)
        self.assertIn(f"Enforcing: 2 allowed hosts", body)

    def test_unchanged_is_a_noop(self):
        self.post(known_hosts=HOST.line("a"), allowed_hosts="a")
        n = len(self.events("ssh_hosts_changed"))
        status, body = self.post(known_hosts=HOST.line("a"), allowed_hosts="a")
        self.assertEqual((status, len(self.events("ssh_hosts_changed"))), (200, n))
        self.assertIn("unchanged", body)

    def test_empty_removes_the_key_entirely(self):
        self.post(known_hosts=HOST.line("a"), allowed_hosts="a")
        self.assertIn("ssh_hosts", self.stored())
        self.assertEqual(self.post(known_hosts="", allowed_hosts="", confirm_weaken="1")[0], 200)
        self.assertNotIn("ssh_hosts", self.stored())
        self.assertNotIn("ssh_hosts", self.live())
        self.assertNotIn("ssh_hosts", self.reload().cfg["secrets"]["deploy"])
        self.assertIn("ssh_hosts_changed", self.stored())

    def test_known_hosts_only_and_forward_only(self):
        self.post(known_hosts=HOST.line("a"))
        self.assertEqual(self.stored()["ssh_hosts"], {"known_hosts": [HOST.line("a")]})
        self.post(known_hosts="", allow_forwarded="1")
        self.assertEqual(self.stored()["ssh_hosts"], {"allow_forwarded": True})
        self.assertTrue(self.live()["ssh_hosts"]["allow_forwarded"])

    def test_editing_keeps_other_metadata(self):
        self.post(known_hosts=HOST.line("a"))
        d = self.stored()
        self.assertTrue(d["ssh"])
        self.assertIn("ssh_public_key", d)
        self.assertIn("vars", d)

    def test_backend_failure_is_audited_and_leaves_state(self):
        with mock.patch.object(self.broker.backend, "set_meta", side_effect=OSError("disk full")):
            status, body = self.post(known_hosts=HOST.line("a"), allowed_hosts="a")
        self.assertEqual(status, 500)
        self.assertIn("Could not save", body)
        self.assertNotIn("ssh_hosts", self.live())
        self.assertEqual(len(self.events("ssh_hosts_change_failed")), 1)
        self.assertEqual(self.events("ssh_hosts_changed"), [])

    def test_ignored_lines_and_warnings_are_listed_with_reasons(self):
        hashed = "|1|abcd=|efgh= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA"
        lines = [hashed, "# a comment", "@revoked h ssh-ed25519 AAAA", "*.example.com " + HOST.line("x").split(" ", 1)[1],
                 "short ssh-ed25519", "h ssh-dss AAAA", "h ssh-ed25519 !!!notbase64", HOST.line("known.example")]
        fp_missing = "SHA256:" + "A" * 43
        status, body = self.post(known_hosts="\n".join(lines),
                                 allowed_hosts=f"known.example\nghost.example\n{fp_missing}\n{HOST.fp}")
        self.assertEqual(status, 200)
        for why in ("hashed host names are not supported", "comment", "marker lines",
                    "no usable host names", "not a known_hosts line", "unsupported key type",
                    "not valid base64"):
            self.assertIn(why, body)
        self.assertIn("unknown name: no known_hosts line gives it", body)
        self.assertIn("ghost.example", body)
        self.assertIn("will only match by fingerprint", body)
        self.assertEqual(body.count("will only match by fingerprint"), 1)     # HOST.fp is in known_hosts
        self.assertEqual(body.count("unknown name"), 1)


class Rejected(Base):
    ssh_hosts = {"known_hosts": [HOST.line("keep.example")], "allowed_hosts": ["keep.example"]}

    def test_rejected_inputs_change_nothing_and_audit_only_the_class(self):
        good = HOST.line("a")
        cases = [
            ("too many known lines", dict(known_hosts="\n".join([good] * 201)), "limit is 200"),
            ("over-long known line", dict(known_hosts=good + " " + "x" * 2100), "longer than 2048"),
            ("too many allowed", dict(known_hosts=good, allowed_hosts="\n".join(f"h{i}.example" for i in range(51))),
             "limit is 50"),
            ("long allowed", dict(known_hosts=good, allowed_hosts="a" * 256), "longer than 255"),
            ("space in allowed", dict(known_hosts=good, allowed_hosts="a b"), "one host name"),
            ("short fingerprint", dict(known_hosts=good, allowed_hosts="SHA256:abc"), "not a valid SHA256"),
            ("lowercase prefix", dict(known_hosts=good, allowed_hosts="sha256:" + "A" * 43), "not a valid SHA256"),
            ("bad name chars", dict(known_hosts=good, allowed_hosts="a/b"), "not a valid host name"),
            ("control in allowed", dict(known_hosts=good, allowed_hosts="a\x00.example"), "control characters"),
            ("control in known", dict(known_hosts=good + "\x07"), "control characters"),
            ("escape in known", dict(known_hosts="a\x1b[31m " + good), "control characters"),
        ]
        for label, form, word in cases:
            status, body = self.post(confirm_weaken="1", save_anyway="1", **form)
            self.assertEqual(status, 400, label)
            self.assertIn(word, body.replace("&#x27;", "'"), label)
            self.assertIn("class=err", body, label)
            self.assertEqual(self.stored()["ssh_hosts"], self.ssh_hosts, label)
            self.assertEqual(self.live()["ssh_hosts"]["allowed"], ["keep.example"], label)
        ev = self.events("ssh_hosts_change_refused")
        self.assertEqual(len(ev), len(cases))
        self.assertEqual({e["reason"] for e in ev}, {"invalid"})
        self.assertEqual(self.events("ssh_hosts_changed"), [])
        raw = self.audit_text()
        self.assertNotIn("keep.example", raw)
        self.assertNotIn("x" * 50, raw)

    def test_posted_text_is_kept_in_the_error_page(self):
        status, body = self.post(known_hosts="MY-DRAFT-LINE", allowed_hosts="bad name")
        self.assertEqual(status, 400)
        self.assertIn("MY-DRAFT-LINE", body)
        self.assertIn("<details class='card gbox sbox' open>", body)

    def test_limits_at_the_boundary_are_accepted_and_the_loader_agrees(self):
        known = [HOST.line("a")] * 199 + [(HOST.line("a") + " " + "c" * 2048)[:2048]]
        allowed = [f"h{i}.example" for i in range(50)]
        status, _ = self.post(known_hosts="\n".join(known), allowed_hosts="\n".join(allowed),
                              confirm_weaken="1", save_anyway="1")
        self.assertEqual(status, 200)
        self.assertEqual(len(self.reload().cfg["secrets"]["deploy"]["ssh_hosts"]["allowed"]), 50)


class Parity(unittest.TestCase):
    """Whatever the editor builds, the catalog loader's validator accepts."""

    def test_everything_built_is_accepted_by_the_loader(self):
        pub = th.sshkey.public_line(th.sshkey.load_private(th.ts._openssh(ed25519.Ed25519PrivateKey.generate())))
        samples = [
            ("", "", False), (HOST.line("a"), "", False), ("", "a.example", False), ("", "", True),
            (HOST.line("[h.example]:2222,*.x,!y"), "h.example:2222", True),
            ("|1|a=|b= ssh-ed25519 AAAA\n# c\n@revoked x", "SHA256:" + "A" * 43, False),
            ("\n  " + HOST.line("A.Example") + "  \r\n", "A.Example\n\nb.example", False),
            (HOST.line("a"), "SHA256:" + "B" * 43 + "=", False), ("", "[::1]x", False),
            ("", "::1", False), ("", "10.0.0.5", False), ("", "h_1.example:22", False),
        ]
        for k, a, f in samples:
            try:
                raw = sshhosts.build(k, a, f)
            except ValueError:
                continue
            _, e = Broker._entry("k", {"ssh": True, "ssh_public_key": pub, "ssh_hosts": raw,
                                       "vars": {"K_SSH_KEY": {"field": "private_key"}}})
            self.assertEqual(("ssh_hosts" in e), bool(raw), (k, a, f))

    def test_can_ever_match(self):
        self.assertTrue(sshhosts.can_ever_match({"allowed": None, "known": {}}))
        self.assertFalse(sshhosts.can_ever_match({"allowed": ["a"], "known": {}}))
        self.assertFalse(sshhosts.can_ever_match({"allowed": ["a"], "known": {"fp": ["b"]}}))
        self.assertTrue(sshhosts.can_ever_match({"allowed": ["a", "b"], "known": {"fp": ["b"]}}))
        self.assertTrue(sshhosts.can_ever_match({"allowed": ["SHA256:x"], "known": {}}))


class Rails(Base):
    ssh_hosts = {"known_hosts": [HOST.line("web.example.com")], "allowed_hosts": ["web.example.com"]}

    def test_clearing_allowed_needs_confirmation(self):
        status, body = self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="")
        self.assertEqual(status, 400)
        self.assertIn("name=confirm_weaken", body)
        self.assertIn("I understand this reduces enforcement", body)
        self.assertEqual(self.live()["ssh_hosts"]["allowed"], ["web.example.com"])
        self.assertEqual(self.events("ssh_hosts_change_refused")[0]["reason"], "needs_confirmation")
        status, _ = self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="", confirm_weaken="1")
        self.assertEqual(status, 200)
        self.assertFalse((self.live().get("ssh_hosts") or {}).get("allowed"))
        e = self.events("ssh_hosts_changed")[0]
        self.assertEqual((e["enforcing_old"], e["enforcing_new"]), (True, False))

    def test_turning_on_forwarding_needs_confirmation(self):
        kw = dict(known_hosts=HOST.line("web.example.com"), allowed_hosts="web.example.com")
        status, body = self.post(allow_forwarded="1", **kw)
        self.assertEqual(status, 400)
        self.assertIn("name=confirm_weaken", body)
        self.assertIn("checked", body)                          # the draft keeps the ticked box
        self.assertEqual(self.post(allow_forwarded="1", confirm_weaken="1", **kw)[0], 200)
        self.assertTrue(self.live()["ssh_hosts"]["allow_forwarded"])

    def test_tightening_and_non_enforcing_changes_need_no_confirmation(self):
        status, _ = self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts=f"web.example.com\n{HOST.fp}")
        self.assertEqual(status, 200)

    def test_confirmation_box_not_shown_on_a_clean_card(self):
        self.assertNotIn("confirm_weaken", self.page())
        self.assertNotIn("save_anyway", self.page())

    def test_lockout_needs_save_anyway(self):
        status, body = self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="nowhere.example")
        self.assertEqual(status, 400)
        self.assertIn("lock the key out of use", body)
        self.assertIn("name=save_anyway", body)
        self.assertEqual(self.live()["ssh_hosts"]["allowed"], ["web.example.com"])
        self.assertEqual(self.events("ssh_hosts_change_refused")[0]["reason"], "lockout")
        status, _ = self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="nowhere.example",
                              save_anyway="1")
        self.assertEqual(status, 200)
        self.assertEqual(self.live()["ssh_hosts"]["allowed"], ["nowhere.example"])

    def test_fingerprint_entries_never_lock_out(self):
        self.assertEqual(self.post(known_hosts="", allowed_hosts="SHA256:" + "A" * 43)[0], 200)

    def test_both_rails_at_once_show_both_boxes(self):
        # weakening is not the case here (still enforcing), so only the lock-out box appears
        status, body = self.post(known_hosts="", allowed_hosts="zzz.example", allow_forwarded="1")
        self.assertEqual(status, 400)
        self.assertIn("name=confirm_weaken", body)
        self.assertIn("name=save_anyway", body)

    def test_first_enforcement_needs_no_confirmation(self):
        self.post(known_hosts="", allowed_hosts="", confirm_weaken="1")
        status, body = self.post(known_hosts=HOST.line("w.example"), allowed_hosts="w.example")
        self.assertEqual(status, 200)
        self.assertIn("will be refused for this key", body)


class TakesEffect(Base):
    ssh_hosts = None

    def test_enforcement_applies_to_the_next_sign_request_without_restart(self):
        self.assertEqual(self.bound(OTHER)[0], 202)             # no policy: any server
        self.assertEqual(self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="web.example.com")[0], 200)
        self.assertEqual(self.bound(HOST)[0], 202)
        code, _ = self.bound(OTHER)
        self.assertEqual(code, 403)
        self.assertEqual([r["reason"] for r in self.refused()], ["host_not_allowed"])
        self.assertEqual(self.sign(th.login(SID_A))[0], 403)    # unbound
        self.assertEqual(self.refused()[-1]["reason"], "host_unverified")
        # and lifting it takes effect just as fast
        self.post(known_hosts="", allowed_hosts="", confirm_weaken="1")
        self.assertEqual(self.bound(OTHER)[0], 202)

    def test_allow_forwarded_toggle_is_live(self):
        self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="web.example.com")
        fwd = lambda: self.sign(th.login(SID_A), [HOST.bind(SID_A, forwarding=True)])[0]  # noqa: E731
        self.assertEqual(fwd(), 403)
        self.assertEqual(self.refused()[-1]["reason"], "host_forwarded")
        self.post(known_hosts=HOST.line("web.example.com"), allowed_hosts="web.example.com",
                  allow_forwarded="1", confirm_weaken="1")
        self.assertEqual(fwd(), 202)


class Secrecy(Base):
    ssh_hosts = {"known_hosts": [OTHER.line(CANARY)], "allowed_hosts": [HOST.fp, CANARY2]}

    def test_audit_events_are_hidden_from_the_agent_api(self):
        for ev in ("ssh_hosts_changed", "ssh_hosts_change_refused", "ssh_hosts_change_failed"):
            self.assertIn(ev, audit_api.HIDDEN)
            self.assertIsNone(audit_api.redact({"seq": 1, "ts": 1.0, "event": ev, "secret": "deploy",
                                                "known_lines": 3, "new_sha256": "ab", "request": "r"}))

    def test_canaries_reach_no_agent_visible_surface(self):
        self.post(known_hosts=HOST.line("w.example") + "\n" + OTHER.line(CANARY),
                  allowed_hosts=f"{HOST.fp}\n{CANARY2}\n{CANARY}", allow_forwarded="1", confirm_weaken="1")
        self.post(known_hosts="x", allowed_hosts="bad name")                       # a refusal too
        code, body = self.bound(HOST)
        self.assertEqual(code, 202)
        rid = json.loads(body)["id"]
        surfaces = [body]
        for path in ("/v1/status", "/v1/secrets", f"/v1/requests/{rid}?wait=0", "/v1/audit?limit=500", "/v1/audit/verify"):
            surfaces.append(self.api("GET", path)[1])
        surfaces.append(self.api("POST", "/v1/requests", {"mode": "ssh_sign", "names": ["deploy"], "flags": 0,
                                                          "data_b64": base64.b64encode(th.login(SID_A)).decode(),
                                                          "binds": [OTHER.bind(SID_A)]})[1])
        for s in surfaces:
            for c in (CANARY, CANARY2):
                self.assertNotIn(c, s)
            self.assertNotIn("ssh_hosts", s)
        # nor does it reach the notification the approver gets about this request
        for n in self.notifier.sent:
            self.assertNotIn(CANARY2, json.dumps(n))
        # the approval page for a non-approver is forbidden
        nonce = self.broker._by_id[rid].nonce
        status, page = t.req(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "mallory"})
        self.assertEqual(status, 403)
        self.assertNotIn(CANARY, page)
        status, page = t.req(self.abase + "/policies", headers={"X-authentik-username": "mallory"})
        self.assertEqual(status, 403)
        self.assertNotIn(CANARY, page)

    def test_policies_page_for_the_owner_does_show_it(self):
        self.assertIn(CANARY, self.page())


if __name__ == "__main__":
    unittest.main()
