"""Request mode `sudo`: a root helper asks the broker before running a command as root.

The properties: off by default and only for clients on `sudo.clients`; always HIGH by code with
no model call; decided only by a human on the approval page (never a policy, grant, Always or
notification button); the approval carries no value, only {"approved": true}, delivered once;
the audit log keeps the command's words and nothing else.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import shutil
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
from test_client_rules import ClientMixin  # noqa: E402
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import sudomode  # noqa: E402

ARGV = ["/usr/bin/systemctl", "restart", "nginx"]


class NoModel:
    """An analyzer that must never be asked about a root command."""

    def analyze(self, *a, **k):
        raise AssertionError("a sudo request must not reach a model")

    summarize = analyze


class SudoBase(ClientMixin, tg.Base):
    """A broker with sudo enabled for one enrolled client (`helper`) and one that is not (`other`)."""

    def setUp(self):
        super().setUp()
        self.helper = self.mk("root-helper")
        self.other = self.mk("someone-else")
        self.broker.summarizer = NoModel()
        self.enable()

    def enable(self, **kw):
        self.broker.sudo_cfg = sudomode.parse_config({"enabled": True, "clients": [self.helper.id], **kw})

    def ask(self, c=None, **body):
        body = {"mode": "sudo", "argv": ARGV, "cwd": "/home/ryan", "invoker": "ryan", **body}
        return self.api("POST", "/v1/requests", body, key=(c or self.helper).secret)

    def pending(self, **body):
        code, b = self.ask(**body)
        self.assertEqual(code, 202, b)
        return json.loads(b)["id"]

    def result_now(self, rid, wait=0):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait={wait}", key=self.helper.secret)
        return json.loads(b)

    def result(self, rid):
        return self.result_now(rid, wait=3)


class Sudo(SudoBase):
    def test_off_by_default(self):
        self.broker.sudo_cfg = sudomode.parse_config(None)
        code, b = self.ask()
        self.assertEqual(code, 403, b)
        self.assertEqual(self.notifier.sent, [])

    def test_only_listed_clients(self):
        for key in (self.other.secret, t.KEY):
            code, b = self.api("POST", "/v1/requests", {"mode": "sudo", "argv": ARGV}, key=key)
            self.assertEqual(code, 403, b)
        self.assertEqual(self.notifier.sent, [])
        self.assertTrue(self.events("rejected"))

    def test_high_risk_no_model_and_no_auto_approval(self):
        rid = self.pending()
        self.assertEqual(self.result_now(rid)["status"], "pending")
        a = self.events("assessed")[-1]
        self.assertEqual(a["risk"], "high")
        self.assertIsNone(a["model"])
        self.assertEqual(self.events("approved"), [])
        self.assertEqual(len(self.notifier.sent), 1)

    def test_notification_shows_the_command_and_offers_no_buttons(self):
        self.pending()
        n = self.notifier.notifications[0]
        self.assertIn("systemctl restart nginx", n.text)
        self.assertEqual(n.actions, [])
        self.assertIsNone(n.action_token)

    def test_approval_is_a_bare_flag_delivered_once(self):
        rid = self.pending()
        status, _, _ = self.decide(rid, "approve")
        self.assertIn(status, (200, 302, 303))
        got = self.result(rid)
        self.assertEqual(got, {"status": "approved", "approved": True})
        self.assertEqual(self.result(rid), {"status": "released"})
        self.assertEqual(self.events("approved")[-1]["via"], "user")

    def test_denial_is_final(self):
        rid = self.pending()
        self.decide(rid, "deny")
        self.assertEqual(self.result(rid)["status"], "denied")

    def test_grants_and_always_cannot_cover_it(self):
        rid = self.pending()
        for decision in ("approve_grant_5", "approve_always"):
            self.decide(rid, decision)
            self.assertEqual(self.result_now(rid)["status"], "pending", decision)
        self.assertEqual(self.events("approved"), [])
        self.assertFalse(self.broker.grant_eligibility(self.broker._by_id[rid])[0])
        self.assertFalse(self.broker.always_allow_eligibility(self.broker._by_id[rid])[0])

    def test_audit_keeps_the_command_words_only(self):
        code, _ = self.ask(argv=ARGV + ["x" * 5000])    # over the limit: nothing is requested or logged
        self.assertEqual(code, 400)
        self.assertEqual(self.events("requested"), [])
        rid = self.pending()
        ev = self.events("requested")[-1]
        self.assertEqual((ev["argv"], ev["cwd"], ev["invoker"], ev["target_user"]),
                         (ARGV, "/home/ryan", "ryan", "root"))
        self.assertEqual(ev["id"], rid)
        self.assertEqual(ev["names"], [])

    def test_bad_requests_are_refused(self):
        for body in ({"argv": []}, {"argv": ""}, {"argv": [""]}, {"argv": "ls"}, {"argv": ["ls", 3]}, {"argv": ["a\x00b"]},
                     {"argv": ["a‮b"]}, {"user": "bob"}, {"cwd": "relative"}, {"names": ["svc"]},
                     {"invoker": "Not A User"}):
            code, b = self.ask(**body)
            self.assertEqual(code, 400, (body, b))
        self.assertEqual(self.notifier.sent, [])

    def test_per_client_pending_cap(self):
        self.enable(max_pending_per_client=2)
        self.pending()
        self.pending()
        code, b = self.ask()
        self.assertEqual(code, 403, b)

    def test_another_client_cannot_read_the_answer(self):
        rid = self.pending()
        self.decide(rid, "approve")
        _, b = self.api("GET", f"/v1/requests/{rid}", key=self.other.secret)
        self.assertNotIn("approved", json.loads(b))

    def test_pages_render_the_card_the_link_page_and_history(self):
        rid = self.pending(argv=["/bin/echo", "two words", "caf\u00e9"])
        nonce = self.broker._by_id[rid].nonce
        for path in ("/", f"/a/{nonce}"):
            status, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn("Run as root", body)
            self.assertIn("&#x27;two words&#x27;", body)         # one argument, quoted: not two
            self.assertIn("&lt;U+00E9&gt;", body)               # non-ASCII is never shown as itself
            self.assertNotIn("approve_grant", body)
            self.assertNotIn("Always", body)
        self.decide(rid, "approve")
        status, body = self.get("/?view=all")
        self.assertEqual(status, 200)
        self.assertIn("run as root", body)

    def test_newlines_and_tabs_are_made_visible_everywhere_the_command_is_shown(self):
        # to a shell the newline separates two commands; rendered as a space it would look like one
        rid = self.pending(argv=["/bin/sh", "-c", "echo hi\nrm /x\tz"])
        nonce = self.broker._by_id[rid].nonce
        for path in ("/", f"/a/{nonce}"):
            _, body = self.get(path)
            self.assertIn("&lt;U+000A&gt;", body, path)
            self.assertIn("&lt;U+0009&gt;", body, path)
            self.assertIn("Contains a newline or tab", body, path)
            self.assertNotIn("echo hi\nrm", body, path)
        text = self.notifier.sent[0]["message"]
        self.assertIn("echo hi<U+000A>rm /x<U+0009>z", text)
        self.assertNotIn("\nrm", text)
        self.decide(rid, "approve")
        _, hist = self.get("/?view=all")
        self.assertIn("&lt;U+000A&gt;", hist)

    def test_the_history_detail_shows_the_command_and_cwd(self):
        rid = self.pending(argv=["/bin/sh", "-c", "echo a\nb"])
        self.decide(rid, "approve")
        self.result(rid)
        status, body = self.get(f"/request/{rid}")
        self.assertEqual(status, 200)
        self.assertIn("run a command as root", body)
        self.assertIn("/bin/sh -c", body)                    # the command itself, not only its label
        self.assertIn("echo a&lt;U+000A&gt;b", body)         # the newline is visible, as everywhere else
        self.assertIn("/home/ryan", body)                    # the directory
        self.assertIn("Asked by local user", body)

    def test_a_long_command_says_how_much_of_it_the_detail_page_keeps(self):
        words = [f"longword{i}" for i in range(40)]
        rid = self.pending(argv=["/bin/echo", *words])
        self.decide(rid, "approve")
        self.result(rid)
        body = self.get(f"/request/{rid}")[1]
        self.assertIn("41 words in all", body)
        self.assertIn("longword28", body)
        self.assertNotIn("longword29", body)       # history keeps the first 30 words, /bin/echo included

    def test_html_in_a_command_is_escaped_on_every_page(self):
        evil = "<script>alert(1)</script>"
        rid = self.pending(argv=["/bin/echo", evil], cwd="/home/ryan")
        nonce = self.broker._by_id[rid].nonce
        pages = {"/": self.get("/")[1], f"/a/{nonce}": self.get(f"/a/{nonce}")[1]}
        self.decide(rid, "approve")
        self.result(rid)
        pages["/?view=all"] = self.get("/?view=all")[1]
        pages[f"/request/{rid}"] = self.get(f"/request/{rid}")[1]
        for path, body in pages.items():
            self.assertNotIn(evil, body, path)
            self.assertIn("&lt;script&gt;", body, path)

    def test_creating_one_directly_with_credential_names_is_refused(self):
        with self.assertRaises(ValueError):
            self.broker.create("sudo", ["svc"], {"argv": ARGV}, "ryan@box", client={
                "id": self.helper.id, "name": "root-helper", "legacy": False})

    def test_config_is_validated(self):
        for bad in ({"enabled": "yes"}, {"clients": ["legacy"]}, {"clients": "c-1a2b3c4d"},
                    {"ttl_s": 5}, {"nope": 1}, [], {"max_pending_per_client": 0},
                    {"max_pending_per_client": 21}, {"max_pending_per_client": "3"},
                    {"max_pending_per_client": True}):
            with self.assertRaises(ValueError):
                sudomode.parse_config(bad)


ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "sudo")


def fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class Contract(SudoBase):
    """The wire fixtures shared with the Rust crates (tests/fixtures/sudo/) match this broker."""

    def test_the_request_fixture_is_accepted_and_the_answers_have_the_fixture_shape(self):
        code, b = self.api("POST", "/v1/requests", fixture("request.json"), key=self.helper.secret)
        self.assertEqual(code, 202, b)
        created, want = json.loads(b), fixture("created.json")
        self.assertEqual(set(created), set(want))
        self.assertEqual((created["status"], created["error"]), (want["status"], want["error"]))
        self.assertTrue(0 < created["expires_in"] <= want["expires_in"])
        self.decide(created["id"], "approve")
        self.assertEqual(self.result(created["id"]), fixture("approved.json"))
        self.assertEqual(self.result(created["id"]), fixture("released.json"))

    def test_denied_has_the_fixture_shape(self):
        rid = json.loads(self.api("POST", "/v1/requests", fixture("request.json"), key=self.helper.secret)[1])["id"]
        self.decide(rid, "deny")
        self.assertEqual(self.result(rid), fixture("denied.json"))


@unittest.skipUnless(shutil.which("cargo"), "needs a Rust toolchain")
class RustClient(SudoBase):
    """The real Rust client (crates/asb-client, example sudo_ask) against this real broker."""
    binary = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        r = subprocess.run(["cargo", "build", "-q", "-p", "asb-client", "--example", "sudo_ask"], cwd=ROOT,
                           capture_output=True, text=True)
        if r.returncode:
            raise unittest.SkipTest("cargo build failed: " + r.stderr[-300:])
        cls.binary = os.path.join(ROOT, "target", "debug", "examples", "sudo_ask")

    def ask_with_rust(self, key, decision):
        env = {**os.environ, "ASB_URL": self.base, "ASB_KEY": key}
        p = subprocess.Popen([self.binary, "/usr/bin/true", "x y"], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
        try:
            if decision:
                end = time.time() + 15
                while time.time() < end:
                    pend = [r for r in list(self.broker._by_id.values()) if r.mode == "sudo" and r.status == "pending"]
                    if pend:
                        break
                    time.sleep(0.05)
                self.assertTrue(pend, "the Rust client never asked")
                self.assertEqual(pend[0].spec["argv"], ["/usr/bin/true", "x y"])
                self.decide(pend[0].id, decision)
            out, err = p.communicate(timeout=30)
        finally:
            p.kill()
        return p.returncode, out, err

    def test_approved(self):
        rc, out, err = self.ask_with_rust(self.helper.secret, "approve")
        self.assertEqual((rc, out.strip()), (0, "approved"), err)

    def test_denied_exits_4(self):
        rc, out, err = self.ask_with_rust(self.helper.secret, "deny")
        self.assertEqual(rc, 4, err)
        self.assertNotIn("approved", out)

    def test_a_client_not_on_the_list_is_refused_and_exits_3(self):
        rc, out, err = self.ask_with_rust(self.other.secret, None)
        self.assertEqual(rc, 3, err)
        self.assertIn("may not make sudo requests", err)
        self.assertNotIn("approved", out)


if __name__ == "__main__":
    unittest.main()
