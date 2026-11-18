"""A credential's Policies sub-tab: where the policy forms answer, and how /grants/revoke finds its way back."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
from test_ui_auto_rules import ManageBase, svc_rule  # noqa: E402

H = {"X-authentik-username": "alice"}


class PostBase(ManageBase):
    def post(self, path, user="alice", csrf=True, **form):
        if csrf is True:
            form["csrf"] = self.broker.csrf_token("alice")
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + path, data=urllib.parse.urlencode(form, doseq=True).encode(),
                headers={"X-authentik-username": user} if user else {}, method="POST"), timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def get(self, path):
        try:
            r = urllib.request.urlopen(urllib.request.Request(self.abase + path, headers=H), timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def grant(self, names=("svc",), client="*"):
        return self.broker.grants.add(list(names), 5, "any", "alice", "dashboard", "r", client=client)["id"]

    def assert_credential_policies_page(self, body, name):
        self.assertIn(f"<h1>Edit {name}</h1>", body)
        self.assertIn(f"href='/credentials/{name}?tab=policies'", body)                   # the sub-tab strip
        self.assertNotIn("<h1>Policies</h1>", body)


class PolicyPosts(PostBase):
    def test_each_policy_post_renders_that_credentials_policies_tab(self):
        form = dict(name="news", mode="http", host="api.example.com", scheme="https", methods=["GET"],
                    path_prefix="/v1", argv="", client="*", expires="never", confirm="1")
        code, body = self.post("/policies/auto_rules/add", secret="svc", **form)
        self.assertEqual(code, 200)
        self.assertIn("Auto-approve rule added: svc", body)
        self.assert_credential_policies_page(body, "svc")
        rid = self.live()[0]["id"]
        code, body = self.post("/policies/auto_rules/revoke", secret="svc", rule=rid)
        self.assertEqual(code, 200)
        self.assertIn("Auto-approve rule revoked: svc", body)
        self.assert_credential_policies_page(body, "svc")
        code, body = self.post("/policies/guidance", name="svc", guidance="Reads are fine")
        self.assertEqual(code, 200)
        self.assertIn("Guidance saved: svc", body)
        self.assert_credential_policies_page(body, "svc")
        code, body = self.post("/policies/ssh_hosts", secret="deploy", known_hosts="", allowed_hosts="")
        self.assertEqual(code, 200)
        self.assertIn("SSH host policy unchanged: deploy", body)
        self.assert_credential_policies_page(body, "deploy")
        code, body = self.post("/policies/ssh_rules/revoke", secret="deploy", rule="nope1234")
        self.assertEqual(code, 200)
        self.assertIn("That SSH rule no longer exists: deploy", body)
        self.assert_credential_policies_page(body, "deploy")
        code, body = self.post("/policies/ssh_rules/add", secret="deploy", host="", fp="", account="x",
                               expires="never")
        self.assertEqual(code, 400)
        self.assertIn("Could not add the SSH rule: deploy", body)
        self.assert_credential_policies_page(body, "deploy")

    def test_the_legacy_tighten_post_lands_on_the_credentials_page(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"
        code, body = self.post("/policies", name="svc", approval="prompt")
        self.assertEqual(code, 200)
        self.assertIn("Updated: svc", body)
        self.assert_credential_policies_page(body, "svc")

    def test_a_refused_add_shows_its_fixed_error_in_the_credential_page(self):
        code, body = self.post("/policies/auto_rules/add", secret="svc", name="n", mode="http",
                               host="api.example.com", scheme="https", methods=["GET"], path_prefix="/",
                               client="*", expires="never")
        self.assertEqual(code, 400)
        self.assertIn("Tick the box", body)
        self.assert_credential_policies_page(body, "svc")
        self.assertEqual(self.stored(), [])

    def test_a_post_for_one_credential_never_changes_another(self):
        self.seed(svc_rule(id="b0001", name="b rule"), name="other")
        before = self.stored("other")
        self.assertEqual(self.post("/policies/auto_rules/add", secret="svc", name="mine", mode="http",
                                   host="api.example.com", scheme="https", methods=["GET"], path_prefix="/",
                                   client="*", expires="never", confirm="1")[0], 200)
        self.assertEqual(len(self.stored("svc")), 1)                                        # control: it changed svc
        self.assertEqual(self.stored("other"), before)
        self.assertEqual(self.post("/policies/auto_rules/revoke", secret="svc", rule="b0001")[1].count("no longer"), 1)
        self.assertEqual(self.stored("other"), before)                                      # an id of B's does nothing to svc's revoke


class GrantsBack(PostBase):
    def revoke(self, gid, **extra):
        return self.post("/grants/revoke", grant=gid, **extra)

    def test_back_naming_a_credential_renders_its_page(self):
        gid = self.grant()
        code, body = self.revoke(gid, back="svc")
        self.assertEqual(code, 200)
        self.assertIn("Standing approval revoked", body)
        self.assert_credential_policies_page(body, "svc")
        self.assertNotIn(gid, [r["id"] for r in self.broker.standing_rows()])

    def test_missing_hostile_or_gone_back_falls_back_to_the_policies_tab(self):
        for back in (None, "policies", "<script>alert(1)</script>", "nope", "svc' onmouseover='x"):
            gid = self.grant()
            extra = {} if back is None else {"back": back}
            code, body = self.revoke(gid, **extra)
            self.assertEqual(code, 200, back)
            self.assertIn("<h1>Policies</h1>", body, back)
            self.assertIn("Standing approval revoked", body, back)
            self.assertNotIn("<h1>Edit", body, back)
            if back and back not in ("policies", "nope"):
                self.assertNotIn(back, body)                                               # never reflected
        code, body = self.revoke(self.grant(), back="svc")                                 # control: a real name lands there
        self.assertIn("<h1>Edit svc</h1>", body)

    def test_back_for_an_inactive_grant_says_so_on_the_credential_page(self):
        code, body = self.revoke("nope1234", back="svc")
        self.assertEqual(code, 200)
        self.assertIn("That standing approval is no longer active", body)
        self.assert_credential_policies_page(body, "svc")
