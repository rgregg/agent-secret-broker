"""A credential's Policies sub-tab: where the policy forms answer, and how /grants/revoke finds its way back."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_credential_editor as tce  # noqa: E402
import test_e2e as t  # noqa: E402
from test_ssh_rules import NoMeta  # noqa: E402
from secret_broker import autorules  # noqa: E402
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


class Tabs(PostBase):
    def test_tab_policies_renders_the_policies_body(self):
        code, body = self.get("/credentials/svc?tab=policies")
        self.assertEqual(code, 200)
        self.assert_credential_policies_page(body, "svc")
        for heading in ("<h3>Standing approvals", "<h3>Auto-approve rules", "<h3>Risk guidance"):
            self.assertIn(heading, body)
        self.assertNotIn("<h3>SSH host", body)

    def test_an_unknown_or_empty_tab_is_settings(self):
        for q in ("?tab=nope", "?tab=", "?tab=settings", ""):
            code, body = self.get("/credentials/svc" + q)
            self.assertEqual(code, 200, q)
            self.assertIn("<h2>Allowed hosts</h2>", body, q)
            self.assertNotIn("<h3>Standing approvals", body, q)
        self.assertIn("<h3>Standing approvals", self.get("/credentials/svc?tab=policies")[1])      # control

    def test_an_unknown_credential_is_the_same_404_on_both_tabs(self):
        a, b = self.get("/credentials/nope"), self.get("/credentials/nope?tab=policies")
        self.assertEqual((a[0], b[0]), (404, 404))
        self.assertIn("<h1>Not found</h1>", a[1])
        self.assertIn("<h1>Not found</h1>", b[1])
        self.assertEqual(self.get("/credentials/svc")[0], 200)                                      # control

    def test_settings_carries_the_tab_strip_and_a_summary_with_a_link(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"                                    # the harness sets allow
        self.grant()
        self.seed(svc_rule(id="x0001", name="one"), svc_rule(id="x0002", name="two"))
        self.broker.cfg["secrets"]["svc"]["guidance"] = "Reads are fine"
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertIn("class=ctabs", body)
        self.assertIn("Policies (3)", body)
        self.assertIn("1 standing approval", body)
        self.assertIn("2 auto-approve rules", body)
        self.assertIn("risk guidance set", body)
        self.assertIn("href='/credentials/svc?tab=policies'", body)
        del self.broker.cfg["secrets"]["svc"]["guidance"]
        self.assertIn("risk guidance not set", self.get("/credentials/svc")[1])
        self.broker.cfg["secrets"]["svc"]["approval"] = "allow"                                     # the legacy allow is a standing approval
        body = self.get("/credentials/svc")[1]
        self.assertIn("2 standing approvals", body)
        self.assertIn("Policies (4)", body)

    def test_an_ssh_key_shows_ssh_sections_and_no_rules_section(self):
        body = self.get("/credentials/deploy?tab=policies")[1]
        self.assertIn("<h3>SSH host policy", body)
        self.assertIn("<h3>SSH host rules", body)
        self.assertNotIn("<h3>Auto-approve rules", body)
        self.assertIn("<h3>Auto-approve rules", self.get("/credentials/svc?tab=policies")[1])     # the reverse

    def test_a_backend_that_cannot_write_metadata_still_renders_and_says_so(self):
        ok = self.get("/credentials/svc?tab=policies")[1]
        self.assertNotIn("cannot store metadata", ok)
        self.broker.backend = NoMeta(self.broker.backend)
        code, body = self.get("/credentials/svc?tab=policies")
        self.assertEqual(code, 200)
        self.assertIn("cannot store metadata", body)
        code, _ = self.post("/policies/auto_rules/add", secret="svc", name="n", mode="http", host="api.example.com",
                            scheme="https", methods=["GET"], path_prefix="/", client="*", expires="never",
                            confirm="1")
        self.assertEqual(code, 400)                                                                 # the write refusal is unchanged

    def test_an_ssh_keys_host_rules_and_config_rule_are_counted_and_shown(self):
        from secret_broker import sshrules
        self.broker.cfg["secrets"]["deploy"]["ssh_rules"] = sshrules.parse([{
            "id": "sr0001", "fp": "SHA256:" + "A" * 43, "user": "deploy", "host": "web", "by": "alice",
            "at": "2026-11-18T00:00:00Z", "expires_at": None}])
        self.broker.auto_rules = autorules.parse([{"name": "cfg-ssh", "mode": "ssh_sign", "secret": "deploy",
                                                   "host": "web.example.com", "account": "deploy"}])
        settings = self.get("/credentials/deploy")[1]
        self.assertIn("Policies (2)", settings)                                          # the host rule and the config rule
        self.assertIn("1 SSH host rule", settings)
        self.assertIn("1 auto-approve rule", settings)
        pol = self.get("/credentials/deploy?tab=policies")[1]
        self.assertIn("cfg-ssh", pol)                                                    # the config rule is findable
        self.assertEqual(pol.count("data-label=Name>cfg-ssh<"), 1)
        row = [r for r in self.get("/credentials")[1].split("<tr class=r") if "href='/credentials/deploy'" in r][0]
        self.assertIn("href='/credentials/deploy?tab=policies'>2</a>", row)
        self.assertIn("<td class=ic data-label=Policies><small class=muted>-</small>",
                      [r for r in self.get("/credentials")[1].split("<tr class=r") if "href='/credentials/other'" in r][0])

    def test_the_credentials_tab_stays_highlighted(self):
        for q in ("", "?tab=policies"):
            self.assertIn("href='/credentials' class=on", self.get("/credentials/svc" + q)[1], q)


class SettingsReview(tce.Base):
    def test_the_review_step_has_no_strip_but_settings_does(self):
        code, body = self.get("/credentials/svc")
        self.assertEqual(code, 200)
        self.assertIn("class=ctabs", body)                                                          # control
        pc, preview = self.post("/credentials/svc/preview", **self.form(approval="allow"))
        self.assertEqual(pc, 200)
        self.assertIn("Review changes to svc", preview)                                             # the premise: it is the review page
        self.assertNotIn("class=ctabs", preview)


class ListCounts(PostBase):
    def row(self, body, name):
        rows = [r for r in body.split("<tr class=r") if f"href='/credentials/{name}'" in r]
        self.assertEqual(len(rows), 1, name)                                                         # the premise: one row per credential
        return rows[0]

    def test_the_list_shows_each_credentials_policy_count_and_links_to_it(self):
        self.grant()
        self.seed(svc_rule(id="l0001", name="one"))
        code, body = self.get("/credentials")
        self.assertEqual(code, 200)
        self.assertIn("<th class=ic>Policies</th>", body)
        svc = self.row(body, "svc")
        self.assertIn("data-label=Policies><a class=clink href='/credentials/svc?tab=policies'>3</a>", svc)  # grant + rule + legacy allow
        self.assertIn("data-label=Policies><small class=muted>-</small>", self.row(body, "other"))
        self.assertNotIn("?tab=policies", self.row(body, "other"))

    def test_the_search_filter_is_unaffected(self):
        body = self.get("/credentials?q=svc")[1]
        self.assertIn("1 of 3 credentials", body)


class PoliciesTab(PostBase):
    """The Policies tab now shows only what spans credentials (or names a credential that is gone)."""
    SHARED = "<h3>Timed approvals covering several credentials"

    def tab(self):
        code, body = self.get("/policies")
        self.assertEqual(code, 200)
        return body

    def test_it_lists_only_shared_policies(self):
        pair = self.grant(["svc", "other"])
        solo = self.grant(["svc"], client="c-0a0b0c0d")
        self.broker.cfg["secrets"]["svc"]["guidance"] = "Reads are fine"
        body = self.tab()
        self.assertIn(self.SHARED, body)
        self.assertIn(f"name=grant value='{pair}'", body)                                         # the shared one is here
        self.assertNotIn(f"name=grant value='{solo}'", body)                                      # the per-credential one is not
        for gone in ("<h3>Risk guidance", "<h3>SSH host policy", "<h3>SSH host rules", "<h3>Auto-approve rules ("):
            self.assertNotIn(gone, body)
        self.assertIn(f"name=grant value='{solo}'", self.get("/credentials/svc?tab=policies")[1])  # control: it lives there now

    def test_shared_rows_revoke_back_to_the_tab(self):
        pair = self.grant(["svc", "other"])
        self.assertIn("name=back value='policies'", self.tab())
        code, body = self.post("/grants/revoke", grant=pair, back="policies")
        self.assertEqual(code, 200)
        self.assertIn("<h1>Policies</h1>", body)
        self.assertIn("Standing approval revoked", body)
        self.assertNotIn(pair, [r["id"] for r in self.broker.standing_rows()])

    def test_an_orphan_is_visible_revocable_and_unlinked(self):
        gid = self.grant(["svc"])
        live = self.grant(["other"])
        del self.broker.cfg["secrets"]["svc"]
        body = self.tab()
        self.assertIn(f"name=grant value='{gid}'", body)
        self.assertIn("names a credential that no longer exists", body)
        self.assertNotIn("href='/credentials/svc", body)                                          # a gone credential has no page
        self.assertNotIn(f"name=grant value='{live}'", body)                                      # control: the living one is not here
        code, after = self.post("/grants/revoke", grant=gid, back="svc")                          # back to a gone credential: the tab
        self.assertEqual(code, 200)
        self.assertIn("<h1>Policies</h1>", after)
        self.assertNotIn(gid, [r["id"] for r in self.broker.standing_rows()])

    def test_shared_names_link_to_the_credentials_that_exist(self):
        self.grant(["svc", "other"])
        body = self.tab()
        self.assertIn("href='/credentials/svc?tab=policies'", body)
        self.assertIn("href='/credentials/other?tab=policies'", body)

    def test_empty_state_points_to_the_credential_pages(self):
        body = self.tab()
        self.assertIn("No policy covers more than one credential.", body)
        self.assertIn("Policies for a single credential live on that credential's page", body)
        self.assertIn("href='/credentials'", body)
        self.grant(["svc", "other"])
        self.assertNotIn("No policy covers more than one credential.", self.tab())               # control

    def test_shared_config_rules_and_the_orphan_marker(self):
        self.broker.auto_rules = autorules.parse([
            {"name": "cfg-one", "mode": "env", "secret": "svc", "argv": ["echo"]},
            {"name": "cfg-pair", "mode": "env", "secrets": ["svc", "other"], "argv": ["echo"]},
            {"name": "cfg-gone", "mode": "env", "secret": "missing", "argv": ["echo"]}])
        body = self.tab()
        self.assertIn("<h3>Auto-approve rules covering several credentials", body)
        self.assertIn("cfg-pair", body)
        self.assertIn("cfg-gone", body)
        self.assertNotIn("cfg-one", body)                                                          # a single-credential rule is on its page
        self.assertEqual(body.count("names a credential that no longer exists"), 1)                # only the orphan is marked
        self.assertIn("cfg-one", self.get("/credentials/svc?tab=policies")[1])

    def test_nothing_is_lost_or_doubled_across_the_pages(self):
        self.broker.cfg["secrets"]["svc"]["approval"] = "prompt"
        solo = self.grant(["svc"])
        self.grant(["svc"], client="c-0a0b0c0d")
        pair = self.grant(["svc", "other"])
        orphan = self.grant(["svc", "ghost"])
        self.seed(svc_rule(id="u0001", name="stored-one"))
        self.broker.auto_rules = autorules.parse([
            {"name": "cfg-one", "mode": "env", "secret": "svc", "argv": ["echo"]},
            {"name": "cfg-pair", "mode": "env", "secrets": ["svc", "other"], "argv": ["echo"]},
            {"name": "cfg-gone", "mode": "env", "secret": "missing", "argv": ["echo"]},
            {"name": "cfg-ssh", "mode": "ssh_sign", "secret": "deploy", "host": "web.example.com",
             "account": "deploy"}])
        pages = {"policies": self.get("/policies")[1]}
        for name in self.broker.cfg["secrets"]:
            pages[name] = self.get(f"/credentials/{name}?tab=policies")[1]
        def seen(needle):
            return sorted(k for k, body in pages.items() for _ in range(body.count(needle)))
        every = {r["id"] for r in self.broker.standing_rows()}
        self.assertEqual(len(every), 4)                                                           # the premise: four distinct grants
        for gid in every:
            where = seen(f"name=grant value='{gid}'")
            self.assertEqual(len(where), 1, (gid, where))                                         # exactly one place
        self.assertEqual(seen(f"name=grant value='{solo}'"), ["svc"])
        self.assertEqual(seen(f"name=grant value='{pair}'"), ["policies"])
        self.assertEqual(seen(f"name=grant value='{orphan}'"), ["policies"])
        self.assertEqual(seen("name=rule value='u0001'"), ["svc"])
        self.assertEqual(seen("data-label=Name>cfg-one<"), ["svc"])
        self.assertEqual(seen("data-label=Name>cfg-pair<"), ["other", "policies", "svc"])         # each credential it names, and the tab
        self.assertEqual(seen("data-label=Name>cfg-gone<"), ["policies"])
        self.assertEqual(seen("data-label=Name>cfg-ssh<"), ["deploy"])                            # an ssh key's config rule is not lost
