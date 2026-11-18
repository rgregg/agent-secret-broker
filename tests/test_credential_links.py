"""Every place a page shows a credential's name links to that credential's page.

Names of credentials that exist become anchors to `/credentials/NAME` (to `?tab=policies` where the name sits in a
policy: a standing approval, a rule, a plan). A name that is not in the catalog (a deleted credential) stays plain
text. The scan reads the visible text of a page, ignoring anchors, scripts, styles and <option> text (a select cannot
hold links) and <button> text (a history row is one button that opens the request's pop-over, and a link cannot sit
inside a button: the name is linked in the pop-over's title instead) and the detail timeline's `key=value` dump of
audit fields (`<span class=ev>`), so a name shown anywhere else without a link fails the test.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
from plan_base import PBase  # noqa: E402

H = {"X-authentik-username": "alice"}


def visible(page):
    page = re.sub(r"<(script|style|option|button)\b.*?</\1>", " ", page, flags=re.S | re.I)
    page = re.sub(r"<span class=ev>.*?</span>", " ", page, flags=re.S)
    page = re.sub(r"<a\b[^>]*>.*?</a>", " ", page, flags=re.S)
    return re.sub(r"<[^>]*>", " ", page)


def bare(page, name):
    """Where `name` appears in the page's visible text without being a link (context snippets)."""
    vis = visible(page)
    return [vis[max(0, m.start() - 30):m.end() + 20].replace("\n", " ")
            for m in re.finditer(r"(?<![\w.-])%s(?![\w.-])" % re.escape(name), vis)]


def anchors(page, name, tab=None):
    q = "?tab=policies" if tab else ""
    return page.count(f"<a class=clink href='/credentials/{name}{q}'>")


class Pages(tg.Base):
    def setUp(self):
        super().setUp()
        self.pending = self.http()                         # a request waiting for a decision
        self.grant_it(minutes=15)                          # a timed approval (a standing row on svc's page and the Clients tab)
        self.settled = self.http(path="/x2")               # approved by that grant: a settled history row

    def page(self, path):
        code, body = t.req(self.abase + path, headers=H)[:2]
        self.assertEqual(code, 200, path)
        return body

    def assert_linked(self, path, min_links, tab=None):
        body = self.page(path)
        self.assertGreaterEqual(anchors(body, "svc", tab), min_links, path)              # the surface is populated
        self.assertEqual(bare(body, "svc"), [], path)                                    # and nothing is left unlinked
        return body

    def test_dashboard_card_chip_and_history_row(self):
        self.assert_linked("/", 3)

    def test_history_list(self):
        self.assert_linked("/?view=all", 3)

    def test_request_detail(self):
        self.assert_linked(f"/request/{self.settled}?fragment=1", 1)

    def test_approval_link_page(self):
        self.assert_linked(f"/a/{self.broker._by_id[self.pending].nonce}", 2)

    def test_clients_tab_rules_link_to_the_policies_tab(self):
        self.assert_linked("/clients", 1, tab="policies")

    def test_policies_tab_shared_names(self):
        self.broker.grants.add(["svc", "other"], 10, "any", "alice", "dashboard", "r")
        body = self.page("/policies")
        self.assertIn("Timed approvals covering several credentials", body)                # the premise: the shared row is there
        self.assertGreaterEqual(anchors(body, "svc", "policies"), 1)
        self.assertGreaterEqual(anchors(body, "other", "policies"), 1)
        self.assertEqual(bare(body, "svc"), [])
        self.assertEqual(bare(body, "other"), [])

    def test_a_credential_that_is_not_in_the_catalog_stays_plain_text(self):
        self.assertGreater(anchors(self.page("/"), "svc"), 0)                            # control: while it exists it links
        self.broker.linkable_names = lambda: frozenset({"other"})                        # as if it were gone from the catalog
        body = self.page("/")
        self.assertEqual(anchors(body, "svc"), 0)
        self.assertNotIn("href='/credentials/svc", body)
        self.assertGreater(len(bare(body, "svc")), 0)                                    # and it is still shown, as text

    def test_scan_helper_sees_an_unlinked_name(self):
        self.assertEqual(len(bare("<p>svc</p><a href='x'>svc</a><option>svc</option>", "svc")), 1)
        self.assertEqual(bare("<a href='x'>svc</a><script>svc</script><option>svc</option><button>svc</button>", "svc"), [])
        self.assertEqual(bare("<p>svc2 and my-svc and svc.v2</p>", "svc"), [])             # only the whole name counts
        self.assertEqual(bare("<span class=ev>names=svc</span>", "svc"), [])               # the raw audit-field dump


class PlanLinks(PBase):
    def test_the_plans_table_links_to_the_policies_page(self):
        self.approve()
        body = t.req(self.abase + "/clients", headers=H)[1]
        self.assertIn("Active plans", body)                                              # the premise: the plans table is there
        plan_part = body.split("Active plans")[1]
        self.assertGreaterEqual(anchors(plan_part, "svc", "policies") + anchors(plan_part, "ledger", "policies"), 1)
        self.assertEqual(bare(plan_part, "svc"), [])
        self.assertEqual(bare(plan_part, "ledger"), [])
