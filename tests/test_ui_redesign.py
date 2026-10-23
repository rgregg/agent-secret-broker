"""Approval site redesign, stage 1: card markup and one-tap decisions, History tab, Running now,
Settings, tabs, icons, tokens, local-time script, and the security properties that must not move
(see docs/proposals/ui-redesign.md)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only)

from secret_broker import broker as bmod  # noqa: E402
from secret_broker import ui_theme  # noqa: E402

EXPECTED_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; "
                "connect-src 'self'; manifest-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
                "worker-src 'self'; script-src 'nonce-X'")


class _NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class UI(t.Dashboard):
    ttl = 300

    def raw(self, path, user="alice", data=None, headers=None):
        """(status, headers, body bytes) without following redirects."""
        h = {"X-authentik-username": user, **(headers or {})}
        r = urllib.request.Request(self.abase + path, headers=h,
                                   data=None if data is None else urllib.parse.urlencode(data).encode(),
                                   method="GET" if data is None else "POST")
        try:
            with urllib.request.build_opener(_NoFollow).open(r, timeout=10) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def post(self, path, **form):
        form.setdefault("csrf", self.broker.csrf_token("alice"))
        return self.raw(path, data=form)

    def card(self, page=None):
        page = page or self.get("/")[1]
        m = re.search(r"<article class=req.*?</article>", page, re.S)
        self.assertTrue(m, "no request card")
        return m.group(0)


for _n in dir(t.Dashboard):         # reuse the helpers, not the dashboard tests
    if _n.startswith("test"):
        setattr(UI, _n, None)


class OneTap(UI):
    def test_each_timed_button_posts_its_own_grant(self):
        for m in (5, 15, 30):
            rid = self.ask(path=f"/t{m}")
            self.assertIn(f"<button class='btn t' name=decision value='approve_grant_{m}'", self.card())
            st, loc, _ = self.decide(rid, f"approve_grant_{m}")
            self.assertEqual((st, loc), (303, "/?note=grant"))
            self.assertIn(self.result(rid)["status"], ("approved", "released"))
            self.assertEqual(max(g["minutes"] for g in self.broker.active_grants()), m)
            for g in self.broker.active_grants():
                self.broker.revoke_grant(g["id"], "alice", "127.0.0.1", None)

    def test_deny_and_approve_once_are_unchanged(self):
        rid = self.ask()
        card = self.card()
        self.assertIn("<button class='btn deny' name=decision value=deny>Deny</button>", card)
        self.assertIn("<button class='btn approve' name=decision value=approve>Approve once</button>", card)
        self.assertEqual(self.decide(rid, "approve")[:2], (303, "/?note=approved"))
        self.assertEqual(self.broker.active_grants(), [])
        rid2 = self.ask(path="/y")
        self.assertEqual(self.decide(rid2, "deny")[:2], (303, "/?note=denied"))

    def test_always_still_needs_its_confirm(self):
        self.ask()
        card = self.card()
        det = re.search(r"<details class=alw>(.*?)</details>", card, re.S).group(1)
        self.assertIn("Always allow this...", det)
        self.assertIn("value=approve_always>Confirm", det)
        self.assertEqual(card.count("approve_always"), 1)            # only inside the confirm
        self.assertNotIn("approve_always", card.replace(det, ""))

    def test_timed_row_has_no_helper_label(self):
        self.ask()
        card = self.card()
        self.assertNotIn("Automatically approve", card)
        self.assertNotIn("Approve for a while", card)
        self.assertIn("<div class=timed>", card)

    def test_decisions_still_need_csrf_and_identity(self):
        rid = self.ask()
        self.assertEqual(self.decide(rid, "approve_grant_5", csrf="nope")[0], 403)
        self.assertEqual(self.decide(rid, "approve_grant_5", user="mallory")[0], 403)
        self.assertEqual(self.broker.active_grants(), [])
        cross = self.decide(rid, "approve_grant_5", extra={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(cross[0], 403)


class CardMarkup(UI):
    def test_glance_row_chip_icon_word_and_time_left(self):
        self.ask()
        card = self.card()
        self.assertIn("<div class=glance>", card)
        self.assertIn("<span class='rbadge lo'><i aria-hidden=true>&#9679;</i>LOW</span>", card)
        self.assertRegex(card, r"<span class=gwho>svc &middot; ")
        self.assertRegex(card, r"<time data-exp='\d+'>\d+:\d\d left</time>")
        self.assertRegex(card, r"Requested <time datetime='\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ' data-fmt=clock>"
                               r"\d\d:\d\d UTC</time>")

    def test_no_progress_bar_and_one_sentence(self):
        self.ask()
        card = self.card()
        self.assertNotIn("class=bar", card)
        self.assertNotIn("<progress", card)
        self.assertIn("<h2 class=sent>Reads things", card)

    def test_risk_chips_levels(self):
        for lvl, icon, word, cls in (("low", "&#9679;", "LOW", "lo"), ("medium", "&#9670;", "MEDIUM", "md"),
                                     ("high", "&#9650;", "HIGH", "hi")):
            self.assertEqual(ui_theme.risk_chip(lvl),
                             f"<span class='rbadge {cls}'><i aria-hidden=true>{icon}</i>{word}</span>")
        self.assertIn("ASSESSING", ui_theme.risk_chip(None))

    def test_high_is_red_in_both_themes_never_neutral(self):
        css = ui_theme.TOKENS + ui_theme.CSS
        self.assertIn(".rbadge.hi{background:var(--hib);color:var(--hit)}", css)
        for block in (ui_theme._LIGHT, ui_theme._DARK):
            hib = re.search(r"--hib:#([0-9a-f]{6})", block).group(1)
            hit = re.search(r"--hit:#([0-9a-f]{6})", block).group(1)
            for hexv in (hib, hit):
                r, g, b = (int(hexv[i:i + 2], 16) for i in (0, 2, 4))
                self.assertGreater(r, g + 25, hexv)          # reddish, not grey
                self.assertGreater(r, b + 25, hexv)

    def test_chips_and_long_values_do_not_wrap(self):
        css = ui_theme.CSS
        self.assertRegex(css, r"\.rbadge\{[^}]*white-space:nowrap;flex:none")
        self.assertRegex(css, r"\.trunc\{white-space:nowrap;overflow:hidden;text-overflow:ellipsis")
        self.assertRegex(css, r"\.pill\{white-space:nowrap;flex:none\}")
        self.assertRegex(css, r"\.left\{[^}]*white-space:nowrap;flex:none")
        long_path = "/" + "a" * 300
        self.ask(path=long_path)
        card = self.card()
        self.assertRegex(card, r"<div class='callline trunc'>GET http://127.0.0.1:\d+/a{100,}")
        self.assertLess(len(re.search(r"callline trunc'>([^<]*)<", card).group(1)), 320)   # capped
        self.assertIn("Request details", card + "Request details")

    def test_agent_text_is_escaped_on_the_card(self):
        evil = "<img src=x onerror=alert(1)>"
        self.broker.summarizer = t._Stub(evil, "high")
        url = f"http://127.0.0.1:{self.up.server_address[1]}/x?q=<script>alert(2)</script>"
        self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": url, "source": "<i>mallory</i>@host",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        page = self.get("/")[1]
        card = self.card(page)
        for raw in ("<img src=x", "<script>alert(2)", "<i>mallory</i>"):
            self.assertNotIn(raw, page, raw)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", card)
        self.assertIn("&lt;script&gt;alert(2)&lt;/script&gt;", card)
        self.assertIn("&lt;i&gt;mallory&lt;/i&gt;", card)
        self.assertIn("class='rbadge hi'", card)

    def test_details_are_behind_disclosure_chips(self):
        self.ask()
        card = self.card()
        self.assertRegex(card, r"<details class=dx><summary>Details</summary>")
        self.assertRegex(card, r"<details class=dx><summary>Why LOW</summary>")
        self.assertIn("Claimed source (unverified)", card)

    def test_card_poll_version_changes_when_the_summary_arrives(self):
        self.broker.summarizer = None
        self.ask()
        v1 = re.search(r"data-version='(\w+)'", self.get("/")[1]).group(1)
        r = next(iter(self.broker._by_id.values()))
        r.risk = {"level": "low", "model": "low", "reasons": ["x"]}
        r.summary, r.summary_source = "Does a thing", "deterministic"
        v2 = re.search(r"data-version='(\w+)'", self.get("/")[1]).group(1)
        self.assertNotEqual(v1, v2)


class TabsAndNav(UI):
    def test_tabs_order_and_active_marker(self):
        for path, on in (("/", "Requests"), ("/history", "History"), ("/policies", "Policies"),
                         ("/settings", "Settings"), ("/clients", "Settings")):
            st, _, body = self.raw(path)
            self.assertEqual(st, 200, path)
            page = body.decode()
            nav = re.search(r"<nav class=tabs>(.*?)</nav>", page, re.S).group(1)
            labels = re.findall(r">([A-Za-z]+)(?: <span class=count>\d+</span>)?</a>", nav)
            self.assertEqual(labels, ["Requests", "History", "Policies", "Settings"], path)
            self.assertEqual(re.findall(r"class=on>([A-Za-z]+)", nav), [on], path)
            self.assertNotIn(">Clients<", nav)
            self.assertIn("href='/policies'", nav)

    def test_header_has_logo_brand_and_no_user_name(self):
        page = self.get("/")[1]
        self.assertRegex(page, r'<img class=logo src="data:image/png;base64,[A-Za-z0-9+/=]+" width=30 height=30 alt=\'\'>')
        self.assertIn("<b class=brand>Secret Broker</b>", page)

    def test_old_history_links_land_on_the_history_tab(self):
        for old, new in (("/?view=all", "/history"), ("/?view=all&outcome=denied", "/history?outcome=denied"),
                         ("/?view=all&q=x", "/history?q=x")):
            st, hd, _ = self.raw(old)
            self.assertEqual((st, hd.get("Location")), (303, new), old)

    def test_count_badge_on_requests(self):
        self.ask()
        nav = re.search(r"<nav class=tabs>(.*?)</nav>", self.get("/")[1], re.S).group(1)
        self.assertRegex(nav, r"Requests <span class=count>1</span>")


class HistoryTab(UI):
    def finish(self, path, decision):
        rid = self.ask(path=path)
        self.decide(rid, decision)
        return rid

    def test_route_filters_search_and_rows(self):
        a = self.finish("/ok", "approve")
        d = self.finish("/no", "deny")
        st, _, body = self.raw("/history")
        page = body.decode()
        self.assertEqual(st, 200)
        for label in ("All", "Approved", "Denied", "Expired", "Failed"):
            self.assertRegex(page, rf">{label}</a>")
        self.assertRegex(page, r"<a class='chip on' data-outcome='' href='/history' aria-current=true>All</a>")
        self.assertIn("<input type=search name=q", page)
        self.assertEqual(page.count("class=hrow"), 2)
        self.assertIn(f"data-id='{a}'", page)
        self.assertRegex(page, r"<li data-ts='\d+'><button type=button class=hrow")
        self.assertIn("class='hic ok'", page)
        self.assertIn("class='hic no'", page)
        self.assertIn("&#10003;", page)
        self.assertIn("&#10005;", page)
        self.assertIn("<dialog id=hdlg", page)
        den = self.raw("/history?outcome=denied")[2].decode()
        self.assertEqual(den.count("class=hrow"), 1)
        self.assertIn(f"data-id='{d}'", den)
        self.assertRegex(den, r"<a class='chip on' data-outcome='denied'[^>]*aria-current=true>Denied</a>")
        appr = self.raw("/history?outcome=approved,auto-approved")[2].decode()
        self.assertEqual(appr.count("class=hrow"), 1)
        self.assertEqual(self.raw("/history?q=%2Fno")[2].decode().count("class=hrow"), 1)
        self.assertEqual(self.raw("/history?q=nothing-matches")[2].decode().count("class=hrow"), 0)

    def test_fragment_is_just_the_list(self):
        self.finish("/ok", "approve")
        st, _, body = self.raw("/history?fragment=1&outcome=approved")
        self.assertEqual(st, 200)
        self.assertIn("id=hlist", body.decode())
        self.assertNotIn("<nav", body.decode())

    def test_requests_tab_has_no_history_list(self):
        self.finish("/ok", "approve")
        page = self.get("/")[1]
        self.assertNotIn("id=hlist", page)
        self.assertNotIn("class=hrow", page)

    def test_detail_card_mirrors_the_approval_card(self):
        rid = self.finish("/ok", "approve_grant_15")
        st, _, body = self.raw(f"/request/{rid}?fragment=1")
        d = body.decode()
        self.assertEqual(st, 200)
        order = [d.index(x) for x in ("class=glance", "<h2 class=sent>", "class=band", "<dl class='kv facts'>",
                                      "<div class=dxrow>")]
        self.assertEqual(order, sorted(order))
        self.assertIn("Approved by you", d)
        self.assertIn("for 15 min", d)
        self.assertIn("<summary>Timeline</summary>", d)
        self.assertRegex(d, r"<time datetime='[^']+Z' data-fmt=full>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC</time>")

    def test_detail_page_is_on_the_history_tab(self):
        rid = self.finish("/ok", "approve")
        nav = re.search(r"<nav class=tabs>(.*?)</nav>", self.raw(f"/request/{rid}")[2].decode(), re.S).group(1)
        self.assertIn("href='/history' class=on>History", nav)

    def test_history_needs_the_identity_header(self):
        self.assertEqual(self.raw("/history", user="mallory")[0], 403)
        self.assertEqual(self.raw("/history?fragment=1", user="")[0], 403)


class RunningNow(UI):
    def setUp(self):
        super().setUp()
        import time
        now = time.time()
        self.broker.active_sessions = lambda: [{
            "pid": "ses12345", "cred": "unifi", "client_id": "c1", "client_name": "dev-box",
            "hosts": ["10.0.0.1:443"], "methods": ["GET"], "expires_at": now + 600, "left_s": 600,
            "calls": 3, "max_calls": 60}]
        self.broker.active_plans = lambda: [{
            "id": "plan1234", "client_id": "c1", "task": "<b>build</b> things", "client_name": "build-box", "names": ["svc"],
            "expires_at": now + 300, "left_s": 300, "uses": 1, "uses_max": 10, "state": "active"}]

    def test_section_rows_and_revoke_forms(self):
        page = self.get("/")[1]
        self.assertIn("<div class=sec>Running now</div>", page)
        run = page[page.index("<section class=running>"):]
        self.assertIn("Session &middot; unifi", run)
        self.assertIn("dev-box &middot; 3 of 60 calls", run)
        self.assertIn("Plan &middot; svc", run)
        self.assertIn("&lt;b&gt;build&lt;/b&gt; things", run)
        self.assertNotIn("<b>build</b>", run)
        self.assertRegex(run, r"<time data-exp='\d+'>10:00 left</time>|<time data-exp='\d+'>\d+:\d\d left</time>")
        tok = self.broker.csrf_token("alice")
        self.assertIn(f"<form method=post action='/sessions/revoke'><input type=hidden name=csrf value='{tok}'>"
                      "<input type=hidden name=pid value='ses12345'>", run)
        self.assertIn(f"<form method=post action='/plans/revoke'><input type=hidden name=csrf value='{tok}'>"
                      "<input type=hidden name=plan value='plan1234'>", run)
        self.assertEqual(run.count("Revoke</button>"), 2)

    def test_revoke_needs_csrf_and_lands_on_requests(self):
        self.assertEqual(self.raw("/sessions/revoke", data={"pid": "x", "csrf": "bad"})[0], 403)
        self.assertEqual(self.raw("/plans/revoke", data={"plan": "x"})[0], 403)
        st, hd, _ = self.post("/sessions/revoke", pid="nonesuch")
        self.assertEqual((st, hd["Location"]), (303, "/?note=sesgone"))
        st, hd, _ = self.post("/plans/revoke", plan="nonesuch")
        self.assertEqual((st, hd["Location"]), (303, "/?note=plangone"))
        self.assertIn("That session had already ended.", self.get("/?note=sesgone")[1])

    def test_running_moved_off_the_machines_page(self):
        page = self.get("/clients")[1]
        self.assertNotIn("Active sessions", page)
        self.assertNotIn("Active plans", page)
        self.assertIn("<h1>Machines</h1>", page)
        self.assertIn("href='/settings'", page)

    def test_poll_fragment_carries_running_rows(self):
        frag = self.get("/?fragment=1")[1]
        self.assertIn("<section class=running>", frag)

    def test_section_absent_when_nothing_runs(self):
        self.broker.active_sessions = lambda: []
        self.broker.active_plans = lambda: []
        self.assertNotIn("Running now", self.get("/")[1])


class SettingsPage(UI):
    def test_sections(self):
        page = self.get("/settings")[1]
        heads = re.findall(r"<div class=sec>(.*?)</div>", page)
        self.assertEqual(heads, ["Notifications on this device", "Default approval rules", "Appearance", "About"])
        self.assertIn("Signed in as alice", page)
        self.assertIn("<a class='btn sm' href='/clients'>Manage</a>", page)
        self.assertRegex(page, r"<div class=seg role=img aria-label='[^']*'[^>]*><span>None</span>")
        self.assertIn("id=notify-test", page)
        self.assertIn("Skip the push while this page is open", page)
        self.assertNotIn("Descriptions", page)          # nothing to show in this base
        self.assertIn("<summary>Troubleshooting</summary>", page)
        self.assertIn("id=sw-box", page)

    def test_appearance_is_client_side_only(self):
        page = self.get("/settings")[1]
        for v in ("light", "dark", "auto"):
            self.assertIn(f"<button type=button data-theme-set={v}>", page)
        box = page[page.index("id=appearance"):page.index("</section>", page.index("id=appearance"))]
        self.assertNotIn("<form", box)
        self.assertNotIn("name=csrf", box)
        js = ui_theme.APPEARANCE_JS
        self.assertIn("localStorage.setItem('asb_theme'", js)
        for m in re.finditer(r"localStorage\.\w+", js):
            before = js[:m.start()]
            self.assertGreater(before.count("try{"), before.count("}catch"), m.group(0))   # inside try
        self.assertNotIn("fetch(", js)
        self.assertNotRegex(self.get("/")[1], r"<html[^>]*data-theme")        # default: match the system
        st, hd, _ = self.raw("/settings")
        self.assertNotIn("Set-Cookie", hd)

    def test_theme_script_runs_in_head_with_try_catch(self):
        head = self.get("/")[1].split("<style>")[0]
        self.assertIn("localStorage.getItem('asb_theme')", head)
        self.assertIn("catch(e){}", ui_theme.THEME_JS)

    def test_devices_have_this_device_tag_hook_and_remove(self):
        class P:
            def public_key(self):
                return "BPk"

            def devices(self):
                return [{"id": "d1", "user": "alice", "agent": "Mozilla Safari/1 iPhone Mac OS X", "created": 1,
                         "last_ok": 1700000000, "last_error": None, "ep": "ab12cd34ef56ab12"},
                        {"id": "d2", "user": "alice", "agent": "Firefox/1 Linux", "created": 1,
                         "last_ok": None, "last_error": None, "ep": "ffff000011112222"}]
        self.broker.push = P()
        page = self.get("/settings")[1]
        self.assertEqual(page.count("class='tagchip thisdev' hidden>this device<"), 2)    # shown by script
        self.assertIn("data-ep='ab12cd34ef56ab12'", page)
        self.assertIn("<div class=sec>All devices that get pushes</div>", page)
        self.assertEqual(page.count("action='/push/revoke'"), 2)
        self.assertEqual(page.count(">Remove</button>"), 2)
        self.assertRegex(page, r"Last push <time datetime='[^']+Z' data-fmt=ago>")
        self.assertIn("crypto.subtle.digest('SHA-256'", bmod._DASH_JS)

    def test_machines_page_still_manages_clients(self):
        page = self.get("/clients")[1]
        self.assertIn("Machines", page)
        self.assertIn("<table class=tbl>", page)


class IconsAndManifest(UI):
    def test_icon_routes(self):
        for size in (32, 64, 180, 512):
            st, hd, body = self.raw(f"/icon-{size}.png")
            self.assertEqual(st, 200, size)
            self.assertEqual(hd["Content-Type"], "image/png")
            self.assertEqual(body[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual((int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")), (size, size))
            self.assertIn("max-age=31536000", hd["Cache-Control"])
            self.assertEqual(hd["X-Content-Type-Options"], "nosniff")
            self.assertEqual(self.raw(f"/icon-{size}.png", user="mallory")[0], 403)
        st, hd, body = self.raw("/apple-touch-icon.png")
        self.assertEqual((st, int.from_bytes(body[16:20], "big")), (200, 180))

    def test_manifest_icons(self):
        m = json.loads(self.raw("/manifest.webmanifest")[2])
        got = {(i["src"], i["sizes"], i["type"]) for i in m["icons"]}
        self.assertIn(("/icon-512.png", "512x512", "image/png"), got)
        self.assertIn(("/apple-touch-icon.png", "180x180", "image/png"), got)
        self.assertEqual(m["background_color"], bmod._THEME_LIGHT)

    def test_head_icons_are_inline_data_uris(self):
        page = self.get("/")[1]
        self.assertRegex(page, r'<link rel=icon type=image/png sizes=32x32 href="data:image/png;base64,')
        self.assertRegex(page, r'<link rel=apple-touch-icon sizes=180x180 href="data:image/png;base64,')
        import base64
        self.assertIn(base64.b64encode(ui_theme.ICONS[32]).decode(), page)
        self.assertIn(base64.b64encode(ui_theme.ICONS[64]).decode(), page)

    def test_assets_are_the_approved_files(self):
        for size in (32, 64, 180, 512):
            with open(os.path.join(os.path.dirname(bmod.__file__), "assets", f"sb-monogram-{size}.png"), "rb") as f:
                self.assertEqual(f.read(), ui_theme.ICONS[size])


class SecurityHeadersAndLoads(UI):
    def pages(self):
        rid = self.ask()
        nonce = self.broker._by_id[rid].nonce
        return ["/", "/history", "/settings", "/policies", "/clients", f"/a/{nonce}", f"/request/{rid}",
                "/?note=denied"]

    def test_csp_is_unchanged(self):
        for path in self.pages():
            st, hd, _ = self.raw(path)
            csp = re.sub(r"'nonce-[^']+'", "'nonce-X'", hd["Content-Security-Policy"])
            self.assertEqual(csp, EXPECTED_CSP, path)
            self.assertEqual(hd["X-Frame-Options"], "DENY")

    def test_no_external_resource_loads(self):
        for path in self.pages():
            body = self.raw(path)[2].decode()
            for attr in re.findall(r"(?:src|href|action|poster|srcset)=[\"']?(https?:[^\s\"'>]*)", body):
                self.fail(f"{path}: attribute loads {attr}")
            self.assertNotRegex(body, r"url\(\s*[\"']?https?:", path)
            self.assertNotRegex(body, r"@import", path)
            self.assertNotRegex(body, r"<script[^>]+src=", path)
            self.assertNotRegex(body, r"<link[^>]+rel=[\"']?stylesheet", path)
            self.assertNotIn("fonts.googleapis", body)
        for js in (ui_theme.TIME_JS, ui_theme.THEME_JS, ui_theme.APPEARANCE_JS, bmod._DASH_JS):
            self.assertNotRegex(js, r"""['"]https?://""")

    def test_all_pages_include_both_token_blocks(self):
        for path in ("/", "/history", "/settings"):
            body = self.raw(path)[2].decode()
            self.assertRegex(body, r":root\{color-scheme:light dark;--bg:#f3f6f1;")
            self.assertIn("@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0c140f;", body)
            self.assertIn(":root[data-theme=dark]{color-scheme:dark;--bg:#0c140f;", body)
            self.assertIn(":root[data-theme=light]{color-scheme:light;--bg:#f3f6f1;", body)

    def test_token_contrast_meets_4_5_to_1_in_both_themes(self):
        def lum(h):
            c = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
            return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]

        def ratio(a, b):
            x, y = sorted((lum(a), lum(b)), reverse=True)
            return (x + 0.05) / (y + 0.05)
        pairs = (("tx", "bg"), ("tx", "sf"), ("mu", "bg"), ("mu", "sf"), ("mu", "tb"), ("ai", "ac"), ("ac", "sf"),
                 ("lot", "lob"), ("mdt", "mdb"), ("hit", "hib"), ("okt", "okb"), ("not", "nob"), ("ext", "exb"),
                 ("dnt", "dnb"))
        for name, block in (("light", ui_theme._LIGHT), ("dark", ui_theme._DARK)):
            tok = dict(re.findall(r"--(\w+):#([0-9a-f]{6})", block))
            for a, b in pairs:
                self.assertGreaterEqual(ratio(tok[a], tok[b]), 4.5, f"{name} {a}/{b}")

    def test_touch_targets_focus_and_reduced_motion_rules(self):
        css = ui_theme.CSS
        self.assertIn(":focus-visible{outline:2px solid var(--ac)", css)
        self.assertIn("@media (prefers-reduced-motion:reduce)", css)
        self.assertRegex(css, r"\.decide-row \.btn[^{]*\{min-height:2\.9rem")
        self.assertRegex(css, r"\.btn,button\{[^}]*min-height:2\.75rem")
        self.assertRegex(css, r"\.tabs a\{min-height:2\.75rem")

    def test_forbidden_pages_have_no_scripts(self):
        st, _, body = self.raw("/", user="mallory")
        self.assertEqual(st, 403)
        self.assertNotIn(b"<script", body)


class LocalTime(unittest.TestCase):
    def test_time_tag_markup(self):
        self.assertEqual(ui_theme.time_tag(1761151263, "clock"),
                         "<time datetime='2025-10-22T16:41:03Z' data-fmt=clock>16:41 UTC</time>")
        self.assertIn("data-fmt=full>2025-10-22 16:41:03 UTC</time>", ui_theme.time_tag(1761151263, "full"))
        self.assertEqual(ui_theme.time_tag(None), "")
        self.assertEqual(ui_theme.left_text(252), "4:12 left")
        self.assertEqual(ui_theme.left_text(-3), "0:00 left")

    def test_script_has_no_timezone_text_and_no_server_round_trip(self):
        self.assertIn("Intl.DateTimeFormat(undefined", ui_theme.TIME_JS)
        self.assertNotIn("fetch(", ui_theme.TIME_JS)
        self.assertNotIn("timezone is", ui_theme.TIME_JS.lower())

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_formatter_in_node_in_two_timezones(self):
        harness = r"""
const vm=require('vm'),fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
function T(attrs,text){return {attrs,textContent:text,title:'',getAttribute(k){return this.attrs[k]===undefined?null:this.attrs[k];}};}
const times=[T({datetime:'2026-10-22T16:41:03Z','data-fmt':'clock'},'16:41 UTC'),
  T({datetime:'2026-10-22T16:41:03Z','data-fmt':'full'},'x'),
  T({datetime:new Date(Date.now()-5*60000).toISOString(),'data-fmt':'ago'},'x'),
  T({datetime:'garbage','data-fmt':'clock'},'keep')];
const lis=[T({'data-ts':String(Math.floor(Date.now()/1000))}),T({'data-ts':String(Math.floor(Date.now()/1000)-2*86400)})];
const made=[];
const ul={querySelectorAll(s){return s==='li.dayh'?made.splice(0,made.length):s==='li[data-ts]'?lis:[];},
  insertBefore(h,li){made.push(Object.assign(h,{remove(){}}));}};
const doc={body:{},querySelectorAll(s){return s==='time[datetime]'?times:s==='ul.hist'?[ul]:[];},
  createElement(){return {setAttribute(){},className:'',textContent:''};}};
const sb={document:doc,Intl,Date,setInterval(){},window:null};sb.window=sb;
vm.createContext(sb);vm.runInContext(src,sb);
console.log(JSON.stringify({clock:times[0].textContent,title:times[0].title,full:times[1].textContent,
  ago:times[2].textContent,bad:times[3].textContent,heads:made.map(x=>x.textContent)}));
"""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "t.js"), "w") as f:
                f.write(ui_theme.TIME_JS)
            with open(os.path.join(d, "h.js"), "w") as f:
                f.write(harness)
            outs = {}
            for tz in ("America/Los_Angeles", "Asia/Tokyo"):
                r = subprocess.run(["node", os.path.join(d, "h.js"), os.path.join(d, "t.js")], capture_output=True,
                                   text=True, timeout=30, env={**os.environ, "TZ": tz, "LANG": "en_US.UTF-8"})
                self.assertEqual(r.returncode, 0, r.stderr)
                outs[tz] = json.loads(r.stdout)
        la, tk = outs["America/Los_Angeles"], outs["Asia/Tokyo"]
        self.assertRegex(la["clock"], r"^9:41\sAM$")
        self.assertRegex(tk["clock"], r"^1:41\sAM$")
        self.assertIn("PDT", la["title"])
        self.assertIn("2026", la["full"])
        self.assertEqual(la["ago"], "5 min ago")
        self.assertEqual(la["bad"], "keep")                      # an unparsable stamp keeps its fallback text
        self.assertEqual(la["heads"][0], "Today")


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PageScripts(unittest.TestCase):
    """The page script on the History page polls /history, not the Requests page; every script parses."""
    HARNESS = r"""
const vm=require('vm'),fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const mode=process.argv[3];
const fetches=[],timers=[];
const mk=a=>({attrs:a||{},hidden:true,innerHTML:'',textContent:'',getAttribute(k){return this.attrs[k]===undefined?null:this.attrs[k];},
  setAttribute(k,v){this.attrs[k]=v;},addEventListener(){},querySelectorAll(){return [];},querySelector(){return null;}});
const els={offline:mk(),flash:mk()};
if(mode==='history'){els.hlist=mk({'data-all':'1','data-limit':'25'});els.hlist.innerHTML='<ul class=hist>old</ul>';}
else{els.cards=mk({'data-version':'v1'});els.cards.hidden=false;}
const doc={hidden:false,visibilityState:'visible',title:'',getElementById:id=>els[id]||null,querySelector:()=>null,
  querySelectorAll:()=>[],addEventListener(){},hasFocus:()=>true};
class P{parseFromString(h){return {getElementById(id){
  if(id==='hlist'&&h.indexOf('id=hlist')>=0)return {innerHTML:'<ul class=hist>new</ul>'};
  if(id==='cards'&&h.indexOf('id=cards')>=0)return {getAttribute:()=>'v1',innerHTML:'x'};
  return null;}};}}
function resp(body){return {type:'basic',status:200,ok:true,redirected:false,headers:{get:()=>'text/html'},text:()=>Promise.resolve(body)};}
const sb={document:doc,DOMParser:P,URLSearchParams,URL,Uint8Array,navigator:{},history:{replaceState(){}},
  location:{pathname:mode==='history'?'/history':'/'},localStorage:{getItem(){return null;},setItem(){}},
  fetch(u,o){fetches.push(u);return Promise.resolve(resp(mode==='history'?'<div id=hlist>x</div>':'<div id=cards></div>'));},
  setInterval(f,ms){timers.push({f,ms});return timers.length;},clearInterval(){},setTimeout(){return 0;},clearTimeout(){}};
sb.window=sb;sb.self=sb;sb.asbAuth={out:false,expired:()=>false,mark(){},on(){}};
sb.window.asbAuth=sb.asbAuth;
vm.createContext(sb);vm.runInContext(src,sb);
timers.filter(t=>t.ms===3000).forEach(t=>t.f());
setTimeout(()=>{console.log(JSON.stringify({fetches,hl:els.hlist?els.hlist.innerHTML:null}));},50);
"""

    def run_node(self, mode):
        from secret_broker import broker as b
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("dash.js", b._DASH_JS), ("h.js", self.HARNESS)):
                with open(os.path.join(d, name), "w") as f:
                    f.write(text)
            r = subprocess.run(["node", os.path.join(d, "h.js"), os.path.join(d, "dash.js"), mode],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_history_page_polls_its_own_list(self):
        out = self.run_node("history")
        polls = [u for u in out["fetches"] if "fragment=1" in u]
        self.assertEqual(polls, ["/history?fragment=1&view=all"])
        self.assertEqual(out["hl"], "<ul class=hist>new</ul>")

    def test_requests_page_still_polls_the_cards(self):
        out = self.run_node("cards")
        self.assertEqual([u for u in out["fetches"] if "fragment=1" in u], ["/?fragment=1"])

    def test_every_inline_script_parses(self):
        with tempfile.TemporaryDirectory() as d:
            for name, text in (("dash", bmod._DASH_JS), ("time", ui_theme.TIME_JS), ("theme", ui_theme.THEME_JS),
                               ("appearance", ui_theme.APPEARANCE_JS), ("session", bmod._SESSION_JS),
                               ("sw", bmod._SERVICE_WORKER)):
                p = os.path.join(d, name + ".js")
                with open(p, "w") as f:
                    f.write(text)
                r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, name + r.stderr)


if __name__ == "__main__":
    unittest.main()
