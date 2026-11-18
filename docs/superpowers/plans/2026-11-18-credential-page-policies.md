# Per-credential policies in the credential page: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every per-credential policy (standing approvals, auto-approve rules, risk guidance, SSH host policy and rules) from the Policies tab into a Policies sub-tab of the credential page, keep only multi-credential and orphaned policies on the Policies tab, and link every displayed credential name to its page.

**Architecture:** The four existing section renderers each gain a per-credential function (the card for one credential) that the credential page calls; a new `credpolicy.py` assembles the sub-tab body and the summary strip; the Broker gains placement helpers that split standing approvals and config rules into per-credential and shared sets; a new `credlinks.py` is the only builder of `/credentials/NAME` hrefs, fed a per-request set of linkable names. Existing POST endpoints and guards are unchanged; their responses re-render the credential's Policies sub-tab.

**Tech Stack:** Python 3.12 stdlib, server-rendered HTML, unittest-style tests via `tests/run_tests.py`.

**Spec:** `docs/superpowers/specs/2026-11-18-credential-page-policies-design.md`

## Global Constraints

- Branch `credential-page-policies`; one PR; `client/asb` untouched (no CLI text sync).
- Credential names are `[A-Za-z0-9_.-]{1,64}`; every href is `html.escape`d and URL-quoted.
- Policies sub-tab URL: `/credentials/NAME?tab=policies`; Settings is `/credentials/NAME`; any other `tab` value is Settings.
- Sub-tab label `Policies (n)`: n = standing approvals + auto-approve rules (stored and config) for the credential; guidance is not counted. "Guidance set" = non-empty stored guidance.
- Placement: an entry is on a credential page only when its set of secret names (internal tag stripped, duplicates collapsed) is exactly one credential that exists in the catalog; everything else (two or more, or a missing name) stays on the Policies tab, orphans marked "names a credential that no longer exists" and not linked. A multi-secret config rule also shows on each existing credential it names, marked "covers several credentials".
- Policy forms are independent forms inside the Policies sub-tab (own CSRF field, hidden `secret`), never inside the Settings form; the Settings review step and concurrency hash are untouched.
- All existing POST paths, guards (SSO identity, trusted peer, CSRF, same-origin), status codes (400 refusal, 500 write failure), fixed messages and audit events are unchanged. Per-credential POSTs re-render that credential's Policies sub-tab in the response (no redirect-after-POST). `/grants/revoke` takes an optional hidden `back`: `policies` (default) or an existing credential name; anything else falls back to the Policies tab, never reflected.
- The Policies tab stays in the nav always; empty state says where per-credential policies now live.
- Names in a policy context (standing approval, rule, guidance, plan) link to `?tab=policies`; everywhere else to Settings. A name not in the catalog is plain escaped text.
- Notifications and plans (Clients tab) are unchanged apart from linking names.
- Tests follow AGENTS.md: write each first and watch it fail for the right reason; positive control beside every negative assertion; exact codes; break the code on purpose for each security-relevant test. Old tests that parse the Policies sections are migrated, never weakened or deleted.
- Docs move with behavior (`docs/reference.md`, `docs/setup.md`, `README.md`).

## Review Focus

- A timed approval that names a credential which was deleted or renamed stays visible and revocable on the Policies tab (orphan), unlinked (test in Task 2 and Task 7).
- A credential name with dots and dashes (`orca-news.v2`) or markup-lookalike text in a rule name renders escaped and the links resolve (Task 1, Task 8).
- A forged or hostile `back` value on `/grants/revoke` falls back to the Policies tab and is never reflected (Task 4).
- `/credentials/NAME?tab=policies` for an unknown credential is the same 404 as Settings; an SSH key shows SSH sections and no rules section, a non-SSH credential the reverse (Task 5).
- A backend without `set_meta` still renders the Policies sub-tab (read-only note) and the existing write refusals are unchanged (Task 5).

---

### Task 1: Credential link helper and per-request linkable set

**Files:**
- Create: `secret_broker/credlinks.py`, `tests/test_credlinks.py`
- Modify: `secret_broker/broker.py` (`Broker.linkable_names`; set the set at the top of `do_GET` and `do_POST` of the approval handler)

**Interfaces:**
- Produces:
  - `credlinks.link(name: str, tab: str | None = None) -> str`: an escaped `<a class=clink href='/credentials/NAME[?tab=policies]'>NAME</a>` when `name` is syntactically valid and in the current linkable set (any valid name when no set is active); otherwise the escaped name as plain text. `tab` is `None` or `"policies"` (anything else raises `ValueError`).
  - `credlinks.links(names, tab=None) -> str`: `", "`-joined `link()`s.
  - `credlinks.use(names: frozenset[str] | None)`: sets the linkable set for the current thread's context (`contextvars`), `None` = unrestricted.
  - `Broker.linkable_names() -> frozenset[str]`: `frozenset(self.cfg["secrets"])` under `_cfg_lock`.
- Consumes: nothing.

- [ ] **Step 1: Write failing tests** in `tests/test_credlinks.py`: `test_link_escapes_and_quotes` (name `a.b-c_d`, tab policies gives `href='/credentials/a.b-c_d?tab=policies'`); `test_invalid_names_are_plain_text` (`<img src=x>` and `../x` render escaped, no `<a`); `test_names_outside_the_set_are_plain_text` (`use(frozenset({"a"}))`: `link("b")` has no `<a`, `link("a")` does; control for each); `test_no_set_means_any_valid_name`; `test_bad_tab_raises`; `test_links_joins_in_order`; `test_the_set_is_per_thread` (a second thread sees no restriction while the first has one).
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_credlinks` — Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `credlinks.py` and `Broker.linkable_names`; call `credlinks.use(broker.linkable_names())` at the start of `do_GET` and `do_POST` of the approval-site handler (after the `_user()` check) so each request sees the catalog at that moment.
- [ ] **Step 4: Run** `python tests/run_tests.py -k test_credlinks` then the full suite — Expected: PASS.
- [ ] **Step 5: Commit** `credlinks: one helper for credential page links`.

### Task 2: Placement helpers (per-credential vs shared)

**Files:**
- Modify: `secret_broker/broker.py` (`standing_rows`, new `Broker.standing_by_credential`, `Broker.config_rules_for`, `Broker.shared_policies`)
- Test: `tests/test_credential_placement.py`

**Interfaces:**
- Produces:
  - every row of `Broker.standing_rows()` gains `names: list[str]`, the raw secret names (no internal tag), unchanged `secrets`.
  - `Broker.standing_by_credential(self) -> tuple[dict[str, list[dict]], list[dict]]`: `(per_credential, shared)`; a row goes under name `n` iff `set(row["names"]) == {n}` and `n in self.cfg["secrets"]`; everything else is in `shared`. A `shared` row gets `orphan: bool` (any name missing from the catalog).
  - `Broker.config_rules_for(self, name) -> list[dict]`: config rules (`self.auto_rules`) whose `secrets` contains `name`.
  - `Broker.shared_config_rules(self) -> list[dict]`: config rules with two or more secrets, or any secret missing from the catalog (each with `orphan` flag).

- [ ] **Step 1: Write failing tests** (harness `tests/test_grants.Base`/`t.Harness` with a second credential): `test_single_secret_timed_grant_is_per_credential`, `test_always_approval_is_per_credential`, `test_legacy_allow_is_per_credential`, `test_two_secret_timed_grant_is_shared_and_not_per_credential` (each with the opposite-side control), `test_duplicate_names_count_as_one` (`secrets: [a, a]`), `test_grant_for_a_deleted_credential_is_a_shared_orphan` (create a grant, delete the credential from `cfg["secrets"]`, row in shared with `orphan` True), `test_internal_key_entries_are_per_credential` (the internal secret keeps its page; its `names` has no tag), `test_client_scope_does_not_change_placement`, `test_config_rule_placement` (single, pair, missing name), `test_nothing_is_lost` (count per-credential + shared equals `len(standing_rows())`).
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_credential_placement` — Expected: FAIL (`standing_by_credential` missing).
- [ ] **Step 3: Implement** the four additions in `broker.py`; `names` is added where each row dict is built (timed: `g["secrets"]`; always and legacy: `[name]`).
- [ ] **Step 4: Run** `python tests/run_tests.py` — Expected: PASS (existing standing-row consumers ignore the new key).
- [ ] **Step 5: Commit** `broker: split standing approvals and config rules into per-credential and shared`.

### Task 3: Per-credential section renderers

**Files:**
- Modify: `secret_broker/guidance.py`, `secret_broker/sshhosts.py`, `secret_broker/sshrules.py`, `secret_broker/uirules.py`
- Create: `secret_broker/credpolicy.py`
- Test: `tests/test_credpolicy.py`

**Interfaces:**
- Produces (each module keeps its current `policies_section` for now, rebuilt on top of its new function):
  - `guidance.card(name: str, sc: dict, csrf: str, idx: int = 0) -> str`: the guidance editor for one credential, **open** (not collapsed), same form fields and `action='/policies/guidance'`.
  - `sshhosts.card(name, sc, csrf, state=None) -> str` and `sshrules.card(name, sc, csrf, usage, now=None, state=None, client_names=None, client_choices=()) -> str` and `uirules.card(name, sc, config_rules, csrf, usage, now=None, state=None, client_names=None, client_choices=()) -> str`: the same card each section builds today for one credential, open, "" when the section does not apply (ssh sections for a non-ssh credential; auto rules for an ssh key).
  - `credpolicy.standing_card(name, rows, csrf, cnames) -> str`: table of the credential's standing rows with Revoke (each form carries hidden `back` = the credential name for grants; the legacy row is a read-only line "approval: allow (any method, covered modes): change this under Settings" linking `?tab=settings`... i.e. to `/credentials/NAME` via `credlinks.link`).
  - `credpolicy.body(name, sc, ctx) -> str` where `ctx` is a dataclass `PolicyCtx(csrf, usage_ssh, usage_auto, client_names, client_choices, standing_rows, config_rules, states)` returning the sections in this order: standing approvals, auto-approve rules, risk guidance, SSH host policy, SSH host rules.
  - `credpolicy.counts(name, sc, standing_rows, config_rules) -> dict` with keys `standing`, `rules`, `guidance` (bool), `total` (standing + rules).
- Consumes: Task 2 placement helpers (rows and rules are passed in by the caller).

- [ ] **Step 1: Write failing tests** in `tests/test_credpolicy.py`: `test_each_card_has_the_existing_form_fields` (for guidance, sshhosts, sshrules, uirules: the card contains the same `action=` path and the hidden `secret`/`name` field naming the credential, and is not inside a `<details>` without `open`), `test_cards_do_not_apply_to_the_wrong_kind` (ssh sections empty for an http credential, auto rules empty for an ssh key; each with the applicable control), `test_body_order_and_sections`, `test_legacy_allow_is_a_read_only_line_with_a_settings_link`, `test_standing_forms_carry_back_and_the_grant_id`, `test_counts` (guidance excluded from `total`; config + stored rules counted), `test_every_value_is_escaped` (hostile rule name, guidance text, argv, client name).
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_credpolicy` — Expected: FAIL (functions missing).
- [ ] **Step 3: Implement** the per-credential functions by lifting the per-credential body out of each module's existing loop (the loop then calls the new function, so the Policies tab output is byte-identical for now); implement `credpolicy.py`.
- [ ] **Step 4: Run** `python tests/run_tests.py` — Expected: PASS (old Policies tests still green: output unchanged).
- [ ] **Step 5: Commit** `policies: per-credential section renderers`.

### Task 4: `/grants/revoke` back-field and credential-page POST re-render

**Files:**
- Modify: `secret_broker/broker.py` (new `Handler._credential_policies`, changes in the per-credential POST handlers)
- Test: `tests/test_credential_policies_page.py`

**Interfaces:**
- Produces:
  - `Handler._credential_policies(self, user, name, note="", status=200, ssh_state=None, rule_state=None, auto_state=None, g_state=None)`: renders the credential page with the Policies sub-tab for `name` (chrome, sub-tab links, note), `tab="credentials"`. Unknown `name` is the same 404 page as Settings.
  - the POST handlers for `/policies/guidance`, `/policies/ssh_hosts`, `/policies/ssh_rules/add|revoke`, `/policies/auto_rules/add|revoke` and the legacy `/policies` (approval=prompt) call `_credential_policies(user, name, ...)` instead of `_policies_page(...)`, with the same notes, statuses and state dicts as today.
  - `/grants/revoke`: reads hidden `back`; if `back` is an existing credential name returns `_credential_policies(user, back, note)`, otherwise (missing, `policies`, anything else) `_policies_page(user, note)`; status codes unchanged; `back` is never echoed.
- Consumes: Task 3 `credpolicy.body`, Task 2 helpers.

- [ ] **Step 1: Write failing tests** (reuse `ManageBase`-style harness from `tests/test_ui_auto_rules.py`; migrate in the same file the post-helper): `test_each_policy_post_renders_that_credentials_policies_tab` (status and note unchanged, response contains `Policies (` and the credential name in the sub-tab links), `test_grants_revoke_back_credential_renders_its_page`, `test_grants_revoke_back_missing_hostile_or_gone_falls_back_to_the_policies_tab` (`back=<script>x`, `back=nope`, no `back`; none reflected; positive control: valid back), `test_a_post_for_credential_a_never_changes_b`, `test_error_states_show_in_the_credential_page` (a refused auto-rule add shows its fixed error in the credential's Policies sub-tab, 400).
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_credential_policies_page` — Expected: FAIL.
- [ ] **Step 3: Implement** `_credential_policies` and re-point the handlers; keep `_policies_page` for the Policies tab.
- [ ] **Step 4: Run** `python tests/run_tests.py` — Expected: tests that assert the old Policies-tab response after these POSTs fail: migrate each to assert the credential page (same status, same note text, same strength) in this commit.
- [ ] **Step 5: Commit** `policies: forms answer with the credential's Policies page`.

### Task 5: Sub-tab routing, chrome and summary strip

**Files:**
- Modify: `secret_broker/broker.py` (`do_GET` credentials route, `_credential_edit`), `secret_broker/crededitor.py` (`edit_section` gets `chrome`/`summary` args)
- Test: `tests/test_credential_policies_page.py`

**Interfaces:**
- Produces:
  - `GET /credentials/NAME?tab=policies` renders `_credential_policies(user, name)`; `?tab=` anything else, or absent, renders Settings as today.
  - `crededitor.tabs_html(name, active: str, total: int) -> str`: the `Settings | Policies (n)` link strip, used by both tabs (`active` is `"settings"` or `"policies"`).
  - `crededitor.summary_html(name, counts: dict) -> str`: the strip at the top of Settings: `n standing approvals, m auto-approve rules, guidance set|not set`, with the Policies link.
  - Settings keeps every existing element; `edit_section(..., chrome="", summary="")` places `chrome` under the title and `summary` under it. The preview/review step and conflict view render without the strip (unchanged).
- Consumes: Task 3 `credpolicy.counts`, Task 4 `_credential_policies`.

- [ ] **Step 1: Write failing tests**: `test_tab_policies_renders_the_policies_body`, `test_unknown_tab_is_settings`, `test_unknown_credential_is_404_on_both_tabs`, `test_settings_has_the_summary_strip_and_a_link` (counts match a seeded catalog: 1 standing, 2 rules, guidance set), `test_ssh_key_shows_ssh_sections_and_no_rules_section` (and the reverse for http), `test_read_only_backend_renders_the_policies_tab` (`NoMeta` wrapper: 200, the existing read-only note, the add refusals still `backend`), `test_nav_highlights_credentials`, `test_review_step_has_no_strip`.
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_credential_policies_page` — Expected: FAIL.
- [ ] **Step 3: Implement** the route branch, `tabs_html`, `summary_html`, and pass counts into `_credential_edit` (counts from Task 2 helpers).
- [ ] **Step 4: Run** `python tests/run_tests.py -k credential` then the full suite — Expected: PASS (credential editor tests untouched).
- [ ] **Step 5: Commit** `credential page: Settings and Policies sub-tabs with a summary strip`.

### Task 6: Credentials list shows policy counts

**Files:**
- Modify: `secret_broker/crededitor.py` (`list_section(secrets, flash="", q="", counts=None)`), `secret_broker/broker.py` (`_credentials_page` passes counts)
- Test: `tests/test_credential_policies_page.py`

**Interfaces:**
- Produces: `list_section(..., counts: dict[str, int] | None = None)`; a "Policies" cell per row: the number (linked to `?tab=policies` via `credlinks.link`-style anchor) or an empty-state dash when 0; the search text and filter keep working.
- Consumes: Task 3 `credpolicy.counts`.

- [ ] **Step 1: Write failing tests**: `test_list_shows_counts_and_links` (a credential with 1 grant + 1 rule shows 2 and `?tab=policies`; one with none shows the dash; control), `test_list_still_filters` (existing search behavior unaffected).
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement** column/badge.
- [ ] **Step 4: Run** `python tests/run_tests.py -k credential` — Expected: PASS.
- [ ] **Step 5: Commit** `credentials list: policy counts`.

### Task 7: The Policies tab shows only shared policies

**Files:**
- Modify: `secret_broker/broker.py` (`_policies_page`, `_standing_section` → shared rows only), `secret_broker/uirules.py`/`guidance.py`/`sshhosts.py`/`sshrules.py` (remove the old whole-catalog `policies_section` functions), `tests/*` that read them
- Test: `tests/test_credential_placement.py`, migrated tests

**Interfaces:**
- Produces: `_policies_page(self, user, note="", status=200)` renders: heading, an intro line saying per-credential policies live on each credential's Policies page, "Timed approvals covering several credentials" (shared standing rows, each with Revoke and `back=policies`), "Auto-approve rules covering several credentials" (shared config rules, read-only, with the orphan marker), and an orphan note ("names a credential that no longer exists", names unlinked); empty state: "No policy covers more than one credential." Old per-credential sections are gone from this page.
- Consumes: Task 2 helpers, Task 4 `back`.

- [ ] **Step 1: Write failing tests**: `test_policies_tab_lists_only_shared_policies` (shared grant present; single-secret grant, guidance editor and ssh/rule sections absent; positive controls on both sides), `test_orphan_grant_is_visible_revocable_and_unlinked` (revoke it from the tab with `back=policies`, gone afterwards), `test_policies_tab_empty_state_points_to_the_credential_pages`, `test_shared_config_rule_and_orphan_marker`, `test_nothing_is_lost_across_pages` (for a catalog with single, pair and orphan entries: stored rules, config rules, standing rows each appear exactly once in the per-credential pages (counting each page) plus the tab, except a multi-secret config rule which appears on each existing credential it names and on the tab).
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement** the reduced page; delete the four whole-catalog `policies_section` functions; migrate every old test that called them or parsed the old sections (`tests/test_ssh_rules.py` PoliciesBase/PoliciesTab, `tests/test_ui_auto_rules.py` PoliciesTab, guidance and standing tests) to the credential pages with the same assertions.
- [ ] **Step 4: Run** `python tests/run_tests.py` — Expected: PASS, test count not lower than before the migration except for the deleted duplicates' equivalents (list any removed test and where its assertion moved in the commit message).
- [ ] **Step 5: Commit** `policies tab: only policies that span credentials`.

### Task 8: Link every displayed credential name

**Files:**
- Modify: `secret_broker/broker.py` (approval card `names` at ~5781, chips ~5814/5827, change-hosts text ~5649, detail title ~6136, dashboard/history rows ~6624/6712, plan request ~6826, post-save pages ~6910/6913, link page texts ~7399/7785/7795), `secret_broker/credreq.py` (~188/196/204/334), `secret_broker/sessions.py` (~949), `secret_broker/plans.py` (~1762), `secret_broker/clients.py` (rule listings), `secret_broker/credpolicy.py`
- Test: `tests/test_credential_links.py`

**Interfaces:**
- Consumes: Task 1 `credlinks.link/links`. No new interfaces: each site replaces `html.escape(name)` with `credlinks.link(name)` (or `tab="policies"` in a policy context: standing rows, rules, guidance, plans, "Always allow saved for").

- [ ] **Step 1: Write failing tests** in `tests/test_credential_links.py`: build a catalog with credentials named `orca-news.v2` and `plain`, create one request (http), one env request, a standing approval, a stored rule, a plan, a pending credential request and a session; for each page (`/`, history list `/?view=all`, request detail `/request/ID?fragment=1`, the `/a/NONCE` link page, `/policies`, `/clients`, `/credentials/NAME` both tabs) assert `test_every_displayed_name_is_linked` (every occurrence of the credential name in visible text is inside an `<a class=clink`, with the exact escaped href and `?tab=policies` in policy contexts) with a count assertion that at least N links were found on that page (cannot scan nothing); `test_names_not_in_the_catalog_are_plain_text` (a request naming a since-deleted credential); `test_link_hrefs_are_escaped` (a name that is syntactically valid but contains `.`/`-`).
- [ ] **Step 2: Run** — Expected: FAIL page by page.
- [ ] **Step 3: Implement** the replacements site by site; keep each page's existing escaping for everything else.
- [ ] **Step 4: Run** `python tests/run_tests.py` — Expected: PASS (existing tests that assert exact name markup, e.g. `<b>svc</b>`, are updated to the linked form without weakening).
- [ ] **Step 5: Commit** `pages: credential names link to the credential page`.

### Task 9: Copy, docs and final checks

**Files:**
- Modify: `secret_broker/broker.py` (copy at ~5810, 5823, 5847, 5851), `secret_broker/sshrules.py` (~566), `secret_broker/credreq.py` (~292), `secret_broker/crededitor.py` (~527), `secret_broker/clients.py` (~1033), module docstrings mentioning "the Policies tab", `docs/reference.md`, `docs/setup.md`, `README.md`
- Test: `tests/test_credential_links.py`

- [ ] **Step 1: Write failing tests**: `test_revoke_copy_points_to_the_credentials_policies_page` (the approval card's "Revoke any time ..." text links to `/credentials/NAME?tab=policies` and no longer says "under Policies"), `test_rename_delete_block_message_names_the_new_places`, `test_clients_tab_sentence`.
- [ ] **Step 2: Run** — Expected: FAIL.
- [ ] **Step 3: Implement** the copy changes and write the docs: the Policies tab description (only multi-credential and orphaned policies), the credential page's two sub-tabs and the summary strip, where each policy now lives, the `back` field, the link behavior, the endpoint paths unchanged.
- [ ] **Step 4: Run** `python tests/run_tests.py` and `python -m pytest tests/test_test_quality.py -q` — Expected: all pass.
- [ ] **Step 5: Commit** `docs and copy: per-credential policies live on the credential page`.

## Self-review

- **Spec coverage:** sub-tabs and summary (T3, T5), placement and orphans (T2, T7), `back` (T4), counts on list (T6), Policies tab reduction and empty state (T7), links everywhere (T1, T8), copy and docs (T9), non-goals untouched (plans stay: only linked in T8), tests 1-7 of the spec map to T2/T7 (1, 2), T4 (3), T4/T7 migration (4), T8 (5), T5 (6), T7 (7).
- **Type consistency:** `credlinks.link/links/use`, `Broker.linkable_names`, `standing_by_credential`, `config_rules_for`, `shared_config_rules`, `credpolicy.body/counts/standing_card`, `_credential_policies` are named once in the task that produces them and reused unchanged.
- **Proportion:** the plan states interfaces, test names and the values the spec fixes, not function bodies.
