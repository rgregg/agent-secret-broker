# Auto-approve rules from the Policies tab: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the owner add, list and revoke http and env auto-approve rules per credential from the Policies tab, stored in vault metadata, live without a restart.

**Architecture:** `autorules.py` gains one shared single-rule validator used by config rules and by a new stored form (`auto_rules` in a credential's `broker` metadata). A new `uirules.py` holds the Broker mixin (add / revoke / expire / persist, modelled on `SshRulesMixin`) and the Policies section renderer. The existing rule claim in `create()` also consults the credential's stored rules.

**Tech Stack:** Python 3.12, stdlib only, unittest-style tests run by `tests/run_tests.py`.

**Spec:** `docs/superpowers/specs/2026-11-18-ui-auto-approve-rules-design.md`

## Global Constraints

- Branch `ui-auto-approve-rules`; one PR; title says what changed; body links the issue if there is one.
- `client/asb` is NOT touched, so no `sync_cli_text.py` run.
- Stored field name: `auto_rules` (list) in the item's `broker` metadata. Max 50 rules per credential. Rule names unique case-insensitively within a credential, 1-80 chars.
- Modes: `http` and `env` only. Stored rules never have `secret`/`secrets`; the credential is implicit. Refused on ssh key credentials.
- Methods from the form: GET HEAD POST PUT PATCH DELETE OPTIONS; `autorules` limits stay (10 methods, 64 argv words).
- "Any client" = `clients: []` (never the legacy key). The form never offers the legacy client.
- Expiry choices: `never`, `30`, `90` (reuse `sshrules.expiry_days`). Confirmation tick required.
- Refusal reasons are a closed set: `invalid`, `not_confirmed`, `not_eligible`, `cap`, `backend`, `duplicate_name`.
- Config rules win over stored rules when both match. Expired stored rules never match.
- Usage state file: `auto_rules_state.json` beside the audit log; same format as `ssh_rules_state.json`.
- Events (all hidden from the agent audit API): `auto_rule_created`, `auto_rule_revoked`, `auto_rule_expired`, `auto_rule_refused`, `auto_rule_change_failed`, `auto_rules_state_corrupt`, `auto_rules_state_write_failed`; existing `auto_rule_used` gains `source` and `rule_id`. Approval `decision_source` is `config_rule` or `ui_rule`.
- No form value, rule text or exception text reaches an agent response, notification or the audit log beyond validated fields; errors are fixed labels. Policies-page errors echo only validated fields.
- Docs move with behavior (`docs/reference.md`). Test rules in AGENTS.md "Writing tests" apply: write each test first and watch it fail for the right reason; positive control beside every negative assertion; exact status codes and reasons; break the code on purpose to prove each security test.
- Obvious canaries and `example.com` only; no real hostnames or secrets.

## Review Focus

- A stored rule with `clients: []` approves a request from an enrolled client and never the legacy key (test pins it).
- A rule stored on credential A never approves a request that names A and B, or only B.
- An expired rule is ignored even before the sweeper has dropped it.
- A malformed `auto_rules` makes only that credential invalid; the rest of the catalog loads and the message names `auto_rules[N].field`.
- A vault write failure on add leaves nothing active and the page says so; on revoke the rule stays active and the page says so.

---

### Task 1: Shared validator and stored-rule form in `autorules.py`

**Files:**
- Modify: `secret_broker/autorules.py` (split the body of `parse` into `_parse_rule`)
- Create: `tests/test_ui_auto_rules.py`

**Interfaces:**
- Produces (all in `autorules`):
  - `_parse_rule(r: dict, where: str, *, implicit_secret: str | None) -> dict`: validates one rule object. With `implicit_secret=None` it requires exactly one of `secret`/`secrets` (today's behavior, including the `HUMAN_ONLY`/`MODES` and unknown-key errors); with a name it forbids both and sets `secrets = frozenset({implicit_secret})`.
  - `parse(raw, field="auto_approve")`: unchanged behavior and messages, now calling `_parse_rule`; every returned rule gets `"source": "config"`.
  - `STORED_KEYS = {"id", "by", "at", "expires_at"}`; `MAX_STORED = 50`.
  - `parse_stored(raw, credential: str, field="auto_rules") -> list[dict]`: `None` -> `[]`; mode must be `http` or `env` (else `ValueError` naming `field[i].mode`); allows `STORED_KEYS` beyond the mode's keys; requires `id` (`[A-Za-z0-9_-]{4,16}`, unique), `by` (non-empty str <= 120), `at` and optional `expires_at` (strict ISO via `sshrules.to_epoch`); names unique case-insensitively; at most `MAX_STORED`; returns rules with `source: "ui"`, `id`, `by`, `at`, `expires_at` (str or None) beside the usual normalized keys.
  - `serialize_stored(rules: list[dict]) -> list[dict]`: inverse of `parse_stored` (methods and clients as sorted lists, `clients` omitted when empty, `expires_at` always present, `secrets` omitted, mode-specific fields only).
  - `is_expired(rule: dict, now: float) -> bool`: false for config rules and for `expires_at` None.
  - `find(rules, mode, names, spec, client, now=None)`: as today, additionally skipping `is_expired(rule, now or time.time())`.

- [ ] **Step 1: Write failing tests** in `tests/test_ui_auto_rules.py` class `Parse` (import `autorules`, `sshrules`): `test_config_parse_is_unchanged` (reuse two cases from `tests/test_auto_rules.py` and assert same messages), `test_stored_http_rule_round_trips` (parse_stored then serialize_stored equals the input dict, with `clients` omitted when empty), `test_stored_env_rule_round_trips`, `test_stored_rejects_secret_and_secrets`, `test_stored_rejects_ssh_sign_and_human_only_modes` (each asserts the message names `auto_rules[0].mode`), `test_stored_requires_id_by_at`, `test_stored_duplicate_name_and_id`, `test_stored_cap_is_50` (51 rules refused, 50 parse), `test_unknown_key_names_the_field`, `test_find_skips_expired_and_keeps_unexpired` (positive control: same rule with a future expiry matches), `test_find_ignores_expiry_on_config_rules`.
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_ui_auto_rules` — Expected: FAIL (`parse_stored` missing).
- [ ] **Step 3: Implement** the interfaces above in `secret_broker/autorules.py`; move the per-rule body of `parse` (today lines ~83-140) into `_parse_rule` unchanged apart from the `implicit_secret` branch; keep every existing error message.
- [ ] **Step 4: Run** `python tests/run_tests.py -k auto_rules` — Expected: PASS (new file and existing `test_auto_rules.py`).
- [ ] **Step 5: Commit** `autorules: one validator for config rules and a stored form`.

### Task 2: Load stored rules from vault metadata and match them

**Files:**
- Modify: `secret_broker/broker.py` (catalog entry build near the `ssh_rules` handling, ~lines 440-500; `create()` call site ~1985; `_config_rule_claim` ~2019; history line ~5997)
- Modify: `secret_broker/audit_api.py` (hidden-events set, beside `auto_rule_used`)
- Modify: `secret_broker/sshrules.py` (`Usage.__init__(self, path, on_event=None, prefix="ssh_rules")`; its two event names become `f"{prefix}_state_corrupt"` / `f"{prefix}_state_write_failed"`)
- Test: `tests/test_ui_auto_rules.py`

**Interfaces:**
- Consumes: Task 1 (`parse_stored`, `find`, `is_expired`).
- Produces:
  - catalog entry key `auto_rules` (parsed list), absent when empty; `auto_rules` on an ssh credential raises `ValueError("auto_rules only applies to a credential that is not an ssh key")`; popped from the raw entry like `ssh_rules` so it is never in discovery/status.
  - `Broker.auto_rule_usage: sshrules.Usage` (file `auto_rules_state.json`, prefix `auto_rules`), created beside `_init_ssh_rules()`.
  - `Broker._rule_claim(req) -> bool` replacing `_config_rule_claim`: candidates = `self.auto_rules` + (when `len(req.names) == 1`) `self.cfg["secrets"][req.names[0]].get("auto_rules", [])`; for a stored rule it records usage and, after finishing, sets `decision_source="ui_rule"`, `rule_id`, `rule_name`; for a config rule it behaves exactly as today (`decision_source="config_rule"`). `auto_rule_used` gains `source` ("config"|"ui") and `rule_id` (stored only).
  - history line: `Policies rule "<name>" (auto-approved)` for `decision_source == "ui_rule"`, else unchanged.

- [ ] **Step 1: Write failing tests** in `tests/test_ui_auto_rules.py` class `Match(Enrolled, t.Harness)` (reuse `Enrolled` and the `HttpRules` fixture style from `tests/test_auto_rules.py`; set the rule in `cfg["secrets"][name]["auto_rules"]` through `tweak`): `test_stored_http_rule_approves_like_a_config_rule` (same request approved once with a config rule and once with an equal stored rule; both `approved`, `via: policy`, `decision_source` `config_rule` vs `ui_rule`, `rule_name` equal), `test_matcher_table_is_shared` (feed the cases of `tests/test_auto_rules.Match` — override header, percent-escape, multipart, GET with body — through a stored rule; none match), `test_empty_clients_means_enrolled_not_legacy` (enrolled client approved, legacy key prompts), `test_pinned_client_only`, `test_rule_on_a_never_matches_a_and_b_request`, `test_rule_on_a_never_matches_b`, `test_expired_rule_is_ignored_before_sweep` (positive control: same rule with future expiry approves), `test_never_auto_client_still_prompts`, `test_usage_recorded` (`auto_rule_usage.get(name, id)["uses"] == 1` and `auto_rules_state.json` exists), `test_auto_rules_on_ssh_key_makes_credential_invalid`, `test_malformed_auto_rules_invalidates_only_that_credential` (message contains `auto_rules[0].`; another credential still loads), `test_events_hidden_from_agent_audit` (`auto_rule_used` source ui absent from `GET /v1/audit` while present in the broker log — positive control), `test_history_text`.
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_ui_auto_rules` — Expected: FAIL on the new behavior (not an import error).
- [ ] **Step 3: Implement** the interfaces: parse `meta["auto_rules"]` with `autorules_mod.parse_stored(meta["auto_rules"], name)` next to `ssh_rules`; rename `_config_rule_claim` to `_rule_claim` (update the one call site); parametrize `Usage`; add the new event names to `audit_api` hidden set (`auto_rule_created`, `auto_rule_revoked`, `auto_rule_expired`, `auto_rule_refused`, `auto_rule_change_failed`, `auto_rules_state_corrupt`, `auto_rules_state_write_failed`).
- [ ] **Step 4: Run** `python tests/run_tests.py -k auto_rules` and `-k ssh_rules` — Expected: PASS (the `Usage` change must not alter SSH rule behavior).
- [ ] **Step 5: Mutation check** (AGENTS.md): temporarily (a) drop the `len(req.names) == 1` condition, (b) skip the expiry check in `find`; confirm `test_rule_on_a_never_matches_a_and_b_request` and `test_expired_rule_is_ignored_before_sweep` fail; restore.
- [ ] **Step 6: Commit** `broker: match auto-approve rules stored in a credential's metadata`.

### Task 3: Add, revoke and expire stored rules (`uirules.py`)

**Files:**
- Create: `secret_broker/uirules.py`
- Modify: `secret_broker/broker.py` (`class Broker(...)` bases and `__init__` next to `_init_ssh_rules()`)
- Test: `tests/test_ui_auto_rules.py`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces `UiRulesMixin` (needs `cfg`, `_cfg_lock`, `backend`, `clients`, `log`, `auto_rule_usage`), with:
  - `_init_ui_rules(self)`: starts the 60 s sweeper thread calling `expire_auto_rules()`; creates `self._auto_expire_failed = set()`; also prunes `auto_rule_usage` of ids that no longer exist in any credential (call once at init and after each catalog reload via the existing reload hook, if one exists; otherwise at init only).
  - `auto_rules_of(self, name: str) -> list[dict]`.
  - `_persist_auto_rules(self, name, rules, user)`: copy of `_persist_ssh_rules` using key `auto_rules`, `auto_rules_changed`, and `autorules.serialize_stored`.
  - `add_auto_rule(self, name: str, fields: dict, expiry: str, confirm: bool, user: str, peer=None, client_ip=None) -> dict` returning `{"status": "created"|"refused"|"failed", "message": str, "rule_id"?: str}`; `fields` keys: `name`, `mode`, `host`, `scheme`, `methods` (list), `path_prefix`, `argv` (list), `client` (`"*"` or a client id). Raises `ValueError` for an unknown credential or an ssh credential (the endpoint turns it into 400). Order of checks: confirm (`not_confirmed`), expiry via `sshrules.expiry_days` and client (`SCOPE_RE`, `clients.is_active`, not `legacy`) and the rule through `autorules.parse_stored` (`invalid`), duplicate name (`duplicate_name`), cap (`cap`), `set_meta` capability (`backend`), write failure (`failed`, logs `auto_rule_change_failed`). Every refusal logs `auto_rule_refused` with `reason`, `credential`, `user`, `peer`, `client_ip`, `channel="policies"`. Success logs `auto_rule_created` with `credential`, `rule_id`, `rule_name`, `rule_mode`, `expires_at`, `created_by`, `channel="policies"`, `approver_peer`, `approver_ip` (no host/path/argv text beyond what is validated: log `rule_host` for http only).
  - `revoke_auto_rule(self, name, rule_id, user, peer=None, client_ip=None) -> "revoked"|"missing"|"failed"`: as `revoke_ssh_rule`; forgets usage; logs `auto_rule_revoked`.
  - `expire_auto_rules(self, only=None)`: as `expire_ssh_rules`; logs `auto_rule_expired` once per rule, and `auto_rule_change_failed` once per rule on a failed write.
- Safe-message strings for `message` are fixed per reason (no exception text).

- [ ] **Step 1: Write failing tests** in classes `Add`, `Revoke`, `Expire` (use `PoliciesBase`-style harness from `tests/test_ssh_rules.py`, but with an http credential; `NoMeta` backend wrapper for the `backend` case): `test_add_http_rule_persists_and_is_live` (vault `disk()` holds `auto_rules` and `broker.cfg` has it, `auto_rule_created` event present, then a request approves with `decision_source == "ui_rule"`), `test_add_env_rule`, one test per refusal reason asserting status, exact `reason` in `auto_rule_refused`, and that vault and live rules are unchanged (`not_confirmed`, bad expiry `invalid`, unknown client `invalid`, revoked client `invalid`, legacy client `invalid`, `ssh_sign` mode `invalid`, `sudo` mode `invalid`, duplicate name, 50-rule cap, `NoMeta` backend), `test_ssh_credential_raises_value_error`, `test_vault_write_failure_activates_nothing` (patch `backend.set_meta` to raise `BackendError`; live rules unchanged; `auto_rule_change_failed` logged; positive control: the same call succeeds without the patch), `test_revoke_removes_and_forgets_usage`, `test_revoke_failure_keeps_rule_active`, `test_revoke_missing`, `test_expire_drops_and_audits_once` (fake clock from `tests/_fast.py`; second sweep logs nothing), `test_expire_failure_logs_once`, `test_ssh_and_auto_rules_do_not_clobber_each_other` (an ssh key credential cannot hold `auto_rules`; but add an `auto_rules` change and an `approval` metadata field written earlier stays intact on the same item), `test_usage_state_pruned_for_missing_ids`.
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_ui_auto_rules` — Expected: FAIL (`add_auto_rule` missing).
- [ ] **Step 3: Implement** `secret_broker/uirules.py` per the interfaces, copying the locking and error-handling structure of `SshRulesMixin._add_rule`, `revoke_ssh_rule` and `expire_ssh_rules` (hold `_cfg_lock` for the read-modify-write; update in-memory only after `set_meta` succeeds); add the mixin to `Broker`'s bases and call `_init_ui_rules()` after `_init_ssh_rules()`; add `self.auto_rule_usage` creation to `__init__` if not done in Task 2.
- [ ] **Step 4: Run** `python tests/run_tests.py -k auto_rules` — Expected: PASS.
- [ ] **Step 5: Mutation check:** drop the `confirm` check, drop the `clients.is_active` check, make a write failure still update memory; confirm a test fails for each; restore.
- [ ] **Step 6: Commit** `broker: add, revoke and expire auto-approve rules in vault metadata`.

### Task 4: Policies tab section and endpoints

**Files:**
- Modify: `secret_broker/uirules.py` (add `policies_section`)
- Modify: `secret_broker/broker.py` (`_policies_page` ~7032; POST handlers beside `/policies/ssh_rules/*` ~7549-7575; the CSRF path tuple ~7491 and the 413 tuple if it lists policy paths)
- Test: `tests/test_ui_auto_rules.py`

**Interfaces:**
- Produces:
  - `uirules.policies_section(secrets_cfg: dict, config_rules: list[dict], csrf: str, usage, now=None, state=None, client_names=None, client_choices=()) -> str`: one `<details class='card gbox arules'>` per non-ssh credential that has stored rules, matches a config rule, or is listed in `state` (opened by a failed add); plus, so a credential with no rules can get its first one, a compact "Add a rule for..." credential `<select>`-less layout is NOT used: instead render a card for every non-ssh credential with at least one allowed host or any rule (credentials with no `allowed_hosts` and no rules are omitted: nothing to match). Table columns: Name, Mode, Matches, Client, Source (`config` read-only / `UI`), Created, Expires, Last used, Revoke (UI only). Add form fields exactly: `csrf`, `secret`, `name`, `mode` (`http`|`env`), `host`, `scheme`, `methods` (checkbox, repeated), `path_prefix`, `argv` (textarea, one word per line), `client` (`*` default + `client_choices` excluding `legacy`), `expires`, `confirm`. Confirmation text: "I understand matching requests will be released with no approval, at any risk level". Everything echoed is `html.escape`d. Failed-add state echoes only validated fields.
  - `POST /policies/auto_rules/add` and `POST /policies/auto_rules/revoke`, guarded like the SSH ones (add both paths to the CSRF tuple). Add: unknown credential or ssh credential -> 400 `<h1>Bad request</h1>`; `created` -> 200 page with "Auto-approve rule added"; `refused` -> 400 with the error shown in that credential's block; `failed` -> 500. Revoke: unknown credential 400; `revoked`/`missing`/`failed` messages like SSH (`failed` -> 500). Form parsing: `methods` from `form.get("methods", [])`; `argv` split with `splitlines()`, blank lines dropped.
  - `_policies_page(..., auto_state=None)` extra argument and call of `uirules.policies_section(cfg["secrets"], broker.auto_rules, self._tok(user), broker.auto_rule_usage, ...)` after the SSH rules section.

- [ ] **Step 1: Write failing tests** in classes `PoliciesTab` and `Guards` (copy `PoliciesBase.post/page` pattern; section found by splitting the page on `Auto-approve rules`): `test_listing_shows_stored_and_config_rules` (stored: name, host, methods, creator, `UI`, Revoke button present; config: `config` and no Revoke), `test_add_and_revoke_through_the_page` (POST add -> 200, rule in table and vault; POST revoke -> gone), `test_each_refusal_is_400_with_fixed_text_and_no_write` (not confirmed, bad expiry, unknown client, bad mode, `methods` with a lowercase entry), `test_unknown_and_ssh_credential_are_400`, `test_legacy_client_not_offered` (page has no `value='legacy'` in the add form; positive control: an enrolled client is), `test_guards_csrf_origin_identity_and_peer` (copy of the SSH test over both new paths; vault unchanged), `test_agent_key_cannot_reach_the_endpoints` (POST both paths to the agent API base with the client key: not 200 and nothing written; positive control: same POST on the approval base with the SSO user succeeds), `test_hostile_values_are_escaped` (rule name, host-like, argv with `<script>`; stored hostile values from vault metadata that bypass the form are escaped too), `test_form_values_never_reach_audit_or_agent` (canary in `name`/`path_prefix`/`argv` of a refused add; absent from `GET /v1/audit` and from the broker log text; positive control: `auto_rule_refused` event exists), `test_expired_row_is_marked`, `test_oversized_body_is_413_or_refused` (if the 413 tuple lists policy paths, include the new ones).
- [ ] **Step 2: Run** `python tests/run_tests.py -k test_ui_auto_rules` — Expected: FAIL (404/405 on the new paths).
- [ ] **Step 3: Implement** `policies_section` and the two handlers; reuse `sshrules.CSS` classes/`_when`/`short` helpers only where they already exist; do not import from `broker.py` into `uirules.py`.
- [ ] **Step 4: Run** `python tests/run_tests.py -k auto_rules` and `-k ssh_rules` — Expected: PASS.
- [ ] **Step 5: Mutation check:** remove the two paths from the CSRF tuple (guard test must fail), remove `html.escape` from the name cell (escape test must fail); restore.
- [ ] **Step 6: Commit** `policies: add and revoke auto-approve rules from the dashboard`.

### Task 5: Docs, full suite, PR

**Files:**
- Modify: `docs/reference.md` (new subsection "Rules from the Policies tab" under "Approving by configuration rule"; audit table; Policies tab description; fix the sentence that says rules are only configuration), `README.md` only if it lists Policies contents, `secret_broker/autorules.py` module docstring (storage now two places).

- [ ] **Step 1: Write the docs** covering: storage (`auto_rules` field and the stored object, with an example), trust level (same as SSH rules and `approval`), config vs UI (config wins; config rows read-only in the table), single-credential scope, "any client" meaning, expiry, usage state file, every new event and the `decision_source` values, the refusal reasons, and that agents cannot create or see rules.
- [ ] **Step 2: Run** `python tests/run_tests.py` — Expected: all pass (about 75 s with `-j 4`). If anything unrelated fails, find out why before continuing; do not skip tests.
- [ ] **Step 3: Run** `python -m pytest tests/test_test_quality.py -q` — Expected: pass (new tests all assert).
- [ ] **Step 4: Commit** docs, push the branch, open the PR (`gh pr create`, base `main`, body: what changed, the security-invariant note that this moves unattended-approval creation from config to an authenticated approver session at the same level as SSH rules, tests added, mutation checks done).

## Self-review

- **Spec coverage:** storage/validation (T1-2), matching incl. single-credential and expiry (T2), add/revoke/expire/audit/usage (T3), Policies tab and endpoints and guards (T4), docs (T5), config rows read-only in the table (T4 test), eight security properties map to: 1 -> T4 guards and agent-key test; 2 -> T3 refusals; 3 -> T2 shared matcher table; 4 -> T2; 5 -> T2/T3; 6 -> T2; 7 -> T4 escape and canary tests; 8 -> T3.
- **Open point carried to implementation:** the section shows a card only for credentials that can match something (has `allowed_hosts` or a rule); if the owner wants every credential listed, that is a one-line change in `policies_section`.
