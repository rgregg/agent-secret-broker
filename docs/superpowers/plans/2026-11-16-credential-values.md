# Credential values on the Credentials tab: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show, replace, add and remove a credential's values from the Credentials tab edit page.

**Architecture:** Four broker methods next to `set_credential_meta` in `secret_broker/broker.py` do the vault
work and the audit; four POST routes under `/credentials/<name>/...` call them; `crededitor.values_section`
renders a Values card. The backend contract gains `put(..., add_field=False)` so a new field and the metadata
that names it are one vault write.

**Tech Stack:** Python 3.12 stdlib HTTP server, unittest, the project's backends.

**Spec:** `docs/superpowers/specs/2026-11-16-credential-values-design.md`

## Global Constraints

- A value appears only in the reveal response (JSON, or the no-JS page re-render for that one variable). Never
  in the plain edit page, error pages, audit, history, logs, notifications or exception text.
- Routes only on the approval port; same CSRF / identity / Origin gate as `/credentials/*` (already applied to
  every POST path starting with `/credentials/`).
- Errors are fixed labels; never `str(exc)` for anything that touched a value.
- SSH private keys: never revealed, never replaced, never added here.
- Value limits: non-empty, no NUL, at most `MAX_STORE_VALUE` bytes (same as `asb store`).
- Reveal rate limit: 30 per 60 s per user (`VALUE_RATE = (30, 60)`).
- Audit events, all added to `audit_api.HIDDEN`: `credential_value_revealed`, `credential_value_changed`,
  `credential_value_added`, `credential_value_removed`, `credential_value_refused` (`action`, `reason`).
- Canary values in tests: `S3CR3T-...`; hosts `example.com` / `127.0.0.1`.

## Review Focus

- A replace that fails in the vault: the re-rendered page must not contain the typed value (test in Task 3).
- A `key` variable whose field is not structured: reveal and replace refuse with `invalid`, no exception text
  (test in Task 2).
- An adopted item (no `broker` metadata): reveal and replace work; add and remove refuse with `adopted`
  (test in Task 2).
- Login username variable on Bitwarden: replace writes `login.username` (test in Task 1, bw contract).
- A value containing `'`, `<` or `</script>` shown via the no-JS fallback is escaped (test in Task 3).

---

### Task 1: Backend `add_field`, and Bitwarden username writes

**Files:**
- Modify: `secret_broker/backends/base.py` (`put` signature + docstring), `bitwarden.py` (`_put_locked`,
  `_apply`), `file.py`, `local.py`, `memory.py` (`put`)
- Test: `tests/backend_contract.py`

**Interfaces:**
- Produces: `put(item, field, value, create=False, keep_previous=False, meta=None, add_field=False)`.
  `add_field=True` with `create=False`: the field must be missing (else `BackendConflict`); it is added as a
  custom field (Bitwarden: hidden, type 1), and `meta` (if given) is written in the same operation. Reserved
  names and `notes`/`password`/`username`/`private_key` refused with `BackendInvalid`.

- [ ] Step 1: contract tests `test_add_field_adds_a_missing_field_with_meta` (get returns the value, catalog
  row meta equals the given meta), `test_add_field_refuses_an_existing_field` (BackendConflict, old value
  unchanged), `test_add_field_refuses_builtin_names` (BackendInvalid for `notes`, `password`). Bw contract:
  `test_replace_login_username` (`put(item, "username", "u2")` then `get(item, "username") == "u2"`).
- [ ] Step 2: run `python -m unittest tests.test_backends -k add_field` -> fail (unexpected keyword).
- [ ] Step 3: implement in all four backends.
- [ ] Step 4: `python -m unittest tests.test_backends` -> pass.
- [ ] Step 5: commit.

### Task 2: Broker value methods

**Files:**
- Modify: `secret_broker/broker.py` (after `set_credential_meta`), `secret_broker/audit_api.py` (HIDDEN)
- Test: `tests/test_credential_values.py` (new; `Base` copied from `test_credential_editor` via import)

**Interfaces:**
- Produces (all return `{"status": ok|refused|conflict|failed, "reason": label, "message": fixed text}`):
  - `reveal_value(name, var, user, peer=None, client_ip=None)` -> adds `"value"` on ok.
    Reasons: `unknown_var`, `ssh`, `invalid`, `vault_read`, `rate_limited`.
  - `replace_value(name, var, value, user, ...)` -> reasons `unknown_var`, `ssh`, `empty`, `too_large`,
    `invalid`, `vault_write`. Uses `keep_previous=True`; a `key` var goes through `structured.set_key`.
  - `add_value(name, var, value, old_sha, user, confirm=False, ...)` -> reasons `exists`, `invalid_name`
    (message from `_entry`), `ssh`, `adopted`, `needs_confirmation`, `conflict` (status conflict),
    `empty`, `too_large`, `vault_write`. New meta = stored meta with `vars[var] = {"field": var}`; validated by
    `Broker._entry`; `backend.put(item, var, value, add_field=True, meta=new)`; then the live entry rebuilt like
    `set_credential_meta` does.
  - `remove_value(name, var, old_sha, user, ...)` -> reasons `unknown_var`, `last`, `ssh`, `adopted`,
    `conflict`; writes meta via the `set_credential_meta` path's vault write (`set_meta`), not the field.
- Every refusal logs `credential_value_refused` (`action`, `reason`, `secret`, `user`...); successes log the
  events in Global Constraints with `secret`, `var`, and `value_bytes` for changed/added.

- [ ] Step 1: tests, one class per method, each asserting the vault state, the event and its fields, and that
  the canary value is absent from `open(self.audit).read()`. Include: reveal of a `key` variable; reveal refused
  for ssh and for a non-structured `key` field (`invalid`); 31st reveal in a minute `rate_limited`;
  replace keeps `previous_value`; add without `confirm` writes nothing and gives `needs_confirmation`; add with a
  stale `old_sha` gives conflict; add of an existing var gives `exists`; remove of the only var gives `last`;
  remove leaves the field readable via `backend.get`; adopted item: reveal ok, add `adopted`.
- [ ] Step 2: run `python tests/run_tests.py -k test_credential_values` -> fail.
- [ ] Step 3: implement; add the five events to `audit_api.HIDDEN`.
- [ ] Step 4: run -> pass. Mutation: drop the `confirm` check, drop the ssh check, log `value` in the event;
  each fails a test.
- [ ] Step 5: commit.

### Task 3: Routes, Values card, script

**Files:**
- Modify: `secret_broker/broker.py` (`_credentials_post` actions `reveal`, `value`, `value/add`,
  `value/remove`; `_credential_edit` passes the values card), `secret_broker/crededitor.py`
  (`values_section`, `JS`, `CSS`)
- Test: `tests/test_credential_values.py`

**Interfaces:**
- Consumes: Task 2 methods.
- Produces: `values_section(name, sc, token, sha, *, can_write, revealed=None, flash="") -> str`;
  `revealed` is `(var, value)` for the no-JS fallback only. Routes: `POST /credentials/<n>/reveal`
  (`var`; with header `Accept: application/json` -> `self._json(200, {"value": v})`, else the edit page with
  `revealed`), `POST /credentials/<n>/value` (`var`, `value`), `POST /credentials/<n>/value/add`
  (`var`, `value`, `confirm`, `old_sha`), `POST /credentials/<n>/value/remove` (`var`, `old_sha`).
  Path parsing: `parts[3:]` joined, so `value/add` is one action.

- [ ] Step 1: tests: GET edit page lists each variable name and its location and contains no canary
  (positive control: the name is there); reveal JSON has the value and `Cache-Control: no-store`; reveal page
  fallback shows the value escaped (canary with `'<`); reveal without CSRF 403 and no event; agent port 404 for
  `/credentials/svc/reveal`; replace response contains no value; replace failure (backend raising on put)
  re-renders with no value; add/remove flash and state; ssh credential shows the public key and no Show button.
- [ ] Step 2: run -> fail.
- [ ] Step 3: implement. JS: buttons `data-reveal=VAR` post `csrf` + `var` with `fetch(..., {method:'POST',
  headers:{'Accept':'application/json'}, body: URLSearchParams, credentials:'same-origin', cache:'no-store'})`,
  fill a read-only `<input>`; Hide clears it (sets `value=''`); Copy uses `navigator.clipboard.writeText`.
- [ ] Step 4: run full suite `python tests/run_tests.py -j 4` -> 0 failing.
- [ ] Step 5: commit.

### Task 4: Docs and invariant wording

**Files:** `docs/reference.md` (Credentials tab section + threat model note), `AGENTS.md` (invariant line),
`README.md` (tab blurb).

- [ ] Step 1: document the four actions, refusals, events and the explicit statement that values are shown to
  the authenticated human on request only; AGENTS.md: "pages, except the human's explicit Show on the
  Credentials tab".
- [ ] Step 2: commit, push, open PR with a "Security invariant change" section.
