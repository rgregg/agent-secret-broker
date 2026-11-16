# Credential values on the Credentials tab: view, replace, add, remove

Status: approved by Ryan on 2026-11-16 ("sounds good"). Follows the credential editor (PRs #61-#64).

## Intent

Ryan wants the Credentials tab to handle a credential's *values*, not only its broker metadata, the way the
Vaultwarden web UI does: see a value, change it, and add or remove the extra values (variables) a credential
carries. Today the tab never handles values; changing one needs Bitwarden or `asb store --replace`.

## The invariant this changes

AGENTS.md: "No text from ... a credential ... crosses a trust boundary (agent response, audit, history, logs,
notifications, pages)". This feature puts a value on **one** page, deliberately, for the human. The PR must say
so. What stays true:

- **Agents never receive a value.** The routes are only on the approval port, behind the human's authenticated
  session, CSRF token and Origin check, exactly like the rest of the tab. Nothing new on the agent port.
- **A value appears only when the human asks for that one value** (a Show action per variable), never in the
  edit page's HTML, never in an error page, audit event, history row, log line or notification.
- **Every view is audited** (`credential_value_revealed`: secret, variable name, user, peer, client_ip; never the
  value) and hidden from the agent audit API. Variable names are already public to agents (`asb list`).
- Responses that carry a value are `Cache-Control: no-store`.

No extra phone approval to view: the human is already signed in, as in Vaultwarden (Ryan's call).

## Goals

1. **Show** a variable's current value (per variable, on click), with Hide and Copy.
2. **Replace** a variable's value: a password box per variable, empty by default, never filled back in.
3. **Add** a value: a new variable name + value, stored in a new field on the same vault item.
4. **Remove** a value: drop the variable from the metadata.

## Non-goals

- SSH private keys: not shown and not replaced here (replacing needs the public key in the metadata to change
  with it; `asb store --replace` / `request-credential` remain the way). The public key may be shown.
- Moving a variable to another item (the loader forbids it: a secret only uses its own item's fields).
- Bulk editing several values in one save.
- Changing how agents use values (http/env/session/plan/ws all unchanged).

## Anti-goals (would make this a failure even if it works)

- A value in any HTML the human did not explicitly ask for (the edit page, an error re-render, the review page).
- A value in an audit event, history, log, notification or exception text.
- A value echoed back into a form after an error.
- Any of this reachable from the agent port or with a client key.

## Approaches considered

- **A (picked): per-variable actions on the edit page.** Each variable row has Show, a Replace box with its own
  Save, and Remove; an "Add a value" form below. One value change per save, so `keep_previous` (one previous
  slot per item in the vault) always keeps the value that was just replaced.
- B: values in the metadata form, saved with the rest. One Save for everything, but mixes the stale-hash diff
  flow with values that must never be in a diff, and several replaced values in one save would lose all but
  one previous value.
- C: a separate Values page. Cleaner separation, one more click; rejected because Ryan asked for it in the editor,
  like Vaultwarden.

## Design

### Show (`POST /credentials/<name>/reveal`, form field `var`)

- POST (not GET) so it is never prefetched, bookmarked or in browser history; CSRF + identity + Origin as usual.
- The page script calls it with `fetch` and puts the value into a read-only box next to the variable with Hide
  and Copy; the response is JSON `{"value": "..."}` with `Cache-Control: no-store`. Without the script the form
  posts normally and the edit page re-renders with that one value shown (also `no-store`).
- Reads `backend.get(item, field)`, then `structured.get(raw, key)` when the variable has a `key`.
- Refused (closed labels, audited `credential_value_reveal_refused`): unknown variable, ssh private key,
  `vault_read` failure, `invalid` (structured field does not parse), `rate_limited` (30 a minute per user).
- Audit `credential_value_revealed` (`secret`, `var`, `user`, `peer`, `client_ip`).

### Replace (`POST /credentials/<name>/value`, fields `var`, `value`)

- Writes with `backend.put(item, field, value, create=False, keep_previous=True)`; for a `key` variable,
  `structured.set_key` on the current field text first (as `asb store` does for a key).
- Empty value is refused (`empty`); control characters other than newline/tab refused; size limit as `asb store`.
- Not a widening (hosts, TLS and approval are unchanged). No tick.
- Audit `credential_value_changed` (`secret`, `var`, `value_bytes`, user...). Success returns the edit page with a
  flash "Value replaced: VAR"; failure re-renders without the value.
- Login usernames are values too (`field: username`): the Bitwarden backend's `_apply` gains `username`.

### Add (`POST /credentials/<name>/value/add`, fields `var`, `value`, `confirm`)

- New variable `VAR` -> field named `VAR` (custom field), metadata `vars[VAR] = {"field": VAR}`.
- The new metadata is validated by `Broker._entry` (variable name rules, reserved names) and written **in the
  same vault write** as the new field: `backend.put(item, VAR, value, create=False, add_field=True, meta=new)`.
  `add_field=True` adds the field when it is missing and raises `BackendConflict` when it already exists.
- Counts as widening (agents can now place one more value on the credential's hosts): the form has an
  "I understand agents can use this value on this credential's hosts" tick, required.
- Refused: variable exists, field exists, invalid name, ssh credential, adopted item without metadata (save it
  once first), stale metadata hash (409, same `old_sha` check as the editor).
- Audit `credential_value_added` (`secret`, `var`, `value_bytes`).

### Remove (`POST /credentials/<name>/value/remove`, field `var`)

- Drops `vars[VAR]` from the metadata via `set_meta` (validated by `_entry`); the vault field stays (reversible
  in Bitwarden, no value destroyed). Refused for the last variable (`vars` must be non-empty) and ssh.
- Narrowing: no tick. Stale-hash check. Audit `credential_value_removed` (`secret`, `var`).

### Backend contract

`put(..., add_field=False)` in `backends/base.py`, implemented in `bitwarden`, `file`, `local`, `memory`
(a hidden custom field in Bitwarden, type 1). Existing calls are unaffected. Each backend gets tests for: adds
when missing, conflict when present, metadata written in the same operation.

### Page

The edit page gets a **Values** card above Allowed hosts: one row per variable (name, where it lives:
`notes`, `password`, field `X`, or `field X / key Y`), Show/Hide/Copy, Replace box + Save value, Remove. Below:
Add a value (name, value, tick, Add). SSH credentials show the public key and say replacement is via
`asb store --replace`. Backends without `set_meta` show the card read-only (Show still works).

### Docs

`docs/reference.md` Credentials tab section: the new actions, the audit events, and an explicit note in the
threat-model text that values are shown to the human on request. AGENTS.md invariant wording updated to say
"pages, except the human's explicit Show on the Credentials tab".

## Tests (must be able to fail; mutation-check each guard)

- Show: value appears in the JSON and the no-JS page only after reveal; never in the plain edit page (positive
  control: the variable name is there); `no-store` header; audit has the event and never the value; needs CSRF,
  identity, Origin; not on the agent port; ssh refused; rate limit; structured key.
- Replace: value written, previous kept, value absent from the response, audit, logs; key variables; empty and
  control characters refused; error page has no value.
- Add: field and metadata written together; tick required; duplicate var/field refused; stale hash 409; value
  never echoed on refusal.
- Remove: metadata updated, field still in the vault, last variable refused.
- Backends: `add_field` per backend.
- Secrecy sweep: every new event in `audit_api.HIDDEN`; canary value absent from audit file, broker log output
  and every page except the reveal response.

## Left to the builder

Exact markup and CSS, the rate-limit bucket implementation (reuse the fingerprint limiter's shape), how the
no-JS fallback renders the revealed value.
