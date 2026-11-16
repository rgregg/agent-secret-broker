# Credential editor (approval site)

Status: all three stages built: 1 (list, metadata edit), 2 (create, rename, delete), 3 (fingerprint fetch). Date: 2026-11-14.

Built-as notes for stage 1: the preview step puts the candidate metadata in a hidden `meta_json` field and the save
writes exactly that (re-validated), instead of re-reading form fields; the validator is `Broker._entry` itself, which
already was the single shared function, so no extraction was needed; no `edit_item` or rename in this stage.

Built-as notes for stage 2: rename sets only the `name` key of the metadata (the vault item is not renamed, so
`edit_item` is still unused); instead of dropping grants and plans on rename, rename and delete refuse while any
are bound to the name (the safer reading of the design's "drops them with a warning"); rename also refuses a name
in `plans.deny_secrets`; create is token-only and reuses `_validate_store`/`_create_item`; adopted items and the
summary key can be neither renamed nor deleted.

Built-as notes for stage 3: the fetch is a button on the edit form (`/credentials/<name>/fingerprint`) that
re-renders the form with the fingerprint added to the pins; the human confirms it through the normal review and
the `pin_added` widening tick rather than a separate confirm step. The audit carries a 12-hex host hash. The
form's non-form keys now start from what the page showed (`advanced_orig`) rather than the stored metadata, so a
re-rendered candidate keeps its keys.

## Intent

A credential's policy (allowed hosts and ports, TLS pin or `tls_verify`, approval mode, variables, standing
grants, `ws` and `plans` settings) lives as a JSON object in the `broker` field of its vault item. Today the only
way to change most of it is to hand-edit that JSON in Bitwarden. That is slow and error-prone: it is how a stale
`tls_fingerprint` pin on the `proxmox` credential went unnoticed and broke every call to it with `tls`.

Give the human a **Credentials** tab on the approval site where they can create, edit, rename and delete
credentials, with a form for the common fields, a diff before every write, and a raw-JSON fallback. Bitwarden
stays the store, but a human should rarely need to open it.

## Goals

- Edit everything in a credential's `broker` metadata from the approval site: `allowed_hosts` (with ports),
  `tls_fingerprint` (one or a list), `tls_verify`, `approval`, `vars`, `plans`, `standing`, `ws`, `name`, and keys
  the form does not know (preserved untouched, editable in an "advanced" JSON box).
- Create, rename and delete credentials (a credential is a vault item plus its metadata).
- One validator for every write: the same code the catalog loader runs (`Broker._entry`, `broker.py`). A form
  that accepts what the loader would reject, or the reverse, is a bug.
- Show a diff (old JSON, new JSON) before saving. Every change is one audit event.
- Fetch a server's certificate fingerprint from the page, so a pin is confirmed with the eyes, not copied by hand.

## Non-goals

- Reading or showing credential **values**. Values stay write-only: set through the existing value page
  (`request-credential`, `--replace`, issue #59). The editor may *start* that flow for a credential (a "Set value"
  button) but never displays a stored value.
- Any agent-reachable path. Agents cannot open, call or approve anything here.
- Replacing Bitwarden. Items edited there still work; the broker reloads them as it does now.
- Editing the broker's own config (`approve_*`, risk model, clients). Only credentials.

## Anti-goals (a failure even if it technically works)

- An agent, or anything holding only a client key, can change a credential's hosts, pin, approval mode or
  standing grants. That is the security boundary this broker exists for.
- The editor weakens a credential silently: a widened host list, a loosened TLS policy or a move to an
  always-allow approval mode that saves with no explicit human confirmation.
- Text from a request, an exception, the vault or an agent crosses into a page, log or audit event unescaped
  or unlabelled. Errors are fixed labels (`errclass`), never `str(exc)`.
- A save that races a Bitwarden edit and silently overwrites it.

## Constraints

- Human-only: the same authenticated approval session, CSRF token, Origin check and per-identity token as the
  Policies tab. Reuse `_tok(user)` and the POST gate at `broker.py` ~6721-6731; add the new paths to it.
- Writes go through the backend API that exists: `set_meta`, `edit_item(new_name, meta, drop_meta)`,
  `put(create=True)`, `delete`. A backend missing a capability (`set_meta`, `edit_item`) makes the matching
  controls absent with a visible reason, never a late failure (the existing rule for policy edits).
- Vault first, then the live catalog (`_persist_*` then update `cfg["secrets"][name]`), under `_cfg_lock`, as
  `set_ssh_hosts` does.
- Python `client/asb` is the CLI spec; this feature is the web UI, so no CLI text changes and no Rust port work.
- AGENTS.md rules apply: one shared place for shared rules, tests that can fail (positive controls, exact
  assertions, mutation of each security property), `docs/reference.md` updated in the same PR, no real secrets
  or hostnames in tests.

## Approaches considered

- **A. Structured form + JSON fallback (chosen).** Form for the common fields, diff before save, advanced box for
  the rest. Most code; the form must track new metadata keys (mitigated by the preserved-unknown-keys rule and
  the shared validator).
- **B. Raw JSON editor only.** Cheapest and never out of date, but keeps the pain that motivates the work.
- **C. Form only.** Cleanest, but leaves unrecognised keys editable only in Bitwarden.

The human chose A.

## Design

### Pages and routes (all human-session, CSRF + Origin checked)

| Route | Method | Purpose |
|---|---|---|
| `/credentials` | GET | List: name, item, hosts, approval mode, TLS summary (verified / pinned N / unverified), standing count. Search box. |
| `/credentials/<name>` | GET | Edit form, loaded from the live catalog entry's `_meta`. |
| `/credentials/<name>/preview` | POST | Validate the submitted form with the shared validator; return the diff and any `need_confirm` flags. Writes nothing. |
| `/credentials/<name>/save` | POST | Re-validate, re-check the preview token (below), write, audit. |
| `/credentials/new` | GET/POST | Create (name, kind, hosts, optional initial value via the value page). |
| `/credentials/<name>/rename` | POST | Rename the item and keep metadata. |
| `/credentials/<name>/delete` | POST | Typed-name confirmation, then `delete`. |
| `/credentials/fingerprint` | POST | Fetch a host's certificate fingerprint (below). |

### Form fields

`allowed_hosts` (list of `host` or `host:port`), `tls` (radio: verify normally / pin fingerprints / skip
verification) with a fingerprint list, `approval`, `vars` (name and field), `plans`, `standing` (read-only
summary with a link to the Policies tab, which already revokes it), `ws` and any unknown keys in the advanced
JSON box. The form builds a candidate `meta` dict; the advanced box, if edited, replaces the form's result for the
keys it contains and the preview shows exactly the merged JSON that will be written.

### One validator

Extract the validation inside `Broker._entry` into a function the editor calls with the candidate `meta`, and
have `_entry` call the same function. The editor shows the loader's own error label per field. No second copy
of the rules (host entry regex, `tls_verify` only for private hosts, a pin or `tls_verify=false` needing
private hosts, variable-name rules, ssh/ws constraints).

### Concurrency

The edit page carries a hash of the metadata it loaded (`old_sha256`, as the ssh_hosts audit does). Save re-reads
the item's current metadata from the vault (not the cache); if its hash differs, the save is refused with
"changed since you opened it" and the form re-renders with the new JSON and the user's pending edit. Nothing is
overwritten silently.

### Confirmations (widening needs a tick)

A save that adds an allowed host or port, removes a pin, sets `tls_verify=false`, adds a pin, or moves
`approval` toward always-allow returns `need_confirm` and requires the human to tick "I understand this widens
access". Narrowing changes save without it. The rule is one function so the card and the save agree. (`set_ssh_hosts`
is the model.)

### Fingerprint fetch

`/credentials/fingerprint` takes a `host[:port]` that is already in the credential's pending host list, connects
through `destguard` (allowed-host and port checks, no redirects, validated IP, private-range rules unchanged),
completes a TLS handshake **without** verification only to read the leaf certificate, and returns its sha256 and
its subject/issuer/expiry as escaped text. The human confirms it before it is added to the pin list. It is
rate-limited and writes an audit event (host hash, not name).

### Create, rename, delete

- Create: name (the `_NAME_RE` rule), host list, kind. A new item has no value until the human sets one
  through the existing value page; until then it is listed as "no value".
- Rename: `edit_item(new_name=...)`. Refused if the new name collides case-insensitively. Standing grants and
  plans reference the name; renaming drops them with a warning on the confirm step, because they are bound to
  the old name (they must not follow a name an attacker could re-register).
- Delete: typed-name confirm; refuses while a plan, session or standing grant references it, listing which.

### Audit events (counts and hashes only, never names, hosts or values)

`credentials_viewed` (the list), `credential_changed` (fields changed as a closed list of
labels, `old_sha256`, `new_sha256`, `widened` flag, user, peer), `credential_change_refused` (closed reason
labels: `invalid`, `needs_confirmation`, `conflict`, `unsupported`), `credential_created`, `credential_renamed`,
`credential_deleted`, `credential_fingerprint_fetched`.

## Staging (one PR each, one concern per PR)

1. List page and edit-metadata flow: shared validator, form, preview diff, confirmations, concurrency check,
   audit, docs, tests.
2. Create, rename, delete.
3. Fingerprint fetch.

## Testing (every security property has a test that fails when it is broken)

- Auth: unauthenticated, wrong CSRF, wrong Origin, an agent client key and a stale per-identity token are each
  refused with the exact status, and the credential's metadata is unchanged (positive control: the same request
  with valid auth saves).
- Validator parity: for a corpus of metadata dicts, `_entry` and the editor's validator accept and reject the
  same ones with the same label (catalog-loader and editor cannot drift).
- Widening needs the tick; narrowing does not; each widening type has its own case.
- Concurrency: an edit made in the vault between load and save is refused and not overwritten.
- No leakage: values, exception text and the submitted text never appear in the audit events, the error page
  or the logs (with a positive control that the events exist).
- Hidden Unicode and oversized input rejected as for guidance; scans stay linear.
- Backends without `set_meta` or `edit_item` show the controls disabled with the reason.
- `tools/mutation_check.py` entry not needed (no root helper); mutate the confirm and auth checks by hand and
  confirm the tests fail.

## Left to the builder

Visual layout and copy (follow the Policies tab's style), the exact diff rendering, how the list is paginated
for large catalogs, and the module split (suggest `secret_broker/crededitor.py` for form building and diffing,
with the handlers and `set_credential_meta` in `broker.py` next to `set_ssh_hosts`).
