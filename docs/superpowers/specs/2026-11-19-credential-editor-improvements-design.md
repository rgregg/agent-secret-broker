# Credential editor improvements: design note

Eight changes to the credential Settings page. This note records the calls made without the owner and what each
costs if wrong. Behavior lives in `docs/reference.md`; this is the why.

## Aliases (rename keeps the old name)

- An alias is another name for the same credential, in the credential's `broker` metadata (`aliases: [...]`).
  `Broker._entry` parses it (up to 10 names, the credential-name rule, not reserved, not the credential's own
  name, no repeats). `secret_broker/aliases.py` holds the pure rules.
- The catalog loader builds one `alias -> canonical` map. A name that is also a credential name always wins; an
  alias claimed by two credentials is dropped for both (fail closed, as duplicate credential names already are).
- `Broker.resolve_names` is the ONE place a requested name becomes a canonical name. `create()` calls it first
  (before plan/session routing, before every check), and plan submission calls it on manifest rules. After it,
  every check (deny lists, destination guard, policies, rules, grants, risk, internal-key check) sees only the
  canonical name. `plans.deny_secrets` is also matched against a credential's aliases, so a deny entry naming the
  old name still blocks.
- Using an alias works but is flagged: the request carries `aliases_used`, the card, the approval link page and the
  history details say "requested as OLD", the `requested` audit event records both names, and an `alias_used`
  event is written for the plan-call and session paths that build no card.
- Aliases are never in discovery, `/v1/status` or any agent-facing output (they only exist as an input to
  `resolve_names`). Guidance proposals do not resolve aliases (an alias there is an unknown credential).
- An alias never expires; the human removes it on the credential's page (audited `credential_alias_removed`).
- Creating a credential, or renaming to a name that is another credential's alias, is refused as "exists".

## Deleting a value from the vault

- New optional backend capability `delete_field` (`CAP_DELETE_FIELD`): `delete_field(item, field, meta=None)`
  removes a custom field (idempotent), clears a built-in `password`/`notes`/`username`, and accepts
  `previous_value` / `previous_replaced_at` (removing either removes both). `meta`, if given, is written in the
  same write.
- `remove_value` needs the capability and a `confirm`; otherwise it refuses with a fixed label and changes nothing
  (no fallback to the old metadata-only behavior).
- A variable with a `key` (structured field): only that key is dropped from the field text (the field and its
  other keys stay). A plain variable whose field another variable still uses: the field stays (`field_kept`), only
  the metadata changes. Otherwise the field is deleted.
- `previous_value` is ONE slot per item, not per field. Whenever a field is deleted or a key dropped, the previous
  slot is deleted too (it may hold the removed value). Cost: a remaining variable's rollback copy can be lost.
  When the field is kept, the previous slot is kept.
- "Another variable uses the field" is conservative: `auto`, `password`, `notes` and `private_key` count as the
  same slot (the item's kind decides which one `auto` means, and only the backend knows).

## Editor UI

- The value editor is one password input that shows `••••••` as the "unchanged" sentinel. The server treats a
  submitted value equal to the sentinel, or equal to the stored value, as "no change" (no write, no
  `previous_value`). Show fills the same input from the existing reveal reply; the value is never in the page
  source (the no-script reveal fallback is the one existing exception).
- Multi-line is a per-value toggle button (script only) that swaps the input for a textarea in place.
- TLS, Approval and WebSocket are `<details>` with a one-line summary. Inputs stay in the form, so save, review,
  `widened()` and the dirty flag are unchanged; a section whose fields differ from the stored metadata opens
  itself.
- Rename, Delete and Remove-value open native `<dialog>` pop-overs (focus moves in, Escape closes, focus returns,
  the page's nonce'd script drives them). Dialogs need script; the POST endpoints are unchanged. A refused action
  re-renders the page with that dialog open and its fixed message inside.
