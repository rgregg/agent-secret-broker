# Auto-approve rules from the Policies tab

Status: draft for approval, 2026-11-18

## Intent and why

`auto_approve` rules (docs/reference.md, "Approving by configuration rule") let a job run with nobody there to
tap. Today they exist only in the broker's startup configuration (`BROKER_CONFIG`), so adding one means editing
the compose file on the host, redeploying, and restarting the broker (which drops in-flight approvals). The owner
did this twice in one session (an OpenRouter key and a Buttondown key for a newsletter job) and wants to do it
from the dashboard instead, the way SSH host rules (`ssh_rules`) already can be.

## Goals

- Add, list and revoke http and env auto-approve rules from the Policies tab, no restart, no redeploy.
- A UI rule survives redeploys and vault rebuilds (stored in the credential's vault metadata).
- A UI rule is validated and matched by the same code as a config rule, so the two cannot disagree.
- Same friction and trust level as SSH host rules: SSO identity, trusted peer, CSRF and same-origin checks, a
  confirmation tick, optional expiry. Whoever can use the Policies tab or edit the vault collection can add one.
- Everything is audited, with the channel recorded; use counts and last-used are visible.
- Config rules appear in the same table, read-only, so one screen shows everything that can approve unattended.

## Non-goals

- Rules that span several credentials (`secrets: [a, b]`): config only. A UI rule belongs to one credential.
- Editing or deleting config rules from the UI (they are read at startup; the table labels them "config").
- `ssh_sign` rules from this form (SSH host rules already have their own section and verified-host semantics).
- Any way for an agent to create, propose, widen or extend a rule. No `asb` command, no API an agent key can reach.
- Wildcards: no "any host", no "any command", as for config rules.

## Anti-goals (a failure even if it works)

- A rule the form accepts but the matcher reads differently, or the reverse.
- A UI rule that matches more than the card the human confirmed said.
- Any text from the form, a rule or an exception reaching an agent response, a notification or the audit log
  beyond fixed labels and the validated fields (docs/reference.md security invariants).

## Constraints

- Python 3.12 broker; `client/asb` is untouched (no CLI change), so no CLI text sync.
- Vault writes go through `backend.set_meta` (rate limited, can fail); the backend must report `set_meta` in
  `capabilities`, else the form refuses with the same message SSH rules use.
- Scans of agent text stay linear and read text the way the send will: matching reuses `autorules._http_ok` and
  `_env_ok` unchanged.
- Docs move with behavior: `docs/reference.md` (new subsection under auto_approve, audit event table, Policies tab).
- Tests follow AGENTS.md "Writing tests": each security property has a test shown to fail on the broken code, a
  positive control beside every negative assertion, exact status codes and reasons.

## Approaches considered

- **A. Vault item metadata, like `ssh_rules` (chosen).** Rules live in the credential's `broker` metadata (vault
  field `auto_rules`). Persists across redeploys and vault rebuilds, live without restart, reuses the SSH-rule
  patterns (persist, sweep, usage, Policies form). Costs: one credential per rule; each change is a rate-limited
  vault write that can fail (surfaced on the page); vault-collection editors can add rules without the UI (already
  true of `approval: allow`).
- **B. A broker-owned file (`auto_rules.json`) beside the audit log.** Allows multi-credential rules and avoids
  vault writes, but adds a second persistence mechanism and loses the rules if only the vault is restored.
- **C. The broker rewrites `BROKER_CONFIG`.** Rejected: needs write access to the host's compose file, which the
  design deliberately keeps out of the broker's reach.

The owner chose A.

## Design

### Storage and validation

Per credential, `broker` metadata field `auto_rules`: a list of objects.

    {"id": "3fa9c1d2", "name": "orca newsletter", "mode": "http",
     "host": "openrouter.ai", "scheme": "https", "methods": ["GET", "POST"], "path_prefix": "/api/v1",
     "clients": ["c-076918ad"], "by": "ryan", "at": "2026-11-18T16:00:00Z", "expires_at": null}

`env` rules carry `argv` instead of host/scheme/methods/path_prefix. The credential is implicit: the rule applies to
the credential it is stored on, so `secret`/`secrets` are rejected in this list.

`autorules.py` is refactored so one function validates a single rule object for both sources (config adds the
`secret`/`secrets` requirement; the metadata form adds `id`, `by`, `at`, `expires_at` and forbids `secret(s)`).
The catalog loader (`broker.py`, where `ssh_rules` is parsed) parses `auto_rules` the same way: a malformed list makes
that credential invalid and the message names the field (`auto_rules[1].host`), like `ssh_rules`. `auto_rules` is
refused on an ssh key credential. At most 50 rules per credential; names unique (case-insensitive) within the
credential. Unknown keys rejected.

### Matching

`Broker._config_rule_claim` becomes "rule claim": it first tries config rules, then, when the request names exactly
one credential, that credential's non-expired UI rules, through the same `autorules.find` machinery (a UI rule is
normalized to the same in-memory shape with `secrets = {credential}`). Config wins when both match. Expired rules
are ignored at match time. A client set to never auto-approve, `ssh_hosts`, allowed hosts and the destination guard
all still run before any rule, unchanged.

### Policies tab

A new section "Auto-approve rules" with one block per non-ssh credential that has rules or where the owner opens the
form. Table columns: name, mode, what it matches (host, methods, path, or argv), client name (resolved from id, or
"any client"), source (`config` or `UI`), created by/when, expires, last used, uses, Revoke (UI rules only).

"Add rule" form (per credential): name, mode (http | env), then host, scheme, methods (checkboxes: GET HEAD POST PUT
PATCH DELETE OPTIONS), path prefix; or argv (one word per line) for env; client (select of active enrolled clients,
and an explicit "any client" option), expiry (never | 30 | 90 days, same chips as SSH), and a required confirmation
tick whose text says plainly that matching requests are then released with no approval at any risk level.

### Endpoints

`POST /policies/auto_rules/add` (fields `secret`, `name`, `mode`, `host`, `scheme`, `methods` (repeated),
`path_prefix`, `argv`, `client`, `expires`, `confirm`) and `POST /policies/auto_rules/revoke` (`secret`, `rule`).
Both are guarded exactly like `/policies/ssh_rules/*` (SSO identity, trusted peer, CSRF token, same-origin) and are
added to the same path lists those use. Failures re-render the page with a fixed-label error and the form values
kept for the fields that are safe to echo (validated ones only), as the SSH form does.

### Lifecycle and audit

Expiry: ignored at match time, dropped lazily and by the existing 60 s sweeper (extended), audited once.
Use counts and last-used live in `auto_rules_state.json` beside the audit log (a generalization of `Usage`), not in
the vault. Events (hidden from the agent audit API): `auto_rule_created`, `auto_rule_revoked`, `auto_rule_expired`,
`auto_rule_refused` (with a fixed `reason`), `auto_rule_change_failed`, and the existing `auto_rule_used` gains
`source: config|ui` and `rule_id` for UI rules. The approval event keeps `via: policy` and `decision_source` becomes
`config_rule` or `ui_rule`. Request history reads `configuration rule "name"` or `Policies rule "name"`.

### Security properties to test

1. An agent key cannot reach either endpoint, and neither works without SSO identity, trusted peer, CSRF token and
   same-origin (each shown to fail when the check is removed).
2. No confirmation tick, a bad expiry, an unknown or revoked client, an ssh credential, a human-only mode, an
   over-long list, or a backend without `set_meta`: refused, nothing written, `auto_rule_refused` with the exact reason.
3. A UI rule approves exactly what an identical config rule approves, run over the existing `autorules` matcher
   test table for both sources (and the override-header, percent-escape, multipart cases still never match).
4. A UI rule on credential A never approves a request for A+B, or for B.
5. Expired and revoked rules do not match; an expired rule is audited once.
6. A malformed `auto_rules` in the vault makes the credential invalid with a field-naming message, and the rest of
   the catalog loads.
7. No form value, rule text or exception text appears in an agent response, notification or audit log; the page only
   echoes validated fields. Positive controls: the rule is in the table, the audit event exists.
8. Vault write failure: the rule is not active, the page says so, `auto_rule_change_failed` is audited.

### Docs

`docs/reference.md`: a subsection "Rules from the Policies tab" under auto_approve (storage, trust level, config vs
UI, expiry), the new events in the audit table, the Policies tab description. README table if it lists Policies
contents.

## Settled during review

- **"Any client"** is an empty `clients` list, exactly what `autorules._client_ok` does for config rules: any
  enrolled client, never the legacy shared key. The form stores `clients: []`; no matcher change.
- **A rule pinned to a client that is later revoked** simply stops matching (a revoked client cannot authenticate,
  and `_client_ok` compares ids). The table shows the client as "revoked" and the row stays until the owner revokes
  or it expires. No sweeper behaviour for this.
- **Vault writes** follow `SshRulesMixin._add_rule` / `_persist_ssh_rules`: under `_cfg_lock`, rebuild the metadata
  as `{**sc["_meta"], ...}`, write with `backend.set_meta`, update the in-memory entry; `auto_rules` and
  `ssh_rules` are different keys of the same metadata, and every writer holds `_cfg_lock`, so the sweeper's expiry
  drop and a form submit cannot interleave. A failed write leaves the in-memory rules unchanged.
- **Risk level:** config rules already ignore the risk ceiling and the secret's `approval` setting (reference.md);
  UI rules do the same, and the confirmation text says so.
- **Refusal reasons** are a closed set of fixed labels (`invalid`, `not_confirmed`, `not_eligible`, `cap`,
  `backend`, `duplicate_name`); a tampered mode (anything but `http`/`env`) is `invalid`. "Over-long" means the
  50-rule cap, 10 methods, 64 argv words, using the existing `autorules` limits.
- **Stale usage state:** `auto_rules_state.json` is pruned of ids that no longer exist when the catalog reloads;
  counts for a rule restored from a vault backup start from zero. Acceptable: counts are informational.
- **An invalid credential** (malformed `auto_rules`) is not shown in the table; the owner fixes it in the vault,
  as for `ssh_rules`.

## Left to the builder

- Exact HTML layout and wording of the section and form, within the Policies page's existing styles.
- Rule `id` generation and the per-credential name uniqueness message.
- How `Usage` is generalized (a second instance of the class with another file is fine).
- Whether the sweeper is one thread for both rule types.
- Test file organization (a new `tests/test_ui_auto_rules.py` plus additions to the existing autorules tests).
- Splitting into commits.
