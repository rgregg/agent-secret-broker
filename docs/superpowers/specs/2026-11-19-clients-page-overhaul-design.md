# Clients page overhaul: design calls

Written before the code. Each call says what it costs if wrong. Items are numbered as in the request.

## 2. Email-shaped text (decided first; it touches every page)

Cause: an edge proxy (Cloudflare "Email Address Obfuscation") rewrites anything shaped like an email in HTML text, and
SSH identities (`user@host`, `account@server`) and SSO identities look like one.

Call: one small module, `secret_broker/emailsafe.py`.

- `text(s)` escapes `s` and, for each `@` between word characters, emits `<span>@</span>` and wraps the string in
  `<!--email_off-->...<!--/email_off-->` (the proxy's documented opt-out). The split `@` means no single text node
  matches an address even if the proxy ignores the comment. Visible text, selection, copy and screen-reader reading are
  unchanged (an inline span adds no whitespace and no role).
- `shield(page)` applies the same transformation to the text nodes of a finished page (never inside tags, attributes,
  `<script>`, `<style>`, `<textarea>`, `<title>` or comments). It runs in `_page` and the fragment responder, so a site
  nobody thought of (the signed-in user in the header, a future page) is covered. Explicit `text()` calls stay at the
  known identity sites so each fragment is correct on its own.
- Nothing depends on the proxy. Documented alternative: turn the feature off in Cloudflare (Scrape Shield, Email
  Address Obfuscation).
- Cost if wrong: markup only. `<textarea>`/`<title>` cannot hold markup, so they are skipped (none holds an identity).

## 6. Disabled state

`STATES = ("active", "disabled", "revoked")`.

- Door check: a disabled client's key still authenticates (so we know who asks) but `authenticate` returns reason
  `disabled` and the agent API answers every endpoint `403 {"error": "this client is disabled"}`: one fixed label.
  One chokepoint means standing approvals, rules, plans, sessions, enrollment and every mode are never evaluated for
  it (deny first). No notification is sent.
- Audit: `client_disabled_denied` (HIDDEN), at most one per client per 30 s window with a `suppressed` count.
- Disabling denies the client's pending requests (fixed reason, no deny cooldown) and ends its open sessions (a
  session is an approval; it must not outlive the switch). Rules and plans are KEPT and cannot be used; enabling
  restores whatever has not expired.
- Its name stays reserved, and it is not offered as a scope for new rules.
- Revoke is unchanged and works from active or disabled. Enable works only from disabled. The legacy shared key has
  no row state: `legacy_client_key: allow|deny` in config stays its only switch (the UI shows it; it cannot write
  config).
- Persistence: clients.json `"version": 2` (loader accepts missing/1/2). Old files load unchanged (new fields get
  defaults). An unknown state is still rejected (fail closed). Cost if wrong: rolling the broker BACK to a build
  without this feature after disabling a client fails closed (client list unreadable) until the file is fixed.
  Disable/enable take effect in memory first like revoke; a failed save is retried; a failed enable-save errs toward
  disabled after a restart.

## 7. Version tracking

- Neither CLI sent a version (`asb/1` was a protocol major). Both now send `asb/1.1` (`CLI_VERSION`); the broker
  parses `asb/<digits[.digits]{0,3}>` from `User-Agent` only. Anything else (other tools, no header) is "unknown" and
  never overwrites a version already recorded. Only digits and dots are stored, at most 24 characters.
- Recorded in memory on every authenticated request and persisted with the throttled stats write, now at most every 5
  minutes (it was 30 s, and the sweeper wrote every 10 s while dirty).
- Outdated means version < threshold. Threshold = `clients.min_version` in config if set (`"none"` turns the flag
  off), else the newest version this build knows (`LATEST_CLIENT_VERSION = "1.1"`). Numeric tuple comparison; unknown
  is shown as "unknown" and never flagged. Cost if wrong: informational only.

## 1, 3, 4, 5. The page

- Row: status icon, name, last seen, version (upgrade icon when due), rules count, icon buttons (details, rules,
  rename pencil, disable/enable, revoke X). The list is plain HTML and needs no JS.
- Per client up to three `<dialog class=dlg>`s with server-rendered content: info+rules (details, rules, per-rule
  revoke), rename, revoke (confirm). Buttons are `<a href=#id data-dlg=id>`: JS opens them modally (Escape closes,
  focus returns to the opener, no polling reload underneath: `A.busy` already watches `dialog[open]`); without JS the
  `:target` CSS shows the dialog in place, with a Close link.
- Rule revoke posts to the EXISTING endpoints (`/grants/revoke`, `/policies/ssh_rules/revoke`, `/plans/revoke`);
  their CSRF, same-origin and SSO checks are untouched. A `back=clients` field returns to the Clients tab.
- Icons are inline SVG with `role=img`, aria-label and title; icon controls are real `<button>`/`<a>` with a visible
  focus ring. Colours use the existing theme variables.
