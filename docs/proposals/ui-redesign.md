# Proposal: approval site redesign (moss palette, one column, one-tap decisions)

Status: **stage 1 implemented**; stage 2 (the Secrets tab) not started.
Visual spec: the approved mockup boards (Requests light and dark, approval card, History, Settings,
desktop = same column). Stage 2 boards (Secrets, secret editor, value types) are not part of this stage.

## Problem

The approval site grew tab by tab. A request card shows a wall of text (risk sentence, from-lines, the
raw call, a note, a row of chips, a paragraph of explanation), the decision is two or three taps, the
Clients tab mixes machines with running sessions and plans, history is a dialog under the cards, and
desktop uses a wide layout the phone never sees. The owner decides from a phone, usually from a
notification, usually in a few seconds.

## Principles

1. **Mobile first, one column everywhere.** Desktop is the same column, centered, about 680 px wide.
   There is no two-pane layout for Requests.
2. **Glance, then decide.** A card answers in one look: how risky, which credential and machine, how
   long is left, and what is it doing in one or two sentences. Everything else is one tap deeper.
3. **One tap decides.** Deny, Approve once, and 5 / 15 / 30 minute approvals are single taps on the
   card. There is no choose-then-confirm step for these. `Always allow this...` is the one deliberate
   action: it stays a small link with its existing confirm.
4. **No explanation text where a label is clear.** Helper paragraphs are removed or moved behind a
   disclosure. Safety information is kept, not deleted.
5. **Status is never colour alone.** Risk and outcome are icon plus word plus colour.
6. **Untrusted text stays untrusted.** Agent-supplied text is escaped everywhere, labelled as
   unverified where it appears, and never styled as if the broker said it.
7. **Times are the viewer's.** The server sends UTC; the browser formats it.
8. **Security properties do not move.** CSRF token and identity header on every POST, same-origin
   checks, no exception text, no secret in any page, no external fonts, scripts or images.

## Information architecture

Tabs, left to right: **Requests | History | Policies | Settings**. (`Policies` occupies the slot that
becomes `Secrets` in stage 2.)

| Tab | Route | Contents |
|---|---|---|
| Requests | `/` | Cards that wait for a decision (requests, plan requests, session requests, pending machine enrollments, credential requests). Below them a `Running now` section: active sessions and plans with time left and Revoke. Nothing else. |
| History | `/history` | The history list: filter chips (All, Approved, Denied, Expired, Failed), search, grouping by day, tap a row for the detail card. Detail also at `/request/<id>`. |
| Policies | `/policies` | Existing content (standing approvals, guidance, SSH host rules, per-secret settings), re-skinned with the new tokens and components, not restructured. Replaced by Secrets in stage 2. |
| Settings | `/settings` | Notifications on this device; all push devices; default approval rules; Machines; Appearance; About; and a Troubleshooting disclosure holding the service worker status block. |

`/clients` (the Machines page: enrolled clients with rename and revoke) stays and is reached from
Settings > Machines. Pending enrollments stay as cards on Requests. `/?view=all` redirects to
`/history`; the fragment endpoints used by the page scripts keep working.

## Tokens

CSS custom properties on `:root`, light by default, dark under `prefers-color-scheme: dark`. The
Appearance setting writes `data-theme="light|dark"` on `<html>` (from `localStorage`, read by a tiny
head script, wrapped in try/catch; absent means match the system). Both themes are always present in
the stylesheet.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | #f3f6f1 | #0c140f | page |
| `--sf` | #ffffff | #141e17 | cards |
| `--tx` | #14201a | #e5efe8 | text |
| `--mu` | #53635a | #9db0a4 | secondary text |
| `--ln` | #dde6dd | #26342b | hairlines |
| `--bt` | #8fa396 | #4d6455 | button borders |
| `--ac` / `--ai` | #1f6b43 / #ffffff | #5fd08a / #06180e | primary, and text on it |
| `--lob` / `--lot` | #d3efdc / #14532d | #173826 / #8fe6b0 | LOW chip |
| `--mdb` / `--mdt` | #fdecc8 / #7a4a00 | #3a2f12 / #ffcf6d | MEDIUM chip |
| `--hib` / `--hit` | #fde1dd / #a1241a | #4a1d1a / #ffa79b | HIGH chip (red, never neutral) |
| `--okb` `--nob` `--exb` | green, dark, grey | green, light, grey | history circles |
| `--tb` | #e8efe8 | #1a2620 | timed buttons, segmented control |

The previous token names (`--card`, `--fg`, `--muted`, `--line`, `--accent`, `--ok`, `--warn`, `--bad`,
`--danger`, ...) remain as aliases of the new ones, so the modules that still style themselves with
them (plans, sessions, clients, guidance, SSH rules) take the new palette without a rewrite.

Type: the system UI font stack (no web fonts are loaded; the CSP forbids them) and the system
monospace stack for code, ids and calls. Spacing: 4 px steps; card radius 16 px; button radius 12 px.

## Components

- **Header**: the SB padlock logo (64 px asset shown at 30 px), the name, an online pill.
- **Tabs**: underlined, count badge on Requests.
- **Request card**: glance row (risk chip, credential and machine, time left), the description in
  large type, a one-line requested time plus risk reason, the one-tap rows, the `Always allow this...`
  link, then disclosure chips (Covers, Details, Why <LEVEL>, Request details).
- **Risk chip**: icon, word, colour: `&#9679; LOW` green, `&#9670; MEDIUM` amber, `&#9650; HIGH` red.
  `white-space: nowrap; flex: none`. Pills and chips never wrap or shrink.
- **Buttons**: Deny (pale red fill, red border and text; deep red fill, muted red border, salmon text in
  dark), Approve once (wide, primary), 5 / 15 / 30 min (tonal, single tap, reuse the timed-grant path).
- **Long values** (calls, URLs): one line with an ellipsis; the full text is in Details.
- **History row**: circle (approved filled green with a check, denied dark with a cross, expired grey with
  an ellipsis), the sentence, a status line (`Approved by you . 9:41 AM`), the risk chip.
- **History detail card**: mirrors the approval card: same header row, big sentence, an outcome band
  where the buttons were, the facts list, then disclosure chips (Timeline, Script, Request details).
- **Running now row**: credential, machine, time left, calls used, Revoke.
- **Segmented control**, **switch**, **chip**, **list row**: Settings and History.
- **Times**: `<time datetime="...Z">` with a text fallback; a small script formats with
  `Intl.DateTimeFormat` (time of day, `N min ago` where shown, the exact local date and time in the
  `title`). There is no timezone explanation text.

## Screens

Stage 1: Requests (light, dark), approval card, plan/session/enrollment/credential cards, Running now,
History (list, filters, search, detail card), Settings, Machines, Policies (re-skinned), link approval
pages (`/a/<nonce>`), request detail page, error pages.

Stage 2 (not in this change): Secrets tab (list, editor, new type, value types), replacing Policies.

## Stage 1 and what changes behind it

- Same endpoints, same form field names (`decision`, `id`, `csrf`, `rule_scope`, ...). The timed
  buttons post `decision=approve_grant_<minutes>` exactly as the old chips did; Always still posts
  `approve_always` from inside its confirm.
- Icons: `/icon-32.png`, `/icon-64.png`, `/icon-180.png`, `/icon-512.png` and the old
  `/apple-touch-icon.png`, served from the package with long cache headers, behind the same peer and
  identity check as every page. The head inlines the 32 px favicon and the 180 px touch icon as `data:`
  URIs and the header logo as a 64 px `data:` URI so the Content-Security-Policy is unchanged
  (`img-src data:`). The manifest lists the 512 and 180 icons.
- Content-Security-Policy: unchanged (`default-src 'none'`, nonce scripts, `connect-src 'self'`).
- Service worker version is bumped when the shell changes.
- Settings shows only what exists. The global auto-approve limit and the notification-presence rule are
  set in the broker config, so they are shown, not toggled. Description-model statistics are not in
  this base, so the Descriptions section is not shown.

## Deviations from the mockups (stage 1)

- Fonts: the system stack; Inter and JetBrains Mono are not loaded (the CSP forbids external fonts).
- The history detail card opens in the existing bottom-sheet dialog instead of expanding inside the list.
- A request card also shows the raw call as one truncated monospace line for http, env, ssh and store requests
  (the mockup shows it only in the detail view). Plans, sessions, proposals and credential forms keep their
  whole review on the card, because that review is the decision.
- `Whom a standing approval applies to` (this client / any client) is inside the Always confirm. The timed
  buttons and the SSH host rule apply to the requesting client only, which was the default before.
- The wording of what a timed approval covers is kept, behind a `Covers` chip.
- Settings: the push and notification controls stay buttons (turning them off needs flows that do not exist);
  `Skip the push while this page is open` and the auto-approve limit are shown, not toggled, because they are set
  in the broker config; `Clear the notification once I decide` and the Descriptions section are not in this
  base and are not shown; Machines shows a summary and a Manage link to the Machines page.
- Day headings in History are made by the page script in the viewer's timezone (no headings without scripts).
- The signed-in user is shown under About, not in the header.

## Accessibility

- Contrast: every text/background pair in both themes is at least 4.5:1 (the lowest pair, secondary text
  on the page background, is 5.8:1 light and 8.2:1 dark; chips are 6.1:1 or better).
- Touch targets: Deny, Approve once, the timed buttons, tabs, filter chips and Remove are at least 44 px
  high; the small `Always allow this...` link has a 44 px tall hit area.
- Focus: a 2 px accent focus ring on every interactive element (`:focus-visible`), never removed.
- Reduced motion: the only transitions are 120 ms colour changes; they are disabled under
  `prefers-reduced-motion`.
- Status is icon plus word plus colour. Icons are decorative (`aria-hidden`) and the word carries the
  meaning. Disclosures are native `<details>`.
- Zoom: sizes are in rem, the layout is a single column, nothing is fixed width.

## Not verified

No real browser or iOS device was available while writing this. The markup and scripts are covered by
HTTP-level tests and a node simulation of the time formatter; the look, the iOS home-screen behaviour
and the dark/light switch need a hands-on check.
