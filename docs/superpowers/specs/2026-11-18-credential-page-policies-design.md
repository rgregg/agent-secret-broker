# Per-credential policies move into the credential page

Status: draft for approval, 2026-11-18

## Intent and why

The Policies tab stacks five unrelated sections (standing approvals, risk guidance, SSH host policy, SSH host
rules, auto-approve rules). With around 80 credentials the guidance, SSH and rule sections each render one collapsed
card per credential, so the tab is long, noisy and hard to scan, and the owner cannot answer the natural question
"what can approve requests for THIS credential without a tap, and what does the risk model know about it?" in one
place. The owner wants everything that belongs to one credential on that credential's page, the Policies tab kept only
for policies that span several credentials, and every place that names a credential to link to its page.

## Goals

- The credential page (`/credentials/NAME`) gets two sub-tabs, **Settings** and **Policies**. Settings is today's page
  (hosts, TLS, approval, WebSocket, values, advanced JSON, rename/delete). Policies holds, for that credential only:
  - **Standing approvals**: timed approvals and Always approvals whose secret set is exactly this credential, each
    with Revoke. (The legacy whole-credential `approval: allow` stays the Approval control on Settings; the Policies
    sub-tab shows it as a read-only line linking back to that control.)
  - **Auto-approve rules** (any credential that is not an SSH key): stored rules with Add and Revoke, config rules
    that cover this credential read-only, as built in PR #70.
  - **Risk guidance** for the decision model: the editor that is on the Policies tab today.
  - **SSH host policy** and **SSH host rules** (SSH key credentials only).
- Deep link: `/credentials/NAME?tab=policies` opens the Policies sub-tab; `/credentials/NAME` is Settings (unchanged).
- A summary strip at the top of Settings (visible without switching tabs): number of standing approvals, number of
  auto-approve rules, whether guidance is set, linking to the Policies sub-tab. The sub-tab label carries the count of
  standing approvals plus rules.
- The Credentials list shows the same small count per credential, so you can see which ones have standing policies.
- The **Policies tab stays** but shows only policies that cover more than one credential: timed approvals with two or
  more secrets, and config `auto_approve` rules whose `secrets` list has two or more names. It is always in the nav;
  when empty it says so and says where per-credential policies now live.
- **Deep links everywhere a credential is named**: request cards (dashboard and the `/a/NONCE` page), history rows and
  the request detail, standing approval rows, the Clients tab (per-client rules and plans), the remaining Policies tab,
  the credential request page, and the plans table. A name inside a policy context (standing approval, rule, guidance,
  plan) links to `?tab=policies`; everywhere else it links to Settings.
- All existing behavior, guards, audit events and refusals are unchanged: only where each control lives changes.

## Non-goals

- No new policy type, no change to what any policy does, matches or audits.
- Notifications (push, Telegram, ticker, Home Assistant) are not changed: they cannot carry links to this page.
- Plans stay on the Clients tab ("Active plans"): a plan belongs to a client and may name several credentials.
- No JavaScript framework or client-side tab switching: the sub-tabs are ordinary links to server-rendered pages.
- The Settings form's review step, confirmation ticks and whole-metadata concurrency hash are not touched.

## Anti-goals (a failure even if it works)

- A policy visible in neither place, or in both, after the move (a standing approval that disappears from the UI is a
  security regression: it still approves requests).
- A policy action applied to the wrong credential because one page now holds many forms.
- Folding policy actions into the Settings form so that a Save also adds a rule or a guidance change, or a policy
  change skipping the confirmation it has today.
- A link built from an unescaped name, or a link added for a name that the page did not already show.

## Constraints

- Follow AGENTS.md: security invariants, "Writing tests" rules (a test must be able to fail, positive controls, exact
  assertions), docs move with behavior, `client/asb` untouched, so no CLI text sync.
- Credential names are `[A-Za-z0-9_.-]{1,64}`; every href escapes the name (`html.escape` and URL quoting).
- The credential page stays on the Credentials tab (nav highlight, badge, SSO identity, trusted peer checks unchanged).
- Every POST that exists today keeps its guards (SSO identity, trusted peer, CSRF token, same-origin where it has it)
  and its status codes (400 refusal, 500 write failure) and fixed messages. Existing endpoint paths may be kept.
- Edit-page behaviors that exist today still hold: a read-only note when the vault backend cannot store metadata, a
  404 for an unknown or invalid credential, the concurrency conflict handling on Settings.
- A credential request page and approval cards that say "Revoke any time under Policies" are updated to say where the
  thing now lives, with a link where the page knows the credential.

## Approaches considered

- **A. One long credential page with a jump bar.** Everything stacked, anchors at the top. One scroll, nothing hidden,
  but the page grows long (SSH keys most of all) and the Settings form is buried under policy sections.
- **B. Two sub-tabs, Settings and Policies (chosen).** Each stays short; Policies is one click from anywhere through the
  deep link; plain server-rendered links, no script.
- **C. Fold the policies into the existing edit form** with one Save and Review. Rejected: policy actions take effect
  immediately with their own confirmation, audit event and concurrency rule; the edit form is a staged change guarded by
  a hash of the whole metadata. Merging them would weaken the confirmation each has today.

The owner chose B.

## Design (calls marked "my call" are the author's, not agreed)

### Which policy goes where

| Policy | Where | Rule |
|---|---|---|
| Timed approval (grant) | credential page, Policies sub-tab | its `secrets` is exactly `[this credential]` |
| Timed approval | Policies tab | two or more secrets |
| Always approval | credential page | always exactly one secret |
| Legacy `approval: allow` | credential page, Settings (control) and a read-only line on the Policies sub-tab | as today |
| Auto-approve rule, stored | credential page, Policies sub-tab | always one credential |
| Auto-approve rule, config | credential page for each credential it names; **also** the Policies tab when it names two or more | so a pair rule is visible from both credentials and in one roll-up |
| Risk guidance | credential page | per credential |
| SSH host policy and rules | credential page (SSH keys) | per key |
| Plans | Clients tab | unchanged |

(my call: a multi-secret config rule is shown on each credential it covers as well as on the Policies tab, marked
"covers several credentials", so neither view hides it.)

### Page structure

`/credentials/NAME` and `/credentials/NAME?tab=policies` render the same chrome (title, sub-tab links
`Settings | Policies (n)`, flash and error areas) and a body per tab. An unknown `tab` value is treated as Settings.
Each Policies section is its own card with its own independent forms (their own CSRF hidden field and a hidden
`secret` field naming the credential), never inside the Settings form. Sections that do not apply (SSH sections on a
non-SSH credential, auto-approve rules on an SSH key) are not rendered.

### POST handling

The per-credential POST endpoints keep their paths and guards (`/policies/guidance`, `/policies/ssh_hosts`,
`/policies/ssh_rules/add|revoke`, `/policies/auto_rules/add|revoke`, `/grants/revoke`); the response re-renders the
credential page's Policies sub-tab for that credential with the same note/error and status, instead of the Policies
tab (my call: keep the paths to avoid churning the CSRF tuple and the audit `path` values). `/grants/revoke` for a
multi-credential grant, and a revoke from the Policies tab, still return to the Policies tab: the form says where it
was submitted from (hidden `back` field, validated against a closed set: `policies` or a credential name that exists).

### Links

One helper builds a credential link (`cred_link(name, tab=None) -> str` of escaped HTML) and is the only place that
builds `/credentials/NAME` hrefs outside the credential routes. Names shown in lists of several names (`a, b`) become
several links. Where a name is shown inside a longer sentence or a table cell, only the name is the anchor.

### Copy

"Revoke any time under Policies" on approval cards and the credential request page becomes "Revoke any time on the
credential's Policies page" and links there when the page knows the credential. The rename/delete block message
("Revoke those on the Policies and Clients tabs first") says where each binding now lives. The Clients tab sentence
about rules "in full on the Policies tab" is updated.

### Docs

`docs/reference.md` (Policies tab descriptions, the SSH rules and auto-approve rules and guidance sections, the
Credentials editor description), `docs/setup.md` where it names the Policies tab, `README.md` tab list.

## Tests (what must hold)

1. **Placement:** a single-secret timed grant and an Always approval show on that credential's Policies sub-tab and
   not on the Policies tab; a two-secret timed grant shows on the Policies tab and on neither credential's sub-tab
   (positive control for each side); revoking from either place revokes it.
2. **Nothing lost:** the number of standing approvals, rules and guidance entries visible across the credential
   pages plus the Policies tab equals what `standing_rows()` and the rule lists hold (an invariant test over a catalog
   with single and multi-secret entries).
3. **Wrong-credential:** every per-credential POST acts only on the credential named in `secret`; a form for
   credential A cannot change B (existing refusals stay: unknown or ssh-only credential is 400).
4. **Guards unchanged:** the existing guard tests (identity, peer, CSRF, origin, agent key) are migrated to the new
   pages and keep their strength.
5. **Links:** a test renders the dashboard, a request card page, history list and detail, the standing rows, the
   Clients tab and the Policies tab for a catalog with hostile-looking but valid names, and asserts every displayed
   credential name is an anchor to the escaped `/credentials/NAME` (or `?tab=policies` in policy contexts), with a
   scan that must find at least one link on each page (cannot scan nothing).
6. **Sub-tab routing:** unknown `tab` falls back to Settings; the nav highlights Credentials; an SSH key shows the SSH
   sections and no auto-approve section, a non-SSH credential the reverse; a backend without `set_meta` shows the
   read-only notes.
7. **Existing tests** that parse the old Policies sections (`test_ssh_rules`, `test_ui_auto_rules`, guidance and
   standing tests) are moved to the new location without weakening their assertions.

## Settled during review

- **Placement predicate.** An entry goes on a credential's page only when its set of secret names (internal tags
  stripped, duplicates collapsed) is exactly one credential **that exists in the catalog**. Anything else stays on the
  Policies tab: two or more credentials, or a name that no longer exists (a timed approval made before a rename or
  delete, a config rule naming a missing credential). Orphans are marked "names a credential that no longer exists" and
  are not linked. Always and legacy entries come from existing catalog entries, so they always have a page. The broker's
  own internal key is an existing credential: its Policies page shows its entries, with the existing "cannot be changed
  here" note. (answered by the code and my call)
- **Counting "exactly one".** A client or scope restriction does not change which credential an entry belongs to
  (the client label is shown in the row). A config rule's `secrets` is always a non-empty set (the loader requires it),
  so there are no empty or wildcard rules. (answered by the code)
- **`back` field.** Only `/grants/revoke` takes it, because that one route is used from both the Policies tab and a
  credential page. Values: `policies` (the default) or a credential name; anything else, or a name that no longer
  exists, falls back to the Policies tab (never an error). Every other per-credential POST (`/policies/guidance`,
  `/policies/ssh_hosts`, `/policies/ssh_rules/*`, `/policies/auto_rules/*`), including when submitted from a Clients
  tab row, returns to that credential's Policies sub-tab. (my call)
- **Response URL.** POSTs keep rendering the result in the response, as today (the status codes and fixed error
  text need that); the sub-tab links on the rendered page are the real `?tab=policies` URLs. Redirect-after-POST is
  not introduced here. (my call; the same behavior as every policy form now)
- **Guidance.** "Set" means a non-empty stored guidance (the pill on the old card). The sub-tab label and the
  credentials-list count are standing approvals plus rules and exclude guidance. The Policies tab does not show
  guidance. The "nothing lost" invariant test counts standing approvals and rules; a separate test checks every
  credential's page has its guidance editor. (my call)
- **Links for names that do not resolve.** The link helper takes the set of existing, non-internal-only linkable
  names and renders any other name as plain escaped text. It never links a name that is not in the catalog. (my call)
- **Clients tab.** It keeps showing per-client rules and plans as today (a read-only summary with links); the revoke
  actions it already has keep working. Client-scoped standing entries appear on the credential page with their client
  label, and are not shown on the Policies tab unless they span credentials. (my call)

## Left to the builder

- HTML and CSS of the sub-tab strip, the summary strip and the section cards (reuse the existing styles).
- Where the shared code lives (a new module for the credential Policies body and the link helper is expected, to
  keep `broker.py` from growing).
- How POST responses carry the note and error state back to the credential page.
- Whether the Credentials list count is a column or a badge.
- Order of the sections within the Policies sub-tab (suggested: Standing approvals, Auto-approve rules, Risk
  guidance, SSH host policy, SSH host rules).
- Commit splitting and the migration order of tests.
