# Proposal: plan mode (task-scoped grants for unattended jobs)

Status: **v1 implemented** (revision 3; see "Deviations in the v1 implementation" at the end). Closes issue #5 ("task-scoped grants") and is
designed together with issue #18 (http sessions), as #5's follow-up comment asks. It builds on
per-client credentials (merged, see "Clients" in reference.md) and on the http sessions design
decisions below. The v1 code is secret_broker/plans.py, secret_broker/planflow.py and small hooks in broker.py and client/asb.

## Goal

Let an unattended or long-running agent job (an overnight sync, a multi-step task that runs while
nobody is at the phone) make exactly the calls it declared up front, and nothing else, after a
human approved the whole list once. Today the options are one tap per call, or `approval: allow`,
where the risk model is the only gate. The model reads text the agent controls, so it is a weak
gate at 3am. A plan replaces it with a **deterministic match against a manifest a human read**.

Non-goals: letting an agent decide its own permissions; env mode; SSH; self-renewing recurring
jobs; anything that outlives its deadline.

## Decisions (final; this document applies them and does not reopen them)

Inherited from the sessions design:

- Approvals are **time-bound with an absolute deadline** (sessions: default 15 min, configurable
  hard maximum 60), **no sliding extension, no renewal**. When time is up the thing is abandoned.
- Everything is **bound to the authenticated client id** (per-client credentials). It cannot be
  used from another client.
- **Opening always needs a human.** **http mode only.** May **narrow, never widen**, a
  credential's `allowed_hosts`. **Fail closed.** **No exception text** in agent-visible output.

Decided for plans:

- Plan maximum `plans.max_minutes` default **480** (8 h); the validator ceiling is **720**.
  Default plan length 30 min.
- **v1 is ttl only.** A schedule `window` is phase 2, with absolute UTC timestamps; the card then
  shows local time and UTC, with the date.
- **No renewal** in v1 (and not planned).
- Plan-owned sessions (phase 2) end at `min(plan deadline, sessions.max_minutes)`; the card shows
  when a plan is longer than the session cap.
- **No `--or-ask`** in v1: an off-manifest call is refused, never turned into a prompt.
- GraphQL: v1 supports **read** documents by exact declared document only. A mutation document
  is allowed only when `plans.allow_graphql_mutation` is true (default **false**), and still only
  by exact declared document.
- A broker restart loses every plan (fail closed). Exit 7 carries a `kind` field so it can be told
  apart from normal expiry. Durability is phase 3.
- The second confirmation on the card is for DELETE, any-body, GraphQL mutation and a shallow path
  prefix. **Not** for duration. No typed phrase.
- Per-credential metadata `plans: false` is checked **at submit and at use**.

## 1. What plan mode is, for the user

A plan is for a job that runs without a human in the loop. Before the job starts its agent
writes a manifest of the calls it will make:

    {
      "v": 1,
      "task": "nightly finance sync",
      "description": "pull balances, post one reconciliation note",
      "ttl_seconds": 28800,
      "rules": [
        {"secret": "monarch", "method": "POST", "host": "api.monarchmoney.com",
         "path_prefix": "/graphql", "max_uses": 50,
         "body": {"graphql": {"document": "query Accounts { accounts { id balance } }",
                              "variables_keys": []}}},
        {"secret": "ledger", "method": "POST", "host": "ledger.example.com",
         "path_prefix": "/v1/notes", "max_uses": 5,
         "body": {"json": {"keys": ["text"], "pin": {"kind": "reconcile"}}}}
      ]
    }

`asb plan submit manifest.json` sends it. The human gets one notification (names only), opens the
approval card, reads a plain-language rendering of every rule with the worst case spelled out,
and approves or denies the whole plan once. The job then runs with `asb http ... --plan ID`. A
call that matches a rule is released without a prompt; anything else is refused. When the
deadline passes, the uses run out, or a human revokes it, the plan is dead and nothing remains.

Mental model: "I approved a job's shopping list, with a stopwatch, on one machine."

## 2. Relationship to sessions

### One approval, two records

A plan is a **manifest-bearing approval**. A session (issue #18) is **state** (cookie jar,
captured values) that makes a multi-call flow possible. Two records, because the jobs differ:

| | Plan (`plans.py`, new) | Session (`sessions.py`, from #18) |
| --- | --- | --- |
| Owns | the authorization: client id, rules, deadline, use counters, state | the jar, captured values, host list |
| Answers | "may this exact call be released?" | "what cookies and captured values go with it?" |
| Dies when | deadline, close, revoke, exhausted, client revoked, restart | the same, plus its own deadline |

A session opened for a plan carries `plan_id`. **Authorization flows from plan to session, never
the reverse.** Closing, expiring or revoking a plan closes its sessions. A session never keeps a
plan alive and a plan never extends a session.

### Sessions as plan steps: phase 2 (v1 refuses the keys)

Phase 2 lets the manifest declare `sessions` and name one in a rule (`"session": "unifi"`).
Approving the plan opens each declared session (no second card) with
`deadline = min(plan deadline, open time + sessions.max_minutes)`, the same client, hosts inside the
credential's `allowed_hosts` and the rule hosts, and `plan_id` set. A `--plan ID` call that matches a
session rule runs through that session automatically. The checks are an **intersection**: the plan
rule must match **and** the session's own in-scope check, client binding and cookie host rules must
pass. A plan never loosens a session.

- **Redirects.** Neither feature follows redirects: the shipped sessions (secret_broker/sessions.py,
  `run_http`) return a 3xx as it is (masked) and the agent makes a new in-scope, counted call, and plan
  calls do exactly the same (a 3xx comes back masked, `Set-Cookie` stripped, and a follow-up is a new call that
  needs its own matching rule). A plan session step therefore needs no special redirect rule.
- A plan longer than the session cap: session steps fail closed after the session ends
  (`plan_miss` reason `session_ended`), non-session rules keep working, and the card says so
  ("session steps end after 60 min; this plan lasts 8 h").
- Placeholders: v1 refuses `{{...}}` in URL and body (section 5). Phase 2 revisits this for
  `{{session.NAME}}` with value validation (sessions already restrict captured values).
- **Integration surface, matched to the real sessions code.** A session is `sessions.Session` (public id
  prefix `pid`, secret id kept only as `sha256`, `client`, credential, `hosts`, `methods`, `max_calls`, a
  cookie `Jar`, `expires` as a reading of the monotonic `broker.sessions_clock`, which is `clock.mono`);
  it lives in `SessionsMixin._sess` and ends through `_sess_end_locked(s, reason, now, actor)`.
  Phase 2 adds: (1) `SessionsMixin._session_open_for_plan(plan, name, rule)` building a `Session` from the plan's
  rule (same client, hosts inside the credential's `allowed_hosts` and the rule host, a deadline of
  `min(plan deadline, now + sessions.max_ttl_s)`, a `plan_id` attribute) without a second card, called from
  `_plan_activate`; (2) a `PlanStore` end hook (deadline, close, revoke, revoke_client, restart) that calls
  `_sess_end_locked(..., "plan_ended")` for every session carrying that `plan_id`; (3) in `_plan_call`, after
  `try_use` matches a rule that names a session, delegating to the session call path
  (`scope_problem`, `override_problem`, `run_http`) so the plan rule and the session's own scope check must
  **both** pass. Both features already share status `running` for in-flight calls, the clock module, the
  exit-code contract (7 ended, 8 refused by the approved scope; plans add 9 retry later) and the Clients tab.
- Options A/B/C of issue #18: a session alone is A; a plan with session steps is B; C follows.

### CLI

    asb plan submit manifest.json [--wait]   # prints the plan id once approved
    asb http NAME METHOD URL ... --plan ID   # or ASB_PLAN=ID
    asb plan status ID                       # state, rules, uses used/max, time left (own plans)
    asb plan list                            # this client's plans
    asb plan close ID                        # the agent abandons its own plan early

Client API (agent credential, `X-Client-Key`):

| Call | Meaning |
| --- | --- |
| `POST /v1/plans` | submit a manifest; returns `{id, status: "pending", expires_in}` |
| `GET /v1/plans/<id>` | owner only: `{status, rules (as approved), left_s, uses}` |
| `GET /v1/plans` | the caller's own plans |
| `POST /v1/plans/<id>/close` | owner only |
| `POST /v1/requests` | an `http` request with `"plan": "<id>"` |

`asb guide` and `asb agent-setup` (#14) get a decision rule: use a plan for an unattended job or
one with many calls; do not submit a plan for one call.

### Off-manifest calls: refused

A call made with `--plan ID` that does not match a live rule is **refused**, not turned into a
prompt. The agent gets a fixed message with a coarse reason class. Reasons: a prompt at 3am is the
approver fatigue the plan exists to remove; a fall-through lets an injected agent make a plausible
off-manifest call and rely on a half-asleep Approve; the agent can always make the same call
without `--plan`, which goes through the normal prompt. The broker never converts one into the
other.

## 3. Time and client binding

### Binding

- A plan stores `client_id` of the authenticated submitter. Every operation (`use`, `status`,
  `close`, `list`) requires the authenticated client id to equal it, checked under the plan lock,
  in the same critical section as the use.
- **The plan id is an identifier, never a bearer.** 128 random bits, hex, generated per plan, never
  reused after a restart (it is not derived from anything persistent) and never accepted as a
  credential for anything: it authorizes nothing without the client credential. **No separate plan
  token**: a bearer on top would be a second secret in the same process as `client.json`; it would
  protect nothing against a compromised client, nothing against a thief with only the id (already
  refused), and add storage, hashing, redaction and rotation. Issue #5's "bind to client key or
  peer IP" is answered by the client id; peer IP is not used (NAT, VPN churn, spurious refusals).
- The legacy shared key is one pseudo-client for many machines, so binding means nothing there:
  **plans are refused for the legacy client** (`plans.allow_legacy`, default false).
- Plans follow the **client id**. Revoking a client removes its plans and closes their sessions
  (`Broker.revoke_client` calls `PlanStore.revoke_client`). Revoke then re-enroll creates a new id
  (ids are random and never reused), so an old plan is dead and cannot be inherited.
- A client with `risk.auto_approve_max: "none"` cannot submit plans (403), and a plan owned by a
  client later set that way stops matching (`wrong_policy`, section 9).
- Per-client override `clients.<id>.plans` (`enabled`, `max_minutes`).

### Deadlines

- Config (section 10): `default_minutes` 30, `max_minutes` **480**, validator ceiling **720** (a
  config above 720 is a startup error). A manifest cannot ask for more than `max_minutes`
  (per-client override applies); more is a 400 at submit.
- v1 plans are **ttl only**: `"ttl_seconds"` (default `default_minutes`), clock starts at approval.
- The deadline is **absolute**, fixed at approval, never moved by use. No sliding extension,
  renewal or extend button. On the card the human may pick a **shorter** duration than requested,
  never longer.
- `expires_at = approved_at + granted_s` where `granted_s <= min(requested, max_minutes * 60)`.
  (Phase 2 windows: `expires_at = min(window.not_after, approved_at + granted_s)`, and `not_after`
  is also capped by `approved_at + max_minutes`, so a window can never outlive the maximum.)
- A card waits `plans.pending_ttl_s` (default 900) for a decision; then the submission expires and
  nothing is granted.
- **Clock handling.** Plans, standing grants and sessions share one `now()` / `mono()` pair
  (`secret_broker/clock.py`, injectable in tests; the existing `clock=` parameter of `GrantStore`
  is wired to it). A plan records `approved_mono`. It is expired if **either** clock says so: wall
  `now() >= expires_at` **or** `mono() - approved_mono >= granted_s`. A wall clock stepped back
  cannot revive a plan; one stepped forward only ends it early (safe); suspend (monotonic stops)
  is covered by the wall check. Expiry is enforced on every use and by the existing 15 s sweeper
  (which audits the end and closes sessions); a late sweeper cannot extend life. Phase 2
  `not_before` is wall-clock only; its weakness is documented: a clock stepped forward can open a
  window early, bounded by `expires_at`.

### Show, revoke, expire

- Policies tab: one **Active plans** table (task, client, secrets, countdown, uses used / max,
  state, **Revoke**). Revoke is `POST /plans/revoke`, SSO listener, CSRF and same-origin checked.
  The Clients tab lists each client's active plans.
- Revocation sets state under the lock before the next use. A call already released finishes;
  nothing new starts. `Broker.revoke_plan(id, user)` returns True / False.
- Terminal states: `denied`, `expired` (pending), `active`, `closed` (agent), `revoked`, `ended`
  (deadline), `exhausted`. Terminal plans stay in memory one hour for the owner's `status` and
  History, then are dropped.

## 4. Renewal and recurring jobs: out of scope

"Approve and auto-renew this exact manifest hash" (issue #5) contradicts the decision "no renewal;
abandoned when time is up". A compromised client could resubmit the same hash forever, every
renewal silent; the approver judges one night, not a standing policy; "nothing lingers" would
become unbounded. Recurring jobs in v1: the human approves a fresh plan before each run, one tap
per night, the correct price for unattended write access. If the human ever reverses this, the
minimum safe shape is a count- and date-capped renewal where each renewal is a new plan with its
own absolute deadline, notifies, and ends on any rule change or client revoke (phase 4, not
planned). "Hold for morning" is separate and not part of this design.

## 5. Deterministic match versus the risk model

**The deterministic match is the gate for plan calls.** At use time there is no model call and no
risk check: a matched request is released with `via: "plan:<id>"`.

**v1 has no model call on plans at all.** Risk on the card comes from deterministic,
code-generated tiers (section 6). A later phase may add a model label on the card; its input
would be **enumerated fields only** (secret name, method, host, path prefix, body-matcher kind,
uses, duration) and never `task`, `description` or any free text; it could only raise the tier,
never lower, approve or shorten. This removes the model as an injection surface and as a gate.

**The manifest's text is untrusted.** `task` (1-80 printable characters) and `description` (0-400)
are shown in a box marked "written by the agent, not verified, not used for any decision", every
non-ASCII character shown as `<U+XXXX>`, control and hidden characters refused with the same
checks credential-request purposes use (400 naming class and offset). They are never in a
notification, never given to a model, and the audit log keeps only length and a hash prefix. The
rule lines on the card are generated by code from the validated structure, so they cannot say
anything the structure does not mean.

### The matcher (whole thing, fail closed)

A call matches a rule only if **every** item holds. Any doubt or parse error is a non-match.

**A. One frozen request, built once.** The broker builds the final request it would send
(substituting `{{VAR}}` as in any http call) and the matcher runs on **that exact object**; the
matched object is the one handed to `_release` and sent (no re-parse, re-normalize or re-read
between match and send). Placeholders in v1:

- `{{...}}` in the URL (path, query, host), or in the body, is **refused** (non-match). There is no
  way for a substituted value to change the matched shape.
- In headers a placeholder is allowed only if it is one of the rule's **own credential's**
  variables and is the **entire** header value (optionally behind a scheme such as `Bearer `). The
  matcher validates that pre-substitution form, then matches on the substituted request with those
  header values treated as opaque.
- After substitution, any remaining `{{` anywhere in the request is a non-match.

**B. Host and URL.** Parse the URL once, with one parser (`urllib.parse.urlsplit`), and use only that
parse for matching and for sending. Non-match if: userinfo is present; a fragment is present; the
host has a trailing dot, any non-ASCII character or any uppercase character (checked **before**
comparing, no silent lowercasing); the host is an IP literal unless the rule's host is the same
literal. The host equals the rule host exactly; an explicit port equals the rule's (default port
otherwise). The rule host must be in the credential's `allowed_hosts` **at submit and again at
use** (narrowing after approval takes effect at once). Scheme must be `https`. Plain `http` matches
only when the host is a private **IP literal** (the `ipaddress` private/loopback/link-local test)
or when the credential metadata explicitly pins that host for plain http; note that the existing
`_private_host` helper also treats dotless, `.lan` and `.local` names as private, and plans do
**not** use that: DNS names are never "private" for plans. **Plan calls never follow redirects**:
the 3xx comes back masked and a follow-up is a new call that needs its own rule.

**C. Method.** Exact, uppercase, one method per rule.

**D. Path.** `path_prefix` is absolute, 1-200 ASCII characters, segment aligned: the request path
equals the prefix, or begins with the prefix plus `/`. Matched as sent. Non-match for: dot segments
(`.`, `..`, percent-encoded forms), `%2f`, `%5c`, `%00`, other percent-encoded unreserved
characters, backslash, `;`, control characters, a `//` run. **Percent-encoding is an allowlist**: only
`%20` may appear (no UTF-8 at all, so a normalizing upstream cannot read `%EF%BC%8F` as `/`); every
other encoded byte, including `%25` (which can double-decode upstream), `%2e`, `%2f`, `%5c`, `%00`, encoded
unreserved characters and lowercase hex, is a non-match. A prefix of only `/` needs `plans.allow_root_prefix`
(default false). **`query`**: a rule that writes defaults to `"none"` (any URL query string is a non-match)
and may instead list the allowed query key names (`["dry_run"]`, up to 16, values unconstrained; shown on the
card); a GraphQL rule must be `"none"`; read rules default to `"any"`. Keys must be plain (never
percent-encoded, no `;`) and method or body override parameters (`_method`, `method`, `operationName`,
`variables`, `extensions`, `x-http-method-override`, `body`) are always a non-match, so the URL cannot change
what a matching body means upstream.

**E. Headers.** The request may carry only `plans.allowed_request_headers` (default `Accept`,
`Content-Type`, `Content-Length`, `If-None-Match`, `User-Agent`) plus the placeholder headers of
(A). Anything else (`Host`, `X-HTTP-Method-Override`, `X-Forwarded-*`, `Transfer-Encoding`...) is a
non-match. `Content-Type`, when present, appears **exactly once**; chunked bodies are refused;
`Content-Length`, when present, must equal the actual body size.

**F. Body** by the rule's matcher (next). A rule with no `body` accepts only an empty body. A write
method (anything but GET, HEAD, OPTIONS) must declare a matcher (`"none"` meaning explicitly
empty). `"any"` is refused at submit unless `plans.allow_any_body` (default false) and is shown in
red as "any content". Body larger than `plans.max_body_bytes` (16384) never matches.

**G. Uses and limits** (below), the plan active, same client, and the credential still allowing
plans (`plans: false` and `deny_secrets` are re-checked here, and a per-client deny wins over a
plan, section 9).

### Body matchers (v1: `none`, `json`, `graphql`)

Common **strict JSON parse** (a non-match on any violation): duplicate keys at any depth;
non-finite numbers (NaN, Infinity); integers beyond 2^53; lone surrogates; a leading BOM; trailing
data after the value; nesting over 8 or more than 64 members per object. `Content-Type` must be
exactly `application/json`, optionally with `charset=utf-8`. String comparison is **byte-exact
after JSON decoding** (no normalization, no case folding).

- `{"none": true}`: empty body.
- `{"json": {"keys": [..], "pin": {..}}}`: body is a JSON **object**; top-level keys are a subset
  of `keys` (max 32); every `pin` key is present with exactly the pinned scalar (string, bool,
  integer, null). Unpinned values are free: the card says "not constrained", and **an unpinned
  value in a rule that writes raises the tier** (a free text field is arbitrary content). Nested
  values are never pinned in v1.
- `{"graphql": {"document": "...", "operation_name": "...", "variables_keys": [..]}}`: body is a
  JSON object with only `query`, `operationName`, `variables`. `query` is **byte-equal** to the
  declared `document` (<= 4096 characters; equality, so the human read exactly what runs). A JSON
  **array** (batch), `extensions` (including persisted-query hashes) or any other key is a
  non-match, stated explicitly. `operation_name` is **required whenever the document has more than
  one operation**, and `operationName` must equal it; the name is never trusted for meaning, only
  the document. `variables` keys are a subset of `variables_keys`; values are unconstrained and the
  card says so. **Classification:** a document that contains the token `mutation` or
  `subscription` anywhere (including inside strings or comments: conservative on purpose) or that
  cannot be parsed is a **write**; a document that classifies as neither is a **pure query**,
  read-only even though the method is POST. A write document is accepted at submit only if
  `plans.allow_graphql_mutation` is true (default **false**) and is then tier high. v1 therefore
  supports GraphQL reads by exact document, and mutations only by exact document with the opt-in.
- `"any"`: opt-in only (F).
- Not in v1: regex, JSONPath/pointer pins, wildcards, schema matching. Nothing user-supplied is
  ever compiled as a regular expression.

### Uses, rate and in-flight (precise)

- Every rule needs `max_uses` (1 to `plans.max_uses_per_rule`, default 500); the plan total is
  capped by `plans.max_total_uses` (default 2000).
- **A use is reserved under the plan lock when the match succeeds, before the upstream call.** A
  failed or timed-out upstream still counts: no refunds, so retries cannot loop.
- **Rate limit:** a sliding window of the last 60 s of **released** calls per plan, at most
  `plans.rate_per_min` (default 30, ceiling; v1 has no manifest-level rate and no
  `min_interval_s`). Over the limit: refuse with reason `rate_limited` and `retry_after_s` (seconds
  until the oldest recorded call leaves the window). **It does not consume a use and does not fall
  through to a prompt.**
- **In-flight:** at most `plans.max_inflight` (default 4) calls executing per plan; the counter is
  incremented at reservation and decremented in a `finally` block around the upstream call, so a
  failed, cancelled or crashed worker thread cannot leak a slot (the broker also reconciles the
  counter against live release threads on the 15 s sweep). Over the limit: refuse with reason
  `inflight_limit`; it does not consume a use. The check order is: state and client, rule match,
  rate, in-flight, then uses; a use is consumed only when all pass.

## 6. Risk review and the card

The approver sees the worst case in plain language, generated by code from the validated
structure. The card (Requests tab and `/a/<nonce>`; SSO, CSRF and same-origin like the other
cards) renders, for example:

    Plan requested by "build-box" (client c-1a2b3c4d)
    Lasts at most 8 hours, until 2026-10-22 02:41 local (2026-10-22 09:41 UTC).
    If you approve, this client can do ONLY the following, with no further approval, until then.

    1. monarch     READ-ONLY (pure GraphQL query)
       POST https://api.monarchmoney.com/graphql, up to 50 times.
       Only this GraphQL text:  query Accounts { accounts { id balance } }
       Variables: keys none; values not constrained.
       The path prefix /graphql also covers everything under /graphql/ .
    2. ledger      CAN CHANGE DATA
       POST https://ledger.example.com/v1/notes, up to 5 times.
       Body: JSON with only the field "text"; "kind" must be "reconcile".
       "text" is not constrained: it can contain any content.
       The path prefix /v1/notes also covers everything under /v1/notes/ .

    Worst case: 55 calls in total, 2 credentials, 2 sites, at most 30 per minute.
    Includes changes to data: yes (1 rule). Deletes: no. Any-content bodies: no.
    Credential "monarch" is allowed to reach: api.monarchmoney.com. Credential "ledger" is
    allowed to reach: ledger.example.com. This plan uses only the paths above.

    > Written by the agent (not verified, not used for any decision):
    > task: nightly finance sync   description: ...

    Approve for: [ 8 h | 4 h | 1 h | 30 min ]    [Approve plan: 2 rules, 8 h]    [Deny]

Card rules:

- Every rule line states method, host, path, that a path prefix covers a **subtree**, uses, and
  whether the body is fixed, partly pinned or not constrained ("not constrained" is spelled out).
- The card states, per credential, the **`allowed_hosts` surface** (what the credential could reach
  beyond this plan), and that a path prefix covers a subtree.
- Worst-case line: totals; whether any rule can change data, delete, use `any` body, or has a
  shallow prefix.
- **Deterministic tiers** (code, the only risk signal in v1): *read-only* rules (GET/HEAD/OPTIONS,
  or a POST whose GraphQL document is a pure query) = low; any rule that writes = medium; **high** =
  DELETE, `any` body, GraphQL mutation, or a **shallow prefix** (one path segment or fewer). An
  unpinned json value in a rule that writes keeps it at least medium and is printed on the card.
  **Duration and total uses are not tiers.** A high plan needs a **second confirmation**: the
  Approve button first reveals "This plan can <reason>. Approve anyway?". No typed phrase.
- **Notifications:** push, Home Assistant, Telegram and ticker carry no Approve/Deny; the text is
  `Plan requested: <client name>, <n> rule(s): <secret names>` with a link to the card. `decide_via`
  refuses every token channel for mode `plan` (the credential-request stance).
- **Hard caps** (config; a manifest over them is a 400 at submit naming the field): `max_rules`
  20, `max_uses_per_rule`, `max_total_uses`, `max_minutes`, `rate_per_min`, `max_body_bytes`,
  `allow_any_body` false, `allow_root_prefix` false, `allow_graphql_mutation` false, `deny_secrets`.
- **Fatigue mitigations:** 15-minute card TTL; `plans.max_pending` (2) pending and
  `plans.max_active_per_client` (2) active (excess: 429); 60 s cooldown after a denial of the same
  task name; the card has the same shape every time so a change stands out.

## 7. Audit, history, UI, notifications

v1 audit events (JSONL, hash-chained). All carry `client_id`/`client_name`, never a secret, header,
body, document text, `task` or `description` (only lengths and a hash prefix), never exception text.

| Event | Fields |
| --- | --- |
| `plan_issued` | `plan_id`, `rules` (count), `names`, `granted_s`, `expires_at`, approver, channel, peer, `manifest_hash`, `rules_hash` |
| `plan_closed` | `plan_id`, `cause` (`agent`, `deadline`, `exhausted`), `uses` |
| `plan_revoked` | `plan_id`, `by`, `left_s`, `peer`, `client_ip`, `cause` (`human`, `client_revoked`) |
| `plan_used` | `plan_id`, `rule` (index), `request` (id), `uses_left` (rule, plan), `left_s` |
| `plan_miss` | `plan_id`, `reason` class, `host_class` only; **coalesced** (below) |

Submit, deny and pending-expiry are recorded through the ordinary request events (`requested`,
`denied`, `expired`, `rejected`) for the `plan` mode request, so no extra event types are needed in
v1.

- **`plan_miss` coalescing:** at most **5 records per plan per minute** are written; further misses
  in that minute only increment a counter that is flushed as `suppressed: N` on the next written
  record (the same technique as `client_auth_failed`). A compromised client cannot flood the log.
  Misses with an unknown or foreign plan id are keyed to the caller's client id, with the same cap,
  and never name the foreign plan.
- Each plan-released call also creates a normal request record: `requested`, `approved` with
  `via: policy`, `decision_source: plan`, `plan_id`, then `http_executed`, so History and the Request
  details pop-over work unchanged. History: "Decided by: plan <id> (auto-approved), 3 h 12 min left".
- **Agent audit whitelist (deny by default; a test requires every new event to be listed):**
  `plan_issued`, `plan_closed`, `plan_revoked` (plan id, event, `ts` only: no approver, channel,
  cause, left_s, hashes), `plan_used` (`plan_id`, `rule`, `uses_left`), `plan_miss` (`plan_id`,
  `reason`). A plan-released `approved` shows a plain `approved` with null channel and approver.
  Scoped per client like all agent audit.
- UI: Policies "Active plans" table (one table, with Revoke), Clients tab list, a Settings line
  ("Plans: on, max 8 h, 2 per client"). Notification names only.

## 8. Threat model

| Threat | Handling |
| --- | --- |
| **Injected agent submits a broad manifest** | Caps refuse the widest shapes; every plan needs a human who sees the worst case and tier; high plans need a second confirm; `description` cannot change the rule lines (code-rendered), and is not an input to any model. It can never reach beyond `allowed_hosts`. Residual: a human who approves without reading. Treat an unexpected plan card as a possible injection and deny it. |
| **Approver fatigue** | One card per job, fixed shape, pending/active caps, cooldown, no notification buttons, a second step only when worst case is high (so it stays meaningful). |
| **Stolen plan id** | An identifier, not a bearer: useless without the client credential; unknown, foreign and expired ids all answer 404 identically. |
| **Compromised client** | Holds the credential; can use its own live plans within rules, caps, rate and deadline, nothing more; cannot extend, renew or widen. Revoke the client: plans die at once. Accepted residual, same as a timed grant. |
| **Replay** | Uses counted and capped; the id is worthless after the deadline; nothing reloads from disk in v1; a replayed submit is a new pending plan needing a new human. |
| **TOCTOU approval to use** | The approved manifest is immutable and re-hashed on use; `allowed_hosts`, `plans: false`, `deny_secrets`, per-client policy, credential existence and (when the backend supplies one) the item id recorded at approval are re-read at use; match and send use one frozen request. A rule is checked and its use reserved in one critical section. |
| **Manifest hash and canonicalisation** | `rules_hash = sha256("asb-plan-rules-v1\0" + canonical(sorted rules))`; `manifest_hash = sha256("asb-plan-v1\0" + canonical(v, task, sorted rules, ttl))`. Canonical JSON: UTF-8, sorted keys, no whitespace, integers only (floats invalid), ASCII-only host and path, unknown keys rejected, rules sorted by their own canonical string; `description` excluded. Recorded in audit; the card shows 8 characters. |
| **Clocks** | Section 3: wall OR monotonic expiry; shared `now()`. |
| **Restart** | v1 memory only: plans gone, calls refused. Fail closed. |
| **Resource exhaustion** | Bounded rules, bodies, pending, active, terminal retention, audit coalescing. |
| **Info leaks** | Plan state holds no values; responses are the normal masked http response; leak test (section 11). |

Not protected: an agent that already holds other credentials to the target; an approver who
rubber stamps; **what a matched call does at the target** (the match constrains the request, not
the API's behavior), which is why every write is labelled "can change data".

## 9. Interaction with other features

- **Per-client rules and ceilings (#15).** A plan is bound to one client id and is a separate live
  store, not vault metadata. **Never widen:** a rule is refused **at submit** if any of these
  forbid it: the client's per-client rules (`risk.auto_approve_max: "none"`, a client-level plans
  disable), `plans.deny_secrets`, the credential's `plans: false`, or the credential's approval
  policy (a credential that cannot be used in http mode, or an ssh key). **At use time a
  per-client deny wins over a plan** (`wrong_policy` miss), as do `deny_secrets` and `plans:
  false` set after approval. Reference docs will state plainly: **a plan makes a client
  effectively exempt from its own `auto_approve_max` for exactly the approved calls; that is the
  point**, and it is why the human approves each plan.
- **Per-credential `plans: false`.** New optional boolean in the credential's `broker` metadata
  (validated by the catalog loader like `auto_modes`; default true). Checked at submit and at use.
- **Standing approvals (Always, timed).** For a request with a `plan` field, the plan check runs
  first (before assessment's auto path). A match releases it; a non-match **returns the refusal and
  does not continue** to standing approvals or the prompt. A request without `plan` is exactly as
  today. Standing approvals never open or extend a plan, and a plan never creates one.
- **SSH.** Out of scope; a rule naming an ssh key or any non-http mode is refused at submit.
- **Credential requests.** A plan may name only credentials present at submit.
- **Env, `store`, `guidance`.** Never available through a plan.
- **`approval: allow` credentials.** Permitted (a plan can only narrow); shown like any other.

## 10. Data model, persistence, configuration, errors

### Persistence: memory only in v1

A plan lives in memory (`PlanStore`, like sessions). A restart drops every plan, pending or
active; calls get a 404 and exit 7 with `kind: "unknown"` and the job must submit again, which
needs a human. Reasoning: it fails closed by construction (no durable approval, no stale file after
an incident, no counters whose persistence could lag); it matches sessions (a jar cannot survive a
restart anyway); the cost is that an overnight restart kills the job, which is the right failure
for an unattended write path. Exit 7 carries `kind` so a script can tell the cases apart: `ended`
(deadline), `exhausted`, `closed`, `revoked` (owner only, from the retained terminal record) and
`unknown` (lost: broker restarted, or never existed, or not yours). A plan that should be live but
reports `unknown` means a restart. Phase 3 offers opt-in `plans.persist: true`: `plans.json`
(0600, atomic) of non-secret records, loaded at start, dropping anything past its deadline, with
use counters **written before each release** (write-ahead; a failed write refuses the call), a
corrupt file loading no plans.

### Record (`secret_broker/plans.py`)

    Plan: id, client_id, client_name, task, description, rules[], manifest_hash, rules_hash,
          state, created_at, approved_at, approved_by, expires_at, approved_mono, granted_s,
          uses_total, uses_by_rule[], recent (deque of release times), inflight,
          request_id (the card), item_ids{secret: backend item id or None}

`PlanStore` has one lock; operations: `submit`, `approve(id, user, channel, granted_s)`, `deny`,
`try_use(client_id, plan_id, frozen_spec) -> Match | Miss(reason, retry_after_s)` (all checks and the
reservation under the lock), `finish_use` (in-flight release, called from `finally`), `close`,
`revoke`, `revoke_client`, `sweep`, `active`, `status_for(client_id, id)`. `on_event(name, **fields)`
must not call back in. The approval card is a `Request` with `mode = "plan"` (reuses pending caps,
notification, dashboard polling, CSRF/SSO, decision locking, history); on approval the request
result is only `{"plan": id, "expires_at", "granted_s"}`.

### Config

    "plans": {
      "enabled": true, "default_minutes": 30, "max_minutes": 480, "pending_ttl_s": 900,
      "max_rules": 20, "max_uses_per_rule": 500, "max_total_uses": 2000,
      "rate_per_min": 30, "max_inflight": 4, "max_body_bytes": 16384,
      "max_pending": 2, "max_active_per_client": 2,
      "allow_any_body": false, "allow_root_prefix": false, "allow_graphql_mutation": false,
      "allow_legacy": false,
      "allowed_request_headers": ["Accept", "Content-Type", "Content-Length", "If-None-Match", "User-Agent"],
      "deny_secrets": []
    }

Validated at startup naming the field (unknown keys refused; `max_minutes` 1-720;
`default_minutes <= max_minutes`; `pending_ttl_s` 120-3600; sizes within ceilings), like
`timed_grants`. `enabled: false` makes `POST /v1/plans` a 403 and ignores `plan` on requests.
`GET /v1/status` reports `features.plans` (bool only).

### Errors and exit codes

Unknown, expired, closed and **wrong-client** plans are **always 404** with the same body shape
(no oracle); only the owner's retained terminal record gets a specific `kind`.

| Situation | HTTP | JSON | `asb` exit |
| --- | --- | --- | --- |
| Manifest invalid or over a cap | 400 | fixed message naming field and class | 3 |
| Disabled, legacy client, never-auto client, `plans: false`/`deny_secrets` | 403 | fixed | 3 |
| Submit over `max_pending` or `max_active_per_client` | **429** | `{"error": "too many plans"}` | 3 |
| Plan call outside the plan (`no_rule`, `uses_exhausted`, `session_ended`, `wrong_policy`) | 403 | `{"error": "outside plan", "reason": class}` | **8** |
| `rate_limited` | **429** | `{"error": "outside plan", "reason": "rate_limited", "retry_after_s": N}` | **9** |
| `inflight_limit` | **429** | `{"error": "outside plan", "reason": "inflight_limit", "retry_after_s": 1}` | **9** |
| Plan not usable (unknown, foreign, ended, closed, revoked, exhausted, lost to restart) | 404 | `{"error": "plan not usable", "kind": "ended"\|"exhausted"\|"closed"\|"revoked"\|"unknown"}` | **7** |
| Denied by the human | | | 4 |
| Expired while pending | | | 5 |
| Upstream status 400 or more | | | 22 (unchanged) |

Exit 9 means "slow down and retry"; `asb` prints `retry_after_s`. Exit 8 means "this call is outside the
approved plan" (never retry it as is). Exit 7 means "stop; submit a new plan". The numbers match the http
sessions design (7 ended, 8 out of scope). No exception text anywhere; internal errors are `{"error": "plan error"}` plus an audit
record with the exception class name only.

## 11. Test plan

Files: `tests/test_plans.py` (store, matcher, config), `tests/test_plan_card.py`,
`tests/test_plan_e2e.py` (broker plus a local stub upstream, like `test_e2e.py`).

Matcher and store:
- Each matcher item (A-G) with a matching and a non-matching case. Placeholders: `{{...}}` in URL
  path, query, host or body; a header placeholder of another credential's variable; a placeholder
  that is not the entire header value; a `{{` surviving substitution.
- Host: userinfo, fragment, trailing dot, uppercase, non-ASCII, IP literal vs rule host, port
  mismatch, host not in `allowed_hosts` at submit and (narrowed later) at use; plain http to a DNS
  name (`.lan`, dotless) refused, to a private IP literal accepted; **a 3xx from the stub is
  returned masked and never followed** (the stub records that no second request arrived).
- Path tricks: `..`, `%2e%2e`, `%2f`, `%5c`, `//`, `;`, `/api` vs `/apix`, trailing slash.
- JSON: duplicate keys at depth, NaN, integer 2^53+1, lone surrogate, BOM, trailing data,
  Content-Type variants, two Content-Type headers, Content-Length mismatch, chunked, size cap.
  GraphQL: byte-different but equivalent document, array batch, `extensions`/persisted query,
  extra keys, undeclared variable keys, multi-operation document without `operation_name`, the
  `mutation` token inside a string or comment (classified write), unparsable document, pure query
  over POST classified read-only, mutation refused unless `allow_graphql_mutation`.
- Caps and config validation (each cap; ceiling 720; unknown keys).
- Client binding: another client, the legacy client and a revoked client all get the same 404;
  revoke then re-enroll leaves the old plan dead; revoke removes plans.
- Time: absolute deadline with the shared fake clock; use does not extend; wall clock stepped back
  does not revive; pending expiry.
- Uses, rate, in-flight: exact count with concurrent callers racing for the last use (one wins);
  failed upstream still counts; rate and in-flight misses do not consume a use; the in-flight slot
  is freed when the worker raises or the thread dies; reasons and exit codes.
- TOCTOU: `allowed_hosts` narrowed, credential deleted, `plans: false` set, `deny_secrets`
  changed, per-client policy set to never-auto, catalog item id changed: all become misses; the
  sent request equals the matched one byte for byte.
- Off-manifest: refused, no prompt, no pending request, no fall-through to Always, timed grants or
  `approval: allow`; a call without `--plan` is unchanged.
- Restart: a new broker has no plans; calls get 404 and exit 7 `kind: unknown`.
- `plan_miss` flood: 1,000 misses write at most 5 records a minute plus a counter.
- The model is not called for plans (assert the summarizer is never invoked).

Card and channels: all rules rendered, "not constrained" text, `allowed_hosts` surface and subtree
note, tiers; second confirmation only for DELETE, any-body, mutation, shallow prefix (and **not**
for a long duration); `description` with markup, bidi, zero-width and non-ASCII is escaped or
refused; push, Home Assistant and every token channel refuse to decide a plan; notification text is
names only.

**Leak test** (mirrors sessions and the client leak test): run the full flow with sentinel strings
in the credential value, header values, request body, GraphQL document, `task` and `description`.
Assert none appears in any audit record, `GET /v1/audit`, history, notifications, logs,
`GET /v1/plans*`, error bodies (including forced internal errors) or `asb` output other than the
masked upstream response; and every emitted `plan_*` event is whitelisted or hidden.

**Overnight-job scenario** (e2e, fake clock, local stub): approve a plan for 6 h at 22:05; at 02:00
the job runs a GraphQL read 40 times and one note POST; a 41st call with a different document is
refused (exit 8, no prompt, no notification); the rate limit holds at a burst; at 03:00 the broker
restarts, calls get exit 7 `kind: unknown` and release nothing; a re-submitted plan stays pending
until approved; a plain `asb http` without a plan still prompts; at the deadline calls get exit 7
`kind: ended` and `asb plan status` is `ended`.

## 12. Phased delivery

### v1 (first PR) - exact deliverables

Scope: ttl only; body matchers `none`, `json` (key allowlist, scalar pins), `graphql` (exact
document, read by default); global rate ceiling only (no `min_interval_s`, no manifest-level
`rate_per_min`); one Active plans table with Revoke; audit events `plan_issued`, `plan_closed`,
`plan_revoked`, `plan_used`, `plan_miss` only; no model call; memory only.

1. `secret_broker/clock.py` (new): `now()`, `mono()`, injectable; wire `GrantStore` and the plan store
   to it.
2. `secret_broker/plans.py` (new): manifest validation and canonicalisation (hashes), the matcher
   (A-G), strict JSON parse, GraphQL classification, deterministic tiers, `PlanStore` (memory),
   config parser `parse_config` for `plans` (ceiling 720), per-client `plans` override.
3. `secret_broker/broker.py`: `POST /v1/plans`, `GET /v1/plans`, `GET /v1/plans/<id>`,
   `POST /v1/plans/<id>/close`; `mode = "plan"` request and card (dashboard and `/a/<nonce>`);
   `decide_via` accepts only those channels; `create()` handles `plan` on http requests first
   (build frozen request, `try_use`, release via the existing auto path with `via: policy`,
   `decision_source: plan`; miss returns the refusal; `finally` frees the in-flight slot); hooks in
   `revoke_client`, the 15 s sweeper, shutdown; catalog loader accepts the `plans` boolean metadata;
   Active plans table, Revoke route (`POST /plans/revoke`), Clients tab list, Settings line, History
   wording; no redirects on plan calls (reuse the existing `_NoRedirect` opener).
4. `secret_broker/audit_api.py`: whitelist entries for the five events; `notify.py`: names-only
   plan notification; `request_details.py`/`history.py` as needed for the wording.
5. `client/asb`: `asb plan submit|status|list|close`, `asb http --plan` / `ASB_PLAN`, exit codes 7
   and 8 with `kind` and `retry_after_s`, `asb help plan`, `asb guide` decision rule.
6. Docs: `docs/reference.md` (section "Plans", the `auto_approve_max` exemption note, audit table,
   config), `docs/cli.md` (commands, exit codes 7 and 8), `docs/proposals/task-plans.md` marked
   implemented with deviations.
7. Manifest keys `sessions`, `rules[].session` and `window` are **recognized and refused** with 400
   "not supported yet", so the schema does not change in phase 2.
8. Tests: section 11 minus window and session items.

### Phase 2: windows, sessions, approver editing, model label
- `window` (absolute UTC `not_before`/`not_after`; card shows local and UTC with the date;
  `expires_at = min(not_after, approved_at + granted)`, `not_after` capped by `approved_at +
  max_minutes`; `not_before` wall-clock only).
- Sessions as plan steps (section 2), with the card note when the plan outlives the session cap.
- Per-rule checkboxes on the card; JSON-pointer pins; manifest-level `rate_per_min` and
  `min_interval_s`; the optional model label (enumerated fields only, raise-only); extra audit
  events (`plan_requested`, `plan_exhausted`) if wanted.

### Phase 3: durability (opt-in)
- `plans.persist` with write-ahead counters (section 10).

### Phase 4: renewal (not planned)
- Only if the human reverses the "no renewal" decision (section 4).

## Open questions

All earlier open questions were decided (see "Decisions"). The last one is resolved:

1. **Sessions code coordination.** Resolved by the merge of the sessions work (see the integration surface in
   section 2); the phase-2 names above are the ones to build.

## Deviations in the v1 implementation

Everything above holds except the following, each decided while building it.

1. **Query string and percent-encoding** are stricter than first written (item D above): writes and GraphQL
   default to no query string; only `%20` may be percent-encoded (revised again in item 13).
2. **Rule keys `port` and `scheme`** were added (defaults 443 / `https`; `http` only for a private IP literal
   host), so a rule states exactly what it matches and a loopback stub can be used in tests. The credential
   metadata pin for plain http to a named host is **not** implemented: plain http is private IP literals only.
3. **`asb plan submit` waits for the human by default** and prints the plan id once approved; `--no-wait`
   prints the pending id; `--wait` is accepted as a no-op. `POST /v1/plans` takes `{"manifest": {...},
   "source": "user@host"}` and answers `{"id": <card request id>, "plan": <plan id>, "status", "expires_in"}`;
   the card is polled with `GET /v1/requests/<id>` whose approved result carries the plan id and is repeatable.
4. **`plans.enabled: false`** refuses plan calls (404 `kind: unknown`) instead of ignoring `plan` on a request,
   because ignoring it would turn the call into a prompt.
5. **`GET /v1/plans/<id>` and `asb plan status`** return rule summaries (URL, method, body kind, uses), never
   the task, description, GraphQL document, pins or keys, so those texts have no agent-readable channel.
6. **Item-id re-read** is implemented as a comparison of the credential's vault source (item, field, key of
   every variable) recorded at approval. The catalog is re-read within `CATALOG_TTL` (60 s); changes made
   through the broker's own policy pages apply immediately.
7. **`plan_miss`** carries `why` (the failed matcher item: `method`, `host`, `path`, `query`, `headers`,
   `placeholder`, `size`, `body`, `secret`, `request`) besides `reason`; a use of a plan that is not usable is
   audited as `unusable_<kind>`. The agent audit view shows only `plan_id` and `reason`.
8. **A shallow prefix is high for every rule**, read-only ones too (literal reading), so the example manifest
   in section 1 (`/graphql`) would show the second confirmation; use a deeper prefix to avoid it.
9. **Set-Cookie** is stripped from 3xx responses of plan calls (the doc's session rule, applied to plan calls
   in general).
10. **Per-client `plans.max_minutes`** replaces the global ceiling for that client (1-720); it can be higher
    than the global value.
11. `asb http --plan` sends the method uppercased (ASCII); a plan call's method is matched exactly as sent.
13. **Review hardening (revision 4).** (a) A plan-released call is never registered as a pending request: it
    is created `deciding` and registered only once settled, so it is not listed, counted against the shared
    pending cap, decidable or expirable while running. (b) The denial cooldown is keyed on the client id only
    and escalates 60 s / 5 min / 30 min, reset after a quiet day; `plans.max_pending_per_client` (1) and
    `plans.submits_per_hour` (6) were added; plan cards never use the shared pending cap. (c) The card's
    claimed source must match the plain claim pattern or the socket address is shown. (d) Every matcher
    pattern is a full match, control characters and whitespace are refused anywhere in the URL and matched
    strings, and the object handed to the sender is compared with the matched one. (e) The credential's vault
    source signature is recorded at submit and compared at approval and at use. (f) The refused-submission
    audit record is coalesced. (g) **Paths are ASCII and only `%20` may be percent-encoded** (supersedes the
    UTF-8 allowance in item D and deviation 1). (h) Exit codes follow the sessions contract: 7 ended (with
    `kind`), **8 outside the approved plan** (was 3), **9 retry later** (was 8).
12. Plan cards expire through the same request expiry; the plan record follows its card (denied, expired,
    failed all end it).
14. **Stacked on the shipped http sessions.** In-flight calls of both features use status `running` (no nonce,
    never listed, counted, decidable or expirable); both read time through `clock.py` (sessions keep their
    injectable `sessions_clock`, now `clock.mono`, and the monotonic deadline semantics); the Active plans
    table moved from the Policies tab to the Clients tab, above Active sessions; exit codes 7/8 are one
    contract (plans add 9); a plan call that also names a session is refused (phase 2).
15. **Sessions hardening shared (revision 5).** Plan calls use the sessions' header allowlist (exact names, the five
    Content-Types, charset utf-8, placeholder values only as `(Bearer |Basic |Token )?{{NAME}}` of the rule's
    credential), and the sessions' override-family scan over the URL tail, header names and values and the body,
    all on the template. A rule declaring a key, query key or path prefix that contains `method` is the only
    exception. `plans.allowed_request_headers` may only name headers from that list (and Content-Length).
