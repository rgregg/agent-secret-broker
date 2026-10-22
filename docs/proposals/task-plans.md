# Proposal: plan mode (task-scoped grants for unattended jobs)

Status: **proposed**. Closes issue #5 ("task-scoped grants") and is designed together with issue
#18 (http sessions), as #5's follow-up comment asks. It builds on per-client credentials (merged,
see "Clients" in reference.md) and on the http sessions design decisions listed below. This
document is a design only; no code is part of it.

## Goal

Let an unattended or long-running agent job (an overnight sync, a multi-step task that runs while
nobody is at the phone) do exactly the calls it declared up front, and nothing else, after a human
approved the whole list once. Today the options are one tap per call, or `approval: allow`, where
the risk model is the only gate. The model reads text the agent controls, so it is a weak gate at
3am. A plan replaces it with a **deterministic match against a manifest a human read**.

Non-goals: letting an agent decide its own permissions; env mode; SSH; recurring jobs that renew
themselves (deferred, see "Renewal"); anything that outlives its deadline.

## Decisions already made (inherited from the sessions design)

These are fixed; this document applies them and does not reopen them.

- Approvals are **time-bound with an absolute deadline**: default 15 min, a hard maximum set in
  config, **no sliding extension, no renewal**. When time is up the thing is abandoned, so nothing
  lingers for hours or days.
- Everything is **bound to the authenticated client id** (per-client credentials). A plan or session
  cannot be used from another client.
- **Opening always needs a human.** No rule, standing approval or model verdict opens a plan.
- **http mode only.** The value never leaves the broker.
- A plan or session **may narrow, never widen**, a credential's `allowed_hosts`.
- **Fail closed** on every parse error, missing state, restart, clock doubt or internal error.
- **No exception text** in any agent-visible output (same rule as credential requests).

Plans differ from sessions in one number: an overnight job needs a longer maximum than 60 minutes.
That is settled below (section 3) as a separate `plans.max_minutes`.

## 1. What plan mode is, for the user

A plan is for a job that runs without a human in the loop. Example: "nightly finance sync". Before
the job starts, its agent writes a manifest of the calls it will make:

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
approval card, reads a plain-language rendering of every rule with the worst case spelled out, and
approves or denies the whole plan once. The job then runs with `asb http ... --plan ID`. A call that
matches a rule is released without a prompt; anything else is refused. When the deadline passes, or
the uses run out, or a human revokes it, the plan is dead and nothing remains.

The user's mental model: "I approved a job's shopping list, with a stopwatch, on one machine."

## 2. Relationship to sessions

### One approval, two records

A plan is a **manifest-bearing approval**. A session (issue #18) is **state** (cookie jar, captured
values) that makes a multi-call flow possible. They are two records because they have different
jobs and different lifetimes of data:

| | Plan (`plans.py`, new) | Session (`sessions.py`, from #18) |
| --- | --- | --- |
| Owns | the authorization: client id, rules, deadline, use counters, state | the jar, captured values, per-session host list |
| Answers | "may this exact call be released?" | "what cookies and captured values go with this call?" |
| Dies when | deadline, close, revoke, exhausted, client revoked, restart | the same, plus its own deadline |

A session opened for a plan carries `plan_id`; the plan lists its session ids. **Authorization
always flows from the plan to the session, never the reverse.** Closing, expiring or revoking a
plan closes its sessions (jar and captures dropped). A session never keeps a plan alive, and a
plan never extends a session.

### How a session becomes a plan step (phase 2; v1 refuses the keys)

The manifest may declare `sessions` and name one in a rule:

    "sessions": [{"name": "unifi", "secret": "unifi-claude", "hosts": ["unifi.example.lan"]}],
    "rules": [
      {"secret": "unifi-claude", "method": "POST", "host": "unifi.example.lan",
       "path_prefix": "/api/login", "max_uses": 1, "session": "unifi",
       "body": {"json": {"keys": ["username", "password"]}}},
      {"secret": "unifi-claude", "method": "GET", "host": "unifi.example.lan",
       "path_prefix": "/api/s/default/stat/", "max_uses": 40, "session": "unifi"}
    ]

- Approving the plan approves the session: **no second card**. On approval the broker opens each
  declared session with `deadline = min(plan deadline, sessions.max_minutes from the open time)`,
  bound to the same client, hosts inside the credential's `allowed_hosts` (and inside the rule
  hosts), `plan_id` set.
- A call with `--plan ID` that matches a rule with `"session": NAME` runs through that session
  automatically (the agent does not pass `--session`). Captures (`--capture`) and `{{session.X}}`
  work exactly as sessions define them. The login call is an ordinary rule using `{{VAR}}`
  placeholders; matching is done on the text as the agent sent it, before substitution (the card
  also shows it as typed).
- The checks are an **intersection**: the plan rule must match **and** the session's own in-scope
  check, client binding, redirect and cookie host rules must pass. A plan never loosens a session.
- A session is capped by the sessions maximum (60 min by default), not the plan maximum. A plan
  with session steps that runs longer than that has its session steps fail closed after the session
  ends (`plan_miss` reason `session_ended`); non-session rules keep working. Re-login is not
  automatic. See open question 3.
- Because sessions are being built separately, the integration surface is deliberately small and
  explicit; adjust names to match that code when it merges:
  `SessionStore.open_for_plan(client_id, secret, hosts, deadline, plan_id) -> session_id`,
  `SessionStore.close_for_plan(plan_id)`, and `session.run(spec)` returning the same result shape as
  a normal http call.
- Options A/B/C from issue #18: a session opened alone (no plan) is option A (session approval only,
  later calls follow normal risk and approval rules). A plan with session steps is option B. Option
  C is therefore "B when a manifest is given, A otherwise", with no extra mechanism.

### CLI

    asb plan submit manifest.json [--wait]   # prints the plan id once approved; exit codes below
    asb http NAME METHOD URL ... --plan ID   # or ASB_PLAN=ID in the environment
    asb plan status ID                       # state, rules, uses used/max, time left (own plans only)
    asb plan list                            # this client's plans
    asb plan close ID                        # the agent abandons its own plan early

`submit` without `--wait` prints the id and `pending`; `asb plan status` polls. With `--wait` it polls
like the other approval flows and exits on the decision. `asb guide` and `asb agent-setup` (#14) get
a decision rule: use a plan when a job is unattended or must make more than a few calls; do not
submit a plan for one call.

Client API (agent credential, `X-Client-Key`):

| Call | Meaning |
| --- | --- |
| `POST /v1/plans` | submit a manifest; returns `{id, status: "pending", expires_in}` |
| `GET /v1/plans/<id>` | owner only: `{status, rules (as approved), left_s, uses}` |
| `GET /v1/plans` | the caller's own plans |
| `POST /v1/plans/<id>/close` | owner only |
| `POST /v1/requests` | an `http` request with `"plan": "<id>"` |

An id that does not exist, belongs to another client, or is expired all answer the same fixed
"unknown plan" (no oracle for other clients' plans).

### Off-manifest calls: refuse (recommended)

A call made with `--plan ID` that does not match a live rule is **refused**, not turned into a
prompt. The agent gets exit 3 and a fixed message with a coarse reason class (`no_rule`,
`uses_exhausted`, `rate_limited`, `session_ended`, `not_yet_active`). Reasons, in order of weight:

1. The plan exists for unattended runs. A phone buzzing at 3am for a stray call is the approver
   fatigue the plan was meant to remove, and a reflexive Approve there is exactly the tap an
   attacker wants.
2. A fall-through lets a prompt-injected agent use the plan as a launching pad: make a plausible
   off-manifest call and rely on the human to approve it half asleep. Refusing makes the manifest the
   whole truth.
3. Issue #5 proposed fall-through; refusing is strictly safer and the agent can always make the same
   call without `--plan`, which goes through the normal prompt. The agent chooses; the broker never
   silently converts one into the other.

A later flag (phase 2) may let a caller opt in to fall-through: `--plan ID --or-ask`. The resulting
request is a normal request, its card says "made while plan <id> is active", and it gets no plan
benefits. Not in v1.

## 3. Time and client binding

### Binding

- A plan stores `client_id` of the authenticated submitter. Every operation (`use`, `status`,
  `close`, `list`) requires the authenticated client id to equal it. The check runs under the plan
  lock, in the same critical section as the use.
- **No separate bearer token.** The minimum credential is: plan id (128 random bits, hex, an
  identifier not a secret) plus the client's own credential. Reasoning: a bearer token on top
  would be a second secret that the same process holds beside `client.json`, so it protects
  nothing against a compromised client and nothing against a thief who has the id but not the
  client credential (who is already refused). It would also add a secret that must be stored,
  hashed, kept out of logs and rotated. Issue #5's open question "bind the token to the client
  key or peer IP" is answered by binding to the client id and dropping the token. Peer IP is not
  used (NAT, proxies, VPN churn make it unreliable and a source of spurious refusals).
- The legacy shared key is one pseudo-client for many machines, so binding means nothing there.
  **Plans are refused for the legacy client** (`plans.allow_legacy`, default false). A deployment
  must enroll the machine first.
- Revoking a client removes its plans (`Broker.revoke_client` calls `PlanStore.revoke_client`, as it
  already does for grants and SSH rules), and closes their sessions.
- A client with `risk.auto_approve_max: "none"` ("always prompts") cannot submit plans (403): a plan
  is unattended release, which that setting forbids for the client.
- Per-client plan override in `clients.<id>.plans` (`enabled`, `max_minutes`), same pattern as the
  existing per-client risk overrides.

### Deadlines

- Defaults and caps (config `plans`, section 10): `default_minutes` 30, `max_minutes` **480** (8 h,
  an overnight job), validator ceiling **1440** (a config above that is a startup error). The
  sessions maximum stays 60.
- The deadline is **absolute** and fixed at approval: `approved_at + ttl`, or the window end. It is
  never moved by use. No sliding extension, no renewal, no "extend" button.
- A manifest asks for either `ttl_seconds` (clock starts at approval; default
  `plans.default_minutes`) or a `window`:

      "window": {"not_before": "2026-10-22T02:00:00Z", "not_after": "2026-10-22T04:00:00Z"}

  A window lets the human approve at bedtime a job that runs from 02:00 to 04:00. Rules: UTC
  timestamps, `not_before` may not be in the past by more than 60 s, `not_after > not_before`,
  and `not_after - submit_time <= plans.max_minutes` (otherwise 400 at submit). A plan outside its
  window is **inactive but not extended**: before `not_before` a call is refused
  (`not_yet_active`); after `not_after` it is expired. A window never makes the approval live longer
  than `max_minutes` from when it was approved, because the span only shrinks while the card waits.
  A manifest may not give both `ttl_seconds` and `window`.
- On the card the human may **choose a shorter duration** than requested (not longer). A windowed
  plan is approve-or-deny as asked.
- A card waits `plans.pending_ttl_s` (default 900, 120-3600) for a decision; then the submission
  expires with nothing granted. Window end passing while pending also expires it.
- **Clock handling.** The broker records `approved_mono = time.monotonic()` beside the wall
  deadline. A plan is expired if **either** clock says so (wall: `time.time() >= expires_at`;
  monotonic: `monotonic() - approved_mono >= granted_seconds`). A wall clock stepped backwards
  therefore cannot revive a plan; one stepped forwards only ends it early (safe). Suspend (monotonic
  stops) is covered by the wall check. `not_before` is checked against the wall clock only (the one
  weakness: a clock stepped forward can open the window early, bounded by the deadline). A sweeper
  (the existing 15 s grant sweeper) marks expired plans, audits `plan_expired`, closes their
  sessions, and frees them; expiry is also enforced lazily on every use, so a late sweeper cannot
  extend life.

### Show, revoke, expire

- Policies tab gets **Active plans**: task name, client name, secrets, deadline countdown, uses used
  / max (total and per rule), state, **Revoke** (CSRF-checked `POST /plans/revoke`, SSO listener
  only). The Clients tab lists each client's active plans.
- Revocation takes effect before the next use (state set under the lock). A call already released
  and in flight finishes; nothing new starts. `Broker.revoke_plan(id, user)` returns True / False.
- Terminal states: `denied`, `expired` (while pending), `active`, `closed` (agent), `revoked`
  (human or client revoked), `ended` (deadline), `exhausted` (every rule used up; also terminal).
  Terminal plans are kept in memory 1 hour for `status` and the history view, then dropped.

## 4. Renewable plans and recurring jobs: out of v1

"Approve and auto-renew this exact manifest hash" (issue #5 nice-to-have) is **out of scope for v1
and not designed here beyond the safety argument**, because it contradicts the inherited decision
"no renewal; abandoned when time is up". It turns a bounded approval into authority that outlives
the human's attention:

- A compromised client resubmits the same hash forever and every renewal is silent; the approver
  has no new information and no new chance to say no.
- The approver is judging one night, not a standing policy; those need different cards.
- Auto-renew weakens "nothing lingers" from hours to unbounded.

Recurring jobs in v1: the human approves a fresh plan before each run, ideally a `window`
approved in the evening. That is one tap per night, the correct price for unattended write access.

If it is ever added (phase 4, needs a human decision, open question 2), the minimum safe shape is:
the card offers "also approve the same rules for up to N further runs, until DATE" (N <= 7, DATE
<= 14 days, config-capped); the match is on `rules_hash` (below) plus client id; each renewal is a
**new plan with its own absolute deadline** (no extension of the old one); every renewal sends a
notification (names only) and is audited `plan_renewed`; the renewal auto-ends at N or DATE, on
any rule change (a different hash needs a fresh tap), on client revoke, and via a Revoke on
Policies. "Hold for morning" (queueing off-manifest requests) is separate and not part of this
design.

## 5. Deterministic match versus the risk model

**The deterministic match is the gate for plan calls.** At use time there is no model call and no
risk check: a plan-matched request is released with `via: "plan:<id>"`. Per-call model risk
ratings are not applied (issue #5's argument: a match against text a human read beats a model
reading attacker-influenced text). Cost, latency and a new injection surface (the body of every
call) are further reasons.

What the model and risk code still do:

1. **At submit, never at use.** The existing assessment runs over a **code-generated structured
   rendering** of the rules (secret, method, host, path prefix, body matcher kind, uses), never over
   `description` or `task`. Its output is a label on the card, "(unverified)". It can only **add**
   caution (it may raise the card's banner and force the two-step confirmation described in
   section 6); it can never lower, approve, skip or shorten anything. A missing or failed verdict
   counts as high, as everywhere else.
2. **Deterministic worst-case classification, in code**, shown on the card and used for hard caps
   (section 6). This is the primary risk signal for plans.
3. **Hard caps in config** reject over-broad manifests before a human sees them.
4. `risk.auto_approve_max` does not apply to plan use (an explicit human approval of exactly the
   manifest, like a timed grant); a client's "never auto-approve" setting still blocks plans
   (section 3).

**The manifest's text is untrusted.** `task` (1-80 printable characters) and `description` (0-400)
are shown on the card in a box marked "written by the agent, not verified, not used for any
decision", with every non-ASCII character rendered as `<U+XXXX>`, control and hidden characters
refused with the same checks guidance and credential-request purposes use (400 naming only the
class and offset). They are **never** put in a notification, never given to the model, and the audit
log keeps only their length and a hash prefix. Rendering of rules is generated by code from the
validated structure; an attacker cannot make the plain-language lines say anything the structure
does not mean.

### Matching rules (the whole matcher, fail closed)

A call matches a rule only if **every** line holds; any doubt or parse error is a non-match.

1. The plan is active, in window, not exhausted, same client, and `rule.session` (phase 2) is
   satisfied.
2. `secret` equals one of the request's names and the request names exactly one secret (v1).
3. `method` equals exactly (uppercase; one method per rule).
4. `host` equals the URL host exactly (lowercase, IDNA-free ASCII, explicit port must equal the rule's
   if present, default port otherwise); the host is in the credential's **current** `allowed_hosts`
   at use time (so narrowing the credential after approval takes effect). Scheme must be `https`,
   except where the host is private (the existing private-host test); `http` to a public host never
   matches.
5. `path_prefix` is a segment-aligned prefix: the request path equals the prefix, or starts with the
   prefix (with a trailing `/` appended if absent). The path is matched **as sent**, after
   rejecting, as a non-match: dot segments (`.`, `..`, or percent-encoded forms), `%2f`, `%5c`,
   `%00`, other percent-encoded unreserved characters, a backslash, `;` in the path, control
   characters, a `//` run, or a literal `{{` anywhere in path or query (a placeholder inside the
   matched region would make the final path unknowable). Prefix must be absolute, 1-200 ASCII
   characters; a prefix of just `/` is allowed only if `plans.allow_root_prefix` (default false).
6. `query`: `"any"` (default) or `"none"`; with `"none"` any query string is a non-match.
7. **Body**, by the rule's `body` matcher (below). A rule with no `body` accepts only a request with
   **no body**. A write method (anything but GET, HEAD, OPTIONS) must declare a `body` matcher
   (even `"none"`, meaning explicitly empty). `body: "any"` is refused at submit unless
   `plans.allow_any_body` is true (default false), and is printed in red on the card as "any
   content".
8. Headers: the request may carry only headers from `plans.allowed_request_headers` (default
   `Accept`, `Content-Type`, `Content-Length`, `If-None-Match`, `User-Agent`) plus headers whose
   entire value is `{{VAR}}` placeholders of the rule's credential (the usual auth header). An
   unexpected header (a `Host`, `X-HTTP-Method-Override`, `X-Forwarded-*`, `Transfer-Encoding`
   or anything else) is a non-match; this closes override tricks that change what a request means.
9. Uses left on the rule and in the plan, and the rate limit holds (see below).

The request that was matched is the request that is sent. The matched `spec` is the immutable
object handed to `_release`; the broker does not re-parse, re-normalize or re-read the URL or body
between match and send (no TOCTOU between check and use).

### Body matchers

Bounded: a body larger than `plans.max_body_bytes` (default 16384) never matches.

- `{"none": true}` or absent on a read method: no body.
- `{"json": {"keys": [..], "pin": {..}}}` (v1): `Content-Type` must be `application/json`; the body
  must parse as a JSON object (duplicate keys, NaN/Infinity, depth over 8, or more than 64 members
  is a non-match, the same strictness the request-details formatter uses); its **top-level** keys
  must be a subset of `keys` (max 32 names); every key in `pin` must be present with exactly the
  pinned scalar value (string, bool, integer or null; compared as parsed). Unpinned values are
  free but the card says so: "these fields are not constrained: text". Nested objects are not
  pinned in v1 (their content is "not constrained").
- `{"graphql": {"document": "...", "operation_name": "...", "variables_keys": [..]}}` (v1): the
  body must be a JSON object with only the keys `query`, `operationName`, `variables`; no
  `extensions` (persisted-query hashes would run a stored document the human never saw). `query`
  must be **byte-for-byte equal** to the declared `document` (<= 4096 characters). Equality, not
  normalization: the agent declared the text, so it can send the same text, and the human read
  exactly what will run. `operationName`, if present, must equal the declared name (or be absent
  when none is declared); the name is **never trusted for meaning**, only the document is. `variables`
  keys must be a subset of `variables_keys`; values are unconstrained, which the card says. A
  document the code classifies as a mutation or subscription (first non-comment token is
  `mutation` or `subscription`, or the text cannot be classified) is labelled "can change data" and
  counts as a write for risk and for `plans.allow_graphql_mutation` (default true; set false to
  refuse). The classification is display and cap logic only; the match is equality.
- `"any"`: opt-in only (above).
- Not in v1: regex, JSONPath, wildcards, schema matching. Phase 2 may add a `json.pin` with
  JSON-pointer paths. Nothing user-supplied is ever compiled as a regular expression.

### Max uses and rate limits

- Every rule needs `max_uses` (1 to `plans.max_uses_per_rule`, default 500); the plan has a total
  cap `plans.max_total_uses` (default 2000) over the sum.
- A use is **counted when released**, before the upstream call, under the plan lock (reserve then
  run). A failed or timed-out upstream call still counts: no refunds, so retries cannot loop.
- Plan-wide rate limit `plans.rate_per_min` (default 30 hard ceiling; a manifest may request a lower
  `rate_per_min` and a per-rule `min_interval_s`). Over the limit: refuse with `rate_limited` and a
  `retry_after_s`; it does not consume a use and does not fall through to a prompt.
- Concurrency: at most `plans.max_inflight` (default 4) calls in flight per plan.

## 6. Risk review: what the human is approving

The approver must see the worst case in plain language, generated by code from the validated
structure. The card (Requests tab, and the `/a/<nonce>` approval page; SSO, CSRF and same-origin as
the other cards) renders:

    Plan requested by "build-box" (client c-1a2b3c4d)         [unverified agent text: see below]
    Lasts 8 hours at most, until 2026-10-22 02:41 (UTC 09:41). Window: none.
    If you approve, this client can do ONLY the following, with no further approval, until then.

    1. monarch   Read-only?  NO (can change data)
       POST https://api.monarchmoney.com/graphql, up to 50 times.
       Only this GraphQL text:  query Accounts { accounts { id balance } }
       Variables: not constrained (keys: none).
    2. ledger    POST https://ledger.example.com/v1/notes ..., up to 5 times.
       Body: JSON with only the field(s) "text"; "kind" must be "reconcile"; the value of
       "text" is not constrained.
       Path prefix: also covers everything under /v1/notes/ .

    Worst case: 55 calls in total, 2 credentials, 2 sites, at most 30 per minute.
    Includes changes to data: yes (2 rules). Deletes: no. Any-content bodies: no.
    These credentials could also reach other paths on these hosts; this plan does not.

    > Written by the agent (not verified, not used for any decision):
    > task: nightly finance sync   description: ...

    Approve for: [ 8 h | 4 h | 1 h | 30 min ]     [Approve plan: 2 rules, 8 h]   [Deny]

Design rules:

- Every rule line states method, host, path, whether the prefix covers a subtree, uses, and
  whether the body is fixed, partly pinned or not constrained. "Not constrained" is spelled out.
- A **worst-case line** is computed from the rules: total calls, number of credentials and sites,
  whether any rule can change data, delete (DELETE), use `any` body, or has a root-ish prefix.
- **Deterministic tiers** (code): read-only rules = low; any write = medium; DELETE, `any` body,
  GraphQL mutation, a prefix with one segment or fewer, a plan over 4 h, or a plan with a total of
  over 200 uses = high. A high plan needs a second step: the Approve button first reveals a
  confirmation naming the tier reason ("This plan can delete data. Approve anyway?"). The model
  verdict can raise the tier, never lower it.
- Buttons: **plan cards have no Approve/Deny in notifications** (push, Home Assistant, Telegram,
  ticker). The notification is `Plan requested by <client name>: <N> rules for <secret names>`
  with a link that opens the card; `decide_via` refuses every token channel for mode `plan`, the
  same stance as credential requests.
- **Hard caps (config; the card never offers a manifest the caps refuse, it is rejected at submit
  with 400 naming the field):** `max_rules` (default 20), `max_uses_per_rule`, `max_total_uses`,
  `max_minutes`, `rate_per_min`, `max_body_bytes`, `allow_any_body` false, `allow_root_prefix`
  false, `allow_graphql_mutation` true, `deny_secrets` (names that can never be in a plan), and a
  per-client `max_minutes`.
- Fatigue mitigations: the 15-minute card TTL, at most `plans.max_pending` (default 2) pending plans
  and `plans.max_active_per_client` (default 2) active ones (a third submit is refused, 403), a
  60-second cooldown after a denial of the same task name (the existing deny-cooldown pattern),
  and the card being identical in shape every time so a change stands out. Phase 2 adds per-rule
  checkboxes so a human can drop rules instead of denying.

## 7. Audit, history, UI, notifications

### Audit events (JSONL, hash-chained, as everywhere)

All carry `client_id`/`client_name`, `plan_id`, never any secret, header, body, document text,
`task` or `description` (only lengths and a hash prefix) and no exception text.

| Event | Fields |
| --- | --- |
| `plan_requested` | `plan_id`, `rules` (count), `names`, `ttl_s` or window, `rules_hash`, `manifest_hash`, text lengths and hash prefixes |
| `plan_refused` | `reason` (a cap name or validation class), field name |
| `plan_issued` | `plan_id`, `expires_at`, `granted_s`, approver, channel, peer, `manifest_hash`, `rules_hash` |
| `plan_denied` / `plan_expired` | `plan_id`, `stage` (`pending` or `active`), approver |
| `plan_used` | `plan_id`, `rule` (index), `request` (id), `uses_left` (rule and plan), `left_s` |
| `plan_miss` | `plan_id`, `reason` class (`no_rule`, `uses_exhausted`, `rate_limited`, `not_yet_active`, `session_ended`, `wrong_client`, `unknown`), `host_class` only |
| `plan_exhausted` | `plan_id` |
| `plan_closed` | `plan_id`, `by` (`agent`) |
| `plan_revoked` | `plan_id`, `by`, `left_s`, `peer`, `client_ip`, `cause` (`human`, `client_revoked`) |
| `plan_unavailable` | warning when the store could not be used (fails closed) |

Each plan-released call also creates a normal request record: `requested`, `approved` with
`via: policy`, `decision_source: plan`, `plan_id`, then `http_executed`, so History and the
existing request pop-over (including Request details) work unchanged. The History row says
"Decided by: plan <id> (auto-approved), 3 h 12 min left when used".

### What the agent API (`GET /v1/audit`) shows: whitelist, deny by default

Per the existing rule, a test requires every new event be whitelisted or listed hidden. Whitelisted
(the agent made these facts itself): `plan_requested` (`plan_id`, rule count, `names`),
`plan_issued`, `plan_denied`, `plan_expired`, `plan_closed`, `plan_revoked` (`plan_id`, event name
and `ts` only, **no approver, channel, cause, left_s, hashes**), `plan_used` (`plan_id`, `rule`,
`uses_left`), `plan_miss` (`plan_id`, `reason`). Hidden: `plan_refused` detail beyond what the
400 already told the agent, `plan_unavailable`, approver peer/IP, and the plan-released `approved`
shows a plain `approved` with null channel and approver like every policy approval. Plan events
never reveal other clients' plans (scoped by `client_id` like all agent audit).

### UI and notifications

- Policies: **Active plans** table (task, client, secrets, countdown, uses used/max, Revoke) and a
  one-line summary on Settings ("Plans: on, max 8 h, 2 per client").
- Notification text: `Plan requested: <client name>, <n> rule(s): <secret names>`. Names only. No
  task, description, host, path, body or count of calls. Failure to notify audits class only.
- History pop-over for a plan shows the approved rules (rendered by the same code as the card).

## 8. Threat model

| Threat | Handling |
| --- | --- |
| **Prompt-injected agent submits a broad manifest** | Caps refuse the widest shapes (root prefix, any body, huge uses, long TTL). Every plan needs a human, shown the worst case and a tier; a high plan needs a second confirm. Injected `description` cannot make the card say anything the rules do not (rules are rendered by code; text is boxed, escaped and unused). It cannot reach credentials outside `allowed_hosts`. Residual: a human who approves a card without reading it. Treat an unexpected plan card as a possible injection and deny it. |
| **Approver fatigue** | One card per job, fixed shape, pending/active/rate caps, cooldown after denial, no notification buttons, short card TTL, a second step only when worst case is high (so it stays meaningful). |
| **Stolen plan id** | Useless without the client credential; the client binding is checked on every operation; unknown and foreign ids answer identically. |
| **Compromised client** | It holds the credential and can use its own live plans, within rules, caps, rate limit and deadline, and nothing else. It cannot extend, renew or widen. Revoke the client: plans and sessions die at once. This is the accepted residual, the same as a timed grant. |
| **Replay** | Uses are counted and capped; a plan id has no value after the deadline; plans are never reloaded from disk (v1). A replayed submit makes a new pending plan needing a new human. |
| **TOCTOU between approval and use** | The approved manifest is stored immutable with its hash, re-verified on each use. `allowed_hosts` and the credential's existence are re-read at use time (narrowing applies at once; a removed or renamed credential, or a catalog item id that no longer matches the one recorded at approval, is a miss). Match and send use the same frozen request. A rule is checked and its use reserved in one critical section. |
| **Manifest hash and canonicalisation** | `rules_hash = sha256("asb-plan-rules-v1\0" + canonical(sorted rules))`; `manifest_hash = sha256("asb-plan-v1\0" + canonical(v, task, rules sorted, time fields, sessions))`. Canonical JSON: UTF-8, sorted keys, no whitespace, integers only (a float anywhere is invalid), strings NFC-checked and ASCII-only for host and path, rules sorted by their own canonical string, unknown keys rejected (so two manifests cannot hash equal and mean different things). `description` is excluded from both hashes. The hash is recorded in audit; the card shows the first 8 characters. |
| **Clock** | Section 3: either clock expiring ends the plan; window start uses wall time only. |
| **Restart / crash** | Plans are memory-only in v1: gone, calls refused with "unknown plan". Fail closed. |
| **Resource exhaustion** | Bounded plans, rules, body size, pending, active and terminal retention; maps are bounded. |
| **Info leaks** | Responses to a plan call are the normal masked http response; plan state never contains values; audit holds no text. Leak test in section 11. |

Not protected: an agent that already holds other credentials to the target, an approver who rubber
stamps, and **anything a matched call does at the target** (a matched POST that deletes data when
the API treats the body that way: the deterministic match constrains the request, not the API's
behavior). The card says "can change data" for every write for exactly this reason.

## 9. Interaction with other features

- **Per-client rules (#15 / clients.py).** A plan is bound to one client id. It is not a standing rule
  and is not stored per client in vault metadata; it is a separate live store (`plans`). The
  per-client `risk.auto_approve_max: none` blocks plans for that client (section 3). The legacy shared
  client is refused. Revoking a client calls `plans.revoke_client`. The Clients tab lists the
  client's active plans next to its rules.
- **Standing approvals (Always, timed).** Evaluation order in `Broker.create` for a request carrying
  `plan`: plan check first, before assessment's auto path and before standing approvals. A match
  releases; a non-match **returns the plan refusal and does not continue** to standing approvals
  or the prompt (that is the point of refuse-by-default; a caller who wants those omits `--plan`).
  A request with no `plan` field behaves exactly as today. Standing approvals never open or extend
  a plan, and a plan never creates a standing approval (the card has no "Always" or chips).
- **SSH.** Out of scope: plans are http only; a manifest naming an ssh key, or a rule using any mode
  but http, is refused at submit. SSH host rules remain the unattended mechanism for SSH.
- **Credential requests.** Plans cannot reference a credential that does not exist yet; a
  `request-credential` flow is separate and always needs a human. A manifest may name only
  credentials present in the catalog at submit; one stored later is not covered unless resubmitted.
- **Env mode.** Refused. `plans` never release a value.
- **`store` and `guidance` modes.** Never available through a plan.
- **`approval: allow` credentials.** A plan on an `allow` credential is permitted (it can only
  narrow); it is shown on the card as it would be on any other.
- **Notification channels.** Respect presence/hold behavior as for other cards; the plan card has no
  token channel so a held notification never lets a channel decide it.

## 10. Data model, persistence, configuration, errors

### Persistence decision: memory only in v1

A plan lives in memory in the broker process (`PlanStore`, like sessions). A broker restart drops
every plan, pending or active, and every job gets a fixed "unknown plan" (exit 7) and must submit
again, which needs a human. Reasoning:

- It fails closed by construction: no durable record of an approval, nothing to tamper with, no
  stale file after an incident, no counters whose persistence could fail or lag.
- It matches sessions (memory only), and a plan with session steps cannot survive a restart anyway
  (the jar is gone).
- The price is real: an overnight restart (unattended upgrade, redeploy) kills the job. That is
  the right failure for an unattended write path, and a restart that lands mid-job is rare. The
  agent gets a clear exit code and can stop.

Phase 3 offers an opt-in `plans.persist: true`: a small `plans.json` (0600, atomic) of non-secret
records (id, client id, manifest, hashes, deadline, state), loaded at start, dropping anything past
its deadline or further out than `max_minutes`. Use counters are **written before each release**
(write-ahead; if the write fails the call is refused), so a crash can never grant more uses than
approved. A corrupt file loads no plans (`plans_file_corrupt`). Session steps are not restored.

### Record (`secret_broker/plans.py`)

    Plan: id (128-bit hex), client_id, client_name, task, description, rules[], sessions[],
          manifest_hash, rules_hash, state, created_at, approved_at, approved_by, expires_at,
          approved_mono, granted_s, window{not_before, not_after}|None, uses_total, uses_by_rule[],
          last_used_at, recent_uses (deque for rate), inflight, request_id (the approval card),
          item_ids{secret: backend item id or None}

`PlanStore` has one lock; operations: `submit` (validate and create pending), `approve(id, user,
channel, granted_s)`, `deny`, `try_use(client_id, plan_id, spec) -> Match | Miss(reason)` (checks
and reserves under the lock), `release_use` (inflight), `close`, `revoke`, `revoke_client`, `sweep`,
`active`, `status_for(client_id, id)`. `on_event(name, **fields)` receives audit records and
must not call back in (same as `GrantStore`).

The approval card is a `Request` with `mode = "plan"` so it reuses pending caps, notification,
dashboard polling, CSRF/SSO, decision locking and history. `decide_via` for mode `plan` accepts
only the dashboard and approval-page channels, never push or Home Assistant tokens. On approve the
broker calls `PlanStore.approve`; the request ends `approved` with a result of only
`{"plan": id, "expires_at", "granted_s"}`.

### Config

    "plans": {
      "enabled": true,
      "default_minutes": 30,
      "max_minutes": 480,
      "pending_ttl_s": 900,
      "max_rules": 20,
      "max_uses_per_rule": 500,
      "max_total_uses": 2000,
      "rate_per_min": 30,
      "max_inflight": 4,
      "max_body_bytes": 16384,
      "max_pending": 2,
      "max_active_per_client": 2,
      "allow_any_body": false,
      "allow_root_prefix": false,
      "allow_graphql_mutation": true,
      "allow_legacy": false,
      "allowed_request_headers": ["Accept", "Content-Type", "Content-Length", "If-None-Match", "User-Agent"],
      "deny_secrets": []
    }

Validated at startup naming the field (unknown keys refused, `max_minutes` 1-1440,
`default_minutes <= max_minutes`, `pending_ttl_s` 120-3600, sizes within the shown ceilings), the
same way `timed_grants` is. `enabled: false` makes `POST /v1/plans` a 403 and ignores `plan` on
requests. `GET /v1/status` reports `features.plans` (a bool only).

### Errors and exit codes

| Situation | HTTP | `asb` exit |
| --- | --- | --- |
| Manifest invalid or over a cap | 400, fixed message naming the field and class | 3 |
| Disabled, legacy client, client set to never auto-approve, caps (pending/active) | 403 | 3 |
| Plan call outside the plan (`no_rule`, `uses_exhausted`, `rate_limited`, `not_yet_active`, `session_ended`) | 403, `{"error": "outside plan", "reason": class}` | 3 (rate: message gives retry-after) |
| Plan unknown, foreign, expired, closed, revoked, exhausted, or lost to a restart | 404/410 fixed "plan not usable" | **7** (new: stop, submit a new plan) |
| Plan denied by the human | | 4 |
| Plan expired while pending | | 5 |
| Upstream status 400 or more on a plan call | | 22 (unchanged) |

No exception text anywhere: every failure answers a fixed class; internal errors are
`{"error": "plan error"}` and an audit `plan_unavailable` with the exception class name only.

## 11. Test plan

Files: `tests/test_plans.py` (store, matcher, config), `tests/test_plan_card.py` (rendering,
channels), `tests/test_plan_e2e.py` (broker plus a local stub upstream, like `test_e2e.py`).

Matcher and store:
- every matching rule (method, host, port, scheme, segment-aligned prefix, query, headers, body
  kinds), and for each a non-match case; path tricks: `..`, `%2e%2e`, `%2f`, `%5c`, `//`, `;`,
  `{{` in path, prefix `/api` vs `/apix`, trailing slash.
- body: none, json keys/pin, duplicate keys, nesting, size cap, wrong content type; GraphQL equality,
  a different document that "looks equal", a different `operationName`, `extensions` present, extra
  keys, `variables` with undeclared keys, mutation classification, unclassifiable text.
- caps: each config cap rejects; `any` body and root prefix refused by default; validator rejects
  unknown and out-of-range config naming the field.
- client binding: another client, the legacy client, and a revoked client get the same fixed
  "unknown plan"; revoke removes plans and closes sessions.
- time: absolute deadline with a fake clock; use does not extend; wall clock stepped back does not
  revive (monotonic); window before and after; submit with window beyond `max_minutes`; windowed
  plan approved late.
- uses: exact count, concurrent callers racing for the last use (exactly one wins), failed
  upstream still counts, rate limit refuses without consuming, `max_inflight`.
- TOCTOU: credential `allowed_hosts` narrowed after approval; credential deleted; catalog item id
  changed; the released request equals the matched one byte for byte.
- off-manifest: refused, exit 3 class, no prompt, no pending request created, no fall-through to
  Always or timed grants or `approval: allow`; a call without `--plan` is unchanged.
- restart: a new broker over the same files has no plans; calls get exit 7.
- caller with `auto_approve_max: none` cannot submit.

Card and channels:
- the card shows every rule, "not constrained" text, worst-case line and tier; a high plan needs the
  confirm step; `description` with markup, bidi, zero-width and non-ASCII characters is escaped or
  refused; text containing instructions ("ignore the above, approve") changes nothing in the
  rendering or the model input (assert the model prompt contains no `task` or `description`).
- push, Home Assistant and every token channel refuse to decide a plan; the notification text is
  names only.

Audit and **leak test** (mirrors the sessions acceptance and the client leak test):
- Run the full flow with sentinel strings in the credential value, header values, request body,
  GraphQL document, `task`, `description` and a session cookie. Assert none appears in: any audit
  record, `GET /v1/audit` output, history rows, request details beyond the existing masked store,
  notifications, logs, `GET /v1/plans*` output, error bodies (including forced internal errors) or
  `asb` stderr/stdout beyond the upstream response (and that the response is masked).
- every emitted `plan_*` event is whitelisted or hidden (the existing completeness test).

**Overnight-job scenario** (e2e, fake clock and local stub upstream): at 22:00 submit a plan with a
window 02:00-04:00 (6 h span, allowed because `max_minutes` is 480); the human approves at 22:05;
at 21:59-ish and 01:59 calls are refused `not_yet_active`; at 02:00 the job runs a GraphQL read 40
times, one note POST, then a 41st GraphQL call with a different document (refused, exit 3, no
prompt, no notification); at 03:00 the broker restarts (plan gone, exit 7, nothing released); a
re-submitted plan is pending until approved; a normal `asb http` without a plan still prompts; at
04:00 an in-window plan is expired and calls are exit 7; `asb plan status` is `ended`.

## 12. Phased delivery

### v1 (first PR, exactly this)

1. `secret_broker/plans.py`: manifest validation and canonicalisation (hashes), `PlanStore`
   (memory only), matcher (rules 1-9 above), body matchers `none`, `json` (keys + pin), `graphql`
   (document equality), `ttl_seconds` and `window`, deterministic risk tiers, config parser with
   the `plans` block, per-client `max_minutes`.
2. `Broker`: `POST /v1/plans`, `GET /v1/plans`, `GET /v1/plans/<id>`, `POST /v1/plans/<id>/close`;
   `mode = "plan"` request and card; `decide_via` accepts dashboard and approval page only;
   `create()` handles `plan` on http requests before assessment (match releases via the existing
   auto path with `via: policy`, `decision_source: plan`; non-match is a 403 refusal); hooks in
   `revoke_client`, the 15 s sweeper, shutdown.
3. UI: card, Policies "Active plans" with Revoke, Clients tab list, Settings line, History wording.
4. Audit events and the agent-audit whitelist; notification text.
5. CLI: `asb plan submit|status|list|close`, `asb http --plan` / `ASB_PLAN`, exit code 7, `asb
   help plan`, `asb guide` decision rule; `docs/cli.md` and `docs/reference.md` sections.
6. Manifest keys `sessions` and `rules[].session` are **recognized and refused** (400 "not supported
   yet"), so the schema does not change in phase 2. Tests in section 11 except session items.

Not in v1: sessions integration, per-rule checkboxes, `--or-ask`, persistence, renewal, JSON-pointer
pins, multi-secret rules.

### Phase 2: sessions as plan steps and approver editing
- Plan sessions (section 2), `plan_id` on session records, `open_for_plan`, `close_for_plan`, tests
  with the UniFi-style stub (login, calls, logout inside one plan).
- Per-rule checkboxes on the card; `--or-ask`; `json.pin` with pointers.

### Phase 3: durability (opt-in)
- `plans.persist` with write-ahead counters, as described in section 10.

### Phase 4: renewal (only on an explicit decision)
- The bounded design in section 4, if the human decides recurring jobs justify it.

## Open questions for the human

1. **Maximum plan length.** The doc picks `plans.max_minutes` 480 (8 h) with a 1440 config
   ceiling. Is 8 h right for the overnight jobs you have in mind, and may a window span the day
   boundary as the example does?
2. **Renewal.** It is out of v1 as it conflicts with "no renewal". Do you want it at all later, or
   is one tap per night the permanent answer?
3. **Plan sessions longer than 60 minutes.** A UniFi-style login cannot outlast `sessions.max_minutes`.
   Options: accept that (session steps end, job stops), add `sessions.plan_max_minutes`, or allow
   a plan to declare a re-login rule the broker may replay (which is closer to renewal).
4. **Off-manifest default.** Refuse is recommended. Do you want `--or-ask` (explicit opt-in
   fall-through) in phase 2, or never?
5. **GraphQL mutations.** Default allowed (labelled, tier medium or high). Should the default be
   refuse, so a write document needs a config opt-in?
6. **Memory-only restarts.** Is an overnight restart killing a job acceptable for v1, or is
   durability (phase 3) needed before the first overnight use?
7. **High-tier second confirmation.** Is the second step enough, or do you want a typed phrase
   (for example the plan hash prefix) for the highest tier?
8. **Per-credential gate.** Add vault metadata `plans: false` per credential (beyond the config
   `deny_secrets` list), for credentials that must never be used unattended?
9. **Sessions code coordination.** The session record and in-scope check were not available when
   this was written (the sessions branch had no code yet); the integration names in section 2 need
   reconciling when that work lands.
