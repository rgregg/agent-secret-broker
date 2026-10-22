# Proposal: http sessions (cookie jar and captured values for multi-step API flows)

Status: **implemented** (issue #18; validated against a stub upstream only, see "Not covered"). See "Implementation notes and deviations" at the end.
Relates to issue #5 (task-scoped grants), #15 (per-client credentials) and #14 (agent setup).

## Problem

`asb http` is one stateless call per approval. A multi-step API flow (log in and reuse a session
cookie, carry a CSRF token from one response into the next call, page, poll, chain several calls
for one purpose) cannot be done with it, so agents write a script and use env mode, which hands the
raw secret to a program on the agent's machine (masking is best effort).

Audit evidence from issue #18 (2026-10-15 to 2026-10-22): 114 `http` requests against 107 `env`
requests; since Oct 17 env is about half or more of the daily total. The env requests run `bash`
(69) and `python`/`python3` (26); none are plain `curl`. Several credentials are env-only:
`unifi-claude` 35 env / 0 http, `openrouter` 11 / 0, `condo-control` 11 / 0, `home-assistant`
11 / 7. The likely cause is the stateless call. This proposal makes the safe mode able to do what
the scripts do.

## Goals

- A login-then-calls flow (the UniFi shape: POST a login that sets a cookie and returns a CSRF
  header, then GET/POST/PUT with both, then log out) runs entirely with `asb http --session`.
- The credential, cookies and captured values never reach the agent, the audit log, history,
  request details, logs, notifications or pages.
- One human approval covers a bounded unit of work, and the human sees exactly what they approve:
  credential, hosts, methods, time limit, call cap.
- A session can only narrow what its credential allows.

## Non-goals

- Env mode, ssh keys and non-http credentials. Sessions are http only.
- Persistence: sessions are memory only; a broker restart drops all of them.
- Renewal, extension, idle refresh or any way for activity to move the deadline.
- Path or body matching (see "Extension points" for where plan-mode grants add it).
- Batch/sequence requests and per-credential `modes` (listed in the issue as related ideas).
- Modeling real UniFi quirks (see "Not covered").

## The two rules that shape everything

### Time-bound: absolute expiry, abandoned at the deadline

The deadline is fixed when the human approves: `expires = approved_at + ttl`. Default ttl 15
minutes, hard maximum configurable (default 60). There is no sliding extension, no renewal and no
idle refresh: no code path writes `expires` after creation, and use does not touch it. At the
deadline the session is **abandoned**: jar and captured values are dropped from memory, the record
is marked expired (kept as a small tombstone: id hash, client id, reason), every further call with
that id fails with a clear error and a dedicated exit code, and `session_expired` is audited. A
sweeper ends expired sessions even when nobody calls, and a lookup also ends an overdue session
itself, so the deadline holds even if the sweeper is late. A session that is never used still
expires. The remaining time is shown on the approval card (the limit that will start at approval)
and on the active-sessions list (live countdown).

Why: a session is a standing permission. The only safe standing permission is one that ends on its
own at a time the human chose and that nothing the agent does can move. If more time is needed, the
agent must ask again and a human decides again. Renewal would turn a 15 minute approval into an
open-ended one for any agent that keeps calling (including a prompt-injected one).

### Client-bound

A session is bound at open time to the authenticated client id (per-client credentials, #15).
Any call from a different client, including the legacy shared key when the session belongs to an
enrolled client, gets exactly the answer an unknown id gets: no oracle on whether an id exists.
The legacy shared key counts as one client (`legacy`): it cannot tell machines apart, so two
machines sharing it share each other's sessions. Enrolling each machine removes that.
Session ids are 192 bits from `secrets.token_urlsafe(24)`, looked up by their SHA-256 and compared
in constant time. Revoking a client (#15) ends all its sessions immediately.

Why: the id is a bearer reference. Binding it to the authenticated client means a leaked id (log,
chat paste, another process) is useless to anything that does not also hold that client's key.

## Approval model

The issue offered A (approve the session; later calls follow normal risk and approval rules),
B (the session is a grant with a manifest; matching calls release without prompt, others fall
through to a prompt) and C (both).

Chosen: **B, with a fixed manifest and no fall-through**. The open request carries the manifest
(credential, hosts, methods, ttl, max calls). Matching calls are released without a prompt and
without a model verdict. Calls outside the manifest are **refused with a specific error, never
prompted**.

- A was rejected: it would still prompt for each write, which is the stateless problem again, and
  it would let the model's verdict on attacker-influenced text decide releases.
- C was rejected: a prompt fall-through lets an injected agent turn a session into a stream of
  prompts that train the human to tap. Refusing is deterministic: the agent opens a new session,
  which a human reads in full.
- The deviation from #5's grants is that a session has no path/body rules in v1; its manifest is
  hosts (with ports) + methods + cap. The shape is chosen so #5 can add rules (see below).

Opening always needs a human: always HIGH by code (no model call), never auto-approved (policy
`allow`, Always, timed grants, SSH rules cannot apply), no Always/timed chips, no notification
button, token or hook decision (same as credential requests and enrollment). Only the
authenticated approval site decides. The approver may shorten the time limit and call cap but not
lengthen them beyond the requested value or the configured maximum.

What the human is approving, stated on the card: this client may make the listed calls with this
credential to these hosts, with these methods (non-GET/HEAD methods are called out), until the time
runs out or the call cap is used, without being asked again. Each call is audited; the human is not
shown them live.

## Extension points for task grants (#5, plan mode)

A plan-mode feature builds on sessions rather than beside them:

- **Manifest rules.** The session record carries `hosts` and `methods`. Add a `rules` list
  (method, host, path_prefix, max_uses, optional body match) to the open request and to the card.
  The record already stores the approved manifest (hosts as `host` or `host:port`); rules extend the same record.
- **Max uses.** `max_calls` is the session-wide counter (`Session.calls`, incremented under the
  session lock before the call runs). Per-rule counters live beside it.
- **The session record.** `secret_broker/sessions.py: Session` (id, public prefix, client, credential,
  hosts, methods, ttl, expiry, calls, jar, captures). Expiry is read only from `Session.expires`.
- **The in-scope check function.** `SessionsMixin._session_call` calls one pure function,
  `scope_problem(session, secret_cfg, names, method, spec)` (spec holds url, headers, body), returning None or
  a (reason_class, message) pair. A manifest rule check is added there. It runs WITHOUT the store lock (it reads only
  fields that never change); the cap check and the counter increment happen afterwards under the lock, atomically.
  Per-rule counters must be charged in that same locked step.
- **Audit events.** `session_requested`, `session_opened`, `session_used`, `session_refused`
  (reason class), `session_closed`, `session_expired`, `session_revoked`. A plan feature can add
  rule ids to `session_used`/`session_refused`; the redaction whitelist is deny-by-default, so any
  new field must be named there.
- **Unattended use.** Sessions are memory-only and short; a plan feature that must survive a restart
  needs its own persisted record and must not reuse the session id as a bearer token across restarts.

## State held per session (memory only)

- id (never logged; only the 8-character prefix is), client id and name, credential name, hosts,
  methods, ttl, absolute expiry, call count and cap, the purpose text (agent claim, shown on the
  card and active list, escaped; the audit log keeps only its length and a hash prefix).
- **Cookie jar.** Cookies from upstream `Set-Cookie`, stored per exact host, sent only to that host.
  `Domain` is ignored (never widens), `Path` honoured, `Secure` cookies ignored from plain http and
  never sent over it, `Max-Age`/`Expires` honoured (past = delete). At most 50 cookies, 4096 bytes
  each. `Set-Cookie` is removed from every response the agent sees.
- **Captured values.** `--capture NAME=header:X|cookie:NAME|json:$.a.b`, from the final response.
  Minimal JSONPath: dotted keys and `[n]` indexes only; anything else is a usage error. At most
  16 values of 4096 bytes, scalars without control characters (they are later placed in headers).
  Used as `{{session.NAME}}` in URL, headers and body (single-pass substitution), never returned.
- Masking: credential values, cookie values and captured values are masked in response body and
  headers by exact match, for values of 4 or more characters (shorter ones are not masked: that would corrupt
  ordinary words and numbers; the card says so). Captured values must be printable ASCII.

## API and CLI surface

Client API (existing endpoints, no new secret-taking endpoint):

- `POST /v1/requests` mode `session`: `names:[credential]`, `purpose`, `hosts`, `methods`,
  `ttl_s`, `max_calls`. Result (delivered once): `{"session": {"id", "expires_in", "hosts",
  "methods", "max_calls"}}`.
- `POST /v1/requests` mode `http` with `session` (id) and optional `capture` (list): released
  immediately when in scope; the result carries `session: {captured, missing, calls_left,
  expires_in}` (names and counts only).
- `POST /v1/requests` mode `session_close`; `GET /v1/sessions/<id>` (time and calls left).

CLI:

    asb session open NAME --for "purpose" --host H [--host H2]... [--methods GET,HEAD,POST]
                          [--ttl 15m] [--max-calls N]
    asb session close ID
    asb session status ID
    asb http NAME METHOD URL ... --session ID [--capture NAME=EXPR]...

Hosts are required and must sit inside the credential's `allowed_hosts`. Methods default to
GET,HEAD; others are declared on open and shown on the card. Only http credentials: ssh and
no-`allowed_hosts` (env-only) credentials are refused. Redirects are never followed: the 3xx is returned with its (masked) Location and the agent makes a new in-scope, counted call.

Decision rule for agents: use `asb http` for HTTP APIs, `--session` for multi-step flows (login +
cookie), env mode only when a program needs the secret itself.

Config: `"sessions": {"enabled": true, "default_ttl_s": 900, "max_ttl_s": 3600, "max_calls": 200,
"max_per_client": 3}`; `GET /v1/status` reports it under `features.http_sessions`.

## Errors and exit codes

| Condition | HTTP | `code` | asb exit |
|---|---|---|---|
| unknown id, malformed id, another client's id | 404 | `session_unknown` | 7 |
| expired, closed or revoked (owner only) | 410 | `session_expired` | 7 |
| out of scope (host, method, credential), call cap used, missing `{{session.X}}`, bad placeholder | 403 | `session_refused` | 8 |
| bad capture expression, bad open parameters | 400 | none | 2 / 3 |
| open denied / expired unanswered | | | 4 / 5 |

All messages are fixed text. No exception text appears in any agent-visible output, audit record,
log, history row or page: only class names and coarse categories (`timeout`, `connection`, `tls`,
`dns`, `invalid_request`, `other`).

## Audit events

`session_requested`, `session_opened` (client, hosts, methods, ttl, max calls, expiry),
`session_used` (request id, session prefix, method host, call number), `session_refused` (reason
class), `session_closed`, `session_expired`, `session_revoked` (who). Plus the ordinary
`requested`, `approved` (via `session`), `secret_read`, `http_executed`, `delivered` for each call,
so each call is a history row. Values (credential, cookie, captured) are in none of them. The
agent-visible audit view whitelists these events and fields (deny by default); the human's history
shows them. Active sessions appear on the Clients tab with a live countdown and Revoke.

## Threat model

- **Stolen session id.** Useless without the owning client's key (client-bound; other clients get the
  unknown answer). With the key, it grants only what the card said, until the deadline. It cannot
  be extended, and it never reveals the credential or cookies.
- **Compromised client (key theft).** Can use that client's live sessions within scope, and can ask
  for new ones, which need a human. Revoking the client ends its sessions at once.
- **Prompt-injected agent.** Can spend the session inside its scope (that is the permission the
  human gave: read the card's methods and hosts as the worst case). It cannot widen hosts or methods,
  cannot exceed the cap or the deadline, and out-of-scope calls are refused rather than prompted, so
  it cannot create approval fatigue. The purpose text is untrusted and shown escaped.
- **Malicious upstream redirect.** Not followed at all, so a redirect cannot move the credential or cookies, change the
  method or port, or cause an uncounted hop. Cookies are host-scoped. TLS verification is as for plain http.
- **Cookie leakage.** Set-Cookie is stripped, cookie and captured values are masked if echoed, never
  logged. Not covered: an upstream that echoes a value in a transformed form (encoded, split) can
  show it to the agent; and a response header the agent did not capture (for example a CSRF header)
  is visible to it, as an ordinary response header.
- **Credential never visible.** Substituted by the broker, masked in responses, absent from audit.

## Limits and caps

15 min default, 60 min configurable maximum (absolute ceiling 24 h), 30 s minimum; 200 calls
default and cap (configurable, ceiling 10000); 3 sessions per client (configurable), 20 total; 2
pending open requests per client plus the general pending cap and deny cooldown; 5 hosts; no redirects; 8192-character urls and header values, 50 headers, 100 placeholders of up to 64 characters; 50 cookies; 16 captures; 1 MB response read.

## Failure modes

- Broker restart: all sessions gone; the next call is `session_unknown` (exit 7).
- Credential removed or its hosts narrowed while a session is open: the call is refused.
- Upstream errors: the call fails with a class only; the session and its call count stay as they are.
- Open request unanswered: expires like other requests; no session exists.
- The agent loses the id: the human can see and revoke the session; it expires anyway.

## Not covered (real UniFi quirks)

The test stub models login cookie + CSRF header + cookie-gated GET + CSRF-gated POST/PUT +
logout. It does not model: automatic CSRF rotation via `X-Updated-CSRF-Token` (the stub tests
rotation only with an explicit capture), UniFi OS cookie attributes and JWT expiry inside the
cookie, rate limiting or lockout, self-signed TLS (use the credential's pinned fingerprint),
`rememberMe`, websocket endpoints, controller version differences in paths, 2FA.

## Test plan

Unit: config parser, capture/JSONPath parser (including every rejected form), cookie jar (host
scope, path, secure, max-age, caps), id format. Broker tests with a stub UniFi-like upstream:
full flow, expiry with an injectable clock (no sliding), sweeper, never-used expiry, client binding
(second enrolled client and legacy key, identical errors), revoke (session and client), restart,
max-calls, host/method/credential refusals, allowed_hosts never widened, env/ssh refusal, redirect
scope, masking of echoed values, approval rules (high, no model, no chips, no token channel,
shorten-only), caps and cooldowns, audit whitelist and history, and a leak scan over stdout,
stderr, results, audit, history, request details, logs, notifications and HTML. The real `asb`
against a throwaway broker for the end-to-end flow. Rehearsal scenario in
`tools/rehearse_local_backend.py`.

## Implementation notes and deviations

- Code: `secret_broker/sessions.py` (config, capture parser, jar, `Session`, `scope_problem`, the http executor,
  card and active-list HTML, `SessionsMixin`); hooks in `broker.py` (`create`, `decide_via`, `_release`, handlers),
  `clients.py` (revoke ends sessions), `audit_api.py`, `history.py`, `risk.py`; the CLI in `client/asb`.
- A session call is an ordinary `Request` that is finished inline (`via: session`), so history, request details and the
  `delivered` flow work unchanged. The result carries `session: {captured, missing, calls_left, expires_in}`.
- Ended sessions leave a tombstone (id hash, client, reason; 500 max, 24 h) so the owner is told "expired/closed/revoked"
  while everyone else gets "unknown". Tombstones hold no jar or values.
- The agent's audit view whitelists the session events but deliberately omits `hosts` and `methods` (the agent chose them,
  and the redaction test treats `hosts` as policy context). The human's history shows everything.
- `asb session close` and `status` use `POST /v1/requests` mode `session_close` and `GET /v1/sessions/<id>`, so the client
  API still has exactly one POST endpoint and none takes a secret.
- `features.http_sessions` in `/v1/status` is an object (the config values), not a bool.
- Not done: the `asb agent-setup` instruction block (#14) is unchanged; the decision rule is in `asb guide` and
  `asb help session`. Per-credential `modes`, batch requests and automatic CSRF rotation are out of scope.
- Review round 1 (all fixed, each with regression tests in `tests/test_sessions.py`, class `Hardening` and others):
  linear placeholder scan with size caps and no scope check under the store lock (a cubic regex under the global lock froze
  every session for seconds); in-flight calls are re-checked after the upstream answers (revoke, close, client revoke, deadline
  discard the response and the jar changes); session calls have status `running`, not `pending`, so they cannot be decided or
  counted as pending; method-override headers, `_method` fields and bodies on GET/HEAD are refused; redirects are never
  followed (replacing the earlier follow-inside-hosts design: simpler, and no hop can change method, port or count);
  the manifest and card carry the port and calls are scope-checked on it; deadlines use `time.monotonic()` (an injectable
  clock for tests, wall time for display only); captured values must be printable ASCII and a call that never left the
  broker is not charged; masking threshold lowered to 4; refused-host logging capped at 255 characters; `ASB_SESSION`
  supported and preferred over `--session` (keeps the id out of the process list).
- The cookie jar is deliberately simpler than a browser's: every cookie is host-only, `Domain` and `SameSite` are
  ignored, `__Host-` and `__Secure-` prefixes get no special handling.
