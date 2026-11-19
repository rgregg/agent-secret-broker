# Auto-approving HTTP and WebSocket sessions: design note

Status: implemented on branch `session-auto-approve`. Written before the code; the rulings below are the ones the
repo owner should review.

## What it is

Today a session open request (`mode: session`, http or ws) always waits for the human. This adds two rule modes,
`http_session` and `ws_session`, to the existing auto-approve machinery (config `auto_approve` and the per-credential
rules on the Policies page). A session open request whose manifest lies entirely inside a matching rule is approved
without a tap, with its limits cut down to the rule's caps. Nothing else about a session changes: once opened it is
the same object, the same masking, the same scope checks, the same revoke.

## Threat model

A session is a window of many calls the human never sees. The attacker is a prompt-injected or compromised agent that
can send any open request it likes and can open sessions again and again. The rule is written by the human, so the
question is only whether a request can get MORE than the rule says, or get it when it should not.

1. Widening: a manifest with a host, port, method, path, scheme, lifetime or call budget the rule does not name.
2. Ambiguity: a manifest the matcher reads differently from the way the session will run it (escapes, dot segments).
3. Standing bypass: a legacy-key client, a client set to never auto-approve, an unlisted client, a revoked client,
   an expired rule, a credential the rule does not cover.
4. Skipping the request-time refusals (allowed hosts, destination guard, internal key).
5. Unbounded sessions: a rule with no caps.
6. A refusal or audit line that echoes agent text.

## Design

* One module, `secret_broker/sessionrules.py`, owns the rule fields, their parser and `within(rule, manifest)`, the ONE
  function that says whether a manifest is inside a rule and returns the limits the session gets. `autorules._parse_rule`
  delegates to it for both modes, so config rules, stored rules and the Policies form share one parser, and
  `autorules.find` calls the same `within` for matching.
* `http_session` fields: `hosts` (required list of `host` or `host:port`, the same entries a manifest uses: a bare host
  means ports 80 and 443), `methods` (default GET, HEAD), `max_ttl_s` and `max_calls` (both required).
  Manifest within rule: every manifest host entry's port set is inside a rule entry for the same host; every method is
  in the rule's methods.
* `ws_session` fields: `scheme` (default `wss`), `host`, `port` (default 443 / 80), `path_prefix` (required),
  `allow_query` (default false), `max_ttl_s`, `max_frames` (required). Manifest within rule: same scheme, host and port;
  the path is plain (no escape, `;`, backslash, dot segment) and under the prefix; a query only if `allow_query`.
* Path scope for http: a http session manifest carries no path, so a rule cannot bound one; `path_prefix` is not an
  option of `http_session` (a rule that said so could never be verified). Path-bounded unattended work is plan mode.
* Limits: `ttl = min(request, rule.max_ttl_s)`, `calls = min(request, rule.max_calls)`, stored as
  `spec["final"]` exactly where a human's shortened limits go, so `_session_open` is unchanged.
* The claim runs at the end of `_session_pending`: after `_validate_session` (allowed hosts, destination guard,
  internal key, caps per client, credential must be http / ws-enabled) and after the `requested` / `session_requested`
  audit. A client set to never auto-approve is skipped; the legacy key never matches (`autorules._client_ok`).
* Audit: `auto_rule_used` (already hidden) gains the effective limits; the `approved` event carries
  `decision_source: config_rule | ui_rule` and `rule_name`; `session_opened` / `ws_session_opened` are as before.
  `auto_rule_created` carries the new fields' safe summary. No new event names, so `audit_api` needs no new entry.
* `session_close` stays human-only in the HUMAN_ONLY list: it is not an approval at all (the owning client closes its
  own session with no prompt, which only ever shortens a window), so there is nothing to auto-approve. The word stays
  in the list so a config rule naming that mode is still refused.
* Policies form: the Kind selector gains "HTTP session" and "WebSocket session" with their own fieldsets; defaults are
  narrow (GET and HEAD, 15 minutes, 100 calls / 500 frames, wss, no query; no host default). The tick says plainly
  that matching session requests are opened with no approval, at any risk level, for up to the stated time and budget.

## Rulings (security first)

1. A rule's caps are required, not defaulted: a rule without them does not load.
2. A bare host in a rule means ports 80 and 443 (cleartext included), the same as in a manifest. The form's placeholder
   and help say to write `host:443` for https only. Matching is a subset test, so a rule for `host:443` never admits a
   manifest for bare `host`.
3. A rule never pins the credential's WebSocket sign-in or blocked message types: those are the operator's settings on
   the credential, apply to every session whatever approved it, and the session is bound to them at open time already.
4. Auto-approval has no rate limit beyond the existing per-client open-session and pending caps. A rule can therefore
   be used to open a fresh session each time the last one ends. Revoking the rule, an expiry on the rule, or narrowing
   the credential's hosts stops it; the Clients tab revokes open sessions.
5. Sessions are opened on the requesting thread (like an auto-approved http call): a WebSocket connect can take up to
   the handshake timeouts before the open request answers.
