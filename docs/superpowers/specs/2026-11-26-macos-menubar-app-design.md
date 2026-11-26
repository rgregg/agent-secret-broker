# macOS menubar approver app

Status: approved 2026-11-26 (full design).

## Intent

Approve and deny ASB requests from the Mac you are sitting at, without reaching for the phone or keeping
the approval page open in a browser tab. A small native menubar app shows a macOS notification when a
request is waiting, and clicking the notification or the menubar icon shows the pending requests and lets
you decide them.

The app signs in to an OIDC provider itself and calls a new broker API with a bearer token that **the
broker validates**. That works with any OIDC provider (Authentik, Keycloak, Auth0, Okta, Entra, ...) and
with or without an SSO proxy in front of the web app: not every install uses Authentik the way the author's
does.

An iPhone app is planned later. This design builds the parts both apps share (sign-in, API client, request
models, the broker API) so the iPhone app is a second front end, not a second project.

## Goals

- macOS notification for each new pending request, with Approve and Deny buttons on the banner for
  requests that get buttons on other channels.
- A menubar icon with a pending-count badge; clicking it shows a popover with the pending requests, each
  showing what the dashboard card shows (credential, client, summary, risk level, method and URL, and the
  masked request details).
- From the popover: Approve, Deny, timed approval, and Always, wherever the dashboard offers them for that
  request.
- Requests the app does not handle get an "Open in browser" button that opens that request on the approval
  site.
- Sign in once with OIDC (authorization code + PKCE); stay signed in with a refresh token kept in the
  Keychain.
- New requests show up within about a second (long poll), with no dependency on Apple's push service.
- Decisions are audited with their own channel so the log shows they came from the app.
- Works when the approval web app has no SSO proxy in front of it, and when it does.

## Non-goals (this version)

- In-app handling of: entering a credential value (`credential` mode), guidance proposals (`guidance`),
  plans (`plan`), session approvals with limits (`session`), sudo mode (`sudo`), client enrollment, and SSH
  rule creation. These open in the browser.
- Apple Push Notification service (APNs). Designed for (see "Later: push and iPhone"), not built.
- The iPhone app.
- Managing policies, credentials, clients or settings from the app.
- Mac App Store distribution.

## Anti-goals

- An agent's client key can approve anything through the new API, or the app's token works on the agent
  API. Each is refused on the other's endpoints.
- A token from the wrong issuer, for the wrong audience, expired, badly signed, or for a user other than
  `allowed_user` decides anything.
- Request details, tokens, or secret values appear in a log line, audit entry, notification banner text
  beyond what Web Push already shows, or a crash report.
- The app renders attacker-influenced request text (summaries, URLs, headers, bodies) as anything but
  plain text.
- Turning the feature on changes nothing for installs that do not configure it.

## Constraints

- The approval web app (port 8801) trusts an identity header from an SSO proxy and must never be reached
  directly. The new API therefore cannot live there; it goes on the client listener (port 8800), next to
  `/v1/hooks/ha/decide`, under `/v1/approver/`. Port 8800 is already TLS-fronted and reachable by the
  agents' machines.
- Every decision must go through `Broker.decide_via` (single-decision claim, channel permissions, audit).
- `cryptography` is already a broker dependency; JWT signature checks (RS256, ES256) use it. No new
  Python dependency for this version.
- The broker uses a threaded `http.server`; a long poll holds a thread, so waiters must be capped.
- The Mac app cannot be built on the Linux development machine. It is built and tested on a GitHub
  Actions macOS runner; manual testing happens on the author's Mac.
- The author does not run agents on the Mac where they approve. Other users might, so this must be
  documented prominently (see "Security").

## Approaches

- **A. Bearer token through the Authentik outpost.** The app gets a token for the proxy provider's client
  ID and sends it through the outpost, which sets `X-authentik-username`; the broker's auth is unchanged.
  Rejected: it relies on behavior Authentik does not document (a proxy provider as a public PKCE client,
  refresh tokens, identity headers on bearer requests), works only with Authentik, and the broker cannot
  tell app decisions from browser ones because the outpost strips `Authorization`.
- **B. The broker validates the token itself (chosen).** A dedicated public OIDC client for the app; the
  broker checks the JWT (signature via the provider's JWKS, issuer, audience, expiry, username claim) on a
  new `/v1/approver/` API. Provider-agnostic, works with no proxy, uses only documented OIDC behavior, and
  gives the app its own audit channel. Costs more broker code and puts approvals on port 8800.
- **C. Embed the approval web page in the app (WKWebView).** Rejected: native notifications with action
  buttons would still need a native API, and the SSO login inside a web view is fragile.

Push delivery: **long polling now, APNs later.** A menubar app runs from login, so a held connection is as
fast as APNs and needs no Apple developer account or push key, which matters for other self-hosters. The
iPhone app requires APNs (iOS apps cannot poll in the background), so the API leaves room for device
registration.

## Decided

### Broker configuration

A new optional top-level `approver_api` block. Absent: every `/v1/approver/*` path answers 404, exactly as
today.

    "approver_api": {
      "issuer": "https://auth.example.com/application/o/asb-app/",
      "client_id": "asb-app",
      "audience": "asb-app",            // optional; default: client_id
      "username_claim": "preferred_username",   // optional; default shown
      "required_group": "asb-approvers",        // optional; checked against the "groups" claim
      "scopes": ["openid", "profile", "offline_access"]   // optional; given to the app
    }

- The username taken from `username_claim` must equal the existing `allowed_user`.
- Startup validation names each field (`approver_api.issuer`, ...): issuer must be `https://` (loopback
  `http://` allowed only when the destination guard allows loopback, for tests), client_id non-empty, claim
  names short identifiers.
- The broker fetches `<issuer>/.well-known/openid-configuration` and its `jwks_uri` at startup and caches
  the keys. A token with an unknown `kid` triggers at most one JWKS refetch per 60 s. If discovery fails at
  startup, the broker starts, logs one warning, and the API answers 503 until a refetch succeeds.

### Token validation

- `Authorization: Bearer <JWT>` only. Accepted algorithms: RS256 and ES256 (never `none` or HMAC).
- Checks: signature against the cached JWKS; `iss` equals `issuer` exactly; `aud` contains `audience` (or
  `azp` equals it when `aud` is a list); `exp` and `nbf` with 60 s skew; username claim equals
  `allowed_user`; `required_group`, if set, is in `groups`.
- The provider must issue JWT access tokens (Authentik, Keycloak, Auth0, Okta and Entra do; providers with
  opaque access tokens are not supported in this version, which the docs say).
- The agent client key is refused on `/v1/approver/*` (401), and a JWT is refused on every other client
  listener path (401), like the HA hook key.
- Refusals are audited as `approver_auth_refused` with a fixed reason (`missing`, `malformed`, `alg`,
  `signature`, `issuer`, `audience`, `expired`, `user`, `group`, `jwks_unavailable`), coalesced per window;
  never the token.
- Rate limit: 60 requests/min per source IP for valid tokens; invalid tokens share one bucket (the HA hook
  pattern), so a flood cannot lock the app out.

### API (client listener, `/v1/approver/`)

All responses are JSON; request bodies are JSON with a 4 KB cap.

- `GET /v1/approver/config` (no auth): `{"issuer", "client_id", "scopes", "api_version": 1}`, so the app
  only needs the broker URL. Answers 404 when `approver_api` is absent.
- `GET /v1/approver/pending?since=<version>&wait=<s>`: returns `{"version": n, "requests": [...]}`. With
  `wait` (max 25 s) and a `since` equal to the current version, the call blocks until the pending set
  changes or the wait ends. Concurrent waiters are capped (default 8); beyond that, `wait` is ignored and
  the call answers at once.
- Each request object carries: `id`, `mode`, `created`, `expires`, `credential` names, `client` (name and
  id), `summary` and its source, `risk` (`level`, `reasons`), the target (method and URL, host, or argv as
  the dashboard shows it), the `request_details` view (already masked, as built by
  `request_details.build_view`), and `actions`: the list of decisions the app may offer for this request
  (`approve`, `deny`, `grant:<minutes>` for each offered duration, `always`, `always_script`), and
  `browser_url`, the request's page on the approval site. Requests in non-goal modes have only
  `browser_url` (and `deny`, since denying needs no extra input).
- `POST /v1/approver/decide` with `{"id", "decision": "approve"|"deny", "grant_minutes"?, "always"?,
  "rule_scope"?, "device"?}`: goes through `decide_via("app", ...)`. Answers 200 `{"ok": true}`; 400
  malformed or an action not offered; 404 unknown; 410 already decided or expired.

### The app as a notification target (builder's call, settled in review)

The app is a notify target, not only a viewer of the pending set: a banner must not fire for a request that
is still being assessed or is auto-approved a moment later, and must respect presence holds and fallbacks
like every other transport.

- When `approver_api` is configured, the broker adds an internal `app` notify leaf. When `_push` fires for a
  request (after assessment and auto-approval), the leaf marks the request `notified` and bumps the pending
  version, which wakes long polls. The leaf contributes its actions to `req.offered` like the token
  transports.
- Each request object in `/pending` carries `notified` (bool). The app posts a banner only when a request
  turns `notified`; un-notified requests still show in the popover (marked "assessing").
- Banner buttons come from the usual `notify_actions` policy, narrowed by an optional
  `approver_api.actions` override with the same shape as a notify entry's `actions`. The popover's buttons
  (including timed and Always) come from the request's `actions` list, which is independent of this.
- The long-poll version changes when the pending set changes and when a request is notified, and when its
  risk or summary arrives.

### Presence (decided by the author)

The app counts as presence for `notify_presence`, but **only while the user is active at the Mac**: screen
unlocked and keyboard or mouse input within the last 2 minutes (`CGEventSource` idle time plus screen-lock
notifications). It is not presence merely because it is running.

- `POST /v1/approver/presence` with `{"active": true|false, "device"?}`, OIDC-authenticated like the rest of
  the API. The app sends `active: true` every 10 s while active (the presence `ttl_s` defaults to 25 s, so a slower beat would lapse), and `active: false` at once when the
  user goes idle or locks the screen. The broker feeds this into the existing presence module as a second
  source with the same expiry rules as the approval page's heartbeat.
- Presence still cannot be faked with an agent's client key: the endpoint requires the approver's OIDC token.
  The threat-model text in `docs/reference.md` that says presence is not on the client API port is rewritten
  to say this.
- An open approval page does not suppress the app's own banners; the app's banners always fire when a
  request is notified.

### Decision channel

New `CHANNELS["app"]`: `token_required=False` (the OIDC check is the channel's authentication, as the SSO
header is the dashboard's), `may_create_always=True`, `may_create_grant=True`, `may_create_ssh_rule=False`.
Approver recorded as `app:<username>`, plus `device` (an app-chosen label such as the Mac's name, max 64
chars of `A-Za-z0-9_.:-`, asserted not verified), `approver_ip`, and the token's `jti` or a hash of the
token when there is none. One channel for both the Mac and later the iPhone app; `device` tells them apart.

### The Mac app

- Swift and SwiftUI, `MenuBarExtra` with the window style, macOS 14 or later. Lives at `macos/` in this
  repo: a Swift package `ASBApproverKit` (OIDC sign-in, token storage, API client, models, long-poll loop;
  platform-neutral so the iPhone app can use it) and the app target `ASBApprover`.
- First run: the user enters the broker's client URL; the app reads `/v1/approver/config` and signs in with
  `ASWebAuthenticationSession`, authorization code + PKCE (S256), redirect to a custom URL scheme
  (`asb-approver://callback`). Access and refresh tokens are kept in the Keychain, with the item limited to
  this app. Refresh happens before expiry; a failed refresh shows "Sign in again" in the popover and stops
  polling.
- A long-poll loop keeps the pending list current. On a new request id it posts a local notification
  (`UNUserNotificationCenter`) whose category carries Approve and Deny actions when `actions` includes them.
  The banner fires when a request becomes `notified` (see above), not when it first appears. The banner
  text is the same short line Web Push sends (credential, client, risk), never the request
  details. Tapping the banner opens the popover on that request.
- Menubar icon shows the pending count. The popover lists pending requests oldest first; each row expands
  to the full card, with buttons for exactly the `actions` the broker sent, and "Open in browser".
- All request text renders as plain `Text`, never as Markdown or attributed/HTML content.
- Optional "Launch at login" (`SMAppService`).
- Networking failures show a quiet "Can't reach the broker" state and back off (1 s up to 30 s).

### Build and distribution

- GitHub Actions macOS workflow: `swift test` for `ASBApproverKit`, then `xcodebuild` for the app. When
  signing secrets are present, sign with Developer ID and notarize; otherwise publish an unsigned build as a
  workflow artifact.
- Release zips attached to GitHub releases, like the CLI.

### Security documentation

A prominent section in `docs/reference.md` (and a short warning in `docs/setup.md` and the app's first-run
screen):

- Anything running as you on that Mac can drive the app or use its Keychain session if it gets past the
  Keychain prompt, and so can approve requests. **Do not run agents on a Mac where you approve.** The point
  of ASB is that the agent cannot approve its own requests; an approver app on the agent's machine
  undoes that.
- Approvals are now reachable through port 8800; restrict who can reach it at the network level if that
  matters, and keep the OIDC client limited to `allowed_user` (and `required_group`).
- Revoking the app's sessions at the identity provider (or removing `approver_api`) cuts the app off.

### Tests

- Broker (Python, existing `tests/` suite): token validation with a local test issuer and JWKS (each
  refusal reason), client key refused on the approver API and JWT refused elsewhere, `/pending` contents
  and masking, long-poll wake-up and the waiter cap, `/decide` through `decide_via("app")` including
  `grant_minutes`, `always`, refused SSH rules, 410 on a decided request, and that without `approver_api`
  every path is 404.
- Swift: unit tests for the API client and models against recorded JSON, the PKCE helper, and the
  long-poll loop's backoff, run on the macOS runner.
- Manual: sign-in, notification actions, and the popover on the author's Mac against the home-lab broker.

## Later: push and iPhone

- `POST /v1/approver/devices` registers an APNs device token for the signed-in user; the broker gains an
  APNs sender (token-based `.p8` auth over HTTP/2, a new dependency) as one more notify transport.
- The APNs payload says only that a request is waiting (and its id); a notification service extension
  fetches details over the OIDC-authenticated API, because APNs is not end-to-end encrypted.
- Self-hosters need their own Apple developer account, push key and app build; the long-poll Mac app keeps
  working without any of that.

## Left to the builder

- Exact JSON field names and the shape of `target` per mode, matched to what the dashboard card shows.
- Where `allowed_user` lives today and how the approver API reads it.
- Window lengths for audit coalescing; the waiter cap and rate limits if the values above don't fit the
  server.
- Icon artwork and popover layout details.
- Whether the Xcode project is generated (XcodeGen/Tuist) or checked in.
