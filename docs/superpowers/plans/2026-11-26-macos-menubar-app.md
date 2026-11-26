# macOS Menubar Approver App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A native macOS menubar app that notifies the approver of pending ASB requests and lets them decide
them, signed in with OIDC and calling a new broker API whose bearer tokens the broker validates itself.

**Architecture:** The broker gains an optional `approver_api` (config parse + JWT/JWKS verifier in
`secret_broker/oidc.py`; feed, notify leaf, request views and HTTP handlers in
`secret_broker/approver_api.py`) served on the client listener under `/v1/approver/`, deciding through a new
`app` channel in `decide_via`. The Mac app is a Swift package `ASBApproverKit` (models, API client, OIDC +
PKCE, token store, long-poll feed) plus a SwiftUI `MenuBarExtra` app target `ASBApprover`, built on a GitHub
Actions macOS runner.

**Tech Stack:** Python 3 stdlib + `cryptography` (already a dependency), `unittest` via `tests/run_tests.py`;
Swift 5.10+, SwiftUI, `AuthenticationServices`, `UserNotifications`, `Security` (Keychain), `ServiceManagement`,
XcodeGen for the app project; GitHub Actions `macos-14`.

**Spec:** `docs/superpowers/specs/2026-11-26-macos-menubar-app-design.md`

## Global Constraints

- No `approver_api` in config: every `/v1/approver/*` path answers 404 and nothing else changes.
- No new Python dependency. JWT algorithms accepted: RS256, ES256 only (never `none`, never HMAC).
- `iss` must equal `issuer` exactly; `aud` contains `audience` (default `client_id`) or `azp` equals it; `exp`/`nbf` with 60 s skew; `username_claim` (default `preferred_username`) equals `allowed_user`; `required_group`, if set, in `groups`.
- JWKS refetch on unknown `kid` at most once per 60 s. Discovery failure at startup: start, log one warning, answer 503 until a refetch succeeds.
- The agent client key is refused on `/v1/approver/*` (401); a JWT never authenticates any other client path.
- Refusal reasons (fixed words): `missing`, `malformed`, `alg`, `signature`, `issuer`, `audience`, `expired`, `user`, `group`, `jwks_unavailable`. Audited as `approver_auth_refused`, coalesced per window, never the token.
- Rate limits: 60 requests/min per source IP for valid tokens; invalid tokens share one bucket (HA hook pattern).
- Request bodies JSON, 4 KB cap. `wait` max 25 s; at most 8 concurrent waiters, beyond that `wait` is ignored.
- Channel `app`: `token_required=False`, `may_create_always=True`, `may_create_grant=True`, `may_create_ssh_rule=False`. Approver `app:<username>`; `device` max 64 chars of `A-Za-z0-9_.:-` (`notify.DEVICE_RE`).
- Modes `guidance`, `credential`, `plan`, `session`, `sudo` are browser-only: actions `["deny"]` plus `browser_url`.
- Request text in the app renders as plain `Text` only (never Markdown, attributed or HTML).
- Banner text = the Web Push title/text line; never the request details.
- macOS 14 or later. Redirect URI `asb-approver://callback`. PKCE S256.
- Presence from the app only while the screen is unlocked and input within the last 120 s.
- Commits: this repo's profile is conservative. Run the commit steps only once the user has authorized commits for this work; otherwise stage nothing and report.

## Review Focus

1. **Broker restarts while the app long-polls.** The version resets; an app `since` larger than the broker's current version must get an immediate answer, not a 25 s hang. (Task 2 test `test_wait_returns_at_once_when_since_unknown`.)
2. **A request decided elsewhere (phone, dashboard) while the app shows it.** `/decide` answers 410; the app drops the row and removes the delivered banner without an error alert. (Task 2 test `test_decide_410_after_dashboard_decision`; Task 5 test `testDecide410RemovesRequest`.)
3. **Access token expires during a long poll.** A 401 triggers one refresh and a retry; only a failed refresh shows "Sign in again". (Task 4 test `testRefreshOnceOn401ThenRetry`.)
4. **Identity provider rotates its signing key.** A token with a new `kid` verifies after one JWKS refetch; a second unknown `kid` within 60 s does not refetch. (Task 1 test `test_unknown_kid_refetches_once_per_minute`.)
5. **Very long or hostile request text** (a 10 KB summary, control characters, Markdown links). The view truncates the summary at 500 characters and the app renders it as plain text. (Task 2 test `test_view_caps_summary_and_strips_controls`; Task 6 manual check.)

---

### Task 1: OIDC config and JWT verifier

**Files:**
- Create: `secret_broker/oidc.py`
- Test: `tests/test_approver_oidc.py`

**Interfaces:**
- Consumes: `secret_broker.destguard` (loopback allowance for tests), `cryptography`.
- Produces:
  - `parse_config(raw, allowed_user: str, field="approver_api") -> dict | None` — `None` when `raw` is `None`; raises `ValueError` naming the field (`approver_api.issuer`, ...). Keys out: `issuer, client_id, audience, username_claim, required_group, scopes, actions` (`actions` parsed with `notify.parse_action_policy` or `None`).
  - `class Verifier(cfg: dict, fetch_json=callable(url)->dict, clock=time.time)` with `refresh() -> bool` (discovery + JWKS; never raises) and `verify(token: str) -> tuple[dict | None, str | None]` returning `(claims, None)` or `(None, reason)`.
  - `REASONS` tuple of the ten refusal words.

- [ ] **Step 1: Write the failing tests** in `tests/test_approver_oidc.py` (unittest, keys generated with `cryptography` per test class; a `fetch_json` stub dict keyed by URL):
  - `test_parse_none_is_none`, `test_parse_defaults` (`audience == client_id`, `username_claim == "preferred_username"`, `scopes == ["openid","profile","offline_access"]`), `test_parse_rejects_http_issuer` (message contains `approver_api.issuer`), `test_parse_rejects_unknown_key`.
  - `test_rs256_and_es256_accepted` → claims returned.
  - One test per refusal: `alg` (`none` and `HS256`), `signature` (tampered payload), `issuer`, `audience` (and `azp` path accepted), `expired` (exp 61 s ago refused, 59 s ago accepted), `user`, `group`, `malformed` (not three parts, bad base64), `jwks_unavailable` (discovery fetch raises).
  - `test_unknown_kid_refetches_once_per_minute`: rotate keys in the stub; first new-kid token verifies after one refetch; another unknown kid at +30 s returns `signature` with no extra fetch; at +61 s it refetches.
- [ ] **Step 2: Run** `python -m unittest tests.test_approver_oidc -v` — expected: FAIL (`ModuleNotFoundError: secret_broker.oidc`).
- [ ] **Step 3: Implement `secret_broker/oidc.py`.** Base64url JOSE parsing by hand; RS256 via `RSAPublicNumbers(...).public_key().verify(sig, data, PKCS1v15(), SHA256())`; ES256 via `EllipticCurvePublicNumbers` with the raw `r||s` signature converted by `encode_dss_signature`. Discovery URL is `issuer.rstrip("/") + "/.well-known/openid-configuration"`; the default `fetch_json` uses `urllib.request` with a 5 s timeout and goes through `destguard` like other outbound calls. Keys cached by `kid`; a lock guards the cache.
- [ ] **Step 4: Run** the same command — expected: all PASS.
- [ ] **Step 5: Commit** `git add secret_broker/oidc.py tests/test_approver_oidc.py && git commit -m "approver_api: OIDC config and JWT verifier"`.

### Task 2: Approver feed, `app` notify leaf, request views and channel

**Files:**
- Create: `secret_broker/approver_api.py`
- Modify: `secret_broker/broker.py` (`CHANNELS` at ~line 130; `Broker.__init__` near the `ha_hook` parse ~line 288; `_push` ~line 3020; `_finish`)
- Test: `tests/test_approver_feed.py`

**Interfaces:**
- Consumes: `oidc.parse_config`, `oidc.Verifier` (Task 1); `notify.make_notification`/`leaves`/`MultiNotifier`; `request_details.build_view(spec)`; `Broker.pending()`, `grant_durations()`, `grant_eligibility(req)`, `always_allow_eligibility(req)`, `decide_via(...)`.
- Produces:
  - `class AppNotifier` — `type` attribute `"app"` (via `notify.TRANSPORT_TYPE_ATTR`), `supports_actions = ("approve", "deny")`, optional `action_policy` from `approver_api.actions`; `send(n)` records `feed.mark_notified(n.rid, [a.id for a in n.actions])` and never raises; `resolved(n, status)` calls `feed.bump()`.
  - `class AppFeed(clock=time.time, max_waiters=8)` — `mark_notified(rid, banner_actions)`, `notified(rid) -> list[str] | None`, `bump()`, `version -> int`, `wait(since: int, timeout: float, fingerprint: callable) -> int` (returns at once if `since != version`; otherwise waits on a condition, re-checking `fingerprint()` every 1.0 s and bumping when it changes; returns the version; if `max_waiters` are already waiting it returns at once).
  - `request_view(broker, req) -> dict` — keys `id, mode, created, expires, credentials, client{name,id}, summary, summary_source, risk{level,reasons}|None, target, details, notified, banner_actions, actions, browser_url`. `summary` capped at 500 chars with C0/C1 control characters removed; `details` from `request_details.build_view` for `http`/`env`, else `None`; `target` is the same `what` text `_push` builds (factor it into a `Broker._what(req)` helper and reuse it in `_push`).
  - `offered_actions(broker, req) -> list[str]` — browser-only modes: `["deny"]`; otherwise `["deny","approve"]` + `f"grant:{m}"` for each `grant_durations()` when `grant_eligibility` ok + `"always"` when `always_allow_eligibility` ok (plus `"always_script"` for `env` when the dashboard offers it).
  - `fingerprint(broker) -> tuple` — `(id, notified, risk level, summary is not None)` per pending request.
  - `decide(broker, rid, body, user, peer, token_id: str) -> tuple[int, dict]` — validates `decision`/`grant_minutes`/`always`/`rule_scope`/`device` against `offered_actions` (400 if not offered), calls `decide_via("app", rid, decision, f"app:{user}", always=..., grant_minutes=..., rule_scope=..., peer=peer, device=device, token_id=token_id)`, maps to `(200|400|404|410, {"ok": ...})`. `token_id` is the token's `jti`, or the first 16 hex chars of its SHA-256 when there is none.
  - `Broker.approver` — `None` or an object holding `cfg`, `verifier`, `feed`; `CHANNELS["app"]`.

- [ ] **Step 1: Write the failing tests** in `tests/test_approver_feed.py`, building a `Broker` with `approver_api` and a `FakeNotifier` the way `tests/test_ha_hook.py` does:
  - `test_no_config_no_app_leaf` (`broker.approver is None`, leaves unchanged).
  - `test_app_leaf_added_and_never_held` (with presence present, `_presence_hold_set` excludes the app leaf).
  - `test_notified_only_after_push` (a request in assessment has `notified: False`; after `_push`, `True` and `banner_actions == ["deny","approve"]` for low risk).
  - `test_banner_actions_follow_override` (`approver_api.actions = {"approve_max_risk": "low"}`, a medium request → `["deny"]`).
  - `test_browser_only_modes` (each of the five modes → `actions == ["deny"]`, `banner_actions == []`).
  - `test_offered_actions_grants_and_always` (grants on with durations `[15, 60]` → includes `grant:15`, `grant:60`; `always` present only when eligible).
  - `test_view_caps_summary_and_strips_controls` (10 KB summary with `\x1b` → 500 chars, no control chars).
  - `test_view_masks_details` (an `Authorization: Bearer literal` header shows `[masked]`).
  - `test_wait_wakes_on_new_request` (waiter returns within 2 s of a create), `test_wait_returns_at_once_when_since_unknown` (`since = version + 5` → immediate), `test_waiter_cap` (9th waiter returns immediately).
  - `test_decide_app_channel_audit` (approver `app:alice`, `channel: app`, `device` and `token_id` recorded), `test_decide_grant_and_always`, `test_decide_refuses_unoffered` (approve on `credential` → 400, still pending), `test_decide_ssh_rule_never_created`, `test_decide_410_after_dashboard_decision`.
- [ ] **Step 2: Run** `python -m unittest tests.test_approver_feed -v` — expected: FAIL (import error).
- [ ] **Step 3: Implement** `secret_broker/approver_api.py` and the broker wiring: in `Broker.__init__`, parse `approver_api` with `allowed_user`; when set, build the `Verifier` (call `refresh()` once; on failure log `approver_api_discovery_failed` warning), create the `AppFeed`, and wrap `self.notifier` so its leaves include an `AppNotifier` (a `MultiNotifier([existing, app])`, or extend an existing `MultiNotifier`'s list). Call `feed.bump()` in `_finish`. Factor `Broker._what(req)` out of `_push`.
- [ ] **Step 4: Run** `python -m unittest tests.test_approver_feed tests.test_ha_hook tests.test_notify_pipeline tests.test_presence -v` — expected: all PASS.
- [ ] **Step 5: Commit** `git commit -m "approver_api: feed, app notify leaf, request views, app channel"` (the three files).

### Task 3: `/v1/approver/*` endpoints and presence

**Files:**
- Modify: `secret_broker/approver_api.py` (handlers), `secret_broker/broker.py` (client handler `do_GET`/`do_POST` dispatch next to `/v1/hooks/ha/decide` ~line 6505; rate-limit helpers next to `ha_rate_ok`/`ha_unauth_ok`)
- Test: `tests/test_approver_http.py`

**Interfaces:**
- Consumes: everything from Tasks 1–2; `Presence.beat(user, visible, tab)`.
- Produces (HTTP, all JSON):
  - `GET /v1/approver/config` (no auth) → `{"issuer","client_id","scopes","api_version":1}`.
  - `GET /v1/approver/pending?since=<int>&wait=<int>` → `{"version": int, "requests": [request_view...]}` (oldest first).
  - `POST /v1/approver/decide` `{"id","decision","grant_minutes"?,"always"?,"rule_scope"?,"device"?}` → `{"ok": bool}`.
  - `POST /v1/approver/presence` `{"active": bool, "device"?}` → `{"ok": true}`; calls `presence.beat(allowed_user, active, tab=f"app:{device or 'unknown'}")`.
  - `handle(handler, broker, method, path) -> bool` in `approver_api.py` (True when the path was an approver path and was answered).

- [ ] **Step 1: Write the failing tests** in `tests/test_approver_http.py`, starting `serve(b, ...)` on port 0 with a local stub issuer (an in-process `ThreadingHTTPServer` serving discovery + JWKS, the `FakeHA` pattern):
  - `test_all_paths_404_without_config`.
  - `test_config_unauthenticated`.
  - `test_client_key_refused_on_approver` (401), `test_jwt_refused_on_v1_requests` (401, request not created).
  - `test_each_refusal_audited_without_token` (expired, wrong user → 401, audit `approver_auth_refused` with reason, token string absent from audit file).
  - `test_503_when_jwks_unavailable`.
  - `test_pending_lists_and_long_polls` (`wait=5` returns after a new request with a higher version).
  - `test_wait_capped_at_25` (`wait=600` treated as 25: patch the feed's clock or assert the argument passed).
  - `test_body_over_4k_is_413`.
  - `test_rate_limit_valid_and_shared_invalid_bucket` (61st valid call/min → 429; invalid flood → 429 from the shared bucket and a valid token still works).
  - `test_presence_active_holds_phone_and_inactive_releases` (with a `webpush`-typed `FakeNotifier`: `active:true` → request held; `active:false` → released on `presence_tick`).
- [ ] **Step 2: Run** `python -m unittest tests.test_approver_http -v` — expected: FAIL.
- [ ] **Step 3: Implement** `approver_api.handle` and dispatch it first in the client handler's `do_GET` and `do_POST` (before `_authed`). Bearer parsing as in `_ha_decide`; reuse the HA-hook limiter shape for the two buckets; audit coalescing window 60 s.
- [ ] **Step 4: Run** `python tests/run_tests.py -j 8` — expected: whole suite PASS.
- [ ] **Step 5: Commit** `git commit -m "approver_api: /v1/approver endpoints and app presence"`.

### Task 4: Broker docs

**Files:**
- Modify: `docs/reference.md` (new "Approver app API (`approver_api`)" section after "Home Assistant action buttons"; channel table row for `app`; rewrite the presence threat-model lines near 1639 and 3566), `docs/setup.md` (optional step: "Approve from a Mac"), `README.md` (one feature bullet)

- [ ] **Step 1: Write** the reference section: config block with every key and default, token rules, endpoints and status codes, presence semantics, and a **Security** subsection with this warning verbatim near the top: "Anything running as you on the Mac where the approver app is signed in can act as the app and approve requests. Do not run agents on a Mac where you approve. ASB exists so an agent cannot approve its own requests; an approver app on the agent's machine undoes that." Also: port 8800 now carries approvals (restrict it at the network level if that matters); providers must issue JWT access tokens; revoking the app's sessions at the IdP or removing `approver_api` cuts it off. Include an Authentik example (public OAuth2/OIDC provider, PKCE, redirect `asb-approver://callback`, `offline_access` scope mapping) with placeholders only.
  In `docs/setup.md`, the optional "Approve from a Mac" step repeats the first sentence of that warning and links to the section.
- [ ] **Step 2: Run** `python tests/run_tests.py -j 8` — expected: PASS (doc-sync tests such as `test_cli_text_sync` stay green).
- [ ] **Step 3: Commit** `git commit -m "docs: approver app API and its security model"`.

### Task 5: `ASBApproverKit` Swift package

**Files:**
- Create: `macos/ASBApproverKit/Package.swift` (platforms `.macOS(.v14), .iOS(.v17)`)
- Create: `macos/ASBApproverKit/Sources/ASBApproverKit/{Models.swift, APIClient.swift, PKCE.swift, OIDCClient.swift, TokenStore.swift, PendingFeed.swift}`
- Test: `macos/ASBApproverKit/Tests/ASBApproverKitTests/{ModelsTests.swift, APIClientTests.swift, PKCETests.swift, OIDCClientTests.swift, PendingFeedTests.swift}` with a `StubURLProtocol`
- Create: `.github/workflows/macos.yml` (job `kit` on `macos-14`: `swift test --package-path macos/ASBApproverKit`)

**Interfaces:**
- Consumes: the HTTP API of Task 3.
- Produces:
  - `struct ApproverConfig: Codable { issuer: URL; clientId: String; scopes: [String]; apiVersion: Int }`
  - `struct PendingRequest: Codable, Identifiable, Equatable` mirroring `request_view` (snake_case keys via `JSONDecoder.keyDecodingStrategy = .convertFromSnakeCase`); `struct PendingPage { version: Int; requests: [PendingRequest] }`
  - `enum Decision { case approve, deny, grant(minutes: Int), always, alwaysScript }`
  - `enum DecideResult { case ok, alreadyDecided, notFound, refused }`
  - `actor APIClient(baseURL: URL, tokens: TokenProvider, session: URLSession)` with `config() async throws -> ApproverConfig`, `pending(since: Int?, wait: Int) async throws -> PendingPage`, `decide(id: String, _ d: Decision, device: String) async throws -> DecideResult`, `presence(active: Bool, device: String) async throws`.
  - `protocol TokenProvider { func accessToken() async throws -> String; func refreshAfter401() async throws -> String }`
  - `struct PKCE { verifier: String; challenge: String; static func make() -> PKCE }` (S256, 43–128 chars)
  - `final class OIDCClient: TokenProvider` — `authorizeURL(state:pkce:) -> URL`, `exchange(code:pkce:) async throws`, refresh with rotation, `signOut()`; `OIDCError.signInRequired` when refresh fails.
  - `protocol TokenStore { load() -> Tokens?; save(Tokens); clear() }`, `KeychainTokenStore` (generic password, service `asb-approver`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
  - `actor PendingFeed(api: APIClient)` — `updates: AsyncStream<FeedEvent>` where `FeedEvent = .page(PendingPage) | .newlyNotified([PendingRequest]) | .unreachable | .signInRequired`; backoff 1, 2, 4 … 30 s; resets on success.

- [ ] **Step 1: Write the failing tests:** `testDecodesRecordedPending` (fixture JSON copied from a Task 3 test response), `testPKCEChallengeIsS256OfVerifier` (RFC 7636 appendix B vector), `testAuthorizeURLHasPKCEAndRedirect`, `testRefreshOnceOn401ThenRetry`, `testFailedRefreshRaisesSignInRequired`, `testDecideMaps410ToAlreadyDecided`, `testDecide410RemovesRequest` (feed's next page omits it), `testNewlyNotifiedEmittedOnceAndOnlyWhenNotifiedTurnsTrue`, `testBackoffSequenceCapsAt30`.
- [ ] **Step 2: Run** on macOS (CI or a Mac): `swift test --package-path macos/ASBApproverKit` — expected: FAIL (types missing).
- [ ] **Step 3: Implement** the sources to the interfaces above; no third-party dependencies.
- [ ] **Step 4: Run** the same command — expected: PASS. From the Linux machine this step is the `kit` job's result on the pushed branch (`gh run view`); it cannot run locally.
- [ ] **Step 5: Commit** `git commit -m "macos: ASBApproverKit package and CI job"`.

### Task 6: `ASBApprover` menubar app

**Files:**
- Create: `macos/ASBApprover/project.yml` (XcodeGen: app target, bundle id `io.github.rgregg.asb-approver` overridable, `LSUIElement = YES`, URL scheme `asb-approver`, deployment target 14.0, depends on the local `ASBApproverKit` package)
- Create: `macos/ASBApprover/Sources/{ASBApproverApp.swift, AppModel.swift, MenuContent.swift, RequestRow.swift, SignInView.swift, Notifications.swift, PresenceReporter.swift, LoginItem.swift}`
- Create: `macos/ASBApprover/Resources/Assets.xcassets` (menubar template icon)
- Modify: `.github/workflows/macos.yml` (job `app`: `brew install xcodegen`, `xcodegen --spec macos/ASBApprover/project.yml`, `xcodebuild -scheme ASBApprover -configuration Release build`; sign + notarize only when `MACOS_SIGNING_CERT` secret exists, else upload the unsigned `.app` zip as an artifact; on a `v*` tag, attach the zip to the GitHub release as the CLI binaries are)

**Interfaces:**
- Consumes: all of Task 5.
- Produces: the app. `AppModel` (`@Observable`, main actor) owns `APIClient`, `OIDCClient`, `PendingFeed`, `requests: [PendingRequest]`, `state: .signedOut | .ready | .unreachable`; `decide(_:_:)`.

- [ ] **Step 1: Build the pieces:**
  - First run (`SignInView`): broker URL field → `config()` → `ASWebAuthenticationSession` with the authorize URL. It shows this warning verbatim: "Anything running as you on this Mac can use this app to approve requests. Don't run agents on a Mac where you approve."
  - `MenuBarExtra(.window)`: label is the icon plus the pending count when > 0. Content: rows oldest first; collapsed row shows the credential names, client, risk badge and summary; expanded row shows the target and details, all as `Text(verbatim:)`. Buttons only for the request's `actions` (Deny, Approve, a "For…" menu of `grant:` minutes, Always behind a confirmation dialog), plus "Open in browser" (`NSWorkspace.open(browser_url)`). Shows "Assessing…" when `notified == false`.
  - `Notifications`: categories `ASB_APPROVE_DENY`, `ASB_DENY`, `ASB_NONE` chosen from `banner_actions`; post on `.newlyNotified` with `identifier = request id` and the Web Push title/text. An action calls `decide`; on `.alreadyDecided`, remove the delivered notification. Tapping the banner opens the menubar window scrolled to that request. `removeDeliveredNotifications` for ids that left the pending list.
  - `PresenceReporter`: every 10 s, active = not locked (`com.apple.screenIsLocked`/`screenIsUnlocked` distributed notifications) and `CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: .null) < 120`; sends `presence(active: true)` every 10 s while active (the broker's presence `ttl_s` defaults to 25 s, so 30 s would lapse), and `active: false` once on transition.
  - `LoginItem`: a toggle using `SMAppService.mainApp`.
- [ ] **Step 2: Run** `xcodebuild` in CI (the `app` job) — expected: build succeeds.
- [ ] **Step 3: Manual verification on the author's Mac** against the home-lab broker with `approver_api` configured:
  1. Sign in.
  2. A low-risk `asb http` request shows a banner with Approve/Deny; Approve from the banner, and the agent gets its response.
  3. A `credential` request shows only Deny plus "Open in browser".
  4. A request decided on the phone disappears from the popover.
  5. With the Mac active, the phone gets no push until the fallback; after locking the screen, the phone push arrives.
  6. A summary containing Markdown shows literally.
- [ ] **Step 4: Commit** `git commit -m "macos: ASBApprover menubar app and build job"`.

## Execution notes

- Track the work in beads: one epic ("macOS menubar approver app") with a child per task, created before Task 1 starts.
- Tasks 1→2→3 are strictly sequential; Task 4 needs Task 3's final status codes; Task 5 needs Task 3's JSON; Task 6 needs Task 5.
- Swift tasks cannot be compiled on the Linux dev machine; their verification is the macOS CI job and the manual checklist.
