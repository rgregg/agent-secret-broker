# Telegram Approvals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deny and Approve buttons on the Telegram notification that decide the request in the chat.

**Architecture:** `TelegramNotifier` (secret_broker/notify.py) gains callback buttons and a long-poll loop
(`getUpdates`) that parses taps and checks user, chat and message. Each tap goes to one broker method,
`Broker.telegram_tap`, which audits refusals and sends accepted taps through `decide_via("telegram", ...)`, a new
token-required channel. `serve()` starts the poller.

**Tech Stack:** Python 3.12 stdlib (urllib, threading), unittest, a fake Telegram API on `ThreadingHTTPServer`.

**Spec:** docs/superpowers/specs/2026-11-17-telegram-approvals-design.md

## Global Constraints

- Buttons and polling exist only when the `telegram` entry has a non-empty `allowed_users`; without it, behavior
  is byte-for-byte today's (one URL button, no polling).
- `callback_data` is exactly `ASB|<approve|deny>|<rid>|<token>`; never longer than 64 bytes (else send no action
  buttons, link only).
- Channel `telegram`: `token_required=True`, `may_create_always=False`, no grants, no SSH rules.
- Approver string: `telegram:<numeric user id>`.
- No bot token, action token or raw callback data in any error, log, audit line, toast or page.
- Request kinds `credential`, `plan`, `guidance`, `session`, `sudo` get no buttons (already enforced in
  `Broker._push`; do not change that).
- Canaries only: `S3CR3T-...`, example.com, 127.0.0.1. Docs move with behavior (reference.md, setup.md).

## Review Focus

- A tap after the request was decided, expired or its token spent: toast "Already decided", no state change.
- Approve and Deny tapped quickly (or by two allowed users): only the first decides; the second gets 410.
- Callback data that is not ours (another bot's, garbage, oversize, a `deny` for an unknown rid): refused
  `malformed` or `message`, audited without echoing the data.
- The poll hitting network errors, 401 or 409: backs off, keeps running, logs a fixed label, never the token.
- Buttons from before a broker restart: the rid is not in the transport's map, refused `message`.

---

### Task 1: TelegramNotifier buttons, tap parsing and polling

**Files:**
- Modify: `secret_broker/notify.py` (`TelegramNotifier`, `build`)
- Test: `tests/test_telegram_actions.py` (new)

**Interfaces:**
- Produces:
  - `TelegramNotifier(bot_token, chat_id, api_base=..., timeout=15, allowed_users=())`; `allowed_users` is a
    tuple of ints. `supports_actions` is `("approve", "deny")` when non-empty, else `()` (instance attribute).
  - `TelegramNotifier.actions_enabled -> bool`.
  - `TelegramNotifier.poll_once(on_tap, timeout=30) -> int`: one `getUpdates` call (`offset`,
    `timeout`, `allowed_updates: ["callback_query"]`, HTTP timeout `timeout + 10`), advances `offset` past every
    update returned, calls `on_tap(tap)` per callback query, answers it with `answerCallbackQuery` and the text
    from `tap_text(status, decision)`, returns the number of callback queries handled. Raises `NotifyError` on API failure.
  - `tap` is a dict: `{"rid": str|None, "decision": str|None, "token": str|None, "user": int|None,
    "refused": None|"malformed"|"user"|"chat"|"message"}`. `on_tap(tap) -> int` returns an HTTP-style status
    (200, 403, 404, 410, or 0 for refused-before-decide).
  - `tap_text(status, decision) -> str`: 200 -> "Approved" or "Denied"; 410 -> "Already decided"; anything else
    (0, 403, 404, ...) -> "Not allowed".
  - `TelegramNotifier.start_polling(on_tap, log) -> threading.Thread`: daemon loop of `poll_once`; on
    `NotifyError` calls `log(label)` with label from `poll_error_label(exc)` and sleeps backoff 1, 2, 4 ... capped
    at 60 s, reset on success. `409` logs `"conflict"` once per run of consecutive 409s.
  - `poll_error_label(exc) -> str` in `{"unauthorized", "conflict", "network", "http"}`; `_call` attaches
    `exc.status` (int or None) to the NotifyError it raises.
  - `build()`: telegram entries read `allowed_users`; it must be absent, or a list of ints (`bool` excluded), each
    `> 0`, at most 20; else `ValueError("notify[i].allowed_users must be a list of Telegram user ids")`.

- [ ] **Step 1: Write the failing tests** in `tests/test_telegram_actions.py`. Reuse the fake API shape from
  `tests/test_e2e.py:FakeTelegram`, extended so tests can queue `getUpdates` results and record every call.
  Tests (assert exact bodies):
  - `test_no_allowed_users_is_todays_message`: `send()` body has one keyboard row with one URL button, no
    `callback_data` anywhere; `supports_actions == ()`; `poll_once` is never needed (no thread started by `build`).
  - `test_buttons_carry_rid_and_token`: with `allowed_users=(111,)` and a notification from `make_notification`
    (risk low), row 0 is `[{"text": "Deny", "callback_data": "ASB|deny|<rid>|<tok>"}, {"text": "Approve", ...}]`
    and row 1 is the URL button; every `callback_data` is <= 64 bytes.
  - `test_policy_narrowing_drops_approve`: per-entry `action_policy={"approve_max_risk": "medium", "deny": True}`
    on a high-risk notification: only Deny.
  - `test_overlong_callback_falls_back_to_link`: rid of 40 chars: no callback buttons, URL button kept.
  - `test_tap_from_listed_user_in_chat_on_our_message`: after `send`, queue a callback query (from 111, chat
    4242, message 77, data for that rid): `on_tap` gets `refused=None` with rid/decision/token/user; answer text
    "Approved" for status 200; offset advanced (next `getUpdates` body has `offset = update_id + 1`).
  - `test_refusals` (subTest each): from 999 -> `user`; chat 5 -> `chat`; message 78 -> `message`; rid never
    sent -> `message`; data `"xyz"`, `"ASB|maybe|r|t"`, 200-char data, missing `message` -> `malformed`. Each
    answers "Not allowed". Positive control in the same test: one valid tap gives `refused=None`.
  - `test_410_says_already_decided`.
  - `test_resolved_removes_buttons`: `resolved(n, "approved")` sends `editMessageText` with no `reply_markup`
    and `"-> APPROVED"`; a later tap on that rid is refused `message`.
  - `test_poll_errors_are_labelled_without_token`: fake answers 401, 409, 500, and a closed port in turn;
    `poll_error_label` gives `unauthorized`, `conflict`, `http`, `network`; no label or exception text contains
    the bot token (use `"123456:S3CR3T-BOT"`).
  - `test_build_allowed_users`: valid list builds with actions enabled; `["111"]`, `[True]`, `[0]`, `"111"`, 21
    ids each raise the named ValueError.

- [ ] **Step 2: Run them to see them fail**

Run: `python tests/run_tests.py -k test_telegram_actions`
Expected: FAIL (`allowed_users` unexpected keyword / no `poll_once`).

- [ ] **Step 3: Implement** the Interfaces above in `secret_broker/notify.py`. Keep `self._msg_ids` keyed by
  tag and add `self._by_rid` (rid -> message id) under a lock; `resolved()` pops both. Parse `callback_data` with
  `str.split("|")` into exactly four parts, decision in `("approve", "deny")`, rid and token matching
  `[A-Za-z0-9_-]{1,64}` (no regex on unbounded input: check length <= 64 bytes first). Update the class docstring
  (no longer "deliberately no callback buttons").

- [ ] **Step 4: Run them to see them pass, plus the existing Telegram tests**

Run: `python tests/run_tests.py -k telegram`
Expected: all pass, including `tests/test_e2e.py` `Transports` and `tests/test_notify_pipeline.py`.

- [ ] **Step 5: Mutation-check** each guard (user, chat, message, length, decision set): break it, confirm a test
  fails, restore.

- [ ] **Step 6: Commit** `notify: Telegram Approve/Deny buttons and a getUpdates poller (allowed_users)`.

### Task 2: the `telegram` decision channel in the broker

**Files:**
- Modify: `secret_broker/broker.py` (`CHANNELS`, new `Broker.telegram_tap`, `serve`, channel label map near
  line 5668), `secret_broker/audit_api.py` (`CHANNELS`)
- Test: `tests/test_telegram_actions.py` (broker classes built on `test_e2e.Harness`)

**Interfaces:**
- Consumes: Task 1's `tap` dict, `on_tap` contract, `start_polling(on_tap, log)`, `actions_enabled`.
- Produces:
  - `CHANNELS["telegram"] = Channel(token_required=True, may_create_always=False)`.
  - `Broker.telegram_tap(tap) -> int`: if `tap["refused"]`, audit and return 0; else `decide_via("telegram",
    rid, decision, f"telegram:{user}", token=token)[0]`; a non-200 result is also audited.
  - Audit event `telegram_decide_refused`: fields `reason` (`malformed|user|chat|message` or `status`), `status`
    (int, for decide refusals), `user` (`telegram:<id>` or `telegram:unknown`), `rid` only when the reason is
    `status`. At most 10 lines per 60 s window (window clock: `self.presence_clock`); further ones are counted and
    the first line of the next window carries `suppressed: n`.
  - Audit event `telegram_poll_error`: field `error` (the label).
  - `serve()`: for each leaf of `broker.notifier` with `actions_enabled` true, `leaf.start_polling(
    broker.telegram_tap, lambda label: broker.log("telegram_poll_error", error=label))`. Tests that need no
    thread construct the transport without `allowed_users` or call `poll_once` themselves.
  - `audit_api.CHANNELS` and the label map gain `"telegram"` / `"Telegram"`.

- [ ] **Step 1: Write the failing tests** (Harness with a real `TelegramNotifier(allowed_users=(111,))` against
  the fake API as `self.notifier`; drive taps by queueing updates and calling `poll_once` directly; set
  `cfg["store"]`/risk so the request is pending):
  - `test_approve_from_telegram_releases`: a pending http request; tap Approve; the agent's request ends
    `approved`; the `approved` event has `channel: "telegram"`, `approver: "telegram:111"`; the message is then
    edited with `-> APPROVED` and no `reply_markup`.
  - `test_deny_from_telegram`.
  - `test_second_tap_is_410`: Approve then Deny on the same message: second toast "Already decided", status stays
    approved, one `approved` event.
  - `test_refused_tap_is_audited_and_decides_nothing`: tap from 999: request still pending, one
    `telegram_decide_refused` with `reason: "user"`, `user: "telegram:999"`; the audit file contains neither the
    action token nor the callback data (positive control: the token was on the fake API's sendMessage body).
  - `test_no_buttons_for_page_only_modes` (subTest per mode `credential`, `plan`, `session`): sendMessage body has
    no `callback_data`; a forged tap with a guessed token gets 403 or 404 and the request stays pending.
  - `test_telegram_cannot_create_always`: `decide_via("telegram", ..., always=True)` never creates a standing
    approval, whatever status it returns (assert the standing-approval store is unchanged; positive control: the
    same call on `dashboard` does create one).
  - `test_refusal_audit_is_coalesced`: 25 refused taps in one window -> exactly 10 lines; advance the clock 61 s,
    one more -> its line has `suppressed: 15`.
  - `test_serve_starts_poller_only_when_enabled`: `serve()` with `allowed_users` calls `start_polling` once (patch
    it); without, never.

- [ ] **Step 2: Run them to see them fail**

Run: `python tests/run_tests.py -k test_telegram_actions`
Expected: FAIL (`ValueError: unknown channel telegram`, no `telegram_tap`).

- [ ] **Step 3: Implement** the Interfaces above.

- [ ] **Step 4: Run them to see them pass**

Run: `python tests/run_tests.py -k "telegram or ha_hook or audit_api or notify"`
Expected: all pass.

- [ ] **Step 5: Mutation-check**: drop `token_required` on the channel, skip the refused branch, log the token,
  remove the coalescing cap; each must fail a test. Restore.

- [ ] **Step 6: Commit** `broker: decide from Telegram buttons (channel telegram, audited refusals)`.

### Task 3: docs and full verification

**Files:**
- Modify: `docs/reference.md` (notify transports bullet, Notifier contract "Telegram always gets none",
  Decision channels table row `telegram | yes | no | no | no`, the plans "Notifications" sentence if it lists
  Telegram, a security note next to the HA one), `docs/setup.md` (telegram config line with `allowed_users`, how to
  find your user id, that the bot must have no webhook).

- [ ] **Step 1:** Write the doc changes. Security note text must say: anyone who controls a listed Telegram account
  can approve; request text is stored on Telegram's servers; Telegram can't approve credential entry, plans,
  guidance, sessions, root commands, Always or timed approvals.
- [ ] **Step 2:** Run the whole suite: `python tests/run_tests.py -j 4` -> 0 failing units.
- [ ] **Step 3:** `python tests/test_test_quality.py` passes (it runs in the suite; confirm it is included).
- [ ] **Step 4: Commit** `docs: Telegram Approve/Deny buttons`.
