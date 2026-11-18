# Telegram approvals: Approve and Deny buttons in the chat

Status: approved 2026-11-17 (short design).

## Intent

See an approval request in Telegram and decide it there, without opening the approval page. Today the Telegram
transport sends the card text and one "Review request" link; approving needs the SSO-gated page.

## Goals

- Deny and Approve buttons on the Telegram message for every request that has buttons on other token channels,
  at every risk level the action policy allows (default `approve_max_risk: high`, so all levels).
- A tap decides the request with no page visit; the message is then edited to show the outcome and loses its
  buttons.
- The "Review request" link stays, for the full card.

## Non-goals

- Anything that needs input stays on the page: entering a credential value, Always and timed approvals, SSH
  rules. The request kinds that already get no buttons anywhere (`credential`, `plan`, `guidance`, `session`,
  `sudo`) get none in Telegram either. Telegram does not become the one exception.
- A webhook. The broker is reachable from the internet, but a webhook needs a path that bypasses Authentik,
  guarded only by Telegram's secret header. Polling is just as fast and opens nothing. A webhook can come later.

## Anti-goals

- A tap from anyone but a listed Telegram user, from another chat, or on a message the broker did not send,
  decides anything.
- The bot token or any request secret appears in an error, log, audit line or page.

## Approaches

- **Long polling (chosen).** A broker thread holds `getUpdates` (long poll, `allowed_updates:
  ["callback_query"]`) open to api.telegram.org; a tap arrives at once. Outbound only, no Authentik change.
  Costs one thread and one open connection, and the bot cannot also have a webhook set.
- **Webhook.** Telegram POSTs taps to a public path; needs an Authentik bypass and a `secret_token` header
  check. Rejected for now: a public unauthenticated path is new attack surface for no speed gain.

## Decided

- **Config.** The `telegram` notify entry gains `allowed_users` (list of Telegram user ids, integers). Buttons
  and polling exist only when it is non-empty, the way the ticker buttons need `ha_hook`. Without it the
  transport behaves exactly as today (link only). The per-entry `actions` override still applies, so
  `{"approve_max_risk": "medium"}` narrows Telegram alone. Startup validation names the field
  (`notify[i].allowed_users`).
- **Buttons.** `supports_actions = ("approve", "deny")` when enabled. Row 1: Deny, Approve (callback buttons);
  row 2: the "Review request" URL button. `callback_data` is `ASB|<decision>|<rid>|<token>`, the same single-use
  per-request token as Web Push and the HA hook (57 bytes, under Telegram's 64-byte limit).
- **A tap is accepted only if** `from.id` is in `allowed_users`, `message.chat.id` is the configured chat, and the
  message id is one the transport sent for that `rid`. Then it goes through `decide_via("telegram", rid,
  decision, "telegram:<user id>", token=...)`.
- **Channel.** New `CHANNELS["telegram"]`: `token_required=True`, `may_create_always=False`, no grants, no SSH
  rules. Same enforcement as `push`/`ha`: a decision must be one of the offered actions.
- **After a tap.** `answerCallbackQuery` with a short fixed result ("Approved", "Denied", "Already decided",
  "Not allowed"), never request details. The message is edited to the outcome (existing `resolved()` path) with
  the action buttons removed.
- **Refusals** are audited as `telegram_decide_refused` with a fixed reason (`user`, `chat`, `message`,
  `malformed`, or the decide status) and the sender's numeric id; never the token or callback data. Coalesced
  per window so a flood cannot fill the log.
- **Polling thread.** Started by the broker when enabled, stopped on shutdown. Tracks `offset`. On error it backs
  off (capped) and logs a fixed label; a `409 Conflict` (webhook set elsewhere) is logged once by name. Errors
  never include the bot token (it is in the URL).
- **Tests** run against a fake Telegram API (the transport already takes `api_base`). Each guard (wrong user,
  wrong chat, unknown message, stale/spent token, a mode with no buttons, an action not offered) has a test that
  fails when the guard is removed.
- **Docs.** `docs/reference.md` (transport, decision channel table, security note), `docs/setup.md`. The PR states
  that this, like the HA buttons, lets a channel other than the signed-in page approve: whoever controls the
  listed Telegram account can approve, and request text sits on Telegram's servers (bots are not end-to-end
  encrypted).

## Left to the builder

Thread structure and backoff numbers, the coalescing window, how the transport hands taps to the broker (a
callback set at broker start is the expected shape), and the exact fake-API test harness.
