# agent-secret-broker

Give a CLI agent (Claude Code, scripts, anything that shells out) access to
credentials **only after a human approves each use** on their phone, with a full
audit trail. Self-hosted, no MCP.

    agent                         broker                          you
      | secret-run http NAME ...    |                              |
      |---------------------------->|  push: "NAME, GET /x [LOW]"  |
      |                             |----------------------------->|
      |                             |      tap -> SSO login -> Approve
      |                             |<-----------------------------|
      |<-- response (secret masked) |                              |

The agent never holds the vault password or the approval channel. Approval
happens on a page that only your authenticated SSO session can reach.

## Modes

    secret-run list [--json]             what credentials exist? name, vars, hosts
    secret-run which HOST|URL            is a credential available? (no approval, no push)
    secret-run http NAME METHOD URL [-H 'K: V']... [-d BODY | -d @file | -d @-]
    secret-run NAME[,NAME] -- command args...

- **`http` (enforced).** The broker makes the call itself, only to the secret's
  `allowed_hosts`, never follows redirects, and masks the secret in the response.
  `{{VAR}}` placeholders are substituted inside the broker in the URL, headers
  and body. The value never leaves the broker.
- **env (advisory).** The value is released to the requesting host and injected
  into the command's environment. The command shown in the prompt is what the
  client *said* it would run; approve it only if it looks right.

### Vault access: `backend.serve`

By default each vault read or write launches the `bw` CLI. Set
`"serve": true` in the `backend` block to use one long-lived `bw serve`
(127.0.0.1, random port, inside the container) instead: a request becomes a few
local HTTP calls (milliseconds, not seconds) and the access token is refreshed
only when it really expires, so a burst of requests cannot trip Vaultwarden's
login rate limit. Idle logout still locks the vault, stops the process and logs
out. In this mode items are matched by exact name (case-insensitive) or id; the
CLI's substring search can make a name ambiguous or collide with a longer one.

`bw serve` has no authentication of its own, so the controls are around it:
it listens only on 127.0.0.1 inside the container (nothing else runs there and
the port is not published), it is unlocked only while in use plus the idle
window, the master password and session key never cross the HTTP port (the
session goes in the child's environment), and the broker refuses to talk to it
unless the listener on that port belongs to the process it started. Anyone who
can already run code in the container could read the same state from the
persistent `/bw` volume.

## The vault is the catalog

There is no list of secrets in a config file. A secret is a vault item that
carries one custom text field named `broker`, holding a JSON object:

    {"name": "grafana",
     "allowed_hosts": ["grafana.example.com"],
     "vars": {"GRAFANA_TOKEN": {"field": "notes"}},
     "approval": "prompt"}

- `name` is optional (default: the item name, lower-cased). `vars` maps each
  placeholder variable to a `field` (`notes`, `password`, `username`, a custom
  field name, or `auto`) and optionally a `key` inside a multi-value field
  (below). A secret can only use fields of its own item (an entry that names
  another item, or the reserved `broker`/`previous_value` fields, is rejected),
  so metadata on one item can never pull another item's value. `approval` is
  `prompt` (default) or `allow`.
- `allowed_hosts` may be omitted for credentials that are not HTTP tokens (a
  Wi-Fi password): such a secret can never be used in `http` mode, only fetched
  with approval in env mode.
- **Self-signed devices (TLS).** Normal certificate verification applies unless
  the metadata says otherwise:
  `"tls_fingerprint": "sha256:<hex>"` (or a list of them, for a secret that
  spans several devices) accepts exactly those certificates and nothing else (CA
  and hostname are not consulted; `secret-run fingerprint HOST[:PORT]` prints
  one), or `"tls_verify": false` turns verification off, which is only
  accepted when every allowed host is a private address or `.lan`/`.local`
  name. Prefer the pin: it still fails loudly against an impersonator. A
  request using several secrets with different TLS settings gets the strict
  default.
- Items without that field are invisible to the broker. One item carries one
  secret. If two items claim the same secret name, *both* are dropped and the
  conflict is audited, so a look-alike item cannot shadow a real one.
- The broker reads the catalog from the vault at startup, when a request
  names an unknown secret, and when its cache is a minute old; `list` and
  `which` serve the cache and refresh it in the background. Add or edit an item
  in any Bitwarden client and the broker picks it up without a restart.
  Entries that fail validation are skipped and listed in the `catalog_loaded`
  audit event (fail closed).
- `store` creates the item, its value and this metadata in one write, so there
  is nothing to keep in sync and nothing to roll back. "Always allow" and
  revoking it edit `approval` on the item, with who and when.
- The settings that remain (vault URL, notify transports, risk threshold,
  ports) are wiring, not a catalog. They come from the `BROKER_CONFIG`
  environment variable (a JSON object, see `deploy/config.example.json`) and/or
  `--config FILE`.
- **Trust note:** because policy lives in vault items, anyone who can edit the
  collection can widen a secret's `allowed_hosts` or set `approval: allow`
  without passing the approval gate. Keep write access to that collection to
  people you trust as much as the broker. (The broker's own account is
  writable by design, so `store`/`update` can work.)
- Moving from an older config file: `python -m secret_broker.import_catalog
  --config /data/config.json [--apply]` writes each secret's metadata onto its
  item (dry run by default).

## Policy, risk, discovery

`list` and `which` never touch the vault or send a notification; each call is
recorded as a `discovery` event. They return names, placeholder variable names,
allowed hosts, never values. Approval policy is deliberately
not exposed: whether a credential prompts must not influence which one an agent
chooses.

Per secret in the broker config:

    "approval": "prompt"        # default: every use needs a phone approval
    "approval": "allow"         # no prompt (http mode only unless auto_modes adds env)
    "allowed_hosts": ["api.example.com"]

Every request is rated low/medium/high by the analysis model (the `summary`
block below) and nothing else: there are no per-secret ratings and no rule
baseline. If the model is not configured, fails, times out or returns anything
else, the request counts as **high**, so a missing verdict can only make the
broker ask more. The rating is shown on the push and approval page and recorded
in the audit log (`assessed`). Because the model reads attacker-influenced
text, treat it as a hint for a human who also sees the raw request; where it
carries weight is `allow` secrets: with `"risk": {"escalate_auto_at": "high"}`
such a secret is still prompted at or above that level, so set it to `medium`
if you want only `low` requests released unprompted.

Optional one-line summaries come from a cheap OpenRouter model (`summary`
block). They are labelled unverified and never replace the raw request.

## Notification transports

A transport only delivers the **link** to the approval page; approving always
happens on that page. Configure one or more under `notify`; a request is
delivered if at least one succeeds.

    "notify": [
      {"type": "ticker",   "ha_url": "...", "ha_token_file": "...", "category": "general"},
      {"type": "telegram", "bot_token_file": "...", "chat_id": "123456789"}
    ]

- `ticker`: Home Assistant `ticker.notify`; delivery is verified, since
  Ticker returns 200 even when it drops a notification.
- `telegram`: message with one URL button to the approval page (no callback
  buttons, so nothing can be approved from inside the chat). The message is
  edited to APPROVED/DENIED/EXPIRED when settled.
- Add your own: implement `send(title, message, url, tag)` (raise `NotifyError`
  on failure) and optionally `resolved(tag, status)`.

Messages cross whatever service carries them and include secret names, the
method and URL, and the approval link (single use, expires with the request,
and useless without your SSO session).

## Storing and updating credentials

An agent can add or rotate credentials, always with a fresh approval:

    printf '%s' "$NEW_TOKEN" | secret-run store myapi --hosts api.example.com [--field notes] [--item "Vault item"]
    printf '%s' "$NEW_TOKEN" | secret-run update myapi

- **The value is only read from stdin** (or a hidden prompt on a terminal), never
  an argument, and it is never written to the audit log, notifications, the
  approval page (which shows only its size) or the config.
- **`store` creates** a vault item in the configured organization/collection and
  adds a secret entry to the config with the hosts you pass (`approval: prompt`). The approver sees the item, field and hosts.
- **`update` replaces** the value of an existing secret's field. Hosts and
  mapping cannot change, and the replaced value is kept in the item's
  `previous_value` field for rollback.
- **Item types:** `--field password` creates a Login item and `--field notes`
  (the default) a Secure Note; any other name is a hidden custom field. In
  the item's metadata a var may omit `field` (or say `"auto"`): reads and updates then
  use a Login's password or a Secure Note's text, whichever the item is.
- **Several values in one item:** put `KEY=value` lines (or a JSON object) in
  the note, then map each value to its own variable with a `key`:

      "vars": {"APP_ID":     {"item": "Example App", "key": "CLIENT_ID"},
               "APP_SECRET": {"item": "Example App", "key": "CLIENT_SECRET"}}

  The item is read once per request. A missing key fails the request without
  echoing values. `update NAME --var APP_SECRET` rewrites only that key and
  leaves the other lines (and comments) as they were; the whole previous text
  goes to `previous_value`.
- **Create needs no tap** (it is always rated low: it cannot read or change
  anything that exists, and the new secret still prompts on every use). It is
  recorded as `policy:auto-create`; set `"store": {"create": "prompt"}` to ask
  instead. **Update always needs a human**, regardless of a secret's `approval`
  policy, and is never eligible for "always allow".
- **No half-finished state:** if the config cannot be written after a create, the
  new vault item is removed again.
- Needs a vault account that can edit the target collection, and (when the
  vault has several) `backend.organization` / `backend.collection` to say where
  new items go. Use TLS in front of the client API: the value crosses it.

## Approving from the web UI

`/` on the approval listener is a live list of pending requests, each with
**Approve**, **Deny** and (where the usual rules allow it) **Approve and always
allow**. It is for when the phone is out of reach: open the site, sign in
through your SSO, decide. New requests appear within a few seconds, the tab
title shows how many are waiting, and with scripting disabled the same forms
still work as ordinary page loads.

It uses the same decision path as the push link (atomic claim, identity check,
always-allow eligibility, audit), recorded with `channel: dashboard`. Because
one signed-in session can now decide many requests, decisions are additionally
protected against cross-site requests:

- every decision carries a per-user token the page was rendered with, and a
  request without it is refused and audited (`csrf_refused`);
- `Origin` must match `approve_base_url` and `Sec-Fetch-Site` must be
  same-origin, so set `approve_base_url` to the exact public URL of this site;
- the page never contains a request's approval nonce (it decides by request id);
- a per-response Content-Security-Policy allows only the page's own script
  (`script-src` nonce), `connect-src 'self'`, and no framing.

The standing-approvals form uses the same token.

The approval listener trusts the identity header, so it must only ever hear from
your SSO proxy. Besides not publishing its port, set
`"approval_trusted_peers": ["172.23.0.0/16"]` (the proxy's network) and it
refuses every other peer with a 403 before looking at any header. This matters
more now that the dashboard can decide many requests: a caller that could reach
the listener and forge the header would otherwise be able to list and approve
them all.

### Browser notifications

The dashboard has a **Notify me on this device** button. Click it once, allow
notifications in the browser, and a notification titled "Approval needed" (body:
the secret names, nothing else) appears when a request arrives while the page is
in a background tab or window; clicking it brings the page forward. The choice is
remembered per browser. This works only while the page is open somewhere: it is
a fallback and a convenience, not a replacement for a push transport. Nothing
leaves the page, no third-party service is involved, and the notification never
contains a URL, request body or value. On iOS the site must be installed to the
home screen as a web app before the browser will allow notifications.

If nothing appears, use **Send a test notification** and read the line under the
buttons. The usual cause is the operating system, not the page: the browser
needs its own permission in the OS notification settings (macOS: System
Settings > Notifications > the browser), and Focus or Do Not Disturb modes hide
notifications too.

## Request history

`/history` on the approval listener (same SSO gate and identity check as the
approval page) lists recent requests with how each ended: **approved**,
**auto-approved** (policy), **denied**, **expired**, **failed**, or **pending**.
Each row shows the time, secret, what was asked (method and URL without its
query string, the store operation, or "env"), risk, who decided, and how long
the decision and delivery took. "(not collected)" marks an approval whose
result the client never fetched. Filters: outcome, secret, mode; 50 per page.

It is derived from the audit log, which stays the only record: events sharing a
request id are folded into one row, incrementally, with at most the most recent
5000 requests kept in memory. No values, header values or bodies are ever
shown (the log does not contain them).

## Always allow

On the approval page, **Approve and always allow `NAME`** approves this request
and records `"approval": "allow"` in that secret's vault item metadata (with who
and when), effective immediately. It is offered only
when it would mean something:

- HTTP mode only: the broker makes the call, so the value never leaves it. Never
  offered for env mode.
- One secret per request.
- Not from a request that is itself rated at or above `risk.escalate_auto_at`.

The rules are enforced on the server, so a forged form field is refused and
audited (`policy_change_refused`). Changes are audited as `policy_changed`
(`policy_change_failed` if the file could not be written; the in-memory policy
is then left unchanged). `/policies` on the same SSO-gated listener lists
standing approvals and can put one back to "prompt"; it can only tighten.

## Vault session lifetime

The vault is not kept open. With the `bw` backend it is unlocked on demand,
kept for `idle_timeout` seconds (default 300) after its last use, then logged
out (`backend_closed` in the audit log). With `prewarm` (default true) it is
unlocked when a request is *created*, so the slow login/unlock overlaps with the
human picking up their phone; a run of approvals within the window is fast.
Nothing is released before approval either way.

Mount a persistent directory for the CLI's state (`BITWARDENCLI_APPDATA_DIR`,
see `deploy/compose.yaml`). The CLI keeps its device identifier there across
logouts; without it, every login from a fresh container is a *new device* and
your vault server emails you ("new device logged in") each time.

Approving or denying takes effect immediately: the decision is audited
(`decided`) and the approver's page answers at once. Releasing the secret
happens in the background; if that fails, the failure goes to the audit log and
the requesting client, never to the approver.

## Audit

JSONL, hash-chained, mode 0600, on the broker host. Never contains secret
values, header values or bodies.

Events: `startup` (policies in force), `requested`, `assessed`, `notified`,
`secret_read`, `approved`/`denied`/`expired`/`failed` (with `via` user or
policy, approver, reported client IP, latency), `http_executed`, `delivered`,
`escalated`, `stored`, `policy_changed`, `policy_change_refused`, `policy_change_failed`, and
security events `auth_failed`, `rejected`, `approval_viewed`,
`approval_forbidden`, `approval_stale`, `bad_request`, `discovery`.

    python -m secret_broker.audit verify audit.jsonl
    python -m secret_broker.audit show audit.jsonl approved names=example-api

`verify` detects edited or removed records mid-file. Tail truncation is not
detectable from the file alone: keep the log off the agent's host.

## Deploying

See `deploy/compose.yaml` and `deploy/config.example.json`. You need:

1. A **secret backend**: a Bitwarden/Vaultwarden account (a dedicated read-only
   account scoped to one collection) or, for testing, a JSON file.
2. An **SSO-authenticating reverse proxy** in front of port 8801 (the approval
   listener), passing the authenticated username in `identity_header`. Do not
   publish 8801 anywhere else: the broker trusts that header.
3. A **notify transport**.
4. The CLI on the agent's host with `SECRET_BROKER_URL` / `SECRET_BROKER_KEY`
   (or `~/.config/secret-broker/client.json`). The client key only lets a
   process *create requests*, which still need your approval.

Images are built by CI on every push to `main` and published to
`ghcr.io/rgregg/agent-secret-broker`.

## Threat model, honestly

- **Protects against** an agent (or prompt injection steering it) using
  credentials without you noticing: every use is approved or explicitly
  allow-listed, and logged somewhere the agent cannot rewrite.
- **Does not protect against** an agent that already has other credentials to
  your SSO provider, vault, or notification service (e.g. an admin API token in
  its home directory): those bypass the gate. Move them behind the broker.
- **env mode is advisory** (see above). Prefer `http` mode.
- Output masking is exact-match; a program that transforms a secret before
  printing it (base64, splitting) defeats it.

## Development

    python3 -m unittest discover -s tests

Python 3.12, no third-party dependencies.

## License

MIT
