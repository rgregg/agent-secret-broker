# Reference

How the broker works, in detail. For installing and configuring it see
[setup.md](setup.md); for the command line and agent integration see
[cli.md](cli.md).

## Using credentials: modes

    asb list [--json]             what credentials exist? name, vars, hosts
    asb which HOST|URL            is a credential available? (no approval, no push)
    asb http NAME METHOD URL [-H 'K: V']... [-d BODY | -d @file | -d @-]
    asb NAME[,NAME] -- command args...
    asb help COMMAND              usage + example for one command
    asb guide                     manual for agents: workflow, {{VAR}}, approvals, exit codes

- **`http` (enforced).** The broker makes the call itself, only to the secret's
  `allowed_hosts`, never follows redirects, and masks the secret in the response.
  `{{VAR}}` placeholders are substituted inside the broker in the URL, headers
  and body. The value never leaves the broker.
- **env (advisory).** The value is released to the requesting host and injected
  into the command's environment. The command shown in the prompt is what the
  client *said* it would run; approve it only if it looks right.

### SSH keys: the broker signs, the key never leaves

A secret can be an SSH private key. It is never released or substituted into a
request; instead `asb ssh-agent` serves the ssh-agent protocol on a private local
socket, and every signature ssh asks for becomes a broker request (mode
`ssh_sign`) that you approve like any other.

    asb store deploy --ssh < ~/.ssh/id_ed25519                      # moves the key in
    asb ssh-agent -- git push                                          # one approval per login
    eval "$(asb ssh-agent)"                                            # or keep an agent running

- **Stored as a Bitwarden SSH key item** (item type "SSH key", with private key,
  public key and fingerprint), so the Bitwarden apps show it as one. `store --ssh`
  creates that item and its metadata, `{"ssh": true, "ssh_public_key":
  "ssh-ed25519 AAAA...", "vars": {"DEPLOY_SSH_KEY": {"field": "private_key"}}}`,
  deriving the public key from the value. An SSH key item you add to the broker's
  collection yourself is adopted automatically, signing-only. `asb list` shows the
  key with no variables, and `list`/`which` expose only the public half.
- **Always on.** Run one long-lived agent on a fixed socket and point ssh at it, so
  `ssh`, `git` and `scp` use the broker's keys with no environment setup. Each
  login still waits for your approval.

      # ~/.config/systemd/user/asb-ssh-agent.service
      [Unit]
      Description=asb SSH agent (keys stay in the secret broker)
      [Service]
      ExecStart=%h/.local/bin/asb ssh-agent --socket %t/asb-agent.sock
      Restart=on-failure
      [Install]
      WantedBy=default.target

      # ~/.ssh/config  (%t is $XDG_RUNTIME_DIR, usually /run/user/UID)
      Host *
          IdentityAgent /run/user/1000/asb-agent.sock

  Enable it with `systemctl --user enable --now asb-ssh-agent`. `--socket` replaces
  a stale socket, refuses to start over a live one, requires a directory only you
  can write to, and removes the socket on stop.
- Only unencrypted OpenSSH-format ed25519, ECDSA and RSA (2048+ bits, SHA-2
  signatures only) keys are accepted: the broker is what protects the key, so
  there is no passphrase to type. Remove a passphrase from a copy with
  `ssh-keygen -p -N '' -f COPY` before storing it, then delete the on-disk key.
- An update must carry the same key (same public key); a different key is a new
  credential.
- **What the prompt can and cannot tell you.** SSH signs a login with the account
  name and a session id but not the host. The prompt says what the bytes say
  ("log in over SSH as 'deploy'", or "sign a message, namespace 'git'" for commit
  signing) and names the key, but the host a client connects to is not
  something the broker can see or enforce, unlike `http` mode's `allowed_hosts`.
  The grants are therefore per key and per use: keep a key's server-side
  `authorized_keys` access as narrow as you would for a deploy key.
- `approval: allow` only auto-approves signing if `auto_modes` includes
  `ssh_sign`; "always allow" is never offered for it.

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

There is no list of secrets in a config file. Every login and secure note in the
broker's collection is a secret. An item can carry one custom text field named
`broker`, holding a JSON object, to set its details; without it the broker uses
defaults (next section). The object looks like this:

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
  and hostname are not consulted; `asb fingerprint HOST[:PORT]` prints
  one), or `"tls_verify": false` turns verification off, which is only
  accepted when every allowed host is a private address or `.lan`/`.local`
  name. Prefer the pin: it still fails loudly against an impersonator. A
  request using several secrets with different TLS settings gets the strict
  default.
- **Items without that field are adopted with defaults**, so you can copy an item
  from your own vault into the broker's collection and use it at once. The name is
  the item name (lower-cased); a login gives `<NAME>_USERNAME` and
  `<NAME>_PASSWORD`; a secure note gives `<NAME>_NOTE`; each custom field gives
  `<NAME>_<FIELD>`. `allowed_hosts` come from the login's URLs (no URL means env
  mode only, never `http`), and `approval` is `prompt`. Only the broker's own
  collection is ever adopted, and only logins and secure notes (cards and
  identities are ignored). Add the `broker` field to change any default (for
  example a TLS fingerprint for a self-signed device), or give it
  `{"disabled": true}` to hide an item from the broker. If an item's metadata
  names the same secret as an adopted item, the explicit one wins; two adopted
  items with one name drop each other. One item carries one
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
carries weight is `allow` secrets, through `risk.auto_approve_max`.

### Auto-approve level: `risk.auto_approve_max`

    "risk": {"auto_approve_max": "low"}      # none | low | medium | high, default low

An *auto-eligible* request (an `approval: allow` secret, in the modes it is
allowed for: http unless `auto_modes` adds more; plus creating a new credential
unless `store.create` is `prompt`) is released without a prompt only when its
model risk level is **at or below** this setting. Otherwise a human is asked
and an `escalated` event is audited.

| Value | Auto-approves |
|---|---|
| `none` | nothing: every request asks a human, even for `allow` secrets |
| `low` (default) | requests rated low |
| `medium` | low and medium |
| `high` | every risk level: risk never blocks an eligible request |

`high` does not make more secrets or modes eligible; `approval: prompt`
secrets and modes outside `auto_modes` still ask. A request with no model
verdict (no `summary` model configured, a timeout, an error, or an
unrecognised answer) counts as **high**. **That makes `high` fail open: with
it, an outage of the analysis model lets eligible requests through unprompted.**
Prefer `medium` or lower unless you want exactly that.

The effective value is recorded as `auto_max` on `escalated` events and on the
`approved` event of an auto-approval (shown in the request detail pop-over),
appears read-only on the Settings page, and is reported as
`features.auto_approve_max` by `GET /v1/status`. It is validated at startup
(`risk.auto_approve_max must be one of none, low, medium, high`).

Legacy spelling: `risk.escalate_auto_at` ("prompt at or above this level") is
still read when `auto_approve_max` is absent and means one level below it:
`low` = `none`, `medium` = `low` (the old default), `high` = `medium`. If both
are present `auto_approve_max` wins and a `config_warning` event is logged at
startup.

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
  Ticker returns 200 even when it drops a notification. With `ha_hook`
  configured (below) it also renders Approve/Deny buttons.
- `telegram`: message with one URL button to the approval page (no callback
  buttons, so nothing can be approved from inside the chat). The message is
  edited to APPROVED/DENIED/EXPIRED when settled.
- `webpush`: browser push, described under Web Push below.

### Notifier contract

The broker builds one `Notification` per request (in `Broker._push`, via
`notify.make_notification`) and hands it to every transport. Fields: `rid`,
`tag`, `title`, `text` (the full message), `names`, `risk` (`low|medium|high` or
None), `url`, `source`, `summary` (advisory, or None), `expires_at`, `actions`
(list of `Action(id, label)`, Deny before Approve) and `action_token` (opaque,
None when no action is offered).

A transport implements:

- `send(n)`: deliver it; raise `NotifyError` on failure.
- `resolved(n, status)` (optional, best effort): the request was
  approved/denied/expired/failed; `n` is the same Notification (built-ins match
  on `n.tag`).
- `supports_actions = ("approve", "deny")` (optional, default none): the action
  ids it can render. Each transport only receives the actions it supports, so
  Telegram always gets none, and ticker gets some only when `ha_hook` is
  configured. The token exists only if at least one
  transport carries actions; the broker keeps just its SHA-256.
- `action_policy` (optional): per-transport override, see below.

Deprecated: a transport written as `send(title, message, url, tag, names=None,
context=None)` / `resolved(tag, status)` still works. It is detected once, when
registered (`notify.adapt`, also applied when `broker.notifier` is assigned), and
wrapped; `context` is `{"rid", "risk", "action_token"}` and such a transport is
assumed to render both actions unless it sets `supports_actions`. Port to
`send(n)`.

### Action policy

Which buttons a request gets is decided centrally:

    "notify_actions": {"approve_max_risk": "high", "deny": true}

- `approve_max_risk`: `none|low|medium|high` (default `high`); Approve is offered
  when the request risk is at or below it (no verdict counts as high).
- `deny` (default `true`).

Precedence, most specific first: the `actions` object inside a `notify` entry
(e.g. `{"type": "webpush", "actions": {...}}`); for webpush only, the older
`webpush.actions` block; then top-level `notify_actions`; then the defaults.
An override replaces the policy as a whole (unset keys take the defaults, not the
global values). Invalid values stop the broker at startup naming the field
(`notify_actions.deny`, `notify[0].actions.approve_max_risk`, ...).

The policy is enforced at decision time, not only in what is shown: a decision
on a token channel (`push`, `ha`) must be one of the actions offered. The token
is shared by all transports, so the allowed set is the union of what any
transport offered; a valid token used for an action nobody offered is refused
403, audited as `decision_refused` (channel and attempted decision, never the
token), and the token is not spent. Dashboard and approval-link decisions are
unaffected.

Per-source rate-limit maps (the HA hook per IP, `/push/event` per user) are
capped at 4096 entries and never refuse a legitimate new caller for being full:
at the cap, expired entries are pruned and, if still full, the entry with the
oldest window start is evicted. The HA hook checks the hook key first (constant
time): a correct key gets the per-IP limit (60/min); a missing or wrong key gets
403 and is limited by ONE shared bucket (120/min across all sources, 429 when
exhausted, one `ha_decide_dropped` audit line per window) that creates no per-IP
state, so bad-key floods cannot lock out Home Assistant.

### Decision channels

Every decision (dashboard `/decide`, approval-link page, `/push/decide`,
`/v1/hooks/ha/decide`) goes through `Broker.decide_via(channel, rid, decision, actor, *,
token=None, always=False, nonce=None, peer=None, client_ip=None, grant_minutes=None, **audit_extra)`
-> `(http_status, request)`; `decision` is `approve|deny`. It alone enforces the
single-decision claim, the constant-time token check (spent on match; any
decision kills it), whether `always` may create an always-allow rule and `grant_minutes` a time-boxed grant (400 for a duration that is not on offer, nothing claimed), and the
audit fields (`channel`, `approver`, `approver_peer`, `approver_ip`, plus
`audit_extra`). Status: 200 decided, 403 bad/missing token, 404 unknown, 410
already decided/expired/token spent. Channels are registered in
`broker.CHANNELS` (unknown channel: `ValueError`); the caller does the channel's
own authentication (SSO header, CSRF/origin, `X-Requested-With`):

| Channel | token_required | may_create_always | may_create_grant |
| --- | --- | --- | --- |
| `dashboard` | no | yes | yes |
| `link` (`/a/<nonce>`) | no | yes | yes |
| `push` | yes | no | no |
| `ha` (`/v1/hooks/ha/decide`) | yes | no | no |

### Home Assistant action buttons (`ha_hook`)

Approve/Deny buttons on the iPhone `ticker.notify` notification (Home Assistant
companion app actionable notifications). Tapping one makes Home Assistant call
the broker, so nothing is opened. Config:

    "ha_hook": {
      "key_file": "/run/secrets/asb_hook_key",   // or "key": "..." (tests); >= 32 chars
      "allowed_devices": ["phone-1"]             // optional
    }

- Without `ha_hook` the endpoint answers 404 and the ticker transport carries
  no actions (buttons require a configured hook). The usual `notify_actions`
  policy decides which buttons a request gets (default: Deny and Approve for
  every risk level).
- The hook key is a dedicated secret, different from the agent client key
  (startup refuses equal keys). It is accepted only on this endpoint, and the
  client key is refused here with 403 and the hook key everywhere else with 401.
- `allowed_devices`: when non-empty, a `device` not listed (or absent) is refused
  403 and audited as `ha_decide_refused`. When empty or omitted every device is
  accepted and one `ha_hook_any_device` warning is logged at startup. The
  device is always recorded as approver `ha:<device or unknown>`; it is
  asserted by the caller, not verified.
- Startup validation names the field: `ha_hook.key_file` (missing, unreadable,
  short), `ha_hook.key`, `ha_hook.allowed_devices` (not a list of strings).

Ticker action ids (Deny first, title shown on the button):

    {"action": "ASB|deny|<rid>|<token>",    "title": "Deny"}
    {"action": "ASB|approve|<rid>|<token>", "title": "Approve"}

`rid` and `token` are url-safe (about 22 chars each; the id stays under 100
characters). The token is the same single-use per-request token as Web Push; the
broker keeps only its hash. The notification text is unchanged.

The buttons are sent inside the `data` object of the `ticker.notify` call
(`data.actions`), which Ticker passes through unchanged. Ticker's own top-level
`actions` field is only a switch (`category_default` or `none`); the broker never
sets it, and a list there would be rejected by the service schema.

Endpoint, on the client listener (the port agents use):

    POST /v1/hooks/ha/decide
    Authorization: Bearer <hook key>
    {"rid": "...", "token": "...", "decision": "approve|deny", "device": "phone-1"}

`device` is optional (empty = absent), max 64 chars of `A-Za-z0-9_.:-`. Body cap 2 KB. Status:
200 `{"ok": true, "decision": ...}` decided; 400 malformed; 403 bad or missing
hook key, wrong token, or device not allowed; 404 unknown request (or hook not
configured); 410 already decided, expired or token spent; 413 oversize; 429 more
than 60 calls/min from one source IP (first drop per window audited as
`ha_decide_dropped`). Responses never include request details. Decisions run
through `decide_via("ha", ...)`: audit `channel: ha`, approver `ha:<device>`,
never an always-allow rule.

Security: anyone who controls Home Assistant, or holds the hook key plus a
pending request's token, can approve that request. The token is single-use and
dies with the request, and the agent client key can never approve. The client
listener has no trusted-peer allow-list (only the approval listener has
`approval_trusted_peers`), so restrict who can reach port 8800 at the network
level if that matters.

Home Assistant example (placeholders only). `secrets.yaml`: `asb_hook_key`.

    rest_command:
      asb_decide:
        url: "https://broker.example/v1/hooks/ha/decide"
        method: POST
        headers:
          Authorization: !secret asb_hook_key_header   # "Bearer <hook key>"
          Content-Type: application/json
        payload: >-
          {"rid": "{{ rid }}", "token": "{{ token }}",
           "decision": "{{ decision }}", "device": "{{ device }}"}

    automation:
      - alias: Secret broker action buttons
        trigger:
          - platform: event
            event_type: mobile_app_notification_action
        condition:
          - condition: template
            value_template: "{{ trigger.event.data.action.startswith('ASB|') }}"
        action:
          - variables:
              parts: "{{ trigger.event.data.action.split('|') }}"
          - service: rest_command.asb_decide
            data:
              decision: "{{ parts[1] }}"
              rid: "{{ parts[2] }}"
              token: "{{ parts[3] }}"
              device: "{{ trigger.event.data.device_id | default('') }}"

`rest_command` headers are templates, so a secret can hold the whole header value
(`Bearer <key>`); `!secret` is resolved in YAML. An empty `device` counts as absent
(approver `ha:unknown`; refused if `allowed_devices` is set). The companion-app docs do not document `device_id` in the event
data; check the event in Developer Tools before relying on it.


Messages cross whatever service carries them and include secret names, the
method and URL, and the approval link (single use, expires with the request,
and useless without your SSO session).

## Storing and updating credentials

An agent can add or rotate credentials, always with a fresh approval:

    printf '%s' "$NEW_TOKEN" | asb store myapi --hosts api.example.com [--field notes] [--item "Vault item"]
    printf '%s' "$NEW_TOKEN" | asb update myapi

- **The value is only read from stdin** (or a hidden prompt on a terminal), never
  an argument, and it is never written to the audit log, notifications, the
  approval page (which shows only its size) or the config.
- **`store` creates** a vault item in the configured organization/collection, with
  the hosts you pass in its `broker` metadata (`approval: prompt`). There is no separate list to keep in sync.
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

The approval listener serves a small web app with three tabs: **Requests**,
**Policies** and **Settings**. **Requests** (`/`) is a live list of pending
requests, each with **Approve**, **Deny** and (where the usual rules allow it)
an **Always allow** menu, and below it the most recent decisions as a list. A
history row opens a pop-over with everything recorded for that request (see
[Request history](#request-history)); **Search and filter all history** expands
the same list in place. It is for when the phone is out of reach: open the site, sign in
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

The Revoke buttons on the Policies tab use the same token.

The approval listener trusts the identity header, so it must only ever hear from
your SSO proxy. Besides not publishing its port, set
`"approval_trusted_peers": ["172.23.0.0/16"]` (the proxy's network) and it
refuses every other peer with a 403 before looking at any header. This matters
more now that the dashboard can decide many requests: a caller that could reach
the listener and forge the header would otherwise be able to list and approve
them all.

### Browser notifications

**Settings** has a **Notify me on this device** button. Click it once, allow
notifications in the browser, and a notification titled "Approval needed" (body:
the secret names, nothing else) appears when a request arrives while the dashboard
is open in a background tab or window; clicking it brings the page forward. The choice is
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

### Web Push (notifications with the browser closed)

Add `{"type": "webpush"}` to `notify` and Settings gains **Notifications with the
browser closed** and **Devices receiving push** panels. Click **Enable on this device** once (the
browser asks permission, registers a small service worker and subscribes through
its vendor's push service); from then on a new request produces a notification
even with no tab open, and clicking it opens the dashboard. Remove a device from
the same panel; **Send a test push** checks the whole path.

- The message carries the title and the secret names only, encrypted for the
  browser (RFC 8291, authorised with a VAPID key, RFC 8292). It has no URL, no
  request body, no value and no approval nonce: the decision is still made on
  the dashboard, after SSO.
- Subscriptions (`webpush.json`) and the VAPID private key (`vapid.pem`) are
  kept next to the audit log, mode 0600, outside the vault. Override with
  `webpush.subscriptions_file` / `webpush.vapid_key_file`; `webpush.subject`
  (a `mailto:` or https URL) identifies the sender to the push service and
  defaults to `approve_base_url`.
- A subscription is a URL the broker will POST to, so only known push services
  are accepted (Chrome/Edge via FCM, Firefox, Safari, Windows); add others with
  `webpush.endpoint_hosts`.
- Delivery is weaker than the Home Assistant transport: a push service accepting
  a message is not proof that you saw it. Keep another transport configured as a
  backup; with several, a request is delivered if any one succeeds.
- This is the one transport with a third-party dependency (`pywebpush`, pinned
  in `requirements.txt` and installed in the image).
- A push can only reach a browser that is running. With the browser fully quit
  the push service holds the message (until its TTL, 5 minutes) and delivers it
  when the browser next starts. For "nothing is running", keep a phone transport
  such as the Home Assistant ticker configured alongside. To receive pushes with
  no window open, let the browser run in the background (Chrome: Settings >
  System > "Continue running background apps when Google Chrome is closed") and
  close the windows instead of quitting.
- Chrome only needs notifications allowed for the site and the browser (macOS:
  also System Settings > Notifications). The open-tab notification above stands
  down on a device that is subscribed, so you do not get two.

#### Approve / Deny buttons on the notification

The notification can carry **Deny** and **Approve** buttons (Chrome desktop and
Android), so a request is decided without opening the page. Tapping the body or
**Review** still opens the dashboard. Chrome shows at most `Notification.maxActions`
buttons (often 2): they are ordered Deny, Approve, Review, and the worker keeps
only as many as the browser allows. The visible text stays names-only.

```json
"webpush": {"actions": {"approve_max_risk": "high", "deny": true}}
```

(This block is the webpush override of the global `notify_actions` policy; see
Action policy above.)

- `approve_max_risk`: `none` | `low` | `medium` | `high` (default `high`, so every
  request gets Approve). A request gets Approve only when its risk level is at or
  below this; `none` removes Approve, `low` offers it only for low-risk requests.
  A request with no risk verdict counts as high.
- `deny` (default `true`): show the Deny button.
- An invalid value stops the broker at startup, naming the field.

The server picks the buttons per notification and lists them in the (encrypted)
payload: `{"title","body","tag","actions":["deny","approve"],"rid":"...","token":"..."}`.
`rid` and `token` are present only when at least one button is listed. The token
is random (128 bits), bound to that request id, single use; only its SHA-256 is
kept in memory, never logged or written to the audit log or history, and it dies
when the request is decided (by any channel), expires, or the broker restarts.

`POST /push/decide` (approval listener, same SSO identity and trusted-proxy checks
as every other POST there; the worker's fetch sends the SSO session cookie).
It requires `X-Requested-With: asb`, `Content-Type: application/json` and a
same-origin request; no CSRF form token, since the single-use token plays that
role. Body (max 2 KB): `{"rid": "...", "token": "...", "decision": "approve"|"deny"}`
(`rid` optional; without it the token alone selects the pending request).

| Status | Meaning |
| --- | --- |
| 200 `{"ok":true,"decision":...}` | decided |
| 403 | missing guard header / content type / cross-site, or wrong token |
| 404 | unknown request id |
| 410 | already decided, expired, or token already spent (no state change) |
| 400 / 413 | malformed body / body over 2 KB |

Responses never contain request details, URLs or values. The decision runs
through the same code as the dashboard `/decide` (same single-decision claim,
checks and audit events) with `channel: push` and the approver taken from the SSO
header. A notification never creates an always-allow rule. Audit:
`decided` and `approved`/`denied` carry `channel: "push"`; refused attempts log
`push_decide_refused`. The worker also reports `action_click` and `action_decide`
(`ok`, `note: "http 200"` / `"network"`, `err`) through `/push/event`. On success
it shows a brief "Approved: <names>" / "Denied: <names>" notification that closes
itself after about 4 seconds; on any failure (SSO redirect, 401/403/410, network)
it shows "Could not approve - tap to review", which opens the dashboard.

Security note: anyone who can tap the notification on an unlocked device that
holds the browser's SSO session can approve from it, without seeing the request
details. Use `approve_max_risk` to limit which requests offer Approve (or `none`),
and rely on the audit log: every push decision is recorded with the SSO user.

### Client-side diagnostics (`POST /push/event`)

The service worker and the dashboard page report their own steps (install,
push received, notification shown, click, focus/navigate/openWindow outcome,
close, page load, visibility) so a click that "does nothing" can be traced from
the audit log. The endpoint sits on the approval listener behind the same SSO
and trusted-proxy checks, and requires `X-Requested-With: asb` plus
`Content-Type: application/json` (a cross-site page cannot send that without
CORS, which is never granted). Bodies over 2 KB are refused; the answer is 204.

- `client_event`: `user`, `peer`, `client_ip`, `kind`, plus any of `v`, `tag`,
  `action`, `clients`, `client_paths` (up to 5 pathnames, query removed), `ok`,
  `err` (120 chars), `ms`, `state`, `visible`, `note` (80 chars), `queued`.
  Unknown fields are dropped. Notification titles/bodies and request details
  are never sent or logged. Beacons that fail (expired session, network) are
  queued in the worker (max 20) and sent with the next event.
  The Settings page sends `kind: sw_status` once per load and on Recheck:
  `v` is the running worker version, `state` is `current`, `stale`, `noreply`
  or `none`, and `note` is `expected vN` (the version `/sw.js` serves, also sent
  in the `X-SW-Version` response header). Settings > This browser shows the
  same comparison and an "Update worker now" button.
- `client_event_dropped`: more than 120 events per user per minute are
  discarded; one line is written when dropping starts (`dropped: 1`) and, if
  more were dropped, a final count (`final: true`) when the next window opens.

## Request history

The Requests tab (`/`) shows pending cards on top and, below them, the recent
requests as one list: secret, what was asked (method and URL without its query
string, the store operation, or "env"), an outcome pill (**approved**,
**auto-approved** (policy), **denied**, **expired**, **failed**) and the time.
**Search and filter all history** expands that same list in place: a search
box (secret, URL, source, summary, approver, id), outcome / secret / mode
filters, and **Show more** (25 at a time, up to 500). Filters and paging are
fetched as fragments, so the page neither reloads nor changes layout; the
state is kept in the URL (`/?view=all&q=...`), and the live poll refreshes the
list with it. `/history` redirects to `/?view=all`.

Each row is a button. Selecting it (click, Enter or Space) opens a modal
pop-over (a bottom sheet on phones; Escape, the backdrop or **Close** dismisses
it and focus returns to the row) loaded from `GET /request/<id>?fragment=1`
(same SSO gate and identity check as the other pages). It shows the request id,
secrets, mode, the request as recorded (URL without query, the env command
line, the store or ssh description), source and peer (client-supplied),
the unverified summary, risk level with the model verdict and reasons, the
outcome, who decided and through which channel (dashboard, push, ha, link,
policy), the approver, timestamps and durations (requested, decided, released,
delivered), upstream HTTP status and response size, and a timeline of every
audit event for that request id with its recorded fields. Only a fixed list
of fields is shown; urls, bodies and anything unlisted are not. A pending
request has no detail (409; it has a card), an unknown or malformed id is 404,
and the nonce and action tokens are never shown. All text is HTML-escaped on
the server.

It is derived from the audit log, which stays the only record: events sharing a
request id are folded into one row (and one event list), incrementally, with at
most the most recent 5000 requests kept in memory; a detail view reads that
index, not the file. No values, header values or bodies are ever shown (the log
does not contain them). "(not collected)" in the pop-over marks an approval
whose result the client never fetched.

## Always allow

On the approval page, **Approve and always allow `NAME`** approves this request
and records `"approval": "allow"` in that secret's vault item metadata (with who
and when), effective immediately. It is offered only
when it would mean something:

- HTTP mode only: the broker makes the call, so the value never leaves it. Never
  offered for env mode.
- One secret per request.
- Not from a request rated high, or one the current `risk.auto_approve_max` would not auto-approve (the rule would not take effect for such a request).

The rules are enforced on the server, so a forged form field is refused and
audited (`policy_change_refused`). Changes are audited as `policy_changed`
(`policy_change_failed` if the file could not be written; the in-memory policy
is then left unchanged). The **Policies** tab (`/policies`, same SSO-gated listener) lists only the
secrets that are always allowed, with a **Revoke** button that puts one back to
"prompt"; it can only tighten.

## Time-boxed grants (approve for N minutes)

Instead of plain Approve or Always allow, the approver can pick **Approve for N
min** from the "Approve for a while" menu on the approval card (dashboard) or on
the approval-link page. The request is approved as usual, and for the next N
minutes further requests for the same secret are approved without a tap. The
grant ends by itself at an absolute deadline (using it does not extend it) and
can be revoked early.

- **Per secret name.** A request naming several secrets creates one grant for
  each; a later request is auto-approved only when *every* secret it names has an
  active grant. Granting again for a secret replaces its grant (restarting the clock).
- **Modes where the value never leaves the broker:** `http` and `ssh_sign`
  (a deploy session needs many logins). `env` and `store` (create or update)
  always ask: the value reaches the agent, or credentials change. A grant picked
  on such a request is refused and audited (`grant_refused`).
- **Only an explicit human choice creates a grant**, on the dashboard card or
  the approval-link page, with the same SSO, CSRF and same-origin checks as the
  other buttons. Notification buttons (`push`, `ha`) stay plain Approve/Deny and
  can never create one. A denied or already decided request creates nothing.
- **Config** (`timed_grants`, validated at startup with the field named in the
  error): `enabled` (default `true`), `durations` (minutes offered; 1-6 distinct
  whole numbers > 0 and <= `max_minutes`; default `[5, 15, 30, 60]`),
  `max_minutes` (cap, default 60, at most 1440) and `max_risk`
  (`none|low|medium|high`, default `high` = no ceiling). `enabled: false` hides
  the menu, rejects grant choices and ignores any persisted grants.
- **Risk ceiling.** A request rated above `max_risk` ignores the grant and
  prompts normally (`grant_skipped`, `reason: risk`). A missing model verdict
  counts as high, so it only matters when the ceiling is below `high`. `none`
  means grants are never used. A grant is checked only for requests no
  `approval: allow` policy already approved; a request that policy escalated
  because of risk can still be approved by a grant when the ceiling allows.
- **Persistence.** Active grants live in `grants.json` next to the audit log
  (atomic write, mode 0600; secret names, times, grant id and creator only). It
  is reloaded on start, so a redeploy does not drop them. Expired entries and
  entries whose deadline is further out than `max_minutes` are dropped on load;
  a corrupt file fails closed (no grants, `grants_file_corrupt` audit warning).
- **Revoking.** The **Policies** tab has an "Active grants" card above "Always
  allowed": secret, live time left, who allowed it, and a **Revoke** button
  (`POST /grants/revoke`, CSRF-checked). Programmatic: `Broker.revoke_grant`.
- **Settings** shows the config line (on/off, durations, ceiling).
  `GET /v1/status` reports only `features.timed_grants` (a bool). Which secrets
  currently have a grant is approval context and is not returned by any
  agent-facing endpoint (discovery, request results, status).

Audit events (all but the last three carry the request `id`):

| Event | Fields |
| --- | --- |
| `decided` / `approved` | `grant_minutes` when the approver chose a grant (`via: user`, `channel`) |
| `grant_created` | `grant_ids`, `grant_minutes`, `expires_at`, `created_by`, `channel`, `approver_peer`, `approver_ip` |
| `grant_refused` | `reason` (ineligible mode); the approver's usual `channel`/`approver` fields |
| `grant_used` | `grant_ids`, `grant_left_s` |
| `approved` (auto) | `via: policy`, `grant_id`, `grant_ids`, `grant_left_s` |
| `grant_skipped` | `reason: risk`, `grant_ids`, `risk_level`, `max_risk` |
| `grant_revoked` | `grant_id`, `secret`, `created_by`, `revoked_by`, `left_s`, `peer`, `client_ip` |
| `grant_expired` | `grant_id`, `secret`, `expires_at`, `created_by` (recorded lazily on the next check, by a 15 s sweep, or on load) |
| `grants_file_corrupt`, `grant_dropped`, `grants_file_write_failed` | `warning` / `reason`, `error` |

For any API that exposes audit events outside the approver UI: treat `grant_*`
events and the `grant_id`, `grant_ids`, `grant_left_s` fields as policy context
and show a grant-approved request as a plain `approved`. The history rows and
pop-over show "Decided by: time-boxed grant (auto-approved), 12 min left when
used".

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
`escalated`, `stored`, `request_detail_viewed`, `grant_created`/`grant_used`/`grant_revoked`/`grant_expired` (see Time-boxed grants), `config_warning`, `policy_changed`, `policy_change_refused`, `policy_change_failed`, and
security events `auth_failed`, `rejected`, `approval_viewed`,
`approval_forbidden`, `approval_stale`, `bad_request`, `discovery`,
`ha_decide_refused`, `ha_decide_dropped`, `ha_hook_any_device`.

    python -m secret_broker.audit verify audit.jsonl
    python -m secret_broker.audit show audit.jsonl approved names=example-api

`verify` detects edited or removed records mid-file. Tail truncation is not
detectable from the file alone: keep the log off the agent's host.

### Audit API for the agent

`GET /v1/audit` and `GET /v1/audit/verify` on the client API, authenticated like the other
`/v1` endpoints with `X-Client-Key` (no key, a wrong key or the Home Assistant hook key: 401).
They give the agent a **redacted** read-only view so it can debug its own requests
(`asb audit`). No approval is needed. The full record stays in the audit file and the SSO
History page.

Why redacted: what the agent can see must not reveal approval context (which secrets
auto-approve, risk verdicts and reasons, policy), or the agent could favor credentials that
skip the prompt. Redaction is a **whitelist**: for each event type only the fields below are
returned, and unknown fields are dropped. **Deny by default**: an event type that is not in
the whitelist is not returned at all (not even as an empty envelope, which would still show
that something happened and when), and does not count toward `count`. A test requires every
event the broker emits to be either whitelisted or listed as hidden, so a new event forces a
decision. Hidden on purpose:

- Policy and risk: `startup`, `assessed`, `escalated`, `policy_changed`,
  `policy_change_refused`, `policy_change_failed`, `policies_viewed`, `ha_hook_any_device`,
  `config_warning`.
- Policy by absence. These exist only when a human was asked or acted, so their absence on
  a request would mark it as auto-approved: `notified`, `decided`, `decision_refused`, and
  `dashboard_`/`push_`/`ha_`/`link_decide_refused`.
- Approver presence and activity, so the agent cannot time requests for when you are away:
  `approval_viewed`, `request_detail_viewed`, `approval_stale`, `approval_forbidden`,
  `csrf_refused`, `dashboard_viewed`, `history_viewed`, `push_subscribed`, `push_revoked`,
  `push_refused`, `push_test`, `ha_decide_dropped`.
- Browser telemetry: every `client_event` (page loads, visibility, service-worker delivery
  diagnostics) and `client_event_dropped`. Even the delivery diagnostics only occur when a
  human was notified or acted, and the rest shows whether a page is open. The full
  telemetry stays in the audit file and the SSO History page.

Free text that an error can supply is reduced to a fixed class; a notification failure
reports `other`, since "notify failed" would show that a human was to be asked.
A request that policy approved shows `approved` with `channel` and `approver` null, the
same shape as a human approval. Never returned: risk, model verdict, reasons, summary text,
`via`, `always_requested`, latency on decisions, the `adopted` and catalog name lists, secret
values, tokens, nonces, hashes, `prev`, approver IPs.

Parameters (all optional; unknown, repeated or malformed ones are a 400 with a short message):

| Parameter | Meaning |
|---|---|
| `request=ID` | one request's timeline (default order `asc`) |
| `event=A,B` | event types (lowercase names, up to 20) |
| `secret=NAME` | requests/reads that name this secret |
| `since=`, `until=` | ISO-8601 (`2026-10-18T01:02:03Z`) or relative `90s`, `15m`, `2h`, `3d` |
| `source=S` | the client label (`user@host`) that made the request |
| `limit=N` | 1-500, default 100 |
| `before=SEQ` / `after=SEQ` | cursors (not both): older than / newer than that seq |
| `order=asc\|desc` | default `desc`; `asc` with `request=` or `after=` |

Response: `{"events": [{"seq", "ts" (ISO UTC), "event", "request" (id or null), ...fields}],
"next": seq or null, "truncated": bool, "count": n}`. `next` is the value to pass as `before`
(order `desc`) or `after` (order `asc`) to continue; null means the scan reached the end.
`truncated` is true when the response hit its size cap, the scan bound, or the query reached
the edge of the indexed window.

Limits: 60 requests per minute per client key (bounded limiter map, oldest evicted); response
body capped at 256 KB; a query examines at most 50,000 lines; the index covers the newest 64 MB
of the log and the newest 5,000 request ids, kept incrementally (a query seeks, it does not
rescan the file). Successful queries are not themselves audited.

`GET /v1/audit/verify` walks the whole file once (20 s budget, one at a time) and returns
only `{"ok": bool, "events": n, "first_bad_seq": n|null}`; `first_bad_seq` is the first
record that does not chain from its predecessor (an edited record is reported as its
successor). Tail truncation is still undetectable from the file alone.

Whitelist (output field from the recorded field; every event also has `seq`, `ts`, `event`,
`request`):

| Event | Fields returned |
|---|---|
| `requested` | names, mode, source, peer, method, url, argv, op, field, ssh_kind, fingerprint |
| `rejected` | names, mode, source, peer, url, reason (already returned to the client) |
| `approved`, `denied`, `expired` | channel (dashboard, push, ha, link or null), approver (null for policy) |
| `failed` | error_class (release_failed, timeout, tls, dns, connection, vault, other), channel, approver |
| `secret_read` | secret, vars (variable names) |
| `delivered` | kind |
| `http_executed` | upstream_status, response_bytes, duration_ms |
| `http_failed` | error_class |
| `stored` | names, op, field, duration_ms |
| `ssh_signed` | fingerprint |
| `auth_failed` | peer, method |
| `bad_request` | peer, error (the message the broker already returned to the agent) |
| `discovery` | peer, host, found (names) |
| `catalog_loaded` | count, invalid_count (not names) |
| `backend_ready` | duration_ms |
| `catalog_error`, `backend_error` | envelope only (no fields) |

Residual signals the agent can still infer: a decision with `channel` null is a policy
approval, the time between `requested` and `approved` is milliseconds for one, and `denied`
or `expired` mean a human was asked (the agent also learns that from its own request status).

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

