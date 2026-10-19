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
  - **Script contents.** If the command runs a script file, the client adds a
    `scripts` list to the env request (see `asb help run`, docs/cli.md for what it
    looks for and its limits). Each entry is exactly one of
    `{path, size, sha256, text, truncated}`, `{path, unreadable}` (`missing`,
    `binary`, `permission`, `too_large`, `refused`) or `{stdin: true}`. The broker
    rejects (400) more than 3 entries, unknown keys, a path that is not 1-300
    printable characters, a non-integer `size`, a `sha256` that is not 64 hex
    digits, `text` over 32 KB or non-boolean flags, and `scripts` on any mode other
    than env. It removes control characters other than newline and tab and
    scrubs obvious secrets (`secret_broker/scripts.py`) before storing the entries
    on the request. The card and the `/a/<nonce>` page show a collapsed
    **Script contents (reported by the client)** section: path, size, short hash,
    a notice when only the start is shown, and the text in a scrollable monospace
    box, all HTML-escaped; unreadable and stdin entries show as plain notes. Script
    text is never put in a notification (push, Telegram, ticker, Home Assistant) or in
    the audit log. The audit `requested` event gets only `script_paths`,
    `script_sha256`, `script_sizes` and `script_markers` (marker classes), which the
    audit API returns because they describe the agent's own request. The history
    pop-over shows path, size and short hash, and the (already scrubbed) text from the
    separate, short-lived request-details store (see
    [Request details](#request-details-headers-and-body)), cut to
    `request_details.max_script_bytes`. All of this is advisory: the client chooses what to
    send. The client re-hashes the scripts before running them and exits 6 if one
    changed.

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
- **What the prompt tells you about the server.** An SSH login signature carries
  the account name and a session id but not the host, so the broker gets host
  identity from two layers, shown on the approval card, in the notification and in
  the history pop-over:
  - *Server (verified).* OpenSSH 8.9+ sends `session-bind@openssh.com` to the
    agent before authenticating: the server's host key and that host key's
    signature over the session id. `asb ssh-agent` accepts it (it replies
    `SSH_AGENT_SUCCESS`; any other extension, or a malformed bind, gets
    `SSH_AGENT_FAILURE`, which OpenSSH treats as "agent does not support it") and
    remembers it per agent connection, as an ordered chain (up to 16, each with
    its forwarding flag). The broker checks every signature (ed25519, ECDSA
    P-256/384/521, RSA with SHA-2 or legacy SHA-1 host keys) and that the session
    id inside the userauth data being signed is the one of the **last** bind
    (the connection actually being signed for). A match against only an earlier
    bind is shown as
    "Server identity not verified"; a chain that matches no bind at all (a bind
    replayed from another connection) is refused (`ssh_sign_refused`, reason
    `session_mismatch`). The card reads `Server: SHA256:... (ssh-ed25519)`, plus
    `known as host1, host2` when the key's `ssh_hosts.known_hosts` lists that
    fingerprint. What this proves: the other end of that session holds that host
    key. It does not prove the login is going to the host you expected. git over
    ssh binds too.
    If any bind in the chain has `is_forwarding` set, the key is being used from a
    remote host: the card shows "Agent forwarded through: hop -> hop" with each
    hop's fingerprint, name and flag, and "Agent forwarding: this key may be used
    from the remote host".
  - *Host key in the signed login (host-bound auth).* OpenSSH 8.9+ against a
    server that also supports it (OpenSSH 8.9+ servers do) signs logins with the
    method `publickey-hostbound-v00@openssh.com`, whose signed data ends with the
    server's host key. The server rejects the login if that is not its own key, so
    the signature is only usable at that host. The card shows it as "Server (host
    key in the signed login data)" and "log in over SSH as 'user' to server
    SHA256:...". It needs no session-bind (but is still client-supplied bytes, so
    it is a different label from a bind-verified server). When both exist they must
    agree, otherwise the request is refused (`host_conflict`). Plain `publickey`
    (older client or server) carries no host: "host not shown by SSH". Data that is
    neither an SSH login nor SSHSIG is described as "N bytes of unrecognised data".
  - *Destination (claimed).* With `asb ssh-agent -- <command>` the client reads the
    destination from the command line (`ssh [-l/-p/-J/-o HostName=...] [user@]host`,
    scp/sftp `user@host:path` and `-P`, `rsync -e 'ssh -p N'`, git `ssh://` and
    `user@host:path` remotes; remote-only arguments, never a subprocess) and sends
    `user@host:port` with each sign request. If it cannot tell confidently
    (no remote operand, two different hosts, `git push` with a configured remote,
    anything odd) it sends nothing. The card says "Destination (claimed by the
    client)": ssh_config can rename hosts and any script can lie, so treat it as a
    hint. A bare `eval "$(asb ssh-agent)"` has no command, so there is no claim.
    With `-J`, the claim is the final host (`(via jump)` is appended) and the
    jump hop's own login shows that same claim; the verified Server line tells
    the two apart.
  - Not verified (old OpenSSH or server, a non-ssh client, a failed bind, no
    host-bound auth): the card says "Server identity not verified". Commit signing (SSHSIG) has no server.
  - The key is still never released and signing stays rated HIGH whatever the
    model says; the deterministic summary input includes the server and
    destination lines.
- **Restricting a key to servers: `ssh_hosts`.** Add an optional object to the key
  item's `broker` metadata (the vault item is the only place; there is no
  separate catalog):

      {"ssh": true, "ssh_public_key": "ssh-ed25519 AAAA...",
       "vars": {"DEPLOY_SSH_KEY": {"field": "private_key"}},
       "ssh_hosts": {
         "known_hosts": ["web.example.com,10.0.0.5 ssh-ed25519 AAAA..."],
         "allowed_hosts": ["web.example.com", "SHA256:abc..."],
         "allow_forwarded": false}}

  `known_hosts` (up to 200 plain known_hosts lines, 2 KB each) maps host key
  fingerprints to names for display; copy lines from `~/.ssh/known_hosts`
  (`ssh-keyscan -t ed25519 web.example.com` works). Hashed entries (`|1|...`),
  wildcards, `!negations` and `@markers` are ignored, bad lines too; `[h]:2222`
  names appear as `h:2222`. `allowed_hosts` (up to 50) is a list of names from
  `known_hosts` or `SHA256:` fingerprints. When it is set, a signature is refused
  (HTTP 403, audit `ssh_sign_refused` with reason `host_not_allowed`,
  `host_unverified`, `host_forwarded`, `host_conflict`, `bind_invalid` or `session_mismatch`) unless a verified bind proves the
  server is on the list (by the bind-verified key or by the host key in a host-bound
  login), so an unbound request (old OpenSSH or server, plain `publickey`, failed
  verification, commit signing) is refused: it fails closed. A request whose bind
  chain shows agent forwarding is refused (`host_forwarded`) unless
  `"allow_forwarded": true`; then every hop's host key must also be on the list. A
  bind that disagrees with the host key in the login data is `host_conflict`. If the
  connection sent any session bind that fails verification (or is malformed, or the
  chain exceeds 16 and the agent flags `bind_overflow`), forwarding cannot be ruled
  out: the host key in the login data is then ignored and the request is refused
  as `bind_invalid` regardless of `allow_forwarded`. Without `allowed_hosts` it
  proceeds as "Server identity not verified (the connection sent an invalid session
  bind)". The login data's host key is used only when the connection sent no binds. When it is not set, requests
  proceed as before with whatever identity information exists. An empty list is a
  config error (name the field), not "allow everything". Neither `ssh_hosts` nor
  its contents appear in `list`, `which`, `status`, or the agent's audit view;
  the refusal message does not say what is allowed.
- **Editing `ssh_hosts` on the Policies tab.** The policy lives in the key item's
  `broker` metadata (vault field `ssh_hosts`) and is edited from the **Policies** tab
  ("SSH host policy"): a collapsed card per SSH key with a **Known hosts** box (one
  plain known_hosts line per line, pasted from `~/.ssh/known_hosts`; hashed `|1|`
  entries are unsupported and listed as ignored), an **Allowed hosts** box (one host
  name or `SHA256:` fingerprint per line; empty means no enforcement) and an **Allow
  forwarded agent** checkbox. A badge shows `Enforcing: N allowed hosts` or `Not
  enforcing`. The saved card lists each known_hosts line's names, key type and SHA256
  fingerprint (copy fingerprints into Allowed hosts), lines that were ignored with the
  reason, and Allowed hosts entries that cannot match (`unknown name`, or `will only
  match by fingerprint`). `POST /policies/ssh_hosts` (fields `secret`, `known_hosts`,
  `allowed_hosts`, `allow_forwarded`) has the same SSO, trusted-peer, CSRF and Origin
  checks as the other Policies forms and a 1.5 MB body limit (413 above). It runs the
  same validator as catalog load (plus: no control characters, `SHA256:` entries need
  43 base64 characters, names are letters/digits/`._:-`), so the editor cannot write
  something the loader rejects; any error refuses the whole save (400, nothing
  changed). The change takes effect on the next sign request, without a restart.
  Emptying both boxes and clearing the checkbox removes the key. Safety rails, enforced
  by the server: lowering enforcement (clearing Allowed hosts, or turning on Allow
  forwarded while enforcing) needs the "I understand this reduces enforcement" box,
  which appears on the refused form; an Allowed hosts list in which no entry can ever
  match (all names that no known_hosts line gives to a key, no fingerprints) is refused
  as locking the key out unless "Save anyway" is ticked; after a save that enforces, the
  page reminds you that unbound clients (old OpenSSH, git commit signing) are refused.
  Audit: `ssh_hosts_changed` (secret, user, peer, client_ip, `known_lines`,
  `allowed_entries`, `allow_forwarded_old/new`, `enforcing_old/new`, 12-character
  `old_sha256`/`new_sha256` of the policy; never names or keys),
  `ssh_hosts_change_refused` (`reason`: `invalid`, `needs_confirmation`, `lockout`,
  `not_ssh_key`) and `ssh_hosts_change_failed`. The vault item also gets
  `ssh_hosts_changed: {by, at}`. All three events are hidden from the agent audit API.
- `approval: allow` on an SSH key auto-approves signing (its default `auto_modes`
  is `ssh_sign`), subject to `risk.auto_approve_max` like every other mode. SSH
  requests are rated HIGH, so this only releases a signature when
  `auto_approve_max` is `high`. Host-level refusals (`ssh_hosts.allowed_hosts`,
  unverified or forwarded connections) still apply first. The credential-level
  "always allow" button is never offered for an SSH key; set `approval` in the
  vault item yourself.

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
- `guidance` (optional string, at most 2000 characters) is operator-written
  text telling the risk classifier and the description writer how to rate
  requests made with THIS credential (see [guidance.md](guidance.md) and
  [risk.md](risk.md)). Control characters other than newline and tab are
  removed; a non-string or an over-long value makes the secret invalid
  (reported in `catalog_loaded`, naming the field). Items adopted without
  metadata have none. It is policy context: never returned by `list`, `which`,
  `/v1/secrets`, `/v1/status`, request results, notifications or the agent
  audit API. Edit it on the Policies tab ("Risk guidance"), which writes it into
  the item's `broker` metadata like "always allow" does.
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
  without passing the approval gate. The same holds for `guidance`: text that
  says "deletes are low" lowers ratings, so it has the trust level of
  `approval`. Keep write access to that collection to
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

### Classifier config (`summary` block)

    "summary": {"api_key_file": "/run/secrets/openrouter_key", "model": "openai/gpt-5-mini"}

With no `type` this is the original chat-completions classifier, unchanged.
Set `type` to pick another:

| key | applies to | default | meaning |
|---|---|---|---|
| `type` | both | `openrouter` | `openrouter` (chat model) or `jev` (decision model) |
| `api_key_file` | both | required | file holding the OpenRouter key |
| `model` | both | required for `openrouter`; `typesafe/jev-1.14` for `jev` | OpenRouter model id |
| `timeout` | both | 4 (`openrouter`), 6 (`jev`) | seconds; a timeout is a HIGH verdict |
| `max_content_chars` | both | 300 / 400 | body or command characters sent |
| `max_script_chars` | `jev` | 4000 | script text characters sent per script for an env request that carries scripts (0 sends only name, size, hash and markers; total across scripts is capped at 6000; `send_content: false` withholds all text). The description model gets 1000 |
| `send_content` | both | true | false sends only "present, not shown" |
| `prompt` | `openrouter` | `legacy` | `legacy` (old prompt) or `rubric` (the prompt in docs/risk.md) |
| `high_threshold` | `jev` | 0.5 | rate HIGH when P(high) >= this |
| `low_threshold` | `jev` | 0.5 | a `low` answer with P(low) below this becomes `medium` |
| `summary_text` | `jev` | `chat` | `chat` (a chat model writes a plain-language description, in parallel with the decision call, display only), `deterministic` (a technical one-liner prefixed `auto:`) or `none` |
| `summary_model` | `jev` | `openai/gpt-5-mini` | chat model for `summary_text: chat` |
| `summary_timeout` | `jev` | 4 | seconds for the description call; slow or failed falls back to the `auto:` line |
| `summary_max_per_minute` | `jev` | 30 | cap on description calls; excess uses the `auto:` line |
| `summary_concurrency` | `jev` | 4 | simultaneous description calls |
| `summary_base_url` | `jev` | `https://openrouter.ai/api/v1` | chat endpoint root for descriptions. Required when `base_url` is custom (otherwise descriptions are disabled with a startup warning, so request details and the key are never sent to the default endpoint) |
| `summary_read_endpoints` | `jev` | `[]` | list of `{"host": "name[:port]", "path": "/exact/path"}` for POST endpoints that are pure reads (exact host, case-insensitive, and exact path; request must have no query string, userinfo or method-override header); their descriptions may use read verbs. Other writes get the technical `auto:` line unless the AI phrase starts with a write verb |
| `base_url` | both | OpenRouter | override the decision/chat endpoint root (https; http only for localhost) |

Config with an explicit `type` rejects unknown keys at startup, naming the field
(`summary.<key>`); a block without `type` keeps ignoring extra keys as before.
`ssh_sign` requests are always HIGH regardless of the model (and are never sent
to it). Everything else uses the model's verdict only; no verdict is HIGH. See
[risk.md](risk.md) for the rubric and the evaluation harness.

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
requests, each with **Approve** and **Deny** side by side (Deny is solid red) and, where
the usual rules allow it, an **Automatically approve...** row of **5 min / 15 min
/ 30 min / Always** chips (the configured durations; *Always* asks for a
confirmation first), and below it the most recent decisions as a list. A
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

### Holding notifications while a page is open (`notify_presence`)

If you are looking at an approval page, a phone buzz adds nothing. While at least
one approval tab is visible, the broker holds the configured transports back and
the request simply appears on the page (cards refresh as usual).

```json
"notify_presence": {"enabled": true, "ttl_s": 25, "fallback_s": 60,
                    "transports": ["ticker", "telegram", "webpush"], "require_focus": false}
```

- `enabled` (default true). False restores the old behavior exactly: everything is
  sent at once, and the pages stop sending heartbeats. `POST /presence` still answers 204.
- `ttl_s` (10..120, default 25): a visible beat counts as presence for this long.
- `fallback_s` (5..3600 or `null`, default 60): a held notification is sent this many seconds
  after the request was created if it is still waiting. `null` means never: pure suppression.
- `transports` (default all three): the transport `type`s to hold. Types not listed (and
  any other transport) are sent immediately as usual. `[]` holds nothing.
- `require_focus` (default false): the page also needs `document.hasFocus()` to count as
  present (a visible but unfocused window then does not hold notifications).

Heartbeat protocol: every approval page (any page with the shared chrome: Requests,
Policies, Settings, the approval link page) sends `POST /presence` on the approval listener
with `X-Requested-With: asb`, `Content-Type: application/json` and a body
`{"v": true|false, "tab": "<random id>"}` (`tab` optional). It sends `v: true` about every
10 s while the tab is visible (and focused, with `require_focus`), at once on
`visibilitychange`/`focus`/`blur`, and a final `v: false` when the tab becomes hidden or the
page is left (fetch `keepalive`; it never throws and never blocks the page). The answer is 204
(403 guard/identity, 413 over 256 bytes, 400 bad body, 429 over 120 per minute per user).
It sits behind the same SSO identity and trusted-peer checks as the other approval POSTs, has no CSRF
form token, and is not on the client API port, so an agent cannot fake presence. The broker keeps
the last beat per user and tab in memory (bounded maps); the user is present when some tab's
last beat is visible and younger than `ttl_s`. Beats are not audited.

Rules:

- Every request is treated alike: SSH signing and high-risk requests are held too. The fallback
  keeps an unattended open tab from swallowing a request forever.
- Not held (sent at once) when the request would expire before `fallback_s` + 10 s
  (with `fallback_s: null` this check does not apply), or when nobody is present.
- The Notification is built once as usual (same action token, hash kept on the request), so
  an Approve/Deny button on a late-released notification works.
- A monitor thread (daemon, 2 s tick, never raises) releases a held notification when presence
  lapses (no visible beat within `ttl_s`, or a hidden beat and no other visible tab) or at the
  fallback. One transport failing does not stop the others; if nothing was ever delivered and
  every released transport fails, the request fails with "could not notify" as it does today.
- A request decided, denied, expired or failed while held has its notification dropped, never sent
  late, and transports that never sent get no `resolved` call. After a release the normal
  `resolved` flow applies to the transports that did send.
- Held state is in memory: after a broker restart nothing is held (requests do not survive
  either).
- Sends are asynchronous, always: after the request is created and assessed, the create call returns
  without waiting for any transport (a small pool of daemon workers does the sends and the later
  releases), so its latency is the same whether anything was held, sent at once, or slow, and
  presence cannot be inferred from timing. If a send (with nothing held) fails on every
  transport, the request is marked `failed` ("could not notify", audited as today) a moment later,
  and the agent sees that on its next poll; a decision that arrives first wins. A request settled
  before its queued send starts is never sent; a send already in flight completes and `resolved` is
  called after it. `notified` is audited after at least one successful send.

Audit events (all hidden from the agent audit API): `notify_held` (`transports`,
`reason: presence`), `notify_released` (`transports`, `reason: presence_lapsed|fallback`),
`notify_dropped` (`outcome`: how the request ended). They show in the history timeline of the
request. The agent sees nothing about presence: no field in results, status, discovery or the
audit API. Settings > Broker shows the configured behavior.

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
of audit fields is shown; urls, bodies and anything unlisted are not. A
collapsed **Request details** section adds the headers and body kept in the separate
request-details store (below). A pending
request has no detail (409; it has a card), an unknown or malformed id is 404,
and the nonce and action tokens are never shown. All text is HTML-escaped on
the server.

It is derived from the audit log, which stays the only record: events sharing a
request id are folded into one row (and one event list), incrementally, with at
most the most recent 5000 requests kept in memory; a detail view reads that
index, not the file. No values, header values or bodies are ever shown (the log
does not contain them). "(not collected)" in the pop-over marks an approval
whose result the client never fetched.

## Request details: headers and body

Every pending `http` request card (dashboard and `/a/<nonce>` page) has a
collapsed **Request details** section: the headers, one `name: value` per line, and
the body in a monospace block with its size. It is closed by default; the live poll
keeps a section you opened open when it redraws the card (open ones are noted by
request id before the markup is replaced, and restored after), and with scripting
off it is a plain `<details>`. It is built from the request spec that will be
executed, so what is shown is what is sent; `{{VAR}}` placeholders are shown as typed,
never substituted. Omitted when the request has no headers and no body. `store`,
`ssh_sign` and `env` requests keep their own descriptions (env shows its scripts).

- **Body.** Shown as text only when it is valid UTF-8 and the content type is text-like
  (JSON, XML, form data, plain text, GraphQL, and so on; with no content type, when it
  contains no control characters). Cut at `request_details.max_body_bytes` (default
  2048) with a "truncated, N bytes total" note. JSON that parses (and is at most 64 KB)
  is pretty-printed for the view only, labelled "formatted for display", with a nested
  **Show as sent** toggle holding the original text; the bytes sent are unchanged. If the
  JSON has duplicate keys at any depth, or numbers that would not round-trip exactly
  (precision loss, overflow, integers beyond 2^53, NaN/Infinity), it is NOT formatted: the
  raw text is shown with a warning ("This JSON has duplicate keys or numbers that would
  change when formatted, so it is shown exactly as sent.") naming what was found. Input
  that does not parse or nests too deeply is shown raw. The retained copy follows the same
  logic. Binary or non-text content shows only the content type and length.
  Obvious secret-looking literals in the text are removed with the script scrubber
  (`scripts.scrub`); if it fails or withholds, the body shows
  `[body withheld: could not be scrubbed safely]`.
- **Headers.** At most 40 are shown and each value at most 500 characters, with a note
  when something was cut. Control characters are replaced.
- **Masking.** The value of a credential-like header is shown only when it consists of
  `{{VAR}}` placeholders (optionally behind a scheme such as `Bearer`, joined by
  `:` `;` `,`); anything else, i.e. a literal credential pasted by the agent, is
  replaced by `[masked]`. Credential-like means `Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Api-Secret`, `X-Auth-Token`, `X-Access-Token`,
  or any header whose name contains `token`, `secret`, `key`, `password`, `auth` or
  `credential` (case-insensitive). Masking happens before display and before storage;
  there is no reveal. Other headers are shown in full. The URL display is unchanged.
- **Escaping.** All of it is server-escaped text in `<pre>`; the CSP is unchanged and a
  body is never rendered as HTML.

**History.** The pop-over shows the same section for a finished request, from a separate
small store, never the audit log (which stays free of headers and bodies):
`request_details.db` (SQLite, mode 0600, `secure_delete`) next to the audit log, keyed by
request id with `created_at` and `expires_at`. It is written when the request is created,
from the masked view: headers and a text body (cut at `max_body_bytes`); a binary or
non-text body keeps only its content type and length. For env requests with scripts it
keeps the already-scrubbed script text, up to `max_script_bytes` per script, so the
pop-over shows the same **Script contents** section as the card. Retention is
`retention_days` (default 7): a sweep at startup and then hourly (daemon thread) removes
expired entries, and an expired entry is never shown ("Details are kept for 7 days and
have expired."; the normal audit record stays). A total size cap `max_store_mb` evicts the
oldest entries first. A missing or corrupt file just means "not available" in the pop-over
and an audit warning `request_details_store_error` (operation and exception class only); a
file SQLite cannot read is set aside as `request_details.db.corrupt` and a fresh one started.

```json
"request_details": {"enabled": true, "retention_days": 7, "max_body_bytes": 2048,
                    "max_script_bytes": 4096, "max_store_mb": 20}
```

Validated at startup naming the field: `retention_days` 1-90, `max_body_bytes` 0-65536,
`max_script_bytes` 0-32768, `max_store_mb` 1-1024, `enabled` boolean, no unknown keys.
`enabled: false` shows and stores nothing. With no `audit_log` configured nothing is
retained (the cards still show the section).

**Never in:** notifications (push, Telegram, ticker, Home Assistant), the audit log,
`GET /v1/audit`, discovery, `/v1/status`, request results. The store is read only by the
approver pages (the SSO listener), never by an agent-facing endpoint; the
`request_details_store_error` event is hidden from the audit API.

## Always allow

On the approval page, the **Always** chip in the "Automatically approve..." row
(it opens an "Always approve `NAME`?" confirmation with a **Confirm** button that
submits `approve_always`) approves this request
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

Instead of plain Approve or Always allow, the approver can pick a duration chip
(**5 min**, **15 min**, ... after "Automatically approve...") on the approval card
(dashboard) or on the approval-link page. A chip submits immediately (it expires
by itself); a disabled **Always** chip with a tooltip shows why Always is not offered. The request is approved as usual, and for the next N
minutes further requests for the same secret are approved without a tap. The
grant ends by itself at an absolute deadline (using it does not extend it) and
can be revoked early.

- **Bound to the exact set of secrets.** A grant belongs to the set of secret
  names the human approved. A later request is covered only when its set of
  names *equals* a granted set (order does not matter); a request for a subset or
  a superset prompts. Granting again for the same set replaces that grant
  (restarting the clock).
- **Scoped by method class.** A grant made from an `http` request with method
  GET, HEAD or OPTIONS (`scope: read`) covers only those methods later; a later
  POST/PUT/PATCH/DELETE falls through to a normal prompt (`grant_skipped`,
  `reason: method`). A grant made from any other method (`scope: any`) covers
  all methods. `ssh_sign` has no method: its grant (`scope: any`) covers signing
  for that key. The line under the chips says which applies.
- **Risk does not block creating one.** HIGH-rated requests (every `ssh_sign` is
  rated high) can still be approved with a grant; only `max_risk` limits use.
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
  whole numbers > 0 and <= `max_minutes`; default `[5, 15, 30]`),
  `max_minutes` (cap, default 60, at most 1440) and `max_risk`
  (`none|low|medium|high`, default `high` = no ceiling). `enabled: false` hides
  the chips, rejects grant choices and ignores any persisted grants.
- **Risk ceiling.** A request rated above `max_risk` ignores the grant and
  prompts normally (`grant_skipped`, `reason: risk`). A missing model verdict
  counts as high, so it only matters when the ceiling is below `high`. `none`
  means grants are never used. A grant is checked only for requests no
  `approval: allow` policy already approved; a request that policy escalated
  because of risk can still be approved by a grant when the ceiling allows.
- **Persistence.** Active grants live in `grants.json` next to the audit log
  (atomic write, mode 0600; secret names, scope, times, grant id and creator only). It
  is reloaded on start, so a redeploy does not drop them. Expired entries and
  entries whose deadline is further out than `max_minutes` are dropped on load;
  a corrupt file fails closed (no grants, `grants_file_corrupt` audit warning).
- **Revoking.** The **Policies** tab has an "Active grants" card above "Always
  allowed": all secrets in the set, reads only / all requests, live time left, who allowed it, and a **Revoke** button
  (`POST /grants/revoke`, CSRF-checked). Programmatic: `Broker.revoke_grant`.
- **Settings** shows the config line (on/off, durations, ceiling).
  `GET /v1/status` reports only `features.timed_grants` (a bool). Which secrets
  currently have a grant is approval context and is not returned by any
  agent-facing endpoint (discovery, request results, status).

Audit events (all but the last three carry the request `id`):

| Event | Fields |
| --- | --- |
| `decided` / `approved` | `grant_minutes` when the approver chose a grant (`via: user`, `channel`) |
| `grant_created` | `grant_id`, `scope`, `grant_minutes`, `expires_at`, `created_by`, `channel`, `approver_peer`, `approver_ip` |
| `grant_refused` | `reason` (ineligible mode); the approver's usual `channel`/`approver` fields |
| `grant_used` | `grant_id`, `scope`, `grant_left_s` |
| `approved` (auto) | `via: policy`, `grant_id`, `grant_left_s` |
| `grant_skipped` | `reason: risk` or `method`, `grant_id`, `scope`, `risk_level`, `max_risk` |
| `grant_revoked` | `grant_id`, `secrets`, `scope`, `created_by`, `revoked_by`, `left_s`, `peer`, `client_ip` |
| `grant_expired` | `grant_id`, `secrets`, `expires_at`, `created_by` (recorded lazily on the next check, by a 15 s sweep, or on load) |
| `grants_file_corrupt`, `grant_dropped`, `grants_file_write_failed` | `warning` / `reason`, `error` |

For any API that exposes audit events outside the approver UI: treat `grant_*`
events and the `grant_id`, `scope`, `grant_left_s` fields as policy context
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
values, header values or bodies (those live in the separate, short-lived
[request-details store](#request-details-headers-and-body)).

Events: `startup` (policies in force), `requested`, `assessed`, `notified`,
`secret_read`, `approved`/`denied`/`expired`/`failed` (with `via` user or
policy, approver, reported client IP, latency), `http_executed`, `delivered`,
`escalated`, `stored`, `request_detail_viewed`, `grant_created`/`grant_used`/`grant_revoked`/`grant_expired` (see Time-boxed grants), `config_warning`, `policy_changed`, `policy_change_refused`, `policy_change_failed`, `guidance_changed`
(secret, user, peer, length, sha256 prefixes of the old and new text, never the
text), `guidance_change_refused`, `guidance_change_failed`, and
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

- Notification holding (`notify_held`, `notify_released`, `notify_dropped`): shows when the
  approver had a page open.
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
- Server-identity policy: `ssh_hosts_changed`, `ssh_hosts_change_refused`, `ssh_hosts_change_failed`,
  `ssh_sign_refused` (a key's `ssh_hosts.allowed_hosts` is approval
  policy; the refusal itself is already returned to the client without the allowed list).
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
| `requested` | names, mode, source, peer, method, url, argv, op, field, ssh_kind, fingerprint, script_paths, script_sha256, script_sizes, script_markers (env scripts: never any text), host_fp, host_name, claimed_dest |
| `rejected` | names, mode, source, peer, url, reason (already returned to the client) |
| `approved`, `denied`, `expired` | channel (dashboard, push, ha, link or null), approver (null for policy) |
| `failed` | error_class (release_failed, timeout, tls, dns, connection, vault, other), channel, approver |
| `secret_read` | secret, vars (variable names) |
| `delivered` | kind |
| `http_executed` | upstream_status, response_bytes, duration_ms |
| `http_failed` | error_class |
| `stored` | names, op, field, duration_ms |
| `ssh_signed` | fingerprint, host_fp, host_name, claimed_dest |
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

