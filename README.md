# agent-secret-broker

Give a CLI agent (Claude Code, scripts, anything that shells out) access to
credentials **only after a human approves each use** on their phone, with a full
audit trail. Self-hosted, standard library only, no MCP.

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

## Policy, risk, discovery

Per secret in the broker config:

    "approval": "prompt"        # default: every use needs a phone approval
    "approval": "allow"         # no prompt (http mode only unless auto_modes adds env)
    "sensitivity": "low|medium|high"   # default medium
    "allowed_hosts": ["api.example.com"]

Every request is rated low/medium/high: `max(rule baseline, optional model
verdict)`. The model can only raise the level (its input is attacker-influenced
text). Baseline rules use sensitivity, HTTP method, destructive keywords,
opaque shells and env dumps. With `"risk": {"escalate_auto_at": "high"}`, an
`allow` secret is prompted anyway at or above that level.

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

## Audit

JSONL, hash-chained, mode 0600, on the broker host. Never contains secret
values, header values or bodies.

Events: `startup` (policies in force), `requested`, `assessed`, `notified`,
`secret_read`, `approved`/`denied`/`expired`/`failed` (with `via` user or
policy, approver, reported client IP, latency), `http_executed`, `delivered`,
`escalated`, and security events `auth_failed`, `rejected`, `approval_viewed`,
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
