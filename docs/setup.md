# Setting up the broker

This page takes you from nothing to a running broker with one working
credential. About 30 minutes if you already have a vault and an SSO proxy.
How the pieces behave in detail is in [reference.md](reference.md); installing
the command line for agents is in [cli.md](cli.md).

## What you need

| Piece | Why | Examples |
|---|---|---|
| A **vault** | Holds the credentials. The vault *is* the catalog: no separate list. | Bitwarden, or a self-hosted Vaultwarden |
| An **SSO proxy** in front of the approval page | Proves it is you tapping Approve | authentik proxy outpost, oauth2-proxy, Authelia, Cloudflare Access |
| A **notification path** | Tells you a request is waiting | Web Push (built in), Home Assistant, Telegram |
| A host with **Docker** | Runs the broker | any small VM |
| TLS in front of both URLs | Credential values cross the client API | your reverse proxy |

The broker publishes two ports. Treat them very differently:

- **8800, client API.** The CLI talks to it with a client key. The key only lets
  a process *create requests*, which still need your approval.
- **8801, approval web app.** It trusts the username your SSO proxy puts in a
  header. **Never publish it directly**: only the proxy may reach it.

## 1. Prepare the vault

1. Create (or reuse) a vault account for the broker, for example
   `broker@example.com`.
2. Create an **organization** and a **collection** for broker-managed
   credentials (for example org `Agents`, collection `Agent Secrets`). Give the
   broker's account **Can edit** on that collection only. It must be able to
   write so `asb store` and `asb update` work.
3. In that account's settings, create an **API key** (client id and client
   secret). Choose a **master password** for the account.

Only that collection is visible to the broker: every login and secure note in it
becomes a credential (see "The vault is the catalog" in [reference.md](reference.md)).

## 2. Lay out the stack

On the Docker host:

    mkdir -p /opt/stacks/asb/{data,bw,secrets} && cd /opt/stacks/asb
    cp /path/to/repo/deploy/compose.yaml .

    # files the container reads (mode 600, owned by uid 65534 = nobody)
    printf '%s' 'THE-MASTER-PASSWORD'  > secrets/bw_master_password
    head -c 32 /dev/urandom | base64   > secrets/client_key       # the CLI's key
    printf 'BW_CLIENTID=user.xxxx\nBW_CLIENTSECRET=yyyy\n' > secrets/broker.env
    chown -R 65534:65534 data bw secrets && chmod 600 secrets/* && chmod 700 bw

`data/` holds the audit log and push subscriptions, `bw/` the vault CLI's device
identity. Keep both on a persistent volume (see the compose file for why).

## 3. Configure

Settings are a JSON object in the `BROKER_CONFIG` environment variable of
`compose.yaml` (or a file passed with `--config`; the variable wins). Start from
`deploy/config.example.json`. The ones you must set:

| Key | Meaning |
|---|---|
| `backend` | `{"type": "bw", "server_url": "https://vault.example.com", "master_password_file": "/run/secrets/bw_master_password", "organization": "Agents", "collection": "Agent Secrets", "serve": true}` |
| `client_key_file` | The key the CLI sends (`/run/secrets/client_key`) |
| `approve_base_url` | The exact public URL of the approval site, for example `https://asb.example.com`. Also used for the link in notifications and for CSRF checks |
| `allowed_user` | The SSO username that may approve |
| `identity_header` | Header your proxy sets with that username (for example `X-authentik-username`, `X-Forwarded-User`) |
| `approval_trusted_peers` | CIDR of the proxy's network, for example `["172.23.0.0/16"]`. The listener refuses every other caller. Strongly recommended |
| `notify` | One or more transports, see step 5 |

Useful optional keys: `risk.auto_approve_max` (`low`, the default, is
recommended: an always-allowed secret is released unprompted only for low-risk
requests; `none` turns auto-approval off, `high` lets every risk level through
and fails open when the analysis model is down; see the reference),
`summary` (a one-line AI summary of each request via OpenRouter, marked
unverified), `ttl_seconds` (how long a request waits, default 300),
`audit_log`, `timed_grants` ("Automatically approve... 5/15/30 min" chips on the approval
card; on by default, tune or turn off with `{"enabled": false}`, see the
reference). All keys are in `deploy/config.example.json`.

Leave `serve: true` in the `backend` block: the broker then keeps one long-lived
vault session and cannot trip the vault's login rate limit.

## 4. Put the SSO proxy and TLS in place

- Route `https://asb.example.com` (your `approve_base_url`) through your SSO
  proxy to the broker's port **8801**. The proxy must forward the authenticated
  username in `identity_header`. `deploy/compose.yaml` shows an authentik proxy
  outpost; any proxy that does the same works.
- Route a second hostname, for example `https://asb-api.example.com`, to port
  **8800**. This is the URL agents use. It carries credential values, so it must
  be TLS. It does not go through SSO (the client key protects it); you may
  restrict it to your own networks.
- Do not publish 8801 anywhere else.

## 5. Choose how you get notified

Add transports under `notify`; a request counts as delivered if any one works.

- **Web Push** (no extra service): `{"type": "webpush"}`. Open the approval site,
  go to **Settings**, click **Enable on this device**. Works with the browser
  running and no tab open. Chrome tip: allow it to keep running in the
  background. Safari on iOS needs the site added to the home screen first.
- **Home Assistant** (phone push): `{"type": "ticker", "ha_url": "...", "ha_token_file": "...", "category": "general"}`
  (needs the Ticker integration).
- **Telegram**: `{"type": "telegram", "bot_token_file": "...", "chat_id": "..."}`.

Use Web Push *and* a phone transport if you can: a browser that is fully quit
cannot receive a push until it starts again.

## 6. Start it and check

    docker compose up -d
    docker compose logs broker      # expect: secret-broker listening

Open the approval site. You should be sent through SSO and land on **Requests**
with "Nothing is waiting for approval". If you get a 403 your proxy is not in
`approval_trusted_peers`, or the username does not match `allowed_user`.

## 7. Add a first credential and try it

Either from a Bitwarden client: put a Login or Secure Note in the broker's
collection (copying an existing item works). It appears in `asb list` within a
minute, with variables named after the item (for a login named `Grafana`:
`GRAFANA_USERNAME`, `GRAFANA_PASSWORD`) and hosts taken from its URLs. To choose
the names and hosts yourself, add a custom text field `broker`:
`{"allowed_hosts": ["grafana.example.com"], "vars": {"GRAFANA_TOKEN": {"field": "auto"}}}`

or from the CLI once it is installed (see [cli.md](cli.md)):

    printf '%s' "$TOKEN" | asb store grafana --hosts grafana.example.com

Then request it:

    asb http grafana GET https://grafana.example.com/api/health \
        -H 'Authorization: Bearer {{GRAFANA_TOKEN}}'

Your phone or browser notifies you; approve; the call returns.

### Optional: tie an SSH key to servers

An SSH key (`asb store NAME --ssh`) can say which servers it may log in to. The
easiest way is the **SSH host policy** card for the key on the **Policies** tab: paste
lines from `~/.ssh/known_hosts` into Known hosts, list the allowed names or `SHA256:`
fingerprints in Allowed hosts (empty means no enforcement), and save. After saving the
card shows each line's fingerprint and warns about entries that can never match. The
server asks for an extra tick before it lowers enforcement or saves a list that would
lock the key out, and the change applies to the next signature. The same policy is
stored in the key item's `broker` field in the vault, so you can also edit it there:

    "ssh_hosts": {"known_hosts": ["web.example.com ssh-ed25519 AAAA..."],
                  "allowed_hosts": ["web.example.com"]}

`known_hosts` lines (plain format, from `ssh-keyscan` or `~/.ssh/known_hosts`;
hashed entries are ignored) give host key fingerprints their names on the approval
card. `allowed_hosts` (names from those lines, or `SHA256:` fingerprints) makes the
broker refuse any signature that is not proved to be for one of them. The proof is
OpenSSH's session-bind (client OpenSSH 8.9 or newer; git over ssh uses it too) or
host-bound public key auth (OpenSSH 8.9+ on both ends), so older clients, plain
`publickey` logins and commit signing are refused for such a key. Agent forwarding is
refused unless you add `"allow_forwarded": true`. Without
`allowed_hosts` the approval card still shows the verified server when OpenSSH
sends it. Details and limits: [reference.md](reference.md#ssh-keys-the-broker-signs-the-key-never-leaves).

## Upgrading

    cd /opt/stacks/asb
    docker compose pull broker && docker compose up -d --force-recreate broker

`docker compose` can report "Running" with a stale image, so check the new
behaviour afterwards: run `asb status` and compare `version` with the commit you
expect. To deploy and verify without a shell on the host, see [deploy.md](deploy.md).
Images are built by CI on every push to `main` as
`ghcr.io/rgregg/agent-secret-broker:latest`; pin a tag if you prefer.

## Backups and recovery

- The vault is the catalog, so backing up the vault backs up the credentials *and*
  their policies.
- `data/audit.jsonl` is the audit trail: `python -m secret_broker.audit verify
  data/audit.jsonl` checks the hash chain. Keep a copy off the agent's host.
- `data/webpush.json` and `data/vapid.pem` are push subscriptions and the sending
  key. Losing them only means re-enabling push on each device.

## Moving from an older config file

Earlier versions listed secrets in a config file. Write their metadata onto the
vault items with `python -m secret_broker.import_catalog --config OLD.json
[--apply]` (dry run by default, with the broker stopped).
