# Setting up the broker

This page takes you from nothing to a running broker with one working
credential. About 30 minutes if you already have a vault and an SSO proxy.
How the pieces behave in detail is in [reference.md](reference.md); installing
the command line for agents is in [cli.md](cli.md).

## What you need

| Piece | Why | Examples |
|---|---|---|
| A **vault** (or the built-in encrypted file) | Holds the credentials. The store *is* the catalog: no separate list. | Bitwarden, a self-hosted Vaultwarden, or the [local encrypted store](#alternative-no-vault-the-encrypted-local-store) |
| An **SSO proxy** in front of the approval page | Proves it is you tapping Approve | authentik proxy outpost, oauth2-proxy, Authelia, Cloudflare Access |
| A **notification path** | Tells you a request is waiting | Web Push (built in), Home Assistant, Telegram |
| A host with **Docker** | Runs the broker | any small VM |
| TLS in front of both URLs | Credential values cross the client API | your reverse proxy |

The broker publishes two ports. Treat them very differently:

- **8800, client API.** The CLI talks to it with a client key. The key only lets
  a process *create requests*, which still need your approval.
- **8801, approval web app.** It trusts the username your SSO proxy puts in a
  header. **Never publish it directly**: only the proxy may reach it.

## Choosing a backend

The broker keeps its credentials in a **backend**, chosen by `backend.type`. The
rest of the broker behaves the same either way.

| | `bw` (Bitwarden / Vaultwarden) | `local` (encrypted file) |
|---|---|---|
| Needs | A vault account, an organization and collection, an API key, the `bw` CLI (in the image) | Nothing but a file and a key |
| Edit credentials | In the vault's own apps and web UI, plus `asb store` / `asb update` | `python -m secret_broker.localstore` plus `asb store` / `asb update` |
| Sync, sharing, mobile apps, vault audit trail | Yes (the vault's) | No: one file on the broker host |
| Key to protect | The vault master password and API key | The store key (a file or an environment variable) |
| Failure modes | Vault server down, rate limits, `bw` quirks | A lost key is unrecoverable (keep the recovery key) |

Pick `bw` when you already run a vault or want your credentials usable from other
devices. Pick `local` for a small self-contained install or to remove the vault
as a dependency. You can move from one to the other later (see
[Moving from Bitwarden to the local store](#moving-from-bitwarden-to-the-local-store)).
The steps below describe `bw`; the local store has its own quick start after step 7.

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
| `approve_extra_origins` | Optional. Up to 4 more origins the approval site is reached under (`https://host[:port]`, no path or wildcard). Origin checks accept these as well as `approve_base_url`; links and push stay on `approve_base_url` |
| `allowed_user` | The SSO username that may approve |
| `identity_header` | Header your proxy sets with that username (for example `X-authentik-username`, `X-Forwarded-User`) |
| `approval_trusted_peers` | CIDR of the proxy's network, for example `["172.23.0.0/16"]`. The listener refuses every other caller. Strongly recommended |
| `notify` | One or more transports, see step 5 |

Useful optional keys: `risk.auto_approve_max` (`low`, the default, is
recommended: an always-allowed secret (and an Always standing approval) is released
unprompted only for low-risk requests; `none` turns auto-approval off, `high` lets every risk level through
and fails open when the analysis model is down; see the reference),
`risk.auto_modes` (default `["http", "env"]`: which request types an
`approval: allow` secret auto-approves; `["http"]` keeps run-with-secret
(`NAME -- command`) prompting),
`summary` (a one-line AI summary of each request via OpenRouter, marked
unverified), `ttl_seconds` (how long a request waits, default 300),
`audit_log`, `timed_grants` ("Automatically approve... 5/15/30 min" chips on the approval
card; on by default, tune or turn off with `{"enabled": false}`, see the
reference), `request_details` (headers and body shown on the approval card, kept 7 days for
the history pop-over in a separate file next to the audit log; credential-like headers
that are not `{{PLACEHOLDERS}}` are masked; see the reference). All keys are in
`deploy/config.example.json`.

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

Exposing the approval site under a second name (for example publicly through a tunnel while
the LAN name keeps working): make the public name `approve_base_url` and list the other as
`approve_extra_origins`, e.g. `"approve_extra_origins": ["https://asb-lan.example.com"]`.
When an authentik proxy outpost fronts the public name, its `external_host` must equal that
public origin exactly (scheme and host), or the outpost's redirects and the browser's
`Origin` will not match. Expose only the approval site (8801) this way, never the client API
(8800). The extra name must also reach the broker through a proxy that sets `identity_header`.

## 5. Choose how you get notified

Add transports under `notify`; a request counts as delivered if any one works.

- **Web Push** (no extra service): `{"type": "webpush"}`. Open the approval site,
  go to **Settings**, click **Enable on this device**. Works with the browser
  running and no tab open. Chrome tip: allow it to keep running in the
  background. Safari on iOS needs the site added to the home screen first.
- **Home Assistant** (phone push): `{"type": "ticker", "ha_url": "...", "ha_token_file": "...", "category": "general"}`
  (needs the Ticker integration).
- **Telegram**: `{"type": "telegram", "bot_token_file": "...", "chat_id": "..."}`.

While you have an approval page open and visible, notifications are held back and sent only
if you leave or after 60 s (`notify_presence`; see the reference). To always send immediately
set `"notify_presence": {"enabled": false}`; to never send as a fallback set `"fallback_s": null`.

Use Web Push *and* a phone transport if you can: a browser that is fully quit
cannot receive a push until it starts again.

### Using it as an iOS home-screen app

Open the site in Safari, choose Share, then **Add to Home Screen**. It then runs full screen with the
broker's icon, with an opaque status bar and a header that sits below it. Because the app has no address bar
or reload button, the header shows a small refresh button in this mode.

- **First launch.** The app opens `/`; your SSO proxy redirects to its login page, and after sign-in
  you are returned to the Requests page. Whether iOS keeps that login inside the app window or hands it
  to an in-app browser sheet depends on the identity provider's origin and the iOS version, and has not
  been verified on a device here. If sign-in appears to finish but the app still shows the login or an
  error, close the sheet and tap the refresh button.
- **Session lifetime** is set by your SSO provider (for authentik, the session or token validity of the
  provider), not by the broker. When it ends while the app is open, the page notices at its next poll, shows
  "Your session expired. Sign in again." with a button, and stops polling until you sign in. After the app has
  been in the background for more than 5 minutes it checks on return and, if signed out, reloads itself once
  (at most once per minute) to start the login; if a menu or confirm step is open it shows the banner
  instead.
- **Notification taps** open `/` in the app, which goes through the same sign-in when the session has expired.
  Approve and Deny buttons on the notification need a live session; when it has expired the follow-up says
  "Could not approve - tap to review".
- **Limits.** The page cannot refresh the SSO session itself, cannot control how iOS presents the login (in the
  app window or a sheet), and cannot tell a login redirect from a blocked identity provider; in the latter case
  you will see the provider's own error page and can use the refresh button once it is back. The web app
  manifest `scope` and `start_url` are `/`; a login on another origin leaves that scope, which is
  normal for SSO.

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

### Optional: always allow one server for an SSH key

To stop being asked for a machine the key uses all day, approve one of its logins
with **Always: this host** (in the "Automatically approve..." row of the card, with a
confirm step and an optional 30 or 90 day expiry). From then on, logins with that key
to that server (identified by its verified host key, not by name) as that account are
signed without a prompt, at any `risk.auto_approve_max`. Other servers, other accounts
and anything the broker cannot verify (old OpenSSH, forwarded agents, commit signing)
still ask. You can list, add and revoke these rules on the **Policies** tab under
"SSH host rules"; they are stored in the key's vault item (`ssh_rules`). They are never
visible to agents, and a rule cannot override `allowed_hosts`. See
[reference.md](reference.md#standing-per-host-rules-ssh_rules).

## Alternative: no vault, the encrypted local store

Skip steps 1 and the vault parts of 2 and 3. The credentials live in one
AES-256-GCM encrypted file; the key comes from a file or an environment variable.

1. **Create the key and the store** on the broker host, as the user that will run
   the broker (or a user that can then hand the files to it):

        mkdir -p /opt/stacks/asb/{data,secrets} && cd /opt/stacks/asb
        python -m secret_broker.localstore init \
            --store data/store.enc --key-file secrets/store_key --generate-key

   This writes a random key to `secrets/store_key` (mode 600), creates
   `data/store.enc` (mode 600) and prints a **recovery key once**. Store the
   recovery key offline (a password manager, a safe): if both the key and the
   recovery key are lost the store cannot be opened, by design. Use
   `--no-recovery` to skip it, or give your own passphrase in the key file
   instead of `--generate-key` (a passphrase goes through scrypt).
2. **Add a credential** (the value comes from stdin or a hidden prompt, never
   from the command line):

        python -m secret_broker.localstore add "Example token" \
            --store data/store.enc --key-file secrets/store_key
        python -m secret_broker.localstore list \
            --store data/store.enc --key-file secrets/store_key

   Without `broker` metadata the item is adopted with safe defaults and
   `approval: prompt`; `--meta FILE` or `set-meta` sets hosts, variables and policy.
   Existing `.env` files import with `import-env FILE`; delete the file afterwards.
3. **Configure the broker** (instead of the `bw` backend block):

        "backend": {"type": "local", "path": "/data/store.enc",
                    "key_source": {"type": "file", "path": "/run/secrets/store_key"},
                    "idle_timeout": 300}

   Mount `data/` (read-write, the broker writes the store and keeps a `.bak`) and
   mount `secrets/store_key` as a secret. `{"type": "env", "name": "BROKER_STORE_KEY"}`
   also works but is visible in `docker inspect` and `/proc`; prefer the file.
   Steps 4 to 7 are unchanged.

**Threat model.** Encryption at rest protects against a stolen disk, a leaked
backup or snapshot, and other local users reading the file. It does not protect
against anything that can read both the store and the key while the broker runs.
Run the broker as its own user or container, mount the store and the key only
into it, keep them on different volumes where you can, and keep the agent's
account away from both. If the key is wrong or missing the broker still starts
(catalog empty, requests fail with a clear error, `store_unlock_failed` audited)
and recovers on the next refresh once the key is fixed.

Before relying on it, run the end-to-end rehearsal (`tools/rehearse_local_backend.py`,
[rehearsal.md](rehearsal.md)): it drives a throwaway broker on a scratch store through
requests, restarts, key changes, corruption and Docker.

Other administration (`show`, `set-meta`, `delete`, `change-key`, `rotate-dek`,
`export-names`) is in [reference.md](reference.md#admin-cli-python--m-secret_brokerlocalstore).

## Moving from Bitwarden to the local store

A copy, not a cutover: nothing is deleted in the vault, so `bw` stays your
fallback. Do this when you can afford a short restart.

1. `init` a store as above (on the broker host, or anywhere the broker's config and the
   vault are reachable).
2. Copy the vault's contents: `python -m secret_broker.localstore import-bw
   --bw-config broker-config.json --store data/store.enc --key-file secrets/store_key`.
   `broker-config.json` is the broker's existing config with the `bw` backend block.
   It copies every login, secure note and SSH key in the broker's collection (and
   any item carrying `broker` metadata), with custom fields and the metadata parsed
   into a nested object, then reads each item back and compares before saying
   it succeeded. Use `--dry-run` first. It prints names and counts only.
3. Check: `list` shows the names you expect; `show NAME` shows metadata and field names.
4. Switch: stop the broker, replace the `backend` block with the `local` one, supply the
   key (file or environment variable) and start it. Check `asb status` (`backend` is
   `local` and `ok`) and `asb list` against the old catalog (the same names,
   `catalog.invalid` 0).
5. Keep the `bw` block, the vault and its API key around until you trust the new
   setup: rolling back is restoring the old `backend` block and restarting. New
   credentials added afterwards exist only in whichever backend was live.
   Rotation history (`previous_value`) is not copied.


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
  their policies. With the local backend the store file is the catalog: back up
  `store.enc` (the `.bak` next to it is only the previous write) and keep the key
  and the recovery key somewhere else, because a backup without the key is useless
  and a backup next to the key is not encrypted in any useful sense.
- `data/audit.jsonl` is the audit trail: `python -m secret_broker.audit verify
  data/audit.jsonl` checks the hash chain. Keep a copy off the agent's host.
- `data/webpush.json` and `data/vapid.pem` are push subscriptions and the sending
  key. Losing them only means re-enabling push on each device.

## Moving from an older config file

Earlier versions listed secrets in a config file. Write their metadata onto the
vault items with `python -m secret_broker.import_catalog --config OLD.json
[--apply]` (dry run by default, with the broker stopped).
