# Reference

How the broker works, in detail. For installing and configuring it see
[setup.md](setup.md); for the command line and agent integration see
[cli.md](cli.md).

## Using credentials: modes

    asb list [--json]             what credentials exist? name, vars, hosts
    asb which HOST|URL            is a credential available? (no approval, no push)
    asb http NAME METHOD URL [-H 'K: V']... [-d BODY | -d @file | -d @-]
    asb http NAME METHOD URL ... --session ID     inside an approved http session (see "HTTP sessions")
    asb NAME[,NAME] -- command args...
    asb guidance propose FILE|- | --from-dir DIR   propose risk guidance for a human to review
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
  "Always" button is never offered for an SSH key; set `approval` in the
  vault item yourself. To allow ONE server without that, use a standing host rule
  (next).

#### Standing per-host rules: `ssh_rules`

A rule says "this key may log in to this server as this account without asking".
It is exactly **credential + verified host key fingerprint + account** (no
wildcard accounts; one rule per account). Rules live in the key item's `broker`
metadata (vault field `ssh_rules`, so they survive restarts and redeploys) and are
validated when the catalog loads like the rest of the metadata: a bad shape makes
the secret invalid and the message names the field (`ssh_rules[2].fp`).

    "ssh_rules": [
      {"id": "3fa9c1d2", "fp": "SHA256:...43 characters...", "user": "deploy",
       "host": "web.example.com", "by": "ryan", "at": "2026-10-19T16:00:00Z",
       "expires_at": null}
    ]

| Field | Meaning |
| --- | --- |
| `id` | short random id (4-16 of letters, digits, `-`, `_`), unique in the list |
| `fp` | the server host key fingerprint, `SHA256:` + 43 base64 characters |
| `user` | the account, 1-64 printable ASCII characters, no spaces; compared exactly (case-sensitive) |
| `host` | optional display label (up to 100 characters), taken from `known_hosts` when the rule is created; informational only, never matched on |
| `by`, `at` | who created it and when (UTC, `YYYY-MM-DDTHH:MM:SSZ`) |
| `expires_at` | optional UTC time, or `null` for never |

Unknown keys are rejected; at most 100 rules per key. Last-used time and use counts
are NOT written to the vault (its writes are rate limited): they live in
`ssh_rules_state.json` next to the audit log (atomic, mode 0600). A corrupt file
only loses those numbers (`ssh_rules_state_corrupt` audit warning).

**Matching** (all must hold, otherwise the request prompts exactly as before):

1. the request has a verified host identity: a valid session-bind chain whose last
   bind is for this login's session, or host-bound login data. Plain `publickey`
   logins, failed or invalid binds, mismatched chains and SSHSIG (commit signing)
   never match;
2. the chain has exactly one hop and no forwarding (a forwarded chain, or any
   chain with more than one hop, never matches a rule in this version);
3. the verified host key fingerprint equals the rule's `fp`;
4. the account inside the signed login data equals the rule's `user` exactly, and
   the login is for service `ssh-connection`;
5. the credential is the key that owns the rule;
6. the rule has not expired.

**Order.** All server-identity refusals (`allowed_hosts`, `host_unverified`,
`host_forwarded`, `bind_invalid`, `session_mismatch`, `host_conflict`) run first,
in `Broker.create()` before the request exists, so a rule can never release a
request they refuse. Removing a host from `allowed_hosts` therefore makes its
rules ineffective (they stay stored; the Policies tab flags them). After the
assessment, `create()` checks a matching rule *before* auto-approval, grants and
the prompt. A matching rule releases the signature without a notification at
ANY `risk.auto_approve_max` (including `none`) and regardless of the HIGH rating
SSH requests carry: it is explicit human policy for exactly one server, like a
timed standing approval, and is audited as such (`approved` with `via: policy`,
`rule_id`, `decision_source: rule`; `ssh_rule_used`). If a grant, `approval:
allow` or a rule would each release a request, the audit shows the rule.
Everything else (other servers, other accounts, other keys) still prompts or is
released by grants / `auto_approve_max` as before.

**Creating a rule from the approval card.** For a pending SSH login that is eligible
(verified direct server with a fingerprint and a readable account, no forwarding, no
invalid bind, a vault backend that can write metadata, fewer than 100 rules, and the
server on `allowed_hosts` when that is set) the "Automatically approve..." row has an
**Always: this host** chip on the dashboard card and on the `/a/<nonce>` page. Clicking
it opens a confirm step ("Always approve deploy@web.example.com with this key?", the
server name from `known_hosts` or else the short fingerprint) with an expiry select
(Never expires (default), 30 days, 90 days) and Confirm. The form value is
`approve_ssh_rule` (+ `ssh_rule_expiry`); the fingerprint and account always come from
the stored, verified request, never from the form. `Broker.decide_via(..., ssh_rule={"days": n|None})`
approves this request and creates the rule; only the `dashboard` and `link` channels
may (`Channel.may_create_ssh_rule`; push and ha get 403 and nothing changes). If the
request is not eligible, `ssh_rule_refused` is audited (`reason`: `not_eligible`, `cap`,
`backend`, `not_verified`, `forwarded`) and NOTHING changes: the request stays
pending (dashboard note, or a 409 page on the link). A duplicate (same fingerprint and
account) is a no-op that still approves. If the vault write fails after eligibility, the
request is approved once and `ssh_rule_change_failed` is audited.

**Policies tab: "SSH host rules".** Per SSH key a table: host label, short fingerprint,
account, created by/when, expires, last used and use count, and **Revoke**
(`POST /policies/ssh_rules/revoke`, fields `secret`, `rule`). An "Add rule" form takes a
server from the key's parsed `known_hosts` (or a `SHA256:` fingerprint), an account, an
expiry and a confirmation tick (`POST /policies/ssh_rules/add`, fields `secret`, `host`
or `fp`, `account`, `expires`, `confirm`), validated by the same code as the loader. Both
POSTs are guarded like the other policy forms (SSO identity, trusted peer, CSRF token and
same-origin check). A rule whose host is not on an enforcing `allowed_hosts` shows
"blocked by the allowed hosts list". Whoever can edit the vault collection or use the
Policies tab can add rules: the same trust level as `approval`.

**Expiry.** Expired rules are ignored at match time, dropped lazily (the next matching
request triggers it) and by a 60 s sweep, and `ssh_rule_expired` is audited once.

**Audit** (all hidden from the agent audit API; none carries key material; the full
public-key fingerprint is recorded):

| Event | Fields |
| --- | --- |
| `ssh_rule_created` | `credential`, `host_fp`, `account`, `rule_id`, `rule_host`, `expires_at`, `created_by`, `channel` (`dashboard`, `link` or `policies`), `approver_peer`, `approver_ip`; `id` when made from a request |
| `ssh_rule_used` | request `id`, `credential`, `host_fp`, `account`, `rule_id`, `rule_host` |
| `ssh_rule_revoked` | `credential`, `host_fp`, `account`, `rule_id`, `created_by`, `revoked_by`, `peer`, `client_ip` |
| `ssh_rule_expired` | `credential`, `host_fp`, `account`, `rule_id`, `expires_at`, `created_by` |
| `ssh_rule_refused` | `reason` (see above, or `invalid`/`not_confirmed` from the Policies form), `credential`, who asked |
| `ssh_rule_change_failed` | `op` (`create`, `revoke`, `expire`), `error`, ids when known |
| `ssh_rules_state_corrupt`, `ssh_rules_state_write_failed` | `warning`, `error` |

**What the agent can and cannot see.** Nothing about rules: not in discovery,
`/v1/secrets`, `/v1/status`, request results, notifications or the agent audit API.
A rule-approved request looks like any other approved one (`approved` with null
`channel`/`approver`). History and the request pop-over (approver UI) show "Decided by:
standing SSH rule (auto-approved): account@host, rule <id>".

**Decisions** (issue #10): scope is host + account only (no wildcard accounts); rules
match on the verified fingerprint, never on names; a matching rule is released at any
`auto_approve_max`; no default expiry (never, revocable); git over SSH to a known host
key works through the same rules (it is a login; SSHSIG commit signing stays excluded);
a forwarded chain never matches in this version (no per-hop rules, so
`allow_forwarded` only relaxes the `allowed_hosts` refusal, not rules); a per-host
time-boxed variant is not built.

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

### Local encrypted backend: `backend.type = "local"`

Instead of a vault, the broker can keep its items in one AES-256-GCM encrypted
file (no Bitwarden or Vaultwarden needed). Items have the same shape and
behavior as vault items, including `broker` metadata and auto-adoption.

    "backend": {
      "type": "local",
      "path": "/data/store.enc",
      "key_source": {"type": "file", "path": "/run/secrets/broker_store_key"},
      "idle_timeout": 300
    }

- `path` (required): the store file. `idle_timeout` (default 300; 0 = never):
  seconds after last use before the decrypted contents are dropped from memory.
- `key_source` (required): `{"type": "file", "path": ...}` or
  `{"type": "env", "name": ...}`. The value is a passphrase (run through scrypt)
  or a raw 32-byte key as base64; one trailing newline is trimmed. Prefer the
  file form: environment variables show up in `docker inspect` and `/proc`.
- A missing or unknown field stops the broker at startup, naming the field.
  A wrong or missing key does not: the broker stays up, the catalog is empty,
  and `store_unlock_failed` is audited (names and reasons only, never values).
- Audit events: `store_unlocked`, `store_locked` (idle), `store_unlock_failed`,
  `store_written`, `store_reloaded` (the file was changed by someone else).
- Create and manage the store with `python -m secret_broker.localstore` (below).
  A vault-free quick start is in [setup.md](setup.md#alternative-no-vault-the-encrypted-local-store).

#### What the store protects, and what it does not

Encryption at rest helps against a stolen disk, a leaked backup or snapshot, and
other local users reading the file. It does NOT help against anything that can
read both the store file and the key source while the broker runs (the same
user, root, a process in the container, anything that can `docker exec`). Run
the broker as its own user or container, mount the store and the key only into
it, and keep the agent's account away from both. The key must not live next to
the data: a key file on the same volume as the store protects against nothing
but casual browsing.

#### Store format and behavior

One file, header then body. The header is plain JSON (format version, cipher,
and the key wraps) and is the AEAD associated data of the body, so a changed
version, cipher or wrap makes the body fail to authenticate. The body is
`nonce || AES-256-GCM(JSON document) || tag`, with a fresh random nonce on
every write. A random 256-bit data key encrypts the body; each wrap holds that
key encrypted under a key derived from one passphrase (scrypt, `n` at least
2^15, 16-byte salt) or used directly (a raw 32-byte key, as base64). Changing
the passphrase or adding a recovery key re-wraps the data key only; rotating
the data key re-encrypts the body. Both remove the `.bak` generation, which
the replaced key would otherwise still open; backups and snapshots you made
earlier are yours to destroy. Item names and metadata are inside the
encrypted body.

- Writes take an exclusive `flock` on `<store>.lock`, re-read the file, apply the
  change and replace the file atomically (temp file in the same directory, fsync,
  rename, fsync of the directory). One `.bak` generation (the previous file) is
  kept. A crash or error at any step leaves the old file in place.
- The file's modification time and inode are checked on every read, so a
  restore, or a change made by the admin CLI, is picked up without a restart
  (`store_reloaded`). Two writers (broker and CLI) cannot lose each other's updates.
- The decrypted document lives in memory only and is dropped after
  `idle_timeout` seconds without use (`store_locked`); the next use reads the
  key source again and decrypts.
- A wrong or missing key, an unsupported version, or a damaged file raises a
  `BackendUnavailable` (`StoreError`) with a short reason (`wrong_key`,
  `key_missing`, `corrupt`, `unsupported`, `not_found`). The broker stays up with an empty
  catalog and requests fail with that clear error; it retries on the next
  refresh, so fixing the key needs no restart. A file that fails authentication
  is never overwritten (the error points at the `.bak`).
- Items are logins, secure notes or SSH keys, in the same shape as vault items
  (`username`, `password`, `notes`, `uris`, custom `fields`, nested `broker`
  metadata, `previous_value`). Items without `broker` metadata are adopted with
  `approval: prompt`, exactly as with a vault.

#### Admin CLI: `python -m secret_broker.localstore`

Runs on the broker host. Name the store and the key with `--store PATH` plus
`--key-file PATH` or `--key-env NAME`, or give `--config FILE` (a broker config
whose `backend` block is type `local`). Every command prints only item names,
shapes and counts, never a value; values are read from stdin or a hidden
prompt, never from the command line. The store is created with mode 0600 and
the CLI refuses to open one that group or others can read (key files only
warn, because secret mounts are often 0444).

| Command | What it does |
|---|---|
| `init` | Create the store. Generates a recovery key and prints it once (`--no-recovery` to skip). `--generate-key` creates `--key-file` with a fresh random key (it must not exist). Refuses an existing store without `--force` (the old file is kept as `.replaced`). |
| `list` | Names and shapes (`note notes broker`, `login username password`, ...). |
| `show NAME` | Kind, field names and the `broker` metadata; never values. |
| `add NAME` | Add a note (text from stdin or a hidden prompt), a login (`--kind login`: prompts, or `--json` with an object on stdin), or custom fields (`--field NAME`, prompted). `--meta FILE` sets the metadata, `--uri URL` a login URL. Never overwrites. |
| `set-meta NAME FILE` | Replace the item's `broker` metadata from a JSON file (`-` for stdin). |
| `delete NAME` | Delete (needs `--yes`, or type the name at a terminal). |
| `change-key` | Re-wrap the data key under a new passphrase or key (`--new-key-file`, `--new-key-env`, or a prompt). `--wrap recovery` replaces the recovery wrap instead. Update the broker's key source afterwards. Replacing a key removes the `.bak` (the previous file, which the old key still opens); earlier backups and snapshots still open with the old key. |
| `rotate-dek` | New data key; re-encrypts the contents. Other wraps are dropped unless you supply their keys (`--recovery-key-file/-env`), make a new recovery key (`--new-recovery`) or accept the loss (`--drop-other-wraps`). Removes the `.bak` too, because it holds the old data key and wraps. |
| `import-bw` | One-time copy from the broker's Bitwarden/Vaultwarden collection (`--bw-config FILE`, a broker config with a `bw` backend). Copies every login, secure note and SSH key in the collection, plus any item carrying `broker` metadata anywhere, with custom text fields and the metadata parsed into a nested object. Reads every copied item back from the store and compares before reporting success. Never changes the source. `--dry-run`, `--skip-existing`, `--overwrite`. Rotation history (`previous_value`) is not copied. |
| `import-env FILE` | One-time: each `KEY=value` line becomes a note named `KEY` with `approval: prompt` and a variable `KEY` (field `notes`). Prints a reminder to delete the file. |
| `export-names` | Names only, one per line. |

Day to day, `asb store` and `asb update` work unchanged against the local backend.

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
  the item's `broker` metadata like standing approvals do.
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
  is nothing to keep in sync and nothing to roll back. Always standing approvals
  edit `standing` on the item, and revoking the legacy `approval: allow` edits
  `approval`, with who and when.
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
    "approval": "allow"         # no prompt for web and run-with-secret (env) requests; see auto_modes
    "allowed_hosts": ["api.example.com"]

Every request is rated low/medium/high by the analysis model (the `summary`
block below) and nothing else: there are no per-secret ratings and no rule
baseline. If the model is not configured, fails, times out or returns anything
else, the request counts as **high**, so a missing verdict can only make the
broker ask more. The rating is shown on the push and approval page and recorded
in the audit log (`assessed`). Because the model reads attacker-influenced
text, treat it as a hint for a human who also sees the raw request; where it
carries weight is `allow` secrets, through `risk.auto_approve_max`.

### What `approval: allow` covers: `auto_modes`

**Change (env auto-approval):** `approval: allow` used to auto-approve only `http`
(web) requests. It now also auto-approves `env` (run-with-secret) requests, under
exactly the same rules as web requests. **This widens the policy of every
existing `approval: allow` credential.** To keep the old behaviour either set
`"auto_modes": ["http"]` in that credential's metadata, or set it for all
credentials with `"risk": {"auto_modes": ["http"]}` in the broker config.

- The credential must be `approval: allow` (an explicit per-credential opt-in).
- Its modes are the credential's own `auto_modes` list if it has one, else the
  global `risk.auto_modes` (list of `"http"` and/or `"env"`, default
  `["http", "env"]`, `[]` allowed; validated at startup naming
  `risk.auto_modes`). An SSH key defaults to `["ssh_sign"]` and is unaffected.
- The request's model risk level must be at or below `risk.auto_approve_max`
  (below). A missing model verdict counts as high.
- **Safeguard: the script must be visible.** An env request whose script text
  the classifier and approver cannot see (any `scripts` entry marked
  `unreadable` or `stdin`, or text that was cut off, `truncated`) is **never**
  auto-approved, at any `auto_approve_max`: it always prompts and is audited as
  `escalated` with `reason: script_not_visible`.
- **The broker also checks argv itself, and only auto-approves what it
  positively understands.** It does not trust the client's `scripts` list. A
  request is "script visible" (eligible for env auto-approval, timed-grant
  coverage and the Always/grant chips) only when its argv is one of:
  - (a) a program on a small allowlist of programs that cannot run other
    commands, **with only options on that program's positive flag allowlist**
    (exact spellings; any other option is not understood): cat, ls (`-lahtr1AFRSdisL`,
    no `--color`), head, tail, wc, grep/egrep/fgrep (`-invcEFwxrRHhlLqsoaI`, `-e`,
    `-m/-A/-B/-C N`; no `-f`), echo, printf, date (only a `+FORMAT` operand and
    `-u`/`--utc`/`-R`/`-I`), uname, uptime, df, du, ps, id, whoami, hostname (no
    operands), pwd, stat (`-c`), jq (`-r -c -e -s -n -S`, a filter operand that does not
    mention `input_filename`, `env`, `ENV`, `include`, `import`; never `-f`,
    `--from-file`, `-L`, `--seq`, `--arg*file`, `--rawfile`, `--slurpfile`), ping,
    dig, nslookup, sha256sum, md5sum, sort (no `-o`, `--output`, `-T`,
    `--files0-from`, `--compress-program`), uniq (one operand), test, true, false,
    and curl as a plain fetch: only `-s -S -f -L -I`, `-H` (no newline or `@`), `-X
    GET|HEAD`, `--max-time N`, `--connect-timeout N`, `--retry N`, `--silent`,
    `--show-error`, `--fail`, `--location`, `--head`, `--header`, `--request`, with
    literal `http(s)://` URL operands without `@`. Everything else (`-w`, `-o`,
    `-O`, `-D`, `-c`, `-b`, `-d`, `-F`, `-T`, `-K`, `-k`, `--etag-save`, `--hsts`,
    `--alt-svc`, `--trace*`, `--stderr`, `--libcurl`, ...) is not understood. wget and
    openssl are not on the list. The name must be bare or under
    /bin, /usr/bin, /sbin, /usr/sbin (after `os.path.normpath`; an argv[0] with
    a `..` component, glob character, NUL or newline is never understood).
  - (b) an interpreter (sh bash zsh dash ksh ash fish python node deno bun ruby
    perl php pwsh lua Rscript, `sed -f`, `awk -f`) running a script file
    operand, **which needs a matching readable `scripts` entry**, or running
    inline `-c` code that is a shell and passes the restricted shell rules
    below. Inline code of any other language (`python -c`, `node -e`,
    `python -m`, `sed 's/a/b/'`, `awk '{...}'`) is not understood. Options that load
    other code (`node -r`, `perl -M`, `ruby -r`, `php -d`, `bash --rcfile`) and
    `env VAR=` assignments of BASH_ENV, LD_PRELOAD, PATH and similar are not
    understood. A script run directly (`./run.sh`, a script extension, a path
    outside the system bin dirs) also needs an entry; a program on stdin (`bash -s`,
    `python -`) is never visible;
  - (c) one of a deliberately short list of wrappers whose wrapped command is
    understood under (a), (b) or (c) (nesting at most 32): `env` (only `-i`, `-0`,
    `-u NAME` and their long forms, then `NAME=value` words), `sudo` (`-u USER`,
    `-n`, `-H`; not `-E`, `-s`, `-i`, `-e`, chdir/chroot options), `doas` (`-u`,
    `-n`), `nohup`, `time`, `timeout` (`DURATION`, `-s`, `-k`, `--preserve-status`,
    `--foreground`), `nice` (`-n N`), `stdbuf` (`-i/-o/-e MODE`), `exec` and
    `command` (no options). An option that is not listed makes the command not
    understood, and a wrapper left with no command (`nice`, `sudo -n`, `env LANG=C`)
    is not understood; only a bare `env` (or `env -i`) that prints the environment
    is. **Every other launcher is not understood and prompts**: xargs, parallel,
    watch, script, flock, su, runuser, setsid, setpriv, nsenter, unshare, chroot,
    numactl, busybox, strace, ltrace, taskset, ionice, chrt, `env -S`, `env -C`, ...
    (they feed arguments to other commands, take templates or change the
    environment the command runs in).
  - `NAME=value` as an argv word is understood only as an `env` argument (`env
    LANG=C cmd`) or as a prefix inside a shell string, where the shell performs it:
    NAME must be one of LANG, LANGUAGE, LC_*, TZ, TERM, COLUMNS, LINES, NO_COLOR,
    CLICOLOR, FORCE_COLOR, CI, DEBUG, VERBOSE, TERM_PROGRAM, PYTHONUNBUFFERED,
    PYTHONDONTWRITEBYTECODE, PYTHONIOENCODING, NODE_NO_WARNINGS and the value may
    not contain `/`, `$`, backslash, backtick, whitespace or newline. An
    assignment-shaped argv[0], or one after `sudo`/`nice`/..., is not understood.
  Restricted shell strings (every `sh -c`): the string must contain no newline, `#`, backtick, `$`, backslash,
  here-document, process substitution, braces, parentheses, `&` (background) or
  redirection other than a lone `2>&1`; it is split on unquoted `&&`, `||`, `;`
  and `|`, no segment may start with a reserved word (`if`, `for`, `while`, `{`,
  `!`, `[[`, `time`, ...) or a `VAR=value` assignment, and **every** segment must
  itself be understood under (a), (b) or (c).
  **The cost:** everything else is not understood and prompts, even though it
  may be harmless: git, docker, kubectl, make, npm/npx/yarn/pnpm, cargo, tar,
  rsync, find, ssh/scp, nc, terraform, ansible, helm, aws/gcloud/az, gh,
  systemctl/journalctl, psql/mysql/redis-cli/mongosh, sqlite3, ffmpeg, an
  unknown bare program name, `python -c`, a shell string with a pipe into a
  redirect, and so on. Those need one tap each; a time-boxed grant does not
  cover them either, because a grant also requires visibility. (Visibility
  never changes a request that the credential's own policy already prompts.)
  Matching: the script operand and an entry's `path` (or its optional `given`,
  the path as named before symlinks) must be equal after `os.path.normpath`. A
  relative operand is first resolved against the request's optional `cwd` (the
  client's working directory: an absolute path of at most 300 printable
  characters, no control characters; anything else is a 400). With no `cwd`, a
  relative operand matches only an entry whose absolute path ends in that exact
  relative path at a `/` boundary, never by bare file name (so `./deploy.sh`
  does not match `/other/dir/deploy.sh` when `cwd` is given and differs). Two
  matching entries is fine; no match means not visible. A not-understood command, a
  missing or mismatched entry, or an interpreter reading stdin is audited
  `escalated` / `grant_skipped` with `reason: script_not_visible`. The same
  detection code is in `client/asb` (a test asserts the two copies are identical
  and agree on a table of examples); the client's part is to find and read the
  script files. **This catches clients that omit entries. It cannot stop a client
  that lies**: one that reports a harmless script text for a different file,
  sends a false `cwd`, or runs something other than the argv it states is not
  detected. A script can also call other files the client never read, and an
  interpreter or wrapper is recognised by its base name, wherever it lives (an
  absolute path).
- Scripts that print or send the credential are rated high by the model, so they
  auto-approve only when `auto_approve_max` is `high`.
- What auto-approval of env means: the plaintext secret value is released to the
  requesting machine without a human looking at the request. env mode remains
  advisory (the client chooses what it says it will run, and can lie), so the
  risk rating and the script text are hints, not enforcement. Opt a credential
  out with `auto_modes: ["http"]` when it should never be handed out unattended.
- Store requests, the SSH floor and SSH host rules are unchanged.
- The Policies tab's "Standing approvals" table lists each `approval: allow`
  credential with the modes that are auto-eligible (for example `web,
  run-with-secret`); see "Standing approvals".

### Auto-approve level: `risk.auto_approve_max`

    "risk": {"auto_approve_max": "low"}      # none | low | medium | high, default low

An *auto-eligible* request (an `approval: allow` secret, in the modes it is
allowed for: `auto_modes`, by default http and env; plus creating a new credential
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
token=None, always=False, nonce=None, peer=None, client_ip=None, grant_minutes=None, ssh_rule=None, **audit_extra)`
-> `(http_status, request)`; `decision` is `approve|deny`. It alone enforces the
single-decision claim, the constant-time token check (spent on match; any
decision kills it), whether `always` may create an Always standing approval and `grant_minutes` a timed one (400 for a duration that is not on offer, nothing claimed), and the
audit fields (`channel`, `approver`, `approver_peer`, `approver_ip`, plus
`audit_extra`). Status: 200 decided, 403 bad/missing token, 404 unknown, 410
already decided/expired/token spent. Channels are registered in
`broker.CHANNELS` (unknown channel: `ValueError`); the caller does the channel's
own authentication (SSO header, CSRF/origin, `X-Requested-With`):

| Channel | token_required | may_create_always | may_create_grant | may_create_ssh_rule |
| --- | --- | --- | --- | --- |
| `dashboard` | no | yes | yes | yes |
| `link` (`/a/<nonce>`) | no | yes | yes | yes |
| `push` | yes | no | no | no |
| `ha` (`/v1/hooks/ha/decide`) | yes | no | no | no |

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
never a standing approval.

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

(To have a **human** supply a brand-new secret so it never passes through the agent, see
[Credential requests](#credential-requests-the-agent-asks-the-human-supplies-the-value).)

An agent can add or rotate credentials. Rotating always needs a fresh approval;
creating a new one does not unless `store.create` is `prompt` (below):

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
  policy, and is never eligible for Always.
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
standing-approval eligibility, audit), recorded with `channel: dashboard`. Because
one signed-in session can now decide many requests, decisions are additionally
protected against cross-site requests:

- every decision carries a per-user token the page was rendered with, and a
  request without it is refused and audited (`csrf_refused`);
- `Origin` must match `approve_base_url` (or an `approve_extra_origins` entry, below) and
  `Sec-Fetch-Site` must be same-origin, so set `approve_base_url` to the exact public URL of
  this site;
- the page never contains a request's approval nonce (it decides by request id);
- a per-response Content-Security-Policy allows only the page's own script
  (`script-src` nonce), `connect-src 'self'`, and no framing.

### `approve_extra_origins`

| Key | Type | Meaning |
|---|---|---|
| `approve_extra_origins` | list of strings, at most 4, default none | Additional origins the approval site is reached under, for example `["https://secrets.lan.example.com"]` while `approve_base_url` is the public name |

Each entry is exactly `https://host[:port]` or `http://host[:port]`: no path, no wildcard, no
user info. A POST is accepted when its `Origin` is the primary (`approve_base_url`) or an
exact match of a listed extra (scheme, host and port; the host is case-insensitive; no suffix
or prefix matching, so `https://evil-host.example` and `https://host.example.evil.com` are
refused). Everything else about the check is unchanged: `Sec-Fetch-Site` must be
`same-origin` or `none`, a `null` Origin is refused, and a request with no Origin is held to
the per-user CSRF token as before. An invalid entry, a non-list value or more than four
entries stops the broker at startup with `config error: approve_extra_origins...`.

Extras only widen the Origin check. Links in notifications, the Web Push VAPID subject and
every other generated URL keep using `approve_base_url`; the manifest, service worker scope
and push payloads are origin-relative or carry no URL, so each origin serves its own copy.

The Revoke buttons on the Policies tab use the same token.

The approval listener trusts the identity header, so it must only ever hear from
your SSO proxy. Besides not publishing its port, set
`"approval_trusted_peers": ["172.23.0.0/16"]` (the proxy's network) and it
refuses every other peer with a 403 before looking at any header. This matters
more now that the dashboard can decide many requests: a caller that could reach
the listener and forge the header would otherwise be able to list and approve
them all.

### The iOS home-screen app: layout, sign-in expiry and recovery

Every page with the header carries the same shell, so the site works as an iOS home-screen web app.

- **Safe areas.** The viewport is `viewport-fit=cover`; the header is an opaque surface (the same
  colour as the cards, light and dark) padded by `env(safe-area-inset-top)` and the left/right
  insets, the page bottom, the tab bar and the History pop-over bottom sheet by the other insets.
  Every `env()` has a `0px` fallback, so a normal browser tab renders exactly as before.
- **Meta tags.** `apple-mobile-web-app-capable` and `mobile-web-app-capable` are `yes`,
  `apple-mobile-web-app-status-bar-style` is `default`, `apple-mobile-web-app-title` is `Secret Broker`,
  and `theme-color` is `#ffffff` (light) and `#161b22` (dark), the header surface in each scheme.
  `default` was chosen over `black-translucent` on purpose: the page starts below an opaque system status
  bar, so nothing of ours is ever drawn under the glass and the clock and battery are always legible. The
  CSS already pads the header, so `black-translucent` can be tried by changing that one tag.
- **Icon and manifest.** `<link rel=apple-touch-icon>` carries a 180x180 PNG inlined as a `data:` URI (no
  extra request, so it cannot be blocked by the SSO redirect). The same PNG is served at
  `/apple-touch-icon.png`, and `/manifest.webmanifest` (`display: standalone`, `start_url` and `scope`
  `/`) is linked with `crossorigin=use-credentials` so the browser sends the SSO cookie. Both are served
  by the approval listener behind the same peer and identity check as every page (like `/sw.js`). The only
  CSP change is `manifest-src 'self'`. The PNG is generated by `tools/make_icon.py` into
  `secret_broker/icon.py`.
- **Signed out.** The page scripts (the card poll, the History and detail fetches, the presence heartbeat,
  the audit beacon) use `redirect: 'manual'`. A response counts as *signed out* when it is an opaque
  redirect (`type: opaqueredirect`, status 0), a followed redirect, a 401 or 403, an HTML page where a
  204 or JSON was expected, or a 200 without `id=cards` where the card fragment was expected. A rejected
  fetch (no network) or a 5xx is *not* signed out: it still shows the "Cannot reach the broker" note and
  polling continues. On signed out, a banner "Your session expired. Sign in again." with a **Sign in
  again** button appears at the top (sticky); the button runs `location.assign('/')`, which starts the SSO
  redirect. While signed out the poll, heartbeat and audit beacon stop sending anything.
- **Reload button.** In standalone mode (`navigator.standalone` or `display-mode: standalone`) the header
  shows a refresh button that reloads the page (after a form submission it goes to `/` instead, so a
  POST is never resubmitted). It is hidden in normal tabs.
- **Automatic recovery.** When the page returns to the foreground after more than 5 minutes hidden, it
  makes one probe request. If that says signed out, the page reloads itself (which starts the SSO
  login), unless a dialog or an open `details` menu or confirm step is on screen, the page came from
  a POST, or it already auto-reloaded within the last 60 seconds (kept in `sessionStorage`; if that is
  unavailable it never auto-reloads). In those cases it shows the banner instead. If the identity
  provider is down, the page therefore reloads at most once a minute.
- Notification taps (`notificationclick`) only focus the open window, navigate it to `/`, or open `/`;
  the Approve and Deny buttons POST with `redirect: 'manual'` and, if that is refused, show "Could not
  approve - tap to review", which opens `/`. None of these paths depends on a fetch that the login redirect
  could break.

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
- When a request settles (approved, denied, expired or failed, by any route:
  dashboard, a notification button, or the link page) the broker sends one more
  push to every subscribed device, `{type, tag, status, name}`: names only, no
  id, host, token or action. The service worker replaces the notification under
  the same tag with a brief silent one ("Approved: name") and closes it about a
  second later, so the buttons cannot be tapped after the fact. A request that
  was never pushed (held by presence, or not delivered) sends nothing. This is
  best effort and runs off the settle path: a device that is offline keeps the
  stale notification until it reconnects, and a failed or slow send never
  changes the request's outcome. It cannot be a silent push: browsers (iOS in
  particular) require every push to show a notification (`userVisibleOnly`) and
  may revoke a subscription that shows none, hence the show-then-close. Existing
  devices pick the new worker up automatically (version 8); Settings shows the
  running version.
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
header. A notification never creates a standing approval. Audit:
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

## Standing approvals (Always and time-boxed)

A **standing approval** lets later requests for a secret through without a tap.
"Always" and the **5 min / 15 min / 30 min** chips are one feature: both create
a grant `{id, secrets, mode, scope, expires_at, created_by, created_at}`, and
`expires_at: null` is what makes it **Always**. The chips are on the approval
card (dashboard) and the approval-link page, in the "Automatically approve..."
row; a disabled **Always** chip with a tooltip says why Always is not offered.
Choosing one approves the current request as usual and creates the grant. Form
values are `approve_grant_<minutes>` and `approve_always`.

### What a standing approval covers

- **Exact secret set.** A grant covers a later request only when its set of
  secret names *equals* the granted set (order does not matter); a subset or
  superset prompts. Always is offered only for single-secret requests; timed
  grants can cover a set.
- **Mode.** `http` (web), `env` (run-with-secret) or `ssh_sign` (timed only; see
  below). A grant never crosses modes: a web grant never covers env, and an env
  grant never covers web. Both can exist for the same secret.
- **Scope.** `read` (a request made with GET, HEAD or OPTIONS: covers only those
  methods later; a mutating method falls through and is audited `grant_skipped`
  with `reason: method`) or `any` (every method). A grant takes the scope of the
  request it was made from: a GET makes a reads-only grant, any other method an
  any-method grant. `env` and `ssh_sign` are always `any`. Always is *narrow*
  (this secret, this mode, this method class); it never turns on `approval: allow`
  for the whole credential.
- **`store`** (create or update a credential) always asks; a standing choice on it is
  refused and audited (`grant_refused`).
- **env safeguard.** An env request whose script text is not visible
  (`unreadable`/`stdin` markers, or cut off) is never covered, by either kind: it
  prompts and is audited `grant_skipped` with `reason: script_not_visible`, and
  no grant can be created from such a request. A changed script is still caught
  by the client's sha256 check (exit code 6). An env approval releases the
  plaintext value to the requesting machine; the chip help and the Always
  confirmation say so.
- **SSH.** `ssh_sign` has timed grants only (scope `any`: signing for that key).
  SSH keeps its own per-host rules (see "Standing SSH rules"); the SSH card has no
  Always chip. A standing approval can never release anything an `ssh_hosts`
  refusal blocks (those run before a request exists).

### The two kinds and their ceilings

| | Always | Timed |
| --- | --- | --- |
| Expires | never (until revoked) | at an absolute deadline (using it does not extend it) |
| Risk ceiling | `risk.auto_approve_max` | none by default (`timed_grants.max_risk`, default `high`) |
| Stored in | the credential's vault metadata (`standing`) | `grants.json` beside the audit log |

- **Always** is checked against `risk.auto_approve_max`. A request rated above
  it prompts as usual and is audited `grant_skipped` (`kind: always`,
  `reason: risk`, `risk_level`, `max_risk`). A missing model verdict counts as
  high for this check only. With `auto_approve_max` `none` an Always is never used.
  The Always chip is not offered for a request already rated above the ceiling or
  rated high.
- **Timed grants have no risk ceiling by default.** The human chose one
  explicitly for a short time, so it releases at any risk level, including HIGH
  (every `ssh_sign` is rated high) and with no model verdict. This is
  `timed_grants.max_risk` (`none|low|medium|high`, default `high` = no ceiling);
  set it lower to cap timed grants: a request rated above it prompts and is audited
  `grant_skipped` (`kind: timed`, `reason: risk`), and `none` means timed grants are
  never used. Nothing changes unless an operator opts in.
- **Always respects mode restrictions.** An Always approval is used (and its chip
  offered) only for a mode that is in the credential's effective auto modes: its own
  `auto_modes` metadata, else `risk.auto_modes` (SSH keys default to
  `["ssh_sign"]`). With `auto_modes: ["http"]` there is no env Always chip, and an
  existing env Always entry is skipped (`grant_skipped`, `reason: auto_modes`) and
  shown on the Policies tab as "not active: mode not enabled". Timed grants are
  explicit human choices and are not subject to `auto_modes`.

### Evaluation order

For each new request, after assessment and after an SSH host rule claim:

1. The legacy credential-wide `approval: allow` policy (see
   "What `approval: allow` covers"): `auto_modes` / `risk.auto_modes`, with the
   `auto_approve_max` ceiling and the script safeguard, exactly as before.
2. An Always standing approval (mode, exact set and scope; effective `auto_modes`;
   `auto_approve_max` ceiling; script safeguard for env). One that does not apply is audited
   `grant_skipped` and evaluation continues.
3. A timed grant (mode, exact set and scope; script safeguard; `timed_grants.max_risk`,
   default no ceiling).
4. Otherwise the request prompts (or escalates) as before.

A request that step 1 escalated because of risk can still be released by step 2
or 3. Checks run under the decision lock, so a human decision and a standing
approval never both act. A request released by a standing approval ends
`approved` with `via: policy` and a `grant_id`.

### Creating and revoking

- **Only an explicit human choice creates one**, on the dashboard card or the
  approval-link page, with the same SSO, CSRF and same-origin checks as the other
  buttons. Notification buttons (`push`, `ha`) stay plain Approve/Deny and never
  create one. A denied or already decided request creates nothing.
- **Duplicates are a no-op that still approves.** Choosing Always when a covering
  Always exists approves and changes nothing. A broader Always (any method)
  replaces a narrower one (reads only) for the same secret and mode. A timed
  grant for the same set and mode replaces (and restarts) the old one.
- **Cap:** 50 Always approvals per credential (`grant_refused`, `reason: cap`; the
  request is still approved).
- **Revoking.** The **Policies** tab has one "Standing approvals" table with
  every timed grant, Always approval and legacy always-allowed credential:
  Secrets, Covers (web reads only / web any method / run-with-secret / ssh),
  Expires ("never" or a live countdown, "in 12 min"), who created it and when,
  and **Revoke**. Timed and Always rows `POST /grants/revoke` (CSRF-checked); a
  legacy `approval: allow` row (marked "whole credential, any method, any covered
  mode") posts to `/policies` and sets the policy back to `prompt`, as before.
  Programmatic: `Broker.revoke_grant(id, user)` returns True, False (not found) or
  None (an Always could not be removed from the vault). The SSH host rules section
  is separate.

### Storage

- **Always** approvals live in the credential's vault item, in its `broker`
  metadata field `standing` (written through the same path as `approval` and
  `guidance`), so they survive restarts, redeploys and vault rebuilds, and the live
  catalog entry is updated immediately. Format (a list, at most 50 entries per
  credential; the validator names `standing[i].field`; unknown keys are refused and
  an invalid list makes the credential invalid, like `ssh_rules`):

  ```json
  "standing": [{"id": "9f2c41aa", "secrets": ["svc"], "mode": "http", "scope": "read",
                "expires_at": null, "created_by": "alice", "created_at": "2026-10-19T12:00:00Z"}]
  ```

  `secrets` (if present) must be exactly the credential's own name; `mode` is
  `http` or `env`; `scope` is `read` or `any` (`any` for env); `expires_at` must be
  null. Writing also records `standing_changed` ({by, at}). A failed write leaves
  the live state unchanged, the request is still approved, and
  `standing_change_failed` is audited.
- **Timed** grants live in `grants.json` next to the audit log (atomic write,
  mode 0600; names, mode, scope, times, id and creator only; format version 3,
  unchanged). Reloaded on start; expired entries and entries further out than
  `max_minutes` are dropped on load; a corrupt file fails closed
  (`grants_file_corrupt`). Grants saved before modes were recorded cover web and
  ssh only, never env.
- **Config** (`timed_grants`, validated at startup naming the field): `enabled`
  (default `true`), `durations` (minutes offered; 1-6 distinct whole numbers > 0
  and <= `max_minutes`; default `[5, 15, 30]`), `max_minutes` (cap, default 60, at
  most 1440) and `max_risk` (`none|low|medium|high`, default `high` = no ceiling). `enabled: false` hides the timed chips,
  rejects timed choices and ignores persisted timed grants; Always is unaffected.
  Settings shows "Standing approvals: timed grants (no ceiling) 5/15/30 min; Always
  up to low risk" ("(up to medium risk)" when `max_risk` is lowered).

### Legacy `approval: allow`

A credential with `approval: allow` in its metadata (set by hand in the vault, or by
older versions' Always chip) keeps working unchanged: it covers the whole
credential, every method, and every mode in its `auto_modes`, up to the
`auto_approve_max` ceiling. It appears in the same table and Revoke sets it back to
`prompt` (`policy_changed`). No migration is needed. The new Always chip is not
offered for such a credential ("already always-allowed").

### What the agent can and cannot see

Nothing about standing approvals reaches the agent: discovery, `GET /v1/status`
(only `features.timed_grants`, a bool), request results, notifications and the
audit API show a standing-approved request as a plain `approved`. The Policies
page, approval cards and history are approver-only.

### Audit events

All but the last few carry the request `id`; all are hidden from the agent audit API.

| Event | Fields |
| --- | --- |
| `decided` / `approved` | `grant_minutes` for a timed choice, `always_requested` for Always (`via: user`, `channel`) |
| `grant_created` | `kind` (`always`/`timed`), `grant_id`, `scope`, `grant_mode` (Always) or `mode`, `grant_minutes` (timed), `expires_at` (null for Always), `created_by`, `channel`, `approver_peer`, `approver_ip` |
| `grant_refused` | `kind`, `reason` (ineligible mode, `cap`, `backend`) |
| `policy_change_refused` | `reason` when an Always was requested but is not eligible |
| `grant_used` | `kind`, `grant_id`, `scope`, `grant_minutes`, `grant_left_s` (timed) |
| `approved` (auto) | `via: policy`, `grant_id`, `grant_left_s` |
| `grant_skipped` | `kind`, `reason: risk`, `method`, `auto_modes` (Always only) or `script_not_visible`, `grant_mode`, `grant_id`, `scope`, `risk_level`, `max_risk` |
| `grant_revoked` | `kind`, `mode`, `grant_id`, `secrets`, `scope`, `created_by`, `revoked_by`, `left_s`, `peer`, `client_ip` |
| `grant_expired` | `mode`, `grant_id`, `secrets`, `expires_at`, `created_by` (timed; lazily, by a 15 s sweep, or on load) |
| `standing_change_failed` | `op` (`create`/`revoke`), `error` |
| `grants_file_corrupt`, `grant_dropped`, `grants_file_write_failed` | `warning` / `reason`, `error` |
| `policy_changed` | legacy `approval` changes only (`from`, `to`, `user`) |

For any API that exposes audit events outside the approver UI: treat `grant_*`
events and the `grant_id`, `kind`, `scope`, `grant_left_s` fields as policy
context. The history rows and pop-over say "Decided by: standing approval
(always, reads only) (auto-approved), grant 9f2c41aa" or "standing approval (15
min, any method) (auto-approved), 12 min left when used".

## Guidance proposals (agent-written, human-approved)

Risk guidance can lower ratings, so an agent must never write it: it would weaken its own
approvals. Instead the agent may **propose** guidance, and you review and apply it on the
approval page. The agent never writes guidance directly and you do not copy and paste.

    asb guidance propose FILE|-          [{"name": "komodo", "text": "..."}, ...]
    asb guidance propose --from-dir DIR  DIR/NAME.txt, one file per credential
    asb guidance status ID               applied / denied / failed names (no approval)

Request (client API, agent key): `POST /v1/requests` with

    {"mode": "guidance", "entries": [{"name": "<credential>", "text": "<guidance>"}, ...]}

- 1 to 25 entries. Every `name` must exist in the catalog; an unknown or duplicate name,
  a `text` that is not a string of at most 2000 characters or contains hidden characters (the
  guidance metadata validator, see below), an entry with
  other keys, or a body over 100 KB is refused (400, 413 for the size). An empty `text`
  proposes removing that credential's guidance. The request has no `names` field.
- At most 3 proposals are pending at once (403 `too many pending guidance proposals`).
  They do not count against the pending cap of ordinary requests and a denial starts no
  deny cooldown on the credentials.
- The proposal waits `guidance_proposals.ttl_s` (default 3600, 300 to 86400) instead of
  the normal request TTL.
- Config (validated at startup, naming the field):
  `"guidance_proposals": {"enabled": true, "ttl_s": 3600, "write_spacing_s": 1.5}`.
  `enabled: false` refuses the mode (403). `write_spacing_s` (a number, 0 to 30, default 1.5)
  is the minimum gap between vault writes while applying entries (see "Applying entries"
  below). `GET /v1/status` shows only `features.guidance_proposals` (a bool).
- Result: `GET /v1/requests/<id>` returns `{"status": "approved"|"denied"|"expired"|
  "failed", "error", "guidance": {"applied": [names], "denied": [names], "failed": [names]}}`.
  Names only. Unlike other modes the result is not consumed by the first read, so
  `asb guidance status` can repeat it. Nothing about current guidance is ever returned,
  and there is no client command or endpoint that reads it.

### Applying entries (spacing, retry, failure classes, Retry)

The vault (Vaultwarden through `bw serve`) rate-limits bursts of writes, so applying many
ticked entries one after another used to fail the later ones. Now:

- The decision POST returns at once ("Applying N entries..."). The entries are applied on a
  worker thread that never holds the decision lock. The request stays `deciding` internally
  and the agent's poll shows `pending` until every ticked entry is resolved, then `approved`
  (as before) with the final lists. Entries are independent: one failure never stops the rest.
- Vault writes of all proposals are serialized and at least `write_spacing_s` apart.
- A transient error (`rate_limited`, `backend_unavailable`, `conflict`) is retried 3 times with
  exponential backoff (5 s, 15 s, 45 s, each scaled by a random 0.75 to 1.25) before the entry
  is `failed`. `invalid` and `other` errors fail at once. The class is derived from the
  exception text (e.g. "Too many requests", "Rate limit exceeded", timeouts, refused
  connections, 409); the vault's words are never kept or shown.
- Approver only: the history pop-over (the settled result) lists each entry as `applied`,
  `denied (not ticked)` or `failed: rate limited | backend unavailable | conflict | invalid |
  other error`. The agent result stays names only (`applied`, `denied`, `failed`).
- **Retry failed (N)**: on a settled proposal with failed entries the pop-over shows a button
  (`POST /request/retry`, form fields `id` and `csrf`; same SSO, CSRF, Origin and trusted-peer
  guards as `/decide`; only the dashboard or link channels, never push or HA). It re-applies
  only the failed entries through the same spaced, retried path, audits `guidance_changed`
  with `via: proposal_retry`, and updates the lists the agent polls (status stays `approved`).
  The text of FAILED entries (never denied or applied ones) is held in memory only, for one
  `ttl_s` after the proposal settled; after that, or after a broker restart, the button is
  gone and the entries must be proposed again.
- If the broker restarts while entries are being applied, entries not yet written stay
  unapplied, the in-memory request is gone (the agent's poll gets 404 `unknown request`), and
  the history row shows outcome `unknown`; propose the remaining entries again.

### Hidden characters are rejected

Text a model reads but a reviewer cannot see could differ from what you approve, so one strict
validator (`guidance.validate_text`) is used by proposals, the Policies-tab editor and the
catalog loader. It **rejects**, never strips or normalizes (stored text is byte-identical to
what was reviewed; only CRLF becomes LF and the ends are trimmed of spaces, tabs and newlines),
any of: control characters other than newline and tab; invisible format characters (zero-width
space, joiner and non-joiner, word joiner, BOM, bidi overrides, isolates and marks); tag
characters (U+E0000-E007F); variation selectors; private-use, unassigned and surrogate code
points; line and paragraph separators; any whitespace other than ASCII space, tab and newline
(NBSP, U+2000-200A, U+202F, U+205F, U+3000, U+1680, U+180E ...); the filler code points U+115F,
U+1160, U+3164, U+FFA0; and more than 3 combining marks in a row. The error names the class
and offset (`guidance contains hidden characters (invisible format character at offset 12)`)
and never echoes the characters. A proposal gets 400; the editor re-renders with the error.
In the catalog loader the credential stays valid but its guidance is ignored for
classification, flagged `guidance_invalid` (a note on the Policies page) and reported in a
hidden `guidance_ignored` audit event. Accented letters, curly quotes and dashes are allowed.

On the review card, an entry whose proposed text contains any non-ASCII character shows
**Non-ASCII characters: N (shown escaped as U+XXXX in the box below)**, and every non-ASCII
character is displayed as a `<U+XXXX>` marker (the real character in its tooltip) in both
columns, so a look-alike letter cannot pass for an ASCII one.

### Forced human review

All of this is enforced in code (tests/test_guidance_proposals.py):

- **Always high, no model.** `risk.assess` returns high for mode `guidance` before any
  analyzer is touched. The proposal text is never sent to any model; the request carries
  no guidance of its own, no summary and no description model call.
- **Never auto-approved.** `create` returns right after the notification: it never reaches
  `_auto_allowed`, the standing-approval claim (Always, timed grants), SSH rules or
  `approval: allow` / `risk.auto_approve_max high` / `auto_modes`. `_release` raises for
  the mode as a last guard. The card has no Always or Approve-for-a-while chips.
- **Notification buttons cannot decide it.** The notification carries no action buttons
  and no action token on any transport, and `decide_via` refuses the `push` and `ha`
  channels for the mode (403, nothing spent). Only the dashboard (`POST /decide`) and the
  link page (`POST /a/<nonce>`) can decide, with the same SSO, CSRF, Origin and
  trusted-peer guards, after you viewed the text.
- **Presence hold.** The notification is held while a page is open and released on the
  fallback like any other. The text is the same names-only line either way:
  `Guidance change proposed for N credentials`, with no guidance text.
- **Text lives only on the card.** Never in notifications, the audit log, history rows,
  discovery, status, results or the agent audit API. The text is dropped from memory as
  soon as the request is decided or expires.

### Review card

The pending card (dashboard) and `/a/<nonce>` show a **Guidance proposal** header with the
count and the warning "This text tells the risk classifier how to rate requests made with
these credentials. It can lower ratings. Review each one.", then one collapsible block per
entry (open for up to 5 entries, collapsed beyond that):

- the credential name, the character count and flag pills in the summary;
- the **current** guidance (or "none") and the **proposed** text side by side on a wide
  screen, stacked on a phone, with a deterministic line diff (removed lines red, added
  lines green, unchanged lines plain), all HTML-escaped;
- a visible **Flagged:** note when the proposed text contains a phrase that looks like
  lowering a rating or steering the classifier (case-insensitive, whole words): `always low`,
  `never high`, `rate low` / `rate it low`, `ignore`, `disregard`, `override`, `approve`,
  `safe`, `trusted`, `no risk`. A flag highlights; it never blocks;
- **changed since proposed** when the credential's guidance is different from when the
  agent wrote the proposal (the diff is against the new current text);
- an unticked **Apply this one** box.

Buttons: **Apply selected** (disabled by a little script until a box is ticked; the server
refuses an approval with nothing ticked, 400, and the proposal stays pending) and
**Deny all**. There is no approve-everything shortcut. Deny and expiry apply nothing.

### Applying

Apply selected sends `apply_<index>` for each ticked entry through the normal decision
path. Only ticked entries are applied, each through the same code as the Policies-tab
editor (`set_guidance`: vault first, then the live catalog, the `guidance_changed:
{by, at}` marker in the item's metadata). An entry whose write fails is reported as
`failed` and the others still apply. Entries you did not tick are `denied`.

### Audit events

| Event | Fields |
| --- | --- |
| `requested` | `id`, `mode: guidance`, `names`, `source`, `peer` (no text) |
| `assessed` | `risk: high`, `model: null` |
| `guidance_proposed` | `id`, `count`, `ttl_s`, `entry_names`, `entry_lengths`, `entry_sha256` (12-char prefixes) |
| `decided` | the usual fields (`channel` is `dashboard` or `link`) |
| `guidance_changed` | per applied entry: `secret`, `user`, `peer`, `client_ip`, `length`, `old_sha256`, `new_sha256`, `via: proposal` (or `proposal_retry`), `attempts`, `proposal` (the request id). No event when the text did not change |
| `guidance_proposal_result` | `id`, `status`, `applied`, `denied`, `failed` (counts), `applied_names`, `denied_names`, `failed_names`, `failed_classes` (aligned with `failed_names`); written again with `retry: true` after a Retry |
| `guidance_change_retry` | hidden: `secret`, `proposal`, `error_class`, `attempt`, `delay_s` |
| `guidance_change_failed` | hidden: `secret`, `proposal`, `via`, `error_class`, `attempts`, `error` (truncated) |
| `guidance_retry_requested` / `guidance_retry_refused` | hidden: `proposal`, `count` / `reason`, `channel`, `user`, `peer`, `client_ip` |
| `approved` / `denied` / `expired` / `failed` | as for any request |

The agent audit API shows only the `requested` event (names and mode, never text); the
other guidance events are hidden. The history pop-over for such a request shows the names,
counts, per-entry outcome, lengths and hash prefixes, and "Proposal text: not retained after
the decision".

## Credential requests (the agent asks, the human supplies the value)

`asb store` needs the agent to already hold the secret, which means the value passed through its
context. A credential request removes that step: the agent says it needs a credential for a service,
**you type the value on the approval page**, and the broker stores it. The agent learns only the stored
name.

    asb request-credential NAME --kind token|login --for "what it is for" \
        [--host H[,H]]... [--var VAR] [--mode http|env]

Request (client API, agent key): `POST /v1/requests` with

    {"mode": "credential", "names": ["NAME"], "kind": "token"|"login", "purpose": "...",
     "hosts": ["api.example.com"], "var": "MY_TOKEN", "cred_mode": "http"|"env"}

- `names` is exactly one valid name (`a-z 0-9 _ -`, 1 to 41). A name that already exists is refused (400,
  with the hint to use `asb update NAME`), as is a second pending request for the same name (403).
- `purpose` is one line of 1 to 300 characters with no control characters and none of the hidden
  characters guidance text also refuses (400, the message names the class and offset, never the text).
  It is the agent's own claim: the card marks it unverified and shows every non-ASCII character as
  `<U+XXXX>`. It is never put in a notification, and the audit log keeps only its length and a hash prefix.
- `hosts` (up to 10 plain host names), `var` and `cred_mode` are suggestions the human can edit. `var` must
  look like `MY_TOKEN` and may not be a name that changes how processes run (`PATH`, `LD_*`, ...).
- A request body with any of `value`, `secret`, `token`, `password`, `username`, `credential` is refused
  (400): there is no way to send a secret through the client API, and no client endpoint accepts one.
- Config (validated at startup): `"credential_requests": {"enabled": true, "ttl_s": 900}`. `ttl_s` is 120 to
  3600 (default 900: finding a token takes longer than a tap). `enabled: false` refuses the mode (403).
  `GET /v1/status` shows `features.credential_requests`.
- Caps: at most 2 credential requests pending at once (403), counted in the general pending cap of 3 as
  well, and a denial starts the usual 60 s deny cooldown for that name.
- Result: `GET /v1/requests/<id>` returns `{"status": "approved", "stored": {"name", "op": "create", "item",
  "field"}}` once, then `{"status": "released"}`. A failure returns `status: failed` with
  `store failed: <ExceptionClassName>` and, when the backend gives one, its coarse class
  (`conflict`, `rate_limited`, ...). **Never exception text**, anywhere: not in the result, the approval page,
  history, the audit log or the broker log, because an exception could embed the value in a form no scrubber
  would catch. To investigate a failed store, reproduce it against the backend (for example with
  `asb store` of a throwaway value, or the backend's own tooling).

### What the human sees and does

The card (dashboard, and the approval link the notification opens) shows the name, kind, purpose and the
suggestions, and a **Review and enter value** button and **Deny**. The button opens `/credential/<id>`,
a form with the name, allowed hosts, mode, variable name and the secret: one `type=password` field for a
token, or a plain text username plus a `type=password` password for a login (the username is cleared on a form error, like the secrets). It is a separate page because the dashboard refreshes itself
and must never hold a half-typed secret. **Store credential** posts to `/credential` on the approval
listener only, with the per-user CSRF token and the same-origin check.

- Hosts are required in http mode, so a token can only be sent where you intend. Env mode may have none, but
  only if you tick "No host restriction" (such a credential can never be used by `asb http`).
- A problem (bad name, existing name, missing host, dangerous variable, empty secret) re-renders the page
  with the error (422) and **every field except the secret**; the request stays pending and nothing is stored.
- The form claims the request once. A second or concurrent submit finds it handled; exactly one vault write
  happens.
- After a valid submit the page waits briefly for the vault write and says Stored, or Not stored with the
  failure class. A failed write ends the request: ask the agent to request again.

### What is stored

One backend `put(create=True)` with the value and the broker metadata together (the same atomic create
`asb store` uses), then the live catalog entry: item = name, `approval: prompt`, `allowed_hosts` as confirmed,
`created: {by, at}`. A **token** is a Secure Note (field `notes`) with one variable (default `NAME_TOKEN`).
A **login** is a Secure Note holding `{"username": ..., "password": ...}` as JSON, exposed as two variables by
`key`: `NAME_USERNAME` and `NAME_PASSWORD` (`--var PORTAL` makes the prefix `PORTAL_`). The metadata is
validated exactly as the catalog will read it back before anything is written. It works on every backend
(Bitwarden, local, file); a backend that refuses the create fails the request with the class only.

### Invariants (tests/test_credential_request.py)

- Always HIGH by code (`assessed` reason: credential requests always need a human to supply the value). No
  model call: there is no value at request time and the purpose is untrusted. Never auto-approved: not by
  `approval: allow`, Always, timed grants or SSH rules; the card has none of those controls, and
  `decide_via` refuses an approve without the human's validated entry (400, nothing claimed) and refuses
  every token channel (push, Home Assistant). The notification has no buttons and carries only
  `Credential requested: NAME`.
- The value is held in memory from the form post until the vault write finished. It is never in the audit log,
  history, request details, notifications, results, HTML, redirects, URLs or logs.
- Audit: `requested` (mode, kind, suggested hosts, purpose length and hash), `assessed`, `notified`,
  `decided`, `credential_provided` (kind, hosts, variable names, which fields the human edited, value size),
  `stored` (names only) and `approved`/`denied`/`expired`/`failed`; `credential_refused` for a refused form
  (a problem count). The agent's `asb audit` sees `requested` (name, mode, kind), `stored` and the outcome;
  `credential_provided` and `credential_refused` are hidden approver activity.
  History shows the request, follows a rename, and the detail view says the purpose is not retained.

## Plans (task-scoped grants for unattended jobs)

An unattended or long job (an overnight sync, a multi-step task while nobody is at the phone) can make
exactly the calls it declared up front, after a human approved the whole list once. The alternative is
one tap per call, or `approval: allow`, where the risk model is the only gate and the model reads text the
agent controls. A plan replaces that with a **deterministic match against a manifest a human read**. No
model is involved: not for the card, not for the match. Design and decisions:
[proposals/task-plans.md](proposals/task-plans.md). Commands: [cli.md](cli.md#plans-for-unattended-jobs).

    asb plan submit manifest.json          # waits for you; prints the plan id once approved
    asb http NAME POST URL ... --plan ID   # released with no prompt if it matches a rule
    asb plan status ID | list | close ID

Mental model: you approve a job's shopping list, with a stopwatch, on one machine.

### Plans and sessions

Both are time-boxed approvals bound to one client, with an absolute deadline, no renewal, memory only,
refused rather than prompted when a call is outside them, and both never follow a redirect. They differ in
what they approve: an **HTTP session** (above) is a standing permission for a set of hosts and methods
with a cookie jar and captured values, for login-style flows; a **plan** is an exact list of calls (host, method,
path, body shape, uses) for an unattended job, matched deterministically. They share the in-flight status
`running` (a running call is never pending: not listed, counted, decidable or expirable), the clock module
(`clock.py`), the Clients tab (Active plans, then Active sessions) and the exit codes: 7 ended, 8 refused by
the approved scope, and 9 retry later (plans). A plan with session steps is phase 2
([design](proposals/task-plans.md#2-relationship-to-sessions)); today a plan call that names a session is refused.

### The manifest

    {"v": 1, "task": "nightly finance sync", "description": "pull balances, post one note",
     "ttl_seconds": 28800,
     "rules": [
       {"secret": "monarch", "method": "POST", "host": "api.monarchmoney.com", "path_prefix": "/graphql/read",
        "max_uses": 50, "body": {"graphql": {"document": "query Accounts { accounts { id balance } }",
                                              "variables_keys": []}}},
       {"secret": "ledger", "method": "POST", "host": "ledger.example.com", "path_prefix": "/v1/notes",
        "max_uses": 5, "body": {"json": {"keys": ["text", "kind"], "pin": {"kind": "reconcile"}}}}]}

Rule keys: `secret`, `method` (uppercase), `host` (lowercase ASCII, one of the credential's
`allowed_hosts`), `path_prefix`, `max_uses`; optional `port` (default 443, or 80 for `http`), `scheme`
(`https`, or `http` only for a private IP address host), `query`, `body`. `sessions`, `window` and
`rules[].session` are recognized and refused ("not supported yet"). `task` (1-80 characters) and
`description` (0-400) are **untrusted text**: hidden and control characters are refused (the same checks as
credential-request purposes; the 400 names the class and offset, never the character), the card shows every
non-ASCII character as `<U+XXXX>` in a box marked "written by the agent, not verified, not used for any
decision", they never go into a notification, and the audit log keeps only their length and a hash prefix.
`ttl_seconds` defaults to `plans.default_minutes`; more than `plans.max_minutes` is a 400.

### The matcher

A call made with `--plan ID` is built once into a frozen request (placeholders substituted as in any http
call) and matched against the rules as sent. **Every** item must hold; any doubt or parse error is a
non-match, and that exact object is what is sent (the matcher runs again on the substituted request with
the filled header values treated as opaque).

- **Placeholders.** `{{...}}` in the URL (path, query or host) or in the body is refused. In a header it is
  allowed only if it is one of the rule's **own** credential's variables and is the **entire** value
  (optionally behind a scheme word such as `Bearer `). Nothing may survive substitution.
- **Host and URL.** One parse. Refused: userinfo, a fragment, a trailing dot, uppercase or non-ASCII
  characters in the host (checked before comparing; no silent lowercasing), characters parsers disagree on
  (backslash, spaces, control characters), an IP literal unless it is the rule's own host. Host and explicit
  port must equal the rule's. The rule host must be in the credential's `allowed_hosts` at submit **and at
  every use**. Scheme must equal the rule's; plain `http` only for a private/loopback/link-local IP literal
  (a name such as `.lan` is never "private" for plans). **Redirects are never followed**: the 3xx comes back
  masked, without `Set-Cookie`, and a follow-up is a new call that needs its own rule.
- **Method.** Exact and uppercase, one method per rule.
- **Path.** `path_prefix` is absolute, segment aligned (the path equals it or continues after a `/`), as
  sent. Refused: dot segments, an empty segment (`//`), `;`, backslash, any control character or whitespace.
  **A path is ASCII and the only percent-encoding allowed is `%20`**: every other encoded byte (`%25`, `%2e`,
  `%2f`, `%5c`, `%00`, `%EF%BC%8F` and any other UTF-8, encoded letters and digits, lowercase hex) and every
  byte of 0x80 or more is a non-match, so nothing can double-decode, or be read as another character by a
  Unicode-normalizing upstream. The broker never decodes anything before comparing. Every pattern the matcher
  uses is a full match (a trailing newline never passes), no control character or whitespace is accepted in
  the URL or any matched string, and just before sending, the request object actually handed to the sender is
  compared with the frozen matched one (URL, target, method, body, headers). A prefix of only `/` needs `plans.allow_root_prefix`.
- **Query string.** A rule that writes (anything but GET, HEAD, OPTIONS) defaults to `"query": "none"`: any
  query string is a non-match. It may instead list the allowed key names (`"query": ["dry_run", "page"]`,
  values unconstrained, up to 16); the card shows them. A GraphQL rule must be `"none"`. Read rules default to
  `"any"`. In every mode keys must be plain (`A-Za-z0-9_.-`, never percent-encoded, no `;`), and method or body
  override parameters (`_method`, `method`, `operationName`, `variables`, `extensions`,
  `x-http-method-override`, `body`) are always refused, so a matching body cannot be changed from the URL.
- **Headers.** Exact names only, from the same allowlist the sessions use (`Accept`, `Accept-Language`,
  `Content-Type`, `User-Agent`, `If-None-Match`, `If-Modified-Since`, `Authorization`, `X-Csrf-Token`,
  `X-Updated-Csrf-Token`, `X-Requested-With`, `X-Api-Key`; plus `Content-Length`, checked to equal the body):
  `plans.allowed_request_headers` (default `Accept`, `Content-Type`, `Content-Length`, `If-None-Match`,
  `User-Agent`) chooses among them, and only `Authorization`, `X-Api-Key`, `X-Csrf-Token`,
  `X-Updated-Csrf-Token` and `X-Requested-With` may carry a placeholder (whatever the configuration lists); the
  first four must carry one, never a literal. A placeholder value must be exactly `(Bearer |Basic |Token )?{{NAME}}` with `NAME` a variable of
  the rule's own credential. `Content-Type`, when present, is one of the five session types
  (`application/json`, `application/x-www-form-urlencoded`, `text/plain`, `application/graphql`,
  `multipart/form-data` with a boundary) with at most `charset=utf-8`; a json or GraphQL rule needs
  `application/json`. All of this is checked on the TEMPLATE (a filled credential is a neutral token), so a refusal
  never depends on a secret's value. Anything else (`Host`,
  `X-HTTP-Method-Override`, `X-Forwarded-*`, `Transfer-Encoding`...) is a non-match, as is any duplicate
  header (case-insensitive). `Content-Length`, when present, must equal the body's size in bytes; chunked
  bodies are refused.
- **Override scan.** The sessions' fail-closed rule applies: the text `method` (case-insensitive) in any decoded
  form (percent, HTML entity, `\\u`/`\\x`/quoted-printable escapes, NFKC, up to five rounds, non-letters
  removed) anywhere in the URL after the host, in a header name or value, or in the body refuses the call
  (`why: override`). The only exceptions are text the rule itself declares and the approver sees on the card: a
  path prefix, listed query keys, listed top-level json keys and GraphQL variable keys that contain `method`, and the
  exact GraphQL document. Values and nested keys are always scanned. The code is the sessions' own
  (`sessions.override_problem`, `header_problem`'s Content-Type and placeholder rules), imported, not copied.
- **Body.** `none` (empty), `json` (top-level keys a subset of `keys`; every `pin` present with exactly the
  pinned string, boolean, integer or null; unpinned values are free and the card says so; nested values are
  never pinned), `graphql` (see below) or `any` (opt-in with `plans.allow_any_body`; shown in red). A rule with
  no `body` accepts only an empty one; a write must declare a matcher. All JSON is parsed strictly:
  duplicate keys at any depth, NaN/Infinity, integers beyond 2^53, lone surrogates, a BOM, trailing data,
  nesting over 8 and more than 64 members per object are non-matches. `Content-Type` must be exactly
  `application/json` (optionally `; charset=utf-8`). Strings compare byte-exact after decoding. A body over
  `plans.max_body_bytes` never matches.
- **GraphQL.** `query` must be **byte-equal** to the declared `document` (at most 4096 characters), with
  only `query`, `operationName` and `variables` in the object: a batch (an array), `extensions` (including
  persisted-query hashes) or any other key is a non-match. `variables` keys must be a subset of
  `variables_keys`; values are free. `operation_name` is required when the document has more than one
  operation. A document containing `mutation` or `subscription` anywhere (strings and comments too, on
  purpose) or that cannot be parsed is a **write**; it is accepted only with
  `plans.allow_graphql_mutation` (default false) and is then high.
- **Uses, rate, in-flight.** Every rule needs `max_uses`. A use is **reserved under the plan lock when the
  match succeeds, before the upstream call**; a failed or timed-out call still counts (no refunds). At most
  `plans.rate_per_min` released calls per plan in a sliding 60 s (`rate_limited`, with `retry_after_s`; it
  does not consume a use) and at most `plans.max_inflight` calls executing per plan (`inflight_limit`; the
  slot is released in a `finally`, and the 15 s sweep reconciles it against live threads). Check order: plan
  state and client, rule match, rate, in-flight, uses.

Nothing user-supplied is ever compiled as a regular expression. Not in v1: regex, JSON-pointer pins, wildcards,
schema matching, windows, sessions, renewal.

### Time, binding and revocation

- **Absolute deadline.** `expires_at = approved_at + granted_s`, fixed at approval, never moved by use, no
  renewal and no extend button. On the card you may pick a **shorter** duration than requested, never longer.
  A plan is dead if **either** the wall clock or the monotonic clock says so (a clock set back cannot revive
  it; suspend is covered by the wall check); expiry is enforced on every use and by the 15 s sweeper.
- **Per client.** A plan belongs to the authenticated client id; every operation re-checks it under the plan
  lock. The plan id (128 random bits, hex) is an identifier, never a bearer: it authorizes nothing without the
  client credential. Unknown, expired, foreign and malformed ids all get the **same 404**. The shared legacy
  key cannot submit plans (`plans.allow_legacy`, default false). Revoking a client revokes its plans.
- **Memory only.** A restart drops every plan (fail closed): calls get exit 7 `kind: unknown` and the job must
  submit again, which needs you.
- **Before and after sending.** Immediately before the request is sent (after the vault read and header
  substitution, which can take seconds) the plan's liveness is checked again: client active, plan active and
  inside its deadline on both clocks; if not, nothing is sent, the use is
  given back and the call fails with the fixed text "release failed: plan or client ended". The upstream timeout is
  `min(30 s, time left to the plan deadline)`. After the upstream answers the same check runs and a response for an
  ended plan or revoked client is discarded (answer 404 `plan not usable`, exit 7; the use of a call stopped before
  sending is given back, `plan_used` is audited only for a call cleared to go out, and no `http_failed` is logged for
  a call that never left). A plan becomes `exhausted` (terminal) only when every rule is used up and nothing is in
  flight, so a plan on its last use stays listed, revocable and counted against `max_active_per_client` until its call
  finishes; an exhausted plan answers 403 `uses_exhausted` (exit 8), like an exhausted rule. A deadline noticed by any operation (even a submit) is audited as `plan_closed`.
- **Revoke.** Clients tab, **Active plans** table (above Active sessions), Revoke (SSO, CSRF, same-origin). It takes effect before the
  next call; a call already released finishes. Terminal plans stay visible to their owner and History for an
  hour.
- **Per credential.** `"plans": false` in the credential's broker metadata refuses it in plans, checked at
  submit and at use. Per client: `clients.<id>.plans` with `enabled` and `max_minutes`.

### The card

Requests tab and the link page, behind SSO, CSRF and same-origin. It shows, generated by code from the
validated structure: each rule (method, URL, uses, body fixed / partly pinned / "not constrained", that a path
prefix covers a **subtree**), the worst case (calls, credentials, sites, per minute, whether anything changes
data, deletes or accepts any content), each credential's `allowed_hosts` surface, and the deterministic tier:
read-only rules low; rules that write medium; **high** for DELETE, an any-content body, a GraphQL mutation or
a **shallow prefix** (one path segment or fewer). A high plan needs a **second confirmation** (Approve, then
"This plan can ... Approve anyway?"); the server enforces it, so a forged plain approve is refused. A long
duration is not a reason. The card cannot be approved from a notification, a push or Home Assistant button, a
token or the link page's old form: only the SSO approval pages, with CSRF.

Hard caps (a manifest over one is a 400 naming the field): `max_rules` 20, `max_uses_per_rule`,
`max_total_uses`, `max_minutes`, `rate_per_min`, `max_body_bytes`, no any-body, no `/` prefix, no GraphQL
mutation, `deny_secrets`. Approver-fatigue limits (all 429): a card waits `pending_ttl_s` (900); `max_pending`
4 pending plans overall (`max_pending`) and `max_pending_per_client` 1 per client, validated so that
`max_pending` is at least `2 * max_pending_per_client + 1` (two clients can never hold every pending slot; the
effective ceiling is the smaller of `max_pending` and clients times the per-client cap); `max_active_per_client` 2 active;
`submits_per_hour` 6 per client; and a **denial cooldown keyed on the client id only** (never the
agent-chosen task text, so rewording a task bypasses nothing) that escalates 60 s, 5 min, 30 min with each
further denial and is forgotten after a quiet day. Plan cards have their own pending caps and never consume
the shared limit on pending requests. The refused-submission audit record is coalesced like `plan_miss`.
The card's "claimed source" is shown only if it is a plain user@host claim (letters, digits and `@._:+()[]-`);
otherwise the socket address is shown.

A plan-released call is never a pending request: while it runs it is not listed, counted, decidable or
expirable (nothing asks a human), and it appears (for the agent's poll) only once it has settled.

**A plan makes a client effectively exempt from its own `auto_approve_max` for exactly the approved calls; that
is the point**, and it is why you approve each plan. A plan never widens a credential's `allowed_hosts`,
`deny_secrets`, `plans: false`, a client's `auto_approve_max: "none"` or a client-level `plans.enabled: false`:
each is checked at submit and again at every use (a per-client deny wins over a plan). A catalog change in the
vault is seen within `CATALOG_TTL` (60 s); changes made through the broker apply at once.

### Notifications

Push, Home Assistant, Telegram and ticker carry **no Approve or Deny**: the text is
`Plan requested: <client name>, <n> rule(s): <secret names>` plus a link to the card. Every token channel
refuses mode `plan`.

### Audit and History

| Event | Fields |
|---|---|
| `plan_issued` | `id` (the card), `plan_id`, rule count, `names`, `granted_s`, `expires_at`, approver, channel, peer, `manifest_hash`, `rules_hash`, task and description length and hash prefix |
| `plan_closed` | `plan_id`, `cause` (`agent`, `deadline`, `exhausted`), `uses` |
| `plan_revoked` | `plan_id`, `by`, `left_s`, `cause` (`human`, `client_revoked`), peer, client IP |
| `plan_used` | `id` (the call), `plan_id`, `rule` (index), `uses_left_rule`, `uses_left_plan`, `left_s` |
| `plan_miss` | `plan_id` (only the owner's), `reason`, `why` (the item that failed), `suppressed`; **coalesced** to 5 a minute per plan |

`plan_internal_error` (class name only) is hidden from agents. A plan-released call also writes the normal
`requested`, `approved` (`via: policy`, `decision_source: plan`, `plan_id`), `http_executed`, `delivered`, so
History shows "Decided by: plan abcd1234 (auto-approved), 3 h 12 min left". The agent audit view is a
deny-by-default whitelist: it sees `plan_id`, the rule index, uses left and a coarse reason, never the
approver, channel, cause, hashes or any text, and a plan-released call is a plain `approved`. Nothing in any
channel holds a secret, header value, body, document, `task`, `description` or exception text.

### Config

    "plans": {"enabled": true, "default_minutes": 30, "max_minutes": 480, "pending_ttl_s": 900,
              "max_rules": 20, "max_uses_per_rule": 500, "max_total_uses": 2000, "rate_per_min": 30,
              "max_inflight": 4, "max_body_bytes": 16384, "max_pending": 4, "max_pending_per_client": 1, "max_active_per_client": 2,
              "submits_per_hour": 6, "allow_any_body": false, "allow_root_prefix": false, "allow_graphql_mutation": false,
              "allow_legacy": false,
              "allowed_request_headers": ["Accept", "Content-Type", "Content-Length", "If-None-Match", "User-Agent"],
              "deny_secrets": []}

Validated at startup naming the field (unknown keys refused; `max_minutes` 1-720, the ceiling; routing and
framing headers cannot be allowed). `enabled: false` makes `POST /v1/plans` a 403 and every plan call a 404
`kind: unknown` (it is never turned into a prompt). `GET /v1/status` reports `features.plans`.
Per client: `"clients": {"c-1a2b3c4d": {"plans": {"enabled": true, "max_minutes": 60}}}`.

### Errors and exit codes

Unknown, expired, closed and wrong-client plans are always `404 {"error": "plan not usable", "kind": ...}`;
only the owner's retained record gets a specific `kind` (`ended`, `closed`, `revoked`), else
`unknown`.

| Situation | HTTP | `asb` exit |
|---|---|---|
| Manifest invalid or over a cap | 400 | 3 |
| Disabled, legacy client, never-auto client, `plans: false` or `deny_secrets` | 403 | 3 |
| Too many pending or active plans, or the same task denied recently | 429 | 3 |
| Call outside the plan (`no_rule` with `why`, `uses_exhausted` for a rule or the whole plan, `wrong_policy`) | 403 `{"error": "outside plan", "reason": ...}` | 8 |
| `rate_limited`, `inflight_limit` | 429 with `retry_after_s` | 9 |
| Plan not usable (`ended`, `closed`, `revoked`, `unknown`; also a call stopped mid-flight) | 404 | 7 |
| Denied / expired while pending | | 4 / 5 |
| Upstream status 400 or more | | 22 |

### Threat model for plans

An injected agent can submit a broad manifest: the caps refuse the widest shapes, every plan needs you to read
a code-rendered worst case, a high plan needs a second confirmation, and it can never reach beyond
`allowed_hosts`. The residual is approving without reading: treat an unexpected plan card as a possible
injection and deny it. A stolen plan id is useless without the client credential. A compromised client holds
the credential and can use its own live plans within their rules, caps, rate and deadline, nothing more; revoke
the client and its plans die at once. Not protected: what a matched call does at the target (the match
constrains the request, not the API's behavior), which is why every write is labelled "can change data".
## HTTP sessions (multi-step flows with one approval)

`asb http` is one call per approval. A flow that needs several related calls (log in and reuse a
session cookie, carry a CSRF token from one response into the next call) used to push agents into env
mode, where a program holds the raw secret. An **HTTP session** keeps the secret and the session state in
the broker instead. The design and its rationale are in
[proposals/http-sessions.md](proposals/http-sessions.md).

    asb session open NAME --for "purpose" --host H [--host H2]... [--methods GET,HEAD,POST] [--ttl 15m] [--max-calls N]
    asb http NAME METHOD URL ... [--session ID] [--capture NAME=header:X|cookie:NAME|json:$.a.b]...
    asb session status ID | asb session close ID

**What the human is approving.** A session is a time-boxed standing permission for one client, one
http credential, specific hosts and specific methods. The card says it plainly: this client may make
these calls with this credential to these hosts, without asking again, until the time runs out or the
call cap is used; each call is logged but is not shown to you as it happens. It lists the credential, hosts,
methods (anything beyond GET and HEAD is called out), the time limit (counted from the moment you
approve), the call cap and the client's name; the agent's purpose text is shown as its unverified claim
with every non-ASCII character escaped. You may shorten the time and the cap on the card; you cannot
lengthen them.

**Opening always needs a human.** The open request is high by code (no model sees it), never
auto-approved (`approval: allow`, Always, timed grants and SSH rules do not apply), has no Always or timed
chips, and no notification button, token or Home Assistant hook can decide it: only the authenticated approval
site can. It follows the other approval requests' rules for pending caps (3 requests, 2 session requests per
client), the deny cooldown per credential and the request TTL (`ttl_seconds`).

**Time-bound, abandoned at the deadline.** The deadline is `approval time + ttl` and is never moved:
no sliding extension, no renewal, no idle refresh. Default 15 minutes, hard maximum `sessions.max_ttl_s`
(default 60 minutes, ceiling 24 hours), minimum 30 seconds. At the deadline the cookie jar and captured values
are dropped, the session is marked expired, every further call with its id fails (HTTP 410, `session_expired`,
`asb` exit 7) and `session_expired` is audited. A sweeper does this every few seconds even when nobody
calls, and a lookup ends an overdue session itself. A session nobody uses still expires. A broker restart drops
all sessions (they are memory only). You can revoke one at any time on the Clients tab (immediate, audited) and
the agent can `asb session close ID`.

**Client-bound.** A session is bound to the authenticated client that opened it (see
[Clients](#clients-per-client-credentials-and-enrollment)). A call from any other client, including the legacy
shared key when the session belongs to an enrolled client, gets exactly the answer an unknown id gets (404,
`session_unknown`): no oracle on whether an id exists. Ids are 192 random bits, looked up by their SHA-256 and
compared in constant time. The legacy shared key counts as one client, `legacy`: it cannot tell machines apart, so
machines that share it share each other's sessions; enroll each machine to separate them. Revoking a client
ends its sessions at once.

**Scope (guardrails).**

- Hosts are required, each `HOST` or `HOST:PORT`, and the host must sit inside the credential's `allowed_hosts`: a session can only narrow, never widen
  (re-checked on every call, so narrowing the credential later also narrows the session). Http credentials only:
  ssh keys and credentials without `allowed_hosts` (env-only) are refused with a clear error. The manifest records and the card shows
  the port: a bare `HOST` means ports 80 (http) and 443 (https) only, `HOST:PORT` means exactly that port for either scheme. A call to
  any other port of an allowed host is refused.
- Methods default to GET and HEAD; others must be declared on open. A call outside the hosts, methods or call cap
  (`--max-calls`, default and cap `sessions.max_calls` 200) is **refused** with a specific error (exit 8), never
  prompted: the agent must open a new session, which you read in full. Refusals do not count as calls.
- A session call names exactly the session's credential and may not set a `Host` header. It is released
  without a prompt and without a model verdict. `asb http` without `--session` behaves exactly as before.
- **Redirects are never followed.** A 3xx is returned to the agent with its `Location` (masked); `Set-Cookie` on it is stored in the jar
  and stripped as usual. The agent makes a new call, which is scope-checked and counted like any other. This also means no redirect can
  change the method, port or host, and no hop goes uncounted. TLS verification, pinning and `tls_verify` are as for plain http calls.
- **Headers are allowlisted by exact name** (case-insensitive): `Accept`, `Accept-Language`, `Content-Type`, `User-Agent`, `If-None-Match`,
  `If-Modified-Since`, `Authorization`, `X-CSRF-Token`, `X-Updated-CSRF-Token`, `X-Requested-With`, `X-API-Key`. (The catalog has no
  "declared auth header" metadata, so no credential adds names.) Everything else is refused with one fixed message: `Content-Length` (urllib
  sets it from the bytes it sends, so the body on the wire is exactly the substituted body and never a second pipelined request),
  `Accept-Encoding`, `Connection`, `Expect`, `TE`, `Upgrade`, `Trailer`, `Transfer-Encoding`, `Content-Encoding`, `Host`, `Cookie` (the jar's), `Proxy-*`,
  `Forwarded`, `X-Forwarded-*`, `X-Original-*`, `X-Rewrite-*`, other `X-` names, duplicates, and so on. `Content-Type` must be one of
  `application/json`, `application/x-www-form-urlencoded`, `text/plain`, `application/graphql` or `multipart/form-data` with a `boundary`,
  with no parameter except `charset=utf-8`. A header value that contains a placeholder is allowed only if the whole value is
  `{{NAME}}`, optionally preceded by `Bearer `, `Basic ` or `Token `.
- **The checks never depend on a secret.** The header and method-override checks run on what the agent wrote, with credential placeholders replaced
  by a neutral token; captured values (chosen by the upstream, scanned when captured and again after substitution) are substituted. A credential
  whose value contains `method` neither changes the outcome nor produces a different error; a credential value with a line break or other illegal
  header character gets the same generic `invalid_request` error as any other bad header.
- **Method override is refused by one fail-closed rule.** A session call is refused (fixed message, not charged) if the agent's URL path, parameters,
  query or fragment, any header name or value, or its body contains the text `method` (case-insensitive) in any decoded form: raw, up to 5
  rounds of percent-, HTML numeric entity (`&#109;`, `&#x6d;`), `\uXXXX`, `\xNN` and quoted-printable (`=6D`) decoding with NFKC
  normalisation, and each of those with every non-letter removed. Bodies are scanned as UTF-8, latin-1, UTF-16/32 (when NUL bytes or a BOM suggest it) and double-encoded text, so fullwidth or mojibake spellings cannot hide; a body that is not valid UTF-8 is refused unless it is multipart/form-data or sent as `body_b64` (then all views are still scanned). Userinfo in the URL is refused. A multipart body that declares a
  Content-Transfer-Encoding is refused. This covers `_method` fields in a query, path, form, JSON or multipart, encoded and mixed-case
  variants and `;` separators, without any parser that could disagree with the upstream's. It deliberately also refuses legitimate fields such
  as `payment_method`: a call that needs one must use plain `asb http` without `--session` (one approval per call). The check runs once per call on the agent's text, and again on the substituted text only when the call uses `{{session.NAME}}`. A GET or HEAD call cannot carry a body. A captured value containing `method` (same
  forms) is not stored, so an upstream cannot poison a later call.
- **Refusals are metered and the audit log cannot be flooded.** A refused call is not charged against the call cap, but every refusal (scope, method,
  header, override, missing capture, call cap used, and a refund for a call that never left the broker) counts against a per-session budget of 10;
  the 11th ends the session (`session_ended`, `reason: refusal_budget`, exit 7). `session_refused` audit lines are coalesced: the first 5 per minute
  per session (or per client for unknown ids), then a counter that rides on the next logged line as `suppressed`.
- **Memory.** A session call's body and headers are not kept after the request details are retained; finished results are pruned 30 s after they
  settle, at most 4 uncollected results are kept per session (older ones turn into a "discarded" failure), and a client that never polls cannot pin memory.
- **Masking set.** A response is masked with the values held before it (a deleted or rotated cookie or token may be echoed), those it sets or offers
  (even if the jar, the cap or the method-text rule rejects them) and those held after. One rule for https-only values: every capture taken from an https response (header, cookie or JSON, whatever its source) is only ever
  substituted into a call whose final url is https; this is enforced where the capture values are read, under the same lock, so a concurrent rotation cannot
  flip the outcome (a refusal before anything is sent, not charged). `set-cookie` headers cannot be captured (use `cookie:NAME`), and a Secure cookie is never
  sent over http.
- **No free oracle on a secret.** Characters and length of the url and headers are checked on what the agent wrote, before the call is charged. After the
  credential is substituted the call is charged whatever happens, with one generic `invalid_request` error for any content-dependent failure. At most 100
  placeholders per call in total (a metered refusal). Overdue sessions are swept before the per-client and total caps apply, and an upstream error after
  the deadline or a revoke is `session_expired` (exit 7); the body read is bounded by the deadline.
- **Bounded work.** URL and header values up to 8192 characters, 50 headers, 100 placeholders of up to 64 characters, body up to 256 KB (a larger body is refused with a fixed message; use plain `asb http` for big uploads: every session body is scanned, so its size is bounded).
  Placeholders are scanned in linear time, and the store lock is held only for dictionary work (never for a scope check or an upstream
  call), so one hostile or slow call cannot delay another client's lookup, revoke, close or sweep.
- **In-flight calls do not outlive the session.** A call runs with a timeout of at most 30 seconds and never past the deadline. When the
  upstream answers, the session is checked again: a revoke, close, client revoke or the deadline in the meantime discards the response
  (the agent gets the fixed `session_expired` error, the cookies it set are not kept). A session call has status `running`, never
  `pending`: it is not an approvable request, no card or button exists for it, and `decide` refuses it.
- **Clock.** Deadlines use the monotonic clock; wall time is only for display and the audit log. A wall-clock step backward neither
  extends nor shortens a session.

**State held per session (memory only).**

- A **cookie jar**: cookies from upstream responses are stored per exact host and sent only to that host. `Domain` is
  ignored (it never widens), `Path` is honoured, `Secure` cookies are neither accepted from nor sent over plain http,
  `Max-Age` and `Expires` are honoured. At most 50 cookies of 4096 bytes. `Set-Cookie` headers are removed from every
  response the agent sees.
- **Captured values**: `--capture NAME=header:X-CSRF-Token | cookie:NAME | json:$.a.b[0]` stores a value from the final
  response (the minimal JSONPath allows dotted keys and array indexes only; anything else is a usage error and nothing
  is sent). A value must be short text without control characters. At most 16 per session and 8 expressions per call;
  repeating a name replaces it, which is how a rotating CSRF token is followed. They are used as `{{session.NAME}}` in the
  URL, headers and body (substituted in one pass), never returned. A capture that finds nothing is reported by name
  (`NOT captured`), and a `{{session.NAME}}` that was never captured refuses the call. A value must be printable ASCII (anything else is not stored and is reported as not captured).
- Credential, cookie and captured values are masked in the response body and headers if the upstream echoes them
  (exact-match masking like http mode, but for values of 4 or more characters; shorter values are not masked because that would corrupt ordinary words and numbers in a response, and the card says so). A response header the agent did not
  capture (for example a CSRF header) is an ordinary header and is visible.

**Errors and exit codes.** Messages are fixed text; no exception text reaches an agent, a log, the audit log, history or a
page (only class names and coarse categories such as `timeout`, `connection`, `tls`, `dns`, `invalid_request`).

| Situation | HTTP | `code` | `asb` exit |
|---|---|---|---|
| unknown id, malformed id, another client's id | 404 | `session_unknown` | 7 |
| expired, closed or revoked (told to the owner only) | 410 | `session_expired` | 7 |
| out of scope (host, port, method, credential), method override, body on GET/HEAD, call cap used, missing `{{session.NAME}}`, bad placeholder | 403 | `session_refused` | 8 |
| bad capture expression or open parameters | 400 | none | 2 (client-side) or 3 |

**Config** (validated at startup, naming the field):
`"sessions": {"enabled": true, "default_ttl_s": 900, "max_ttl_s": 3600, "max_calls": 200, "max_per_client": 3}`.
`GET /v1/status` shows `features.http_sessions` with these values. There is also a fixed cap of 20 open sessions in total.

**Audit events.** `session_requested`, `session_opened` (client, hosts, methods, ttl, max calls, expiry; `shortened`
when you lowered the limits), `session_used` (call number and cap, host; the call itself is also an ordinary request:
`requested`, `approved` with `via: session`, `secret_read`, `http_executed`, `delivered`), `session_refused` (reason
class: `max_calls`, `method`, `body`, `host`, `credential`, `placeholder`, `missing_value`, `header`, `unknown`, `expired`,
`closed`, `revoked`, `presend`), `session_closed`, `session_expired`, `session_revoked` (who), `session_ended` (`reason: refusal_budget`). Only the first 8 characters of
the id are ever logged (and a host string at most 255 characters); no cookie, captured value or credential is in any record. The agent's own audit view
([above](#what-a-client-sees-of-the-audit-log)) shows its client's session events through a deny-by-default whitelist
(no approver, no policy). The Clients tab has an **Active sessions** list: credential, client, hosts, methods, live
time left, calls used and the cap, and Revoke (CSRF-protected, audited).

**Threat model.** A session is a time-boxed standing permission: size it by what the card says. A stolen id is
useless without the owning client's key; with the key it can do only what the card allowed until the deadline. A
prompt-injected agent can spend the session inside its scope but cannot widen it, extend it, or turn out-of-scope
calls into prompts. A malicious upstream cannot redirect the credential or cookies anywhere: redirects are not followed. What
masking cannot stop: an upstream that echoes a value in a transformed form (encoded or split), and a program on the
agent's machine that has its own access to the broker's client key.

## Vault session lifetime

The vault is not kept open (the local backend drops its decrypted contents after
`idle_timeout` in the same way). With the `bw` backend it is unlocked on demand,
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

## Backend contract

The broker core talks to its credential store only through the `VaultBackend`
contract in `secret_broker/backends/base.py`. Bitwarden, the encrypted local
store and the test backends are implementations of it; nothing outside a
backend's own module knows about organizations, collections, item type numbers,
a CLI or a server. A new store (another password manager, a cloud secret
manager, a database) is one module plus one registry entry.

### Package layout

| Module | Contents |
|---|---|
| `backends/base.py` | `VaultBackend`, the error classes, `Item`, `CatalogRow`, `AutoShape`, `BackendSpec`, capability names, shared helpers |
| `backends/registry.py` | `register()`, `build_backend(cfg)`, entry-point loading |
| `backends/bitwarden.py` | `BwBackend`, `BwServeBackend` (everything Bitwarden-specific, including `organization`, `collection`, `serve`, `prewarm`) |
| `backends/local.py`, `backends/localstore.py` | `LocalBackend` and the encrypted store it keeps |
| `backends/file.py` | `FileBackend`: plaintext JSON, tests only |
| `backends/memory.py` | `MemoryBackend`: the minimal reference implementation |

`from secret_broker.backends import ...` exports the contract names and the bundled backends.

### Vocabulary

- **item**: a named record: a `login`, a `note` or an `ssh_key`. Names are
  case-sensitive but looked up leniently (see `get`).
- **field**: one value of an item: `password`, `username`, `notes`, `private_key`,
  or a custom field name. `None`, `""` and `"auto"` mean the item's natural secret:
  password for a login, notes for a note, private_key for an ssh_key.
- **meta**: the item's broker metadata, a JSON object (nested objects allowed),
  kept under the reserved field name `broker`.
- Reserved names: `broker`, `previous_value`, `previous_replaced_at`. They can be
  read (except `broker`) but never written through `put`, and never count as an
  adoptable field.

### Required methods

| Method | Contract |
|---|---|
| `get(item, field) -> str` | The value (`""` if present but empty). Lookup: the exact name, else the one case-insensitive match; two case-insensitive matches raise `BackendInvalid`. `previous_value` / `previous_replaced_at` are readable after a `keep_previous` write. A note's `notes` value has surrounding whitespace removed. `BackendNotFound` for a missing item or field, `BackendInvalid` for `broker`. Opens the store on demand. |
| `put(item, field, value, create=False, keep_previous=False, meta=None)` | `create=True` makes a new item in one atomic write: field `password` makes a login, `notes`/auto a note, `private_key` an ssh_key (needs `meta["ssh_public_key"]`), any other name a note with that custom field; `BackendConflict` if the item exists (also case-insensitively). `create=False` replaces the value of an existing field (`BackendNotFound` if the item or field is missing); `keep_previous` first copies a non-empty old value to `previous_value` and the time to `previous_replaced_at`. `meta`, when given, replaces the metadata. `value` must be a `str`; reserved field names raise `BackendInvalid`. |
| `catalog() -> list[CatalogRow]` | One row per item with metadata: `{"item", "meta"}` (`meta` is None only if the stored text is not an object). With the `adopts` capability also one row per login, note or ssh_key without metadata and with something usable: `{"item", "meta": None, "auto": AutoShape}`. Shapes only, never values. Cards, identities and items outside the backend's own scope are never listed. Sees current state. |
| `set_meta(item, meta)` | Replace the metadata with `meta` (nested objects preserved exactly). `BackendNotFound`, or `BackendInvalid` if `meta` is not an object. A backend that cannot persist metadata raises `NotSupported` and omits the `set_meta` capability; the broker then refuses policy edits ("Always allow", guidance, SSH rules) instead of failing late. |
| `delete(item)` | Remove the item. A missing item is not an error. |

`AutoShape` (what an item without metadata could offer; the broker derives
the secret's name, variables and host policy from it):

    login/note:  {"login": bool, "username": bool, "password": bool, "notes": bool,
                  "fields": ["custom field names that hold a value"], "uris": ["https://..."]}
    ssh_key:     {"ssh_public_key": "ssh-ed25519 AAAA..."}      (the public half only)

An empty login, a note with no text, or an ssh key missing either half has no shape and is not adopted.

### Optional capabilities

`backend.capabilities` is a `frozenset` of these names. Each optional method has
a default in the base class that raises `NotSupported`, and the core only ever
asks `"name" in backend.capabilities` (it never probes attributes).

| Capability | Method(s) | Used for |
|---|---|---|
| `set_meta` | `set_meta` works | Always-allow, standing approvals, SSH rules and hosts, guidance edits. |
| `create_login` | `create_login(item, username, password, uri=None, notes=None, meta=None)` | `restructure` (real username/password/URL fields). |
| `edit_item` | `edit_item(item, new_name=None, meta=None, drop_meta=False)` | `restructure`; rename or replace/remove metadata. |
| `warm` | `warm()` | Unlock ahead of the first read, in the background, while a human picks up the phone. A backend whose `prewarm` setting is off omits it. |
| `on_event` | `backend.on_event = fn` | Audit hook `fn(name, **fields)`; fields are names, counts and reasons only. A raising callback is ignored. |
| `adopts` | `catalog()` returns adopted rows | Items without metadata become credentials with safe defaults. |
| `export_items` | `export_items() -> list[Item]` | Migration: every login/note/ssh_key in scope WITH values (treat as secret). |
| `import_items` | `import_items(items, overwrite=False) -> names` | Migration: write whole `Item`s atomically. |

`close()` is part of every backend (the default does nothing): release helper
processes and unlocked state; always safe to call, repeatedly, from any thread;
the backend reopens on next use.

### Rules every backend follows

- **Thread safety.** Any method may be called from many threads at once. A write
  is atomic, and a successful write is visible to the next read from any thread
  and to a re-opened backend on the same storage.
- **No secret in an exception.** Messages, `repr` and chained causes name items and
  fields, never values, passwords, keys or tokens: the broker logs them.
- **Typed errors.** Every failure is a `BackendError` subclass; never a bare
  `KeyError` or `OSError`.
- **No values in events or logs**, ever.

### Error classes

| Class | Meaning | Broker behavior |
|---|---|---|
| `BackendRateLimited` | The store throttled us (HTTP 429). | Guidance applies retry it with backoff. |
| `BackendUnavailable` | Cannot be reached or opened now: server down, timeout, wrong or missing key, damaged file. | Broker stays up, keeps its last catalog, retries on the next refresh; guidance applies retry it. |
| `BackendConflict` | Item already exists, or the store changed under us. | Create refused; guidance applies retry it. |
| `BackendNotFound` | No such item or field. | Reported as invalid. |
| `BackendInvalid` | Malformed or forbidden request: reserved field, non-string value, non-object metadata, ambiguous name. | Reported as invalid. |
| `NotSupported` | The optional capability is not implemented. | Reported as invalid; the core checks capabilities first. |

`backends.error_class(exc)` maps an exception to the coarse class the broker
shows and audits (`rate_limited`, `backend_unavailable`, `conflict`, `invalid`,
`other`). It decides by the exception class first; a plain `BackendError`, or a
foreign exception, falls back to its text (`too many requests`, `timed out`,
`409`, `not found`, ...). Only the class is kept or shown, never the text.

### Configuration and the registry

`backend.type` selects a registered `BackendSpec(name, build, validate, doc)`.
`validate(cfg)` raises `BackendConfigError` naming the field (`backend.path: ...`)
and never opens files or connects; `build(cfg)` makes the backend. An unknown
`type` stops the broker at startup, naming `backend.type` and listing the known
types. Bundled types: `bw`, `local`, `file`, `memory`.

    from secret_broker.backends import BackendSpec, register
    register(BackendSpec("mystore", build=lambda b: MyStore(b["url"]),
                         validate=check_my_config, doc="My store. Keys: url."))

A third-party package can ship a backend without touching the broker: expose a
`BackendSpec` (or a zero-argument function returning one) in the
`secret_broker.backends` entry-point group. A plugin that fails to load is
logged and skipped, never fatal.

### Writing a backend

Subclass `VaultBackend`, set `kind` (the short type name `GET /v1/status`
shows) and `capabilities`, implement the five required methods, and run the
conformance suite. `secret_broker/backends/memory.py` is the minimal correct
implementation (about 150 lines) and the model to copy. `Item` is the neutral
record for adoption, import and export: `name`, `kind` (`login`, `note`,
`ssh_key`), `username`, `password`, `notes`, `uris`, `fields`, `meta`,
`private_key`/`public_key`; `auto_shape(item)` computes the `AutoShape`.

### The conformance suite (acceptance test)

`tests/backend_contract.py` defines `BackendContract`, a reusable mixin of about 100
tests that exercises the whole contract: create/read/update semantics and
error classes, `previous_value` and its timestamp, metadata round trips including
nested objects, catalog rows (explicit, adopted logins, notes, custom fields and
ssh keys, empty items, cards and identities ignored, disabled metadata), delete,
the case-insensitive then unique lookup rule, reserved and aliased field names,
unicode, multiline and 64 KiB values, "no secret value in any exception",
concurrent creates, updates and reads, persistence across a re-opened backend,
visibility of another instance's writes, idle lock and reopen, `close()`
idempotence, and every optional capability (create_login, edit_item, warm,
on_event, export/import, and `NotSupported` for what is not declared). Tests for
a capability a backend does not declare are skipped, and tests for an
undeclared optional method check that it raises `NotSupported`.

    class MyBackendContract(BackendContract, unittest.TestCase):
        persistent = True            # reopen() gives a fresh object over the same storage
        def make(self, **kw):        # a NEW, EMPTY backend (idle_timeout=... if supports_idle)
            return MyBackend(tempfile.mkdtemp())
        def reopen(self, backend):
            return MyBackend(backend.path)

A backend is conformant when its subclass passes. `tests/test_backends.py` runs
it for `MemoryBackend`, `FileBackend`, `LocalBackend` (file and env key sources),
and `BwBackend` / `BwServeBackend` against the fake `bw` of `tests/test_e2e.py`.

## Clients: per-client credentials and enrollment

Every machine or user is a **client** with its own credential. This replaces copying the broker's one
`client_key` everywhere: a leaked key can be revoked for one machine, requests are attributed to a
verified client, and rules can be scoped to one.

### The credential

The client generates 32 random bytes (`asbc1_` + base64url) locally and keeps them in `client.json`
(0600). The broker stores only `sha256("asb-client-secret-v1\0" + secret)` and compares in constant
time (`hmac.compare_digest` against every stored hash and the legacy key, no early exit). A request
presents the secret in `X-Client-Key`, exactly as the shared key was. Python's standard library has no
Ed25519 signing and `asb` must stay stdlib-only, so this is a bearer secret, not a keypair.

**Deviation from the issue (written reason):** the enrollment request carries the *hash*, not the
secret. The broker never sees the secret until the client uses it, so there is nothing secret in the
enrollment body for a proxy to log. The hash cannot be used as a credential.

### Enrollment endpoint

`POST /v1/enroll` and `GET /v1/enroll/<id>` on the client API are the only unauthenticated paths.
Body `{"name", "hash", "claim"}`: exactly those keys, at most 1024 bytes. It creates one thing: a
pending enrollment (never a request: no notification button, link, token or Home Assistant hook can
decide it). The reply is `{id, code, expires_in, interval}`; `id` is a 128-bit random token only the
enroller holds, and the poll returns nothing but that enrollment's status (and, once approved, its
client id and name).

- Limits (fixed-window, per source address and global): 3/10 submissions per minute, 6/20 per hour;
  polls 90/600 per minute; at most `enrollment.max_pending` (3) pending, 2 per source; a source whose
  enrollment was denied or expired waits 5 minutes; the client list holds at most 100 rows. All
  limiter maps are bounded. The listener sees the socket peer, so behind a reverse proxy every
  client looks like one source and the limits act as global ones (`X-Forwarded-For` is never trusted
  on this path).
- No oracle: a name that belongs to an enrolled client is accepted like any other (the human sees
  the clash on the card and must rename). Only duplicate *pending* names, the same hash, a code
  clash and caps are answered specifically. Error strings are fixed; no exception text.
- Notification: one per accepted enrollment, naming the proposed name only, with no buttons and no
  token. Expiry: `enrollment.ttl_s` (600, 30-3600).
- The card (Requests tab) shows the name (editable), the claim marked unverified, the source address
  and the confirmation code `XXXX-XXXX` = base32 of `sha256("asb-enroll-code-v1\0" + hash)`, the
  same code `asb enroll` prints. Approve and Deny exist only on the SSO-authenticated listener behind
  the CSRF token and same-origin checks. A human must refuse any enrollment they did not start. A
  newly enrolled client has no client-scoped rules.

### The client store

`clients.json` next to the audit log (0600, atomic write with fsync of the file and its directory):
id (`c-` + 8 hex, random, never reused), name, hash, created, approved_by, last_seen, last_source,
request count, state (`active`/`revoked`), the unverified claim, the enrolling address. Hashes only;
nothing secret. Statistics are buffered and written at most every 30 s. The legacy key is one
pseudo-client `legacy` / "shared key (legacy)" whose counters are kept in the same file.

- **Revoke** takes effect on the next request and sets state in memory under the lock before
  anything else; `Broker.create` re-checks the client under the request lock, so no request of a
  revoked client can be created or stay pending, and approving one that was pending is refused. The
  client's waiting requests are denied (without a name cooldown), its timed grants, Always
  approvals and SSH rules are removed, and `client_revoked` records the counts. A revoked row stays
  (so the error says "revoked") until removed on the Clients tab.
- **Durable or fail closed:** if the write fails, the revocation stays in effect in memory (it wins
  over loaded state), the Clients tab shows a warning, `asb status` reports `client_list: unsaved`,
  one `clients_file_write_failed` (error class only) is audited, and the save is retried on the next
  request, every 10 s and at SIGTERM. A restart before it succeeds would lose it: fix the disk. If
  the file exists but cannot be read or parsed at startup, **no per-client credential is accepted**
  (`clients_unavailable`, `client_list: unreadable`), enrollment is off and the file is never
  overwritten; the legacy key follows `legacy_client_key`. A missing file is a fresh install.
- Rename keeps the id; audit records carry both.

### Config

    "legacy_client_key": "allow",                       // allow (default) | deny
    "enrollment": {"enabled": true, "ttl_s": 600, "max_pending": 3},
    "clients": {"c-1a2b3c4d": {"risk": {"auto_approve_max": "none", "auto_modes": ["http"]}}}

The override block is keyed by client id (shown on the Clients tab; ids are random, so set it after
enrolling and restart) or `legacy`. Validated at startup, naming the field.

### Per-client rules

Every Always approval, timed grant and SSH host rule has a **client scope**: `*` (any client) or one
client id.

- A rule made from a card defaults to the requesting client; the card has an explicit "any client"
  choice (`rule_scope`; any unrecognised value means the requesting client). The Policies SSH rule
  form has a client select (default: any client, as such rules always were). The legacy shared key is
  one client (`legacy`), so its card rules are legacy-scoped.
- Resolution: a request is covered by a rule scoped to its client or a rule for any client (its own is
  tried first, then the global one; a read-only rule that does not cover a POST falls through to a
  global any-method rule). A rule for client A never applies to client B. Creating a client rule that a
  global rule already covers is a no-op.
- Ceilings: `risk.auto_approve_max` and `risk.auto_modes` are the defaults; a client's override wins.
  A credential's own `auto_modes` still beats both. A client with `auto_approve_max: "none"` **always
  prompts**: unlike the global `none` (which still honours timed grants and SSH rules) it blocks
  `approval: allow`, store-create, Always, timed grants and SSH rules for that client.
  `approval: allow` itself is a property of the credential and stays global. Presence suppression
  concerns the approver, not the client, and is unchanged.
- Storage and migration: a global rule is written exactly as before (no `client` field), so existing
  vault metadata, `ssh_rules` and `grants.json` load as global and nothing changes on upgrade. Only a
  client-scoped Always/SSH rule carries `client` (an older broker rejects that credential's metadata
  until the rule is removed: **remove client-scoped rules before downgrading**). Client-scoped timed
  grants are stored under `client_grants` so an older broker drops them instead of widening them.
- The Policies tables show who each rule applies to; the Clients tab lists each client's own rules.
  Revoking a client removes them.

### Audit events

`enroll_requested` (name, claim, peer, code), `enroll_decided` (approved/denied/expired, approver),
`enroll_refused`, `enroll_notify_failed`, `client_revoked` (counts of denied requests and removed
rules), `client_renamed`, `client_rename_refused`, `client_removed`, `client_auth_failed` (reason
`bad_key`/`revoked`/`legacy_denied`/`clients_unavailable`; one record per source per 30 s with a
`suppressed` count; never key material), `clients_file_corrupt`, `clients_file_write_failed`,
`clients_file_recovered`. Request events gain `client_id` and `client_name`; `grant_created` and
`ssh_rule_created` gain `rule_client`. None of the new events reaches the agent API. Neither the
secret nor its hash is ever logged (the code is the only derived value), and no exception text.

### What a client sees of the audit log

`GET /v1/audit` is scoped: a client authenticated with its own credential receives only events
stamped with its own `client_id` (so other clients' requests, names and ids, and system events,
are not returned, whatever the filters, `--request`, `--after` or `--tail`), plus its own name on
`requested`. The legacy shared key keeps the previous, unscoped view (it is many machines) but is
told no client names at all.

## Audit

JSONL, hash-chained, mode 0600, on the broker host. Never contains secret
values, header values or bodies (those live in the separate, short-lived
[request-details store](#request-details-headers-and-body)).

Events: `startup` (policies in force), `requested`, `assessed`, `notified`,
`secret_read`, `approved`/`denied`/`expired`/`failed` (with `via` user or
policy, approver, reported client IP, latency), `http_executed`, `delivered`,
`escalated`, `stored`, `request_detail_viewed`, `plan_issued`/`plan_used`/`plan_miss`/`plan_closed`/`plan_revoked` (see Plans), `grant_created`/`grant_used`/`grant_revoked`/`grant_expired` (see Standing approvals), `standing_change_failed`, `config_warning`, `policy_changed`, `policy_change_refused`, `policy_change_failed`, `guidance_changed`
(secret, user, peer, length, sha256 prefixes of the old and new text, never the
text), `guidance_change_refused`, `guidance_change_failed`, and
security events `auth_failed` (Home Assistant hook), `client_auth_failed`, `rejected`, `approval_viewed`,
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
- Guidance proposals: `guidance_proposed`, `guidance_proposal_result` and `guidance_changed`
  (the `requested` event for mode `guidance` shows names and mode only, never text).
- Credential requests: `credential_provided` and `credential_refused` (the human's entry and refused forms).
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
- Standing SSH rules: `ssh_rule_created`, `ssh_rule_used`, `ssh_rule_revoked`,
  `ssh_rule_expired`, `ssh_rule_refused`, `ssh_rule_change_failed`,
  `ssh_rules_state_corrupt`, `ssh_rules_state_write_failed`, and the `rule_id` /
  `decision_source` fields (a rule-approved request shows as a plain `approved`).
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
| `backend_closed` | idle_seconds (bw backend idle logout) |
| `store_unlocked`, `store_reloaded`, `store_written` | items (a count) (local backend) |
| `store_locked` | idle_seconds (local backend idle drop) |
| `store_unlock_failed` | reason (`wrong_key`, `key_missing`, `corrupt`, `unsupported`, `not_found`) |
| `store_rekeyed` | wraps (a count; `change-key` / `rotate-dek` while the broker runs) |
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
- **env mode is advisory** (see above). Prefer `http` mode. With `approval: allow`
  (default `auto_modes` includes `env`), an env request that is rated within
  `risk.auto_approve_max` and has visible scripts is released to the requesting
  machine without a prompt; an Always or timed env standing approval does the same.
- **Credential requests are a prompt-injection surface.** A page or document an agent reads can talk it into
  asking you for a credential. The design assumes that: the request carries no value; its purpose is shown as
  untrusted text; the entry form exists only behind your SSO, CSRF and same-origin checks, so you always
  start the paste; hosts are required so a pasted token cannot be sent anywhere; the stored item still asks
  on every use; nothing is stored without your submit. It cannot stop you typing a secret you should not.
  Treat an unexpected card as a possible injection and deny it.
- **Client credentials.** A per-client secret is a bearer token: whoever holds `client.json` is that
  client, until you revoke it. It protects against a leaked shared key (revoke one machine, not all),
  not against malware on the enrolled machine. The enrollment endpoint is the only unauthenticated
  path; its worst case is a few pending cards and notifications within the caps, and an approval
  needs you to match the code. An attacker who can race a pending enrollment gains nothing unless
  you approve a card you did not start. Rate limits are per socket address, so behind a proxy they
  are global. Until `legacy_client_key` is `deny`, anyone with the old shared key still works.
- **Plans** are one human approval for a deterministic list of calls with an absolute deadline; they do not
  stop what an approved call does at the target. See [Plans](#plans-task-scoped-grants-for-unattended-jobs).
- **HTTP sessions are standing permissions.** Approving a session lets that client make any call inside its hosts,
  methods and call cap, without asking, until a deadline that nothing can move. Read the card's methods
  (POST, PUT, PATCH and DELETE change things) and hosts as the worst case, keep the time short, and revoke on the
  Clients tab if in doubt. See [HTTP sessions](#http-sessions-multi-step-flows-with-one-approval).
- Output masking is exact-match; a program that transforms a secret before
  printing it (base64, splitting) defeats it.

