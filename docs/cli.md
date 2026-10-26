# The `asb` command line and agents

`asb` is a single Python 3 file with no dependencies. An agent (or you) runs it
to find a credential and use it; each use waits for your approval.

## Install

On each machine where an agent runs:

    # 1. get the file (any of these)
    git clone https://github.com/rgregg/agent-secret-broker ~/agent-secret-broker
    # or: curl -fsSL -o ~/.local/bin/asb https://raw.githubusercontent.com/rgregg/agent-secret-broker/main/client/asb

    # 2. put it on PATH
    mkdir -p ~/.local/bin
    ln -sf ~/agent-secret-broker/client/asb ~/.local/bin/asb     # (skip if you downloaded it above)
    chmod +x ~/.local/bin/asb

    # 3. tell it where the broker is
    mkdir -p ~/.config/secret-broker
    printf '{"url": "https://asb-api.example.com", "key": "THE-CLIENT-KEY"}\n' \
        > ~/.config/secret-broker/client.json
    chmod 600 ~/.config/secret-broker/client.json

`url` is the broker's client API (port 8800 behind TLS) and `key` is the contents
of the broker's `client_key` file. You can use the environment instead:
`SECRET_BROKER_URL` and `SECRET_BROKER_KEY`. Needs Python 3.

Check it:

    asb list           # names, placeholder variables and hosts; no approval needed

## Everyday use

    asb which api.example.com             # which credential covers this host?
    asb list [--json]                     # everything available
    asb status [--json]                   # broker version, uptime, catalog health (no approval)

    asb audit [--request ID] [--event E[,E]] [--secret NAME] [--since 15m] [--tail] [--json]
    asb audit verify                      # is the audit log's hash chain intact?

    asb http NAME METHOD URL [-H 'K: V']... [-d BODY | -d @file | -d @-]
        e.g.  asb http grafana GET https://grafana.example.com/api/health \
                  -H 'Authorization: Bearer {{GRAFANA_TOKEN}}'

    asb NAME[,NAME] -- command args...    # run a command with the value in its environment

    printf '%s' "$VALUE" | asb store NAME --hosts a.example.com   # add a credential
    printf '%s' "$VALUE" | asb update NAME                        # rotate one (needs approval)
    asb ssh-agent [-- command args...]    # use broker-held SSH keys with ssh/git (see reference.md)

- `asb status` asks the broker what it is running (`GET /v1/status`): the build
  version (git sha), uptime, catalog count, invalid and adopted items, and whether
  the vault backend is healthy. It lists no secret names or hosts. Use it to verify a
  deploy ([deploy.md](deploy.md)).
- `asb ssh-agent -- ssh|scp|sftp|rsync|git ...` also reads the destination from the
  wrapped command line and sends it as an unverified "claimed destination" with
  each signature request (nothing is sent if it cannot be told; `eval "$(asb
  ssh-agent)"` has no command, so no claim). The agent also accepts OpenSSH's
  `session-bind@openssh.com` so the broker can verify the server's host key
  (OpenSSH 8.9+). See [reference.md](reference.md#ssh-keys-the-broker-signs-the-key-never-leaves).
- `asb audit` is for debugging: what happened to my request? It reads a
  **redacted** view of the broker's audit log (`GET /v1/audit`, see
  [reference.md](reference.md#audit-api-for-the-agent)) with the agent's own client key and
  needs no approval. `asb audit --request ID` (the id is in the broker's reply) prints that
  request's timeline; `--since 15m`, `--event failed`, `--secret NAME` and `--source S`
  filter; `--limit N` (default 100, max 500) with `--before SEQ` / `--after SEQ` pages;
  `--tail` follows new events every 2 seconds until Ctrl-C; `--json` prints the broker's
  response. It never shows risk verdicts, approval policy or values; full detail stays in
  the approval site's History page. `asb audit verify` checks the log's hash chain.
- `{{VAR}}` placeholders (the names `which` and `list` show) are replaced
  **inside the broker** in the URL, headers and body, so the agent never sees the
  value. This is `http` mode and it is the one to prefer.
  * The URL and header names/templates must be plain ASCII with no spaces or control
    characters (percent-encode: `?q=caf%C3%A9`; an internationalised host must be written as
    punycode). A `{{VAR}}` may not appear in the scheme, host or port. A trailing newline in
    a stored value is dropped when it is placed in a URL or header.
  * You may not set `Host` (unless it equals the URL's host), `Content-Length`,
    `Transfer-Encoding`, `Connection`, `Cookie`, `Upgrade`, `TE`, `Proxy-*` or
    `X-Secret-Broker-*`, nor the same header twice with different spelling.
  * `Set-Cookie` is removed from the response in plain `http` mode. Cookie flows need an HTTP
    session (below).
  * A failed call says only `release failed: <timeout|tls|dns|connection|invalid request|vault|other>`.
    `invalid request` means that a value filled into the request could not be sent as written; it
    reveals nothing else. A destination the broker refuses reads as `connection`.
- `NAME -- command` (env mode) hands the value to a command on the agent's host.
  The broker cannot check what the command does with it. If the credential is
  `approval: allow` (and not limited to `auto_modes: ["http"]`) and the request
  rates within `risk.auto_approve_max`, it runs without a phone prompt, and the
  plaintext value is released to this machine; a script that cannot be read or
  comes from stdin always asks. A standing approval (Always or timed) can cover it too.
- **Scripts are shown to you.** For `NAME -- command`, `asb` looks for the script
  file the command runs and sends its text with the request, so the approval card
  and the risk check see what the script does, not just `bash deploy.sh`. It skips
  leading wrappers (`env VAR=..`, `sudo`, `doas`, `nohup`, `time`, `timeout N`,
  `nice`, `stdbuf`, `exec`, `command`; the broker understands only this short list,
  anything launched through xargs, parallel, watch, su, flock, setsid, strace and the
  like prompts), then takes either an interpreter's script file
  (`bash`, `sh`, `zsh`, `python3`, `node`, `deno`, `bun`, `ruby`, `perl`, `php`,
  `pwsh`, `awk -f`, `sed -f`: the first operand that is a file) or the command
  itself when it is an executable text script (a bare name must be found on PATH and
  start with `#!`). The broker applies the same rules to the argv it receives and
  **auto-approves only commands it positively understands**: a script file with a
  matching entry, a restricted `sh -c` string, a known wrapper around those, or a
  short list of programs that cannot run other commands (cat, ls, grep, curl as a
  plain fetch with a fixed set of flags, ...). Anything else, including git,
  docker, make, npm, find, wget, openssl, `python -c` and a command with an
  unlisted option, always prompts and is not covered by a time-boxed grant either (see
  docs/reference.md for the full rules and the cost). `asb` sends its working
  directory as `cwd` and each entry's `path` is absolute (symlinks resolved, with
  `given` holding the path as named when it differs); the broker matches the
  operand to an entry by full normalised path, never by file name alone. Inline code (`-c`, `-e`, `-m`) is already in the command and
  reads no file. Limits: at most 3 files, 32 KB of text each (larger files send only
  the head and say so; the hash is of the whole file), text only (a binary, missing,
  unreadable, oversized or protected file is reported as such, never read), one
  `realpath` per file and never `~/tokens`, `~/.ssh`, `~/.config/secret-broker`,
  `/proc`, `/sys` or `/dev`. A script on standard input (`bash -s`, `python -`)
  cannot be seen and is reported as such, which makes the request look more
  opaque. Nothing is executed to find a script, and files the script itself
  includes or downloads are not followed.
  Just before running, `asb` re-hashes each script it sent; if one differs it does
  not run the command, prints `asb: script PATH changed after it was reviewed` and
  exits 6. **This is advisory and best effort**: the client is the agent, so it
  cannot prove what finally runs (a script can call others, and the agent could run
  something else). It catches an edit between the request and the run, nothing more.
  Obvious secrets in the text (`token=...`, `Bearer ...`, `password=...`, AWS and
  GitHub key patterns, private key blocks) are replaced by `[redacted]` by the
  broker before the text is stored, shown or sent to a model.
- Every use asks you to approve, in the browser or from the push notification. The
  command waits, up to about 5 minutes. **A denial or timeout is final**: the
  agent should stop and tell you what it needed rather than retry or look for
  another way.
- Values are only ever read from stdin (or a hidden prompt), never from an
  argument, so they stay out of shell history and `ps`.
- `asb help COMMAND` gives usage and an example for one command, and `asb guide`
  prints the manual written for agents.

### Proposing risk guidance

    asb guidance propose FILE|-            JSON: a list of {"name","text"} or {"entries": [...]}
    asb guidance propose --from-dir DIR    DIR/NAME.txt, one file per credential
    asb guidance status ID                 outcome of a proposal (no approval)

Risk guidance tells the classifier how to rate a credential's requests and can lower ratings,
so an agent cannot set it; it can only **propose** it. `propose` sends 1 to 25 entries (text up
to 2000 characters, empty text proposes removing the guidance; the whole request is limited to
100 KB), prints `asb: proposal ID sent`, waits ("waiting for approval on your phone... review
each entry on the approval page") and then prints the outcome, names only:

    applied: komodo
    denied: grafana
    failed: -

Exit codes: 0 if at least one entry was applied, 4 if you denied it, 5 if it expired (about an
hour), 3 if the broker is unreachable, refused it (unknown name, proposals disabled) or applied
nothing, 2 for usage errors. `asb guidance status ID` prints the same for a proposal already
sent, with the same exit codes. It prints `pending` (exit 0) until the human has decided and
every ticked entry has been applied (a large proposal can take a minute or more while the broker
spaces and retries vault writes); after a Retry of failed entries it prints the updated lists. There is deliberately no command
to read current guidance: the client never sees it. The review flow and its safeguards are in
[reference.md](reference.md#guidance-proposals-agent-written-human-approved) and
[guidance.md](guidance.md#letting-an-agent-propose-guidance).

### Asking the human for a credential

    asb request-credential NAME --kind token|login --for "purpose" [--host H[,H]]... [--var VAR] [--mode http|env]

When the agent needs a service the broker does not know, it runs this instead of asking in chat or
reading a secret itself. A card appears on the approval site (and a notification that names only the
credential); you open it, type the token (or username and password) into the form there, can edit the
name, hosts, mode and variable, and press Store. `asb` prints `stored: NAME` and nothing secret: it never
sees the value and never reads stdin. `--for` (one line, up to 300 characters) is shown to you as the agent's
unverified claim. `--host` may repeat or be comma separated; `--mode http` (default) needs at least one,
`--mode env` may have none. `--var` suggests the placeholder (for a login, the prefix of `NAME_USERNAME` and
`NAME_PASSWORD`). The request waits about 15 minutes (`credential_requests.ttl_s`).

Exit codes: 0 stored, 4 denied, 5 expired, 3 the broker refused it (the name exists: use `asb update`; invalid name;
too many pending; disabled) or the vault write failed, 2 usage errors. After it succeeds the agent uses the
credential through the normal flow, which still asks you on every use. Details, the safeguards and the
prompt-injection stance are in
[reference.md](reference.md#credential-requests-the-agent-asks-the-human-supplies-the-value).

### Plans for unattended jobs

A plan approves an exact list of calls for an unattended job; a session (below) approves hosts and methods for a login-style flow. Use one or the other for a call (`--plan` or `--session`, never both); both are refused, never prompted, outside what you approved, and neither follows redirects.

    asb plan submit FILE|- [--no-wait]      the manifest; waits for you (about 15 minutes), prints the plan id
    asb http NAME METHOD URL ... --plan ID  (or ASB_PLAN=ID) one call under the plan
    asb plan status ID [--json]             state, rules, uses used/max, time left (your own plans)
    asb plan list [--json]                  this client's plans
    asb plan close ID                       abandon your own plan early

For a job that runs with nobody at the phone: the agent writes a manifest of the calls it will make, you
read a rendering of every rule once and approve the whole plan (for a duration you may shorten), and calls
that match a rule then run with no prompt until the deadline. A call that does not match is **refused**
(exit 8, with a reason class such as `no_rule` and `why: path`), never turned into a prompt; making it
without `--plan` asks as usual. Do not submit a plan for one call. Plans need this machine's own credential
(`asb enroll`; the shared key cannot submit), end at their absolute deadline, cannot be renewed and are lost
when the broker restarts (exit 7, `kind: unknown`: submit again). `asb help plan` has the manifest format and
the matching rules (exact host, segment-aligned path, no query string on a write unless its keys are listed,
ASCII paths with only `%20` percent-encoded, a fixed header allowlist, exact GraphQL documents, no redirects); the
full description is in [reference.md](reference.md#plans-task-scoped-grants-for-unattended-jobs).

Plan exit codes: 7 the plan has ended or is not usable (`kind` is `ended`, `exhausted`, `closed`, `revoked` or
`unknown`): stop and submit a new plan; 8 the call is outside the approved plan (`no_rule`, `uses_exhausted`,
`wrong_policy`): do not retry it; 9 slow down (`rate_limited` or `inflight_limit`), retry after the printed
seconds. These match the http-sessions exit codes.

### HTTP sessions: login and cookie flows without a script

    asb session open NAME --for "purpose" --host H [--host H2]... [--methods GET,HEAD,POST] [--ttl 15m] [--max-calls N]
    asb http NAME METHOD URL ... [--session ID] [--capture NAME=header:X|cookie:NAME|json:$.a.b]...
    asb session status ID
    asb session close ID

Use plain `asb http` for one call or a few independent ones, **`--session` for a multi-step HTTP flow** (log in, reuse the
cookie, carry a CSRF token, log out), and env mode only when a program needs the secret itself (an official CLI, a
library). Do not write a script around `curl` or `requests` to do an HTTP flow.

`open` shows you a card (credential, hosts, methods, time limit, call cap, client) and prints a session id when you
approve. Hosts are required (`HOST` for ports 80 and 443, or `HOST:PORT` for exactly that port) and the host must be inside the credential's `allowed_hosts`; methods default to GET and HEAD
(declare POST, PUT, PATCH, DELETE or OPTIONS); the default is 15 minutes and 200 calls, and the broker has a
maximum. The deadline is absolute: it is never extended or renewed, however much the session is used. Then every call
is made with `--session ID` (preferred: `export ASB_SESSION=ID`, which keeps the id out of the process list; the flag wins over it; unset it when the flow is over) and needs no further approval: the broker keeps the cookies (and removes `Set-Cookie` from what
the agent sees) and `--capture` stores a response value for later `{{session.NAME}}` use in the URL, headers and body. A
UniFi-style flow:

    SID=$(asb session open unifi --for "list clients and rename one" --host unifi.local:443 --methods GET,HEAD,POST,PUT)
    asb http unifi POST https://unifi.local/api/auth/login --session $SID -H 'Content-Type: application/json' \
        -d '{"username":"{{UNIFI_USERNAME}}","password":"{{UNIFI_PASSWORD}}"}' --capture CSRF=header:X-CSRF-Token
    asb http unifi GET  https://unifi.local/proxy/network/api/s/default/stat/sta --session $SID
    asb http unifi PUT  https://unifi.local/proxy/network/api/s/default/rest/user/ID --session $SID \
        -H 'X-CSRF-Token: {{session.CSRF}}' -d '{"name":"x"}'
    asb session close $SID

Redirects are never followed (you get the 3xx and its `Location` and make a new call). A call outside the session's hosts, ports or methods, or past its cap, is refused (exit 8), not prompted: open a new session. When the
session has expired, been closed or revoked, or was never yours, the call exits 7. Only the client that opened a session can use
it. Details, limits, the threat model and the audit events are in
[reference.md](reference.md#http-sessions-multi-step-flows-with-one-approval).

### WebSocket sessions: a connection the broker holds

    asb ws NAME URL [--ttl 15m|900] [--max-frames N]      # open; a human approves one card; prints the id
    asb ws send [ID] TEXT|-       asb ws recv [ID] [--wait S] [--max N] [--json]       asb ws close [ID]
    asb ws [ID] [--linger S] [--close]                    # line relay: stdin lines out, frames in on stdout

For services that speak WebSocket (Home Assistant's `/api/websocket`). The broker connects, signs in with the credential's
operator-configured handshake and relays **text** frames; the token never reaches you. The card is always high risk and is
never auto-approved. Once approved, **what you send is not filtered**, so send only what the task needs. `export
ASB_WS_SESSION=ID` lets the later commands omit the id. Received frames have the credential masked; binary frames are not
shown (a note with the length goes to stderr); `recv` says when the broker paused reading because the buffer was full
(nothing is dropped). In the line relay, newlines inside a received frame print as spaces.

    ID=$(asb ws ha wss://ha.example.com:8123/api/websocket --ttl 10m)
    asb ws send $ID '{"id":1,"type":"config/area_registry/list"}'
    asb ws recv $ID --wait 5
    printf '%s\n' '{"id":2,"type":"get_config"}' | asb ws $ID --linger 2
    asb ws close $ID

The operator may restrict a credential with a **profile** (blocked or allowed message types, field rules). A refused message
says "blocked for this credential" or "not allowed for this credential", never reaches the server, and is not a prompt: do not
work around it, ask the human. Which profile applies is the operator's choice and is shown on the approval card.

Exit codes: 0 ok, 2 usage, 3 refused (credential not set up for WebSocket, host not allowed, too many sessions, connect or sign-in
failed), 4 denied, 5 unanswered, 7 ended (expired, closed, revoked, idle, the server closed the connection, unknown), 8
refused (frame or byte cap, oversize frame, rate limit). Details, the operator `ws` setting (handshake steps, query and
header sign-in), limits and the threat model: [reference.md](reference.md#websocket-sessions-the-broker-holds-the-connection).

### Admin: WebSocket profiles

For the broker's operator, not for agents. Runs on the broker host, stdlib only, no network; it reads and writes profile files
only. Profiles are JSON files (built in, or the operator's own in `ws_profiles_dir`) that a credential selects with
`"ws": {"profile": "NAME"}`; the format, rules and built-ins are in
[reference.md](reference.md#profiles).

    python -m secret_broker ws-profile validate FILE...          # exit 0 all valid, 1 any invalid, 2 usage
    python -m secret_broker ws-profile new NAME [--from BUILTIN] [--dir DIR]   # write a starter; never overwrites
    python -m secret_broker ws-profile list [--dir DIR]          # built-in and admin profiles, which overrides which
    python -m secret_broker ws-profile show NAME [--dir DIR]     # the effective JSON, then its risk notes

`DIR` defaults to `ws_profiles_dir` from the broker settings (`--config FILE` and/or `BROKER_CONFIG`, as for the broker), else
`ws-profiles/` next to `audit_log`. `validate` prints one line per file (`ok PATH: NAME` or `INVALID PATH: reason` naming the field,
with fixed text, never the file's content). `new` writes mode 0644, refuses to overwrite and rejects names that are not kebab-case;
`new NAME --from home-assistant` starts from a built-in (a file with a built-in's own name replaces it for every credential).
`list` exits 1 when any profile is invalid. `show` exits 1 for an unknown or invalid name.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Nothing found (`which`, `list`, `audit`); `audit verify`: the chain is broken |
| 2 | Usage or configuration error |
| 3 | Broker unreachable, or it refused the request (`status` too; `enroll`: refused) |
| 4 | Denied by you or by policy |
| 5 | Expired or timed out waiting for approval |
| 6 | Env mode: a script changed between the request and the run (`asb: script PATH changed after it was reviewed`); nothing was executed |
| 7 | **Ended** (sessions and plans share this): the session or plan expired, was closed, revoked, used up, or is unknown (also: lost to a broker restart). `asb` prints the kind. Stop; a new one needs the human again |
| 8 | **Refused by the approved scope** (sessions and plans share this): a call outside the session's hosts, methods or call cap, a missing `{{session.NAME}}`, or a plan call that matches no rule. Never turned into a prompt; do not retry it as is |
| 9 | **Retry later** (plans): rate or in-flight limit; `asb` prints `retry_after_s` |
| 22 | `http`: the upstream answered with status 400 or more (body still printed) |
| other | Env mode returns the wrapped command's own exit code |

## Teaching an agent to use it

The quickest way is `asb agent-setup` (next section). To do it by hand instead:
the CLI documents itself (`asb guide`), so an agent needs only a pointer. Add
this to the agent's instructions: `~/.claude/CLAUDE.md` for Claude Code,
`AGENTS.md` in a repository for agents that read it, or the equivalent for other
tools. Do not put your broker's URL or key in a public repository.

    ## Credentials

    Never read credential files (for example ~/tokens) or hunt for API keys. Use the
    secret broker CLI, `asb`, which is on PATH:
    - `asb which HOST|URL` / `asb list` find the credential and its {{VAR}} names (no approval).
    - `asb http NAME METHOD URL -H 'Authorization: Bearer {{VAR}}'` makes the call;
      the value never reaches you.
    - Every use asks the user to approve. A denial or timeout is final: stop and
      tell them what you needed.
    - Run `asb guide` for the full manual (store/update, exit codes).

### `asb agent-setup`

    asb agent-setup [--agent claude|codex|copilot|all] [--scope user|project] [--dry-run] [--remove]

Installs a short block (about 12 lines, no names or hosts, pointing at `asb guide`) into the
instruction files of the coding agents on this machine. It is local only: it makes no broker
call, never reads `client.json` and never prints the client key.

| Agent | `--scope user` (default) | `--scope project` (current directory) |
|---|---|---|
| `claude` | `~/.claude/CLAUDE.md` | `./CLAUDE.md` (or `./.claude/CLAUDE.md` when only that exists) |
| `codex` | `$CODEX_HOME/AGENTS.md`, default `~/.codex/AGENTS.md` | `./AGENTS.md` |
| `copilot` | `$COPILOT_HOME/copilot-instructions.md`, default `~/.copilot/copilot-instructions.md` | `./.github/copilot-instructions.md` |

- Without `--agent` it auto-detects agents (config directory, program on PATH, or for project scope
  an existing file), prints what it found, and only creates files in directories that already
  exist. With `--agent NAME` or `all` it also creates missing files and directories. Exit 1 when it
  finds no agent.
- The block sits between `<!-- asb:agent-setup begin vN -->` and `<!-- asb:agent-setup end -->`. A
  re-run replaces just that span in place (so a newer `asb` upgrades an older block); text outside
  the markers is never touched. Line endings (LF or CRLF) follow the file.
- Symlinks fail closed. With `--scope project` a target whose resolved path is outside the current
  directory is refused (a cloned repository cannot redirect the write). With `--scope user` a
  symlinked file (dotfile setups) is written through, the resolved path is always shown
  (`PATH -> RESOLVED`, also in `--dry-run`), and a resolved target that is not a regular file or
  whose directory is not owned by you is refused. Temp and backup files are created exclusively
  next to the resolved target and never follow a symlink.
- `--dry-run` prints a unified diff and writes nothing. A file that changes is first copied to
  `FILE.asb-bak-YYYYMMDDHHMMSS`; unchanged files are not rewritten or backed up.
- `--remove` deletes only the block (and the blank line the install added before it).
- It refuses, exit 2 and writing nothing for any target, when a marker is damaged (begin without
  end, end without begin, duplicates, wrong order), the file is read-only, not UTF-8, a directory or
  a dangling symlink. Fix the file by hand and re-run.
- Open: `asb status` does not yet warn about an outdated block; compare the `vN` in the marker.

Verified instruction-file locations (checked 2026-10-21 against the vendors' docs):

- Claude Code (<https://code.claude.com/docs/en/memory>): user `~/.claude/CLAUDE.md`; project
  `./CLAUDE.md` or `./.claude/CLAUDE.md`; also `./CLAUDE.local.md`. All files found from the working
  directory up are concatenated (nearer ones last), not overridden. An `AGENTS.md` is read only when
  there is no `CLAUDE.md` above the working directory.
- Codex CLI (<https://developers.openai.com/codex/guides/agents-md>, now served from
  learn.chatgpt.com): global `$CODEX_HOME/AGENTS.md` (default `~/.codex`), but a non-empty
  `AGENTS.override.md` in that directory replaces it (agent-setup prints a note if one exists);
  project `AGENTS.md` from the repository root down to the working directory, concatenated with the
  nearest last, capped at 32 KiB in total. Restart Codex after changes.
- GitHub Copilot CLI (<https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions>):
  repo `.github/copilot-instructions.md`; user `$HOME/.copilot/copilot-instructions.md`
  (`COPILOT_HOME` replaces `~/.copilot`). User and repo files are merged with no defined precedence.
  Takes effect in a new session.

Not verified: a user-level file for Copilot in VS Code or other IDEs (GitHub documents only
personal instructions set on github.com for Copilot Chat there, which a local file cannot set;
the SSMS docs name `%USERPROFILE%/copilot-instructions.md`, not checked here). The Copilot target
is therefore the CLI's file. Behaviour was not tested against the real agents, only the documented
paths.

Two further steps make it stick:

- **Remove the alternatives.** Delete plaintext token files and standing keys once
  their values are in the vault. Anything the agent can read without asking
  bypasses the broker. (See "Threat model" in [reference.md](reference.md).)
- **Deny file access** to the old locations in the agent's own permission
  settings, where the tool supports it.

When a new credential is needed, prefer `asb request-credential`: you type the value on the
approval page and the agent never sees it. (`asb store` also works if the agent already holds the
value; it goes through stdin and the audit log records the operation, never the value.)

## Several machines and several users

Give every machine its own credential instead of copying one shared key around:

    asb enroll --name build-box --url https://asb-api.example.com

`asb enroll` makes a random 256-bit secret on this machine, sends the broker only a hash of it,
prints a confirmation code such as `K4QZ-7MWD`, and waits. On the approval page a card appears
(name, the `user@host` the machine claims, the address it came from, the same code). **Compare the
code with your terminal and press Approve only if they match and you started it; Deny anything you
did not start.** On approval `asb` writes `~/.config/secret-broker/client.json` (`url` and the new
secret as `key`, mode 0600) and checks that it works. The secret is never printed, never sent
while enrolling and never an argument. No key is copied by hand.

- `--name` is the client's name (lowercase letters, digits, `- _ .`, up to 32; default: this
  host's name). You may change it on the card. `--url` defaults to `SECRET_BROKER_URL` or the
  `url` already in `client.json`.
- An existing `client.json` that holds a key is replaced only with `--force`, and is first copied
  to `client.json.bak-<time>`. If the broker rejects the new key the old file is put back.
  `SECRET_BROKER_KEY` in the environment overrides the file: unset it.
- Exit codes: 0 enrolled, 4 denied, 5 expired (the card lives 10 minutes by default), 3 refused
  or unreachable (a name already waiting, too many pending, enrollment off), 2 usage.
- The **Clients** tab lists every client (name, claimed host, enrolled, last seen, request count,
  state, effective auto-approval ceiling, its own rules) and can rename, revoke and remove them.
  Revoking takes effect on the next request (`asb` then says `this client has been revoked; run
  asb enroll`), denies the client's waiting requests and deletes its own rules.
- Every request now shows the **authenticated client** (verified) next to the `user@host` text
  the client typed (unverified), in cards, history, request details and the audit log.
- The old shared key keeps working as the single client "shared key (legacy)" until the broker
  config sets `legacy_client_key` to `deny`; then it is refused with a message pointing at
  `asb enroll`. Approvals always come from the one `allowed_user` signed in through your SSO,
  whichever machine asked. Details: [reference.md](reference.md#clients-per-client-credentials-and-enrollment).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `no broker config` | `client.json` is missing or malformed, or the environment variables are not set |
| `cannot reach broker` (exit 3) | Wrong URL, TLS name mismatch, or the client API is not routed |
| `unknown secret name` | Not in the broker's collection (or hidden with `{"disabled": true}`); run `asb list` |
| `no credential available for HOST` (exit 1) | No secret lists that host in `allowed_hosts` |
| Waits and then exit 5 | No notification arrived or nobody approved; open the approval site, check Settings |
| Notification arrives but a click does nothing | Allow the browser's notifications in the operating system settings, and see Web Push in [reference.md](reference.md) |
