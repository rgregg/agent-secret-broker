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

    asb http NAME METHOD URL [-H 'K: V']... [-d BODY | -d @file | -d @-]
        e.g.  asb http grafana GET https://grafana.example.com/api/health \
                  -H 'Authorization: Bearer {{GRAFANA_TOKEN}}'

    asb NAME[,NAME] -- command args...    # run a command with the value in its environment

    printf '%s' "$VALUE" | asb store NAME --hosts a.example.com   # add a credential
    printf '%s' "$VALUE" | asb update NAME                        # rotate one (needs approval)
    asb ssh-agent [-- command args...]    # use broker-held SSH keys with ssh/git (see reference.md)

- `{{VAR}}` placeholders (the names `which` and `list` show) are replaced
  **inside the broker** in the URL, headers and body, so the agent never sees the
  value. This is `http` mode and it is the one to prefer.
- `NAME -- command` (env mode) hands the value to a command on the agent's host.
  The broker cannot check what the command does with it.
- Every use asks you to approve, in the browser or from the push notification. The
  command waits, up to about 5 minutes. **A denial or timeout is final**: the
  agent should stop and tell you what it needed rather than retry or look for
  another way.
- Values are only ever read from stdin (or a hidden prompt), never from an
  argument, so they stay out of shell history and `ps`.
- `asb help COMMAND` gives usage and an example for one command, and `asb guide`
  prints the manual written for agents.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Nothing found (`which`, `list`) |
| 2 | Usage or configuration error |
| 3 | Broker unreachable, or it refused the request |
| 4 | Denied by you or by policy |
| 5 | Expired or timed out waiting for approval |
| 22 | `http`: the upstream answered with status 400 or more (body still printed) |
| other | Env mode returns the wrapped command's own exit code |

## Teaching an agent to use it

The CLI documents itself (`asb guide`), so an agent needs only a pointer. Add
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

Two further steps make it stick:

- **Remove the alternatives.** Delete plaintext token files and standing keys once
  their values are in the vault. Anything the agent can read without asking
  bypasses the broker. (See "Threat model" in [reference.md](reference.md).)
- **Deny file access** to the old locations in the agent's own permission
  settings, where the tool supports it.

When a new credential is needed, ask the agent to add it with `asb store`; the
value goes through stdin and the audit log records the operation, never the
value.

## Several machines and several users

Each machine needs the `asb` file and a `client.json`; they share the broker's
one client key (the broker has a single key today, so rotating it means updating
every machine). Approvals always come from the one `allowed_user` signed in through your SSO,
whichever machine asked; the request shows where it came from
(`user@hostname`).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `no broker config` | `client.json` is missing or malformed, or the environment variables are not set |
| `cannot reach broker` (exit 3) | Wrong URL, TLS name mismatch, or the client API is not routed |
| `unknown secret name` | Not in the broker's collection (or hidden with `{"disabled": true}`); run `asb list` |
| `no credential available for HOST` (exit 1) | No secret lists that host in `allowed_hosts` |
| Waits and then exit 5 | No notification arrived or nobody approved; open the approval site, check Settings |
| Notification arrives but a click does nothing | Allow the browser's notifications in the operating system settings, and see Web Push in [reference.md](reference.md) |
