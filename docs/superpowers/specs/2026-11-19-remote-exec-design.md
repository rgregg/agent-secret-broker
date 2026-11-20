# Remote exec: the broker runs a command over SSH and returns the output

Status: draft for approval, 2026-11-19

## Intent and why

An SSH signature is a blank check. `asb ssh-agent` signs a login without knowing what the session will do, so
every login is a tap and none can be auto-approved safely. In 36 days of the owner's audit log, `agent-ssh`
caused 195 of 674 human taps (28%), the biggest single source; 32 of them took longer than sshd's two-minute
login window and 21 SSH requests expired unanswered.

Remote exec turns the unknowable into text the broker can read. The agent asks the broker to run one command
or script on a host; the broker (which already holds the key) connects, runs exactly that, and returns the
output. The human, the risk model and the rule matcher all see the command before anything runs, the same way
they see an HTTP request. Low-risk commands can then be auto-approved by rule.

The owner's stance: this does not have to be airtight. It gives far better observability than the agent
signing path (every command and result is in the audit and history), and the goal is to auto-approve more,
not to wall everything off.

## Goals

- A new request mode `exec`: host, account, and either one command or a script. The broker connects as that
  account with a stored SSH key, runs it, and returns exit status and output.
- The exact text that runs is the text that was shown, rated and approved (no re-interpretation after approval).
- Reuse what exists: SSH key credentials, `ssh_hosts` known-hosts pinning, the risk model, guidance, auto-approve
  rules, the approval card, history and audit.
- Deterministic low risk for a small allowlist of plain read-only commands, so they can be auto-approved
  without a model.
- A per-key switch that stops the agent-signing path (`ssh_sign`) for that key, so a host moved to exec cannot be
  reached around the vetting.
- Full observability: the command (or its hash for scripts), host, exit status, duration and sizes are in the
  audit log and the history pop-over.

## Non-goals

- Interactive sessions, a TTY, `scp`/`rsync`/`sftp`, git over ssh, port or agent forwarding, jump hosts. These
  stay on `asb ssh-agent`, always asking a human.
- Classifying arbitrary shell perfectly. Shell is Turing-complete; anything the broker cannot parse simply is
  not low risk (see Classification).
- Streaming output while the command runs (v1 returns the output when the command finishes; incremental
  polling is a later step).
- A gate installed on each target host (the "forced command" alternative, below).
- Multi-host fan-out, remote file transfer, Windows targets.

## Anti-goals (a failure even if it works)

- The command that runs differs from the one the human or model saw.
- The private key ever reaches disk, an environment variable, a log, an agent response or the agent's machine.
- The broker connects to a server whose host key is not pinned (no trust on first use).
- The request can choose SSH options, a proxy, a port forward, environment variables or a remote key: the only
  inputs are host, account, command or script, and a timeout.
- Command output, the command text or an exception string reaching a notification or the audit log beyond the
  fixed fields listed below (docs/reference.md security invariants).

## Constraints

- Broker is Python 3.12, stdlib only. There is no stdlib SSH client, so the broker runs the OpenSSH client
  binary; the image gains `openssh-client` (it runs as `nobody`, as today).
- Backends expose the key through the existing secret-read path; the value stays in memory and is passed to
  OpenSSH only through a pipe.
- `client/asb` (Python CLI, the spec) and `crates/asb-cli` (Rust) both gain `asb exec`; the CLI parity tests
  and the client version bump (`clientver.py`) apply.
- The broker needs a network route to each target host (VM 122 reaching the LAN works today for HTTP).
- Docs move with behavior: `docs/reference.md` (new section, audit events, config), `docs/guidance.md`
  (exec guidance example), `docs/cli.md`.
- Tests follow AGENTS.md "Writing tests": each security property shown to fail on broken code, positive control
  beside every negative assertion, exact statuses and reasons, no sleeping (fake clocks, `tests/_fast.py`).

## Approaches considered

- **A. The broker runs OpenSSH itself (chosen by the owner).** Needs `openssh-client` in the image and a route
  to hosts. Output is visible to the broker, so it can be scanned and capped; the key never leaves the broker.
- **B. A gate on each host.** A forced command in `authorized_keys` asks the broker before running
  `SSH_ORIGINAL_COMMAND` (the `asb-root-exec` pattern). Needs no broker network access, but must be installed
  and kept current on every host, and the broker never sees the output. Not chosen; possible later for hosts the
  broker cannot reach.
- **C. Both.** Deferred.

## Design

### Request

`POST /v1/requests`:

    {"mode": "exec", "names": ["agent-ssh"], "host": "nas", "user": "ryan", "port": 22,
     "command": "systemctl status nginx", "timeout_s": 60, "source": "..."}

or `"script": {"text": "...", "interpreter": "sh"}` instead of `command` (exactly one). `names` is exactly one
SSH key credential. `host` must be a name in that key's `ssh_hosts.allowed_hosts` that also has a
`known_hosts` line (an allowed fingerprint alone is not enough: the broker needs a name to connect to and a key
to verify). `user` matches the same account pattern SSH rules use. `port` defaults to 22. `timeout_s`
defaults to 60, at most 600. Command at most 4096 characters, script at most 32 KiB, no control characters other
than tab and newline, hidden/bidi characters refused (400, fixed label), the same checks as `sudo` argv.

Off by default: `"exec": {"enabled": true, "clients": [...], "max_concurrent": 4, "max_output_bytes": 262144,
"max_seconds": 600, "readonly": [...]}`, validated at startup like `sudo`. Only listed client ids may ask; the
legacy shared key may not. `GET /v1/status` shows `features.exec`.

### Classification

1. **Simple command.** The text parses under a deliberately small grammar: words separated by spaces, single
   quotes literal, double quotes with no `$`, backtick or backslash inside, and no unquoted `; & | < > ( ) $ `
   backtick \ newline * ? [ ] { } ~ ! #`. The result is an argv. (Anything else is not simple.)
2. **Deterministic low.** A simple command whose program (bare name or absolute path) is on the read-only table,
   with its subcommand and flags inside that entry's allowed set, is **low** with no model call. The built-in
   table is short and conservative (for example `systemctl status|is-active|is-enabled|show|list-units`,
   `docker ps|images|inspect|logs`, `journalctl`, `df`, `uptime`, `free`, `uname`, `hostname`, `date`, `ls`,
   `ps`, `ip addr|route`, `ss`, `zpool|zfs list|status`); the owner can extend it with `exec.readonly`.
   File readers (`cat`, `head`, `tail`, `grep`) are not on it: they can read secrets, so they go to the model.
3. **Everything else** (not simple, not on the table, or a script) goes to the existing risk model with the
   credential's guidance, exactly as an env or http request does. The model sees the command or script text as
   untrusted data, scrubbed of obvious secrets. No model verdict means high. A script or non-simple command is
   never rated low by the table; only the model (with the owner's guidance and `approval: allow`) can lower it.
4. **The text that runs is the text that was classified.** A simple command is rebuilt from the parsed argv with
   shell quoting and that string is what the remote shell receives. A non-simple command is sent byte for byte
   as shown. A script is sent on standard input to `<interpreter> -s`, byte for byte, with its SHA-256 shown on
   the card and recorded in the audit event.

### Approval

- Same policy chain as http: client may use the credential, `approval: allow` plus the risk ceiling, Always
  is **not** offered (see below), then auto-approve rules, otherwise a human.
- **Timed grants and Always do not apply to `exec`.** A grant on the key would allow any command, which is the
  agent-signing problem again. Standing permission for exec is expressed as rules, which are specific.
- **Auto-approve rules** gain mode `exec`: `{"name", "mode": "exec", "secret", "host", "account", "clients",
  "argv": [...]}`. For a simple command the rule's `argv` is a prefix of the parsed argv (so `["systemctl",
  "status"]` allows `systemctl status nginx`); for anything not simple, a rule never matches. They live in
  the same two places as http rules (config, and the credential editor's stored rules) and share the matcher.
- The card shows host, account, the command shell-quoted with every non-ASCII character as `<U+XXXX>` (as the
  sudo card does), or the script text in full with its hash, plus the classification reason. Notifications
  carry host, account and a clipped command, and a link; buttons follow the same action policy as http.

### Execution

Runs on its own thread after approval (as `_release_by_policy` does for HTTP), so it never ties up the request
thread; the agent polls `GET /v1/requests/ID?wait=` and receives
`{"status": "released", "exit_code": N, "stdout": "...", "stderr": "...", "truncated": false}` once.

Per call the broker creates a private directory (0700, under its state directory), writes a `known_hosts` file
generated from the key's pinned `known_hosts` lines for that host only, starts a private `ssh-agent`, loads the
key with `ssh-add -` from a pipe, and runs `ssh` with: `-F /dev/null`, `BatchMode=yes`,
`StrictHostKeyChecking=yes`, `UserKnownHostsFile=<generated>`, `IdentitiesOnly=yes` (agent only),
`ForwardAgent=no`, `ClearAllForwardings=yes`, `RequestTTY=no`, `ControlMaster=no`, `ProxyCommand=none`,
`ConnectTimeout=10`, `ServerAliveInterval=15`, and no environment passed on. Nothing from the request becomes an
option. The agent and directory are removed in a `finally`. Output is read with a byte cap
(`max_output_bytes`, stdout and stderr separately), decoded as UTF-8 with replacement, masked with the existing
credential-value masker, and returned with `truncated` set if cut. The process is killed at the timeout.

Fixed failure labels, never exception text: `host_key_mismatch`, `host_not_pinned`, `connect_failed`,
`auth_failed`, `timeout`, `output_cap`, `ssh_unavailable`, `internal`. They appear in the audit event and the
agent response.

### Closing the agent-signing path

Key metadata `ssh_agent`: `"allow"` (default, today's behavior), `"ask"` (every `ssh_sign` for this key goes to a
human with no timed grant, Always or SSH rule), `"off"` (`ssh_sign` for this key is refused with a fixed
label). The owner sets it per key in the credential editor once a host works over exec. It exists so the
exec vetting cannot be walked around, not as a requirement to use exec.

### Audit and history

Events (hidden from the agent audit API): the usual `requested` (command: first 50 words, each clipped to 300;
for a script, only length and SHA-256), `approved`, plus `exec_started` and `exec_finished` (exit code, byte
counts, duration, truncated flag, failure label, host name, account). Command output is never in the audit
log and never in a notification. The history pop-over shows the command or script and the result from the
short-lived request-details store, as it does for env scripts.

### Client

`asb exec NAME HOST [--user U] [--timeout S] -- COMMAND...` (the words are joined and quoted the way the
broker will classify them) and `asb exec NAME HOST --script FILE`. Prints stdout and stderr to the matching
streams and exits with the remote exit code; broker-side failures use exit 3 with the fixed label. A refusal or
denial uses the existing codes. The Python CLI is the spec; the Rust CLI follows with the parity test.

## Decisions made on the owner's behalf (please check)

- Output is returned when the command finishes, not streamed (cost if wrong: long commands show nothing until done).
- No timed grants or Always for exec; rules only (cost: no one-tap "allow for 30 minutes" on a host).
- The deterministic table is deliberately tiny and excludes file readers (cost: more model calls, which is the
  safe direction).
- Hosts must be named in `allowed_hosts` and have a `known_hosts` line; fingerprint-only hosts cannot be used.
- The agent-signing switch is per key, not per host.
- Image gains `openssh-client`; no other new dependency.

## Left to the builder

- Exact grammar implementation and read-only table contents beyond the examples; where the table lives.
- Names of config keys inside `exec`, and the layout of the card and the credential-editor controls.
- How `ssh-agent`/`ssh-add` are driven (a tiny wrapper is fine) and temp-dir placement; the `ssh_path` override
  used by tests.
- Test structure: unit tests against a stub `ssh` binary, plus an end-to-end test against a real sshd in a
  throwaway container like `tests/e2e_root_exec/`.
- Commit splitting; whether the Rust CLI lands in the same PR.

## Security properties to test

1. An agent key cannot make an `exec` request unless its client id is in `exec.clients`; the legacy shared key
   is refused (each shown to fail with the check removed).
2. A host not in `allowed_hosts`, or without a `known_hosts` line, is refused before any connection.
3. A host key mismatch fails closed with `host_key_mismatch` and no command is sent.
4. The command the stub `ssh` receives is exactly the text on the card (simple: the requoted argv; non-simple:
   byte for byte; script: stdin byte for byte with the shown hash); an edit between request and run is impossible.
5. Every shell metacharacter in the grammar list makes a command non-simple and never deterministic low
   (a table over each character, positive control with a plain command).
6. A read-only table entry with a disallowed subcommand or flag is not low.
7. A rule never matches a non-simple command or a script; a rule on credential A never approves B.
8. The key never appears in an environment, a file, argv of any process, a log, an audit event or a response
   (canary key, inspect the stub's view and the captured logs).
9. Output and command text never appear in a notification or the audit log; `exec_finished` carries counts and
   a fixed label only. Output is masked for known values and capped.
10. `ssh_agent: "off"` refuses `ssh_sign` for that key with a fixed label; `"ask"` never uses a grant or rule.
11. The ssh option list contains nothing derived from the request (a request with option-looking values in
    host, user or command changes no option).
