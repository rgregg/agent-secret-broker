# Proposal: root-exec (sudo without an account password, approved through the broker)

Status: **implemented** (native `sudo` broker mode, Rust helper and `asb sudo --`). Install and operation:
[../root-exec.md](../root-exec.md). Validated against the real broker with the real Rust client in tests;
the helper's final `exec` as uid 0 is covered by unit tests of everything before it, not run as root in CI.
one stays as the fallback for machines where a root helper cannot be installed.

## Problem

An agent sometimes needs root (restart a service, read a protected log). Today that means either a
password somewhere the agent can reach, or passwordless sudo for everything. Neither lets the human
see and approve the exact command.

## Goals

- The human approves each root command on their phone, seeing the exact argv. No account password
  exists anywhere: not in the vault, not in a file, not in an environment.
- The agent cannot reach root without that approval, even by calling the helper directly.
- A compiled, small, auditable helper (Rust, one static binary, few dependencies).

## Non-goals

- Plain `sudo` working unchanged (that needs PAM or a sudo approval plugin; see "Rejected").
- Interactive root shells, `sudoedit`, or running anything as a user other than root (v1).
- A new broker request mode (see "How it talks to the broker").

## Design

    agent --> asb sudo -- CMD...
                 `--> sudo -n /usr/local/sbin/asb-root-exec -- CMD...     (one NOPASSWD sudoers line)
                          `--> broker: env-mode request, argv = ["sudo", CMD...]   (root-only client key)
                                 human approves on the phone (card shows the command)
                          `--> helper execs CMD as root, clean environment, no shell

- **Sudoers.** `RYAN ALL=(root) NOPASSWD: /usr/local/sbin/asb-root-exec` is the only passwordless
  rule. The helper is root-owned, mode 0755, in a root-owned directory.
- **The helper makes the request itself** with its own broker client credential, stored in a
  root-only file (`/etc/secret-broker/root-exec.json`, 0600). The agent's key cannot approve or
  forge it, and a approval cannot be replayed: the helper only runs a command whose own request
  came back approved. Denial, timeout, broker unreachable: exit non-zero and run nothing (fail
  closed).
- **Exec.** argv is run directly (no shell) with the path resolved against a fixed secure PATH,
  environment cleared except `LANG`, `TERM` and a fixed PATH, cwd kept, stdin/stdout/stderr
  inherited, exit code passed through. `SUDO_USER` is recorded in the audit via `source`.
- **A native broker mode, `sudo`.** The request is `{mode: "sudo", argv, cwd, user}` with no credential
  names: there is no secret to release, and the approved answer carries only `{"approved": true}`. The
  broker owns everything around it, so it is not a variant of env mode:
  * *Who may ask:* off by default. `sudo: {enabled: true, clients: [...]}` lists the client ids (the
    helper's own enrolled client) that may create one; any other client is refused.
  * *Approval:* every request prompts. It is never auto-approved, never covered by a standing or timed
    grant, and has no one-tap action on a notification (open the approval page, read the command, decide).
  * *Risk:* always HIGH, rated without a model call, like `ssh_sign`.
  * *Card and audit:* the card shows the exact argv, cwd and target user; the audit log records the argv
    (first 50 words, as env mode does) and the client, never environment values.
  * *Delivery:* once, like env values; a second poll says `released`.
- **Client.** `asb sudo -- CMD...` becomes a thin front end for `sudo -n asb-root-exec -- CMD...`.
  `asb sudo NAME -- CMD...` (password credential) keeps working.

## Constraints and risks

- Whoever can write the helper, its directory or `/etc/secret-broker/root-exec.json` owns root.
  The installer checks ownership and modes and the helper refuses to run if its own checks fail.
- The approval is for the argv shown. A command that itself runs other things (`bash -c`, an
  editor, a package manager) is as powerful as its text; the broker's existing risk rating and the
  human reading the card are the control, as in env mode.
- A broker outage means no root. Deliberate.

## Rejected

- **PAM `pam_exec`:** PAM never sees the command, so the approval would be blind.
- **sudo approval plugin:** sees the command but is C against sudo's plugin ABI, and ties the
  feature to sudo 1.9+. Revisit if plain `sudo` compatibility matters.
- **Overloading env mode with a throwaway credential:** works with no broker change, but root
  commands would be rated, carded, granted and audited as "run with a secret", and a mis-set
  `approval: allow` would auto-approve root. A distinct mode keeps those decisions separate.

## Build

`helper/` Rust crate, `cargo build --release --locked`, built in CI and attached to releases.
Install is documented, not scripted, because it writes to `/usr/local/sbin`, `/etc` and sudoers.

## Implementation notes and deviations

- **Wire contract:** `tests/fixtures/sudo/*.json`, checked by both `tests/test_sudo_mode.py` and
  `crates/asb-proto`. A Rust server would be held to the same files.
- **Crates:** `asb-proto` (types and limits), `asb-client` (config, calls, approval polling; fails closed unless
  a poll says `approved` with `"approved": true`), `asb-root-exec` (library plus binary). A test-only `mock`
  feature gives the tools a scripted fake broker.
- **Stricter than designed:** the helper refuses (exit 10, before contacting the broker) any command file or
  directory the agent could write, so a script in the user's home is refused rather than approved; it re-resolves
  the command after approval and refuses if it changed; it checks its own binary and config file ownership and
  modes on every start.
- **What the card shows:** the resolved real path, not the name typed or the link followed (found in
  review: a link in an agent-writable directory could otherwise make `rm` display as `ls`). The same path is
  `argv[0]`, so multi-call binaries do not work through aliases.
- **Script operands:** a security review found that `bash x.sh` approved as root could be edited by the agent
  afterwards (the card shows argv, not the file). A first fix that scanned the arguments for files was found
  leaky in two further review rounds (`--rcfile` decoys, `-m`, `-s`, `-i`, `-h`, `--version` followed by a file,
  `xargs`, stdin programs): parsing each interpreter's options does not converge. It was replaced by a strict
  grammar (`scriptcheck.rs`): for a known interpreter only `INTERP SCRIPT [ARGS]` (SCRIPT first, trusted, shown
  and run as its resolved real path) or `INTERP -c CODE` is allowed, a lone `--version`/`--help` too, and
  everything else is refused; wrappers are refused outright. It is re-checked after approval.
- **Not covered:** programs that are not known interpreters (`find -exec`, `git`, `make`, editors, `awk -f`, ...),
  and what a trusted script itself runs, sources or imports; the card is the control for those.
- **User-Agent:** unrelated but shipped alongside: the broker's outbound requests, and the `asb` and Rust
  clients, now send a name of their own instead of urllib's default, which Cloudflare blocks.
