# Remote exec: prompt for unpinned and changed hosts (addendum)

Status: draft for approval, 2026-11-20. Amends `2026-11-19-remote-exec-design.md` (PR #80).

## Why

Today `exec` refuses a host or port the key has not pinned ("that host is not approved for this key"), and refuses
a host whose key changed. The owner wants flexibility: an agent that needs a different port or a new machine
should produce an approval prompt with a "remember this" option, not a dead end. A changed host key is also a
legitimate event sometimes (reinstall, rotated key), so it must prompt too, with a large caution banner.

## Behavior

A request for a host the key does not fully pin becomes an **unpinned exec request**, classified in one of
three states by comparing the host key the server presents with the key's `known_hosts` / `allowed_hosts`:

1. **new**: no pinned line for this host and port, and the presented key matches nothing pinned for that name.
2. **same key elsewhere**: no line for this host and port, but the presented key equals a key pinned for the
   same host name on another port. The card says so ("same key as nas:22").
3. **changed**: a line exists for this host and port and the presented key differs. This is the case that is
   also how a man-in-the-middle looks.

Rules for all three:
- Always a human decision. Never auto-approved: rules, `approval: allow`, grants and Always do not apply
  (the same refusal as `sudo`). A form post asking for one is refused (400) and claims nothing.
- The broker connects once, before the card exists, only to read the server's host key (SSH handshake, no
  authentication, no command), and shows the SHA-256 fingerprint, host, port and command.
- Buttons: **Approve once** (connect using exactly the key shown; nothing is saved) and **Approve and
  remember** (also writes the pinned `known_hosts` line and the `allowed_hosts` entry to the key's metadata
  through `set_meta`, like SSH rules; audited; revocable in the credential editor).
- **Changed** shows a large red banner above the command: the presented fingerprint, the pinned one, and the
  text "This server's key is not the one you pinned. This is what a man-in-the-middle looks like; it is also
  what a reinstalled or rekeyed server looks like. Approve only if you expect that." For `changed`, "Approve
  and remember" is replaced by **Approve and replace the pinned key**, which needs an extra confirmation tick
  and writes the new line in place of the old one (audited with both fingerprints).
- The connection that runs the command pins the fingerprint shown on the card (a one-line `known_hosts` for
  that request), so what you approved is what is connected to, even if the server's key changes in between.
- A card for an unpinned request states the limit plainly: "First time seeing this key. Compare the fingerprint
  with the host before approving." (trust on first use).

## Probe limits (the new capability)

An enrolled agent can now make the broker open a connection to a host and port it names. Limits:
- Only clients in `exec.clients`, only for an SSH key credential the client may use.
- The destination must pass the existing guard for operator-side connections: not loopback, link-local,
  the broker's own addresses, or a metadata name; `destination_deny_cidrs` applies.
- Per-client and global rate limit on probes, and the existing `max_pending_per_client`; a probe has a short
  connect timeout and reads only the handshake. Results (fingerprint or a fixed failure label:
  `unreachable`, `not_ssh`, `timeout`) are cached briefly per host and port.
- The agent never sees the fingerprint or any probe detail, only the request status.

## Also in this change

- `asb exec` without `--user`: the client sends the local `$USER` by default (broker still requires a user).
- Rules accept `host` as a list and `port` as a list (every entry still has to be pinned at match time).

## Audit

New hidden events: `exec_probe` (host, port, outcome label, never the banner), `exec_host_remembered` and
`exec_host_replaced` (fingerprints, who approved, channel). The card and notification show host and port; the
notification never shows the fingerprint as something to approve from (no approve button, the card is the
decision), as for `sudo`.

## Tests to write

Each shown to fail on the broken code, with a positive control beside it:
1. A new, same-key-elsewhere and changed host each produce a pending request, never a refusal, never an
   auto-approval, even with a matching rule and `approval: allow`.
2. The command connects with exactly the fingerprint on the card; a server key that changes after approval fails
   closed with `host_key_mismatch`.
3. "Approve once" persists nothing; "remember" persists the line and the allowed host; "replace" requires the
   extra tick and writes both fingerprints to the audit.
4. The probe refuses loopback, link-local, own and metadata destinations, honors the rate limit, and returns no
   banner or fingerprint to the agent.
5. A probe failure is a fixed label on the request, never an exception string.
6. Default `--user`, host and port lists in rules.
