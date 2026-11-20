# Exec: unpinned and changed hosts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `exec` prompts a human (with "remember") for a host or port the key does not pin, and prompts with a caution banner when a pinned host's key changed, instead of refusing; plus the `--user` default and host/port lists in rules.

**Architecture:** A probe module reads a server's host key (handshake only); intake classifies the request as pinned / new / same-key-elsewhere / changed and routes the three unpinned states to a human-only path (like `sudo`); the approval card and decision handler gain the banner, "remember" and "replace" actions persisted through the existing `set_meta` path; the runner pins the approved fingerprint for that one connection.

**Tech Stack:** Python 3.12 stdlib, the OpenSSH client (`ssh-keyscan` or `ssh` with a throwaway known_hosts for the probe), Rust and Python CLIs for the `--user` default.

**Spec:** `docs/superpowers/specs/2026-11-20-exec-unpinned-hosts-design.md` (binding), amending `docs/superpowers/specs/2026-11-19-remote-exec-design.md`. Read both and AGENTS.md. The code to extend is already on `main` (PR #80): `secret_broker/execmode.py`, `execrun.py`, the `exec` sites in `broker.py`, `autorules.py` (`_exec_ok`), `sshkey.py`, `sshhosts.py`, `tests/test_exec_*.py`, `tests/e2e_remote_exec/`.

## Global Constraints

- Python 3.12 stdlib only. No new dependency.
- All three unpinned states are always a human decision: no rule, `approval: allow`, grant, Always or SSH-rule chip can approve them; a form post asking for one is refused (400) and claims nothing.
- The probe reads only the SSH handshake: no authentication, no command, short connect timeout, results cached briefly per (host, port). Destination guard: refuse loopback, link-local, the broker's own addresses, metadata names, and `destination_deny_cidrs`. Rate limits per client and global, plus `exec.max_pending_per_client`.
- Probe failure labels (closed set, never exception text): `unreachable`, `not_ssh`, `timeout`, `refused_destination`, `rate_limited`.
- The agent never sees a fingerprint or probe detail, only the request status.
- The connection that runs the command pins exactly the fingerprint shown on the card (one-line `known_hosts` for that request); a key that changes after approval fails closed with `host_key_mismatch`.
- "Remember" writes the pinned `known_hosts` line and the `allowed_hosts` entry through `set_meta` under the existing config lock (follow `SshRulesMixin._persist_ssh_rules`); "replace" needs an extra confirmation tick, replaces the old line, and audits both fingerprints.
- New hidden audit events: `exec_probe`, `exec_host_remembered`, `exec_host_replaced`. Notifications carry host and port, never the fingerprint as something to approve from, and no approve button (as `sudo`).
- No real secrets, hostnames or personal details anywhere; `S3CR3T-` canaries, `example.com`, `127.0.0.1`. Docs move with behavior. Tests follow AGENTS.md "Writing tests" (fail on broken code, positive control beside each negative, exact assertions, fake clocks).
- Run the suite with `python tests/run_tests.py`. Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Review Focus

- A request that is `new` but whose presented key equals a key pinned for a different host name must NOT be shown as "same key" (only the same name on another port).
- A server that presents different keys on the probe and on the real connection (race): the real connection must fail closed.
- A probe to a name that resolves to a forbidden address (DNS), and a redirect-like trick via IPv6-mapped IPv4.
- The `changed` state must never offer plain "remember"; the replace action needs its tick and must not apply when only the id and decision fields are forged.
- Concurrent requests for the same unpinned host: one probe (cache), two cards, and "remember" twice must not duplicate the pinned line.

---

### Task 1: Probe module and classification (pure and probe code)

**Files:**
- Create: `secret_broker/execprobe.py`
- Test: `tests/test_execprobe.py`

**Interfaces:**
- Produces:
  - `probe(host, port, cfg, guard, clock=time.monotonic) -> {"fingerprint": "SHA256:...", "key_type": str} | {"label": <probe failure label>}` (uses the OpenSSH `ssh-keyscan` binary from `exec.ssh_path`, or a stub; handshake only; guard check on every resolved address; per-(host,port) cache with a short TTL).
  - `classify(host, port, presented_fp, known_lines, allowed_hosts) -> {"state": "pinned"|"new"|"same_key_elsewhere"|"changed", "pinned_fp": str|None, "matches": "host:port"|None}`.
  - `RateLimiter` per client and global (injectable clock).

- [ ] **Step 1: Failing tests** with stubbed `ssh-keyscan` and a fake guard: each state classified correctly (including the Review Focus items: a key pinned only under a different host name is `new`; IPv6-mapped and DNS-to-forbidden refused with `refused_destination`); each failure label from the matching stub behavior; cache hit makes one subprocess call; rate limit returns `rate_limited`; the stub is never given anything from the request except host and port.
- [ ] **Step 2: Run, see them fail. Step 3: Implement** `execprobe.py`. **Step 4:** run the new tests. **Step 5: Commit** `exec: host key probe and classification`.

### Task 2: Intake, human-only path, card and decisions

**Files:**
- Modify: `secret_broker/broker.py` (the `exec` intake where "that host is not approved for this key" is raised; the decision handler near `/decide`; the card renderer `describe_html` path; notification text; request details), `secret_broker/execmode.py` (card pieces: banner text, fixed fingerprint rendering), `docs/reference.md`
- Test: `tests/test_exec_unpinned.py`

**Interfaces:**
- Consumes: Task 1 `probe`, `classify`, `RateLimiter`.
- Produces: an `unpinned` exec request carrying `spec["host_state"]`, `spec["presented_fp"]`, `spec["pinned_fp"]`; decision values `approve` (once), `remember`, `replace` (form fields `decision`, `confirm_replace`); fixed refusal text when `exec.enabled` is false or the credential is not an SSH key.

- [ ] **Step 1: Failing tests:** new, same-key-elsewhere and changed each yield a pending request (never a refusal, never an auto-approval, even with a matching rule and `approval: allow`, a grant and Always); the card shows host, port, fingerprint, the same-key line, and for `changed` the red banner with both fingerprints and no "remember" button (only "replace" with its tick); forged form posts (`remember` on a changed host, `replace` without the tick, an Always/grant field) are refused 400 and claim nothing; the card and notification contain no approve button and the notification has no fingerprint; probe failure label appears on the request as a fixed label; pending cap and rate limit apply to probes.
- [ ] **Step 2-5:** fail, implement (route the three states through the `sudo`-style human-only branch; render the card; handle the three decisions), run the suite, commit `exec: prompt for unpinned and changed hosts`.

### Task 3: Persist "remember" and "replace"; pin the approved fingerprint at connect

**Files:**
- Modify: `secret_broker/broker.py` (persist helper beside `_persist_ssh_rules`, audit events), `secret_broker/execrun.py` (accept `approved_fp` and build the one-line known_hosts from it), `secret_broker/crededitor.py` (nothing new needed beyond showing the new line; verify revocation works), `docs/reference.md`
- Test: extend `tests/test_exec_unpinned.py`, `tests/test_execrun.py`

**Interfaces:**
- Consumes: Task 2 decisions and `spec["presented_fp"]`.
- Produces: `Broker._remember_host(name, host, port, fp, user, replace=False)` returning the new `ssh_hosts` metadata; `execrun.run(..., known_hosts_lines=[line_for_approved_fp])` for unpinned approvals.

- [ ] **Step 1: Failing tests:** "approve once" persists nothing; "remember" persists the line and the allowed host (credential editor shows it, a later request to that host is a normal pinned exec); remembering twice does not duplicate; "replace" writes the new line in place of the old and audits both fingerprints; a `set_meta` failure leaves the old metadata and says so; the runner is given only the approved fingerprint (a stub server presenting a different key after approval fails with `host_key_mismatch` and the command never runs).
- [ ] **Step 2-5:** fail, implement, suite, commit `exec: remember and replace pinned hosts`.

### Task 4: Rule lists for host and port; `asb exec` default user

**Files:**
- Modify: `secret_broker/autorules.py` (`exec` rule keys accept `host` as a string or list, `port` as an int or list; matching requires the request's host and port to be in the lists), `secret_broker/uirules.py` and `secret_broker/crededitor.py` (form accepts comma-separated lists), `client/asb` and `crates/asb-cli` (`asb exec` sends the local `$USER` when `--user` is not given; help text updated and regenerated), `docs/reference.md`, `docs/cli.md`
- Test: extend `tests/test_exec_rules.py`, `tests/test_asb_exec.py`; Rust tests and the CLI text-sync/parity lists

- [ ] **Step 1: Failing tests:** a rule with a host list and a port list matches only listed combinations and never a non-pinned one (positive controls); a one-element list behaves exactly like the old string form; stored rules written in the old shape still load; `asb exec` without `--user` sends `$USER` (and refuses with a usage message when `$USER` is unset or invalid), `--user` overrides; Python and Rust agree (golden fixture).
- [ ] **Step 2-5:** fail, implement Python then Rust, run `python tests/run_tests.py`, `cargo test --workspace`, `python tools/run_tests_against_rust_cli.py`, commit `exec: rule lists and default user`.

### Task 5: End-to-end and docs

**Files:**
- Modify: `tests/e2e_remote_exec/driver.py` (add the three unpinned scenarios), `docs/reference.md` (the unpinned-host section, events, config), `docs/guidance.md` only if needed, `docs/setup.md`

- [ ] **Step 1:** extend the e2e driver against the real sshd: a new host/port prompts and "approve once" runs and persists nothing; "remember" makes the next call a normal pinned call; a rekeyed server prompts with `changed`, and a key that changes between probe and connect fails closed. **Step 2:** run it locally (and in Docker if available, else say so). **Step 3:** full suite and commit `exec: e2e for unpinned hosts, docs`.

## Execution

One branch off `origin/main` (confirm `secret_broker/execmode.py` exists after fetching). First commit the new spec and this plan. Final: whole-branch review, full suite, CI-equivalent checks; nothing is pushed or merged without the owner's say.
