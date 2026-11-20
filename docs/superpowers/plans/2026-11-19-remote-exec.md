# Remote exec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new request mode `exec` where the broker SSHes to a host with a stored key, runs one vetted command or script, and returns the output, so low-risk commands can be auto-approved.

**Architecture:** A pure module (`execmode.py`) parses and classifies command text; broker intake mirrors `sudo` mode (`sudomode.py`, broker.py `mode == "sudo"` sites) but runs the normal policy chain (risk model, rules, `approval: allow`) instead of always-human; a runner (`execrun.py`) drives OpenSSH with a private `ssh-agent` and runs on its own thread after approval (as `Broker._release_by_policy` does); `asb exec` is added to the Python CLI (spec) and the Rust CLI.

**Tech Stack:** Python 3.12 stdlib, OpenSSH client binaries (`ssh`, `ssh-agent`, `ssh-add`), Rust CLI (`crates/asb-cli`, `crates/asb-client`).

**Spec:** `docs/superpowers/specs/2026-11-19-remote-exec-design.md` (binding authority; read it first, and AGENTS.md).

## Global Constraints

- Python 3.12, stdlib only in the broker; no new Python dependency. Image gains `openssh-client` only.
- Off by default: `"exec": {"enabled": false, ...}`; only `exec.clients` ids may ask; the legacy shared key gets 403.
- `host` must be in the key's `ssh_hosts.allowed_hosts` by name AND have a `known_hosts` line; `StrictHostKeyChecking=yes`, no TOFU.
- The request chooses only host, user, port, command or script, `timeout_s` (default 60, max `exec.max_seconds`, 600). Nothing from it becomes an ssh option.
- Command at most 4096 chars, script at most 32 KiB; control characters other than tab and newline, and hidden/bidi characters, refused with 400 and a fixed label (same checks as `sudomode.validate`).
- Output caps: `exec.max_output_bytes` (default 262144) for stdout and stderr each; masked with the existing credential-value masker; never in a notification or the audit log.
- Failure labels (closed set, never exception text): `host_key_mismatch`, `host_not_pinned`, `connect_failed`, `auth_failed`, `timeout`, `output_cap`, `ssh_unavailable`, `internal`.
- No timed grants, Always, or SSH-rule chips for `exec` (rules and policy only).
- Docs move with behavior; no real secrets, hostnames or personal details anywhere (`S3CR3T-...` canaries, `example.com`, `127.0.0.1`).
- Tests follow AGENTS.md "Writing tests". Run the suite with `python tests/run_tests.py`. Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Wire contract (shared by the broker and the client)

Create: `POST /v1/requests` `{"mode": "exec", "names": ["KEY"], "host": "h", "user": "u", "port": 22, "command": "text" | "script": {"text": "...", "interpreter": "sh"}, "timeout_s": 60, "source": "..."}` (exactly one of `command` and `script`; `interpreter` is `sh` or `bash`).
Result: `GET /v1/requests/ID?wait=S` returns `{"status": "running"}` while it runs, then once
`{"status": "released", "exit_code": 0, "stdout": "...", "stderr": "...", "truncated": false, "label": null}`;
on a failure `exit_code` is `null` and `label` is one of the failure labels. Denial and expiry are final as for every mode.

## Review Focus

- A command that parses as simple but is rebuilt differently from what the card showed (quote handling, unicode lookalikes).
- A table entry allowed by prefix that also admits a dangerous flag (`docker logs --follow`, `journalctl -f` hang until timeout; `systemctl show` is fine, `systemctl edit` is not).
- Concurrency: two exec requests for the same key at once (private agent sockets and temp dirs must not collide), and a runner crash leaving an `ssh-agent` or key file behind.
- A request whose `host` is a different spelling of an allowed host (case, trailing dot, IP literal) must not bypass the pinned-name check.
- The key reaching a process listing: `ssh-add -` must read the key from a pipe, never argv.

---

### Task 1: Command grammar, classification and config (pure module)

**Files:**
- Create: `secret_broker/execmode.py`
- Test: `tests/test_execmode.py`

**Interfaces:**
- Produces:
  - `MODE = "exec"`; `DEFAULTS = {"enabled": False, "clients": [], "max_concurrent": 4, "max_output_bytes": 262144, "max_seconds": 600, "max_pending_per_client": 3, "readonly": [], "ssh_path": None}`.
  - `parse_config(raw, field="exec") -> dict` (validated at startup like `sudomode.parse_config`; unknown keys, bad types and ranges raise `ValueError` with a fixed message).
  - `check_allowed(cfg, client)` (same contract as `sudomode.check_allowed`: 403-style `PermissionError` for a client not listed and for the legacy shared key).
  - `validate(spec) -> None` (raises `ValueError` with a fixed label; checks lengths, characters, exactly one of command/script, interpreter, user pattern, port 1-65535, timeout range).
  - `parse_simple(text) -> list[str] | None` (the grammar in the design: argv, or `None` when not simple).
  - `rebuild(argv) -> str` (shell-quoted string; `parse_simple(rebuild(a)) == a` for every simple argv).
  - `classify(spec, cfg) -> {"level": "low"|None, "reason": str, "argv": list|None}` (`low` only for a simple command on the read-only table; `None` means "ask the model").
  - `remote_payload(spec) -> (command_string: str, stdin: bytes|None)` (simple: rebuilt string, no stdin; non-simple: the text byte for byte; script: command `<interpreter> -s`, stdin the script bytes).
  - `display_text(spec)`, `push_text(spec)`, `audit_fields(spec)` (first 50 words each clipped to 300 for commands; for scripts only length and SHA-256), `script_sha256(spec)`.

- [ ] **Step 1: Write failing tests** in `tests/test_execmode.py`: grammar table (each of `; & | < > ( ) $ ` backtick \ newline * ? [ ] { } ~ ! #` unquoted makes a command non-simple, with a plain-command positive control; `$` and backtick inside double quotes non-simple; single quotes literal), `parse_simple`/`rebuild` round trip including quotes and spaces, read-only table (allowed: `systemctl status nginx`, `docker ps -a`; not allowed: `systemctl restart x`, `docker exec x y`, `journalctl -f`, `cat /etc/passwd`, `rm`; `exec.readonly` extension works and cannot be set to a name with a shell character), `validate` refusals (control and hidden characters, lengths, both/neither of command and script, bad user, bad port, timeout over max), `parse_config` (defaults, unknown key, bad types), `remote_payload` for the three forms, `check_allowed`.
- [ ] **Step 2: Run to see them fail:** `python tests/run_tests.py test_execmode` — expect import errors.
- [ ] **Step 3: Implement** `secret_broker/execmode.py` to the signatures above, following `sudomode.py` for config validation, character checks, `display_text` (non-ASCII as `<U+XXXX>`) and `describe_html`. The built-in table is a dict `program -> allowed subcommands/flags` kept short per the design.
- [ ] **Step 4: Run:** `python tests/run_tests.py test_execmode` — expect all pass. Break the metacharacter list and the table check on purpose and confirm a test fails each time.
- [ ] **Step 5: Commit** `execmode: command grammar, read-only table, config`.

### Task 2: Broker intake, risk, approval surface

**Files:**
- Modify: `secret_broker/broker.py` (every `mode == "sudo"` site is the map of places to extend: intake near line 2048, pending cap near 2118, `_sudo_pending` near 2467, push text 2981, notification buttons 3008, history/label tables 5951 and 6190, request list 6894/6924, result serving 4494, CSRF/mode tuples), `secret_broker/risk.py`, `secret_broker/audit_api.py`, `docs/reference.md`
- Test: `tests/test_exec_intake.py`

**Interfaces:**
- Consumes: Task 1 (`parse_config`, `check_allowed`, `validate`, `classify`, `audit_fields`, `describe_html`).
- Produces: `Broker.exec_cfg`; mode `exec` accepted by `POST /v1/requests`; `features.exec` in `GET /v1/status`; `Request.mode == "exec"` with `req.spec` holding the validated fields.

- [ ] **Step 1: Failing tests** (use `tests/` harness patterns from `test_sudo_*` and `test_ssh_rules`): disabled by default (mode refused); client not in `exec.clients` 403 and legacy key 403, each with a positive control; `names` must be exactly one SSH key credential; host not in `allowed_hosts` and host without a `known_hosts` line refused before anything runs, with spelling variants (case, trailing dot, IP literal) refused; pending cap; a simple allowlisted command is rated low with no model call (assert the fake model was not called); a non-simple command and a script reach the model with guidance and default to high with no verdict; the card shows host, account and the command shell-quoted with `<U+XXXX>`, script full text and hash; notification text carries host, account, clipped command and a link and never the script; no Always/timed-grant/SSH-rule chip is offered for `exec` and a form post asking for one is refused (400) and claims nothing; the `requested` audit event carries `audit_fields` only; `exec` events hidden from the agent audit API.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement** intake by mirroring the `sudo` branches but running the normal policy chain (the `_pending`/`approval: allow`/risk-ceiling path http uses, with the low classification from `execmode.classify` short-circuiting the model). Reuse `_validate_ssh_sign`'s pinned-host helpers for the `allowed_hosts` + `known_hosts` check. Add `exec` to the request-mode tuples and labels ("remote command").
- [ ] **Step 4: Run** the new tests and the full suite; fix migrated tests only if forced and say which.
- [ ] **Step 5: Commit** `exec mode: intake, classification and approval surface`.

### Task 3: Auto-approve rules for exec

**Files:**
- Modify: `secret_broker/autorules.py` (allowed keys table line ~51, normalization ~113), `secret_broker/uirules.py`, `secret_broker/crededitor.py` (add `exec` to the rule form), `secret_broker/broker.py` (rule claim site), `docs/reference.md`
- Test: `tests/test_exec_rules.py`, extend `tests/test_ui_auto_rules.py` only if the shared matcher table is parametrized there

**Interfaces:**
- Consumes: Task 1 `parse_simple`; Task 2 intake.
- Produces: rule mode `exec` with keys `{"name", "mode", "secret", "clients", "host", "account", "argv"}` (`secrets` list not allowed for exec); matcher approves iff the request's command is simple, the host/account/client match, and the rule's `argv` is a non-empty prefix of the parsed argv. Never matches a non-simple command or a script.

- [ ] **Step 1: Failing tests:** prefix match and non-match (`["systemctl","status"]` vs `systemctl status x` yes, `systemctl restart x` no, `systemctl status; reboot` no); script never matches; wrong host/account/client no; rule on credential A never approves B; config and stored (vault metadata) rules behave identically over one shared table; stored rule requires confirmation tick and optional expiry like http rules; a malformed stored rule invalidates the credential naming the field; positive controls beside each negative.
- [ ] **Step 2: Run, fail. Step 3: Implement** in the same validator the http rules use (one function for both sources, per the UI auto-approve design). Step 4: run suite. Step 5: commit `exec: auto-approve rules`.

### Task 4: The SSH runner and result delivery

**Files:**
- Create: `secret_broker/execrun.py`
- Modify: `secret_broker/broker.py` (start the runner after approval on its own thread, `running` status, serve the result once), `secret_broker/audit_api.py`
- Test: `tests/test_execrun.py`, `tests/fake_ssh/` (a stub `ssh`, `ssh-agent`, `ssh-add` shell/Python scripts used through `exec.ssh_path`)

**Interfaces:**
- Consumes: Task 1 `remote_payload`, `exec.ssh_path`; the key value via the existing secret-read path.
- Produces: `execrun.run(spec, key_pem: bytes, known_hosts_lines: list[str], cfg, masker) -> {"exit_code": int|None, "stdout": str, "stderr": str, "truncated": bool, "label": str|None, "duration_ms": int}`; events `exec_started` (host name, account, command or script hash) and `exec_finished` (exit code, byte counts, duration, truncated, label).

- [ ] **Step 1: Failing tests with the stub binaries:** the ssh argv contains exactly the fixed option list from the design and nothing derived from the request (option-looking host/user/command values change no option); the stub ssh receives `remote_payload`'s command string and stdin; the key reaches `ssh-add` only on stdin (assert argv/env of every stub invocation contains no key bytes, using a `S3CR3T-` canary key); the temp dir and agent are gone after success, failure, timeout and an exception; two concurrent runs use different sockets and dirs; output cap truncates and sets `truncated`; masked values never appear; timeout kills the process and returns `timeout`; each failure label is produced by the matching stub behavior (host key mismatch, connect refused, auth failure, ssh missing); the audit events carry counts and labels only; no output or command text in a notification or audit event.
- [ ] **Step 2: Run, fail. Step 3: Implement** per the design's Execution section (private 0700 dir under the broker state dir, generated `known_hosts` for that host only, `ssh-agent -D -a SOCK`, `ssh-add -` from a pipe, the fixed options, cleanup in `finally`, byte-capped reads of both streams, UTF-8 with replacement, masker). Wire it into the broker the way `_release_by_policy` releases HTTP requests, honoring `exec.max_concurrent`. Step 4: full suite. Step 5: commit `exec: ssh runner and result delivery`.

### Task 5: `ssh_agent` switch on the key

**Files:**
- Modify: `secret_broker/broker.py` (key metadata validation near `_ssh_hosts` line ~539, the `ssh_sign` intake near `_validate_ssh_sign` line ~2802 and the policy/grant/rule paths), `secret_broker/crededitor.py` (a control), `docs/reference.md`
- Test: `tests/test_ssh_agent_switch.py`

**Interfaces:**
- Produces: key metadata `ssh_agent` in `{"allow","ask","off"}` (default `allow`, unchanged behavior); `ask` forces a human for every `ssh_sign` for the key with no timed grant, Always or SSH rule used or offered; `off` refuses `ssh_sign` for the key with a fixed label (`ssh_agent_off`) audited as `ssh_sign_refused`.

- [ ] **Step 1: Failing tests:** default unchanged (existing ssh tests stay green: positive control); `ask` never uses an existing grant or rule and offers no chips; `off` refuses with the fixed label; invalid value makes the credential invalid naming the field; exec on the same key is unaffected by either value.
- [ ] **Step 2-5:** run/fail, implement, suite, commit `ssh keys: ssh_agent allow|ask|off`.

### Task 6: Image, end-to-end test, docs

**Files:**
- Modify: `Dockerfile` (`apt-get install -y --no-install-recommends openssh-client` in the runtime stage, then clean the apt lists), `.github/workflows/ci.yml` (run the e2e job), `docs/reference.md` (new section "Remote commands (request mode `exec`)", audit table, config), `docs/guidance.md` (exec example guidance), `docs/setup.md`
- Create: `tests/e2e_remote_exec/` modeled on `tests/e2e_root_exec/`: a throwaway container with a real sshd, a real broker, a pinned host key; checks a read-only command is auto-approved by a rule and returns output, a wrong host key fails closed, and `ssh_agent: off` stops agent signing.

- [ ] **Step 1: Write the e2e test first and watch it fail. Step 2: Implement the Dockerfile/CI/doc changes. Step 3: Run the e2e and the full suite. Step 4: Commit** `exec: image, e2e test, docs`.

### Task 7: `asb exec` in the Python and Rust clients

**Files:**
- Modify: `client/asb` (the Python CLI is the spec), `crates/asb-cli`, `crates/asb-client`, `docs/cli.md`, `docs/reference.md` (client section), `tests/rust_cli_python_internal.txt` only if a Python-internal test is added, `secret_broker/clientver.py` (bump `LATEST_CLIENT_VERSION` and `asb guide` text; follow how the last bump was done)
- Test: `tests/test_asb_exec.py`; Rust tests beside `crates/asb-cli`; the CLI parity test lists

**Interfaces:**
- Consumes: the Wire contract above only (the broker side is built in parallel by Tasks 1-6).
- Produces: `asb exec NAME HOST [--user U] [--port P] [--timeout S] -- COMMAND...` and `asb exec NAME HOST --script FILE [--interpreter sh|bash]`. Stdout and stderr go to the matching streams; the exit code is the remote exit code; a failure label prints `asb: exec failed: LABEL` and exits 3; denial/expiry use the existing codes; `asb help exec` and `asb guide` mention it with the "use for any command you would otherwise ssh for" line. Words after `--` are joined with the same quoting `execmode.rebuild` uses, so the broker's classification matches what was typed.

- [ ] **Step 1: Failing tests against a fake broker** (the existing client test harness): request body exactly per the contract, polling `running` then `released`, exit-code mapping, stdout/stderr streams, label handling, `--script` reads the file and sends text and interpreter, refuses a file over 32 KiB or with control characters before sending; Rust parity tests mirror the same cases.
- [ ] **Step 2-4:** fail, implement Python then Rust, run `python tests/run_tests.py` and `cargo test` plus the parity test. Step 5: commit `asb exec`.

## Execution split

Two branches in separate worktrees, no shared files except `docs/reference.md` (keep edits in separate sections): **broker** (Tasks 1-6, in order) and **client** (Task 7). Final: whole-branch review of each, full suite, CI green; nothing is pushed or merged without the owner's say.
