# Proposal: port the `asb` CLI to Rust

Status: **in progress** (branch `rust-cli`). The Python `client/asb` stays the specification and the supported client
until the Rust one passes the same tests; nothing about the broker or its API changes.

## Why

One static binary (no Python on the agent's machine, faster start, nothing to `curl` and `chmod`), a client that can
share crates with the root helper (`asb-client`, `asb-proto`), and a typed home for the wire protocol if the server is
ever ported too. Not a rewrite for its own sake: behaviour does not change.

## Goals and non-goals

- **Same behaviour, byte for byte where a script could notice:** the same commands and flags, the same stdout and stderr
  text, the same exit codes, the same requests to the broker (headers, bodies, polling), the same files written.
- **Non-goals:** new commands, new flags, a different config format, changing the broker API, Windows/macOS packaging in
  this branch (the Python client keeps working there), removing `client/asb` before parity is proven.

## How parity is proven (not assumed)

1. **The existing suite, against the Rust binary, unmodified.** About 18 test files run the CLI as a subprocess.
   `tools/run_tests_against_rust_cli.py` copies the repo, replaces `client/asb` with a shim that `exec`s the Rust binary,
   and runs everything. A failure is a real behavioural difference, down to the exact message. The tests that still fail
   because their command is not ported yet are listed in `tests/rust_cli_known_gaps.txt`; the runner fails on a new
   failure and on a listed test that now passes, so the list only shrinks and **empty means parity** for everything the
   black-box tests can see.
2. **Help and guide text cannot drift.** `tools/sync_cli_text.py` extracts `--help`, `asb guide` and `asb help TOPIC` from
   `client/asb` into `crates/asb-cli/text/` (embedded with `include_str!`); `tests/test_cli_text_sync.py` fails if they
   differ. The source of truth flips to those files when the Python client is retired.
3. **Python-internal logic gets golden vectors.** The script analyser (`argv_runs_script`, `find_scripts`, ...) and the
   ssh-host parser are exercised by tests that import Python functions, so the shim cannot cover them. Their Python
   output over the tests' existing corpus is recorded as JSON, and the Rust port must reproduce it exactly.
4. **Python-compatible formatting** (`json.dumps`, `urllib.parse.quote`, `repr`) is implemented once in `pyfmt.rs` and
   unit-tested against values produced by Python.

## Crates

`asb-cli` (binary `asb`) on top of `asb-client` (config-free HTTP and approval polling, shared with the root helper) and
`asb-proto`. No new heavy dependencies: `ureq`+rustls, `serde_json`, `libc`.

## Progress

| Stage | State |
|---|---|
| 0 plumbing, `help`/`guide`/`list`/`which`/`status` | done |
| 1 `http` `store` `update` `request-credential` `guidance` `audit` `sudo` `enroll` | done |
| 2 `session` `plan` `agent-setup` | done (`agent-setup`'s dry-run diff is Python's `difflib`, ported and held to 30 golden cases) |
| 3 env mode `NAME -- command` and the script analyser | not started |
| 4 `ws` (and its line pipe), `ssh-agent`, `fingerprint` | not started |

`tests/rust_cli_known_gaps.txt` lists what still fails against the Rust binary (17 tests, all from stages 3 and 4);
`tests/rust_cli_python_internal.txt` lists the 29 tests that import Python functions and can never pass against a
binary (their Rust side is the unit tests and golden vectors). CI runs the parity suite on every change.

## Order

| Stage | Commands | Why this order |
|---|---|---|
| 0 | `--help`, `guide`, `help`, `list`, `which`, `status` | the plumbing: config, one JSON call, text, formatting, the runner |
| 1 | `http`, `store`, `update`, `request-credential`, `guidance`, `audit`, `sudo`, `enroll` | all share the "ask a human, wait" flow |
| 2 | `session`, `plan`, `agent-setup` | state machines and file editing, big test counts |
| 3 | `NAME -- command` (env mode) with the script analyser | the hard one: must match the broker's rules exactly |
| 4 | `ws` (with the line pipe), `ssh-agent`, `fingerprint` | protocol servers and raw TLS |

Each stage removes its tests from `tests/rust_cli_known_gaps.txt` in the same commit.

## Switching over

When the gaps list is empty and the golden vectors pass: release `asb` binaries from CI, point the install docs at them,
keep `client/asb` as a deprecated single-file fallback for platforms without a binary, and make the extracted text the
source of truth. Retiring the Python client is a separate decision.
