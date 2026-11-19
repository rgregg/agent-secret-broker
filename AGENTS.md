# Agent Secret Broker: guide for contributors and coding agents

A self-hosted broker that lets a CLI agent use credentials only after a human approves each use, with a hash-chained
audit log. The agent asks; the broker makes the call (or releases a value) and the agent never holds the vault
password or the approval channel. Read `README.md` for the product and `docs/reference.md` for how it works.
This file is about changing it safely.

(`asb agent-setup` writes a marked block into the instruction files of *users'* agents. That is a product feature
and unrelated to this file.)

## Layout

| Path | What lives there |
|---|---|
| `secret_broker/` | The broker (Python 3.12). `broker.py` is the large core: the request lifecycle, the HTTP handlers, the approval pages. The rest is one concern per module: `masking`, `httpcheck`, `errclass`, `destguard`, `placeholders`, `sessions`/`wssessions`, `plans`, `standing`, `clients`, `audit`, `riskmodel`, `backends/` |
| `client/asb` | The `asb` CLI (Python, no dependencies). **The specification** while the Rust port exists |
| `crates/` | Rust: `asb-cli` (the port of `client/asb`), `asb-client`, `asb-proto`, `asb-root-exec` (root helper) |
| `tests/` | The suite (unittest style). `run_tests.py` is the runner; `_fast.py` has the fake clocks |
| `tools/` | Generators and checks (`sync_cli_text.py`, `gen_cli_golden.py`, `mutation_check.py`, `run_tests_against_rust_cli.py`) |
| `docs/` | `reference.md` (behavior and threat model), `setup.md`, `cli.md`, `deploy.md`, `proposals/` |
| `deploy/` | Example compose and config |

## Commands

    pip install -r requirements.txt          # pinned; without it the webpush tests fail
    python tests/run_tests.py                # the suite, parallel (about 75s with -j 4); CI runs 4 shards
    python tests/run_tests.py -k SUBSTRING   # a subset
    python -m pytest tests/test_x.py -k name # one test (see "Mind how classes inherit tests")
    cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --workspace --locked

Run the whole Python suite before you open a PR, and the Rust commands if you touched `crates/`. CI also builds the
CLI for four platforms and runs the Python suite against the Rust binary (`tools/run_tests_against_rust_cli.py`).

## Working in this repo

- Branch off `main`, open a PR, and let CI run. One concern per PR; the title says what changed and the body links the
  issue (`Fixes #N`). Look at `git log` for the house style.
- **Docs move with behavior.** If you change what the broker or CLI does, update `docs/reference.md` (and
  `docs/cli.md` or the README table where relevant) in the same PR.
- **`client/asb` is the source of truth for CLI text and behavior** until the Rust CLI replaces it. After editing any
  help, guide or usage text in `client/asb`, run `python tools/sync_cli_text.py` and commit the regenerated
  `crates/asb-cli/text/*` (`tests/test_cli_text_sync.py` fails otherwise). Parsing/analysis logic the Rust port must
  reproduce is pinned by `python tools/gen_cli_golden.py` (`--check` to verify). Do not make Rust change behavior
  that Python does not.
- Put a new protocol or policy rule in one shared place, not in each caller. Where two code paths must agree on what
  something *is* (what counts as a `{{placeholder}}`, what is a credential header), they call one function. The two
  disagreeing is how a card shows one thing and the send does another.

## Security invariants (do not weaken these casually)

The broker's value is that a compromised or prompt-injected agent cannot get a secret without a human noticing. When
you change code near these, say so in the PR and add a test that fails if the property breaks.

- **The agent never receives a credential value** in `http`, `session`, `plan` or `ws` modes; responses are masked
  (`masking.py`), including values split across chunks and ranges.
- **No text from an exception, a filled request, a credential or the agent's own input crosses a trust boundary**
  (agent response, audit, history, logs, notifications, pages). The one exception is deliberate: the human's own
  **Show** on the Credentials tab returns that one value to their authenticated session (`reveal_value`), audited
  by name only. Nothing else may put a value on a page. Errors are fixed labels from a closed set
  (`errclass.py`, `httpcheck.py`), not `str(exc)` and not an echo of what the agent sent. A filled value can contain
  anything, so never build an error message from one.
- **Destinations are checked before a value is released** (`destguard.py`): allowed hosts and ports per credential,
  no redirects followed, no value in the scheme or authority of a URL.
- **Approval comes from the human's authenticated session only.** Agents cannot approve, widen, extend or reuse a
  grant; CSRF, origin and per-identity token checks stay on. Standing and timed approvals are narrow and revocable.
- **Scans of agent text read it the way the send will** (`placeholders.scan`). A check that sees different text than
  the send can be bypassed.
- **Scans stay linear** in the length of hostile input (no backtracking regexes on agent text; cap candidates).
- The audit log is append-only and hash-chained; every decision and refusal is an event.

## Writing tests

This is a security tool, so most tests say "X must never happen". Those are the easiest to get wrong: they pass when
X never happens *and* when the test never set up the situation where X could happen. An audit that broke the code
each test guards found vacuous tests across the suite, all in the shapes below.

- **A test must be able to fail.** New behavior or a bug fix: write the test first and watch it fail for the right
  reason on the old code. A security property (never logged, never reaches the agent, refused): break the code on
  purpose, confirm the test fails, restore. Deleting the assertion is not a mutation.
- **A negative assertion needs a positive control.** `assertNotIn(SECRET, text)` proves nothing if `text` is empty.
  In the same test assert the surface is populated (the canary is on the pending card, the audit event is there, the
  response is 200). Pair `== []` with proof the code under test ran.
- **Assert the premise, not just the outcome.** Fixtures and constants drift and the test then passes for an
  unrelated reason. Seen here: a grants fixture in an old format was always dropped as malformed; a plan's
  `max_uses` ran out after six iterations of a loop meant to cover every offset; a request was refused for a
  different reason than the one under test. Assert the setup took effect and assert the *reason* for a refusal.
- **"Does not raise" is not an assertion.** Assert the effect. If it truly is only that, add it to
  `NO_ASSERTION_OK` in `tests/test_test_quality.py` with the reason.
- **Be exact.** `assertEqual(code, 400)`, not `assertIn(code, (200, 400, 403))`; the specific exception class, not
  `assertRaises(Exception)`; the expected value, not `assertIn(x, (old, new))`.
- **A scan for a forbidden pattern** (in source or text) should be shown to fail on one planted occurrence and must
  not be able to scan nothing.
- **Mind how classes inherit tests.** `tests/run_tests.py`, and so CI, runs the methods a class defines itself;
  plain `pytest`/`unittest` also run inherited ones, which is wrong for a subclass that changes the setup (for
  example a high-risk request, where "Always" is never offered). Override the test there.
- Tests never sleep for a timeout; drive time with `tests/_fast.py`.
- For the root helper, `python tools/mutation_check.py` mutates security-critical lines and fails if a test does not
  notice. Add an entry when you add a security check there.

`tests/test_test_quality.py` enforces the objective part mechanically (no assertion even via helpers, empty bodies,
constant asserts, a value compared with itself). Judging the rest is on the author and the reviewer.

## Don'ts

- Don't put real secrets, hostnames, tokens or personal details in code, tests, fixtures, docs or commit messages.
  Use obvious canaries (`S3CR3T-...`) and `example.com`/`127.0.0.1`.
- Don't commit generated output without regenerating it with its tool, or hand-edit what a tool owns.
- Don't skip or delete a failing test to get green; find out why it fails. If a test is wrong, fix it and say so.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:46cd31e7 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
