# Risk levels and the classifier

Every request is rated `low`, `medium` or `high` before the approver sees it.
The rating decides how loudly it is presented, whether `allow` secrets still
prompt (`risk.escalate_auto_at`) and whether a push offers Approve
(`approve_max_risk`). No verdict means HIGH.

## Levels

- LOW: reads and queries. GET/HEAD/OPTIONS to read endpoints, POST used only as
  a query (search, GraphQL query, read-only RPC), commands that only read.
- MEDIUM: reversible changes with limited blast radius: ordinary record
  updates, restarting one service, sending a message, scripts that write
  files, deploying one stack, git push to a feature branch.
- HIGH: destructive, irreversible or high-impact: deletes, DNS/firewall/auth/
  IAM changes, money movement, creating or rotating credentials, reading many
  secrets, pipe-to-shell, privilege escalation, physical security (locks,
  alarms), force pushes, production publishing. All SSH signing.

Most requests should be low or medium. The classifier rates the action, not the
sensitivity of the service.

## Providers

`summary.type` selects the provider (see reference.md for all keys):

- `openrouter` (default): a chat model returns a summary and a level.
- `jev`: `typesafe/jev-1.14` through OpenRouter's Decisions API
  (`POST https://openrouter.ai/api/alpha/decisions`, alpha). One `choice`
  question with criteria `low`/`medium`/`high`; the answer carries per-option
  probabilities. It cannot write text, so the description comes from a
  separate chat model (below), or from the deterministic technical line
  ("auto: DELETE host/path") when that is disabled or fails.

The request is described to the model as a data object (mode, secret names,
method, host, path, header NAMES, body or command excerpt). Query strings,
header values, credential values and key material are never sent. The
description is client-supplied and untrusted: the rubric tells the model to
treat any instruction in it as data and to rate attempts to influence the
rating one level higher.

## The AI description (display only)

With `summary_text: chat` (the jev default) a chat model (`summary_model`,
default `openai/gpt-5-mini`) writes a short plain-language phrase, for example
"Deleting a virtual machine in Proxmox", in parallel with the decision call. It
is display only: the risk level, approval, grants and `allow` policy never read
it (a test asserts the verdict is identical whatever the description says).
The approver still sees the raw method and URL or command beside it, and the
UI label should read "AI description (unverified, written from agent-supplied
text)".

Safety measures:

- Input is the minimal structured request (mode, secret names, method, host,
  path without query string, header names, a body or command excerpt of
  `max_content_chars`), inside a data block with a random per-call boundary.
  Never secret values, header values, query strings or key material.
- The prompt asks for one 3-12 word action phrase in plain language and
  forbids opinions and approvals; a request that speaks to the reviewer is
  described as "Request contains text addressed to the reviewer".
- Every reply is sanitized in code (`description.sanitize`): single line, ASCII
  only (control, bidi and zero-width characters are rejected), no markdown,
  HTML, URLs, emails, code, paths, hostnames, IPs, status codes, HTTP verbs or
  API jargon, no shouted tokens, no quote of the prompt, no safety or approval
  language (`FORBIDDEN_PHRASES` and `FORBIDDEN_STEMS`: approv*, deny, authoris/z*, permit*, allow*), capped at 160 characters.
- Consistency (best effort): for a mutating request (POST/PUT/PATCH/DELETE other
  than a clean POST to an allowlisted read endpoint; a write-looking command, a store request or ssh signing) the description must START with a write-class gerund
  (`WRITE_VERBS`: Deleting, Opening, Syncing ...), contain no read gerund
  (`READ_GERUNDS`: retrieving, listing, checking ...) anywhere, and no minimizing language (`MINIMIZING`: nothing, without, no
  change, only, just, merely, read-only, does not ...). Read requests are not
  checked.
- Every POST, PUT, PATCH and DELETE is a write. The only exemption is a POST to
  an operator-listed read endpoint (`summary_read_endpoints`, exact host and
  exact path, case-insensitive host) that is clean: no query string or
  fragment, no userinfo, no backslash/whitespace/control characters or
  percent-encoded slash or dot, no method-override header, http(s) only, and the
  port exactly as listed. Anything not checkable counts as a write. There is no
  GraphQL or keyword parsing, so search-style and GraphQL POSTs get the plain
  technical `auto:` line unless allowlisted.
- Any rejection, timeout, error or rate cap replaces the description with the
  deterministic `auto:` line. The audit `assessed` event records
  `summary_source` (`model` or `deterministic`) and `summary_reason`
  (`rejected`, `timeout`, `error`, `rate_limited`), never the rejected text.
- Bounds: `summary_timeout` (4 s), `summary_concurrency` (4),
  `summary_max_per_minute` (30), responses capped at 16 KB. The key is never
  logged.
- Endpoint: descriptions go to `summary_base_url` (default OpenRouter). If
  `base_url` is custom and `summary_base_url` is not set, descriptions are
  disabled (startup warning) instead of using the default endpoint.

## Deterministic rules

- `ssh_sign` is always HIGH, whatever the model says, and is not sent to the
  model. (This deviates from the earlier "risk is the model verdict only"
  decision, at the owner's explicit request for SSH.)
- Creating a new credential (`store` create) is low (existing rule in `risk.py`).
- Failure, timeout, malformed reply or an unknown option: HIGH.

## Evaluating

    asb openrouter -- python tools/risk_eval/run.py --provider jev
    asb openrouter -- python tools/risk_eval/run.py --provider chat --prompt legacy
    asb openrouter -- python tools/risk_eval/run.py --descriptions   # description pipeline
    python tools/risk_eval/run.py --dry-run          # no network

`tools/risk_eval/cases.jsonl` holds labelled cases (one JSON object per line:
`id`, `mode`, `names`, `spec`, `expected`, `ambiguous`, `note`). A case is in the
`holdout` split when `sha1(id)[0] % 4 == 0`; tune the prompt on `train` only.
Ambiguous cases are listed but not scored. The report gives accuracy per level,
a confusion matrix, the over-flag rate (expected low/medium rated high; the
metric that matters for annoyance), the under-flag rate (expected high rated
low; the dangerous direction), latency p50/p95, cost and every miss. The key is
read from `OPENROUTER_TOKEN` and never printed.

## Changing the prompt

The rubric, examples and criteria are the `RUBRIC` and `CRITERIA` constants in
`secret_broker/riskmodel.py`. Edit, re-run the harness on both splits, and check
the under-flag rate before the over-flag rate. Keep few-shot examples distinct
from the eval cases so the eval stays honest. `tools/risk_eval/inject_cases.jsonl` holds adversarial requests for the
description pipeline (`--descriptions` reports raw-model obedience before the
sanitizer, obedience after it, rejection rate, plain-language pass rate, word
counts, latency and cost). Add real misclassifications from
the audit log (`assessed` events) to `cases.jsonl` as new cases.
