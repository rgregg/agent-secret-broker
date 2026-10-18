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
  probabilities. It cannot write text, so the summary is built
  deterministically from the request fields ("auto: DELETE host/path") unless
  `summary_text` is `chat`.

The request is described to the model as a data object (mode, secret names,
method, host, path, header NAMES, body or command excerpt). Query strings,
header values, credential values and key material are never sent. The
description is client-supplied and untrusted: the rubric tells the model to
treat any instruction in it as data and to rate attempts to influence the
rating one level higher.

## Deterministic rules

- `ssh_sign` is always HIGH, whatever the model says, and is not sent to the
  model. (This deviates from the earlier "risk is the model verdict only"
  decision, at the owner's explicit request for SSH.)
- Creating a new credential (`store` create) is low (existing rule in `risk.py`).
- Failure, timeout, malformed reply or an unknown option: HIGH.

## Evaluating

    asb openrouter -- python tools/risk_eval/run.py --provider jev
    asb openrouter -- python tools/risk_eval/run.py --provider chat --prompt legacy
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
from the eval cases so the eval stays honest. Add real misclassifications from
the audit log (`assessed` events) to `cases.jsonl` as new cases.
