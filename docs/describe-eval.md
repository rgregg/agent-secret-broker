# Comparing description models

`tools/describe_eval/run.py` replays a corpus of scrubbed request shapes through the real
description pipeline (`secret_broker/description.py`: prompt, `sanitize`, `consistent_with`,
fallback) for one or more chat models and reports how each behaves. A fallback in the report is a
fallback the live broker would show. Stdlib only.

## Run it

Offline, with scripted replies from a local server (no key, no network):

    python -m tools.describe_eval.run --stub --models a/one,b/two

Live, through the broker so the key never reaches the agent (one approval per run):

    asb openrouter -- python -m tools.describe_eval.run \
        --models openai/gpt-5-mini,google/gemini-2.5-flash-lite --timeout 30 --json /tmp/eval.json

Options: `--models` (comma separated) or repeated `--model`, `--timeout` seconds per call,
`--base-url` (default OpenRouter), `--key-env` (default `OPENROUTER_TOKEN`) or `--key-file`,
`--corpus`, `--only id1,id2`, `--json PATH` (raw rows, no key). The key is never printed, logged or
written to the report. Each live run makes one call per model per corpus case (about 30 cases).

## What it reports

Per model: fallback rate and count by reason class and rejecting check (`rejected/read_word`,
`timeout`, `empty`, ...), latency p50, p95 and max, prompt and completion tokens, estimated cost
(from the `usage.cost` the provider returns; "n/a" when absent), words and sentences per shown
description (average and maximum). Then a side-by-side table of the produced texts per case for human
review. Cases that never reach a model are listed as such: credential requests, guidance
proposals and client enrollment have no description at all, and SSH signing data is never sent to a
model (the plain line is always used).

## The corpus

`tools/describe_eval/corpus.json` holds shapes only, with example hosts and no secrets: plain
GET, paging GET, status check, long odd path, login-style POST, GraphQL POST, search-style POST,
webhook, custom User-Agent, PUT/PATCH/DELETE, DNS create, container restart, session open and
session call, plan submit and plan step (sessions and plans are not in every build, so these are
shapes only), env scripts (bash, python, read-only, deploy, unreadable, standard input), common
commands, store create/update, SSH signing. Add a case by appending to `cases`; `stub_reply` (or
`stub_replies` keyed by model) is what `--stub` serves.

## Using the result

To try another model for real descriptions set `summary.summary_model` in the broker config (for
example `google/gemini-2.5-flash-lite`). `summary_timeout` is how long the card waits before it is
drawn with the plain line; `summary_hard_timeout` is how long the call may keep running so a late
description can still replace it (see risk.md, "Late descriptions and late ratings").
