# Suggest guidance: an LLM drafts a credential's risk guidance

Status: built autonomously on branch `guidance-suggest`; the rulings below are for Ryan to review.

## What it is

A **Suggest guidance** button in the Risk guidance card of a credential's Policies page. It asks the model the broker
already uses for ratings to draft guidance for THAT credential. The draft lands in the editor textarea, unsaved, with
the review aids the proposals page uses (character count, flagged phrases, non-ASCII count). The human edits and
saves with the existing Save. Human-only: one POST on the approval port, no agent route, no `asb` command.

## Rulings (what each costs if wrong)

1. **Reuse the configured model through a new `complete(system, user, max_tokens)` method** on the chat classes
   (`OpenRouterSummarizer`/`ChatAnalyzer`) and, for `type: jev`, on its chat describer (`summary_text: chat`). One
   shared helper (`summarize.chat_complete`) does the call and returns a closed reason, never exception text. Cost:
   a `jev` config with `summary_text` other than `chat` has no chat model, so the button is absent with a fixed
   message; Ryan would have to switch that on.
2. **Timeout floor of 30 s.** The rating timeout (4 to 6 s) is far too short for a 400-token draft. Cost: the human
   waits up to 30 s on a hung provider; the HTTP handler thread is held that long.
3. **Prompt = structural facts only** (see docs/guidance.md for the user-facing statement): name, kind, allowed hosts,
   variable names, SSH flag, existing guidance (owner text, delimited and defanged), a digest of recent history.
   The digest is built from the history row's method, host, path, outcome and risk only. The path is untrusted agent
   text, so a segment survives only if it is a short plain word (letters, `_`, `-`, optional short extension, or a
   `v1`-style version); anything with a digit, a long or high-entropy token, or other characters becomes `{id}` or
   `{other}`; at most 6 segments. Host must be one of the credential's allowed hosts. Cost: a path of 20 letters
   chosen by an attacker can still be read by the model; it sits in a delimited data block that is declared
   untrusted, and the output is reviewed by a human who must press Save.
4. **Digest size**: newest 200 http rows of that credential, grouped, at most 25 groups. Cost: very old behaviour is
   not seen.
5. **SSH keys are allowed** (as specified); the prompt says guidance does not affect SSH signing. Cost: a wasted call.
   **The broker's own summary key is refused** (`internal`).
6. **Reply handling**: untrusted. Same `guidance.validate_text` as the editor; fixed-label errors (`invalid`,
   `too_long`, `empty`, `truncated`, `timeout`, `error`, `unavailable`); the text of a rejected reply is never shown
   or logged. A reply that does not end with `unknown operations: high` gets a note (not a rejection).
7. **Rate limits**: 3 per credential and 10 in total per 5 minutes (class constants, not config). Cost: a legitimate
   burst of retries is refused with 429 for a few minutes.
8. **Mechanism**: the button submits the editor form to `POST /policies/guidance/suggest`. With JS it is intercepted
   and answered as JSON (`Accept: application/json`, as Show does); without JS the page is re-rendered with the draft.
   Statuses: 400 refused, 429 rate limited, 500 failed, 200 ok.
9. **Audit**: `guidance_suggested`, `guidance_suggest_refused`, `guidance_suggest_failed`, all HIDDEN from the agent
   API. They carry the credential, user, peer, model, counts (history rows used, digest groups, prompt chars,
   output length, flags) and a closed reason. Never a prompt, a reply or exception text.
10. **No config block.** Cost: the limits cannot be tuned without a code change.
