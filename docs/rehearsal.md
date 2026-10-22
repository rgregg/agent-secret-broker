# Rehearsing the encrypted local backend

`tools/rehearse_local_backend.py` is an end-to-end check that the encrypted local
store (`backend.type: local`) behaves as documented when the **real broker** runs on
it. It is not a unit test (those are in `tests/`); it starts real processes, talks
to them over loopback HTTP and with the real `client/asb`, and prints one `PASS` or
`FAIL` line per check. Run it before you move a live broker from Bitwarden to the
local store, and after any change to `secret_broker/backends/local*.py`, the admin
CLI, or the policy-write paths (`set_meta`).

## What it needs

- Python 3.12 with the broker's requirements (`pip install -r requirements.txt`).
- `ssh-keygen` and `ssh-add` (group E).
- `docker` (group H only; skipped with a `SKIP` line when it is missing). Group H
  builds the image from the worktree `Dockerfile` (needs network the first time) as
  `asb-rehearsal:local`, falling back to pulling
  `ghcr.io/rgregg/agent-secret-broker:latest`. Use `--docker-image IMAGE` to test
  a specific image.
- Nothing else: no vault, no model key, no SSO proxy, no internet for groups A-G.

## How to run it

    python3 tools/rehearse_local_backend.py                 # everything, about 2 minutes
    python3 tools/rehearse_local_backend.py --groups ABD    # a subset (C-F pull in A and B)
    python3 tools/rehearse_local_backend.py --groups H --docker-image my/image:tag
    python3 tools/rehearse_local_backend.py --root /tmp/rehearsal-x   # keep the scratch tree

The exit code is 0 only when every check passed. The scratch tree is a new mode-0700
directory under `/tmp`, removed at the end unless you pass `--root` or `--keep`.

## Safety

It only ever touches things it creates. Every `asb` call gets a clean environment
(scratch `HOME`, `SECRET_BROKER_URL=http://127.0.0.1:<port>` and a made-up client key),
so it cannot fall back to `~/.config/secret-broker/client.json`; the helper refuses a
non-loopback URL; the first thing group B does is `asb status` against the throwaway
broker and it aborts unless the uptime is fresh and the backend is the local one. All
secrets are fake strings defined at the top of the script. Listeners bind to 127.0.0.1
(ports from 18800 up). It kills only the PIDs it started, and removes the containers
it created (`asb-reh-*`). The image `asb-rehearsal:local` is left as a build cache;
`docker rmi asb-rehearsal:local` removes it.

## What it stands up

- **The real broker**: `python -m secret_broker --config <file>` with a `local` backend,
  `approval_trusted_peers` 127.0.0.1, identity header `X-authentik-username`.
- **A stub upstream** that echoes request headers and body (so http mode and
  substitution can be asserted without the internet).
- **A stub model and notification endpoint**: an OpenRouter-style `/chat/completions`
  that rates everything low (so `approval: allow`, Always and `store` auto-approval can
  be tested deterministically) and a Telegram-style API so the notifier is real. The
  stub also records every notification so the script can assert none carries a value.
- **The approval web app is driven over HTTP**: the script reads the pending card and the
  CSRF token from the page and POSTs `/decide`, `/policies/guidance`, `/policies/ssh_hosts`
  and `/request/retry`, exactly as the SSO proxy and a browser would.

## What the groups check

| Group | Covers |
|---|---|
| A. Setup | `localstore init` with a passphrase key file and (separate store) an env key; `add` of an http note, an env note, an `approval: allow` note, a plain login with no metadata (adoption), a login with username and password; `list`/`show` print no values; store file is 0600 and holds no plaintext. |
| B. Broker on the store | Starts, `asb status` (fresh uptime, backend `local` ok, 7 items, 1 adopted, 0 invalid), `asb list`, `asb which`. |
| C. Request flows | http approved (secret substituted upstream, masked in the response), POST body placeholder, login username+password, adopted item, rotating an adopted item with `asb update --var`, denied (exit 4), expired (exit 5), `approval: allow` auto-approved, env mode with a visible script, `asb store`, `asb update` (needs approval), read-back, `asb audit verify` and `asb audit`, the offline `secret_broker.audit verify`, notifications carry no values. Then, on its own fresh store and throwaway broker, **agent-initiated credential requests** (`asb request-credential`): the card and the password-type entry page, the human's Store, a token and a login stored and then used through `asb http` against the stub upstream, a refused form (no host) that stays pending and echoes no secret, deny (exit 4), existing name and invalid name (exit 3), names-only notification, audit without value or purpose, survival across a broker restart, no plaintext in the encrypted store. Then **HTTP sessions** on the main broker with the real `asb`: the card (credential, hosts, methods, time, cap, no chips), the approver shortening the cap, a login that sets a cookie and a CSRF header with `--capture`, the next call carrying both upstream while the agent never sees them, refusals (method, host, call cap: exit 8), `status`, `close` and the Clients-tab revoke (exit 7), and no cookie or CSRF value in the audit log. Then **per-client credentials** on the main broker: `asb enroll` end to end (the card's confirmation code equals the terminal's, approval writes a 0600 `client.json` with a per-client key and prints no secret), the new key authenticating, an Always made from the client's card applying to that client only (the shared key is still asked), the Clients tab, revoke (exit 3 "revoked", the shared key unaffected, the client's rules removed, no key or hash in the audit log). |
| D. Policy persistence | Always, timed grant, Policies-editor guidance, `asb guidance propose` with 8 entries (apply 6, deny 2), Retry-failed after an injected write failure (store directory made read-only), SSH host policy editor, request details; then SIGTERM, restart on the same store: every item's metadata byte-identical, Always and the grant still effective, audit chain continues, no duplicates, no temp files left behind. |
| E. SSH | `asb store --ssh` into the local store (kind `ssh_key`), `asb ssh-agent`, `ssh-add -L`, `ssh-keygen -Y sign` needing approval, `-Y check-novalidate` verifying, an unapproved signature failing, no key material in notifications. |
| F. Failure and recovery | Wrong key at startup (up, empty catalog, `backend.ok` false, clear error, audited), key file fixed with no restart; flipped byte (never overwritten) and `.bak` restore; truncation to 0 and 50 bytes; missing and unknown config fields named; env key unset (`key_missing`); missing store and key appearing later; `change-key` (running and stopped), old key rejected, recovery key still works, `rotate-dek` (refuses to orphan the recovery wrap, then works); `idle_timeout` 5 s lock/unlock events; kill -9 then restart; 0640 store warning; admin CLI used while the broker runs (`store_reloaded`, no lost updates under concurrent writers); `import-env`; `import-bw` against a fake `bw` shim (dry run, real import, read-back equality, source untouched, refuses to clobber); finally a scan that no fake secret appears in any log, audit file, request-details file, encrypted store, captured CLI output, notification or process list (with a canary proving the scanner works). |
| G. Scale | A 300-item store and 20+20 policy edits: file size, cold and warm catalog load, write latency, broker start to loaded catalog, broker RSS. Numbers are printed at the end. |
| H. Docker | Container as `nobody` (65534) with `read_only`, `cap_drop ALL`, `no-new-privileges` and the store bind-mounted at `/data`: key as a mounted secret file, then as an environment variable; admin CLI run inside the image; core flows (http, Always, env, guidance, `asb store`); `docker restart` persistence; ownership and modes of `store.enc`, `.bak`, `.lock` and the audit files; loopback-only listeners; `docker inspect` shows no secret for the file key and only the env key for the env variant (documented); plus a bridge-network run with ports published on 127.0.0.1. |

## Expected output

    scratch: /tmp/asb-rehearsal-xxxxxxxx
    PASS [A] init (file key source, passphrase): rc=0 recovery_key_printed=1
    ...
    PASS [B] SAFETY asb status reports the throwaway broker (fresh uptime, local backend): ...
    ...
    == summary ==
    A: 8/8 passed
    ...
    number G store file size, 300 items (KiB): 83.7
    ...
    RESULT: ALL CHECKS PASSED

Reference numbers from the first run (a 4-core dev VM; yours will differ): a 300-item
store is about 84 KiB; a cold catalog load including the scrypt unlock takes about
55 ms and a warm one about 1.5 ms; a metadata write takes about 6 ms; the broker has
a 300-item catalog 0.3 s after start and uses about 43 MiB RSS; `docker restart`
is back in about half a second.

## What it does not cover

- **A real risk model.** Risk comes from a stub that says "low" (the string `highrisk`
  in a request makes it "high", but no check uses that yet). Prompt wording, prompt
  injection and the model's failure modes are covered by `tools/risk_eval`.
- **A real SSO proxy, TLS and the reverse proxy** in front of the two ports; the script
  plays the proxy by sending the identity header itself.
- **Real notification delivery** (Web Push, Home Assistant, Telegram) and phone UX.
- **Concurrency beyond the cases above**, power loss in the middle of a write (the
  atomic-replace sequence is unit-tested, not pulled out from under a running process
  with `kill -9` at a chosen instant), full disks, and file systems without `flock`
  (NFS, some FUSE mounts): put the store on a local disk.
- **Two brokers on one store.** `flock` protects writes, but the supported shape is
  one broker per store.
- **Bitwarden itself.** `import-bw` is exercised against a fake `bw` that implements
  only the commands the importer uses; run `import-bw --dry-run` against your real
  vault before cutting over.
- **Key custody.** The script cannot tell you where your real key and recovery key live.
  Encryption at rest does not help against anything that can read the store and the key
  while the broker runs (see the threat model in [reference.md](reference.md)).
- **Docker bridge networking with upstreams.** The container runs use host networking
  so the loopback stubs are reachable; the extra bridge run only proves the published
  ports and the store load.

## Reading a failure

Each `FAIL` line says which check and gives a short reason (never a value). The
scratch tree is removed on exit; re-run with `--root DIR` to keep the broker logs
(`DIR/logs/*.log`), the audit files (`DIR/data/*.audit.jsonl`) and the stores for
inspection. Many checks race the broker's background work (the first catalog load,
the moment a card is visible before auto-approval); where a check can race, the script
asks the audit log what happened instead of the approval page. If a check is flaky,
treat that as a finding and say which one.
