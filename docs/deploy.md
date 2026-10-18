# Deploying and verifying without a shell on the host

You can roll out a new broker image and confirm it is the one you meant without
logging in to the Docker host. Deploy through Komodo's API, then verify through the
broker's own API with `asb status`. No root or host shell access is needed at any
step.

## 1. Deploy through Komodo

This assumes the broker runs as a Komodo stack (compose file in the stack, image
`ghcr.io/rgregg/agent-secret-broker:latest` or a pinned tag). CI builds the image
on every push to `main` and stamps it with the commit sha (see below).

Use a Komodo API key and secret (created in Komodo under your user settings). Send
them as `X-Api-Key` and `X-Api-Secret` headers. Each call is a POST to `/execute`
with a JSON body of the form `{"type": ..., "params": {...}}`.

    KOMODO=https://komodo.example.com        # your Komodo Core address
    STACK=asb                                # your stack name (or id)

    # pull the new image, then recreate the container
    curl -fsS -X POST "$KOMODO/execute" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: $KOMODO_KEY" -H "X-Api-Secret: $KOMODO_SECRET" \
      -d "{\"type\": \"PullStack\", \"params\": {\"stack\": \"$STACK\"}}"

    curl -fsS -X POST "$KOMODO/execute" \
      -H "Content-Type: application/json" \
      -H "X-Api-Key: $KOMODO_KEY" -H "X-Api-Secret: $KOMODO_SECRET" \
      -d "{\"type\": \"DeployStack\", \"params\": {\"stack\": \"$STACK\"}}"

Each call returns a Komodo `Update` object. Run the two calls in order: `PullStack`
fetches the image (`docker compose pull`), `DeployStack` runs `docker compose up`.
Keep the API key and secret in the secret broker or your CI secret store, not in
shell history.

What was checked against Komodo's public docs and source (via the Komodo
repository docs and the `komodo_client` API reference):

- Confirmed: authentication is the `X-Api-Key` and `X-Api-Secret` headers.
- Confirmed: `PullStack` takes `stack` (id or name) and optional `services`;
  `DeployStack` takes `stack` (id or name), optional `services` and optional
  `stop_time`; both return an `Update`.
- Confirmed: Komodo's read and write routers accept a POST to the base path with a
  `{"type", "params"}` body, and also a POST to `/<path>/<type>` with just the params.
- Assumed: the execute router behaves the same as the read and write routers
  (base path with `{"type", "params"}`, or `/execute/<type>` with the params). It
  is the same client code path, but test it once against your Komodo version.
- Assumed: the call returns as soon as the update is queued, so the container may
  still be restarting. The verify step below retries until the new version appears.

## 2. Verify with the broker's own API

The broker reports what it is running at `GET /v1/status` (client API, same
`X-Client-Key` as the other `/v1` endpoints). `asb status` calls it:

    asb status
    asb status --json

Check that:

- `version` equals the commit sha you expected (for example the output of
  `git rev-parse HEAD` for the commit you pushed, or `${{ github.sha }}` in CI), and
- `catalog` shows `0 invalid` (a non-zero count means a vault item has bad broker
  metadata and was skipped), and
- `backend` is `ok`.

A small retry loop works well right after a deploy (exit code 3 means the broker is
not reachable yet):

    for i in $(seq 1 30); do
      v=$(asb status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])') \
        && [ "$v" = "$EXPECTED_SHA" ] && break
      sleep 5
    done
    asb status

`/v1/status` needs the client key (a hook key or no key is refused), takes no
approval, and never reads the vault: it reports the broker's in-memory state. It
returns counts and type names only, with no secret names, hosts, keys or config
values.

## How the version is stamped

The image build takes `GIT_SHA` and `BUILD_TIME` build arguments and stores them in
the `BROKER_GIT_SHA` and `BROKER_BUILD_TIME` environment variables. The CI workflow
passes `${{ github.sha }}` and the build time. When you build locally without those
arguments, or run `python -m secret_broker` from a checkout, the broker reports
`unknown`:

    docker build --build-arg GIT_SHA="$(git rev-parse HEAD)" \
                 --build-arg BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -t asb .

## Response shape

    {
      "version": "<git sha or unknown>",
      "build_time": "<iso utc or unknown>",
      "started_at": "<iso utc>",
      "uptime_s": 1234,
      "catalog": {"count": 5, "invalid": 0, "adopted": 1, "loaded_at": "<iso utc or null>"},
      "backend": {"type": "bw|file|local", "ok": true},
      "notifiers": ["ticker", "webpush"],
      "features": {"ha_hook": true, "ssh": false, "webpush_actions": true}
    }

`backend.ok` turns false when the most recent vault read failed (the broker keeps
serving the last good catalog). `catalog.invalid` counts vault items whose broker
metadata was rejected.
