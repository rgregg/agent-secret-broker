# Client update notice: design calls

The broker already knows the newest client it expects (`clients.min_version`, else `LATEST_CLIENT_VERSION`). It now
tells every client that number; a client older than it prints a short notice on stderr.

## Calls

1. **The broker sends one validated version string and nothing else.** Field `latest_client_version` in the
   `POST /v1/requests` 202 answer and in `GET /v1/status`, built in one place (`clientver.expected`). It is absent
   when `clients.min_version: "none"` or `clients.update_notice: false`. Same value for every client. A body field,
   not a header: both CLIs already parse the JSON body, a header would need an API change in `asb-client`.
2. **Who compares.** The client, with the same numeric rule as `clientver.outdated` (missing trailing fields count
   as 0; anything that is not digits-and-dots is "unknown", never outdated). The broker's value is untrusted: it is
   validated against the `clientver` grammar (max 4 fields of 1-4 digits) and anything else is ignored silently.
3. **URL and instruction text are compiled into each client**, never read from the broker. Fork builds change the
   constant (not configurable at runtime, so a hostile config or broker cannot redirect an agent).
4. **Where and when.** stderr only, once per 24h per machine, from the first broker answer that carries the field.
   The state file is `$XDG_STATE_HOME/asb/update-notice` (else `~/.local/state/asb/`), holding a unix time, written
   atomically. If it cannot be written the notice is NOT printed (otherwise a read-only home would nag on every
   call). `ASB_NO_UPDATE_CHECK=1` turns it off. No extra request is made: the notice rides on answers the command
   already fetched. `asb status`, `asb version` and `asb guide` never print the notice (they show it deliberately).
5. **`asb version`** prints the client version, the version the broker expects, whether an update is available and
   the release URL. It makes one `GET /v1/status` (a command the user ran, not a background check); with no broker
   config or an unreachable broker it still prints the client version and exits 0.
6. **Agent instructions** live in one constant (`UPDATE_HOWTO`) used by the notice, `asb version`, `asb guide` and the
   `agent-setup` block (block version 1 -> 2 so existing files are refreshed). No code downloads or installs anything.
7. Version numbers are unchanged (`1.1`): the notice is testable by pointing a broker at a higher `min_version`.
