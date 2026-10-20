# Per-credential risk guidance

A secret can carry operator-written guidance that tells the risk classifier how
to rate requests made with that credential. The generic rubric knows nothing
about what "PullStack" or "unlock" means for your service; guidance does.

Set it on the Policies tab ("Risk guidance" under each secret) or put a
`guidance` string in the item's `broker` metadata. Plain text, at most 2000
characters. How it is used and its limits: [risk.md](risk.md#per-credential-guidance).

Keep it accurate. Guidance can lower ratings, so a line such as "deletes are
low" makes the broker less careful. Describe what is dangerous as clearly as
what is harmless, and prefer "unknown operations: high" as the last line. It
does not change SSH signing (always high), and the approve ceiling
(`risk.auto_approve_max`) still applies.

The texts below are starting points. Names of operations differ by version;
adjust them to what you actually use. Paste one into the editor for the matching
secret.

## Letting an agent propose guidance

An agent can never set guidance: it can lower ratings, so an agent that could write it
would weaken its own approvals. It can only propose text, and you decide.

    asb guidance propose proposal.json     # [{"name": "komodo", "text": "..."}, ...]
    asb guidance propose --from-dir ./g    # g/komodo.txt, g/grafana.txt
    asb guidance status ID                 # applied / denied / failed names

The command prints the request id and waits ("review each entry on the approval page").
A proposal shows up on the dashboard and as a notification that says only "Guidance change
proposed for N credentials"; the notification has no Approve or Deny button and no Always
or "for a while" option exists. Open the card (or the link) to review.

How review works:

- Each credential is a block with the **current** guidance and the **proposed** text side
  by side, a line diff, a character count, and a **Flagged:** note if the new text contains
  phrases like "always low", "never high", "rate it low", "ignore", "disregard", "override",
  "approve", "safe", "trusted" or "no risk". Flags highlight, they do not block.
- Nothing is ticked. Tick **Apply this one** on the entries you want, then **Apply
  selected** (it stays disabled until something is ticked). **Deny all**, or letting it
  expire (an hour by default, `guidance_proposals.ttl_s`), changes nothing.
- If the current guidance changed after the agent wrote its proposal, that entry says
  **changed since proposed**; check the diff before ticking it.
- Only ticked entries are written, exactly as if you had saved them in the Policies editor
  (same limits, same `guidance_changed` marker). The agent is told only the names that were
  applied, denied or failed.
- Treat every proposal like a pull request from someone with an interest in the outcome.
  Read the whole text, not just the flagged words. Because the agent cannot read the current
  guidance, its text is a fresh draft: ask for edits as a new proposal rather than ticking a
  draft you do not fully agree with.

The agent never sees any guidance, current or proposed, in discovery, status, results or the
audit API. The proposal text is shown only on the approval card and dropped once it is
decided; the audit log keeps names, lengths and short hashes. Details and the audit events:
[reference.md](reference.md#guidance-proposals-agent-written-human-approved).

## Komodo

    Komodo executes actions through POST /execute with the action name in the path or body.
    PullStack, PullDeployment, Get*/List* reads, and reads of logs and stats: low.
    DeployStack, DeployDeployment, RestartStack, RestartDeployment, StartStack, StopStack,
    RunBuild, RunProcedure, updating a stack's config: medium.
    DestroyStack, DestroyDeployment, DeleteStack, PruneSystem, PruneImages used on a server,
    deleting servers, builds or resources, editing users, API keys or variables holding
    secrets: high.

## Grafana

    Reads: dashboards, folders, datasource queries, search, alert rule listing, annotations: low.
    Creating or updating dashboards, annotations, alert rules, silences and contact points: medium.
    Deleting dashboards, folders, datasources or alert rules; creating or deleting API keys,
    service accounts, users or teams; changing permissions or organization settings;
    changing data source credentials: high.

## Home Assistant

    Reading states, history, logbook, config and the entity list: low.
    Turning lights, switches, fans, media players and scenes on or off, setting
    temperature, running ordinary scripts and automations, sending notifications: medium
    (turning a single light on or off may be treated as low).
    Unlocking doors, opening garage doors, disarming alarms, switching cameras off,
    changing alarm modes, calling services on locks, covers that are doors, or
    alarm_control_panel; restarting or reloading Home Assistant itself; editing
    automations, users or integrations; creating long-lived tokens: high.

## Proxmox

    Reading cluster, node, VM and container status, config, tasks, storage and backups: low.
    Starting, stopping, rebooting or snapshotting one guest, taking a backup, console
    or guest-agent commands that only read: medium.
    Deleting or destroying guests, snapshots, disks, volumes or backups; migrating,
    restoring over or cloning to replace a guest; changing firewall, network, storage,
    users, roles, tokens or permissions; guest-agent exec of arbitrary commands;
    node shutdown or reboot: high.

## Cloudflare (DNS and Pages)

    Listing zones, DNS records, Pages projects and deployments, analytics: low.
    Creating a Pages deployment or retrying one, purging cache for a path, creating a
    new DNS record that does not replace anything: medium.
    Updating or deleting DNS records (they change where traffic and mail go), changing
    zone settings, SSL mode, firewall or WAF rules, redirects, tunnels, Workers routes;
    deleting Pages projects or domains; creating or editing API tokens: high.

## UniFi

    Reading sites, devices, clients, stats, events and settings: low.
    Blocking, unblocking or reconnecting one client, restarting one access point or
    switch port (power-cycling PoE), locating a device: medium.
    Changing firewall rules, networks, VLANs, port forwarding, Wi-Fi passwords or SSIDs,
    DHCP or DNS settings, adopting or forgetting devices, firmware upgrades, rebooting
    the gateway or a whole site, creating admins or API keys, factory resets: high.

## Immich

    Searching, listing and viewing assets, albums, people and server statistics: low.
    Uploading assets, creating or editing albums, tags, descriptions and favorites,
    adding assets to an album, starting a job: medium.
    Deleting assets or albums, emptying the trash, deleting people or libraries,
    changing sharing or creating shared links, admin user changes, creating API keys,
    bulk actions across many assets: high.

## Tailscale

    Listing devices, users, routes, ACL and DNS settings: low.
    Authorizing or tagging one device, expiring one node key, setting a device name: medium.
    Editing the ACL policy, DNS or split DNS, enabling subnet routes or exit nodes,
    creating auth keys or API keys, deleting devices, inviting or removing users,
    changing tailnet settings: high.

## OpenAI and OpenRouter

    Listing models, reading usage and credit balances, one ordinary chat or embedding
    completion within normal size: low.
    Large or repeated generation, fine-tuning or batch jobs that spend real money,
    uploading files: medium.
    Creating, rotating or deleting API keys, changing billing, limits or organization
    members, deleting files or fine-tuned models, any request that moves credits or
    adds payment methods: high.

## Stripe

    Retrieving and listing customers, charges, invoices, payouts, balance and events: low.
    Creating or updating a customer, product, price, draft invoice or payment link
    without moving money: medium.
    Anything that moves or commits money: creating charges, payment intents, refunds,
    payouts, transfers, subscriptions or finalizing and paying invoices; deleting
    customers or products; changing webhook endpoints, API keys or account settings: high.

## Twilio

    Reading messages, calls, usage records and phone number lists: low.
    Sending one SMS or placing one call to a known number: medium.
    Bulk or repeated messages, sending to unknown numbers or international numbers,
    buying or releasing phone numbers, changing webhooks, messaging services or
    subaccounts, creating or deleting API keys, closing accounts: high.

## Authentik

    Reading users, groups, applications, providers, events and flows: low.
    Editing one application, provider or flow binding; sending a recovery email;
    updating a user's name or attributes: medium.
    Creating, deleting or deactivating users or groups, changing passwords or
    permissions, superuser status, tokens and API keys, outposts, policies, flows
    that gate login, sources, certificates, impersonation, or deleting applications
    and providers: high.

## InfluxDB

    Flux or InfluxQL read queries, listing buckets, tasks and dashboards: low.
    Writing points to a bucket, creating or updating a task, dashboard or notification
    rule: medium.
    Deleting data (the delete API), deleting buckets, changing retention, creating,
    changing or deleting tokens, users, orgs or authorizations, queries containing
    to() or other writes presented as reads: high.

## Frigate and other NVR APIs

    Reading events, snapshots, thumbnails, clips, stats, configuration and live status: low.
    Creating or editing one event, label or sub-label, toggling detection, recording or
    snapshots for one camera, PTZ moves, exporting a clip: medium.
    Deleting events, recordings or exports in bulk, restarting the service, saving
    configuration, changing users or passwords, disabling all cameras or audio,
    enabling remote access: high.

## Plex, Sonarr and Radarr

    Searching, listing libraries, queues, calendars, history and status: low.
    Adding a movie or series, searching for releases, triggering a library scan or a
    refresh, editing one item's monitored state or quality profile: medium.
    Deleting media, files or series, deleting from disk, bulk edits, importing over
    existing files, changing quality profiles, root folders or download clients,
    settings or API keys, claiming or sharing servers, deleting users: high.

## Nginx Proxy Manager

    Listing proxy hosts, certificates, streams, access lists and users: low.
    Enabling or disabling one proxy host, renewing one certificate: medium.
    Creating, updating or deleting proxy hosts, redirections, streams or custom
    locations (they change what is exposed), requesting certificates for new
    domains, changing access lists, users, admin passwords or tokens: high.

## Wi-Fi or modem login

    Reading status pages, connected devices and signal statistics: low.
    Rebooting the modem or a single access point, renaming a device: medium.
    Anything that changes Wi-Fi names or passwords, DNS, port forwarding, firewall,
    remote administration, router or admin passwords, firmware, factory reset, or
    that uses the login to read the stored Wi-Fi password: high.
