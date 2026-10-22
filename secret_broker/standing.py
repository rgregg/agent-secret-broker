"""Standing approvals: the one concept behind "Always" and the time-boxed chips.

A standing approval is a grant: {id, secrets (the exact set), mode (http | env |
ssh_sign), scope (read | any), expires_at (null = Always), created_by, created_at}.
A request is covered only by an approval whose secret set, mode and scope all
match (a reads-only approval never covers a mutating method; env and ssh are
always `any`). Two kinds exist:

  Always   expires_at is null. Stored in the credential's vault metadata (field
           `standing`, validated here), so it survives restarts and vault rebuilds.
           Checked against `risk.auto_approve_max`.
  timed    expires_at is a deadline. Kept in grants.json by grants.GrantStore.
           No risk ceiling: the human chose it explicitly for a short time.

This module holds the metadata schema and validator plus the display helpers used
by the Policies page and the approval card. The decision hooks live in broker.py
(`Broker._standing_claim`, `Broker._always_create`, `Broker.revoke_grant`).

Audit note for anything that exposes audit events to the agent side: standing
approvals are approval policy context. The `grant_*` events, `grant_id` and
`kind` describe them; show a standing-approved request as a plain "approved" and
never reveal which secrets have one.
"""
import re
import time

from . import clients as clients_mod
from . import grants as grants_mod

MAX_STANDING = 50                       # Always approvals per credential
KEYS = ("id", "secrets", "mode", "scope", "expires_at", "created_by", "created_at", "client")
ALWAYS_MODES = ("http", "env")          # SSH keeps its own per-host rules (sshrules.py)
_ID = re.compile(r"[A-Za-z0-9_-]{4,16}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
MAX_BY = 120


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def parse(raw, name, field="standing"):
    """Validate a credential's `standing` metadata -> normalized list of Always
    approvals (every entry has all seven keys; `expires_at` is None). Raises
    ValueError naming the offending `standing[i].field`."""
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list")
    if len(raw) > MAX_STANDING:
        raise ValueError(f"{field} has more than {MAX_STANDING} entries")
    out, ids = [], set()
    for i, r in enumerate(raw):
        at = f"{field}[{i}]"
        if not isinstance(r, dict):
            raise ValueError(f"{at} must be an object")
        extra = sorted(set(r) - set(KEYS))
        if extra:
            raise ValueError(f"{at}.{extra[0]} is not a known field ({', '.join(KEYS)})")
        for k in ("id", "mode", "scope", "created_by", "created_at"):
            if k not in r:
                raise ValueError(f"{at}.{k} is required")
        sid = r["id"]
        if not isinstance(sid, str) or not _ID.fullmatch(sid):
            raise ValueError(f"{at}.id must be 4-16 letters, digits, - or _")
        if sid in ids:
            raise ValueError(f"{at}.id {sid!r} is used twice")
        ids.add(sid)
        if r.get("secrets", [name]) != [name]:
            raise ValueError(f"{at}.secrets must be exactly [{name!r}]")
        if r["mode"] not in ALWAYS_MODES:
            raise ValueError(f"{at}.mode must be one of {', '.join(ALWAYS_MODES)}")
        if r["scope"] not in ("read", "any"):
            raise ValueError(f"{at}.scope must be read or any")
        if r["mode"] != "http" and r["scope"] != "any":
            raise ValueError(f"{at}.scope must be any for {r['mode']} approvals")
        if r.get("expires_at") is not None:
            raise ValueError(f"{at}.expires_at must be null (timed grants are not stored in the vault)")
        by = r["created_by"]
        if not isinstance(by, str) or not by.strip() or len(by) > MAX_BY:
            raise ValueError(f"{at}.created_by must be text of 1-{MAX_BY} characters")
        when = r["created_at"]
        if not isinstance(when, str) or not _TIME.fullmatch(when):
            raise ValueError(f"{at}.created_at must be a UTC time like 2026-10-19T12:00:00Z")
        client = clients_mod.parse_scope(r.get("client"), f"{at}.client")
        entry = {"id": sid, "secrets": [name], "mode": r["mode"], "scope": r["scope"],
                 "expires_at": None, "created_by": _CTRL.sub(" ", by).strip(), "created_at": when}
        if client != clients_mod.ANY:       # a global rule has exactly the shape it always had
            entry["client"] = client
        out.append(entry)
    return out


def serialize(entries):
    """The vault form of parsed Always approvals. A global rule (`client` is `*`) is written
    exactly as before this field existed, so existing data and older brokers are untouched;
    only a client-scoped rule carries `client`."""
    out = []
    for e in entries:
        d = {k: v for k, v in e.items() if k != "client"}
        if e.get("client", clients_mod.ANY) != clients_mod.ANY:
            d["client"] = e["client"]
        out.append(d)
    return out


def covers_label(mode, scope):
    """Short phrase for what a standing approval covers."""
    if mode == "env":
        return "run-with-secret"
    if mode == "ssh_sign":
        return "ssh"
    if mode == grants_mod.LEGACY:       # a grant saved before modes were recorded
        return "web reads only, ssh" if scope == "read" else "web any method, ssh"
    return "web reads only" if scope == "read" else "web any method"


def decided_by(kind, minutes, mode, scope):
    """History wording: 'standing approval (always, reads only)'."""
    what = ("run-with-secret" if mode == "env" else "ssh" if mode == "ssh_sign" else
            "reads only" if scope == "read" else "any method")
    how = "always" if kind == "always" else (f"{int(minutes)} min" if minutes else "timed")
    return f"standing approval ({how}, {what})"


def confirm_text(name, mode, scope, auto_max):
    """The question behind the Always chip."""
    if mode == "env":
        return (f"Always approve run-with-secret requests for {name}? The secret value will be "
                "released to the requesting machine without asking again when the request is "
                f"rated {auto_max} or lower.")
    what = "reads-only" if scope == "read" else "any-method"
    return (f"Always approve {what} requests for {name}? The secret will be used for matching "
            f"requests without asking again when the request is rated {auto_max} or lower.")


def scope_phrase(mode, scope):
    if mode == "env":
        return "run-with-secret requests only"
    return "reads only (GET, HEAD, OPTIONS)" if scope == "read" else "any method"
