"""Time-boxed grants: "approve for the next N minutes".

When the human approves a request they may choose "Approve for N minutes".
For that window, further requests for exactly the same SET of secret names in
the same mode (`http`, `ssh_sign` or `env`) are approved without a tap. An env
grant releases the value to the requesting machine; it never covers a request
whose script text is not visible, and a grant made in one mode never covers
another. A grant made from a read-only http request (GET/HEAD/OPTIONS)
covers only such methods; one made from any other method covers all.
The grant expires at an absolute deadline (no sliding extension) and can be
revoked early. Grants are persisted (names, times and creator only; no values,
no tokens) so a broker restart does not drop them.

A timed grant has no risk ceiling by default (the human chose it explicitly for
a short time; `timed_grants.max_risk` defaults to `high`, and an operator may set
it lower to cap them); the no-expiry kind, "Always", lives in the credential's vault metadata
and is checked against risk.auto_approve_max (see standing.py).

This module holds the store, config validation and persistence. The decision
hooks live in broker.py (`Broker.create`, `Broker.decide_via`).

Audit note for anything that exposes audit events to the agent side: the
`grant_*` events and the `grant_id` / `grant_left_s` fields describe approval
context. Treat them like policy events and show a grant-approved request as a
plain "approved"; never reveal which secrets currently have a grant.
"""
import json
import os
import secrets
import threading
import time

from . import clients as clients_mod
from . import risk as risk_mod

ELIGIBLE_MODES = ("http", "ssh_sign", "env")
LEGACY = "legacy"           # grants saved before they recorded a mode: http and ssh_sign only
MODE_LABEL = {"http": "web", "env": "run-with-secret", "ssh_sign": "ssh", LEGACY: "web, ssh"}
READ_METHODS = ("GET", "HEAD", "OPTIONS")


def scope_for(mode, spec):
    """'read' when the approved request was a safe http method, else 'any'."""
    if mode == "http" and str((spec or {}).get("method", "")).upper() in READ_METHODS:
        return "read"
    return "any"


def covers(grant, mode, spec):
    """True when `grant` (by scope) may approve a later request."""
    if mode == "env" and grant.get("mode") != "env":
        return False
    if grant["scope"] == "any":
        return True
    return mode == "http" and str((spec or {}).get("method", "")).upper() in READ_METHODS
DEFAULTS = {"enabled": True, "durations": [5, 15, 30], "max_minutes": 60, "max_risk": "high"}
MAX_DURATIONS = 6
HARD_MAX_MINUTES = 24 * 60
RISK_CEILINGS = risk_mod.AUTO_MAX          # none|low|medium|high


def parse_config(raw, field="timed_grants"):
    """Validate the `timed_grants` object -> normalized dict. Raises ValueError
    naming the offending field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    unknown = sorted(set(raw) - set(DEFAULTS))
    if unknown:
        raise ValueError(f"{field}.{unknown[0]} is not a known setting")
    out = dict(DEFAULTS)
    out.update(raw)
    if not isinstance(out["enabled"], bool):
        raise ValueError(f"{field}.enabled must be true or false")

    def whole(v):
        return isinstance(v, int) and not isinstance(v, bool)
    mm = out["max_minutes"]
    if not whole(mm) or not 1 <= mm <= HARD_MAX_MINUTES:
        raise ValueError(f"{field}.max_minutes must be a whole number of minutes, 1-{HARD_MAX_MINUTES}")
    d = out["durations"]
    if not isinstance(d, list) or not 1 <= len(d) <= MAX_DURATIONS:
        raise ValueError(f"{field}.durations must be a list of 1-{MAX_DURATIONS} minute values")
    if not all(whole(x) and x > 0 for x in d):
        raise ValueError(f"{field}.durations must be whole numbers of minutes greater than 0")
    if any(x > mm for x in d):
        raise ValueError(f"{field}.durations must not exceed {field}.max_minutes ({mm})")
    if len(set(d)) != len(d):
        raise ValueError(f"{field}.durations must not repeat a value")
    out["durations"] = sorted(d)
    if out["max_risk"] not in RISK_CEILINGS:
        raise ValueError(f"{field}.max_risk must be one of {', '.join(RISK_CEILINGS)}")
    return out


def describe(cfg, auto_max="low"):
    """One line for the Settings page."""
    ceil = cfg["max_risk"]
    if not cfg["enabled"]:
        timed = "timed grants off"
    else:
        lim = ("(no ceiling)" if ceil == "high" else "(never used)" if ceil == "none"
               else f"(up to {ceil} risk)")
        timed = f"timed grants {lim} " + "/".join(str(m) for m in cfg["durations"]) + " min"
    always = ("Always off (risk.auto_approve_max none)" if auto_max == "none"
              else f"Always up to {auto_max} risk")
    return f"Standing approvals: {timed}; {always}"


class GrantStore:
    """In-memory grants keyed by the exact SET of secret names, the mode and the CLIENT
    scope (`*` = any client, else one client id), mirrored to a small JSON file. A request
    is covered only by a grant whose set equals its own (a subset or superset does not
    match) and whose client scope is the requesting client or `*`. Granting again for the
    same set, mode and client replaces (and so restarts) the grant, whatever its scope was.
    `on_event(name, **fields)` receives audit records; it must not call back in.
    """

    def __init__(self, path, on_event, clock=time.time, max_minutes=60):
        self._path = path
        self._log = on_event
        self._clock = clock
        self._max_s = max_minutes * 60
        self._lock = threading.Lock()
        self._by_set = {}       # (frozenset(names), mode, client) -> grant

    # -- persistence -------------------------------------------------------
    def load(self):
        """Read the file, dropping expired or implausible entries. A corrupt file
        fails closed: no grants, and an audit warning."""
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                data = json.load(f)
            items = data["grants"]
            if not isinstance(items, list):
                raise ValueError("grants is not a list")
            # client-scoped grants live under their own key, so a broker from before client
            # scoping (which reads only "grants") drops them instead of widening them to everyone
            scoped = data.get("client_grants", [])
            if not isinstance(scoped, list):
                raise ValueError("client_grants is not a list")
            items = items + scoped
        except (OSError, ValueError, KeyError, TypeError) as e:
            self._log("grants_file_corrupt", warning="grants file ignored: no grants loaded",
                      error=str(e)[:120])
            return
        now = self._clock()
        with self._lock:
            for g in items:
                try:
                    names = sorted({str(n)[:80] for n in g["secrets"]})
                    if not names or g["scope"] not in ("read", "any"):
                        raise ValueError("bad entry")
                    g = {"id": str(g["id"])[:16], "secrets": names, "scope": g["scope"],
                         "minutes": int(g["minutes"]), "created_at": float(g["created_at"]),
                         "expires_at": float(g["expires_at"]), "created_by": str(g["created_by"])[:120],
                         "channel": str(g.get("channel") or "")[:20],
                         "request_id": str(g.get("request_id") or "")[:64],
                         "mode": g.get("mode") if g.get("mode") in ELIGIBLE_MODES else LEGACY,
                         "client": clients_mod.parse_scope(g.get("client"))}
                except (KeyError, TypeError, ValueError):
                    self._log("grants_file_corrupt", warning="skipped a malformed grant entry")
                    continue
                if g["expires_at"] <= now:
                    self._log("grant_expired", grant_id=g["id"], secrets=g["secrets"],
                              expires_at=g["expires_at"], created_by=g["created_by"],
                              note="expired while the broker was down")
                elif g["expires_at"] - now > self._max_s + 60:
                    self._log("grant_dropped", grant_id=g["id"], secrets=g["secrets"],
                              reason="deadline is further out than max_minutes allows")
                else:
                    self._by_set[(frozenset(g["secrets"]), g["mode"], g["client"])] = g

    def _save_locked(self):
        if not self._path:
            return
        every = sorted(self._by_set.values(), key=lambda g: g["id"])
        data = {"version": 4, "grants": [g for g in every if g["client"] == clients_mod.ANY],
                "client_grants": [g for g in every if g["client"] != clients_mod.ANY]}
        tmp = f"{self._path}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=1)
            os.replace(tmp, self._path)
        except OSError as e:
            self._log("grants_file_write_failed", warning="grants are kept in memory only",
                      error=str(e)[:120])

    # -- operations --------------------------------------------------------
    def _expire_locked(self):
        now = self._clock()
        gone = [g for g in self._by_set.values() if g["expires_at"] <= now]
        for g in gone:
            del self._by_set[(frozenset(g["secrets"]), g["mode"], g["client"])]
            self._log("grant_expired", grant_id=g["id"], secrets=g["secrets"], mode=g["mode"],
                      client_id=g["client"],
                      expires_at=g["expires_at"], created_by=g["created_by"])
        if gone:
            self._save_locked()
        return gone

    def sweep(self):
        with self._lock:
            return self._expire_locked()

    def add(self, names, minutes, scope, created_by, channel, request_id, mode=None, client=clients_mod.ANY):
        now = self._clock()
        key = (frozenset(names), mode or LEGACY, client)
        g = {"id": secrets.token_hex(4), "secrets": sorted(key[0]), "scope": scope, "mode": key[1],
             "client": client,
             "minutes": int(minutes), "created_at": now, "expires_at": now + minutes * 60,
             "created_by": created_by, "channel": channel, "request_id": request_id or ""}
        with self._lock:
            self._expire_locked()
            self._by_set[key] = g
            self._save_locked()
        return dict(g)

    def find(self, names, mode=None, client=None):
        """The active grant for exactly this set of names and mode that applies to `client`,
        or None. A grant scoped to that client wins over one for any client. A grant scoped
        to another client never applies. With no client, only a grant for any client.
        With no mode, any grant for the set (a legacy grant has no mode)."""
        scopes = [client, clients_mod.ANY] if client and client != clients_mod.ANY else [clients_mod.ANY]
        with self._lock:
            self._expire_locked()
            for sc in scopes:
                if mode is None:
                    g = next((g for (k, _, c), g in self._by_set.items()
                              if k == frozenset(names) and c == sc), None)
                else:
                    g = self._by_set.get((frozenset(names), mode, sc))
                    if g is None and mode in ("http", "ssh_sign"):
                        g = self._by_set.get((frozenset(names), LEGACY, sc))
                if g:
                    return dict(g)
            return None

    def active(self):
        with self._lock:
            self._expire_locked()
            return sorted((dict(g) for g in self._by_set.values()), key=lambda g: g["expires_at"])

    def revoke_client(self, client):
        """Remove every grant scoped to one client; returns them."""
        with self._lock:
            gone = [g for g in self._by_set.values() if g["client"] == client]
            for g in gone:
                del self._by_set[(frozenset(g["secrets"]), g["mode"], g["client"])]
            if gone:
                self._save_locked()
            return [dict(g) for g in gone]

    def revoke(self, grant_id):
        """Remove a grant by id; returns it, or None when not active."""
        with self._lock:
            self._expire_locked()
            for key, g in list(self._by_set.items()):
                if g["id"] == grant_id:
                    del self._by_set[key]
                    self._save_locked()
                    return dict(g)
        return None

    def left_s(self, g):
        return max(0, int(g["expires_at"] - self._clock()))
