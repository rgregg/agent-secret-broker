"""Per-client credentials and human-approved enrollment.

Every machine (or user) that talks to the broker is a CLIENT with its own random 256-bit
secret. The client generates the secret locally; the broker stores only a SHA-256 hash of it
(the secret is high entropy, so a plain hash is enough) and compares in constant time. A
request carries the secret in `X-Client-Key`, exactly as the old shared key did.

Enrolling a new client:

  1. `asb enroll` makes the secret, computes its hash and POSTs {name, hash, claim} to
     `POST /v1/enroll`, the ONLY unauthenticated client-API path. The secret itself is never
     sent while enrolling; the hash is not usable as a credential. (This is a deliberate
     deviation from "send the key over TLS once": nothing secret crosses the wire or can be
     logged by a reverse proxy during enrollment.)
  2. The broker creates a pending enrollment (never a Request, so no notification button,
     link, token or Home Assistant hook can decide it) and sends a names-only notification.
  3. The approval page shows a card: the proposed name, the unverified `user@host` claim,
     the source address and a confirmation code derived from the hash. The client prints the
     same code. The human matches the two and presses Approve or Deny (identity header +
     CSRF, like every other approval-page action).
  4. The client polls `GET /v1/enroll/<id>` (the id is a 128-bit random token only the enroller
     holds) until it is approved, denied or expired, then writes its client.json.

This module holds the config parser, the pure helpers (hashing, names, the code), the
persisted ClientStore with its in-memory enrollments and rate limits, the page fragments, and
`ClientsMixin`, the Broker methods (authentication results, enrollment decisions, revoke,
rename and the client-scoped rule cleanup).

Fail closed, and no exception text anywhere an agent, a log, the audit log, history or a page
could show it: every failure here is reported as a fixed string or a class name.

Audit note for anything that exposes audit events to the agent side: enrollment and client
administration events are approval context (HIDDEN in audit_api); an agent sees only the
client NAME on its own `requested` events.
"""
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time

from . import risk as risk_mod
from . import ui_theme

ANY = "*"                       # a rule scope that applies to every client
LEGACY_ID = "legacy"
LEGACY_NAME = "shared key (legacy)"
ID_RE = re.compile(r"c-[0-9a-f]{8}")
SCOPE_RE = re.compile(r"\*|legacy|c-[0-9a-f]{8}")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,31}")
CLAIM_RE = re.compile(r"[A-Za-z0-9@._:+()\[\]-]{1,120}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
STATES = ("active", "revoked")
MAX_CLIENTS = 100               # rows kept (active and revoked); remove revoked rows to make room
SECRET_PREFIX = "asbc1_"        # per-client secrets; the legacy shared key has no such prefix
BODY_LIMIT = 1024               # bytes of an enrollment request
DEFAULTS = {"enabled": True, "ttl_s": 600, "max_pending": 3}
TTL_MIN, TTL_MAX = 30, 3600
MAX_PENDING_CEILING = 10
SOURCE_PENDING = 2              # pending enrollments per source address
RESOLVED_KEEP_S = 600           # a decided enrollment stays pollable this long
COOLDOWN_S = 300                # a source whose enrollment was denied or expired waits this long
# fixed-window limits: (per source, global)
SUBMIT_MIN = (3, 10)
SUBMIT_HOUR = (6, 20)
POLL_MIN = (90, 600)
STATS_FLUSH_S = 30
RETRY_S = 5                     # after a failed write, retry on the next operation this much later
FAIL_LOG_S = 30                 # one auth-failure audit record per source per window
RATE_MAP_CAP = 4096
LEGACY_VALUES = ("allow", "deny")


# ---------------------------------------------------------------- pure helpers
def hash_secret(secret):
    """Hex SHA-256 of a client secret, domain separated from every other use of the secret.
    client/asb carries an identical copy; tests pin both to the same vector."""
    return hashlib.sha256(b"asb-client-secret-v1\0" + secret.encode()).hexdigest()


def confirm_code(secret_hash):
    """The short code both the card and the terminal show: derived from the hash (never the
    raw secret), 8 base32 characters as XXXX-XXXX."""
    d = hashlib.sha256(b"asb-enroll-code-v1\0" + secret_hash.encode()).digest()
    s = base64.b32encode(d).decode()[:8]
    return s[:4] + "-" + s[4:]


def valid_name(name):
    """A client name: lowercase letters, digits, - _ . up to 32 characters, and never
    shaped like a client id or the reserved word."""
    return (isinstance(name, str) and NAME_RE.fullmatch(name) is not None
            and ID_RE.fullmatch(name) is None and name != LEGACY_ID)


def clean_claim(text):
    return text if isinstance(text, str) and CLAIM_RE.fullmatch(text) else None


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def scope_label(scope, names):
    """Display for a rule scope: 'any client', or the client's name (id if unknown)."""
    if scope in (None, ANY):
        return "any client"
    return names.get(scope) or f"{scope} (removed)"


def parse_scope(raw, field="client"):
    """Validate a stored rule scope; '*' when absent. ValueError naming the field."""
    if raw is None:
        return ANY
    if not isinstance(raw, str) or not SCOPE_RE.fullmatch(raw):
        raise ValueError(f"{field} must be * or a client id")
    return raw


# ---------------------------------------------------------------- config
def parse_config(cfg):
    """Validate `legacy_client_key`, `enrollment` and `clients` -> a normalized dict
    {"legacy": allow|deny, "enrollment": {...}, "overrides": {client id: {...}}}. ValueError
    naming the field."""
    legacy = cfg.get("legacy_client_key", "allow")
    if legacy not in LEGACY_VALUES:
        raise ValueError("legacy_client_key must be allow or deny")
    raw = cfg.get("enrollment")
    raw = {} if raw is None else raw
    if not isinstance(raw, dict):
        raise ValueError("enrollment must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"enrollment.{k} is not a known option")
    enr = {**DEFAULTS, **raw}
    whole = lambda v: isinstance(v, int) and not isinstance(v, bool)  # noqa: E731
    if not isinstance(enr["enabled"], bool):
        raise ValueError("enrollment.enabled must be true or false")
    if not whole(enr["ttl_s"]) or not TTL_MIN <= enr["ttl_s"] <= TTL_MAX:
        raise ValueError(f"enrollment.ttl_s must be a whole number of seconds from {TTL_MIN} to {TTL_MAX}")
    if not whole(enr["max_pending"]) or not 1 <= enr["max_pending"] <= MAX_PENDING_CEILING:
        raise ValueError(f"enrollment.max_pending must be a whole number from 1 to {MAX_PENDING_CEILING}")
    overrides = {}
    block = cfg.get("clients")
    block = {} if block is None else block
    if not isinstance(block, dict):
        raise ValueError("clients must be an object")
    for cid, spec in block.items():
        at = f"clients.{cid}"
        if not (ID_RE.fullmatch(cid) or cid == LEGACY_ID):
            raise ValueError(f"{at}: the key must be a client id such as c-1a2b3c4d, or legacy")
        if not isinstance(spec, dict):
            raise ValueError(f"{at} must be an object")
        extra = sorted(set(spec) - {"risk", "plans"})
        if extra:
            raise ValueError(f"{at}.{extra[0]} is not a known option (risk, plans)")
        rk = spec.get("risk")
        if rk is not None and not isinstance(rk, dict):
            raise ValueError(f"{at}.risk must be an object")
        rk = rk or {}
        extra = sorted(set(rk) - {"auto_approve_max", "auto_modes"})
        if extra:
            raise ValueError(f"{at}.risk.{extra[0]} is not a known option (auto_approve_max, auto_modes)")
        ov = {}
        if "auto_approve_max" in rk:
            if rk["auto_approve_max"] not in risk_mod.AUTO_MAX:
                raise ValueError(f"{at}.risk.auto_approve_max must be one of {', '.join(risk_mod.AUTO_MAX)}")
            ov["auto_approve_max"] = rk["auto_approve_max"]
        if "auto_modes" in rk:
            ov["auto_modes"] = risk_mod.parse_auto_modes({"auto_modes": rk["auto_modes"]}, f"{at}.risk")
        if spec.get("plans") is not None:
            from . import plans as plans_mod        # late: plans.py imports nothing from here
            ov["plans"] = plans_mod.parse_client_override(spec["plans"], f"{at}.plans")
        overrides[cid] = ov
    return {"legacy": legacy, "enrollment": enr, "overrides": overrides}


# ---------------------------------------------------------------- the store
def _record(r):
    """A validated client record from the persisted form, or ValueError."""
    if not isinstance(r, dict):
        raise ValueError("record")
    cid, name, h = r.get("id"), r.get("name"), r.get("hash")
    if not (isinstance(cid, str) and ID_RE.fullmatch(cid)) or not valid_name(name):
        raise ValueError("record")
    if not (isinstance(h, str) and HASH_RE.fullmatch(h)) or r.get("state") not in STATES:
        raise ValueError("record")
    num = lambda v: v is None or (isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0)  # noqa: E731
    if not (num(r.get("created")) and num(r.get("last_seen")) and num(r.get("revoked_at"))
            and isinstance(r.get("requests", 0), int) and not isinstance(r.get("requests", 0), bool)):
        raise ValueError("record")
    text = lambda v, n: v[:n] if isinstance(v, str) and v.isascii() and v.isprintable() else ""  # noqa: E731
    return {"id": cid, "name": name, "hash": h, "state": r["state"],
            "created": float(r.get("created") or 0), "last_seen": r.get("last_seen"),
            "requests": max(0, int(r.get("requests", 0))), "last_source": text(r.get("last_source"), 64),
            "approved_by": text(r.get("approved_by"), 120), "claim": text(r.get("claim"), 120),
            "enrolled_from": text(r.get("enrolled_from"), 64), "revoked_at": r.get("revoked_at"),
            "revoked_by": text(r.get("revoked_by"), 120)}


class ClientStore:
    """The enrolled clients (persisted), the pending enrollments (memory) and the limiters.
    `log(event, **fields)` receives audit records; it must not call back in."""

    def __init__(self, path, log, config, clock=time.time):
        self._path = path
        self._log = log
        self.cfg = config               # parse_config() output; ttl/cap are read live (tests)
        self.clock = clock
        self._lock = threading.RLock()
        self._clients = {}              # id -> record
        self._legacy = {"last_seen": None, "last_source": "", "requests": 0}
        self._pending = {}              # enrollment id -> enrollment
        self._cooldown = {}             # source -> until
        self._rates = {}                # (kind, window) -> {key: {"t", "n"}}
        self._dirty = False
        self._saved_at = 0.0
        self._lapsed = []               # enrollments that expired and are not yet audited
        self._revoked = set()           # ids revoked in this process: wins over any loaded or saved state
        self._failing = False           # the last write failed; a retry is due
        self._retry_at = 0.0
        self.unreadable = False         # the file exists but cannot be read
        self._fail_log = {}             # source -> {"t", "n"}
        self.broken = False             # the file exists but could not be read: never overwritten
        self._load()

    # -- persistence -------------------------------------------------------
    def _load(self):
        if not self._path:
            return
        try:
            with open(self._path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return                      # a fresh install: no clients yet
        except (OSError, ValueError):
            self._fail_closed()
            return
        try:
            if not isinstance(data, dict) or not isinstance(data.get("clients"), list):
                raise ValueError("shape")
            clients = {}
            for r in data["clients"]:
                rec = _record(r)
                if rec["id"] in clients:
                    raise ValueError("duplicate")
                clients[rec["id"]] = rec
            leg = data.get("legacy")
            if isinstance(leg, dict) and isinstance(leg.get("requests", 0), int):
                seen, src = leg.get("last_seen"), str(leg.get("last_source") or "")
                self._legacy = {"last_seen": seen if isinstance(seen, (int, float)) else None,
                                "last_source": src[:64] if src.isascii() and src.isprintable() else "",
                                "requests": max(0, leg.get("requests", 0))}
            self._clients = clients
        except (ValueError, TypeError, KeyError):
            self._fail_closed()

    def _fail_closed(self):
        """The client list cannot be trusted: no per-client credential is accepted (a missing or
        unreadable list must never read as 'nobody was revoked'), enrollment is off and the file
        is never overwritten. The legacy shared key follows its own setting."""
        self.broken = self.unreadable = True
        self._clients = {}
        self._log("clients_file_corrupt", warning="clients file unreadable and left untouched: "
                  "per-client credentials and enrollment are off until it is fixed or removed")

    def _save_locked(self):
        """Atomic write. True when the file now holds the current state (or there is no
        file); False otherwise, with the state kept in memory and retried later."""
        if not self._path:
            self._dirty = False
            return True
        if self.broken:
            return False
        for cid in self._revoked:       # an in-memory revocation always wins over what was loaded
            if cid in self._clients:
                self._clients[cid]["state"] = "revoked"
        data = {"version": 1, "clients": sorted(self._clients.values(), key=lambda c: c["created"]),
                "legacy": self._legacy}
        tmp = f"{self._path}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
            dfd = os.open(os.path.dirname(os.path.abspath(self._path)), os.O_RDONLY)
            try:
                os.fsync(dfd)           # the rename itself must survive a power cut
            finally:
                os.close(dfd)
        except OSError as e:
            self._dirty = True
            self._retry_at = self.clock() + RETRY_S
            if not self._failing:       # one record per failure streak; the class only, never the text
                self._log("clients_file_write_failed", error_class=type(e).__name__,
                          warning="client changes are kept in memory only and retried")
            self._failing = True
            return False
        if self._failing:
            self._log("clients_file_recovered")
        self._failing = False
        self._dirty = False
        self._saved_at = self.clock()
        return True

    def flush(self):
        """Persist now when something is waiting (a failed write, or buffered statistics)."""
        with self._lock:
            if self._dirty:
                return self._save_locked()
            return True

    def unsaved(self):
        """True while a change (a revocation, say) is only in memory because the write failed."""
        with self._lock:
            return self._failing

    def _retry_locked(self):
        if self._failing and self.clock() >= self._retry_at:
            self._save_locked()

    # -- authentication ----------------------------------------------------
    @staticmethod
    def view(rec):
        return {"id": rec["id"], "name": rec["name"], "legacy": False}

    LEGACY_VIEW = {"id": LEGACY_ID, "name": LEGACY_NAME, "legacy": True}

    def authenticate(self, presented, legacy_key):
        """(client view or None, reason). reason: ok | bad_key | revoked | legacy_denied.
        Every stored hash and the legacy key are compared in constant time, with no early
        exit, so timing does not tell which (if any) matched."""
        presented = presented if isinstance(presented, str) else ""
        h = hash_secret(presented) if 0 < len(presented) <= 256 and presented.isascii() else None
        found = None
        with self._lock:
            for rec in self._clients.values():
                same = h is not None and hmac.compare_digest(rec["hash"], h)
                if same:
                    found = rec
            view = self.view(found) if found is not None else None
            revoked = found is not None and (found["state"] == "revoked" or found["id"] in self._revoked)
            unavailable = self.unreadable
        is_legacy = bool(legacy_key) and hmac.compare_digest(
            presented.encode("utf-8", "replace"), legacy_key.encode("utf-8", "replace"))
        if view is not None:
            return (None, "revoked") if revoked else (view, "ok")
        if is_legacy:
            if self.cfg["legacy"] == "deny":
                return None, "legacy_denied"
            return dict(self.LEGACY_VIEW), "ok"
        if unavailable:
            return None, "clients_unavailable"      # could be a per-client key we cannot check
        return None, "bad_key"

    def touch(self, view, source):
        """Count one authenticated request and remember where it came from. Buffered: written
        at most every STATS_FLUSH_S seconds."""
        now = self.clock()
        with self._lock:
            tgt = self._legacy if view["legacy"] else self._clients.get(view["id"])
            if tgt is None:
                return
            tgt["last_seen"], tgt["requests"] = now, tgt["requests"] + 1
            tgt["last_source"] = str(source)[:64]
            self._dirty = True
            self._retry_locked()
            if now - self._saved_at >= STATS_FLUSH_S:
                self._save_locked()

    def fail_should_log(self, source):
        """True for the first authentication failure from `source` in each FAIL_LOG_S window;
        the count of the ones skipped since is returned with it."""
        now = self.clock()
        with self._lock:
            st = self._fail_log.get(source)
            if st is not None and now - st["t"] < FAIL_LOG_S:
                st["n"] += 1
                return False, 0
            skipped = st["n"] if st else 0
            if st is None:
                _make_room(self._fail_log, now, FAIL_LOG_S)
            self._fail_log[source] = {"t": now, "n": 0}
            return True, skipped

    # -- reading -----------------------------------------------------------
    def get(self, cid):
        with self._lock:
            rec = self._clients.get(cid)
            return dict(rec) if rec else None

    def rows(self):
        """Enrolled clients, newest first (copies)."""
        with self._lock:
            return sorted((dict(c) for c in self._clients.values()), key=lambda c: -c["created"])

    def legacy_row(self):
        with self._lock:
            return dict(self._legacy)

    def is_active(self, cid):
        if cid == LEGACY_ID:
            return self.cfg["legacy"] == "allow"
        with self._lock:
            rec = self._clients.get(cid)
            return rec is not None and rec["state"] == "active" and cid not in self._revoked

    def names(self):
        """id -> name for every known client, for labels."""
        with self._lock:
            out = {c["id"]: c["name"] for c in self._clients.values()}
        out[LEGACY_ID] = LEGACY_NAME
        return out

    def active_choices(self):
        """[(id, name)] of clients a rule may be scoped to (the legacy client first)."""
        with self._lock:
            act = sorted(((c["id"], c["name"]) for c in self._clients.values() if c["state"] == "active"),
                         key=lambda x: x[1])
        return [(LEGACY_ID, LEGACY_NAME)] + act

    # -- limiting ----------------------------------------------------------
    def _hit(self, kind, key, window, limit, now):
        """Fixed-window counter: True while under `limit`. `key` None is the global bucket."""
        m = self._rates.setdefault((kind, window), {})
        st = m.get(key)
        if st is None or now - st["t"] >= window:
            if st is None:
                _make_room(m, now, window)
            st = m[key] = {"t": now, "n": 0}
        st["n"] += 1
        return st["n"] <= limit

    def rate_ok(self, kind, source, limits, window=60):
        """Charge one hit to the global and the per-source bucket. False when either is full."""
        now = self.clock()
        with self._lock:
            a = self._hit(kind + ":src", source, window, limits[0], now)
            b = self._hit(kind + ":all", None, window, limits[1], now)
        return a and b

    # -- enrollment --------------------------------------------------------
    def _expire_locked(self):
        now = self.clock()
        for e in self._pending.values():
            if e["status"] == "pending" and now >= e["expires"]:
                e["status"], e["decided_at"] = "expired", now
                self._cooldown[e["source"]] = now + COOLDOWN_S
                self._lapsed.append(dict(e))
        for eid in [k for k, e in self._pending.items()
                    if e["status"] != "pending" and now - e["decided_at"] > RESOLVED_KEEP_S]:
            del self._pending[eid]
        for src in [s for s, until in self._cooldown.items() if until <= now]:
            del self._cooldown[src]

    def expire(self):
        """Mark overdue enrollments expired; returns the ones not reported before (for auditing)."""
        with self._lock:
            self._expire_locked()
            out, self._lapsed = self._lapsed, []
            return out

    def submit(self, name, secret_hash, claim, source):
        """Validate and record an enrollment request. Returns (http status, body dict, event)
        where `event` is the enrollment (or None) for the caller to audit and notify. Every
        message is a fixed string; nothing says which names or hashes already exist except
        a name that is PENDING (an attacker can only learn what they could create)."""
        cfg = self.cfg["enrollment"]
        if self.broken:
            return 503, {"error": "enrollment is not available"}, None
        if not cfg["enabled"]:
            return 403, {"error": "enrollment is disabled"}, None
        if not valid_name(name):
            return 400, {"error": "name must be 1-32 lowercase letters, digits, - _ . "
                                  "and start with a letter or digit"}, None
        if not (isinstance(secret_hash, str) and HASH_RE.fullmatch(secret_hash)):
            return 400, {"error": "invalid enrollment request"}, None
        if clean_claim(claim) is None:
            return 400, {"error": "invalid enrollment request"}, None
        now = self.clock()
        with self._lock:
            self._expire_locked()
            if self._cooldown.get(source, 0) > now:
                return 429, {"error": "too many enrollment requests; try again later"}, None
            if not (self._hit("hour:src", source, 3600, SUBMIT_HOUR[0], now)
                    & self._hit("hour:all", None, 3600, SUBMIT_HOUR[1], now)):
                return 429, {"error": "too many enrollment requests; try again later"}, None
            same = next((e for e in self._pending.values()
                         if e["status"] == "pending" and hmac.compare_digest(e["hash"], secret_hash)), None)
            if same is not None:                    # the client retried after a lost reply
                return 202, self._accepted(same, now), None
            if any(hmac.compare_digest(c["hash"], secret_hash) for c in self._clients.values()):
                return 409, {"error": "this key is already enrolled"}, None
            pend = [e for e in self._pending.values() if e["status"] == "pending"]
            if len(pend) >= cfg["max_pending"]:
                return 429, {"error": "too many pending enrollments; try again later"}, None
            if sum(e["source"] == source for e in pend) >= SOURCE_PENDING:
                return 429, {"error": "too many pending enrollments from this address"}, None
            if any(e["name"] == name for e in pend):
                return 409, {"error": "an enrollment with that name is already waiting"}, None
            code = confirm_code(secret_hash)
            if any(e["code"] == code for e in pend):
                return 409, {"error": "confirmation code clash; generate a new key and retry"}, None
            if len(self._clients) >= MAX_CLIENTS:
                return 429, {"error": "enrollment is not available right now"}, None
            e = {"id": secrets.token_urlsafe(16), "name": name, "hash": secret_hash, "code": code,
                 "claim": claim, "source": source, "created": now, "expires": now + cfg["ttl_s"],
                 "status": "pending", "client_id": None, "decided_at": None, "decided_by": None}
            self._pending[e["id"]] = e
            return 202, self._accepted(e, now), dict(e)

    def _accepted(self, e, now):
        return {"id": e["id"], "code": e["code"], "expires_in": max(0, int(e["expires"] - now)),
                "interval": 2}

    def poll(self, eid):
        """The public status of one enrollment, or None. Reveals nothing but its own state."""
        if not isinstance(eid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,32}", eid):
            return None
        with self._lock:
            self._expire_locked()
            e = self._pending.get(eid)
            if e is None:
                return None
            out = {"status": e["status"]}
            if e["status"] == "approved":
                out.update(client_id=e["client_id"], name=e["name_final"])
            return out

    def pending(self):
        """Open enrollments, oldest first (copies)."""
        with self._lock:
            self._expire_locked()
            return sorted((dict(e) for e in self._pending.values() if e["status"] == "pending"),
                          key=lambda e: e["created"])

    def pending_one(self, eid):
        with self._lock:
            self._expire_locked()
            e = self._pending.get(eid)
            return dict(e) if e is not None and e["status"] == "pending" else None

    def name_in_use(self, name, except_id=None):
        with self._lock:
            return any(c["name"] == name and c["state"] == "active" and c["id"] != except_id
                       for c in self._clients.values())

    def decide(self, eid, approve, name, actor):
        """Settle one enrollment. Returns (status, enrollment copy, client record or None):
        status is approved | denied | gone | name_invalid | name_taken | full | not_saved.
        An approval is persisted before it is reported; if the file cannot be written the
        enrollment stays pending."""
        with self._lock:
            self._expire_locked()
            e = self._pending.get(eid)
            if e is None or e["status"] != "pending":
                return "gone", None, None
            now = self.clock()
            if not approve:
                e["status"], e["decided_at"], e["decided_by"] = "denied", now, actor
                self._cooldown[e["source"]] = now + COOLDOWN_S
                return "denied", dict(e), None
            final = name if name else e["name"]
            if not valid_name(final):
                return "name_invalid", dict(e), None
            if self.name_in_use(final):
                return "name_taken", dict(e), None
            if len(self._clients) >= MAX_CLIENTS or self.broken:
                return "full", dict(e), None
            cid = "c-" + secrets.token_hex(4)
            while cid in self._clients:
                cid = "c-" + secrets.token_hex(4)
            rec = {"id": cid, "name": final, "hash": e["hash"], "state": "active", "created": now,
                   "last_seen": None, "requests": 0, "last_source": "", "approved_by": actor[:120],
                   "claim": e["claim"], "enrolled_from": e["source"], "revoked_at": None,
                   "revoked_by": ""}
            self._clients[cid] = rec
            if not self._save_locked():
                del self._clients[cid]
                return "not_saved", dict(e), None
            e.update(status="approved", decided_at=now, decided_by=actor, client_id=cid, name_final=final)
            return "approved", dict(e), dict(rec)

    # -- administration ----------------------------------------------------
    def rename(self, cid, new):
        """'renamed' | 'missing' | 'name_invalid' | 'name_taken' | 'not_saved' (old name kept)."""
        with self._lock:
            rec = self._clients.get(cid)
            if rec is None:
                return "missing", None
            if not valid_name(new):
                return "name_invalid", None
            if rec["name"] == new:
                return "renamed", rec["name"]
            if self.name_in_use(new, except_id=cid):
                return "name_taken", None
            old, rec["name"] = rec["name"], new
            if not self._save_locked():
                rec["name"] = old
                return "not_saved", None
            return "renamed", old

    def revoke(self, cid, by):
        """Revoke at once in memory (the next request fails), then persist. Returns
        (status, record copy): revoked | already | missing | memory_only (revoked but not yet
        saved; the write is retried)."""
        with self._lock:
            rec = self._clients.get(cid)
            if rec is None:
                return "missing", None
            if rec["state"] == "revoked":
                return "already", dict(rec)
            self._revoked.add(cid)      # in memory first, under the lock: effective before anything else
            rec.update(state="revoked", revoked_at=self.clock(), revoked_by=by[:120])
            saved = self._save_locked()
            return ("revoked" if saved else "memory_only"), dict(rec)

    def remove(self, cid):
        """Forget a REVOKED client's row. 'removed' | 'missing' | 'active' | 'not_saved'."""
        with self._lock:
            rec = self._clients.get(cid)
            if rec is None:
                return "missing"
            if rec["state"] != "revoked":
                return "active"
            del self._clients[cid]
            if not self._save_locked():
                self._clients[cid] = rec
                return "not_saved"
            return "removed"


def _make_room(m, now, window):
    """Make room for one NEW key in a limiter map without refusing it (the map is bounded)."""
    if len(m) >= RATE_MAP_CAP:
        for k in [k for k, v in m.items() if now - v["t"] >= window]:
            del m[k]
        while len(m) >= RATE_MAP_CAP:
            del m[min(m, key=lambda k: m[k]["t"])]


# ---------------------------------------------------------------- Broker mixin
class ClientsMixin:
    """Methods mixed into Broker. Needs: cfg, log, audit, _lock, _by_id, _finish, _cfg_lock,
    grants, backend, notifier, _notify_submit, _persist_standing, _persist_ssh_rules, _auto_max,
    _default_auto_modes."""

    def _init_clients(self, config):
        self.clients_cfg = parse_config(config)
        apath = self._audit._path
        cpath = os.path.join(os.path.dirname(os.path.abspath(apath)), "clients.json") if apath else None
        self.clients = ClientStore(cpath, self.log, self.clients_cfg)
        threading.Thread(target=self._clients_sweeper, daemon=True).start()

    def _clients_sweeper(self):
        while True:
            time.sleep(10)
            try:
                self.sweep_enrollments()
                self.clients.flush()
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    # -- per-client ceilings -------------------------------------------------
    def client_override(self, cid):
        return self.clients_cfg["overrides"].get(cid) or {}

    def auto_max_for(self, cid):
        """risk.auto_approve_max for this client: its own override, else the global value."""
        return self.client_override(cid).get("auto_approve_max", self._auto_max)

    def client_never_auto(self, cid):
        """A client whose override is auto_approve_max none always prompts: no policy
        allow, Always, timed grant or SSH rule applies to it."""
        return self.client_override(cid).get("auto_approve_max") == "none"

    def auto_modes_default_for(self, cid):
        """risk.auto_modes for this client: its own override, else the global default."""
        return list(self.client_override(cid).get("auto_modes", self._default_auto_modes))

    def client_ceiling_text(self, cid):
        ov = self.client_override(cid)
        mx = self.auto_max_for(cid)
        modes = ", ".join(self.auto_modes_default_for(cid)) or "none"
        src = "its own setting" if ov else "the global default"
        if self.client_never_auto(cid):
            return f"never auto-approves (every request asks) - {src}"
        return f"up to {mx} risk; modes {modes} - {src}"

    # -- authentication ------------------------------------------------------
    def client_auth(self, presented, legacy_key, peer, method, path):
        """(client view or None, reason). Failures are audited at most once per source per
        window (client_auth_failed), never with key material."""
        view, why = self.clients.authenticate(presented, legacy_key)
        if view is None:
            ok, skipped = self.clients.fail_should_log(peer)
            if ok:
                fields = {"peer": peer, "method": method, "path": path[:60], "reason": why}
                if skipped:
                    fields["suppressed"] = skipped
                self.log("client_auth_failed", **fields)
            return None, why
        self.clients.touch(view, peer)
        return view, why

    # -- enrollment ------------------------------------------------------------
    def enroll_submit(self, body, source):
        """POST /v1/enroll after the size and rate gates. Returns (status, body dict)."""
        if not isinstance(body, dict) or set(body) - {"name", "hash", "claim"}:
            return 400, {"error": "invalid enrollment request"}
        code, out, e = self.clients.submit(body.get("name"), body.get("hash"), body.get("claim"), source)
        if e is not None:
            self.log("enroll_requested", enroll_id=e["id"][:8], name=e["name"], claim=e["claim"],
                     peer=source, code=e["code"], expires_in=int(e["expires"] - e["created"]))
            self._enroll_notify(e)
        elif code in (409, 429, 503):
            self.log("enroll_refused", peer=source, status=code)
        return code, out

    def enroll_poll(self, eid, source):
        st = self.clients.poll(eid)
        if st is None:
            return 404, {"error": "unknown enrollment"}
        return 200, st

    def _enroll_notify(self, e):
        """Names-only notification, no buttons, no token, no link to a decision channel."""
        from . import notify as notify_mod
        import dataclasses
        base = self.cfg.get("approve_base_url", "").rstrip("/")
        n = notify_mod.Notification(
            rid="enroll-" + e["id"][:8], tag="enroll-" + e["id"][:8], title="Client enrollment requested",
            text=f"A new client asked to enroll as '{e['name']}'. Open the approval page to compare "
                 "the confirmation code and approve or deny. Refuse any you did not start.",
            names=[e["name"]], risk=None, url=base + "/", source="enrollment", summary=None,
            expires_at=e["expires"], actions=[], action_token=None,
            transport_actions={id(leaf): [] for leaf in notify_mod.leaves(self.notifier)})
        self._notify_submit(lambda: self._enroll_send(n))

    def _enroll_send(self, n):
        try:
            self.notifier.send(n)
        except Exception:  # noqa: BLE001 -- the card is on the page whatever the transport does
            self.log("enroll_notify_failed", warning="the enrollment notification could not be sent")

    def sweep_enrollments(self):
        for e in self.clients.expire():
            self.log("enroll_decided", enroll_id=e["id"][:8], name=e["name"], decision="expired",
                     peer=e["source"], code=e["code"])

    def decide_enrollment(self, eid, decision, name, actor, peer=None, client_ip=None):
        """The approval-page decision. Returns (status, enrollment): see ClientStore.decide;
        'bad' for an unknown decision. Audited as enroll_decided."""
        if decision not in ("approve", "deny"):
            return "bad", None
        self.sweep_enrollments()
        status, e, rec = self.clients.decide(eid, decision == "approve", (name or "").strip(), actor)
        who = dict(approver=actor, approver_peer=peer, approver_ip=client_ip, channel="dashboard")
        if status in ("approved", "denied"):
            self.log("enroll_decided", enroll_id=e["id"][:8], name=e["name"], decision=status,
                     source=e["source"], code=e["code"], **who,
                     **({"client_id": rec["id"], "client_name": rec["name"]} if rec else {}))
        elif status in ("name_taken", "name_invalid", "full", "not_saved"):
            self.log("enroll_refused", enroll_id=e["id"][:8] if e else None, reason=status, **who)
        return status, e

    # -- administration ----------------------------------------------------------
    def rename_client(self, cid, new, actor, peer=None, client_ip=None):
        status, old = self.clients.rename(cid, (new or "").strip())
        if status == "renamed" and old != (new or "").strip():
            self.log("client_renamed", client_id=cid, old_name=old, new_name=(new or "").strip(),
                     user=actor, peer=peer, client_ip=client_ip)
        elif status in ("name_taken", "name_invalid", "not_saved"):
            self.log("client_rename_refused", client_id=cid, reason=status, user=actor, peer=peer,
                     client_ip=client_ip)
        return status

    def revoke_client(self, cid, actor, peer=None, client_ip=None):
        """Revoke a client: its next request fails, its pending requests are denied and its
        client-scoped rules are removed. Returns the ClientStore status."""
        status, rec = self.clients.revoke(cid, actor)
        if status not in ("revoked", "memory_only"):
            return status
        denied = self._deny_client_pending(cid)
        gone = self._purge_client_rules(cid)
        plans_gone = self._revoke_client_plans(cid, actor, peer, client_ip)
        ended = self.revoke_client_sessions(cid, actor)
        self.log("client_revoked", client_id=cid, client_name=rec["name"], revoked_by=actor, user=actor,
                 peer=peer, client_ip=client_ip, denied_pending=denied, sessions_ended=ended, rules_removed=gone["removed"],
                 rules_failed=gone["failed"], plans_revoked=plans_gone, saved=status == "revoked")
        return status

    def remove_client(self, cid, actor, peer=None, client_ip=None):
        rec = self.clients.get(cid)
        status = self.clients.remove(cid)
        if status == "removed":
            self.log("client_removed", client_id=cid, client_name=rec["name"] if rec else None,
                     user=actor, peer=peer, client_ip=client_ip)
        return status

    def _deny_client_pending(self, cid):
        """Deny every open request of this client (not counting against the deny cooldown)."""
        mine = []
        with self._lock:
            for r in self._by_id.values():
                if r.status == "pending" and r.client["id"] == cid:
                    r.status = "deciding"
                    mine.append(r)
        for r in mine:
            self._finish(r, "denied", error="this client was revoked", via="client_revoked")
        return len(mine)

    def _purge_client_rules(self, cid):
        """Remove every rule scoped to this client: timed grants, Always approvals and SSH
        rules. Returns {"removed": {...}, "failed": n}. A vault write that fails leaves the
        rule in place but harmless (client ids are never reused) and is reported."""
        removed, failed = {"timed": 0, "always": 0, "ssh": 0}, 0
        removed["timed"] = len(self.grants.revoke_client(cid))
        with self._cfg_lock:
            for name, sc in list(self.cfg["secrets"].items()):
                entries = sc.get("standing") or []
                keep = [e for e in entries if e.get("client", ANY) != cid]
                if len(keep) != len(entries):
                    try:
                        self._persist_standing(name, keep, "system:client-revoked")
                        removed["always"] += len(entries) - len(keep)
                    except Exception:  # noqa: BLE001
                        failed += len(entries) - len(keep)
                rules = sc.get("ssh_rules") or []
                keep = [r for r in rules if r.get("client", ANY) != cid]
                if len(keep) != len(rules):
                    try:
                        self._persist_ssh_rules(name, keep, "system:client-revoked")
                        removed["ssh"] += len(rules) - len(keep)
                    except Exception:  # noqa: BLE001
                        failed += len(rules) - len(keep)
        return {"removed": removed, "failed": failed}

    def client_rule_rows(self, cid):
        """The rules scoped to one client, for its Clients row: [(kind, secret(s), covers)]."""
        rows = []
        for r in self.standing_rows():
            if r.get("client") == cid:
                rows.append((r["kind"], ", ".join(r["secrets"]), r["covers"]))
        for name, sc in sorted(self.cfg["secrets"].items()):
            for r in sc.get("ssh_rules") or []:
                if r.get("client", ANY) == cid:
                    rows.append(("ssh host rule", name, f"{r['user']} on {r['host'] or r['fp'][:19]}"))
        for v in self.active_plans():
            if v["client_id"] == cid:
                rows.append(("plan", ", ".join(v["names"]),
                             f"{v['uses']}/{v['uses_max']} calls used, {max(0, v['left_s']) // 60} min left"))
        return rows


# ---------------------------------------------------------------- page fragments
CSS = """
.enr .code{font:700 1.5rem ui-monospace,monospace;letter-spacing:.12em;background:var(--bg);border:1px solid var(--line);
border-radius:.5rem;padding:.3rem .8rem;display:inline-block;margin:.2rem 0}
.enr .warnline{color:var(--wfg);font-size:.85rem}
.enr label{display:block;font-weight:600;font-size:.85rem;margin:.6rem 0 .2rem}
.enr input[type=text],.cl input[type=text]{font:inherit;min-height:2.5rem;padding:.3rem .6rem;border-radius:.5rem;
border:1px solid var(--line);background:var(--card);color:var(--fg);width:100%;max-width:18rem}
.cl .st-active{color:var(--ok)}.cl .st-revoked{color:var(--bad)}
.cl form.inline{display:inline-block;margin:.15rem .3rem .15rem 0}
.cl details.rv>summary{cursor:pointer;display:inline-block;padding:.35rem .7rem;border:1px solid var(--line);border-radius:.5rem}
.cl .rules{margin:.3rem 0 0 1rem;padding:0;font-size:.82rem}
.rscope{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;margin:.2rem 0 .5rem;font-size:.85rem;font-weight:600}
.rscope select{font:inherit;min-height:2.25rem;border-radius:.5rem;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.cl .idn{font-family:ui-monospace,monospace;font-size:.78rem;color:var(--muted)}
"""


def enroll_card_html(e, csrf, now, clash):
    """The dashboard card for one pending enrollment. `clash` says the proposed name is
    already used by an active client (the approver edits it). Everything shown is either
    ASCII-restricted by validation or escaped."""
    esc = html.escape
    left = max(0, int(e["expires"] - now))
    warn = (f"<p class=warnline>The name <b>{esc(e['name'])}</b> is already used by another client; "
            "pick a different one before approving.</p>") if clash else ""
    return (
        f"<article class='req enr' data-id='{esc(e['id'][:8])}' data-names='New machine {esc(e['name'])}'>"
        "<div class=glance><span class='rbadge hi'><i aria-hidden=true>&#9650;</i>HIGH</span>"
        "<span class=gwho>New machine</span>"
        f"<span class=left><time data-exp='{int(e['expires'])}'>{left // 60}:{left % 60:02d} left</time></span></div>"
        f"<h2 class=sent>Client enrollment: &ldquo;{esc(e['name'])}&rdquo; wants its own broker credential.</h2>"
        "<div class=rqmeta>Confirmation code: <span class=code>" + esc(e["code"]) + "</span> "
        "Match it with the code printed in your terminal. If it differs, press Deny.</div>"
        f"{warn}"
        "<form method=post action='/enroll/decide' class=decide>"
        f"<input type=hidden name=id value='{esc(e['id'])}'>"
        f"<input type=hidden name=csrf value='{esc(csrf)}'>"
        f"<div class=dxrow><details class=dx{' open' if clash else ''}><summary>Rename</summary><div class=dxbody>"
        "<label for=ename>Name (you may change it)</label>"
        f"<input id=ename type=text name=name value='{esc(e['name'])}' maxlength=32 required "
        "spellcheck=false autocapitalize=off autocomplete=off></div></details></div>"
        "<div class=decide-row><button class='btn deny' name=decision value=deny>Deny</button>"
        "<button class='btn approve' name=decision value=approve>Approve</button></div></form>"
        "<div class=dxrow><details class=dx><summary>Details</summary><div class=dxbody>"
        f"<dl class=facts><dt>Source</dt><dd>{esc(e['source'])}</dd>"
        f"<dt>Claims to be</dt><dd>{esc(e['claim'])} <small class=muted>(unverified, typed by the client)</small></dd></dl>"
        "<p class=scope><small class=muted>An approved client starts with no rules of its own: it gets "
        "only the rules set for any client, and every other request asks you. Never auto-approved; "
        "no notification button can decide this.</small></p></div></details></div></article>")


def from_html(req):
    """'From:' lines of a request card: the authenticated client (verified, by name and id) and
    the user@host the client claimed (unverified). Both are escaped."""
    esc = html.escape
    c = getattr(req, "client", None) or ClientStore.LEGACY_VIEW
    return (f"Client: <b>{esc(c['name'])}</b> <span class=muted>({esc(c['id'])})</span><br>"
            f"Claimed source (unverified): {esc(req.source)}")


def _ago(t, now):
    if not t:
        return "never"
    s = max(0, int(now - t))
    for lim, div, unit in ((90, 1, "s"), (5400, 60, "m"), (172800, 3600, "h")):
        if s < lim:
            return f"{s // div}{unit} ago"
    return f"{s // 86400}d ago"


def clients_section(broker, csrf, now=None, flash=""):
    """The Machines page body (reached from Settings)."""
    esc = html.escape
    now = time.time() if now is None else now
    legacy_on = broker.clients.cfg["legacy"] == "allow"

    def rules_cell(cid):
        rr = broker.client_rule_rows(cid)
        if not rr:
            return "no rules of its own"
        return (f"<details><summary>{len(rr)} rule{'' if len(rr) == 1 else 's'}</summary><ul class=rules>"
                + "".join(f"<li>{esc(k)}: {esc(s)} - {esc(c)}</li>" for k, s, c in rr) + "</ul></details>")

    rows = []
    leg = broker.clients.legacy_row()
    rows.append(
        f"<tr><td data-label=Name><b>{esc(LEGACY_NAME)}</b><br><span class=idn>id legacy</span></td>"
        "<td data-label=Host>every machine using the shared key</td>"
        "<td data-label=Enrolled>-</td>"
        f"<td data-label='Last seen'>{esc(_ago(leg['last_seen'], now))}"
        f"{'<br><small class=muted>' + esc(leg['last_source']) + '</small>' if leg['last_source'] else ''}</td>"
        f"<td data-label=Requests>{leg['requests']}</td>"
        f"<td data-label=State><span class='{'st-active' if legacy_on else 'st-revoked'}'>"
        f"{'allowed' if legacy_on else 'denied'}</span></td>"
        f"<td data-label=Ceiling>{esc(broker.client_ceiling_text(LEGACY_ID))}</td>"
        f"<td data-label=Rules>{rules_cell(LEGACY_ID)}</td>"
        "<td data-label=Actions><small class=muted>Set <code>legacy_client_key</code> to "
        "<code>deny</code> in the broker config once every machine is enrolled.</small></td></tr>")
    for c in broker.clients.rows():
        active = c["state"] == "active"
        if active:
            acts = (
                "<form method=post action='/clients/rename' class=inline>"
                f"<input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=id value='{esc(c['id'])}'>"
                f"<input type=text name=name value='{esc(c['name'])}' maxlength=32 required "
                f"aria-label='New name for {esc(c['name'], quote=True)}' spellcheck=false autocomplete=off>"
                "<button>Rename</button></form>"
                "<details class=rv><summary>Revoke...</summary><form method=post action='/clients/revoke' "
                f"class=inline><input type=hidden name=csrf value='{esc(csrf)}'>"
                f"<input type=hidden name=id value='{esc(c['id'])}'>"
                "<p><small>This client stops working on its next request, its waiting requests are denied "
                "and its own rules are removed. It can enroll again as a new client.</small></p>"
                f"<button class='btn deny'>Confirm revoke</button></form></details>")
        else:
            acts = (f"<small class=muted>revoked {ui_theme.time_tag(c['revoked_at'], 'when', fallback=iso(c['revoked_at'])) if c['revoked_at'] else ''}"
                    f" by {esc(c['revoked_by'] or 'unknown')}</small>"
                    "<form method=post action='/clients/remove' class=inline>"
                    f"<input type=hidden name=csrf value='{esc(csrf)}'><input type=hidden name=id value='{esc(c['id'])}'>"
                    "<button>Remove from list</button></form>")
        rows.append(
            f"<tr><td data-label=Name><b>{esc(c['name'])}</b><br><span class=idn>id {esc(c['id'])}</span></td>"
            f"<td data-label=Host>{esc(c['claim'] or '-')}<br><small class=muted>unverified; enrolled from "
            f"{esc(c['enrolled_from'] or '?')}</small></td>"
            f"<td data-label=Enrolled>{ui_theme.time_tag(c['created'], 'when', fallback=iso(c['created']))}<br><small class=muted>approved by "
            f"{esc(c['approved_by'] or '?')}</small></td>"
            f"<td data-label='Last seen'>{esc(_ago(c['last_seen'], now))}"
            f"{'<br><small class=muted>' + esc(c['last_source']) + '</small>' if c['last_source'] else ''}</td>"
            f"<td data-label=Requests>{c['requests']}</td>"
            f"<td data-label=State><span class='st-{c['state']}'>{esc(c['state'])}</span></td>"
            f"<td data-label=Ceiling>{esc(broker.client_ceiling_text(c['id']))}</td>"
            f"<td data-label=Rules>{rules_cell(c['id'])}</td>"
            f"<td data-label=Actions>{acts}</td></tr>")
    table = ("<table class=tbl><thead><tr><th>Name</th><th>Host</th><th>Enrolled</th><th>Last seen</th>"
             "<th>Requests</th><th>State</th><th>Effective ceiling</th><th>Own rules</th><th></th></tr></thead>"
             "<tbody>" + "".join(rows) + "</tbody></table>")
    cfg = broker.clients.cfg["enrollment"]
    hint = ("<p><small class=muted>Add a machine by running <code>asb enroll --name NAME</code> on it; "
            "a card appears on the Requests tab and you approve exactly that card after matching its "
            "confirmation code. Refuse any enrollment you did not start. "
            + ("Enrollment is turned off in the broker config." if not cfg["enabled"] else "")
            + "</small></p>")
    note = f"<div class=flash>{esc(flash)}</div>" if flash else ""
    if broker.clients.unreadable:
        note += ("<div class=crerr role=alert><b>The client list could not be read.</b> Every per-client "
                 "credential is being refused (fail closed) until the file is fixed or removed.</div>")
    elif broker.clients.unsaved():
        note += ("<div class=crerr role=alert><b>The client list could not be saved.</b> A revoke, rename or "
                 "enrollment is in effect now but is only in memory; if the broker restarts before the "
                 "write succeeds, a revoked client would work again. The write is retried every few "
                 "seconds. Check the disk.</div>")
    return (f"<p><a href='/settings'>&lsaquo; Settings</a></p><h1>Machines</h1>{note}{hint}<div class=cl>{table}</div>"
            "<p><small class=muted>A rule made for one client never applies to another; rules for "
            "<i>any client</i> apply to all. Rules are listed per client above and in full on the Policies "
            "tab.</small></p>")
