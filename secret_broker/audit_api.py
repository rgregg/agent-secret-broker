"""Read-only, REDACTED view of the audit log for the agent (client) API.

GET /v1/audit and GET /v1/audit/verify. The full log stays in the SSO history
page; this view exists so an agent can debug its own requests ("why did my
call fail?") without learning anything about approval context. Standing rule:
what the agent can see must not reveal which secrets auto-approve, risk
verdicts or reasons, or policy, so the agent cannot favor credentials that
skip the prompt.

Redaction is a WHITELIST: for each event type, the exact fields that may be
returned. Deny by default: an event type that is not listed is not returned at all
(a test forces every event the broker emits into WHITELIST or HIDDEN, so a new event
needs a conscious decision). Fields that are not listed are dropped. HIDDEN names the
event types that were considered and refused: they reveal policy or approver presence
by their mere existence.
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

DEFAULT_LIMIT, MAX_LIMIT = 100, 500
MAX_SCAN_LINES = 50_000          # lines examined per query before giving up (truncated=true)
MAX_BODY_BYTES = 256 * 1024      # response cap
INDEX_WINDOW_BYTES = 64 * 1024 * 1024    # the index covers at most the last 64 MB of the log
STRIDE = 64                      # one byte offset kept per STRIDE lines
MAX_REQUEST_IDS = 5000           # requests whose event seqs are indexed (newest kept)
RATE_PER_MIN = 60                # per client key; `asb audit --tail` polls at 30/min
VERIFY_BUDGET_S = 20.0
CHANNELS = ("dashboard", "push", "ha", "link")

# -- the whitelist ---------------------------------------------------------
# kind -> sanitizer. Anything that fails its check is dropped, not coerced.
_S = "str"          # string, capped at 200 chars
_I = "int"
_B = "bool"
_L = "strlist"      # list of strings, 50 items max
_CH = "channel"     # one of CHANNELS
_IL = "intlist"     # list of ints, 50 items max
_ERR = "errclass"   # free text reduced to a coarse class

# event -> {output field: (source field, kind)}
# `request` (from id / request_id), `seq`, `ts` and `event` are always added.
WHITELIST = {
    "requested": {"names": ("names", _L), "mode": ("mode", _S), "source": ("source", _S),
                  "peer": ("peer", _S), "method": ("method", _S), "url": ("url", _S),
                  "argv": ("argv", _L), "op": ("op", _S), "field": ("field", _S),
                  "ssh_kind": ("ssh_kind", _S), "fingerprint": ("ssh_fingerprint", _S),
                  # env mode scripts the client reported: paths, hashes, sizes and marker
                  # classes describe the agent's own request; script text is never logged
                  "script_paths": ("script_paths", _L), "script_sha256": ("script_sha256", _L),
                  "script_sizes": ("script_sizes", _IL), "script_markers": ("script_markers", _L),
                  "host_fp": ("host_fp", _S), "host_name": ("host_name", _S),
                  "claimed_dest": ("claimed_dest", _S)},
    "rejected": {"names": ("names", _L), "mode": ("mode", _S), "source": ("source", _S),
                 "peer": ("peer", _S), "url": ("url", _S), "reason": ("reason", _S)},
    # Decision outcomes. channel/approver are ALWAYS present (null when there was
    # no human decision), so an auto-approved request has the same shape.
    "approved": {"channel": ("channel", _CH), "approver": ("approver", _S)},
    "denied": {"channel": ("channel", _CH), "approver": ("approver", _S)},
    "expired": {"channel": ("channel", _CH), "approver": ("approver", _S)},
    "failed": {"error_class": ("error", _ERR), "channel": ("channel", _CH),
               "approver": ("approver", _S)},
    "secret_read": {"secret": ("secret", _S), "vars": ("vars", _L)},
    "delivered": {"kind": ("kind", _S)},
    "http_executed": {"upstream_status": ("upstream_status", _I),
                      "response_bytes": ("response_bytes", _I), "duration_ms": ("duration_ms", _I)},
    "http_failed": {"error_class": ("error", _ERR)},
    "stored": {"names": ("names", _L), "op": ("op", _S), "field": ("field", _S),
               "duration_ms": ("duration_ms", _I)},
    "ssh_signed": {"fingerprint": ("ssh_fingerprint", _S), "host_fp": ("host_fp", _S),
                   "host_name": ("host_name", _S), "claimed_dest": ("claimed_dest", _S)},
    "auth_failed": {"peer": ("peer", _S), "method": ("method", _S)},
    "bad_request": {"peer": ("peer", _S), "error": ("error", _S)},
    "discovery": {"peer": ("peer", _S), "host": ("host", _S), "found": ("found", _L)},
    "catalog_loaded": {"count": ("count", _I), "invalid_count": ("invalid", "count")},
    "catalog_error": {}, "backend_error": {},
    "backend_ready": {"duration_ms": ("duration_ms", _I)},
}

# Not returned at all. Several of these carry policy or risk outright; `notified`
# and `decided` exist only for requests a human was asked about, so their absence
# on an auto-approved request would give the policy away; `decided` is also
# redundant with approved/denied.
HIDDEN = frozenset({
    "startup", "assessed", "escalated", "notified", "decided",
    "policy_changed", "policy_change_refused", "policy_change_failed", "policies_viewed",
    "guidance_changed", "guidance_change_refused", "guidance_change_failed",
    "ssh_hosts_changed", "ssh_hosts_change_refused", "ssh_hosts_change_failed",
    "ha_hook_any_device", "config_warning",
    # time-boxed grants are approval policy context: a grant-approved request shows as plain "approved"
    "grant_created", "grant_refused", "grant_used", "grant_skipped", "grant_revoked", "grant_expired",
    "grant_dropped", "grants_file_corrupt", "grants_file_write_failed", "client_event",
    "request_details_store_error",
    # exist only when a human was asked to decide (policy / presence by absence)
    "decision_refused", "dashboard_decide_refused", "push_decide_refused", "ha_decide_refused",
    "link_decide_refused",
    # approver presence / activity: which pages are open, when, from which device
    "approval_viewed", "approval_stale", "approval_forbidden", "csrf_refused", "dashboard_viewed",
    "history_viewed", "request_detail_viewed", "client_event_dropped", "push_subscribed",
    "push_revoked", "push_refused",
    "push_test", "ha_decide_dropped",
    # server-identity policy (a key's allowed_hosts) is approval context
    "ssh_sign_refused",
    # standing per-host SSH rules are approval policy: a rule-approved request shows as plain "approved",
    # and the agent must never learn which servers have rules
    "ssh_rule_created", "ssh_rule_used", "ssh_rule_revoked", "ssh_rule_expired", "ssh_rule_refused",
    "ssh_rule_change_failed", "ssh_rules_state_corrupt", "ssh_rules_state_write_failed",
})

def error_class(text):
    """Reduce an error string to a coarse class; vault, host and path details stay out."""
    t = str(text or "").lower()
    if not t:
        return None
    if "could not notify" in t:
        return "other"      # a notification is only sent when a human is asked: not a class
    for needle, cls in (("timed out", "timeout"), ("timeout", "timeout"),
                        ("certificate", "tls"), ("ssl", "tls"), ("tls", "tls"),
                        ("name or service", "dns"), ("resolution", "dns"), ("getaddrinfo", "dns"),
                        ("refused", "connection"), ("reset", "connection"),
                        ("unreachable", "connection"), ("release failed", "release_failed"),
                        ("vault", "vault"), ("catalog", "vault")):
        if needle in t:
            return cls
    return "other"


def _clean(val, kind, rec, event):
    if kind == _S:
        return val[:200] if isinstance(val, str) else None
    if kind == _I:
        return val if isinstance(val, int) and not isinstance(val, bool) else None
    if kind == _B:
        return val if isinstance(val, bool) else None
    if kind == _L:
        if not isinstance(val, list):
            return None
        return [x[:200] for x in val[:50] if isinstance(x, str)]
    if kind == _IL:
        if not isinstance(val, list):
            return None
        return [x for x in val[:50] if isinstance(x, int) and not isinstance(x, bool)]
    if kind == _CH:
        return val if val in CHANNELS else None
    if kind == _ERR:
        if event == "client_event":
            return client_error_class(val) if isinstance(val, str) else None
        return error_class(val) if isinstance(val, str) else None
    if kind == "count":
        return len(val) if isinstance(val, list) else None
    return None


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")


def redact(rec):
    """The agent-visible form of one audit record, or None when it must not be shown."""
    if not isinstance(rec, dict):
        return None
    event, seq, ts = rec.get("event"), rec.get("seq"), rec.get("ts")
    if (not isinstance(event, str) or event in HIDDEN or isinstance(seq, bool)
            or not isinstance(seq, int) or isinstance(ts, bool) or not isinstance(ts, (int, float))):
        return None
    rid = rec.get("id") or rec.get("request_id")
    out = {"seq": seq, "ts": iso(ts), "event": event[:60],
           "request": rid if isinstance(rid, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rid)
           else None}
    spec = WHITELIST.get(event)
    if spec is None:
        return None                     # deny by default: unlisted event types are not shown at all
    for name, (src, kind) in spec.items():
        val = _clean(rec.get(src), kind, rec, event)
        if name == "approver" and isinstance(val, str) and val.startswith("policy"):
            val = None
        if val is not None or event in ("approved", "denied", "expired", "failed") and name in (
                "channel", "approver"):
            out[name] = val
    # A decision made by policy has no channel and no approver, whatever else was logged.
    if event in ("approved", "denied", "expired", "failed") and rec.get("via") == "policy":
        out["channel"], out["approver"] = None, None
    return out


# -- parameter validation ----------------------------------------------------
_KNOWN = {"request", "event", "secret", "since", "until", "source", "limit", "before", "after",
          "order"}
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_EVT_RE = re.compile(r"[a-z][a-z0-9_]{0,59}")
_SECRET_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_REL_RE = re.compile(r"(\d{1,6})([smhd])")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class BadParam(ValueError):
    pass


def parse_time(text, now):
    if not isinstance(text, str) or not 1 <= len(text) <= 40 or not text.isascii():
        raise BadParam("bad time: use ISO-8601 (2026-10-18T01:02:03Z) or 90s/15m/2h/3d")
    m = _REL_RE.fullmatch(text)
    if m:
        return now - int(m.group(1)) * _UNIT[m.group(2)]
    try:
        dt = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    except ValueError:
        raise BadParam("bad time: use ISO-8601 (2026-10-18T01:02:03Z) or 90s/15m/2h/3d") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.timestamp()
    except (OverflowError, OSError, ValueError):
        raise BadParam("time out of range") from None


def parse_params(query, now=None):
    now = time.time() if now is None else now
    q = urllib.parse.parse_qs(query, keep_blank_values=True, max_num_fields=20)
    for k, v in q.items():
        if k not in _KNOWN:
            raise BadParam(f"unknown parameter {k[:40]!r}")
        if len(v) != 1:
            raise BadParam(f"{k} given more than once")
        if not v[0].isascii() or not v[0].isprintable() or len(v[0]) > 400:
            raise BadParam(f"bad {k}")
    one = lambda k: q[k][0] if k in q else None  # noqa: E731
    p = {"request": None, "events": None, "secret": None, "since": None, "until": None,
         "source": None, "before": None, "after": None}
    if one("request") is not None:
        if not _ID_RE.fullmatch(one("request")):
            raise BadParam("bad request id")
        p["request"] = one("request")
    if one("event") is not None:
        evs = one("event").split(",")
        if not 1 <= len(evs) <= 20 or not all(_EVT_RE.fullmatch(e) for e in evs):
            raise BadParam("bad event: 1-20 comma-separated names like http_executed")
        p["events"] = frozenset(evs)
    if one("secret") is not None:
        if not _SECRET_RE.fullmatch(one("secret")):
            raise BadParam("bad secret name")
        p["secret"] = one("secret")
    if one("source") is not None:
        if not 1 <= len(one("source")) <= 80:
            raise BadParam("bad source")
        p["source"] = one("source")
    for k in ("since", "until"):
        if one(k) is not None:
            p[k] = parse_time(one(k), now)
    if p["since"] is not None and p["until"] is not None and p["since"] > p["until"]:
        raise BadParam("since is after until")
    limit = DEFAULT_LIMIT
    if one("limit") is not None:
        if not re.fullmatch(r"\d{1,6}", one("limit")) or not 1 <= int(one("limit")) <= MAX_LIMIT:
            raise BadParam(f"limit must be 1-{MAX_LIMIT}")
        limit = int(one("limit"))
    p["limit"] = limit
    for k in ("before", "after"):
        if one(k) is not None:
            if not re.fullmatch(r"\d{1,15}", one(k)):
                raise BadParam(f"{k} must be a seq number from a previous response")
            p[k] = int(one(k))
    if p["before"] is not None and p["after"] is not None:
        raise BadParam("use before or after, not both")
    order = one("order")
    if order is not None and order not in ("asc", "desc"):
        raise BadParam("order must be asc or desc")
    p["order"] = order or ("asc" if p["request"] or p["after"] is not None else "desc")
    return p


# -- the reader --------------------------------------------------------------
class AuditView:
    """Indexed, incremental reader over the audit file. The index holds a byte
    offset every STRIDE lines (so a query can seek instead of scanning from the
    start) and, for the newest requests, the seqs of their events. It covers at
    most the last INDEX_WINDOW_BYTES of the file."""

    def __init__(self, path, window=INDEX_WINDOW_BYTES, stride=STRIDE):
        self._path, self._window, self._stride = path, window, stride
        self._lock = threading.Lock()
        self._reset()
        self._ino = None

    def _reset(self):
        self._pos = 0               # next unread byte
        self._base = None           # seq of the first indexed line
        self._offsets = []          # byte offset of line seq = base + i*stride
        self._next = 0              # seq the next indexed line must have (base + lines seen)
        self._req = OrderedDict()   # request id -> [seq, ...]
        self._started_mid = False   # window begins after the start of the file

    def refresh(self):
        with self._lock:
            return self._refresh()

    def _refresh(self):
        if not self._path or not os.path.exists(self._path):
            return False
        st = os.stat(self._path)
        if st.st_ino != self._ino or st.st_size < self._pos:
            self._reset()
            self._ino = st.st_ino
        if self._base is None and st.st_size > self._window:
            self._pos = st.st_size - self._window
            self._started_mid = True
            with open(self._path, "rb") as f:        # skip the partial first line
                f.seek(self._pos)
                self._pos += len(f.readline())
        if st.st_size == self._pos:
            return True
        with open(self._path, "rb") as f:
            f.seek(self._pos)
            chunk = f.read(st.st_size - self._pos)
        end = chunk.rfind(b"\n") + 1
        off = self._pos
        for line in chunk[:end].splitlines(keepends=True):
            try:
                rec = json.loads(line)
                seq = rec["seq"]
                if not isinstance(seq, int):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                off += len(line)
                continue
            if self._base is None:
                self._base, self._next = seq, seq
            if seq != self._next:           # a gap (tampering or a skipped bad line): index restarts
                self._offsets, self._base, self._next = [], seq, seq
                self._req.clear()
                self._started_mid = True
            if (seq - self._base) % self._stride == 0:
                self._offsets.append(off)
            self._next = seq + 1
            rid = rec.get("id") or rec.get("request_id")
            if isinstance(rid, str):
                lst = self._req.get(rid)
                if lst is None:
                    lst = self._req[rid] = []
                    while len(self._req) > MAX_REQUEST_IDS:
                        self._req.popitem(last=False)
                lst.append(seq)
            off += len(line)
        self._pos += end
        return True

    def bounds(self):
        with self._lock:
            self._refresh()
            return self._base, self._next, self._started_mid

    def _read_from(self, seq_lo, seq_hi):
        """Parsed records with seq_lo <= seq < seq_hi, ascending."""
        with self._lock:
            if self._base is None or seq_hi <= self._base:
                return []
            seq_lo = max(seq_lo, self._base)
            i = (seq_lo - self._base) // self._stride
            start = self._offsets[i]
            j = (seq_hi - 1 - self._base) // self._stride + 1
            stop = self._offsets[j] if j < len(self._offsets) else self._pos
        with open(self._path, "rb") as f:
            f.seek(start)
            data = f.read(stop - start)
        out = []
        for line in data.splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            s = rec.get("seq")
            if isinstance(s, int) and seq_lo <= s < seq_hi:
                out.append(rec)
        return out

    def request_seqs(self, rid):
        with self._lock:
            self._refresh()
            return list(self._req.get(rid, ()))

    # -- queries -------------------------------------------------------------
    def _walk(self, lo, hi, desc, block=1024):
        """Raw records with lo <= seq < hi, in blocks, ascending or descending."""
        if desc:
            cur = hi
            while cur > lo:
                start = max(lo, cur - block)
                yield from reversed(self._read_from(start, cur))
                cur = start
        else:
            cur = lo
            while cur < hi:
                end = min(hi, cur + block)
                yield from self._read_from(cur, end)
                cur = end

    def _request_records(self, rid, p, desc):
        seqs = sorted((s for s in self.request_seqs(rid)
                       if (p["before"] is None or s < p["before"])
                       and (p["after"] is None or s > p["after"])), reverse=desc)
        for s in seqs:
            yield from self._read_from(s, s + 1)

    @staticmethod
    def _matches(p, ev, rec):
        if p["events"] and ev["event"] not in p["events"]:
            return False
        if p["secret"]:
            names = set(rec.get("names") or []) if isinstance(rec.get("names"), list) else set()
            if rec.get("secret"):
                names.add(rec["secret"])
            if p["secret"] not in names:
                return False
        if p["source"] and rec.get("source") != p["source"]:
            return False
        if p["since"] is not None and rec["ts"] < p["since"]:
            return False
        if p["until"] is not None and rec["ts"] > p["until"]:
            return False
        return True

    def query(self, p):
        """The response dict for parse_params output `p`."""
        base, nxt, started_mid = self.bounds()
        res = {"events": [], "next": None, "truncated": False, "count": 0}
        if base is None:
            return res
        limit, desc = p["limit"], p["order"] == "desc"
        if p["request"]:
            records = self._request_records(p["request"], p, desc)
        elif desc:
            records = self._walk(base, nxt if p["before"] is None else min(p["before"], nxt), True)
        else:
            records = self._walk(base if p["after"] is None else max(base, p["after"] + 1), nxt, False)
        events, scanned, last, stop = [], 0, None, None
        for rec in records:
            ts = rec.get("ts")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                # The log is written in time order: past the window asked for, stop.
                if desc and p["since"] is not None and ts < p["since"] and not p["request"]:
                    stop = "done"
                    break
                if not desc and p["until"] is not None and ts > p["until"] and not p["request"]:
                    stop = "done"
                    break
            scanned += 1
            last = rec.get("seq")
            ev = redact(rec)
            if ev is not None and self._matches(p, ev, rec):
                events.append(ev)
                if len(events) >= limit:
                    stop = "limit"
                    break
            if scanned >= MAX_SCAN_LINES:
                stop = "bound"
                break
        if stop is None and desc and started_mid and not p["request"]:
            res["truncated"] = True         # older history exists but is outside the index
        if stop == "bound":
            res["truncated"] = True
        # Response size cap: drop events from the far end until the body fits.
        if len(json.dumps(events, separators=(",", ":"))) > MAX_BODY_BYTES:
            while events and len(json.dumps(events, separators=(",", ":"))) > MAX_BODY_BYTES:
                events.pop()
            res["truncated"], stop = True, "limit"
        res["events"], res["count"] = events, len(events)
        if stop == "limit":
            res["next"] = events[-1]["seq"] if events else last
        elif stop == "bound":
            res["next"] = last
        return res


# -- verification --------------------------------------------------------------
def verify_chain(path, budget_s=VERIFY_BUDGET_S, now=time.monotonic):
    """(ok, events, first_bad_seq) over the whole file; raises TimeoutError when
    the budget runs out. first_bad_seq is the first record that does not chain
    from its predecessor (so an edited record is reported as its successor)."""
    genesis = "0" * 64
    prev, seq, n = genesis, 0, 0
    if not path or not os.path.exists(path):
        return True, 0, None
    deadline = now() + budget_s
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\n")
            if not line:
                continue
            if n % 2048 == 0 and now() > deadline:
                raise TimeoutError("verify budget exceeded")
            try:
                rec = json.loads(line)
                ok = rec["seq"] == seq and rec["prev"] == prev
            except (ValueError, KeyError, TypeError):
                ok = False
            if not ok:
                return False, n, seq
            prev = hashlib.sha256(line).hexdigest()
            seq += 1
            n += 1
    return True, n, None


# -- the HTTP-facing object ----------------------------------------------------
class AuditApi:
    """Rate limiting and dispatch for the two endpoints. One per client listener."""

    def __init__(self, path, make_room, rate_per_min=RATE_PER_MIN, map_cap=4096):
        self.path = path
        self.view = AuditView(path)
        self._make_room = make_room
        self.rate_per_min = rate_per_min
        self._rate = {}
        self._rate_lock = threading.Lock()
        self._verify_lock = threading.Lock()

    def rate_ok(self, key_id, now=None):
        now = time.time() if now is None else now
        with self._rate_lock:
            st = self._rate.get(key_id)
            if st is None:
                self._make_room(self._rate, now)
                st = self._rate[key_id] = {"t": now, "n": 0}
            if now - st["t"] >= 60:
                st.update(t=now, n=0)
            st["n"] += 1
            return st["n"] <= self.rate_per_min

    def handle(self, subpath, query, key_id):
        """-> (status, json-able body, extra headers)."""
        if not self.rate_ok(key_id):
            return 429, {"error": "audit rate limit: try again in a minute"}, {"Retry-After": "30"}
        if subpath == "/v1/audit/verify":
            if query:
                return 400, {"error": "verify takes no parameters"}, {}
            if not self._verify_lock.acquire(blocking=False):
                return 429, {"error": "a verify is already running"}, {"Retry-After": "10"}
            try:
                ok, n, bad = verify_chain(self.path)
            except TimeoutError:
                return 503, {"error": "verify budget exceeded; run it on the broker host"}, {}
            except OSError:
                return 503, {"error": "audit log unavailable"}, {}
            finally:
                self._verify_lock.release()
            return 200, {"ok": ok, "events": n, "first_bad_seq": bad}, {}
        try:
            p = parse_params(query)
        except BadParam as e:
            return 400, {"error": str(e)}, {}
        try:
            return 200, self.view.query(p), {}
        except OSError:
            return 503, {"error": "audit log unavailable"}, {}
