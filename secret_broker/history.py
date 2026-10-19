"""Request history, derived from the audit log.

The audit log stays the only record. This module reads it incrementally and
folds the events that share a request id into one row (what was asked, risk,
how it ended, who decided). Values never appear: the audit log does not hold
them, and URLs are shown without their query string.
"""
import json
import os
import re
import threading
import urllib.parse
from collections import OrderedDict

OUTCOMES = ("pending", "approved", "auto-approved", "denied", "expired", "failed")
_FINAL = ("approved", "denied", "expired", "failed")

# Fields kept per event for the detail view. A whitelist, not a copy: anything
# not named here (urls, argv, bodies, anything unforeseen) never reaches a page.
_EV_KEYS = ("reason", "reasons", "model", "risk", "error", "via", "channel", "decision",
            "approver", "approver_peer", "approver_ip", "always_requested", "latency_ms",
            "duration_ms", "upstream_status", "response_bytes", "secret", "vars", "kind",
            "to_peer", "auto_max", "ssh_fingerprint", "sign_bytes", "value_bytes", "op",
            "item", "field", "key", "hosts", "grant_id", "scope", "secrets", "grant_minutes",
            "grant_left_s", "expires_at", "created_by", "max_risk", "risk_level")
_MAX_EVENTS = 60            # per request
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


def valid_id(rid):
    """Request ids are url-safe tokens; anything else is not looked up."""
    return isinstance(rid, str) and bool(_ID_RE.match(rid))


def _clean(v, depth=0):
    if isinstance(v, str):
        return "".join(ch if ch.isprintable() else " " for ch in v)[:300]
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    if isinstance(v, (list, tuple)) and depth == 0:
        return [_clean(x, 1) for x in v[:20]]
    return None


def _scripts(rec):
    """[{path, size, sha}] from a `requested` record: path, size and hash only (the
    text is not in the audit log; keeping it for history is a separate store)."""
    paths = rec.get("script_paths")
    if not isinstance(paths, list):
        return []
    sizes, shas = rec.get("script_sizes") or [], rec.get("script_sha256") or []
    return [{"path": _clean(p), "size": sizes[i] if i < len(sizes) else None,
             "sha": (shas[i] if i < len(shas) and isinstance(shas[i], str) else "")[:12]}
            for i, p in enumerate(paths[:5])]


def _short_url(url):
    if not url:
        return None
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}{u.path}" + ("?..." if u.query else "")


class History:
    def __init__(self, path, max_requests=5000):
        self._path = path
        self._max = max_requests
        self._lock = threading.Lock()
        self._rows = OrderedDict()
        self._events = {}               # request id -> [whitelisted event dicts]
        self._pos = 0
        self._ino = None

    def _reset(self):
        self._rows.clear()
        self._events.clear()
        self._pos = 0

    def refresh(self):
        """Fold any new audit lines into the index. Cheap when nothing changed."""
        if not self._path or not os.path.exists(self._path):
            return
        with self._lock:
            st = os.stat(self._path)
            if st.st_ino != self._ino or st.st_size < self._pos:   # rotated / truncated
                self._reset()
                self._ino = st.st_ino
            if st.st_size == self._pos:
                return
            with open(self._path, "rb") as f:
                f.seek(self._pos)
                chunk = f.read(st.st_size - self._pos)
            end = chunk.rfind(b"\n") + 1            # never consume a half-written line
            self._pos += end
            for line in chunk[:end].splitlines():
                try:
                    self._fold(json.loads(line))
                except (ValueError, KeyError):
                    continue

    def _fold(self, rec):
        rid, ev = rec.get("id"), rec.get("event")
        if not rid or ev in ("approval_viewed",):
            return
        row = self._rows.get(rid)
        if row is None:
            if ev != "requested":
                return                              # started before the retained window
            row = self._rows[rid] = {
                "id": rid, "ts": rec["ts"], "time": rec["time"], "names": rec.get("names") or [],
                "mode": rec.get("mode"), "source": rec.get("source"), "outcome": "pending",
                "via": None, "approver": None, "risk": None, "summary": None, "summary_model": None, "summary_source": None, "error": None,
                "latency_ms": None, "grant_id": None, "delivered": False, "escalated": False,
                "method": rec.get("method"), "url": _short_url(rec.get("url")),
                "op": rec.get("op"), "item": rec.get("item"), "field": rec.get("field"),
                "key": rec.get("key"), "hosts": rec.get("hosts"), "final_seq": -1,
                "ssh_what": rec.get("ssh_what"), "peer": rec.get("peer"),
                "argv": _clean(rec.get("argv")), "scripts": _scripts(rec), "risk_reasons": None, "risk_model": None,
            }
            self._events[rid] = []
            while len(self._rows) > self._max:
                self._events.pop(self._rows.popitem(last=False)[0], None)
        evs = self._events[rid]
        if len(evs) < _MAX_EVENTS:
            e = {"event": ev, "ts": rec.get("ts"), "time": rec.get("time")}
            for k in _EV_KEYS:
                if k in rec and (v := _clean(rec[k])) is not None:
                    e[k] = v
            evs.append(e)
        if ev == "assessed":
            row["risk_reasons"], row["risk_model"] = _clean(rec.get("reasons")), rec.get("model")
            row["summary_source"] = rec.get("summary_source")
        if rec.get("risk"):
            row["risk"] = rec["risk"]
        if rec.get("summary"):
            row["summary"] = rec["summary"]
            if rec.get("summary_model"):
                row["summary_model"] = rec["summary_model"]
        if ev == "escalated":
            row["escalated"] = True
        elif ev == "delivered":
            row["delivered"] = True
        elif ev in _FINAL and rec["seq"] > row["final_seq"]:
            row["final_seq"] = rec["seq"]
            row["outcome"] = ev
            row["via"] = rec.get("via")
            row["approver"] = rec.get("approver")
            row["error"] = rec.get("error")
            row["latency_ms"] = rec.get("latency_ms")
            row["grant_id"] = rec.get("grant_id")
            if ev == "approved" and row["via"] == "policy":
                row["outcome"] = "auto-approved"

    def detail(self, rid, pending_ids=()):
        """(row, events) for one request, or (None, None) when unknown. A request
        still open is returned with outcome "pending" for the caller to refuse."""
        if not valid_id(rid):
            return None, None
        self.refresh()
        with self._lock:
            row = self._rows.get(rid)
            if row is None:
                return None, None
            row, evs = dict(row), [dict(e) for e in self._events.get(rid, [])]
        if row["outcome"] == "pending" and rid not in pending_ids:
            row["outcome"] = "unknown"
        return row, evs

    def rows(self, pending_ids=(), outcome=None, secret=None, mode=None, q=None):
        """Newest first. `pending_ids` are requests the broker still holds open;
        a row with no final event that is not among them ended without a record."""
        self.refresh()
        with self._lock:
            rows = [dict(r) for r in self._rows.values()]
        for r in rows:
            if r["outcome"] == "pending" and r["id"] not in pending_ids:
                r["outcome"] = "unknown"           # e.g. the broker restarted mid-request
        rows.reverse()
        if outcome:
            rows = [r for r in rows if r["outcome"] == outcome]
        if secret:
            rows = [r for r in rows if secret in r["names"]]
        if mode:
            rows = [r for r in rows if r["mode"] == mode]
        if q:
            q = q.lower()
            rows = [r for r in rows if q in " ".join(
                str(x) for x in (r["id"], ", ".join(r["names"]), r["method"], r["url"], r["source"],
                                 r["summary"], r["approver"], r["error"], r["ssh_what"], r["op"],
                                 r["mode"], " ".join(r["argv"] or ()))
                if x).lower()]
        return rows

    def secrets_seen(self):
        with self._lock:
            return sorted({n for r in self._rows.values() for n in r["names"]})
