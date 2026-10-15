"""Request history, derived from the audit log.

The audit log stays the only record. This module reads it incrementally and
folds the events that share a request id into one row (what was asked, risk,
how it ended, who decided). Values never appear: the audit log does not hold
them, and URLs are shown without their query string.
"""
import json
import os
import threading
import urllib.parse
from collections import OrderedDict

OUTCOMES = ("pending", "approved", "auto-approved", "denied", "expired", "failed")
_FINAL = ("approved", "denied", "expired", "failed")


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
        self._pos = 0
        self._ino = None

    def _reset(self):
        self._rows.clear()
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
                "via": None, "approver": None, "risk": None, "summary": None, "error": None,
                "latency_ms": None, "delivered": False, "escalated": False,
                "method": rec.get("method"), "url": _short_url(rec.get("url")),
                "op": rec.get("op"), "item": rec.get("item"), "field": rec.get("field"),
                "key": rec.get("key"), "hosts": rec.get("hosts"), "final_seq": -1,
            }
            while len(self._rows) > self._max:
                self._rows.popitem(last=False)
        if rec.get("risk"):
            row["risk"] = rec["risk"]
        if rec.get("summary"):
            row["summary"] = rec["summary"]
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
            if ev == "approved" and row["via"] == "policy":
                row["outcome"] = "auto-approved"

    def rows(self, pending_ids=(), outcome=None, secret=None, mode=None):
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
        return rows

    def secrets_seen(self):
        with self._lock:
            return sorted({n for r in self._rows.values() for n in r["names"]})
