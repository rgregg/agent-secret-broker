"""Approver presence: hold phone notifications while an approval page is open.

The approval pages send a small heartbeat (`POST /presence`) while the tab is
visible. This module keeps the last-seen state per user and per tab, in
memory only, and parses the `notify_presence` config. The hold/release
decisions live in the broker (`Broker._push`, `Broker.presence_tick`).

The state is never exposed to the agent: only the SSO-authenticated approval
listener can write it, and nothing here reaches a client-API response.
"""
import re
import threading
import time

TRANSPORT_TYPES = ("ticker", "telegram", "webpush")
DEFAULTS = {"enabled": True, "ttl_s": 25, "fallback_s": 60,
            "transports": list(TRANSPORT_TYPES), "require_focus": False}
MIN_LIFE_MARGIN_S = 10      # never hold a request that expires before fallback_s + this
TAB_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_config(raw, field="notify_presence"):
    """Validate `notify_presence` -> a full config dict. None means the defaults.
    Raises ValueError naming the field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"{field}.{k} is not a known option")
    out = {**DEFAULTS, **raw}
    for k in ("enabled", "require_focus"):
        if not isinstance(out[k], bool):
            raise ValueError(f"{field}.{k} must be true or false")
    if not _int(out["ttl_s"]) or not 10 <= out["ttl_s"] <= 120:
        raise ValueError(f"{field}.ttl_s must be a whole number of seconds from 10 to 120")
    fb = out["fallback_s"]
    if fb is not None and (not _int(fb) or not 5 <= fb <= 3600):
        raise ValueError(f"{field}.fallback_s must be 5 to 3600 seconds, or null for never")
    tr = out["transports"]
    if (not isinstance(tr, list) or not all(isinstance(t, str) and t in TRANSPORT_TYPES for t in tr)):
        raise ValueError(f"{field}.transports must be a list of {', '.join(TRANSPORT_TYPES)}")
    out["transports"] = list(dict.fromkeys(tr))
    return out


def describe(cfg):
    """One line for the Settings page."""
    if not cfg["enabled"]:
        return "Notifications are always sent immediately."
    fb = cfg["fallback_s"]
    tail = (f"sent after {fb} s if still waiting" if fb is not None
            else "never sent as a fallback")
    what = ", ".join(cfg["transports"]) or "none"
    return (f"Notifications ({what}) are held while an approval page is open here; {tail}. "
            "Set in the broker config (notify_presence).")


class Presence:
    """Last heartbeat per user and per browser tab. Present = some tab of the user
    sent a visible beat younger than `ttl_s` and has not sent a hidden one since.
    All maps are bounded."""
    MAX_USERS = 64
    MAX_TABS = 16

    def __init__(self, ttl_s, clock=time.time):
        self.ttl_s = ttl_s
        self._clock = clock
        self._lock = threading.Lock()
        self._users = {}        # user -> {tab -> (visible, t)}

    def beat(self, user, visible, tab=""):
        now = self._clock()
        with self._lock:
            tabs = self._users.get(user)
            if tabs is None:
                while len(self._users) >= self.MAX_USERS:
                    del self._users[min(self._users, key=lambda u: max(
                        (t for _, t in self._users[u].values()), default=0))]
                tabs = self._users[user] = {}
            for k in [k for k, (_, t) in tabs.items() if now - t > self.ttl_s]:
                del tabs[k]
            if tab not in tabs:
                while len(tabs) >= self.MAX_TABS:
                    del tabs[min(tabs, key=lambda k: tabs[k][1])]
            tabs[tab] = (bool(visible), now)

    def present(self, user):
        now = self._clock()
        with self._lock:
            return any(v and now - t <= self.ttl_s
                       for v, t in (self._users.get(user) or {}).values())
