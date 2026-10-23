"""Where the summary/classifier API key comes from.

The analyzers hold a `KeyProvider` and call `get()` for every request instead of
keeping a string. `ConstKey` wraps a key read from a file at startup (the old
behaviour). `VaultKey` reads it from the broker's own vault, lazily, and caches it
for a few minutes so a rotation is picked up without a restart.

`get()` never raises and returns None when no usable key is available (missing
item or variable, vault down or locked, empty or malformed value). Callers treat
None exactly like a provider failure. Only fixed reason classes are ever logged or
audited, never the key and never exception text.
"""
import logging
import re
import threading
import time

# same shapes as the catalog (broker._NAME_RE / broker._VAR_RE; a test pins them together)
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,60}$")

TTL_DEFAULT, TTL_MIN, TTL_MAX = 300, 30, 3600
FAIL_TTL = 30               # how long a failed read is remembered (no vault hammering)
LOG_EVERY = 300             # at most one failure line per this many seconds

REASONS = ("not_found", "backend_unavailable", "rate_limited", "empty", "invalid", "other",
           "not_attached")
_BAD_CHARS = re.compile(r"[\x00-\x20\x7f]")      # a key with whitespace or controls is not a key


class KeyUnavailable(Exception):
    """Raised by a vault reader. Carries only a fixed reason class."""

    def __init__(self, reason):
        super().__init__(reason if reason in REASONS else "other")
        self.reason = reason if reason in REASONS else "other"


class ConstKey:
    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value

    def __repr__(self):
        return "ConstKey()"


def as_provider(key):
    """A provider for `key`: providers pass through, a string is wrapped."""
    return key if callable(getattr(key, "get", None)) and not isinstance(key, str) else ConstKey(key)


def parse_secret(raw):
    """Validate summary.api_key_secret; return (name, var). ValueError names the field."""
    if not isinstance(raw, dict) or set(raw) != {"name", "var"}:
        raise ValueError('summary.api_key_secret must be {"name": "<credential>", "var": "<VARIABLE>"}')
    name, var = raw["name"], raw["var"]
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ValueError("summary.api_key_secret.name must be a credential name (lowercase letters, "
                         "digits, - and _, up to 41 characters)")
    if not isinstance(var, str) or not VAR_RE.match(var):
        raise ValueError("summary.api_key_secret.var must be a variable name like OPENROUTER_KEY")
    return name, var


def parse_ttl(sc):
    t = sc.get("api_key_ttl_s", TTL_DEFAULT)
    if isinstance(t, bool) or not isinstance(t, int) or not TTL_MIN <= t <= TTL_MAX:
        raise ValueError(f"summary.api_key_ttl_s must be an integer {TTL_MIN}-{TTL_MAX}")
    return t


class VaultKey:
    """The key from catalog credential `name`, variable `var`, read through the broker."""

    def __init__(self, name, var, ttl=TTL_DEFAULT, clock=time.monotonic):
        self.name, self.var, self.ttl, self._clock = name, var, ttl, clock
        self._reader = self._log = None
        self._lock = threading.Lock()
        self._value, self._until = None, 0.0
        self._last_fail_log = None

    def __repr__(self):
        return "VaultKey()"

    def attach(self, reader, log=None):
        """`reader(name, var)` returns the value or raises KeyUnavailable; `log(event, **f)` audits."""
        self._reader, self._log = reader, log

    def get(self):
        try:
            return self._get()
        except Exception:  # noqa: BLE001  (never into the request path)
            return None

    def _get(self):
        with self._lock:
            now = self._clock()
            if now < self._until:
                return self._value
            value, result = None, "ok"
            try:
                if self._reader is None:
                    raise KeyUnavailable("not_attached")
                raw = self._reader(self.name, self.var)
                if not isinstance(raw, str) or not raw.strip():
                    raise KeyUnavailable("empty")
                value = raw.strip()
                if _BAD_CHARS.search(value):
                    value = None
                    raise KeyUnavailable("invalid")
            except KeyUnavailable as e:
                result = e.reason
            except Exception:  # noqa: BLE001
                result = "other"
            self._value = value
            self._until = now + (self.ttl if value is not None else min(FAIL_TTL, self.ttl))
            self._record(now, result)
            return value

    def _record(self, now, result):
        if result != "ok":
            if self._last_fail_log is not None and now - self._last_fail_log < LOG_EVERY:
                return
            self._last_fail_log = now
            logging.getLogger("secret_broker").warning("summary key unavailable: reason=%s", result)
        if self._log is not None:
            try:
                self._log("summary_key_read", secret=self.name, result=result)
            except Exception:  # noqa: BLE001
                pass
