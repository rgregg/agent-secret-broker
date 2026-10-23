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
GRACE_DEFAULT, GRACE_MAX = 900, 3600
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


def parse_grace(sc):
    g = sc.get("api_key_grace_s", GRACE_DEFAULT)
    if isinstance(g, bool) or not isinstance(g, int) or not 0 <= g <= GRACE_MAX:
        raise ValueError(f"summary.api_key_grace_s must be an integer 0-{GRACE_MAX}")
    return g


class VaultKey:
    """The key from catalog credential `name`, variable `var`, read through the broker.

    get() never waits for the vault. Within `ttl` of the last good read the cached key is
    returned. After that exactly one background read refreshes it while every caller keeps
    getting the old key for up to `grace` more seconds (stale-while-revalidate). With no
    key at all (first use, after invalidate(), or a permanent failure) callers get None
    while the one background read runs. A transient failure (vault down, throttled) keeps
    the last good key for the grace period; not_found / empty / invalid drop it at once.
    """

    TRANSIENT = ("backend_unavailable", "rate_limited", "other")

    def __init__(self, name, var, ttl=TTL_DEFAULT, clock=time.monotonic, grace=GRACE_DEFAULT):
        self.name, self.var, self.ttl, self.grace, self._clock = name, var, ttl, grace, clock
        self._reader = self._log = None
        self._lock = threading.Lock()           # guards the fields below; never held across a read
        self._value = None
        self._fresh_until = 0.0                 # next refresh is due at this time
        self._serve_until = 0.0                 # the cached value may be served until this time
        self._busy = None                       # the background thread while a read runs
        self._gen = 0
        self._last_fail_log = None

    def __repr__(self):
        return "VaultKey()"

    def attach(self, reader, log=None):
        """`reader(name, var)` returns the value or raises KeyUnavailable; `log(event, **f)` audits."""
        self._reader, self._log = reader, log

    def invalidate(self):
        """Forget the cached key (the catalog entry for it changed): the next get() re-reads."""
        with self._lock:
            self._gen += 1
            self._value, self._fresh_until, self._serve_until = None, 0.0, 0.0

    def wait(self, timeout=10.0):
        """Block until a running background read ends (tests, and a deploy self-check)."""
        t = self._busy
        if t is not None:
            t.join(timeout)

    def get(self):
        try:
            return self._get()
        except Exception:  # noqa: BLE001  (never into the request path)
            return None

    def _get(self):
        start = False
        with self._lock:
            now = self._clock()
            value = self._value if (self._value is not None and now < self._serve_until) else None
            if now >= self._fresh_until and self._busy is None:
                gen = self._gen
                self._busy = t = threading.Thread(target=self._refresh, args=(gen,), daemon=True)
                start = True
        if start:
            try:
                t.start()
            except Exception:  # noqa: BLE001
                with self._lock:
                    self._busy = None
        return value

    def _refresh(self, gen):
        value, result = None, "ok"
        try:
            if self._reader is None:
                raise KeyUnavailable("not_attached")
            raw = self._reader(self.name, self.var)
            if not isinstance(raw, str) or not raw.strip():
                raise KeyUnavailable("empty")
            value = raw.strip()
            if not value.isascii() or _BAD_CHARS.search(value):
                value = None
                raise KeyUnavailable("invalid")
        except KeyUnavailable as e:
            result = e.reason
        except Exception:  # noqa: BLE001
            result = "other"
        try:
            now = self._clock()                 # after the read: a slow read does not shorten the TTL
            with self._lock:
                if gen == self._gen:
                    if value is not None:
                        self._value = value
                        self._fresh_until = now + self.ttl
                        self._serve_until = self._fresh_until + self.grace
                    elif result in self.TRANSIENT and self._value is not None:
                        self._fresh_until = now + min(FAIL_TTL, self.ttl)    # keep the last good key
                    else:
                        self._value, self._serve_until = None, 0.0
                        self._fresh_until = now + min(FAIL_TTL, self.ttl)
            self._record(now, result)
        except Exception:  # noqa: BLE001
            pass
        finally:
            with self._lock:
                self._busy = None

    def _record(self, now, result):
        if result != "ok":
            with self._lock:
                last = self._last_fail_log
                if last is not None and now - last < LOG_EVERY:
                    return
                self._last_fail_log = now
            logging.getLogger("secret_broker").warning("summary key unavailable: reason=%s", result)
        if self._log is not None:
            try:
                self._log("summary_key_read", secret=self.name, result=result)
            except Exception:  # noqa: BLE001
                pass
