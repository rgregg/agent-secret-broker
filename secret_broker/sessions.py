"""HTTP sessions: a time-boxed standing permission for one credential, specific hosts and methods.

An agent that must make several related calls (log in, reuse the session cookie, carry a CSRF
token, log out) opens a session (`asb session open`, request mode `session`). A human approves it
once on a card that shows the credential, hosts, methods, time limit and call cap. The agent gets
a session id, not a secret. `asb http NAME METHOD URL --session ID` then goes through the broker
as usual but is released WITHOUT a new prompt and without a model verdict, as long as the call is
inside the session's scope. The broker keeps a per-session cookie jar and captured values in
memory; neither ever reaches the agent.

Invariants (enforced in broker.py and here, tested in tests/test_sessions.py):
  * a session is always opened by a human: the open request is HIGH by code (no model call),
    never auto-approved (policy allow, Always, timed grants, SSH rules), and no notification
    button, token or hook can decide it; only the authenticated approval site can;
  * absolute expiry: the deadline is fixed at approval time (default 15 minutes, hard maximum
    configurable). No sliding extension, no renewal, no idle refresh: use never moves it. At the
    deadline the session is abandoned: jar and captured values are dropped, it is marked expired,
    every further call fails with a dedicated error, `session_expired` is audited. A sweeper does
    this even when nobody calls;
  * bound to the authenticated client: another client (or the legacy shared key, when the session
    belongs to an enrolled client) gets exactly the answer an unknown id gets. Ids are 192 bits of
    randomness, looked up by their hash and compared in constant time;
  * a session can only narrow its credential: hosts inside `allowed_hosts`, http credentials only,
    methods declared up front (GET and HEAD by default), a call cap. Anything out of scope is
    REFUSED, never prompted: the agent opens a new session if it needs more;
  * jar and captured values live in memory only, are masked wherever an upstream echoes them,
    and appear in no audit record, history row, request detail, log, notification, page or result;
  * no exception text reaches an agent, a log, the audit log, history or a page: only class names
    and coarse categories.
"""
import hashlib
import hmac
import html
import json
import math
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from email.utils import parsedate_to_datetime

from .backends import BackendError
from . import clients as clients_mod
from . import credreq as credreq_mod
from . import guidance as guidance_mod

DEFAULTS = {"enabled": True, "default_ttl_s": 900, "max_ttl_s": 3600, "max_calls": 200, "max_per_client": 3}
TTL_FLOOR = 30                  # seconds: the shortest session
TTL_CEIL = 86400                # the largest `max_ttl_s` the config may set
CALLS_CEIL = 10000              # the largest `max_calls` the config may set
DEFAULT_CALLS = 200             # what `asb session open` asks for when --max-calls is not given
METHODS_ALL = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
DEFAULT_METHODS = ("GET", "HEAD")
MAX_HOSTS = 5
MAX_TOTAL = 20                  # open sessions across all clients
MAX_PENDING_PER_CLIENT = 2      # session requests waiting for the human, per client
MAX_COOKIES = 50                # per jar
MAX_COOKIE_BYTES = 4096         # name + value
MAX_CAPTURES = 16               # captured values per session
MAX_CAPTURE_BYTES = 4096        # per captured value
MAX_CAPTURE_EXPRS = 8           # capture expressions per call
MAX_REDIRECTS = 5
MAX_TOMBSTONES = 500            # ended sessions remembered (id hash -> client, reason) so the owner is told why
TOMBSTONE_S = 86400
SWEEP_S = 5
READ_LIMIT = 1_000_000          # response bytes read (same ceiling as plain http)
SID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_PH_RE = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
REASON = "an HTTP session always needs a human to approve it; always high"
WARNING = ("The requesting agent asked for this session. Its purpose text is the agent's own claim and "
           "is not verified. If you approve, this client may make the calls described here, using the "
           "stored credential, WITHOUT asking you again, until the time runs out or the call cap is used. "
           "Each call is logged but you are not asked about it. The time limit is fixed from the moment "
           "you approve: it is never extended or renewed.")


class SessionError(PermissionError):
    """A session call that is refused. `code` is the machine-readable class the client maps to an
    exit code; the text is fixed (never exception text, never the id or a value)."""

    def __init__(self, message, code, http=403):
        super().__init__(message)
        self.code, self.http = code, http


class SessionOpenError(Exception):
    """Opening failed at approval time; the message is curated and safe to show the agent."""


# ---------------------------------------------------------------- config
def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_config(raw, field="sessions"):
    """Validate `sessions` -> the full dict with defaults. None means the defaults. Raises
    ValueError naming the field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"{field}.{k} is not a known option")
    out = {**DEFAULTS, **raw}
    if not isinstance(out["enabled"], bool):
        raise ValueError(f"{field}.enabled must be true or false")
    if not _int(out["max_ttl_s"]) or not TTL_FLOOR <= out["max_ttl_s"] <= TTL_CEIL:
        raise ValueError(f"{field}.max_ttl_s must be a whole number of seconds from {TTL_FLOOR} to {TTL_CEIL}")
    if not _int(out["default_ttl_s"]) or not TTL_FLOOR <= out["default_ttl_s"] <= out["max_ttl_s"]:
        raise ValueError(f"{field}.default_ttl_s must be a whole number of seconds from {TTL_FLOOR} "
                         f"up to {field}.max_ttl_s")
    if not _int(out["max_calls"]) or not 1 <= out["max_calls"] <= CALLS_CEIL:
        raise ValueError(f"{field}.max_calls must be a whole number from 1 to {CALLS_CEIL}")
    if not _int(out["max_per_client"]) or not 1 <= out["max_per_client"] <= 20:
        raise ValueError(f"{field}.max_per_client must be a whole number from 1 to 20")
    return out


# ---------------------------------------------------------------- capture expressions
def parse_jsonpath(text):
    """`$.a.b[0].c` -> ["a", "b", 0, "c"]. Dotted keys and array indexes only; anything else
    (wildcards, filters, recursion, quoted keys, slices) is a ValueError: fail closed."""
    if not isinstance(text, str) or not text.startswith("$") or len(text) > 200:
        raise ValueError("bad capture json path")
    segs, i, n = [], 1, len(text)
    while i < n:
        if text[i] == ".":
            j = i + 1
            while j < n and text[j] not in ".[":
                j += 1
            key = text[i + 1:j]
            if not _KEY_RE.match(key):
                raise ValueError("bad capture json path")
            segs.append(key)
            i = j
        elif text[i] == "[":
            j = text.find("]", i)
            idx = text[i + 1:j] if j > 0 else ""
            if not (idx.isascii() and idx.isdigit() and len(idx) <= 4):
                raise ValueError("bad capture json path")
            segs.append(int(idx))
            i = j + 1
        else:
            raise ValueError("bad capture json path")
    if not segs or len(segs) > 12:
        raise ValueError("bad capture json path")
    return segs


def parse_capture(text):
    """`NAME=header:X-CSRF-Token | cookie:NAME | json:$.a.b` -> (name, kind, arg). ValueError on
    anything else; the message is fixed text and never repeats the input."""
    if not isinstance(text, str) or len(text) > 300 or "=" not in text:
        raise ValueError("bad capture expression: use NAME=header:X | cookie:NAME | json:$.a.b")
    name, _, expr = text.partition("=")
    kind, _, arg = expr.partition(":")
    if not NAME_RE.match(name):
        raise ValueError("bad capture name: a letter, then letters, digits or _ (up to 32)")
    if kind == "header" and _HEADER_RE.match(arg):
        return name, "header", arg.lower()
    if kind == "cookie" and _COOKIE_NAME_RE.match(arg):
        return name, "cookie", arg
    if kind == "json":
        return name, "json", parse_jsonpath(arg)
    raise ValueError("bad capture expression: use NAME=header:X | cookie:NAME | json:$.a.b")


def json_value(obj, segs):
    """The string form of a scalar at `segs`, or None (missing, wrong type, an object or array)."""
    for s in segs:
        if isinstance(s, int):
            if not isinstance(obj, list) or s >= len(obj):
                return None
            obj = obj[s]
        else:
            if not isinstance(obj, dict) or s not in obj:
                return None
            obj = obj[s]
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    return obj if isinstance(obj, str) else None


def storable(value):
    """A captured value is stored only if it is short text with no control characters: it will be
    placed into URLs, headers and bodies later, so a line break would be a header injection."""
    return (isinstance(value, str) and 0 < len(value.encode("utf-8", "replace")) <= MAX_CAPTURE_BYTES
            and not _CTRL.search(value))


# ---------------------------------------------------------------- cookie jar
class Jar:
    """A minimal, host-scoped cookie jar. Every cookie belongs to the exact host that set it (a
    Domain attribute widens nothing), is sent only to that host, honours Path, Secure, Max-Age and
    Expires, and is bounded in number and size. Memory only."""

    def __init__(self, clock):
        self._clock = clock
        self._c = OrderedDict()         # (host, path, name) -> {"value", "secure", "exp"}

    def store(self, host, req_path, https, set_cookies):
        now = self._clock()
        for raw in set_cookies:
            parsed = self._parse(raw)
            if parsed is None:
                continue
            name, value, attrs = parsed
            path = attrs.get("path", "")
            if not path.startswith("/"):
                path = req_path.rsplit("/", 1)[0] or "/"
            if "secure" in attrs and not https:
                continue                    # a secure cookie from a plain-http response is ignored
            exp = None
            if "max-age" in attrs:
                try:
                    age = int(attrs["max-age"])
                except ValueError:
                    age = None
                if age is not None:
                    if age <= 0:
                        self._c.pop((host, path, name), None)
                        continue
                    exp = now + age
            elif "expires" in attrs:
                try:
                    when = parsedate_to_datetime(attrs["expires"]).timestamp()
                except (TypeError, ValueError, IndexError, OverflowError):
                    when = None
                if when is not None:
                    if when <= now:
                        self._c.pop((host, path, name), None)
                        continue
                    exp = when
            key = (host, path, name)
            if key not in self._c and len(self._c) >= MAX_COOKIES:
                continue
            self._c[key] = {"value": value, "secure": "secure" in attrs, "exp": exp}

    @staticmethod
    def _parse(raw):
        if not isinstance(raw, str) or len(raw) > 8192 or _CTRL.search(raw):
            return None
        parts = [p.strip() for p in raw.split(";")]
        name, eq, value = parts[0].partition("=")
        name = name.strip()
        if not eq or not _TOKEN_RE.match(name) or len(name) + len(value) > MAX_COOKIE_BYTES:
            return None
        attrs = {}
        for p in parts[1:]:
            k, _, v = p.partition("=")
            k = k.strip().lower()
            if k in ("path", "max-age", "expires", "secure", "domain", "samesite", "httponly") and k not in attrs:
                attrs[k] = v.strip()
        return name, value.strip(), attrs

    def header(self, host, path, https):
        """The Cookie header value for a request, or None."""
        now = self._clock()
        out = []
        for key in list(self._c):
            h, cpath, name = key
            c = self._c[key]
            if c["exp"] is not None and c["exp"] <= now:
                del self._c[key]
                continue
            if h != host or (c["secure"] and not https):
                continue
            if not (path == cpath or (path.startswith(cpath) and (cpath.endswith("/") or path[len(cpath)] == "/"))):
                continue
            out.append((-len(cpath), name, c["value"]))
        out.sort(key=lambda t: t[0])
        return "; ".join(f"{n}={v}" for _, n, v in out) or None

    def get(self, host, name):
        now = self._clock()
        best = None
        for (h, cpath, n), c in self._c.items():
            if h == host and n == name and (c["exp"] is None or c["exp"] > now):
                if best is None or len(cpath) > len(best[0]):
                    best = (cpath, c["value"])
        return best[1] if best else None

    def values(self):
        return [c["value"] for c in self._c.values()]

    def __len__(self):
        return len(self._c)

    def clear(self):
        self._c.clear()


class Session:
    """One approved session. Everything secret about it (jar, captures) stays in this object."""

    def __init__(self, sid, pid, client, cred, hosts, methods, ttl_s, max_calls, opened, purpose, approver,
                 clock):
        self.id, self.pid = sid, pid
        self.cid, self.cname = client["id"], client["name"]
        self.cred, self.hosts, self.methods = cred, tuple(hosts), tuple(methods)
        self.ttl_s, self.max_calls = ttl_s, max_calls
        self.opened, self.expires = opened, opened + ttl_s       # absolute: never moved
        self.calls = 0
        self.purpose, self.approver = purpose, approver
        self.jar = Jar(clock)
        self.captures = {}
        self.lock = threading.Lock()
        self.dead = False

    def drop(self):
        """Abandon: forget every secret this session holds."""
        with self.lock:
            self.dead = True
            self.jar.clear()
            self.captures.clear()


# ---------------------------------------------------------------- performing a call
def coarse_class(exc):
    """A coarse category for a failed upstream call. Never the exception's text."""
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
        exc = exc.reason if isinstance(exc.reason, BaseException) else exc
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ConnectionError):
        return "connection"
    if isinstance(exc, ValueError):
        return "invalid_request"
    if isinstance(exc, OSError):
        return "connection"
    return "other"


def fill(text, values):
    """Substitute {{NAME}} in one pass (a substituted value is never scanned again, so an
    upstream-supplied value cannot smuggle in another placeholder). KeyError for an unknown name."""
    return _PH_RE.sub(lambda m: values[m.group(1)], text)


def placeholders(text):
    return [m.group(1) for m in _PH_RE.finditer(text or "")]


def _host_of(url):
    try:
        u = urllib.parse.urlsplit(url)
        return u.scheme, (u.hostname or "").lower(), (u.path or "/") + (("?" + u.query) if u.query else "")
    except ValueError:
        return "", "", ""


def run_http(sess, spec, env, tls, allowed_now, opener_for, mask, expr):
    """Perform one session call. `env` holds the credential values, `expr` the parsed capture
    expressions. Returns (out, info): out is {"status", "headers", "body"} with Set-Cookie removed
    and every credential, cookie and captured value masked; info is {"captured": [names],
    "missing": [names]} (names only). Raises only ValueError/OSError/SSLError and friends for the
    caller to reduce to a coarse class."""
    with sess.lock:
        if sess.dead:
            raise SessionError("session ended", "session_unknown", 404)
        values = {**env, **{"session." + k: v for k, v in sess.captures.items()}}
    method = spec["method"]
    if spec.get("body_b64") is not None:
        import base64
        data = base64.b64decode(spec["body_b64"])
    elif spec.get("body"):
        data = fill(spec["body"], values).encode()
    else:
        data = None
    url = fill(spec["url"], values)
    headers = {k: fill(v, values) for k, v in spec["headers"].items()}
    opener = opener_for(tls)
    for hop in range(MAX_REDIRECTS + 1):
        scheme, host, path = _host_of(url)
        if scheme not in ("http", "https") or host not in sess.hosts or host not in allowed_now:
            raise ValueError("host outside the session")
        https = scheme == "https"
        hdr = dict(headers)
        with sess.lock:
            cookie = sess.jar.header(host, path.split("?")[0], https)
        if cookie:
            have = next((k for k in hdr if k.lower() == "cookie"), None)
            hdr[have or "Cookie"] = (hdr[have] + "; " + cookie) if have else cookie
        r = urllib.request.Request(url, data=data, method=method, headers=hdr)
        try:
            with opener.open(r, timeout=30) as resp:
                status, msg, body = resp.status, resp.headers, resp.read(READ_LIMIT)
        except urllib.error.HTTPError as e:
            try:
                status, msg, body = e.code, e.headers, e.read(READ_LIMIT)
            finally:
                e.close()
        with sess.lock:
            if not sess.dead:
                sess.jar.store(host, path.split("?")[0], https, msg.get_all("Set-Cookie") or [])
        loc = msg.get("Location")
        if status in (301, 302, 303, 307, 308) and loc and hop < MAX_REDIRECTS:
            nxt = urllib.parse.urljoin(url, loc)
            ns, nh, _ = _host_of(nxt)
            if ns in ("http", "https") and nh in sess.hosts and nh in allowed_now and not (https and ns == "http"):
                if status in (301, 302, 303) and method not in ("GET", "HEAD"):
                    method, data = "GET", None
                    headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
                url = nxt
                continue
        break
    caps, missing = {}, []
    if expr:
        parsed = None
        for name, kind, arg in expr:
            val = None
            if kind == "header":
                val = msg.get(arg)
            elif kind == "cookie":
                with sess.lock:
                    val = sess.jar.get(host, arg)
            else:
                if parsed is None:
                    try:
                        parsed = [json.loads(body.decode("utf-8"))]
                    except (ValueError, UnicodeDecodeError, RecursionError):
                        parsed = [None]
                val = json_value(parsed[0], arg)
            if storable(val):
                caps[name] = val
            else:
                missing.append(name)
    with sess.lock:
        if not sess.dead:
            for name, val in list(caps.items()):
                if name in sess.captures or len(sess.captures) < MAX_CAPTURES:
                    sess.captures[name] = val
                else:
                    del caps[name]
                    missing.append(name)
        secret_values = list(env.values()) + sess.jar.values() + list(sess.captures.values())
    out_headers = {}
    for k, v in msg.items():
        if k.lower() in ("set-cookie", "set-cookie2"):
            continue
        out_headers[k] = mask(v, secret_values)
    out = {"status": status, "headers": out_headers, "body": mask(body.decode("utf-8", "replace"), secret_values)}
    return out, {"captured": sorted(caps), "missing": sorted(set(missing))}


def scope_problem(s, sc, names, method, spec):
    """None when a call is inside the session's scope, else (reason_class, fixed message). `sc` is the
    credential's current catalog entry (None if it vanished). Pure: no state is changed. Call it under
    the store lock so the check and the call-count increment are atomic. (Extension point: a manifest
    rule check belongs here.)"""
    scheme, host, _ = _host_of(spec["url"])
    if list(names) != [s.cred]:
        return "credential", "the call names a different credential than the session's"
    if sc is None or sc.get("ssh") or host not in (sc.get("allowed_hosts") or []):
        return "host", "that host is not allowed for this session's credential"
    if scheme not in ("http", "https") or host not in s.hosts:
        return "host", "that host is outside this session's hosts; open a new session for it"
    if method not in s.methods:
        return "method", (f"{method} is not one of this session's methods ({', '.join(s.methods)}); "
                          "open a new session that declares it")
    if any(k.lower() == "host" for k in spec["headers"]):
        return "header", "a session call cannot set the Host header"
    if s.calls >= s.max_calls:
        return "max_calls", f"this session used all {s.max_calls} of its calls; open a new one"
    for text in [spec["url"], spec.get("body") or ""] + list(spec["headers"].values()):
        for ph in placeholders(text):
            if ph.startswith("session."):
                if ph[8:] not in s.captures:
                    return "missing_value", "a {{session.NAME}} value used here has not been captured in this session"
            elif ph not in sc["vars"]:
                return "placeholder", "a placeholder is not provided by the session's credential"
    return None


# ---------------------------------------------------------------- agent-side checks
def validate_open(cfg, spec, allowed_hosts):
    """The agent's open request -> the normalized spec, or ValueError/PermissionError with fixed
    text. `allowed_hosts` is the credential's list. Never repeats the agent's input."""
    purpose = credreq_mod.validate_purpose(spec.get("purpose"))
    hosts = spec.get("hosts")
    if (not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_HOSTS
            or not all(isinstance(h, str) and re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", h)
                       for h in hosts)):
        raise ValueError(f"hosts must be 1 to {MAX_HOSTS} plain host names (--host)")
    hosts = sorted({h.lower() for h in hosts})
    if any(h not in allowed_hosts for h in hosts):
        raise PermissionError("a session host is outside this credential's allowed hosts: a session can "
                              "only narrow what the credential allows (see `asb list`)")
    methods = spec.get("methods")
    if methods is None:
        methods = list(DEFAULT_METHODS)
    if (not isinstance(methods, list) or not 1 <= len(methods) <= len(METHODS_ALL)
            or not all(isinstance(m, str) and m.upper() in METHODS_ALL for m in methods)):
        raise ValueError("methods must be some of " + ", ".join(METHODS_ALL))
    methods = [m for m in METHODS_ALL if m in {x.upper() for x in methods}]
    ttl = spec.get("ttl_s", cfg["default_ttl_s"])
    if not _int(ttl) or ttl < TTL_FLOOR:
        raise ValueError(f"the time limit must be at least {TTL_FLOOR} seconds")
    if ttl > cfg["max_ttl_s"]:
        raise ValueError(f"the time limit is above this broker's maximum of {cfg['max_ttl_s'] // 60} minutes")
    calls = spec.get("max_calls", min(DEFAULT_CALLS, cfg["max_calls"]))
    if not _int(calls) or calls < 1:
        raise ValueError("max calls must be a whole number of at least 1")
    if calls > cfg["max_calls"]:
        raise ValueError(f"max calls is above this broker's maximum of {cfg['max_calls']}")
    return {"purpose": purpose, "hosts": hosts, "methods": methods, "ttl_s": ttl, "max_calls": calls}


def parse_limits(get):
    """The approver's optional limits from the decision form: `get(name)` -> str or ''. Returns
    None when nothing was set, else {"ttl_s": int|None, "max_calls": int|None}, or {"bad": True}."""
    out, any_ = {"ttl_s": None, "max_calls": None}, False
    t, c = (get("session_ttl_min") or "").strip(), (get("session_max_calls") or "").strip()
    if t:
        any_ = True
        try:
            x = float(t) if len(t) <= 10 else float("nan")
            out["ttl_s"] = int(round(x * 60)) if math.isfinite(x) and x > 0 else None
        except ValueError:
            pass
        if out["ttl_s"] is None:
            return {"bad": True}
    if c:
        any_ = True
        if not (c.isascii() and c.isdigit() and len(c) <= 6):
            return {"bad": True}
        out["max_calls"] = int(c)
    return out if any_ else None


def check_limits(limits, spec):
    """The final (ttl_s, max_calls) for an approval, or None when the limits would lengthen the
    request or fall outside the allowed range. The approver may shorten, never lengthen."""
    ttl, calls = spec["ttl_s"], spec["max_calls"]
    if limits:
        if limits.get("bad"):
            return None
        t, c = limits.get("ttl_s"), limits.get("max_calls")
        if t is not None:
            if not TTL_FLOOR <= t <= ttl:
                return None
            ttl = t
        if c is not None:
            if not 1 <= c <= calls:
                return None
            calls = c
    return ttl, calls


# ---------------------------------------------------------------- html
CSS = """
.ses .meta{color:var(--muted);font-size:.8rem}
.sesbox{border:1px solid var(--warn);border-radius:.6rem;padding:.4rem .8rem;margin:.5rem 0}
.sesbox label{display:inline-flex;align-items:center;gap:.4rem;font-weight:600;font-size:.85rem;margin:.3rem .8rem .3rem 0}
.sesbox input[type=number]{font:inherit;width:6.5rem;min-height:2.25rem;padding:.2rem .5rem;border-radius:.5rem;
border:1px solid var(--line);background:var(--card);color:var(--fg)}
"""


def _fmt_ttl(s):
    if s % 3600 == 0:
        return f"{s // 3600} hr"
    if s % 60 == 0:
        return f"{s // 60} min"
    return f"{s} s"


def describe_html(req):
    """(what_html, note_html) for the card header. The purpose is shown escaped and marked as the
    agent's claim; every other value is validated text, escaped anyway."""
    sp, e = req.spec, html.escape
    na = guidance_mod.non_ascii_count(sp["purpose"])
    flag = (f" <span class='pill warn'>Non-ASCII characters: {na} (shown as U+XXXX)</span>" if na else "")
    extra = [m for m in sp["methods"] if m not in DEFAULT_METHODS]
    meth = ", ".join(sp["methods"])
    if extra:
        meth += (f" <span class='pill warn'>changes things: {e(', '.join(extra))}</span>")
    what = (f"<b>HTTP session</b> with credential <b>{e(req.names[0])}</b><br>"
            f"Purpose, as the agent put it (unverified):<div class=crpurpose>{credreq_mod._esc(sp['purpose'])}</div>{flag}"
            f"Hosts: {e(', '.join(sp['hosts']))}<br>Methods: {meth}<br>"
            f"Time limit: {e(_fmt_ttl(sp['ttl_s']))} from the moment you approve (fixed, never extended)<br>"
            f"Call cap: {sp['max_calls']} calls")
    return what, WARNING


def actions_html(broker, req):
    """The decision controls: shorten the limits if you want, then Approve or Deny. No Always, no
    timed grant, no notification button."""
    sp = req.spec
    return (
        "<div class=sesbox><small class=muted>You may shorten these; you cannot lengthen them.</small><br>"
        f"<label>Minutes <input type=number name=session_ttl_min step=any min=0.5 "
        f"max='{sp['ttl_s'] / 60:g}' value='{sp['ttl_s'] / 60:g}'></label>"
        f"<label>Max calls <input type=number name=session_max_calls step=1 min=1 "
        f"max='{sp['max_calls']}' value='{sp['max_calls']}'></label></div>"
        "<div class=decide-row><button class='btn approve' name=decision value=approve>Approve session</button>"
        "<button class='btn deny' name=decision value=deny>Deny</button></div>"
        "<p class=scope><small class=muted>Always needs you: no standing approval, grant or Always "
        "covers a session, and no notification button can approve it. Revoke it any time on the "
        "Clients tab.</small></p>")


def sessions_section(broker, csrf, now=None):
    """'Active sessions' on the Clients tab: credential, client, hosts, methods, live time left,
    calls used, Revoke."""
    e = html.escape
    rows = broker.active_sessions()
    head = ("<h2 style='margin-top:1.6rem'>Active sessions</h2><p><small class=muted>A session lets one "
            "client make a limited set of calls without asking again. It ends at its deadline (never "
            "extended), when the agent closes it, or when you revoke it here; it is also dropped if the "
            "broker restarts.</small></p>")
    if not rows:
        return head + "<div class='card empty'>No active sessions</div>"
    body = []
    for r in rows:
        left = f"<time data-gexp='{int(r['expires_at'])}'>in {max(0, -(-r['left_s'] // 60))} min</time>"
        body.append(
            f"<tr><td data-label=Credential><b>{e(r['cred'])}</b>"
            f"<br><span class=idn>session {e(r['pid'])}</span></td>"
            f"<td data-label=Client>{e(r['client_name'])}<br><span class=idn>id {e(r['client_id'])}</span></td>"
            f"<td data-label=Hosts>{e(', '.join(r['hosts']))}</td>"
            f"<td data-label=Methods>{e(', '.join(r['methods']))}</td>"
            f"<td data-label='Time left'>{left}</td>"
            f"<td data-label=Calls>{r['calls']} / {r['max_calls']}</td>"
            "<td><form method=post action='/sessions/revoke' class=inline>"
            f"<input type=hidden name=csrf value='{e(csrf)}'><input type=hidden name=pid value='{e(r['pid'])}'>"
            "<button class='btn deny'>Revoke</button></form></td></tr>")
    return (head + "<div class='cl ses'><table class=tbl><thead><tr><th>Credential</th><th>Client</th><th>Hosts</th>"
            "<th>Methods</th><th>Time left</th><th>Calls</th><th></th></tr></thead><tbody>"
            + "".join(body) + "</tbody></table></div>")


# ---------------------------------------------------------------- broker mixin
class SessionsMixin:
    """Methods mixed into Broker. Needs: cfg, log, audit, _lock, _by_id, _by_nonce, clients, _finish,
    _release helpers, _new_request, _retain_details."""

    def _init_sessions(self, config):
        self.sessions_cfg = parse_config(config.get("sessions"))
        self.sessions_clock = lambda: time.time()      # injectable (tests); the deadline is read from it
        self._sess = {}                                # sha256(id) -> Session
        self._sess_tomb = OrderedDict()                # sha256(id) -> {"cid", "reason", "t"}
        self._sess_lock = threading.Lock()
        threading.Thread(target=self._sessions_sweeper, daemon=True).start()

    def _sessions_sweeper(self):
        while True:
            time.sleep(SWEEP_S)
            try:
                self.sweep_sessions()
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    @staticmethod
    def _skey(sid):
        return hashlib.sha256(sid.encode()).hexdigest()

    # -- state transitions (callers hold _sess_lock) ---------------------------------
    def _sess_end_locked(self, s, reason, now, actor=None, **extra):
        """Remove an active session, drop everything it holds, remember why, audit it. `reason` is
        expired | closed | revoked."""
        self._sess.pop(self._skey(s.id), None)
        used = s.calls
        s.drop()
        self._sess_tomb[self._skey(s.id)] = {"cid": s.cid, "reason": reason, "t": now}
        while len(self._sess_tomb) > MAX_TOMBSTONES:
            self._sess_tomb.popitem(last=False)
        fields = {"session": s.pid, "client_id": s.cid, "client_name": s.cname, "calls": used,
                  "max_calls": s.max_calls, "unused": used == 0, "lifetime_s": max(0, int(now - s.opened)),
                  "names": [s.cred]}
        if actor is not None:
            fields["revoked_by"] = actor
        self.log("session_" + reason, **fields, **extra)

    def _sess_lookup(self, sid, cid, now):
        """(Session or None, state) for `sid` as seen by client `cid`: ok | unknown | expired | closed |
        revoked. Another client's session, a malformed id and a made-up id are all `unknown`. An expired
        session is ended here (and audited) if the sweeper has not got to it yet. Caller holds _sess_lock."""
        if not isinstance(sid, str) or not SID_RE.match(sid):
            return None, "unknown"
        k = self._skey(sid)
        s = self._sess.get(k)
        if s is not None:
            if not hmac.compare_digest(s.id.encode(), sid.encode()) or s.cid != cid:
                return None, "unknown"
            if now >= s.expires:
                self._sess_end_locked(s, "expired", now)
                return None, "expired"
            return s, "ok"
        t = self._sess_tomb.get(k)
        if t is not None and t["cid"] == cid and now - t["t"] < TOMBSTONE_S:
            return None, t["reason"]
        return None, "unknown"

    def sweep_sessions(self):
        """End every session past its deadline (even when nobody calls) and forget old tombstones.
        Returns how many expired."""
        now = self.sessions_clock()
        n = 0
        with self._sess_lock:
            for s in list(self._sess.values()):
                if now >= s.expires:
                    self._sess_end_locked(s, "expired", now)
                    n += 1
            for k in [k for k, t in self._sess_tomb.items() if now - t["t"] >= TOMBSTONE_S]:
                del self._sess_tomb[k]
        return n

    def active_sessions(self):
        """Rows for the Clients tab, soonest-expiring first."""
        self.sweep_sessions()
        now = self.sessions_clock()
        with self._sess_lock:
            rows = [{"pid": s.pid, "cred": s.cred, "client_id": s.cid, "client_name": s.cname,
                     "hosts": list(s.hosts), "methods": list(s.methods), "expires_at": s.expires,
                     "left_s": max(0, int(s.expires - now)), "calls": s.calls, "max_calls": s.max_calls}
                    for s in self._sess.values()]
        return sorted(rows, key=lambda r: r["expires_at"])

    def session_counts(self, cid):
        with self._sess_lock:
            return sum(s.cid == cid for s in self._sess.values()), len(self._sess)

    # -- opening ---------------------------------------------------------------------
    def _validate_session(self, names, spec, client):
        """Validate an agent's open request and rewrite `spec` to what the card shows."""
        if not self.sessions_cfg["enabled"]:
            raise PermissionError("http sessions are disabled")
        if len(names) != 1 or not isinstance(names[0], str):
            raise ValueError("a session uses exactly one credential")
        sc = self.cfg["secrets"].get(names[0])
        if sc is None:
            if not self._backend_ok:
                raise ValueError("unknown secret name, but the credential backend is not healthy "
                                 "(ask the operator to check `asb status`)")
            raise ValueError("unknown secret name")
        if sc.get("ssh"):
            raise PermissionError("an ssh key can only be used to sign (asb ssh-agent); a session is for "
                                  "http credentials")
        if not sc.get("allowed_hosts"):
            raise PermissionError("this credential has no allowed hosts, so it is not an http credential; "
                                  "a session works only with http credentials")
        out = validate_open(self.sessions_cfg, spec, sc["allowed_hosts"])
        spec.clear()
        spec.update(out)

    def _session_pending(self, req):
        """Hand a validated open request to the human: high by code with no model call, notified
        without any action button, decided only on the approval site."""
        from . import risk as risk_mod
        a = risk_mod.assess("session", req.names, {}, None)
        req.risk = {k: a[k] for k in ("level", "model", "reasons")}
        self.audit("assessed", req, model=None, reasons=a["reasons"], summary_source=None, summary_reason=None)
        sp = req.spec
        self.audit("session_requested", req, hosts=sp["hosts"], methods=sp["methods"], ttl_s=sp["ttl_s"],
                   max_calls=sp["max_calls"])
        try:
            self._push(req)
        except Exception:  # noqa: BLE001 -- the card is on the page whatever the transport does
            self._finish(req, "failed", error="could not notify")
        return req

    def _session_open(self, req, who):
        """The human approved: create the session. Returns the result handed to the agent once."""
        sp, cid, now = req.spec, req.client["id"], self.sessions_clock()
        ttl, calls = sp["final"]
        if not self.clients.is_active(cid):
            raise SessionOpenError("this client was revoked")
        sc = self.cfg["secrets"].get(req.names[0])
        if sc is None or sc.get("ssh") or not sc.get("allowed_hosts"):
            raise SessionOpenError("the credential is no longer available for http")
        if any(h not in sc["allowed_hosts"] for h in sp["hosts"]):
            raise SessionOpenError("a host is no longer allowed for this credential")
        with self._sess_lock:
            mine = sum(s.cid == cid for s in self._sess.values())
            if mine >= self.sessions_cfg["max_per_client"] or len(self._sess) >= MAX_TOTAL:
                raise SessionOpenError("too many open sessions")
            sid = secrets.token_urlsafe(24)
            while any(s.pid == sid[:8] for s in self._sess.values()):
                sid = secrets.token_urlsafe(24)
            s = Session(sid, sid[:8], req.client, req.names[0], sp["hosts"], sp["methods"], ttl, calls, now,
                        sp["purpose"], who.get("approver"), self.sessions_clock)
            self._sess[self._skey(sid)] = s
        self.audit("session_opened", req, session=s.pid, hosts=sp["hosts"], methods=sp["methods"], ttl_s=ttl,
                   max_calls=calls, expires_at=int(s.expires), shortened=(ttl, calls) != (sp["ttl_s"], sp["max_calls"]))
        return {"session": {"id": sid, "expires_in": ttl, "hosts": sp["hosts"], "methods": sp["methods"],
                            "max_calls": calls}}

    # -- using -----------------------------------------------------------------------
    def _refuse(self, client, sess, reason, message, code="session_refused", http=403, **fields):
        """Audit a refused call (class only) and raise the fixed error."""
        self.log("session_refused", session=sess.pid if sess else None, reason_class=reason,
                 client_id=client["id"], client_name=client["name"], **fields)
        raise SessionError(message, code, http)

    _MISSING = {"unknown": ("unknown session", "session_unknown", 404),
                "expired": ("session expired: it reached its time limit and cannot be extended; open a new "
                            "one with `asb session open`", "session_expired", 410),
                "closed": ("session closed; open a new one with `asb session open`", "session_expired", 410),
                "revoked": ("session revoked by the human; do not reopen it without asking",
                            "session_expired", 410)}

    def _session_call(self, names, spec, source, peer, client):
        """A `--session` http call: released with no prompt and no model verdict when it is inside
        the session's scope, refused (never prompted) otherwise. Returns the finished request."""
        client = client or dict(clients_mod.ClientStore.LEGACY_VIEW)
        cid, now = client["id"], self.sessions_clock()
        if not self.sessions_cfg["enabled"]:
            raise PermissionError("http sessions are disabled")
        for k in ("method", "url", "headers"):
            if k not in spec:
                raise ValueError("bad request")
        if not isinstance(spec["headers"], dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in spec["headers"].items()):
            raise ValueError("headers must be text")
        try:
            expr = [parse_capture(x) for x in (spec.get("capture") or [])]
        except TypeError:
            raise ValueError("bad capture expression") from None
        if len(expr) > MAX_CAPTURE_EXPRS or len({e[0] for e in expr}) != len(expr):
            raise ValueError("too many or repeated capture names")
        if spec.get("body_b64") is not None:
            import base64
            import binascii
            try:
                base64.b64decode(spec["body_b64"], validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("body_b64 is not valid base64") from None
            if spec.get("body") is not None:
                raise ValueError("send body or body_b64, not both")
        sid = spec.get("session")
        method = spec["method"].upper()
        scheme, host, _ = _host_of(spec["url"])
        with self._sess_lock:
            s, state = self._sess_lookup(sid, cid, now)
            problem = None
            if s is None:
                problem = ("missing", state)
            else:
                problem = scope_problem(s, self.cfg["secrets"].get(s.cred), names, method, spec)
                if problem is None:
                    s.calls += 1
                    calls_now, max_calls = s.calls, s.max_calls
        if problem is not None:
            kind, text = problem
            if kind == "missing":
                msg, code, http = self._MISSING[text]
                self.log("session_refused", session=None, reason_class=text, client_id=cid,
                         client_name=client["name"], method=method, host=host or None)
                raise SessionError(msg, code, http)
            self._refuse(client, s, kind, text, method=method, host=host or None)
        req = self._new_request("http", list(names), {
            "method": method, "url": spec["url"], "headers": dict(spec["headers"]), "body": spec.get("body"),
            "body_b64": spec.get("body_b64"), "capture_expr": expr}, source, 30, peer, client)
        req.session = s
        with self._lock:
            self._by_id[req.id] = req
            self._by_nonce[req.nonce] = req
        self.audit("requested", req)
        self._retain_details(req)
        self.audit("session_used", req, session=s.pid, host=host, calls=calls_now, max_calls=max_calls,
                   left_s=max(0, int(s.expires - now)))
        try:
            result = self._release(req)
        except Exception as e:  # noqa: BLE001 -- the request must always settle; never repeat the text
            if getattr(e, "public", None):
                err = e.public
            elif isinstance(e, BackendError):
                err = "release failed (credential store)"
            else:
                err = "upstream call failed (" + coarse_class(e) + ")"
            self._finish(req, "failed", error=err, via="session")
            return req
        self._finish(req, "approved", result=result, via="session")
        return req

    def _session_http(self, req, env):
        """Execute one session call (called from _release with the credential values read)."""
        from . import broker as broker_mod
        s, t0 = req.session, time.time()
        sc = self.cfg["secrets"].get(req.names[0]) or {}
        try:
            out, info = run_http(s, req.spec, env, self._tls_policy(req.names), set(sc.get("allowed_hosts") or []),
                                 broker_mod._opener_for, broker_mod._mask, req.spec.get("capture_expr") or [])
        except SessionError:
            raise
        except Exception as e:  # noqa: BLE001 -- class only, never the exception's text
            cls = coarse_class(e)
            self.audit("http_failed", req, error=cls, session=s.pid)
            err = OSError("upstream call failed (" + cls + ")")
            err.public = "upstream call failed (" + cls + ")"
            raise err from None
        self.audit("http_executed", req, upstream_status=out["status"], response_bytes=len(out["body"]),
                   duration_ms=int((time.time() - t0) * 1000), session=s.pid)
        left = max(0, int(s.expires - self.sessions_clock()))
        return {"http": out, "session": {**info, "calls_left": max(0, s.max_calls - s.calls), "expires_in": left}}

    # -- ending ----------------------------------------------------------------------
    def session_close(self, sid, client):
        """The agent closes its own session. True when it was open; otherwise the same answer for
        unknown, other-client and already-ended ids is raised as a SessionError by the caller."""
        cid, now = client["id"], self.sessions_clock()
        with self._sess_lock:
            s, state = self._sess_lookup(sid, cid, now)
            if s is None:
                return state
            self._sess_end_locked(s, "closed", now)
        return "closed"

    def session_status(self, sid, client):
        cid, now = client["id"], self.sessions_clock()
        with self._sess_lock:
            s, state = self._sess_lookup(sid, cid, now)
            if s is None:
                return state, None
            return "ok", {"expires_in": max(0, int(s.expires - now)), "calls_left": max(0, s.max_calls - s.calls),
                          "calls": s.calls, "max_calls": s.max_calls, "hosts": list(s.hosts),
                          "methods": list(s.methods), "names": [s.cred]}

    def revoke_session(self, pid, actor, peer=None, client_ip=None):
        """The human revokes one session (by its public prefix). True when it was active."""
        now = self.sessions_clock()
        with self._sess_lock:
            s = next((x for x in self._sess.values() if x.pid == pid), None)
            if s is None:
                return False
            self._sess_end_locked(s, "revoked", now, actor=actor, peer=peer, client_ip=client_ip)
        return True

    def revoke_client_sessions(self, cid, actor):
        """Every session of a revoked client ends now. Returns how many."""
        now = self.sessions_clock()
        with self._sess_lock:
            mine = [s for s in self._sess.values() if s.cid == cid]
            for s in mine:
                self._sess_end_locked(s, "revoked", now, actor=actor)
        return len(mine)
