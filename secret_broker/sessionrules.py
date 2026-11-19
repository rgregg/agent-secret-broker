"""Auto-approve rules for sessions: modes `http_session` and `ws_session` (see autorules.py for the rest).

A session is a window of many calls, so a rule here BOUNDS the window instead of naming one request. A session open
request matches a rule only when its whole manifest is a SUBSET of what the rule allows, and the session it gets is
cut down to the rule's caps. This module is the one place that knows what the fields are (`parse`, `serialize`,
`describe`) and the one place that decides whether a manifest is inside a rule (`within`). The config
`auto_approve` list, the rules stored on a credential and the Policies-page form all go through `parse`; the matcher
(`autorules.find`) and the approval path both go through `within`. A check that read the manifest differently from the
way the session will run it could be bypassed, so the manifest is read with the session's own host parser
(`sessions.parse_host_entry`) and anything unreadable does not match.

    "auto_approve": [
      {"name": "unifi reads", "mode": "http_session", "secret": "unifi", "hosts": ["unifi.example.com:443"],
       "methods": ["GET", "HEAD"], "max_ttl_s": 600, "max_calls": 50, "clients": ["c-1a2b3c4d"]},
      {"name": "ha stream", "mode": "ws_session", "secret": "ha", "host": "ha.example.com", "scheme": "wss",
       "port": 443, "path_prefix": "/api/websocket", "max_ttl_s": 900, "max_frames": 500}
    ]

  * `http_session`: `hosts` (required, `host` or `host:port` as in a session manifest: a bare host means ports 80 and
    443), `methods` (default GET and HEAD). A http session manifest carries no path, so there is no `path_prefix`:
    a rule could not verify one.
  * `ws_session`: `host`, `scheme` (default `wss`), `port` (default 443, or 80 for `ws`), `path_prefix` (required),
    `allow_query` (default false: a manifest with a query string does not match).
  * Both need `max_ttl_s` and `max_calls` (`max_frames` for ws). The session gets the lower of what it asked for and
    what the rule allows, so a rule can never open an unbounded session.
"""
import re
import urllib.parse

from . import sessions as S

MODES = ("http_session", "ws_session")
COMMON = {"name", "mode", "secret", "secrets", "clients"}
KEYS = {
    "http_session": {"hosts", "methods", "max_ttl_s", "max_calls"},
    "ws_session": {"scheme", "host", "port", "path_prefix", "allow_query", "max_ttl_s", "max_frames"},
}
WS_FRAMES_CEIL = 100_000
_METHOD = re.compile(r"[A-Z]{3,10}")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
DEFAULT_HOST_PORTS = (80, 443)


# ---------------------------------------------------------------- text helpers shared with autorules
def valid_prefix(prefix):
    """A path prefix a rule may hold: absolute, plain, no query, no `..`."""
    return (isinstance(prefix, str) and prefix.startswith("/") and len(prefix) <= 255 and "?" not in prefix
            and not re.search(r"[\x00-\x20\x7f]", prefix) and ".." not in prefix.split("/"))


def path_under(path, prefix):
    """`path` is `prefix` or below it, by whole segments ('/v1' covers '/v1/x', not '/v10')."""
    if prefix == "/":
        return True
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def plain_path(path):
    """True for a path with nothing a server could read differently from a rule: no percent-escape, `;` parameter,
    backslash, control character, space or dot segment."""
    return not re.search(r"[%;\\\x00-\x20\x7f]", path) and not any(seg in (".", "..") for seg in path.split("/"))


# ---------------------------------------------------------------- parsing
def _bad(where, field, what):
    raise ValueError(f"{where}.{field} {what}")


def _cap(r, field, where, lo, hi):
    v = r.get(field)
    if not S._int(v) or not lo <= v <= hi:
        _bad(where, field, f"is required: a whole number from {lo} to {hi} (the most a session opened by this rule may get)")
    return v


def parse(mode, r, where):
    """The mode's own fields of rule object `r` -> a dict to merge into the normalized rule. ValueError names
    `where.field` and never repeats a value. The caller has already checked the common fields and that no key is
    outside COMMON | KEYS[mode]."""
    out = {}
    if mode == "http_session":
        hosts = r.get("hosts")
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= S.MAX_HOSTS:
            _bad(where, "hosts", f"is required: 1 to {S.MAX_HOSTS} entries, each host or host:port")
        try:
            parsed = [S.parse_host_entry(h) for h in hosts]
        except ValueError:
            _bad(where, "hosts", "must be plain host names, each optionally with :port (no scheme or path)")
        out["hosts"] = tuple(sorted({h if p is None else f"{h}:{p}" for h, p in parsed}))
        methods = r.get("methods", list(S.DEFAULT_METHODS))
        if (not isinstance(methods, list) or not 1 <= len(methods) <= len(S.METHODS_ALL)
                or not all(isinstance(m, str) and _METHOD.fullmatch(m) and m in S.METHODS_ALL for m in methods)):
            _bad(where, "methods", "must be upper-case HTTP methods such as GET (" + ", ".join(S.METHODS_ALL) + ")")
        out["methods"] = frozenset(methods)
        out["max_calls"] = _cap(r, "max_calls", where, 1, S.CALLS_CEIL)
    else:
        host = r.get("host")
        if not isinstance(host, str) or not _HOST.fullmatch(host.lower()):
            _bad(where, "host", "is required (a host name, no scheme or port)")
        scheme = r.get("scheme", "wss")
        if scheme not in ("wss", "ws"):
            _bad(where, "scheme", "must be \"wss\" (the default) or \"ws\"")
        port = r.get("port", 443 if scheme == "wss" else 80)
        if not S._int(port) or not 1 <= port <= 65535:
            _bad(where, "port", "must be a whole number from 1 to 65535")
        prefix = r.get("path_prefix")
        if not valid_prefix(prefix):
            _bad(where, "path_prefix", "is required: a path starting with '/' (no query, no '..'); use '/' for any path")
        allow_query = r.get("allow_query", False)
        if not isinstance(allow_query, bool):
            _bad(where, "allow_query", "must be true or false")
        out.update(host=host.lower(), scheme=scheme, port=port, path_prefix=prefix, allow_query=allow_query,
                   max_calls=_cap(r, "max_frames", where, 1, WS_FRAMES_CEIL))
    out["max_ttl_s"] = _cap(r, "max_ttl_s", where, S.TTL_FLOOR, S.TTL_CEIL)
    return out


def serialize(rule):
    """The JSON form of a parsed rule's own fields, as `parse` reads it back."""
    if rule["mode"] == "http_session":
        return {"hosts": list(rule["hosts"]), "methods": sorted(rule["methods"]),
                "max_ttl_s": rule["max_ttl_s"], "max_calls": rule["max_calls"]}
    d = {"host": rule["host"], "path_prefix": rule["path_prefix"], "max_ttl_s": rule["max_ttl_s"],
         "max_frames": rule["max_calls"]}
    if rule["scheme"] != "wss":
        d["scheme"] = rule["scheme"]
    if rule["port"] != (443 if rule["scheme"] == "wss" else 80):
        d["port"] = rule["port"]
    if rule["allow_query"]:
        d["allow_query"] = True
    return d


def _minutes(s):
    return f"{s // 60} min" if s % 60 == 0 else f"{s} s"


def describe(rule):
    """What a session rule allows, as text for the rule tables (closed set of validated fields)."""
    if rule["mode"] == "http_session":
        return (f"HTTP session on {', '.join(S.host_label(h) for h in rule['hosts'])} "
                f"({', '.join(sorted(rule['methods']))}), up to {_minutes(rule['max_ttl_s'])} and "
                f"{rule['max_calls']} calls")
    q = ", query allowed" if rule["allow_query"] else ""
    return (f"WebSocket session on {rule['scheme']}://{rule['host']}:{rule['port']}{rule['path_prefix']}{q}, "
            f"up to {_minutes(rule['max_ttl_s'])} and {rule['max_calls']} frames")


# ---------------------------------------------------------------- the one subset check
def _ports(entry):
    host, port = S.parse_host_entry(entry)
    return host, (set(DEFAULT_HOST_PORTS) if port is None else {port})


def _limits(rule, spec):
    ttl, calls = spec.get("ttl_s"), spec.get("max_calls")
    if not S._int(ttl) or not S._int(calls) or ttl < 1 or calls < 1:
        return None
    return min(ttl, rule["max_ttl_s"]), min(calls, rule["max_calls"])


def _http_within(rule, spec):
    hosts, methods = spec.get("hosts"), spec.get("methods")
    if (not isinstance(hosts, list) or not hosts or not isinstance(methods, list) or not methods
            or not all(isinstance(m, str) for m in methods) or not all(isinstance(h, str) for h in hosts)):
        return None
    allowed = {}
    for entry in rule["hosts"]:
        host, ports = _ports(entry)
        allowed.setdefault(host, set()).update(ports)
    for entry in hosts:
        host, ports = _ports(entry)
        if not ports <= allowed.get(host, set()):
            return None
    if not set(methods) <= rule["methods"]:
        return None
    return _limits(rule, spec)


def _ws_within(rule, spec):
    scheme, host, port, target = (spec.get(k) for k in ("scheme", "host", "port", "target"))
    if (not isinstance(scheme, str) or not isinstance(host, str) or not S._int(port)
            or not isinstance(target, str) or spec.get("kind") != "ws"):
        return None
    if scheme != rule["scheme"] or host != rule["host"] or port != rule["port"]:
        return None
    if spec.get("hosts") != [f"{host}:{port}"]:            # the card's list and the fields agree, or nothing matches
        return None
    path, qmark, query = target.partition("?")
    if not path.startswith("/") or not plain_path(path) or not path_under(path, rule["path_prefix"]):
        return None
    if qmark and (not rule["allow_query"] or not_plain(query)):
        return None
    return _limits(rule, spec)


def not_plain(text):
    """True for text a rule cannot reason about: it still changes when decoded a second time (`%255f`), carries
    a unicode escape, or is not plain printable ASCII."""
    once = urllib.parse.unquote_plus(text)
    return (once != text and urllib.parse.unquote_plus(once) != once) or "\\u" in text.lower() \
        or not all(c in "\t\r\n" or " " <= c <= "~" for c in text)


def within(rule, mode, spec):
    """The (ttl_s, max_calls) a session open request would get under `rule`, or None when the request does not
    match: the mode differs, or any part of the manifest `spec` (the validated open request) is outside the rule.
    Never raises: anything unreadable does not match."""
    if rule.get("mode") != mode or mode not in MODES or not isinstance(spec, dict):
        return None
    try:
        return (_http_within if mode == "http_session" else _ws_within)(rule, spec)
    except (ValueError, TypeError, KeyError):
        return None
