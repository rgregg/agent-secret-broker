"""Plan mode: task-scoped grants for unattended jobs (issue #5; design in docs/proposals/task-plans.md).

An agent writes a manifest of the calls a job will make. A human reads a code-generated rendering
of every rule once and approves the whole plan, with a stopwatch, for one client. While the plan
lives, an `asb http ... --plan ID` call that matches a rule EXACTLY is released without a prompt;
anything else is refused (never turned into a prompt). Nothing here calls a model.

What lives where:
  * config parsing (`parse_config`, the per-client override lives in clients.py);
  * manifest validation and canonical hashing (`validate_manifest`, `rules_hash`, `manifest_hash`);
  * the deterministic matcher (`freeze`, `match_rule`, `substitute`): strict JSON, GraphQL
    classification, host/URL/path/header/body rules, one parse, fail closed;
  * deterministic risk tiers (`rule_tier`, `plan_tier`) and the approval card (`describe_html`);
  * the in-memory `PlanStore` (memory only: a restart drops every plan).

Invariants (tests/test_plans.py, test_plan_card.py, test_plan_e2e.py):
  * a plan is bound to the authenticated client id; the plan id is an identifier, never a bearer;
    unknown, expired and wrong-client ids all get the SAME 404;
  * the matcher runs on the exact frozen request that is sent; any doubt is a non-match;
  * a use is reserved under the store lock before the upstream call, in the same critical section
    as the checks; failed upstream calls still count; the in-flight slot is released in a finally;
  * the manifest's `task` and `description` are untrusted text: hidden characters are refused, every
    non-ASCII character is shown as <U+XXXX>, they are never in a notification or any audit record
    (length and hash prefix only) and never given to a model;
  * no exception text anywhere: refusals are fixed strings with a coarse reason class.
"""
import hashlib
import html
import hmac
import ipaddress
import json
import math
import re
import secrets
import threading
import time
from collections import deque

from . import clock as clock_mod
from . import guidance as guidance_mod

# ---------------------------------------------------------------- constants
SCHEMA_VERSION = 1
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
MAX_ID_AGE_S = 3600                  # a terminal plan stays visible to its owner and to History this long
MAX_PLANS = 500                      # records held (any state); beyond it a submit is a 429
MAX_TASK, MAX_DESC = 80, 400
MAX_DOC, MAX_PIN_STR, MAX_KEYS = 4096, 200, 32
MAX_PREFIX = 200
RATE_WINDOW_S = 60
MISS_PER_MIN = 5                     # plan_miss records written per key per minute
MISS_KEYS_MAX = 4096
DENY_COOLDOWN_S = 60                 # same client + same task name after a denial
TWO_53 = 2 ** 53
STANDARD_MINUTES = (480, 240, 60, 30, 15)     # the durations the card offers, never above the request
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_OPNAME_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,63}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_PREFIX_RE = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,=:@/-]*$")
_HDR_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
_URL_RE = re.compile(r"^[\x21-\x7e]{1,4096}$")
_URL_BAD = re.compile(r"[\\\"<>^`{}|]")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")
_NETLOC_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$")
_PLACEHOLDER_HDR = re.compile(r"^(?:([A-Za-z][A-Za-z0-9_-]{0,19}) )?\{\{ ?([A-Z][A-Z0-9_]{0,60}) ?\}\}$")
_CT_JSON = re.compile(r"^application/json(?:; ?charset=utf-8)?$")
_DIGITS = re.compile(r"^(0|[1-9][0-9]{0,15})$")
_QKEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# URL query parameters that can override the method or replace parts of a body upstream. Refused in
# every plan call, whatever the rule says.
_QUERY_OVERRIDES = frozenset((
    "_method", "method", "_http_method", "http_method", "x-http-method-override", "x_http_method_override",
    "_httpmethod", "operationname", "variables", "extensions", "_body", "body", "_json"))
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

# Headers a plan call may never carry, whatever the configuration says: they change how the
# request is routed, framed or interpreted.
_FORBIDDEN_HEADERS = frozenset((
    "host", "transfer-encoding", "te", "upgrade", "connection", "keep-alive", "trailer",
    "proxy-authorization", "proxy-authenticate", "proxy-connection", "forwarded", "via",
    "x-http-method-override", "x-http-method", "x-method-override", "x-real-ip", "x-original-url",
    "x-rewrite-url", "expect", "content-encoding", "content-range", "range", "x-forwarded-for"))
_FORBIDDEN_PREFIXES = ("x-forwarded-", "x-envoy-", "x-original-")

DEFAULTS = {
    "enabled": True, "default_minutes": 30, "max_minutes": 480, "pending_ttl_s": 900,
    "max_rules": 20, "max_uses_per_rule": 500, "max_total_uses": 2000, "rate_per_min": 30,
    "max_inflight": 4, "max_body_bytes": 16384, "max_pending": 2, "max_active_per_client": 2,
    "allow_any_body": False, "allow_root_prefix": False, "allow_graphql_mutation": False,
    "allow_legacy": False,
    "allowed_request_headers": ["Accept", "Content-Type", "Content-Length", "If-None-Match", "User-Agent"],
    "deny_secrets": [],
}
MINUTES_CEILING = 720
_BOOLS = ("enabled", "allow_any_body", "allow_root_prefix", "allow_graphql_mutation", "allow_legacy")
_RANGES = {"default_minutes": (1, MINUTES_CEILING), "max_minutes": (1, MINUTES_CEILING),
           "pending_ttl_s": (120, 3600), "max_rules": (1, 50), "max_uses_per_rule": (1, 10000),
           "max_total_uses": (1, 100000), "rate_per_min": (1, 600), "max_inflight": (1, 32),
           "max_body_bytes": (1, 262144), "max_pending": (1, 10), "max_active_per_client": (1, 10)}

# Why a call did not match (the coarse class the agent sees).
REASONS = ("no_rule", "uses_exhausted", "session_ended", "wrong_policy", "rate_limited", "inflight_limit")
KINDS = ("ended", "exhausted", "closed", "revoked", "unknown")
STATES = ("pending", "denied", "expired", "active", "closed", "revoked", "ended", "exhausted")
_TERMINAL = ("denied", "expired", "closed", "revoked", "ended", "exhausted")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def valid_id(v):
    return isinstance(v, str) and _ID_RE.match(v) is not None


def parse_config(raw, field="plans"):
    """Validate the `plans` object -> normalized dict. None means the defaults. Raises ValueError
    naming the offending field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"{field}.{k} is not a known option")
    out = {**DEFAULTS, **raw}
    out["allowed_request_headers"] = list(out["allowed_request_headers"]) if isinstance(
        out["allowed_request_headers"], list) else out["allowed_request_headers"]
    for k in _BOOLS:
        if not isinstance(out[k], bool):
            raise ValueError(f"{field}.{k} must be true or false")
    for k, (lo, hi) in _RANGES.items():
        if not _int(out[k]) or not lo <= out[k] <= hi:
            raise ValueError(f"{field}.{k} must be a whole number from {lo} to {hi}")
    if out["default_minutes"] > out["max_minutes"]:
        raise ValueError(f"{field}.default_minutes must not be above {field}.max_minutes")
    if out["max_total_uses"] < out["max_uses_per_rule"]:
        raise ValueError(f"{field}.max_total_uses must not be below {field}.max_uses_per_rule")
    hs = out["allowed_request_headers"]
    if not isinstance(hs, list) or len(hs) > 20 or not all(isinstance(h, str) and _HDR_NAME_RE.match(h) for h in hs):
        raise ValueError(f"{field}.allowed_request_headers must be a list of up to 20 header names")
    for h in hs:
        if _forbidden_header(h):
            raise ValueError(f"{field}.allowed_request_headers may not include a routing or framing header")
    ds = out["deny_secrets"]
    if not isinstance(ds, list) or len(ds) > 200 or not all(isinstance(n, str) and _NAME_RE.match(n) for n in ds):
        raise ValueError(f"{field}.deny_secrets must be a list of credential names")
    out["deny_secrets"] = sorted(set(ds))
    out["allowed_request_headers"] = list(dict.fromkeys(hs))
    return out


def parse_client_override(raw, at):
    """Validate one client's `plans` override -> {"enabled"?, "max_minutes"?}. ValueError names the field."""
    if not isinstance(raw, dict):
        raise ValueError(f"{at} must be an object")
    extra = sorted(set(raw) - {"enabled", "max_minutes"})
    if extra:
        raise ValueError(f"{at}.{extra[0]} is not a known option (enabled, max_minutes)")
    out = {}
    if "enabled" in raw:
        if not isinstance(raw["enabled"], bool):
            raise ValueError(f"{at}.enabled must be true or false")
        out["enabled"] = raw["enabled"]
    if "max_minutes" in raw:
        mm = raw["max_minutes"]
        if not _int(mm) or not 1 <= mm <= MINUTES_CEILING:
            raise ValueError(f"{at}.max_minutes must be a whole number from 1 to {MINUTES_CEILING}")
        out["max_minutes"] = mm
    return out


def describe_config(cfg):
    """One line for the Settings page."""
    if not cfg["enabled"]:
        return "Plans are turned off"
    return (f"Plans: on, up to {_hm(cfg['max_minutes'] * 60)} each, {cfg['max_active_per_client']} active per "
            f"client, {cfg['rate_per_min']} calls a minute at most")


def _forbidden_header(name):
    n = name.lower()
    return n in _FORBIDDEN_HEADERS or n.startswith(_FORBIDDEN_PREFIXES)


# ---------------------------------------------------------------- strict JSON
class StrictError(ValueError):
    """The text is not acceptable JSON for a plan. The message is a fixed class, never the text."""


def _no_const(_name):
    raise StrictError("non-finite number")


def _int_hook(text):
    v = int(text)
    if abs(v) > TWO_53:
        raise StrictError("integer too large")
    return v


def _float_hook(text):
    v = float(text)
    if not math.isfinite(v):
        raise StrictError("non-finite number")
    return v


def _pairs(items):
    out = {}
    for k, v in items:
        if k in out:
            raise StrictError("duplicate key")
        out[k] = v
    return out


def _walk(v, depth, max_depth, max_members):
    """Nesting and size limits, and no lone surrogate anywhere (keys included)."""
    if depth > max_depth:
        raise StrictError("nesting too deep")
    if isinstance(v, str):
        if _has_surrogate(v):
            raise StrictError("lone surrogate")
    elif isinstance(v, dict):
        if len(v) > max_members:
            raise StrictError("too many members")
        for k, x in v.items():
            if _has_surrogate(k):
                raise StrictError("lone surrogate")
            _walk(x, depth + 1, max_depth, max_members)
    elif isinstance(v, list):
        for x in v:
            _walk(x, depth + 1, max_depth, max_members)


def _has_surrogate(s):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def strict_loads(raw, max_depth=8, max_members=64):
    """Parse JSON (bytes or str) or raise StrictError: duplicate keys at any depth, NaN/Infinity,
    integers beyond 2**53, lone surrogates, a leading BOM, trailing data, nesting over `max_depth`,
    more than `max_members` members in an object, invalid UTF-8."""
    try:
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw)
            if raw.startswith(b"\xef\xbb\xbf"):
                raise StrictError("byte order mark")
            text = raw.decode("utf-8")
        else:
            text = raw
        if text.startswith("\ufeff"):
            raise StrictError("byte order mark")
        v = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_const,
                       parse_int=_int_hook, parse_float=_float_hook)
        _walk(v, 1, max_depth, max_members)
        return v
    except StrictError:
        raise
    except (ValueError, RecursionError, TypeError, OverflowError):
        raise StrictError("not valid JSON") from None


# ---------------------------------------------------------------- GraphQL
_GQL_WRITE_RE = re.compile(r"mutation|subscription", re.I)


def _gql_tokens(doc):
    """Tokens of a GraphQL document with strings and comments removed, or None when the text is
    not tokenizable (unterminated string, stray character). Names, numbers and punctuation only."""
    toks, i, n = [], 0, len(doc)
    while i < n:
        c = doc[i]
        if c in " \t\n,":
            i += 1
        elif c == "#":
            while i < n and doc[i] != "\n":
                i += 1
        elif c == '"':
            if doc.startswith('"""', i):
                i += 3
                while True:
                    j = doc.find('"""', i)
                    if j < 0:
                        return None
                    if doc[j - 1:j] == "\\":
                        i = j + 3
                        continue
                    i = j + 3
                    break
            else:
                i += 1
                while i < n and doc[i] != '"':
                    if doc[i] == "\n":
                        return None
                    i += 2 if doc[i] == "\\" else 1
                if i >= n:
                    return None
                i += 1
            toks.append("<str>")
        elif c.isascii() and (c.isalpha() or c == "_"):
            j = i + 1
            while j < n and doc[j].isascii() and (doc[j].isalnum() or doc[j] == "_"):
                j += 1
            toks.append(doc[i:j])
            i = j
        elif c.isascii() and (c.isdigit() or c == "-"):
            j = i + 1
            while j < n and doc[j].isascii() and (doc[j].isalnum() or doc[j] in "+-."):
                j += 1
            toks.append("<num>")
            i = j
        elif c in "{}()[]:=!$@&|" or doc.startswith("...", i):
            if doc.startswith("...", i):
                toks.append("...")
                i += 3
            else:
                toks.append(c)
                i += 1
        else:
            return None
    return toks


def classify_graphql(doc):
    """(kind, operations): kind is "read" for a document that is a pure query, else "write". A
    document is a write when the text contains `mutation` or `subscription` ANYWHERE (strings and
    comments too, on purpose) or cannot be parsed. `operations` is the number of operation
    definitions (0 when unparsable)."""
    if _GQL_WRITE_RE.search(doc):
        return "write", _count_ops(doc) or 0
    ops = _count_ops(doc)
    if ops is None or ops == 0:
        return "write", 0
    return "read", ops


def _count_ops(doc):
    toks = _gql_tokens(doc)
    if not toks:
        return None
    depth = paren = ops = 0
    start = True
    for t in toks:
        if t in "([":
            paren += 1
            continue
        if t in ")]":
            paren -= 1
            if paren < 0:
                return None
            continue
        if paren:
            continue
        if t == "{":
            if depth == 0 and start:
                ops += 1
                start = False
            depth += 1
        elif t == "}":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                start = True
        elif depth == 0 and start:
            if t in ("query", "mutation", "subscription"):
                ops += 1
                start = False
            elif t == "fragment":
                start = False
            else:
                return None
    if depth != 0 or paren != 0:
        return None
    return ops


# ---------------------------------------------------------------- manifest validation
class ManifestError(ValueError):
    """A manifest problem. `str(e)` is a fixed sentence naming the schema field and the class."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _bad(field, what):
    raise ManifestError(f"{field}: {what}")


def _text(v, field, lo, hi, multiline=False):
    if not isinstance(v, str):
        _bad(field, "must be a string")
    if not lo <= len(v) <= hi:
        _bad(field, f"must be {lo} to {hi} characters" if lo else f"must be at most {hi} characters")
    bad = guidance_mod.hidden_problem(v)
    if bad:
        _bad(field, f"contains hidden characters ({bad[0]} at offset {bad[1]})")
    if _has_surrogate(v):
        _bad(field, "contains an invalid character")
    if not (v.isprintable() or (multiline and all(c.isprintable() or c in "\n\t" for c in v))):
        _bad(field, "must be printable text without control characters")
    return v


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def rules_hash(rules):
    ordered = sorted(_canon(r) for r in rules)
    return hashlib.sha256(b"asb-plan-rules-v1\0" + b"[" + b",".join(ordered) + b"]").hexdigest()


def manifest_hash(task, rules, ttl_s):
    ordered = sorted(_canon(r) for r in rules)
    body = (b'{"rules":[' + b",".join(ordered) + b'],"task":' + _canon(task)
            + b',"ttl":' + _canon(ttl_s) + b',"v":1}')
    return hashlib.sha256(b"asb-plan-v1\0" + body).hexdigest()


def text_digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _norm_host(v, field):
    if not isinstance(v, str) or not v.isascii():
        _bad(field, "must be an ASCII host name or IP address")
    try:
        ip = ipaddress.ip_address(v)
        if str(ip) != v:
            _bad(field, "must be the canonical form of the address")
        return v
    except ValueError:
        pass
    if v != v.lower() or v.endswith(".") or not _HOSTNAME_RE.match(v):
        _bad(field, "must be a lowercase host name without a trailing dot")
    if not re.search(r"[a-z]", v.rsplit(".", 1)[-1]):
        _bad(field, "must be a host name or a standard IP address")
    return v


def is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _utf8_ok(raw):
    try:
        bytes(raw).decode("utf-8")      # strict: overlong forms, surrogates and truncation fail
        return True
    except UnicodeDecodeError:
        return False


def path_problem(path, prefix=False):
    """None when `path` is acceptable for matching, else a short class. Checked as sent: no
    normalisation, so nothing is ever decoded before it is compared."""
    if not path.startswith("/"):
        return "relative"
    if "//" in path:
        return "empty segment"
    if ";" in path or "\\" in path:
        return "forbidden character"
    for seg in path.split("/"):
        if seg in (".", ".."):
            return "dot segment"
    # Percent-encoding is allowed only for a space (%20) and for non-ASCII UTF-8 sequences, with
    # UPPERCASE hex. Everything else encoded (%25, %2e, %2f, %5c, %00, unreserved, reserved...) is
    # refused, so nothing can double-decode or change meaning at the upstream.
    i, run = 0, bytearray()
    while i < len(path):
        if path[i] != "%":
            if run and not _utf8_ok(run):
                return "bad percent-encoding"
            run = bytearray()
            i += 1
            continue
        m = _PCT_RE.match(path, i)
        if not m or m.group(1) != m.group(1).upper():
            return "bad percent-encoding"
        b = int(m.group(1), 16)
        if b == 0x20:
            if run and not _utf8_ok(run):
                return "bad percent-encoding"
            run = bytearray()
        elif b >= 0x80:
            run.append(b)
        else:
            return "encoded special character"
        i += 3
    if run and not _utf8_ok(run):
        return "bad percent-encoding"
    return None


def _norm_rule(raw, i, cfg, graphql_write_ok):
    f = f"rules[{i}]"
    if not isinstance(raw, dict):
        _bad(f, "must be an object")
    allowed = {"secret", "method", "host", "port", "scheme", "path_prefix", "query", "max_uses", "body",
               "session"}
    extra = sorted(k for k in raw if k not in allowed)
    if extra:
        _bad(f, "has an unknown key" + (f" ({extra[0]})" if re.fullmatch(r"[a-z_]{1,30}", extra[0]) else ""))
    if "session" in raw:
        _bad(f"{f}.session", "not supported yet")
    secret = raw.get("secret")
    if not isinstance(secret, str) or not _NAME_RE.match(secret):
        _bad(f"{f}.secret", "must be a credential name")
    method = raw.get("method")
    if method not in METHODS:
        _bad(f"{f}.method", "must be one of " + ", ".join(METHODS) + " (uppercase)")
    host = _norm_host(raw.get("host"), f"{f}.host")
    scheme = raw.get("scheme", "https")
    if scheme not in ("https", "http"):
        _bad(f"{f}.scheme", "must be https or http")
    if scheme == "http" and not is_private_ip(host):
        _bad(f"{f}.scheme", "plain http is only allowed for a private IP address host")
    port = raw.get("port", 443 if scheme == "https" else 80)
    if not _int(port) or not 1 <= port <= 65535:
        _bad(f"{f}.port", "must be a whole number from 1 to 65535")
    prefix = raw.get("path_prefix")
    if not isinstance(prefix, str) or not prefix.isascii() or not 1 <= len(prefix) <= MAX_PREFIX:
        _bad(f"{f}.path_prefix", f"must be an absolute ASCII path of 1 to {MAX_PREFIX} characters")
    if not _PREFIX_RE.match(prefix):
        _bad(f"{f}.path_prefix", "contains a character that must not appear in a path prefix")
    if path_problem(prefix, True):
        _bad(f"{f}.path_prefix", "must not contain dot segments, empty segments or encoded characters")
    if prefix != "/" and prefix.endswith("/"):
        _bad(f"{f}.path_prefix", "must not end with /")
    if prefix == "/" and not cfg["allow_root_prefix"]:
        _bad(f"{f}.path_prefix", "a prefix of only / is not allowed")
    query = _norm_query(raw.get("query"), method, raw.get("body"), f"{f}.query")
    mu = raw.get("max_uses")
    if not _int(mu) or not 1 <= mu <= cfg["max_uses_per_rule"]:
        _bad(f"{f}.max_uses", f"must be a whole number from 1 to {cfg['max_uses_per_rule']}")
    body = _norm_body(raw.get("body"), method, f"{f}.body", cfg, graphql_write_ok)
    return {"secret": secret, "method": method, "scheme": scheme, "host": host, "port": port,
            "path_prefix": prefix, "query": query, "max_uses": mu, "body": body}


def _norm_query(v, method, body, f):
    """"none" (no query string), "any" (read methods only) or a sorted list of allowed key names.
    The default is "none" for a method that writes. A GraphQL rule never allows a query string."""
    gql = isinstance(body, dict) and "graphql" in body
    if v is None:
        v = "any" if method in READ_METHODS and not gql else "none"
    if v == "none":
        return "none"
    if gql:
        _bad(f, 'a GraphQL rule must use "none" (a query string could override the document)')
    if v == "any":
        if method not in READ_METHODS:
            _bad(f, 'a rule that writes must use "none" or list the allowed query keys')
        return "any"
    if (isinstance(v, list) and 1 <= len(v) <= 16 and all(isinstance(k, str) and _QKEY_RE.match(k) for k in v)):
        if any(k.lower() in _QUERY_OVERRIDES for k in v):
            _bad(f, "a method or body override parameter is never allowed")
        return sorted(set(v))
    _bad(f, 'must be "none", "any" (read methods only) or a list of up to 16 query key names')


def query_problem(q, rule_query):
    """None when the raw query string `q` (without the ?) is acceptable for the rule."""
    if q == "":
        return None
    if ";" in q:
        return "query"
    for part in q.split("&"):
        key = part.split("=", 1)[0]
        if not _QKEY_RE.match(key):
            return "query"              # empty, encoded or odd keys
        if key.lower() in _QUERY_OVERRIDES:
            return "query"
        if isinstance(rule_query, list) and key not in rule_query:
            return "query"
    return None


def _norm_body(raw, method, f, cfg, graphql_write_ok):
    if raw is None:
        if method not in READ_METHODS:
            _bad(f, 'is required for a method that writes (use {"none": true} for an empty body)')
        return {"none": True}
    if not isinstance(raw, dict) or len(raw) != 1:
        _bad(f, "must be an object with exactly one of none, json, graphql, any")
    (kind, spec), = raw.items()
    if kind not in ("none", "json", "graphql", "any"):
        _bad(f, "must be an object with exactly one of none, json, graphql, any")
    if kind != "none" and method in READ_METHODS:
        _bad(f, f"a {method} rule cannot have a request body")
    if kind == "none":
        if spec is not True:
            _bad(f"{f}.none", "must be true")
        return {"none": True}
    if kind == "any":
        if spec is not True:
            _bad(f"{f}.any", "must be true")
        if not cfg["allow_any_body"]:
            _bad(f"{f}.any", "an any-content body is not allowed on this broker")
        return {"any": True}
    if not isinstance(spec, dict):
        _bad(f"{f}.{kind}", "must be an object")
    if kind == "json":
        extra = sorted(set(spec) - {"keys", "pin"})
        if extra:
            _bad(f"{f}.json", "has an unknown key")
        keys = spec.get("keys")
        if (not isinstance(keys, list) or len(keys) > MAX_KEYS
                or not all(isinstance(k, str) and _text_key(k) for k in keys)):
            _bad(f"{f}.json.keys", f"must be a list of up to {MAX_KEYS} field names")
        keys = sorted(set(keys))
        pin = spec.get("pin", {})
        if not isinstance(pin, dict) or len(pin) > MAX_KEYS:
            _bad(f"{f}.json.pin", "must be an object of scalar values")
        for k, v in pin.items():
            if not _text_key(k) or k not in keys:
                _bad(f"{f}.json.pin", "may only pin a field that is listed in keys")
            if isinstance(v, str):
                _text(v, f"{f}.json.pin value", 0, MAX_PIN_STR)
            elif not (v is None or isinstance(v, bool) or (_int(v) and abs(v) <= TWO_53)):
                _bad(f"{f}.json.pin", "values must be a string, true/false, a whole number or null")
        return {"json": {"keys": keys, "pin": dict(sorted(pin.items()))}}
    # graphql
    extra = sorted(set(spec) - {"document", "operation_name", "variables_keys"})
    if extra:
        _bad(f"{f}.graphql", "has an unknown key")
    doc = _text(spec.get("document"), f"{f}.graphql.document", 1, MAX_DOC, multiline=True)
    vk = spec.get("variables_keys", [])
    if (not isinstance(vk, list) or len(vk) > MAX_KEYS
            or not all(isinstance(k, str) and _text_key(k) for k in vk)):
        _bad(f"{f}.graphql.variables_keys", f"must be a list of up to {MAX_KEYS} variable names")
    kind_, ops = classify_graphql(doc)
    if kind_ == "write" and not (cfg["allow_graphql_mutation"] and graphql_write_ok):
        _bad(f"{f}.graphql.document", "a GraphQL mutation, subscription or unparsable document is not "
                                      "allowed on this broker")
    on = spec.get("operation_name")
    if on is not None and (not isinstance(on, str) or not _OPNAME_RE.match(on)):
        _bad(f"{f}.graphql.operation_name", "must be an operation name")
    if ops > 1 and on is None:
        _bad(f"{f}.graphql.operation_name", "is required when the document has more than one operation")
    out = {"document": doc, "variables_keys": sorted(set(vk))}
    if on is not None:
        out["operation_name"] = on
    return {"graphql": out}


def _text_key(k):
    return isinstance(k, str) and _KEY_RE.match(k) is not None


def validate_manifest(raw, cfg, max_minutes=None):
    """The agent's manifest -> normalized dict {"task", "description", "ttl_s", "rules", ...}, or
    ManifestError (a 400). `max_minutes` is the effective ceiling (global or per-client)."""
    if not isinstance(raw, dict):
        _bad("manifest", "must be a JSON object")
    for k in ("sessions", "window"):
        if k in raw:
            _bad(k, "not supported yet")
    extra = sorted(set(raw) - {"v", "task", "description", "ttl_seconds", "rules"})
    if extra:
        _bad("manifest", "has an unknown key" + (f" ({extra[0]})" if re.fullmatch(r"[a-z_]{1,30}", extra[0]) else ""))
    if raw.get("v") != SCHEMA_VERSION or isinstance(raw.get("v"), bool):
        _bad("v", f"must be {SCHEMA_VERSION}")
    task = _text(raw.get("task"), "task", 1, MAX_TASK)
    desc = _text(raw.get("description", ""), "description", 0, MAX_DESC)
    mm = max_minutes or cfg["max_minutes"]
    ttl = raw.get("ttl_seconds", cfg["default_minutes"] * 60)
    if not _int(ttl) or ttl < 60:
        _bad("ttl_seconds", "must be a whole number of seconds, at least 60")
    if ttl > mm * 60:
        _bad("ttl_seconds", f"is above the maximum of {mm * 60} seconds")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= cfg["max_rules"]:
        _bad("rules", f"must be a list of 1 to {cfg['max_rules']} rules")
    norm = [_norm_rule(r, i, cfg, True) for i, r in enumerate(rules)]
    seen = set()
    for r in norm:
        c = _canon(r)
        if c in seen:
            _bad("rules", "has a duplicate rule")
        seen.add(c)
    if sum(r["max_uses"] for r in norm) > cfg["max_total_uses"]:
        _bad("rules", f"the uses add up to more than the maximum of {cfg['max_total_uses']}")
    return {"task": task, "description": desc, "ttl_s": ttl, "rules": norm,
            "manifest_hash": manifest_hash(task, norm, ttl), "rules_hash": rules_hash(norm)}


# ---------------------------------------------------------------- deterministic tiers
def prefix_segments(prefix):
    return len([s for s in prefix.split("/") if s])


def rule_writes(rule):
    """True when a call this rule allows can change data at the target."""
    b = rule["body"]
    if rule["method"] in READ_METHODS:
        return False
    if "graphql" in b and classify_graphql(b["graphql"]["document"])[0] == "read":
        return False
    return True


def rule_flags(rule):
    """The reasons a rule is high, as a list of short phrases (empty = not high)."""
    out = []
    if rule["method"] == "DELETE":
        out.append("delete data (DELETE)")
    if "any" in rule["body"]:
        out.append("send any content (any-content body)")
    if "graphql" in rule["body"] and classify_graphql(rule["body"]["graphql"]["document"])[0] == "write":
        out.append("run a GraphQL mutation")
    if prefix_segments(rule["path_prefix"]) <= 1:
        out.append(f"reach everything under the broad path {rule['path_prefix']}")
    return out


def rule_tier(rule):
    if rule_flags(rule):
        return "high"
    return "medium" if rule_writes(rule) else "low"


_TIER_RANK = {"low": 0, "medium": 1, "high": 2}


def plan_tier(rules):
    t = "low"
    for r in rules:
        if _TIER_RANK[rule_tier(r)] > _TIER_RANK[t]:
            t = rule_tier(r)
    return t


def plan_flags(rules):
    out = []
    for r in rules:
        for fl in rule_flags(r):
            if fl not in out:
                out.append(fl)
    return out


def tier_reasons(rules):
    tier = plan_tier(rules)
    flags = plan_flags(rules)
    if flags:
        return ["can " + "; ".join(flags)]
    if tier == "medium":
        return ["can change data at the target, only in the ways listed"]
    return ["read-only calls, only the ones listed"]


# ---------------------------------------------------------------- the frozen request and the matcher
class NoMatch(Exception):
    """A non-match; `why` is a coarse class of the first item that failed."""

    def __init__(self, why):
        super().__init__(why)
        self.why = why


class Frozen:
    """The final request, built once. Nothing about it changes after `freeze` returns."""
    __slots__ = ("method", "url", "headers", "body")

    def __init__(self, method, url, headers, body):
        self.method, self.url, self.headers, self.body = method, url, tuple(headers), body


def freeze(spec):
    """Frozen request from an http request spec ({"method","url","headers","body","body_b64"}),
    or NoMatch("request") when it is not even well formed."""
    try:
        method, url = spec["method"], spec["url"]
        hdrs = spec.get("headers") or {}
        if not isinstance(method, str) or not isinstance(url, str) or not isinstance(hdrs, dict):
            raise NoMatch("request")
        pairs = []
        for k, v in hdrs.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise NoMatch("headers")
            pairs.append((k, v))
        if spec.get("body_b64") is not None:
            if spec.get("body") is not None:
                raise NoMatch("body")
            import base64
            body = base64.b64decode(spec["body_b64"], validate=True)
        elif spec.get("body") is not None:
            if not isinstance(spec["body"], str):
                raise NoMatch("body")
            body = spec["body"].encode("utf-8")
        else:
            body = b""
    except NoMatch:
        raise
    except Exception:   # noqa: BLE001 -- anything odd is a non-match, never an error with text
        raise NoMatch("request") from None
    return Frozen(method, url, pairs, body)


def _parse_url(url):
    """(scheme, host, port, path, has_query) from the URL text with ONE parse, or NoMatch. The URL
    must be plain printable ASCII with none of the characters that different parsers disagree on."""
    if "{{" in url or "}}" in url:
        raise NoMatch("placeholder")
    if not _URL_RE.match(url) or _URL_BAD.search(url):
        raise NoMatch("url")
    if "#" in url:
        raise NoMatch("url")        # a fragment
    for scheme in ("https", "http"):
        if url.startswith(scheme + "://"):
            break
    else:
        raise NoMatch("url")
    rest = url[len(scheme) + 3:]
    cut = len(rest)
    for ch in "/?":
        j = rest.find(ch)
        if j >= 0:
            cut = min(cut, j)
    netloc, tail = rest[:cut], rest[cut:]
    if "@" in netloc:
        raise NoMatch("host")       # userinfo
    m = _NETLOC_RE.match(netloc)
    if not m:
        raise NoMatch("host")
    host, port = m.group(1), m.group(2)
    if host.startswith("["):
        host = host[1:-1]
        try:
            if ipaddress.ip_address(host).version != 6:
                raise ValueError
        except ValueError:
            raise NoMatch("host") from None
    if host != host.lower() or host.endswith(".") or not host.isascii() or not host:
        raise NoMatch("host")
    if port is not None and not re.fullmatch(r"[1-9][0-9]{0,4}", port):
        raise NoMatch("host")
    if not tail.startswith("/"):
        raise NoMatch("path")       # "https://host" or "https://host?x": no path at all
    path, _, q = tail.partition("?")
    has_query = "?" in tail
    return scheme, host, int(port) if port else (443 if scheme == "https" else 80), path, has_query, q


def _norm_headers(frozen, cfg, own_vars, opaque, post=False):
    """Validate the request headers (item E). Returns {lowercase name: value}. `opaque` is the set
    of lowercase names whose values were substituted (post-substitution pass); otherwise a
    placeholder header must be exactly `[Scheme ]{{OWN_VAR}}` for a variable of the rule's credential."""
    allowed = {h.lower() for h in cfg["allowed_request_headers"]}
    out = {}
    for name, value in frozen.headers:
        low = name.lower()
        if not _HDR_NAME_RE.match(name):
            raise NoMatch("headers")
        if low in out:
            raise NoMatch("headers")            # duplicate (Content-Type exactly once, and the rest too)
        if len(value) > 4000 or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", value):
            raise NoMatch("headers")
        out[low] = value
        if low in opaque:
            if low in allowed or _forbidden_header(low):
                raise NoMatch("headers")
            continue
        if "{{" in name or "}}" in name:
            raise NoMatch("placeholder")
        if "{{" in value or "}}" in value:
            if post:
                raise NoMatch("placeholder")        # nothing may survive substitution
            m = _PLACEHOLDER_HDR.match(value)
            if not m or m.group(2) not in own_vars:
                raise NoMatch("placeholder")
            if low in allowed or _forbidden_header(low):
                raise NoMatch("headers")
            continue
        if low not in allowed or _forbidden_header(low):
            raise NoMatch("headers")
    return out


def match_rule(rule, frozen, cfg, own_vars, opaque=frozenset(), post=False):
    """Item A-F for one rule: returns None on a match, raises NoMatch(why) otherwise. Pure: no state,
    no clock, no I/O. `own_vars` are the variable names of the rule's own credential."""
    if frozen.method != rule["method"]:
        raise NoMatch("method")
    scheme, host, port, path, has_query, _q = _parse_url(frozen.url)
    if scheme != rule["scheme"]:
        raise NoMatch("host")
    if host != rule["host"] or port != rule["port"]:
        raise NoMatch("host")
    if scheme == "http" and not is_private_ip(host):
        raise NoMatch("host")
    if path_problem(path):
        raise NoMatch("path")
    pre = rule["path_prefix"]
    if not (path == pre or (pre != "/" and path.startswith(pre + "/")) or (pre == "/" and path.startswith("/"))):
        raise NoMatch("path")
    if rule["query"] == "none" and has_query:
        raise NoMatch("query")
    if query_problem(_q, rule["query"]):
        raise NoMatch("query")
    hdrs = _norm_headers(frozen, cfg, own_vars, opaque, post)
    if len(frozen.body) > cfg["max_body_bytes"]:
        raise NoMatch("size")
    cl = hdrs.get("content-length")
    if cl is not None and (not _DIGITS.match(cl) or int(cl) != len(frozen.body)):
        raise NoMatch("headers")
    if b"{{" in frozen.body:
        raise NoMatch("placeholder")
    _match_body(rule["body"], frozen.body, hdrs)
    return None


def _match_body(spec, body, hdrs):
    if "none" in spec:
        if body:
            raise NoMatch("body")
        return
    if "any" in spec:
        return
    if not _CT_JSON.match(hdrs.get("content-type", "")):
        raise NoMatch("body")
    try:
        doc = strict_loads(body)
    except StrictError:
        raise NoMatch("body") from None
    if not isinstance(doc, dict):
        raise NoMatch("body")
    if "json" in spec:
        j = spec["json"]
        if not set(doc) <= set(j["keys"]):
            raise NoMatch("body")
        for k, v in j["pin"].items():
            if k not in doc or type(doc[k]) is not type(v) or doc[k] != v:
                raise NoMatch("body")
        return
    g = spec["graphql"]
    if not set(doc) <= {"query", "operationName", "variables"}:
        raise NoMatch("body")           # a batch is an array (refused above); extensions and extras land here
    if doc.get("query") != g["document"]:
        raise NoMatch("body")
    want = g.get("operation_name")
    if doc.get("operationName") != want and not (want is None and doc.get("operationName") is None):
        raise NoMatch("body")
    vs = doc.get("variables")
    if vs is not None:
        if not isinstance(vs, dict) or not set(vs) <= set(g["variables_keys"]):
            raise NoMatch("body")


def own_placeholder_headers(frozen):
    """{lowercase header name: variable name} for the headers that are a placeholder."""
    out = {}
    for name, value in frozen.headers:
        m = _PLACEHOLDER_HDR.match(value)
        if m:
            out[name.lower()] = m.group(2)
    return out


def substitute(frozen, env, rule, cfg, own_vars):
    """Fill the validated placeholder headers from `env` and return the Frozen that will be sent.
    The URL, method and body are the very same objects; the result is matched again with the filled
    headers treated as opaque. NoMatch("placeholder") if a value would break the request."""
    ph = own_placeholder_headers(frozen)
    out = []
    for name, value in frozen.headers:
        if name.lower() in ph:
            m = _PLACEHOLDER_HDR.match(value)
            var = m.group(2)
            val = env.get(var)
            if not isinstance(val, str) or re.search(r"[\x00-\x1f\x7f]", val):
                raise NoMatch("placeholder")
            value = (m.group(1) + " " if m.group(1) else "") + val
        out.append((name, value))
    done = Frozen(frozen.method, frozen.url, out, frozen.body)
    if done.url is not frozen.url or done.body is not frozen.body or done.method is not frozen.method:
        raise NoMatch("placeholder")
    match_rule(rule, done, cfg, own_vars, opaque=frozenset(ph), post=True)
    return done


# ---------------------------------------------------------------- the store
class Plan:
    def __init__(self, pid, client, manifest, request_id, requested_s, now, mono, pending_ttl):
        self.id = pid
        self.client_id, self.client_name = client["id"], client["name"]
        self.task, self.description = manifest["task"], manifest["description"]
        self.rules = tuple(manifest["rules"])
        self.manifest_hash, self.rules_hash = manifest["manifest_hash"], manifest["rules_hash"]
        self.state = "pending"
        self.created_at, self.pending_until = now, now + pending_ttl
        self.requested_s = requested_s
        self.request_id = request_id
        self.approved_at = self.approved_by = self.expires_at = self.approved_mono = None
        self.granted_s = None
        self.ended_at = None
        self.uses_total = 0
        self.uses_by_rule = [0] * len(self.rules)
        self.recent = deque()
        self.inflight = 0
        self.tickets = set()
        self.item_sigs = {}
        self.names = sorted({r["secret"] for r in self.rules})


class Match:
    """A reserved use. Call `release()` (idempotent) when the upstream call ends, in a finally."""

    def __init__(self, store, plan, idx, rule, ticket, left_rule, left_plan, left_s):
        self.store, self.plan_id, self.rule_index, self.rule = store, plan.id, idx, rule
        self.client_id = plan.client_id
        self.uses_left_rule, self.uses_left_plan, self.left_s = left_rule, left_plan, left_s
        self.ticket = ticket

    def release(self):
        self.store._release_ticket(self.plan_id, self.ticket)


class Miss:
    def __init__(self, reason, why=None, retry_after_s=None, kind=None, plan_id=None):
        self.reason, self.why, self.retry_after_s, self.kind, self.plan_id = reason, why, retry_after_s, kind, plan_id

    @property
    def http(self):
        if self.reason == "unusable":
            return 404
        return 429 if self.reason in ("rate_limited", "inflight_limit") else 403

    def body(self):
        if self.reason == "unusable":
            return {"error": "plan not usable", "kind": self.kind if self.kind in KINDS else "unknown"}
        out = {"error": "outside plan", "reason": self.reason}
        if self.why:
            out["why"] = self.why
        if self.retry_after_s is not None:
            out["retry_after_s"] = self.retry_after_s
        return out


class _Ticket:
    __slots__ = ("thread", "done")

    def __init__(self):
        self.thread, self.done = threading.current_thread(), False


class PlanStore:
    """Plans in memory. One lock; every method that changes state takes it. Audit events are
    handed to `on_event(name, **fields)` AFTER the lock is released, and `on_event` must not call
    back into the store. Time comes from `now()` / `mono()` (clock.py by default)."""

    def __init__(self, cfg, on_event=None, now=None, mono=None):
        self.cfg = cfg
        self._on_event = on_event or (lambda *a, **k: None)
        self.now = now or clock_mod.now
        self.mono = mono or clock_mod.mono
        self._lock = threading.Lock()
        self._plans = {}
        self._denied = {}               # (client id, task) -> time of denial
        self._miss = {}                 # key -> {"t", "n", "supp"}

    # -- helpers (lock held) ---------------------------------------------------
    def _expired_locked(self, p):
        if p.approved_mono is None:
            return False
        return self.now() >= p.expires_at or self.mono() - p.approved_mono >= p.granted_s

    def _end_locked(self, p, state, ev):
        """Move a live plan to a terminal state once; the event is appended to `ev`."""
        if p.state in _TERMINAL:
            return False
        p.state, p.ended_at = state, self.now()
        return True

    def _tick_locked(self, p, ev):
        if p.state == "pending" and self.now() >= p.pending_until:
            p.state, p.ended_at = "expired", self.now()
        elif p.state == "active" and self._expired_locked(p):
            p.state, p.ended_at = "ended", self.now()
            ev.append(("plan_closed", p, {"cause": "deadline", "uses": p.uses_total}))

    def _emit(self, ev):
        for name, p, extra in ev:
            fields = {"client_id": p.client_id, "client_name": p.client_name, "plan_id": p.id}
            if name == "plan_issued":
                fields["id"] = p.request_id
            fields.update(extra)
            try:
                self._on_event(name, **fields)
            except Exception:   # noqa: BLE001 -- audit trouble never breaks a plan operation
                pass

    def _left_locked(self, p):
        return max(0, min(int(p.expires_at - self.now()), int(p.granted_s - (self.mono() - p.approved_mono))))

    # -- submit / decide ---------------------------------------------------------
    def submit(self, client, manifest, request_id, requested_s):
        """Create a pending plan -> (plan, None) or (None, error class: "too_many"|"cooldown"|"full")."""
        with self._lock:
            now = self.now()
            for p in list(self._plans.values()):
                self._tick_locked(p, [])
            self._drop_old_locked(now)
            if len(self._plans) >= MAX_PLANS:
                return None, "full"
            cid = client["id"]
            if sum(p.state == "pending" for p in self._plans.values()) >= self.cfg["max_pending"]:
                return None, "too_many"
            if sum(p.state == "active" and p.client_id == cid for p in self._plans.values()) >= \
                    self.cfg["max_active_per_client"]:
                return None, "too_many"
            if now - self._denied.get((cid, manifest["task"]), -1e9) < DENY_COOLDOWN_S:
                return None, "cooldown"
            p = Plan(secrets.token_hex(16), client, manifest, request_id, requested_s, now, self.mono(),
                     self.cfg["pending_ttl_s"])
            self._plans[p.id] = p
            return p, None

    def _drop_old_locked(self, now):
        for pid in [k for k, p in self._plans.items()
                    if p.ended_at is not None and now - p.ended_at > MAX_ID_AGE_S]:
            del self._plans[pid]
        for k in [k for k, t in self._denied.items() if now - t > DENY_COOLDOWN_S]:
            del self._denied[k]

    def set_request(self, pid, request_id):
        with self._lock:
            p = self._plans.get(pid)
            if p is not None:
                p.request_id = request_id

    def settle(self, pid, state):
        """The card ended without an approval: state "denied" or "expired" (or "failed" -> expired)."""
        with self._lock:
            p = self._plans.get(pid)
            if p is None or p.state != "pending":
                return False
            p.state = "denied" if state == "denied" else "expired"
            p.ended_at = self.now()
            if p.state == "denied":
                self._denied[(p.client_id, p.task)] = self.now()
            return True

    def approve(self, pid, by, channel, granted_s, item_sigs, extra=None):
        """pending -> active with an absolute deadline. Returns (plan view dict, None) or (None, class)."""
        ev = []
        with self._lock:
            p = self._plans.get(pid)
            if p is None:
                return None, "gone"
            self._tick_locked(p, ev)
            if p.state != "pending":
                return None, "gone"
            if sum(q.state == "active" and q.client_id == p.client_id for q in self._plans.values()) >= \
                    self.cfg["max_active_per_client"]:
                return None, "too_many"
            if not _int(granted_s) or not 60 <= granted_s <= p.requested_s:
                return None, "bad_duration"
            now, mono = self.now(), self.mono()
            p.state, p.approved_by = "active", by
            p.approved_at, p.approved_mono, p.granted_s = now, mono, granted_s
            p.expires_at = now + granted_s
            p.item_sigs = dict(item_sigs)
            view = self._view_locked(p)
            ev.append(("plan_issued", p, {"rules": len(p.rules), "names": p.names, "granted_s": granted_s,
                                          "expires_at": p.expires_at, "approver": by, "channel": channel,
                                          "manifest_hash": p.manifest_hash, "rules_hash": p.rules_hash,
                                          "task_length": len(p.task), "task_sha256": text_digest(p.task),
                                          "description_length": len(p.description),
                                          "description_sha256": text_digest(p.description) if p.description else None,
                                          **(extra or {})}))
        self._emit(ev)
        return view, None

    def needs_confirm(self, pid):
        with self._lock:
            p = self._plans.get(pid)
            return bool(p and plan_tier(p.rules) == "high")

    # -- use ------------------------------------------------------------------------
    def try_use(self, client_id, plan_id, names, frozen, live, client_ok, cfg=None):
        """Every check and the reservation, in one critical section. `live(secret)` returns the
        credential's current state {"hosts", "plans", "sig", "vars"} or None; `client_ok(client_id)`
        says whether this client may still use plans. Returns Match or Miss."""
        cfg = cfg or self.cfg
        ev = []
        try:
            return self._try_use(client_id, plan_id, names, frozen, live, client_ok, cfg, ev)
        finally:
            self._emit(ev)

    def _try_use(self, client_id, plan_id, names, frozen, live, client_ok, cfg, ev):
        with self._lock:
            p = self._plans.get(plan_id) if valid_id(plan_id) else None
            if p is None or not hmac.compare_digest(p.client_id.encode(), client_id.encode()):
                return Miss("unusable", kind="unknown")
            self._tick_locked(p, ev)
            if p.state != "active":
                kind = {"ended": "ended", "exhausted": "exhausted", "closed": "closed",
                        "revoked": "revoked"}.get(p.state, "unknown")
                return Miss("unusable", kind=kind, plan_id=p.id)
            if rules_hash(p.rules) != p.rules_hash:
                return Miss("wrong_policy", plan_id=p.id)       # the approved rules no longer hash right
            if not client_ok(p.client_id):
                return Miss("wrong_policy", plan_id=p.id)
            if not (isinstance(names, list) and len(names) == 1 and isinstance(names[0], str)):
                return Miss("no_rule", why="secret", plan_id=p.id)
            cands, why, rank = [], "secret", -1
            order = ("method", "host", "path", "query", "headers", "placeholder", "size", "body")
            for i, r in enumerate(p.rules):
                if r["secret"] != names[0]:
                    continue
                cur = live(r["secret"])
                if cur is None:
                    return Miss("wrong_policy", plan_id=p.id)      # the credential is gone
                if cur is None or cur["plans"] is False or r["secret"] in cfg["deny_secrets"] \
                        or r["host"] not in cur["hosts"] or p.item_sigs.get(r["secret"]) != cur["sig"]:
                    why_policy = True
                else:
                    why_policy = False
                try:
                    match_rule(r, frozen, cfg, cur["vars"] if cur else frozenset())
                except NoMatch as e:
                    k = order.index(e.why) if e.why in order else -1
                    if k > rank:
                        rank, why = k, e.why
                    continue
                if why_policy:
                    return Miss("wrong_policy", plan_id=p.id)
                cands.append(i)
            if not cands:
                return Miss("no_rule", why=why, plan_id=p.id)
            mono = self.mono()
            while p.recent and mono - p.recent[0] >= RATE_WINDOW_S:
                p.recent.popleft()
            if len(p.recent) >= cfg["rate_per_min"]:
                return Miss("rate_limited", retry_after_s=max(1, int(math.ceil(RATE_WINDOW_S - (mono - p.recent[0])))),
                            plan_id=p.id)
            if p.inflight >= cfg["max_inflight"]:
                return Miss("inflight_limit", retry_after_s=1, plan_id=p.id)
            idx = next((i for i in cands if p.uses_by_rule[i] < p.rules[i]["max_uses"]), None)
            if idx is None:
                return Miss("uses_exhausted", plan_id=p.id)
            p.uses_by_rule[idx] += 1
            p.uses_total += 1
            p.recent.append(mono)
            p.inflight += 1
            t = _Ticket()
            p.tickets.add(t)
            left_rule = p.rules[idx]["max_uses"] - p.uses_by_rule[idx]
            left_plan = sum(r["max_uses"] for r in p.rules) - p.uses_total
            if all(p.uses_by_rule[i] >= r["max_uses"] for i, r in enumerate(p.rules)):
                p.state, p.ended_at = "exhausted", self.now()
                ev.append(("plan_closed", p, {"cause": "exhausted", "uses": p.uses_total}))
            return Match(self, p, idx, p.rules[idx], t, left_rule, left_plan, self._left_locked(p))

    def _release_ticket(self, pid, ticket):
        with self._lock:
            if ticket.done:
                return
            ticket.done = True
            p = self._plans.get(pid)
            if p is not None:
                p.tickets.discard(ticket)
                p.inflight = max(0, p.inflight - 1)

    # -- miss bookkeeping (coalesced audit) -----------------------------------------
    def note_miss(self, key):
        """(write, suppressed): whether a plan_miss record may be written now for `key`, and how
        many were swallowed since the last one."""
        now = self.mono()
        with self._lock:
            m = self._miss.get(key)
            if m is None:
                if len(self._miss) >= MISS_KEYS_MAX:
                    for k in sorted(self._miss, key=lambda k: self._miss[k]["t"])[:MISS_KEYS_MAX // 4]:
                        del self._miss[k]
                m = self._miss[key] = {"t": now, "n": 0, "supp": 0}
            if now - m["t"] >= 60:
                m["t"], m["n"] = now, 0
            if m["n"] >= MISS_PER_MIN:
                m["supp"] += 1
                return False, 0
            m["n"] += 1
            supp, m["supp"] = m["supp"], 0
            return True, supp

    # -- owner operations -------------------------------------------------------------
    def _view_locked(self, p):
        v = {"id": p.id, "state": p.state, "task": p.task, "client_id": p.client_id,
             "client_name": p.client_name, "names": list(p.names), "request_id": p.request_id,
             "created_at": p.created_at, "requested_s": p.requested_s, "granted_s": p.granted_s,
             "expires_at": p.expires_at, "approved_by": p.approved_by,
             "uses": p.uses_total, "uses_max": sum(r["max_uses"] for r in p.rules),
             "rules": [{**r, "uses": p.uses_by_rule[i]} for i, r in enumerate(p.rules)],
             "inflight": p.inflight, "manifest_hash": p.manifest_hash, "rules_hash": p.rules_hash,
             "left_s": self._left_locked(p) if p.state == "active" else 0, "ended_at": p.ended_at}
        return v

    def status_for(self, client_id, plan_id):
        """The owner's view, or None (unknown, expired and foreign are indistinguishable)."""
        ev = []
        with self._lock:
            p = self._plans.get(plan_id) if valid_id(plan_id) else None
            if p is None or not hmac.compare_digest(p.client_id.encode(), client_id.encode()):
                return None
            self._tick_locked(p, ev)
            v = self._view_locked(p)
        self._emit(ev)
        return v

    def list_for(self, client_id):
        ev = []
        with self._lock:
            out = []
            for p in self._plans.values():
                if hmac.compare_digest(p.client_id.encode(), client_id.encode()):
                    self._tick_locked(p, ev)
                    out.append(self._view_locked(p))
        self._emit(ev)
        return sorted(out, key=lambda v: v["created_at"])

    def close(self, client_id, plan_id):
        """The owner abandons its plan: True, or None when it is not usable."""
        ev = []
        with self._lock:
            p = self._plans.get(plan_id) if valid_id(plan_id) else None
            if p is None or not hmac.compare_digest(p.client_id.encode(), client_id.encode()):
                return None
            self._tick_locked(p, ev)
            if p.state != "active":
                done = None
            else:
                p.state, p.ended_at = "closed", self.now()
                ev.append(("plan_closed", p, {"cause": "agent", "uses": p.uses_total}))
                done = True
        self._emit(ev)
        return done

    def revoke(self, plan_id, by, **extra):
        """A human revokes: True if it was active, else False. Takes effect before the next use."""
        ev = []
        with self._lock:
            p = self._plans.get(plan_id) if valid_id(plan_id) else None
            if p is None:
                return False
            self._tick_locked(p, ev)
            ok = p.state == "active"
            if ok:
                left = self._left_locked(p)
                p.state, p.ended_at = "revoked", self.now()
                ev.append(("plan_revoked", p, {"by": by, "left_s": left, "cause": "human", **extra}))
        self._emit(ev)
        return ok

    def revoke_client(self, client_id, by="system:client-revoked", **extra):
        """A revoked client loses every plan, pending and active. Returns the ids."""
        ev, gone = [], []
        with self._lock:
            for p in self._plans.values():
                if p.client_id != client_id or p.state in _TERMINAL:
                    continue
                left = self._left_locked(p) if p.state == "active" else 0
                was = p.state
                p.state, p.ended_at = ("revoked" if was == "active" else "denied"), self.now()
                gone.append(p.id)
                if was == "active":
                    ev.append(("plan_revoked", p, {"by": by, "left_s": left, "cause": "client_revoked", **extra}))
        self._emit(ev)
        return gone

    def sweep(self):
        """Expire what is due and reconcile in-flight counters against live threads. Returns the
        number of plans whose state changed."""
        ev, n = [], 0
        with self._lock:
            now = self.now()
            for p in self._plans.values():
                before = p.state
                self._tick_locked(p, ev)
                n += p.state != before
                for t in list(p.tickets):
                    if not t.thread.is_alive() and not t.done:
                        t.done = True
                        p.tickets.discard(t)
                        p.inflight = max(0, p.inflight - 1)
            self._drop_old_locked(now)
        self._emit(ev)
        return n

    def rows(self, states=("active",)):
        ev = []
        with self._lock:
            out = []
            for p in self._plans.values():
                self._tick_locked(p, ev)
                if p.state in states:
                    out.append(self._view_locked(p))
        self._emit(ev)
        return sorted(out, key=lambda v: v["created_at"])

    def get_view(self, plan_id):
        """Any plan by id for the approver pages (not for agents)."""
        with self._lock:
            p = self._plans.get(plan_id) if valid_id(plan_id) else None
            return self._view_locked(p) if p else None

    def pending_rules(self, plan_id):
        with self._lock:
            p = self._plans.get(plan_id)
            return list(p.rules) if p else None

    def shutdown(self):
        with self._lock:
            self._plans.clear()


# ---------------------------------------------------------------- the card
CSS = """
.pl h3{margin:.8rem 0 .3rem;font-size:1rem}
.pl ol{margin:.3rem 0 .6rem 1.2rem;padding:0}
.pl li{margin:.55rem 0}
.pl pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);
border-radius:.4rem;padding:.4rem .6rem;margin:.25rem 0}
.pl .agent{border:1px dashed var(--line);border-radius:.4rem;padding:.4rem .6rem;margin:.5rem 0;background:var(--bg)}
.pl .worst{border:1px solid var(--warn);border-radius:.5rem;padding:.4rem .7rem;margin:.6rem 0}
.pl .tier{font-weight:700;font-size:.75rem;margin-left:.4rem}
.pl select{font:inherit;min-height:2.5rem;border-radius:.5rem;border:1px solid var(--line);
background:var(--card);color:var(--fg);padding:.2rem .5rem}
"""


def _esc(text):
    """Escaped HTML of agent-written text with every non-ASCII character shown as <U+XXXX>."""
    return "".join(
        html.escape(ch) if ord(ch) < 128 else
        f"<span class=gu title=\"{html.escape(ch)}\">&lt;U+{ord(ch):04X}&gt;</span>" for ch in text)


def _hm(s):
    s = int(s)
    if s >= 3600 and s % 3600 == 0:
        h = s // 3600
        return f"{h} hour" + ("" if h == 1 else "s")
    if s >= 3600:
        return f"{s // 3600} h {(s % 3600) // 60} min"
    return f"{max(1, s // 60)} min"


def _chunk_label(s):
    return _hm(s).replace(" hours", " h").replace(" hour", " h")


def duration_choices(requested_s):
    """Seconds the approver may pick: the requested length and the standard shorter ones."""
    out = [requested_s] + [m * 60 for m in STANDARD_MINUTES if m * 60 < requested_s]
    return sorted(set(out), reverse=True)


def rule_lines(rule):
    """Plain-language lines for one rule, as HTML, generated from the validated structure only."""
    e = html.escape
    tier = rule_tier(rule)
    writes = rule_writes(rule)
    label = ("READ-ONLY" + (" (pure GraphQL query)" if rule["method"] == "POST" else "")) if not writes else (
        "CAN CHANGE DATA")
    if rule_flags(rule) and tier == "high":
        label = "HIGH: " + "; ".join(rule_flags(rule))
    port = "" if rule["port"] == (443 if rule["scheme"] == "https" else 80) else f":{rule['port']}"
    where = f"{rule['scheme']}://{rule['host']}{port}{rule['path_prefix']}"
    n = rule["max_uses"]
    lines = [f"<b>{e(rule['secret'])}</b> <span class='pill {'bad' if tier == 'high' else 'warn' if tier == 'medium' else 'ok'}'>"
             f"{e(label)}</span>",
             f"{e(rule['method'])} {e(where)}, up to {n} time{'' if n == 1 else 's'}."
             + (" No query string." if rule["query"] == "none" else
                " Any query string (no method or body override parameters)." if rule["query"] == "any" else
                " Query keys allowed: " + e(", ".join(rule["query"])) + " (values not constrained).")]
    b = rule["body"]
    if "none" in b:
        lines.append("Body: none (an empty body only).")
    elif "any" in b:
        lines.append("<b>Body: ANY CONTENT</b> (not constrained at all).")
    elif "json" in b:
        j = b["json"]
        keys = ", ".join(f'"{k}"' for k in j["keys"]) or "none"
        txt = f"Body: JSON object with only the fields {_esc(keys)}."
        for k, v in j["pin"].items():
            txt += f" {_esc(json.dumps(k))} must be {_esc(json.dumps(v))}."
        free = [k for k in j["keys"] if k not in j["pin"]]
        lines.append(txt)
        if free:
            lines.append("Not constrained (can contain any value): " + _esc(", ".join(f'"{k}"' for k in free)) + ".")
    else:
        g = b["graphql"]
        lines.append("Only this GraphQL text:")
        lines.append(f"<pre>{_esc(g['document'])}</pre>")
        if g.get("operation_name"):
            lines.append(f"Operation name: {_esc(g['operation_name'])}.")
        vk = ", ".join(g["variables_keys"]) or "none"
        lines.append(f"Variables: keys {_esc(vk)}; values not constrained.")
    pre = rule["path_prefix"]
    lines.append(f"The path prefix {e(pre)} also covers everything under {e(pre.rstrip('/') + '/')} .")
    return lines


def describe_html(req):
    """(what_html, note_html) for the pending card of a plan request. The credential surface line
    comes from `req.spec["surface"]` (allowed hosts at submit)."""
    sp = req.spec
    rules = sp["rules"]
    e = html.escape
    now = clock_mod.now()
    until = now + sp["requested_s"]
    local = time.strftime("%Y-%m-%d %H:%M", time.localtime(until))
    utc = time.strftime("%Y-%m-%d %H:%M", time.gmtime(until))
    total = sum(r["max_uses"] for r in rules)
    creds = sorted({r["secret"] for r in rules})
    sites = sorted({r["host"] for r in rules})
    out = [f"<div class=pl><p><b>Plan requested</b> by {e(req.client['name'])} "
           f"<small class=muted>({e(req.client['id'])})</small></p>",
           f"<p>Lasts at most {_hm(sp['requested_s'])}, until about {e(local)} local ({e(utc)} UTC) if you "
           "approve now. If you approve, this client can do ONLY the following, with no further approval, "
           "until then.</p><ol>"]
    for r in rules:
        out.append("<li>" + "<br>".join(rule_lines(r)) + "</li>")
    out.append("</ol>")
    flags = plan_flags(rules)
    writes = sum(rule_writes(r) for r in rules)
    dele = sum(r["method"] == "DELETE" for r in rules)
    anyb = sum("any" in r["body"] for r in rules)
    out.append(
        f"<div class=worst><b>Worst case:</b> {total} calls in total, {len(creds)} credential"
        f"{'' if len(creds) == 1 else 's'}, {len(sites)} site{'' if len(sites) == 1 else 's'}, at most "
        f"{req.spec['rate_per_min']} per minute.<br>Includes changes to data: "
        f"{'yes (' + str(writes) + ' rule' + ('' if writes == 1 else 's') + ')' if writes else 'no'}. "
        f"Deletes: {'yes' if dele else 'no'}. Any-content bodies: {'yes' if anyb else 'no'}.")
    for c in creds:
        hs = sp.get("surface", {}).get(c)
        if hs is not None:
            out.append(f"<br>Credential {e(c)} is allowed to reach: {e(', '.join(hs) if hs else 'nothing')}. "
                       "This plan uses only the paths above.")
    out.append("</div>")
    desc = sp.get("description") or ""
    na = guidance_mod.non_ascii_count(sp["task"] + desc)
    flag = (f" <span class='pill warn'>Non-ASCII characters: {na} (shown as U+XXXX)</span>" if na else "")
    out.append("<div class=agent><small>Written by the agent, not verified, not used for any decision:</small>"
               f"<br>task: {_esc(sp['task'])}" + (f"<br>description: {_esc(desc)}" if desc else "") + f"{flag}</div>")
    out.append(f"<small class=muted>Manifest {e(sp['manifest_hash'][:8])}.</small></div>")
    note = ("Every line above was generated by the broker from the validated manifest. The agent's own "
            "words are only in the dashed box. No standing approval, Always or timed grant can cover a plan; "
            "approve only a plan you expected. An unexpected plan card may be an injection: deny it.")
    return "".join(out), note


def card_actions_html(req):
    """The controls of a pending plan card: a duration, Approve (with a second step for a high
    plan) and Deny. The form posts to /plans/decide; the notification channels never reach it."""
    sp, e = req.spec, html.escape
    opts = "".join(f"<option value='{s}'{' selected' if s == sp['requested_s'] else ''}>{e(_chunk_label(s))}</option>"
                   for s in duration_choices(sp["requested_s"]))
    n = len(sp["rules"])
    sel = (f"<label class=rscope>Approve for <select name=granted aria-label='How long the plan lasts'>"
           f"{opts}</select></label>")
    if sp["tier"] == "high":
        flags = "; ".join(sp["flags"])
        approve = ("<details class=alw><summary class='btn approve'>Approve plan: "
                   f"{n} rule{'' if n == 1 else 's'}</summary><div class=confirm><span>This plan can "
                   f"{e(flags)}. Approve anyway?</span><button class='btn approve' name=decision "
                   "value=approve_confirmed>Approve anyway</button></div></details>")
    else:
        approve = (f"<button class='btn approve' name=decision value=approve>Approve plan: {n} rule"
                   f"{'' if n == 1 else 's'}</button>")
    return (f"{sel}<div class=decide-row>{approve}"
            "<button class='btn deny' name=decision value=deny>Deny</button></div>"
            "<p class=scope><small class=muted>One decision for the whole plan. Nothing outside the listed "
            "calls is ever released, and it ends at the deadline whatever happens.</small></p>")


def active_table_html(rows, token, names=None):
    """The Policies tab 'Active plans' table with Revoke."""
    e = html.escape
    body = []
    for r in rows:
        left = max(0, int(r["left_s"]))
        body.append(
            f"<tr><td data-label=Task>{_esc(r['task'])}</td>"
            f"<td data-label=Client>{e(r['client_name'])}</td>"
            f"<td data-label=Secrets>{e(', '.join(r['names']))}</td>"
            f"<td data-label=Ends><time data-gexp='{int(r['expires_at'] or 0)}'>in {_hm(left) if left >= 60 else 'under a minute'}</time></td>"
            f"<td data-label=Used>{r['uses']} / {r['uses_max']}</td>"
            f"<td data-label=State>{e(r['state'])}</td>"
            "<td><form method=post action='/plans/revoke' class=inline>"
            f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=plan value='{e(r['id'])}'>"
            "<button>Revoke</button></form></td></tr>")
    head = ("<h3>Active plans</h3><p><small class=muted>A plan lets one client make exactly the listed "
            "calls without asking, until its deadline. Revoke ends it before the next call. Plans live in "
            "memory only: a broker restart ends every plan.</small></p>")
    if not body:
        return head + "<div class='card empty'>No active plans</div>"
    return (head + "<table class=tbl><thead><tr><th>Task</th><th>Client</th><th>Secrets</th><th>Ends</th>"
            "<th>Used</th><th>State</th><th></th></tr></thead><tbody>" + "".join(body) + "</tbody></table>")
