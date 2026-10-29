"""Configuration rules that approve a request without a human: `auto_approve` in the broker config.

    "auto_approve": [
      {"name": "reach openclaw", "mode": "ssh_sign", "secret": "agent-ssh",
       "host": "openclaw-linux.lan", "account": "ryan", "clients": ["sheridan-dev-box"]},
      {"name": "read komodo", "mode": "http", "secret": "komodo",
       "host": "komodo.local.dibbleapps.com", "methods": ["POST"], "path_prefix": "/read"},
      {"name": "nightly report", "mode": "env", "secret": "reports",
       "argv": ["python3", "report.py"], "clients": ["batch-box"]}
    ]

A request that matches a rule is released without a prompt at any risk level and whatever the secret's
`approval` setting says: the rule is explicit policy written by the person who runs the broker (it lives in
the broker's own configuration, which no agent can edit), like a standing SSH rule or a plan. It is audited as
an ordinary approval with `decision_source: config_rule` and the rule's name. Everything else prompts as before.

What a rule can and cannot do:
  * Modes: `ssh_sign`, `http`, `env`. Root commands (`sudo`), credential requests, guidance proposals, plans
    and sessions are decided by a human by design and are refused at load, so a typo cannot open them.
  * Every rule names the secret(s) it covers and says exactly what it matches. There is no "any host" or "any
    command": ssh needs an account and a server, http a host, env the full argv.
  * `clients` (names or ids) limits which enrolled clients a rule applies to. Leave it out for any enrolled
    client; the legacy shared key never matches a rule.
  * A client set to "never auto-approve" still prompts, and the request-time refusals (`ssh_hosts`, the vault's
    own allowed hosts, forwarding) all run before a rule is looked at.
  * Matching uses only facts the broker checked: an SSH server is matched by its verified host key (by
    fingerprint, or by a name the key's `known_hosts` gives that verified fingerprint), never by what the client
    claimed; an env request whose script text nobody could read never matches.
"""
import base64
import re
import urllib.parse

from . import clients as clients_mod
from . import sshrules
from . import scripts as scripts_mod

MODES = ("ssh_sign", "http", "env")
HUMAN_ONLY = ("sudo", "credential", "guidance", "plan", "session", "session_close", "store")
MAX_RULES = 200
MAX_NAME = 80
KEYS = {
    "ssh_sign": {"name", "mode", "secret", "secrets", "clients", "host", "host_fp", "account"},
    "http": {"name", "mode", "secret", "secrets", "clients", "scheme", "host", "methods", "path_prefix"},
    "env": {"name", "mode", "secret", "secrets", "clients", "argv"},
}
_SECRET = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_HOST = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_METHOD = re.compile(r"[A-Z]{3,10}")
_FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


def _strings(rule, field, where, *, max_n=50, max_len=255, required=False):
    v = rule.get(field)
    if v is None:
        if required:
            raise ValueError(f"{where}.{field} is required")
        return None
    if (not isinstance(v, list) or not v or len(v) > max_n
            or not all(isinstance(x, str) and 0 < len(x) <= max_len for x in v)):
        raise ValueError(f"{where}.{field} must be a non-empty list of up to {max_n} strings")
    return list(v)


def parse(raw, field="auto_approve"):
    """Validate the `auto_approve` list -> a list of normalized rules. None means no rules. Raises ValueError
    naming the field (`auto_approve[2].host`)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list of rules")
    if len(raw) > MAX_RULES:
        raise ValueError(f"{field} has more than {MAX_RULES} rules")
    out, seen = [], set()
    for i, r in enumerate(raw):
        where = f"{field}[{i}]"
        if not isinstance(r, dict):
            raise ValueError(f"{where} must be an object")
        mode = r.get("mode")
        if mode in HUMAN_ONLY:
            raise ValueError(f"{where}.mode {mode!r} always needs a human and cannot be auto-approved by a rule")
        if mode not in MODES:
            raise ValueError(f"{where}.mode must be one of {', '.join(MODES)}")
        extra = sorted(set(r) - KEYS[mode])
        if extra:
            raise ValueError(f"{where}.{extra[0]} is not an option for {mode} rules ({', '.join(sorted(KEYS[mode]))})")
        name = r.get("name")
        if not isinstance(name, str) or not 0 < len(name.strip()) <= MAX_NAME or re.search(r"[\x00-\x1f\x7f]", name):
            raise ValueError(f"{where}.name is required (1-{MAX_NAME} characters): it is what the audit log shows")
        name = name.strip()
        if name.lower() in seen:
            raise ValueError(f"{where}.name {name!r} is used twice")
        seen.add(name.lower())
        if ("secret" in r) == ("secrets" in r):
            raise ValueError(f"{where} needs exactly one of secret (a name) or secrets (a list of names)")
        secrets = [r["secret"]] if "secret" in r else None
        if secrets is not None and not isinstance(r["secret"], str):
            raise ValueError(f"{where}.secret must be a name")
        secrets = secrets or _strings(r, "secrets", where, max_n=20, max_len=64, required=True)
        if not all(_SECRET.fullmatch(s) for s in secrets):
            raise ValueError(f"{where}: secret names are letters, digits, '.', '_' and '-'")
        clients = _strings(r, "clients", where, max_n=50, max_len=64) or []
        if not all(clients_mod.ID_RE.fullmatch(c) for c in clients):
            raise ValueError(f"{where}.clients are client ids such as c-1a2b3c4d (see the Clients tab): "
                             "a name can be reused by another client, an id cannot")
        rule = {"name": name, "mode": mode, "secrets": frozenset(secrets), "clients": frozenset(clients)}
        if mode == "ssh_sign":
            host, fp = r.get("host"), r.get("host_fp")
            if (host is None) == (fp is None):
                raise ValueError(f"{where} needs exactly one of host (a name) or host_fp (a SHA256: fingerprint)")
            if host is not None and not (isinstance(host, str) and _HOST.fullmatch(host.lower())):
                raise ValueError(f"{where}.host must be a host name or address")
            if fp is not None and not (isinstance(fp, str) and _FP.fullmatch(fp.rstrip("="))):
                raise ValueError(f"{where}.host_fp must look like SHA256:...")
            acct = r.get("account")
            if not isinstance(acct, str) or not re.fullmatch(r"[\x21-\x7e]{1,64}", acct):
                raise ValueError(f"{where}.account is required (the login name, e.g. \"ryan\")")
            rule.update(host=host.lower() if host else None, host_fp=fp.rstrip("=") if fp else None, account=acct)
        elif mode == "http":
            host = r.get("host")
            if not isinstance(host, str) or not _HOST.fullmatch(host.lower()):
                raise ValueError(f"{where}.host is required (a host name, no scheme or port)")
            scheme = r.get("scheme", "https")
            if scheme not in ("https", "http"):
                raise ValueError(f"{where}.scheme must be \"https\" (the default) or \"http\"")
            methods = _strings(r, "methods", where, max_n=10, max_len=10) or ["GET", "HEAD"]
            if not all(_METHOD.fullmatch(m) for m in methods):
                raise ValueError(f"{where}.methods must be upper-case HTTP methods such as GET")
            prefix = r.get("path_prefix", "/")
            if not isinstance(prefix, str) or not prefix.startswith("/") or len(prefix) > 255 or "?" in prefix \
                    or re.search(r"[\x00-\x20\x7f]", prefix) or ".." in prefix.split("/"):
                raise ValueError(f"{where}.path_prefix must start with '/' (a path, no query, no '..')")
            rule.update(host=host.lower(), scheme=scheme, methods=frozenset(methods), path_prefix=prefix)
        else:
            argv = r.get("argv")
            if (not isinstance(argv, list) or not argv or len(argv) > 64
                    or not all(isinstance(a, str) and len(a) <= 4096 for a in argv)):
                raise ValueError(f"{where}.argv is required: the exact command as a list of words")
            rule["argv"] = tuple(argv)
        out.append(rule)
    return out


def _path_ok(path, prefix):
    if prefix == "/":
        return True
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _client_ok(rule, client):
    if not rule["clients"]:
        return not (client or {}).get("legacy")
    if (client or {}).get("legacy"):
        return False
    return (client or {}).get("id") in rule["clients"]


def _ssh_ok(rule, spec):
    fp, account, why = sshrules.identity(spec)
    if why or account != rule["account"]:
        return False
    if rule["host_fp"]:
        return fp == rule["host_fp"]
    names = [n.lower() for n in ((spec.get("host") or {}).get("names") or [])]
    return rule["host"] in names


OVERRIDE_HEADERS = ("x-http-method-override", "x-method-override", "x-http-method", "x-original-method",
                    "x-forwarded-method",                       # a different method than the one the rule saw
                    "x-original-url", "x-rewrite-url", "x-original-uri", "x-forwarded-uri",
                    "x-forwarded-path")                         # a different path than the one the rule saw


def _names_a_method_override(text):
    """True when a query string or form body carries a `_method` parameter (frameworks read it as the method),
    however it is escaped or separated (`&` or `;`)."""
    for part in re.split(r"[&;]", text):
        name = urllib.parse.unquote_plus(part.split("=", 1)[0]).strip().strip('"').lower()
        if name == "_method":
            return True
    return "_method" in urllib.parse.unquote_plus(text).lower()


def _not_plain(text):
    """True for text a rule cannot reason about, so the request never matches: it still changes when decoded a
    second time (`%255f`), carries a JSON or unicode escape (`\\u005f`), or is not plain printable ASCII."""
    once = urllib.parse.unquote_plus(text)
    return (once != text and urllib.parse.unquote_plus(once) != once) or "\\u" in text.lower() \
        or not all(c in "\t\r\n" or " " <= c <= "~" for c in text)


def _http_ok(rule, spec):
    """Host, scheme, method and path are compared on the raw request as the broker will send it. Anything that
    could make the server read a different method or path than the rule saw never matches: method-override
    headers or parameters, a body on a read, and any percent-escape, `;` parameter, backslash or dot segment in
    the path (a rule's path is plain text, so a plain path is all it matches)."""
    try:
        u = urllib.parse.urlsplit(spec["url"])
        host = (u.hostname or "").lower()
    except (KeyError, ValueError):
        return False
    method = str(spec.get("method") or "GET").upper()
    path = u.path or "/"
    if u.scheme != rule["scheme"] or host != rule["host"] or method not in rule["methods"]:
        return False
    if re.search(r"[%;\\\x00-\x20\x7f]", path) or any(seg in (".", "..") for seg in path.split("/")):
        return False
    if any(str(h).lower() in OVERRIDE_HEADERS for h in (spec.get("headers") or {})):
        return False
    if any(str(h).lower() in ("content-encoding", "transfer-encoding") for h in (spec.get("headers") or {})):
        return False                    # a body the broker cannot read as sent
    if _names_a_method_override(u.query) or _not_plain(u.query):
        return False
    body = spec.get("body")
    if spec.get("body_b64"):
        try:
            body = base64.b64decode(spec["body_b64"], validate=True).decode("latin-1")
        except (ValueError, TypeError):
            return False                # a body that cannot be read cannot be shown to be free of an override
    if isinstance(body, str) and (_names_a_method_override(body) or _not_plain(body)):
        return False
    if method in ("GET", "HEAD") and (spec.get("body") or spec.get("body_b64")):
        return False
    return _path_ok(path, rule["path_prefix"])


def _env_ok(rule, spec):
    argv = spec.get("argv")
    if not isinstance(argv, list) or tuple(argv) != rule["argv"]:
        return False
    return not scripts_mod.script_not_visible(argv, spec.get("scripts"), spec.get("cwd"))


def find(rules, mode, names, spec, client):
    """The first rule that approves this request, or None. `names` are the secrets the request names."""
    if not rules or not names:
        return None
    wanted = set(names)
    for rule in rules:
        if rule["mode"] != mode or not wanted <= rule["secrets"] or not _client_ok(rule, client):
            continue
        ok = {"ssh_sign": _ssh_ok, "http": _http_ok, "env": _env_ok}[mode](rule, spec or {})
        if ok:
            return rule
    return None
