"""WebSocket profiles: a named JSON file that bundles what a service needs for `asb ws`.

A profile holds the sign-in (handshake steps, query, headers, origin, subprotocols), the message types the broker
blocks or allows on the way out (`deny_send`, `allow_send`), field-level `rules` for nested matching, and a short
fixed sentence for the approval card. Profiles come from two places:

  * built in: `secret_broker/ws_profiles/*.json`, shipped with the package;
  * admin: `*.json` in the directory named by the config key `ws_profiles_dir` (default: `ws-profiles/` next to
    the audit log). An admin profile with the name of a built-in one REPLACES it.

A credential selects one with `"ws": {"profile": "home-assistant"}` in its operator metadata. That is the only way:
no agent request, `store` or credential-request flow can name or write a profile.

Trust and failure rules (tests/test_ws_profiles.py):
  * a profile file is admin input and is still validated strictly: strict UTF-8 JSON (no BOM, no duplicate keys, no
    NaN/Infinity, no lone surrogate, nested at most 12 deep), at most 64 KiB, unknown keys refused, every field
    type- and size-checked. Anything wrong makes THAT profile invalid; the broker starts, and a credential that
    selects an invalid profile is invalid in the catalog. An invalid admin file also shadows a built-in of the same
    name (fail closed: a broken override never silently falls back to the looser built-in);
  * files are opened without following symlinks, must be regular files and not world-writable, and the directory
    may hold at most 100 of them; an unreadable directory makes every profile invalid (an override might hide in it);
  * the only thing that ever reaches the agent from a profile is nothing: refusals use fixed texts, and the card
    text is escaped when rendered.
"""
import hashlib
import json
import os
import re
import stat

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*\Z")
MAX_NAME = 64
MAX_FILE_BYTES = 64 * 1024
MAX_FILES = 100
MAX_DIR_ENTRIES = 10_000
MAX_JSON_DEPTH = 12
MAX_DENY, MAX_ALLOW, MAX_RULES = 50, 100, 50
MAX_TYPE_LEN = 128
MAX_MATCH_KEYS, MAX_MATCH_DEPTH, MAX_ANY_OF = 8, 3, 20
MAX_TEXT = 200                       # description, card_text, a risk note
MAX_REASON = 120
MAX_NOTES = 10
KEYS = ("name", "description", "handshake", "query", "headers", "origin", "subprotocols", "deny_send",
        "allow_send", "rules", "card_text", "risk_notes")
REQUIRED = ("name", "description", "card_text")
SIGNIN_KEYS = ("handshake", "query", "headers", "origin", "subprotocols")
BUILTIN_NAMES = ("home-assistant", "home-assistant-admin", "home-assistant-readonly")
BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ws_profiles")
DEFAULT_DIR_NAME = "ws-profiles"
_PLAIN_RE = re.compile(r"^[ -~]+\Z")          # printable ASCII only: no control, no bidi, no markup tricks needed
_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}\Z")


# ---------------------------------------------------------------- strict JSON
def strict_loads(text):
    """Strict JSON by Python's rules: no duplicate keys, no NaN/Infinity, no lone surrogate, at most
    MAX_JSON_DEPTH deep. ValueError (fixed text) otherwise."""
    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d

    def const(name):
        raise ValueError("not strict JSON")
    if not isinstance(text, str) or text.startswith("﻿"):
        raise ValueError("not strict JSON")
    try:
        obj = json.loads(text, object_pairs_hook=pairs, parse_constant=const)
    except (ValueError, RecursionError):
        raise ValueError("not strict JSON") from None
    stack = [(obj, 1)]
    while stack:
        v, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError("nested too deeply")
        if isinstance(v, str):
            if any("\ud800" <= c <= "\udfff" for c in v):
                raise ValueError("not strict JSON")
        elif isinstance(v, list):
            stack += [(x, depth + 1) for x in v]
        elif isinstance(v, dict):
            for k, x in v.items():
                stack += [(k, depth + 1), (x, depth + 1)]
    return obj


def _plain(v, lo, hi):
    return isinstance(v, str) and lo <= len(v) <= hi and bool(_PLAIN_RE.match(v))


def _type_list(raw, field, hi, lo=0):
    if (not isinstance(raw, list) or not lo <= len(raw) <= hi
            or not all(_plain(x, 1, MAX_TYPE_LEN) for x in raw)):
        what = f"at least {lo}, " if lo else ""
        raise ValueError(f"{field} is a list of {what}up to {hi} message type names (printable ASCII)")
    return list(dict.fromkeys(raw))


# ---------------------------------------------------------------- rules
def _scalar_ok(v):
    if isinstance(v, bool):
        return True
    if isinstance(v, int):
        return abs(v) <= 2 ** 53
    return _plain(v, 1, MAX_TYPE_LEN)


def _parse_match(m, depth):
    if depth > MAX_MATCH_DEPTH:
        raise ValueError(f"rules[].match is nested more than {MAX_MATCH_DEPTH} deep")
    if not isinstance(m, dict) or not 1 <= len(m) <= MAX_MATCH_KEYS:
        raise ValueError(f"rules[].match is an object of 1 to {MAX_MATCH_KEYS} fields")
    out = {}
    for k, v in m.items():
        if not _plain(k, 1, 64):
            raise ValueError("rules[].match field names are plain text of up to 64 characters")
        if isinstance(v, dict):
            out[k] = _parse_match(v, depth + 1)
        elif isinstance(v, list):
            if not 1 <= len(v) <= MAX_ANY_OF or not all(_scalar_ok(x) for x in v):
                raise ValueError(f"rules[].match list values are 1 to {MAX_ANY_OF} text, whole-number or true/false values")
            out[k] = list(v)
        elif _scalar_ok(v):
            out[k] = v
        else:
            raise ValueError("rules[].match values are text, whole numbers, true/false, a list of those or an object")
    return out


def _parse_rules(raw):
    if not isinstance(raw, list) or len(raw) > MAX_RULES:
        raise ValueError(f"rules is a list of up to {MAX_RULES} rules")
    out = []
    for r in raw:
        if not isinstance(r, dict):
            raise ValueError("a rule is an object")
        for k in r:
            if k not in ("match", "action", "reason"):
                raise ValueError("a rule takes match, action and reason only")
        if "match" not in r:
            raise ValueError("a rule needs match")
        if r.get("action", "deny") != "deny":
            raise ValueError("rules[].action must be \"deny\"")
        reason = r.get("reason", "")
        if reason != "" and not _plain(reason, 1, MAX_REASON):
            raise ValueError(f"rules[].reason is plain text of up to {MAX_REASON} characters")
        out.append({"match": _parse_match(r["match"], 1), "action": "deny", "reason": reason})
    return out


def _canon(v):
    """The text form a scalar is compared by: 1, 1.0, "1" are one value; true and "true" are one value. Deny rules
    compare this way on purpose (a server that coerces types must not be able to dodge a rule with 1.0 or "1").
    Case still matters. None for anything that is not a scalar."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v == v and v not in (float("inf"), float("-inf")) and v.is_integer() else repr(v)
    if isinstance(v, str):
        return v
    return None


def _match_value(spec, val, depth=0):
    if depth > MAX_MATCH_DEPTH + 1:
        return False
    if isinstance(spec, dict):
        return isinstance(val, dict) and all(k in val and _match_value(s, val[k], depth + 1) for k, s in spec.items())
    got = _canon(val)
    if got is None:
        return False
    if isinstance(spec, list):
        return any(_canon(s) == got for s in spec)
    return _canon(spec) == got


def rule_matches(rule, item):
    """Does one parsed JSON message (an object) match a rule? Every listed field must be present with an equal
    value (a list is any-of; objects match as subsets; exact, case-sensitive; scalars by `_canon`)."""
    return isinstance(item, dict) and _match_value(rule["match"], item)


def rule_groups(rule):
    """The backstop for a rule: lower-cased alternative strings, one group per string field of the match (a list is
    any-of). If EVERY group has a member somewhere in the frame text the rule is treated as hit, whatever the
    structure says (a parser that reads the frame differently must not slip past)."""
    groups = []

    def walk(m):
        for v in m.values():
            if isinstance(v, dict):
                walk(v)
            elif isinstance(v, list):
                alts = [x.lower() for x in v if isinstance(x, str)]
                if alts:
                    groups.append(alts)
            elif isinstance(v, str):
                groups.append([v.lower()])
    walk(rule["match"])
    return groups


def rule_backstop(rule, hay):
    groups = rule_groups(rule)
    return bool(groups) and all(any(a in hay for a in alts) for alts in groups)


# ---------------------------------------------------------------- profile schema
def parse_profile(obj, expect_name=None):
    """A parsed profile file -> the normalized profile dict. ValueError (fixed text naming the field) on anything
    wrong. `expect_name`: the file stem the `name` must equal."""
    from . import wssessions as W          # lazy: wssessions imports this module
    if not isinstance(obj, dict):
        raise ValueError("a profile is a JSON object")
    for k in obj:
        if k not in KEYS:
            raise ValueError(f"{k if isinstance(k, str) and _FIELD_RE.match(k) else 'a field'} is not a known profile field")
    for k in REQUIRED:
        if k not in obj:
            raise ValueError(f"{k} is required")
    name = obj["name"]
    if not isinstance(name, str) or len(name) > MAX_NAME or not NAME_RE.match(name):
        raise ValueError("name must be kebab-case (lowercase letters, digits and single hyphens, up to 64)")
    if expect_name is not None and name != expect_name:
        raise ValueError("name must match the file name (NAME.json)")
    if not _plain(obj["description"], 1, MAX_TEXT):
        raise ValueError(f"description is plain printable ASCII text of 1 to {MAX_TEXT} characters")
    if not _plain(obj["card_text"], 1, MAX_TEXT):
        raise ValueError(f"card_text is plain printable ASCII text of 1 to {MAX_TEXT} characters (one short sentence)")
    out = {"name": name, "description": obj["description"], "card_text": obj["card_text"], "handshake": None,
           "query": {}, "headers": {}, "origin": None, "subprotocols": [], "deny_send": [], "allow_send": None,
           "rules": [], "risk_notes": []}
    signin = {k: obj[k] for k in SIGNIN_KEYS if k in obj}
    for k, v in signin.items():
        if v is None:
            raise ValueError(f"{k} must not be null (leave it out)")
    if "handshake" in signin and not isinstance(signin["handshake"], dict):
        raise ValueError("handshake must be an object ({\"steps\": [...]} or wait/send/expect)")
    if signin:
        try:
            W.parse_cred_config(signin, ["VAR"], profiles=_NO_PROFILES)      # {{VAR}} is the only placeholder a profile may use
        except ValueError as e:
            raise ValueError(str(e).replace("ws.", "", 1)) from None
        for k, v in signin.items():
            out[k] = json.loads(json.dumps(v))
    if "deny_send" in obj:
        out["deny_send"] = _type_list(obj["deny_send"], "deny_send", MAX_DENY)
    if "allow_send" in obj:
        out["allow_send"] = _type_list(obj["allow_send"], "allow_send", MAX_ALLOW, lo=1)
    if "rules" in obj:
        out["rules"] = _parse_rules(obj["rules"])
    if "risk_notes" in obj:
        rn = obj["risk_notes"]
        if not isinstance(rn, list) or len(rn) > MAX_NOTES or not all(_plain(x, 1, MAX_TEXT) for x in rn):
            raise ValueError(f"risk_notes is a list of up to {MAX_NOTES} plain text lines of up to {MAX_TEXT} characters")
        out["risk_notes"] = list(rn)
    return out


class _NoProfiles:
    """A registry with nothing in it (used while validating a profile's own sign-in fields)."""
    def resolve(self, name):
        raise ValueError("ws.profile is not known")


_NO_PROFILES = _NoProfiles()


def content_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=list).encode()).hexdigest()


# ---------------------------------------------------------------- reading files
class BadFile(Exception):
    """A profile file that cannot be used. `label` is a fixed word; `detail` a fixed message (never file content)."""
    def __init__(self, label, detail=None):
        super().__init__(label)
        self.label, self.detail = label, detail or label


def _read_limited(fd):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise BadFile("not_a_file", "not a regular file")
    if st.st_mode & 0o002:
        raise BadFile("world_writable", "the file is writable by every user")
    if st.st_size > MAX_FILE_BYTES:
        raise BadFile("too_large", f"larger than {MAX_FILE_BYTES // 1024} KiB")
    chunks, total = [], 0
    while True:
        b = os.read(fd, 65536)
        if not b:
            break
        total += len(b)
        if total > MAX_FILE_BYTES:
            raise BadFile("too_large", f"larger than {MAX_FILE_BYTES // 1024} KiB")
        chunks.append(b)
    return b"".join(chunks)


def _decode_profile(data, expect_name):
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise BadFile("not_utf8", "not valid UTF-8") from None
    try:
        obj = strict_loads(text)
    except ValueError as e:
        raise BadFile("not_json", f"not strict JSON ({e})") from None
    try:
        return parse_profile(obj, expect_name)
    except ValueError as e:
        raise BadFile("invalid", str(e)) from None


def read_profile_file(path, expect_name=None, follow_symlinks=True):
    """One profile file -> the normalized profile. BadFile on any problem. The CLI follows an explicit path; the
    broker's directory scan never follows a link."""
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | (0 if follow_symlinks else os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise BadFile("unreadable", "cannot be opened (a link, missing or no permission)") from None
    try:
        data = _read_limited(fd)
    finally:
        os.close(fd)
    return _decode_profile(data, expect_name)


def load_dir(path):
    """Scan one directory of profiles. -> (profiles {name: profile}, errors {stem: BadFile}, dir_error BadFile|None).
    A directory that does not exist is simply empty. Never follows a symlink out of the directory (every file is
    opened relative to the directory's own descriptor with O_NOFOLLOW), reads at most MAX_FILES files."""
    profiles, errors = {}, {}
    if not path:
        return profiles, errors, None
    try:
        dfd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return profiles, errors, None
    except OSError:
        return profiles, errors, BadFile("dir_unreadable", "the profiles directory cannot be read")
    try:
        st = os.fstat(dfd)
        if not stat.S_ISDIR(st.st_mode):
            return profiles, errors, BadFile("dir_unreadable", "the profiles path is not a directory")
        if st.st_mode & 0o002:
            return profiles, errors, BadFile("dir_world_writable", "the profiles directory is writable by every user")
        names = []
        try:
            with os.scandir(dfd) as it:
                for n, e in enumerate(it):
                    if n >= MAX_DIR_ENTRIES:
                        return profiles, errors, BadFile("dir_too_big", "the profiles directory holds too many entries")
                    if e.name.endswith(".json"):
                        names.append(e.name)
        except OSError:
            return profiles, errors, BadFile("dir_unreadable", "the profiles directory cannot be read")
        names.sort()
        for i, fname in enumerate(names):
            stem = fname[:-5]
            if len(stem) > MAX_NAME:
                stem = stem[:MAX_NAME]
            if i >= MAX_FILES:
                errors[stem] = BadFile("too_many", f"more than {MAX_FILES} profile files")
                continue
            try:
                fd = os.open(fname, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
            except OSError:
                errors[stem] = BadFile("unreadable", "cannot be opened (a link, missing or no permission)")
                continue
            try:
                p = _decode_profile(_read_limited(fd), fname[:-5])
                profiles[p["name"]] = p
            except BadFile as e:
                errors[stem] = e
            except OSError:
                errors[stem] = BadFile("unreadable", "cannot be read")
            finally:
                os.close(fd)
    finally:
        os.close(dfd)
    return profiles, errors, None


# ---------------------------------------------------------------- the registry
class Registry:
    """Built-in and admin profiles, resolved by name. Immutable once built."""

    def __init__(self, builtin, builtin_errors, admin, admin_errors, dir_error, directory):
        self.builtin, self.builtin_errors = builtin, builtin_errors
        self.admin, self.admin_errors = admin, admin_errors
        self.dir_error, self.directory = dir_error, directory

    def names(self):
        return sorted(set(self.builtin) | set(self.admin) | set(self.builtin_errors) | set(self.admin_errors))

    def overridden(self):
        """Built-in names an admin profile replaces."""
        return sorted(set(self.builtin) & set(self.admin))

    def status(self, name):
        """('ok', source) or ('invalid', source-or-None)."""
        if self.dir_error is not None:
            return "invalid", None
        if name in self.admin_errors:
            return "invalid", "admin"
        if name in self.admin:
            return "ok", "admin"
        if name in self.builtin_errors:
            return "invalid", "built-in"
        if name in self.builtin:
            return "ok", "built-in"
        return "unknown", None

    def invalid_names(self):
        return sorted({n for n in self.names() if self.status(n)[0] == "invalid"})

    def resolve(self, name):
        """The profile dict plus `source` and a content `sha256`. ValueError with a fixed text naming the profile
        (never the file's content) when it is unknown or invalid."""
        if not isinstance(name, str) or not NAME_RE.match(name) or len(name) > MAX_NAME:
            raise ValueError("ws.profile must be a profile name (lowercase, digits and hyphens)")
        st, src = self.status(name)
        if st == "unknown":
            raise ValueError(f"ws profile {name!r} is not known (see `python -m secret_broker ws-profile list`)")
        if st == "invalid":
            raise ValueError(f"ws profile {name!r} is invalid (see the broker log and `ws-profile validate`)")
        p = (self.admin if src == "admin" else self.builtin)[name]
        return {**p, "source": src, "sha256": content_hash(p)}


_BUILTIN = None


def builtin():
    """(profiles, errors) of the package's own profiles, read once."""
    global _BUILTIN
    if _BUILTIN is None:
        profiles, errors, derr = load_dir(BUILTIN_DIR)
        if derr is not None:                      # the package itself is damaged: every built-in is unusable
            errors = {n: derr for n in BUILTIN_NAMES}
        _BUILTIN = (profiles, errors)
    return _BUILTIN


def build_registry(directory=None):
    bp, be = builtin()
    ap, ae, derr = load_dir(directory)
    return Registry(bp, be, ap, ae, derr, directory)


def builtin_registry():
    return build_registry(None)


# ---------------------------------------------------------------- config
def parse_dir_config(cfg, field="ws_profiles_dir"):
    """The profiles directory for a config dict: `ws_profiles_dir`, else `ws-profiles/` next to the audit log, else
    None (built-ins only). ValueError names the field."""
    raw = (cfg or {}).get("ws_profiles_dir")
    if raw is not None:
        if not isinstance(raw, str) or not raw or len(raw) > 4096 or "\x00" in raw:
            raise ValueError(f"{field} must be a directory path")
        return raw
    audit = (cfg or {}).get("audit_log")
    if isinstance(audit, str) and audit:
        return os.path.join(os.path.dirname(os.path.abspath(audit)), DEFAULT_DIR_NAME)
    return None
