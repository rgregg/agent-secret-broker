"""Script contents reported by the client for an env-mode request.

`asb NAME -- bash deploy.sh` runs a local program with the credential in its
environment. The client looks for the script(s) the command will run and sends
what it found (`scripts` in the request) so the risk model and the approver can
see more than an argv. Everything here is advisory: the client is the agent, it
decides what to send and what it finally runs. The only checks are that the
shapes are sane, that obvious secrets are scrubbed before anything is stored,
shown or sent to a model, and that the client re-hashes each script right before
it runs (a script edited between request and run is refused).

Entry shapes (exactly one of):
  {"path", "size", "sha256", "text", "truncated"}   a text script
  {"path", "unreadable": missing|binary|permission|too_large|refused}
  {"stdin": true}                                   code read from standard input

Script text is untrusted data. It is held in memory with the request (spec) and
shown on the approval card; it is never put in notifications or in the audit
log. The audit log gets paths, sizes, hashes and marker classes only. The
history pop-over shows the text from the separate, short-lived request-details
store (request_details.py), cut to request_details.max_script_bytes.
"""
import html
import os
import re
import shlex
import time

MAX_SCRIPTS = 3
MAX_TEXT = 32 * 1024            # characters of text per script
MAX_PATH = 300
UNREADABLE = ("missing", "binary", "permission", "too_large", "refused")
_PATH_RE = re.compile(r"^[^\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]{1,%d}$" % MAX_PATH)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]")
_KEYS_TEXT = {"path", "size", "sha256", "text", "truncated"}
_KEYS_UNREADABLE = {"path", "unreadable"}
_KEYS_STDIN = {"stdin"}
MAX_SIZE = 1 << 40

# -- scrubbing ----------------------------------------------------------------
# Best effort, applied to script text as soon as it arrives and again before it
# goes to a model. Replaces obvious secret-looking values, not variable names.
# Linear time by construction: fixed-prefix patterns have bounded quantifiers,
# keyword rules look only at a bounded window after each keyword hit (hits are
# capped), and a wall-clock budget makes the scrubber fail closed: when it runs
# out of time the WHOLE text is withheld, never sent half-scrubbed.
REDACTED = "[redacted]"
WITHHELD = "[scrub budget exceeded; text withheld]"
BUDGET_S = 0.05
MAX_HITS = 200
MAX_SCRUB_CHARS = 2 * MAX_TEXT
_ID_AFTER = 64          # identifier characters examined after a keyword
_VALUE_MAX = 200        # value characters examined after the separator

_AZN = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# (prefix regex, characters of the rest, minimum length of the rest). The whole run of
# those characters after the prefix is redacted, however long it is, so no tail is left.
_FIXED = (
    (re.compile(r"\b(?:AKIA|ASIA)"), frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"), 16),
    (re.compile(r"\bgh[pousr]_"), frozenset(_AZN), 30),
    (re.compile(r"\bgithub_pat_"), frozenset(_AZN + "_"), 20),
    (re.compile(r"\bglpat-"), frozenset(_AZN + "_-"), 16),
    (re.compile(r"\bxox[abprs]-"), frozenset(_AZN + "-"), 10),
    (re.compile(r"\bsk-"), frozenset(_AZN + "_-"), 20),
)
_JWT_PREFIX = re.compile(r"\beyJ")
_JWTCH = frozenset(_AZN + "_-.")
_KEYWORDS = re.compile(
    r"password|passwd|pwd|passphrase|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth|"
    r"credential|bearer|basic", re.I)
_PASSWORDISH = re.compile(r"password|passwd|pwd|passphrase", re.I)
_IDCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
_TOKCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+/=-")
_VALCH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_.:@!#%^&*~-")
_NOT_VALUE_START = frozenset("$({<[%/~.")


class _Budget(Exception):
    pass


def _run(s, i, chars, limit):
    """End index of the run of `chars` starting at i, looking at most `limit` characters."""
    j, stop = i, min(len(s), i + limit)
    while j < stop and s[j] in chars:
        j += 1
    return j


def _keyword_spans(text, deadline):
    spans, hits, last = [], 0, 0
    for m in _KEYWORDS.finditer(text):
        if m.start() < last:
            continue
        hits += 1
        if hits % 32 == 0 and time.monotonic() > deadline:
            raise _Budget
        if len(spans) > MAX_HITS:
            raise _Budget                                   # cap reached: fail closed
        kw = m.group(0).lower()
        i = _run(text, m.end(), _IDCH, _ID_AFTER)           # rest of the identifier
        if i < len(text) and text[i] in _IDCH:
            raise _Budget                                   # identifier too long to judge: withhold
        j = i
        if j < len(text) and text[j] in "\"'":
            j += 1
        k = j
        while k < len(text) and k - j < 8 and text[k] in " \t":
            k += 1
        if k < len(text) and text[k] in ":=" and k > j - 1:
            k += 1
            while k < len(text) and k - j < 16 and text[k] in " \t":
                k += 1
            if k < len(text) and text[k] in "\"'":
                k += 1
            end = _run(text, k, _VALCH, len(text))
            need = 4 if _PASSWORDISH.fullmatch(kw) or _PASSWORDISH.search(text[m.start():i]) else 8
            if end - k >= need and text[k] not in _NOT_VALUE_START:
                spans.append((k, end))
                last = end
            continue
        if kw in ("bearer", "basic", "token") and i == m.end() and k > j and k - j <= 8:
            end = _run(text, k, _TOKCH, len(text))
            if end - k >= 16 and text[k] not in _NOT_VALUE_START:
                spans.append((k, end))
                last = end
    if len(spans) > MAX_HITS:
        raise _Budget
    return spans


def _userinfo_spans(text, deadline):
    spans, pos = [], 0
    while True:
        a = text.find("://", pos)
        if a < 0:
            break
        pos = a + 3
        u = _run(text, pos, _TOKCH - {"/"}, len(text))
        if u < len(text) and text[u] == ":":
            p = u + 1
            q = p
            while q < len(text) and text[q] not in "/@ \t\r\n'\"":
                q += 1
            if q < len(text) and text[q] == "@" and q - p >= 3:
                spans.append((p, q))
                if len(spans) > MAX_HITS:
                    raise _Budget
        if time.monotonic() > deadline:
            raise _Budget
    pos = 0
    while True:
        a = text.find(" -u ", pos)
        if a < 0:
            break
        pos = a + 4
        p = pos
        if p < len(text) and text[p] in "\"'":
            p += 1
        u = _run(text, p, _TOKCH - {":"}, len(text))
        if u < len(text) and text[u] == ":":
            q = _run(text, u + 1, frozenset(c for c in map(chr, range(33, 127)) if c not in "'\""), len(text))
            if q - (u + 1) >= 3 and text[u + 1] not in _NOT_VALUE_START:
                spans.append((u + 1, q))
                if len(spans) > MAX_HITS:
                    raise _Budget
        if time.monotonic() > deadline:
            raise _Budget
    return spans


def _fixed_spans(text, deadline):
    spans = []
    for rx, chars, need in _FIXED:
        pos = 0
        while True:
            m = rx.search(text, pos)
            if not m:
                break
            end = _run(text, m.end(), chars, len(text))
            if end - m.end() >= need:
                spans.append((m.start(), end))
                if len(spans) > MAX_HITS:
                    raise _Budget
                pos = end
            else:
                pos = m.end()
        if time.monotonic() > deadline:
            raise _Budget
    pos = 0
    while True:
        m = _JWT_PREFIX.search(text, pos)
        if not m:
            break
        end = _run(text, m.end(), _JWTCH, len(text))
        parts = text[m.start():end].split(".")
        if len(parts) >= 3 and len(parts[0]) >= 11 and len(parts[1]) >= 8 and len(parts[2]) >= 4:
            spans.append((m.start(), end))
            if len(spans) > MAX_HITS:
                raise _Budget
            pos = end
        else:
            pos = m.end()
    return spans


MAX_KEYS = 20
_KEY_WINDOW = 16384


def _private_key_spans(text):
    """Spans covering the body of each PRIVATE KEY block, from just after the BEGIN line's
    closing dashes to the start of its END line. A block with no END line in reach is
    redacted to the end of the text (never left half-visible)."""
    spans, pos = [], 0
    while True:
        a = text.find("-----BEGIN ", pos)
        if a < 0:
            break
        head_end = text.find("-----", a + 11, a + 80)
        if head_end < 0 or "PRIVATE KEY" not in text[a:head_end]:
            pos = a + 11
            continue
        if len(spans) >= MAX_KEYS:
            raise _Budget                                   # more keys than we scrub: withhold all
        e = text.find("-----END ", head_end + 5, head_end + 5 + _KEY_WINDOW)
        end = len(text) if e < 0 else e          # the END line itself stays (idempotent rescrub)
        spans.append((head_end + 5, end))
        pos = max(end, a + 11)
    return spans


def _apply(text, spans):
    out, cur = [], 0
    for a, b in sorted(spans):
        if not (isinstance(a, int) and isinstance(b, int) and 0 <= a <= b <= len(text)):
            raise _Budget                                   # invalid span: fail closed
        if a < cur:
            if b > cur:
                cur = b                                     # overlap: extend the redaction
            continue
        out.append(text[cur:a])
        out.append(REDACTED)
        cur = b
    out.append(text[cur:])
    return "".join(out)


def scrub(text, budget=None):
    """Replace obvious secret-looking values with [redacted]. Idempotent. Linear time;
    if the time budget runs out the whole text is replaced by WITHHELD."""
    if not isinstance(text, str):
        return ""
    if len(text) > MAX_SCRUB_CHARS:
        return WITHHELD
    deadline = time.monotonic() + (BUDGET_S if budget is None else budget)
    try:
        text = _apply(text, _fixed_spans(text, deadline))
        spans = _private_key_spans(text)
        text = _apply(text, spans)
        text = _apply(text, _userinfo_spans(text, deadline))
        text = _apply(text, _keyword_spans(text, deadline))
        if time.monotonic() > deadline:
            raise _Budget
    except _Budget:
        return WITHHELD
    return text


def clean_text(text):
    """Control characters other than newline and tab removed (and CR, bidi, zero-width)."""
    return _CTRL_RE.sub("", text)


# -- validation ---------------------------------------------------------------

def validate(raw):
    """Check the client-supplied `scripts` list and return the cleaned copy.
    Raises ValueError (a 400) for anything malformed. None/missing -> []."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("scripts must be a list")
    if len(raw) > MAX_SCRIPTS:
        raise ValueError(f"at most {MAX_SCRIPTS} scripts")
    out = []
    for i, e in enumerate(raw):
        if not isinstance(e, dict):
            raise ValueError(f"scripts[{i}] must be an object")
        e = dict(e)
        given = e.pop("given", None)        # optional: the path as named, before symlinks were resolved
        keys = set(e)
        if given is not None and "path" not in keys:
            raise ValueError(f"scripts[{i}].given needs a path")
        if keys == _KEYS_STDIN:
            if e["stdin"] is not True:
                raise ValueError(f"scripts[{i}].stdin must be true")
            out.append({"stdin": True})
        elif keys == _KEYS_UNREADABLE:
            if e["unreadable"] not in UNREADABLE:
                raise ValueError(f"scripts[{i}].unreadable must be one of {', '.join(UNREADABLE)}")
            out.append({"path": _path(e["path"], i), "unreadable": e["unreadable"]})
            if given is not None:
                out[-1]["given"] = _path(given, i)
        elif keys == _KEYS_TEXT:
            size = e["size"]
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_SIZE:
                raise ValueError(f"scripts[{i}].size must be a non-negative integer")
            if not isinstance(e["sha256"], str) or not _SHA_RE.match(e["sha256"]):
                raise ValueError(f"scripts[{i}].sha256 must be 64 hex characters")
            if not isinstance(e["truncated"], bool):
                raise ValueError(f"scripts[{i}].truncated must be true or false")
            text = e["text"]
            if not isinstance(text, str) or len(text) > MAX_TEXT:
                raise ValueError(f"scripts[{i}].text must be a string of at most {MAX_TEXT} characters")
            out.append({"path": _path(e["path"], i), "size": size, "sha256": e["sha256"].lower(),
                        "text": scrub(clean_text(text)), "truncated": e["truncated"]})
            if given is not None:
                out[-1]["given"] = _path(given, i)
        else:
            raise ValueError(f"scripts[{i}] has unexpected or missing keys")
    return out


def _path(p, i):
    if not isinstance(p, str) or not _PATH_RE.match(p):
        raise ValueError(f"scripts[{i}].path must be 1-{MAX_PATH} printable characters")
    return p


# -- views of a validated list -------------------------------------------------

def marker(s):
    """The marker class of an entry without text, else None."""
    if s.get("stdin"):
        return "stdin"
    return s.get("unreadable")


def audit_fields(scripts):
    """What the audit log gets: never any text. Lists are index-aligned over the
    scripts that have a path; `script_markers` lists the marker classes."""
    paths = [s["path"] for s in scripts if "path" in s]
    return {"script_paths": paths,
            "script_sha256": [s.get("sha256") or "" for s in scripts if "path" in s],
            "script_sizes": [s.get("size", -1) for s in scripts if "path" in s],
            "script_markers": [m for m in (marker(s) for s in scripts) if m]}


def basename(path):
    return os.path.basename(str(path).rstrip("/")) or str(path)


def model_view(scripts, per_script=4000, total=6000, with_text=True):
    """The scripts as a classifier or describer may see them: base name, size,
    short hash, an excerpt of the (scrubbed) text and markers. `per_script` caps
    each excerpt and `total` caps all excerpts together."""
    out, budget = [], max(0, total)
    for s in scripts or []:
        if s.get("stdin"):
            out.append({"stdin": True, "note": "read from standard input, contents unknown"})
        elif s.get("unreadable"):
            out.append({"name": basename(s["path"]), "unreadable": s["unreadable"],
                        "note": "contents unknown"})
        else:
            item = {"name": basename(s["path"]), "size": s["size"], "sha256_prefix": s["sha256"][:12]}
            text = scrub(s.get("text") or "")
            if with_text and per_script > 0 and budget > 0:
                n = min(per_script, budget)
                item["text"] = text[:n]
                budget -= len(item["text"])
                if len(text) > n or s.get("truncated"):
                    item["text_truncated"] = True
            else:
                item["text"] = "<not shown>"
            out.append(item)
    return out


def has_blind_spot(scripts):
    """True when any entry is opaque (unreadable or stdin) or its text is cut."""
    return any(s.get("stdin") or s.get("unreadable") or s.get("truncated") for s in scripts or [])


# -- the classifier-independent "certainly only reads" heuristic ----------------
# Fails closed: only a short list of plainly read-only commands, in a plain shell
# script, with no redirection to files, no substitution and no tricks, counts. A
# curl/wget counts only as a plain GET of one literal https URL. Anything unusual
# or unparseable is "not read-only", which makes the description need a write verb.
_SHELL_SHEBANG = re.compile(r"^#!\s*(?:/usr/bin/env\s+(?:-S\s+)?)?\S*?(?:ba|z|da|k)?sh\b")
READ_CMDS = frozenset((
    "cat", "ls", "head", "tail", "grep", "egrep", "fgrep", "wc", "stat", "date", "uname", "uptime", "df",
    "du", "ps", "hostname", "whoami", "id", "pwd", "true", "false", "test", "[", "[[", "echo", "printf",
    "jq", "cd", "exit", "set", ":", "curl", "wget",
))
_CTRL_WORDS = frozenset(("if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!"))
_SEPS = frozenset((";", "&&", "||", "|", "\n"))
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/%?&=+,:@-]*)?$")
_METHOD_HDR = re.compile(r"^\s*x-(?:http-)?method(?:-override)?\s*:", re.I)
_SET_OK = re.compile(r"^[-+][euo]+$|^pipefail$")
_CURL_FLAGS = re.compile(r"^-[sSf]+$")
_CURL_LONG = frozenset(("--silent", "--show-error", "--fail", "--fail-with-body", "--compressed"))
_CURL_VALUED = frozenset(("--max-time", "-m", "--connect-timeout", "--retry"))
_ALLOWED_REDIR = re.compile(r"(?<![0-9A-Za-z_])\d?>&\d\b|\d?>>?\s*/dev/null|&>\s*/dev/null")


def _curl_ok(toks):
    urls, i = 0, 0
    while i < len(toks):
        t = toks[i]
        if t in ("-H", "--header") and i + 1 < len(toks):
            if _METHOD_HDR.match(toks[i + 1]):
                return False
            i += 2
        elif t in _CURL_VALUED and i + 1 < len(toks) and re.match(r"^\d{1,4}$", toks[i + 1]):
            i += 2
        elif _CURL_FLAGS.match(t) or t in _CURL_LONG:
            i += 1
        elif t.startswith("-"):
            return False                        # -X, -d, -o, -u, -L, -K, -T, --json, ... anything else
        else:
            if not _URL.match(t):
                return False                    # not a literal https URL (variable, quote trick, http://)
            urls += 1
            i += 1
    return urls == 1


def _wget_ok(toks):
    urls, i = 0, 0
    while i < len(toks):
        t = toks[i]
        if t in ("-qO-", "-O-", "-q", "--quiet", "-nv"):
            i += 1
        elif t == "-O" and i + 1 < len(toks) and toks[i + 1] == "-":
            i += 2
        elif t.startswith("-"):
            return False
        else:
            if not _URL.match(t):
                return False
            urls += 1
            i += 1
    return urls == 1 and ("-qO-" in toks or "-O-" in toks or "-O" in toks)


# Positive per-command flag allowlists: only these exact spellings pass. A single-dash
# cluster passes when every letter is listed; a double-dash option passes only when it
# is listed in full (GNU abbreviations such as --se= are therefore rejected). Anything
# else makes the script "not read-only".
_DIGITS = "0123456789"
_FLAGS = {
    "cat": ("nbsAEeTtuv", (), "--number", "--number-nonblank", "--squeeze-blank", "--show-all",
            "--show-ends", "--show-tabs"),
    "ls": ("1aAdFghiklLnprRsStuxCmH", (), "--all", "--almost-all", "--human-readable", "--classify",
           "--directory", "--recursive", "--reverse", "--size", "--inode", "--si"),
    "head": ("nqvc" + _DIGITS, (), "--quiet", "--silent", "--verbose"),
    "tail": ("nqvc" + _DIGITS, (), "--quiet", "--silent", "--verbose"),
    "grep": ("ivnclLhHsEFGwxqoaIrRzeABC" + _DIGITS, (), "--ignore-case", "--invert-match",
             "--line-number", "--count", "--files-with-matches", "--files-without-match", "--no-filename",
             "--with-filename", "--quiet", "--silent", "--word-regexp", "--line-regexp", "--only-matching",
             "--recursive", "--extended-regexp", "--fixed-strings", "--no-messages"),
    "wc": ("lwcmL", (), "--lines", "--words", "--bytes", "--chars"),
    "stat": ("cLfFt", (), "--dereference", "--file-system", "--terse"),
    "uname": ("asnrvmpio", (), "--all", "--kernel-name", "--nodename", "--kernel-release",
              "--kernel-version", "--machine", "--processor", "--hardware-platform", "--operating-system"),
    "uptime": ("ps", (), "--pretty", "--since"),
    "df": ("aHhiklPTm", (), "--human-readable", "--si", "--all", "--local", "--inodes", "--portability",
           "--print-type"),
    "du": ("ahskcxdSmbHL", (), "--human-readable", "--summarize", "--total", "--all", "--si",
           "--apparent-size"),
    "ps": ("AaefxuwlLjHmcTop", (), "--forest", "--no-headers"),
    "id": ("ugGnrz", (), "--user", "--group", "--groups", "--name", "--real"),
    "whoami": ("", ()),
    "pwd": ("LP", ()),
    "echo": ("neE", ()),
    "jq": ("rcsnSeCMjaR", (), "--raw-output", "--compact-output", "--slurp", "--null-input", "--sort-keys",
           "--exit-status", "--monochrome-output", "--join-output", "--ascii-output", "--raw-input",
           "--tab", "--arg", "--argjson"),
    "date": ("uR", (), "--utc", "--universal", "--rfc-email", "--rfc-3339=date", "--rfc-3339=seconds",
             "--rfc-3339=ns"),
    "hostname": ("sfIid", (), "--short", "--fqdn", "--all-ip-addresses", "--ip-address", "--domain"),
}
for _k, _v in list(_FLAGS.items()):
    _FLAGS[_k] = (frozenset(_v[0]), frozenset(_v[2:]))


def _flags_ok(cmd, args):
    short, longs = _FLAGS[cmd]
    for a in args:
        if a.startswith("--"):
            if a not in longs:                  # exact spelling only; "--" itself is refused too
                return False
        elif a.startswith("-") and len(a) > 1:
            if not all(c in short for c in a[1:]):
                return False
    return True


_DANGEROUS_VAR = re.compile(
    r"^(?:PATH|LD_.*|DYLD_.*|BASH_ENV|ENV|IFS|CDPATH|PS[0-9]|PROMPT_COMMAND|PYTHON.*|NODE_.*|GIT_.*|"
    r"[A-Za-z0-9]*_PROXY|CURL_.*|WGETRC|HOME|SHELL|TMPDIR|SHELLOPTS|BASHOPTS|GLOBIGNORE|FIGNORE|"
    r"BASH_.*|PERL.*|RUBY.*|LANG|LC_.*|TZ|TERM|USER|LOGNAME|OLDPWD|PWD)$", re.I)


def _segment_ok(toks):
    while toks and toks[0] in _CTRL_WORDS:
        toks = toks[1:]
    if not toks:
        return True
    if _ASSIGN.match(toks[0]):
        return False                            # any assignment (PATH=, LD_PRELOAD=, ...) is not read-only
    if toks[0] == "for":                        # for x in a b c  (the body is separate segments)
        return (len(toks) >= 4 and toks[2] == "in" and re.match(r"^[A-Za-z_]\w*$", toks[1]) is not None
                and not _DANGEROUS_VAR.match(toks[1]))
    cmd, args = toks[0], toks[1:]
    if cmd not in READ_CMDS:
        return False
    if cmd in ("grep", "egrep", "fgrep"):
        return _flags_ok("grep", args)
    if cmd in _FLAGS:
        if not _flags_ok(cmd, args):
            return False
        ops = [a for a in args if not (a.startswith("-") and len(a) > 1)]
        if cmd == "date":
            return len(ops) <= 1 and all(o.startswith("+") for o in ops)
        if cmd == "hostname":
            return not ops
        return True
    if cmd == "printf":
        return bool(args) and not args[0].startswith("-") and "-v" not in args
    if cmd == "set":
        return all(_SET_OK.match(a) for a in args) and bool(args)
    if cmd == "curl":
        return _curl_ok(args)
    if cmd == "wget":
        return _wget_ok(args)
    return True


def script_is_read_only(s):
    """True only when the whole script is certainly a plain shell script made of
    plainly read-only commands. Everything else is False (see the module comment)."""
    if s.get("stdin") or s.get("unreadable") or s.get("truncated") or "text" not in s:
        return False
    text = s["text"]
    if len(text) > MAX_TEXT:
        return False
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        if not _SHELL_SHEBANG.match(first):
            return False
    elif not str(s.get("path", "")).endswith((".sh", ".bash")):
        return False
    import shlex
    text = text.replace("\\\n", " ")
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "`" in line or "$(" in line or "<" in line or "\x00" in line:
            return False
        probe = _ALLOWED_REDIR.sub(" ", line)
        if ">" in probe:
            return False
        try:
            lex = shlex.shlex(probe, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            lex.commenters = ""
            toks = list(lex)
        except ValueError:
            return False
        seg = []
        for t in toks:
            if t in _SEPS:
                if not _segment_ok(seg):
                    return False
                seg = []
            elif t and set(t) <= set("();&|") or t == "{" or t == "}":
                return False                    # subshells, background jobs, groups, stray operators
            else:
                seg.append(t)
        if not _segment_ok(seg):
            return False
    return True


def all_read_only(scripts):
    return bool(scripts) and all(script_is_read_only(s) for s in scripts)


# -- the approval card ----------------------------------------------------------

def _size(n):
    return f"{n} bytes" if n < 1024 else f"{n / 1024:.1f} KB"


NOTES = {"missing": "the file was not found", "binary": "binary file", "permission": "permission denied",
         "too_large": "too large to read", "refused": "a protected location that is never read"}


def card_html(scripts):
    """Collapsed 'Script contents' block for the approval card and page. Everything
    from the client is escaped; the text sits in a scrollable <pre>."""
    if not scripts:
        return ""
    e = html.escape
    parts = []
    for s in scripts:
        if s.get("stdin"):
            parts.append("<p class=note>Script is read from standard input and cannot be shown.</p>")
        elif s.get("unreadable"):
            parts.append(f"<p class=note><code>{e(s['path'])}</code><br>Script could not be read: "
                         f"{e(s['unreadable'])}"
                         f"{' (' + e(NOTES[s['unreadable']]) + ')' if s['unreadable'] in NOTES else ''}.</p>")
        else:
            parts.append(
                f"<p class=note><code>{e(s['path'])}</code><br>{e(_size(s['size']))}, sha256 "
                f"<code>{e(s['sha256'][:12])}</code>"
                + ("<br><b>Only the start of this script is shown.</b>" if s.get("truncated") else "")
                + f"</p><pre class=scripttext tabindex=0>{e(s['text'])}</pre>")
    return ("<details class=scripts><summary>Script contents (reported by the client)</summary>"
            + "".join(parts)
            + "<p class=note><small>Advisory: the client chose what to send and runs what it likes. "
              "Obvious secrets are removed.</small></p></details>")


CSS = (".scripts{margin-top:.5rem}.scripts summary{cursor:pointer;color:var(--muted)}"
       ".scripts .note{margin:.4rem 0 .2rem}"
       "pre.scripttext{max-height:14rem;overflow:auto;white-space:pre;font-family:ui-monospace,monospace;"
       "font-size:.78rem;background:var(--card);border:1px solid var(--line);border-radius:.4rem;"
       "padding:.4rem .55rem;margin:.2rem 0}")


# -- broker-side check: does the command run a script the client did not report? --
# The client decides what goes in `scripts`; a client that leaves it out would make a
# script run look like a plain command. This mirrors the client's detection (kept in
# step with client/asb by hand) so the broker can notice the omission. It catches
# clients that omit entries; it cannot stop a client that reports false contents.
# --- shared-detection:begin (identical in client/asb; tests/test_scripts.py compares them) ---
# PRINCIPLE: a command is "understood" only when it is positively recognised; anything
# else (a parse doubt, an unknown option on a wrapper, unusual shell syntax, a program
# that can run other programs) is NOT understood and the broker prompts for it.
# _analyze() returns ([(path, strict)], understood). The paths are the script files the
# command runs ("-": code from stdin); the broker also needs an entry for each.
MAX_SPLIT_DEPTH = 4         # nested env -S / shell strings examined before giving up
MAX_HOPS = 32               # wrapper commands skipped before giving up
_SYSTEM_BIN = ("/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/")
_SCRIPT_EXT = (".sh", ".py", ".js", ".rb", ".pl", ".php", ".ps1", ".lua", ".R")
_NO_SPEC = {"short": "", "valued": {}, "long": frozenset(), "longv": {}, "exact": frozenset(), "digits": False,
            "max_operands": None, "operand": None}
_PLAIN_NUM = r"^\d+(?:\.\d+)?$"
_PLAIN_URL = r"^https?://[^\s@]+$"
_PLAIN_HOST = r"^[A-Za-z0-9._:@+=-]+$"


def _plain(**kw):
    sp = {**_NO_SPEC, **kw}
    sp["long"], sp["exact"] = frozenset(sp["long"]), frozenset(sp["exact"])
    return sp


def _jq_filter_ok(operands):
    return not operands or not re.search(r"\b(?:input_filename|ENV|env|include|import|get_search_list)\b",
                                         operands[0])


# Programs that cannot run other commands, each with an explicit allowlist of its plain
# read-only options (exact spellings; anything else makes the command not understood).
# short: flag letters (may be clustered); valued: short options with a value pattern;
# long / longv: long flags / long options with a value pattern; exact: other whole tokens.
PLAIN_PROGRAMS = {
    "cat": _plain(short="nbsvAET"),
    "ls": _plain(short="lahtr1AFRSdisL"),
    "head": _plain(short="qv", valued={"n": _PLAIN_NUM, "c": _PLAIN_NUM}, digits=True),
    "tail": _plain(short="qvfF", valued={"n": r"^[+]?\d+$", "c": r"^[+]?\d+$"}, digits=True),
    "wc": _plain(short="lwcmL"),
    **{n: _plain(short="invcEFwxrRHhlLqsoaI", valued={"e": None, "m": _PLAIN_NUM, "A": _PLAIN_NUM, "B": _PLAIN_NUM, "C": _PLAIN_NUM})
       for n in ("grep", "egrep", "fgrep")},
    "echo": _plain(short="neE"),
    "printf": _plain(),
    "date": _plain(short="uRI", long=("--utc", "--rfc-email"), max_operands=1,
                   operand=lambda ops: all(o.startswith("+") for o in ops)),
    "uname": _plain(short="asnrvmpio"),
    "uptime": _plain(short="ps"),
    "df": _plain(short="hHTikPla"),
    "du": _plain(short="shackmbx", valued={"d": r"^\d+$"}),
    "ps": _plain(short="aefulwAxHjLm", valued={"p": r"^[\d,]+$"},
                 operand=lambda ops: all(re.match(r"^[A-Za-z]+$", o) for o in ops)),
    "id": _plain(short="ugGnrz", max_operands=1),
    "whoami": _plain(max_operands=0),
    "hostname": _plain(short="sfiI", max_operands=0),
    "pwd": _plain(short="LP", max_operands=0),
    "stat": _plain(short="L", valued={"c": None}),
    "jq": _plain(short="rcesnSCMajR", long=("--raw-output", "--compact-output", "--exit-status", "--slurp",
                                         "--null-input", "--sort-keys", "--tab", "--join-output"),
                 operand=_jq_filter_ok),
    "ping": _plain(short="n46q", valued={"c": r"^\d+$", "W": _PLAIN_NUM, "w": r"^\d+$", "i": _PLAIN_NUM},
                   max_operands=1, operand=lambda ops: all(re.match(_PLAIN_HOST, o) for o in ops)),
    "dig": _plain(short="46x", valued={"t": r"^[A-Za-z]+$", "p": r"^\d+$"},
                  operand=lambda ops: all(re.match(_PLAIN_HOST, o) for o in ops)),
    "nslookup": _plain(operand=lambda ops: all(re.match(_PLAIN_HOST, o) for o in ops)),
    "sha256sum": _plain(short="bt"),
    "md5sum": _plain(short="bt"),
    "sort": _plain(short="nrubdfghMVsc", valued={"k": r"^[\d.,nrb]+$", "t": r"^.$"}),
    "uniq": _plain(short="cdui", max_operands=1),
    "test": _plain(exact=("-e", "-f", "-d", "-r", "-w", "-x", "-s", "-z", "-n", "-L", "-h", "-eq", "-ne", "-lt",
                          "-le", "-gt", "-ge", "-a", "-o")),
    "true": _plain(max_operands=0),
    "false": _plain(max_operands=0),
    "curl": _plain(short="sSfLI", valued={"H": r"^[^\n\r@]+$", "X": r"^(?:GET|HEAD)$"},
                   long=("--silent", "--show-error", "--fail", "--location", "--head"),
                   longv={"--max-time": _PLAIN_NUM, "--connect-timeout": _PLAIN_NUM, "--retry": r"^\d+$",
                          "--header": r"^[^\n\r@]+$", "--request": r"^(?:GET|HEAD)$"},
                   operand=lambda ops: all(re.match(_PLAIN_URL, o) for o in ops)),
}
def _val_ok(rx, v):
    return "\0" not in v and (rx is None or bool(re.match(rx, v)))


def _plain_ok(name, args):
    sp = PLAIN_PROGRAMS[name]
    operands, i, opts = [], 0, True
    while i < len(args):
        a = args[i]
        if "\0" in a:
            return False
        if opts and a == "--":
            opts, i = False, i + 1
        elif opts and a.startswith("--"):
            nm, eq, val = a.partition("=")
            if nm in sp["long"] and not eq:
                i += 1
            elif nm in sp["longv"]:
                if eq:
                    v, i = val, i + 1
                elif i + 1 < len(args):
                    v, i = args[i + 1], i + 2
                else:
                    return False
                if not _val_ok(sp["longv"][nm], v):
                    return False
            else:
                return False
        elif opts and a.startswith("-") and len(a) > 1:
            i += 1
            if a in sp["exact"] or (sp["digits"] and re.fullmatch(r"-\d+", a)):
                continue
            j = 1
            while j < len(a):
                c = a[j]
                if c in sp["short"]:
                    j += 1
                elif c in sp["valued"]:
                    rest = a[j + 1:]
                    if rest:
                        v = rest
                    elif i < len(args):
                        v, i = args[i], i + 1
                    else:
                        return False
                    if not _val_ok(sp["valued"][c], v):
                        return False
                    break
                else:
                    return False
        else:
            operands.append(a)
            i += 1
    if sp["max_operands"] is not None and len(operands) > sp["max_operands"]:
        return False
    return sp["operand"] is None or bool(sp["operand"](operands))


def _w(s="", sv="", so="", l=(), lv=(), pos=0, pos_unless=(), digits=False, dash=False, chdir=()):
    # chdir: options that change the directory/filesystem view the command runs in ("*": always),
    # after which the files the client read are not the ones that run: not understood
    return {"s": s, "sv": sv, "so": so, "l": frozenset(l), "lv": frozenset(lv), "pos": pos,
            "pos_unless": frozenset(pos_unless), "digits": digits, "dash": dash, "chdir": frozenset(chdir)}


# wrapper -> its recognised options. s: flags, sv: options taking a value, so: optional
# attached value (rest of the cluster), l/lv: long flags / long options with a value.
# An option not listed means the command is not understood.
SCRIPT_WRAPPERS = {
    "sudo": _w("nH", "u", l=("--non-interactive", "--set-home"), lv=("--user",)),
    "doas": _w("n", "u"),
    "nohup": _w(),
    "time": _w(),
    "timeout": _w("", "sk", l=("--preserve-status", "--foreground"), lv=("--signal", "--kill-after"), pos=1),
    "nice": _w("", "n", lv=("--adjustment",)),
    "stdbuf": _w("", "ioe", lv=("--input", "--output", "--error")),
    "exec": _w(),
    "command": _w(),
}
_ENV_OPTS = _w("i0", "u", l=("--ignore-environment", "--null"), lv=("--unset",))
_ENV_NAMES = re.compile(r"^(?:LANG|LANGUAGE|LC_[A-Z_]+|TZ|TERM|COLUMNS|LINES|NO_COLOR|CLICOLOR|FORCE_COLOR|CI|"
                        r"DEBUG|VERBOSE|TERM_PROGRAM|PYTHONUNBUFFERED|PYTHONDONTWRITEBYTECODE|PYTHONIOENCODING|"
                        r"NODE_NO_WARNINGS)$")


def _assignment(word):
    """None when `word` is not NAME=value; else True/False: is it an allowed assignment
    (an allowlisted NAME, and a value with no $, backslash, backtick or newline)."""
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", word, re.S)
    if not m:
        return None
    return bool(_ENV_NAMES.match(m.group(1))) and not re.search(r"[$\\`\n\r\0/ \t]", m.group(2))


_SHELL_RESERVED = frozenset("if then else elif fi for while until do done case esac function select time { } ! [[ "
                      "coproc in".split())
# interpreter name pattern -> (kind, flags that take the next arg, inline-code flags, stdin flags)
_SHELLS = r"(?:ba|z|da|k|a|c|tc)?sh|fish"
SCRIPT_INTERPRETERS = (
    (re.compile(r"^(?:%s)$" % _SHELLS), {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}, {"-c"}, {"-s"}),
    (re.compile(r"^python(?:\d+(?:\.\d+)*)?$"), {"-W", "-X", "-Q"}, {"-c", "-m"}, set()),
    (re.compile(r"^(?:node|nodejs)$"), {"-r", "--require", "--import", "--loader", "--input-type"},
     {"-e", "--eval", "-p", "--print"}, set()),
    (re.compile(r"^ruby$"), {"-I", "-r", "-C", "-x"}, {"-e"}, set()),
    (re.compile(r"^perl$"), {"-I", "-M", "-m"}, {"-e", "-E"}, set()),
    (re.compile(r"^php$"), {"-d", "-c", "-z"}, {"-r"}, set()),
    (re.compile(r"^(?:pwsh|powershell)$"), set(), {"-c", "-command", "-encodedcommand", "-e"}, set()),
    (re.compile(r"^(?:lua|luajit)$"), {"-l"}, {"-e"}, set()),
    (re.compile(r"^Rscript$"), set(), {"-e"}, set()),
)
SCRIPT_FILE_FLAGS = {"php": {"-f"}, "awk": {"-f", "--file"}, "gawk": {"-f", "--file"}, "mawk": {"-f"},
                     "sed": {"-f", "--file"}, "pwsh": {"-file", "-f"}, "powershell": {"-file", "-f"}}
_AWK_LIKE = re.compile(r"^(?:awk|gawk|mawk|sed)$")
_RUNNERS = re.compile(r"^(?:deno|bun)$")


def _script_args(name, args, loaders=True):
    """-> ("file", [candidate paths]) | ("inline", None) | ("stdin", None) | ("none", None)
    for the arguments of a recognised interpreter."""
    spec = next((x for x in SCRIPT_INTERPRETERS if x[0].match(name)), None)
    is_awk = bool(_AWK_LIKE.match(name))
    if spec is None and not is_awk and not _RUNNERS.match(name):
        return None
    lo = _loader_opts(name) if loaders else set()
    if _RUNNERS.match(name):
        # deno run [opts] file | deno eval ... | bun [run] file
        sub = args[0] if args else ""
        if sub == "eval":
            return ("inline", None)
        rest = args[1:] if sub in ("run", "x") else args
        for i, a in enumerate(rest):
            if a == "-":
                return ("stdin", None)
            if not a.startswith("-"):
                return ("file", [a])
        return ("none", None)
    if is_awk:
        files, i = [], 0
        ffl = SCRIPT_FILE_FLAGS[name] if name in SCRIPT_FILE_FLAGS else SCRIPT_FILE_FLAGS["awk"]
        inline = False
        while i < len(args):
            a = args[i]
            if a in ffl and i + 1 < len(args):
                files.append(args[i + 1])
                i += 2
                continue
            if a.startswith("--file="):
                files.append(a.split("=", 1)[1])
            elif a in ("-e", "--expression", "--source") or a.startswith(("--expression=", "--source=")):
                inline = True
                if a in ("-e", "--expression", "--source"):
                    i += 1
            elif a.startswith("-") and a != "-":
                pass
            elif not files and not inline:
                return ("inline", None)             # the program text is the first operand
            else:
                break
            i += 1
        if files and inline:
            return ("unknown", None)
        return ("file", files) if files else ("inline" if inline else "none", None)
    _, valued, inline_flags, stdin_flags = spec
    short_inline = {f[1] for f in inline_flags if len(f) == 2}
    short_stdin = {f[1] for f in stdin_flags if len(f) == 2}
    ffl = SCRIPT_FILE_FLAGS.get(name, set())
    i = 0
    while i < len(args):
        a = args[i]
        if lo and (a in lo or a.split("=")[0] in lo or (len(a) > 2 and not a.startswith("--") and a[:2] in lo)):
            return ("unknown", None)                # loads code that is not a reported script
        if a == "--":
            return ("file", [args[i + 1]]) if i + 1 < len(args) else ("none", None)
        if a == "-":
            return ("stdin", None)
        if a in ffl and i + 1 < len(args):
            return ("file", [args[i + 1]])
        if a in inline_flags or a.lower() in inline_flags:
            return ("inline", args[i + 1] if i + 1 < len(args) else None)
        if a in stdin_flags:
            return ("stdin", None)
        if a in valued:
            i += 2
            continue
        if name == "perl" and re.match(r"^-[A-Za-z]*[eE]$", a):
            return ("inline", None)
        if re.match(r"^-[A-Za-z]+$", a) and len(a) > 2 and name != "perl":
            letters = a[1:]
            if short_inline & set(letters):
                return ("inline", args[i + 1] if i + 1 < len(args) else None)
            if short_stdin & set(letters):
                return ("stdin", None)
        elif a.startswith("-") or a.startswith("+"):
            if name == "perl" and re.match(r"^-[eE]", a):
                return ("inline", None)
            if name.startswith("python") and re.match(r"^-[cm]", a):
                return ("inline", None)
        else:
            return ("file", [a])
        i += 1
    return ("none", None)


def _loader_opts(name):
    """Interpreter options that load code which is not a reported script."""
    if name in ("node", "nodejs"):
        return {"-r", "--require", "--import", "--loader", "--experimental-loader"}
    if name == "ruby":
        return {"-r", "-I"}
    if name == "perl":
        return {"-M", "-m", "-I"}
    if name == "php":
        return {"-d", "-c", "-z"}
    if name in ("lua", "luajit"):
        return {"-l"}
    if re.match(r"^(?:%s)$" % _SHELLS, name):
        return {"--rcfile", "--init-file"}
    return set()


def _canon_long(nm, spec):
    names = spec["l"] | spec["lv"]
    if nm in names:
        return nm
    hits = [n for n in names if len(nm) > 2 and n.startswith(nm)]
    return hits[0] if len(hits) == 1 else None


def _parse_one(args, i, spec, seen, vals):
    """Parse the option at args[i] -> index after it, or None when not recognised."""
    a = args[i]
    if a.startswith("--"):
        nm, eq, val = a.partition("=")
        canon = _canon_long(nm, spec)
        if canon is None:
            return None
        seen.add(canon)
        if canon in spec["lv"]:
            if eq:
                vals.append((canon, val))
                return i + 1
            if i + 1 >= len(args):
                return None
            vals.append((canon, args[i + 1]))
            return i + 2
        return i + 1
    if spec["digits"] and re.fullmatch(r"-\d+", a):
        return i + 1
    j, nxt = 1, i + 1
    while j < len(a):
        c = a[j]
        seen.add("-" + c)
        if c in spec["sv"]:
            rest = a[j + 1:]
            if rest:
                vals.append(("-" + c, rest))
                return nxt
            if nxt >= len(args):
                return None
            vals.append(("-" + c, args[nxt]))
            return nxt + 1
        if c in spec["so"]:
            vals.append(("-" + c, a[j + 1:]))
            return nxt
        if c not in spec["s"]:
            return None
        j += 1
    return nxt


def _parse_opts(args, spec):
    """-> (operands, seen options, [(option, value)]) or None when an option is not
    recognised (or the wrapper changes the directory/filesystem the command runs in)."""
    i, seen, vals = 0, set(), []
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a == "-" and spec["dash"]:
            seen.add("-")
            i += 1
        elif a.startswith("-") and len(a) > 1:
            i = _parse_one(args, i, spec, seen, vals)
            if i is None:
                return None
        else:
            break
    if spec["chdir"] and ("*" in spec["chdir"] or seen & spec["chdir"]):
        return None
    return args[i:], seen, vals


def _env_unwrap(args, splits):
    """env's options and VAR=value words skipped -> (command argv, splits used), or
    (None, splits) when something is not recognised. An -S/--split-string value is
    split with shlex and parsing carries on over the pieces; a value with a
    backslash, $, # or newline (GNU env's own escapes and comments) is refused."""
    i, done, seen, vals = 0, False, set(), []
    while i < len(args):
        a = args[i]
        if not done and a == "--":
            done, i = True, i + 1
        elif not done and a == "-":
            i += 1
        elif not done and a.startswith("-") and len(a) > 1:
            n0 = len(vals)
            i = _parse_one(args, i, _ENV_OPTS, seen, vals)
            if i is None or seen & _ENV_OPTS["chdir"]:
                return None, splits
            for k, v in vals[n0:]:
                if k in ("-S", "--split-string"):
                    splits += 1
                    if re.search(r"[\\$#\n\r\0]", v):
                        return None, splits
                    try:
                        pieces = shlex.split(v)
                    except ValueError:
                        return None, splits
                    args, i = pieces + args[i:], 0
        else:
            ok = _assignment(a)
            if ok is None:
                break
            if not ok:
                return None, splits
            i += 1
    return args[i:], splits


def _shell_string(s, depth):
    """A restricted shell command line -> ([(path, strict)], understood). Anything
    beyond plain words, quotes, && || ; | and a lone 2>&1 is not understood; every
    command in it must itself be understood."""
    if depth > MAX_SPLIT_DEPTH or not isinstance(s, str):
        return [], False
    if re.search(r"[\n\r#`$\\\0]", s) or "<<" in s or "<(" in s or ">(" in s:
        return [], False
    segs, word, i, n = [[]], None, 0, len(s)
    while i < n:
        c = s[i]
        if c in " \t":
            if word is not None:
                segs[-1].append("".join(word))
                word = None
            i += 1
        elif c in "'\"":
            j = s.find(c, i + 1)
            if j < 0:
                return [], False
            word = (word or []) + list(s[i + 1:j])
            i = j + 1
        elif c in "&|;":
            two = s[i:i + 2]
            if two in (";;", "|&") or (c == "&" and two != "&&"):
                return [], False
            if word is not None:
                segs[-1].append("".join(word))
                word = None
            segs.append([])
            i += len(two) if two in ("&&", "||") else 1
        elif c in "<>":
            if c == ">" and word == ["2"] and s.startswith(">&1", i) and (i + 3 == n or s[i + 3] in " \t&|;"):
                word = None
                i += 3
            else:
                return [], False
        elif c in "(){}":
            return [], False
        else:
            word = (word or []) + [c]
            i += 1
    if word is not None:
        segs[-1].append("".join(word))
    out, ok = [], True
    for seg in segs:
        while seg and _assignment(seg[0]) is not None:      # the shell performs VAR=value prefixes
            if not _assignment(seg[0]):
                return out, False
            seg = seg[1:]
        if not seg or seg[0] in _SHELL_RESERVED:
            return out, False
        found, good = _analyze(seg, depth + 1)
        out += [x for x in found if x not in out]
        ok = ok and good
    return out, ok


def _bad_path(p):
    return "\0" in p or "\n" in p or ".." in p.split("/") or any(c in p for c in "*?[")


def _in_system_bin(p):
    return not _bad_path(p) and os.path.isabs(p) and os.path.normpath(p).startswith(_SYSTEM_BIN)


def _analyze(argv, depth=0, trace=None):
    """-> ([(path, strict)], understood). `strict` marks argv[0] itself being the
    script (a client may skip a compiled program); "-" is code read from stdin.
    understood is True only when every command in argv is positively recognised: a
    plain program, an interpreter with a script file or a restricted shell string,
    or a known wrapper whose command is understood. See argv_runs_script."""
    out = []

    def add(p, strict=False):
        if (p, strict) not in out:
            out.append((p, strict))

    def merge(items):
        for it in items:
            add(*it)
    cmd, hops, splits = list(argv), 0, 0
    while True:
        if not cmd:
            return out, False                   # nothing left to run: not understood
        hops += 1
        if hops > MAX_HOPS or depth + splits > MAX_SPLIT_DEPTH:
            return out, False
        a0, args = cmd[0], cmd[1:]
        if _bad_path(a0):
            return out, False
        if _assignment(a0) is not None:                     # only env and shell strings may assign
            return out, False
        name = os.path.basename(a0)
        simple = "/" not in a0 or _in_system_bin(a0)        # bare name or a standard system path
        if simple and name == "env":
            nxt, splits = _env_unwrap(args, splits)
            if nxt is None or depth + splits > MAX_SPLIT_DEPTH:
                return out, False
            if not nxt:
                # a bare `env` (plain options only) just prints the environment
                return out, hops == 1 and depth == 0 and splits == 0 and not any("=" in a for a in args)
            cmd = nxt
            continue
        if simple and name in SCRIPT_WRAPPERS:
            parsed = _parse_opts(args, SCRIPT_WRAPPERS[name])
            if parsed is None:
                return out, False
            rest, seen, _ = parsed
            spec = SCRIPT_WRAPPERS[name]
            if not (seen & spec["pos_unless"]):
                if len(rest) < spec["pos"]:
                    return out, False
                rest = rest[spec["pos"]:]
            cmd = rest
            continue
        break
    if trace is not None:
        trace["cmd"] = cmd
    found = _script_args(name, args) if ("/" not in a0 or os.path.isabs(a0)) else None
    if found is not None:
        kind, payload = found
        if kind == "stdin" or (kind == "none" and not name.startswith(("sed", "awk", "gawk", "mawk"))):
            add("-")
            return out, True
        if kind == "file":
            for p in payload:
                add(p)
            return out, True
        if kind == "inline" and re.match(r"^(?:ba|z|da|k|a)?sh$", name):
            found2, good = _shell_string(payload, depth + 1)
            merge(found2)
            return out, good
        if kind == "unknown":                               # still report the script file(s), if any
            again = _script_args(name, args, False)
            if again and again[0] == "file":
                merge((q, False) for q in again[1])
        return out, False                                   # other inline code, unknown options, bare sed/awk
    if a0.endswith(_SCRIPT_EXT) or ("/" in a0 and not _in_system_bin(a0)):
        add(a0, True)                                       # the command is itself a script file
        return out, True
    if simple and name in PLAIN_PROGRAMS:
        return out, _plain_ok(name, args)
    return out, False


def argv_runs_script(argv):
    """The script files `argv` appears to execute, in order ([] when none): an
    interpreter's script operand, a script run directly (a script extension or a
    path outside /bin, /usr/bin, /sbin, /usr/sbin, compared after normpath), looked
    through wrappers and the commands of restricted shell strings. "-" is code read
    from standard input. Whether the whole command is understood is separate:
    see argv_understood."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        return []
    return [p for p, _ in _analyze(argv)[0]]


def argv_understood(argv):
    """True only when every command in `argv` is positively recognised (see
    _analyze). Anything else is not visible: the broker prompts for it."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        return False
    return _analyze(argv)[1]
# --- shared-detection:end ---


def _norm(p):
    return os.path.normpath(p)


def _same_path(p, cand, cwd=None):
    """Does operand `p` (as written in argv) name the file the client reported as
    `cand`? Full normalised paths only, never a bare file name: an absolute operand
    must equal it; a relative one is resolved against `cwd` when given, else must be
    a whole trailing path (at a `/` boundary) of an absolute `cand`."""
    if not isinstance(cand, str) or "\0" in p or "\0" in cand:
        return False
    c = _norm(cand)
    if os.path.isabs(p):
        return _norm(p) == c
    if cwd:
        return _norm(os.path.join(cwd, p)) == c
    r = _norm(p)
    return r == c or (os.path.isabs(c) and c.endswith("/" + r) and not r.startswith(("..", "/")))


def validate_cwd(raw):
    """The client's working directory (absolute, at most MAX_PATH characters, no
    control characters) or None when not sent. Raises ValueError otherwise."""
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.startswith("/") or not _PATH_RE.match(raw):
        raise ValueError(f"cwd must be an absolute path of at most {MAX_PATH} printable characters")
    return raw


def script_not_visible(argv, scripts, cwd=None):
    """True when the script text for this command is not fully visible: an entry is
    unreadable, from stdin or cut off, `argv` is not positively understood, or it runs
    a script file that has no matching readable entry in `scripts`."""
    scripts = scripts or []
    if has_blind_spot(scripts):
        return True
    if not argv_understood(argv):
        return True
    for p in argv_runs_script(argv):
        if p == "-" or not any(_same_path(p, s[k], cwd) for s in scripts for k in ("path", "given") if k in s):
            return True
    return False
