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
        keys = set(e)
        if keys == _KEYS_STDIN:
            if e["stdin"] is not True:
                raise ValueError(f"scripts[{i}].stdin must be true")
            out.append({"stdin": True})
        elif keys == _KEYS_UNREADABLE:
            if e["unreadable"] not in UNREADABLE:
                raise ValueError(f"scripts[{i}].unreadable must be one of {', '.join(UNREADABLE)}")
            out.append({"path": _path(e["path"], i), "unreadable": e["unreadable"]})
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
