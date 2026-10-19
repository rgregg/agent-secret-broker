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
log. The audit log gets paths, sizes, hashes and marker classes only. Keeping
text for the request history is a separate store (issue #9); until then the
history pop-over shows path, size and hash only.
"""
import html
import os
import re

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
REDACTED = "[redacted]"
_NOT_VAR = r"(?![\$\{\(<\[%/~.])"        # a value that is not a variable, placeholder or path
_SCRUBS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
     "-----BEGIN PRIVATE KEY----- " + REDACTED),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), REDACTED),
    (re.compile(r"(?i)\b(bearer|basic|token)(\s+)" + _NOT_VAR + r"[A-Za-z0-9._~+/=-]{16,}"),
     lambda m: m.group(1) + m.group(2) + REDACTED),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^/\s@]{3,}(@)"), lambda m: m.group(1) + REDACTED + m.group(2)),
    (re.compile(r"(?i)(\s-u\s+['\"]?[^\s:'\"]+:)" + _NOT_VAR + r"[^\s'\"]{3,}"),
     lambda m: m.group(1) + REDACTED),
    (re.compile(r"(?i)\b(x-api-key|api-key|x-auth-token|x-token)(\s*:\s*['\"]?)" + _NOT_VAR + r"[A-Za-z0-9._~+/=-]{8,}"),
     lambda m: m.group(1) + m.group(2) + REDACTED),
    # NAME=value / name: "value" where the name says it is a secret
    (re.compile(r"(?i)(\b[A-Za-z0-9_-]*(?:password|passwd|pwd|passphrase)[A-Za-z0-9_-]*['\"]?\s*[:=]\s*['\"]?)"
                + _NOT_VAR + r"[^\s'\"`;&|)]{4,}"), lambda m: m.group(1) + REDACTED),
    (re.compile(r"(?i)(\b[A-Za-z0-9_-]*(?:token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
                r"auth|credential)[A-Za-z0-9_-]*['\"]?\s*[:=]\s*['\"]?)" + _NOT_VAR
                + r"[A-Za-z0-9+/=_.:@!#%^&*~-]{8,}"), lambda m: m.group(1) + REDACTED),
)


def scrub(text):
    """Replace obvious secret-looking values with [redacted]. Idempotent."""
    if not isinstance(text, str):
        return ""
    for rx, rep in _SCRUBS:
        text = rx.sub(rep, text)
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

_SHELL_SHEBANG = re.compile(r"^#!\s*(?:/usr/bin/env\s+(?:-S\s+)?)?\S*?(?:ba|z|da|k)?sh\b")
READ_CMDS = frozenset((
    "echo", "printf", "cat", "ls", "grep", "egrep", "fgrep", "head", "tail", "wc", "date", "sort", "uniq",
    "jq", "cut", "tr", "basename", "dirname", "pwd", "true", "false", "test", "[", "[[", "set",
    "export", "cd", "exit", "return", "read", "local", "declare", "uname", "hostname", "whoami", "id",
    "uptime", "df", "du", "free", "ps", "stat", "file", "which", "type", "sleep", "curl", ":",
))
_CTRL_WORDS = frozenset(("if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}",
                         "for", "esac"))
_CURL_WRITE = re.compile(r"(?:^|\s)(?:-X|--request|-d|--data\S*|-F|--form\S*|-T|--upload-file|-o|-O|--output|"
                         r"-K|--config|--json|-w|--post\S*|--remote-name\S*|-J)(?:\s|=|$)|\s-[A-Za-z]*[dFToOXK]\b")


def script_is_read_only(s):
    """True only when the whole script is certainly a plain shell script made of
    read-like commands. Anything unusual (other languages, substitutions,
    redirections other than to /dev/null, pipes into non-read commands, heredocs,
    functions, unknown commands, cut text) is NOT certain, so False."""
    if s.get("stdin") or s.get("unreadable") or s.get("truncated") or "text" not in s:
        return False
    text = s["text"]
    first = text.split("\n", 1)[0]
    if first.startswith("#!"):
        if not _SHELL_SHEBANG.match(first):
            return False
    elif not str(s.get("path", "")).endswith((".sh", ".bash")):
        return False
    text = text.replace("\\\n", " ")
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.search(r"[`]|\$\(|<<|<\(|>\(|\beval\b|\bsource\b|^\.\s", line):
            return False
        probe = re.sub(r"\d?>\s*&\d|\d?>>?\s*/dev/null|&>\s*/dev/null", "", line)
        if ">" in probe or "<" in probe:
            return False
        for seg in re.split(r"&&|\|\||[;|&]|\n", probe):
            toks = seg.split()
            while toks and (toks[0] in _CTRL_WORDS or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0])):
                if toks[0] == "for":
                    toks = []
                    break
                toks = toks[1:]
            if not toks:
                continue
            cmd = toks[0]
            if cmd not in READ_CMDS:
                return False
            rest = " ".join(toks[1:])
            if cmd == "curl" and _CURL_WRITE.search(" " + rest):
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
