"""Remote commands: request mode `exec`.

The agent asks the broker to run ONE command or script on a host over SSH, with a stored SSH key;
the broker connects (execrun.py), runs exactly that text and returns the output. Because the
broker can read the command, the human, the risk model and the auto-approve rules all see it
before anything runs. See docs/superpowers/specs/2026-11-19-remote-exec-design.md.

This module is the pure part, plain data in and out: the config parser, the request checks, the
command grammar and read-only table, the exact payload that is sent, and the card/notification/
audit text. Invariants (enforced in broker.py and execrun.py, tested in tests/test_exec_*.py):
  * off by default: `exec.enabled` must be true AND the client's id in `exec.clients`; the legacy
    shared key is never accepted;
  * the text that runs is the text that was classified and shown: a simple command is rebuilt from
    its parsed argv (`rebuild`) and that string is what the remote shell receives; anything else
    is sent byte for byte; a script goes on stdin with its SHA-256 on the card;
  * only a SIMPLE command (a deliberately tiny grammar, no shell syntax at all) on the read-only
    table is low without a model. Everything else is the risk model's call and defaults to high;
  * the request chooses host, user, port, the command and a timeout; nothing else, and none of it
    can become an ssh option (validate refuses a host, user or command that begins with a dash).
"""
import hashlib
import html
import os
import re

from . import clients as clients_mod
from . import guidance as guidance_mod
from . import sshkey
from . import sudomode

MODE = "exec"
DEFAULTS = {"enabled": False, "clients": [], "max_concurrent": 4, "max_output_bytes": 262144,
            "max_seconds": 600, "max_pending_per_client": 3, "readonly": [], "ssh_path": None,
            "probe_per_client": 30, "probe_overall": 120}
MAX_COMMAND_CHARS = 4096
MAX_SCRIPT_BYTES = 32 * 1024
DEFAULT_TIMEOUT_S = 60
INTERPRETERS = ("sh", "bash")
AUDIT_WORDS, AUDIT_WORD_CHARS = 50, 300
LABELS = ("host_key_mismatch", "host_not_pinned", "connect_failed", "auth_failed", "timeout", "output_cap",
          "ssh_unavailable", "internal")

_BAD_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")       # tab and newline are legal
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_FIELDS = {"host", "user", "port", "command", "script", "timeout_s"}
HOST_STATES = ("new", "same_key_elsewhere", "changed")      # a request for a host the key does not fully pin (execprobe)
FIRST_USE = "First time seeing this key. Compare the fingerprint with the host before approving."
CHANGED_TEXT = ("This server's key is not the one you pinned. This is what a man-in-the-middle looks like; it is "
                "also what a reinstalled or rekeyed server looks like. Approve only if you expect that.")
_FP_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_KEY_RE = re.compile(r"(?:ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) [A-Za-z0-9+/]{20,}={0,2}")
WARNING = ("An agent asked the broker to run this on a remote host over SSH. The text shown is exactly what "
           "will run. Approve only a command you recognise and meant to allow.")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ---------------------------------------------------------------- config

def parse_config(raw, field="exec"):
    """Validate `exec` -> the full config dict (DEFAULTS filled in). None means the defaults (off).
    Raises ValueError naming the field; messages never echo a value."""
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
    if not isinstance(out["clients"], list) or not all(
            isinstance(c, str) and clients_mod.ID_RE.fullmatch(c) for c in out["clients"]):
        raise ValueError(f"{field}.clients must be a list of client ids such as c-1a2b3c4d")
    out["clients"] = sorted(set(out["clients"]))
    for key, lo, hi in (("max_concurrent", 1, 32), ("max_output_bytes", 1024, 16 * 1024 * 1024),
                        ("max_seconds", 1, 600), ("max_pending_per_client", 1, 20),
                        ("probe_per_client", 1, 1000), ("probe_overall", 1, 5000)):
        if not _int(out[key]) or not lo <= out[key] <= hi:
            raise ValueError(f"{field}.{key} must be a whole number from {lo} to {hi}")
    ro = out["readonly"]
    if not isinstance(ro, list) or len(ro) > 100 or not all(_extension_ok(e) for e in ro):
        raise ValueError(f"{field}.readonly must be a list of up to 100 entries, each a program name "
                         "(or an absolute path in a standard bin directory) and up to two plain subcommand words")
    out["readonly"] = sorted(set(ro))
    sp = out["ssh_path"]
    if sp is not None and not (isinstance(sp, str) and os.path.isabs(sp) and "\x00" not in sp):
        raise ValueError(f"{field}.ssh_path must be an absolute directory holding ssh, ssh-agent, ssh-add and ssh-keyscan")
    return out


def check_allowed(cfg, client):
    """PermissionError unless exec requests are enabled and `client` (a client view) may make them.
    The messages say what to fix without revealing the allow-list."""
    if not cfg["enabled"]:
        raise PermissionError("remote command requests are disabled")
    cid = (client or {}).get("id")
    if (client or {}).get("legacy") or cid not in cfg["clients"]:
        raise PermissionError("this client may not make remote command requests")


# ---------------------------------------------------------------- request checks

def validate(spec, cfg=None):
    """Check the agent-side fields of an exec request and rewrite `spec` in place to the normalized
    {"host", "user", "port", "timeout_s", and "command" or "script": {"text", "interpreter"}}.
    Raises ValueError; a message never repeats what the agent sent."""
    cfg = cfg or DEFAULTS
    if any(k not in _FIELDS for k in spec):
        raise ValueError("unknown field in an exec request")
    host = spec.get("host")
    host = host.lower() if isinstance(host, str) else host
    if not (isinstance(host, str) and _HOST_RE.fullmatch(host) and ".." not in host):
        raise ValueError("host must be a plain host name (letters, digits, dots and dashes)")
    user = spec.get("user")
    if not (isinstance(user, str) and sshkey.ACCOUNT_RE.fullmatch(user) and not user.startswith("-")):
        raise ValueError("user must be a plain account name (printable ASCII, no spaces, not starting with a dash)")
    port = 22 if spec.get("port") is None else spec["port"]
    if not _int(port) or not 1 <= port <= 65535:
        raise ValueError("port must be a whole number from 1 to 65535")
    maxs = cfg["max_seconds"]
    timeout = min(DEFAULT_TIMEOUT_S, maxs) if spec.get("timeout_s") is None else spec["timeout_s"]
    if not _int(timeout) or not 1 <= timeout <= maxs:
        raise ValueError(f"timeout_s must be a whole number of seconds from 1 to {maxs}")
    command, script = spec.get("command"), spec.get("script")
    if (command is None) == (script is None):
        raise ValueError("give exactly one of command and script")
    out = {"host": host, "user": user, "port": port, "timeout_s": timeout}
    if command is not None:
        if not isinstance(command, str) or not command.strip():
            raise ValueError("command must be a non-empty string")
        if len(command) > MAX_COMMAND_CHARS:
            raise ValueError(f"command is longer than {MAX_COMMAND_CHARS} characters")
        _check_text(command, "command")
        if command.lstrip().startswith("-"):
            # after the host, an old ssh client would read a leading dash as one of its own options
            raise ValueError("command must not start with a dash")
        out["command"] = command
    else:
        if not isinstance(script, dict) or set(script) - {"text", "interpreter"}:
            raise ValueError("script must be an object with text and an optional interpreter")
        text, interp = script.get("text"), script.get("interpreter", "sh")
        if not isinstance(text, str) or not text:
            raise ValueError("script text must be a non-empty string")
        if interp not in INTERPRETERS:
            raise ValueError("script interpreter must be sh or bash")
        if len(text.encode("utf-8", "surrogatepass")) > MAX_SCRIPT_BYTES:
            raise ValueError(f"script is longer than {MAX_SCRIPT_BYTES} bytes")
        _check_text(text, "script")
        out["script"] = {"text": text, "interpreter": interp}
    spec.clear()
    spec.update(out)


def _check_text(text, what):
    if _BAD_CHARS.search(text) or "\r" in text:
        raise ValueError(f"{what} contains a control character")
    bad = guidance_mod.hidden_problem(text)
    if bad:
        raise ValueError(f"{what} contains hidden characters ({bad[0]})")


# ---------------------------------------------------------------- grammar

_UNQUOTED_BAD = set(";&|<>()$`\\\n*?[]{}~!#\t\r")
_DQ_BAD = set("$`\\")
# Inside quotes a POSIX shell reads these literally, but fish (backslash), csh and tcsh (newline, `!` history) do not, and
# the login shell on the target is not ours to know: a command with such a character in any word is not simple, so it is
# never low, never matched by a rule, and is sent byte for byte for the model and the human to judge.
_NON_POSIX_IN_QUOTES = "\\\n!"
_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_SAFE_WORD = re.compile(r"[A-Za-z0-9@%+=:,./_-]+", re.ASCII)      # what a shell reads literally, unquoted


def parse_simple(text):
    """The argv of `text` under the deliberately small grammar, or None when it is not simple: words
    separated by spaces; single quotes literal; double quotes with no `$`, backtick or backslash;
    and none of `; & | < > ( ) $ ` backtick \\ newline * ? [ ] { } ~ ! #` (or a tab) outside quotes.
    A leading NAME=value is not simple (it sets an environment the argv would not show)."""
    argv, cur, started, i, n = [], [], False, 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            j = text.find("'", i + 1)
            if j < 0:
                return None
            cur.append(text[i + 1:j])
            started, i = True, j + 1
        elif ch == '"':
            j = text.find('"', i + 1)
            if j < 0:
                return None
            body = text[i + 1:j]
            if any(c in _DQ_BAD for c in body):
                return None
            cur.append(body)
            started, i = True, j + 1
        elif ch == " ":
            if started:
                argv.append("".join(cur))
                cur, started = [], False
            i += 1
        elif ch in _UNQUOTED_BAD:
            return None
        else:
            cur.append(ch)
            started, i = True, i + 1
    if started:
        argv.append("".join(cur))
    if any(c in w for w in argv for c in _NON_POSIX_IN_QUOTES):
        return None
    if not argv or _ASSIGN_RE.match(argv[0]):
        return None
    return argv


def _quote(word, first=False):
    # a word that starts with `=` or `%` is expanded by zsh, and a first word starting with `-` could be read as an
    # option by an old ssh client: those are quoted whatever else is safe about them
    if word and _SAFE_WORD.fullmatch(word) and word[0] not in "=%" and not (first and word[0] == "-"):
        return word
    return "'" + word.replace("'", "'\"'\"'") + "'"


def rebuild(argv):
    """`argv` as one shell string; parse_simple(rebuild(a)) == a for every simple argv. Anything
    beyond plain word characters is single-quoted, so what the remote shell sees is exactly argv."""
    return " ".join(_quote(a, i == 0) for i, a in enumerate(argv))


# ---------------------------------------------------------------- read-only table

_POS = re.compile(r"[A-Za-z0-9@%+=:,./_][A-Za-z0-9@%+=:,./_-]*", re.ASCII)
_RESTWORD = re.compile(r"[A-Za-z0-9._:/-]+", re.ASCII)
_VAL = {"num": re.compile(r"\d{1,6}"), "words": re.compile(r"[a-z,]+"), "pos": _POS,
        "time": re.compile(r"[A-Za-z0-9 :._+-]{1,40}"), "prio": re.compile(r"[a-z0-9.. ]{1,20}"),
        "kv": re.compile(r"[A-Za-z0-9=_.:/-]{1,80}"), "out": re.compile(r"[a-z-]{1,20}")}
_DATE_POS = re.compile(r"\+[A-Za-z0-9%:_.,/ -]*")
_STD_DIRS = ("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")


def _e(short="", flags=(), val=None, pos=_POS, lead=None, pre=()):
    """One table entry. `short` are the letters allowed in a cluster such as -la; `flags` exact long
    flags; `val` maps a `--name=` flag to a value pattern; `pos` the pattern a positional word
    must match (None: no positional at all); `lead` the words the FIRST positional may be."""
    return {"short": short, "flags": frozenset(flags), "val": val or {}, "pos": pos, "lead": lead,
            "pre": frozenset(pre)}


# No --full/-l (untruncated command lines in the output) and no -n (a large count dumps journal lines): --lines is capped.
_SYSD = _e("a", ("--no-pager", "--all", "--no-legend", "--failed"),
           {"--type": _VAL["words"], "--state": _VAL["words"], "--lines": re.compile(r"[1-9]|[1-4][0-9]|50")})
_IPF = ("-4", "-6", "-br", "-brief", "-j", "-o", "-s")
_ZP = _e("vxHpDLPgo")
READONLY = {
    "systemctl": {"subs": {s: _SYSD for s in ("status", "is-active", "is-enabled", "is-failed",
                                                "list-units", "list-unit-files", "list-timers")},
                  "pre": frozenset(("--no-pager", "--all", "--no-legend", "--failed"))},
    # Left OFF the table on purpose (they print environment or config that often holds secrets, or arbitrary
    # program output, so the model rates them): `docker inspect` (Config.Env), `docker info` (proxy URLs),
    # `docker logs` and `journalctl` (application output), `systemctl show` (Environment=), `ps` with an
    # environment modifier or a custom format.
    "docker": {"subs": {
        "ps": _e("aqsl", ("--all", "--quiet", "--size", "--latest"),       # no --no-trunc: it prints whole command lines
                 {"--filter": _VAL["kv"], "--last": _VAL["num"]}, pos=None),
        "images": _e("aq", ("--all", "--quiet", "--no-trunc", "--digests"), {"--filter": _VAL["kv"]}),
        "version": _e(pos=None)}},
    "df": {"entry": _e("hTikaPlHxB", ("--human-readable", "--si", "--local", "--all", "--print-type"))},
    "uptime": {"entry": _e("ps", ("--pretty", "--since"), pos=None)},
    "free": {"entry": _e("hmgbtwkl", ("--human", "--si", "--total", "--wide", "--lohi"), pos=None)},
    "uname": {"entry": _e("asnrvmpio", ("--all",), pos=None)},
    "hostname": {"entry": _e("fisdIa", ("--fqdn", "--short", "--domain", "--all-ip-addresses"), pos=None)},
    "date": {"entry": _e("uRI", ("--utc",), pos=_DATE_POS)},
    "ls": {"entry": _e("lahtrSR1dFiAnsLHGgopX", ("--all", "--almost-all", "--human-readable", "--long"),
                       {"--color": re.compile(r"auto|never|always")})},
    # `ps` alone (own terminal, command NAMES) or -o/-eo with plain columns. Never aux, -ef, an `e` modifier or a
    # column that prints arguments (args, cmd, command): other processes' arguments often hold passwords.
    "ps": {"special": lambda args: _ps_ok(args)},
    "ip": {"pre": frozenset(_IPF), "subs": {
        "addr": _e(lead={"show", "list"}, pos=_RESTWORD), "address": _e(lead={"show", "list"}, pos=_RESTWORD),
        "route": _e(lead={"show", "list", "get"}, pos=_RESTWORD), "link": _e(lead={"show"}, pos=_RESTWORD)}},
    "ss": {"entry": _e("tulnpaxsoi46e", pos=None)},
    "zpool": {"subs": {"list": _ZP, "status": _ZP}},
    "zfs": {"subs": {"list": _e("HprdtoSs")}},
}


def _program(word):
    """The table name of a program word (bare name, or an absolute path in a standard bin directory),
    else None."""
    if "/" not in word:
        return word
    d, _, base = word.rpartition("/")
    return base if d in _STD_DIRS else None


def _match_args(entry, args):
    """True when every argument is a flag the entry allows or a positional it accepts."""
    npos = 0
    for a in args:
        if a.startswith("-"):
            if a in entry["flags"] or a in entry["pre"]:
                continue
            if re.fullmatch(r"-[A-Za-z0-9]+", a) and entry["short"] and all(c in entry["short"] for c in a[1:]):
                continue
            name, eq, val = a.partition("=")
            pat = entry["val"].get(name)
            if eq and pat is not None and pat.fullmatch(val):
                continue
            return False
        if entry["pos"] is None:
            return False
        if npos == 0 and entry["lead"] is not None:
            if a not in entry["lead"]:
                return False
        elif not entry["pos"].fullmatch(a):
            return False
        npos += 1
    return True


_PS_COLUMNS = frozenset(("pid", "ppid", "comm", "etime", "stat", "%cpu", "%mem", "user"))


def _ps_ok(args):
    if not args:
        return True
    if len(args) != 2 or args[0] not in ("-o", "-eo"):
        return False
    cols = args[1].split(",")
    return bool(cols) and all(c in _PS_COLUMNS for c in cols)


def _builtin_low(argv):
    prog = _program(argv[0])
    spec = READONLY.get(prog)
    if spec is None:
        return None
    args = argv[1:]
    if "special" in spec:
        return prog if spec["special"](args) else None
    if "subs" not in spec:
        return prog if _match_args(spec["entry"], args) else None
    pre = spec.get("pre", frozenset())
    i = 0
    while i < len(args) and args[i] in pre:
        i += 1
    if i >= len(args) or args[i] not in spec["subs"]:
        return None
    sub = args[i]
    entry = spec["subs"][sub]
    return f"{prog} {sub}" if _match_args(entry, args[i + 1:]) else None


_EXT_PROG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}", re.ASCII)
_EXT_SUB = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}", re.ASCII)
_EXT_FLAG = re.compile(r"--?[A-Za-z][A-Za-z0-9-]{0,31}", re.ASCII)


def _extension_split(entry):
    """(prefix words, flags) of an `exec.readonly` entry, or None when malformed: a program (a bare name, or
    an absolute path in a standard bin directory), up to two plain subcommand words, then up to 10 flags
    the owner allows (each `-x` or `--long`, no value, listed exactly)."""
    if not isinstance(entry, str) or len(entry) > 300:
        return None
    words = entry.split(" ")
    flags = [w for w in words if w.startswith("-")]
    prefix = words[:len(words) - len(flags)]
    if words[len(prefix):] != flags or not 1 <= len(prefix) <= 3 or len(flags) > 10:
        return None
    prog = _program(prefix[0])
    if prog is None or not _EXT_PROG.fullmatch(prog) or not all(_EXT_SUB.fullmatch(w) for w in prefix[1:]):
        return None
    if not all(_EXT_FLAG.fullmatch(f) for f in flags):
        return None
    return prefix, frozenset(flags)


def _extension_ok(entry):
    return _extension_split(entry) is not None


def _extension_low(argv, cfg):
    """The owner's entry an argv matches: the program and subcommand words, then only the flags that entry
    lists and plain positional words. Any other argument starting with a dash does not match."""
    for entry in cfg["readonly"]:
        prefix, flags = _extension_split(entry)
        n = len(prefix)
        if len(argv) < n or [_program(argv[0])] + argv[1:n] != [_program(prefix[0])] + prefix[1:]:
            continue
        if _program(argv[0]) is None:
            continue
        if all((a in flags) if a.startswith("-") else _POS.fullmatch(a) is not None for a in argv[n:]):
            return entry
    return None


def classify(spec, cfg):
    """{"level": "low"|None, "reason", "argv"}. `low` only for a simple command on the read-only table
    (built in, or the owner's `exec.readonly`); None means "ask the model", which defaults to high.
    `argv` is the parsed command when it is simple (whether or not it is low), else None."""
    if "script" in spec:
        return {"level": None, "reason": "a script: only the risk model can rate it", "argv": None}
    argv = parse_simple(spec["command"])
    if argv is None:
        return {"level": None, "reason": "not a plain command (it uses shell syntax): the risk model rates it",
                "argv": None}
    hit = _builtin_low(argv)
    if hit:
        return {"level": "low", "reason": f"plain read-only command ({hit}) on the built-in list", "argv": argv}
    hit = _extension_low(argv, cfg)
    if hit:
        return {"level": "low", "reason": f"plain read-only command ({hit}) on the owner's list", "argv": argv}
    return {"level": None, "reason": "not on the read-only list: the risk model rates it", "argv": argv}


# ---------------------------------------------------------------- what is sent, what is shown

def remote_payload(spec):
    """(command string for ssh, stdin bytes or None): exactly what the remote side gets. A simple
    command is rebuilt from its parsed argv; any other command goes byte for byte; a script is
    `<interpreter> -s` with the script on stdin."""
    if "script" in spec:
        sc = spec["script"]
        return f"{sc['interpreter']} -s", sc["text"].encode("utf-8")
    argv = parse_simple(spec["command"])
    return (rebuild(argv) if argv is not None else spec["command"]), None


def script_sha256(spec):
    if "script" not in spec:
        return None
    return hashlib.sha256(spec["script"]["text"].encode("utf-8")).hexdigest()


def _shown(text):
    """`text` with every non-ASCII character as <U+XXXX> and tab/newline visible (a newline inside a
    quoted argument separates commands to a shell but renders as a space almost everywhere)."""
    out = []
    for ch in text:
        if ch == "\n":
            out.append("<U+000A>")
        elif ch == "\t":
            out.append("<U+0009>")
        elif ord(ch) > 127:
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def display_text(spec):
    """One plain-text line for any display of the command: the text that runs, non-ASCII and
    whitespace controls visible. A script shows its interpreter, size and hash, never its body."""
    if "script" in spec:
        sc = spec["script"]
        return (f"{sc['interpreter']} script, {len(sc['text'].encode('utf-8'))} bytes, "
                f"sha256 {script_sha256(spec)}")
    return _shown(remote_payload(spec)[0])


def push_text(spec):
    """One line for a notification: where, as whom, and the command (clipped); never a script body."""
    what = "a script" if "script" in spec else scrub(display_text(spec))[:200]
    where = f"{spec['host']}:{spec['port']}" if spec.get("host_state") else spec["host"]
    lead = {"new": "NEW HOST, ", "same_key_elsewhere": "NEW PORT, SAME KEY, ",
            "changed": "HOST KEY CHANGED, "}.get(spec.get("host_state"), "")
    return f"{lead}run on {where} as {spec['user']}: {what}"


def audit_fields(spec):
    """Fields for the audit log's `requested` event: the command's first words (each clipped), or for
    a script only its size and SHA-256; where and as whom."""
    out = {"host": spec["host"], "account": spec["user"], "port": spec["port"], "timeout_s": spec["timeout_s"]}
    if spec.get("host_state"):          # fingerprints are public values and shaped by code (see host_fields_ok)
        out.update(host_state=spec["host_state"], presented_fp=spec.get("presented_fp"),
                   pinned_fp=spec.get("pinned_fp"), same_as=spec.get("same_as"))
    if "script" in spec:
        out.update(script_len=len(spec["script"]["text"].encode("utf-8")), script_digest=script_sha256(spec),
                   interpreter=spec["script"]["interpreter"])
    else:
        # scrubbed (the log is append-only) and with newlines and non-ASCII visible, so one line and two differ
        out["argv"] = [w[:AUDIT_WORD_CHARS] for w in scrub(_shown(spec["command"])).split()[:AUDIT_WORDS]]
    return out


_SECRETISH = re.compile(r"(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|authorization|bearer|credential)"
                        r"""(["']?\s*[=:]\s*["']?|\s+)(?:(?:bearer|basic|token)\s+)?[^\s"']{4,}""")
_OPAQUE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_OPAQUE_NO_SLASH = re.compile(r"[A-Za-z0-9+_=-]{32,}")      # for the audit log and notifications: paths stay readable


def scrub(text):
    """`text` with obvious secrets replaced (NAME=value after password/token/key words, `Authorization: Bearer ...`,
    long opaque strings). For anything that is written down or sent on: the audit log, notifications. Linear."""
    text = _SECRETISH.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)
    return _OPAQUE_NO_SLASH.sub("<redacted>", text)


def model_text(spec, limit=4000):
    """The command or script text for the risk model: non-ASCII shown as <U+XXXX>, obvious secrets
    (NAME=value after password/token/key words, long opaque strings) replaced, clipped to `limit`.
    The model treats it as untrusted data. Both patterns are linear in the length of the text."""
    text = spec["script"]["text"] if "script" in spec else remote_payload(spec)[0]
    text = _SECRETISH.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text[:limit * 2])
    text = _OPAQUE.sub("<redacted>", text)
    return _shown(text)[:limit]


def details_record(spec):
    """What the history pop-over keeps of the request itself (the request-details store, never the audit
    log): the text as shown, and for a script its full text."""
    out = {"shown": display_text(spec), "host": spec["host"], "account": spec["user"]}
    if spec.get("host_state"):
        out.update(host_state=spec["host_state"], port=spec["port"], presented_fp=spec.get("presented_fp"),
                   pinned_fp=spec.get("pinned_fp"), same_as=spec.get("same_as"))
    if "script" in spec:
        out.update(script=spec["script"]["text"], interpreter=spec["script"]["interpreter"])
    return out


def result_record(result, limit):
    """The outcome for the pop-over: exit status, label, and each stream clipped to `limit` characters."""
    return {"exit_code": result.get("exit_code"), "label": result.get("label"), "truncated": result.get("truncated"),
            "stdout": (result.get("stdout") or "")[:limit], "stderr": (result.get("stderr") or "")[:limit]}


def retained_html(rec):
    """The pop-over block for a finished remote command (server-escaped, every non-ASCII character as U+XXXX)."""
    if not isinstance(rec, dict):
        return ""
    e = sudomode._esc
    parts = ["<details class=reqdetails open><summary>Remote command</summary>"]
    if rec.get("host_state") in HOST_STATES:
        parts.append(f"<p class=note>{html.escape(_STATE_LABEL[rec['host_state']])}: "
                     f"{html.escape(str(rec.get('host') or ''))}:{html.escape(str(rec.get('port') or ''))}, key "
                     f"{fp_html(rec.get('presented_fp'))}"
                     + (f" (pinned {fp_html(rec['pinned_fp'])})" if rec.get("pinned_fp") else "") + "</p>")
    if rec.get("script") is not None:
        parts.append(f"<p class=note>{html.escape(str(rec.get('interpreter') or 'sh'))} script</p>"
                     f"<pre class=reqtext tabindex=0>{e(rec['script'])}</pre>")
    else:
        parts.append(f"<pre class=reqtext tabindex=0>{e(str(rec.get('shown') or ''))}</pre>")
    res = rec.get("result")
    if isinstance(res, dict):
        head = (f"Exit status {html.escape(str(res.get('exit_code')))}" if res.get("exit_code") is not None
                else f"Failed: {html.escape(str(res.get('label')))}")
        parts.append(f"<p class=note>{head}{' (output cut)' if res.get('truncated') else ''}</p>")
        for k in ("stdout", "stderr"):
            if res.get(k):
                parts.append(f"<p class=note>{k}</p><pre class=reqtext tabindex=0>{e(str(res[k]))}</pre>")
    parts.append("<p class=note><small>Output is shown as the broker returned it to the agent, with credential "
                 "values masked.</small></p></details>")
    return "".join(parts)


def describe_html(req):
    """(what_html, note_html) for the card header: host, account, and the exact text that runs (a
    script in full with its hash)."""
    sp = req.spec
    where = (f"<b>Run on {html.escape(sp['host'])}</b> as <code>{html.escape(sp['user'])}</code> "
             f"(port {sp['port']}, timeout {sp['timeout_s']}s) for {html.escape(req.source)}:")
    if "script" in sp:
        sc = sp["script"]
        body = (f"<div class=crpurpose>{html.escape(sc['interpreter'])} script, SHA-256 "
                f"<code>{script_sha256(sp)}</code><pre>{sudomode._esc(sc['text'])}</pre></div>")
        text = sc["text"]
    else:
        text = remote_payload(sp)[0]
        body = f"<div class=crpurpose><code>{sudomode._esc(text)}</code></div>"
    flag = ""
    na = guidance_mod.non_ascii_count(text)
    if na:
        flag += f" <span class='pill warn'>Non-ASCII characters: {na} (shown as U+XXXX)</span>"
    return f"{host_html(sp)}{where}{body}{flag}", WARNING


# ---------------------------------------------------------------- unpinned hosts

_STATE_LABEL = {"new": "New host key", "same_key_elsewhere": "New port, same key", "changed": "HOST KEY CHANGED"}


def fp_html(fp):
    """A fingerprint for a page: only a well-formed `SHA256:...` value is shown (it came from the broker's own probe,
    never from the agent), anything else is a fixed placeholder; escaped as everything is."""
    if isinstance(fp, str) and _FP_RE.fullmatch(fp):
        return f"<code class=fp>{html.escape(fp)}</code>"
    return "<code>(unavailable)</code>"


def host_fields_ok(sp):
    """True when the host-key fields of a request spec are what the broker's probe produces: a known state, SHA256
    fingerprints, and a `type base64` key. Checked wherever they are used to connect or to persist."""
    st = sp.get("host_state")
    return (st in HOST_STATES and bool(_FP_RE.fullmatch(sp.get("presented_fp") or ""))
            and bool(_KEY_RE.fullmatch(sp.get("presented_key") or ""))
            and (st != "changed" or bool(_FP_RE.fullmatch(sp.get("pinned_fp") or ""))))


def host_html(sp):
    """The block above the command for an unpinned request: what is new, the fingerprint the server presented, and
    for a changed key a large red caution with both fingerprints. Empty for an ordinary request."""
    st = sp.get("host_state")
    if st not in HOST_STATES:
        return ""
    where = f"{html.escape(sp['host'])}, port {int(sp['port'])}"
    if st == "changed":
        return ("<div class=hostban role=alert style='border:3px solid var(--bad);background:var(--badbg);"
                "color:var(--bad);border-radius:.5rem;padding:.7rem .9rem;margin:.4rem 0;font-size:1.05rem'>"
                f"<b style='font-size:1.25rem'>HOST KEY CHANGED</b> for {where}<br>"
                f"Presented now: {fp_html(sp.get('presented_fp'))}<br>"
                f"Pinned: {fp_html(sp.get('pinned_fp'))}<br>{html.escape(CHANGED_TEXT)}</div>")
    if st == "same_key_elsewhere":
        head = (f"A host and port this key has not pinned: {where}. Same key as "
                f"{html.escape(str(sp.get('same_as') or '?'))}")
    else:
        head = f"A host this key has not pinned: {where}"
    return ("<div class=hostban style='border:2px solid var(--warn);border-radius:.5rem;padding:.5rem .8rem;"
            f"margin:.4rem 0'><b>{head}.</b><br>Key presented: {fp_html(sp.get('presented_fp'))}<br>"
            f"{html.escape(FIRST_USE)}</div>")


def host_actions_html(sp, remember_why=None):
    """The decision controls of an unpinned request. Approve once (nothing is saved) and Deny always; then, only
    when the key can store it (`remember_why` is None): Approve and remember for a new host or port, or, for a
    changed key, Approve and replace the pinned key behind an extra tick. No Always, no timed approval, no rule."""
    st = sp.get("host_state")
    row = ("<div class=decide-row><button class='btn approve' name=decision value=approve>Approve once</button>"
           "<button class='btn deny' name=decision value=deny>Deny</button></div>")
    if remember_why is not None:
        extra = f"<p class=scope><small class=muted>Not offered: {html.escape(remember_why)}.</small></p>"
    elif st == "changed":
        extra = ("<div class=scope><label><input type=checkbox name=confirm_replace value=1> I expect this server's key "
                 "to have changed, and I want to replace the pinned key with the one shown.</label> "
                 "<button class='btn sm approve' name=decision value=approve_replace>Approve and replace the pinned "
                 "key</button></div>")
    else:
        extra = ("<div class=scope><button class='btn sm approve' name=decision value=approve_remember>Approve and "
                 "remember</button> <small class=muted>also pins this key for this host and port on the credential "
                 "(and lets ssh signing with it accept this server); revoke it in the credential editor.</small></div>")
    return (row + extra + "<p class=scope><small class=muted>Approves this one command, as shown, connecting only to "
            "the key shown above. There is no Always or timed approval for an unpinned host.</small></p>")
