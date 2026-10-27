"""Root commands approved by a human: request mode `sudo`.

A helper running as root on the agent's machine (`asb-root-exec`, see
docs/proposals/root-exec.md) asks the broker before it runs a command as root. The request
carries the command (argv), its working directory, the target user and the local user who
asked; it names no credential and the approved answer carries no value, only
{"approved": true}. The helper runs nothing unless it gets that answer.

Invariants (enforced in broker.py, tested in tests/test_sudo_mode.py):
  * off by default: `sudo.enabled` must be true AND the requesting client's id must be in
    `sudo.clients`. The legacy shared key is never accepted, whatever the list says;
  * HIGH by code with no model call, never auto-approved (`approval: allow`, Always, timed
    grants, SSH rules, a client's auto_modes: none of them can reach this mode);
  * no notification button can decide it: only the approval page can, after the human read
    the exact command;
  * the command is untrusted text. Hidden characters are rejected, every non-ASCII character
    is shown as <U+XXXX> on the card, and arguments are shown shell-quoted so the word
    boundaries are unambiguous;
  * the audit log records the argv (first words, each clipped) and never an environment.

This module holds the config parser, the checks that need no broker state, and the card
text. Everything is plain data in and out so it ports unchanged.
"""
import html
import re
import shlex

from . import clients as clients_mod
from . import guidance as guidance_mod
from . import scripts as scripts_mod

MODE = "sudo"
DEFAULTS = {"enabled": False, "clients": [], "ttl_s": 300, "max_pending_per_client": 3}
TTL_MIN, TTL_MAX = 60, 900
MAX_ARGS = 64
MAX_ARG_CHARS = 4096
MAX_TOTAL_CHARS = 16384
AUDIT_ARGS, AUDIT_ARG_CHARS = 50, 300
TARGET_USERS = ("root",)                    # v1: root only
_BAD_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")      # tab and newline are legal inside an argument
_INVOKER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
REASON = "root commands always need a human to read the exact command; always high"
WARNING = ("A helper on the requesting machine asked to run this command as root. The command text is "
           "what the client sent: the broker cannot see what it will really do. Approve only a command "
           "you recognise and meant to allow.")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_config(raw, field="sudo"):
    """Validate `sudo` -> {"enabled", "clients", "ttl_s", "max_pending_per_client"}. None means the
    defaults (off). Raises ValueError naming the field."""
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
    if not _int(out["ttl_s"]) or not TTL_MIN <= out["ttl_s"] <= TTL_MAX:
        raise ValueError(f"{field}.ttl_s must be a whole number of seconds from {TTL_MIN} to {TTL_MAX}")
    if not _int(out["max_pending_per_client"]) or not 1 <= out["max_pending_per_client"] <= 20:
        raise ValueError(f"{field}.max_pending_per_client must be a whole number from 1 to 20")
    return out


def check_allowed(cfg, client):
    """PermissionError unless sudo requests are enabled and `client` (a client view) may make them.
    The messages say what to fix without revealing the allow-list."""
    if not cfg["enabled"]:
        raise PermissionError("sudo requests are disabled")
    cid = (client or {}).get("id")
    if (client or {}).get("legacy") or cid not in cfg["clients"]:
        raise PermissionError("this client may not make sudo requests")


def validate(spec):
    """Check the agent-side fields of a sudo request and rewrite `spec` in place to the
    normalized {"argv", "cwd", "user", "invoker"}. Raises ValueError; messages never repeat the
    command."""
    argv = spec.get("argv")
    if (not isinstance(argv, list) or not 1 <= len(argv) <= MAX_ARGS
            or not all(isinstance(a, str) for a in argv)):
        raise ValueError(f"argv must be a list of 1 to {MAX_ARGS} strings")
    if not argv[0]:
        raise ValueError("argv[0] must not be empty")
    if any(len(a) > MAX_ARG_CHARS for a in argv) or sum(len(a) for a in argv) > MAX_TOTAL_CHARS:
        raise ValueError(f"an argument is longer than {MAX_ARG_CHARS} characters, or the command "
                         f"is longer than {MAX_TOTAL_CHARS} in total")
    for a in argv:
        if _BAD_CHARS.search(a):
            raise ValueError("argv contains a control character")
        bad = guidance_mod.hidden_problem(a)
        if bad:
            raise ValueError(f"argv contains hidden characters ({bad[0]} in an argument)")
    user = spec.get("user", "root")
    if user not in TARGET_USERS:
        raise ValueError("user must be root")
    invoker = spec.get("invoker")
    if invoker is not None and not (isinstance(invoker, str) and _INVOKER_RE.fullmatch(invoker)):
        raise ValueError("invoker must be a local user name")
    cwd = scripts_mod.validate_cwd(spec.get("cwd"))
    spec.clear()
    spec.update(argv=list(argv), cwd=cwd, user=user, invoker=invoker)


def command_text(spec):
    """The command as one shell-quoted line: word boundaries are unambiguous, so `a b` (one
    argument) cannot pass for `a` `b` (two). Plain text, not escaped for any output."""
    return shlex.join(spec["argv"])


def push_text(spec):
    """One line for a notification: the command, clipped."""
    return "run as root: " + command_text(spec)[:200]


def audit_fields(spec):
    """Fields for the audit log: the command's first words, each clipped, the directory and who
    asked. Never an environment."""
    return {"argv": [a[:AUDIT_ARG_CHARS] for a in spec["argv"][:AUDIT_ARGS]],
            "argc": len(spec["argv"]), "cwd": spec.get("cwd"), "target_user": spec["user"],
            "invoker": spec.get("invoker")}


def _esc(text):
    """HTML for untrusted text where every non-ASCII character is shown as <U+XXXX> (the real
    character in the tooltip), so a look-alike cannot pass for an ASCII letter."""
    return "".join(
        html.escape(ch) if ord(ch) < 128 else
        f"<span class=gu title=\"{html.escape(ch)}\">&lt;U+{ord(ch):04X}&gt;</span>" for ch in text)


def describe_html(req):
    """(what_html, note_html) for the card header: the exact command, directory and asker."""
    sp = req.spec
    text = command_text(sp)
    na = guidance_mod.non_ascii_count(text)
    flag = (f" <span class='pill warn'>Non-ASCII characters: {na} (shown as U+XXXX)</span>" if na else "")
    where = f"<br>In directory: <code>{_esc(sp['cwd'])}</code>" if sp.get("cwd") else ""
    who = f"<br>Asked by local user: <code>{html.escape(sp['invoker'])}</code> (unverified)" if sp.get("invoker") else ""
    what = (f"<b>Run as {html.escape(sp['user'])}</b> on {html.escape(req.source)}:"
            f"<div class=crpurpose><code>{_esc(text)}</code></div>{flag}{where}{who}")
    return what, WARNING
