"""Agent-initiated credential requests: the agent asks, the HUMAN supplies the value.

An agent that needs a credential the broker does not hold can say so
(`asb request-credential`, request mode `credential`). The request carries a name,
a kind (token or login), a purpose and suggested hosts, variable and mode: never a
value. A human opens the approval page, types the secret into a form that exists
only there, may edit the name, hosts, variable and mode, and presses Store. The broker
then creates the vault item through the normal backend create path with its broker
metadata, and the agent learns only the stored name. The value never reaches the agent.

Invariants (enforced in broker.py, tested in tests/test_credential_request.py):
  * a request is always HIGH by code: no model call (there is nothing to classify and
    the purpose is untrusted agent text), and it can never be auto-approved (legacy
    `approval: allow`, Always, timed grants, SSH rules); no notification button can
    decide it; only the approval page can, after the human typed the value there;
  * the entry form is served and accepted only by the authenticated approval listener,
    with the per-user CSRF token. The client API has no endpoint that takes a value;
  * the secret is held in memory from the form post until the vault write finished and is
    then dropped. It is never in the audit log, history, request details, notifications,
    results, HTML, redirects, URLs or logs. An error re-render shows everything except
    the secret fields;
  * the purpose is untrusted text: hidden characters are rejected, every non-ASCII
    character is shown as <U+XXXX> on the card, and it appears nowhere else (the audit log
    keeps only its length and a hash prefix).

This module holds the config parser, the agent-side checks that need no broker state, and
the card and entry-page HTML.
"""
import hashlib
import html
import re
import time

from . import guidance as guidance_mod

KINDS = ("token", "login")
MODES = ("http", "env")
MAX_PENDING = 2                 # open credential requests at once (on top of the general cap)
MAX_PURPOSE = 300               # characters
MAX_SECRET_CHARS = 16384        # one entered field
FORM_LIMIT = 100_000            # bytes of the entry form body
DEFAULTS = {"enabled": True, "ttl_s": 900}
TTL_MIN, TTL_MAX = 120, 3600
REASON = "credential requests always need a human to supply the value; always high"
WARNING = ("The requesting agent asked for this credential. Its purpose text is the agent's own claim "
           "and is not verified. Enter a secret only if you meant to give this service access. "
           "The agent never sees the value you type.")
# keys a client request must never carry: the value is entered by the human, on the approval page
FORBIDDEN_KEYS = ("value", "secret", "token", "password", "username", "credential", "values", "data",
                  "field_values")
_PURPOSE_BAD = re.compile(r"[\x00-\x1f\x7f]")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def parse_config(raw, field="credential_requests"):
    """Validate `credential_requests` -> {"enabled", "ttl_s"}. None means the defaults.
    Raises ValueError naming the field."""
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
    if not _int(out["ttl_s"]) or not TTL_MIN <= out["ttl_s"] <= TTL_MAX:
        raise ValueError(f"{field}.ttl_s must be a whole number of seconds from {TTL_MIN} to {TTL_MAX}")
    return out


def validate_purpose(raw):
    """The agent's purpose text, or ValueError. One line of at most MAX_PURPOSE characters,
    no control characters and none of the hidden characters guidance text also refuses.
    Nothing is normalized except trimming ASCII spaces; the messages never repeat the text."""
    if not isinstance(raw, str):
        raise ValueError("purpose must be a string")
    text = raw.strip(" ")
    if not text or len(text) > MAX_PURPOSE:
        raise ValueError(f"purpose must be 1 to {MAX_PURPOSE} characters")
    if _PURPOSE_BAD.search(text):
        raise ValueError("purpose must be a single line without control characters")
    bad = guidance_mod.hidden_problem(text)
    if bad:
        raise ValueError(f"purpose contains hidden characters ({bad[0]} at offset {bad[1]})")
    return text


def purpose_digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def default_vars(name, kind, var=None):
    """The variable name(s) a credential exposes: {"role": VAR}. A token has one (default
    NAME_TOKEN); a login has two, VAR_USERNAME and VAR_PASSWORD, where VAR (default NAME)
    is the prefix."""
    base = re.sub(r"[^A-Za-z0-9]", "_", var or name).upper()
    if kind == "login":
        return {"username": base + "_USERNAME", "password": base + "_PASSWORD"}
    return {"token": var if var else base + "_TOKEN"}


# ---------------------------------------------------------------- html
CSS = """
.cr{margin:.6rem 0}
.cr label{display:block;font-weight:600;font-size:.85rem;margin:.7rem 0 .2rem}
.cr input[type=text],.cr input[type=password],.cr select{font:inherit;width:100%;min-height:2.5rem;padding:.3rem .6rem;
border-radius:.5rem;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.cr .hint{display:block;font-weight:400;color:var(--muted);font-size:.8rem;margin-top:.15rem}
.cr .chk{display:flex;align-items:center;gap:.5rem;font-weight:400;min-height:2.25rem}
.cr .chk input{width:1.2rem;height:1.2rem}
.cr .vault{border:1px solid var(--warn);border-radius:.6rem;padding:.4rem .8rem .8rem;margin:.9rem 0}
.cr .vault legend{font-weight:700;padding:0 .4rem}
.crerr{margin:.5rem 0;padding:.5rem .8rem;border:1px solid var(--bad);border-radius:.5rem;background:var(--badbg);color:var(--bad)}
.crerr ul{margin:.2rem 0 0 1.1rem;padding:0}
.crpurpose{border:1px dashed var(--line);border-radius:.4rem;padding:.4rem .6rem;margin:.3rem 0;background:var(--bg)}
.crbtns{display:flex;gap:.6rem;margin:.9rem 0 .2rem}
.crbtns .btn,.crbtns button{flex:1 1 0;min-height:2.75rem}
a.btn{display:inline-flex;align-items:center;justify-content:center;text-decoration:none}
"""


def _esc(text):
    """HTML for untrusted text where every non-ASCII character is shown as <U+XXXX> (the real
    character in the tooltip), so a look-alike cannot pass for an ASCII letter."""
    return "".join(
        html.escape(ch) if ord(ch) < 128 else
        f"<span class=gu title=\"{html.escape(ch)}\">&lt;U+{ord(ch):04X}&gt;</span>" for ch in text)


def describe_html(req):
    """(what_html, note_html) for the card header: name, kind, purpose, suggestions. The
    purpose is shown escaped and marked as the agent's claim."""
    sp, e = req.spec, html.escape
    hosts = ", ".join(sp.get("hosts") or []) or "none suggested"
    na = guidance_mod.non_ascii_count(sp["purpose"])
    flag = (f" <span class='pill warn'>Non-ASCII characters: {na} (shown as U+XXXX)</span>" if na else "")
    what = (f"<b>Credential request</b>: {e(req.names[0])} ({e(sp['kind'])})<br>"
            f"Purpose, as the agent put it (unverified):<div class=crpurpose>{_esc(sp['purpose'])}</div>{flag}"
            f"Suggested hosts: {e(hosts)}<br>Suggested mode: {e(sp['cred_mode'])}")
    return what, WARNING


def card_actions_html(req):
    """The dashboard card controls: open the entry page, or Deny. No value field here (the
    dashboard refreshes itself and must never hold a half-typed secret)."""
    return (f"<div class=decide-row><a class='btn approve' href='/credential/{html.escape(req.id)}'>"
            "Review and enter value</a>"
            "<button class='btn deny' name=decision value=deny>Deny</button></div>"
            "<p class=scope><small class=muted>Nothing is stored unless you enter a value and press "
            "Store. No standing approval can cover a credential request.</small></p>")


def form_html(req, csrf, values=None, errors=()):
    """The entry page body: the request, the editable fields, the secret inputs and the two
    buttons. `values` re-populates the editable fields after an error; the secret fields are
    NEVER filled in."""
    sp, e = req.spec, html.escape
    v = {"name": req.names[0], "hosts": ", ".join(sp.get("hosts") or []), "var": sp.get("var") or "",
         "cred_mode": sp["cred_mode"], "no_hosts": ""}
    v.update(values or {})
    what, note = describe_html(req)
    errs = ""
    if errors:
        errs = ("<div class=crerr role=alert><b>Nothing was stored.</b> Fix this and enter the value again "
                "(the secret fields are always cleared):<ul>"
                + "".join(f"<li>{e(m)}</li>" for m in errors) + "</ul></div>")
    kind = sp["kind"]
    if kind == "login":
        secret = ("<label for=username>Username<span class=hint>Stored in the vault with the password; "
                  "never shown again.</span></label>"
                  "<input id=username type=password name=username autocomplete=off required "
                  "spellcheck=false autocapitalize=off>"
                  "<label for=password>Password</label>"
                  "<input id=password type=password name=password autocomplete=new-password required "
                  "spellcheck=false>")
    else:
        secret = ("<label for=token>Token<span class=hint>Paste the API token or key. It is stored in the "
                  "vault and never shown again.</span></label>"
                  "<input id=token type=password name=token autocomplete=new-password required "
                  "spellcheck=false autocapitalize=off>")
    sel = "".join(f"<option value={m}{' selected' if v['cred_mode'] == m else ''}>{m}</option>" for m in MODES)
    var_hint = ("Prefix for the two variables (PREFIX_USERNAME, PREFIX_PASSWORD)." if kind == "login"
                else "The placeholder name agents use, as in {{NAME}}.")
    return (
        "<h1>Credential request</h1>"
        f"<div class=box>From: {e(req.source)}<br>{what}</div>"
        f"<p><small>{e(note)}</small></p>"
        f"<p><small>Expires in {max(0, int(req.expires - time.time()))}s</small></p>"
        f"{errs}"
        "<form method=post action='/credential' id=f autocomplete=off class=cr>"
        f"<input type=hidden name=id value='{e(req.id)}'>"
        f"<input type=hidden name=csrf value='{e(csrf)}'>"
        "<label for=name>Name<span class=hint>What agents call this credential. Lowercase letters, digits, "
        "- and _.</span></label>"
        f"<input id=name type=text name=name value='{e(v['name'])}' maxlength=41 required "
        "spellcheck=false autocapitalize=off>"
        "<label for=hosts>Allowed hosts<span class=hint>The credential is only ever sent to these "
        "hosts. Comma or space separated host names.</span></label>"
        f"<input id=hosts type=text name=hosts value='{e(v['hosts'])}' spellcheck=false autocapitalize=off>"
        "<label for=cred_mode>Mode<span class=hint>http: the broker makes calls for the agent and needs "
        "hosts. env: the value may also be handed to a command on the agent's machine, and hosts can be "
        "left out.</span></label>"
        f"<select id=cred_mode name=cred_mode>{sel}</select>"
        f"<label class=chk><input type=checkbox name=no_hosts value=1{' checked' if v['no_hosts'] else ''}> "
        "No host restriction (env mode only; the value can then never be used by the http command)</label>"
        "<label for=var>Variable name<span class=hint>" + e(var_hint) + "</span></label>"
        f"<input id=var type=text name=var value='{e(v['var'])}' spellcheck=false autocapitalize=off "
        "placeholder='default from the name'>"
        f"<fieldset class=vault><legend>The secret ({e(kind)})</legend>{secret}</fieldset>"
        "<div class=crbtns><button class='btn approve' type=submit name=decision value=approve>"
        "Store credential</button>"
        "<button class='btn deny' type=submit name=decision value=deny formnovalidate>Deny</button></div>"
        "</form>"
        "<p><small class=muted>Stored with approval on every use: no standing approval, grant or Always "
        "applies to it unless you add one later under Policies. The value is sent only to this page's "
        "broker and is not logged.</small></p>")
