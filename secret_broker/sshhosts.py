"""The Policies-page editor for an SSH key's `ssh_hosts` policy.

`ssh_hosts` lives in the key item's `broker` metadata (see Broker._ssh_hosts for
the validator the catalog loader runs, and docs/reference.md for what the policy
does). This module turns the editor's form text into that metadata object,
checks it more strictly than the loader (so the editor can never write something
the loader rejects), analyses it for the owner (parsed fingerprint table,
warnings) and renders the cards. Like risk guidance it is policy context: it is
never shown to the agent and the audit events carry counts and hashes only.
"""
import base64
import binascii
import hashlib
import html
import json
import re

from . import sshkey

MAX_KNOWN, MAX_KNOWN_LEN = 200, 2048
MAX_ALLOWED, MAX_ALLOWED_LEN = 50, 255
FORM_LIMIT = 1_500_000      # 200 lines x 2 KB, percent-encoded, plus slack

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]")
_FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?")
_NAME = re.compile(r"[a-z0-9_][a-z0-9._:-]*")
NOTE_HELP = ("When Allowed hosts is set, the broker refuses to sign unless the server's verified host key "
             "is on the list; unverified, forwarded (unless allowed) and malformed connections are "
             "refused; git commit signing with this key will also be refused because it has no server.")
WARNING = ("Mistakes here can lock this key out of use: a wrong or unmatched entry means every signature "
           "is refused until you fix it.")


def _lines(text, what):
    if not isinstance(text, str):
        raise ValueError(f"{what} must be text")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if _CTRL.search(text.replace("\n", "").replace("\t", " ")):
        raise ValueError(f"{what} contains control characters")
    return [ln.strip() for ln in text.split("\n") if ln.strip()]


def build(known_text, allowed_text, allow_forwarded):
    """Form text -> the `ssh_hosts` metadata object ({} when there is no policy).
    Raises ValueError (message safe to show; it never repeats the input)."""
    known = _lines(known_text, "Known hosts")
    allowed = _lines(allowed_text, "Allowed hosts")
    if len(known) > MAX_KNOWN:
        raise ValueError(f"Known hosts has {len(known)} lines; the limit is {MAX_KNOWN}")
    for i, ln in enumerate(known, 1):
        if len(ln) > MAX_KNOWN_LEN:
            raise ValueError(f"Known hosts line {i} is longer than {MAX_KNOWN_LEN} characters")
    if len(allowed) > MAX_ALLOWED:
        raise ValueError(f"Allowed hosts has {len(allowed)} entries; the limit is {MAX_ALLOWED}")
    for i, a in enumerate(allowed, 1):
        if len(a) > MAX_ALLOWED_LEN:
            raise ValueError(f"Allowed hosts entry {i} is longer than {MAX_ALLOWED_LEN} characters")
        if re.search(r"\s", a):
            raise ValueError(f"Allowed hosts entry {i}: one host name or SHA256: fingerprint per line")
        if a.lower().startswith("sha256:"):
            if not _FP.fullmatch(a):
                raise ValueError(f"Allowed hosts entry {i}: not a valid SHA256: fingerprint "
                                 "(SHA256: followed by 43 base64 characters)")
        elif not _NAME.fullmatch(a.lower()):
            raise ValueError(f"Allowed hosts entry {i}: not a valid host name "
                             "(letters, digits, dots, dashes; host:port for other ports)")
    out = {}
    if known:
        out["known_hosts"] = known
    if allowed:
        out["allowed_hosts"] = allowed
    if allow_forwarded:
        out["allow_forwarded"] = True
    return out


def normalize(raw):
    """Canonical form of stored `ssh_hosts` metadata, for comparing and hashing."""
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    if raw.get("known_hosts"):
        out["known_hosts"] = [str(x).strip() for x in raw["known_hosts"]]
    if raw.get("allowed_hosts"):
        out["allowed_hosts"] = [str(x).strip() for x in raw["allowed_hosts"]]
    if raw.get("allow_forwarded") is True:
        out["allow_forwarded"] = True
    return out


def digest(raw):
    """Short sha256 prefix of a normalized policy for audit; None when empty."""
    n = normalize(raw)
    return hashlib.sha256(json.dumps(n, sort_keys=True).encode()).hexdigest()[:12] if n else None


def can_ever_match(parsed):
    """False when an allowed list is set but no entry can ever equal a verified
    server: every entry is a name that no known_hosts line gives to any key."""
    allowed = parsed.get("allowed")
    if not allowed:
        return True
    names = {n for ns in (parsed.get("known") or {}).values() for n in ns}
    return any(a.startswith("SHA256:") or a in names for a in allowed)


def _reason(line):
    f = line.split()
    if line.startswith("#"):
        return "comment"
    if f[0].startswith("@"):
        return "marker lines (@cert-authority, @revoked) are not supported"
    if f[0].startswith("|"):
        return "hashed host names are not supported (paste the plain form, e.g. from ssh-keyscan)"
    if len(f) < 3:
        return "not a known_hosts line (needs host names, key type and key)"
    if f[1] not in sshkey._HOSTKEY_TYPES:
        return "unsupported key type"
    try:
        blob = base64.b64decode(f[2], validate=True)
    except (ValueError, binascii.Error):
        return "the key is not valid base64"
    if sshkey._blob_type(blob) != f[1]:
        return "the key type does not match the key data"
    return "no usable host names (wildcards, negations and hashed names are ignored)"


def analyze(raw):
    """What the saved policy means, for display: parsed known_hosts lines, ignored
    lines with reasons, and warnings about Allowed hosts entries that cannot match."""
    raw = normalize(raw)
    rows, ignored, fps, names = [], [], set(), set()
    for ln in raw.get("known_hosts", []):
        got = sshkey.parse_known_hosts([ln])
        if not got:
            ignored.append((ln, _reason(ln)))
            continue
        (fp, ns), = got.items()
        rows.append({"names": ns, "type": ln.split()[1], "fp": fp})
        fps.add(fp)
        names.update(ns)
    warnings = []
    for a in raw.get("allowed_hosts", []):
        if a.startswith("SHA256:"):
            if a.rstrip("=") not in fps:
                warnings.append((a, "will only match by fingerprint (no known_hosts line has it)"))
        elif a.lower() not in names:
            warnings.append((a, "unknown name: no known_hosts line gives it, so it can never match"))
    return {"rows": rows, "ignored": ignored, "warnings": warnings}


# ------------------------------------------------------------------ UI
CSS = """
.sbox .help{font-size:.85rem;color:var(--muted);margin:.2rem 0 .6rem}
.sbox .lock{border:1px solid var(--warn);background:var(--wbg);color:var(--wfg);border-radius:.5rem;padding:.5rem .7rem;margin:.5rem 0;font-size:.85rem}
.sbox .err{border:1px solid var(--bad);background:var(--badbg);color:var(--bad);border-radius:.5rem;padding:.5rem .7rem;margin:.5rem 0}
.sbox label.l{display:block;font-weight:600;margin:.7rem 0 .25rem}
.sbox label.chk{display:flex;gap:.5rem;align-items:flex-start;margin:.6rem 0;min-height:1.6rem}
.sbox input[type=checkbox]{margin-top:.2rem}
.sbox textarea{font-family:ui-monospace,monospace;font-size:.78rem;white-space:pre;overflow-x:auto}
.sbox .fp{font-family:ui-monospace,monospace;font-size:.78rem;word-break:break-all}
.sbox ul.warns{margin:.3rem 0;padding-left:1.2rem;font-size:.85rem}
.sbox ul.warns code{word-break:break-all}
"""

JS = r"""
(function(){
  document.querySelectorAll('textarea[data-scount]').forEach(function(t){
    var c=document.getElementById(t.getAttribute('data-scount'));if(!c)return;
    function u(){var n=t.value.split('\n').filter(function(l){return l.trim();}).length;c.textContent=n+' lines';}
    t.addEventListener('input',u);u();});
})();
"""


def _badge(sc):
    allowed = (sc.get("ssh_hosts") or {}).get("allowed")
    if allowed:
        return f"<span class='pill ok'>Enforcing: {len(allowed)} allowed hosts</span>"
    return "<span class='pill plain'>Not enforcing (any server accepted, identity shown only)</span>"


def _analysis(raw):
    esc = html.escape
    a = analyze(raw)
    if not (a["rows"] or a["ignored"] or a["warnings"]):
        return ""
    out = ["<h4 style='margin:1rem 0 .3rem'>Saved known hosts</h4>"]
    if a["rows"]:
        trs = "".join(
            f"<tr><td data-label=Names>{esc(', '.join(r['names']))}</td><td data-label=Type>{esc(r['type'])}</td>"
            f"<td data-label=SHA256><span class=fp>{esc(r['fp'])}</span></td></tr>" for r in a["rows"])
        out.append("<table class=tbl><thead><tr><th>Names</th><th>Key type</th><th>Fingerprint</th></tr></thead>"
                   f"<tbody>{trs}</tbody></table>")
    else:
        out.append("<p><small class=muted>No usable known_hosts lines.</small></p>")
    if a["ignored"]:
        lis = "".join(f"<li><code>{esc(ln[:70] + ('...' if len(ln) > 70 else ''))}</code>: {esc(why)}</li>"
                      for ln, why in a["ignored"])
        out.append(f"<p><b>Ignored lines</b></p><ul class=warns>{lis}</ul>")
    if a["warnings"]:
        lis = "".join(f"<li><code>{esc(x)}</code>: {esc(why)}</li>" for x, why in a["warnings"])
        out.append(f"<p><b>Allowed hosts warnings</b></p><ul class=warns>{lis}</ul>")
    return "".join(out)


def policies_section(secrets_cfg, csrf, state=None):
    """The 'SSH host policy' cards for the Policies tab: one collapsed card per
    SSH key. `state` maps a secret name to {"error", "known", "allowed", "fwd",
    "need_confirm", "need_anyway", "open"} to re-render after a refused or saved
    form."""
    esc = html.escape
    state = state or {}
    rows = []
    for i, (name, sc) in enumerate(sorted(secrets_cfg.items())):
        if not sc.get("ssh"):
            continue
        st = state.get(name) or {}
        raw = normalize((sc.get("_meta") or {}).get("ssh_hosts"))
        known = st["known"] if "known" in st else "\n".join(raw.get("known_hosts", []))
        allowed = st["allowed"] if "allowed" in st else "\n".join(raw.get("allowed_hosts", []))
        fwd = st["fwd"] if "fwd" in st else bool(raw.get("allow_forwarded"))
        extra = ""
        if st.get("error"):
            extra += f"<div class=err role=alert>{esc(st['error'])}</div>"
        if st.get("need_confirm"):
            extra += ("<label class=chk><input type=checkbox name=confirm_weaken value=1> "
                      "<span>I understand this reduces enforcement</span></label>")
        if st.get("need_anyway"):
            extra += ("<label class=chk><input type=checkbox name=save_anyway value=1> "
                      "<span>Save anyway (I understand this key will be refused for every server)</span></label>")
        rows.append(
            f"<details class='card gbox sbox'{' open' if st.get('open') else ''}><summary><b>{esc(name)}</b> "
            f"{_badge(sc)}<small class=muted>SSH host policy</small></summary>"
            "<form method=post action='/policies/ssh_hosts'>"
            f"<input type=hidden name=csrf value='{esc(csrf)}'>"
            f"<input type=hidden name=secret value='{esc(name)}'>"
            f"<p class=help>{esc(NOTE_HELP)}</p><div class=lock>{esc(WARNING)}</div>{extra}"
            f"<label class=l for='sk{i}'>Known hosts</label>"
            "<p class=help>One OpenSSH known_hosts line per line, pasted from ~/.ssh/known_hosts "
            "(or ssh-keyscan output). Hashed entries (starting with |1|) are not supported and are ignored; "
            f"they are listed after saving. Up to {MAX_KNOWN} lines.</p>"
            f"<textarea id='sk{i}' name=known_hosts rows=6 wrap=off data-scount='skc{i}' "
            f"aria-label='Known hosts for {esc(name)}'>{esc(known)}</textarea>"
            f"<small class=muted id='skc{i}'></small>"
            f"<label class=l for='sa{i}'>Allowed hosts</label>"
            "<p class=help>One host name (from Known hosts) or SHA256:fingerprint per line. Empty means no "
            f"enforcement. Up to {MAX_ALLOWED} entries.</p>"
            f"<textarea id='sa{i}' name=allowed_hosts rows=4 wrap=off data-scount='sac{i}' "
            f"aria-label='Allowed hosts for {esc(name)}'>{esc(allowed)}</textarea>"
            f"<small class=muted id='sac{i}'></small>"
            f"<label class=chk><input type=checkbox name=allow_forwarded value=1{' checked' if fwd else ''}> "
            "<span>Allow forwarded agent (every hop must also be allowed)</span></label>"
            "<div class=grow><button>Save</button><small class=muted>Emptying both boxes and clearing the "
            "checkbox removes the policy.</small></div></form>"
            + _analysis(raw) + "</details>")
    head = ("<h3>SSH host policy</h3><p><small class=muted>Restrict an SSH key to the servers it may log in to. "
            "This is never shown to agents.</small></p>")
    if not rows:
        return ""
    return f"<style>{CSS}</style>" + head + "".join(rows)
