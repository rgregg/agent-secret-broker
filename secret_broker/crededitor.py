"""The Credentials-tab editor: change a credential's `broker` metadata from the approval site.

A credential's policy is a JSON object in its vault item (see Broker._entry, the validator the catalog loader
runs; the editor calls that same function, so it can never accept what the loader would reject). This module turns
the form into a candidate metadata object, compares it with the stored one (a diff for the human, and a list of
ways the change *widens* what the credential can do), and renders the pages. It never handles credential values.

Everything a page shows from the metadata is escaped. Audit events carry counts, closed labels and hashes only.
"""
import hashlib
import html
import json
import re

MAX_JSON = 100_000          # the advanced box, in characters
FORM_LIMIT = 400_000        # percent-encoding of the above, plus the form fields
MAX_PINS = 20
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")

# the keys the form manages; every other key in the metadata is carried through untouched
FORM_KEYS = ("allowed_hosts", "tls_fingerprint", "tls_verify", "approval", "plans")
TLS_MODES = ("verify", "pin", "skip")


def digest(meta):
    """Stable hash of a metadata object (the concurrency token and the audit fingerprint)."""
    return hashlib.sha256(json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def pretty(meta):
    return json.dumps(meta, indent=2, sort_keys=True, ensure_ascii=True)


def tls_mode(meta):
    if meta.get("tls_fingerprint") is not None:
        return "pin"
    return "verify" if meta.get("tls_verify", True) is not False else "skip"


def tls_summary(meta):
    mode = tls_mode(meta)
    if mode == "pin":
        fp = meta["tls_fingerprint"]
        return f"pinned ({len(fp) if isinstance(fp, list) else 1})"
    return "verified" if mode == "verify" else "NOT verified"


def _lines(text, what):
    if not isinstance(text, str):
        raise ValueError(f"{what} must be text")
    if _CTRL.search(text.replace("\n", "").replace("\r", "").replace("\t", " ")):
        raise ValueError(f"{what} contains control characters")
    return [ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if ln.strip()]


def build(old, form):
    """The candidate metadata from the form (`form`: field -> text), starting from the stored `old`.

    The form's fields replace the keys they manage; every other key is kept. When the advanced JSON box was
    edited (it differs from what the page showed, `advanced_orig`), it replaces the result outright: it is the
    human's explicit whole-object edit. Raises ValueError (a short fixed message) for malformed input."""
    adv = form.get("advanced", "").replace("\r\n", "\n")
    orig = form.get("advanced_orig", "").replace("\r\n", "\n")
    if adv.strip() and adv.strip() != orig.strip():
        if len(adv) > MAX_JSON:
            raise ValueError("the JSON is too long")
        try:
            new = json.loads(adv)
        except ValueError:
            raise ValueError("the advanced JSON is not valid JSON") from None
        if not isinstance(new, dict):
            raise ValueError("the advanced JSON must be an object")
        return new
    new = {k: v for k, v in old.items() if k not in FORM_KEYS}
    hosts = _lines(form.get("allowed_hosts", ""), "allowed hosts")
    if hosts:
        new["allowed_hosts"] = hosts
    mode = form.get("tls", tls_mode(old))
    if mode not in TLS_MODES:
        raise ValueError("choose how TLS is checked")
    if mode == "pin":
        pins = _lines(form.get("tls_fingerprint", ""), "fingerprints")
        if not pins or len(pins) > MAX_PINS:
            raise ValueError(f"pin mode needs 1 to {MAX_PINS} fingerprints")
        new["tls_fingerprint"] = pins[0] if len(pins) == 1 else pins
    elif mode == "skip":
        new["tls_verify"] = False
    approval = form.get("approval", "")
    if approval and (approval != old.get("approval", "prompt") or "approval" in old):
        new["approval"] = approval          # an untouched default is not written, so an untouched form is a no-op
    if form.get("plans") == "1":
        new["plans"] = True
    elif "plans" in old:
        new["plans"] = False
    return new


def _hosts(meta):
    h = meta.get("allowed_hosts")
    return {str(x).lower() for x in h} if isinstance(h, list) else set()


def _pins(meta):
    fp = meta.get("tls_fingerprint")
    if fp is None:
        return set()
    return {re.sub(r"^sha256:", "", str(x).strip(), flags=re.I).replace(":", "").lower()
            for x in (fp if isinstance(fp, list) else [fp])}


def widened(old, new):
    """Closed labels for each way `new` lets the credential do more, or be checked less, than `old`.
    Narrowing (removing a host, adding verification) returns nothing. The save needs a tick for any label."""
    out = []
    if _hosts(new) - _hosts(old):
        out.append("host_added")
    if _pins(new) - _pins(old):
        out.append("pin_added")
    if _pins(old) - _pins(new):
        out.append("pin_removed")
    if tls_mode(old) != "skip" and tls_mode(new) == "skip":
        out.append("tls_unverified")
    if old.get("approval", "prompt") != "allow" and new.get("approval", "prompt") == "allow":
        out.append("approval_allow")
    if not old.get("plans") and new.get("plans"):
        out.append("plans_enabled")
    return out


WIDEN_TEXT = {
    "host_added": "adds an allowed host or port",
    "pin_added": "adds a trusted TLS fingerprint",
    "pin_removed": "removes a TLS fingerprint pin",
    "tls_unverified": "turns TLS verification off",
    "approval_allow": "lets requests through without asking",
    "plans_enabled": "allows plans for this credential",
}


def changed_keys(old, new):
    """The top-level keys that differ, as a sorted list (names of metadata keys are a closed vocabulary here
    only for the form's own keys; anything else is counted, never named, in the audit event)."""
    return sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))


def diff_html(old, new):
    """A line diff of the two pretty-printed objects, escaped."""
    a, b = pretty(old).splitlines(), pretty(new).splitlines()
    import difflib
    rows = []
    for ln in difflib.unified_diff(a, b, "stored", "new", lineterm="", n=2):
        cls = "add" if ln.startswith("+") and not ln.startswith("+++") else (
            "del" if ln.startswith("-") and not ln.startswith("---") else "ctx")
        rows.append(f"<div class='df {cls}'>{html.escape(ln)}</div>")
    return "<pre class=diff>" + "".join(rows) + "</pre>" if rows else "<p><small class=muted>No changes.</small></p>"


CSS = """
.df{white-space:pre-wrap}.df.add{background:rgba(40,160,80,.18)}.df.del{background:rgba(220,60,60,.18)}
.diff{overflow:auto;max-height:24em;padding:.6em;border:1px solid rgba(128,128,128,.4);border-radius:8px}
.cred-form label{display:block;margin:.8em 0 .2em;font-weight:600}
.cred-form textarea{width:100%;font-family:monospace}
"""


def list_section(secrets, flash=""):
    e = html.escape
    rows = []
    for name, sc in sorted(secrets.items()):
        meta = sc.get("_meta") or {}
        hosts = ", ".join(e(h) for h in sc.get("allowed_hosts") or []) or "<small class=muted>none (env mode only)</small>"
        kind = "ssh key" if sc.get("ssh") else "credential"
        rows.append(f"<tr><td><a href='/credentials/{e(name)}'>{e(name)}</a></td><td>{kind}</td><td>{hosts}</td>"
                    f"<td>{e(str(sc.get('approval', 'prompt')))}</td><td>{e(tls_summary(meta))}</td></tr>")
    body = ("<table><tr><th>Name</th><th>Kind</th><th>Hosts</th><th>Approval</th><th>TLS</th></tr>"
            + "".join(rows) + "</table>") if rows else "<p><small class=muted>No credentials.</small></p>"
    return f"<h1>Credentials</h1>{flash}{body}"


def edit_section(name, meta, token, stored, *, can_write, error="", preview=None, widen=(), conflict=False):
    """The edit page. `stored`: the metadata the vault holds (what the diff is against and what the
    concurrency hash covers); `meta`: what the form fields show (the stored metadata, or the human's
    rejected candidate). `preview`: the candidate metadata on the confirm step (diff + save button)."""
    e = html.escape
    sha = digest(stored)
    pins = meta.get("tls_fingerprint")
    pin_text = "\n".join(pins if isinstance(pins, list) else [pins]) if pins is not None else ""
    mode = tls_mode(meta)
    radios = "".join(
        f"<label style='font-weight:400'><input type=radio name=tls value={m}{' checked' if mode == m else ''}> {t}</label> "
        for m, t in (("verify", "Verify the certificate normally"), ("pin", "Trust only these fingerprints"),
                     ("skip", "Do not verify (private hosts only)")))
    approval = meta.get("approval", "prompt")
    sel = "".join(f"<option value={v}{' selected' if approval == v else ''}>{v}</option>" for v in ("prompt", "allow"))
    shown = pretty(meta)
    err = f"<p class=err>{e(error)}</p>" if error else ""
    if conflict:
        err += ("<p class=err>This credential changed in the vault after you opened it. The form below shows "
                "the current stored values; make your change again.</p>")
    off = "" if can_write else ("<p class=err>This vault backend cannot store metadata, so credentials cannot "
                                "be edited here.</p>")
    dis = "" if can_write else " disabled"
    form = (f"<form class=cred-form method=post action='/credentials/{e(name)}/preview'>"
            f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=old_sha value='{e(sha)}'>"
            f"<input type=hidden name=advanced_orig value='{e(pretty(stored))}'>"
            f"<label>Allowed hosts (one per line, <code>host</code> or <code>host:port</code>)</label>"
            f"<textarea name=allowed_hosts rows=4{dis}>{e(chr(10).join(meta.get('allowed_hosts') or []))}</textarea>"
            f"<label>TLS</label>{radios}"
            f"<label>Pinned fingerprints (one per line, <code>sha256:&lt;64 hex&gt;</code>)</label>"
            f"<textarea name=tls_fingerprint rows=3{dis}>{e(pin_text)}</textarea>"
            f"<label>Approval</label><select name=approval{dis}>{sel}</select>"
            f"<label style='font-weight:400'><input type=checkbox name=plans value=1"
            f"{' checked' if meta.get('plans') else ''}{dis}> Allow plans</label>"
            f"<details><summary>Advanced: the whole metadata as JSON</summary>"
            f"<p><small class=muted>Edit this only for keys the form does not cover. If you change it, it "
            f"replaces the form's fields.</small></p>"
            f"<textarea name=advanced rows=14{dis}>{e(shown)}</textarea></details>"
            f"<p><button type=submit{dis}>Review changes</button> <a href='/credentials'>Cancel</a></p></form>")
    if preview is not None:
        ticks = ""
        if widen:
            ticks = ("<p><strong>This change widens access:</strong></p><ul>"
                     + "".join(f"<li>{e(WIDEN_TEXT[w])}</li>" for w in widen)
                     + "</ul><label><input type=checkbox name=confirm_widen value=1> "
                       "I understand this widens access</label>")
        return (f"<h1>Review: {e(name)}</h1>{err}{diff_html(stored, preview)}"
                f"<form method=post action='/credentials/{e(name)}/save'>"
                f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=old_sha value='{e(sha)}'>"
                f"<input type=hidden name=meta_json value='{e(json.dumps(preview, sort_keys=True))}'>"
                f"{ticks}<p><button type=submit>Save</button> <a href='/credentials/{e(name)}'>Back</a></p></form>")
    return f"<h1>Edit {e(name)}</h1>{err}{off}{form}"
