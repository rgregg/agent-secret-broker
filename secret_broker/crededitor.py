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

from . import peek

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


def base_from_form(form, stored):
    """The metadata the page showed (its hidden `advanced_orig`), the starting point for the form's
    fields; the stored metadata when it is missing or not an object. Only ever a starting point: the
    result is validated by the loader and diffed against `stored` before anything is written."""
    try:
        shown = json.loads(form.get("advanced_orig", "") or "null")
    except ValueError:
        shown = None
    return shown if isinstance(shown, dict) else stored


def norm_pin(fp):
    return re.sub(r"^sha256:", "", str(fp).strip(), flags=re.I).replace(":", "").lower()


def add_pin(meta, fp):
    """`meta` switched to pin mode with `fp` (sha256:<hex>) added to its fingerprints (no duplicates)."""
    pins = meta.get("tls_fingerprint")
    pins = [] if pins is None else (list(pins) if isinstance(pins, list) else [pins])
    if norm_pin(fp) not in {norm_pin(p) for p in pins}:
        pins.append(fp)
    out = {k: v for k, v in meta.items() if k != "tls_verify"}
    out["tls_fingerprint"] = pins[0] if len(pins) == 1 else pins
    return out


def cert_details(der):
    """What the human checks before trusting a certificate: its sha256 and, when it parses, subject,
    issuer, names and validity. Values from the certificate are returned as text for the page to escape."""
    out = {"fingerprint": "sha256:" + hashlib.sha256(der).hexdigest()}
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        out["subject"] = c.subject.rfc4514_string()[:300]
        out["issuer"] = c.issuer.rfc4514_string()[:300]
        out["self_signed"] = c.subject == c.issuer
        out["not_after"] = c.not_valid_after_utc.strftime("%Y-%m-%d %H:%M UTC")
        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            out["names"] = [str(n.value)[:255] for n in san][:20]
        except x509.ExtensionNotFound:
            out["names"] = []
    except Exception:  # noqa: BLE001 -- an unparsable certificate still has a fingerprint
        out["unparsed"] = True
    return out


def fetched_html(entry, d):
    e = html.escape
    rows = [("Fingerprint", f"<code>{e(d['fingerprint'])}</code>")]
    if d.get("unparsed"):
        rows.append(("Certificate", "could not be parsed; check the fingerprint some other way"))
    else:
        rows += [("Subject", e(d["subject"])), ("Issuer", e(d["issuer"]) + (" (self-signed)" if d["self_signed"] else "")),
                 ("Names", e(", ".join(d["names"])) or "<small class=muted>none</small>"),
                 ("Expires", e(d["not_after"]))]
    body = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
    return (f"<div class=flash><p><b>Certificate from {e(entry)}</b></p><dl class=kv>{body}</dl>"
            f"<p><small class=muted>Added to the pinned fingerprints below. Check that this is the device you "
            f"mean (compare it with its own console or a known value) before you save. A pin also expires "
            f"with the certificate: a renewed certificate has a new fingerprint.</small></p></div>")


def host_lines(text):
    """The allowed-hosts box -> a list of host entries (ValueError for control characters)."""
    return _lines(text, "allowed hosts")


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
.diff{overflow:auto;max-height:24em;padding:.6em;border:1px solid var(--line);border-radius:.5rem;background:var(--card)}
.cred-form label{display:block;margin:.8em 0 .2em;font-weight:600}
.cred-form textarea,.cred-form input[type=text],.cred-form input[type=password],.cred-form select{font:inherit;width:100%;
padding:.45rem .6rem;border:1px solid var(--line);border-radius:.5rem;background:var(--bg);color:var(--fg)}
.cred-form textarea{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}
.cred-form input[type=checkbox],.cred-form input[type=radio]{width:auto}
.chead2{display:flex;align-items:center;gap:.8rem;flex-wrap:wrap;margin:0 0 .9rem}.chead2 h1{margin:0;flex:1}
.ctool{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:0 0 .8rem}
.ctool input{flex:1 1 16rem;font:inherit;min-height:2.5rem;padding:.3rem .75rem;border-radius:.5rem;
border:1px solid var(--line);background:var(--card);color:var(--fg)}
.ctool .n{color:var(--muted);font-size:.85rem;white-space:nowrap}
.ctbl td{vertical-align:middle}.ctbl tr.r:hover td{background:var(--hov)}
.ctbl tr[hidden]{display:none!important}
.cname{display:flex;align-items:center;gap:.6rem}.cname a{font-weight:600;text-decoration:none;overflow-wrap:anywhere}
.cname small{display:block;font-size:.78rem}
.ci{display:inline-flex;align-items:center;justify-content:center;width:1.9rem;height:1.9rem;border-radius:.45rem;
background:var(--hov);color:var(--muted);flex:none;cursor:default}
.ci svg{width:1.05rem;height:1.05rem;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.ci.ok{background:var(--okbg);color:var(--okfg)}.ci.warn{background:var(--wbg);color:var(--wfg)}
.ci.bad{background:var(--badbg);color:var(--bad)}.ci.acc{color:var(--accent)}
.ctbl th.ic,.ctbl td.ic{text-align:center;width:5rem;white-space:nowrap}
.hchips{display:flex;flex-wrap:wrap;gap:.3rem}
.hchip{font:.78rem/1.5 ui-monospace,Menlo,monospace;padding:0 .45rem;border:1px solid var(--line);border-radius:.35rem;
background:var(--bg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:22rem}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.ckey{display:flex;flex-wrap:wrap;gap:.4rem 1.1rem;margin:.8rem 0 0;font-size:.8rem;color:var(--muted)}
.ckey span{display:inline-flex;align-items:center;gap:.35rem}.ckey .ci{width:1.5rem;height:1.5rem}
.ckey .ci svg{width:.85rem;height:.85rem}
.ced{max-width:46rem}.ced .card h2{margin-bottom:.15rem}
.ced .hint{font-size:.82rem;color:var(--muted);margin:.2rem 0 .55rem}
.seg{display:grid;gap:.4rem}.seg label{display:flex;gap:.6rem;align-items:flex-start;margin:0;padding:.55rem .7rem;
border:1px solid var(--line);border-radius:.55rem;cursor:pointer;font-weight:400}
.seg label:has(input:checked){border-color:var(--accent);background:var(--hov)}
.seg b{display:block}.seg small{display:block}
.fprow{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.5rem}.fprow input{flex:1 1 14rem}
.ced details{margin:0 0 .8rem}.ced summary{cursor:pointer;font-weight:600}
.abar{position:sticky;bottom:.5rem;z-index:20;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;
padding:.7rem 1rem;margin:1rem 0 0;background:var(--card);border:1px solid var(--line);border-radius:.7rem;
box-shadow:0 4px 18px #0002}
.abar .sp{flex:1}.abar .dirty{color:var(--wfg);font-size:.85rem;font-weight:600}
.dzone{border-color:var(--badbg)}
.vrow{border-top:1px solid var(--line);padding:.7rem 0}.vrow:first-of-type{border-top:0}
.vhead{display:flex;align-items:baseline;gap:.6rem;flex-wrap:wrap}.vhead code{font-weight:600}
.vline{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin-top:.4rem}
.vline input{flex:1 1 14rem;font:.85rem ui-monospace,Menlo,monospace;padding:.4rem .6rem;border:1px solid var(--line);
border-radius:.5rem;background:var(--bg);color:var(--fg)}
.vline form{display:contents}.vrow details{margin:.45rem 0 0}.vrow summary{font-weight:400;font-size:.85rem}
.pubkey{font:.78rem ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
@media (max-width:42rem){.ctbl th.ic,.ctbl td.ic{text-align:left;width:100%}
 .ctbl td .vh{position:static;width:auto;height:auto;clip:auto;align-self:center;font-size:.85rem}
 .abar .btn,.abar button{flex:1 1 auto}}
"""

# Feather-style line icons (24x24, stroked by CSS). Static markup: nothing from the metadata goes in them.
_ICONS = {
    "key": "<circle cx=7.5 cy=15.5 r=4.5 /><path d='M10.7 12.3 21 2m-5 5 3 3m-6-0 2 2'/>",
    "user": "<path d='M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'/><circle cx=12 cy=7 r=4 />",
    "term": "<path d='m4 17 6-6-6-6m8 14h8'/>",
    "phone": "<rect x=5 y=2 width=14 height=20 rx=2 /><path d='M12 18h.01'/>",
    "zap": "<path d='M13 2 3 14h9l-1 8 10-12h-9z'/>",
    "lock": "<rect x=3 y=11 width=18 height=11 rx=2 /><path d='M7 11V7a5 5 0 0 1 10 0v4'/>",
    "pin": "<path d='M12 17v5M9 10.8V4h6v6.8l3 3.2v2H6v-2z'/>",
    "unlock": "<rect x=3 y=11 width=18 height=11 rx=2 /><path d='M7 11V7a5 5 0 0 1 9.9-1'/>",
    "list": "<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>",
}


def icon(name, tone, label):
    """A labelled icon: the label is the tooltip, the accessible name and (in the narrow layout) the text."""
    t = html.escape(label, quote=True)
    return (f"<span class='ci {tone}' title='{t}' role=img aria-label='{t}'><svg viewBox='0 0 24 24' "
            f"aria-hidden=true>{_ICONS[name]}</svg></span><span class=vh>{t}</span>")


def kind_of(sc):
    """'ssh', 'login' or 'token', from the parsed catalog entry (a login's variables name username/password)."""
    if sc.get("ssh"):
        return "ssh"
    for ref in (sc.get("vars") or {}).values():
        if isinstance(ref, dict) and {ref.get("field"), ref.get("key")} & {"username", "password"}:
            return "login"
    return "token"


KIND_ICON = {"ssh": ("term", "acc", "SSH key"), "login": ("user", "acc", "Login"), "token": ("key", "acc", "Token")}


def _approval_icon(sc):
    if sc.get("approval", "prompt") == "allow":
        return icon("zap", "warn", "Approval: allowed without asking")
    return icon("phone", "", "Approval: asks on your phone")


def _tls_icon(meta):
    mode = tls_mode(meta)
    if mode == "pin":
        return icon("pin", "ok", "TLS: " + tls_summary(meta))
    if mode == "skip":
        return icon("unlock", "bad", "TLS: NOT verified")
    return icon("lock", "ok", "TLS: verified")


def _search_text(name, sc):
    meta = sc.get("_meta") or {}
    words = [name, kind_of(sc), KIND_ICON[kind_of(sc)][2], sc.get("approval", "prompt"),
             "tls " + tls_summary(meta), "unverified" if tls_mode(meta) == "skip" else "",
             "plans" if sc.get("plans") else "", " ".join(sc.get("allowed_hosts") or []) or "env"]
    return " ".join(str(w) for w in words if w).lower()


def matches(text, q):
    """Every whitespace-separated word of the query appears in `text` (the same rule the page's script uses)."""
    return all(w in text for w in q.lower().split())


MAX_CHIPS = 3


def list_section(secrets, flash="", q=""):
    e = html.escape
    q = q[:200]
    rows, shown = [], 0
    for name, sc in sorted(secrets.items()):
        meta = sc.get("_meta") or {}
        hosts = sc.get("allowed_hosts") or []
        chips = "".join(f"<code class=hchip title='{e(h)}'>{e(h)}</code>" for h in hosts[:MAX_CHIPS])
        if len(hosts) > MAX_CHIPS:
            rest = hosts[MAX_CHIPS:]
            chips += f"<small class=muted title='{e(', '.join(rest))}'>+{len(rest)} more</small>"
        hosts_html = f"<div class=hchips>{chips}</div>" if hosts else "<small class=muted>none: env mode only</small>"
        ic, tone, label = KIND_ICON[kind_of(sc)]
        nvars = len(sc.get("vars") or {})
        s = _search_text(name, sc)
        hit = matches(s, q)
        shown += hit
        plans = icon("list", "warn", "Plans allowed") if sc.get("plans") else "<small class=muted>-</small>"
        rows.append(
            f"<tr class=r data-s='{e(s)}'{'' if hit else ' hidden'}>"
            f"<td data-label=Name><div class=cname>{icon(ic, tone, label)}<div><a href='/credentials/{e(name)}'>"
            f"{e(name)}</a><small class=muted>{label} &middot; {nvars} variable{'s' if nvars != 1 else ''}</small>"
            f"</div></div></td>"
            f"<td data-label=Hosts>{hosts_html}</td>"
            f"<td class=ic data-label=Approval>{_approval_icon(sc)}</td>"
            f"<td class=ic data-label=TLS>{_tls_icon(meta)}</td>"
            f"<td class=ic data-label=Plans>{plans}</td></tr>")
    total = len(rows)
    count = f"{shown} of {total} credentials" if q.strip() else f"{total} credential{'s' if total != 1 else ''}"
    none = (f"<p id=cnone{'' if q.strip() and not shown else ' hidden'}><small class=muted>No credentials match "
            f"the search.</small></p>")
    tool = (f"<form class=ctool method=get action='/credentials' role=search>"
            f"<input type=search id=cq name=q value='{e(q)}' autocomplete=off "
            f"placeholder='Search by name, host or kind (ssh, login, allow, pinned...)' aria-label='Search credentials'>"
            f"<span class=n id=cn aria-live=polite>{count}</span></form>")
    table = ("<table class='tbl ctbl' id=ctbl><thead><tr><th>Name</th><th>Hosts</th><th class=ic>Approval</th>"
             "<th class=ic>TLS</th><th class=ic>Plans</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>")
    key = ("<div class=ckey>" + "".join(f"<span>{icon(n, t, l)}{l}</span>" for n, t, l in (
        ("key", "acc", "Token"), ("user", "acc", "Login"), ("term", "acc", "SSH key"),
        ("phone", "", "Asks on your phone"), ("zap", "warn", "Allowed without asking"),
        ("lock", "ok", "TLS verified"), ("pin", "ok", "TLS pinned"), ("unlock", "bad", "TLS not verified"))) + "</div>")
    body = (tool + table + none + key) if rows else "<p><small class=muted>No credentials.</small></p>"
    head = ("<div class=chead2><h1>Credentials</h1><a class='btn approve' href='/credentials/new'>New credential</a></div>")
    return head + flash + body


JS = r"""
(function(){
  var q=document.getElementById('cq');
  if(q){
    var rows=[].slice.call(document.querySelectorAll('#ctbl tbody tr.r')),n=document.getElementById('cn'),
        none=document.getElementById('cnone');
    var f=function(){
      var w=q.value.toLowerCase().split(/\s+/).filter(Boolean),shown=0;
      rows.forEach(function(r){var s=r.getAttribute('data-s')||'';
        var ok=w.every(function(x){return s.indexOf(x)>=0;});r.hidden=!ok;if(ok)shown++;});
      if(n)n.textContent=w.length?shown+' of '+rows.length+' credentials':rows.length+' credential'+(rows.length===1?'':'s');
      if(none)none.hidden=!(w.length&&!shown);
      try{history.replaceState(null,'',q.value?'/credentials?q='+encodeURIComponent(q.value):'/credentials');}catch(x){}
    };
    q.addEventListener('input',f);
    q.form.addEventListener('submit',function(e){e.preventDefault();f();});
    document.addEventListener('keydown',function(e){var t=document.activeElement&&document.activeElement.tagName;
      if(e.key==='/'&&t!=='INPUT'&&t!=='TEXTAREA'&&t!=='SELECT'){e.preventDefault();q.focus();}});
  }
  var fm=document.getElementById('cedit');
  if(fm){
    var dirty=fm.hasAttribute('data-dirty'),st=document.getElementById('cdirty'),pins=document.getElementById('cpins');
    var mark=function(){dirty=true;if(st)st.hidden=false;};
    var tls=function(){var m=fm.querySelector('input[name=tls]:checked');if(pins)pins.hidden=!(m&&m.value==='pin');};
    fm.addEventListener('input',mark);
    fm.addEventListener('change',function(){mark();tls();});
    fm.addEventListener('submit',function(){dirty=false;});
    tls();
    var cl=document.getElementById('cclose');
    if(cl)cl.addEventListener('click',function(e){if(dirty&&!confirm('Discard your unsaved changes?'))e.preventDefault();});
  }
  var btn=function(kind,v){return document.querySelector('[data-'+kind+'="'+v+'"]');};
  [].forEach.call(document.querySelectorAll('[data-reveal]'),function(b){
    b.form.addEventListener('submit',function(e){
      e.preventDefault();var v=b.getAttribute('data-reveal'),box=document.getElementById('val-'+v);
      fetch(b.form.action,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'manual',
        headers:{'Accept':'application/json'},body:new URLSearchParams(new FormData(b.form))})
      .then(function(r){return r.json();}).then(function(d){
        if(d.value===undefined){alert(d.error||'Could not show the value');return;}
        box.value=d.value;box.type='text';btn('copy',v).hidden=false;btn('hide',v).hidden=false;b.hidden=true;
      }).catch(function(){alert('Could not show the value');});
    });
  });
  [].forEach.call(document.querySelectorAll('[data-hide]'),function(b){b.addEventListener('click',function(){
    var v=b.getAttribute('data-hide');document.getElementById('val-'+v).value='';b.hidden=true;
    btn('copy',v).hidden=true;var r=btn('reveal',v);if(r)r.hidden=false;});});
  [].forEach.call(document.querySelectorAll('[data-copy]'),function(b){b.addEventListener('click',function(){
    var v=b.getAttribute('data-copy'),box=document.getElementById('val-'+v);
    if(navigator.clipboard)navigator.clipboard.writeText(box.value).then(function(){b.textContent='Copied';
      setTimeout(function(){b.textContent='Copy';},1500);});});});
  [].forEach.call(document.querySelectorAll('form[data-confirm]'),function(f){f.addEventListener('submit',function(e){
    if(!confirm(f.getAttribute('data-confirm')))e.preventDefault();});});
})();
"""


def new_section(token, name="", hosts="", error="", can_write=True):
    """The create form. The value is a password box and is never filled back in."""
    e = html.escape
    err = f"<p class=err>{e(error)}</p>" if error else ""
    off = "" if can_write else "<p class=err>This vault backend cannot store metadata, so credentials cannot be created here.</p>"
    dis = "" if can_write else " disabled"
    return (f"<div class=ced><h1>New credential</h1>{err}{off}<div class=card>"
            f"<form class=cred-form method=post action='/credentials/new' autocomplete=off>"
            f"<input type=hidden name=csrf value='{e(token)}'>"
            f"<label>Name (a-z, 0-9, _ and -, up to 41 characters)</label>"
            f"<input type=text name=name value='{e(name)}' maxlength=41{dis}>"
            f"<label>Allowed hosts (one per line, <code>host</code> or <code>host:port</code>)</label>"
            f"<textarea name=allowed_hosts rows=3{dis}>{e(hosts)}</textarea>"
            f"<label>Token (the value the broker will keep; it is never shown again)</label>"
            + peek.wrap(f"<input type=password name=value autocomplete=new-password{dis}>") +
            f"<p><small class=muted>Created like <code>asb store</code>: a vault item with this name, the token in "
            f"its <code>notes</code> field and the variable <code>NAME_TOKEN</code>. Approval is "
            f"<code>prompt</code>. You can change everything but the name afterwards.</small></p>"
            f"<div class=abar><button type=submit class='btn approve'{dis}>Create</button><span class=sp></span>"
            f"<a class=btn href='/credentials'>Cancel</a></div></form></div></div>")


def manage_section(name, token, sha, bindings, *, can_write, blocked=""):
    """Rename and delete, under the edit form. `bindings`: {kind: count} of what is bound to the name;
    `blocked`: why neither is possible (internal key, adopted item), or ''."""
    e = html.escape
    bound = {k: v for k, v in bindings.items() if v}
    note = ""
    if blocked:
        note = f"<p><small class=muted>{e(blocked)}</small></p>"
    elif bound:
        what = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in sorted(bound.items()))
        note = (f"<p><small class=muted>Rename and delete are unavailable while this credential is in use "
                f"({e(what)}). Revoke those on the Policies and Clients tabs first.</small></p>")
    dis = "" if (can_write and not blocked and not bound) else " disabled"
    return (f"<h2>Rename or delete</h2>{note}"
            f"<form class=cred-form method=post action='/credentials/{e(name)}/rename'>"
            f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=old_sha value='{e(sha)}'>"
            f"<label>New name</label><input type=text name=new_name maxlength=41{dis}>"
            f"<p><small class=muted>Only the name changes; the vault item and its value stay. Anything that "
            f"refers to the old name (a deny rule in the config, an agent's saved command) must be updated.</small></p>"
            f"<p><button type=submit{dis}>Rename</button></p></form>"
            f"<form class=cred-form method=post action='/credentials/{e(name)}/delete'>"
            f"<input type=hidden name=csrf value='{e(token)}'>"
            f"<label>Delete: type <code>{e(name)}</code> to confirm</label>"
            f"<input type=text name=typed autocomplete=off{dis}>"
            f"<p><small class=muted>This deletes the vault item and its value. It cannot be undone from here.</small></p>"
            f"<p><button type=submit class='btn deny'{dis}>Delete this credential</button></p></form>")


def _where(ref):
    """Where a variable's value lives, for the page (field and key names are metadata, never values)."""
    e = html.escape
    f = ref.get("field") or "auto"
    out = "the item's own value" if f == "auto" else f"field <code>{e(f)}</code>"
    return out + (f", key <code>{e(ref['key'])}</code>" if ref.get("key") else "")


def values_section(name, sc, token, sha, *, can_write, revealed=None):
    """The Values card. No value is ever in it, except `revealed` = (var, value): the one value the human just
    asked to see through the no-script fallback (the script fills the box from a JSON reply instead)."""
    e = html.escape
    n = e(name)
    hid = f"<input type=hidden name=csrf value='{e(token)}'>"
    if sc.get("ssh"):
        return (f"<div class=card><h2>Values</h2><p class=hint>An SSH key. The private key is never shown or "
                f"changed here; replace it with <code>asb store --replace</code>.</p>"
                f"<p><b>Public key</b></p><p class=pubkey>{e(str(sc.get('ssh_public_key') or ''))}</p></div>")
    vars_ = sc.get("vars") or {}
    rows = []
    for var, ref in vars_.items():
        v = e(var)
        shown = revealed[1] if revealed and revealed[0] == var else None
        box = (f"<input type=text readonly id='val-{v}' aria-label='Value of {v}' placeholder='hidden' "
               f"autocomplete=off spellcheck=false value='{e(shown)}'>" if shown is not None else
               f"<input type=text readonly id='val-{v}' aria-label='Value of {v}' placeholder='hidden' "
               f"autocomplete=off spellcheck=false>")
        remove = ""
        if can_write and len(vars_) > 1 and not sc.get("auto"):
            remove = (f"<form method=post action='/credentials/{n}/value/remove' data-confirm='Remove {v} from "
                      f"this credential? The value stays in the vault item.'>{hid}"
                      f"<input type=hidden name=old_sha value='{e(sha)}'><input type=hidden name=var value='{v}'>"
                      f"<button type=submit class='btn sm'>Remove</button></form>")
        rows.append(
            f"<div class=vrow><div class=vhead><code>{v}</code><small class=muted>{_where(ref)}</small></div>"
            f"<div class=vline>{box}"
            f"<form method=post action='/credentials/{n}/reveal'>{hid}<input type=hidden name=var value='{v}'>"
            f"<button type=submit class='btn sm' data-reveal='{v}'>Show</button></form>"
            f"<button type=button class='btn sm' data-copy='{v}'{'' if shown is not None else ' hidden'}>Copy</button>"
            f"<button type=button class='btn sm' data-hide='{v}'{'' if shown is not None else ' hidden'}>Hide</button>"
            f"{remove}</div>"
            f"<details><summary>Replace the value</summary>"
            f"<form method=post action='/credentials/{n}/value' autocomplete=off class=vline>{hid}"
            f"<input type=hidden name=var value='{v}'>"
            + peek.wrap(f"<input type=password name=value autocomplete=new-password aria-label='New value of {v}'"
                        f" placeholder='new value'>")
            + f"<button type=submit class='btn sm'>Save value</button></form>"
            f"<p class=hint>The old value is kept in the item's <code>previous_value</code>.</p></details></div>")
    add = ""
    if can_write and not sc.get("auto"):
        add = (f"<details><summary>Add a value</summary>"
               f"<form method=post action='/credentials/{n}/value/add' autocomplete=off class=cred-form>{hid}"
               f"<input type=hidden name=old_sha value='{e(sha)}'>"
               f"<label>Variable name (letters, digits and _, like <code>API_SECRET</code>)</label>"
               f"<input type=text name=var maxlength=64 spellcheck=false>"
               f"<label>Value</label>" + peek.wrap("<input type=password name=value autocomplete=new-password>") +
               f"<label style='font-weight:400'><input type=checkbox name=confirm value=1> I understand agents can "
               f"use this value on this credential's hosts</label>"
               f"<p class=hint>Stored in a new hidden field of the same vault item, named like the variable.</p>"
               f"<p><button type=submit class='btn sm'>Add value</button></p></form></details>")
    elif sc.get("auto"):
        add = "<p class=hint>Save this credential once below to give it its own metadata; then values can be added.</p>"
    return (f"<div class=card><h2>Values</h2><p class=hint>Shown only when you press Show; each view is recorded "
            f"in the audit log.</p>{''.join(rows)}{add}</div>")


def edit_section(name, meta, token, stored, *, can_write, error="", preview=None, widen=(), conflict=False,
                 extra="", fetched="", values="", flash=""):
    """The edit page. `stored`: the metadata the vault holds (what the diff is against and what the
    concurrency hash covers); `meta`: what the form fields show (the stored metadata, or the human's
    rejected candidate). `preview`: the candidate metadata on the confirm step (diff + save button)."""
    e = html.escape
    sha = digest(stored)
    pins = meta.get("tls_fingerprint")
    pin_text = "\n".join(pins if isinstance(pins, list) else [pins]) if pins is not None else ""
    mode = tls_mode(meta)
    approval = meta.get("approval", "prompt")
    sel = "".join(f"<option value={v}{' selected' if approval == v else ''}>{t}</option>"
                  for v, t in (("prompt", "prompt: ask on my phone for each use"),
                               ("allow", "allow: let requests through without asking")))
    shown = pretty(meta)
    err = f"<p class=err>{e(error)}</p>" if error else ""
    if conflict:
        err += ("<p class=err>This credential changed in the vault after you opened it. The form below shows "
                "the current stored values; make your change again.</p>")
    off = "" if can_write else ("<p class=err>This vault backend cannot store metadata, so credentials cannot "
                                "be edited here.</p>")
    dis = "" if can_write else " disabled"
    close = f"<a class=btn id=cclose href='/credentials'>Close</a>"
    if preview is not None:
        ticks = ""
        if widen:
            ticks = ("<div class='card dzone'><p><strong>This change widens access:</strong></p><ul>"
                     + "".join(f"<li>{e(WIDEN_TEXT[w])}</li>" for w in widen)
                     + "</ul><label><input type=checkbox name=confirm_widen value=1> "
                       "I understand this widens access</label></div>")
        return (f"<div class=ced><h1>Review changes to {e(name)}</h1>{err}"
                f"<p class=hint>Lines marked <b>-</b> are removed and <b>+</b> are added. Nothing is saved until "
                f"you press Save.</p>{diff_html(stored, preview)}"
                f"<form method=post action='/credentials/{e(name)}/save'>"
                f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=old_sha value='{e(sha)}'>"
                f"<input type=hidden name=meta_json value='{e(json.dumps(preview, sort_keys=True))}'>"
                f"{ticks}<div class=abar><button type=submit class='btn approve'>Save</button>"
                f"<a class=btn href='/credentials/{e(name)}'>Back to editing</a><span class=sp></span>{close}"
                f"</div></form></div>")
    seg = "".join(
        f"<label><input type=radio name=tls value={m}{' checked' if mode == m else ''}{dis}><span><b>{t}</b>"
        f"<small class=muted>{h}</small></span></label>"
        for m, t, h in (("verify", "Verify the certificate", "The normal check against trusted authorities."),
                        ("pin", "Trust only pinned fingerprints", "For a self-signed device. A renewed "
                         "certificate needs a new pin."),
                        ("skip", "Do not verify", "Private hosts only: anyone in the path could read the traffic.")))
    dirty = " data-dirty" if meta != stored else ""
    form = (f"<form class=cred-form id=cedit method=post action='/credentials/{e(name)}/save'{dirty}>"
            f"<input type=hidden name=csrf value='{e(token)}'><input type=hidden name=old_sha value='{e(sha)}'>"
            f"<input type=hidden name=advanced_orig value='{e(shown)}'>"
            f"<div class=card><h2>Allowed hosts</h2><p class=hint>Where the broker will send this credential. One "
            f"per line, <code>host</code> or <code>host:port</code>.</p>"
            f"<textarea name=allowed_hosts rows=4{dis}>"
            f"{e(chr(10).join(meta.get('allowed_hosts') or []))}</textarea></div>"
            f"<div class=card><h2>TLS</h2><p class=hint>How the broker checks the server's certificate.</p>"
            f"<div class=seg>{seg}</div>"
            f"<div id=cpins><label>Pinned fingerprints (one per line, <code>sha256:&lt;64 hex&gt;</code>)</label>"
            f"<textarea name=tls_fingerprint rows=3{dis}>{e(pin_text)}</textarea>"
            f"<div class=fprow><input type=text name=fp_host placeholder='host or host:port from the list above' "
            f"aria-label='Host to fetch a certificate from' autocomplete=off{dis}>"
            f"<button type=submit formaction='/credentials/{e(name)}/fingerprint'{dis}>Fetch fingerprint</button>"
            f"</div></div></div>"
            f"<div class=card><h2>Approval</h2><p class=hint>Whether each use waits for you.</p>"
            f"<select name=approval aria-label=Approval{dis}>{sel}</select>"
            f"<label style='font-weight:400'><input type=checkbox name=plans value=1"
            f"{' checked' if meta.get('plans') else ''}{dis}> Allow plans (a batch of calls approved once)</label>"
            f"</div>"
            f"<details><summary>Advanced: the whole metadata as JSON</summary>"
            f"<p class=hint>Edit this only for keys the form does not cover. If you change it, it "
            f"replaces the form's fields.</p>"
            f"<textarea name=advanced rows=14{dis}>{e(shown)}</textarea></details>"
            f"<div class=abar><button type=submit class='btn approve'{dis}>Save</button>"
            f"<button type=submit formaction='/credentials/{e(name)}/preview'{dis}>Review changes</button>"
            f"<span class=dirty id=cdirty{'' if dirty else ' hidden'}>Unsaved changes</span>"
            f"<span class=sp></span>{close}</div></form>"
            f"<p class=hint>Save stores the change and returns to the list. A change that widens access (a new "
            f"host, a TLS pin added or removed, checks turned off, approval or plans allowed) opens a review "
            f"page first and needs your tick.</p>")
    manage = f"<div class='card dzone'>{extra}</div>" if extra else ""
    note = f"<div class=flash>{e(flash)}</div>" if flash else ""
    return f"<div class=ced><h1>Edit {e(name)}</h1>{note}{err}{off}{fetched}{values}{form}{manage}</div>"
