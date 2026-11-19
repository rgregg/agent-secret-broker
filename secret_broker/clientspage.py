"""The Clients tab body.

One compact row per client: a status icon, the name, when it was last seen, the `asb` version it runs (with an
upgrade icon when that is below the recommended one), a rules count, and icon controls. Everything else lives in
pop-over dialogs the row opens:

    cd-<id>  details: identity, host claim, enrollment, last seen, version, ceiling, and the controls
    cr-<id>  rules: every rule scoped to this client, each with a revoke control
    cn-<id>  rename
    cv-<id>  revoke (permanent; asks for confirmation)

The list needs no JavaScript. The row controls are links to the dialogs; with script they open modally (focus moves in,
Escape closes, focus returns to the control), and without it the dialog's `:target` style shows it in place, with a
Close link. Disable/enable and the revoke of a rule are plain forms.

Every value shown comes from the store's validated records or is escaped; identity-shaped text goes through
`emailsafe.text`. Revoking a rule posts to the same endpoints as the credential's Policies page (same CSRF and
identity guards), with `back=clients` so the human lands on this tab again.
"""
import html
import time

from . import clients as C
from . import clientver
from . import credlinks
from . import emailsafe

esc = html.escape

# Feather-style line icons (24x24, stroked by CSS). Static markup: nothing from a client goes in them.
_ICONS = {
    "active": "<path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'/><path d='m22 4-10 10.01-3-3'/>",
    "disabled": "<circle cx=12 cy=12 r=10 /><path d='M10 15V9m4 6V9'/>",
    "revoked": "<circle cx=12 cy=12 r=10 /><path d='m15 9-6 6m0-6 6 6'/>",
    "pending": "<circle cx=12 cy=12 r=10 /><path d='M12 6v6l4 2'/>",
    "denied": "<circle cx=12 cy=12 r=10 /><path d='m4.9 4.9 14.2 14.2'/>",
    "expired": "<circle cx=12 cy=12 r=10 /><path d='M8 12h8'/>",
    "approved": "<path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'/><path d='m22 4-10 10.01-3-3'/>",
    "rename": "<path d='M12 20h9'/><path d='M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z'/>",
    "revoke": "<path d='M18 6 6 18M6 6l12 12'/>",
    "pause": "<path d='M6 4h4v16H6zM14 4h4v16h-4z'/>",
    "play": "<path d='m6 4 14 8-14 8z'/>",
    "rules": "<path d='M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01'/>",
    "info": "<circle cx=12 cy=12 r=10 /><path d='M12 16v-4m0-4h.01'/>",
    "upgrade": "<circle cx=12 cy=12 r=10 /><path d='m16 12-4-4-4 4m4 4V8'/>",
    "trash": "<path d='M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14'/>",
}
_STATE_TONE = {"active": "ok", "approved": "ok", "disabled": "warn", "pending": "warn", "revoked": "bad",
               "denied": "bad", "expired": "mute"}
STATE_LABEL = {"active": "Active", "disabled": "Disabled (requests are refused)", "revoked": "Revoked",
               "pending": "Pending", "denied": "Denied", "expired": "Expired", "approved": "Approved"}


def _svg(name):
    return f"<svg viewBox='0 0 24 24' aria-hidden=true focusable=false>{_ICONS[name]}</svg>"


def icon(name, label, tone=""):
    """A status icon that is not a control: the label is its accessible name and its tooltip."""
    t = esc(label, quote=True)
    return f"<span class='cx {tone}' role=img aria-label='{t}' title='{t}'>{_svg(name)}</span>"


def state_icon(state, label=None):
    """The icon for a client state or an enrollment status (active, disabled, revoked, pending, denied...)."""
    return icon(state, label or STATE_LABEL.get(state, state), _STATE_TONE.get(state, ""))


def ctl_link(name, label, target, tone="", extra=""):
    """An icon control that opens a dialog: a real link (it works without script), with an accessible name."""
    t = esc(label, quote=True)
    return (f"<a class='{('ib ' + tone).strip()}' href='#{esc(target, quote=True)}' data-dlg='{esc(target, quote=True)}' "
            f"aria-haspopup=dialog aria-label='{t}' title='{t}'>{_svg(name)}{extra}</a>")


def ctl_button(name, label, tone="", extra=""):
    """An icon submit button (inside a form), with an accessible name."""
    t = esc(label, quote=True)
    return f"<button class='{('ib ' + tone).strip()}' type=submit aria-label='{t}' title='{t}'>{_svg(name)}{extra}</button>"


def _form(action, csrf, fields, inner, cls="inline"):
    hid = "".join(f"<input type=hidden name='{esc(k, quote=True)}' value='{esc(str(v), quote=True)}'>"
                  for k, v in {"csrf": csrf, **fields}.items())
    return f"<form method=post action='{esc(action, quote=True)}' class={cls}>{hid}{inner}</form>"


def _ago(t, now):
    return C._ago(t, now)


def _dialog(did, title_html, body, close_to):
    return (f"<dialog id='{esc(did, quote=True)}' class='dlg cdlg' aria-labelledby='{esc(did, quote=True)}-t'>"
            f"<div class=dhead><h2 id='{esc(did, quote=True)}-t'>{title_html}</h2>"
            f"<a class='btn sm' href='#{esc(close_to, quote=True)}' data-dclose>Close</a></div>"
            f"<div class=dbody>{body}</div></dialog>")


# ---------------------------------------------------------------- rules (what a client may do without asking)
def rule_rows(broker, csrf):
    """{client id: [rule dict]} for every rule scoped to one client. A rule dict: kind (label), names (credentials,
    linked), covers (text), detail (text), revoke (None, or (action, fields, label) for the existing endpoint)."""
    out = {}

    def add(cid, **row):
        out.setdefault(cid, []).append(row)
    for r in broker.standing_rows():
        if r.get("client") in (None, C.ANY):
            continue
        kind = "Timed approval" if r["kind"] == "timed" else "Always approval"
        det = "" if r["kind"] != "timed" or r["left_s"] is None else f"{max(0, int(r['left_s'])) // 60} min left"
        add(r["client"], kind=kind, names=r["names"], covers=r["covers"], detail=det,
            revoke=("/grants/revoke", {"grant": r["id"], "back": "clients"}, f"Revoke this {kind.lower()}"))
    with broker._cfg_lock:
        secrets_now = sorted(broker.cfg["secrets"].items())
    for name, sc in secrets_now:
        for r in sc.get("ssh_rules") or []:
            cid = r.get("client", C.ANY)
            if cid != C.ANY:
                exp = r.get("expires_at")
                add(cid, kind="SSH host rule", names=[name], covers=f"{r['user']} on {r['host'] or r['fp'][:19]}",
                    detail=f"expires {exp}" if exp else "",
                    revoke=("/policies/ssh_rules/revoke", {"secret": name, "rule": r["id"], "back": "clients"},
                            "Revoke this SSH host rule"))
        for r in sc.get("auto_rules") or []:
            for cid in sorted(r.get("clients") or ()):
                add(cid, kind="Auto-approve rule", names=[name], covers=_auto_text(r), detail=r.get("name", ""),
                    revoke=("/policies/auto_rules/revoke", {"secret": name, "rule": r["id"], "back": "clients"},
                            "Revoke this auto-approve rule"))
    for r in broker.auto_rules:
        for cid in sorted(r.get("clients") or ()):
            add(cid, kind="Auto-approve rule (configuration)", names=sorted(r["secrets"]), covers=_auto_text(r),
                detail=r.get("name", ""), revoke=None)
    for v in broker.active_plans():
        add(v["client_id"], kind="Plan", names=v["names"],
            covers=f"{v['uses']}/{v['uses_max']} calls used, {max(0, v['left_s']) // 60} min left", detail="",
            revoke=("/plans/revoke", {"plan": v["id"]}, "Revoke this plan"))
    return out


def _auto_text(rule):
    from . import uirules
    try:
        return uirules.describe(rule)
    except (KeyError, TypeError):
        return str(rule.get("mode", "rule"))


def _rule_li(r, csrf):
    names = credlinks.links(r["names"], tab="policies")
    if r["revoke"] is None:
        act = "<small class=muted>set in the configuration file</small>"
    else:
        action, fields, label = r["revoke"]
        act = _form(action, csrf, fields, ctl_button("revoke", label + ": " + ", ".join(r["names"]), "bad"))
    det = f" <small class=muted>{esc(r['detail'])}</small>" if r["detail"] else ""
    return (f"<li class=rrow><div class=rtxt><span class=rkind>{esc(r['kind'])}</span> "
            f"<b>{names}</b><br><span class=muted>{esc(r['covers'])}</span>{det}</div>"
            f"<div class=ract>{act}</div></li>")


# ---------------------------------------------------------------- the rows and dialogs
def _version_bits(view_version, threshold):
    """(short text for the row, upgrade tooltip or '')."""
    label = clientver.label(view_version)
    if not clientver.valid(view_version):
        return "version unknown", ""
    if clientver.outdated(view_version, threshold):
        return f"asb {label}", (f"Upgrade recommended: this client runs asb {label}; {threshold} or newer is "
                                "current. Run the installer again on that machine.")
    return f"asb {label}", ""


def _kv(rows):
    return "<dl class=kv>" + "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows if v not in (None, "")) + "</dl>"


def _client(broker, c, rules, csrf, now, threshold):
    """(row html, dialogs html) for one enrolled client record."""
    cid, name, state = c["id"], c["name"], c["state"]
    vtext, upgrade = _version_bits(c.get("client_version"), threshold)
    seen = _ago(c["last_seen"], now)
    return _row_and_dialogs(
        broker, cid=cid, name=name, state=state, legacy=False, seen=seen, seen_abs=C.iso(c["last_seen"]) if c["last_seen"] else "",
        source=c["last_source"], vtext=vtext, upgrade=upgrade, rules=rules, csrf=csrf, rec=c)


def _legacy(broker, rules, csrf, now, threshold):
    leg = broker.clients.legacy_row()
    allowed = broker.clients.cfg["legacy"] == "allow"
    vtext, upgrade = _version_bits(leg.get("client_version"), threshold)
    return _row_and_dialogs(
        broker, cid=C.LEGACY_ID, name=C.LEGACY_NAME, state="active" if allowed else "denied", legacy=True,
        seen=_ago(leg["last_seen"], now), seen_abs=C.iso(leg["last_seen"]) if leg["last_seen"] else "",
        source=leg["last_source"], vtext=vtext, upgrade=upgrade, rules=rules, csrf=csrf, rec=leg)


def _row_and_dialogs(broker, cid, name, state, legacy, seen, seen_abs, source, vtext, upgrade, rules, csrf, rec):
    n = len(rules)
    d_id, r_id, n_id, v_id = f"cd-{cid}", f"cr-{cid}", f"cn-{cid}", f"cv-{cid}"
    row_id = f"cl-{cid}"
    live = not legacy and state in ("active", "disabled")
    label = ("Allowed (shared key)" if state == "active" else "Denied: legacy_client_key is deny") if legacy else None
    st = state_icon(state, label)
    up = icon("upgrade", upgrade, "warn") if upgrade else ""
    rule_lbl = f"{n} rule{'' if n == 1 else 's'} for {name}: view" if n else f"No rules of its own for {name}"
    rules_btn = ctl_link("rules", rule_lbl, r_id, extra=f"<span class=cnt>{n}</span>")
    acts = [rules_btn]
    if live:
        acts.append(ctl_link("rename", f"Rename {name}", n_id))
        if state == "active":
            acts.append(_form("/clients/disable", csrf, {"id": cid},
                              ctl_button("pause", f"Disable {name}: refuse every request, keep its rules", "warn")))
        else:
            acts.append(_form("/clients/enable", csrf, {"id": cid}, ctl_button("play", f"Enable {name}", "ok")))
        acts.append(ctl_link("revoke", f"Revoke {name}: permanent", v_id, "bad"))
    elif state == "revoked":
        acts.append(_form("/clients/remove", csrf, {"id": cid}, ctl_button("trash", f"Remove {name} from the list")))
    seen_txt = f"seen <time title='{esc(seen_abs, quote=True)}'>{esc(seen)}</time>" if seen_abs else "never seen"
    meta = (f"<span>{seen_txt}</span><span class=ver>{esc(vtext)}{up}</span>"
            + (f"<span>{'allowed' if state == 'active' else 'denied'} by configuration</span>" if legacy else ""))
    row = (f"<li class='crow st-{esc(state)}' id='{row_id}'>"
           f"<span class=cstat>{st}</span>"
           f"<div class=cmain><a class=cname href='#{d_id}' data-dlg='{d_id}' aria-haspopup=dialog>{esc(name)}</a>"
           f"<span class=idn>{'shared key' if legacy else esc(cid)}</span>"
           f"<div class=cmeta>{meta}</div></div>"
           f"<div class=cact>{''.join(acts)}</div></li>")
    dialogs = [_dialog(d_id, f"{st} {esc(name)}", _details(broker, cid, name, state, legacy, rec, seen, source, vtext,
                                                          upgrade, n, r_id, n_id, v_id, row_id, csrf), row_id),
               _dialog(r_id, f"Rules for {esc(name)}", _rules_body(rules, csrf, name, legacy), row_id)]
    if live:
        dialogs.append(_dialog(n_id, f"Rename {esc(name)}", _rename_body(cid, name, csrf, row_id), row_id))
        dialogs.append(_dialog(v_id, f"Revoke {esc(name)}", _revoke_body(cid, name, csrf, row_id), row_id))
    return row, "".join(dialogs)


def _details(broker, cid, name, state, legacy, rec, seen, source, vtext, upgrade, n, r_id, n_id, v_id, row_id, csrf):
    ceiling = broker.client_ceiling_text(cid)
    rows = [("Status", state_icon(state, None if not legacy else ("Allowed" if state == "active" else "Denied"))
             + f" {esc(STATE_LABEL[state] if not legacy else ('Allowed (shared key)' if state == 'active' else 'Denied'))}"),
            ("Client id", f"<code>{esc(cid)}</code>"),
            ("Last seen", esc(seen) + (f" <span class=muted>from {esc(source)}</span>" if source else "")),
            ("Requests served", str(rec["requests"])),
            ("Version", esc(vtext) + (f"<br>{icon('upgrade', upgrade, 'warn')} <small>{esc(upgrade)}</small>" if upgrade else "")),
            ("Effective ceiling", esc(ceiling))]
    if legacy:
        rows.insert(2, ("Applies to", "every machine using the shared key"))
    else:
        rows[2:2] = [("Host it claimed", (emailsafe.text(rec["claim"] or "-")
                                          + " <small class=muted>(unverified, typed by the client)</small>")),
                     ("Enrolled", f"{esc(C.iso(rec['created']))} <span class=muted>approved by {esc(rec['approved_by'] or '?')}"
                                  f" from {esc(rec['enrolled_from'] or '?')}</span>")]
        if state == "disabled" and rec.get("disabled_at"):
            rows.append(("Disabled", f"{esc(C.iso(rec['disabled_at']))} <span class=muted>by "
                                     f"{esc(rec.get('disabled_by') or 'unknown')}</span>"))
        if state == "revoked":
            rows.append(("Revoked", f"{esc(C.iso(rec['revoked_at'])) if rec['revoked_at'] else ''} "
                                    f"<span class=muted>by {esc(rec['revoked_by'] or 'unknown')}</span>"))
    rows.append(("Rules", f"<a href='#{esc(r_id)}' data-dlg='{esc(r_id)}' aria-haspopup=dialog>"
                          f"{n} rule{'' if n == 1 else 's'} of its own</a>"))
    body = _kv(rows)
    if legacy:
        body += ("<p><small class=muted>Set <code>legacy_client_key</code> to <code>deny</code> in the broker config "
                 "once every machine is enrolled. It cannot be disabled or revoked from this page.</small></p>")
    elif state in ("active", "disabled"):
        toggle = (_form("/clients/disable", csrf, {"id": cid}, f"<button class='btn'>{_svg('pause')} Disable</button>")
                  if state == "active" else
                  _form("/clients/enable", csrf, {"id": cid}, f"<button class='btn approve'>{_svg('play')} Enable</button>"))
        body += ("<div class=dacts>"
                 f"<a class=btn href='#{esc(n_id)}' data-dlg='{esc(n_id)}' aria-haspopup=dialog>{_svg('rename')} Rename</a>"
                 f"{toggle}"
                 f"<a class='btn deny' href='#{esc(v_id)}' data-dlg='{esc(v_id)}' aria-haspopup=dialog>{_svg('revoke')} Revoke</a>"
                 "</div><p><small class=muted><b>Disable</b> refuses every request from this client until you enable it "
                 "again, without asking you; its rules are kept but cannot be used. <b>Revoke</b> is permanent: "
                 "the key stops working and its rules are removed.</small></p>")
    return body


def _rules_body(rules, csrf, name, legacy):
    if not rules:
        return ("<p>No rules of its own.</p><p><small class=muted>It still gets the rules set for any client, and "
                "every other request asks you.</small></p>")
    return ("<ul class=rules2>" + "".join(_rule_li(r, csrf) for r in rules) + "</ul>"
            "<p><small class=muted>Rules for any client are listed on each credential's Policies page.</small></p>")


def _rename_body(cid, name, csrf, row_id):
    return _form("/clients/rename", csrf, {"id": cid},
                 f"<label for='rn-{esc(cid)}'>New name</label>"
                 f"<input id='rn-{esc(cid)}' type=text name=name value='{esc(name, quote=True)}' maxlength=32 required "
                 "spellcheck=false autocapitalize=off autocomplete=off data-autofocus>"
                 "<p><small class=muted>Lowercase letters, digits, - _ . (up to 32). Rules and history keep following "
                 "the client; only the label changes.</small></p>"
                 "<div class=decide-row><button class='btn approve'>Rename</button>"
                 f"<a class=btn href='#{esc(row_id)}' data-dclose>Cancel</a></div>", cls="stack")


def _revoke_body(cid, name, csrf, row_id):
    return _form("/clients/revoke", csrf, {"id": cid},
                 "<p>This client stops working on its next request, its waiting requests are denied and its own "
                 "rules are removed. It can enroll again as a new client. <b>This cannot be undone.</b></p>"
                 "<p><small class=muted>To stop it for now and keep its rules, disable it instead.</small></p>"
                 "<div class=decide-row><button class='btn deny' data-autofocus>Confirm revoke</button>"
                 f"<a class=btn href='#{esc(row_id)}' data-dclose>Cancel</a></div>", cls="stack")


def section(broker, csrf, now=None, flash=""):
    """The Clients tab body (everything above the plans and sessions tables)."""
    now = time.time() if now is None else now
    store = broker.clients
    threshold = clientver.threshold(store.cfg.get("min_version"))
    by_client = rule_rows(broker, csrf)
    items, dialogs = [], []
    r, d = _legacy(broker, by_client.get(C.LEGACY_ID, []), csrf, now, threshold)
    items.append(r)
    dialogs.append(d)
    for c in store.rows():
        r, d = _client(broker, c, by_client.get(c["id"], []), csrf, now, threshold)
        items.append(r)
        dialogs.append(d)
    cfg = store.cfg["enrollment"]
    waiting = len(store.pending())
    wait = (f"<p class=cwait>{state_icon('pending', 'Enrollment waiting')} <a href='/'>{waiting} enrollment"
            f"{' is' if waiting == 1 else 's are'} waiting for your decision on the Requests tab.</a></p>") if waiting else ""
    hint = ("<p><small class=muted>Add a machine by running <code>asb enroll --name NAME</code> on it; "
            "a card appears on the Requests tab and you approve exactly that card after matching its "
            "confirmation code. Refuse any enrollment you did not start. "
            + ("Enrollment is turned off in the broker config." if not cfg["enabled"] else "")
            + "</small></p>")
    note = f"<div class=flash>{esc(flash)}</div>" if flash else ""
    if store.unreadable:
        note += ("<div class=crerr role=alert><b>The client list could not be read.</b> Every per-client "
                 "credential is being refused (fail closed) until the file is fixed or removed.</div>")
    elif store.unsaved():
        note += ("<div class=crerr role=alert><b>The client list could not be saved.</b> A revoke, disable, rename "
                 "or enrollment is in effect now but is only in memory; if the broker restarts before the "
                 "write succeeds, a revoked client would work again. The write is retried every few "
                 "seconds. Check the disk.</div>")
    return (f"<h1>Clients</h1>{note}{wait}{hint}<div class=cl><ul class=cl-list>{''.join(items)}</ul>{''.join(dialogs)}</div>"
            "<p><small class=muted>A rule made for one client never applies to another; rules for "
            "<i>any client</i> apply to all. Rules are listed per client above (open its rules) and in full on each "
            "credential's Policies page.</small></p>")


CSS = """
.cl-list{list-style:none;margin:0 0 1rem;padding:0;border:1px solid var(--line);border-radius:.7rem;background:var(--card)}
.crow{display:flex;align-items:center;gap:.7rem;padding:.6rem .9rem;border-top:1px solid var(--line);flex-wrap:wrap}
.crow:first-child{border-top:0}.crow.st-revoked .cmain{opacity:.65}
.cmain{flex:1 1 14rem;min-width:0}.cname{font-weight:600;font-size:1rem;overflow-wrap:anywhere}
.cmeta{display:flex;flex-wrap:wrap;gap:.2rem .9rem;font-size:.8rem;color:var(--muted)}
.cmeta .ver{display:inline-flex;align-items:center;gap:.25rem}
.cact{display:flex;align-items:center;gap:.35rem;flex-wrap:wrap}.cact form{display:contents}
.cx{display:inline-flex;align-items:center;justify-content:center;width:1.7rem;height:1.7rem;border-radius:50%;vertical-align:middle;flex:none}
.cx svg,.ib svg{width:1.1rem;height:1.1rem;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.cmeta .cx{width:1.2rem;height:1.2rem}.cmeta .cx svg{width:.9rem;height:.9rem}
.cx.ok{color:var(--okfg);background:var(--okbg)}.cx.warn{color:var(--wfg);background:var(--wbg)}
.cx.bad{color:var(--bad);background:var(--badbg)}.cx.mute{color:var(--muted)}
.ib{display:inline-flex;align-items:center;justify-content:center;gap:.3rem;min-width:2.25rem;min-height:2.25rem;padding:0 .5rem;
border:1px solid var(--line);border-radius:.5rem;background:var(--card);color:var(--fg);cursor:pointer;font:inherit;line-height:1;text-decoration:none}
.ib:hover{background:var(--bg)}.ib:focus-visible,.cname:focus-visible,.cl .btn:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.ib.bad{color:var(--bad)}.ib.warn{color:var(--wfg)}.ib.ok{color:var(--okfg)}
.ib .cnt{font-size:.8rem;font-weight:600}
.cwait{display:flex;align-items:center;gap:.5rem}
.cl dialog.cdlg:target{display:flex;flex-direction:column;position:fixed;inset:0;margin:auto;height:fit-content;z-index:5}
.rules2{list-style:none;margin:0;padding:0}.rrow{display:flex;gap:.8rem;align-items:center;justify-content:space-between;
padding:.6rem 0;border-top:1px solid var(--line)}.rrow:first-child{border-top:0}.rtxt{min-width:0;overflow-wrap:anywhere}
.rkind{display:inline-block;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.dacts{display:flex;flex-wrap:wrap;gap:.5rem;margin:.8rem 0}.dacts form{display:contents}
.dacts .btn svg{width:1rem;height:1rem;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vertical-align:-.15rem}
form.stack label{display:block;font-weight:600;font-size:.85rem;margin:.2rem 0}
form.stack input[type=text]{font:inherit;min-height:2.5rem;padding:.3rem .6rem;border-radius:.5rem;border:1px solid var(--line);
background:var(--card);color:var(--fg);width:100%;max-width:18rem}
@media (max-width:42rem){.crow{align-items:flex-start}.cact{width:100%}}
"""

JS = r"""
(function(){
  var opener=null;
  function show(id,from){
    var d=document.getElementById(id);
    if(!d||typeof d.showModal!=='function')return false;
    var cur=from&&from.closest?from.closest('dialog'):null;
    if(cur&&cur.open){cur.close();from=opener;}      // one pop-over at a time; Close returns to the row
    opener=from;
    if(!d.open)d.showModal();
    var f=d.querySelector('[data-autofocus]')||d.querySelector('input,select,button,a[href]');
    if(f)try{f.focus();if(f.select&&f.type==='text')f.select();}catch(e){}
    return true;}
  document.addEventListener('click',function(e){
    var a=e.target.closest&&e.target.closest('[data-dlg]');
    if(a&&show(a.getAttribute('data-dlg'),a)){e.preventDefault();return;}
    var c=e.target.closest&&e.target.closest('[data-dclose]');
    if(c){var d=c.closest('dialog');if(d&&d.open){e.preventDefault();d.close();}return;}
    if(e.target.tagName==='DIALOG'&&e.target.classList.contains('cdlg')&&e.target.open)e.target.close();});
  document.addEventListener('close',function(e){
    var d=e.target;
    if(d&&d.classList&&d.classList.contains('cdlg')&&opener&&opener.isConnected&&!document.querySelector('dialog[open]')){
      try{opener.focus();}catch(x){}opener=null;}},true);
})();
"""
