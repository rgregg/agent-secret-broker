"""The Policies sub-tab of a credential's page: everything that can approve requests for this credential
without a tap, and what the decision model knows about it, in one place.

Sections, in order: standing approvals (timed, Always, and the legacy whole-credential allow), auto-approve rules
(credentials that are not SSH keys), risk guidance, SSH host policy and SSH host rules (SSH keys). Each section is
its own form with its own CSRF field and a hidden field naming the credential; none sits inside the Settings form.
The caller passes in only what belongs to this credential (see Broker.standing_by_credential).
"""
import dataclasses
import html
import time

from . import clients as clients_mod
from . import credlinks, guidance, guidancesuggest, sshhosts, sshrules, uirules


@dataclasses.dataclass
class PolicyCtx:
    csrf: str
    usage_ssh: object               # sshrules.Usage (SSH rule counters)
    usage_auto: object              # sshrules.Usage (auto-approve rule counters)
    client_names: dict
    client_choices: list
    standing_rows: list             # this credential's rows from Broker.standing_by_credential()
    config_rules: list              # config rules naming this credential (Broker.config_rules_for)
    states: dict = dataclasses.field(default_factory=dict)   # {"ssh_hosts", "ssh_rules", "auto_rules"}: re-render state
    grants_enabled: bool = True


def counts(name, sc, standing_rows, config_rules):
    """The numbers shown on the sub-tab label, the summary strip and the credentials list. Guidance is a flag and
    is not part of `total`."""
    standing = len(standing_rows)
    rules = len(sc.get("auto_rules") or []) + len(config_rules)
    ssh_rules = len(sc.get("ssh_rules") or [])          # standing SSH host rules sign without asking, so they count
    return {"standing": standing, "rules": rules, "ssh_rules": ssh_rules, "guidance": bool(sc.get("guidance")),
            "total": standing + rules + ssh_rules}


def _in_min(s):
    s = int(s or 0)
    return f"in {-(-s // 60)} min" if s >= 60 else "in under a minute"


def standing_card(name, rows, csrf, cnames):
    """This credential's standing approvals with Revoke (a grant form carries `back` so the answer lands here)."""
    e = html.escape
    if not rows:
        return "<div class='card empty'>No standing approvals</div>"
    out = []
    for r in rows:
        who = e(r["created_by"]) + (f" <small class=muted>{e(r['created_at'])}</small>" if r["created_at"] else "")
        if r["kind"] == "legacy":
            out.append(
                "<tr><td data-label=Covers colspan=5><b>approval: allow</b> "
                f"({e(r['covers'])}). Change this under {credlinks.link(name, text='Settings')} "
                "(Approval).</td></tr>")
            continue
        exp = ("never" if r["expires_at"] is None else
               f"<time data-gexp='{int(r['expires_at'])}'>{e(_in_min(r['left_s']))}</time>")
        out.append(
            f"<tr><td data-label=Covers>{e(r['covers'])}</td><td data-label=Expires>{exp}</td>"
            f"<td data-label='Created by'>{who}</td>"
            f"<td data-label='Applies to'>{e(clients_mod.scope_label(r['client'], cnames))}</td>"
            "<td><form method=post action='/grants/revoke' class=inline>"
            f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
            f"<input type=hidden name=grant value='{e(r['id'], quote=True)}'>"
            f"<input type=hidden name=back value='{e(name, quote=True)}'>"
            "<button>Revoke</button></form></td></tr>")
    return ("<table class=tbl><thead><tr><th>Covers</th><th>Expires</th><th>Created by</th><th>Applies to</th>"
            "<th></th></tr></thead><tbody>" + "".join(out) + "</tbody></table>")


ORPHAN = "names a credential that no longer exists"


def shared_standing_section(rows, csrf, cnames):
    """Timed approvals that cover several credentials, or one that is gone (Broker.standing_by_credential's
    shared rows). Names link to the credentials that exist; Revoke comes back to the Policies tab."""
    e = html.escape
    out = []
    for r in rows:
        who = e(r["created_by"]) + (f" <small class=muted>{e(r['created_at'])}</small>" if r["created_at"] else "")
        exp = ("never" if r["expires_at"] is None else
               f"<time data-gexp='{int(r['expires_at'])}'>{e(_in_min(r['left_s']))}</time>")
        mark = f"<br><small class=muted>{ORPHAN}</small>" if r.get("orphan") else ""
        out.append(
            f"<tr><td data-label=Secrets><b>{credlinks.links(r['names'], tab='policies')}</b>{mark}</td>"
            f"<td data-label=Covers>{e(r['covers'])}</td><td data-label=Expires>{exp}</td>"
            f"<td data-label='Created by'>{who}</td>"
            f"<td data-label='Applies to'>{e(clients_mod.scope_label(r['client'], cnames))}</td>"
            "<td><form method=post action='/grants/revoke' class=inline>"
            f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
            f"<input type=hidden name=grant value='{e(r['id'], quote=True)}'>"
            "<input type=hidden name=back value='policies'>"
            "<button>Revoke</button></form></td></tr>")
    return ("<h3>Timed approvals covering several credentials</h3><p><small class=muted>Requests these cover "
            "are approved without asking, with no risk limit, until the deadline. Each covers exactly the "
            "secrets, mode and method class shown. Revoke to ask every time again.</small></p>"
            "<table class=tbl><thead><tr><th>Secrets</th><th>Covers</th><th>Expires</th><th>Created by</th>"
            "<th>Applies to</th><th></th></tr></thead><tbody>" + "".join(out) + "</tbody></table>")


def shared_rules_section(rules, cnames):
    """Config auto-approve rules that name several credentials, or one that is gone (read-only)."""
    e = html.escape
    out = []
    for r in rules:
        mark = f"<br><small class=muted>{ORPHAN}</small>" if r.get("orphan") else ""
        out.append(
            f"<tr><td data-label=Name>{e(r['name'])}</td><td data-label=Mode>{e(r['mode'])}</td>"
            f"<td data-label=Matches><span class=mono>{e(uirules.describe(r))}</span></td>"
            f"<td data-label=Covers>{credlinks.links(sorted(r['secrets']), tab='policies')}{mark}</td>"
            f"<td data-label=Client>{e(uirules._client_label(r['clients'], cnames, set(cnames)))}</td>"
            "<td><small class=muted>edit the configuration</small></td></tr>")
    return (f"<style>{uirules.CSS}</style><h3>Auto-approve rules covering several credentials</h3><p><small "
            "class=muted>Rules in the broker's configuration that name more than one credential. A request "
            "that matches is released without asking, at any risk level. Never shown to agents.</small></p>"
            "<table class=tbl><thead><tr><th>Name</th><th>Mode</th><th>Matches</th><th>Covers</th>"
            "<th>Client</th><th></th></tr></thead><tbody>" + "".join(out) + "</tbody></table>")


def body(name, sc, ctx):
    """The Policies sub-tab body for one credential."""
    st = ctx.states or {}
    c = counts(name, sc, ctx.standing_rows, ctx.config_rules)
    parts = [
        f"<style>{guidance.CSS}</style>",
        f"<h3>Standing approvals ({c['standing']})</h3><p><small class=muted>Requests these cover are approved "
        "without asking. A time-boxed approval has no risk limit and ends at its deadline; an Always approval "
        "never expires and is used only within the auto-approve limit. Revoke to ask every time again.</small></p>"
        + ("" if ctx.grants_enabled else "<p><small class=muted>Time-boxed grants are turned off.</small></p>"),
        standing_card(name, ctx.standing_rows, ctx.csrf, ctx.client_names)]
    if sc.get("ssh") and ctx.config_rules:
        parts.append(f"<style>{uirules.CSS}</style><h3>Auto-approve rules ({len(ctx.config_rules)})</h3><p><small "
                     "class=muted>Rules in the broker's configuration that name this key. A request that matches "
                     "is released without asking, at any risk level. Edit them in the configuration. Never shown "
                     "to agents.</small></p>" + uirules.config_table(ctx.config_rules, ctx.client_names,
                                                                      {cid for cid, _ in ctx.client_choices}))
    if not sc.get("ssh"):
        parts.append(f"<style>{uirules.CSS}</style><h3>Auto-approve rules ({c['rules']})</h3><p><small class=muted>"
                     "A request that matches is released without asking, at any risk level. Each rule belongs to "
                     "this credential and names exactly what it covers. Never shown to agents.</small></p>")
        parts.append(uirules.card(name, sc, ctx.config_rules, ctx.csrf, ctx.usage_auto, None, st.get("auto_rules"),
                                  ctx.client_names, ctx.client_choices, open_=True))
    parts.append("<h3>Risk guidance</h3><p><small class=muted>" + html.escape(guidance.NOTE) +
                 " Guidance is never shown to agents.</small></p>")
    gs_state = st.get("guidance")
    parts.append(guidance.card(name, sc, ctx.csrf, open_=True, suggest=(
        None if gs_state is None else {**gs_state, "unavailable": guidancesuggest.MESSAGES["unavailable"]})))
    if sc.get("ssh"):
        parts.append(f"<style>{uirules.CSS}</style><h3>Remote command rules ({len(sc.get('auto_rules') or [])})</h3>"
                     "<p><small class=muted>Plain remote commands this key may run through <code>asb exec</code> "
                     "without asking. Each rule names one server, one account and the first words of the command. "
                     "Scripts and commands with shell syntax always go through the normal approval. Never shown "
                     "to agents.</small></p>")
        parts.append(uirules.card(name, sc, [], ctx.csrf, ctx.usage_auto, None, st.get("auto_rules"),
                                  ctx.client_names, ctx.client_choices, open_=True))
        parts.append(f"<style>{sshhosts.CSS}{sshrules.CSS}</style><h3>SSH host policy</h3><p><small class=muted>"
                     "Restrict an SSH key to the servers it may log in to. This is never shown to agents."
                     "</small></p>")
        parts.append(sshhosts.card(name, sc, ctx.csrf, st.get("ssh_hosts"), open_=True))
        parts.append("<h3>SSH host rules</h3><p><small class=muted>Standing approvals: a key may sign logins to "
                     "one verified server as one account without asking, whatever the auto-approve limit. "
                     "Everything else still asks. Never shown to agents.</small></p>")
        parts.append(sshrules.card(name, sc, ctx.csrf, ctx.usage_ssh, None, st.get("ssh_rules"), ctx.client_names,
                                   ctx.client_choices, open_=True))
    return "".join(parts)
