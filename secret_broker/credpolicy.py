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
from . import credlinks, guidance, sshhosts, sshrules, uirules


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


def counts(name, sc, standing_rows, config_rules):
    """The numbers shown on the sub-tab label, the summary strip and the credentials list. Guidance is a flag and
    is not part of `total`."""
    standing = len(standing_rows)
    rules = len(sc.get("auto_rules") or []) + len(config_rules)
    return {"standing": standing, "rules": rules, "guidance": bool(sc.get("guidance")), "total": standing + rules}


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


def body(name, sc, ctx):
    """The Policies sub-tab body for one credential."""
    st = ctx.states or {}
    c = counts(name, sc, ctx.standing_rows, ctx.config_rules)
    parts = [
        f"<style>{guidance.CSS}</style>",
        f"<h3>Standing approvals ({c['standing']})</h3><p><small class=muted>Requests these cover are approved "
        "without asking. A time-boxed approval has no risk limit and ends at its deadline; an Always approval "
        "never expires and is used only within the auto-approve limit. Revoke to ask every time again.</small></p>",
        standing_card(name, ctx.standing_rows, ctx.csrf, ctx.client_names)]
    if not sc.get("ssh"):
        parts.append(f"<style>{uirules.CSS}</style><h3>Auto-approve rules ({c['rules']})</h3><p><small class=muted>"
                     "A request that matches is released without asking, at any risk level. Each rule belongs to "
                     "this credential and names exactly what it covers. Never shown to agents.</small></p>")
        parts.append(uirules.card(name, sc, ctx.config_rules, ctx.csrf, ctx.usage_auto, None, st.get("auto_rules"),
                                  ctx.client_names, ctx.client_choices, open_=True))
    parts.append("<h3>Risk guidance</h3><p><small class=muted>" + html.escape(guidance.NOTE) +
                 " Guidance is never shown to agents.</small></p>")
    parts.append(guidance.card(name, sc, ctx.csrf, open_=True))
    if sc.get("ssh"):
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
