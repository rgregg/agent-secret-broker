"""Auto-approve rules kept in a credential's vault metadata and managed from the credential's Policies page.

A rule here is the same thing as an `auto_approve` rule in the broker config (autorules.py: one validator, one
matcher), with three differences: it belongs to the one credential it is stored on, it is created and revoked by
the human on the credential's Policies page (a confirmation tick, an optional expiry) instead of by editing the configuration,
and it lives in the credential's `broker` metadata (vault field `auto_rules`), so it survives restarts and
redeploys and takes effect at once. Whoever can use the approval site or edit the vault collection can add one: the
same trust level as `approval` and the SSH host rules. An agent can neither create nor see them.

Nothing typed into the form is ever echoed into a message, an event or a log line: refusals are one of a closed set
of reasons and the page names at most a field, taken from this module's own list.
"""
import html
import math
import re
import secrets
import threading
import time

from . import autorules
from . import clients as clients_mod
from . import destguard
from . import sessionrules
from . import sessions as S
from . import sshrules
from .backends import BackendError
from .backends import base as backend_base

REASONS = ("invalid", "not_confirmed", "cap", "backend", "duplicate_name")
FIELDS = ("name", "mode", "host", "scheme", "methods", "path_prefix", "argv", "clients", "expires_at",
          "hosts", "port", "allow_query", "max_ttl_s", "max_calls", "max_frames")
_CATCH = (OSError, ValueError, KeyError, BackendError)
_FIELD_IN_ERROR = re.compile(r"auto_rules\[0\]\.([a-z_]+)")
MESSAGES = {
    "not_confirmed": "Tick the box to confirm that matching requests may then be released without asking.",
    "cap": f"This credential already has the maximum number of rules ({autorules.MAX_STORED}).",
    "backend": "The vault backend cannot record rules.",
    "duplicate_name": "This credential already has a rule with that name.",
    "invalid": "The rule is not valid.",
}


def _invalid(field=None):
    """The one 'invalid' message: it may name a field from FIELDS, never a value."""
    if field in FIELDS:
        return f"Not a valid value for {field}."
    return MESSAGES["invalid"]


def _secs(minutes):
    """Minutes typed in the form -> whole seconds; anything else is passed on as it is, and the shared parser
    refuses it (a blank or unreadable cap is never turned into a default)."""
    try:
        m = float(minutes)
    except (TypeError, ValueError):
        return minutes or None
    return int(round(m * 60)) if math.isfinite(m) and 0 < m <= 24 * 60 else minutes


def _count(v):
    return int(v) if isinstance(v, str) and v.isascii() and v.isdigit() and len(v) <= 6 else (v or None)


def fields_from_form(form):
    """The `fields` dict `add_auto_rule` takes, from a parsed POST body (`form`: name -> list of str). The one
    place that knows the form's input names; the stored-rule names are used inside."""
    one = lambda k: form.get(k, [""])[0]  # noqa: E731
    f = dict(name=one("name"), mode=one("mode"), host=one("host"), scheme=one("scheme"),
             methods=form.get("methods", []), path_prefix=one("path_prefix"),
             argv=[w.strip() for w in one("argv").splitlines() if w.strip()],
             client=one("client") or clients_mod.ANY)
    if f["mode"] == "http_session":
        f.update(hosts=one("shosts").split(), methods=form.get("smethods", []),
                 max_ttl_s=_secs(one("ttl_min")), max_calls=_count(one("max_calls")))
    elif f["mode"] == "ws_session":
        f.update(host=one("whost").strip(), scheme=one("wscheme"), path_prefix=one("wpath"),
                 port=_count(one("wport")) if one("wport").strip() else None, allow_query=one("wquery") == "1",
                 max_ttl_s=_secs(one("ttl_min")), max_frames=_count(one("max_frames")))
    return f


def _raw_rule(fields, rid, by, now, days, client):
    """The stored form of a new rule from the form's fields (unvalidated: parse_stored does that)."""
    mode = fields.get("mode")
    raw = {"id": rid, "name": fields.get("name"), "mode": mode}
    if mode in sessionrules.MODES:
        raw.update({k: fields[k] for k in sessionrules.KEYS[mode] if fields.get(k) is not None})
    elif mode == "http":
        raw.update(host=fields.get("host"), scheme=fields.get("scheme") or "https",
                   methods=list(fields.get("methods") or []), path_prefix=fields.get("path_prefix") or "/")
    elif mode == "env":
        raw["argv"] = list(fields.get("argv") or [])
    if client != clients_mod.ANY:
        raw["clients"] = [client]
    raw.update(by=by, at=sshrules.iso(now), expires_at=sshrules.iso(now + days * 86400) if days else None)
    return raw


class UiRulesMixin:
    """Methods mixed into Broker. Needs: cfg, _cfg_lock, backend, clients, log, auto_rule_usage."""

    def _init_ui_rules(self):
        self._auto_expire_failed = set()
        threading.Thread(target=self._auto_rule_sweeper, daemon=True).start()

    def _auto_rule_sweeper(self):
        while True:
            time.sleep(60)
            try:
                self.expire_auto_rules()
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    def auto_rules_of(self, name):
        return list((self.cfg["secrets"].get(name) or {}).get("auto_rules") or [])

    def prune_auto_rule_usage(self):
        """Forget the use counts of rules that are no longer stored anywhere (a vault restore, a removal)."""
        keep = {(n, r["id"]) for n, sc in self.cfg["secrets"].items() for r in sc.get("auto_rules") or []}
        self.auto_rule_usage.retain(keep)

    def _persist_auto_rules(self, name, rules, user):
        """Write the rule list into the credential's broker metadata in the vault, then into memory; an empty
        list removes the field. Raises on a failed write and leaves memory unchanged."""
        sc = self.cfg["secrets"][name]
        meta = {**sc["_meta"], "auto_rules_changed": {"by": user, "at": sshrules.iso(time.time())}}
        if rules:
            meta["auto_rules"] = autorules.serialize_stored(rules)
        else:
            meta.pop("auto_rules", None)
        self.backend.set_meta(sc["_item"], meta)
        self._cfg_gen += 1              # a catalog refresh that read the vault before this write must not swap in
        sc["_meta"] = meta
        if rules:
            sc["auto_rules"] = list(rules)
        else:
            sc.pop("auto_rules", None)

    def add_auto_rule(self, name, fields, expiry, confirm, user, peer=None, client_ip=None):
        """The credential Policies page's 'Add rule'. `fields`: name, mode (http|env), host, scheme, methods (list),
        path_prefix, argv (list), client ("*" = any enrolled client, or a client id). Returns {"status":
        created|refused|failed, "message", "rule_id"?}; raises ValueError for an unknown or ssh credential."""
        sc = self.cfg["secrets"].get(name)
        if not sc or sc.get("ssh"):
            raise ValueError("bad auto-approve rule change")
        who = dict(credential=name, user=user, peer=peer, client_ip=client_ip, channel="policies")

        def refused(reason, msg):
            self.log("auto_rule_refused", reason=reason, **who)
            return {"status": "refused", "message": msg}
        if not confirm:
            return refused("not_confirmed", MESSAGES["not_confirmed"])
        try:
            days = sshrules.expiry_days(expiry)
        except ValueError:
            return refused("invalid", _invalid("expires_at"))
        client = fields.get("client") or clients_mod.ANY
        if client != clients_mod.ANY and not (clients_mod.ID_RE.fullmatch(str(client))
                                              and self.clients.is_active(client)):
            return refused("invalid", _invalid("clients"))
        now = time.time()
        with self._cfg_lock:
            sc = self.cfg["secrets"][name]
            existing = list(sc.get("auto_rules") or [])
            taken = {r["id"] for r in existing}
            rid = secrets.token_hex(4)
            while rid in taken:
                rid = secrets.token_hex(4)
            try:
                [rule] = autorules.parse_stored(
                    [_raw_rule(fields, rid, str(user)[:120] or "unknown", now, days, client)], name)
            except ValueError as e:
                m = _FIELD_IN_ERROR.match(str(e))
                return refused("invalid", _invalid(m.group(1) if m else None))
            if rule["mode"] in sessionrules.MODES:      # a rule for a host the credential does not allow could never match
                allowed = destguard.host_parts(sc.get("allowed_hosts") or [])
                names = ([h.rsplit(":", 1)[0] for h in rule["hosts"]] if rule["mode"] == "http_session"
                         else [rule["host"]])
                if not all(n in allowed for n in names):
                    return refused("invalid", _invalid("hosts" if rule["mode"] == "http_session" else "host"))
            if any(r["name"].lower() == rule["name"].lower() for r in existing):
                return refused("duplicate_name", MESSAGES["duplicate_name"])
            if len(existing) >= autorules.MAX_STORED:
                return refused("cap", MESSAGES["cap"])
            if "set_meta" not in self.backend.capabilities:
                return refused("backend", MESSAGES["backend"])
            try:
                self._persist_auto_rules(name, existing + [rule], user)
            except _CATCH as e:
                self.log("auto_rule_change_failed", op="create", error_class=backend_base.error_class(e), **who)
                return {"status": "failed", "message": "Could not save the rule."}
        extra = {"rule_host": rule["host"]} if rule["mode"] == "http" else {}
        if rule["mode"] in sessionrules.MODES:
            extra = {"rule_hosts": list(rule["hosts"]) if rule["mode"] == "http_session"
                     else [f"{rule['host']}:{rule['port']}"],
                     "rule_max_ttl_s": rule["max_ttl_s"], "rule_max_calls": rule["max_calls"]}
        self.log("auto_rule_created", credential=name, rule_id=rule["id"], rule_name=rule["name"],
                 rule_mode=rule["mode"], rule_client=client, expires_at=rule["expires_at"], created_by=user,
                 channel="policies", approver_peer=peer, approver_ip=client_ip, **extra)
        return {"status": "created", "message": "", "rule_id": rule["id"]}

    def revoke_auto_rule(self, name, rule_id, user, peer=None, client_ip=None):
        """Remove a rule. Returns "revoked", "missing" or "failed"."""
        sc = self.cfg["secrets"].get(name)
        if not sc or sc.get("ssh"):
            return "missing"
        with self._cfg_lock:
            rules = list(self.cfg["secrets"][name].get("auto_rules") or [])
            gone = next((r for r in rules if r["id"] == rule_id), None)
            if gone is None:
                return "missing"
            try:
                self._persist_auto_rules(name, [r for r in rules if r["id"] != rule_id], user)
            except _CATCH as e:
                self.log("auto_rule_change_failed", op="revoke", credential=name, rule_id=rule_id, user=user,
                         peer=peer, client_ip=client_ip, error_class=backend_base.error_class(e))
                return "failed"
        self.auto_rule_usage.forget(name, rule_id)
        self.log("auto_rule_revoked", credential=name, rule_id=rule_id, rule_name=gone["name"],
                 created_by=gone["by"], revoked_by=user, user=user, peer=peer, client_ip=client_ip,
                 channel="policies")
        return "revoked"

    def expire_auto_rules(self, only=None):
        """Drop expired rules (all credentials, or just `only`), auditing each once. A rule that cannot be
        dropped (the vault write failed) stays stored but never matches, and the failure is audited once."""
        now = time.time()
        for name in ([only] if only else sorted(self.cfg["secrets"])):
            sc = self.cfg["secrets"].get(name)
            if not sc or not any(autorules.is_expired(r, now) for r in sc.get("auto_rules") or []):
                continue
            with self._cfg_lock:
                rules = list((self.cfg["secrets"].get(name) or {}).get("auto_rules") or [])
                gone = [r for r in rules if autorules.is_expired(r, now)]
                if not gone:
                    continue
                try:
                    self._persist_auto_rules(name, [r for r in rules if r not in gone], "system:expiry")
                except _CATCH as e:
                    for r in gone:
                        if (name, r["id"]) not in self._auto_expire_failed:
                            self._auto_expire_failed.add((name, r["id"]))
                            self.log("auto_rule_change_failed", op="expire", credential=name, rule_id=r["id"],
                                     error_class=backend_base.error_class(e))
                    continue
            for r in gone:
                self.auto_rule_usage.forget(name, r["id"])
                self.log("auto_rule_expired", credential=name, rule_id=r["id"], rule_name=r["name"],
                         expires_at=r["expires_at"], created_by=r["by"])


# ---------------------------------------------------------------- Policies page
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
CSS = """
.arules .mono{font-family:ui-monospace,monospace;font-size:.82rem;word-break:break-all}
.arules form.add{margin-top:.8rem;display:grid;gap:.5rem;max-width:34rem}
.arules fieldset{border:1px solid var(--line,#8884);border-radius:.5rem;padding:.5rem .7rem}
.arules .meth label{display:inline-block;margin-right:.8rem}
.arules .err{border:1px solid var(--bad);background:var(--badbg);color:var(--bad);border-radius:.5rem;padding:.5rem .7rem;margin:.5rem 0}
"""


def _client_label(ids, names, active):
    if not ids:
        return "any client"
    out = []
    for cid in sorted(ids):
        nm = names.get(cid)
        out.append(f"{nm} (revoked)" if nm and cid not in active else nm or f"{cid} (removed)")
    return ", ".join(out)


def _matches(rule):
    if rule["mode"] in sessionrules.MODES:
        return sessionrules.describe(rule)
    if rule["mode"] == "ssh_sign":
        return f"sign in as {rule['account']} on {rule['host'] or rule['host_fp']}"
    if rule["mode"] == "env":
        return "run: " + " ".join(rule["argv"])
    return f"{rule['scheme']}://{rule['host']}{rule['path_prefix']} ({', '.join(sorted(rule['methods']))})"


def describe(rule):
    """What a rule matches, as text (the same words as the rule tables)."""
    return _matches(rule)


def _when(t):
    try:
        return sshrules.iso(t) if isinstance(t, (int, float)) else ""
    except (OverflowError, ValueError, OSError):
        return ""


def _config_row(r, names, active):
    """One read-only table row for a config rule."""
    e = html.escape
    return (
        f"<tr><td data-label=Name>{e(r['name'])}</td><td data-label=Mode>{e(r['mode'])}</td>"
        f"<td data-label=Matches><span class=mono>{e(_matches(r))}</span></td>"
        f"<td data-label=Client>{e(_client_label(r['clients'], names, active))}</td>"
        "<td data-label=Source>config"
        + ("<br><small class=muted>covers several credentials</small>" if len(r["secrets"]) > 1 else "")
        + "</td><td data-label=Created>-</td><td data-label=Expires>never</td>"
        "<td data-label='Last used'>-</td><td><small class=muted>edit the configuration</small></td></tr>")


def config_table(rules, client_names, active):
    """A read-only table of config rules (the only auto-approve rules an SSH key's page can show)."""
    names = client_names or {}
    return ("<table class=tbl><thead><tr><th>Name</th><th>Mode</th><th>Matches</th><th>Client</th><th>Source</th>"
            "<th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead><tbody>"
            + "".join(_config_row(r, names, active) for r in rules) + "</tbody></table>")


def card(name, sc, config_rules, csrf, usage, now=None, state=None, client_names=None, client_choices=(),
         idx=0, open_=False):
    """The auto-approve rules table and 'Add rule' form for one credential ("" for an SSH key). `config_rules`
    are the config rules that name this credential; `state` is {"error", "open"} for a re-render; `idx` keeps
    the element ids unique; `open_` renders it expanded."""
    if sc.get("ssh"):
        return ""
    e = html.escape
    now = time.time() if now is None else now
    st = dict(state or {})
    if open_:
        st["open"] = True
    names = client_names or {}
    active = {cid for cid, _ in client_choices}
    choices = [(cid, nm) for cid, nm in client_choices if cid != clients_mod.LEGACY_ID]
    i = idx
    stored = sc.get("auto_rules") or []     # every credential gets a card: an env-only one has no hosts
    cfg_rules = config_rules
    rows = [_config_row(r, names, active) for r in cfg_rules]
    for r in stored:
        u = usage.get(name, r["id"])
        expired = autorules.is_expired(r, now)
        exp = (e(r["expires_at"]) + (" <b>(expired)</b>" if expired else "")) if r["expires_at"] else "never"
        rows.append(
            f"<tr><td data-label=Name>{e(r['name'])}</td><td data-label=Mode>{e(r['mode'])}</td>"
            f"<td data-label=Matches><span class=mono>{e(_matches(r))}</span></td>"
            f"<td data-label=Client>{e(_client_label(r['clients'], names, active))}</td>"
            "<td data-label=Source>UI</td>"
            f"<td data-label=Created>{e(r['by'])}<br><small class=muted>{e(r['at'])}</small></td>"
            f"<td data-label=Expires>{exp}</td>"
            f"<td data-label='Last used'>{e(_when(u['last_used']) or 'never')}"
            f"<br><small class=muted>{int(u['uses'])} uses</small></td>"
            "<td><form method=post action='/policies/auto_rules/revoke' class=inline>"
            f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
            f"<input type=hidden name=secret value='{e(name, quote=True)}'>"
            f"<input type=hidden name=rule value='{e(r['id'], quote=True)}'>"
            "<button>Revoke</button></form></td></tr>")
    table = ("<table class=tbl><thead><tr><th>Name</th><th>Mode</th><th>Matches</th><th>Client</th>"
             "<th>Source</th><th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead><tbody>"
             + "".join(rows) + "</tbody></table>") if rows else "<div class='card empty'>No rules</div>"
    err = f"<div class=err role=alert>{e(st['error'])}</div>" if st.get("error") else ""
    meth = "".join(f"<label><input type=checkbox name=methods value='{m}'"
                   f"{' checked' if m in ('GET', 'HEAD') else ''}> {m}</label>" for m in METHODS)
    smeth = "".join(f"<label><input type=checkbox name=smethods value='{m}'"
                    f"{' checked' if m in ('GET', 'HEAD') else ''}> {m}</label>" for m in METHODS)
    opts = "<option value='*' selected>Any enrolled client</option>" + "".join(
        f"<option value='{e(cid, quote=True)}'>Only {e(cn)}</option>" for cid, cn in choices)
    return (
        f"<details class='card gbox arules'{' open' if st.get('open') else ''}><summary><b>{e(name)}</b> "
        f"<small class=muted>{len(stored)} of {autorules.MAX_STORED} stored</small></summary>{err}{table}"
        "<form method=post action='/policies/auto_rules/add' class=add>"
        f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
        f"<input type=hidden name=secret value='{e(name, quote=True)}'>"
        f"<b>Add rule</b><label for='arn{i}'>Name (shown in the audit log)</label>"
        f"<input id='arn{i}' name=name maxlength={autorules.MAX_NAME} autocomplete=off>"
        f"<label for='arm{i}'>Kind</label><select id='arm{i}' name=mode>"
        "<option value=http selected>Web request (http)</option><option value=env>Run with secret (env)</option>"
        "<option value=http_session>HTTP session</option><option value=ws_session>WebSocket session</option>"
        "</select>"
        f"<fieldset><legend>Web request</legend><label for='arh{i}'>Host (no scheme or port)</label>"
        f"<input id='arh{i}' name=host autocomplete=off placeholder='api.example.com'>"
        f"<label for='ars{i}'>Scheme</label><select id='ars{i}' name=scheme>"
        "<option value=https selected>https</option><option value=http>http</option></select>"
        f"<div class=meth><span>Methods</span> {meth}</div>"
        f"<label for='arp{i}'>Path prefix</label>"
        f"<input id='arp{i}' name=path_prefix autocomplete=off placeholder='/ (everything under the host)'>"
        "</fieldset>"
        f"<fieldset><legend>Run with secret</legend><label for='ara{i}'>Exact command, one word per line</label>"
        f"<textarea id='ara{i}' name=argv rows=3 autocomplete=off></textarea></fieldset>"
        "<fieldset><legend>HTTP session</legend><small class=muted>A session opened by this rule may use only "
        "these hosts and methods, for at most the time and calls below, with no approval and no further prompt. "
        "Write host:443 for https only: a bare host also allows plain http on port 80.</small>"
        f"<label for='arsh{i}'>Hosts, one per line (host or host:port)</label>"
        f"<textarea id='arsh{i}' name=shosts rows=2 autocomplete=off placeholder='api.example.com:443'></textarea>"
        f"<div class=meth><span>Methods</span> {smeth}</div></fieldset>"
        "<fieldset><legend>WebSocket session</legend><small class=muted>Only this server and path, for at most the "
        "time and frames below. Message types the credential blocks stay blocked.</small>"
        f"<label for='arwh{i}'>Host (no scheme or port)</label>"
        f"<input id='arwh{i}' name=whost autocomplete=off placeholder='ha.example.com'>"
        f"<label for='arws{i}'>Scheme</label><select id='arws{i}' name=wscheme>"
        "<option value=wss selected>wss (encrypted)</option><option value=ws>ws (plain, not encrypted)</option></select>"
        f"<label for='arwp{i}'>Port (blank: 443 for wss, 80 for ws)</label>"
        f"<input id='arwp{i}' name=wport inputmode=numeric autocomplete=off>"
        f"<label for='arwx{i}'>Path prefix</label>"
        f"<input id='arwx{i}' name=wpath autocomplete=off placeholder='/api/websocket'>"
        "<label class=chk><input type=checkbox name=wquery value=1> <span>Allow a query string</span></label>"
        f"<label for='arwf{i}'>Most frames the session may send</label>"
        f"<input id='arwf{i}' name=max_frames type=number min=1 max={sessionrules.WS_FRAMES_CEIL} value=500></fieldset>"
        "<fieldset><legend>Session limits (HTTP and WebSocket session)</legend>"
        f"<label for='artl{i}'>Longest session, minutes</label>"
        f"<input id='artl{i}' name=ttl_min type=number min=0.5 max=1440 step=any value=15>"
        f"<label for='arcl{i}'>Most calls (HTTP session)</label>"
        f"<input id='arcl{i}' name=max_calls type=number min=1 max={S.CALLS_CEIL} value=100></fieldset>"
        f"<label for='arc{i}'>Applies to</label><select id='arc{i}' name=client>{opts}</select>"
        f"<label for='are{i}'>Expires</label><select id='are{i}' name=expires>"
        "<option value=never selected>Never expires (default)</option><option value=30>30 days</option>"
        "<option value=90>90 days</option></select>"
        "<label class=chk><input type=checkbox name=confirm value=1> <span>I understand matching requests "
        "will be released with no approval, at any risk level. For a session kind: a matching session opens with no "
        "approval and keeps running, unattended, until its time or call limit</span></label>"
        "<div class=grow><button>Add rule</button></div></form></details>")
