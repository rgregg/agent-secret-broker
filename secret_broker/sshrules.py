"""Standing per-host SSH rules: "always allow this key to log in to this server
as this account".

A rule is exactly: the SSH key that owns it (the rule lives in that key's vault
metadata, field `ssh_rules`) + the server's verified host key fingerprint + the
account name signed inside the login data. A signing request that matches an
active rule is signed without a prompt, at any `risk.auto_approve_max` and past
the HIGH floor SSH requests carry: it is explicit human policy for exactly that
server, like a time-boxed grant, and is audited as such (decision source
`rule`). Everything else prompts as before.

Matching uses only facts the broker verified (see Broker._ssh_host): the last
session-bind of a valid chain, or the host key inside host-bound login data. A
request with no verified server, an invalid or mismatched bind, forwarding,
more than one hop, SSHSIG (commit signing) or non-login data never matches.
Names from known_hosts are labels for the approver; they are never matched on.
Server-side refusals (`ssh_hosts`) run in Broker.create() before a request
exists, so a rule can never release anything they refuse.

This module holds the rule schema/validator, the matching helpers, the small
last-used state file, the Policies-page section, the approval-card chip and the
Broker mixin (rule creation, revoke, expiry, claim). Audit note for anything that
exposes audit events to the agent: every `ssh_rule_*` event and the `rule_id`
field are policy context (hidden in audit_api); a rule-approved request shows
as a plain "approved". The agent must never learn which servers have rules.
"""
import calendar
import html
import json
import os
import re
import secrets
import threading
import time

from . import clients as clients_mod
from . import sshkey
from .backends import BackendError

MAX_RULES = 100
MAX_LABEL = 100
EXPIRY_CHOICES = ("never", "30", "90")          # days; the card and the Policies form offer these
RULE_KEYS = ("id", "fp", "user", "host", "by", "at", "expires_at", "client")
_FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?")
_ID = re.compile(r"[A-Za-z0-9_-]{4,16}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
FORM_FIELDS = ("secret", "host", "fp", "account", "expires", "confirm", "csrf", "rule")
REFUSAL_CLASSES = ("not_eligible", "cap", "backend", "not_verified", "forwarded")


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def to_epoch(text):
    """Strict ISO UTC time -> epoch seconds; ValueError otherwise."""
    if not isinstance(text, str) or not _TIME.fullmatch(text):
        raise ValueError("not a UTC time like 2026-10-19T12:00:00Z")
    return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))


def valid_fp(text):
    """Canonical SHA256:... fingerprint (no '=' padding) or ValueError."""
    if not isinstance(text, str) or not _FP.fullmatch(text.strip()):
        raise ValueError("not a SHA256: fingerprint (SHA256: followed by 43 base64 characters)")
    return text.strip().rstrip("=")


def valid_account(text):
    if not isinstance(text, str) or not sshkey.ACCOUNT_RE.fullmatch(text):
        raise ValueError("account must be 1-64 printable ASCII characters with no spaces")
    return text


def clean_label(text):
    """A display label from known_hosts names: printable text only, short, or None."""
    text = _CTRL.sub(" ", str(text or "")).strip()
    return text[:MAX_LABEL] or None


def short_fp(fp):
    return fp[:19] if isinstance(fp, str) else ""


def parse(raw, field="ssh_rules"):
    """Validate a key's `ssh_rules` metadata -> normalized list (every rule has all
    seven keys; `host` and `expires_at` may be None). Raises ValueError naming the
    offending field."""
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list")
    if len(raw) > MAX_RULES:
        raise ValueError(f"{field} has more than {MAX_RULES} rules")
    out, ids = [], set()
    for i, r in enumerate(raw):
        at = f"{field}[{i}]"
        if not isinstance(r, dict):
            raise ValueError(f"{at} must be an object")
        extra = sorted(set(r) - set(RULE_KEYS))
        if extra:
            raise ValueError(f"{at}.{extra[0]} is not a known field ({', '.join(RULE_KEYS)})")
        for k in ("id", "fp", "user", "by", "at"):
            if k not in r:
                raise ValueError(f"{at}.{k} is required")
        rid = r["id"]
        if not isinstance(rid, str) or not _ID.fullmatch(rid):
            raise ValueError(f"{at}.id must be 4-16 letters, digits, - or _")
        if rid in ids:
            raise ValueError(f"{at}.id {rid!r} is used twice")
        ids.add(rid)
        try:
            fp = valid_fp(r["fp"])
        except ValueError as e:
            raise ValueError(f"{at}.fp: {e}") from None
        try:
            user = valid_account(r["user"])
        except ValueError as e:
            raise ValueError(f"{at}.user: {e}") from None
        host = r.get("host")
        if host is not None and (not isinstance(host, str) or len(host) > MAX_LABEL):
            raise ValueError(f"{at}.host must be text of up to {MAX_LABEL} characters or null")
        by = r["by"]
        if not isinstance(by, str) or not 0 < len(by) <= 120:
            raise ValueError(f"{at}.by must be text of 1-120 characters")
        times = {}
        for k in ("at", "expires_at"):
            v = r.get(k)
            if v is None and k == "expires_at":
                times[k] = None
                continue
            try:
                to_epoch(v)
            except ValueError as e:
                raise ValueError(f"{at}.{k}: {e}") from None
            times[k] = v
        client = clients_mod.parse_scope(r.get("client"), f"{at}.client")
        rule = {"id": rid, "fp": fp, "user": user, "host": host or None, "by": by, **times}
        if client != clients_mod.ANY:       # a global rule has exactly the shape it always had
            rule["client"] = client
        out.append(rule)
    return out


def serialize(rules):
    """The vault form of parsed rules: a global rule (`client` is `*`) is written exactly as
    before the field existed; only a client-scoped rule carries `client`."""
    out = []
    for r in rules:
        d = {k: v for k, v in r.items() if k != "client"}
        if r.get("client", clients_mod.ANY) != clients_mod.ANY:
            d["client"] = r["client"]
        out.append(d)
    return out


def is_expired(rule, now):
    return bool(rule.get("expires_at")) and to_epoch(rule["expires_at"]) <= now


def find(rules, fp, user, now, client=None):
    """The active rule for exactly this host key and account that applies to `client`, or
    (None, expired_hit). A rule scoped to that client wins over one for any client; a rule
    scoped to another client never applies; with no client only a rule for any client does.
    Account compare is exact (case-sensitive)."""
    expired = False
    best = None
    for r in rules or ():
        if r["fp"] == fp and r["user"] == user:
            scope = r.get("client", clients_mod.ANY)
            if scope != clients_mod.ANY and scope != client:
                continue
            if is_expired(r, now):
                expired = True
                continue
            if best is None or (scope != clients_mod.ANY and best.get("client", clients_mod.ANY) == clients_mod.ANY):
                best = r
    return best, expired


def new_rule(fp, user, label, by, days, now, taken_ids=(), client=clients_mod.ANY):
    rid = secrets.token_hex(4)
    while rid in taken_ids:
        rid = secrets.token_hex(4)
    rule = {"id": rid, "fp": valid_fp(fp), "user": valid_account(user), "host": clean_label(label),
            "by": str(by)[:120] or "unknown", "at": iso(now),
            "expires_at": iso(now + days * 86400) if days else None}
    if client != clients_mod.ANY:
        rule["client"] = client
    return rule


def expiry_days(choice):
    """'never' | '30' | '90' -> days (None for never); ValueError otherwise."""
    if choice in (None, "", "never"):
        return None
    if choice in EXPIRY_CHOICES:
        return int(choice)
    raise ValueError("expiry must be never, 30 or 90 days")


def identity(spec):
    """(fp, account, None) for a request that a rule can match or be created from,
    else (None, None, reason_class). Verified, direct, unforwarded logins only."""
    if (spec.get("ssh") or {}).get("kind") != "userauth" or not isinstance(spec.get("data"), bytes):
        return None, None, "not_eligible"
    account = sshkey.account(spec["data"])
    host = spec.get("host") or {}
    if not host.get("fp") or host.get("bind_invalid") or host.get("chain_mismatch"):
        return None, None, "not_verified"
    if host.get("forwarding"):
        return None, None, "forwarded"
    if len(host.get("hops") or []) > 1 or account is None:
        return None, None, "not_eligible"
    return host["fp"], account, None


def server_name(host):
    names = (host or {}).get("names") or []
    return names[0] if names else short_fp((host or {}).get("fp"))


def parse_decision(decision, form):
    """('approve_ssh_rule', form) -> {"days": int|None}; None for any other decision;
    False for a malformed expiry."""
    if decision != "approve_ssh_rule":
        return None
    try:
        return {"days": expiry_days((form.get("ssh_rule_expiry") or ["never"])[0])}
    except ValueError:
        return False


# ---------------------------------------------------------------- last-used state
class Usage:
    """Last-used time and use counts per rule, in a small file next to the audit
    log (never in the vault: its writes are rate limited). Atomic, 0600. A corrupt
    or unreadable file just loses the numbers."""

    def __init__(self, path, on_event=None):
        self._path, self._log = path, on_event or (lambda *a, **k: None)
        self._lock = threading.Lock()
        self._d = {}
        self._load()

    def _load(self):
        if not self._path or not os.path.exists(self._path):
            return
        try:
            with open(self._path) as f:
                raw = json.load(f)["rules"]
            d = {}
            for key, v in raw.items():
                d[str(key)[:200]] = {"last_used": float(v["last_used"]), "uses": int(v["uses"])}
            self._d = d
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            self._d = {}
            self._log("ssh_rules_state_corrupt", warning="last-used data ignored", error=str(e)[:120])

    @staticmethod
    def _key(secret, rid):
        return f"{secret}\x1f{rid}"

    def _save_locked(self):
        if not self._path:
            return
        tmp = f"{self._path}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"version": 1, "rules": self._d}, f)
            os.replace(tmp, self._path)
        except OSError as e:
            self._log("ssh_rules_state_write_failed", warning="last-used kept in memory only",
                      error=str(e)[:120])

    def record(self, secret, rid, now):
        with self._lock:
            v = self._d.setdefault(self._key(secret, rid), {"last_used": 0.0, "uses": 0})
            v["last_used"], v["uses"] = now, v["uses"] + 1
            self._save_locked()

    def get(self, secret, rid):
        with self._lock:
            v = self._d.get(self._key(secret, rid))
            return dict(v) if v else {"last_used": None, "uses": 0}

    def forget(self, secret, rid):
        with self._lock:
            if self._d.pop(self._key(secret, rid), None) is not None:
                self._save_locked()


# ---------------------------------------------------------------- Broker mixin
class SshRulesMixin:
    """Methods mixed into Broker. Needs: cfg, _cfg_lock, _lock, backend, log, audit,
    _release, _finish, _audit._path."""

    def _init_ssh_rules(self):
        apath = self._audit._path
        spath = os.path.join(os.path.dirname(os.path.abspath(apath)), "ssh_rules_state.json") if apath else None
        self.ssh_rule_usage = Usage(spath, self.log)
        self._rule_expire_failed = set()
        threading.Thread(target=self._ssh_rule_sweeper, daemon=True).start()

    def _ssh_rule_sweeper(self):
        while True:
            time.sleep(60)
            try:
                self.expire_ssh_rules()
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    def ssh_rules_of(self, name):
        sc = self.cfg["secrets"].get(name) or {}
        return [dict(r) for r in sc.get("ssh_rules") or []]

    def _persist_ssh_rules(self, name, rules, user):
        """Write the rule list into the key's broker metadata in the vault (the same
        path as _persist_ssh_hosts); an empty list removes the field."""
        sc = self.cfg["secrets"][name]
        meta = {**sc["_meta"], "ssh_rules_changed": {"by": user, "at": iso(time.time())}}
        if rules:
            meta["ssh_rules"] = serialize(rules)
        else:
            meta.pop("ssh_rules", None)
        self.backend.set_meta(sc["_item"], meta)
        sc["_meta"] = meta
        if rules:
            sc["ssh_rules"] = [dict(r) for r in rules]
        else:
            sc.pop("ssh_rules", None)

    def _host_allowed_now(self, sc, fp):
        """True when the key's allowed_hosts policy (if any) accepts this server."""
        policy = sc.get("ssh_hosts") or {}
        allowed = policy.get("allowed")
        if not allowed:
            return True
        names = (policy.get("known") or {}).get(fp, [])
        return fp in allowed or any(n in allowed for n in names)

    def ssh_rule_eligibility(self, req):
        """(ok, reason_class) for creating a rule from this pending request. Computed
        from the stored, verified request only."""
        if req.mode != "ssh_sign" or len(req.names) != 1:
            return False, "not_eligible"
        sc = self.cfg["secrets"].get(req.names[0])
        if not sc or not sc.get("ssh"):
            return False, "not_eligible"
        fp, _account, why = identity(req.spec)
        if why:
            return False, why
        if "set_meta" not in self.backend.capabilities:
            return False, "backend"
        if not self._host_allowed_now(sc, fp):
            return False, "not_eligible"
        if len(sc.get("ssh_rules") or []) >= MAX_RULES and find(
                sc["ssh_rules"], fp, _account, time.time(), req.client["id"])[0] is None:
            return False, "cap"
        return True, ""

    def ssh_rule_chip(self, req):
        """(account, server label, fp) for the card chip, or None when not offered."""
        ok, _ = self.ssh_rule_eligibility(req)
        if not ok:
            return None
        fp, account, _ = identity(req.spec)
        return account, server_name(req.spec.get("host")), fp

    def _add_rule(self, name, fp, account, label, by, days, client=clients_mod.ANY):
        """Create (or find) a rule for one client (or `*` = any). Returns (status, rule):
        created | exists | cap | backend | failed. A rule that already covers this client
        (its own, or one for any client) counts as existing."""
        with self._cfg_lock:
            sc = self.cfg["secrets"][name]
            rules = [dict(r) for r in sc.get("ssh_rules") or []]
            now = time.time()
            have, _ = find(rules, fp, account, now, client)
            if have is not None:
                return "exists", have
            rules = [r for r in rules if not (r["fp"] == fp and r["user"] == account
                                              and r.get("client", clients_mod.ANY) == client)]
            if len(rules) >= MAX_RULES:
                return "cap", None
            if "set_meta" not in self.backend.capabilities:
                return "backend", None
            rule = new_rule(fp, account, label, by, days, now, {r["id"] for r in rules}, client)
            try:
                self._persist_ssh_rules(name, rules + [rule], by)
            except (OSError, ValueError, KeyError, BackendError):
                return "failed", None
        return "created", rule

    def _ssh_rule_create(self, req, days, actor, channel, who, scope=clients_mod.ANY):
        """Create the rule a human asked for on this request's card. Never raises;
        returns a short status for the approval page."""
        name = req.names[0]
        ok, cls = self.ssh_rule_eligibility(req)
        if not ok:
            self.audit("ssh_rule_refused", req, credential=name, reason=cls, **who)
            return "refused"
        fp, account, _ = identity(req.spec)
        status, rule = self._add_rule(name, fp, account, ", ".join(req.spec["host"].get("names") or []),
                                      actor, days, scope)
        if status == "created":
            self.audit("ssh_rule_created", req, credential=name, account=account, rule_id=rule["id"],
                       rule_host=rule["host"], expires_at=rule["expires_at"], created_by=actor,
                       rule_client=scope,
                       **{k: v for k, v in who.items() if k in ("channel", "approver_peer", "approver_ip")})
        elif status == "exists":
            return "exists"
        elif status == "failed":
            self.audit("ssh_rule_change_failed", req, credential=name, op="create", account=account,
                       error="could not write the vault metadata", **who)
        else:
            self.audit("ssh_rule_refused", req, credential=name, reason=status, **who)
        return status

    def add_ssh_rule(self, name, fp, account, expiry, confirm, user, peer=None, client_ip=None,
                     client=clients_mod.ANY):
        """Policies-page 'Add rule' for one client (or `*` = any client). Returns {"status":
        created|exists|refused|failed, "message"}; raises ValueError for an unknown or non-ssh
        secret."""
        sc = self.cfg["secrets"].get(name)
        if not sc or not sc.get("ssh"):
            raise ValueError("bad ssh rule change")
        who = dict(credential=name, user=user, peer=peer, client_ip=client_ip, channel="policies")

        def refused(cls, msg):
            self.log("ssh_rule_refused", reason=cls, **who)
            return {"status": "refused", "message": msg}
        try:
            fp, account, days = valid_fp(fp), valid_account(account), expiry_days(expiry)
        except ValueError as e:
            return refused("invalid", str(e))
        if client != clients_mod.ANY and not (clients_mod.SCOPE_RE.fullmatch(str(client))
                                              and self.clients.is_active(client)):
            return refused("invalid", "Pick an enrolled client, or any client.")
        if not confirm:
            return refused("not_confirmed", "Tick the box to confirm that this key may then sign for "
                                            "this server and account without asking.")
        known = (sc.get("ssh_hosts") or {}).get("known") or {}
        status, rule = self._add_rule(name, fp, account, ", ".join(known.get(fp, [])), user, days, client)
        if status == "exists":
            return {"status": "exists", "message": "That rule already exists."}
        if status == "created":
            self.log("ssh_rule_created", host_fp=fp, account=account, rule_id=rule["id"], rule_client=client,
                     rule_host=rule["host"], expires_at=rule["expires_at"], created_by=user,
                     **{k: v for k, v in who.items() if k != "user"}, approver_peer=peer, approver_ip=client_ip)
            return {"status": "created", "message": ""}
        if status == "failed":
            self.log("ssh_rule_change_failed", host_fp=fp, account=account, op="create",
                     error="could not write the vault metadata", **who)
            return {"status": "failed", "message": "Could not save the rule"}
        return refused(status, "This key already has the maximum number of rules." if status == "cap"
                       else "The vault backend cannot record rules.")

    def revoke_ssh_rule(self, name, rule_id, user, peer=None, client_ip=None):
        """Remove a rule. Returns "revoked", "missing" or "failed"."""
        if name not in self.cfg["secrets"] or not self.cfg["secrets"][name].get("ssh"):
            return "missing"
        with self._cfg_lock:
            sc = self.cfg["secrets"][name]
            rules = [dict(r) for r in sc.get("ssh_rules") or []]
            gone = next((r for r in rules if r["id"] == rule_id), None)
            if gone is None:
                return "missing"
            try:
                self._persist_ssh_rules(name, [r for r in rules if r["id"] != rule_id], user)
            except (OSError, ValueError, KeyError, BackendError) as e:
                self.log("ssh_rule_change_failed", credential=name, op="revoke", host_fp=gone["fp"],
                         account=gone["user"], rule_id=rule_id, user=user, peer=peer, client_ip=client_ip,
                         error=str(e)[:200])
                return "failed"
        self.ssh_rule_usage.forget(name, rule_id)
        self.log("ssh_rule_revoked", credential=name, host_fp=gone["fp"], account=gone["user"],
                 rule_id=rule_id, created_by=gone["by"], revoked_by=user, user=user, peer=peer,
                 client_ip=client_ip, channel="policies")
        return "revoked"

    def expire_ssh_rules(self, only=None):
        """Drop expired rules (all keys, or just `only`), auditing each once."""
        now = time.time()
        for name in ([only] if only else sorted(self.cfg["secrets"])):
            sc = self.cfg["secrets"].get(name)
            if not sc or not any(is_expired(r, now) for r in sc.get("ssh_rules") or []):
                continue
            with self._cfg_lock:
                sc = self.cfg["secrets"].get(name) or {}
                rules = [dict(r) for r in sc.get("ssh_rules") or []]
                gone = [r for r in rules if is_expired(r, now)]
                if not gone:
                    continue
                try:
                    self._persist_ssh_rules(name, [r for r in rules if r not in gone], "system:expiry")
                except (OSError, ValueError, KeyError, BackendError) as e:
                    for r in gone:
                        if (name, r["id"]) not in self._rule_expire_failed:
                            self._rule_expire_failed.add((name, r["id"]))
                            self.log("ssh_rule_change_failed", credential=name, op="expire",
                                     host_fp=r["fp"], account=r["user"], rule_id=r["id"],
                                     error=str(e)[:200])
                    continue
            for r in gone:
                self.ssh_rule_usage.forget(name, r["id"])
                self.log("ssh_rule_expired", credential=name, host_fp=r["fp"], account=r["user"],
                         rule_id=r["id"], expires_at=r["expires_at"], created_by=r["by"])

    def _ssh_rule_claim(self, req):
        """Approve `req` from a matching standing rule. Called from create() after the
        assessment and before any auto-approval, grant or prompt (the server-identity
        refusals already ran). Returns True when the request was finished here."""
        if req.mode != "ssh_sign" or len(req.names) != 1:
            return False
        sc = self.cfg["secrets"].get(req.names[0])
        if not sc or not sc.get("ssh") or not sc.get("ssh_rules"):
            return False
        fp, account, why = identity(req.spec)
        if why:
            return False
        now = time.time()
        if self.client_never_auto(req.client["id"]):
            return False            # a client set to never auto-approve always prompts
        rule, saw_expired = find(sc["ssh_rules"], fp, account, now, req.client["id"])
        if saw_expired:
            threading.Thread(target=self.expire_ssh_rules, args=(req.names[0],), daemon=True).start()
        if rule is None:
            return False
        with self._lock:                # a human decision and a rule never both act
            if req.status != "pending":
                return False
            req.status = "deciding"
        name = req.names[0]
        self.audit("ssh_rule_used", req, credential=name, account=account, rule_id=rule["id"],
                   rule_host=rule["host"])
        self.ssh_rule_usage.record(name, rule["id"], now)
        extra = dict(rule_id=rule["id"], decision_source="rule")
        try:
            result = self._release(req)
        except (BackendError, OSError, ValueError) as e:
            self._finish(req, "failed", error=f"release failed: {e}", via="policy", **extra)
        else:
            self._finish(req, "approved", result=result, via="policy", **extra)
        return True


# ---------------------------------------------------------------- approval card chip
def chip_html(account, server, fp):
    """The 'Always: this host' chip with its inline confirm step, for the
    'Automatically approve...' row of the card (dashboard and /a/<nonce> page)."""
    e = html.escape
    shown = f"{account}@{server}"
    tip = (f"Approve this request and always approve this key for {shown} "
           f"({fp}) without asking. Revoke any time under Policies.")
    return (f"<details class='alw sshrule'><summary class='chip always' data-tip='{e(tip, quote=True)}' "
            f"aria-label='Always approve {e(shown, quote=True)} with this key: {e(tip, quote=True)}'>"
            "Always: this host</summary>"
            f"<div class=confirm><span>Always approve {e(shown)} with this key?</span>"
            "<label>Expires <select name=ssh_rule_expiry aria-label='Rule expiry'>"
            "<option value=never selected>Never expires (default)</option>"
            "<option value=30>30 days</option><option value=90>90 days</option></select></label>"
            "<button class='btn sm approve' name=decision value=approve_ssh_rule>Confirm</button>"
            "<span class=muted>Click Always: this host again to cancel.</span></div></details>")


# ---------------------------------------------------------------- Policies page
CSS = """
.srules .fp{font-family:ui-monospace,monospace;font-size:.78rem;word-break:break-all}
.srules .warnline{color:var(--wfg);font-size:.85rem}
.srules form.add{margin-top:.8rem;display:grid;gap:.5rem;max-width:34rem}
.srules .err{border:1px solid var(--bad);background:var(--badbg);color:var(--bad);border-radius:.5rem;padding:.5rem .7rem;margin:.5rem 0}
"""


def _when(t):
    try:
        return iso(t) if isinstance(t, (int, float)) else ""
    except (OverflowError, ValueError, OSError):
        return ""


def policies_section(secrets_cfg, csrf, usage, now=None, state=None, client_names=None, client_choices=()):
    """'SSH host rules' for the Policies tab: per SSH key a table of its rules with
    Revoke and an 'Add rule' form. `state` maps a secret name to {"error", "open"}."""
    e = html.escape
    now = time.time() if now is None else now
    state = state or {}
    client_names = client_names or {}
    keys = [(n, sc) for n, sc in sorted(secrets_cfg.items()) if sc.get("ssh")]
    head = ("<h3>SSH host rules</h3><p><small class=muted>Standing approvals: a key may sign "
            "logins to one verified server as one account without asking, whatever the auto-approve "
            "limit. Everything else still asks. Never shown to agents.</small></p>")
    if not keys:
        return ""
    cards = []
    for i, (name, sc) in enumerate(keys):
        rules = sc.get("ssh_rules") or []
        policy = sc.get("ssh_hosts") or {}
        known = policy.get("known") or {}
        allowed = policy.get("allowed")
        st = state.get(name) or {}
        rows = []
        for r in rules:
            u = usage.get(name, r["id"])
            warn = ""
            if allowed and not (r["fp"] in allowed or any(n in allowed for n in known.get(r["fp"], []))):
                warn = ("<br><span class=warnline>Not on the allowed hosts list: blocked by the "
                        "allowed hosts list, so this rule has no effect.</span>")
            expired = is_expired(r, now)
            exp = (e(r["expires_at"]) + (" <b>(expired)</b>" if expired else "")) if r["expires_at"] else "never"
            rows.append(
                f"<tr><td data-label=Host>{e(r['host'] or '(no name)')}{warn}</td>"
                f"<td data-label=Fingerprint><span class=fp title='{e(r['fp'], quote=True)}'>{e(short_fp(r['fp']))}...</span></td>"
                f"<td data-label=Account><code>{e(r['user'])}</code></td>"
                f"<td data-label=Client>{e(clients_mod.scope_label(r.get('client', clients_mod.ANY), client_names))}</td>"
                f"<td data-label=Created>{e(r['by'])}<br><small class=muted>{e(r['at'])}</small></td>"
                f"<td data-label=Expires>{exp}</td>"
                f"<td data-label='Last used'>{e(_when(u['last_used']) or 'never')}"
                f"<br><small class=muted>{int(u['uses'])} uses</small></td>"
                "<td><form method=post action='/policies/ssh_rules/revoke' class=inline>"
                f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
                f"<input type=hidden name=secret value='{e(name, quote=True)}'>"
                f"<input type=hidden name=rule value='{e(r['id'], quote=True)}'>"
                "<button>Revoke</button></form></td></tr>")
        table = ("<table class=tbl><thead><tr><th>Host</th><th>Fingerprint</th><th>Account</th><th>Client</th>"
                 "<th>Created</th><th>Expires</th><th>Last used</th><th></th></tr></thead><tbody>"
                 + "".join(rows) + "</tbody></table>") if rows else "<div class='card empty'>No standing SSH rules</div>"
        opts = "<option value=''>Enter a fingerprint below</option>" + "".join(
            f"<option value='{e(fp, quote=True)}'>{e(', '.join(ns) or '(no name)')} - {e(short_fp(fp))}...</option>"
            for fp, ns in sorted(known.items(), key=lambda kv: kv[1]))
        err = f"<div class=err role=alert>{e(st['error'])}</div>" if st.get("error") else ""
        cards.append(
            f"<details class='card gbox srules'{' open' if st.get('open') else ''}><summary><b>{e(name)}</b> "
            f"<small class=muted>{len(rules)} of {MAX_RULES} rules</small></summary>{err}{table}"
            "<form method=post action='/policies/ssh_rules/add' class=add>"
            f"<input type=hidden name=csrf value='{e(csrf, quote=True)}'>"
            f"<input type=hidden name=secret value='{e(name, quote=True)}'>"
            f"<b>Add rule</b><label for='srh{i}'>Server from this key's known hosts</label>"
            f"<select id='srh{i}' name=host>{opts}</select>"
            f"<label for='srf{i}'>or a SHA256: fingerprint</label>"
            f"<input id='srf{i}' name=fp placeholder='SHA256:...' autocomplete=off>"
            f"<label for='sra{i}'>Account</label><input id='sra{i}' name=account maxlength=64 autocomplete=off>"
            f"<label for='src{i}'>Applies to</label><select id='src{i}' name=client>"
            "<option value='*' selected>Any client (every machine)</option>"
            + "".join(f"<option value='{e(cid, quote=True)}'>Only {e(cn)}</option>" for cid, cn in client_choices)
            + "</select>"
            f"<label for='sre{i}'>Expires</label><select id='sre{i}' name=expires>"
            "<option value=never selected>Never expires (default)</option><option value=30>30 days</option>"
            "<option value=90>90 days</option></select>"
            "<label class=chk><input type=checkbox name=confirm value=1> <span>I understand this key will "
            "sign for that server and account without asking</span></label>"
            "<div class=grow><button>Add rule</button></div></form></details>")
    return f"<style>{CSS}</style>" + head + "".join(cards)
