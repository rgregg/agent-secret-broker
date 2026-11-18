"""Auto-approve rules kept in a credential's vault metadata and managed from the Policies tab.

A rule here is the same thing as an `auto_approve` rule in the broker config (autorules.py: one validator, one
matcher), with three differences: it belongs to the one credential it is stored on, it is created and revoked by
the human on the Policies tab (a confirmation tick, an optional expiry) instead of by editing the configuration,
and it lives in the credential's `broker` metadata (vault field `auto_rules`), so it survives restarts and
redeploys and takes effect at once. Whoever can use the Policies tab or edit the vault collection can add one: the
same trust level as `approval` and the SSH host rules. An agent can neither create nor see them.

Nothing typed into the form is ever echoed into a message, an event or a log line: refusals are one of a closed set
of reasons and the page names at most a field, taken from this module's own list.
"""
import re
import secrets
import threading
import time

from . import autorules
from . import clients as clients_mod
from . import sshrules
from .backends import BackendError
from .backends import base as backend_base

REASONS = ("invalid", "not_confirmed", "cap", "backend", "duplicate_name")
FIELDS = ("name", "mode", "host", "scheme", "methods", "path_prefix", "argv", "clients", "expires_at")
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


def _raw_rule(fields, rid, by, now, days, client):
    """The stored form of a new rule from the form's fields (unvalidated: parse_stored does that)."""
    mode = fields.get("mode")
    raw = {"id": rid, "name": fields.get("name"), "mode": mode}
    if mode == "http":
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
        self.prune_auto_rule_usage()
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
        sc["_meta"] = meta
        if rules:
            sc["auto_rules"] = list(rules)
        else:
            sc.pop("auto_rules", None)

    def add_auto_rule(self, name, fields, expiry, confirm, user, peer=None, client_ip=None):
        """The Policies page's 'Add rule'. `fields`: name, mode (http|env), host, scheme, methods (list),
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
