"""Approval broker core and its two HTTP listeners.

Client API  (CLI, `X-Client-Key`):  create a request, long-poll for the result.
Approval UI (behind Authentik):      the page the push notification opens.

The approval nonce exists only in the push URL. It is never returned to the
client, which gets an opaque request id to poll with.

Per-secret policy (`approval` in config):
  prompt  every use needs a phone approval (default)
  allow   released without a prompt, but only for modes in `auto_modes`
          (default ["http"]: the broker makes the call, the value never leaves)
Everything, including auto-approved use and rejected attempts, is audited.
"""
import base64
import binascii
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import AuditLog
from .backends import BackendError
from . import notify as notify_mod
from .notify import NotifyError
from . import risk as risk_mod
from . import structured
from .history import History, OUTCOMES

MAX_PENDING = 3
DENY_COOLDOWN = 60
MAX_RESPONSE_BYTES = 1_000_000
MAX_REQUEST_BYTES = 8_000_000
MAX_STORE_VALUE = 65_536
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,60}$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .-]{0,59}$")
_ITEM_RE = re.compile(r"^[^\x00-\x1f]{1,100}$")
APPROVAL_VALUES = ("prompt", "allow")


class Request:
    def __init__(self, mode, names, spec, source, ttl, peer=None):
        self.id = secrets.token_urlsafe(16)
        self.nonce = secrets.token_urlsafe(24)
        self.mode = mode          # "env" | "http"
        self.names = names
        self.spec = spec
        self.source = source      # client-claimed
        self.peer = peer          # actual socket peer
        self.created = time.time()
        self.expires = self.created + ttl
        self.status = "pending"   # pending|approved|denied|expired|failed|released
        self.error = None
        self.result = None
        self.summary = None       # advisory, unverified
        self.risk = None          # {"level","model","reasons"}
        self.always = None        # outcome of an "always allow" click, if any
        self.approver = None
        self.done = threading.Event()


class Broker:
    def __init__(self, config, backend, notifier, audit=None, summarizer=None,
                 background_load=False, push=None):
        self.push = push                # PushStore when the webpush transport is configured
        self.cfg = config
        self.cfg["secrets"] = {}        # the catalog lives in the vault; see refresh_catalog()
        self._catalog_at = 0.0
        self._catalog_sig = None
        self._refreshing = threading.Lock()
        self._cfg_lock = threading.Lock()
        self.summarizer = summarizer
        self.backend = backend
        self.notifier = notifier
        self._audit = audit if isinstance(audit, AuditLog) else AuditLog(audit)
        self.history = History(self._audit._path)
        self._csrf_key = secrets.token_bytes(32)    # per process: tokens die with a restart
        self._lock = threading.Lock()
        self._by_id = {}
        self._by_nonce = {}
        self._denied_at = {}
        if hasattr(backend, "on_event"):
            backend.on_event = self.log
        esc = config.get("risk", {}).get("escalate_auto_at")
        if esc is not None and esc not in risk_mod.LEVELS:
            raise ValueError(f"risk.escalate_auto_at must be one of {risk_mod.LEVELS}")
        if background_load:
            # Listen right away; the first requests wait on the same lock.
            self._refreshing.acquire()
            threading.Thread(target=self._initial_load, daemon=True).start()
        else:
            self._initial_load(locked=False)

    def _initial_load(self, locked=True):
        try:
            try:
                self.refresh_catalog()
            except Exception as e:  # noqa: BLE001 -- start anyway; requests retry the load
                self.log("catalog_error", error=str(e)[:200])
            self.log("startup", policies={
                n: {"approval": sc.get("approval", "prompt"), "auto_modes": self._auto_modes(sc)}
                for n, sc in sorted(self.cfg["secrets"].items())})
        finally:
            if locked:
                self._refreshing.release()

    # -- catalog (the vault is the source of truth) ---------------------------
    CATALOG_TTL = 60            # a request refreshes if the catalog is older than this
    CATALOG_BG_TTL = 300        # discovery serves the cache and refreshes in the background

    @staticmethod
    def _entry(item, meta):
        """Validated in-memory secret entry from an item's broker metadata."""
        name = meta.get("name") or re.sub(r"[^a-z0-9_-]+", "-", item.lower()).strip("-")[:41]
        if not _NAME_RE.match(name or ""):
            raise ValueError(f"cannot derive a secret name from {item!r}")
        approval = meta.get("approval", "prompt")
        if approval not in APPROVAL_VALUES:
            raise ValueError(f"approval must be one of {APPROVAL_VALUES}")
        # No hosts = not an HTTP credential (a Wi-Fi password, say): it can never
        # be used in http mode, only fetched with approval in env mode.
        hosts = meta.get("allowed_hosts") or []
        if (not isinstance(hosts, list) or len(hosts) > 10
                or not all(isinstance(h, str) and _HOST_RE.match(h) for h in hosts)):
            raise ValueError("allowed_hosts must be up to 10 plain hostnames")
        fp = meta.get("tls_fingerprint")
        if fp is not None:
            raw_fps = fp if isinstance(fp, list) else [fp]
            if not 1 <= len(raw_fps) <= 20:
                raise ValueError("tls_fingerprint must be one value or a list of up to 20")
            fps = []
            for one in raw_fps:
                one = re.sub(r"^sha256:", "", str(one).strip(), flags=re.I).replace(":", "").lower()
                if not re.fullmatch(r"[0-9a-f]{64}", one):
                    raise ValueError("tls_fingerprint must be sha256:<64 hex digits>")
                fps.append(one)
            fp = tuple(sorted(set(fps)))
        verify = meta.get("tls_verify", True)
        if not isinstance(verify, bool):
            raise ValueError("tls_verify must be true or false")
        if not verify and fp is None:
            public = [h for h in hosts if not _private_host(h)]
            if public or not hosts:
                raise ValueError("tls_verify=false is only allowed for private hosts "
                                 f"(not {', '.join(public) or 'a secret without hosts'}); pin a fingerprint instead")
        raw_vars = meta.get("vars")
        if not isinstance(raw_vars, dict) or not raw_vars:
            raise ValueError("vars must be a non-empty object")
        vars_ = {}
        for var, ref in raw_vars.items():
            ref = ref if isinstance(ref, dict) else {}
            if not _VAR_RE.match(var):
                raise ValueError(f"bad variable name {var!r}")
            if ref.get("item") not in (None, "", item):
                raise ValueError(f"{var}: a secret can only use its own item's fields")
            field = ref.get("field") or "auto"
            if field in ("broker", "previous_value", "previous_replaced_at"):
                raise ValueError(f"{var}: field {field!r} is reserved")
            vars_[var] = {"item": item, "field": field}
            if ref.get("key"):
                vars_[var]["key"] = str(ref["key"])
        return name, {**meta, "vars": vars_, "allowed_hosts": [h.lower() for h in hosts],
                      "approval": approval, "_item": item, "_meta": meta,
                      "_tls": {"fingerprint": fp, "verify": verify}}

    def refresh_catalog(self):
        """Rebuild the secret catalog from the vault's items. Raises if the vault
        cannot be read, leaving the previous catalog in place."""
        if not hasattr(self.backend, "catalog"):
            return
        rows = self.backend.catalog()
        out, bad, owners = {}, [], {}
        for row in rows:
            try:
                if row["meta"] is None:
                    raise ValueError("broker metadata is not a JSON object")
                name, entry = self._entry(row["item"], row["meta"])
                out[name] = entry
                owners.setdefault(name, []).append(row["item"])
            except ValueError as e:
                bad.append({"item": row["item"], "reason": str(e)[:120]})
        # A name claimed by two items is ambiguous, and "first wins" would let a
        # look-alike item shadow a real secret: drop every claimant (fail closed).
        for name, items in owners.items():
            if len(items) > 1:
                out.pop(name, None)
                bad.extend({"item": i, "reason": f"duplicate secret name {name!r}"} for i in items)
        with self._cfg_lock:
            self.cfg["secrets"] = out
            self._catalog_at = time.time()
        sig = json.dumps([sorted(out), bad], sort_keys=True)
        if sig != self._catalog_sig:
            self._catalog_sig = sig
            self.log("catalog_loaded", count=len(out), names=sorted(out), invalid=bad)

    def _refresh_if(self, stale_after, wait=True):
        if time.time() - self._catalog_at <= stale_after:
            return
        if not self._refreshing.acquire(blocking=wait):
            return
        try:
            if time.time() - self._catalog_at > stale_after:
                self.refresh_catalog()
        except Exception as e:  # noqa: BLE001 -- keep serving the last good catalog
            self.log("catalog_error", error=str(e)[:200])
        finally:
            self._refreshing.release()

    def _tls_policy(self, names):
        """TLS handling for a request: a pinned fingerprint, or verification off
        (private hosts only), or normal verification. If the secrets disagree the
        strict default applies."""
        pol = {(self.cfg["secrets"][n].get("_tls", {}).get("fingerprint"),
                self.cfg["secrets"][n].get("_tls", {}).get("verify", True))
               for n in names if n in self.cfg["secrets"]}
        if len(pol) == 1:
            fp, verify = next(iter(pol))
            return {"fingerprint": fp, "verify": verify}
        return {"fingerprint": None, "verify": True}

    # -- audit ------------------------------------------------------------
    def log(self, event, **fields):
        self._audit.log(event, **fields)

    def audit(self, event, req, **extra):
        rec = {"id": req.id, "mode": req.mode, "names": req.names,
               "source": req.source, "peer": req.peer, **extra}
        if req.summary:
            rec["summary"] = req.summary
        if req.risk:
            rec["risk"] = req.risk["level"]
        if req.mode == "http":
            rec["method"], rec["url"] = req.spec["method"], req.spec["url"]
        elif req.mode == "store":
            sp = req.spec
            rec.update(op=sp.get("op"), item=sp.get("item"), field=sp.get("field"), key=sp.get("key"),
                       hosts=sp.get("allowed_hosts"), value_bytes=sp.get("value_bytes"))
        else:
            rec["argv"] = (req.spec.get("argv") or [])[:50]
        self._audit.log(event, **rec)

    # -- policy -----------------------------------------------------------
    @staticmethod
    def _auto_modes(sc):
        if sc.get("approval", "prompt") != "allow":
            return []
        return list(sc.get("auto_modes", ["http"]))

    def _auto_allowed(self, mode, names, spec=None):
        if mode == "store":
            # Creating a credential is low risk (it cannot read or change anything
            # that exists, and the new secret still prompts on every use), so it
            # needs no tap unless `"store": {"create": "prompt"}`. An update
            # overwrites a live credential and always needs a human.
            return (bool(spec) and spec.get("op") == "create"
                    and self.cfg.get("store", {}).get("create", "auto") != "prompt")
        return all(mode in self._auto_modes(self.cfg["secrets"][n]) for n in names)

    # -- standing policy changes (approver-initiated, persisted) ------------
    def always_allow_eligibility(self, req):
        """(ok, reason). `reason` is shown to the approver when not ok.

        A standing allow is only meaningful (and only offered) when it would
        actually take effect, and it is never established from a request that is
        itself high risk or that releases the value to the requesting host.
        """
        if req.mode == "store":
            return False, "storing a credential always needs a fresh approval"
        if req.mode != "http":
            return False, "env-mode requests release the value to the requesting host"
        if len(req.names) != 1:
            return False, "this request involves several secrets"
        name = req.names[0]
        sc = self.cfg["secrets"][name]
        if sc.get("approval", "prompt") == "allow":
            return False, "already always-allowed"
        if not hasattr(self.backend, "set_meta"):
            return False, "the vault backend cannot record this"
        esc = self._escalate_at()
        if esc:
            if req.risk and risk_mod.rank(req.risk["level"]) >= risk_mod.rank(esc):
                return False, f"this request is rated {req.risk['level']}; such requests always prompt"
        return True, ""

    def _escalate_at(self):
        """Level at or above which an `allow` secret is prompted anyway.

        Defaults to medium, so only a request the model rated low (or, with no
        model verdict, nothing: that counts as high) is released unprompted.
        """
        return self.cfg.get("risk", {}).get("escalate_auto_at") or "medium"

    def _persist_approval(self, name, value, user):
        """Write the new policy into the item's broker metadata in the vault."""
        sc = self.cfg["secrets"][name]
        meta = {**sc["_meta"], "approval": value,
                "approval_changed": {"by": user, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}
        self.backend.set_meta(sc["_item"], meta)
        sc["_meta"] = meta

    def set_approval(self, name, value, user, peer=None, client_ip=None, request_id=None):
        """Change a secret's standing approval policy: file first, then memory."""
        if value not in APPROVAL_VALUES or name not in self.cfg["secrets"]:
            raise ValueError("bad policy change")
        with self._cfg_lock:
            sc = self.cfg["secrets"][name]
            old = sc.get("approval", "prompt")
            if old == value:
                return True
            try:
                self._persist_approval(name, value, user)
            except (OSError, ValueError, KeyError, BackendError) as e:
                self.log("policy_change_failed", secret=name, to=value, user=user,
                         request_id=request_id, error=str(e)[:200])
                return False
            sc["approval"] = value
            sc["approval_changed"] = {"by": user}
        self.log("policy_changed", secret=name, **{"from": old, "to": value}, user=user, peer=peer,
                 client_ip=client_ip, request_id=request_id)
        return True

    # -- discovery (no approval, no push, no values) ----------------------
    def available(self, host=None):
        """Secrets usable for `host` in http mode. Names and placeholder
        variable names only; this never sends a notification or reads a value.
        Serves the cached catalog and refreshes it in the background."""
        if self._catalog_at == 0.0:
            self._refresh_if(0, wait=True)   # first load still running: wait for it
        elif time.time() - self._catalog_at > self.CATALOG_BG_TTL:
            threading.Thread(target=self._refresh_if, args=(self.CATALOG_BG_TTL, False),
                             daemon=True).start()
        out = []
        for name, sc in sorted(self.cfg["secrets"].items()):
            hosts = sc.get("allowed_hosts") or []
            if host is None or host in hosts:
                # Deliberately no approval policy or sensitivity here: whether a
                # credential prompts must not influence which one an agent picks.
                out.append({"name": name, "vars": sorted(sc["vars"]), "allowed_hosts": hosts})
        return out

    # -- request lifecycle ------------------------------------------------
    def create(self, mode, names, spec, source, peer=None):
        try:
            self._refresh_if(0 if (mode != "store" and any(n not in self.cfg["secrets"] for n in names))
                             else self.CATALOG_TTL)
            secrets_cfg = self.cfg["secrets"]
            if mode == "store":
                self._validate_store(names, spec)
            else:
                if not names or any(n not in secrets_cfg for n in names):
                    raise ValueError("unknown secret name")
                if mode == "http":
                    self._validate_http(names, spec)
        except (ValueError, PermissionError) as e:
            self.log("rejected", reason=str(e), names=names, mode=mode, source=source, peer=peer,
                     url=spec.get("url") if isinstance(spec, dict) and mode == "http" else None)
            raise
        with self._lock:
            self._expire_locked()
            err = None
            if sum(r.status == "pending" for r in self._by_id.values()) >= MAX_PENDING:
                err = "too many pending requests"
            now = time.time()
            for n in names:
                if now - self._denied_at.get(n, 0) < DENY_COOLDOWN:
                    err = f"{n} was denied recently; try again later"
            if err is None:
                req = Request(mode, names, spec, source, self.cfg.get("ttl_seconds", 120), peer)
                self._by_id[req.id] = req
                self._by_nonce[req.nonce] = req
        if err:
            self.log("rejected", reason=err, names=names, mode=mode, source=source, peer=peer)
            raise PermissionError(err)
        self.audit("requested", req)
        if self.cfg.get("backend", {}).get("prewarm", True):
            # unlock while the human is reaching for their phone
            self.warm_backend()
        a = risk_mod.assess(mode, names, spec, self.summarizer)
        req.summary, req.risk = a["summary"], {k: a[k] for k in ("level", "model", "reasons")}
        self.audit("assessed", req, model=a["model"], reasons=a["reasons"])
        auto = self._auto_allowed(mode, names, spec)
        esc = self._escalate_at()
        if auto and esc and risk_mod.rank(a["level"]) >= risk_mod.rank(esc):
            self.audit("escalated", req, reason=f"risk {a['level']} >= {esc}; policy allow overridden")
            auto = False
        if auto:
            if mode == "store":
                req.approver = "policy:auto-create"
            try:
                result = self._release(req)
            except (BackendError, OSError, ValueError) as e:
                self._finish(req, "failed", error=f"release failed: {e}", via="policy")
            else:
                self._finish(req, "approved", result=result, via="policy")
            return req
        try:
            self._push(req)
        except (NotifyError, OSError) as e:
            self._finish(req, "failed", error=f"could not notify: {e}")
        return req

    def _validate_store(self, names, spec):
        """Validate (and fill defaults for) a request to create/update a credential."""
        if len(names) != 1 or not _NAME_RE.match(names[0]):
            raise ValueError("secret name must be 1-41 chars of a-z 0-9 _ - ")
        name, op = names[0], spec.get("op")
        value = spec.get("value")
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("value must be a non-empty string")
        if len(value.encode()) > MAX_STORE_VALUE:
            raise ValueError(f"value is larger than {MAX_STORE_VALUE} bytes")
        spec["value_bytes"] = len(value.encode())
        secrets_cfg = self.cfg["secrets"]
        if op == "create":
            if name in secrets_cfg:
                raise ValueError(f"{name} already exists; use update")
            if not hasattr(self.backend, "catalog"):
                raise PermissionError("this vault backend has no secret catalog")
            hosts = spec.get("allowed_hosts")
            if (not isinstance(hosts, list) or not 1 <= len(hosts) <= 10
                    or not all(isinstance(h, str) and _HOST_RE.match(h) for h in hosts)):
                raise ValueError("allowed_hosts must be 1-10 plain hostnames")
            spec["allowed_hosts"] = sorted(set(h.lower() for h in hosts))
            spec["field"] = spec.get("field") or "notes"
            spec["item"] = spec.get("item") or name
            spec["var"] = spec.get("var") or re.sub(r"[^A-Za-z0-9]", "_", name).upper() + "_TOKEN"
            if not _FIELD_RE.match(spec["field"]) or spec["field"] in (
                    "previous_value", "previous_replaced_at", "broker"):
                raise ValueError("bad field name")
            if not _ITEM_RE.match(spec["item"]):
                raise ValueError("bad item name")
            if not _VAR_RE.match(spec["var"]):
                raise ValueError("variable must look like MY_TOKEN")
            for other, sc in secrets_cfg.items():
                for ref in sc["vars"].values():
                    if ref["item"] == spec["item"]:
                        raise ValueError(f"vault item {spec['item']!r} is already used by {other}")
        elif op == "update":
            if name not in secrets_cfg:
                raise ValueError("unknown secret name")
            for k in ("allowed_hosts", "item"):
                if spec.get(k):
                    raise ValueError(f"{k} cannot be changed by an update")
            vars_ = secrets_cfg[name]["vars"]
            var = spec.get("var")
            if var is None:
                if len(vars_) != 1:
                    raise ValueError("this secret has several variables; say which with var")
                var = next(iter(vars_))
            if var not in vars_:
                raise ValueError(f"{name} has no variable {var}")
            ref = vars_[var]
            spec["var"], spec["item"], spec["field"] = var, ref["item"], ref.get("field") or "auto"
            spec["key"] = ref.get("key")
        else:
            raise ValueError("op must be create or update")

    def _validate_http(self, names, spec):
        u = urllib.parse.urlsplit(spec["url"])
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("bad url")
        allowed = None
        for n in names:
            hosts = set(self.cfg["secrets"][n].get("allowed_hosts") or [])
            allowed = hosts if allowed is None else allowed & hosts
        if u.hostname not in (allowed or set()):
            raise PermissionError(f"host {u.hostname} is not allowed for {','.join(names)}")
        if spec.get("body_b64") is not None:
            try:
                base64.b64decode(spec["body_b64"], validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("body_b64 is not valid base64")
            if spec.get("body") is not None:
                raise ValueError("send body or body_b64, not both")
        known = {v for n in names for v in self.cfg["secrets"][n]["vars"]}
        for text in [spec["url"], spec.get("body") or ""] + list(spec["headers"].values()):
            for var in _placeholders(text):
                if var not in known:
                    raise ValueError(f"placeholder {var} not provided by requested secrets")

    def _push(self, req):
        url = f"{self.cfg['approve_base_url'].rstrip('/')}/a/{req.nonce}"
        if req.mode == "http":
            what = f"{req.spec['method']} {req.spec['url']}"
        elif req.mode == "store":
            sp = req.spec
            what = (f"{sp['op']} credential: item {sp['item']!r} field {sp['field']}"
                    f"{' key ' + sp['key'] if sp.get('key') else ''} "
                    f"({sp['value_bytes']} bytes, value not shown)")
        else:
            what = "run: " + " ".join(req.spec.get("argv") or [])[:200]
        head = f"{req.summary} (unverified)\n" if req.summary else ""
        why = f"\nWhy: {'; '.join(req.risk['reasons'][:3])}" if req.risk and req.risk["reasons"] else ""
        msg = f"{head}{', '.join(req.names)} from {req.source}\n{what}{why}"
        title = f"Secret request [{req.risk['level'].upper()}]" if req.risk else "Secret request"
        notify_mod.deliver(self.notifier, title, msg, url, f"secret-{req.id[:8]}", list(req.names))
        self.audit("notified", req)

    def _resolved(self, req, status):
        """Tell the transport the request is settled (e.g. edit the chat message)."""
        fn = getattr(self.notifier, "resolved", None)
        if fn is None or req.mode is None:
            return
        tag = f"secret-{req.id[:8]}"

        def run():
            try:
                fn(tag, status)
            except Exception:
                pass
        threading.Thread(target=run, daemon=True).start()

    def _expire_locked(self):
        now = time.time()
        for r in self._by_id.values():
            if r.status == "pending" and now > r.expires:
                r.status = "expired"
                if r.mode == "store":
                    r.spec["value"] = None
                self.audit("expired", r)
                self._resolved(r, "expired")
                r.done.set()
        for rid in [k for k, r in self._by_id.items() if now > r.expires + 300]:
            r = self._by_id.pop(rid)
            self._by_nonce.pop(r.nonce, None)

    def _finish(self, req, status, error=None, result=None, **extra):
        with self._lock:
            if req.status not in ("pending", "deciding"):
                return False
            req.status, req.error, req.result = status, error, result
            if req.mode == "store":
                req.spec["value"] = None        # never keep a credential longer than needed
        if status == "denied":
            now = time.time()
            for n in req.names:
                self._denied_at[n] = now
        extra["latency_ms"] = int((time.time() - req.created) * 1000)
        self.audit(status, req, error=error, **extra)
        if extra.get("via") != "policy" and status != "approved":
            self._resolved(req, status)     # approvals were announced at decision time
        req.done.set()
        return True

    def peer_trusted(self, peer):
        """`approval_trusted_peers`: CIDRs the approval listener will answer.
        The listener trusts the identity header, so it should only ever hear
        from the SSO proxy; unset means no restriction (network isolation)."""
        nets = self.cfg.get("approval_trusted_peers")
        if not nets:
            return True
        try:
            ip = ipaddress.ip_address(peer)
            return any(ip in ipaddress.ip_network(n, strict=False) for n in nets)
        except ValueError:
            return False

    def csrf_token(self, user):
        """Token a page must echo back with a decision. Bound to the identity, so
        one user's page cannot be replayed by another session."""
        return hmac.new(self._csrf_key, ("csrf:" + user).encode(), hashlib.sha256).hexdigest()

    def pending(self):
        """Open requests, oldest first."""
        with self._lock:
            self._expire_locked()
            rows = [r for r in self._by_id.values() if r.status == "pending"]
        return sorted(rows, key=lambda r: r.created)

    def decide(self, nonce, approve, user, peer=None, client_ip=None, always=False, channel="link"):
        with self._lock:
            self._expire_locked()
            req = self._by_nonce.get(nonce)
            if req is not None and req.status == "pending":
                req.status = "deciding"      # claim it: a second submit must not also act
            else:
                req = None
        if req is None:
            self.log("approval_stale", user=user, peer=peer, client_ip=client_ip, approve=approve)
            return None
        who = {"via": "user", "approver": user, "approver_peer": peer, "approver_ip": client_ip,
               "channel": channel}
        req.approver = user
        # The decision itself is recorded and announced immediately.
        self.audit("decided", req, decision="approve" if approve else "deny",
                   always_requested=bool(always and approve), **who)
        if not approve:
            self._finish(req, "denied", **who)
            return req
        if always:
            ok, why = self.always_allow_eligibility(req)
            if not ok:
                req.always = f"not applied: {why}"
                self.audit("policy_change_refused", req, reason=why, **who)
            elif self.set_approval(req.names[0], "allow", user, peer, client_ip, req.id):
                req.always = "applied"
            else:
                req.always = "not applied: could not write the config file"
        self._resolved(req, "approved")
        # Releasing can take seconds (vault unlock, upstream call). It runs off
        # the request thread: the approver's page has already been answered, the
        # result reaches the client through its poll, and any failure is audited
        # and surfaced to the client, never to the approver.
        threading.Thread(target=self._release_and_finish, args=(req, who), daemon=True).start()
        return req

    def _release_and_finish(self, req, who):
        try:
            result = self._release(req)
        except (BackendError, OSError, ValueError) as e:
            self._finish(req, "failed", error=f"release failed: {e}", **who)
            return
        self._finish(req, "approved", result=result, **who)

    def warm_backend(self):
        """Pre-unlock the backend in the background; never raises."""
        fn = getattr(self.backend, "warm", None)
        if fn is None:
            return

        def run():
            t0 = time.time()
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                self.log("backend_error", error=str(e)[:200])
            else:
                self.log("backend_ready", duration_ms=int((time.time() - t0) * 1000))
        threading.Thread(target=run, daemon=True).start()

    def _store(self, req):
        """Write the credential to the vault; a create also writes its catalog entry."""
        sp = req.spec
        name, by = req.names[0], req.approver or "unknown"
        if not hasattr(self.backend, "put"):
            raise BackendError("this backend cannot store credentials")
        t0 = time.time()
        if sp["op"] == "create":
            # One atomic vault write: the item, its value and its broker metadata
            # (the catalog entry) are created together, so there is nothing to
            # roll back and no second place to keep in sync.
            stamp = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            meta = {"name": name, "vars": {sp["var"]: {"field": sp["field"]}},
                    "allowed_hosts": sp["allowed_hosts"], "approval": "prompt", "created": stamp}
            self.backend.put(sp["item"], sp["field"], sp["value"], create=True, meta=meta)
            _, entry = self._entry(sp["item"], meta)
            with self._cfg_lock:
                self.cfg["secrets"][name] = entry
        else:
            value = sp["value"]
            if sp.get("key"):                       # one key of a multi-value field
                try:
                    value = structured.set_key(self.backend.get(sp["item"], sp["field"]),
                                               sp["key"], value)
                except structured.StructuredError as e:
                    raise BackendError(str(e)) from None
            self.backend.put(sp["item"], sp["field"], value, create=False, keep_previous=True)
        self.audit("stored", req, duration_ms=int((time.time() - t0) * 1000))
        return {"stored": {"name": name, "op": sp["op"], "item": sp["item"], "field": sp["field"]}}

    def _release(self, req):
        if req.mode == "store":
            return self._store(req)
        env, raw = {}, {}
        for n in req.names:
            if n not in self.cfg["secrets"]:
                raise BackendError(f"{n} is no longer in the vault catalog")
            for var, ref in self.cfg["secrets"][n]["vars"].items():
                src = (ref["item"], ref.get("field") or "auto")
                if src not in raw:                  # one vault read per item/field
                    raw[src] = self.backend.get(*src)
                try:
                    env[var] = (structured.get(raw[src], ref["key"]) if ref.get("key")
                                else raw[src])
                except structured.StructuredError as e:
                    raise BackendError(f"{var}: {e}") from None
            self.audit("secret_read", req, secret=n, vars=sorted(self.cfg["secrets"][n]["vars"]))
        if req.mode == "env":
            return {"env": env}
        t0 = time.time()
        try:
            out = _do_http(req.spec, env, self._tls_policy(req.names))
        except OSError as e:
            self.audit("http_failed", req, error=str(e)[:200])
            raise
        self.audit("http_executed", req, upstream_status=out["status"],
                   response_bytes=len(out["body"]), duration_ms=int((time.time() - t0) * 1000))
        return {"http": out}

    def wait(self, rid, timeout):
        req = self._by_id.get(rid)
        if req is None:
            return None
        req.done.wait(timeout)
        with self._lock:
            self._expire_locked()
        return req

    def take_result(self, req, peer=None):
        """Return the client-facing view; secret values are handed out once."""
        with self._lock:
            if req.status == "approved":
                out, req.result = req.result, None
                req.status = "released"
                delivered = True
            else:
                delivered = False
        if delivered:
            self.audit("delivered", req, to_peer=peer, kind="env" if req.mode == "env" else "http_response")
            return {"status": "approved", **(out or {})}
        if req.status == "released":
            return {"status": "released"}
        return {"status": req.status, "error": req.error}


def _placeholders(text):
    out, i = [], 0
    while True:
        a = text.find("{{", i)
        if a < 0:
            return out
        b = text.find("}}", a)
        if b < 0:
            return out
        out.append(text[a + 2:b].strip())
        i = b + 2


def _fill(text, env):
    for var in _placeholders(text):
        text = text.replace("{{" + var + "}}", env[var]).replace("{{ " + var + " }}", env[var])
    return text


def _mask(text, values):
    for v in sorted(values, key=len, reverse=True):
        if len(v) >= 6:
            text = text.replace(v, "***")
    return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: only the originally approved URL is contacted,
    so injected credentials cannot be forwarded to a host outside allowed_hosts.
    The 3xx is returned to the caller as-is."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _private_host(host):
    """True for addresses/names that only exist on a private network."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    h = host.lower()
    return "." not in h or h.endswith((".lan", ".local", ".internal", ".home.arpa", ".localdomain"))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS with the CA/hostname check replaced by an exact certificate match."""
    pins = ()

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not der or hashlib.sha256(der).hexdigest() not in self.pins:
            self.close()
            raise ssl.SSLError("server certificate does not match any pinned fingerprint")


def _opener_for(tls):
    if not tls or (tls.get("verify", True) and not tls.get("fingerprint")):
        return _opener
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    pins = tls.get("fingerprint")
    if pins:
        if isinstance(pins, str):
            pins = (pins,)
        conn = type("_Pinned", (_PinnedHTTPSConnection,), {"pins": tuple(pins)})
        handler = type("_PinnedHandler", (urllib.request.HTTPSHandler,), {
            "https_open": lambda self, req: self.do_open(
                lambda host, **kw: conn(host, context=ctx, **{k: v for k, v in kw.items() if k != "context"}),
                req)})()
    else:
        handler = urllib.request.HTTPSHandler(context=ctx)
    return urllib.request.build_opener(_NoRedirect, handler)


def _do_http(spec, env, tls=None):
    if spec.get("body_b64") is not None:
        data = base64.b64decode(spec["body_b64"])
    elif spec.get("body"):
        data = _fill(spec["body"], env).encode()
    else:
        data = None
    req = urllib.request.Request(
        _fill(spec["url"], env), data=data, method=spec["method"],
        headers={k: _fill(v, env) for k, v in spec["headers"].items()},
    )
    try:
        with _opener_for(tls).open(req, timeout=30) as r:
            status, headers, body = r.status, dict(r.headers), r.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers), e.read(MAX_RESPONSE_BYTES)
    values = list(env.values())
    return {
        "status": status,
        "headers": {k: _mask(v, values) for k, v in headers.items()},
        "body": _mask(body.decode("utf-8", "replace"), values),
    }


# -- HTTP layer -------------------------------------------------------------
def _json(h, code, obj):
    raw = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)


_CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;
--accent:#0969da;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#30363d;
--card:#161b22;--accent:#4493f8;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:72rem;margin:0 auto;padding:1rem}
main.narrow{max-width:38rem}
nav{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;padding:.75rem 1rem;border-bottom:1px solid var(--line);
background:var(--card)}
nav a{color:var(--accent);text-decoration:none;padding:.35rem 0;font-weight:600}
h1{font-size:1.5rem;margin:.25rem 0 1rem}
a{color:var(--accent)}
small,.muted{color:var(--muted)}
p,td,li{overflow-wrap:anywhere}
.actions{display:flex;flex-wrap:wrap;gap:.75rem;margin:1.25rem 0}
.btn,button{font:inherit;font-weight:600;min-height:3rem;padding:.6rem 1.4rem;border-radius:.6rem;
border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
[hidden]{display:none!important}
.pushpanel{margin-top:2rem;border-top:1px solid var(--line);padding-top:1rem}
.devices{list-style:none;padding:0}.devices li{display:flex;gap:.8rem;align-items:center;
justify-content:space-between;padding:.5rem 0;border-bottom:1px solid var(--line)}
form.inline{display:inline}
.notify{margin:.25rem 0 1rem}.notify .btn{margin-right:.6rem}
.btn.approve{background:var(--ok);border-color:var(--ok);color:#fff}
.btn.deny{background:var(--bad);border-color:var(--bad);color:#fff}
.actions .btn{flex:1 1 9rem}
button:disabled{opacity:.6;cursor:default}
.risk{border-left:.4rem solid var(--muted);padding:.4rem .8rem;background:var(--card);border-radius:.3rem;margin:1rem 0}
.risk.low{border-color:var(--ok)}.risk.medium{border-color:var(--warn)}.risk.high{border-color:var(--bad)}
.risk b{display:block}
.risk.low b{color:var(--ok)}.risk.medium b{color:var(--warn)}.risk.high b{color:var(--bad)}
.box{background:var(--card);border:1px solid var(--line);border-radius:.5rem;padding:.6rem .9rem;margin:.75rem 0;
overflow-wrap:anywhere}
.filters{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}
.filters select{font:inherit;min-height:2.75rem;flex:1 1 9rem;padding:.3rem .5rem;border-radius:.5rem;
border:1px solid var(--line);background:var(--bg);color:var(--fg)}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:.85rem;color:var(--muted);padding:.5rem;border-bottom:2px solid var(--line)}
.tbl td{padding:.55rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
.tbl td[data-label=Time],.tbl td[data-label=Outcome],.tbl td[data-label=Risk],.tbl td[data-label=Took]
{white-space:nowrap;overflow-wrap:normal}
.pager{display:flex;gap:1.25rem;align-items:center;flex-wrap:wrap}
.req{background:var(--card);border:1px solid var(--line);border-radius:.8rem;padding:.25rem 1rem 1rem;margin:0 0 1rem}
.req h2{font-size:1.15rem;margin:.75rem 0 .25rem}
.flash{background:var(--card);border:1px solid var(--line);border-left:.4rem solid var(--accent);border-radius:.4rem;padding:.5rem .8rem;margin:.75rem 0}
.offline{border-left-color:var(--bad)}
@media (min-width:60rem){.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}.req{margin:0}}
@media (max-width:42rem){
 main{padding:.75rem}
 .tbl thead{display:none}
 .tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}
 .tbl tr{background:var(--card);border:1px solid var(--line);border-radius:.6rem;margin:0 0 .75rem;padding:.4rem .7rem}
 .tbl td{border:0;padding:.2rem 0;display:flex;gap:.75rem}
 .tbl td::before{content:attr(data-label);flex:0 0 5.5rem;color:var(--muted);font-size:.85rem;padding-top:.1rem}
 .tbl td>*{min-width:0}
 .actions .btn{flex-basis:100%}
}
"""

_WORKING_JS = (
    "document.getElementById('f').addEventListener('submit',function(){"
    "setTimeout(function(){document.querySelectorAll('button').forEach(function(b){b.disabled=true});"
    "document.getElementById('w').hidden=false},0)});")

_DASH_JS = r'''
(function(){
  var cards=document.getElementById('cards'), flash=document.getElementById('flash'),
      off=document.getElementById('offline'), last=cards.getAttribute('data-version');
  function secs(){document.querySelectorAll('time[data-exp]').forEach(function(t){
    var s=Math.max(0,Math.floor(t.getAttribute('data-exp')-Date.now()/1000));
    t.textContent='expires in '+s+'s';});}
  function title(){var n=cards.querySelectorAll('article').length;
    document.title=(n?'('+n+') ':'')+'Secret broker';}
  function parse(h){return new DOMParser().parseFromString(h,'text/html');}
  var nbtn=document.getElementById('notify'), nmsg=document.getElementById('notify-state'),
      seen={};
  function ids(root){var o={};root.querySelectorAll('article[data-id]').forEach(function(a){
    o[a.getAttribute('data-id')]=a.querySelector('h2')?a.querySelector('h2').textContent:'';});return o;}
  function want(){try{return localStorage.getItem('notify')==='1';}catch(e){return false;}}
  function remember(v){try{localStorage.setItem('notify',v?'1':'0');}catch(e){}}
  function nshow(){
    if(!nbtn)return;
    var tbtn=document.getElementById('notify-test');
    if(!('Notification' in window)){nbtn.hidden=true;
      nmsg.textContent='This browser cannot show notifications.';return;}
    var p=Notification.permission;
    if(p==='denied'){nbtn.hidden=true;
      nmsg.textContent='Notifications are blocked for this site in the browser settings.';return;}
    var on=p==='granted'&&want();
    nbtn.hidden=false;
    if(tbtn)tbtn.hidden=!on;
    nbtn.textContent=on?'Turn off notifications on this device':'Notify me on this device';
    nmsg.textContent=on?'You will get a notification when a request arrives, as long as this page '
      +'stays open in a tab or window.':'Notifications only arrive while this page is open.';}
  function why(t){var e=document.getElementById('notify-why');if(e)e.textContent=t;}
  function fire(title,body,tag){
    try{var n=new Notification(title,{body:body,tag:tag,requireInteraction:true});
      n.onclick=function(){try{window.focus();}catch(x){}poll();n.close();};return true;}
    catch(e){why('The browser refused to show a notification ('+e.name+'). '
      +'Some mobile browsers need an installed web app for this.');return false;}}
  function announce(found){
    var fresh=Object.keys(found).filter(function(id){return seen[id]===undefined;});
    if(!fresh.length||pushOn)return;
    if(!('Notification' in window)||Notification.permission!=='granted'||!want()){
      why('A request arrived but notifications are off on this device.');return;}
    if(!document.hidden&&document.hasFocus()){
      why('A request arrived while this page was in front, so no pop-up was shown.');return;}
    fresh.forEach(function(id){fire('Approval needed',found[id]||'A secret was requested',id);});
    why('Last request: notification sent to the browser ('+new Date().toLocaleTimeString()+'). '
      +'If nothing appeared, check the operating system notification settings for this browser.');}
  function track(found){announce(found);seen=found;}
  var tbtn=document.getElementById('notify-test');
  if(tbtn)tbtn.addEventListener('click',function(){
    if(!('Notification' in window)||Notification.permission!=='granted'){
      why('Notifications are not allowed for this site yet.');return;}
    if(fire('Test notification','If you can see this, notifications work on this device.','test'))
      why('Test sent ('+new Date().toLocaleTimeString()+'). If nothing appeared, the browser or '
        +'operating system is hiding it.');});
  if(nbtn)nbtn.addEventListener('click',function(){
    if(!('Notification' in window))return;
    if(Notification.permission==='granted'&&want()){remember(false);nshow();return;}
    var go=function(p){if(p==='granted')remember(true);nshow();};
    var r=Notification.requestPermission(go);if(r&&r.then)r.then(go);});
  var pbtn=document.getElementById('push-enable'), pst=document.getElementById('push-state'),
      pushOn=false;
  function u8(b){var s=(b+'='.repeat((4-b.length%4)%4)).replace(/-/g,'+').replace(/_/g,'/'),
    r=atob(s),o=new Uint8Array(r.length);for(var i=0;i<r.length;i++)o[i]=r.charCodeAt(i);return o;}
  function pshow(){
    if(!pbtn)return;
    if(!('serviceWorker' in navigator)||!('PushManager' in window)){pbtn.hidden=true;
      pst.textContent='This browser cannot receive push notifications.';return;}
    navigator.serviceWorker.getRegistration('/').then(function(reg){
      return reg?reg.pushManager.getSubscription():null;}).then(function(sub){
      pushOn=!!sub;pbtn.hidden=false;
      pbtn.textContent=sub?'Register this device again':'Enable on this device';
      pst.textContent=sub?'This device has a subscription. It receives notifications with the '
        +'browser closed, as long as the browser is allowed to run in the background.':
        'Not enabled on this device.';});}
  if(pbtn)pbtn.addEventListener('click',function(){
    pst.textContent='Working...';
    Notification.requestPermission().then(function(p){
      if(p!=='granted')throw new Error('notifications are not allowed for this site');
      return navigator.serviceWorker.register('/sw.js',{scope:'/'});})
    .then(function(){return navigator.serviceWorker.ready;})
    .then(function(reg){return reg.pushManager.getSubscription().then(function(sub){
      return sub||reg.pushManager.subscribe({userVisibleOnly:true,
        applicationServerKey:u8(pbtn.getAttribute('data-key'))});});})
    .then(function(sub){var j=sub.toJSON();
      return fetch('/push/subscribe',{method:'POST',credentials:'same-origin',
        body:new URLSearchParams({csrf:pbtn.getAttribute('data-csrf'),endpoint:j.endpoint,
          p256dh:j.keys.p256dh,auth:j.keys.auth})});})
    .then(function(r){if(!r.ok)throw new Error('the broker refused the subscription');
      location.reload();})
    .catch(function(e){pst.textContent='Could not enable: '+(e&&e.message||e);});});
  function poll(){
    return fetch('/?fragment=1',{credentials:'same-origin',cache:'no-store'})
      .then(function(r){if(!r.ok)throw 0;return r.text();})
      .then(function(h){var c=parse(h).getElementById('cards');
        if(c&&c.getAttribute('data-version')!==last){
          last=c.getAttribute('data-version');cards.innerHTML=c.innerHTML;bind();
          track(ids(c));}
        off.hidden=true;secs();title();})
      .catch(function(){off.hidden=false;});}
  function bind(){document.querySelectorAll('form.decide').forEach(function(f){
    if(f.getAttribute('data-bound'))return;f.setAttribute('data-bound','1');
    f.addEventListener('submit',function(e){
      if(!window.fetch||!e.submitter)return;e.preventDefault();
      var body=new URLSearchParams(new FormData(f));
      body.append(e.submitter.name,e.submitter.value);
      f.querySelectorAll('button').forEach(function(b){b.disabled=true;});
      fetch(f.action,{method:'POST',body:body,credentials:'same-origin'})
        .then(function(r){return r.text();})
        .then(function(h){var n=parse(h).getElementById('flash');
          if(n){flash.textContent=n.textContent;flash.hidden=!n.textContent;}
          last=null;return poll();})
        .catch(function(){off.hidden=false;});});});}
  seen=ids(cards);nshow();pshow();
  bind();secs();title();setInterval(secs,1000);setInterval(poll,3000);
  document.addEventListener('visibilitychange',function(){if(!document.hidden)poll();});
  if('serviceWorker' in navigator)navigator.serviceWorker.addEventListener('message',function(m){
    if(m.data&&m.data.type==='poll')poll();
    if(m.data&&m.data.type==='diag')why('Service worker v'+m.data.v+': '+m.data.what+' at '
      +new Date().toLocaleTimeString()+'.');});
})();
'''

_SERVICE_WORKER = r"""
var SW_VERSION='4';
function tell(m){return self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(cs){
  cs.forEach(function(c){try{c.postMessage(m);}catch(x){}});return cs;});}
self.addEventListener('install',function(){self.skipWaiting();});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim());});
self.addEventListener('push',function(e){
  var d={};try{d=e.data.json();}catch(x){}
  tell({type:'diag',what:'push received',v:SW_VERSION});
  e.waitUntil(self.registration.showNotification(d.title||'Approval needed',{
    body:d.body||'A secret was requested',tag:d.tag||'secret-request',requireInteraction:true,
    data:{url:'/'},actions:[{action:'open',title:'Review'}],renotify:true,
    timestamp:Date.now()}));});
self.addEventListener('notificationclick',function(e){
  e.notification.close();
  tell({type:'diag',what:'notification clicked',v:SW_VERSION});
  // Focus an open dashboard tab (preferring one already on "/"); if focusing is
  // refused or there is no tab, open a new one so a click never does nothing.
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(cs){
    var pick=null;
    for(var i=0;i<cs.length;i++){
      if(!('focus' in cs[i]))continue;
      if(!pick||new URL(cs[i].url).pathname==='/')pick=cs[i];}
    if(!pick)return self.clients.openWindow('/');
    return pick.focus().then(function(c){
      if(c&&c.postMessage)c.postMessage({type:'poll'});
      return c;}).catch(function(){return self.clients.openWindow('/');});
  }).catch(function(){return self.clients.openWindow('/');}));});
"""

def _agent_label(ua):
    ua = ua or ""
    for token, name in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                        ("Safari/", "Safari")):
        if token in ua:
            browser = name
            break
    else:
        return "Unknown browser"
    for token, name in (("Windows", "Windows"), ("Mac OS X", "macOS"), ("Android", "Android"),
                        ("iPhone", "iPhone"), ("iPad", "iPad"), ("Linux", "Linux")):
        if token in ua:
            return f"{browser} on {name}"
    return browser


_NAV = ("<nav><a href='/'>Pending</a><a href='/history'>History</a>"
        "<a href='/policies'>Standing approvals</a></nav>")


def _page(h, code, body, wide=False, nav=True, script=None):
    nonce = secrets.token_urlsafe(16)
    scr = f"<script nonce='{nonce}'>{script}</script>" if script else ""
    csp = ("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'; "
           f"base-uri 'none'; frame-ancestors 'none'; worker-src 'self'; script-src 'nonce-{nonce}'")
    raw = ("<!doctype html><html lang=en><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<meta name=color-scheme content='light dark'><title>Secret broker</title>"
           f"<style>{_CSS}</style><body>{_NAV if nav else ''}"
           f"<main class='{'wide' if wide else 'narrow'}'>{body}</main>{scr}</body></html>").encode()
    h.send_response(code)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(raw)))
    h.send_header("Cache-Control", "no-store")
    h.send_header("X-Frame-Options", "DENY")
    h.send_header("Content-Security-Policy", csp)
    h.end_headers()
    h.wfile.write(raw)


def _describe(req):
    """(what_html, note_html) for a request, escaped."""
    if req.mode == "http":
        return (f"{html.escape(req.spec['method'])} {html.escape(req.spec['url'])}",
                "The broker will make this call itself; the secret never leaves it.")
    if req.mode == "store":
        sp = req.spec
        hosts = (f"<br>Usable only for: {html.escape(', '.join(sp['allowed_hosts']))}"
                 if sp.get("allowed_hosts") else "<br>Hosts and mapping stay unchanged")
        key = f", key: {html.escape(sp['key'])}" if sp.get("key") else ""
        return (f"<b>{html.escape(sp['op'].upper())}</b> credential in the vault<br>"
                f"Item: {html.escape(sp['item'])}, field: {html.escape(sp['field'])}{key}{hosts}<br>"
                f"New value: {sp['value_bytes']} bytes (never displayed)",
                "An update replaces the current value; the old one is kept in the item's "
                "previous_value field. This will not run without your approval.")
    return ("run <code>" + html.escape(" ".join(req.spec.get("argv") or [])) + "</code>",
            "Advisory only: the secret is released to the requesting host and the "
            "command shown is what it <em>said</em> it would run.")


def _risk_html(req):
    lvl = req.risk["level"] if req.risk else "medium"
    out = (f"<div class='risk {lvl}'><b>{lvl.upper()} RISK</b><small>"
           + html.escape("; ".join(req.risk["reasons"]) if req.risk else "") + "</small></div>")
    if req.summary:
        out += (f"<p>AI summary <small>(unverified, from client-supplied text)</small>:<br>"
                f"<i>{html.escape(req.summary)}</i></p>")
    return out


def client_handler(broker, client_key):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _authed(self):
            if not secrets.compare_digest(self.headers.get("X-Client-Key", ""), client_key):
                broker.log("auth_failed", peer=self.client_address[0], method=self.command,
                           path=self.path.split("?")[0])
                _json(self, 401, {"error": "bad client key"})
                return False
            return True

        def do_POST(self):
            if not self._authed() or self.path != "/v1/requests":
                return
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > MAX_REQUEST_BYTES:
                    return _json(self, 413, {"error": "request too large"})
                body = json.loads(self.rfile.read(n))
                mode = body["mode"]
                names = list(body["names"])
                if mode == "http":
                    spec = {"method": str(body["method"]).upper(), "url": str(body["url"]),
                            "headers": dict(body.get("headers") or {}), "body": body.get("body"),
                            "body_b64": body.get("body_b64")}
                elif mode == "env":
                    spec = {"argv": [str(a) for a in body.get("argv") or []]}
                elif mode == "store":
                    spec = {"op": body.get("op"), "value": body.get("value"),
                            "field": body.get("field"), "item": body.get("item"),
                            "var": body.get("var"), "allowed_hosts": body.get("allowed_hosts")}
                else:
                    raise ValueError("bad mode")
                req = broker.create(mode, names, spec, str(body.get("source", self.client_address[0]))[:80],
                                    peer=self.client_address[0])
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
                if not str(e) or not isinstance(e, ValueError) or isinstance(e, json.JSONDecodeError):
                    broker.log("bad_request", peer=self.client_address[0], error=str(e)[:200])
                return _json(self, 400, {"error": str(e)})
            except PermissionError as e:
                return _json(self, 403, {"error": str(e)})
            _json(self, 202, {"id": req.id, "status": req.status, "error": req.error,
                              "expires_in": int(req.expires - time.time())})

        def do_GET(self):
            if not self._authed():
                return
            u = urllib.parse.urlsplit(self.path)
            if u.path == "/v1/secrets":
                q = urllib.parse.parse_qs(u.query)
                host = q.get("host", [None])[0]
                if q.get("url"):
                    host = urllib.parse.urlsplit(q["url"][0]).hostname
                found = broker.available(host)
                broker.log("discovery", peer=self.client_address[0], host=host,
                           found=[f["name"] for f in found])
                return _json(self, 200, {"host": host, "secrets": found})
            if not u.path.startswith("/v1/requests/"):
                return _json(self, 404, {"error": "not found"})
            q = urllib.parse.parse_qs(u.query)
            timeout = min(float(q.get("wait", ["25"])[0]), 30)
            req = broker.wait(u.path.rsplit("/", 1)[1], timeout)
            if req is None:
                return _json(self, 404, {"error": "unknown request"})
            _json(self, 200, broker.take_result(req, self.client_address[0]))

    return H


def approval_handler(broker):
    cfg = broker.cfg

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _fwd(self):
            """Client IP as reported by the proxy chain. Informational: it is
            only as trustworthy as the proxies in front of this listener."""
            return (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()[:64]) or None

        def _user(self):
            if not broker.peer_trusted(self.client_address[0]):
                broker.log("approval_forbidden", reason="peer is not a trusted proxy",
                           peer=self.client_address[0], client_ip=self._fwd(), method=self.command)
                _page(self, 403, "<h1>Forbidden</h1>", nav=False)
                return None
            user = self.headers.get(cfg.get("identity_header", "X-authentik-username"), "")
            if user != cfg["allowed_user"]:
                broker.log("approval_forbidden", claimed_user=user[:80], peer=self.client_address[0],
                           client_ip=self._fwd(), method=self.command)
                _page(self, 403, "<h1>Forbidden</h1>", nav=False)
                return None
            return user

        def _same_origin(self):
            """Browsers always send these on a POST; a cross-site form cannot forge
            them. Non-browser clients that send neither are still held to the
            per-user token."""
            if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
                return False
            origin = self.headers.get("Origin")
            if origin and origin != "null":
                want = urllib.parse.urlsplit(cfg.get("approve_base_url", "")).netloc
                return bool(want) and urllib.parse.urlsplit(origin).netloc == want
            return origin is None

        def _csrf_ok(self, user, token):
            return (self._same_origin()
                    and hmac.compare_digest(token or "", broker.csrf_token(user)))

        def _dashboard(self, user, fragment=False, note=""):
            notes = {"approved": "Approved. Releasing now.", "denied": "Denied.",
                     "always": "Approved, and always allowed from now on.",
                     "stale": "That request was already handled or has expired.",
                     "push_removed": "Device removed.",
                     "push_test_ok": "Test push sent. It should arrive even with the browser closed.",
                     "push_failed": "The test push was not delivered to any device.",
                     "bad": "That request could not be processed."}
            reqs = broker.pending()
            token = broker.csrf_token(user)
            cards = []
            for r in reqs:
                what, rnote = _describe(r)
                ok, why = broker.always_allow_eligibility(r)
                always = (
                    "<button class=btn name=decision value=approve_always>"
                    f"Approve and always allow {html.escape(r.names[0])}</button>"
                    "<p><small>Future HTTP calls with this secret run without asking, except "
                    "requests rated at or above the risk threshold. Revoke any time under "
                    "Standing approvals.</small></p>" if ok else
                    f"<p><small>Always allow not offered: {html.escape(why)}.</small></p>")
                cards.append(
                    f"<article class=req data-id='{html.escape(r.id)}'>"
                    f"<h2>{html.escape(', '.join(r.names))}</h2>{_risk_html(r)}"
                    f"<div class=box>From: {html.escape(r.source)}<br>{what}</div>"
                    f"<p><small>{rnote}</small></p>"
                    f"<p><small><time data-exp='{int(r.expires)}'>expires in "
                    f"{max(0, int(r.expires - time.time()))}s</time></small></p>"
                    "<form method=post action='/decide' class=decide>"
                    f"<input type=hidden name=id value='{html.escape(r.id)}'>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    "<div class=actions><button class='btn approve' name=decision value=approve>"
                    "Approve</button><button class='btn deny' name=decision value=deny>Deny</button>"
                    f"</div>{always}</form></article>")
            version = hashlib.sha256("|".join(r.id for r in reqs).encode()).hexdigest()[:16]
            inner = ("".join(cards) if cards else
                     "<p class=muted>No requests are waiting for approval.</p>")
            block = f"<div id=cards class=cards data-version='{version}'>{inner}</div>"
            if fragment:
                return _page(self, 200, block, nav=False)
            msg = notes.get(note, "")
            panel = self._push_panel(token) if broker.push is not None else ""
            _page(self, 200,
                  "<h1>Pending requests</h1>"
                  "<p class=notify><button id=notify class=btn type=button hidden></button>"
                  "<button id=notify-test class=btn type=button hidden>Send a test notification"
                  "</button> <small id=notify-state class=muted></small></p>"
                  "<p class=notify><small id=notify-why class=muted></small></p>"
                  f"<div id=flash class=flash{'' if msg else ' hidden'}>{html.escape(msg)}</div>"
                  "<div id=offline class='flash offline' hidden>Cannot reach the broker (signed out?). "
                  "Reload this page.</div>" + block + panel, wide=True, script=_DASH_JS)

        def _push_panel(self, token):
            rows = []
            for d in broker.push.devices():
                when = time.strftime("%Y-%m-%d", time.gmtime(d["created"] or 0))
                status = ("last delivery OK" if d["last_ok"] else
                          f"last error: {d['last_error']}" if d["last_error"] else "not used yet")
                rows.append(
                    f"<li><span>{html.escape(_agent_label(d['agent']))} "
                    f"<small class=muted>({html.escape(d['user'])}, added {when}, "
                    f"{html.escape(status)})</small></span>"
                    "<form method=post action='/push/revoke' class=inline>"
                    f"<input type=hidden name=id value='{html.escape(d['id'])}'>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    "<button>Remove</button></form></li>")
            test = ("<form method=post action='/push/test' class=inline>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    "<button>Send a test push</button></form>" if rows else "")
            return (
                "<section class=pushpanel><h2>Notifications with the browser closed</h2>"
                "<p><small class=muted>Subscribed devices get a notification even when no tab is "
                "open. The message carries only the secret names; decisions still happen here, "
                "after you sign in.</small></p>"
                f"<p><button id=push-enable class=btn type=button hidden data-key='"
                f"{html.escape(broker.push.public_key())}' data-csrf='{token}'>Enable on this "
                "device</button> <small id=push-state class=muted></small></p>"
                f"<ul class=devices>{''.join(rows) or '<li class=muted>No devices yet.</li>'}</ul>"
                f"{test}</section>")

        def _json(self, code, obj):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _service_worker(self):
            raw = _SERVICE_WORKER.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Service-Worker-Allowed", "/")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def _redirect(self, where):
            self.send_response(303)
            self.send_header("Location", where)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _nonce(self):
            parts = self.path.split("?")[0].strip("/").split("/")
            return parts[1] if len(parts) == 2 and parts[0] == "a" else None

        def _policies_page(self, user, note=""):
            rows = []
            for name, sc in sorted(cfg["secrets"].items()):
                state = sc.get("approval", "prompt")
                by = (sc.get("approval_changed") or {}).get("by")
                btn = ""
                if state == "allow":
                    btn = ("<form method=post>"
                           f"<input type=hidden name=csrf value='{broker.csrf_token(user)}'>"
                           f"<input type=hidden name=name value='{html.escape(name)}'>"
                           "<button name=approval value=prompt>Require approval again</button></form>")
                rows.append(f"<tr><td data-label=Secret><b>{html.escape(name)}</b></td>"
                            f"<td data-label=Policy>{html.escape(state)}"
                            f"{' (set by ' + html.escape(by) + ')' if by and state == 'allow' else ''}</td>"
                            f"<td data-label=''>{btn}</td></tr>")
            _page(self, 200, f"<h1>Standing approvals</h1>{note}<table class=tbl>"
                  "<thead><tr><th>Secret</th><th>Policy</th><th></th></tr></thead><tbody>"
                  + "".join(rows) + "</tbody></table>", wide=True)

        def _history_page(self):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)

            def arg(k):
                return (q.get(k) or [""])[0][:60]
            outcome = arg("outcome") if arg("outcome") in OUTCOMES + ("unknown",) else ""
            secret, mode = arg("secret"), arg("mode") if arg("mode") in ("http", "env", "store") else ""
            try:
                page = max(1, int(arg("page") or 1))
            except ValueError:
                page = 1
            pending = {r.id for r in broker._by_id.values() if r.status == "pending"}
            rows = broker.history.rows(pending, outcome or None, secret or None, mode or None)
            per = 50
            total, rows = len(rows), rows[(page - 1) * per: page * per]

            def opt(vals, cur, label):
                o = "".join(f"<option value='{html.escape(v)}'{' selected' if v == cur else ''}>"
                            f"{html.escape(v)}</option>" for v in vals)
                return f"<option value=''>{label}</option>{o}"
            form = ("<form method=get class=filters>"
                    f"<select name=outcome>{opt(OUTCOMES + ('unknown',), outcome, 'any outcome')}</select> "
                    f"<select name=secret>{opt(broker.history.secrets_seen(), secret, 'any secret')}</select> "
                    f"<select name=mode>{opt(('http', 'env', 'store'), mode, 'any mode')}</select> "
                    "<button>Filter</button></form>")
            body = []
            for r in rows:
                if r["mode"] == "http":
                    what = f"{r['method'] or ''} {r['url'] or ''}"
                elif r["mode"] == "store":
                    what = (f"{r['op'] or 'store'} credential: item {r['item']!r} field {r['field']}"
                            + (f" key {r['key']}" if r.get("key") else ""))
                else:
                    what = "env: value released to the requesting host"
                if r["outcome"] in ("approved", "auto-approved") and not r["delivered"]:
                    label = r["outcome"] + " (not collected)"
                else:
                    label = r["outcome"]
                who = ("policy" if r["via"] == "policy" else
                       (r["approver"] or "")) if r["outcome"] not in ("pending", "expired", "unknown") else ""
                lat = f"{r['latency_ms'] / 1000:.1f}s" if r["latency_ms"] else ""
                note = html.escape(r["error"] or r["summary"] or "")[:200]
                body.append(
                    "<tr>"
                    f"<td data-label=Time>{html.escape(r['time'])}</td>"
                    f"<td data-label=Outcome><span><b>{html.escape(label)}</b>"
                    f"{' (escalated to a prompt)' if r['escalated'] else ''}</span></td>"
                    f"<td data-label=Secret>{html.escape(', '.join(r['names']))}</td>"
                    f"<td data-label=Request><span>{html.escape(what)}<br><small>{note}</small></span></td>"
                    f"<td data-label=Risk>{html.escape(r['risk'] or '')}</td>"
                    f"<td data-label='Decided by'>{html.escape(who)}</td>"
                    f"<td data-label=Took>{lat}</td></tr>")
            nav = ""
            if total > per:
                base = urllib.parse.urlencode({k: v for k, v in
                                               (("outcome", outcome), ("secret", secret), ("mode", mode)) if v})
                prev = f"<a href='?{base}&page={page - 1}'>newer</a>" if page > 1 else ""
                nxt = f"<a href='?{base}&page={page + 1}'>older</a>" if page * per < total else ""
                nav = f"<p class=pager>{prev} {nxt} <span class=muted>{total} requests</span></p>"
            _page(self, 200, "<h1>Request history</h1>" + form
                  + "<table class=tbl><thead><tr><th>Time (UTC)</th><th>Outcome</th><th>Secret</th>"
                  "<th>Request</th><th>Risk</th><th>Decided by</th><th>Took</th></tr></thead><tbody>"
                  + "".join(body) + f"</tbody></table>{nav}"
                  + ("" if body else "<p class=muted>No requests match.</p>"), wide=True)

        def do_GET(self):
            user = self._user()
            if user is None:
                return
            u = urllib.parse.urlsplit(self.path)
            if u.path == "/sw.js" and broker.push is not None:
                return self._service_worker()
            if u.path == "/":
                q = urllib.parse.parse_qs(u.query)
                frag = q.get("fragment", [""])[0] == "1"
                if not frag:
                    broker.log("dashboard_viewed", peer=self.client_address[0], client_ip=self._fwd())
                return self._dashboard(user, fragment=frag, note=(q.get("note") or [""])[0][:12])
            if self.path.split("?")[0].rstrip("/") == "/history":
                broker.log("history_viewed", peer=self.client_address[0], client_ip=self._fwd())
                return self._history_page()
            if self.path.split("?")[0].rstrip("/") == "/policies":
                broker.log("policies_viewed", peer=self.client_address[0], client_ip=self._fwd())
                return self._policies_page(user)
            nonce = self._nonce()
            req = broker._by_nonce.get(nonce) if nonce else None
            broker.log("approval_viewed", user=self.headers.get(
                cfg.get("identity_header", "X-authentik-username"), ""), peer=self.client_address[0],
                client_ip=self._fwd(), request_id=req.id if req else None,
                found=bool(req and req.status == "pending" and time.time() <= req.expires))
            if req is None or req.status != "pending" or time.time() > req.expires:
                return _page(self, 404, "<h1>Request not found or already handled</h1>")
            what, note = _describe(req)
            summary_html = _risk_html(req)
            ok, why = broker.always_allow_eligibility(req)
            if ok:
                always_html = (
                    "<p><button class=btn name=decision value=approve_always>"
                    f"Approve and always allow {html.escape(req.names[0])}</button><br><small>"
                    "Future HTTP calls with this secret will run without asking, except requests "
                    "rated high risk. Revoke any time at /policies.</small></p>")
            else:
                always_html = f"<p><small>Always allow not offered: {html.escape(why)}.</small></p>"
            _page(self, 200, f"""
<h1>Secret request</h1>
<p><b>{html.escape(', '.join(req.names))}</b></p>
{summary_html}
<div class=box>From: {html.escape(req.source)}<br>{what}</div>
<p><small>{note}</small></p>
<p><small>Expires in {int(req.expires - time.time())}s</small></p>
<form method=post id=f>
<div class=actions>
<button class='btn approve' name=decision value=approve>Approve</button>
<button class='btn deny' name=decision value=deny>Deny</button>
</div>
{always_html}
</form>
<p id=w hidden>Working...</p>""", script=_WORKING_JS)

        def _push_post(self, path, form, user):
            peer, fwd = self.client_address[0], self._fwd()
            if broker.push is None:
                return self._json(404, {"ok": False})
            if path == "/push/subscribe":
                try:
                    sid = broker.push.add(user, form.get("endpoint", [""])[0],
                                          form.get("p256dh", [""])[0], form.get("auth", [""])[0],
                                          self.headers.get("User-Agent", ""))
                except ValueError as e:
                    broker.log("push_refused", user=user, reason=str(e)[:80], peer=peer,
                               client_ip=fwd)
                    return self._json(400, {"ok": False, "error": str(e)[:80]})
                broker.log("push_subscribed", user=user, device=sid, peer=peer, client_ip=fwd)
                return self._json(200, {"ok": True})
            if path == "/push/revoke":
                gone = broker.push.remove(form.get("id", [""])[0])
                broker.log("push_revoked", user=user, device=form.get("id", [""])[0][:16],
                           removed=gone, peer=peer, client_ip=fwd)
                return self._redirect("/?note=push_removed")
            if path == "/push/test":
                ok, errors = broker.push.send_all({"title": "Test notification",
                                                   "body": "Push notifications work on this device.",
                                                   "tag": "test"})
                broker.log("push_test", user=user, delivered=ok, errors=errors[:3], peer=peer,
                           client_ip=fwd)
                return self._redirect("/?note=" + ("push_test_ok" if ok else "push_failed"))
            return self._json(404, {"ok": False})

        def do_POST(self):
            user = self._user()
            if user is None:
                return
            form = urllib.parse.parse_qs(
                self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 8192)).decode())
            path = self.path.split("?")[0].rstrip("/")
            if path in ("/decide", "/policies", "/push/subscribe", "/push/revoke",
                        "/push/test") and not self._csrf_ok(user, form.get("csrf", [""])[0]):
                broker.log("csrf_refused", path=path, peer=self.client_address[0],
                           client_ip=self._fwd(), origin=(self.headers.get("Origin") or "")[:80],
                           fetch_site=self.headers.get("Sec-Fetch-Site"))
                return _page(self, 403, "<h1>Forbidden</h1><p>Reload the page and try again.</p>")
            if path.startswith("/push/"):
                return self._push_post(path, form, user)
            if path == "/decide":
                rid = form.get("id", [""])[0]
                decision = form.get("decision", [""])[0]
                r = broker._by_id.get(rid)
                if decision not in ("approve", "deny", "approve_always") or r is None:
                    return self._redirect("/?note=stale")
                done = broker.decide(r.nonce, decision != "deny", user, self.client_address[0],
                                     self._fwd(), always=(decision == "approve_always"),
                                     channel="dashboard")
                if done is None:
                    return self._redirect("/?note=stale")
                tag = ("denied" if decision == "deny" else
                       "always" if done.always == "applied" else "approved")
                return self._redirect(f"/?note={tag}")
            if self.path.split("?")[0].rstrip("/") == "/policies":
                name = form.get("name", [""])[0]
                # this page can only *tighten*: granting happens in the context of a request
                if form.get("approval", [""])[0] != "prompt" or name not in cfg["secrets"]:
                    return _page(self, 400, "<h1>Bad request</h1>")
                done = broker.set_approval(name, "prompt", user, self.client_address[0], self._fwd())
                return self._policies_page(
                    user, f"<p>{'Updated' if done else 'Could not update'}: {html.escape(name)}</p>")
            nonce = self._nonce()
            decision = form.get("decision", [""])[0]
            approve = decision in ("approve", "approve_always")
            req = (broker.decide(nonce, approve, user, self.client_address[0], self._fwd(),
                                 always=(decision == "approve_always"))
                   if nonce else None)
            if req is None:
                return _page(self, 404, "<h1>Request not found or already handled</h1>")
            if not approve:
                return _page(self, 200, "<h1>Denied</h1>")
            extra = ""
            if req.always == "applied":
                extra = (f"<p>Always allow saved for <b>{html.escape(req.names[0])}</b>. "
                         "Revoke it at <a href='/policies'>/policies</a>.</p>")
            elif req.always:
                extra = f"<p><small>Always allow {html.escape(req.always)}.</small></p>"
            _page(self, 200, "<h1>Approved</h1><p>Releasing now. You can close this page.</p>" + extra)

    return H


def serve(broker, client_addr, approval_addr, client_key):
    c = ThreadingHTTPServer(client_addr, client_handler(broker, client_key))
    a = ThreadingHTTPServer(approval_addr, approval_handler(broker))
    for s in (c, a):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return c, a
