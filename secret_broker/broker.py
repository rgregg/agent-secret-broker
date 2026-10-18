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
from . import audit_api
from . import notify as notify_mod
from .notify import NotifyError
from . import grants as grants_mod
from . import risk as risk_mod
from . import sshkey
from . import structured
from .history import History, OUTCOMES

MAX_PENDING = 3
DENY_COOLDOWN = 60
HIST_RECENT, HIST_PAGE, HIST_MAX = 8, 25, 500   # history rows: collapsed, per page, ceiling
MAX_RESPONSE_BYTES = 1_000_000
MAX_REQUEST_BYTES = 8_000_000
MAX_STORE_VALUE = 65_536
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,60}$")
# Variable names that change how a process loads code or resolves commands: a
# secret exposed under one of these in env mode would be a code-execution primitive.
_DANGEROUS_VAR_RE = re.compile(
    r"^(LD_.*|DYLD_.*|PYTHON.*|NODE_.*|GIT_.*|PERL.*|RUBY.*|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|"
    r"PATH|BASH_ENV|ENV|IFS|PS4|PROMPT_COMMAND|SHELL|HOME|CDPATH|GCONV_PATH|HOSTALIASES|"
    r"LOCPATH|NLSPATH|MALLOC_.*|TMPDIR|SSH_ASKPASS|EDITOR|VISUAL|PAGER|"
    r"CLASSPATH|JDK_JAVA_OPTIONS|OPENSSL_.*|SSL_CERT_.*|REQUESTS_CA_BUNDLE|CURL_.*|DOCKER_.*|"
    r"KUBECONFIG|.*_PROXY|SHELLOPTS|BASHOPTS|ZDOTDIR|SUDO_ASKPASS|BROWSER|LESS.*|SECRET_BROKER_.*)$")
_FIELD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .-]{0,59}$")
_ITEM_RE = re.compile(r"^[^\x00-\x1f]{1,100}$")
APPROVAL_VALUES = ("prompt", "allow")


class Channel:
    """How a decision may arrive. Every decision goes through Broker.decide_via;
    the channel only says what that entry must enforce for it. The caller of
    decide_via is responsible for the channel's own authentication (SSO header,
    CSRF / same-origin guards, ...)."""

    def __init__(self, token_required, may_create_always, may_create_grant=False):
        self.token_required = token_required        # must present the request's action token
        self.may_create_always = may_create_always  # may create an always-allow rule
        self.may_create_grant = may_create_grant    # may create a time-boxed grant


# Registry of decision channels; the key is the `channel` audit field.
CHANNELS = {
    "dashboard": Channel(token_required=False, may_create_always=True,
                         may_create_grant=True),                          # POST /decide
    "link": Channel(token_required=False, may_create_always=True,
                    may_create_grant=True),                               # POST /a/<nonce>
    "push": Channel(token_required=True, may_create_always=False),        # POST /push/decide
    "ha": Channel(token_required=True, may_create_always=False),          # POST /v1/hooks/ha/decide
}


class Request:
    def __init__(self, mode, names, spec, source, ttl, peer=None):
        self.id = secrets.token_urlsafe(16)
        self.nonce = secrets.token_urlsafe(24)
        self.mode = mode          # "env" | "http" | "store" | "ssh_sign"
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
        self.summary_model = None  # model that wrote the summary (None: unknown)
        self.summary_source = None  # "model", "deterministic" or None
        self.risk = None          # {"level","model","reasons"}
        self.always = None        # outcome of an "always allow" click, if any
        self.approver = None
        self.action_hash = None   # sha256 of the push-button token; None once spent
        self.notification = None  # the Notification sent for this request
        self.offered = frozenset()  # action ids offered on any token-carrying transport
        self.done = threading.Event()


class Broker:
    def __init__(self, config, backend, notifier, audit=None, summarizer=None,
                 background_load=False, push=None):
        self.push = push                # PushStore when the webpush transport is configured
        self.cfg = config
        self.cfg["secrets"] = {}        # the catalog lives in the vault; see refresh_catalog()
        self._catalog_at = 0.0
        self._catalog_sig = None
        self._started_at = time.time()
        self._catalog_stats = {"count": 0, "invalid": 0, "adopted": 0, "loaded_at": None}
        self._backend_ok = True         # False while the last vault read failed
        self._refreshing = threading.Lock()
        self._cfg_lock = threading.Lock()
        self.summarizer = summarizer
        self.backend = backend
        self.notifier = notifier            # property: adapts legacy transports
        self.action_policy = notify_mod.parse_action_policy(
            config.get("notify_actions"), "notify_actions")
        self._audit = audit if isinstance(audit, AuditLog) else AuditLog(audit)
        self.ha_hook = notify_mod.parse_ha_hook(
            config.get("ha_hook"), lambda p: open(p).read().strip())
        self._ha_rate = {}              # source ip -> {"t", "n", "drop"}; <= RATE_MAP_CAP
        self._ha_unauth = {"t": 0.0, "n": 0, "drop": 0}   # shared bad-key bucket
        self._ha_rate_lock = threading.Lock()
        if self.ha_hook is not None and not self.ha_hook["allowed_devices"]:
            self.log("ha_hook_any_device", warning="ha_hook.allowed_devices is empty: "
                     "any device id is accepted (it is recorded, not verified)")
        self.history = History(self._audit._path)
        self._csrf_key = secrets.token_bytes(32)    # per process: tokens die with a restart
        self._lock = threading.Lock()
        self._by_id = {}
        self._by_nonce = {}
        self._denied_at = {}
        if hasattr(backend, "on_event"):
            backend.on_event = self.log
        self._auto_max, warn = risk_mod.parse_auto_approve_max(config.get("risk"), "risk")
        if warn:
            self.log("config_warning", warning=warn)
        self._init_grants(config)
        if background_load:
            # Listen right away; the first requests wait on the same lock.
            self._refreshing.acquire()
            threading.Thread(target=self._initial_load, daemon=True).start()
        else:
            self._initial_load(locked=False)

    @property
    def notifier(self):
        return self._notifier

    @notifier.setter
    def notifier(self, value):
        self._notifier = notify_mod.adapt(value)    # signature detection happens once, here

    def _initial_load(self, locked=True):
        try:
            try:
                self.refresh_catalog()
            except Exception as e:  # noqa: BLE001 -- start anyway; requests retry the load
                self._backend_ok = False
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
        ssh = meta.get("ssh", False)
        if not isinstance(ssh, bool):
            raise ValueError("ssh must be true or false")
        if ssh:
            if len(raw_vars) != 1:
                raise ValueError("an ssh key secret has exactly one variable (the private key)")
            try:
                sshkey.blob_from_line(str(meta.get("ssh_public_key") or ""))
            except sshkey.SshKeyError:
                raise ValueError("an ssh key secret needs ssh_public_key (ssh-ed25519 AAAA...)") from None
            ref0 = next(iter(raw_vars.values()))
            if (ref0 if isinstance(ref0, dict) else {}).get("field", "auto") not in ("private_key", "auto"):
                raise ValueError("an ssh key secret's variable must use the private_key field")
        vars_ = {}
        for var, ref in raw_vars.items():
            ref = ref if isinstance(ref, dict) else {}
            if not _VAR_RE.match(var):
                raise ValueError(f"bad variable name {var!r}")
            if _DANGEROUS_VAR_RE.match(var):
                raise ValueError(f"variable name {var!r} is reserved (it changes how processes run)")
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

    @staticmethod
    def _auto_meta(item, info):
        """Defaults for an item that has no broker metadata (copied or created in
        a vault client): hosts from its login URLs, one variable per usable field,
        approval on every use. None if there is nothing to expose."""
        base = re.sub(r"[^A-Z0-9]+", "_", item.upper()).strip("_")[:30]
        if not base or not base[0].isalpha():
            base = "ITEM_" + base
        vars_ = {}
        if info.get("username"):
            vars_[f"{base}_USERNAME"] = {"field": "username"}
        if info.get("password"):
            vars_[f"{base}_PASSWORD"] = {"field": "password"}
        if info.get("notes") and not info.get("login"):
            vars_[f"{base}_NOTE"] = {"field": "notes"}
        for f in info.get("fields") or []:
            v = f"{base}_" + re.sub(r"[^A-Z0-9]+", "_", f.upper()).strip("_")
            if _VAR_RE.match(v):
                vars_[v] = {"field": f}
        hosts = []
        for uri in info.get("uris") or []:
            host = urllib.parse.urlsplit(uri if "//" in uri else "//" + uri).hostname
            if host and _HOST_RE.match(host) and host.lower() not in hosts:
                hosts.append(host.lower())
        if info.get("ssh_public_key"):
            # a Bitwarden SSH key item: only ever usable to sign, never released
            return {"allowed_hosts": [], "vars": {f"{base}_SSH_KEY": {"field": "private_key"}},
                    "approval": "prompt", "ssh": True, "ssh_public_key": info["ssh_public_key"]}
        if not vars_:
            return None
        return {"allowed_hosts": hosts[:10], "vars": vars_, "approval": "prompt"}

    def refresh_catalog(self):
        """Rebuild the secret catalog from the vault's items. Raises if the vault
        cannot be read, leaving the previous catalog in place."""
        if not hasattr(self.backend, "catalog"):
            return
        rows = self.backend.catalog()
        out, bad, owners, autos = {}, [], {}, []
        for row in rows:
            if row.get("auto") is not None:
                autos.append(row)
                continue
            if isinstance(row["meta"], dict) and row["meta"].get("disabled") is True:
                continue                               # hidden from the broker on purpose
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
        # Items with no metadata are adopted with defaults, but an explicitly
        # configured secret always wins a name (so a stray copy cannot shadow it),
        # and two adopted items with the same name drop each other.
        adopted, claims = {}, {}
        for row in autos:
            meta = self._auto_meta(row["item"], row["auto"])
            try:
                name, entry = self._entry(row["item"], meta) if meta else (None, None)
            except ValueError as e:
                bad.append({"item": row["item"], "reason": str(e)[:120]})
                continue
            if name is None or name in out:
                continue
            entry["auto"] = True
            adopted[name] = entry
            claims.setdefault(name, []).append(row["item"])
        for name, items in claims.items():
            if len(items) > 1:
                adopted.pop(name, None)
                bad.extend({"item": i, "reason": f"duplicate secret name {name!r}"} for i in items)
        out.update(adopted)
        with self._cfg_lock:
            self.cfg["secrets"] = out
            self._catalog_at = time.time()
            self._backend_ok = True
            self._catalog_stats = {"count": len(out), "invalid": len(bad), "adopted": len(adopted),
                                   "loaded_at": _iso(self._catalog_at)}
        sig = json.dumps([sorted(out), bad], sort_keys=True)
        if sig != self._catalog_sig:
            self._catalog_sig = sig
            self.log("catalog_loaded", count=len(out), names=sorted(out), invalid=bad,
                     adopted=sorted(adopted))

    def status(self):
        """Deploy-verification summary for GET /v1/status. Counts and type names
        only: no secret names, hosts, keys or config values. Reads in-memory state
        and never touches the vault."""
        specs = self.cfg.get("notify")
        kinds = ([sp.get("type") for sp in specs] if specs is not None
                 else (["ticker"] if self.cfg.get("ha_url") else []))
        notifiers = sorted({k for k in kinds if k in ("ticker", "telegram", "webpush")})
        bname = type(self.backend).__name__
        btype = "bw" if bname.startswith("Bw") else "file" if bname == "FileBackend" else "local"
        now = time.time()
        with self._cfg_lock:
            stats = dict(self._catalog_stats)
            has_ssh = any(sc.get("ssh") for sc in self.cfg["secrets"].values())
        return {
            "version": os.environ.get("BROKER_GIT_SHA") or "unknown",
            "build_time": os.environ.get("BROKER_BUILD_TIME") or "unknown",
            "started_at": _iso(self._started_at),
            "uptime_s": int(now - self._started_at),
            "catalog": stats,
            "backend": {"type": btype, "ok": bool(self._backend_ok)},
            "notifiers": notifiers,
            "features": {"ha_hook": self.ha_hook is not None, "ssh": has_ssh,
                         "webpush_actions": "webpush" in notifiers and self.push is not None,
                         "auto_approve_max": self._auto_max,
                         "timed_grants": bool(self.grants_cfg["enabled"])},
        }

    def _refresh_if(self, stale_after, wait=True):
        if time.time() - self._catalog_at <= stale_after:
            return
        if not self._refreshing.acquire(blocking=wait):
            return
        try:
            if time.time() - self._catalog_at > stale_after:
                self.refresh_catalog()
        except Exception as e:  # noqa: BLE001 -- keep serving the last good catalog
            self._backend_ok = False
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
            if req.summary_model:
                rec["summary_model"] = req.summary_model
        if req.risk:
            rec["risk"] = req.risk["level"]
        if req.mode == "http":
            rec["method"], rec["url"] = req.spec["method"], req.spec["url"]
        elif req.mode == "store":
            sp = req.spec
            rec.update(op=sp.get("op"), item=sp.get("item"), field=sp.get("field"), key=sp.get("key"),
                       hosts=sp.get("allowed_hosts"), value_bytes=sp.get("value_bytes"))
        elif req.mode == "ssh_sign":
            sp = req.spec
            rec.update(ssh_kind=sp["ssh"]["kind"], ssh_what=sp["ssh"]["text"],
                       ssh_fingerprint=sp.get("fingerprint"), sign_bytes=sp.get("data_bytes"))
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
        if req.risk:
            lvl = req.risk["level"]
            if lvl == "high" or not risk_mod.auto_ok(lvl, self._auto_max):
                return False, f"this request is rated {lvl}; such requests always prompt"
        return True, ""

    def auto_approve_max(self):
        """Highest risk level at which an auto-eligible request is released
        unprompted: none|low|medium|high (default low; see risk.auto_approve_max).
        A missing model verdict counts as high."""
        return self._auto_max

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
                if sc.get("ssh"):
                    # not usable as a {{VAR}}: only `asb ssh-agent` signs with it
                    out.append({"name": name, "vars": [], "allowed_hosts": hosts,
                                "ssh_public_key": sc["ssh_public_key"]})
                    continue
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
                if mode == "ssh_sign":
                    self._validate_ssh_sign(names, spec)
                elif any(secrets_cfg[n].get("ssh") for n in names):
                    raise PermissionError("an ssh key can only be used to sign (asb ssh-agent), "
                                          "never released or placed in a request")
                seen = {}
                for n in dict.fromkeys(names):
                    for var in secrets_cfg[n]["vars"]:
                        if seen.setdefault(var, n) != n:
                            raise ValueError(f"{seen[var]} and {n} both define {var}; request them separately")
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
        req.summary_model = a.get("summary_model") if a.get("summary_source") != "deterministic" else None
        req.summary_source = a.get("summary_source")
        self.audit("assessed", req, model=a["model"], reasons=a["reasons"],
                   summary_source=a.get("summary_source"), summary_reason=a.get("summary_reason"))
        auto = self._auto_allowed(mode, names, spec)
        auto_max = self._auto_max
        if not auto and self._grant_claim(req):
            return req
        if auto and not risk_mod.auto_ok(a["level"], auto_max):
            why = ("auto-approve is off (risk.auto_approve_max none)" if auto_max == "none" else
                   f"risk {a['level']} is above auto_approve_max {auto_max}")
            self.audit("escalated", req, auto_max=auto_max, reason=f"{why}; policy allow overridden")
            auto = False
        if auto:
            if mode == "store":
                req.approver = "policy:auto-create"
            try:
                result = self._release(req)
            except (BackendError, OSError, ValueError) as e:
                self._finish(req, "failed", error=f"release failed: {e}", via="policy",
                             auto_max=auto_max)
            else:
                self._finish(req, "approved", result=result, via="policy", auto_max=auto_max)
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
        if spec.get("ssh") and op == "create":
            try:
                spec["ssh_public_key"] = sshkey.public_line(sshkey.load_private(value))
            except sshkey.SshKeyError as e:
                raise ValueError(str(e)) from None
            spec["allowed_hosts"] = spec.get("allowed_hosts") or []
        elif spec.get("ssh"):
            raise ValueError("--ssh applies when creating a credential; an update keeps its type")
        if op == "update" and secrets_cfg.get(name, {}).get("ssh"):
            try:
                same = sshkey.public_line(sshkey.load_private(value)) == secrets_cfg[name]["ssh_public_key"]
            except sshkey.SshKeyError as e:
                raise ValueError(str(e)) from None
            if not same:
                raise ValueError("the new key has a different public key; store it as a new credential")
        if op == "create":
            if name in secrets_cfg:
                raise ValueError(f"{name} already exists; use update")
            if not hasattr(self.backend, "catalog"):
                raise PermissionError("this vault backend has no secret catalog")
            hosts = spec.get("allowed_hosts")
            if (not isinstance(hosts, list) or not (0 if spec.get("ssh") else 1) <= len(hosts) <= 10
                    or not all(isinstance(h, str) and _HOST_RE.match(h) for h in hosts)):
                raise ValueError("allowed_hosts must be 1-10 plain hostnames")
            spec["allowed_hosts"] = sorted(set(h.lower() for h in hosts))
            spec["field"] = spec.get("field") or ("private_key" if spec.get("ssh") else "notes")
            if spec.get("ssh") and spec["field"] != "private_key":
                raise ValueError("an ssh key is stored in an SSH key item (field private_key)")
            spec["item"] = spec.get("item") or name
            spec["var"] = spec.get("var") or re.sub(r"[^A-Za-z0-9]", "_", name).upper() + (
                "_SSH_KEY" if spec.get("ssh") else "_TOKEN")
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

    def _validate_ssh_sign(self, names, spec):
        if len(names) != 1 or not self.cfg["secrets"][names[0]].get("ssh"):
            raise ValueError("ssh signing needs exactly one ssh key secret")
        try:
            data = base64.b64decode(spec.get("data_b64") or "", validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("data_b64 is not valid base64") from None
        if not data or len(data) > sshkey.MAX_SIGN_DATA:
            raise ValueError(f"data must be 1-{sshkey.MAX_SIGN_DATA} bytes")
        flags = spec.get("flags", 0)
        if not isinstance(flags, int) or isinstance(flags, bool) or not 0 <= flags < 64:
            raise ValueError("bad flags")
        sc = self.cfg["secrets"][names[0]]
        spec["data"], spec["flags"] = data, flags
        spec["data_bytes"] = len(data)
        spec["ssh"] = sshkey.describe_data(data)
        spec["fingerprint"] = sshkey.fingerprint(sshkey.blob_from_line(sc["ssh_public_key"]))

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
        elif req.mode == "ssh_sign":
            what = f"SSH key {req.spec['fingerprint']}: {req.spec['ssh']['text']}"
        else:
            what = "run: " + " ".join(req.spec.get("argv") or [])[:200]
        head = f"{req.summary} (unverified)\n" if req.summary else ""
        why = f"\nWhy: {'; '.join(req.risk['reasons'][:3])}" if req.risk and req.risk["reasons"] else ""
        msg = f"{head}{', '.join(req.names)} from {req.source}\n{what}{why}"
        title = f"Secret request [{req.risk['level'].upper()}]" if req.risk else "Secret request"
        n = notify_mod.make_notification(
            rid=req.id, tag=f"secret-{req.id[:8]}", title=title, text=msg, names=req.names,
            risk=req.risk["level"] if req.risk else None, url=url, source=req.source,
            summary=req.summary, expires_at=req.expires, transport=self.notifier,
            default_policy=self.action_policy)
        req.notification = n
        # The token is shared by every transport, so what it may do is the UNION
        # of the actions offered anywhere (per-transport narrowing is not tracked).
        req.offered = frozenset(a.id for a in n.actions) if n.action_token else frozenset()
        if n.action_token:                          # only its hash is kept
            req.action_hash = hashlib.sha256(n.action_token.encode()).digest()
        try:
            self.notifier.send(n)
        except BaseException:
            req.action_hash = None
            raise
        self.audit("notified", req)

    def _resolved(self, req, status):
        """Tell the transport the request is settled (e.g. edit the chat message)."""
        fn = getattr(self.notifier, "resolved", None)
        if fn is None or req.mode is None:
            return
        n = req.notification or notify_mod.Notification(
            rid=req.id, tag=f"secret-{req.id[:8]}", title="", text="", names=list(req.names),
            risk=req.risk["level"] if req.risk else None, url="", source=req.source,
            summary=req.summary, expires_at=req.expires)

        def run():
            try:
                fn(n, status)
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

    HA_LIMIT_PER_MIN = 60
    RATE_MAP_CAP = 4096     # hard bound on every per-IP / per-user limiter map

    HA_UNAUTH_LIMIT_PER_MIN = 120   # ONE shared bucket for all missing/wrong-key hook requests

    @staticmethod
    def rate_map_make_room(m, now, window=60):
        """Make room for one NEW key in limiter map `m` without ever refusing
        it: when at RATE_MAP_CAP, prune expired entries, and if still full
        evict the entry with the oldest window start. Call with the map's lock
        held."""
        if len(m) >= Broker.RATE_MAP_CAP:
            for k in [k for k, v in m.items() if now - v["t"] >= window]:
                del m[k]
            while len(m) >= Broker.RATE_MAP_CAP:
                del m[min(m, key=lambda k: m[k]["t"])]

    def ha_rate_ok(self, ip):
        """Fixed-window limit on the Home Assistant hook, per source IP. Only
        called for requests that presented the correct hook key. The first drop
        in a window is audited."""
        now = time.time()
        with self._ha_rate_lock:
            st = self._ha_rate.get(ip)
            if st is None:
                self.rate_map_make_room(self._ha_rate, now)
                st = self._ha_rate[ip] = {"t": now, "n": 0, "drop": 0}
            if now - st["t"] >= 60:
                st.update(t=now, n=0, drop=0)
            st["n"] += 1
            if st["n"] <= self.HA_LIMIT_PER_MIN:
                return True
            st["drop"] += 1
            first = st["drop"] == 1
        if first:
            self.log("ha_decide_dropped", peer=ip, limit_per_min=self.HA_LIMIT_PER_MIN)
        return False

    def ha_unauth_ok(self, ip):
        """Shared fixed-window limit for hook requests with a missing/wrong key.
        Creates no per-source state, so bad-key traffic cannot fill or churn the
        per-IP map or starve the authenticated caller. First drop per window is
        audited."""
        now = time.time()
        with self._ha_rate_lock:
            st = self._ha_unauth
            if now - st["t"] >= 60:
                st.update(t=now, n=0, drop=0)
            st["n"] += 1
            if st["n"] <= self.HA_UNAUTH_LIMIT_PER_MIN:
                return True
            st["drop"] += 1
            first = st["drop"] == 1
        if first:
            self.log("ha_decide_dropped", peer=ip, limit_per_min=self.HA_UNAUTH_LIMIT_PER_MIN,
                     unauthenticated=True)
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

    def decide_via(self, channel, rid, decision, actor, *, token=None, always=False,
                   nonce=None, peer=None, client_ip=None, grant_minutes=None, **audit_extra):
        """The single entry for every decision. Returns (http_status, req):
        200 decided; 403 wrong/missing token; 404 unknown; 410 already decided,
        expired or token spent (no state change). `decision` is "approve" or
        "deny". Enforced here and nowhere else: the single-decision claim, the
        token check (constant time; spent on match, and it dies with any
        decision), no always-allow rule from channels that may not create one,
        and the audit fields. The request is found by `rid`, or by `nonce` (the
        approval-link channel), or, for token channels with neither, by the
        token alone. Channel authentication (SSO header, CSRF, origin guards)
        is the caller's job. Unknown channel or decision raises ValueError."""
        ch = CHANNELS.get(channel)
        if ch is None:
            raise ValueError(f"unknown decision channel {channel!r}")
        if decision not in ("approve", "deny"):
            raise ValueError("decision must be approve or deny")
        approve = decision == "approve"
        always = bool(always and approve and ch.may_create_always)
        grant_minutes = grant_minutes if (approve and ch.may_create_grant) else None
        if grant_minutes is not None and not self.grant_minutes_ok(grant_minutes):
            return 400, None            # unknown duration: nothing is claimed or changed
        check = ch.token_required or token is not None
        digest = hashlib.sha256((token or "").encode()).digest()
        stale_log, refused_log, code, req = False, False, None, None
        unoffered = None
        with self._lock:
            self._expire_locked()
            if nonce is not None:
                cands = [r for r in [self._by_nonce.get(nonce)] if r is not None]
                if not cands or cands[0].status != "pending":
                    code, stale_log = 404 if not cands else 410, True
            elif rid:
                r = self._by_id.get(rid)
                if r is None:
                    code, cands = 404, []
                elif r.status != "pending":
                    code, cands, stale_log = 410, [], not check
                else:
                    cands = [r]
            elif check:
                cands = [r for r in self._by_id.values() if r.status == "pending"]
            else:
                code, cands = 404, []
            if code is None:
                if check:
                    match = None
                    for r in cands:
                        if r.action_hash is not None and hmac.compare_digest(r.action_hash, digest):
                            match = r
                    if match is None:
                        code, refused_log = (403 if cands else 410), True
                    elif ch.token_required and decision not in match.offered:
                        # Token is valid but this action was never offered (action
                        # policy): refuse like a bad token and do NOT spend it.
                        code, refused_log, unoffered = 403, True, match
                    else:
                        match.action_hash = None        # spent, whatever happens next
                        req = match
                else:
                    req = cands[0]
                if req is not None:
                    req.status = "deciding"     # claim it: a second submit must not also act
        if req is None:
            if unoffered is not None:
                self.audit("decision_refused", unoffered, channel=channel, decision=decision,
                           reason="action not offered", approver=actor, approver_peer=peer,
                           approver_ip=client_ip)
            if refused_log:
                self.log(f"{channel}_decide_refused", user=actor, peer=peer, client_ip=client_ip,
                         status=code)
            elif stale_log:
                self.log("approval_stale", user=actor, peer=peer, client_ip=client_ip,
                         approve=approve)
            return code, None
        who = {"via": "user", "approver": actor, "approver_peer": peer, "approver_ip": client_ip,
               "channel": channel}
        who.update(audit_extra)
        if grant_minutes is not None:
            who["grant_minutes"] = grant_minutes
        req.approver = actor
        req.action_hash = None           # a push-button token dies with the decision
        # The decision itself is recorded and announced immediately.
        self.audit("decided", req, decision=decision, always_requested=always, **who)
        if not approve:
            self._finish(req, "denied", **who)
            return 200, req
        if always:
            ok, why = self.always_allow_eligibility(req)
            if not ok:
                req.always = f"not applied: {why}"
                self.audit("policy_change_refused", req, reason=why, **who)
            elif self.set_approval(req.names[0], "allow", actor, peer, client_ip, req.id):
                req.always = "applied"
            else:
                req.always = "not applied: could not write the config file"
        if grant_minutes is not None:
            self._grant_create(req, grant_minutes, actor, channel, who)
        self._resolved(req, "approved")
        # Releasing can take seconds (vault unlock, upstream call). It runs off
        # the request thread: the approver's page has already been answered, the
        # result reaches the client through its poll, and any failure is audited
        # and surfaced to the client, never to the approver.
        threading.Thread(target=self._release_and_finish, args=(req, who), daemon=True).start()
        return 200, req

    # -- time-boxed grants (see grants.py) ----------------------------------
    def _init_grants(self, config):
        self.grants_cfg = grants_mod.parse_config(config.get("timed_grants"))
        apath = self._audit._path
        gpath = os.path.join(os.path.dirname(os.path.abspath(apath)), "grants.json") if apath else None
        self.grants = grants_mod.GrantStore(gpath, self.log, clock=lambda: time.time(),
                                            max_minutes=self.grants_cfg["max_minutes"])
        if self.grants_cfg["enabled"]:      # disabled: any persisted grants are ignored
            self.grants.load()
            threading.Thread(target=self._grant_sweeper, daemon=True).start()

    def _grant_sweeper(self):
        while True:
            time.sleep(15)
            try:
                self.grants.sweep()         # audits grant_expired
            except Exception:  # noqa: BLE001 -- never let the sweeper die
                pass

    def grant_minutes_ok(self, minutes):
        c = self.grants_cfg
        return (c["enabled"] and isinstance(minutes, int) and not isinstance(minutes, bool)
                and minutes in c["durations"] and 0 < minutes <= c["max_minutes"])

    def grant_durations(self):
        """Minutes offered on the approval card; empty when grants are off."""
        return list(self.grants_cfg["durations"]) if self.grants_cfg["enabled"] else []

    def grant_eligibility(self, req):
        """(ok, reason): whether an approval of `req` may also create grants."""
        if not self.grants_cfg["enabled"]:
            return False, "time-boxed grants are off"
        if req.mode not in grants_mod.ELIGIBLE_MODES:
            return False, ("env-mode requests release the value to the requesting host"
                           if req.mode == "env" else "storing a credential always needs a fresh approval")
        return True, ""

    def active_grants(self):
        """Active grants (with seconds left) for the Policies page."""
        if not self.grants_cfg["enabled"]:
            return []
        return [{**g, "left_s": self.grants.left_s(g)} for g in self.grants.active()]

    def _grant_create(self, req, minutes, actor, channel, who):
        ok, why = self.grant_eligibility(req)
        if not ok:
            self.audit("grant_refused", req, reason=why, **who)
            return
        g = self.grants.add(req.names, minutes, grants_mod.scope_for(req.mode, req.spec), actor,
                            channel, req.id)
        self.audit("grant_created", req, grant_id=g["id"], scope=g["scope"], grant_minutes=minutes,
                   expires_at=g["expires_at"], created_by=actor, channel=channel,
                   approver_peer=who.get("approver_peer"), approver_ip=who.get("approver_ip"))

    def _grant_claim(self, req):
        """Approve `req` from active grants when every secret has one. Called from
        create() for requests no policy already approved. Returns True when the
        request was claimed and finished here. Checked and claimed under the
        decision lock, so a human decision and a grant never both act."""
        cfg = self.grants_cfg
        if not cfg["enabled"] or req.mode not in grants_mod.ELIGIBLE_MODES:
            return False
        level = req.risk["level"] if req.risk else "high"     # no verdict counts as high
        with self._lock:
            g = self.grants.find(req.names)
            if g is None:
                return False
            skip = None
            if not grants_mod.covers(g, req.mode, req.spec):
                skip = "method"
            elif not risk_mod.auto_ok(level, cfg["max_risk"]):
                skip = "risk"
            elif req.status != "pending":
                return False
            else:
                req.status = "deciding"
        if skip:
            self.audit("grant_skipped", req, reason=skip, grant_id=g["id"], scope=g["scope"],
                       risk_level=level, max_risk=cfg["max_risk"])
            return False
        left = self.grants.left_s(g)
        self.audit("grant_used", req, grant_id=g["id"], scope=g["scope"], grant_left_s=left)
        try:
            result = self._release(req)
        except (BackendError, OSError, ValueError) as e:
            self._finish(req, "failed", error=f"release failed: {e}", via="policy",
                         grant_id=g["id"], grant_left_s=left)
        else:
            self._finish(req, "approved", result=result, via="policy",
                         grant_id=g["id"], grant_left_s=left)
        return True

    def revoke_grant(self, grant_id, user, peer=None, client_ip=None):
        """End a grant early. Returns True when it was active."""
        g = self.grants.revoke(grant_id) if self.grants_cfg["enabled"] else None
        if g is None:
            return False
        self.log("grant_revoked", grant_id=g["id"], secrets=g["secrets"], scope=g["scope"],
                 created_by=g["created_by"], revoked_by=user, left_s=max(0, int(g["expires_at"] - time.time())), peer=peer,
                 client_ip=client_ip)
        return True

    def decide_push(self, rid, token, approve, user, peer=None, client_ip=None):
        """Decision from a browser notification button: decide_via on the
        `push` channel. Returns (http_status, req)."""
        return self.decide_via("push", rid, "approve" if approve else "deny", user,
                               token=token or "", peer=peer, client_ip=client_ip)

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
            if sp.get("ssh"):
                meta.update(ssh=True, ssh_public_key=sp["ssh_public_key"])   # item type 5 in Bitwarden
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
        if req.mode == "ssh_sign":
            return self._ssh_sign(req)
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

    def _ssh_sign(self, req):
        name = req.names[0]
        sc = self.cfg["secrets"].get(name)
        if sc is None or not sc.get("ssh"):
            raise BackendError(f"{name} is no longer an ssh key in the vault catalog")
        (var, ref), = sc["vars"].items()
        pem = self.backend.get(ref["item"], ref.get("field") or "auto")
        self.audit("secret_read", req, secret=name, vars=[var])
        try:
            key = sshkey.load_private(structured.get(pem, ref["key"]) if ref.get("key") else pem)
            if sshkey.public_line(key) != sc["ssh_public_key"]:
                raise BackendError(f"{name}: the vault key no longer matches ssh_public_key")
            sig = sshkey.sign(key, req.spec["data"], req.spec["flags"])
        except (sshkey.SshKeyError, structured.StructuredError) as e:
            raise BackendError(f"{name}: {e}") from None
        self.audit("ssh_signed", req, ssh_fingerprint=req.spec["fingerprint"])
        return {"ssh_signature": base64.b64encode(sig).decode()}

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
            self.audit("delivered", req, to_peer=peer, kind={"env": "env", "ssh_sign": "ssh_signature"}.get(req.mode, "http_response"))
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
def _json(h, code, obj, headers=None):
    raw = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)


_CSS = """
:root{color-scheme:light dark;--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--muted:#656d76;--line:#d0d7de;
--accent:#2563eb;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e;--danger:#cf222e;--dangerh:#a40e26;--okbg:#dcfce7;--okfg:#166534;
--wbg:#fef3c7;--wfg:#92400e;--badbg:#ffebe9;--hov:#f3f4f6}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8b949e;
--line:#30363d;--accent:#4c8dff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--danger:#da3633;--dangerh:#b62324;--okbg:#12301c;--okfg:#3fb950;
--wbg:#3a2a0a;--wfg:#e3b341;--badbg:#3d1418;--hov:#1c2230}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:72rem;margin:0 auto;padding:1.25rem 1rem 3rem}
main.narrow>*{max-width:46rem}
.top{background:var(--card);border-bottom:1px solid var(--line)}
.bar{display:flex;align-items:center;gap:.65rem;max-width:72rem;margin:0 auto;padding:.7rem 1rem}
.tabs{--edge:max(1rem,calc((100% - 72rem)/2 + 1rem))}
.logo{width:1.7rem;height:1.7rem;border-radius:.45rem;background:var(--accent);color:#fff;display:grid;
place-items:center;font-weight:700}
.brand{font-size:1.05rem}.who{margin-left:auto;color:var(--muted);font-size:.85rem}
.tabs{background:var(--card);border-bottom:1px solid var(--line);display:flex;gap:1.4rem;padding:0 var(--edge);
overflow-x:auto}
.tabs a{display:flex;align-items:center;gap:.4rem;padding:.7rem 0 .6rem;margin-bottom:-1px;
border-bottom:2px solid transparent;color:var(--muted);text-decoration:none;font-weight:600;white-space:nowrap;
line-height:1.25rem}
.tabs a.on{color:var(--accent);border-bottom-color:var(--accent)}
.count{background:var(--accent);color:#fff;border-radius:99px;padding:0 .5rem;font-size:.75rem;line-height:1.1rem}
h1{font-size:1.25rem;margin:.1rem 0 .9rem}
h2{font-size:1.05rem;margin:0}
h3{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:1.4rem 0 .5rem}
a{color:var(--accent)}
small,.muted{color:var(--muted)}
.info{display:inline-grid;place-items:center;box-sizing:border-box;width:1.05rem;height:1.05rem;min-width:0;min-height:0;flex:none;padding:0;margin:0 .15rem;border:1px solid var(--muted);border-radius:50%;background:none;color:var(--muted);font:italic 700 .7rem/1 Georgia,serif;cursor:help;position:relative;vertical-align:baseline}
.info:hover::after,.info:focus::after{content:attr(data-tip);position:absolute;left:0;top:1.5rem;z-index:30;width:max-content;max-width:min(16rem,70vw);padding:.4rem .6rem;border:1px solid var(--line);border-radius:.4rem;background:var(--card);color:var(--fg);font:normal .8rem/1.3 system-ui,sans-serif;text-align:left;box-shadow:0 4px 14px #0003}
p,td,li{overflow-wrap:anywhere}
.pill{display:inline-block;padding:0 .55rem;border-radius:99px;font-size:.75rem;font-weight:600;line-height:1.1rem;
white-space:nowrap}
.pill.ok{background:var(--okbg);color:var(--okfg)}.pill.warn{background:var(--wbg);color:var(--wfg)}
.pill.bad{background:var(--badbg);color:var(--bad)}.pill.plain{background:var(--hov);color:var(--muted)}
.decide-row{display:flex;gap:.6rem;margin:.9rem 0 .2rem}
.decide-row .btn{flex:1 1 0;min-width:0;min-height:2.75rem}
.auto{position:relative;display:flex;flex-wrap:wrap;align-items:center;gap:.4rem .5rem;margin:.7rem 0 0}
.auto .lbl{font-size:.85rem;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem}
.chip{display:inline-flex;align-items:center;font:inherit;font-weight:600;font-size:.82rem;min-height:2.1rem;
padding:.2rem .8rem;border-radius:99px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;
list-style:none}
.chip:hover{background:var(--hov)}
.chip::-webkit-details-marker{display:none}
.chip.always{border-color:var(--warn);color:var(--wfg);background:var(--wbg)}
.chip.off{opacity:.55;cursor:help;border-style:dashed}
.chip[data-tip]:hover::after,.chip[data-tip]:focus::after{content:attr(data-tip);position:absolute;left:0;top:100%;z-index:30;
margin-top:.3rem;width:max-content;max-width:min(16rem,70vw);padding:.4rem .6rem;border:1px solid var(--line);
border-radius:.4rem;background:var(--card);color:var(--fg);font:normal .8rem/1.3 system-ui,sans-serif;text-align:left;
box-shadow:0 4px 14px #0003;font-weight:400}
details.alw{display:inline-block}
details.alw[open]>summary{border-style:dashed}
details.alw[open]>summary::after{display:none!important}
details.alw .confirm{margin-top:.4rem;max-width:100%;display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;font-size:.85rem;
padding:.5rem .6rem;border:1px solid var(--warn);border-radius:.5rem}
.scope{flex-basis:100%;margin:.1rem 0 0}
:is(.btn,.chip,button,summary):focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn,button{font:inherit;font-weight:600;font-size:.85rem;min-height:2.25rem;padding:.35rem .95rem;
border-radius:.5rem;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.btn:hover,button:hover{background:var(--hov)}
.btn.approve{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.approve:hover{filter:brightness(1.08)}
.btn.deny{background:var(--danger);border-color:var(--danger);color:#fff}
.btn.deny:hover{background:var(--dangerh);border-color:var(--dangerh)}
.btn.sm,td button{min-height:1.8rem;padding:.15rem .65rem;font-size:.8rem}
[hidden]{display:none!important}
body:has(dialog[open]){overflow:hidden}
button:disabled{opacity:.6;cursor:default}
form.inline{display:inline}
.card,.req{background:var(--card);border:1px solid var(--line);border-radius:.7rem;padding:1rem;margin:0 0 .8rem}
.card h2{margin-bottom:.4rem}
.reqhead{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.reqhead h2{font-size:1.15rem}.reqhead time{margin-left:auto;color:var(--muted);font-size:.8rem}
.risk{display:inline-flex;align-items:center;gap:.5rem;margin:.1rem 0}
.risk b{font-size:.75rem;padding:0 .55rem;border-radius:99px;line-height:1.1rem;background:var(--hov);color:var(--muted)}
.risk.low b{background:var(--okbg);color:var(--okfg)}.risk.medium b{background:var(--wbg);color:var(--wfg)}
.risk.high b{background:var(--badbg);color:var(--bad)}
.box{background:var(--bg);border:1px solid var(--line);border-radius:.5rem;padding:.5rem .75rem;margin:.6rem 0;
font-size:.85rem;overflow-wrap:anywhere}
.flash{background:var(--card);border:1px solid var(--line);border-left:.3rem solid var(--accent);
border-radius:.5rem;padding:.5rem .8rem;margin:0 0 .9rem}
.offline{border-left-color:var(--bad)}
.empty{color:var(--muted);text-align:center;padding:1.2rem}
.hist{list-style:none;margin:0;padding:0}
.hist li{border-bottom:1px solid var(--line)}
.hist li:last-child{border-bottom:0}
.hist .hrow{display:flex;align-items:center;gap:.7rem;width:100%;min-height:0;padding:.6rem 1rem;border:0;
border-radius:0;background:none;text-align:left;font-weight:400;font-size:inherit}
.hist .hrow:hover{background:var(--hov)}
.hist .hrow:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.hist .what{min-width:0;flex:1}.hist .what b{font-weight:600}
.hist .what small{display:block;font-family:ui-monospace,Menlo,monospace;font-size:.75rem;overflow-wrap:anywhere}
.hist .when{color:var(--muted);font-size:.8rem;white-space:nowrap}
.card.flush{padding:0;overflow:hidden}
.card.flush .more-link{display:block;padding:.6rem 1rem;border-top:1px solid var(--line);font-size:.85rem}
.hfoot{display:flex;flex-wrap:wrap;gap:0 1.25rem;align-items:center;border-top:1px solid var(--line)}
.hfoot .more-link,.card.flush .hfoot .more-link{border-top:0}.hfoot .muted{font-size:.8rem;margin-left:auto;padding-right:1rem}
.hfilters{display:flex;flex-wrap:wrap;gap:.5rem;padding:.7rem 1rem;border-bottom:1px solid var(--line)}
.hfilters input,.hfilters select{font:inherit;min-height:2.25rem;flex:1 1 9rem;padding:.2rem .5rem;
border-radius:.5rem;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.hfilters input{flex-basis:100%}
dialog.dlg{padding:0;border:1px solid var(--line);border-radius:.8rem;background:var(--card);color:var(--fg);
width:min(46rem,calc(100% - 2rem));max-height:calc(100dvh - 3rem);overflow:hidden}
dialog.dlg[open]{display:flex;flex-direction:column}
dialog.dlg::backdrop{background:rgba(0,0,0,.55)}
.dhead{display:flex;align-items:center;gap:.8rem;padding:.7rem 1rem;border-bottom:1px solid var(--line)}
.dhead h2{flex:1;font-size:1rem}
.dbody{overflow:auto;padding:.4rem 1rem 1.2rem;overscroll-behavior:contain}
.dtitle{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;margin:.6rem 0 .2rem}
.dtitle b{font-size:1.1rem;overflow-wrap:anywhere}
dl.kv{display:grid;grid-template-columns:9rem minmax(0,1fr);gap:.35rem .9rem;margin:.6rem 0}
dl.kv dt{color:var(--muted);font-size:.8rem;padding-top:.1rem}dl.kv dd{margin:0;overflow-wrap:anywhere}
dl.kv code,.tl code{font-family:ui-monospace,Menlo,monospace;font-size:.82rem}
.tl{list-style:none;margin:0;padding:0;border-left:2px solid var(--line)}
.tl li{padding:.15rem 0 .5rem .8rem;position:relative;overflow-wrap:anywhere}
.tl li::before{content:"";position:absolute;left:-.38rem;top:.55rem;width:.6rem;height:.6rem;border-radius:50%;
background:var(--line)}
.tl time{color:var(--muted);font-size:.78rem;margin-right:.4rem}.tl .ev{display:block;color:var(--muted);
font-size:.78rem;font-family:ui-monospace,Menlo,monospace}
@media (max-width:42rem){
 dialog.dlg{width:100%;max-width:100%;margin:auto 0 0;max-height:92dvh;border-radius:.8rem .8rem 0 0;border-bottom:0}
 dl.kv{grid-template-columns:1fr;gap:.05rem}dl.kv dd{margin-bottom:.45rem}
}
.devices{list-style:none;padding:0;margin:0}.devices li{display:flex;gap:.8rem;align-items:center;
padding:.7rem 1rem;border-top:1px solid var(--line)}
.srow{display:flex;align-items:center;gap:1rem;padding:.75rem 0;border-top:1px solid var(--line)}
.card h2+.srow{border-top:0;margin-top:.2rem}
.t{flex:1;min-width:0}.t b,.t small{display:block}
.chead{display:flex;align-items:center;gap:.8rem;padding:1rem 1rem .2rem}.chead h2{margin:0;flex:1}
.cnote{margin:0;padding:0 1rem .6rem}
.notify{margin:.5rem 0}.notify .btn{margin-right:.5rem}
.tbl{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:.7rem;
overflow:hidden}
.tbl th{text-align:left;font-size:.75rem;color:var(--muted);padding:.55rem .8rem;border-bottom:1px solid var(--line)}
.tbl td{padding:.6rem .8rem;border-bottom:1px solid var(--line);vertical-align:top}
.tbl tr:last-child td{border-bottom:0}
.tbl td[data-label=Time],.tbl td[data-label=Outcome],.tbl td[data-label=Risk],.tbl td[data-label=Took]
{white-space:nowrap;overflow-wrap:normal}
@media (max-width:42rem){
 main{padding:.9rem .75rem 2.5rem}
 .who{display:none}
 .tbl thead{display:none}
 .tbl,.tbl tbody,.tbl tr,.tbl td{display:block;width:100%}
 .tbl tr{border-bottom:1px solid var(--line);padding:.4rem .7rem}
 .tbl td{border:0;padding:.2rem 0;display:flex;gap:.75rem}
 .tbl td::before{content:attr(data-label);flex:0 0 5.5rem;color:var(--muted);font-size:.8rem;padding-top:.1rem}
 .tbl td>*{min-width:0}
}
@media (max-width:19.99rem){.decide-row{flex-direction:column}}
"""

_WORKING_JS = (
    "document.getElementById('f').addEventListener('submit',function(){"
    "setTimeout(function(){document.querySelectorAll('button').forEach(function(b){b.disabled=true});"
    "document.getElementById('w').hidden=false},0)});")

_GRANTS_JS = r'''
(function(){
  function fmt(s){var m=Math.floor(s/60);return m+'m '+('0'+(s%60)).slice(-2)+'s';}
  function tick(){var any=false;document.querySelectorAll('time[data-gexp]').forEach(function(t){
    var s=Math.floor(t.getAttribute('data-gexp')-Date.now()/1000);
    if(s<=0){t.textContent='expired';any=true;return;}t.textContent=fmt(s);});
    if(any)setTimeout(function(){location.reload();},1500);}
  tick();setInterval(tick,1000);
})();
'''

_CE_LOCK = threading.Lock()
_CE_LIMIT = 120          # client events per user per minute


def _ce_str(v, n):
    if not isinstance(v, str):
        return None
    return "".join(ch if ch.isprintable() else " " for ch in v)[:n]


def _ce_int(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        return max(-1, min(int(v), 10**9))
    except (ValueError, OverflowError):
        return None


def _ce_path(v):
    """A URL reduced to its pathname: no scheme, host, query or fragment."""
    if not isinstance(v, str):
        return None
    try:
        p = urllib.parse.urlsplit(v[:300]).path
    except ValueError:
        return None
    return _ce_str(p, 80) or "/"


def sanitize_client_event(obj):
    """Allowlisted, length-capped copy of a browser-reported event, or None."""
    if not isinstance(obj, dict):
        return None
    out = {}
    for key, n in (("kind", 40), ("v", 8), ("tag", 40), ("action", 40), ("err", 120),
                   ("state", 24), ("note", 80)):
        if key in obj:
            val = _ce_str(obj[key], n)
            if val is not None:
                out[key] = val
    for key in ("clients", "ms", "queued"):
        if key in obj:
            val = _ce_int(obj[key])
            if val is not None:
                out[key] = val
    for key in ("ok", "visible"):
        if isinstance(obj.get(key), bool):
            out[key] = obj[key]
    if isinstance(obj.get("client_paths"), list):
        out["client_paths"] = [p for p in (_ce_path(x) for x in obj["client_paths"][:5])
                               if p is not None]
    if "kind" not in out:
        return None
    return out


_DASH_JS = r'''
(function(){
  var lastRep={};
  function report(kind,extra,gap){try{
    var now=Date.now();if(gap&&lastRep[kind]&&now-lastRep[kind]<gap)return;lastRep[kind]=now;
    var b=extra||{};b.kind=kind;
    fetch('/push/event',{method:'POST',credentials:'same-origin',keepalive:true,
      headers:{'Content-Type':'application/json','X-Requested-With':'asb'},
      body:JSON.stringify(b)}).catch(function(){});}catch(x){}}
  report('page_load',{note:location.pathname,state:document.visibilityState});
  var cards=document.getElementById('cards'), flash=document.getElementById('flash'),
      off=document.getElementById('offline'), recent=document.getElementById('recent'),
      last=cards?cards.getAttribute('data-version'):null,
      hl=document.getElementById('hlist'), hform=document.getElementById('hform'),
      hs={all:hl?hl.getAttribute('data-all')==='1':false,limit:hl?+hl.getAttribute('data-limit'):0},
      hseq=0, hmore=25;
  function secs(){document.querySelectorAll('time[data-exp]').forEach(function(t){
    var s=Math.max(0,Math.floor(t.getAttribute('data-exp')-Date.now()/1000));
    t.textContent='expires in '+s+'s';});}
  function title(){if(!cards)return;var n=cards.querySelectorAll('article').length;
    document.title=(n?'('+n+') ':'')+'Agent Secret Broker';}
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
    if(!('serviceWorker' in navigator)||!('PushManager' in window)){
      if(pbtn){pbtn.hidden=true;pst.textContent='This browser cannot receive push notifications.';}return;}
    navigator.serviceWorker.getRegistration('/').then(function(reg){
      return reg?reg.pushManager.getSubscription():null;}).then(function(sub){
      pushOn=!!sub;if(!pbtn)return;pbtn.hidden=false;
      pbtn.textContent=sub?'Register this device again':'Enable on this device';
      pst.textContent=sub?'This device has a subscription. It receives notifications with the '
        +'browser closed, as long as the browser is allowed to run in the background.':
        'Not enabled on this device.';});}
  if(pbtn)pbtn.addEventListener('click',function(){
    pst.textContent='Working...';
    Notification.requestPermission().then(function(p){
      if(p!=='granted')throw new Error('notifications are not allowed for this site');
      return navigator.serviceWorker.register('/sw.js',{scope:'/'}).then(function(r){
        report('sw_registered',{ok:true});return r;},function(e){
        report('sw_register_failed',{ok:false,err:String(e&&e.message||e)});throw e;});})
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
  // Service worker status block (Settings only): what the browser runs vs what the server serves
  var swbox=document.getElementById('sw-box');
  function swt(id,t){var e=document.getElementById(id);if(e)e.textContent=t;}
  function swv(v){return v?'v'+v:'none';}
  // Ask a worker for its version; resolves null (no worker), a string, or undefined (no reply in 2 s)
  function swask(w,id){return new Promise(function(res){
    if(!w){res(null);return;}
    var done=false,t=setTimeout(function(){fin(undefined);},2000);
    function fin(v){if(done)return;done=true;clearTimeout(t);
      navigator.serviceWorker.removeEventListener('message',on);res(v);}
    function on(m){var d=m.data;if(d&&d.type==='version'&&d.id===id)fin(String(d.v));}
    navigator.serviceWorker.addEventListener('message',on);
    try{w.postMessage({type:'version',id:id});}catch(x){fin(undefined);}});}
  function swpath(u){try{return new URL(u).pathname;}catch(x){return String(u||'');}}
  function swstatus(cls,text,note){var s=document.getElementById('sw-status');
    if(s){s.className='pill '+cls;s.textContent=text;}swt('sw-note',note||'');}
  function swcheck(){
    if(!swbox)return Promise.resolve();
    var exp=swbox.getAttribute('data-expected'),upd=document.getElementById('sw-update');
    swt('sw-expected',swv(exp));
    swstatus('plain','Checking','');
    if(upd)upd.hidden=true;
    if(!('serviceWorker' in navigator)){swstatus('bad','Unsupported',
      'This browser has no service workers.');return Promise.resolve();}
    swt('sw-controlled',navigator.serviceWorker.controller?'yes':'no');
    var cs=document.getElementById('sw-clear');
    if(window.caches&&caches.keys)caches.keys().then(function(n){
      swt('sw-caches',n.length?n.length+': '+n.join(', '):'No caches');if(cs)cs.hidden=!n.length;
      cs&&(cs.onclick=function(){Promise.all(n.map(function(k){return caches.delete(k);}))
        .then(swcheck);});},function(){swt('sw-caches','No caches');});
    else swt('sw-caches','No caches');
    // the server may have moved on since this page loaded: ask /sw.js itself
    var live=fetch('/sw.js',{credentials:'same-origin',cache:'no-store'}).then(function(r){
      return r.headers.get('X-SW-Version')||exp;},function(){return exp;});
    return live.then(function(e2){exp=e2;swt('sw-expected',swv(exp));
      return navigator.serviceWorker.getRegistration('/');}).then(function(reg){
      if(!reg){swt('sw-running','none');swt('sw-waiting','none');swt('sw-reg','none');
        swt('sw-sub','absent');
        swstatus('bad','No worker registered','Use "Enable on this device" above to register it.');
        report('sw_status',{state:'none',note:'expected '+swv(exp)});return;}
      var wk=reg.waiting||reg.installing;
      swt('sw-reg',reg.scope?swpath(reg.scope)+', '+(reg.active?reg.active.state:wk?wk.state:'none')
        +', '+swpath((reg.active||wk||{}).scriptURL):'none');
      reg.pushManager.getSubscription().then(function(sub){
        swt('sw-sub',sub?'present':'absent');},function(){swt('sw-sub','absent');});
      return Promise.all([swask(reg.active,'active'),swask(wk,'waiting')]).then(function(r){
        var run=r[0],wv=r[1],state;
        swt('sw-running',run===null?'none':run===undefined?'not responding':swv(run));
        swt('sw-waiting',wk?(wv===undefined?'not responding':swv(wv))+' ('+wk.state+')':'none');
        var note=wk?'A newer worker is waiting; the old one keeps control until all tabs '
          +'close or you update it here.':'';
        if(run&&run===exp){state='current';swstatus('ok','Up to date',note);}
        else if(run){state='stale';swstatus('warn','Stale: running v'+run+', server has v'+exp,note);}
        else if(run===undefined){state='noreply';swstatus('warn','Stale: running worker did not answer, '
          +'server has v'+exp,'Workers older than v6 cannot answer this check.'+(note?' '+note:''));}
        else{state='none';swstatus('bad','No active worker',note);}
        if(upd)upd.hidden=state==='current'&&!wk;
        report('sw_status',{v:run||undefined,state:state,note:'expected '+swv(exp)});});
    }).catch(function(e){swstatus('bad','Check failed',String(e&&e.message||e));});}
  function swupdate(){
    var upd=document.getElementById('sw-update');if(upd)upd.disabled=true;
    swstatus('plain','Updating','');
    var done=false;
    navigator.serviceWorker.addEventListener('controllerchange',function(){
      if(done)return;done=true;location.reload();});
    navigator.serviceWorker.getRegistration('/').then(function(reg){
      if(!reg)throw new Error('no registration');
      function skip(){if(reg.waiting)reg.waiting.postMessage({type:'skip'});}
      reg.addEventListener('updatefound',function(){var w=reg.installing;
        if(w)w.addEventListener('statechange',function(){if(w.state==='installed')skip();});});
      return reg.update().then(skip);})
    .then(function(){setTimeout(function(){if(done)return;if(upd)upd.disabled=false;
      swcheck();},8000);})
    .catch(function(e){if(upd)upd.disabled=false;swstatus('bad','Update failed',String(e&&e.message||e));});}
  if(swbox){
    var sr=document.getElementById('sw-recheck'),su=document.getElementById('sw-update');
    if(sr)sr.addEventListener('click',swcheck);
    if(su)su.addEventListener('click',swupdate);
    swcheck();}
  // History list: one component, one query. hq() is the state (view, filters, how
  // many rows) as a query string; polls and filter changes fetch the same fragment.
  function hq(){
    var p=new URLSearchParams();
    if(hs.all){p.set('view','all');
      ['q','outcome','secret','mode'].forEach(function(k){
        var el=hform&&hform.elements[k];if(el&&el.value)p.set(k,el.value);});
      if(hs.limit>hmore)p.set('limit',hs.limit);}
    return p.toString();}
  function poll(){
    if(!cards)return Promise.resolve();
    var seq=hseq,q=hq();
    return fetch('/?fragment=1'+(q?'&'+q:''),{credentials:'same-origin',cache:'no-store'})
      .then(function(r){if(!r.ok)throw 0;return r.text();})
      .then(function(h){var d=parse(h),c=d.getElementById('cards'),nl=d.getElementById('hlist');
        if(c&&c.getAttribute('data-version')!==last){
          last=c.getAttribute('data-version');cards.innerHTML=c.innerHTML;bind();
          track(ids(c));}
        if(hl&&nl&&seq===hseq&&nl.innerHTML!==hl.innerHTML)hl.innerHTML=nl.innerHTML;
        off.hidden=true;secs();title();})
      .catch(function(){off.hidden=false;});}
  function hload(){
    hseq++;if(hform)hform.hidden=!hs.all;
    try{var q=hq();history.replaceState(null,'',q?'/?'+q:'/');}catch(x){}
    return poll();}
  var htimer=null;
  if(hform){
    hform.addEventListener('submit',function(e){e.preventDefault();hs.limit=hmore;hload();});
    hform.addEventListener('change',function(){hs.limit=hmore;hload();});
    hform.addEventListener('input',function(e){if(e.target.name!=='q')return;
      clearTimeout(htimer);htimer=setTimeout(function(){hs.limit=hmore;hload();},300);});}
  // Detail pop-over: the server renders (and escapes) the fragment; it is the
  // only thing put into the dialog, and the dialog sits outside the polled areas.
  var dlg=document.getElementById('hdlg'), dbody=document.getElementById('hbody'),
      dseq=0, dfor=null, dopener=null;
  function opendetail(btn){
    var id=btn.getAttribute('data-id');
    if(!dlg||!dlg.showModal){location.href='/request/'+encodeURIComponent(id);return;}
    var n=++dseq;dfor=id;dopener=btn;
    dbody.textContent='Loading...';
    if(!dlg.open)dlg.showModal();
    fetch('/request/'+encodeURIComponent(id)+'?fragment=1',{credentials:'same-origin',cache:'no-store'})
      .then(function(r){return r.text().then(function(t){return {s:r.status,t:t};});})
      .then(function(o){if(n!==dseq)return;
        if(o.s===200)dbody.innerHTML=o.t;
        else dbody.textContent=o.s===409?'This request is still waiting; decide it from its card.'
          :'This request is not in the history.';})
      .catch(function(){if(n===dseq)dbody.textContent='Could not load the details.';});}
  if(dlg){
    dlg.addEventListener('click',function(e){if(e.target===dlg)dlg.close();});
    var dc=document.getElementById('hclose');if(dc)dc.addEventListener('click',function(){dlg.close();});
    dlg.addEventListener('close',function(){dseq++;
      // the list may have been redrawn while open: find the row again by id
      var b=recent&&dfor?recent.querySelector('button.hrow[data-id="'+dfor+'"]'):null;
      var t=b||dopener;if(t&&t.isConnected)t.focus();dfor=dopener=null;});}
  if(recent)recent.addEventListener('click',function(e){
    var a=e.target.closest('[data-hact]');
    if(a){e.preventDefault();var k=a.getAttribute('data-hact');
      if(k==='all'){hs.all=true;hs.limit=hmore;}
      else if(k==='less'){hs.all=false;hs.limit=0;}
      else if(k==='more'){hs.limit+=hmore;}
      hload();return;}
    var b=e.target.closest('button.hrow');if(b)opendetail(b);});
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
  seen=cards?ids(cards):{};nshow();pshow();
  bind();secs();title();if(cards){setInterval(secs,1000);setInterval(poll,3000);}
  document.addEventListener('visibilitychange',function(){
    report('visibility',{visible:!document.hidden,state:document.visibilityState},5000);
    if(!document.hidden)poll();});
  if('serviceWorker' in navigator)navigator.serviceWorker.addEventListener('message',function(m){
    if(m.data&&m.data.type&&m.data.type!=='version')report('sw_message',{note:String(m.data.type),v:String(m.data.v||'')},2000);
    if(m.data&&m.data.type==='poll'){report('poll_requested',{},2000);poll();}
    if(m.data&&m.data.type==='diag')why('Service worker v'+m.data.v+': '+m.data.what+' at '
      +new Date().toLocaleTimeString()+'.');});
})();
'''

# Single source of truth for the worker version: rendered into the worker, the
# X-SW-Version header on /sw.js, and the Settings page ("expected" version).
SW_VERSION = "7"

_SERVICE_WORKER = r"""
var SW_VERSION='__SW_VERSION__';
var Q=[],T0={};
function tell(m){return self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(cs){
  cs.forEach(function(c){try{c.postMessage(m);}catch(x){}});return cs;});}
// Report a step to the broker audit log. Never throws and never rejects; a
// failed beacon (expired SSO session, network) is queued and retried next time.
function rep(kind,x){
  try{
    var b=x||{};b.kind=kind;b.v=SW_VERSION;
    var batch=Q.splice(0,Q.length);
    if(batch.length)b.queued=batch.length;
    batch.push(b);
    return Promise.all(batch.map(function(o){
      return fetch('/push/event',{method:'POST',credentials:'same-origin',keepalive:true,
        redirect:'manual',headers:{'Content-Type':'application/json','X-Requested-With':'asb'},
        body:JSON.stringify(o)}).then(function(r){
        if(r.status!==204&&r.status!==200)throw new Error('http '+r.status);
      }).catch(function(){if(Q.length<20)Q.push(o);});
    })).catch(function(){});
  }catch(e){return Promise.resolve();}
}
function em(e){return String(e&&(e.name||'')+(e&&e.message?': '+e.message:'')||e).slice(0,120);}
self.addEventListener('install',function(e){
  e.waitUntil(rep('sw_install').then(function(){return self.skipWaiting();}));});
self.addEventListener('activate',function(e){
  e.waitUntil(self.clients.claim().then(function(){return rep('sw_activate');},
    function(){return rep('sw_activate',{ok:false});}));});
self.addEventListener('push',function(e){
  var d={},parsed=true;try{d=e.data.json();}catch(x){parsed=false;}
  var tag=d.tag||'secret-request',t0=Date.now();T0[tag]=t0;
  tell({type:'diag',what:'push received',v:SW_VERSION});
  var r1=rep('push',{ok:parsed,tag:tag});
  // Buttons: only what the payload lists (Deny, Approve), then Review, capped to
  // what this browser/platform allows. The notification body click always opens.
  var data={url:'/',names:String(d.body||'').slice(0,200)};
  var acts=[];
  if(d.token&&d.rid&&Array.isArray(d.actions)){
    data.rid=String(d.rid);data.token=String(d.token);
    if(d.actions.indexOf('deny')>=0)acts.push({action:'deny',title:'Deny'});
    if(d.actions.indexOf('approve')>=0)acts.push({action:'approve',title:'Approve'});
  }
  acts.push({action:'open',title:'Review'});
  var mx=(self.Notification&&typeof Notification.maxActions==='number')?Notification.maxActions:2;
  acts=acts.slice(0,Math.max(mx,0));
  var r2=self.registration.showNotification(d.title||'Approval needed',{
    body:d.body||'A secret was requested',tag:tag,requireInteraction:true,
    data:data,actions:acts,renotify:true,
    timestamp:t0}).then(function(){return rep('show',{ok:true,tag:tag,ms:Date.now()-t0,
      note:acts.map(function(a){return a.action;}).join(',')});},
    function(err){return rep('show',{ok:false,tag:tag,err:em(err),ms:Date.now()-t0});});
  e.waitUntil(Promise.all([r1,r2]));});
self.addEventListener('notificationclose',function(e){
  var tag=(e.notification&&e.notification.tag)||'';
  e.waitUntil(rep('notificationclose',{tag:tag,note:'dismissed'}));});
self.addEventListener('pushsubscriptionchange',function(e){
  e.waitUntil(rep('pushsubscriptionchange'));});
self.addEventListener('notificationclick',function(e){
  var tag=(e.notification&&e.notification.tag)||'',action=e.action||'',t0=Date.now();
  var nd=(e.notification&&e.notification.data)||{};
  try{e.notification.close();}catch(x){}
  tell({type:'diag',what:'notification clicked',v:SW_VERSION});
  var shown=T0[tag];
  function step(name,ok,err){return rep(name,{ok:ok,tag:tag,err:err?em(err):undefined,ms:Date.now()-t0});}
  // Robust chain: focus an open dashboard window, navigating it to "/" first if it
  // is elsewhere; on any failure or no window, open one. Every step is reported.
  function openApp(){return self.clients.matchAll({type:'window',includeUncontrolled:true}).then(function(cs){
    var paths=cs.slice(0,5).map(function(c){try{return new URL(c.url).pathname;}catch(x){return '?';}});
    var info={tag:tag,action:action,clients:cs.length,client_paths:paths};
    if(shown)info.ms=Date.now()-shown;
    var pick=null;
    for(var i=0;i<cs.length;i++){
      if(!('focus' in cs[i]))continue;
      var p='';try{p=new URL(cs[i].url).pathname;}catch(x){}
      if(!pick||p==='/')pick=cs[i];}
    return rep('notificationclick',info).then(function(){
      if(!pick)return null;
      var pp='';try{pp=new URL(pick.url).pathname;}catch(x){}
      var nav=Promise.resolve(pick);
      if(pp!=='/'&&'navigate' in pick){
        nav=pick.navigate('/').then(function(c){
          return step('click_navigate',true).then(function(){return c||pick;});},
          function(err){return step('click_navigate',false,err).then(function(){return pick;});});}
      return nav.then(function(c){
        return (c||pick).focus().then(function(f){
          try{(f||c||pick).postMessage({type:'poll'});}catch(x){}
          return step('click_focus',true).then(function(){return f||c||pick;});});
      }).catch(function(err){
        return step('click_focus',false,err).then(function(){throw err;});});
    });
  }).catch(function(err){
    return null;
  }).then(function(done){
    if(done)return rep('click_outcome',{ok:true,tag:tag,state:'focused',ms:Date.now()-t0});
    return self.clients.openWindow('/').then(function(w){
      return step('click_openwindow',true).then(function(){
        return rep('click_outcome',{ok:true,tag:tag,state:'opened',ms:Date.now()-t0});});
    },function(err){
      return step('click_openwindow',false,err).then(function(){
        return rep('click_outcome',{ok:false,tag:tag,state:'failed',ms:Date.now()-t0});});
    });
  }).catch(function(){});}
  // Approve / Deny straight from the notification: one POST with the single-use
  // token from the payload; the reply is a short follow-up notification.
  function followUp(text,ok){
    var o={body:'',tag:tag,renotify:true,requireInteraction:false,data:{url:'/'}};
    if(ok){
      return self.registration.showNotification(text,o).then(function(){
        return new Promise(function(res){setTimeout(function(){
          self.registration.getNotifications({tag:tag}).then(function(ns){
            ns.forEach(function(n){try{n.close();}catch(x){}});res();},function(){res();});
        },4000);});},function(){});
    }
    o.requireInteraction=true;
    return self.registration.showNotification(text,o).catch(function(){});
  }
  function decideFlow(){
    var verb=action==='approve'?'approve':'deny',done=action==='approve'?'Approved':'Denied';
    var names=String(nd.names||'').slice(0,120);
    rep('action_click',{tag:tag,action:action,ok:!!nd.token});
    if(!nd.token||!nd.rid){
      rep('action_decide',{tag:tag,action:action,ok:false,note:'no token',ms:Date.now()-t0});
      return followUp('Could not '+verb+' - tap to review',false);}
    return fetch('/push/decide',{method:'POST',credentials:'same-origin',redirect:'manual',
      headers:{'Content-Type':'application/json','X-Requested-With':'asb'},
      body:JSON.stringify({rid:nd.rid,token:nd.token,decision:verb})}).then(function(r){
        var ok=r.status===200;
        return rep('action_decide',{tag:tag,action:action,ok:ok,
          note:'http '+r.status+(r.type==='opaqueredirect'?' redirect':''),ms:Date.now()-t0}).then(function(){
          return ok?followUp(done+(names?': '+names:''),true):followUp('Could not '+verb+' - tap to review',false);});
      },function(err){
        return rep('action_decide',{tag:tag,action:action,ok:false,err:em(err),note:'network',
          ms:Date.now()-t0}).then(function(){return followUp('Could not '+verb+' - tap to review',false);});
      }).catch(function(){});
  }
  if(action==='approve'||action==='deny')e.waitUntil(decideFlow());
  else e.waitUntil(openApp());});
// Settings page probes: {type:'version'} is answered with the running version
// (echoing the caller's id); {type:'skip'} lets a waiting worker take over now.
self.addEventListener('message',function(e){
  var d=e.data||{};
  if(d.type==='version'){
    var m={type:'version',v:SW_VERSION,id:d.id};
    try{if(e.source)e.source.postMessage(m);else tell(m);}catch(x){}
  }else if(d.type==='skip'){e.waitUntil(self.skipWaiting());}});
"""
_SERVICE_WORKER = _SERVICE_WORKER.replace("__SW_VERSION__", SW_VERSION)

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


_ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
         "%3Crect width='32' height='32' rx='8' fill='%232563eb'/%3E%3Ctext x='16' y='23' "
         "font-family='system-ui,Arial,sans-serif' font-size='20' font-weight='700' fill='white' "
         "text-anchor='middle'%3EA%3C/text%3E%3C/svg%3E")

_TABS = (("requests", "/", "Requests"), ("policies", "/policies", "Policies"),
         ("settings", "/settings", "Settings"))


def _chrome(tab, badge, user):
    who = f"<span class=who>{html.escape(user)}</span>" if user else ""
    head = ("<header class=top><div class=bar><span class=logo>A</span>"
            "<b class=brand>Agent Secret Broker</b><span class='pill ok'>&#9679; online</span>"
            f"{who}</div></header>")
    if tab is None:
        return head
    links = "".join(
        f"<a href='{href}'{' class=on' if key == tab else ''}>{label}"
        + (f" <span class=count>{badge}</span>" if key == "requests" and badge else "") + "</a>"
        for key, href, label in _TABS)
    return head + f"<nav class=tabs>{links}</nav>"


def _page(h, code, body, wide=False, nav=True, script=None, tab=None, badge=0, user=""):
    nonce = secrets.token_urlsafe(16)
    scr = f"<script nonce='{nonce}'>{script}</script>" if script else ""
    csp = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; connect-src 'self'; "
           f"base-uri 'none'; frame-ancestors 'none'; worker-src 'self'; script-src 'nonce-{nonce}'")
    raw = ("<!doctype html><html lang=en><meta charset=utf-8>"
           "<meta name=viewport content='width=device-width,initial-scale=1'>"
           "<meta name=color-scheme content='light dark'><title>Agent Secret Broker</title>"
           f"<link rel=icon href=\"{_ICON}\">"
           f"<style>{_CSS}</style><body>{_chrome(tab, badge, user) if nav else ''}"
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
    if req.mode == "ssh_sign":
        return (f"SSH signature with key <code>{html.escape(req.spec['fingerprint'])}</code><br>"
                f"{html.escape(req.spec['ssh']['text'])}",
                "The private key stays in the broker; only the signature goes back. "
                "Advisory: the request text is what the client sent.")
    return ("run <code>" + html.escape(" ".join(req.spec.get("argv") or [])) + "</code>",
            "Advisory only: the secret is released to the requesting host and the "
            "command shown is what it <em>said</em> it would run.")


def _info_icon(model, source=None):
    """The (i) icon whose tooltip says which model wrote a description (or that
    a plain line was built from the request details, with no model involved)."""
    if source == "deterministic":
        tip = html.escape("Built from the request details; no AI model was used.")
    else:
        tip = html.escape(f"Generated by {model or 'an AI model'} based on the request.")
    # data-tip drives the CSS tooltip (hover, focus, tap); no title attribute, or the
    # browser would draw its own second tooltip on top
    return (f'<button type=button class=info aria-label="{tip}" data-tip="{tip}">i</button>')


def _risk_html(req):
    if not req.risk:        # the assessment has not been attached yet: say so, never guess a level
        return ("<div class='risk assessing'><b>ASSESSING</b>"
                "<small>rating this request...</small></div>")
    lvl = req.risk["level"]
    out = (f"<div class='risk {lvl}'><b>{lvl.upper()} RISK</b><small>"
           + html.escape("; ".join(req.risk["reasons"]) if req.risk else "") + "</small></div>")
    if req.summary:
        out += (f"<p>{'Summary' if req.summary_source == 'deterministic' else 'AI summary'} "
                f"{_info_icon(req.summary_model, req.summary_source)}:<br>"
                f"<i>{html.escape(req.summary)}</i></p>")
    return out


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


_CHANNEL_LABEL = {"dashboard": "web dashboard", "push": "browser push notification",
                  "ha": "Home Assistant", "link": "approval link"}
_AUTO_LABEL = {"none": "off (every request asks a human)", "low": "up to low risk",
               "medium": "up to medium risk",
               "high": "any risk level, including requests with no model verdict"}


def _approve_actions(broker, req):
    """The decision controls of a pending request (dashboard card and approval
    link page): Approve and Deny side by side, then an 'Automatically approve...'
    row of timed-grant chips and a confirmed 'Always'. Chips are offered only
    when the request is eligible; the form values are unchanged."""
    e = html.escape
    names = e(", ".join(req.names))
    row1 = ("<div class=decide-row><button class='btn approve' name=decision value=approve>"
            "Approve</button><button class='btn deny' name=decision value=deny>Deny</button></div>")
    ok_g, _ = broker.grant_eligibility(req)
    mins = broker.grant_durations() if ok_g else []
    ok_a, why = broker.always_allow_eligibility(req)
    if not mins and not ok_a:
        return row1
    scope = grants_mod.scope_for(req.mode, req.spec)
    chips = []
    for m in mins:
        label = _fmt_minutes(m)
        chips.append(
            f"<button class=chip name=decision value='approve_grant_{m}' "
            f"aria-label='Approve this request, and approve further requests for exactly {names} "
            f"for {label}'>{label}</button>")
    if ok_a:
        tip = ("Approve this request and release future calls with this secret without asking "
               "when the request is low risk. Revoke any time under Policies.")
        chips.append(
            f"<details class=alw><summary class='chip always' data-tip='{e(tip)}' "
            f"aria-label='Always approve {e(req.names[0])}: {e(tip)}'>Always</summary>"
            f"<div class=confirm><span>Always approve {e(req.names[0])}?</span>"
            "<button class='btn sm approve' name=decision value=approve_always>Confirm</button>"
            "<span class=muted>Click Always again to cancel.</span></div></details>")
    elif mins:
        tip = f"Always not offered: {why}."
        chips.append(f"<span class='chip off' tabindex=0 role=img data-tip='{e(tip)}' "
                     f"aria-label='{e(tip)}'>Always</span>")
    out = ("<div class=auto><span class=lbl>Automatically approve...</span>"
           f"<div class=chips>{''.join(chips)}</div>")
    if mins:
        out += (f"<p class=scope><small class=muted>Applies to exactly: {names}. "
                f"{'Reads only (GET, HEAD, OPTIONS)' if scope == 'read' else 'Any method'}. "
                "Revoke any time under Policies.</small></p>")
    return row1 + out + "</div>"


def _fmt_minutes(m):
    return f"{m} min" if m < 60 or m % 60 else f"{m // 60} hr"


def _parse_decision(decision):
    """Form value -> (decision, always, grant_minutes) or None when malformed."""
    if decision in ("approve", "deny"):
        return decision, False, None
    if decision == "approve_always":
        return "approve", True, None
    if decision.startswith("approve_grant_") and decision[14:].isdigit() and len(decision) < 22:
        return "approve", False, int(decision[14:])
    return None


def _left(s):
    return f"{s // 60}m {s % 60:02d}s"


def _utc(t):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(t)) if t else ""


def _secs(a, b):
    if not a or not b or b < a:
        return ""
    d = b - a
    return f"{d:.1f}s" if d < 120 else f"{int(d // 60)}m {int(d % 60)}s"


def _ev_val(v):
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def _detail_html(r, evs):
    """Server-escaped detail of one finished request: the history row plus its
    audit events (whitelisted fields only; see history._EV_KEYS)."""
    e = html.escape

    def first(*names):
        return next((x for x in evs if x["event"] in names), None)

    def last(*names):
        return next((x for x in reversed(evs) if x["event"] in names), None)
    t0 = r["ts"]
    final, decided = last("approved", "denied", "expired", "failed"), first("decided")
    ran = last("http_executed", "stored", "ssh_signed") or last("secret_read")
    deliv, esc = first("delivered"), first("escalated")
    run = first("http_executed")
    outcome = r["outcome"]
    kind = ("ok" if outcome in ("approved", "auto-approved") else
            "bad" if outcome in ("denied", "failed") else "plain")
    label = outcome + (" (not collected)" if outcome in ("approved", "auto-approved")
                       and not r["delivered"] and r["mode"] != "store" else "")
    rows = []

    def add(k, v, raw=False):
        if v not in (None, "", []):
            rows.append(f"<dt>{e(k)}</dt><dd>{v if raw else e(str(v))}</dd>")
    add("Request id", f"<code>{e(r['id'])}</code>", True)
    add("Secrets", ", ".join(r["names"]))
    add("Mode", r["mode"])
    if r["mode"] == "http":
        add("Request", f"{r['method'] or ''} {r['url'] or ''}".strip())
    elif r["mode"] == "env":
        add("Command", "<code>" + e(" ".join(r["argv"] or [])) + "</code>", True)
    elif r["mode"] == "store":
        add("Operation", f"{r['op'] or 'store'} credential")
        add("Vault item", r["item"])
        add("Field", r["field"])
        add("Key", r["key"])
        add("Allowed hosts", ", ".join(r["hosts"] or []))
        if (last("stored") or {}).get("value_bytes") is not None:
            add("Value size", f"{last('stored')['value_bytes']} bytes (never recorded)")
    else:
        add("Signing", r.get("ssh_what"))
        add("Key fingerprint", (first("ssh_signed") or {}).get("ssh_fingerprint"))
    add("Source (claimed by the client)", r["source"])
    add("Peer", r["peer"])
    if r["summary"]:
        add("Summary", f"{e(r['summary'])} {_info_icon(r.get('summary_model'), r.get('summary_source'))}", True)
    if r["risk"]:
        reasons = "; ".join(r["risk_reasons"] or [])
        add("Risk", f"<span class='risk {e(r['risk'])}'><b>{e(r['risk'].upper())}</b></span> "
            + e(reasons) + (f" <small class=muted>(model verdict: {e(str(r['risk_model']))})</small>"
                            if r["risk_model"] else ""), True)
    add("Outcome", f"<span class='pill {kind}'>{e(label)}</span>"
        + (f" {e(r['error'])}" if r["error"] else ""), True)
    if r["via"] == "policy" and r.get("grant_id"):
        left = (final or {}).get("grant_left_s")
        gs = (first("grant_used") or {}).get("scope")
        add("Decided by", "time-boxed grant"
            + (" (reads only)" if gs == "read" else " (all requests)" if gs else "") + " (auto-approved)"
            + ((f", {left // 60} min left when used" if left >= 60 else ", under a minute left when used")
               if isinstance(left, int) else "")
            + f", grant {str(r['grant_id'])[:8]}")
    elif r["via"] == "policy":
        am = (final or {}).get("auto_max")
        add("Decided by", "policy (auto-approved)" + (f", auto-approve limit: {am}" if am else ""))
    elif decided:
        who = decided.get("approver") or ""
        how = _CHANNEL_LABEL.get(decided.get("channel"), decided.get("channel") or "")
        add("Decided by", f"{who} via {how}" if who else how)
        if who.startswith("ha:"):
            add("Device", who[3:])
        add("Approver address", ", ".join(x for x in (decided.get("approver_peer"),
                                                      decided.get("approver_ip")) if x))
        add("Decision", (decided.get("decision") or "")
            + (" and always allow" if decided.get("always_requested") else "")
            + (f" and approve for {decided['grant_minutes']} min"
               if decided.get("grant_minutes") else ""))
    elif outcome == "expired":
        add("Decided by", "nobody (expired unanswered)")
    elif r["approver"]:
        add("Decided by", r["approver"])
    if esc:
        add("Auto-approve", esc.get("reason"))
    add("Requested", _utc(t0))
    add("Decided", _utc((decided or final or {}).get("ts")))
    add("Released", _utc((ran or {}).get("ts")))
    add("Delivered to client", _utc((deliv or {}).get("ts")))
    add("Time to decision", _secs(t0, (decided or final or {}).get("ts")))
    if r["latency_ms"] is not None:
        add("Total until final", f"{r['latency_ms'] / 1000:.1f}s")
    if run:
        add("Upstream call took", f"{run['duration_ms'] / 1000:.2f}s" if run.get("duration_ms") is not None else "")
        add("Upstream HTTP status", run.get("upstream_status"))
        add("Response size", f"{run['response_bytes']} bytes" if run.get("response_bytes") is not None else "")
    tl = []
    for x in evs:
        extra = " ".join(f"{k}={_ev_val(v)}" for k, v in x.items() if k not in ("event", "ts", "time"))
        t = (x.get("time") or "")[11:19]
        dt = _secs(t0, x.get("ts"))
        tl.append(f"<li><time>{e(t)}</time><b>{e(x['event'])}</b>"
                  + (f" <small class=muted>+{e(dt)}</small>" if dt and x.get("ts") != t0 else "")
                  + (f"<span class=ev>{e(extra)}</span>" if extra else "") + "</li>")
    return (f"<div class=dtitle><b>{e(', '.join(r['names']))}</b>"
            f"<span class='pill {kind}'>{e(label)}</span></div>"
            f"<dl class=kv>{''.join(rows)}</dl><h3>Timeline</h3><ol class=tl>{''.join(tl)}</ol>")


def client_handler(broker, client_key):
    audit_view = audit_api.AuditApi(broker._audit._path, Broker.rate_map_make_room)
    key_id = hashlib.sha256(client_key.encode()).hexdigest()[:16]

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

        def _ha_decide(self):
            """POST /v1/hooks/ha/decide, authenticated by the dedicated hook key
            only (the agent client key is refused here, the hook key everywhere
            else). Responses never carry request details."""
            hook = broker.ha_hook
            peer = self.client_address[0]
            if hook is None:
                return _json(self, 404, {"error": "not found"})
            auth = self.headers.get("Authorization", "")
            presented = auth[7:] if auth[:7].lower() == "bearer " else ""
            if not (presented and secrets.compare_digest(presented.encode(), hook["key"].encode())):
                self.close_connection = True
                if not broker.ha_unauth_ok(peer):       # shared bucket, no per-IP state
                    return _json(self, 429, {"ok": False})
                broker.log("auth_failed", peer=peer, method=self.command,
                           path="/v1/hooks/ha/decide")
                return _json(self, 403, {"ok": False})
            if not broker.ha_rate_ok(peer):
                self.close_connection = True
                return _json(self, 429, {"ok": False})
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                n = -1
            if n < 0 or n > 2048:
                self.close_connection = True
                return _json(self, 413 if n > 2048 else 400, {"ok": False})
            try:
                body = json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                body = None
            ok_id = lambda v, mx: isinstance(v, str) and re.fullmatch(  # noqa: E731
                r"[A-Za-z0-9_-]{1,%d}" % mx, v) is not None
            dev = body.get("device") if isinstance(body, dict) else None
            dev = None if dev == "" else dev        # templates send "" for "no device id"
            if (not isinstance(body, dict) or body.get("decision") not in ("approve", "deny")
                    or not ok_id(body.get("rid"), 64) or not ok_id(body.get("token"), 128)
                    or (dev is not None and not (isinstance(dev, str)
                                                 and notify_mod.DEVICE_RE.match(dev)))):
                return _json(self, 400, {"ok": False})
            if hook["allowed_devices"] and dev not in hook["allowed_devices"]:
                broker.log("ha_decide_refused", user=f"ha:{dev or 'unknown'}", peer=peer,
                           status=403, reason="device not allowed")
                return _json(self, 403, {"ok": False})
            code, _ = broker.decide_via("ha", body["rid"], body["decision"], f"ha:{dev or 'unknown'}",
                                        token=body["token"], peer=peer)
            if code == 200:
                return _json(self, 200, {"ok": True, "decision": body["decision"]})
            return _json(self, code, {"ok": False})

        def do_POST(self):
            if self.path.split("?")[0] == "/v1/hooks/ha/decide":
                return self._ha_decide()
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
                            "var": body.get("var"), "allowed_hosts": body.get("allowed_hosts"),
                            "ssh": body.get("ssh") is True}
                elif mode == "ssh_sign":
                    spec = {"data_b64": body.get("data_b64"), "flags": body.get("flags", 0)}
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
            if u.path == "/v1/status":
                return _json(self, 200, broker.status())
            if u.path in ("/v1/audit", "/v1/audit/verify"):
                code, body, hdrs = audit_view.handle(u.path, u.query, key_id)
                return _json(self, code, body, hdrs)
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

        def _dashboard(self, user, fragment=False, note="", q=None):
            notes = {"approved": "Approved. Releasing now.", "denied": "Denied.",
                     "always": "Approved, and always allowed from now on.",
                     "grant": "Approved, and further requests are approved for a while.",
                     "revoked": "Grant revoked.",
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
                cards.append(
                    f"<article class=req data-id='{html.escape(r.id)}'>"
                    f"<div class=reqhead><h2>{html.escape(', '.join(r.names))}</h2>"
                    f"<time data-exp='{int(r.expires)}'>expires in "
                    f"{max(0, int(r.expires - time.time()))}s</time></div>{_risk_html(r)}"
                    f"<div class=box>From: {html.escape(r.source)}<br>{what}</div>"
                    f"<p><small>{rnote}</small></p>"
                    "<form method=post action='/decide' class=decide>"
                    f"<input type=hidden name=id value='{html.escape(r.id)}'>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    f"{_approve_actions(broker, r)}</form></article>")
            # the card must refresh when its assessment arrives, not only when requests come and go
            version = hashlib.sha256(
                "|".join(f"{r.id}:{1 if r.risk else 0}" for r in reqs).encode()).hexdigest()[:16]
            inner = ("".join(cards) if cards else
                     "<div class='card empty'>Nothing is waiting for approval.</div>")
            block = f"<div id=cards class=cards data-version='{version}'>{inner}</div>"
            pend_ids = {r.id for r in broker._by_id.values() if r.status == "pending"}
            a = self._hist_args(q or {})
            if fragment:
                return _page(self, 200, block + self._hist_list(a, pend_ids), nav=False)
            recent = self._recent_history(a, pend_ids)
            msg = notes.get(note, "")
            _page(self, 200,
                  f"<div id=flash class=flash{'' if msg else ' hidden'}>{html.escape(msg)}</div>"
                  "<div id=offline class='flash offline' hidden>Cannot reach the broker (signed out?). "
                  "Reload this page.</div><h3 style='margin-top:0'>Waiting for you</h3>"
                  + block + recent + self._detail_dialog(), script=_DASH_JS, tab="requests",
                  badge=len(reqs), user=user)

        def _hist_args(self, q):
            """History list state from a query string: view=all turns on the search
            box, filters and paging; without it the list is the last few rows."""
            def arg(k):
                return (q.get(k) or [""])[0][:60]
            a = {"all": arg("view") == "all", "q": arg("q").strip(), "outcome": "", "secret": "",
                 "mode": ""}
            if a["all"]:
                if arg("outcome") in OUTCOMES + ("unknown",) and arg("outcome") != "pending":
                    a["outcome"] = arg("outcome")
                a["secret"] = arg("secret")
                if arg("mode") in ("http", "env", "store", "ssh_sign"):
                    a["mode"] = arg("mode")
            try:
                n = int(arg("limit") or HIST_PAGE)
            except ValueError:
                n = HIST_PAGE
            a["limit"] = min(max(n, HIST_PAGE), HIST_MAX) if a["all"] else HIST_RECENT
            return a

        def _hist_list(self, a, pend_ids):
            """The `#hlist` block: rows, then the footer. The same markup for the
            first view, filtered views, "show more" and the live poll."""
            rows = [r for r in broker.history.rows(
                pend_ids, a["outcome"] or None, a["secret"] or None, a["mode"] or None,
                a["q"] or None) if r["outcome"] != "pending"]
            total, rows = len(rows), rows[:a["limit"]]
            good, bad = ("approved", "auto-approved"), ("denied", "failed")
            today = time.strftime("%Y-%m-%d", time.gmtime())
            items = []
            for r in rows:
                if r["mode"] == "http":
                    what = f"{r['method'] or ''} {r['url'] or ''}".strip()
                elif r["mode"] == "store":
                    what = f"{r['op'] or 'store'} credential"
                elif r["mode"] == "ssh_sign":
                    what = r.get("ssh_what") or "ssh signature"
                else:
                    what = "env"
                kind = "ok" if r["outcome"] in good else "bad" if r["outcome"] in bad else "plain"
                when = r["time"][11:16] if r["time"][:10] == today else r["time"][5:10] + " " + r["time"][11:16]
                items.append(
                    f"<li><button type=button class=hrow data-id='{html.escape(r['id'])}' "
                    f"aria-haspopup=dialog><span class=what><b>{html.escape(', '.join(r['names']))}</b>"
                    f"<small>{html.escape(what[:120])}</small></span>"
                    f"<span class='pill {kind}'>{html.escape(r['outcome'])}</span>"
                    f"<span class=when title='{html.escape(r['time'])}'>{html.escape(when)}</span>"
                    "</button></li>")
            if items:
                body = "".join(items)
            else:
                body = ("<li class='muted empty'>No requests match.</li>" if a["all"] or a["q"] else
                        "<li class='muted empty'>No requests yet.</li>")
            if a["all"]:
                qs = urllib.parse.urlencode(
                    [("view", "all")] + [(k, a[k]) for k in ("q", "outcome", "secret", "mode") if a[k]])
                foot = ""
                if total > len(rows):
                    foot += (f"<a class=more-link data-hact=more href='/?{html.escape(qs)}"
                             f"&amp;limit={a['limit'] + HIST_PAGE}'>Show more "
                             f"({total - len(rows)} older)</a>")
                foot += "<a class=more-link data-hact=less href='/'>Show recent only</a>"
                foot += f"<span class=muted>{total} request{'' if total == 1 else 's'}</span>"
            else:
                foot = ("<a class=more-link data-hact=all href='/?view=all'>"
                        "Search and filter all history</a>")
            return (f"<div id=hlist data-all={'1' if a['all'] else '0'} data-limit={a['limit']}>"
                    f"<ul class=hist>{body}</ul><div class=hfoot>{foot}</div></div>")

        def _recent_history(self, a, pend_ids):
            def opt(vals, cur, label):
                o = "".join(f"<option value='{html.escape(v)}'{' selected' if v == cur else ''}>"
                            f"{html.escape(v)}</option>" for v in vals)
                return f"<option value=''>{label}</option>{o}"
            outcomes = tuple(o for o in OUTCOMES if o != "pending") + ("unknown",)
            form = (f"<form id=hform class=hfilters method=get action='/'{'' if a['all'] else ' hidden'}>"
                    "<input type=hidden name=view value=all>"
                    f"<input type=search name=q value='{html.escape(a['q'])}' maxlength=60 "
                    "placeholder='Search secret, URL, source, id' aria-label='Search history'>"
                    f"<select name=outcome aria-label=Outcome>{opt(outcomes, a['outcome'], 'any outcome')}</select>"
                    f"<select name=secret aria-label=Secret>"
                    f"{opt(broker.history.secrets_seen(), a['secret'], 'any secret')}</select>"
                    f"<select name=mode aria-label=Mode>"
                    f"{opt(('http', 'env', 'store', 'ssh_sign'), a['mode'], 'any mode')}</select>"
                    "<noscript><button>Filter</button></noscript></form>")
            return ("<section id=recent><h3>History</h3><div class='card flush'>"
                    f"{form}{self._hist_list(a, pend_ids)}</div></section>")

        def _detail_dialog(self):
            return ("<dialog id=hdlg class=dlg aria-labelledby=hdt><div class=dhead>"
                    "<h2 id=hdt>Request details</h2>"
                    "<button type=button id=hclose class='btn sm'>Close</button></div>"
                    "<div id=hbody class=dbody></div></dialog>")

        def _request_detail(self, user, rid, fragment):
            """GET /request/<id>: everything the audit log holds about one finished
            request, as server-escaped HTML. Pending requests are refused (they
            have cards); an unknown or malformed id is a plain 404."""
            pend_ids = {r.id for r in broker._by_id.values() if r.status == "pending"}
            row, evs = broker.history.detail(rid, pend_ids)
            if row is None or rid in pend_ids or row["outcome"] == "pending":
                code = 404 if row is None else 409
                msg = "Request not found." if row is None else "That request is still waiting."
                if fragment:
                    return self._fragment(code, f"<p class=muted>{msg}</p>")
                return _page(self, code, f"<h1>{msg}</h1>", tab="requests",
                             badge=len(broker.pending()), user=user)
            broker.log("request_detail_viewed", peer=self.client_address[0],
                       client_ip=self._fwd(), request_id=rid)
            body = _detail_html(row, evs)
            if fragment:
                return self._fragment(200, body)
            _page(self, 200, "<h1>Request</h1><div class=card>" + body + "</div>",
                  tab="requests", badge=len(broker.pending()), user=user)

        def _fragment(self, code, body):
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(raw)

        def _settings_page(self, user, note=""):
            token = broker.csrf_token(user)
            notes = {"push_removed": "Device removed.",
                     "push_test_ok": "Test push sent. It should arrive even with the browser closed.",
                     "push_failed": "The test push was not delivered to any device."}
            msg = notes.get(note, "")
            auto = _AUTO_LABEL[broker.auto_approve_max()]
            push_row = self._push_enable_row(token) if broker.push is not None else ""
            devices = self._push_devices(token) if broker.push is not None else ""
            _page(self, 200,
                  "<h1>Settings</h1>"
                  f"<div class=flash{'' if msg else ' hidden'}>{html.escape(msg)}</div>"
                  "<section class=card><h2>Broker</h2><div class=srow><div class=t>"
                  "<b>Auto-approve</b><small class=muted>"
                  f"{html.escape(auto[0].upper() + auto[1:])}."
                  " Applies only to secrets set to always allow; set in the broker config "
                  "(risk.auto_approve_max).</small></div></div>"
                  "<div class=srow><div class=t><b>Time-boxed grants</b><small class=muted>"
                  f"{html.escape(grants_mod.describe(broker.grants_cfg))}. "
                  "Set in the broker config (timed_grants).</small></div></div></section>"
                  "<section class=card><h2>This browser</h2>"
                  "<div class=srow><div class=t><b>Notifications while this page is open</b>"
                  "<small id=notify-state class=muted></small></div>"
                  "<button id=notify class=btn type=button hidden></button></div>"
                  + push_row +
                  "<div class=srow><div class=t><b>Test</b>"
                  "<small id=notify-why class=muted>Shows a notification on this device.</small></div>"
                  "<button id=notify-test class=btn type=button hidden>Send a test notification"
                  "</button></div>" + self._sw_block() + "</section>" + devices,
                  script=_DASH_JS, tab="settings", user=user)

        def _sw_block(self):
            # Filled in by _DASH_JS; the expected version comes from the same constant /sw.js serves
            def row(id_, label):
                return (f"<div class=srow><div class=t><b>{label}</b>"
                        f"<small id={id_} class=muted>...</small></div></div>")
            return (
                f"<div id=sw-box data-expected='{html.escape(SW_VERSION)}'>"
                "<div class=srow><div class=t><b>Service worker</b>"
                "<small id=sw-note class=muted></small></div>"
                "<span id=sw-status class='pill plain'>Checking</span></div>"
                + row("sw-expected", "Expected (server)") + row("sw-running", "Running (active worker)")
                + row("sw-waiting", "Waiting / installing")
                + row("sw-controlled", "This tab is controlled by the worker")
                + row("sw-reg", "Registration") + row("sw-sub", "Push subscription")
                + row("sw-caches", "Caches")
                + "<div class=srow><div class=t>"
                "<button id=sw-update class=btn type=button hidden>Update worker now</button> "
                "<button id=sw-clear class=btn type=button hidden>Clear caches</button> "
                "<button id=sw-recheck class=btn type=button>Recheck</button></div></div></div>")

        def _push_enable_row(self, token):
            return (
                "<div class=srow><div class=t><b>Notifications with the browser closed</b>"
                "<small id=push-state class=muted></small></div>"
                f"<button id=push-enable class=btn type=button hidden data-key='"
                f"{html.escape(broker.push.public_key())}' data-csrf='{token}'>Enable on this "
                "device</button></div>")

        def _push_devices(self, token):
            rows = []
            for d in broker.push.devices():
                when = time.strftime("%Y-%m-%d", time.gmtime(d["created"] or 0))
                ok = d["last_ok"]
                status = ("<span class='pill ok'>last delivery OK</span>" if ok else
                          f"<span class='pill bad'>{html.escape(str(d['last_error']))[:60]}</span>"
                          if d["last_error"] else "<span class='pill plain'>not used yet</span>")
                rows.append(
                    f"<li><div class=t><b>{html.escape(_agent_label(d['agent']))}</b>"
                    f"<small class=muted>{html.escape(d['user'])}, added {when}</small></div>"
                    f"{status}"
                    "<form method=post action='/push/revoke' class=inline>"
                    f"<input type=hidden name=id value='{html.escape(d['id'])}'>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    "<button class='btn sm deny'>Remove</button></form></li>")
            test = ("<form method=post action='/push/test' class=inline>"
                    f"<input type=hidden name=csrf value='{token}'>"
                    "<button class='btn sm'>Send a test push</button></form>" if rows else "")
            return (
                "<section class='card flush'><div class=chead><h2>Devices receiving push</h2>"
                f"{test}</div>"
                "<p class=cnote><small class=muted>The message carries only the secret names; "
                "decisions still happen here, after you sign in.</small></p>"
                f"<ul class=devices>{''.join(rows) or '<li class=muted>No devices yet.</li>'}</ul>"
                "</section>")

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
            self.send_header("X-SW-Version", SW_VERSION)
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
                if sc.get("approval", "prompt") != "allow":
                    continue
                by = (sc.get("approval_changed") or {}).get("by")
                rows.append(
                    f"<tr><td data-label=Secret><b>{html.escape(name)}</b></td>"
                    f"<td data-label='Allowed by'>{html.escape(by or '')}</td>"
                    "<td><form method=post class=inline>"
                    f"<input type=hidden name=csrf value='{broker.csrf_token(user)}'>"
                    f"<input type=hidden name=name value='{html.escape(name)}'>"
                    "<button name=approval value=prompt>Revoke</button></form></td></tr>")
            table = ("<table class=tbl><thead><tr><th>Secret</th><th>Allowed by</th><th></th></tr></thead>"
                     "<tbody>" + "".join(rows) + "</tbody></table>" if rows else
                     "<div class='card empty'>Nothing is always allowed. Every use asks you first.</div>")
            _page(self, 200, f"<h1>Policies</h1>{note}{self._grants_section(user)}"
                  "<h3>Always allowed</h3>"
                  "<p><small class=muted>These secrets are released without asking when the request's "
                  f"risk is within the auto-approve limit ({_AUTO_LABEL[broker.auto_approve_max()]}). "
                  "Revoke to ask every time again.</small></p>" + table,
                  script=_GRANTS_JS, tab="policies", badge=len(broker.pending()), user=user)

        def _grants_section(self, user):
            """'Active grants' card on the Policies tab: who allowed what, time left, Revoke."""
            head = ("<h3 style='margin-top:0'>Active grants</h3><p><small class=muted>Time-boxed "
                    "approvals: until the clock runs out, requests for these secrets that the broker "
                    "runs itself are approved without asking, when the request names exactly the same secrets. Revoke to ask every time again."
                    "</small></p>")
            if not broker.grants_cfg["enabled"]:
                return head + "<div class='card empty'>Time-boxed grants are turned off.</div>"
            rows = []
            for g in broker.active_grants():
                rows.append(
                    f"<tr><td data-label=Secret><b>{html.escape(', '.join(g['secrets']))}</b></td>"
                    f"<td data-label=Covers>{'reads only' if g['scope'] == 'read' else 'all requests'}</td>"
                    f"<td data-label='Time left'><time data-gexp='{int(g['expires_at'])}'>"
                    f"{html.escape(_left(g['left_s']))}</time></td>"
                    f"<td data-label='Allowed by'>{html.escape(g['created_by'])}"
                    f" <small class=muted>({int(g['minutes'])} min)</small></td>"
                    "<td><form method=post action='/grants/revoke' class=inline>"
                    f"<input type=hidden name=csrf value='{broker.csrf_token(user)}'>"
                    f"<input type=hidden name=grant value='{html.escape(g['id'])}'>"
                    "<button>Revoke</button></form></td></tr>")
            if not rows:
                return head + "<div class='card empty'>No active grants</div>"
            return (head + "<table class=tbl><thead><tr><th>Secrets</th><th>Covers</th><th>Time left</th>"
                    "<th>Allowed by</th><th></th></tr></thead><tbody>" + "".join(rows)
                    + "</tbody></table>")

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
                return self._dashboard(user, fragment=frag, note=(q.get("note") or [""])[0][:12], q=q)
            if self.path.split("?")[0].rstrip("/") == "/history":
                # the old standalone table: the same list now lives on the Requests tab
                q = urllib.parse.parse_qs(u.query)
                keep = [("view", "all")] + [(k, (q.get(k) or [""])[0][:60])
                                            for k in ("outcome", "secret", "mode") if (q.get(k) or [""])[0]]
                return self._redirect("/?" + urllib.parse.urlencode(keep))
            if u.path.startswith("/request/"):
                q = urllib.parse.parse_qs(u.query)
                return self._request_detail(user, u.path[len("/request/"):],
                                            q.get("fragment", [""])[0] == "1")
            if self.path.split("?")[0].rstrip("/") == "/settings":
                q = urllib.parse.parse_qs(u.query)
                return self._settings_page(user, (q.get("note") or [""])[0][:12])
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
            _page(self, 200, f"""
<h1>Secret request</h1>
<p><b>{html.escape(', '.join(req.names))}</b></p>
{summary_html}
<div class=box>From: {html.escape(req.source)}<br>{what}</div>
<p><small>{note}</small></p>
<p><small>Expires in {int(req.expires - time.time())}s</small></p>
<form method=post id=f>
{_approve_actions(broker, req)}
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
                return self._redirect("/settings?note=push_removed")
            if path == "/push/test":
                ok, errors = broker.push.send_all({"title": "Test notification",
                                                   "body": "Push notifications work on this device.",
                                                   "tag": "test"})
                broker.log("push_test", user=user, delivered=ok, errors=errors[:3], peer=peer,
                           client_ip=fwd)
                return self._redirect("/settings?note=" + ("push_test_ok" if ok else "push_failed"))
            return self._json(404, {"ok": False})

        _ce_state = {}

        def _client_event(self, user):
            peer, fwd = self.client_address[0], self._fwd()
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                n = -1
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if (self.headers.get("X-Requested-With") != "asb" or ctype != "application/json"
                    or not self._same_origin()):
                self.close_connection = True
                return self._json(403, {"ok": False})
            if n < 0 or n > 2048:
                self.close_connection = True
                return self._json(413, {"ok": False})
            raw = self.rfile.read(n)
            try:
                ev = sanitize_client_event(json.loads(raw.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                ev = None
            if ev is None:
                return self._json(400, {"ok": False})
            now = time.time()
            with _CE_LOCK:
                st = self._ce_state.get(user)
                if st is None:
                    Broker.rate_map_make_room(self._ce_state, now)   # full: evict oldest
                    st = self._ce_state[user] = {"t": now, "n": 0, "drop": 0}
                if now - st["t"] >= 60:
                    prev = st["drop"]
                    st.update(t=now, n=0, drop=0)
                    if prev > 1:
                        broker.log("client_event_dropped", user=user, dropped=prev,
                                   limit_per_min=_CE_LIMIT, final=True, peer=peer, client_ip=fwd)
                st["n"] += 1
                over = st["n"] > _CE_LIMIT
                if over:
                    st["drop"] += 1
                    first = st["drop"] == 1
            if over:
                if first:
                    broker.log("client_event_dropped", user=user, dropped=1,
                               limit_per_min=_CE_LIMIT, peer=peer, client_ip=fwd)
            else:
                broker.log("client_event", user=user, peer=peer, client_ip=fwd, **ev)
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _push_decide(self, user):
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            try:
                n = int(self.headers.get("Content-Length", 0))
            except ValueError:
                n = -1
            if (self.headers.get("X-Requested-With") != "asb" or ctype != "application/json"
                    or not self._same_origin()):
                self.close_connection = True
                broker.log("push_decide_refused", user=user, peer=self.client_address[0],
                           client_ip=self._fwd(), status=403, reason="guard")
                return self._json(403, {"ok": False})
            if n < 0 or n > 2048:
                self.close_connection = True
                return self._json(413, {"ok": False})
            try:
                body = json.loads(self.rfile.read(n).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                body = None
            if (not isinstance(body, dict) or body.get("decision") not in ("approve", "deny")
                    or not isinstance(body.get("token"), str) or not body["token"]
                    or not isinstance(body.get("rid", ""), str)):
                return self._json(400, {"ok": False})
            code, _ = broker.decide_push(body.get("rid") or None, body["token"],
                                         body["decision"] == "approve", user,
                                         self.client_address[0], self._fwd())
            if code == 200:
                return self._json(200, {"ok": True, "decision": body["decision"]})
            return self._json(code, {"ok": False})

        def do_POST(self):
            user = self._user()
            if user is None:
                return
            if self.path.split("?")[0].rstrip("/") == "/push/event":
                return self._client_event(user)
            if self.path.split("?")[0].rstrip("/") == "/push/decide":
                return self._push_decide(user)
            form = urllib.parse.parse_qs(
                self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 8192)).decode())
            path = self.path.split("?")[0].rstrip("/")
            if path in ("/decide", "/policies", "/grants/revoke", "/push/subscribe", "/push/revoke",
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
                parsed = _parse_decision(decision)
                if parsed is None or r is None:
                    return self._redirect("/?note=stale")
                code, done = broker.decide_via(
                    "dashboard", rid, parsed[0], user, always=parsed[1], grant_minutes=parsed[2],
                    peer=self.client_address[0], client_ip=self._fwd())
                if done is None:
                    return self._redirect("/?note=" + ("bad" if code == 400 else "stale"))
                tag = ("denied" if decision == "deny" else
                       "always" if done.always == "applied" else
                       "grant" if parsed[2] is not None else "approved")
                return self._redirect(f"/?note={tag}")
            if path == "/grants/revoke":
                gid = form.get("grant", [""])[0][:16]
                done = broker.revoke_grant(gid, user, self.client_address[0], self._fwd())
                return self._policies_page(
                    user, f"<p>{'Grant revoked' if done else 'That grant is no longer active'}.</p>")
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
            parsed = _parse_decision(decision) or ("deny", False, None)
            approve = parsed[0] == "approve"
            code, req = (broker.decide_via("link", None, parsed[0], user, nonce=nonce,
                                           always=parsed[1], grant_minutes=parsed[2],
                                           peer=self.client_address[0], client_ip=self._fwd())
                         if nonce else (404, None))
            if code == 400:
                return _page(self, 400, "<h1>That duration is not available</h1>"
                             "<p>Go back and pick one of the offered options.</p>")
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
            if parsed[2] is not None:
                extra += (f"<p>Further requests for <b>{html.escape(', '.join(req.names))}</b> are "
                          f"approved for {parsed[2]} minutes (same secrets only). Revoke it at "
                          "<a href='/policies'>/policies</a>.</p>")
            _page(self, 200, "<h1>Approved</h1><p>Releasing now. You can close this page.</p>" + extra)

    return H


def serve(broker, client_addr, approval_addr, client_key):
    if broker.ha_hook is not None and secrets.compare_digest(
            broker.ha_hook["key"].encode(), client_key.encode()):
        raise ValueError("ha_hook key must differ from the agent client key")
    c = ThreadingHTTPServer(client_addr, client_handler(broker, client_key))
    a = ThreadingHTTPServer(approval_addr, approval_handler(broker))
    for s in (c, a):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return c, a
