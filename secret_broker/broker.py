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
import html
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import AuditLog
from .backends import BackendError
from .notify import NotifyError
from . import risk as risk_mod

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
        self.risk = None          # {"level","baseline","model","reasons"}
        self.always = None        # outcome of an "always allow" click, if any
        self.approver = None
        self.done = threading.Event()


class Broker:
    def __init__(self, config, backend, notifier, audit=None, summarizer=None, config_path=None):
        self.cfg = config
        self._config_path = config_path
        self._cfg_lock = threading.Lock()
        self.summarizer = summarizer
        self.backend = backend
        self.notifier = notifier
        self._audit = audit if isinstance(audit, AuditLog) else AuditLog(audit)
        self._lock = threading.Lock()
        self._by_id = {}
        self._by_nonce = {}
        self._denied_at = {}
        if hasattr(backend, "on_event"):
            backend.on_event = self.log
        for name, sc in config["secrets"].items():
            if sc.get("approval", "prompt") not in APPROVAL_VALUES:
                raise ValueError(f"secret {name!r}: approval must be one of {APPROVAL_VALUES}")
            if sc.get("sensitivity", "medium") not in risk_mod.LEVELS:
                raise ValueError(f"secret {name!r}: sensitivity must be one of {risk_mod.LEVELS}")
        esc = config.get("risk", {}).get("escalate_auto_at")
        if esc is not None and esc not in risk_mod.LEVELS:
            raise ValueError(f"risk.escalate_auto_at must be one of {risk_mod.LEVELS}")
        self.log("startup", policies={
            n: {"approval": sc.get("approval", "prompt"), "auto_modes": self._auto_modes(sc)}
            for n, sc in sorted(config["secrets"].items())})

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
            rec.update(op=sp.get("op"), item=sp.get("item"), field=sp.get("field"),
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

    def _auto_allowed(self, mode, names):
        if mode == "store":
            return False                    # writing credentials always needs a human
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
        if not self._config_path:
            return False, "the broker has no config file to record this in"
        esc = self.cfg.get("risk", {}).get("escalate_auto_at")
        if esc:
            sens = sc.get("sensitivity", "medium")
            if risk_mod.rank(sens) >= risk_mod.rank(esc):
                return False, f"{name} is marked {sens} sensitivity, so it would still prompt"
            if req.risk and risk_mod.rank(req.risk["level"]) >= risk_mod.rank(esc):
                return False, f"this request is rated {req.risk['level']}; such requests always prompt"
        return True, ""

    def _persist_approval(self, name, value, user):
        def mutate(disk):
            entry = disk["secrets"][name]
            entry["approval"] = value
            entry["approval_changed"] = {
                "by": user, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self._write_config(mutate)

    def _write_config(self, mutate):
        """Read-modify-write the config file atomically, preserving its mode."""
        path = self._config_path
        with open(path) as f:
            disk = json.load(f)
        mutate(disk)
        mode = os.stat(path).st_mode & 0o777
        tmp = f"{path}.tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(disk, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

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
            except (OSError, ValueError, KeyError) as e:
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
        variable names only; this never touches the backend or the notifier."""
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
        a = risk_mod.assess(mode, names, spec, self.cfg["secrets"], self.summarizer)
        req.summary, req.risk = a["summary"], {k: a[k] for k in ("level", "baseline", "model", "reasons")}
        self.audit("assessed", req, baseline=a["baseline"], model=a["model"], reasons=a["reasons"])
        auto = self._auto_allowed(mode, names)
        esc = self.cfg.get("risk", {}).get("escalate_auto_at")
        if auto and esc and risk_mod.rank(a["level"]) >= risk_mod.rank(esc):
            self.audit("escalated", req, reason=f"risk {a['level']} >= {esc}; policy allow overridden")
            auto = False
        if auto:
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
            if not self._config_path:
                raise PermissionError("the broker has no config file to record a new secret in")
            hosts = spec.get("allowed_hosts")
            if (not isinstance(hosts, list) or not 1 <= len(hosts) <= 10
                    or not all(isinstance(h, str) and _HOST_RE.match(h) for h in hosts)):
                raise ValueError("allowed_hosts must be 1-10 plain hostnames")
            spec["allowed_hosts"] = sorted(set(h.lower() for h in hosts))
            spec["field"] = spec.get("field") or "notes"
            spec["item"] = spec.get("item") or name
            spec["var"] = spec.get("var") or re.sub(r"[^A-Za-z0-9]", "_", name).upper() + "_TOKEN"
            if not _FIELD_RE.match(spec["field"]) or spec["field"] in ("previous_value", "previous_replaced_at"):
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
            spec["var"], spec["item"], spec["field"] = var, ref["item"], ref["field"]
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
            what = (f"{sp['op']} credential: item {sp['item']!r} field {sp['field']} "
                    f"({sp['value_bytes']} bytes, value not shown)")
        else:
            what = "run: " + " ".join(req.spec.get("argv") or [])[:200]
        head = f"{req.summary} (unverified)\n" if req.summary else ""
        why = f"\nWhy: {'; '.join(req.risk['reasons'][:3])}" if req.risk and req.risk["reasons"] else ""
        msg = f"{head}{', '.join(req.names)} from {req.source}\n{what}{why}"
        title = f"Secret request [{req.risk['level'].upper()}]" if req.risk else "Secret request"
        self.notifier.send(title, msg, url, f"secret-{req.id[:8]}")
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

    def decide(self, nonce, approve, user, peer=None, client_ip=None, always=False):
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
        who = {"via": "user", "approver": user, "approver_peer": peer, "approver_ip": client_ip}
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
        """Write the credential to the vault; for a create, also map it in the config."""
        sp = req.spec
        name, by = req.names[0], req.approver or "unknown"
        if not hasattr(self.backend, "put"):
            raise BackendError("this backend cannot store credentials")
        t0 = time.time()
        if sp["op"] == "create":
            self.backend.put(sp["item"], sp["field"], sp["value"], create=True)
            entry = {"vars": {sp["var"]: {"item": sp["item"], "field": sp["field"]}},
                     "allowed_hosts": sp["allowed_hosts"], "approval": "prompt", "sensitivity": "medium"}
            try:
                with self._cfg_lock:
                    stamp = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                    self._write_config(lambda disk: disk["secrets"].__setitem__(
                        name, {**entry, "created": stamp}))
                    self.cfg["secrets"][name] = {**entry, "created": stamp}
            except Exception as e:  # noqa: BLE001
                # no half-finished state: remove the item we just created
                try:
                    self.backend.delete(sp["item"])
                except Exception:  # noqa: BLE001
                    self.audit("store_rollback_failed", req, item=sp["item"])
                raise BackendError(f"config not updated, vault change rolled back: {e}") from None
        else:
            self.backend.put(sp["item"], sp["field"], sp["value"], create=False, keep_previous=True)
        self.audit("stored", req, duration_ms=int((time.time() - t0) * 1000))
        return {"stored": {"name": name, "op": sp["op"], "item": sp["item"], "field": sp["field"]}}

    def _release(self, req):
        if req.mode == "store":
            return self._store(req)
        env = {}
        for n in req.names:
            for var, ref in self.cfg["secrets"][n]["vars"].items():
                env[var] = self.backend.get(ref["item"], ref["field"])
            self.audit("secret_read", req, secret=n, vars=sorted(self.cfg["secrets"][n]["vars"]))
        if req.mode == "env":
            return {"env": env}
        t0 = time.time()
        try:
            out = _do_http(req.spec, env)
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


def _do_http(spec, env):
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
        with _opener.open(req, timeout=30) as r:
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


def _page(h, code, body):
    raw = ("<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
           "<body style='font-family:system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem'>"
           + body).encode()
    h.send_response(code)
    h.send_header("Content-Type", "text/html; charset=utf-8")
    h.send_header("Content-Length", str(len(raw)))
    h.send_header("Cache-Control", "no-store")
    h.end_headers()
    h.wfile.write(raw)


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
            user = self.headers.get(cfg.get("identity_header", "X-authentik-username"), "")
            if user != cfg["allowed_user"]:
                broker.log("approval_forbidden", claimed_user=user[:80], peer=self.client_address[0],
                           client_ip=self._fwd(), method=self.command)
                _page(self, 403, "<h1>Forbidden</h1>")
                return None
            return user

        def _nonce(self):
            parts = self.path.split("?")[0].strip("/").split("/")
            return parts[1] if len(parts) == 2 and parts[0] == "a" else None

        def _policies_page(self, note=""):
            rows = []
            for name, sc in sorted(cfg["secrets"].items()):
                state = sc.get("approval", "prompt")
                by = (sc.get("approval_changed") or {}).get("by")
                btn = ""
                if state == "allow":
                    btn = ("<form method=post style='display:inline'>"
                           f"<input type=hidden name=name value='{html.escape(name)}'>"
                           "<button name=approval value=prompt>Require approval again</button></form>")
                rows.append(f"<tr><td><b>{html.escape(name)}</b></td><td>{html.escape(state)}"
                            f"{' (set by ' + html.escape(by) + ')' if by and state == 'allow' else ''}</td>"
                            f"<td>{btn}</td></tr>")
            _page(self, 200, f"<h1>Standing approvals</h1>{note}<table cellpadding=8>"
                  "<tr><th align=left>Secret</th><th align=left>Policy</th><th></th></tr>"
                  + "".join(rows) + "</table>")

        def do_GET(self):
            if self._user() is None:
                return
            if self.path.split("?")[0].rstrip("/") == "/policies":
                broker.log("policies_viewed", peer=self.client_address[0], client_ip=self._fwd())
                return self._policies_page()
            nonce = self._nonce()
            req = broker._by_nonce.get(nonce) if nonce else None
            broker.log("approval_viewed", user=self.headers.get(
                cfg.get("identity_header", "X-authentik-username"), ""), peer=self.client_address[0],
                client_ip=self._fwd(), request_id=req.id if req else None,
                found=bool(req and req.status == "pending" and time.time() <= req.expires))
            if req is None or req.status != "pending" or time.time() > req.expires:
                return _page(self, 404, "<h1>Request not found or already handled</h1>")
            if req.mode == "http":
                what = f"{html.escape(req.spec['method'])} {html.escape(req.spec['url'])}"
                note = "The broker will make this call itself; the secret never leaves it."
            elif req.mode == "store":
                sp = req.spec
                hosts = (f"<br>Usable only for: {html.escape(', '.join(sp['allowed_hosts']))}"
                         if sp.get("allowed_hosts") else "<br>Hosts and mapping stay unchanged")
                what = (f"<b>{html.escape(sp['op'].upper())}</b> credential in the vault<br>"
                        f"Item: {html.escape(sp['item'])}, field: {html.escape(sp['field'])}{hosts}<br>"
                        f"New value: {sp['value_bytes']} bytes (never displayed)")
                note = ("An update replaces the current value; the old one is kept in the item's "
                        "previous_value field. This will not run without your approval.")
            else:
                what = "run <code>" + html.escape(" ".join(req.spec.get("argv") or [])) + "</code>"
                note = ("Advisory only: the secret is released to the requesting host and the "
                        "command shown is what it <em>said</em> it would run.")
            lvl = req.risk["level"] if req.risk else "medium"
            color = {"low": "#1a7f37", "medium": "#9a6700", "high": "#cf222e"}[lvl]
            risk_html = (f"<p style='border-left:6px solid {color};padding-left:.6rem'>"
                         f"<b style='color:{color}'>{lvl.upper()} RISK</b><br><small>"
                         + html.escape("; ".join(req.risk["reasons"]) if req.risk else "")
                         + "</small></p>")
            ok, why = broker.always_allow_eligibility(req)
            if ok:
                always_html = (
                    "<p><button name=decision value=approve_always style='font-size:1rem;padding:.7rem 1.2rem'>"
                    f"Approve and always allow {html.escape(req.names[0])}</button><br><small>"
                    "Future HTTP calls with this secret will run without asking, except requests "
                    "rated high risk. Revoke any time at /policies.</small></p>")
            else:
                always_html = f"<p><small>Always allow not offered: {html.escape(why)}.</small></p>"
            summary_html = risk_html + (
                f"<p>AI summary <small>(unverified, from client-supplied text)</small>:<br>"
                f"<i>{html.escape(req.summary)}</i></p>" if req.summary else "")
            _page(self, 200, f"""
<h1>Secret request</h1>
<p><b>{html.escape(', '.join(req.names))}</b></p>
{summary_html}
<p>From: {html.escape(req.source)}<br>{what}</p>
<p><small>{note}</small></p>
<p><small>Expires in {int(req.expires - time.time())}s</small></p>
<form method=post onsubmit="setTimeout(function(){{document.querySelectorAll('button').forEach(function(b){{b.disabled=true}});document.getElementById('w').hidden=false}},0)">
<button name=decision value=approve style='font-size:1.4rem;padding:1rem 2rem'>Approve</button>
<button name=decision value=deny style='font-size:1.4rem;padding:1rem 2rem'>Deny</button>
{always_html}
</form>
<p id=w hidden>Working...</p>""")

        def do_POST(self):
            user = self._user()
            if user is None:
                return
            form = urllib.parse.parse_qs(
                self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            if self.path.split("?")[0].rstrip("/") == "/policies":
                name = form.get("name", [""])[0]
                # this page can only *tighten*: granting happens in the context of a request
                if form.get("approval", [""])[0] != "prompt" or name not in cfg["secrets"]:
                    return _page(self, 400, "<h1>Bad request</h1>")
                done = broker.set_approval(name, "prompt", user, self.client_address[0], self._fwd())
                return self._policies_page(
                    f"<p>{'Updated' if done else 'Could not update'}: {html.escape(name)}</p>")
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
