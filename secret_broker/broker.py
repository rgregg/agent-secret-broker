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
        self.done = threading.Event()


class Broker:
    def __init__(self, config, backend, notifier, audit=None, summarizer=None):
        self.cfg = config
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
        return all(mode in self._auto_modes(self.cfg["secrets"][n]) for n in names)

    # -- discovery (no approval, no push, no values) ----------------------
    def available(self, host=None):
        """Secrets usable for `host` in http mode. Names and placeholder
        variable names only; this never touches the backend or the notifier."""
        out = []
        for name, sc in sorted(self.cfg["secrets"].items()):
            hosts = sc.get("allowed_hosts") or []
            if host is None or host in hosts:
                out.append({"name": name, "vars": sorted(sc["vars"]),
                            "allowed_hosts": hosts, "approval": sc.get("approval", "prompt")})
        return out

    # -- request lifecycle ------------------------------------------------
    def create(self, mode, names, spec, source, peer=None):
        try:
            secrets_cfg = self.cfg["secrets"]
            if not names or any(n not in secrets_cfg for n in names):
                raise ValueError("unknown secret name")
            if mode == "http":
                self._validate_http(names, spec)
        except (ValueError, PermissionError) as e:
            self.log("rejected", reason=str(e), names=names, mode=mode, source=source, peer=peer,
                     url=spec.get("url") if isinstance(spec, dict) else None)
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

    def decide(self, nonce, approve, user, peer=None, client_ip=None):
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
        # The decision itself is recorded and announced immediately.
        self.audit("decided", req, decision="approve" if approve else "deny", **who)
        if not approve:
            self._finish(req, "denied", **who)
            return req
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

    def _release(self, req):
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

        def do_GET(self):
            if self._user() is None:
                return
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
</form>
<p id=w hidden>Working...</p>""")

        def do_POST(self):
            user = self._user()
            if user is None:
                return
            nonce = self._nonce()
            form = urllib.parse.parse_qs(
                self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
            approve = form.get("decision", [""])[0] == "approve"
            req = (broker.decide(nonce, approve, user, self.client_address[0], self._fwd())
                   if nonce else None)
            if req is None:
                return _page(self, 404, "<h1>Request not found or already handled</h1>")
            if approve:
                _page(self, 200, "<h1>Approved</h1><p>Releasing now. You can close this page.</p>")
            else:
                _page(self, 200, "<h1>Denied</h1>")

    return H


def serve(broker, client_addr, approval_addr, client_key):
    c = ThreadingHTTPServer(client_addr, client_handler(broker, client_key))
    a = ThreadingHTTPServer(approval_addr, approval_handler(broker))
    for s in (c, a):
        s.daemon_threads = True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return c, a
