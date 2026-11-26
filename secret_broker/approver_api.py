"""The optional `approver_api`, broker side: what the macOS approver app sees and decides.

- `AppNotifier` is an internal notify leaf (type `app`). `_push` reaches it like every other
  transport, after assessment and auto-approval and never held by presence, so a request becomes
  `notified` (and the app posts a banner) only when a human is really being asked.
- `AppFeed` is the long-poll version: it changes when a request is notified or settles, and when
  the pending set's fingerprint (ids, notified, risk, summary) changes.
- `request_view` is one pending request as the app shows it. Everything in it except the fixed
  fields is attacker-influenced text: it is cleaned of control characters and capped, the request
  details are the masked `request_details` view, and no secret value is ever in it.
- `decide` validates an app decision against `offered_actions` and goes through
  `Broker.decide_via("app", ...)`.

`handle` answers the `/v1/approver/*` routes on the client listener (dispatched before the client
key check). Every route but `config` needs the approver's OIDC bearer token; the agent's client key
is refused there, and a JWT authenticates nothing else.
"""
import collections
import hashlib
import json
import re
import threading
import time
import urllib.parse

from . import notify, oidc, standing
from . import request_details as details_mod

FETCH_JSON = None           # the verifier's fetch_json (None: oidc.default_fetch_json); tests patch this
POLL_S = 1.0                # how often a long poll re-checks the pending set's fingerprint
SUMMARY_MAX = 500
TEXT_MAX = 2000             # target lines, risk reasons
MAX_REASONS = 10
MAX_NOTIFIED = 4096         # rids remembered as notified (settled ones are forgotten at once)
BROWSER_ONLY = ("guidance", "credential", "plan", "session", "sudo")
_KEYS = frozenset({"id", "decision", "grant_minutes", "always", "rule_scope", "device"})
PREFIX = "/v1/approver"
BODY_MAX = 4096
WAIT_MAX = 25               # seconds a long poll may block
RETRY_AFTER_BUSY = "2"      # a poll that asked to wait but could not (waiter cap) backs off this long
REFUSAL_WINDOW_S = 60
API_VERSION = 1
_PRESENCE_KEYS = frozenset({"active", "device"})
_TAB_BAD = re.compile(r"[^A-Za-z0-9_-]")
_QINT = re.compile(r"^[0-9]{1,12}$")

# C0, DEL, C1; plus bidi overrides and zero-width characters, which can make plain text lie
_CTRL = re.compile("[\x00-\x1f\x7f-\x9f­؜᠎​-‏‪-‮⁠-⁯﻿]")
_CTRL_KEEP_NL = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f­؜᠎​-‏‪-‮"
                           "⁠-⁯﻿]")


def clean(s, limit, keep_newlines=False):
    """`s` as plain display text: control and invisible characters removed, at most `limit` chars."""
    if s is None:
        return None
    return (_CTRL_KEEP_NL if keep_newlines else _CTRL).sub("", str(s))[:limit]


class AppFeed:
    """Version counter + condition for the app's long poll, and which requests were notified."""

    def __init__(self, clock=time.time, max_waiters=8):
        self._clock = clock
        self.max_waiters = max_waiters
        self._cv = threading.Condition()
        self._version = 0
        self._fp = None                 # the pending set's fingerprint when last observed
        self._waiting = 0
        self._notified = collections.OrderedDict()     # rid -> banner action ids

    @property
    def version(self):
        with self._cv:
            return self._version

    @property
    def waiting(self):
        with self._cv:
            return self._waiting

    def _bump_locked(self):
        self._version += 1
        self._cv.notify_all()

    def bump(self):
        with self._cv:
            self._bump_locked()

    def mark_notified(self, rid, banner_actions):
        with self._cv:
            self._notified[rid] = list(banner_actions)
            self._notified.move_to_end(rid)
            while len(self._notified) > MAX_NOTIFIED:
                self._notified.popitem(last=False)
            self._bump_locked()

    def notified(self, rid):
        """The banner action ids the app leaf was sent for `rid`, or None if it was not notified."""
        with self._cv:
            got = self._notified.get(rid)
            return None if got is None else list(got)

    def forget(self, rid):
        with self._cv:
            self._notified.pop(rid, None)

    def _observe(self, fingerprint):
        """Compare the pending set with the last look; bump when it changed. True if it bumped.
        `fingerprint` runs outside the feed's lock (it takes the broker's)."""
        fp = fingerprint()
        with self._cv:
            changed = self._fp is not None and fp != self._fp
            self._fp = fp
            if changed:
                self._bump_locked()
            return changed

    def wait(self, since, timeout, fingerprint):
        """The current version, once it differs from `since` or `timeout` seconds pass. Answers at
        once when `since` is not the current version (a broker restart resets it) or when
        `max_waiters` calls are already waiting. While waiting, `fingerprint()` is re-checked every
        POLL_S, so a new, decided or re-rated request wakes the poll even without a notify."""
        self._observe(fingerprint)
        with self._cv:
            if since != self._version or self._waiting >= self.max_waiters or timeout <= 0:
                return self._version
            self._waiting += 1
        try:
            end = self._clock() + timeout
            while True:
                with self._cv:
                    if self._version != since:
                        return self._version
                    left = end - self._clock()
                    if left <= 0:
                        return self._version
                    self._cv.wait(min(POLL_S, left))
                    if self._version != since:
                        return self._version
                if self._observe(fingerprint):
                    return self.version
        finally:
            with self._cv:
                self._waiting -= 1


class AppNotifier:
    """The internal `app` notify leaf. Sending only records that the request was notified (and
    with which banner actions); it never raises, so it never fails or slows a request. It never
    carries the shared action token (the app decides through `offered_actions`), so its actions do
    not widen what a push/ha/telegram token may do; and reaching it alone is not a delivery that
    hides failing real transports (see notify._deliver)."""
    supports_actions = ("approve", "deny")
    carries_token = False
    counts_as_delivery = False

    def __init__(self, feed, action_policy=None):
        self.feed = feed
        self.action_policy = action_policy
        setattr(self, notify.TRANSPORT_TYPE_ATTR, "app")

    def send(self, n):
        try:
            self.feed.mark_notified(n.rid, [a.id for a in n.actions])
        except Exception:   # noqa: BLE001 -- never fails a request
            pass

    def resolved(self, n, status):
        try:
            self.feed.forget(n.rid)
            self.feed.bump()
        except Exception:   # noqa: BLE001
            pass


class Approver:
    """What `Broker.approver` holds when `approver_api` is configured."""

    def __init__(self, cfg, verifier, feed, notifier, log=None):
        self.cfg, self.verifier, self.feed, self.notifier = cfg, verifier, feed, notifier
        self._log = log
        self.clock = time.time          # the refusal-audit window's clock (tests replace it)
        self._refused = {}              # reason -> {"t": window start, "n": suppressed in it}
        self._refused_lock = threading.Lock()

    def refused(self, reason, peer):
        """Audit one token refusal, coalesced: at most one `approver_auth_refused` line per reason
        per REFUSAL_WINDOW_S. Refusals inside a window are counted, and the count rides on the next
        line for that reason as `suppressed` (a count still open when refusals stop is not
        written). Only the fixed reason and the peer; never the token or its claims."""
        if reason not in oidc.REASONS:
            reason = "malformed"
        now = self.clock()
        with self._refused_lock:
            st = self._refused.get(reason)
            if st is not None and now - st["t"] < REFUSAL_WINDOW_S:
                st["n"] += 1
                return
            suppressed = st["n"] if st is not None else 0
            self._refused[reason] = {"t": now, "n": 0}
        if self._log is not None:
            extra = {"suppressed": suppressed} if suppressed else {}
            self._log("approver_auth_refused", reason=reason, peer=peer, **extra)

    def on_undelivered(self, n, failures):
        """Every real transport failed and only the app got the request: it stays pending (the app
        shows it), and the failure is logged by transport type and exception class, never text."""
        if self._log is None:
            return
        self._log("notify_failed", id=n.rid, transports=sorted({a for a, _ in failures}),
                  errors=sorted({b for _, b in failures}),
                  warning="no notification transport delivered this request; it waits in the approver app")


def setup(raw, allowed_user, log):
    """Parse `approver_api` and build the Approver, or None when it is not configured. Raises
    ValueError naming the field. Discovery runs once here; failing it logs one warning and the
    broker starts anyway (the API answers 503 until a refetch succeeds)."""
    cfg = oidc.parse_config(raw, allowed_user)
    if cfg is None:
        return None
    verifier = oidc.Verifier(cfg, fetch_json=FETCH_JSON)
    if not verifier.refresh():
        log("approver_api_discovery_failed",
            warning="approver_api: the identity provider's discovery document or keys could not be "
                    "fetched; the approver API answers 503 until they can")
    feed = AppFeed()
    return Approver(cfg, verifier, feed, AppNotifier(feed, cfg["actions"]), log)


def with_app_leaf(notifier, app, on_undelivered=None):
    """`notifier` with the app leaf among its leaves (unchanged if it already is), reporting
    app-only deliveries to `on_undelivered`."""
    if not any(leaf is app for leaf in notify.leaves(notifier)):
        inner = getattr(notifier, "transports", None)
        notifier = notify.MultiNotifier((list(inner) if isinstance(inner, list) else [notifier]) + [app])
    if isinstance(notifier, notify.MultiNotifier):
        notifier.on_undelivered = on_undelivered
    return notifier


def browser_only(req):
    """Requests that only the approval site can decide (anything but a deny needs input there)."""
    return req.mode in BROWSER_ONLY or (req.mode == "exec" and bool(req.spec.get("host_state")))


def offered_actions(broker, req):
    """The decisions the app may offer (and `decide` accepts) for `req`, as action ids."""
    if browser_only(req):
        return ["deny"]
    out = ["deny"]
    if req.mode == "exec" and req.spec.get("probe") != "ready":
        return out                      # the host check is unfinished or failed: deny only
    out.append("approve")
    if broker.grant_eligibility(req)[0]:
        out += [f"grant:{m}" for m in broker.grant_durations()]
    if broker.always_allow_eligibility(req)[0]:
        out.append("always")
        if req.mode == "env" and _script_binding(req):
            out.append("always_script")
    return out


def _script_binding(req):
    return standing.script_binding(req.spec)


def _details(broker, req):
    if req.mode == "http":
        return broker.details_view(req)         # masked; None when request_details is off
    if req.mode == "env" and req.spec.get("scripts") and broker.details_cfg["enabled"]:
        return {"scripts": details_mod.scripts_view(req.spec["scripts"],
                                                    broker.details_cfg["max_script_bytes"])}
    return None


def request_view(broker, req):
    """One pending request as the app shows it (plain text only; see the module docstring)."""
    banner = broker.approver.feed.notified(req.id) if broker.approver is not None else None
    risk = None
    if req.risk:
        risk = {"level": req.risk.get("level"),
                "reasons": [clean(r, TEXT_MAX) for r in (req.risk.get("reasons") or [])[:MAX_REASONS]]}
    return {
        "id": req.id,
        "mode": req.mode,
        "created": req.created,
        "expires": req.expires,
        "credentials": list(req.names),
        "client": {"name": clean(req.client.get("name"), 200), "id": req.client.get("id")},
        "summary": clean(req.summary, SUMMARY_MAX),
        "summary_source": req.summary_source,
        "risk": risk,
        "target": clean(broker._what(req), TEXT_MAX, keep_newlines=True),
        "details": _details(broker, req),
        "notified": banner is not None,
        "banner_actions": banner or [],
        "actions": offered_actions(broker, req),
        "browser_url": broker._approve_url(req),
    }


def fingerprint(broker):
    """What the long poll compares: one tuple per pending request."""
    feed = broker.approver.feed if broker.approver is not None else None
    return tuple((r.id, feed is not None and feed.notified(r.id) is not None,
                  r.risk.get("level") if r.risk else None, r.summary is not None)
                 for r in broker.pending())


def token_id(claims, token):
    """What the audit records for the token: its `jti`, else the first 16 hex chars of its SHA-256."""
    jti = (claims or {}).get("jti")
    if isinstance(jti, str) and jti:
        return clean(jti, 128)
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _parse(body):
    """Validated decision fields, or None when malformed."""
    if not isinstance(body, dict) or set(body) - _KEYS:
        return None
    decision = body.get("decision")
    gm, always = body.get("grant_minutes"), body.get("always", False)
    scope, device = body.get("rule_scope", "client"), body.get("device")
    if decision not in ("approve", "deny"):
        return None
    if gm is not None and (isinstance(gm, bool) or not isinstance(gm, int)):
        return None
    if always not in (False, True, "script"):
        return None
    if scope not in ("client", "any"):
        return None
    if device is not None and not (isinstance(device, str) and notify.DEVICE_RE.match(device)):
        return None
    if (gm is not None or always) and decision != "approve":
        return None
    if gm is not None and always:
        return None
    action = (f"grant:{gm}" if gm is not None else "always_script" if always == "script"
              else "always" if always else decision)
    return decision, gm, always, scope, device, action


def decide(broker, rid, body, user, peer, token_id):
    """An app decision -> (http status, body). 400 malformed or not offered, 404 unknown, 410
    already decided or expired; nothing is claimed unless it is 200."""
    p = _parse(body)
    if p is None or not isinstance(rid, str) or (isinstance(body, dict) and body.get("id", rid) != rid):
        return 400, {"ok": False}
    decision, gm, always, scope, device, action = p
    with broker._lock:
        req = broker._by_id.get(rid)
    if req is None:
        return 404, {"ok": False}
    if req.status != "pending" or req.session is not None:
        return 410, {"ok": False}
    if action not in offered_actions(broker, req):
        return 400, {"ok": False}
    code, _ = broker.decide_via("app", rid, decision, f"app:{user}", always=always, grant_minutes=gm,
                                rule_scope=scope, peer=peer, device=device, token_id=token_id)
    if code == 200:
        return 200, {"ok": True}
    return (code if code in (404, 410) else 400), {"ok": False}


# -- HTTP routes (client listener) -------------------------------------------------------------
_ROUTES = {PREFIX + "/config": "GET", PREFIX + "/pending": "GET",
           PREFIX + "/decide": "POST", PREFIX + "/presence": "POST"}
_BAD = object()             # a body or query read that already answered / was invalid


def _reply(h, code, obj, headers=None):
    raw = json.dumps(obj).encode()
    h.send_response(code)
    h.send_header("Content-Type", "application/json")
    h.send_header("Cache-Control", "no-store")
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.send_header("Content-Length", str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)


def presence_tab(device):
    """The presence tab id for an app device: `app-<device>` with anything outside
    [A-Za-z0-9_-] replaced by `_`, at most 32 chars (presence.TAB_RE)."""
    if not device:
        return "app-unknown"
    return _TAB_BAD.sub("_", "app-" + device)[:32]


def _authenticate(h, broker, app):
    """-> (claims, token), or None once a refusal was answered. The bearer token is the only
    credential: a request that also carries the agent's client key is refused. Refusals share one
    rate bucket (no per-source state); valid tokens are limited per source IP."""
    peer = h._ip
    auth = h.headers.get("Authorization", "")
    token = auth[7:] if auth[:7].lower() == "bearer " else ""
    if h.headers.get("X-Client-Key") is not None or (auth and not token):
        claims, reason = None, ("malformed" if auth else "missing")
    else:
        claims, reason = app.verifier.verify(token)
    if claims is not None:
        if not broker.app_rate_ok(peer):
            h.close_connection = True
            _reply(h, 429, {"error": "rate limited"}, {"Retry-After": "60"})
            return None
        return claims, token
    h.close_connection = True
    if not broker.app_unauth_ok(peer):
        _reply(h, 429, {"error": "rate limited"}, {"Retry-After": "60"})
        return None
    app.refused(reason, peer)
    if reason == "jwks_unavailable":
        _reply(h, 503, {"error": "identity provider unavailable"}, {"Retry-After": "30"})
    else:
        _reply(h, 401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
    return None


def _read_json(h):
    """The JSON body (any JSON value; None when unparseable), or _BAD once 413/400 was answered."""
    try:
        n = int(h.headers.get("Content-Length", ""))
    except ValueError:
        n = -1
    if n > BODY_MAX:
        h.close_connection = True
        _reply(h, 413, {"error": "request too large"})
        return _BAD
    if n < 0:
        h.close_connection = True
        _reply(h, 400, {"error": "bad request"})
        return _BAD
    try:
        return json.loads(h.rfile.read(n).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def _qint(q, key):
    """-> int, None when absent, or _BAD when not a plain non-negative integer."""
    vals = q.get(key)
    if not vals:
        return None
    return int(vals[-1]) if _QINT.match(vals[-1]) else _BAD


def _pending(h, broker, app, query):
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    since, wait = _qint(q, "since"), _qint(q, "wait")
    if since is _BAD or wait is _BAD:
        return _reply(h, 400, {"error": "bad request"})
    wait = min(wait or 0, WAIT_MAX)
    since = -1 if since is None else since          # never a version: answers at once
    t0 = time.monotonic()
    version = app.feed.wait(since, wait, lambda: fingerprint(broker))
    headers = {}
    # Asked to wait, got nothing new, and was not made to wait: the waiter cap was hit. Ask the
    # app to back off rather than let it spin.
    if wait > 0 and version == since and time.monotonic() - t0 < min(1.0, wait / 2):
        headers["Retry-After"] = RETRY_AFTER_BUSY
    rows = [request_view(broker, r) for r in broker.pending()]     # oldest first
    _reply(h, 200, {"version": version, "requests": rows}, headers)


def _presence(h, broker, body):
    if (not isinstance(body, dict) or set(body) - _PRESENCE_KEYS
            or not isinstance(body.get("active"), bool)):
        return _reply(h, 400, {"ok": False})
    device = body.get("device")
    if device is not None and not (isinstance(device, str) and notify.DEVICE_RE.match(device)):
        return _reply(h, 400, {"ok": False})
    if broker.presence_cfg["enabled"]:          # disabled: nothing is held; accept and ignore
        if not broker.presence_beat(broker.cfg["allowed_user"], body["active"],
                                    presence_tab(device), h._ip):
            return _reply(h, 429, {"ok": False})
    _reply(h, 200, {"ok": True})


def handle(h, broker, method, path):
    """Answer `path` if it is an approver API path; True when it was. Without `approver_api`
    configured every such path is 404 and nothing else happens."""
    u = urllib.parse.urlsplit(path)
    p = u.path
    if not (p == PREFIX or p.startswith(PREFIX + "/")):
        return False
    app = broker.approver
    want = _ROUTES.get(p)
    if app is None or want is None:
        _reply(h, 404, {"error": "not found"})
        return True
    if method != want:
        _reply(h, 405, {"error": "method not allowed"})
        return True
    if p == PREFIX + "/config":
        cfg = app.cfg
        _reply(h, 200, {"issuer": cfg["issuer"], "client_id": cfg["client_id"],
                        "scopes": list(cfg["scopes"]), "api_version": API_VERSION})
        return True
    auth = _authenticate(h, broker, app)
    if auth is None:
        return True
    claims, token = auth
    if p == PREFIX + "/pending":
        _pending(h, broker, app, u.query)
        return True
    body = _read_json(h)
    if body is _BAD:
        return True
    if p == PREFIX + "/presence":
        _presence(h, broker, body)
        return True
    rid = body.get("id") if isinstance(body, dict) else None
    code, out = decide(broker, rid, body, claims.get(app.cfg["username_claim"]), h._ip,
                       token_id(claims, token))
    _reply(h, code, out)
    return True
