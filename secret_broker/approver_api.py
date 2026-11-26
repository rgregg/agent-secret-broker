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

No HTTP here: the routes on the client listener call these.
"""
import collections
import hashlib
import re
import threading
import time

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
    with which banner actions); it never raises, so it never fails or slows a request."""
    supports_actions = ("approve", "deny")

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

    def __init__(self, cfg, verifier, feed, notifier):
        self.cfg, self.verifier, self.feed, self.notifier = cfg, verifier, feed, notifier


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
    return Approver(cfg, verifier, feed, AppNotifier(feed, cfg["actions"]))


def with_app_leaf(notifier, app):
    """`notifier` with the app leaf among its leaves (unchanged if it already is)."""
    if any(leaf is app for leaf in notify.leaves(notifier)):
        return notifier
    inner = getattr(notifier, "transports", None)
    return notify.MultiNotifier((list(inner) if isinstance(inner, list) else [notifier]) + [app])


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
