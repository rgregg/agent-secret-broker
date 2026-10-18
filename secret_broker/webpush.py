"""Web Push: deliver an approval alert to a browser with no page open.

The browser registers a service worker and subscribes through its vendor's
push service; the broker keeps the subscription and later sends an encrypted
message (RFC 8291) authorised by its VAPID key (RFC 8292). The message carries
only a title and the secret NAMES: never a URL, request body, value or approval
nonce. Clicking the notification opens the dashboard, where the decision is
made behind SSO as usual.

Subscriptions live in a small JSON file (not in the vault); the VAPID private
key sits next to it. A subscription's endpoint is a URL the broker will POST
to, so it is accepted only for known push-service hosts.
"""
import json
import os
import re
import secrets
import threading
import time
import urllib.parse

from .notify import (APPROVE_MAX_RISK, RISK_LEVELS, NotifyError, action_ids_for,  # noqa: F401
                     parse_action_policy)

# push services of the major browsers; extend with `webpush.endpoint_hosts`
PUSH_HOSTS = ("fcm.googleapis.com", "push.services.mozilla.com", "push.apple.com",
              "notify.windows.com")
MAX_PER_USER = 20
_B64 = re.compile(r"^[A-Za-z0-9_=-]{8,256}$")


class PushError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _host_ok(host, allowed):
    return any(host == h or host.endswith("." + h) for h in allowed)


def _send_with_pywebpush(sub, data, key_path, subject, ttl):
    from pywebpush import WebPushException, webpush   # imported lazily: only when sending
    try:
        webpush(subscription_info={"endpoint": sub["endpoint"], "keys": sub["keys"]},
                data=data, vapid_private_key=key_path, vapid_claims={"sub": subject},
                ttl=ttl, headers={"Urgency": "high"}, timeout=10)
    except WebPushException as e:
        resp = getattr(e, "response", None)
        raise PushError(getattr(resp, "status_code", None), str(e)[:160]) from None
    except OSError as e:
        raise PushError(None, f"network error: {e}"[:160]) from None


class PushStore:
    def __init__(self, path, vapid_key_path, subject, extra_hosts=(), sender=None):
        self._path = path
        self._vapid_path = vapid_key_path
        self._subject = subject
        self._hosts = tuple(PUSH_HOSTS) + tuple(h.lower() for h in extra_hosts)
        self._send = sender or _send_with_pywebpush
        self._lock = threading.Lock()
        self._public = None

    # -- persistence -----------------------------------------------------
    def _load(self):
        try:
            with open(self._path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return {"subs": []}
        return data if isinstance(data, dict) and isinstance(data.get("subs"), list) else {"subs": []}

    def _save(self, data):
        tmp = f"{self._path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, self._path)

    # -- VAPID key ---------------------------------------------------------
    def public_key(self):
        """The application server key (base64url, uncompressed P-256 point)."""
        if self._public:
            return self._public
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from py_vapid import Vapid
        from py_vapid.utils import b64urlencode
        with self._lock:
            if os.path.exists(self._vapid_path):
                v = Vapid.from_file(self._vapid_path)
            else:
                v = Vapid()
                v.generate_keys()
                old = os.umask(0o077)
                try:
                    v.save_key(self._vapid_path)
                finally:
                    os.umask(old)
            raw = v.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            self._public = b64urlencode(raw)
        return self._public

    # -- subscriptions -----------------------------------------------------
    def check_endpoint(self, endpoint):
        u = urllib.parse.urlsplit(endpoint or "")
        if (u.scheme != "https" or not u.hostname or u.username or u.password
                or u.port not in (None, 443) or len(endpoint) > 1024):
            raise ValueError("not an acceptable push endpoint")
        if not _host_ok(u.hostname.lower(), self._hosts):
            raise ValueError("not a known push service")

    def add(self, user, endpoint, p256dh, auth, agent=""):
        self.check_endpoint(endpoint)
        if not (_B64.match(p256dh or "") and _B64.match(auth or "")):
            raise ValueError("malformed subscription keys")
        with self._lock:
            data = self._load()
            for s in data["subs"]:
                if s["endpoint"] == endpoint:
                    s.update(user=user, keys={"p256dh": p256dh, "auth": auth},
                             agent=agent[:160])
                    self._save(data)
                    return s["id"]
            if sum(1 for s in data["subs"] if s["user"] == user) >= MAX_PER_USER:
                raise ValueError("too many subscribed devices; remove some first")
            sid = secrets.token_urlsafe(9)
            data["subs"].append({"id": sid, "user": user, "endpoint": endpoint,
                                 "keys": {"p256dh": p256dh, "auth": auth},
                                 "agent": agent[:160], "created": int(time.time()),
                                 "last_ok": None, "last_error": None})
            self._save(data)
            return sid

    def remove(self, sid):
        with self._lock:
            data = self._load()
            keep = [s for s in data["subs"] if s["id"] != sid]
            if len(keep) == len(data["subs"]):
                return False
            data["subs"] = keep
            self._save(data)
            return True

    def devices(self):
        """What the UI may show: no endpoint, no keys."""
        return [{k: s.get(k) for k in ("id", "user", "agent", "created", "last_ok", "last_error")}
                for s in self._load()["subs"]]

    def send_all(self, payload, ttl=300):
        """Push `payload` to every subscription. Returns (delivered, errors).
        Gone subscriptions (404/410) are dropped."""
        data = json.dumps(payload, separators=(",", ":"))
        with self._lock:
            subs = self._load()["subs"]
        ok, errors, gone, outcome = 0, [], [], {}
        for s in subs:
            try:
                self._send(s, data, self._vapid_path, self._subject, ttl)
                ok += 1
                outcome[s["id"]] = (int(time.time()), None)
            except PushError as e:
                if e.status in (404, 410):
                    gone.append(s["id"])
                    errors.append("subscription expired and was removed")
                else:
                    outcome[s["id"]] = (None, f"HTTP {e.status}" if e.status else str(e)[:80])
                    errors.append(f"push service refused ({e.status or 'network'})")
        if gone or outcome:
            with self._lock:
                data2 = self._load()
                data2["subs"] = [s for s in data2["subs"] if s["id"] not in gone]
                for s in data2["subs"]:
                    if s["id"] in outcome:
                        ok_at, err = outcome[s["id"]]
                        if ok_at:
                            s["last_ok"], s["last_error"] = ok_at, None
                        else:
                            s["last_error"] = err
                self._save(data2)
        return ok, errors


def parse_actions(wp):
    """Validate `webpush.actions` -> {"approve_max_risk": str, "deny": bool}.
    This block is the webpush-specific override of the global `notify_actions`
    policy (kept for backward compatibility). Raises ValueError naming the field."""
    return parse_action_policy((wp or {}).get("actions"), "webpush.actions")


class WebPushNotifier:
    """Notify transport. Deliberately ignores the message text and the link.
    It renders both action buttons; which ones a request gets is decided by the
    central policy (or this transport's `actions` override) and arrives in
    `n.actions` together with the request id and single-use token."""

    supports_actions = ("deny", "approve")

    def __init__(self, store, actions=None):
        self.store = store
        self.action_policy = actions        # None: use the global notify_actions policy
        self.actions = actions or parse_actions(None)

    def actions_for(self, risk):
        """Buttons for a request of this risk level (unknown risk counts as high)."""
        return action_ids_for(self.actions, risk, self.supports_actions)

    def send(self, n):
        body = ", ".join(n.names) if n.names else "A secret was requested"
        if not self.store.devices():
            raise NotifyError("no browser is subscribed for push notifications")
        payload = {"title": n.title, "body": body[:200], "tag": n.tag}
        if n.actions and n.action_token and n.rid:
            payload.update(actions=[a.id for a in n.actions], rid=n.rid, token=n.action_token)
        ok, errors = self.store.send_all(payload)
        if not ok:
            raise NotifyError("; ".join(errors[:3]) or "push delivery failed")


def store_from_config(cfg):
    wp = cfg.get("webpush") or {}
    base = os.path.dirname(os.path.abspath(cfg.get("audit_log") or "/data/audit.jsonl"))
    return PushStore(wp.get("subscriptions_file") or os.path.join(base, "webpush.json"),
                     wp.get("vapid_key_file") or os.path.join(base, "vapid.pem"),
                     wp.get("subject") or cfg.get("approve_base_url") or "mailto:admin@example.invalid",
                     extra_hosts=wp.get("endpoint_hosts") or ())
