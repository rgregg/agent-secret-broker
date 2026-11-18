"""Notification pipeline and transports.

The broker builds ONE `Notification` per request (see `make_notification`):
what is said, which action buttons exist and the single-use action token.
Transports only decide how to deliver it. A transport only *delivers the link*
to the approval page unless it can render action buttons; approval itself
otherwise happens on that page (behind SSO). Contract:

    send(n: Notification) -> None      raise NotifyError if not delivered
    resolved(n, status)    -> None     optional, best effort: the request was
                                       approved/denied/expired/failed (same
                                       Notification that was sent)
    supports_actions = ("approve", "deny")   optional class attribute: which
                                       action ids the transport can render
                                       (default: none)
    action_policy = {...}              optional per-transport override of the
                                       action policy (default: global policy)

Deprecated: the old `send(title, message, url, tag, names=None, context=None)`
/ `resolved(tag, status)` signature still works through `adapt()`, which
detects it once when the transport is registered.

Configure one or more under `notify` in the broker config; with several, a
request is delivered if at least one transport succeeds.
"""
import dataclasses
import inspect
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from . import destguard


class NotifyError(Exception):
    pass


RISK_LEVELS = ("low", "medium", "high")
APPROVE_MAX_RISK = ("none",) + RISK_LEVELS
ACTION_LABELS = {"deny": "Deny", "approve": "Approve"}      # display order
DEFAULT_POLICY = {"approve_max_risk": "high", "deny": True}


@dataclasses.dataclass(frozen=True)
class Action:
    id: str
    label: str


@dataclasses.dataclass
class Notification:
    rid: str
    tag: str
    title: str
    text: str                       # the full message
    names: list
    risk: object                    # "low"|"medium"|"high" or None
    url: str
    source: str
    summary: object                 # advisory, unverified; or None
    expires_at: float
    actions: list = dataclasses.field(default_factory=list)       # [Action], display order
    action_token: object = None     # opaque; None when no action is offered
    # per-transport action lists (id(transport) -> [Action]); see for_transport()
    transport_actions: dict = dataclasses.field(default_factory=dict, repr=False, compare=False)

    def for_transport(self, transport):
        """The notification as `transport` should see it: only the actions it can carry."""
        acts = self.transport_actions.get(id(transport))
        if acts is None:
            return self
        return dataclasses.replace(self, actions=list(acts),
                                   action_token=self.action_token if acts else None)


def parse_action_policy(raw, field):
    """Validate an action policy object -> {"approve_max_risk": str, "deny": bool}.
    None means defaults. Raises ValueError naming `field`."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in ("approve_max_risk", "deny"):
            raise ValueError(f"{field}.{k} is not a known option")
    mx = raw.get("approve_max_risk", "high")
    if mx not in APPROVE_MAX_RISK:
        raise ValueError(f"{field}.approve_max_risk must be one of {', '.join(APPROVE_MAX_RISK)}")
    deny = raw.get("deny", True)
    if not isinstance(deny, bool):
        raise ValueError(f"{field}.deny must be true or false")
    return {"approve_max_risk": mx, "deny": deny}


def action_ids_for(policy, risk, supported):
    """Action ids (Deny first, then Approve) the policy allows for this risk
    level, limited to what the transport supports. Unknown risk counts as high."""
    out = []
    if policy["deny"] and "deny" in supported:
        out.append("deny")
    mx = policy["approve_max_risk"]
    lvl = risk if risk in RISK_LEVELS else "high"
    if mx != "none" and RISK_LEVELS.index(lvl) <= RISK_LEVELS.index(mx) and "approve" in supported:
        out.append("approve")
    return out


def leaves(transport):
    """The individual transports behind a (possibly fan-out) notifier."""
    inner = getattr(transport, "transports", None)
    if isinstance(inner, list):
        for t in inner:
            yield from leaves(t)
    else:
        yield transport


def make_notification(*, rid, tag, title, text, names, risk, url, source, summary,
                      expires_at, transport, default_policy=None):
    """Build the Notification for a request, in one place, applying the action
    policy per transport: policy = the transport's own `action_policy` if set,
    else `default_policy` (the global `notify_actions`), else the defaults. A
    token is created only if at least one transport will carry actions."""
    per = {}
    for leaf in leaves(transport):
        pol = getattr(leaf, "action_policy", None) or default_policy or DEFAULT_POLICY
        ids = action_ids_for(pol, risk, tuple(getattr(leaf, "supports_actions", ()) or ()))
        per[id(leaf)] = [Action(i, ACTION_LABELS[i]) for i in ids]
    union = [Action(i, ACTION_LABELS[i]) for i in ACTION_LABELS
             if any(a.id == i for acts in per.values() for a in acts)]
    return Notification(
        rid=rid, tag=tag, title=title, text=text, names=list(names), risk=risk, url=url,
        source=source, summary=summary, expires_at=expires_at, actions=union,
        action_token=secrets.token_urlsafe(16) if union else None,   # 128 bits
        transport_actions=per)


class LegacyAdapter:
    """DEPRECATED path: wraps a transport written against
    send(title, message, url, tag, names=None, context=None) and
    resolved(tag, status). `context` is {"rid", "risk", "action_token"}."""

    def __init__(self, wrapped, takes_names, takes_context):
        self.wrapped = wrapped
        self._names = takes_names
        self._ctx = takes_context
        # a legacy transport that took `context` rendered buttons itself
        self.supports_actions = tuple(getattr(wrapped, "supports_actions",
                                              ("deny", "approve") if takes_context else ()))
        self.action_policy = getattr(wrapped, "action_policy", None)

    def __getattr__(self, name):
        return getattr(self.wrapped, name)

    def send(self, n):
        kw = {}
        if self._names:
            kw["names"] = list(n.names)
        if self._ctx:
            kw["context"] = {"rid": n.rid, "risk": n.risk, "action_token": n.action_token}
        return self.wrapped.send(n.title, n.text, n.url, n.tag, **kw)

    def resolved(self, n, status):
        fn = getattr(self.wrapped, "resolved", None)
        if fn:
            fn(n.tag, status)


def adapt(transport):
    """Return a transport speaking the Notification contract. Signature
    inspection happens here, once, at registration. A `send` with four or more
    required positional parameters is the deprecated legacy form."""
    if isinstance(transport, LegacyAdapter):
        return transport
    try:
        params = inspect.signature(transport.send).parameters
    except (TypeError, ValueError, AttributeError):
        return transport
    required = [p for p in params.values()
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is p.empty]
    if len(required) < 4:
        return transport
    var_kw = any(p.kind is p.VAR_KEYWORD for p in params.values())
    return LegacyAdapter(transport, "names" in params or var_kw, "context" in params or var_kw)


HOOK_KEY_MIN = 32
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")       # url-safe: needs no escaping anywhere
DEVICE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def parse_ha_hook(raw, read_secret):
    """Validate `ha_hook` -> {"key": str, "allowed_devices": [str]} or None when
    not configured. Raises ValueError naming the field."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("ha_hook must be an object")
    for k in raw:
        if k not in ("key", "key_file", "allowed_devices"):
            raise ValueError(f"ha_hook.{k} is not a known option")
    if ("key" in raw) == ("key_file" in raw):
        raise ValueError("ha_hook needs exactly one of key_file or key")
    if "key_file" in raw:
        if not isinstance(raw["key_file"], str) or not raw["key_file"]:
            raise ValueError("ha_hook.key_file must be a path")
        try:
            key = read_secret(raw["key_file"])
        except OSError:
            raise ValueError("ha_hook.key_file is missing or unreadable") from None
        field = "ha_hook.key_file"
    else:
        key, field = raw["key"], "ha_hook.key"
    if not isinstance(key, str) or len(key) < HOOK_KEY_MIN:
        raise ValueError(f"{field}: the hook key must be at least {HOOK_KEY_MIN} characters")
    devs = raw.get("allowed_devices", [])
    if (not isinstance(devs, list)
            or not all(isinstance(d, str) and DEVICE_RE.match(d) for d in devs)):
        raise ValueError("ha_hook.allowed_devices must be a list of strings "
                         "(1-64 chars of A-Za-z0-9_.:-)")
    return {"key": key, "allowed_devices": list(devs)}


TRANSPORT_TYPE_ATTR = "type_name"        # a transport's config `type`; see transport_type()


def transport_type(transport):
    """The config `type` of a transport ("ticker", "telegram", "webpush"), or None."""
    return getattr(getattr(transport, "wrapped", transport), TRANSPORT_TYPE_ATTR, None)


def send_to(transports, n):
    """Deliver `n` to just these (leaf) transports, with MultiNotifier's rule:
    NotifyError if none of them succeeded."""
    errors, ok = [], 0
    for t in transports:
        try:
            t.send(n.for_transport(t))
            ok += 1
        except (NotifyError, OSError) as e:
            errors.append(f"{type(getattr(t, 'wrapped', t)).__name__}: {type(e).__name__}")
    if not ok:
        raise NotifyError("; ".join(errors) or "no transports configured")


class TickerNotifier:
    """ticker.notify. With `actions_enabled` (the broker has an `ha_hook`) it
    can render Approve/Deny buttons whose action id is
    `ASB|<decision>|<rid>|<token>`; without a hook it supports no actions."""
    type_name = "ticker"

    def __init__(self, ha_url, ha_token, category="general", timeout=15, actions_enabled=False):
        self.supports_actions = ("approve", "deny") if actions_enabled else ()
        self._url = ha_url.rstrip("/")
        self._token = ha_token
        self._category = category
        self._timeout = timeout

    def _call(self, path, body=None):
        req = urllib.request.Request(
            f"{self._url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        with destguard.operator_urlopen(req, timeout=self._timeout) as r:
            return json.load(r)

    def action_list(self, n):
        """Companion-app actions for this notification (Deny first), or [].
        Ids are `ASB|<decision>|<rid>|<token>`; rid and token are url-safe, and
        anything else (never expected) drops the buttons rather than risk a
        malformed id."""
        if not self.supports_actions or not n.actions or not n.action_token:
            return []
        if not (_ID_RE.match(n.rid or "") and _ID_RE.match(n.action_token)):
            return []
        return [{"action": f"ASB|{a.id}|{n.rid}|{n.action_token}", "title": a.label}
                for a in n.actions if a.id in self.supports_actions]

    def send(self, n):
        """Send the push and confirm Ticker actually delivered it to a device.

        ticker.notify returns 200 even when the category is `never` for every
        subscriber, so check the sensor's newest notification afterwards.
        """
        body = {
            "category": self._category,
            "title": n.title,
            "message": n.text,
            "data": {"url": n.url, "clickAction": n.url, "tag": n.tag},
        }
        acts = self.action_list(n)
        if acts:
            # Custom buttons go in data.actions. Ticker's top-level `actions` is
            # only a switch (category_default|none); a list there is rejected.
            body["data"]["actions"] = acts
        self._call("/api/services/ticker/notify", body)
        time.sleep(1.5)
        state = self._call(f"/api/states/sensor.ticker_{self._category}")
        notes = state.get("attributes", {}).get("notifications") or []
        if not notes or not notes[-1].get("delivered"):
            raise NotifyError("ticker accepted the notification but delivered it to no device")


MAX_CALLBACK_BYTES = 64                 # Telegram's limit on callback_data
_TG_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def tap_text(status, decision):
    """The fixed toast shown after a tap. Never carries request details."""
    if status == 200:
        return "Approved" if decision == "approve" else "Denied"
    return "Already decided" if status == 410 else "Not allowed"


def poll_error_label(exc):
    """A fixed label for a failed Telegram call (never its text, which may echo the API)."""
    st = getattr(exc, "status", None)
    if st is None:
        return "network"
    return {401: "unauthorized", 409: "conflict"}.get(st, "http")


class TelegramNotifier:
    """Telegram bot: the card text, a URL button to the approval page and, when
    `allowed_users` is set, Deny/Approve callback buttons.

    A tap arrives through `poll_once` (long-poll `getUpdates`; nothing listens
    for Telegram) and is passed to the broker only if it comes from a listed
    user, in the configured chat, on a message this transport sent for that
    request; the broker then decides it through channel `telegram`, which needs
    the request's single-use action token. Error text never includes the bot
    token (it is part of the API URL).
    """
    type_name = "telegram"

    def __init__(self, bot_token, chat_id, api_base="https://api.telegram.org", timeout=15,
                 allowed_users=()):
        self._base = f"{api_base.rstrip('/')}/bot{bot_token}"
        self._chat = str(chat_id)
        self._timeout = timeout
        self._lock = threading.Lock()
        self._msg_ids = {}
        self._texts = {}
        self._by_rid = {}               # rid -> message id, while the request is open
        self.allowed_users = tuple(allowed_users)
        self.supports_actions = ("approve", "deny") if self.allowed_users else ()
        self._offset = None
        self._stop = threading.Event()
        self._sleep = self._stop.wait   # injectable (tests)

    @property
    def actions_enabled(self):
        return bool(self.allowed_users)

    def _call(self, method, body, timeout=None):
        req = urllib.request.Request(
            f"{self._base}/{method}", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with destguard.operator_urlopen(req, timeout=timeout or self._timeout) as r:
                out = json.load(r)
        except urllib.error.HTTPError as e:
            err = NotifyError(f"telegram {method} failed: HTTP {e.code}")
            err.status = e.code
            raise err from None
        except (urllib.error.URLError, OSError, ValueError):
            err = NotifyError(f"telegram {method} failed: network error")
            err.status = None
            raise err from None
        if not out.get("ok"):
            err = NotifyError(f"telegram {method} failed: not ok")
            err.status = 0
            raise err
        return out["result"]

    def _buttons(self, n):
        if not (self.actions_enabled and n.action_token and n.actions):
            return []
        row = [{"text": a.label, "callback_data": f"ASB|{a.id}|{n.rid}|{n.action_token}"}
               for a in n.actions if a.id in self.supports_actions]
        if any(len(b["callback_data"].encode()) > MAX_CALLBACK_BYTES for b in row):
            return []                   # cannot carry it: link only
        return [row] if row else []

    def send(self, n):
        text = f"{n.title}\n\n{n.text}"
        kb = self._buttons(n) + [[{"text": "Review request", "url": n.url}]]
        res = self._call("sendMessage", {
            "chat_id": self._chat, "text": text, "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": kb}})
        with self._lock:
            self._msg_ids[n.tag], self._texts[n.tag] = res["message_id"], text
            if len(kb) > 1:
                self._by_rid[n.rid] = res["message_id"]

    def resolved(self, n, status):
        with self._lock:
            mid, text = self._msg_ids.pop(n.tag, None), self._texts.pop(n.tag, "")
            self._by_rid.pop(n.rid, None)
        if mid is None:
            return
        self._call("editMessageText", {"chat_id": self._chat, "message_id": mid,
                                       "text": f"{text}\n\n-> {status.upper()}"})

    # -- taps -------------------------------------------------------------
    def _parse(self, cq):
        """callback_query -> tap dict. Checks shape, sender, chat and message; the token
        is checked by the broker. Nothing from a refused tap is kept but the sender id."""
        frm = cq.get("from") if isinstance(cq.get("from"), dict) else {}
        user = frm.get("id") if isinstance(frm.get("id"), int) and not isinstance(frm.get("id"), bool) else None
        tap = {"rid": None, "decision": None, "token": None, "user": user, "refused": None}
        data, msg = cq.get("data"), cq.get("message")
        parts = (data.split("|") if isinstance(data, str) and len(data.encode()) <= MAX_CALLBACK_BYTES
                 else None)
        if (parts is None or len(parts) != 4 or parts[0] != "ASB" or parts[1] not in ("approve", "deny")
                or not _TG_ID_RE.fullmatch(parts[2]) or not _TG_ID_RE.fullmatch(parts[3])
                or not isinstance(msg, dict) or not isinstance(msg.get("chat"), dict)):
            tap["refused"] = "malformed"
        elif user is None or user not in self.allowed_users:
            tap["refused"] = "user"
        elif str(msg["chat"].get("id")) != self._chat:
            tap["refused"] = "chat"
        else:
            with self._lock:
                mid = self._by_rid.get(parts[2])
            if mid is None or msg.get("message_id") != mid:
                tap["refused"] = "message"
            else:
                tap.update(rid=parts[2], decision=parts[1], token=parts[3])
        return tap

    def poll_once(self, on_tap, timeout=30):
        """One getUpdates call; every callback query is checked, handed to `on_tap` and
        answered. Returns how many callback queries were handled."""
        body = {"timeout": timeout, "allowed_updates": ["callback_query"]}
        if self._offset is not None:
            body["offset"] = self._offset
        updates = self._call("getUpdates", body, timeout=timeout + 10)
        handled = 0
        for up in updates if isinstance(updates, list) else ():
            if not isinstance(up, dict) or not isinstance(up.get("update_id"), int):
                continue
            self._offset = max(self._offset or 0, up["update_id"] + 1)
            cq = up.get("callback_query")
            if not isinstance(cq, dict):
                continue
            handled += 1
            tap = self._parse(cq)
            status = on_tap(tap)
            if isinstance(cq.get("id"), str):
                try:
                    self._call("answerCallbackQuery", {"callback_query_id": cq["id"],
                                                       "text": tap_text(status, tap["decision"])})
                except NotifyError:
                    pass                # the decision stands; the toast is cosmetic
        return handled

    def start_polling(self, on_tap, log, timeout=30):
        """Run poll_once in a daemon thread until stop_polling(). Errors are logged by
        fixed label (a run of 409s once) and backed off 1, 2, 4 ... 60 s."""
        def run():
            delay, last = 1, None
            while not self._stop.is_set():
                try:
                    self.poll_once(on_tap, timeout=timeout)
                    delay, last = 1, None
                except NotifyError as e:
                    label = poll_error_label(e)
                    if not (label == "conflict" and last == "conflict"):
                        log(label)
                    last = label
                    self._sleep(delay)
                    delay = min(delay * 2, 60)
                except Exception:       # noqa: BLE001 -- never let the poller die
                    log("internal")
                    self._sleep(delay)
                    delay = min(delay * 2, 60)
        th = threading.Thread(target=run, daemon=True, name="telegram-poll")
        th.start()
        return th

    def stop_polling(self):
        self._stop.set()


class MultiNotifier:
    """Fan out to several transports; delivered if at least one succeeds."""

    def __init__(self, notifiers):
        self.transports = [adapt(t) for t in notifiers]

    def send(self, n):
        errors, ok = [], 0
        for t in self.transports:
            try:
                t.send(n.for_transport(t))
                ok += 1
            except (NotifyError, OSError) as e:
                errors.append(f"{type(getattr(t, 'wrapped', t)).__name__}: {type(e).__name__}")
        if not ok:
            raise NotifyError("; ".join(errors) or "no transports configured")

    def resolved(self, n, status):
        for t in self.transports:
            fn = getattr(t, "resolved", None)
            if fn:
                try:
                    fn(n, status)
                except Exception:
                    pass


def build(cfg, read_secret, push_store=None):
    """Build the notifier from config. `read_secret(path)` returns file text.

    New style:  "notify": [{"type": "ticker", ...}, {"type": "telegram", ...}]
    Legacy:     top-level ha_url / ha_token_file / category (single ticker).
    """
    specs = cfg.get("notify")
    if specs is None:
        specs = [{"type": "ticker", "ha_url": cfg["ha_url"], "ha_token_file": cfg["ha_token_file"],
                  "category": cfg.get("category", "general")}]
    out = []
    for i, sp in enumerate(specs):
        kind = sp.get("type")
        override = (parse_action_policy(sp["actions"], f"notify[{i}].actions")
                    if sp.get("actions") is not None else None)
        if kind == "ticker":
            out.append(TickerNotifier(sp["ha_url"], read_secret(sp["ha_token_file"]),
                                      sp.get("category", "general"),
                                      actions_enabled=cfg.get("ha_hook") is not None))
        elif kind == "telegram":
            users = sp.get("allowed_users", [])
            if not (isinstance(users, list) and len(users) <= 20 and all(
                    isinstance(u, int) and not isinstance(u, bool) and u > 0 for u in users)):
                raise ValueError(f"notify[{i}].allowed_users must be a list of Telegram user ids")
            out.append(TelegramNotifier(read_secret(sp["bot_token_file"]), sp["chat_id"],
                                        sp.get("api_base", "https://api.telegram.org"),
                                        allowed_users=tuple(users)))
        elif kind == "webpush":
            if push_store is None:
                raise ValueError("webpush transport needs a push store")
            from .webpush import WebPushNotifier, parse_actions
            if override is None and "actions" in (cfg.get("webpush") or {}):
                override = parse_actions(cfg.get("webpush"))      # backward-compatible location
            out.append(WebPushNotifier(push_store, override))
            override = None
        else:
            raise ValueError(f"unknown notify transport {kind!r}")
        if override is not None:
            out[-1].action_policy = override
    if not out:
        raise ValueError("no notify transports configured")
    return out[0] if len(out) == 1 else MultiNotifier(out)


class FakeNotifier:
    """Test double: records sends, optionally auto-decides via a callback."""

    def __init__(self, on_send=None, supports_actions=(), type_name=None):
        self.sent = []
        self.notifications = []         # the Notification objects, parallel to `sent`
        self.resolutions = []           # (tag, status)
        self.resolved_notifications = []
        self.supports_actions = tuple(supports_actions)
        self.type_name = type_name      # which `type` this double stands in for (presence hold)
        self._on_send = on_send

    def send(self, n):
        self.sent.append({"title": n.title, "message": n.text, "url": n.url, "tag": n.tag,
                          "context": {"rid": n.rid, "risk": n.risk, "action_token": n.action_token}})
        self.notifications.append(n)
        if self._on_send:
            self._on_send(n.url)

    def resolved(self, n, status):
        self.resolutions.append((n.tag, status))
        self.resolved_notifications.append((n, status))
