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
import secrets
import threading
import time
import urllib.error
import urllib.request


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


class TickerNotifier:
    def __init__(self, ha_url, ha_token, category="general", timeout=15):
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
        with urllib.request.urlopen(req, timeout=self._timeout) as r:
            return json.load(r)

    def send(self, n):
        """Send the push and confirm Ticker actually delivered it to a device.

        ticker.notify returns 200 even when the category is `never` for every
        subscriber, so check the sensor's newest notification afterwards.
        """
        self._call("/api/services/ticker/notify", {
            "category": self._category,
            "title": n.title,
            "message": n.text,
            "data": {"url": n.url, "clickAction": n.url, "tag": n.tag},
        })
        time.sleep(1.5)
        state = self._call(f"/api/states/sensor.ticker_{self._category}")
        notes = state.get("attributes", {}).get("notifications") or []
        if not notes or not notes[-1].get("delivered"):
            raise NotifyError("ticker accepted the notification but delivered it to no device")


class TelegramNotifier:
    """Telegram bot: message with a single URL button to the approval page.

    Deliberately no callback buttons: approving from inside the chat would
    bypass the SSO-gated page. Error text never includes the bot token (it is
    part of the API URL).
    """

    def __init__(self, bot_token, chat_id, api_base="https://api.telegram.org", timeout=15):
        self._base = f"{api_base.rstrip('/')}/bot{bot_token}"
        self._chat = str(chat_id)
        self._timeout = timeout
        self._msg_ids = {}
        self._texts = {}

    def _call(self, method, body):
        req = urllib.request.Request(
            f"{self._base}/{method}", data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                out = json.load(r)
        except urllib.error.HTTPError as e:
            try:
                desc = json.load(e).get("description", "")
            except (ValueError, OSError):
                desc = ""
            raise NotifyError(f"telegram {method} failed: HTTP {e.code} {desc}"[:200]) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise NotifyError(f"telegram {method} failed: network error") from None
        if not out.get("ok"):
            raise NotifyError(f"telegram {method} failed: {out.get('description', '')}"[:200])
        return out["result"]

    def send(self, n):
        text = f"{n.title}\n\n{n.text}"
        res = self._call("sendMessage", {
            "chat_id": self._chat, "text": text, "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": [[{"text": "Review request", "url": n.url}]]}})
        self._msg_ids[n.tag], self._texts[n.tag] = res["message_id"], text

    def resolved(self, n, status):
        mid, text = self._msg_ids.pop(n.tag, None), self._texts.pop(n.tag, "")
        if mid is None:
            return
        self._call("editMessageText", {"chat_id": self._chat, "message_id": mid,
                                       "text": f"{text}\n\n-> {status.upper()}"})


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
                errors.append(f"{type(getattr(t, 'wrapped', t)).__name__}: {e}")
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
                                      sp.get("category", "general")))
        elif kind == "telegram":
            out.append(TelegramNotifier(read_secret(sp["bot_token_file"]), sp["chat_id"],
                                        sp.get("api_base", "https://api.telegram.org")))
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

    def __init__(self, on_send=None, supports_actions=()):
        self.sent = []
        self.notifications = []         # the Notification objects, parallel to `sent`
        self.resolutions = []           # (tag, status)
        self.resolved_notifications = []
        self.supports_actions = tuple(supports_actions)
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
