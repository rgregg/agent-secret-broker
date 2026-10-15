"""Notification transports.

A transport only *delivers the link* to the approval page; approval itself
always happens on that page (behind SSO). Contract:

    send(title, message, url, tag) -> None   raise NotifyError if not delivered
    resolved(tag, status)          -> None   optional, best effort: called when
                                             the request is approved/denied/expired

Configure one or more under `notify` in the broker config; with several, a
request is delivered if at least one transport succeeds.
"""
import json
import threading
import time
import urllib.error
import urllib.request


class NotifyError(Exception):
    pass


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

    def send(self, title, message, url, tag):
        """Send the push and confirm Ticker actually delivered it to a device.

        ticker.notify returns 200 even when the category is `never` for every
        subscriber, so check the sensor's newest notification afterwards.
        """
        self._call("/api/services/ticker/notify", {
            "category": self._category,
            "title": title,
            "message": message,
            "data": {"url": url, "clickAction": url, "tag": tag},
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

    def send(self, title, message, url, tag):
        text = f"{title}\n\n{message}"
        res = self._call("sendMessage", {
            "chat_id": self._chat, "text": text, "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": [[{"text": "Review request", "url": url}]]}})
        self._msg_ids[tag], self._texts[tag] = res["message_id"], text

    def resolved(self, tag, status):
        mid, text = self._msg_ids.pop(tag, None), self._texts.pop(tag, "")
        if mid is None:
            return
        self._call("editMessageText", {"chat_id": self._chat, "message_id": mid,
                                       "text": f"{text}\n\n-> {status.upper()}"})


class MultiNotifier:
    """Fan out to several transports; delivered if at least one succeeds."""

    def __init__(self, notifiers):
        self._n = list(notifiers)

    def send(self, title, message, url, tag):
        errors, ok = [], 0
        for n in self._n:
            try:
                n.send(title, message, url, tag)
                ok += 1
            except (NotifyError, OSError) as e:
                errors.append(f"{type(n).__name__}: {e}")
        if not ok:
            raise NotifyError("; ".join(errors) or "no transports configured")

    def resolved(self, tag, status):
        for n in self._n:
            fn = getattr(n, "resolved", None)
            if fn:
                try:
                    fn(tag, status)
                except Exception:
                    pass


def build(cfg, read_secret):
    """Build the notifier from config. `read_secret(path)` returns file text.

    New style:  "notify": [{"type": "ticker", ...}, {"type": "telegram", ...}]
    Legacy:     top-level ha_url / ha_token_file / category (single ticker).
    """
    specs = cfg.get("notify")
    if specs is None:
        specs = [{"type": "ticker", "ha_url": cfg["ha_url"], "ha_token_file": cfg["ha_token_file"],
                  "category": cfg.get("category", "general")}]
    out = []
    for sp in specs:
        kind = sp.get("type")
        if kind == "ticker":
            out.append(TickerNotifier(sp["ha_url"], read_secret(sp["ha_token_file"]),
                                      sp.get("category", "general")))
        elif kind == "telegram":
            out.append(TelegramNotifier(read_secret(sp["bot_token_file"]), sp["chat_id"],
                                        sp.get("api_base", "https://api.telegram.org")))
        else:
            raise ValueError(f"unknown notify transport {kind!r}")
    if not out:
        raise ValueError("no notify transports configured")
    return out[0] if len(out) == 1 else MultiNotifier(out)


class FakeNotifier:
    """Test double: records sends, optionally auto-decides via a callback."""

    def __init__(self, on_send=None):
        self.sent = []
        self._on_send = on_send

    def send(self, title, message, url, tag):
        self.sent.append({"title": title, "message": message, "url": url, "tag": tag})
        if self._on_send:
            self._on_send(url)

    def resolved(self, tag, status):
        self.resolutions = getattr(self, "resolutions", []) + [(tag, status)]
