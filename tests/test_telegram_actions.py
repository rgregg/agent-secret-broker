"""Telegram Approve/Deny buttons: the transport renders callback buttons when `allowed_users` is set, polls
`getUpdates` for taps, and accepts a tap only from a listed user, in the configured chat, on a message it sent.
"""
import _fast  # noqa: F401
import json
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()
from secret_broker import notify  # noqa: E402
from secret_broker.notify import NotifyError  # noqa: E402

TOKEN = "123456:S3CR3T-BOT"
CHAT = 4242
USER = 111
RID = "Rid_abc-123"


class FakeAPI(BaseHTTPRequestHandler):
    calls = []              # (method, body)
    updates = []            # queued getUpdates results (each a list of updates)
    fail = None             # HTTP status to answer every call with
    next_mid = 77

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = self.path.rsplit("/", 1)[-1]
        FakeAPI.calls.append((method, body))
        if FakeAPI.fail:
            code, out = FakeAPI.fail, {"ok": False, "description": f"error {TOKEN}"}
        elif method == "getUpdates":
            code, out = 200, {"ok": True, "result": FakeAPI.updates.pop(0) if FakeAPI.updates else []}
        elif method == "sendMessage":
            code, out = 200, {"ok": True, "result": {"message_id": FakeAPI.next_mid}}
        else:
            code, out = 200, {"ok": True, "result": True}
        raw = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def calls(method):
    return [b for m, b in FakeAPI.calls if m == method]


def update(uid, data, user=USER, chat=CHAT, mid=77, with_message=True):
    cq = {"id": f"cq{uid}", "from": {"id": user}, "data": data}
    if with_message:
        cq["message"] = {"message_id": mid, "chat": {"id": chat}}
    return {"update_id": uid, "callback_query": cq}


class Base(unittest.TestCase):
    def setUp(self):
        FakeAPI.calls, FakeAPI.updates, FakeAPI.fail, FakeAPI.next_mid = [], [], None, 77
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAPI)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.srv.server_address[1]}"
        self.taps = []

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def tg(self, users=(USER,), policy=None):
        t = notify.TelegramNotifier(TOKEN, CHAT, api_base=self.api, allowed_users=users)
        if policy is not None:
            t.action_policy = policy
        return t

    def note(self, t, risk="low", rid=RID):
        n = notify.make_notification(
            rid=rid, tag=f"secret-{rid[:8]}", title="Secret request [LOW]", text="svc from host\nGET x",
            names=["svc"], risk=risk, url="https://secrets.example/a/NONCE", source="host", summary=None,
            expires_at=1.0, transport=t)
        return n.for_transport(t)

    def on_tap(self, status=200):
        def fn(tap):
            self.taps.append(tap)
            return status
        return fn


class Buttons(Base):
    def test_no_allowed_users_is_todays_message(self):
        t = self.tg(users=())
        self.assertEqual(t.supports_actions, ())
        self.assertFalse(t.actions_enabled)
        n = self.note(t)
        self.assertEqual(n.actions, [])
        t.send(n)
        body = calls("sendMessage")[0]
        self.assertEqual(body["reply_markup"], {"inline_keyboard": [
            [{"text": "Review request", "url": "https://secrets.example/a/NONCE"}]]})
        self.assertNotIn("callback_data", json.dumps(body))

    def test_buttons_carry_rid_and_token(self):
        t = self.tg()
        self.assertEqual(t.supports_actions, ("approve", "deny"))
        self.assertTrue(t.actions_enabled)
        n = self.note(t)
        self.assertTrue(n.action_token)
        t.send(n)
        kb = calls("sendMessage")[0]["reply_markup"]["inline_keyboard"]
        self.assertEqual(kb, [
            [{"text": "Deny", "callback_data": f"ASB|deny|{RID}|{n.action_token}"},
             {"text": "Approve", "callback_data": f"ASB|approve|{RID}|{n.action_token}"}],
            [{"text": "Review request", "url": "https://secrets.example/a/NONCE"}]])
        for b in kb[0]:
            self.assertLessEqual(len(b["callback_data"].encode()), 64)

    def test_policy_narrowing_drops_approve(self):
        t = self.tg(policy={"approve_max_risk": "medium", "deny": True})
        t.send(self.note(t, risk="high"))
        kb = calls("sendMessage")[0]["reply_markup"]["inline_keyboard"]
        self.assertEqual([b["text"] for b in kb[0]], ["Deny"])

    def test_overlong_callback_falls_back_to_link(self):
        t = self.tg()
        n = self.note(t, rid="R" * 40)
        self.assertTrue(n.action_token)
        t.send(n)
        body = calls("sendMessage")[0]
        self.assertEqual(body["reply_markup"]["inline_keyboard"],
                         [[{"text": "Review request", "url": "https://secrets.example/a/NONCE"}]])
        self.assertNotIn(n.action_token, json.dumps(body))


class Taps(Base):
    def setUp(self):
        super().setUp()
        self.t = self.tg()
        self.n = self.note(self.t)
        self.t.send(self.n)
        self.data = f"ASB|approve|{RID}|{self.n.action_token}"

    def test_tap_from_listed_user_in_chat_on_our_message(self):
        FakeAPI.updates = [[update(500, self.data)]]
        self.assertEqual(self.t.poll_once(self.on_tap(200), timeout=0), 1)
        self.assertEqual(self.taps, [{"rid": RID, "decision": "approve", "token": self.n.action_token,
                                      "user": USER, "refused": None}])
        self.assertEqual(calls("answerCallbackQuery"), [{"callback_query_id": "cq500", "text": "Approved"}])
        first = calls("getUpdates")[0]
        self.assertEqual(first["allowed_updates"], ["callback_query"])
        self.assertEqual(first["timeout"], 0)
        self.t.poll_once(self.on_tap(), timeout=0)
        self.assertEqual(calls("getUpdates")[1]["offset"], 501)

    def test_deny_answer(self):
        FakeAPI.updates = [[update(1, f"ASB|deny|{RID}|{self.n.action_token}")]]
        self.t.poll_once(self.on_tap(200), timeout=0)
        self.assertEqual(self.taps[0]["decision"], "deny")
        self.assertEqual(calls("answerCallbackQuery")[0]["text"], "Denied")

    def test_refusals(self):
        tok = self.n.action_token
        cases = [
            ("user", update(1, self.data, user=999)),
            ("chat", update(2, self.data, chat=5)),
            ("message", update(3, self.data, mid=78)),
            ("message", update(4, f"ASB|approve|Other_rid|{tok}")),
            ("malformed", update(5, "xyz")),
            ("malformed", update(6, f"ASB|maybe|{RID}|{tok}")),
            ("malformed", update(7, "ASB|approve|" + "a" * 200 + f"|{tok}")),
            ("malformed", update(11, f"ASB|approve|{'r' * 40}|{'t' * 40}")),   # each part fine, over 64 bytes
            ("malformed", update(8, f"ASB|approve|{RID}|{tok}|extra")),
            ("malformed", update(9, f"ASB|approve|{RID}|to ken")),
            ("malformed", update(10, self.data, with_message=False)),
        ]
        for i, (reason, up) in enumerate(cases):
            with self.subTest(reason=reason, i=i):
                self.taps.clear()
                FakeAPI.calls.clear()
                FakeAPI.updates = [[up]]
                self.t.poll_once(self.on_tap(0), timeout=0)
                self.assertEqual(len(self.taps), 1)
                self.assertEqual(self.taps[0]["refused"], reason)
                self.assertEqual(calls("answerCallbackQuery")[0]["text"], "Not allowed")
        self.taps.clear()
        FakeAPI.updates = [[update(99, self.data)]]                   # positive control: the same tap, valid
        self.t.poll_once(self.on_tap(200), timeout=0)
        self.assertIsNone(self.taps[0]["refused"])

    def test_refused_tap_carries_no_token_or_data(self):
        FakeAPI.updates = [[update(1, self.data, user=999)]]
        self.t.poll_once(self.on_tap(0), timeout=0)
        tap = self.taps[0]
        self.assertEqual(tap["refused"], "user")
        self.assertEqual(tap["user"], 999)
        self.assertIsNone(tap["token"])
        self.assertNotIn(self.n.action_token, json.dumps(tap))

    def test_410_says_already_decided(self):
        FakeAPI.updates = [[update(1, self.data)]]
        self.t.poll_once(self.on_tap(410), timeout=0)
        self.assertEqual(calls("answerCallbackQuery")[0]["text"], "Already decided")
        for st in (403, 404, 500):
            self.assertEqual(notify.tap_text(st, "approve"), "Not allowed")

    def test_non_callback_updates_advance_offset(self):
        FakeAPI.updates = [[{"update_id": 40, "message": {"text": "hi"}}]]
        self.assertEqual(self.t.poll_once(self.on_tap(), timeout=0), 0)
        self.t.poll_once(self.on_tap(), timeout=0)
        self.assertEqual(calls("getUpdates")[1]["offset"], 41)
        self.assertEqual(self.taps, [])

    def test_resolved_removes_buttons(self):
        self.t.resolved(self.n, "approved")
        edit = calls("editMessageText")[0]
        self.assertEqual(edit["message_id"], 77)
        self.assertTrue(edit["text"].endswith("-> APPROVED"))
        self.assertNotIn("reply_markup", edit)
        FakeAPI.updates = [[update(1, self.data)]]
        self.t.poll_once(self.on_tap(200), timeout=0)
        self.assertEqual(self.taps[0]["refused"], "message")


class PollErrors(Base):
    def test_poll_errors_are_labelled_without_token(self):
        t = self.tg()
        for code, label in ((401, "unauthorized"), (409, "conflict"), (500, "http")):
            with self.subTest(code=code):
                FakeAPI.fail = code
                with self.assertRaises(NotifyError) as cm:
                    t.poll_once(self.on_tap(), timeout=0)
                self.assertEqual(cm.exception.status, code)
                self.assertEqual(notify.poll_error_label(cm.exception), label)
                self.assertNotIn("S3CR3T-BOT", str(cm.exception))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        dead = notify.TelegramNotifier(TOKEN, CHAT, api_base=f"http://127.0.0.1:{port}", allowed_users=(USER,))
        with self.assertRaises(NotifyError) as cm:
            dead.poll_once(self.on_tap(), timeout=0)
        self.assertIsNone(cm.exception.status)
        self.assertEqual(notify.poll_error_label(cm.exception), "network")
        self.assertNotIn("S3CR3T-BOT", str(cm.exception))

    def test_polling_thread_logs_labels_and_keeps_going(self):
        t = self.tg()
        logged, slept = [], []
        done = threading.Event()
        FakeAPI.fail = 409

        def sleep(s):
            slept.append(s)
            if len(slept) == 3:
                FakeAPI.fail = None
                FakeAPI.updates = [[update(1, "xyz")]]

        def tap(x):
            done.set()
            return 0
        t._sleep = sleep
        th = t.start_polling(tap, logged.append, timeout=0)
        self.assertTrue(done.wait(10))
        t.stop_polling()
        th.join(10)
        self.assertFalse(th.is_alive())
        self.assertEqual(logged, ["conflict"])              # once per run of 409s
        self.assertEqual(slept[:3], [1, 2, 4])


class Build(unittest.TestCase):
    def test_build_allowed_users(self):
        rd = lambda p: TOKEN  # noqa: E731
        t = notify.build({"notify": [{"type": "telegram", "bot_token_file": "b", "chat_id": 1,
                                      "allowed_users": [111, 222]}]}, rd)
        self.assertTrue(t.actions_enabled)
        self.assertEqual(t.allowed_users, (111, 222))
        plain = notify.build({"notify": [{"type": "telegram", "bot_token_file": "b", "chat_id": 1}]}, rd)
        self.assertFalse(plain.actions_enabled)
        for bad in (["111"], [True], [0], [-5], "111", list(range(1, 23)), [1.5]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as cm:
                    notify.build({"notify": [{"type": "ticker", "ha_url": "http://ha", "ha_token_file": "x"},
                                             {"type": "telegram", "bot_token_file": "b", "chat_id": 1,
                                              "allowed_users": bad}]}, rd)
                self.assertEqual(str(cm.exception),
                                 "notify[1].allowed_users must be a list of Telegram user ids")


if __name__ == "__main__":
    unittest.main()
