import base64
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only: its tests are not re-collected)

from secret_broker import broker as broker_mod  # noqa: E402
from secret_broker import webpush  # noqa: E402
from secret_broker.notify import NotifyError  # noqa: E402

try:
    import pywebpush  # noqa: F401
    HAVE_LIB = True
except ImportError:
    HAVE_LIB = False

EP = "https://fcm.googleapis.com/fcm/send/abc123"
P256DH = "BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM"
AUTH = "tBHItJI5svbpez7KI4CCXg"


class Sender:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail or {}

    def __call__(self, sub, data, key_path, subject, ttl):
        self.calls.append({"endpoint": sub["endpoint"], "data": data, "ttl": ttl})
        err = self.fail.get(sub["endpoint"])
        if err is not None:
            raise webpush.PushError(err, "boom")


def make_store(sender=None, **kw):
    d = tempfile.mkdtemp()
    return webpush.PushStore(os.path.join(d, "webpush.json"), os.path.join(d, "vapid.pem"),
                             "https://secrets.example", sender=sender or Sender(), **kw)


class Store(unittest.TestCase):
    def test_add_dedupes_by_endpoint(self):
        s = make_store()
        a = s.add("alice", EP, P256DH, AUTH, "UA one")
        b = s.add("alice", EP, P256DH, AUTH, "UA two")
        self.assertEqual(a, b)
        self.assertEqual(len(s.devices()), 1)
        self.assertEqual(s.devices()[0]["agent"], "UA two")

    def test_endpoint_must_be_a_known_push_service(self):
        s = make_store()
        for bad in ("http://fcm.googleapis.com/x", "https://evil.example/x",
                    "https://fcm.googleapis.com.evil.example/x", "https://u:p@fcm.googleapis.com/x",
                    "https://fcm.googleapis.com:8443/x", "https://127.0.0.1/x", ""):
            with self.assertRaises(ValueError, msg=bad):
                s.add("alice", bad, P256DH, AUTH)
        with self.assertRaises(ValueError):
            s.add("alice", EP, "not base64!", AUTH)
        self.assertEqual(s.devices(), [])

    def test_extra_hosts_can_be_configured(self):
        s = make_store(extra_hosts=("push.internal.example",))
        s.add("alice", "https://push.internal.example/x", P256DH, AUTH)

    def test_devices_never_expose_endpoint_or_keys(self):
        s = make_store()
        s.add("alice", EP, P256DH, AUTH)
        blob = json.dumps(s.devices())
        self.assertNotIn("fcm.googleapis.com", blob)
        self.assertNotIn(AUTH, blob)

    def test_file_is_private(self):
        s = make_store()
        s.add("alice", EP, P256DH, AUTH)
        self.assertEqual(os.stat(s._path).st_mode & 0o777, 0o600)

    def test_gone_subscription_is_removed_and_errors_recorded(self):
        sender = Sender({EP + "-gone": 410, EP + "-flaky": 503})
        s = make_store(sender)
        s.add("alice", EP, P256DH, AUTH)
        s.add("alice", EP + "-gone", P256DH, AUTH)
        s.add("alice", EP + "-flaky", P256DH, AUTH)
        ok, errors = s.send_all({"title": "t"})
        self.assertEqual(ok, 1)
        self.assertEqual(len(errors), 2)
        left = {d["id"]: d for d in s.devices()}
        self.assertEqual(len(left), 2)                      # the 410 one is gone
        self.assertEqual(sorted(bool(d["last_ok"]) for d in left.values()), [False, True])
        self.assertTrue(any(d["last_error"] == "HTTP 503" for d in left.values()))

    def test_remove(self):
        s = make_store()
        sid = s.add("alice", EP, P256DH, AUTH)
        self.assertTrue(s.remove(sid))
        self.assertFalse(s.remove(sid))

    @unittest.skipUnless(HAVE_LIB, "pywebpush not installed")
    def test_public_key_is_generated_once_and_private(self):
        s = make_store()
        key = s.public_key()
        self.assertEqual(len(base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))), 65)
        self.assertEqual(os.stat(s._vapid_path).st_mode & 0o777, 0o600)
        self.assertEqual(make_store.__name__, "make_store")
        again = webpush.PushStore(s._path, s._vapid_path, "https://x.example")
        self.assertEqual(again.public_key(), key)


class Contract(unittest.TestCase):
    def test_old_style_transports_still_work_alone_and_in_a_multi(self):
        from secret_broker import notify
        got = []

        class Old:
            def send(self, title, message, url, tag):
                got.append(("old", title))

        class New:
            def send(self, title, message, url, tag, names=None):
                got.append(("new", names))
        notify.deliver(Old(), "t", "m", "u", "tag", ["a"])
        notify.MultiNotifier([Old(), New()]).send("t", "m", "u", "tag", names=["a", "b"])
        self.assertEqual(got, [("old", "t"), ("old", "t"), ("new", ["a", "b"])])


class Notifier(unittest.TestCase):
    def test_payload_is_title_and_names_only(self):
        sender = Sender()
        s = make_store(sender)
        s.add("alice", EP, P256DH, AUTH)
        webpush.WebPushNotifier(s).send(
            "Secret request [LOW]", "svc from host\nGET https://x.example/p?token=SEKRIT",
            "https://secrets.example/a/NONCE123", "secret-abcd1234", names=["svc", "other"])
        data = json.loads(sender.calls[0]["data"])
        self.assertEqual(data, {"title": "Secret request [LOW]", "body": "svc, other",
                                "tag": "secret-abcd1234"})
        blob = sender.calls[0]["data"]
        for leak in ("SEKRIT", "NONCE123", "secrets.example", "x.example"):
            self.assertNotIn(leak, blob)

    def test_no_devices_is_a_delivery_failure(self):
        with self.assertRaises(NotifyError):
            webpush.WebPushNotifier(make_store()).send("t", "m", "u", "tag", names=["a"])

    def test_all_pushes_refused_is_a_delivery_failure(self):
        s = make_store(Sender({EP: 500}))
        s.add("alice", EP, P256DH, AUTH)
        with self.assertRaises(NotifyError):
            webpush.WebPushNotifier(s).send("t", "m", "u", "tag", names=["a"])

    @unittest.skipUnless(HAVE_LIB, "pywebpush not installed")
    def test_real_encryption_roundtrip_with_library(self):
        """The library really can encrypt for a browser-shaped subscription."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from pywebpush import WebPusher
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        sub = {"endpoint": EP, "keys": {"p256dh": b64(pub), "auth": b64(os.urandom(16))}}
        enc = WebPusher(sub).encode(b'{"title":"x"}', "aes128gcm")
        self.assertTrue(enc)


@unittest.skipUnless(HAVE_LIB, "pywebpush not installed")
class RealSend(unittest.TestCase):
    """The production sender: VAPID-signed, encrypted request to the push service."""

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        self.sub = {"endpoint": EP, "keys": {"p256dh": b64(pub), "auth": b64(os.urandom(16))}}
        d = tempfile.mkdtemp()
        self.store = webpush.PushStore(os.path.join(d, "s.json"), os.path.join(d, "k.pem"),
                                       "https://secrets.example")
        self.store.public_key()                                # creates the key file

    def run_send(self, status):
        from unittest import mock
        seen = {}

        class Resp:
            status_code = status
            ok = status < 400
            text = ""
            reason = "x"
            content = b""
            headers = {}

            def raise_for_status(self):
                import requests
                if status >= 400:
                    raise requests.HTTPError(response=self)

        def fake_post(url, data=None, headers=None, **kw):
            seen.update(url=url, data=data, headers=dict(headers or {}), kw=kw)
            return Resp()
        with mock.patch("requests.post", fake_post), mock.patch("requests.Session.post",
                                                               lambda self, *a, **k: fake_post(*a, **k)):
            err = None
            try:
                webpush._send_with_pywebpush({"endpoint": EP, "keys": self.sub["keys"]},
                                             '{"title":"x"}', self.store._vapid_path,
                                             "https://secrets.example", 120)
            except webpush.PushError as e:
                err = e
        return seen, err

    def test_request_is_signed_encrypted_and_has_ttl(self):
        seen, err = self.run_send(201)
        self.assertIsNone(err)
        self.assertEqual(seen["url"], EP)
        h = {k.lower(): v for k, v in seen["headers"].items()}
        self.assertTrue(h["authorization"].startswith("vapid "))
        self.assertEqual(str(h["ttl"]), "120")
        self.assertEqual(h["content-encoding"], "aes128gcm")
        self.assertNotIn(b"title", seen["data"])               # ciphertext, not the plaintext

    def test_gone_status_is_reported(self):
        _, err = self.run_send(410)
        self.assertIsNotNone(err)
        self.assertEqual(err.status, 410)


@unittest.skipUnless(HAVE_LIB, "pywebpush not installed")
class Listener(t.Dashboard):
    """Subscribe / revoke / test over the approval listener, behind CSRF."""

    def setUp(self):
        super().setUp()
        self.sender = Sender()
        self.store = make_store(self.sender)
        self.broker.push = self.store

    def post(self, path, form, user="alice", csrf="ok"):
        form = dict(form)
        if csrf is not None:
            form["csrf"] = self.broker.csrf_token(user) if csrf == "ok" else csrf
        import urllib.request

        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            r = urllib.request.build_opener(NoFollow).open(urllib.request.Request(
                self.abase + path, data=urllib.parse.urlencode(form).encode(),
                headers={"X-authentik-username": user}, method="POST"), timeout=10)
            return r.status, r.headers.get("Location"), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location"), e.read().decode()

    def sub_form(self, endpoint=EP):
        return {"endpoint": endpoint, "p256dh": P256DH, "auth": AUTH}

    def test_dashboard_offers_push_and_serves_the_service_worker(self):
        code, body = self.get("/settings")
        self.assertEqual(code, 200)
        self.assertIn("id=push-enable", body)
        self.assertIn("data-key='", body)
        import urllib.request
        r = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/sw.js", headers={"X-authentik-username": "alice"}))
        js = r.read().decode()
        self.assertEqual(r.headers["Service-Worker-Allowed"], "/")
        self.assertIn("javascript", r.headers["Content-Type"])
        self.assertIn("showNotification", js)
        self.assertNotIn("nonce", js.lower())
        # a click must never do nothing: focus failure or no tab opens a window
        self.assertIn("notificationclick", js)
        self.assertGreaterEqual(js.count("openWindow"), 1)
        self.assertIn(".catch(", js)
        self.assertIn(f"SW_VERSION='{broker_mod.SW_VERSION}'", js)
        self.assertEqual(r.headers["X-SW-Version"], broker_mod.SW_VERSION)
        self.assertIn("no-cache", r.headers["Cache-Control"])
        self.assertNotIn("__SW_VERSION__", js)
        for needle in ("addEventListener('message'", "type==='version'", "type==='skip'",
                       "skipWaiting", "/push/event", "X-Requested-With", "notificationclose",
                       "pushsubscriptionchange", "click_navigate", "click_focus",
                       "click_openwindow", "click_outcome", "sw_install", "sw_activate",
                       "keepalive", "Q.length<20"):
            self.assertIn(needle, js)

    def test_settings_shows_service_worker_status_block(self):
        code, body = self.get("/settings")
        self.assertEqual(code, 200)
        self.assertIn(f"id=sw-box data-expected='{broker_mod.SW_VERSION}'", body)
        for el in ("sw-status", "sw-expected", "sw-running", "sw-waiting", "sw-controlled",
                   "sw-reg", "sw-sub", "sw-caches", "sw-update", "sw-clear", "sw-recheck"):
            self.assertIn(f"id={el}", body)
        for label in ("Expected (server)", "Running (active worker)", "Waiting / installing",
                      "This tab is controlled by the worker", "Registration",
                      "Push subscription", "Update worker now", "Recheck"):
            self.assertIn(label, body)
        for js in ("sw_status", "Up to date", "Stale: running v", "No worker registered",
                   "not responding", "controllerchange", "type:'skip'"):
            self.assertIn(js, body)

    def test_sw_status_event_is_accepted_and_sanitized(self):
        self.assertEqual(self.ev({"kind": "sw_status", "v": "5", "state": "stale" * 20,
                                  "note": "expected v6", "title": "SEKRIT"}), 204)
        (r,) = self.events("client_event")
        self.assertEqual((r["kind"], r["v"], r["note"]), ("sw_status", "5", "expected v6"))
        self.assertEqual(len(r["state"]), 24)
        self.assertNotIn("title", r)

    def ev(self, body, user="alice", hdr=None, raw=None):
        import urllib.request
        h = {"X-authentik-username": user, "Content-Type": "application/json",
             "X-Requested-With": "asb"}
        h.update(hdr or {})
        h = {k: v for k, v in h.items() if v is not None}
        data = raw if raw is not None else json.dumps(body).encode()
        try:
            return urllib.request.urlopen(urllib.request.Request(
                self.abase + "/push/event", data=data, headers=h, method="POST"), timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_client_event_requires_header_type_size_and_user(self):
        ok = {"kind": "push"}
        self.assertEqual(self.ev(ok, hdr={"X-Requested-With": None}), 403)
        self.assertEqual(self.ev(ok, hdr={"Content-Type": "text/plain"}), 403)
        self.assertEqual(self.ev(ok, hdr={"Content-Type": "application/x-www-form-urlencoded"}), 403)
        self.assertEqual(self.ev({"kind": "x", "note": "a" * 3000}), 413)
        self.assertEqual(self.ev(None, user="mallory"), 403)
        self.assertEqual(self.ev(None, raw=b"not json"), 400)
        self.assertEqual(self.ev(None, raw=b"[1]"), 400)
        self.assertEqual(self.ev({"note": "no kind"}), 400)
        self.assertEqual(self.events("client_event"), [])
        self.assertEqual(self.ev(ok, hdr={"Sec-Fetch-Site": "cross-site"}), 403)

    def test_client_event_is_sanitized_and_audited(self):
        code = self.ev({"kind": "notificationclick", "v": "5", "tag": "t" * 99, "action": "open",
                        "clients": 2, "ms": 1234, "ok": True, "visible": False, "state": "focused",
                        "err": "e" * 500, "note": "n" * 500, "queued": 3,
                        "client_paths": ["https://h/settings?token=SEKRIT#f", "/", "/a/b?x=1",
                                         "/4", "/5", "/6-dropped"],
                        "title": "SEKRIT-title", "body": "SEKRIT-body", "user": "evil",
                        "peer": "6.6.6.6", "url": "https://x/?token=SEKRIT"})
        self.assertEqual(code, 204)
        (r,) = self.events("client_event")
        self.assertEqual(r["user"], "alice")
        self.assertEqual(r["peer"], "127.0.0.1")
        self.assertEqual(len(r["tag"]), 40)
        self.assertEqual(len(r["err"]), 120)
        self.assertEqual(len(r["note"]), 80)
        self.assertEqual(r["client_paths"], ["/settings", "/", "/a/b", "/4", "/5"])
        self.assertEqual((r["clients"], r["ms"], r["ok"], r["visible"], r["queued"]),
                         (2, 1234, True, False, 3))
        for k in ("title", "body", "url"):
            self.assertNotIn(k, r)
        self.assertNotIn("SEKRIT", json.dumps(r))

    def test_client_event_rate_limit_drops_and_audits_once(self):
        lim = broker_mod._CE_LIMIT
        for _ in range(lim):
            self.assertEqual(self.ev({"kind": "visibility"}), 204)
        for _ in range(5):
            self.assertEqual(self.ev({"kind": "visibility"}), 204)
        self.assertEqual(len(self.events("client_event")), lim)
        (d,) = self.events("client_event_dropped")
        self.assertEqual((d["user"], d["dropped"], d["limit_per_min"]), ("alice", 1, lim))

    def test_service_worker_reports_every_step(self):
        import urllib.request
        js = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/sw.js", headers={"X-authentik-username": "alice"})).read().decode()
        self.assertIn(f"SW_VERSION='{broker_mod.SW_VERSION}'", js)
        self.assertIn("/push/event", js)
        self.assertIn("X-Requested-With", js)
        for step in ("notificationclick", "notificationclose", "pushsubscriptionchange",
                     "click_navigate", "click_focus", "click_openwindow", "click_outcome",
                     "sw_install", "sw_activate", "'show'", "keepalive"):
            self.assertIn(step, js)
        # the dashboard page reports too, and the CSP lets it fetch same-origin
        import urllib.request as ur
        r = ur.urlopen(ur.Request(self.abase + "/settings", headers={"X-authentik-username": "alice"}))
        page, csp = r.read().decode(), r.headers["Content-Security-Policy"]
        self.assertIn("connect-src 'self'", csp)
        for k in ("page_load", "sw_registered", "sw_register_failed", "sw_message",
                  "poll_requested", "visibility"):
            self.assertIn(k, page)

    def test_subscribe_requires_the_csrf_token(self):
        code, _, _ = self.post("/push/subscribe", self.sub_form(), csrf=None)
        self.assertEqual(code, 403)
        self.assertEqual(self.store.devices(), [])
        code, _, body = self.post("/push/subscribe", self.sub_form())
        self.assertEqual(code, 200)
        self.assertEqual(len(self.store.devices()), 1)
        self.assertEqual(len(self.events("push_subscribed")), 1)

    def test_subscribe_refuses_an_unknown_push_host(self):
        code, _, _ = self.post("/push/subscribe", self.sub_form("https://evil.example/x"))
        self.assertEqual(code, 400)
        self.assertEqual(self.store.devices(), [])
        self.assertEqual(len(self.events("push_refused")), 1)

    def test_revoke_and_test_push(self):
        self.post("/push/subscribe", self.sub_form())
        sid = self.store.devices()[0]["id"]
        code, loc, _ = self.post("/push/test", {})
        self.assertEqual((code, loc), (303, "/settings?note=push_test_ok"))
        self.assertEqual(len(self.sender.calls), 1)
        code, loc, _ = self.post("/push/revoke", {"id": sid})
        self.assertEqual((code, loc), (303, "/settings?note=push_removed"))
        self.assertEqual(self.store.devices(), [])
        self.assertEqual(len(self.events("push_revoked")), 1)

    def test_a_request_pushes_names_only_through_the_real_pipeline(self):
        self.store.add("alice", EP, P256DH, AUTH)
        self.broker.notifier = webpush.WebPushNotifier(self.store)
        self.ask("/path-with-detail?token=SEKRIT")
        end = time.time() + 5
        while not self.sender.calls and time.time() < end:
            time.sleep(0.1)
        self.assertTrue(self.sender.calls)
        data = json.loads(self.sender.calls[0]["data"])
        self.assertEqual(sorted(data), ["actions", "body", "rid", "tag", "title", "token"])
        self.assertEqual(data["body"], "svc")
        self.assertNotIn("SEKRIT", self.sender.calls[0]["data"])
        self.assertNotIn("path-with-detail", self.sender.calls[0]["data"])


class ParseActions(unittest.TestCase):
    def test_defaults_and_valid(self):
        self.assertEqual(webpush.parse_actions(None), {"approve_max_risk": "high", "deny": True})
        self.assertEqual(webpush.parse_actions({}), {"approve_max_risk": "high", "deny": True})
        self.assertEqual(webpush.parse_actions({"actions": {"approve_max_risk": "low", "deny": False}}),
                         {"approve_max_risk": "low", "deny": False})

    def test_invalid_names_the_field(self):
        for bad, field in (({"approve_max_risk": "critical"}, "approve_max_risk"),
                           ({"approve_max_risk": 3}, "approve_max_risk"),
                           ({"deny": "yes"}, "deny"), ({"nope": 1}, "nope"), ("x", "actions")):
            with self.assertRaises(ValueError) as cm:
                webpush.parse_actions({"actions": bad})
            self.assertIn(field, str(cm.exception))

    def test_actions_per_risk_and_setting(self):
        def acts(mx, deny, risk):
            n = webpush.WebPushNotifier(make_store(), {"approve_max_risk": mx, "deny": deny})
            return n.actions_for(risk)
        for risk in ("low", "medium", "high", None):
            self.assertEqual(acts("high", True, risk), ["deny", "approve"])
            self.assertEqual(acts("none", True, risk), ["deny"])
        self.assertEqual(acts("low", True, "low"), ["deny", "approve"])
        self.assertEqual(acts("low", True, "medium"), ["deny"])
        self.assertEqual(acts("low", True, None), ["deny"])
        self.assertEqual(acts("medium", True, "medium"), ["deny", "approve"])
        self.assertEqual(acts("medium", True, "high"), ["deny"])
        self.assertEqual(acts("medium", False, "high"), [])
        self.assertEqual(acts("high", False, "high"), ["approve"])

    def test_context_is_only_passed_to_notifiers_that_take_it(self):
        from secret_broker import notify
        got = {}

        class Old:
            def send(self, title, message, url, tag):
                got["old"] = True

        class Names:
            def send(self, title, message, url, tag, names=None):
                got["names"] = names

        class New:
            def send(self, title, message, url, tag, names=None, context=None):
                got["ctx"] = context
        for n in (Old(), Names(), New()):
            notify.deliver(n, "t", "m", "u", "g", ["a"], {"rid": "r"})
        self.assertEqual((got["old"], got["names"], got["ctx"]), (True, ["a"], {"rid": "r"}))


class PushDecide(t.Dashboard):
    """Approve / Deny buttons on the notification: POST /push/decide."""

    def setUp(self):
        super().setUp()
        self.sender = Sender()
        self.store = make_store(self.sender)
        self.broker.push = self.store
        self.store.add("alice", EP, P256DH, AUTH)
        self.set_actions()

    def set_actions(self, **actions):
        self.broker.notifier = webpush.WebPushNotifier(
            self.store, webpush.parse_actions({"actions": actions}))

    def pushed(self, n=1):
        end = time.time() + 5
        while len(self.sender.calls) < n and time.time() < end:
            time.sleep(0.05)
        self.assertGreaterEqual(len(self.sender.calls), n)
        return json.loads(self.sender.calls[n - 1]["data"])

    def pd(self, body, user="alice", hdr=None, raw=None):
        import urllib.request
        h = {"X-authentik-username": user, "Content-Type": "application/json",
             "X-Requested-With": "asb"}
        h.update(hdr or {})
        h = {k: v for k, v in h.items() if v is not None}
        data = raw if raw is not None else json.dumps(body).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + "/push/decide", data=data, headers=h, method="POST"), timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def audit_text(self):
        with open(self.audit) as f:
            return f.read()

    def test_payload_has_actions_rid_and_token_but_no_details(self):
        rid = self.ask("/path-with-detail?token=SEKRIT")
        d = self.pushed()
        self.assertEqual(sorted(d), ["actions", "body", "rid", "tag", "title", "token"])
        self.assertEqual(d["actions"], ["deny", "approve"])
        self.assertEqual(d["rid"], rid)
        self.assertEqual(d["body"], "svc")
        self.assertNotIn("SEKRIT", json.dumps(d))
        self.assertGreaterEqual(len(d["token"]), 22)       # 128 bits, base64url

    def test_config_controls_the_listed_actions(self):
        self.set_actions(approve_max_risk="none")
        self.ask()
        self.assertEqual(self.pushed(1)["actions"], ["deny"])
        self.set_actions(deny=False)
        self.ask("/y")
        self.assertEqual(self.pushed(2)["actions"], ["approve"])

    def test_risk_ordering_gates_approve(self):
        self.set_actions(approve_max_risk="low")
        self.broker.summarizer = t._Stub("Reads things", "medium")
        self.ask()
        self.assertEqual(self.pushed(1)["actions"], ["deny"])
        self.broker.summarizer = t._Stub("Reads things", "low")
        self.ask("/y")
        self.assertEqual(self.pushed(2)["actions"], ["deny", "approve"])

    def test_no_actions_means_no_token_in_the_payload(self):
        self.set_actions(approve_max_risk="none", deny=False)
        self.ask()
        d = self.pushed()
        self.assertEqual(sorted(d), ["body", "tag", "title"])

    def test_approve_by_push_delivers_and_is_audited_as_push(self):
        rid = self.ask()
        d = self.pushed()
        code, body = self.pd({"rid": rid, "token": d["token"], "decision": "approve"}, user="alice")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"ok": True, "decision": "approve"})
        self.assertEqual(self.result(rid)["status"], "approved")
        (dec,) = self.events("decided")
        self.assertEqual((dec["channel"], dec["approver"], dec["decision"]),
                         ("push", "alice", "approve"))
        self.assertFalse(dec["always_requested"])
        (ok,) = self.events("approved")
        self.assertEqual(ok["channel"], "push")

    def test_deny_by_push_denies(self):
        rid = self.ask()
        d = self.pushed()
        code, body = self.pd({"token": d["token"], "decision": "deny"})   # rid optional
        self.assertEqual((code, json.loads(body)), (200, {"ok": True, "decision": "deny"}))
        self.assertEqual(self.result(rid)["status"], "denied")
        (den,) = self.events("denied")
        self.assertEqual(den["channel"], "push")
        self.assertEqual(den["approver"], "alice")

    def test_no_always_allow_rule_is_ever_created(self):
        rid = self.ask()
        d = self.pushed()
        self.pd({"rid": rid, "token": d["token"], "decision": "approve", "always": True,
                 "decision_extra": "approve_always"})
        self.assertEqual(self.events("policy_change"), [])
        self.assertEqual(self.broker.cfg["secrets"]["svc"].get("approval", "prompt"), "prompt")
        self.assertFalse(self.events("decided")[0]["always_requested"])

    def test_replay_after_decision_is_410_and_changes_nothing(self):
        rid = self.ask()
        d = self.pushed()
        self.assertEqual(self.pd({"rid": rid, "token": d["token"], "decision": "deny"})[0], 200)
        before = self.audit_text()
        self.assertEqual(self.pd({"rid": rid, "token": d["token"], "decision": "approve"})[0], 410)
        self.assertEqual(self.pd({"token": d["token"], "decision": "approve"})[0], 410)
        self.assertEqual(self.result(rid)["status"], "denied")
        self.assertEqual(len(self.events("decided")), 1)
        self.assertEqual(self.events("approved"), [])
        self.assertNotIn(d["token"], self.audit_text())
        self.assertEqual(before.count('"decided"'), self.audit_text().count('"decided"'))

    def test_dashboard_decision_kills_the_token(self):
        rid = self.ask()
        d = self.pushed()
        self.decide(rid, "deny")
        self.assertEqual(self.pd({"rid": rid, "token": d["token"], "decision": "approve"})[0], 410)
        self.assertEqual(self.result(rid)["status"], "denied")

    def test_wrong_token_is_403_and_leaves_the_request_pending(self):
        rid = self.ask()
        d = self.pushed()
        self.assertEqual(self.pd({"rid": rid, "token": "x" * 22, "decision": "approve"})[0], 403)
        self.assertEqual(self.pd({"token": "x" * 22, "decision": "approve"})[0], 403)
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.pd({"rid": rid, "token": d["token"], "decision": "approve"})[0], 200)

    def test_token_is_bound_to_its_request(self):
        rid1 = self.ask("/a")
        d1 = self.pushed(1)
        rid2 = self.ask("/b")
        d2 = self.pushed(2)
        self.assertNotEqual(d1["token"], d2["token"])
        self.assertEqual(self.pd({"rid": rid2, "token": d1["token"], "decision": "approve"})[0], 403)
        self.assertEqual(self.pd({"rid": rid1, "token": d2["token"], "decision": "approve"})[0], 403)
        self.assertEqual(self.pd({"rid": rid1, "token": d1["token"], "decision": "deny"})[0], 200)
        self.assertEqual(self.result(rid1)["status"], "denied")
        self.assertEqual(self.broker._by_id[rid2].status, "pending")

    def test_unknown_request_and_bad_bodies(self):
        self.assertEqual(self.pd({"rid": "nope", "token": "x" * 22, "decision": "approve"})[0], 404)
        self.assertEqual(self.pd({"token": "x", "decision": "maybe"})[0], 400)
        self.assertEqual(self.pd({"decision": "approve"})[0], 400)
        self.assertEqual(self.pd(None, raw=b"not json")[0], 400)
        self.assertEqual(self.pd(None, raw=b"[1]")[0], 400)
        self.assertEqual(self.pd({"token": "a" * 3000, "decision": "deny"})[0], 413)

    def test_guard_headers_and_user_are_required(self):
        rid = self.ask()
        d = self.pushed()
        ok = {"rid": rid, "token": d["token"], "decision": "approve"}
        self.assertEqual(self.pd(ok, hdr={"X-Requested-With": None})[0], 403)
        self.assertEqual(self.pd(ok, hdr={"X-Requested-With": "x"})[0], 403)
        self.assertEqual(self.pd(ok, hdr={"Content-Type": "text/plain"})[0], 403)
        self.assertEqual(self.pd(ok, hdr={"Content-Type": "application/x-www-form-urlencoded"})[0], 403)
        self.assertEqual(self.pd(ok, hdr={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.pd(ok, user="mallory")[0], 403)
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.pd(ok)[0], 200)

    def test_expired_request_is_410(self):
        rid = self.ask()
        d = self.pushed()
        self.broker._by_id[rid].expires = time.time() - 1
        self.assertEqual(self.pd({"rid": rid, "token": d["token"], "decision": "approve"})[0], 410)
        self.assertEqual(self.events("decided"), [])
        self.assertEqual(self.broker._by_id[rid].status, "expired")

    def test_response_never_carries_request_details(self):
        rid = self.ask("/path-with-detail?token=SEKRIT")
        d = self.pushed()
        for body in ({"rid": rid, "token": "x" * 22, "decision": "approve"},
                     {"rid": rid, "token": d["token"], "decision": "approve"},
                     {"rid": rid, "token": d["token"], "decision": "approve"}):
            _, text = self.pd(body)
            self.assertNotIn("SEKRIT", text)
            self.assertNotIn("svc", text)
            self.assertNotIn(d["token"], text)

    def test_token_never_reaches_audit_or_history(self):
        rid = self.ask()
        d = self.pushed()
        self.pd({"rid": rid, "token": d["token"], "decision": "approve"})
        self.result(rid)
        self.assertNotIn(d["token"], self.audit_text())
        code, page = self.get("/")
        self.assertNotIn(d["token"], page)

    def test_service_worker_has_v7_decide_and_fallbacks(self):
        import urllib.request
        js = urllib.request.urlopen(urllib.request.Request(
            self.abase + "/sw.js", headers={"X-authentik-username": "alice"})).read().decode()
        self.assertEqual(broker_mod.SW_VERSION, "7")
        self.assertIn("SW_VERSION='7'", js)
        for needle in ("/push/decide", "X-Requested-With", "credentials:'same-origin'",
                       "redirect:'manual'", "action_click", "action_decide",
                       "Could not '+verb+' - tap to review", "'Approved'", "'Denied'",
                       "maxActions", "openWindow"):
            self.assertIn(needle, js)

    # -- worker simulation under node --------------------------------------
    NODE_HARNESS = r"""
const fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const scenario=process.argv[3], action=process.argv[4];
const listeners={}, shown=[], fetches=[], closed=[];
global.setTimeout=(f,ms)=>{return setImmediate(f);};
const reg={showNotification:(t,o)=>{shown.push({t,o});return Promise.resolve();},
  getNotifications:()=>Promise.resolve([{close(){closed.push(1);}}])};
global.self={addEventListener:(n,f)=>{listeners[n]=f;},registration:reg,
  clients:{matchAll:()=>Promise.resolve([]),claim:()=>Promise.resolve(),openWindow:(u)=>{fetches.push('open '+u);return Promise.resolve({});}},
  skipWaiting:()=>Promise.resolve(),Notification:{maxActions:2}};
global.Notification={maxActions:+(process.env.MAXA||2)};
global.fetch=(u,o)=>{
  fetches.push(u+' '+(o&&o.body||''));
  if(u==='/push/event')return Promise.resolve({status:204});
  if(scenario==='net')return Promise.reject(new TypeError('Failed to fetch'));
  if(scenario==='redirect')return Promise.resolve({status:0,type:'opaqueredirect'});
  return Promise.resolve({status:scenario==='gone'?410:200,type:'basic'});
};
new Function(src).call(global);
(async()=>{
  let p;
  listeners.push({data:{json:()=>({title:'Secret request [LOW]',body:'svc',tag:'secret-abc',
    actions:['deny','approve'],rid:'RID',token:'TOK'})},waitUntil:(x)=>{p=x;}});
  await p;
  const first=shown[0];
  shown.length=0;fetches.length=0;
  p=null;
  listeners.notificationclick({action,notification:{tag:'secret-abc',data:first.o.data,close(){}},waitUntil:(x)=>{p=x;}});
  await p;
  await new Promise(r=>setTimeout(r,10));
  console.log(JSON.stringify({first:{actions:first.o.actions.map(a=>a.action),data:first.o.data},shown,
    fetches,closed:closed.length}));
})();
"""

    def run_worker(self, scenario, action, maxa=2):
        import subprocess
        import shutil
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "sw.js"), "w") as f:
            f.write(broker_mod._SERVICE_WORKER)
        with open(os.path.join(d, "h.js"), "w") as f:
            f.write(self.NODE_HARNESS)
        chk = subprocess.run([node, "--check", os.path.join(d, "sw.js")], capture_output=True, text=True)
        self.assertEqual(chk.returncode, 0, chk.stderr)
        r = subprocess.run([node, os.path.join(d, "h.js"), os.path.join(d, "sw.js"), scenario, action],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "MAXA": str(maxa)})
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def decide_fetches(self, out):
        return [f for f in out["fetches"] if f.startswith("/push/decide")]

    def beacon_kinds(self, out):
        return [json.loads(f.split(" ", 1)[1]) for f in out["fetches"] if f.startswith("/push/event ")]

    def test_worker_renders_buttons_deny_first_and_caps_to_browser_max(self):
        out = self.run_worker("ok", "open")
        self.assertEqual(out["first"]["actions"], ["deny", "approve"])
        self.assertEqual(out["first"]["data"]["token"], "TOK")
        out1 = self.run_worker("ok", "open", maxa=1)
        self.assertEqual(out1["first"]["actions"], ["deny"])
        out3 = self.run_worker("ok", "open", maxa=3)
        self.assertEqual(out3["first"]["actions"], ["deny", "approve", "open"])

    def test_worker_approve_success_shows_short_names_only_followup(self):
        out = self.run_worker("ok", "approve")
        (post,) = self.decide_fetches(out)
        self.assertEqual(json.loads(post.split(" ", 1)[1]),
                         {"rid": "RID", "token": "TOK", "decision": "approve"})
        (n,) = out["shown"]
        self.assertEqual(n["t"], "Approved: svc")
        self.assertEqual(n["o"]["tag"], "secret-abc")
        self.assertFalse(n["o"]["requireInteraction"])
        self.assertEqual(out["closed"], 1)                 # auto-closed
        kinds = [b["kind"] for b in self.beacon_kinds(out)]
        self.assertEqual(kinds, ["action_click", "action_decide"])
        dec = self.beacon_kinds(out)[1]
        self.assertTrue(dec["ok"])
        self.assertEqual(dec["note"], "http 200")
        self.assertNotIn("TOK", json.dumps(self.beacon_kinds(out)))

    def test_worker_deny_success(self):
        out = self.run_worker("ok", "deny")
        self.assertEqual(json.loads(self.decide_fetches(out)[0].split(" ", 1)[1])["decision"], "deny")
        self.assertEqual(out["shown"][0]["t"], "Denied: svc")

    def test_worker_410_shows_could_not_and_tap_opens_app(self):
        out = self.run_worker("gone", "approve")
        (n,) = out["shown"]
        self.assertEqual(n["t"], "Could not approve - tap to review")
        self.assertEqual(n["o"]["data"], {"url": "/"})
        self.assertEqual(out["closed"], 0)
        dec = self.beacon_kinds(out)[1]
        self.assertEqual((dec["kind"], dec["ok"], dec["note"]), ("action_decide", False, "http 410"))

    def test_worker_network_failure_and_sso_redirect(self):
        for scenario, note in (("net", "network"), ("redirect", "http 0 redirect")):
            out = self.run_worker(scenario, "deny")
            self.assertEqual(out["shown"][0]["t"], "Could not deny - tap to review")
            dec = self.beacon_kinds(out)[1]
            self.assertFalse(dec["ok"])
            self.assertEqual(dec["note"], note)

    def test_worker_review_click_does_not_decide(self):
        out = self.run_worker("ok", "open")
        self.assertEqual(self.decide_fetches(out), [])
        self.assertIn("open /", out["fetches"])


if __name__ == "__main__":
    unittest.main()
