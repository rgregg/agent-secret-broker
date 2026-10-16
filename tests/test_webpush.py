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
        code, body = self.get()
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
        self.assertGreaterEqual(js.count("openWindow"), 2)
        self.assertIn(".catch(", js)

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
        self.assertEqual((code, loc), (303, "/?note=push_test_ok"))
        self.assertEqual(len(self.sender.calls), 1)
        code, loc, _ = self.post("/push/revoke", {"id": sid})
        self.assertEqual((code, loc), (303, "/?note=push_removed"))
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
        self.assertEqual(sorted(data), ["body", "tag", "title"])
        self.assertEqual(data["body"], "svc")
        self.assertNotIn("SEKRIT", self.sender.calls[0]["data"])
        self.assertNotIn("path-with-detail", self.sender.calls[0]["data"])


if __name__ == "__main__":
    unittest.main()
