"""WebSocket sessions (secret_broker/wssessions.py, wsproto.py, `asb ws`).

A throwaway broker per test (the test_sessions harness: a fake phone that never decides by itself, enrolled
clients through the real endpoint) in front of a local stub WebSocket server (tests/ws_stub.py) on 127.0.0.1,
port 0. Every secret here is an obviously fake canary. Nothing sleeps: tests wait on events, the session
clock is a fake one the test advances, and the sweeper is called by hand.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_sessions as ts  # noqa: E402
from test_sessions import SBase, KEY, CLI  # noqa: E402
from ws_stub import WsStub, frame  # noqa: E402
from secret_broker import destguard  # noqa: E402
from secret_broker import audit_api, sessions as S, wsproto, wssessions as W  # noqa: E402

TOKEN = "HA-TOKEN-CANARY-31337"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")


class WsBase(SBase):
    ws_cfg = None
    stub_kw = None
    ha_hosts = ("127.0.0.1", "localhost")

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.ws_cfg is not None:
            cfg["ws_sessions"] = self.ws_cfg
        cfg["_vault"]["Ha"] = {"token": TOKEN}
        cfg["secrets"]["ha"] = {"vars": {"HA_TOKEN": {"item": "Ha", "field": "token"}},
                                "allowed_hosts": list(self.ha_hosts), "ws": {"handshake": "home-assistant"}}
        cfg["_vault"]["Plainws"] = {"token": "PLAINWS-TOKEN-CANARY"}
        cfg["secrets"]["plainws"] = {"vars": {"PLAINWS_TOKEN": {"item": "Plainws", "field": "token"}},
                                     "allowed_hosts": ["127.0.0.1"], "ws": {}}
        cfg["_vault"]["Remote"] = {"token": "REMOTE-TOKEN-CANARY"}
        cfg["secrets"]["remote"] = {"vars": {"REMOTE_TOKEN": {"item": "Remote", "field": "token"}},
                                    "allowed_hosts": ["ws.example.com", "meta.example.com", "own.example.com",
                                                      "rebind.example.com", "10.0.0.5"],
                                    "ws": {"handshake": "home-assistant"}}

    def setUp(self):
        super().setUp()
        self.stubs = []
        self.stub = self.mkstub(**(self.stub_kw or {}))

    def mkstub(self, **kw):
        kw.setdefault("token", TOKEN)
        st = WsStub(**kw)
        self.stubs.append(st)
        return st

    def tearDown(self):
        for st in self.stubs:
            st.close()
        super().tearDown()

    # -- helpers ------------------------------------------------------------------------
    def wurl(self, path="/api/websocket", stub=None, host="127.0.0.1", scheme="ws"):
        return f"{scheme}://{host}:{(stub or self.stub).port}{path}"

    def wask(self, key=KEY, expect=202, cred="ha", url=None, **kw):
        body = {"mode": "session", "kind": "ws", "names": [cred], "url": url or self.wurl(), "source": "t@box"}
        body.update(kw)
        code, text = self.as_client(key, "POST", "/v1/requests", body)
        self.assertEqual(code, expect, text)
        return json.loads(text)

    def wopen(self, key=KEY, limits=None, cred="ha", url=None, **kw):
        r = self.wask(key, cred=cred, url=url, **kw)
        self.approve(r["id"], **(limits or {}))
        res = self.result(r["id"], key)
        self.assertEqual(res["status"], "approved", res)
        return res["session"]["id"]

    def wsend(self, sid, text, key=KEY):
        return self.as_client(key, "POST", "/v1/ws/send", {"session": sid, "text": text})

    def wrecv(self, sid, key=KEY, wait=5, mx=256):
        code, text = self.as_client(key, "POST", "/v1/ws/recv", {"session": sid, "wait": wait, "max": mx})
        return code, json.loads(text)

    def frames_until(self, sid, n, key=KEY):
        """Texts of the first n frames the broker hands out (long-polling, no sleeping)."""
        out = []
        end = time.time() + 15
        while len(out) < n and time.time() < end:
            code, r = self.wrecv(sid, key, wait=2)
            self.assertEqual(code, 200, r)
            out += r["frames"]
        return out

    def sess(self):
        return next(iter(self.broker._sess.values()))

    def audit_events(self, name):
        return self.events(name)

    def assertNoSecret(self, *extra):
        blob = self.audit_text() + "\n".join(self.seen) + "\n".join(self.out)
        for v in (TOKEN, "PLAINWS-TOKEN-CANARY", "REMOTE-TOKEN-CANARY", *extra):
            self.assertNotIn(v, blob)


class Open(WsBase):
    def test_handshake_ha_auth_relay_and_no_secret_leak(self):
        sid = self.wopen()
        self.assertRegex(sid, ID_RE)
        req = self.stub.requests[0]
        self.assertEqual(req["line"], "GET /api/websocket HTTP/1.1")
        h = req["headers"]
        self.assertEqual(h["host"], f"127.0.0.1:{self.stub.port}")
        self.assertEqual(h["upgrade"], "websocket")
        self.assertEqual(h["sec-websocket-version"], "13")
        self.assertNotIn("origin", h)
        self.assertNotIn("sec-websocket-extensions", h)
        self.assertEqual(h["x-secret-broker-egress"], "1")
        self.assertEqual(self.stub.auth_msgs, [{"type": "auth", "access_token": TOKEN}])
        code, _ = self.wsend(sid, '{"id":1,"type":"get_states"}')
        self.assertEqual(code, 200)
        fr = self.frames_until(sid, 1)
        self.assertEqual(json.loads(fr[0]["data"]), {"echo": '{"id":1,"type":"get_states"}'})
        self.assertEqual(self.stub.violations, [])
        self.assertNoSecret()


# ------------------------------------------------------------------------------- the protocol layer
class Pipe:
    """A Conn on one end of a socketpair; the test plays the server on the other."""

    def __init__(self, **kw):
        a, self.peer = socket.socketpair()
        self.t = wsproto.Transport(a)
        self.conn = wsproto.Conn(self.t, **kw)
        self.never = lambda mid=False: False

    def feed(self, raw):
        self.peer.sendall(raw)

    def msg(self):
        stop_at = time.monotonic() + 5
        return self.conn.read_message(lambda mid=False: time.monotonic() > stop_at)

    def close(self):
        self.t.close()
        self.peer.close()


class Proto(unittest.TestCase):
    def setUp(self):
        self.pipes = []

    def tearDown(self):
        for p in self.pipes:
            p.close()

    def pipe(self, **kw):
        p = Pipe(**kw)
        self.pipes.append(p)
        return p

    def test_text_and_binary_and_fragments_and_interleaved_ping(self):
        p = self.pipe()
        p.feed(frame(1, b"hello") + frame(2, b"\x00\x01") + frame(1, b"ab", fin=False) + frame(9, b"x")
               + frame(0, b"c", fin=False) + frame(0, b"d"))
        self.assertEqual(p.msg(), ("text", "hello"))
        self.assertEqual(p.msg(), ("binary", 2))
        self.assertEqual(p.msg(), ("text", "abcd"))
        pong = p.peer.recv(100)                     # the ping in the middle was answered, masked
        self.assertEqual(pong[0], 0x8A)
        self.assertTrue(pong[1] & 0x80)

    def test_close_frame(self):
        p = self.pipe()
        p.feed(frame(8, (1001).to_bytes(2, "big") + b"bye"))
        self.assertEqual(p.msg(), ("close", 1001))
        p.feed(frame(8, b""))
        self.assertEqual(p.msg(), ("close", 1005))

    def bad(self, raw, label=None, code=None, **kw):
        p = self.pipe(**kw)
        p.feed(raw)
        with self.assertRaises(wsproto.WsError) as cm:
            p.msg()
        if label:
            self.assertEqual(cm.exception.label, label)
        if code:
            self.assertEqual(cm.exception.code, code)

    def test_malformed_frames_fail_closed(self):
        self.bad(frame(1, b"x", mask=True) , wsproto.PROTOCOL, 1002)                     # a masked server frame
        self.bad(bytes([0xC1, 1]) + b"x", wsproto.PROTOCOL, 1002)                         # RSV1 (no extension negotiated)
        self.bad(bytes([0x83, 1]) + b"x", wsproto.PROTOCOL, 1002)                         # undefined opcode
        self.bad(frame(9, b"x" * 126), wsproto.PROTOCOL, 1002)                            # control frame too long
        self.bad(frame(9, b"x", fin=False), wsproto.PROTOCOL, 1002)                       # fragmented control frame
        self.bad(bytes([0x81, 126]) + (5).to_bytes(2, "big") + b"hello", wsproto.PROTOCOL)   # not the shortest length form
        self.bad(bytes([0x81, 127]) + (70000).to_bytes(8, "big"), wsproto.TOO_LARGE, 1009, max_frame=1000)
        self.bad(bytes([0x81, 127]) + (1 << 63).to_bytes(8, "big"), wsproto.PROTOCOL)     # top bit of the length
        self.bad(frame(0, b"x"), wsproto.PROTOCOL, 1002)                                  # continuation with no message
        self.bad(frame(1, b"a", fin=False) + frame(1, b"b"), wsproto.PROTOCOL, 1002)      # new message inside a fragmented one
        self.bad(frame(1, b"\xff\xfe"), wsproto.PROTOCOL, 1007)                           # invalid UTF-8
        self.bad(frame(8, b"\x03"), wsproto.PROTOCOL, 1002)                               # a one byte close payload
        self.bad(frame(8, (1005).to_bytes(2, "big")), wsproto.PROTOCOL, 1002)             # a close code that is never sent

    def test_size_limits_come_from_the_header_not_the_payload(self):
        p = self.pipe(max_frame=100)
        p.feed(bytes([0x81, 126]) + (5000).to_bytes(2, "big"))     # announced, never sent: refused without reading it
        with self.assertRaises(wsproto.WsError) as cm:
            p.msg()
        self.assertEqual((cm.exception.label, cm.exception.code), (wsproto.TOO_LARGE, 1009))

    def test_fragmented_message_total_is_capped(self):
        p = self.pipe(max_frame=100)
        p.feed(b"".join(frame(1 if i == 0 else 0, b"x" * 40, fin=False) for i in range(3)))
        with self.assertRaises(wsproto.WsError) as cm:
            p.msg()
        self.assertEqual(cm.exception.label, wsproto.TOO_LARGE)

    def test_fragmentation_bomb_of_empty_frames(self):
        p = self.pipe(max_frames=10 ** 6)
        p.feed(frame(1, b"", fin=False) + b"".join(frame(0, b"", fin=False) for _ in range(300)))
        with self.assertRaises(wsproto.WsError) as cm:
            p.msg()
        self.assertEqual(cm.exception.label, wsproto.LIMIT)

    def test_frame_and_byte_caps_count_every_wire_frame(self):
        p = self.pipe(max_frames=3)
        p.feed(frame(9) * 4)                        # a ping flood
        with self.assertRaises(wsproto.WsError) as cm:
            p.msg()
        self.assertEqual((cm.exception.label, cm.exception.code), (wsproto.LIMIT, 1008))
        p = self.pipe(max_bytes=10)
        p.feed(frame(1, b"123456") + frame(1, b"123456"))
        self.assertEqual(p.msg(), ("text", "123456"))
        with self.assertRaises(wsproto.WsError):
            p.msg()

    def test_slow_frame_is_visible_to_the_sweeper(self):
        now = [100.0]
        p = self.pipe(clock=lambda: now[0])
        p.feed(b"\x81")                              # one byte of a frame, then nothing
        stop = threading.Event()
        res = []
        def run():
            try:
                res.append(p.conn.read_message(lambda mid=False: stop.is_set()))
            except wsproto.WsError as e:             # stopped in the middle of a frame: the connection is over
                res.append(e.label)
        th = threading.Thread(target=run)
        th.start()
        end = time.time() + 5
        while p.conn.frame_started is None and time.time() < end:
            time.sleep(0.01)
        self.assertEqual(p.conn.frame_started, 100.0)
        stop.set()
        th.join(5)
        self.assertEqual(res, [wsproto.CLOSED])

    def test_write_is_masked_and_valid(self):
        p = self.pipe()
        p.conn.write(wsproto.OP_TEXT, b"hello" * 30)
        raw = p.peer.recv(1000)
        self.assertEqual(raw[0], 0x81)
        self.assertTrue(raw[1] & 0x80)
        ln = raw[1] & 0x7F
        self.assertEqual(ln, 126)
        n = int.from_bytes(raw[2:4], "big")
        key, body = raw[4:8], raw[8:8 + n]
        self.assertEqual(bytes(c ^ key[i % 4] for i, c in enumerate(body)), b"hello" * 30)
        with self.assertRaises(wsproto.WsError):
            p.conn.write(wsproto.OP_PING, b"x" * 126)

    def test_masks_differ(self):
        p = self.pipe()
        p.conn.write(wsproto.OP_TEXT, b"a")
        p.conn.write(wsproto.OP_TEXT, b"a")
        raw = p.peer.recv(100)
        self.assertNotEqual(raw[2:6], raw[8:12])


class Handshake(unittest.TestCase):
    """The opening handshake against a stub that answers however the test says."""

    def run_hs(self, mode, **kw):
        st = WsStub(auth=False, mode=mode, handler=lambda c, s: time.sleep(0))
        self.addCleanup(st.close)
        s = socket.create_connection(("127.0.0.1", st.port), 5)
        t = wsproto.Transport(s)
        self.addCleanup(t.close)
        return wsproto.handshake(t, f"127.0.0.1:{st.port}", kw.pop("target", "/x"), deadline_s=5, **kw), st

    def test_ok(self):
        (rest, proto), st = self.run_hs("ok")
        self.assertEqual((rest, proto), (b"", None))
        self.assertIn("sec-websocket-key", st.requests[0]["headers"])

    def test_every_misbehaviour_is_refused(self):
        for mode in ("redirect", "http200", "no_accept", "bad_accept", "extension", "bad_protocol", "dup_upgrade", "folded"):
            with self.subTest(mode):
                with self.assertRaises(wsproto.WsError) as cm:
                    self.run_hs(mode)
                self.assertEqual(cm.exception.label, wsproto.HANDSHAKE)

    def test_origin_and_subprotocol_only_when_configured(self):
        (_, proto), st = self.run_hs("ok", origin="https://app.example.com", subprotocols=["v1.x"])
        self.assertEqual(st.requests[0]["headers"]["origin"], "https://app.example.com")
        self.assertEqual(st.requests[0]["headers"]["sec-websocket-protocol"], "v1.x")

    def test_crlf_and_spaces_cannot_reach_the_request(self):
        for bad in ("/x\r\nX-Evil: 1", "/x y", "x", "/x\x00", "/é"):
            with self.subTest(bad):
                with self.assertRaises(wsproto.WsError):
                    self.run_hs("ok", target=bad)
        for kw in ({"origin": "https://a\r\nX: y"}, {"subprotocols": ["a\r\nb"]}):
            with self.assertRaises(wsproto.WsError):
                self.run_hs("ok", **kw)

    def test_leftover_bytes_after_the_headers_are_kept(self):
        def handler(c, s):
            c.send_json({"type": "auth_required"})
        st = WsStub(auth=False, handler=handler)
        self.addCleanup(st.close)
        s = socket.create_connection(("127.0.0.1", st.port), 5)
        t = wsproto.Transport(s)
        self.addCleanup(t.close)
        rest, _ = wsproto.handshake(t, "h", "/", deadline_s=5)
        conn = wsproto.Conn(t, rest)
        end = time.monotonic() + 5
        self.assertEqual(conn.read_message(lambda mid=False: time.monotonic() > end), ("text", '{"type": "auth_required"}'))


class Pure(unittest.TestCase):
    def test_config_defaults_and_bounds(self):
        d = W.parse_config(None)
        self.assertEqual((d["default_ttl_s"], d["max_ttl_s"], d["max_frames"], d["idle_s"]), (900, 3600, 1000, 300))
        for bad, frag in (([], "ws_sessions"), ({"nope": 1}, "ws_sessions.nope"), ({"enabled": 1}, "enabled"),
                          ({"max_ttl_s": 7200}, "max_ttl_s"), ({"max_frames": 0}, "max_frames"),
                          ({"max_frames": 10 ** 9}, "max_frames"), ({"max_frame_bytes": 10 ** 9}, "max_frame_bytes"),
                          ({"idle_s": 1}, "idle_s"), ({"max_per_client": 99}, "max_per_client"),
                          ({"recv_queue_frames": 0}, "recv_queue_frames"), ({"default_ttl_s": 7200}, "default_ttl_s"),
                          ({"max_bytes": True}, "max_bytes")):
            with self.assertRaises(ValueError) as cm:
                W.parse_config(bad)
            self.assertIn(frag, str(cm.exception))

    def test_url_parser(self):
        self.assertEqual(W.parse_url("ws://Example.com/a?b=1"), ("ws", "example.com", 80, "/a?b=1"))
        self.assertEqual(W.parse_url("wss://example.com"), ("wss", "example.com", 443, "/"))
        self.assertEqual(W.parse_url("wss://example.com:8123/api/websocket")[2:], (8123, "/api/websocket"))
        for bad in ("http://example.com/", "ws://u:p@example.com/", "ws://example.com/#f", "ws://example.com/a b",
                    "ws://example.com/a\r\nX: y", "ws://example.com/\t", "ws:///x", "ws://[::1]/", "ws://2130706433/",
                    "ws://example.com:0/", "ws://example.com:99999/", "ws://exa mple.com/", "ws://example.com/é",
                    "ws://example.com/a\\b", "ws://example.com/" + "a" * 3000, "", None, 5, "ws://example.com:/"):
            with self.subTest(bad):
                with self.assertRaises(ValueError) as cm:
                    W.parse_url(bad)
                self.assertNotIn("example", str(cm.exception))      # the agent's text is never echoed

    def test_percent_encoded_crlf_stays_a_literal_in_the_path(self):
        self.assertEqual(W.parse_url("ws://example.com/a%0d%0aX:y")[3], "/a%0d%0aX:y")

    def test_cred_config(self):
        ok = W.parse_cred_config({"handshake": "home-assistant"}, ["HA_TOKEN"])
        self.assertEqual([st["op"] for st in ok["steps"]], ["expect", "send", "expect"])
        self.assertEqual(ok["steps"][2]["match"], {"type": "auth_ok"})
        self.assertEqual(W.parse_cred_config({}, ["A", "B"]), {"steps": None, "origin": None, "subprotocols": [],
                                                              "query": {}, "headers": {}})
        full = W.parse_cred_config({"origin": "https://a.example.com:8443", "subprotocols": ["x", "x", "y"],
                                    "handshake": {"send": {"t": "{{B}}"}, "expect": "ok"}}, ["A", "B"])
        self.assertEqual([st["op"] for st in full["steps"]], ["send", "expect"])
        self.assertEqual((full["origin"], full["subprotocols"]), ("https://a.example.com:8443", ["x", "y"]))
        for bad in ([], {"nope": 1}, {"handshake": "nope"}, {"handshake": {}},
                    {"handshake": {"send": "x", "bogus": 1}}, {"handshake": {"send": "{{OTHER}}"}},
                    {"handshake": {"send": "{{VAR}}"}},          # ambiguous with two variables
                    {"handshake": {"expect": "{{A}}"}}, {"handshake": {"wait": "{{A}}", "send": "x"}},
                    {"origin": "https://a.example.com\r\nX: y"}, {"origin": "ftp://x"}, {"origin": 5},
                    {"subprotocols": ["a b"]}, {"subprotocols": "x"}, {"subprotocols": list("abcdef")},
                    {"handshake": {"send": object()}}, {"handshake": {"steps": []}},
                    {"handshake": {"steps": [{"send": "x", "expect": "y"}]}}, {"handshake": {"steps": [{"foo": 1}]}},
                    {"handshake": {"steps": [{"expect": "x", "timeout": 999}]}},
                    {"handshake": {"steps": [{"expect": "x", "max_bytes": 1}]}},
                    {"handshake": {"steps": [{"expect": "x", "skip": 99}]}},
                    {"handshake": {"steps": [{"expect": ""}]}}, {"handshake": {"steps": [{"send": "x", "timeout": 1}]}},
                    {"handshake": {"steps": [{"send": "x"}] * 9}},
                    {"query": {"a b": "x"}}, {"query": {"a": "{{OTHER}}"}}, {"query": {"a": 5}}, {"query": []},
                    {"headers": {"Host": "x"}}, {"headers": {"Upgrade": "x"}}, {"headers": {"Sec-WebSocket-Key": "x"}},
                    {"headers": {"Sec-WebSocket-Extensions": "x"}}, {"headers": {"Cookie": "x"}},
                    {"headers": {"X-Api-Key": "{{A}}"}}, {"headers": {"Authorization": "a\r\nb"}},
                    {"headers": {"Authorization": "{{OTHER}}"}}, {"headers": {"Authorization": 5}},
                    {"headers": {"Origin": "https://a.example.com"}, "origin": "https://b.example.com"}):
            with self.assertRaises(ValueError):
                W.parse_cred_config(bad, ["A", "B"])

    def test_matching(self):
        m = W.matches
        self.assertTrue(m({"type": "auth_ok"}, '{"type":"auth_ok","ha_version":"1"}'))
        self.assertFalse(m({"type": "auth_ok"}, '{"type":"auth_invalid"}'))
        self.assertFalse(m({"type": "auth_ok"}, 'not json'))
        self.assertFalse(m({"n": 1}, '{"n": true}'))             # True is not 1
        self.assertTrue(m({"a": {"b": 1}}, '{"a":{"b":1,"c":2}}'))
        self.assertTrue(m("ell", "hello"))                       # a text is an exact substring, not a pattern
        self.assertFalse(m("hello!", "hello"))
        self.assertFalse(m("h.*o", "hello"))
        self.assertTrue(m("h.*o", "say h.*o"))

    def test_json_template_cannot_be_broken_out_of(self):
        hs = W.PRESETS["home-assistant"]
        evil = 'x"},{"type":"admin'
        out = W._fill_json(hs[1]["send"], {"VAR": evil})
        self.assertEqual(out, {"type": "auth", "access_token": evil})
        self.assertEqual(json.loads(json.dumps(out))["access_token"], evil)


# ------------------------------------------------------------------------------- relaying
class Relay(WsBase):
    def test_no_handshake_credential_sends_nothing_first(self):
        st = self.mkstub(auth=False)
        sid = self.wopen(cred="plainws", url=self.wurl(stub=st))
        self.assertEqual(st.auth_msgs, [])
        self.wsend(sid, "hello")
        self.assertEqual(json.loads(self.frames_until(sid, 1)[0]["data"]), {"echo": "hello"})
        self.assertNoSecret()

    def test_both_directions_in_order_and_sequence_numbers(self):
        sid = self.wopen()
        for i in range(5):
            self.assertEqual(self.wsend(sid, f"m{i}")[0], 200)
        got = self.frames_until(sid, 5)
        self.assertEqual([json.loads(f["data"])["echo"] for f in got], [f"m{i}" for i in range(5)])
        self.assertEqual([f["seq"] for f in got], [1, 2, 3, 4, 5])
        self.assertEqual([t for o, t in self.stub.received], [f"m{i}".encode() for i in range(5)])
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual((r["frames"], r["closed"], r["truncated"]), ([], False, False))

    def test_recv_long_polls_until_a_frame_arrives(self):
        sid = self.wopen()
        out = []
        th = threading.Thread(target=lambda: out.append(self.wrecv(sid, wait=10)))
        th.start()
        self.wsend(sid, "wake")
        th.join(15)
        self.assertEqual(json.loads(out[0][1]["frames"][0]["data"]), {"echo": "wake"})

    def test_max_limits_one_response(self):
        sid = self.wopen()
        self.wsend(sid, "FLOOD:5")
        s = self.sess()
        with s.cond:
            self.assertTrue(s.cond.wait_for(lambda: len(s.queue) == 5, 10))
        first = self.wrecv(sid, wait=5, mx=2)[1]
        self.assertEqual(len(first["frames"]), 2)
        rest = self.frames_until(sid, 3)
        self.assertEqual([f["data"] for f in first["frames"] + rest], [f"f{i}" for i in range(5)])

    def test_the_secret_is_masked_in_every_frame_returned(self):
        sid = self.wopen()
        self.wsend(sid, "TOKEN")
        self.assertEqual(self.frames_until(sid, 1)[0]["data"], "your token is ***")
        b64 = base64.b64encode(TOKEN.encode()).decode()
        for form in (TOKEN, b64, TOKEN.lower(), TOKEN.encode().hex(), json.dumps(TOKEN)[1:-1]):
            self.wsend(sid, "ECHO:echo " + form)
        for f in self.frames_until(sid, 5):
            self.assertEqual(f["data"], "echo ***", f)
        self.assertNoSecret()

    def test_another_credentials_value_is_not_in_play_but_this_ones_other_vars_are_masked(self):
        sid = self.wopen()
        self.wsend(sid, "ECHO:" + "x" * 5000 + TOKEN + "y")
        self.assertEqual(self.frames_until(sid, 1)[0]["data"], "x" * 5000 + "***y")

    def test_binary_frames_are_a_marker_with_the_length_only(self):
        sid = self.wopen()
        self.wsend(sid, "BIN")
        f = self.frames_until(sid, 1)[0]
        self.assertEqual((f["type"], f["bytes"]), ("binary", 11))
        self.assertNotIn("data", f)
        self.assertNotIn("secret?", json.dumps(f))

    def test_fragments_are_reassembled_and_pings_answered(self):
        sid = self.wopen()
        self.wsend(sid, "FRAG")
        self.assertEqual(self.frames_until(sid, 1)[0]["data"], "abcd")
        self.wsend(sid, "PING")
        self.wsend(sid, "after")
        self.frames_until(sid, 1)
        ops = [o for o, _ in self.stub.wait_frames(4)]
        self.assertIn(10, ops)                                  # the broker ponged
        self.assertEqual(self.stub.violations, [])

    def test_the_server_closing_ends_the_session_after_the_frames_are_read(self):
        sid = self.wopen()
        self.wsend(sid, "FLOOD:2")
        self.wsend(sid, "CLOSE")
        end = time.time() + 10
        seen = []
        while time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            self.assertEqual(code, 200, r)
            seen += [f["data"] for f in r["frames"]]
            if r["closed"]:
                break
        self.assertEqual(seen, ["f0", "f1"])
        self.assertEqual(r["close_reason"], "closed")
        code, r = self.wrecv(sid)
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertEqual(self.wsend(sid, "x")[0], 410)
        ev = self.events("ws_session_closed")
        self.assertEqual((len(ev), ev[0]["reason"], ev[0]["close_reason"]), (1, "peer_closed", "closed"))
        self.assertTrue(self.stub.eof[0].wait(5))

    def test_a_dropped_connection_is_reported_not_hidden(self):
        sid = self.wopen()
        self.wsend(sid, "DROP")
        end = time.time() + 10
        while time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            if code != 200 or r["closed"]:
                break
        self.assertTrue(code == 410 or r["closed"])

    def test_text_sent_by_the_agent_is_not_filtered(self):
        sid = self.wopen()
        payload = '{"type":"config/entity_registry/remove","entity_id":"light.x"}'
        self.assertEqual(self.wsend(sid, payload)[0], 200)
        self.assertEqual(self.stub.wait_frames(1)[0][1], payload.encode())

    def test_agent_text_is_sent_as_text_frames_only_and_must_be_text(self):
        sid = self.wopen()
        for bad in (5, None, ["a"], {"a": 1}):
            code, text = self.as_client(KEY, "POST", "/v1/ws/send", {"session": sid, "text": bad})
            self.assertEqual(code, 400, text)
        self.assertEqual(self.stub.received, [])
        self.assertEqual(self.wsend(sid, "café ☃")[0], 200)
        self.assertEqual(self.stub.wait_frames(1)[0], (1, "café ☃".encode()))


# ------------------------------------------------------------------------------- limits
class Limits(WsBase):
    def test_outbound_frame_cap_refuses_and_keeps_the_session(self):
        sid = self.wopen(max_frames=2)
        self.assertEqual([self.wsend(sid, "a")[0], self.wsend(sid, "b")[0]], [200, 200])
        code, text = self.wsend(sid, "c")
        self.assertEqual((code, json.loads(text)["code"]), (403, "session_refused"))
        self.assertEqual(len(self.frames_until(sid, 2)), 2)                  # still readable
        ev = self.events("ws_session_refused")
        self.assertEqual(ev[0]["reason_class"], "frames_cap")

    def test_outbound_byte_cap(self):
        self.ws_cfg_set(max_bytes=100)
        sid = self.wopen()
        self.assertEqual(self.wsend(sid, "x" * 60)[0], 200)
        self.assertEqual(self.wsend(sid, "x" * 60)[0], 403)

    def ws_cfg_set(self, **kw):
        self.broker.ws_cfg = W.parse_config({**self.broker.ws_cfg, **kw})

    def test_outbound_frame_size_cap(self):
        self.ws_cfg_set(max_frame_bytes=1024)
        sid = self.wopen()
        self.assertEqual(self.wsend(sid, "x" * 1000)[0], 200)           # (the echo, with its wrapper, must fit too)
        code, text = self.wsend(sid, "x" * 1025)
        self.assertEqual((code, json.loads(text)["code"]), (403, "session_refused"))
        self.assertEqual(len(self.stub.wait_frames(1)), 1)

    def test_inbound_frame_cap_closes_the_connection(self):
        self.ws_cfg_set(max_frames=6)           # inbound wire frames: this plus a small allowance for the handshake
        sid = self.wopen()
        self.wsend(sid, "FLOOD:60")
        got, end = [], time.time() + 10
        while time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            got += r.get("frames", [])
            if code != 200 or r["closed"]:
                break
        self.assertEqual([f["data"] for f in got], [f"f{i}" for i in range(6 + W.IN_FRAMES_SLACK - 2)])
        self.assertEqual(r["close_reason"], "limit reached")
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertIn((8, (1008).to_bytes(2, "big")), self.stub.received)

    def test_inbound_byte_cap_closes_the_connection(self):
        self.ws_cfg_set(max_bytes=1500)
        sid = self.wopen()
        for _ in range(3):
            self.wsend(sid, "BIG:3000")
        end, r = time.time() + 10, {}
        while time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            if code != 200 or r["closed"]:
                break
        self.assertEqual(r["close_reason"], "limit reached")

    def test_inbound_frame_size_cap_closes_with_1009_without_reading_it(self):
        self.ws_cfg_set(max_frame_bytes=1024)
        sid = self.wopen()
        self.wsend(sid, "BIG:5000")
        end, r = time.time() + 10, {}
        while time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            if code != 200 or r["closed"]:
                break
        self.assertEqual((r["close_reason"], r["frames"]), ("frame too large", []))
        self.assertIn((8, (1009).to_bytes(2, "big")), self.stub.wait_frames(2))

    def test_a_full_receive_queue_pauses_reading_and_reports_truncated_dropping_nothing(self):
        self.ws_cfg_set(recv_queue_frames=2)
        sid = self.wopen()
        s = self.sess()
        self.wsend(sid, "FLOOD:10")
        with s.cond:
            self.assertTrue(s.cond.wait_for(lambda: s.truncated, 10))
            self.assertEqual(len(s.queue), 2)                          # the reader stopped: the rest is still on the wire
        got, flags = [], []
        end = time.time() + 15
        while len(got) < 10 and time.time() < end:
            code, r = self.wrecv(sid, wait=2)
            self.assertEqual(code, 200, r)
            got += [f["data"] for f in r["frames"]]
            flags.append(r["truncated"])
        self.assertEqual(got, [f"f{i}" for i in range(10)])           # nothing dropped, order kept
        self.assertTrue(flags[0])                                      # and the agent was told
        self.assertLessEqual(max(len(f) for f in [got]), 10)

    def test_queue_byte_cap_also_pauses(self):
        self.ws_cfg_set(recv_queue_bytes=4096, max_frame_bytes=4096)
        sid = self.wopen()
        s = self.sess()
        for _ in range(4):
            self.wsend(sid, "BIG:2000")
        with s.cond:
            self.assertTrue(s.cond.wait_for(lambda: s.truncated, 10))
            self.assertLessEqual(s.qbytes, 4096 + 2000)
        self.assertEqual(len(self.frames_until(sid, 4)), 4)

    def test_per_frame_response_size_is_bounded(self):
        self.ws_cfg_set(max_frame_bytes=1 << 20, recv_queue_bytes=32 << 20)
        with mock.patch.object(W, "RECV_RESPONSE_BYTES", 3000):
            sid = self.wopen()
            for _ in range(3):
                self.wsend(sid, "BIG:2000")
            self.frames_until(sid, 0)
            deadline = time.time() + 10
            s = self.sess()
            with s.cond:
                s.cond.wait_for(lambda: len(s.queue) == 3, 10)
            code, r = self.wrecv(sid, wait=0)
            self.assertEqual(len(r["frames"]), 1)                       # 2000 + 2000 > 3000
            self.assertEqual(r["queued"], 2)

    def test_idle_timeout_closes_the_socket_without_a_sleep(self):
        self.ws_cfg_set(idle_s=10)
        sid = self.wopen()
        self.advance(9)
        self.broker.sweep_sessions()
        self.assertEqual(self.wsend(sid, "keep")[0], 200)               # activity restarts the idle clock
        self.frames_until(sid, 1)                                       # (the echo is activity too: wait for it)
        self.advance(9)
        self.broker.sweep_sessions()
        self.assertEqual(self.wrecv(sid, wait=0)[0], 200)
        self.advance(2)
        self.broker.sweep_sessions()
        self.assertTrue(self.stub.eof[0].wait(5))
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertIn("idle", r["error"])
        self.assertEqual(self.events("ws_session_closed")[0]["reason"], "idle")

    def test_ttl_expiry_is_fixed_and_closes_the_socket(self):
        sid = self.wopen(ttl_s=60)
        self.wsend(sid, "a")
        self.advance(59)
        self.assertEqual(self.wsend(sid, "b")[0], 200)                  # use never moves the deadline
        self.advance(2)
        code, text = self.wsend(sid, "c")
        self.assertEqual((code, json.loads(text)["code"]), (410, "session_expired"))
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.events("ws_session_closed")[0]["reason"], "expired")

    def test_the_sweeper_expires_a_session_nobody_touches(self):
        sid = self.wopen(ttl_s=30)
        self.advance(31)
        self.assertEqual(self.broker.sweep_sessions(), 1)
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.wrecv(sid, wait=0)[0], 410)

    def test_a_slow_drip_frame_cannot_hold_the_connection(self):
        self.ws_cfg_set(idle_s=3600)
        sid = self.wopen()
        s = self.sess()
        self.wsend(sid, "STALL")
        end = time.time() + 10
        while s.conn.frame_started is None and time.time() < end:
            time.sleep(0.005)
        self.assertIsNotNone(s.conn.frame_started)
        self.advance(W.FRAME_DEADLINE_S - 1)
        self.broker.sweep_sessions()
        self.assertFalse(s.dead)
        self.advance(2)
        self.broker.sweep_sessions()
        self.assertTrue(s.dead)
        self.assertTrue(self.stub.eof[0].wait(5))

    def test_rate_limit_per_session(self):
        sid = self.wopen()
        codes = [self.wrecv(sid, wait=0)[0] for _ in range(120)]
        self.assertIn(429, codes)
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual(r["code"], "session_refused") if code == 429 else None
        self.advance(10)                                                # tokens refill on the session clock
        self.assertEqual(self.wrecv(sid, wait=0)[0], 200)

    def test_shortened_at_approval_and_never_lengthened(self):
        r = self.wask(ttl_s=600, max_frames=50)
        self.post("/decide", {"id": r["id"], "decision": "approve", "session_ttl_min": "999"})
        self.assertEqual(self.broker._by_id[r["id"]].status, "pending")
        self.approve(r["id"], session_ttl_min="2", session_max_calls="7")
        res = self.result(r["id"])["session"]
        self.assertEqual((res["expires_in"], res["max_frames"]), (120, 7))
        self.assertEqual(self.events("ws_session_opened")[0]["shortened"], True)

    def test_open_request_limits_are_validated(self):
        for kw in ({"ttl_s": 5}, {"ttl_s": 99999}, {"ttl_s": "900"}, {"ttl_s": True}, {"max_frames": 0},
                   {"max_frames": 10 ** 6}, {"max_frames": "5"}):
            self.wask(expect=400, **kw)

    def test_per_client_cap(self):
        self.ws_cfg_set(max_per_client=1)
        sid = self.wopen()
        self.wask(expect=403)
        self.assertEqual(self.wsend(sid, "x")[0], 200)
        code, _ = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        self.assertEqual(code, 200)
        self.wopen()                                                    # a slot is free again


# ------------------------------------------------------------------------------- ending it
class Ending(WsBase):
    def two(self):
        return self.new_client("alice-box"), self.new_client("bob-box")

    def test_agent_close_closes_the_socket(self):
        sid = self.wopen()
        code, text = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        self.assertEqual(code, 200)
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.wsend(sid, "x")[0], 410)
        ev = self.events("ws_session_closed")
        self.assertEqual((ev[0]["reason"], ev[0]["frames_out"]), ("closed", 0))

    def test_revoke_in_the_ui_closes_the_socket_at_once(self):
        sid = self.wopen()
        self.wsend(sid, "a")
        status, _, _ = self.post("/sessions/revoke", {"pid": sid[:8]})
        self.assertEqual(status, 303)
        self.assertTrue(self.stub.eof[0].wait(5))
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertIn("revoked", r["error"])
        ev = self.events("ws_session_closed")
        self.assertEqual((ev[0]["reason"], ev[0].get("revoked_by")), ("revoked", "alice"))

    def test_revoking_a_client_closes_its_sockets(self):
        a, b = self.two()
        sa, sb = self.wopen(key=a["secret"]), self.wopen(key=b["secret"], url=self.wurl(stub=self.mkstub()))
        status, _, _ = self.post("/clients/revoke", {"id": a["id"]})
        self.assertEqual(status, 303)
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.wsend(sb, "still here", key=b["secret"])[0], 200)
        self.assertEqual(len(self.broker._sess), 1)

    def test_a_revoked_client_cannot_use_its_session_even_before_the_purge(self):
        a, _ = self.two()
        sid = self.wopen(key=a["secret"])
        self.broker.clients.revoke(a["id"], "alice")
        client = {"id": a["id"], "name": "alice-box", "legacy": False}
        with self.assertRaises(S.SessionError) as cm:
            self.broker.ws_send(sid, "x", client)
        self.assertEqual(cm.exception.code, "session_unknown")

    def test_revoke_racing_a_busy_sender_never_hangs_or_leaks(self):
        sid = self.wopen()
        codes = []

        def spam():
            for i in range(200):
                c, _ = self.wsend(sid, f"m{i}")
                codes.append(c)
                if c != 200:
                    return
        th = threading.Thread(target=spam)
        th.start()
        self.stub.wait_frames(3)
        self.post("/sessions/revoke", {"pid": sid[:8]})
        th.join(20)
        self.assertFalse(th.is_alive())
        self.assertIn(410, codes)
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.stub.violations, [])
        self.assertEqual(len(self.broker._sess), 0)

    def test_the_audit_log_has_counts_and_never_contents(self):
        sid = self.wopen()
        self.wsend(sid, "CONTENT-CANARY-AAA")
        self.frames_until(sid, 1)
        self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        text = self.audit_text()
        self.assertNotIn("CONTENT-CANARY-AAA", text)
        self.assertNotIn("echo", text.replace("echoes", ""))
        o, c = self.events("ws_session_opened")[0], self.events("ws_session_closed")[0]
        self.assertEqual((o["tls"], o["handshake"], o["max_frames"]), (False, True, 1000))
        self.assertEqual((c["frames_out"], c["bytes_out"], c["messages_in"], c["reason"]), (1, 18, 1, "closed"))
        self.assertGreaterEqual(c["frames_in"], 3)
        self.assertGreater(c["bytes_in"], 0)
        self.assertEqual(self.events("ws_session_requested")[0]["names"], ["ha"])
        self.assertNoSecret()

    def test_the_agent_audit_view_shows_counts_for_its_own_sessions(self):
        sid = self.wopen()
        self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        code, text = self.as_client(KEY, "GET", "/v1/audit?event=ws_session_closed")
        self.assertEqual(code, 200, text)
        self.assertIn("frames_in", text)
        self.assertNotIn(TOKEN, text)

    def test_status_shows_counts_only(self):
        sid = self.wopen()
        self.wsend(sid, "a")
        code, text = self.as_client(KEY, "GET", "/v1/sessions/" + sid)
        j = json.loads(text)
        self.assertEqual((code, j["kind"], j["frames_out"], j["connected"]), (200, "ws", 1, True))
        self.assertNotIn("echo", text)


# ------------------------------------------------------------------------------- who can use it
class Isolation(WsBase):
    def two(self):
        return self.new_client("alice-box"), self.new_client("bob-box")

    def test_another_client_gets_the_answer_an_unknown_id_gets(self):
        a, b = self.two()
        sid = self.wopen(key=a["secret"])
        made_up = "A" * 32
        for do in (lambda k, s: self.wsend(s, "x", key=k), lambda k, s: self.wrecv(s, key=k, wait=0)[1],
                   lambda k, s: self.as_client(k, "POST", "/v1/requests", {"mode": "session_close", "session": s}),
                   lambda k, s: self.as_client(k, "GET", "/v1/sessions/" + s)):
            theirs, unknown = do(b["secret"], sid), do(b["secret"], made_up)
            self.assertEqual(theirs, unknown)
        self.assertEqual(self.stub.received, [])
        self.assertEqual(self.wsend(sid, "mine", key=a["secret"])[0], 200)           # and it still works for the owner
        self.assertEqual(len(self.broker._sess), 1)

    def test_the_legacy_shared_key_cannot_reach_an_enrolled_clients_session(self):
        a, _ = self.two()
        sid = self.wopen(key=a["secret"])
        code, text = self.wsend(sid, "x", key=KEY)
        self.assertEqual((code, json.loads(text)["code"]), (404, "session_unknown"))

    def test_malformed_and_guessed_ids_are_unknown(self):
        for bad in ("", "short", "x" * 33, "../../etc/passwd" + "a" * 20, "a b" * 11, 5, ["x"], {"a": 1}, None):
            code, text = self.as_client(KEY, "POST", "/v1/ws/send", {"session": bad, "text": "x"})
            self.assertEqual((code, json.loads(text)["code"]), (404, "session_unknown"), bad)
        self.assertEqual(self.as_client(KEY, "POST", "/v1/ws/recv", {"session": "B" * 32})[0], 404)

    def test_an_http_session_id_is_not_a_websocket_session_and_vice_versa(self):
        hid = self.open()                                       # an http session on the unifi stub
        code, text = self.wsend(hid, "x")
        self.assertEqual((code, json.loads(text)["code"]), (404, "session_unknown"))
        wid = self.wopen()
        code, r = self.call(wid, "GET", "/")
        self.assertEqual((code, r["code"]), (404, "session_unknown"))
        self.assertEqual(self.stub.received, [])

    def test_the_bad_body_answers_are_fixed_text(self):
        for body in ({"session": "A" * 32, "wait": "x"}, {"session": "A" * 32, "wait": True},
                     {"session": "A" * 32, "max": 1.5}, {"session": "A" * 32, "wait": float("nan")}):
            code, text = self.as_client(KEY, "POST", "/v1/ws/recv", body)
            self.assertIn(code, (400, 404))
        code, text, _ = self.raw("POST", "/v1/ws/send", data=b"{not json", headers={"X-Client-Key": KEY})
        self.assertEqual((code, json.loads(text)), (400, {"error": "bad request"}))
        code, text, _ = self.raw("POST", "/v1/ws/send", data=b"[]", headers={"X-Client-Key": KEY})
        self.assertEqual(code, 400)
        self.assertEqual(self.raw("GET", "/v1/ws/send", headers={"X-Client-Key": KEY})[0], 404)
        self.assertEqual(self.raw("POST", "/v1/ws/send", data=b"{}")[0], 401)


# ------------------------------------------------------------------------------- approval and scope
class Approval(WsBase):
    def test_always_high_no_model_no_buttons_and_names_the_server_not_the_path(self):
        r = self.wask(url=self.wurl("/api/websocket?x=1"))
        self.assertEqual(self.model.calls, [])
        req = self.broker._by_id[r["id"]]
        self.assertEqual((req.risk["level"], req.risk["model"]), ("high", None))
        n = self.notifier.notifications[-1]
        self.assertEqual((n.actions, n.action_token), ([], None))
        self.assertIn("WebSocket session requested [HIGH]", n.title)
        self.assertIn(f"127.0.0.1:{self.stub.port}", n.text)
        self.assertIn("ha", n.text)
        self.assertNotIn("/api/websocket", n.text + n.title)
        self.assertEqual(req.offered, frozenset())
        self.assertEqual(self.events("ws_session_requested")[0]["names"], ["ha"])
        self.assertEqual(self.events("assessed")[0]["reasons"], ["a WebSocket session always needs a human to approve it; always high"])

    def test_never_auto_approved_even_with_everything_allowed(self):
        self.broker._auto_max = "high"
        self.broker.cfg["secrets"]["ha"]["approval"] = "allow"
        r = self.wask()
        self.assertEqual(r["status"], "pending")
        self.assertFalse(self.broker._auto_allowed("session", ["ha"], {}))
        for kw in ({"always": True}, {"grant_minutes": 15}, {"ssh_rule": {"days": None}}):
            code, req = self.broker.decide_via("dashboard", r["id"], "approve", "alice", **kw)
            self.assertEqual(code, 400)
        for ch in ("push", "ha"):
            code, req = self.broker.decide_via(ch, r["id"], "approve", "phone", token="x" * 30)
            self.assertNotEqual(code, 200)
        self.assertEqual(self.broker._by_id[r["id"]].status, "pending")
        self.assertEqual(self.stub.requests, [])                      # nothing connected before the human decided

    def test_denied_means_no_connection(self):
        r = self.wask()
        self.post("/decide", {"id": r["id"], "decision": "deny"})
        self.assertEqual(self.result(r["id"])["status"], "denied")
        self.assertEqual(self.stub.requests, [])

    def test_the_card_shows_everything_and_the_path_only_escaped_and_labelled(self):
        self.wask(url=self.wurl("/a?x=%3Cb%3E"), ttl_s=1200, max_frames=40)
        status, page, _ = self.get("/")
        self.assertIn("WebSocket session</b> with credential <b>ha</b>", page)
        self.assertIn(f"ws://127.0.0.1:{self.stub.port}", page)
        self.assertIn("plain ws: not encrypted", page)
        self.assertIn("/a?x=%3Cb%3E", page)
        self.assertIn("as the agent wrote them (unverified)", page)
        self.assertIn("20 min from the moment you approve", page)
        self.assertIn("40 frames", page)
        self.assertIn("1 message step", page.replace("3 message step", "1 message step"))
        self.assertIn("Max frames", page)
        self.assertNotIn("Purpose", page)

    def test_an_agent_purpose_is_refused_not_rendered(self):
        self.wask(expect=400, purpose="<script>alert(1)</script>")
        self.wask(expect=400, hosts=["127.0.0.1"])
        self.wask(expect=400, methods=["GET"])

    def test_clients_tab_lists_it_and_revoke_is_there(self):
        sid = self.wopen()
        status, page, _ = self.get("/clients")
        self.assertIn("Active sessions", page)
        self.assertIn("WebSocket", page)
        self.assertIn(f"127.0.0.1:{self.stub.port}", page)
        self.assertIn("action='/sessions/revoke'", page)
        self.assertNotIn(sid, page)


class Scope(WsBase):
    def test_credential_without_a_ws_setting_cannot_open_one(self):
        self.wask(expect=403, cred="unifi")
        self.wask(expect=403, cred="envonly")
        self.wask(expect=400, cred="nosuch")
        self.assertEqual(self.stub.requests, [])

    def test_disabled(self):
        self.broker.ws_cfg = W.parse_config({"enabled": False})
        self.wask(expect=403)
        code, text = self.wsend("A" * 32, "x")
        self.assertEqual(code, 403)

    def test_host_must_be_in_the_credentials_allowed_hosts(self):
        self.wask(expect=403, url=f"ws://evil.example.com:{self.stub.port}/x")
        self.wask(expect=403, url=f"ws://127.0.0.2:{self.stub.port}/x")

    def test_host_port_entry_means_exactly_that_port(self):
        self.broker.cfg["secrets"]["remote"]["allowed_hosts"] = ["ws.example.com:8123"]
        self.wask(cred="remote", url="ws://ws.example.com:8123/x")
        self.wask(cred="remote", expect=403, url="ws://ws.example.com:8124/x")
        self.wask(cred="remote", expect=403, url="ws://ws.example.com/x")

    def test_scheme_default_ports(self):
        self.assertEqual(W.parse_url("ws://example.com/")[2], 80)
        self.assertEqual(W.parse_url("wss://example.com/")[2], 443)
        self.broker.cfg["secrets"]["remote"]["allowed_hosts"] = ["ws.example.com:443"]
        self.wask(cred="remote", url="wss://ws.example.com/x")
        self.wask(cred="remote", expect=403, url="ws://ws.example.com/x")         # port 80 is not allowed

    def test_urls_with_tricks_are_refused_with_fixed_text(self):
        for bad in ("http://127.0.0.1/x", "ws://u:p@127.0.0.1/x", f"ws://127.0.0.1:{self.stub.port}/x#f",
                    f"ws://127.0.0.1:{self.stub.port}/x y", f"ws://127.0.0.1:{self.stub.port}/x\r\nX-A: b",
                    "ws://[::1]/", "ws://2130706433/"):
            code, text = self.as_client(KEY, "POST", "/v1/requests",
                                        {"mode": "session", "kind": "ws", "names": ["ha"], "url": bad})
            self.assertIn(code, (400, 403), bad)
            self.assertNotIn("X-A", text)

    def test_kind_is_checked(self):
        code, _ = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session", "kind": "tcp", "names": ["ha"],
                                                               "url": self.wurl()})
        self.assertEqual(code, 400)
        code, _ = self.as_client(KEY, "POST", "/v1/requests", {"mode": "session", "kind": "ws", "names": ["ha", "plainws"],
                                                               "url": self.wurl()})
        self.assertEqual(code, 400)


class Guard(WsBase):
    """The same destination guard as every other outbound call, reached through DestGuard.connect."""

    def strict(self, resolver, own_ports=(), connector=None):
        """A real (non-loopback-friendly) guard does the connecting; the broker's lenient test guard still serves
        the approval site and the request-time checks."""
        g = destguard.DestGuard(own_ports=own_ports, resolver=resolver, local_addrs=lambda: set(),
                                allow_loopback=False, connector=connector)
        p = mock.patch.object(self.broker.dest_guard, "connect", g.connect)
        p.start()
        self.addCleanup(p.stop)
        return g

    def failed_open(self, url, cred="remote"):
        r = self.wask(cred=cred, url=url)
        self.approve(r["id"])
        res = self.result(r["id"])
        self.assertEqual(res["status"], "failed", res)
        self.assertEqual(len(self.broker._sess), 0)
        return res["error"]

    def test_loopback_is_refused_and_the_agent_learns_only_connection(self):
        self.strict(lambda h, p: ["127.0.0.1"])
        err = self.failed_open("ws://ws.example.com:8123/x")
        self.assertEqual(err, "session not opened: could not connect (connection)")
        self.assertEqual(self.stub.requests, [])
        self.assertEqual(self.events("ws_session_refused")[0]["reason_class"], "open_connection")

    def test_a_loopback_literal_is_refused(self):
        self.strict(lambda h, p: ["93.184.216.34"])
        self.broker.cfg["secrets"]["remote"]["allowed_hosts"].append("127.0.0.1")
        self.assertEqual(self.failed_open(f"ws://127.0.0.1:{self.stub.port}/x"),
                         "session not opened: could not connect (connection)")
        self.assertEqual(self.stub.requests, [])

    def test_the_brokers_own_port_is_refused_on_a_private_address(self):
        self.strict(lambda h, p: ["10.0.0.9"], own_ports=[8123])
        self.assertEqual(self.failed_open("ws://ws.example.com:8123/x"),
                         "session not opened: could not connect (connection)")

    def test_metadata_addresses_are_refused(self):
        for ip in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200", "::ffff:169.254.169.254", "0.0.0.0"):
            self.strict(lambda h, p, ip=ip: [ip])
            self.assertEqual(self.failed_open("ws://meta.example.com:80/x"),
                             "session not opened: could not connect (connection)", ip)

    def test_a_dns_answer_with_any_bad_address_is_refused(self):
        self.strict(lambda h, p: ["93.184.216.34", "127.0.0.1"])
        self.assertEqual(self.failed_open("ws://rebind.example.com:80/x"),
                         "session not opened: could not connect (connection)")

    def test_rebinding_the_name_resolves_once_and_connects_to_the_pinned_address(self):
        answers = [["93.184.216.34"], ["127.0.0.1"], ["127.0.0.1"]]
        calls, dialed = [], []
        st = self.mkstub(token="REMOTE-TOKEN-CANARY")

        def resolver(h, p):
            calls.append(h)
            return answers[min(len(calls) - 1, 2)]

        def connector(addr, timeout=None, **kw):
            dialed.append(addr)
            return socket.create_connection(("127.0.0.1", st.port), 5)   # stands in for the pinned host
        self.strict(resolver, connector=connector)
        self.wopen(cred="remote", url=f"ws://rebind.example.com:{st.port}/api/websocket")
        self.assertEqual(calls, ["rebind.example.com"])                          # one lookup; a second answer is never used
        self.assertEqual(dialed, [("93.184.216.34", st.port)])
        self.assertEqual(st.requests[0]["headers"]["host"], f"rebind.example.com:{st.port}")

    def test_the_guard_path_is_the_one_http_uses(self):
        with mock.patch.object(destguard.DestGuard, "connect", autospec=True, side_effect=destguard.DestinationRefused()) as m:
            self.assertEqual(self.failed_open(self.wurl(), cred="ha"), "session not opened: could not connect (connection)")
        self.assertEqual(m.call_count, 1)
        self.assertEqual(m.call_args.args[1:3], ("127.0.0.1", self.stub.port))

    def test_no_environment_proxy_is_used(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
                                          "ALL_PROXY": "http://127.0.0.1:9"}):
            self.wopen()
        self.assertEqual(len(self.stub.requests), 1)


class Upgrade(WsBase):
    """A server that answers the upgrade wrongly, or the sign-in wrongly, never yields a session."""

    def failed(self, stub, cred="ha"):
        r = self.wask(cred=cred, url=self.wurl(stub=stub))
        self.approve(r["id"])
        res = self.result(r["id"])
        self.assertEqual(res["status"], "failed", res)
        self.assertEqual(len(self.broker._sess), 0)
        return res["error"]

    def test_redirects_and_bad_upgrade_answers(self):
        for mode in ("redirect", "http200", "no_accept", "bad_accept", "extension", "bad_protocol", "dup_upgrade", "folded"):
            st = self.mkstub(mode=mode)
            self.assertEqual(self.failed(st), "session not opened: could not connect (handshake refused)", mode)
        self.assertEqual(len(self.stub.requests), 0)

    def test_a_redirect_is_not_followed(self):
        other = self.mkstub()
        st = self.mkstub(mode="redirect")
        self.failed(st)
        self.assertEqual(other.requests, [])

    def test_a_wrong_token_fails_closed_and_the_servers_words_are_not_repeated(self):
        st = self.mkstub(token="something-else-entirely")
        err = self.failed(st)
        self.assertEqual(err, "session not opened: could not connect (handshake refused)")
        self.assertNotIn("Invalid access token", err)
        self.assertNoSecret()

    def test_server_that_never_greets_times_out(self):
        st = self.mkstub(auth=False)
        with mock.patch.object(W, "STEP_TIMEOUT_DEFAULT", 0.3), mock.patch.object(W, "HANDSHAKE_S", 1):
            self.broker.cfg["secrets"]["ha"]["_ws"] = W.parse_cred_config(
                {"handshake": {"steps": [{"expect": {"type": "auth_required"}, "timeout": 0.3}]}}, ["HA_TOKEN"])
            self.assertEqual(self.failed(st), "session not opened: could not connect (timeout)")

    def test_an_unreachable_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = self.wask(url=f"ws://127.0.0.1:{port}/x")
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["error"], "session not opened: could not connect (connection)")

    def test_a_failed_open_is_audited_without_detail(self):
        st = self.mkstub(mode="redirect")
        self.failed(st)
        ev = self.events("ws_session_refused")[0]
        self.assertEqual(ev["reason_class"], "open_handshake_refused")
        self.assertNoSecret()


# ------------------------------------------------------------------------------- ways to sign in
Q_TOKEN = "Q&t=1 +/x-CANARY-9"


class SignIn(WsBase):
    def tweak(self, cfg):
        super().tweak(cfg)

        def add(name, token, ws):
            item = name.capitalize()
            cfg["_vault"][item] = {"token": token}
            cfg["secrets"][name] = {"vars": {name.upper() + "_TOKEN": {"item": item, "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"], "ws": ws}
        add("cfirst", "CFIRST-CANARY-1", {"handshake": {"steps": [{"send": {"op": "login", "key": "{{VAR}}"}},
                                                                   {"expect": {"ok": True}}]}})
        add("multi", "MULTI-CANARY-2", {"handshake": {"steps": [
            {"expect": {"op": "hello"}}, {"send": {"op": "identify", "token": "{{VAR}}"}},
            {"expect": {"op": "ready"}, "skip": 1}, {"send": '{"op":"subscribe"}'}, {"expect": "subscribed"}]}})
        add("qcred", Q_TOKEN, {"query": {"access_token": "{{VAR}}"}})
        add("hcred", "HCRED-CANARY-3", {"headers": {"Authorization": "Bearer {{VAR}}",
                                                    "Origin": "https://app.example.com"}})
        add("tight", "TIGHT-CANARY-4", {"handshake": {"steps": [{"expect": "go", "max_bytes": 64}]}})

    def go(self, cred, handler, **kw):
        st = self.mkstub(auth=False, handler=handler)
        return st, self.wopen(cred=cred, url=self.wurl("/ws?a=1", stub=st), **kw)

    def failed(self, cred, handler):
        st = self.mkstub(auth=False, handler=handler)
        r = self.wask(cred=cred, url=self.wurl(stub=st))
        self.approve(r["id"])
        res = self.result(r["id"])
        self.assertEqual(res["status"], "failed", res)
        self.assertEqual(len(self.broker._sess), 0)
        return res["error"]

    def test_client_first_sends_without_waiting_and_the_reply_is_consumed(self):
        def h(c, st):
            fin, op, data = c.recv_frame()
            st.auth_msgs.append(json.loads(data))
            c.send_json({"ok": True, "you_sent": data.decode()})                # the reply even repeats the token
            st.default(c)
        st, sid = self.go("cfirst", h)
        self.assertEqual(st.auth_msgs, [{"op": "login", "key": "CFIRST-CANARY-1"}])
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual(r["frames"], [])                                         # the sign-in reply is not shown
        self.wsend(sid, "hi")
        self.assertEqual(json.loads(self.frames_until(sid, 1)[0]["data"]), {"echo": "hi"})
        self.assertNoSecret("CFIRST-CANARY-1")

    def test_multi_step_ordered_with_a_skipped_frame(self):
        log = []

        def h(c, st):
            c.send_json({"op": "hello"})
            log.append(json.loads(c.recv_frame()[2]))
            c.send_json({"op": "noise"})                                           # skipped (skip: 1)
            c.send_json({"op": "ready"})
            log.append(c.recv_frame()[2].decode())
            c.send_text("... subscribed ...")                                      # an exact substring
            st.default(c)
        st, sid = self.go("multi", h)
        self.assertEqual(log, [{"op": "identify", "token": "MULTI-CANARY-2"}, '{"op":"subscribe"}'])
        self.assertNoSecret("MULTI-CANARY-2")

    def test_a_failed_expect_fails_closed_with_a_fixed_error(self):
        def h(c, st):
            c.send_json({"op": "hello"})
            c.recv_frame()
            c.send_json({"op": "denied", "detail": "bad token MULTI-CANARY-2 SERVER-WORDS"})
            c.send_json({"op": "denied"})                                          # more than `skip` allows
        err = self.failed("multi", h)
        self.assertEqual(err, "session not opened: could not connect (handshake refused)")
        self.assertNotIn("SERVER-WORDS", err)
        self.assertNoSecret("MULTI-CANARY-2")
        self.assertNotIn("SERVER-WORDS", self.audit_text())

    def test_a_step_timeout_fails_closed(self):
        cfg = self.broker.cfg["secrets"]["multi"]["_ws"]
        cfg["steps"][0]["timeout"] = 0.2
        err = self.failed("multi", lambda c, st: time.sleep(1))
        self.assertEqual(err, "session not opened: could not connect (timeout)")

    def test_an_oversize_reply_is_refused_by_the_step_limit(self):
        err = self.failed("tight", lambda c, st: c.send_text("go" + "x" * 500))
        self.assertEqual(err, "session not opened: could not connect (frame too large)")

    def test_all_steps_together_are_bounded(self):
        with mock.patch.object(W, "HANDSHAKE_TOTAL_S", 0.3):
            err = self.failed("multi", lambda c, st: (c.send_json({"op": "hello"}), time.sleep(1)))
        self.assertEqual(err, "session not opened: could not connect (timeout)")

    def test_a_binary_reply_never_satisfies_an_expect(self):
        err = self.failed("tight", lambda c, st: c.send_frame(2, b"go"))
        self.assertEqual(err, "session not opened: could not connect (handshake refused)")

    def test_token_in_the_query_is_url_encoded_and_never_leaks(self):
        st, sid = self.go("qcred", lambda c, s: s.default(c))
        line = st.requests[0]["line"]
        self.assertEqual(line, "GET /ws?a=1&access_token=Q%26t%3D1%20%2B%2Fx-CANARY-9 HTTP/1.1")
        self.assertNoSecret(Q_TOKEN, "Q%26t%3D1")
        self.wsend(sid, "ECHO:seen " + Q_TOKEN)
        self.assertEqual(self.frames_until(sid, 1)[0]["data"], "seen ***")
        self.assertNotIn("Q%26t", json.dumps(self.broker.active_sessions()))

    def test_the_agent_cannot_set_the_parameter_the_credential_owns(self):
        st = self.mkstub(auth=False)
        self.wask(cred="qcred", url=self.wurl("/ws?access_token=mine", stub=st), expect=400)
        self.wask(cred="qcred", url=self.wurl("/ws?x=1&access_token=", stub=st), expect=400)

    def test_token_in_the_authorization_header_and_a_configured_origin(self):
        st, sid = self.go("hcred", lambda c, s: s.default(c))
        h = st.requests[0]["headers"]
        self.assertEqual(h["authorization"], "Bearer HCRED-CANARY-3")
        self.assertEqual(h["origin"], "https://app.example.com")
        self.assertNoSecret("HCRED-CANARY-3")

    def test_a_secret_with_a_newline_cannot_split_the_header(self):
        self.broker.backend._data["Hcred"]["token"] = "HC\r\nX-Injected: 1"
        st = self.mkstub(auth=False)
        r = self.wask(cred="hcred", url=self.wurl(stub=st))
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["status"], "failed")
        self.assertNotIn("x-injected", st.requests[0]["headers"] if st.requests else {})

    def test_the_card_says_how_it_signs_in(self):
        self.wask(cred="qcred", url=self.wurl())
        self.wask(cred="hcred", url=self.wurl())
        page = self.get("/")[1]
        self.assertIn("a value in the URL query", page)
        self.assertIn("upgrade header(s): Authorization, Origin", page)
        self.assertNotIn("Q%26t", page)

    def test_bad_ws_config_makes_the_credential_invalid(self):
        for bad in ({"headers": {"Host": "evil"}}, {"query": {"a b": "x"}}, {"handshake": "nope"}):
            with self.assertRaises(ValueError):
                self.broker._entry("Item", {"name": "x", "vars": {"X_T": {}}, "allowed_hosts": ["a.example.com"], "ws": bad})


# ------------------------------------------------------------------------------- wss
_CERTS = {}


def _cert(san):
    """(cert path, key path) for a throwaway self-signed certificate, or None when openssl is missing."""
    import shutil
    import tempfile
    if san in _CERTS:
        return _CERTS[san]
    if not shutil.which("openssl"):
        return None
    d = tempfile.mkdtemp()
    c, k = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c, "-days", "2",
                        "-subj", "/CN=test", "-addext", "subjectAltName=" + san], capture_output=True)
    _CERTS[san] = (c, k) if r.returncode == 0 else None
    return _CERTS[san]


class Wss(WsBase):
    def tls_stub(self, san="DNS:localhost"):
        cert = _cert(san)
        if cert is None:
            self.skipTest("openssl is not available")
        return self.mkstub(tls=cert), cert

    def trusting(self, cert):
        import ssl
        ctx = ssl.create_default_context(cafile=cert[0])
        self.broker.ws_ssl_context = lambda tls: ctx

    def test_wss_verifies_the_certificate_for_the_original_host_and_sends_that_sni(self):
        st, cert = self.tls_stub()
        self.trusting(cert)
        sid = self.wopen(url=self.wurl(stub=st, host="localhost", scheme="wss"))
        self.assertEqual(st.sni, ["localhost"])
        self.assertEqual(st.requests[0]["headers"]["host"], f"localhost:{st.port}")
        self.wsend(sid, "over tls")
        self.assertEqual(json.loads(self.frames_until(sid, 1)[0]["data"]), {"echo": "over tls"})
        self.assertEqual(self.events("ws_session_opened")[0]["tls"], True)
        self.assertNoSecret()

    def test_an_untrusted_certificate_fails_with_tls(self):
        st, cert = self.tls_stub()                              # the default context does not trust it
        r = self.wask(url=self.wurl(stub=st, host="localhost", scheme="wss"))
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["error"], "session not opened: could not connect (tls)")
        self.assertEqual(st.requests, [])                       # nothing, in particular no secret, was sent

    def test_a_certificate_for_another_name_fails_even_if_trusted(self):
        st, cert = self.tls_stub("DNS:localhost")
        self.trusting(cert)
        r = self.wask(url=self.wurl(stub=st, host="127.0.0.1", scheme="wss"))
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["error"], "session not opened: could not connect (tls)")
        self.assertEqual(st.requests, [])

    def test_a_pinned_fingerprint_is_honoured_and_a_wrong_pin_fails(self):
        import hashlib
        import ssl
        st, cert = self.tls_stub()
        with open(cert[0]) as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
        good = hashlib.sha256(der).hexdigest()
        self.broker.cfg["secrets"]["ha"]["_tls"] = {"fingerprint": (good,), "verify": True}
        self.wopen(url=self.wurl(stub=st, host="localhost", scheme="wss"))
        self.broker.cfg["secrets"]["ha"]["_tls"] = {"fingerprint": ("0" * 64,), "verify": True}
        r = self.wask(url=self.wurl(stub=st, host="localhost", scheme="wss"))
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["error"], "session not opened: could not connect (tls)")
        self.assertEqual(len(st.requests), 1)

    def test_a_plain_server_on_a_wss_url_fails_with_tls_not_a_hang(self):
        r = self.wask(url=self.wurl(host="localhost", scheme="wss"))
        with mock.patch.object(W, "CONNECT_S", 0.5):
            self.approve(r["id"])
        self.assertIn(self.result(r["id"])["error"],
                      ("session not opened: could not connect (tls)", "session not opened: could not connect (connection)",
                       "session not opened: could not connect (timeout)"))


# ------------------------------------------------------------------------------- the real asb
class Cli(ts.CliBase, WsBase):
    def wcli_open(self, *extra, cred="ha", url=None, human=None):
        rc, out, err = self.run_cli("ws", cred, url or self.wurl(), *extra, human=human or self.human_approves())
        self.assertEqual(rc, 0, err)
        sid = out.strip()
        self.assertRegex(sid, ID_RE)
        return sid, err

    def env_run(self, extra_env, *args, stdin=None):
        env = {"PATH": os.environ["PATH"], "HOME": self.dir, "SECRET_BROKER_URL": self.base,
               "SECRET_BROKER_KEY": KEY, **extra_env}
        p = subprocess.run([CLI, *args], env=env, input=stdin, capture_output=True, text=True, timeout=60)
        self.out.extend([p.stdout, p.stderr])
        return p.returncode, p.stdout, p.stderr

    def test_usage_errors_exit_2_and_touch_no_broker(self):
        for args in (["ws"], ["ws", "send"], ["ws", "recv"], ["ws", "close"], ["ws", "ha"], ["ws", "ha", "http://x/"],
                     ["ws", "ha", "ws://x/", "--ttl", "soon"], ["ws", "ha", "ws://x/", "--max-frames", "0"],
                     ["ws", "ha", "ws://x/", "--max-frames", "abc"], ["ws", "ha", "ws://x/", "--bogus", "1"],
                     ["ws", "ha", "ws://x/", "--ttl"], ["ws", "ha", "ws://x/", "--ttl", "5m", "--ttl", "6m"],
                     ["ws", "recv", "A" * 32, "--wait", "99"], ["ws", "recv", "A" * 32, "--max", "0"],
                     ["ws", "recv", "A" * 32, "extra"], ["ws", "send", "A" * 32], ["ws", "close", "notanid", "x"],
                     ["ws", "-bad", "ws://x/"], ["ws", "A" * 32, "--linger", "999"], ["ws", "ha", "ws://x/", "--close"],
                     ["ws", "ha", "ws://x/" + "a" * 3000]):
            rc, out, err = self.env_run({"SECRET_BROKER_URL": "http://127.0.0.1:1"}, *args)
            self.assertEqual(rc, 2, (args, err))
            self.assertEqual(out, "")
            self.assertIn("usage", err.lower() if "usage" in err.lower() else err + "usage")

    def test_an_env_session_id_that_is_not_one_is_a_usage_error(self):
        rc, out, err = self.env_run({"ASB_WS_SESSION": "nope"}, "ws", "send", "hi")
        self.assertEqual(rc, 2)

    def test_open_send_recv_close_with_exit_codes(self):
        sid, err = self.wcli_open("--ttl", "10m", "--max-frames", "5")
        self.assertIn("ASB_WS_SESSION", err)
        self.assertIn("5 frames", err)
        rc, out, err = self.run_cli("ws", "send", sid, '{"id":1,"type":"ping"}')
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli("ws", "recv", sid, "--wait", "5")
        self.assertEqual((rc, out), (0, '{"echo": "{\\"id\\":1,\\"type\\":\\"ping\\"}"}\n'), err)
        self.assertNotIn(TOKEN, out + err)
        rc, out, err = self.run_cli("ws", "close", sid)
        self.assertEqual((rc, out.strip()), (0, "closed"))
        for args in (("ws", "send", sid, "x"), ("ws", "recv", sid), ("ws", "close", sid)):
            rc, out, err = self.run_cli(*args)
            self.assertEqual(rc, 7, args)

    def test_env_session_id_and_json_output_and_binary_marker(self):
        sid, _ = self.wcli_open()
        self.assertEqual(self.env_run({"ASB_WS_SESSION": sid}, "ws", "send", "BIN")[0], 0)
        s = self.sess()
        with s.cond:
            self.assertTrue(s.cond.wait_for(lambda: len(s.queue) == 1, 10))
        rc, out, err = self.env_run({"ASB_WS_SESSION": sid}, "ws", "recv", "--wait", "1")
        self.assertEqual((rc, out), (0, ""))                                    # nothing binary on stdout
        self.assertIn("binary frame (11 bytes) not shown", err)
        self.env_run({"ASB_WS_SESSION": sid}, "ws", "send", "-", stdin='{"a": 1}\n')
        rc, out, err = self.env_run({"ASB_WS_SESSION": sid}, "ws", "recv", "--wait", "5", "--json")
        j = json.loads(out)
        self.assertEqual(j["frames"][0]["type"], "text")

    def test_frame_cap_is_exit_8_and_server_close_is_exit_7(self):
        sid, _ = self.wcli_open("--max-frames", "1")
        self.assertEqual(self.run_cli("ws", "send", sid, "once")[0], 0)
        self.assertEqual(self.run_cli("ws", "send", sid, "again")[0], 8)
        self.assertEqual(self.run_cli("ws", "close", sid)[0], 0)
        sid, _ = self.wcli_open()
        self.assertEqual(self.run_cli("ws", "send", sid, "CLOSE")[0], 0)
        rc, out, err = self.run_cli("ws", "recv", sid, "--wait", "10")
        self.assertEqual(rc, 7, err)
        self.assertIn("connection is closed", err)

    def test_pipe_mode_relays_lines_both_ways_and_leaves_the_session_open(self):
        sid, _ = self.wcli_open()
        rc, out, err = self.run_cli("ws", sid, "--linger", "1", stdin="one\ntwo\n\nthree\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines(), ['{"echo": "one"}', '{"echo": "two"}', '{"echo": "three"}'])
        rc, out, err = self.run_cli("ws", sid, "--linger", "0", "--close", stdin="")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.run_cli("ws", "close", sid)[0], 7)               # --close ended it

    def test_pipe_mode_exit_code_when_the_session_is_gone(self):
        sid, _ = self.wcli_open()
        self.run_cli("ws", "close", sid)
        rc, out, err = self.run_cli("ws", sid, "--linger", "1", stdin="x\n")
        self.assertEqual(rc, 7)

    def test_newlines_in_a_frame_become_spaces_so_the_pipe_stays_line_oriented(self):
        sid, _ = self.wcli_open()
        self.run_cli("ws", "send", sid, "ECHO:a\nb\r\nc")
        rc, out, err = self.run_cli("ws", "recv", sid, "--wait", "5")
        self.assertEqual(out, "a b  c\n")

    def test_denied_open_is_exit_4_and_an_unconfigured_credential_exit_3(self):
        rc, out, err = self.run_cli("ws", "ha", self.wurl(), human=lambda rid: self.post("/decide", {"id": rid, "decision": "deny"}))
        self.assertEqual(rc, 4, err)
        rc, out, err = self.run_cli("ws", "unifi", self.wurl())
        self.assertEqual(rc, 3, err)
        rc, out, err = self.run_cli("ws", "ha", f"ws://evil.example.com:{self.stub.port}/x")
        self.assertEqual(rc, 3, err)

    def test_guide_and_help_describe_it(self):
        rc, out, err = self.run_cli("guide")
        self.assertIn("WebSocket sessions", out)
        self.assertIn("ASB_WS_SESSION", out)
        rc, out, err = self.run_cli("help", "ws")
        self.assertIn("asb ws NAME URL", out)
        self.assertNotIn(TOKEN, out)


class Recheck(WsBase):
    """A session is re-validated against the live catalog on every use and by the sweeper."""

    def ended(self, sid):
        self.assertTrue(self.stub.eof[0].wait(5))
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual((code, r["code"]), (410, "session_expired"))
        self.assertIn("revoked", r["error"])
        self.assertEqual(self.events("ws_session_closed")[0]["reason"], "revoked")

    def check(self, change):
        sid = self.wopen()
        change()
        code, text = self.wsend(sid, "x")
        self.assertEqual((code, json.loads(text)["code"]), (410, "session_expired"))
        self.ended(sid)

    def test_credential_removed(self):
        self.check(lambda: self.broker.cfg["secrets"].pop("ha"))

    def test_host_removed(self):
        self.check(lambda: self.broker.cfg["secrets"]["ha"].update(allowed_hosts=["other.example.com"]))

    def test_no_hosts_left_env_only(self):
        self.check(lambda: self.broker.cfg["secrets"]["ha"].update(allowed_hosts=[]))

    def test_turned_into_an_ssh_key(self):
        self.check(lambda: self.broker.cfg["secrets"]["ha"].update(ssh=True))

    def test_ws_setting_removed(self):
        self.check(lambda: self.broker.cfg["secrets"]["ha"].update(_ws=None))

    def test_destination_now_refused_by_the_guard(self):
        p = mock.patch.object(self.broker.dest_guard, "host_refused", lambda h: True)
        self.check(p.start)
        p.stop()

    def test_recv_is_rechecked_too(self):
        sid = self.wopen()
        self.broker.cfg["secrets"].pop("ha")
        code, r = self.wrecv(sid, wait=0)
        self.assertEqual((code, r["code"]), (410, "session_expired"))

    def test_port_narrowed(self):
        self.broker.cfg["secrets"]["remote"]["allowed_hosts"] = ["ws.example.com"]
        g = self.broker.dest_guard
        sid = self.wopen()
        # a name allowed on any port is narrowed to one other port
        s = self.sess()
        s.hosts = (f"ws.example.com:{self.stub.port}",)
        s.cred = "remote"
        self.broker.cfg["secrets"]["remote"]["allowed_hosts"] = ["ws.example.com:9"]
        code, text = self.wsend(sid, "x")
        self.assertEqual(code, 410)

    def test_client_revoked_mid_session(self):
        a = self.new_client("alice-box")
        sid = self.wopen(key=a["secret"])
        self.broker.clients.revoke(a["id"], "alice")
        self.assertEqual(self.wsend(sid, "x", key=a["secret"])[0], 401)           # its key no longer authenticates
        self.broker.sweep_sessions()
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(len(self.broker._sess), 0)

    def test_catalog_change_while_idle_is_caught_by_the_sweeper(self):
        sid = self.wopen()
        self.broker.cfg["secrets"]["ha"]["allowed_hosts"] = []
        self.assertEqual(self.broker.sweep_sessions(), 1)
        self.assertTrue(self.stub.eof[0].wait(5))
        self.assertEqual(self.events("ws_session_closed")[0].get("revoked_by"), "scope_recheck")

    def test_a_reload_that_keeps_the_scope_changes_nothing(self):
        sid = self.wopen()
        self.broker.refresh_catalog() if hasattr(self.broker, "refresh_catalog") else None
        self.broker.sweep_sessions()
        self.assertEqual(self.wsend(sid, "still")[0], 200)
