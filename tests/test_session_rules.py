"""Auto-approve rules for sessions (`http_session`, `ws_session`): the parser and the one subset check.

The properties: one parser for config rules and stored rules; caps are required; a manifest matches only when it is
a SUBSET of the rule (hosts and ports, methods, scheme, plain path under the prefix, query only if allowed); the
effective limits are the minimum of the request and the rule; the legacy key, an unlisted client, an expired rule
and an uncovered credential never match; anything unreadable fails closed.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import autorules, sessionrules  # noqa: E402

BOX = "c-0a0b0c0d"
OTHER = "c-0e0f0a0b"
CLIENT = {"id": BOX, "name": "box", "legacy": False}


def hs(**kw):
    return {"name": "unifi reads", "mode": "http_session", "secret": "unifi",
            "hosts": ["api.example.com:443"], "max_ttl_s": 600, "max_calls": 50, **kw}


def ws(**kw):
    return {"name": "ha stream", "mode": "ws_session", "secret": "ha", "host": "ha.example.com",
            "path_prefix": "/api/websocket", "max_ttl_s": 600, "max_frames": 200, **kw}


def hmanifest(**kw):
    return {"purpose": "p", "hosts": ["api.example.com:443"], "methods": ["GET", "HEAD"], "ttl_s": 900,
            "max_calls": 200, **kw}


def wmanifest(**kw):
    return {"kind": "ws", "scheme": "wss", "host": "ha.example.com", "port": 443, "target": "/api/websocket",
            "hosts": ["ha.example.com:443"], "methods": [], "ttl_s": 900, "max_calls": 1000, **kw}


def find(rule, mode, spec, names=("unifi",), client=CLIENT, now=None):
    return autorules.find(autorules.parse([rule]), mode, list(names), spec, client, now)


class Parse(unittest.TestCase):
    def test_http_session_rule_parses_with_narrow_defaults(self):
        r = autorules.parse([hs()])[0]
        self.assertEqual((r["mode"], r["max_ttl_s"], r["max_calls"]), ("http_session", 600, 50))
        self.assertEqual(r["methods"], frozenset({"GET", "HEAD"}))
        self.assertEqual(r["hosts"], ("api.example.com:443",))

    def test_ws_session_rule_parses_with_narrow_defaults(self):
        r = autorules.parse([ws()])[0]
        self.assertEqual((r["scheme"], r["port"], r["allow_query"], r["max_calls"]), ("wss", 443, False, 200))
        r = autorules.parse([ws(scheme="ws")])[0]
        self.assertEqual(r["port"], 80)

    def test_caps_are_required_and_bounded(self):
        for key in ("max_ttl_s", "max_calls"):
            raw = hs()
            del raw[key]
            with self.assertRaises(ValueError) as cm:
                autorules.parse([raw])
            self.assertIn(f"auto_approve[0].{key}", str(cm.exception))
        raw = ws()
        del raw["max_frames"]
        with self.assertRaises(ValueError) as cm:
            autorules.parse([raw])
        self.assertIn("auto_approve[0].max_frames", str(cm.exception))
        for key, val in (("max_ttl_s", 29), ("max_ttl_s", 86401), ("max_ttl_s", True), ("max_ttl_s", "600"),
                         ("max_calls", 0), ("max_calls", 10001), ("max_calls", 1.5)):
            with self.assertRaises(ValueError, msg=(key, val)) as cm:
                autorules.parse([hs(**{key: val})])
            self.assertIn(f"auto_approve[0].{key}", str(cm.exception))
        self.assertEqual(len(autorules.parse([hs(max_ttl_s=30, max_calls=1)])), 1)      # positive control

    def test_every_mistake_names_the_field(self):
        bad = {
            "no hosts": ("hosts", {k: v for k, v in hs().items() if k != "hosts"}),
            "empty hosts": ("hosts", hs(hosts=[])),
            "hosts with scheme": ("hosts", hs(hosts=["https://api.example.com"])),
            "hosts with path": ("hosts", hs(hosts=["api.example.com/x"])),
            "too many hosts": ("hosts", hs(hosts=[f"h{i}.example.com" for i in range(6)])),
            "bad port": ("hosts", hs(hosts=["api.example.com:99999"])),
            "lower-case method": ("methods", hs(methods=["get"])),
            "unknown method": ("methods", hs(methods=["TRACE"])),
            "http path_prefix": ("path_prefix", hs(path_prefix="/v1")),
            "ws no prefix": ("path_prefix", {k: v for k, v in ws().items() if k != "path_prefix"}),
            "ws dotdot": ("path_prefix", ws(path_prefix="/a/../b")),
            "ws relative": ("path_prefix", ws(path_prefix="a")),
            "ws query in prefix": ("path_prefix", ws(path_prefix="/a?x=1")),
            "ws bad scheme": ("scheme", ws(scheme="https")),
            "ws bad port": ("port", ws(port=0)),
            "ws port string": ("port", ws(port="443")),
            "ws allow_query not bool": ("allow_query", ws(allow_query="yes")),
            "ws host with port": ("host", ws(host="ha.example.com:8123")),
            "ws no host": ("host", {k: v for k, v in ws().items() if k != "host"}),
            "http host key": ("host", hs(host="api.example.com")),
            "ws methods key": ("methods", ws(methods=["GET"])),
        }
        for label, (field, rule) in bad.items():
            with self.assertRaises(ValueError, msg=label) as cm:
                autorules.parse([rule])
            self.assertIn(f"auto_approve[0].{field}", str(cm.exception), label)

    def test_session_close_is_still_human_only_and_session_points_at_the_new_modes(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "session_close", "secret": "a"}])
        self.assertIn("always needs a human", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "session", "secret": "a"}])
        self.assertIn("http_session", str(cm.exception))
        self.assertIn("ws_session", str(cm.exception))

    def test_stored_rules_round_trip_and_share_the_parser(self):
        extra = {"id": "r0001", "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None}
        for raw in (hs(**extra), ws(allow_query=True, **extra), ws(scheme="ws", port=8123, **extra)):
            raw.pop("secret")
            rules = autorules.parse_stored([raw], "cred")
            self.assertEqual(rules[0]["secrets"], frozenset({"cred"}))
            self.assertEqual(autorules.serialize_stored(rules)[0]["mode"], raw["mode"])
            again = autorules.parse_stored(autorules.serialize_stored(rules), "cred")
            self.assertEqual(again, rules)
        raw = hs(**extra)
        raw.pop("secret")
        self.assertEqual(autorules.serialize_stored(autorules.parse_stored([raw], "cred")), [{
            **{k: v for k, v in raw.items()}, "methods": ["GET", "HEAD"]}])


class HttpWithin(unittest.TestCase):
    def test_a_manifest_inside_the_rule_matches_and_gets_the_lower_limits(self):
        rule = autorules.parse([hs()])[0]
        self.assertEqual(sessionrules.within(rule, "http_session", hmanifest()), (600, 50))
        self.assertEqual(sessionrules.within(rule, "http_session", hmanifest(ttl_s=60, max_calls=5)), (60, 5))
        self.assertIsNotNone(find(hs(), "http_session", hmanifest()))

    def test_every_way_of_widening_is_refused(self):
        rule = hs(hosts=["api.example.com:443", "b.example.com"], methods=["GET", "HEAD", "POST"])
        base = hmanifest(hosts=["api.example.com:443"], methods=["GET"])
        self.assertIsNotNone(find(rule, "http_session", base))                          # premise: this one matches
        refused = {
            "other host": hmanifest(hosts=["evil.example.com:443"]),
            "suffix host": hmanifest(hosts=["api.example.com.evil.net:443"]),
            "other port": hmanifest(hosts=["api.example.com:8443"]),
            "bare host is wider than host:443": hmanifest(hosts=["api.example.com"]),
            "extra host": hmanifest(hosts=["api.example.com:443", "evil.example.com:443"]),
            "extra method": hmanifest(methods=["GET", "DELETE"]),
            "other method": hmanifest(methods=["PUT"]),
            "no hosts": hmanifest(hosts=[]),
            "no methods": hmanifest(methods=[]),
            "hosts not a list": hmanifest(hosts="api.example.com:443"),
            "methods not a list": hmanifest(methods="GET"),
            "malformed host": hmanifest(hosts=["api.example.com:443/x"]),
            "bad ttl": hmanifest(ttl_s="900"),
            "bad calls": hmanifest(max_calls=None),
            "zero ttl": hmanifest(ttl_s=0),
            "zero calls": hmanifest(max_calls=0),
        }
        for label, m in refused.items():
            self.assertIsNone(find(rule, "http_session", m), label)

    def test_bare_host_rule_admits_both_default_ports_but_not_others(self):
        rule = hs(hosts=["b.example.com"])
        for host in ("b.example.com", "b.example.com:443", "b.example.com:80", "B.example.com"):
            self.assertIsNotNone(find(rule, "http_session", hmanifest(hosts=[host])), host)
        self.assertIsNone(find(rule, "http_session", hmanifest(hosts=["b.example.com:8080"])))

    def test_rule_methods_default_to_reads(self):
        raw = {k: v for k, v in hs().items()}
        self.assertIsNotNone(find(raw, "http_session", hmanifest(methods=["GET", "HEAD"])))
        self.assertIsNone(find(raw, "http_session", hmanifest(methods=["GET", "POST"])))

    def test_mode_must_match_the_kind(self):
        self.assertIsNone(find(hs(), "ws_session", wmanifest()))
        self.assertIsNone(find(ws(), "http_session", hmanifest()))
        self.assertIsNone(find(hs(), "http", {"method": "GET", "url": "https://api.example.com/"}))


class WsWithin(unittest.TestCase):
    def test_a_manifest_inside_the_rule_matches_and_gets_the_lower_limits(self):
        rule = autorules.parse([ws()])[0]
        self.assertEqual(sessionrules.within(rule, "ws_session", wmanifest()), (600, 200))
        self.assertEqual(sessionrules.within(rule, "ws_session", wmanifest(ttl_s=60, max_calls=7)), (60, 7))
        self.assertIsNotNone(find(ws(), "ws_session", wmanifest(target="/api/websocket/sub"), names=("ha",)))

    def test_every_way_of_widening_is_refused(self):
        self.assertIsNotNone(find(ws(), "ws_session", wmanifest(), names=("ha",)))          # premise
        refused = {
            "other host": wmanifest(host="evil.example.com", hosts=["evil.example.com:443"]),
            "other port": wmanifest(port=8443, hosts=["ha.example.com:8443"]),
            "plain ws for a wss rule": wmanifest(scheme="ws", port=80, hosts=["ha.example.com:80"]),
            "other path": wmanifest(target="/api/other"),
            "sibling prefix": wmanifest(target="/api/websocketx"),
            "parent path": wmanifest(target="/api"),
            "dot segment": wmanifest(target="/api/websocket/../admin"),
            "escape": wmanifest(target="/api/websocket/%2e%2e/admin"),
            "escape in segment": wmanifest(target="/api/websocket/a%2fb"),
            "semicolon": wmanifest(target="/api/websocket;x=1"),
            "backslash": wmanifest(target="/api/websocket\\x"),
            "query not allowed": wmanifest(target="/api/websocket?token=1"),
            "no target": {k: v for k, v in wmanifest().items() if k != "target"},
            "target not text": wmanifest(target=None),
            "port not int": wmanifest(port="443"),
        }
        for label, m in refused.items():
            self.assertIsNone(find(ws(), "ws_session", m, names=("ha",)), label)

    def test_query_only_when_the_rule_allows_it(self):
        m = wmanifest(target="/api/websocket?v=2")
        self.assertIsNone(find(ws(), "ws_session", m, names=("ha",)))
        self.assertIsNotNone(find(ws(allow_query=True), "ws_session", m, names=("ha",)))
        self.assertIsNone(find(ws(allow_query=True), "ws_session", wmanifest(target="/api/websocket?a=%255f"),
                               names=("ha",)))                         # double encoding: not something to reason about

    def test_a_root_prefix_covers_any_plain_path(self):
        self.assertIsNotNone(find(ws(path_prefix="/"), "ws_session", wmanifest(target="/x/y"), names=("ha",)))


class Standing(unittest.TestCase):
    def test_clients_credentials_and_expiry(self):
        rule = hs(clients=[BOX])
        self.assertIsNotNone(find(rule, "http_session", hmanifest()))
        self.assertIsNone(find(rule, "http_session", hmanifest(), client={"id": OTHER, "name": "o", "legacy": False}))
        self.assertIsNone(find(rule, "http_session", hmanifest(), client={"id": "legacy", "name": "l", "legacy": True}))
        self.assertIsNone(find(hs(), "http_session", hmanifest(), client={"id": "legacy", "name": "l", "legacy": True}))
        self.assertIsNone(find(hs(), "http_session", hmanifest(), names=("other",)))
        self.assertIsNone(find(hs(), "http_session", hmanifest(), names=("unifi", "other")))
        stored = autorules.parse_stored([{"id": "r0001", "by": "a", "at": "2026-11-18T00:00:00Z",
                                          "expires_at": "2026-11-19T00:00:00Z",
                                          **{k: v for k, v in hs().items() if k != "secret"}}], "unifi")
        past = time.mktime((2026, 11, 20, 0, 0, 0, 0, 0, 0))
        before = time.mktime((2026, 11, 18, 12, 0, 0, 0, 0, 0))
        self.assertIsNotNone(autorules.find(stored, "http_session", ["unifi"], hmanifest(), CLIENT, before))
        self.assertIsNone(autorules.find(stored, "http_session", ["unifi"], hmanifest(), CLIENT, past))


if __name__ == "__main__":
    unittest.main()
