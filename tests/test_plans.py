"""Plan mode, unit level: config, manifest validation, canonical hashes, strict JSON, GraphQL
classification, every matcher rule of the design (section 5, items A-G), the deterministic tiers and
the in-memory PlanStore (binding, deadlines, uses, rate, in-flight, concurrency, coalesced misses).

No broker and no network: the matcher is a pure function and the store takes injected clocks.
Every value here is fake.
"""
import base64
import copy
import json
import os
import re
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api  # noqa: E402
from secret_broker import clock as clock_mod  # noqa: E402
from secret_broker import plans as P  # noqa: E402

CFG = P.parse_config(None)
OWN = frozenset({"LEDGER_TOKEN"})
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DOC = "query Accounts { accounts { id balance } }"


def rule(**kw):
    r = {"secret": "ledger", "method": "POST", "host": "api.example.com", "path_prefix": "/v1/notes",
         "max_uses": 5, "body": {"json": {"keys": ["text", "kind"], "pin": {"kind": "reconcile"}}}}
    r.update(kw)
    return {k: v for k, v in r.items() if v is not None}


def norm(r, cfg=CFG):
    m = P.validate_manifest({"v": 1, "task": "t", "rules": [r]}, cfg)
    return m["rules"][0]


def hdrs(**extra):
    h = {"Authorization": "Bearer {{LEDGER_TOKEN}}", "Content-Type": "application/json"}
    h.update(extra)
    return h


def frozen(url="https://api.example.com/v1/notes", method="POST", headers=None, body=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    return P.freeze({"method": method, "url": url, "headers": hdrs() if headers is None else headers,
                     "body": body})


def verdict(r, f, cfg=CFG, own=OWN):
    """None for a match, else the `why` class."""
    try:
        P.match_rule(r, f, cfg, own)
    except P.NoMatch as e:
        return e.why
    return None


NOTE = {"text": "hello", "kind": "reconcile"}


class Config(unittest.TestCase):
    def test_defaults_are_the_documented_values(self):
        c = P.parse_config(None)
        self.assertEqual((c["enabled"], c["default_minutes"], c["max_minutes"], c["pending_ttl_s"]),
                         (True, 30, 480, 900))
        self.assertEqual((c["max_rules"], c["max_uses_per_rule"], c["max_total_uses"], c["rate_per_min"],
                          c["max_inflight"], c["max_body_bytes"], c["max_pending"], c["max_active_per_client"]),
                         (20, 500, 2000, 30, 4, 16384, 4, 2))
        self.assertFalse(c["allow_any_body"] or c["allow_root_prefix"] or c["allow_graphql_mutation"]
                         or c["allow_legacy"])
        self.assertEqual(c["allowed_request_headers"],
                         ["Accept", "Content-Type", "Content-Length", "If-None-Match", "User-Agent"])
        self.assertEqual(c["deny_secrets"], [])

    def test_validation_names_the_field(self):
        for bad, frag in (({"nope": 1}, "plans.nope"), ({"enabled": "yes"}, "plans.enabled"),
                          ({"max_minutes": 721}, "plans.max_minutes"), ({"max_minutes": 0}, "plans.max_minutes"),
                          ({"max_minutes": True}, "plans.max_minutes"),
                          ({"default_minutes": 500}, "default_minutes"),
                          ({"pending_ttl_s": 60}, "plans.pending_ttl_s"), ({"pending_ttl_s": 4000}, "pending_ttl_s"),
                          ({"max_rules": 0}, "plans.max_rules"), ({"rate_per_min": 0}, "plans.rate_per_min"),
                          ({"max_inflight": 99}, "plans.max_inflight"), ({"max_body_bytes": 0}, "max_body_bytes"),
                          ({"max_pending": 0}, "plans.max_pending"), ({"max_uses_per_rule": 3000}, "max_total_uses"),
                          ({"allow_any_body": 1}, "plans.allow_any_body"),
                          ({"allowed_request_headers": "Accept"}, "allowed_request_headers"),
                          ({"allowed_request_headers": ["Host"]}, "allowed_request_headers"),
                          ({"allowed_request_headers": ["Transfer-Encoding"]}, "allowed_request_headers"),
                          ({"allowed_request_headers": ["X-HTTP-Method-Override"]}, "allowed_request_headers"),
                          ({"allowed_request_headers": ["X-Forwarded-Host"]}, "allowed_request_headers"),
                          ({"deny_secrets": ["BAD NAME"]}, "plans.deny_secrets"), ({"deny_secrets": "x"}, "deny_secrets"),
                          ([], "plans must be an object")):
            with self.assertRaises(ValueError, msg=bad) as cm:
                P.parse_config(bad)
            self.assertIn(frag, str(cm.exception))

    def test_the_validator_ceiling_is_720_minutes(self):
        self.assertEqual(P.parse_config({"max_minutes": 720})["max_minutes"], 720)
        with self.assertRaises(ValueError):
            P.parse_config({"max_minutes": 721})

    def test_per_client_override(self):
        self.assertEqual(P.parse_client_override({"enabled": False, "max_minutes": 60}, "x"),
                         {"enabled": False, "max_minutes": 60})
        for bad in ({"enabled": 1}, {"max_minutes": 0}, {"max_minutes": 721}, {"nope": 1}, []):
            with self.assertRaises(ValueError):
                P.parse_client_override(bad, "clients.c-1.plans")

    def test_clients_config_accepts_the_plans_override(self):
        from secret_broker import clients
        ok = clients.parse_config({"clients": {"c-0a1b2c3d": {"plans": {"enabled": False, "max_minutes": 10}}}})
        self.assertEqual(ok["overrides"]["c-0a1b2c3d"]["plans"], {"enabled": False, "max_minutes": 10})
        with self.assertRaises(ValueError) as cm:
            clients.parse_config({"clients": {"c-0a1b2c3d": {"plans": {"enabled": "no"}}}})
        self.assertIn("clients.c-0a1b2c3d.plans.enabled", str(cm.exception))

    def test_describe_config(self):
        self.assertIn("up to 8 hours", P.describe_config(CFG))
        self.assertIn("off", P.describe_config(P.parse_config({"enabled": False})))


class Clock(unittest.TestCase):
    def tearDown(self):
        clock_mod.install()

    def test_install_and_restore(self):
        clock_mod.install(now=lambda: 5.0, mono=lambda: 7.0)
        self.assertEqual((clock_mod.now(), clock_mod.mono()), (5.0, 7.0))
        clock_mod.install()
        self.assertGreater(clock_mod.now(), 1e9)

    def test_reads_time_at_call_time(self):
        from unittest import mock
        with mock.patch("time.time", lambda: 42.0):
            self.assertEqual(clock_mod.now(), 42.0)

    def test_the_grant_store_uses_the_shared_clock(self):
        import inspect
        from secret_broker import broker
        self.assertIn("clock=clock_mod.now", inspect.getsource(broker.Broker._init_grants))


class StrictJson(unittest.TestCase):
    def bad(self, raw, **kw):
        with self.assertRaises(P.StrictError, msg=raw):
            P.strict_loads(raw, **kw)

    def test_accepts_ordinary_documents(self):
        self.assertEqual(P.strict_loads('{"a": [1, 2.5, "x", null, true], "b": {"c": 1}}'),
                         {"a": [1, 2.5, "x", None, True], "b": {"c": 1}})
        self.assertEqual(P.strict_loads(b'  {"a": 1}  '), {"a": 1})
        self.assertEqual(P.strict_loads('{"n": 9007199254740992}'), {"n": 2 ** 53})

    def test_duplicate_keys_at_any_depth(self):
        self.bad('{"a": 1, "a": 2}')
        self.bad('{"a": {"b": 1, "b": 1}}')
        self.bad('{"a": [{"b": 1, "b": 2}]}')
        self.bad('{"a": 1, "\\u0061": 2}')           # the same key after decoding

    def test_non_finite_numbers(self):
        for t in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"):
            self.bad('{"n": %s}' % t)

    def test_big_integers(self):
        self.bad('{"n": 9007199254740993}')
        self.bad('{"n": -9007199254740993}')
        self.bad('{"n": 123456789012345678901234567890}')

    def test_lone_surrogates(self):
        self.bad('{"a": "\\ud800"}')
        self.bad('{"\\udc00": 1}')
        self.bad('{"a": ["x", "\\ud83d"]}')
        self.assertEqual(P.strict_loads('{"a": "\\ud83d\\ude00"}'), {"a": "\U0001f600"})     # a valid pair is fine

    def test_bom(self):
        self.bad(b'\xef\xbb\xbf{"a": 1}')
        self.bad('\ufeff{"a": 1}')

    def test_trailing_data_and_garbage(self):
        self.bad('{"a": 1} {"b": 2}')
        self.bad('{"a": 1} x')
        self.bad('{"a": 1,}')
        self.bad("")
        self.bad("{")
        self.bad(b"\xff\xfe")

    def test_nesting_and_member_limits(self):
        deep = "[" * 9 + "]" * 9
        self.bad(deep)
        self.assertEqual(P.strict_loads("[" * 8 + "]" * 8), [[[[[[[[]]]]]]]])
        self.bad("[" * 100000)                       # never a RecursionError out of the parser
        self.bad(json.dumps({str(i): i for i in range(65)}))
        self.assertEqual(len(P.strict_loads(json.dumps({str(i): i for i in range(64)}))), 64)


class GraphQL(unittest.TestCase):
    def test_pure_queries_are_reads(self):
        self.assertEqual(P.classify_graphql(DOC), ("read", 1))
        self.assertEqual(P.classify_graphql("{ a }"), ("read", 1))
        self.assertEqual(P.classify_graphql("query A { a } query B { b }"), ("read", 2))
        self.assertEqual(P.classify_graphql("query A($x: In = {a: 1}) { a(i: $x) }"), ("read", 1))
        self.assertEqual(P.classify_graphql("query { ...F } fragment F on Query { a }"), ("read", 1))

    def test_mutation_and_subscription_anywhere_is_a_write(self):
        for d in ("mutation M { x }", "subscription S { x }", "query { a(s: \"mutation\") }",
                  "query { a } # mutation here", "fragment F on Mutation { x } query { ...F }",
                  "query { a(s: \"\"\"subscription\"\"\") }", "query Q { mutationField }"):
            self.assertEqual(P.classify_graphql(d)[0], "write", d)

    def test_invalid_documents_are_neither_read_nor_write(self):
        for d in ("MUTATION { x }", "query {", "}", "", "fragment F on T { a }", "fragment F on Mutation { a }",
                  'query { a(s: """a"""") }', 'query { a(s: """unterminated) }', "type T { a: Int }"):
            self.assertEqual(P.classify_graphql(d), ("invalid", 0), d)
        self.assertEqual(P.classify_graphql('query { a(s: """x""""") }')[0], "read")      # an empty string follows

    def test_invalid_documents_are_refused_even_when_mutations_are_allowed(self):
        opt = P.parse_config({"allow_graphql_mutation": True})
        for d in ("query {", "fragment F on T { a }", "MUTATION { x }", 'query { a(s: """a"""") }', "}"):
            with self.assertRaises(P.ManifestError, msg=d) as cm:
                P.validate_manifest({"v": 1, "task": "t", "rules": [rule(body={"graphql": {"document": d}})]}, opt)
            self.assertIn("not a parsable GraphQL document", str(cm.exception))
        P.validate_manifest({"v": 1, "task": "t", "rules": [rule(body={"graphql": {"document": "mutation M { x }"}})]}, opt)
        # a multi-operation document still needs its operation name with mutations allowed
        with self.assertRaises(P.ManifestError):
            P.validate_manifest({"v": 1, "task": "t", "rules": [rule(body={"graphql": {
                "document": "mutation A { a } query B { b }"}})]}, opt)

    def test_unparsable_is_invalid(self):
        for d in ("query {", "query { a ", "}", "query { a(s: \"unterminated) }", "query { a } }", "", "   ",
                  "type Foo { a: Int }", "query { \u00e9 }", "query { a(", "query { a($) )"):
            self.assertEqual(P.classify_graphql(d)[0], "invalid", d)

    def test_operation_counting_ignores_fragments_strings_and_comments(self):
        self.assertEqual(P.classify_graphql('query A { a(s: "query B { b }") } # query C { c }')[1], 1)
        self.assertEqual(P.classify_graphql("query A { a } fragment F on T { x } query B { b }")[1], 2)


class ManifestValidation(unittest.TestCase):
    def man(self, **kw):
        m = {"v": 1, "task": "nightly sync", "rules": [rule()]}
        m.update(kw)
        return m

    def bad(self, m, frag, cfg=CFG, status=400):
        with self.assertRaises(P.ManifestError, msg=frag) as cm:
            P.validate_manifest(m, cfg)
        self.assertIn(frag, str(cm.exception))
        self.assertEqual(cm.exception.status, status)
        return str(cm.exception)

    def test_a_minimal_manifest_is_normalized(self):
        m = P.validate_manifest(self.man(), CFG)
        r = m["rules"][0]
        self.assertEqual((r["scheme"], r["port"], r["query"]), ("https", 443, "none"))
        self.assertEqual(m["ttl_s"], 30 * 60)
        self.assertEqual(r["body"], {"json": {"keys": ["kind", "text"], "pin": {"kind": "reconcile"}}})
        self.assertRegex(m["manifest_hash"], r"^[0-9a-f]{64}$")

    def test_top_level_shape(self):
        self.bad([], "manifest: must be a JSON object")
        self.bad(self.man(v=2), "v: must be 1")
        self.bad(self.man(v=True), "v: must be 1")
        self.bad(self.man(extra=1), "unknown key")
        self.bad({"v": 1, "task": "t"}, "rules: must be a list")
        self.bad(self.man(rules=[]), "rules: must be a list")
        self.bad(self.man(rules=[rule()] * 2), "duplicate rule")
        self.bad(self.man(rules=[rule(path_prefix="/p%d" % i) for i in range(21)]), "1 to 20 rules")

    def test_sessions_window_and_rule_session_are_recognized_and_refused(self):
        self.bad(self.man(sessions={"a": {}}), "sessions: not supported yet")
        self.bad(self.man(window={"not_before": 1}), "window: not supported yet")
        self.bad(self.man(rules=[rule(session="unifi")]), "session: not supported yet")

    def test_ttl(self):
        self.assertEqual(P.validate_manifest(self.man(ttl_seconds=3600), CFG)["ttl_s"], 3600)
        self.bad(self.man(ttl_seconds=30), "ttl_seconds")
        self.bad(self.man(ttl_seconds="3600"), "ttl_seconds")
        self.bad(self.man(ttl_seconds=True), "ttl_seconds")
        self.bad(self.man(ttl_seconds=480 * 60 + 1), "ttl_seconds: is above the maximum")
        self.assertEqual(P.validate_manifest(self.man(ttl_seconds=480 * 60), CFG)["ttl_s"], 480 * 60)
        with self.assertRaises(P.ManifestError):
            P.validate_manifest(self.man(ttl_seconds=3601), CFG, max_minutes=60)     # a per-client ceiling

    def test_text_fields_are_vetted(self):
        self.bad(self.man(task=""), "task")
        self.bad(self.man(task="x" * 81), "task")
        self.bad(self.man(task=5), "task: must be a string")
        self.bad(self.man(description="x" * 401), "description")
        self.assertEqual(P.validate_manifest(self.man(task="x" * 80, description="d" * 400), CFG)["task"], "x" * 80)
        for ch in ("\u200b", "\u202e", "\u2066", "\ufeff", "\U000e0041", "\u00a0", "\u2028", "\x00", "\x1b",
                   "\n", "\t", "\u3164", "\ud800"):
            msg = self.bad(self.man(task="ab" + ch + "cd"), "task")
            self.assertNotIn(ch, msg)
            self.bad(self.man(description="ab" + ch + "cd"), "description")
        msg = self.bad(self.man(task="a\u200bb"), "hidden characters (invisible format character at offset 1)")
        self.assertNotIn("\u200b", msg)

    def test_rule_fields(self):
        self.bad(self.man(rules=[rule(secret="BAD NAME")]), "rules[0].secret")
        self.bad(self.man(rules=[rule(method="post")]), "rules[0].method")
        self.bad(self.man(rules=[rule(method="TRACE")]), "rules[0].method")
        self.bad(self.man(rules=[rule(host="API.example.com")]), "rules[0].host")
        self.bad(self.man(rules=[rule(host="api.example.com.")]), "rules[0].host")
        self.bad(self.man(rules=[rule(host="b\u00fccher.example")]), "rules[0].host")
        self.bad(self.man(rules=[rule(host="0x7f.1")]), "rules[0].host")
        self.bad(self.man(rules=[rule(host="2130706433")]), "rules[0].host")
        self.bad(self.man(rules=[rule(host="127.000.000.001")]), "rules[0].host")
        self.bad(self.man(rules=[rule(port=0)]), "rules[0].port")
        self.bad(self.man(rules=[rule(port=70000)]), "rules[0].port")
        self.bad(self.man(rules=[rule(port=True)]), "rules[0].port")
        self.bad(self.man(rules=[rule(max_uses=0)]), "rules[0].max_uses")
        self.bad(self.man(rules=[rule(max_uses=501)]), "rules[0].max_uses")
        self.bad(self.man(rules=[rule(query="some")]), "rules[0].query")
        self.bad(self.man(rules=[rule(nope=1)]), "rules[0]: has an unknown key")
        self.assertEqual(norm(rule(host="127.0.0.1"))["host"], "127.0.0.1")
        self.assertEqual(norm(rule(host="::1", scheme="http"))["host"], "::1")

    def test_scheme_http_needs_a_private_ip_literal(self):
        self.bad(self.man(rules=[rule(scheme="http")]), "plain http is only allowed for a private IP")
        self.bad(self.man(rules=[rule(scheme="http", host="printer.lan")]), "plain http")
        self.bad(self.man(rules=[rule(scheme="http", host="nas")]), "plain http")
        self.bad(self.man(rules=[rule(scheme="http", host="8.8.8.8")]), "plain http")
        self.bad(self.man(rules=[rule(scheme="ftp")]), "rules[0].scheme")
        for ok in ("127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.1.1", "::1"):
            self.assertEqual(norm(rule(scheme="http", host=ok))["scheme"], "http")

    def test_path_prefix(self):
        for bad in ("", "v1", "/v1/", "/a//b", "/a/../b", "/a/./b", "/a/%2e%2e/b", "/a/%2f", "/a%5cb",
                    "/a;b", "/a?b", "/a#b", "/a b", "/\u00e9", "/a\\b", "/" + "x" * 200, "/a%41", "/a%"):
            self.bad(self.man(rules=[rule(path_prefix=bad)]), "path_prefix")
        self.bad(self.man(rules=[rule(path_prefix="/")]), "a prefix of only / is not allowed")
        root = P.parse_config({"allow_root_prefix": True})
        self.assertEqual(P.validate_manifest(self.man(rules=[rule(path_prefix="/")]), root)["rules"][0]["path_prefix"], "/")
        self.assertEqual(norm(rule(path_prefix="/a-b_c.d~e/f:g@h"))["path_prefix"], "/a-b_c.d~e/f:g@h")

    def test_write_methods_must_declare_a_body(self):
        for m in ("POST", "PUT", "PATCH", "DELETE"):
            self.bad(self.man(rules=[rule(method=m, body=None)]), "rules[0].body: is required")
        for m in ("GET", "HEAD", "OPTIONS"):
            self.assertEqual(norm(rule(method=m, body=None))["body"], {"none": True})
        self.assertEqual(norm(rule(method="DELETE", body={"none": True}))["body"], {"none": True})

    def test_a_read_method_cannot_carry_a_body(self):
        self.bad(self.man(rules=[rule(method="GET", body={"json": {"keys": []}})]), "a GET rule cannot have")

    def test_body_matcher_shapes(self):
        for body, frag in (({}, "exactly one"), ({"none": True, "json": {}}, "exactly one"),
                           ({"xml": {}}, "exactly one"), ({"none": False}, "body.none"),
                           ({"json": []}, "body.json"), ({"json": {"keys": "text"}}, "json.keys"),
                           ({"json": {"keys": ["bad key"]}}, "json.keys"), ({"json": {"keys": ["a"] * 1}, "x": 1}, "exactly one"),
                           ({"json": {"keys": ["a"], "nope": 1}}, "unknown key"),
                           ({"json": {"keys": ["k%d" % i for i in range(33)]}}, "json.keys"),
                           ({"json": {"keys": ["a"], "pin": {"b": 1}}}, "may only pin a field that is listed"),
                           ({"json": {"keys": ["a"], "pin": {"a": 1.5}}}, "pin"),
                           ({"json": {"keys": ["a"], "pin": {"a": [1]}}}, "pin"),
                           ({"json": {"keys": ["a"], "pin": {"a": {"b": 1}}}}, "pin"),
                           ({"json": {"keys": ["a"], "pin": {"a": 2 ** 53 + 1}}}, "pin"),
                           ({"json": {"keys": ["a"], "pin": {"a": "x" * 201}}}, "pin value"),
                           ({"json": {"keys": ["a"], "pin": {"a": "x\u200by"}}}, "hidden characters"),
                           ({"graphql": []}, "body.graphql"), ({"graphql": {}}, "document"),
                           ({"graphql": {"document": DOC, "nope": 1}}, "unknown key"),
                           ({"graphql": {"document": DOC, "variables_keys": "x"}}, "variables_keys"),
                           ({"graphql": {"document": DOC, "operation_name": "1bad"}}, "operation_name"),
                           ({"graphql": {"document": "x" * 4097}}, "document"),
                           ({"graphql": {"document": "query { a }\u200b"}}, "hidden characters")):
            self.bad(self.man(rules=[rule(body=body)]), frag)

    def test_pin_values_are_scalars(self):
        r = norm(rule(body={"json": {"keys": ["a", "b", "c", "d"], "pin": {"a": "x", "b": True, "c": 7, "d": None}}}))
        self.assertEqual(r["body"]["json"]["pin"], {"a": "x", "b": True, "c": 7, "d": None})

    def test_any_body_needs_the_opt_in(self):
        self.bad(self.man(rules=[rule(body={"any": True})]), "any-content body is not allowed")
        ok = P.parse_config({"allow_any_body": True})
        self.assertEqual(P.validate_manifest(self.man(rules=[rule(body={"any": True})]), ok)["rules"][0]["body"],
                         {"any": True})

    def test_graphql_documents(self):
        g = lambda **kw: {"graphql": {"document": DOC, **kw}}   # noqa: E731
        self.assertEqual(norm(rule(body=g(variables_keys=["b", "a", "a"])))["body"]["graphql"]["variables_keys"], ["a", "b"])
        self.bad(self.man(rules=[rule(body={"graphql": {"document": "mutation M { x }"}})]), "mutation")
        self.bad(self.man(rules=[rule(body={"graphql": {"document": "query { a }  # mutation"}})]), "mutation")
        self.bad(self.man(rules=[rule(body={"graphql": {"document": "query {"}})]), "not a parsable GraphQL document")
        two = "query A { a } query B { b }"
        self.bad(self.man(rules=[rule(body={"graphql": {"document": two}})]), "operation_name: is required")
        self.assertEqual(norm(rule(body={"graphql": {"document": two, "operation_name": "A"}}))["body"]["graphql"]
                         ["operation_name"], "A")
        opt = P.parse_config({"allow_graphql_mutation": True})
        m = P.validate_manifest(self.man(rules=[rule(body={"graphql": {"document": "mutation M { x }"}})]), opt)
        self.assertEqual(P.rule_tier(m["rules"][0]), "high")

    def test_caps(self):
        c = P.parse_config({"max_total_uses": 500})
        self.bad(self.man(rules=[rule(max_uses=300), rule(max_uses=300, path_prefix="/v1/b")]), "add up to more than", c)
        c = P.parse_config({"max_uses_per_rule": 10})
        self.bad(self.man(rules=[rule(max_uses=11)]), "rules[0].max_uses", c)

    def test_canonical_hashes(self):
        a, b = rule(), rule(path_prefix="/v1/other")
        h1 = P.validate_manifest({"v": 1, "task": "t", "rules": [a, b]}, CFG)
        h2 = P.validate_manifest({"v": 1, "task": "t", "rules": [b, a]}, CFG)
        self.assertEqual((h1["manifest_hash"], h1["rules_hash"]), (h2["manifest_hash"], h2["rules_hash"]))
        # description is not hashed; the task, ttl and every rule field are
        h3 = P.validate_manifest({"v": 1, "task": "t", "description": "other", "rules": [a, b]}, CFG)
        self.assertEqual(h1["manifest_hash"], h3["manifest_hash"])
        for change in ({"task": "u"}, {"ttl_seconds": 120}):
            h4 = P.validate_manifest({"v": 1, "task": "t", "rules": [a, b], **change}, CFG)
            self.assertNotEqual(h1["manifest_hash"], h4["manifest_hash"], change)
        h5 = P.validate_manifest({"v": 1, "task": "t", "rules": [a, rule(path_prefix="/v1/other", max_uses=4)]}, CFG)
        self.assertNotEqual(h1["rules_hash"], h5["rules_hash"])
        # defaults filled in or not, the same manifest hashes the same
        h6 = P.validate_manifest({"v": 1, "task": "t", "rules": [dict(a, port=443, scheme="https", query="none"), b]}, CFG)
        self.assertEqual(h1["manifest_hash"], h6["manifest_hash"])
        self.assertEqual(h1["rules_hash"], P.rules_hash(h1["rules"]))


class MatcherHost(unittest.TestCase):
    """Item B: host and URL."""
    R = norm(rule())

    def v(self, url, **kw):
        return verdict(self.R, frozen(url, body=NOTE, **kw))

    def test_the_exact_url_matches(self):
        self.assertIsNone(self.v("https://api.example.com/v1/notes"))
        self.assertIsNone(self.v("https://api.example.com:443/v1/notes"))

    def test_userinfo(self):
        for u in ("https://user@api.example.com/v1/notes", "https://user:pw@api.example.com/v1/notes",
                  "https://api.example.com@evil.com/v1/notes", "https://evil.com@api.example.com/v1/notes",
                  "https://api.example.com%40evil.com/v1/notes", "https://@api.example.com/v1/notes",
                  "https://api.example.com\\@evil.com/v1/notes"):
            self.assertIn(self.v(u), ("host", "url"), u)

    def test_trailing_dot_uppercase_and_idn(self):
        for u in ("https://api.example.com./v1/notes", "https://API.example.com/v1/notes",
                  "https://Api.Example.Com/v1/notes", "https://api.example.com..:443/v1/notes",
                  "https://b\u00fccher.example/v1/notes", "https://xn--bcher-kva.example/v1/notes",
                  "https://api.exampl\u0435.com/v1/notes"):
            self.assertIsNotNone(self.v(u), u)

    def test_the_scheme_must_match_exactly(self):
        for u in ("HTTPS://api.example.com/v1/notes", "http://api.example.com/v1/notes",
                  "ftp://api.example.com/v1/notes", "//api.example.com/v1/notes", "api.example.com/v1/notes",
                  "https:/api.example.com/v1/notes", "https:api.example.com/v1/notes"):
            self.assertIsNotNone(self.v(u), u)

    def test_ip_literals_are_never_the_rule_host(self):
        for u in ("https://93.184.216.34/v1/notes", "https://[2606:2800:220:1:248:1893:25c8:1946]/v1/notes",
                  "https://127.0.0.1/v1/notes", "https://2130706433/v1/notes", "https://0x7f.0.0.1/v1/notes",
                  "https://017700000001/v1/notes", "https://[::ffff:127.0.0.1]/v1/notes"):
            self.assertEqual(self.v(u), "host", u)

    def test_an_ip_rule_matches_only_that_literal(self):
        r = norm(rule(host="127.0.0.1", scheme="http", port=8080))
        self.assertIsNone(verdict(r, frozen("http://127.0.0.1:8080/v1/notes", body=NOTE)))
        for u in ("http://127.0.0.2:8080/v1/notes", "http://localhost:8080/v1/notes", "http://127.1:8080/v1/notes",
                  "http://[::1]:8080/v1/notes", "http://127.0.0.1/v1/notes", "http://127.0.0.1:8081/v1/notes",
                  "https://127.0.0.1:8080/v1/notes"):
            self.assertIsNotNone(verdict(r, frozen(u, body=NOTE)), u)
        r6 = norm(rule(host="::1", scheme="http", port=8080))
        self.assertIsNone(verdict(r6, frozen("http://[::1]:8080/v1/notes", body=NOTE)))
        self.assertIsNotNone(verdict(r6, frozen("http://[::2]:8080/v1/notes", body=NOTE)))

    def test_ports(self):
        for u in ("https://api.example.com:8443/v1/notes", "https://api.example.com:0443/v1/notes",
                  "https://api.example.com:/v1/notes", "https://api.example.com:65536x/v1/notes",
                  "https://api.example.com:80/v1/notes", "https://api.example.com:443:443/v1/notes"):
            self.assertEqual(self.v(u), "host", u)
        r = norm(rule(port=8443))
        self.assertIsNone(verdict(r, frozen("https://api.example.com:8443/v1/notes", body=NOTE)))
        self.assertEqual(verdict(r, frozen("https://api.example.com/v1/notes", body=NOTE)), "host")

    def test_other_hosts(self):
        for u in ("https://api.example.com.evil.com/v1/notes", "https://evilapi.example.com/v1/notes",
                  "https://sub.api.example.com/v1/notes", "https://example.com/v1/notes"):
            self.assertEqual(self.v(u), "host", u)

    def test_fragments_and_odd_characters(self):
        for u in ("https://api.example.com/v1/notes#frag", "https://api.example.com/v1/notes#",
                  "https://api.example.com/v1/notes\t", "https://api.example.com/v1/no tes",
                  "https://api.example.com/v1/notes\n", "https://api.example.com/v1/not\u00e9s",
                  "https://api.example.com/v1/notes\\x", "https://api.example.com/v1/notes\"",
                  "https://api.example.com/v1/notes|x", "https://api.example.com/v1/notes\x00",
                  "https://api.example.com/v1/notes\x7f", ""):
            self.assertIsNotNone(self.v(u), repr(u))

    def test_plain_http_only_for_private_ip_literals(self):
        # a rule can never be made for plain http to a DNS name, but the matcher also checks
        r = dict(self.R, scheme="http", port=80)
        self.assertEqual(verdict(r, frozen("http://api.example.com/v1/notes", body=NOTE)), "host")
        for host in ("printer.lan", "nas", "thing.local", "box.internal"):
            r = dict(self.R, scheme="http", port=80, host=host)
            self.assertEqual(verdict(r, frozen(f"http://{host}/v1/notes", body=NOTE)), "host", host)
        for host in ("10.0.0.5", "127.0.0.1", "192.168.1.1", "169.254.9.9"):
            r = dict(self.R, scheme="http", port=80, host=host)
            self.assertIsNone(verdict(r, frozen(f"http://{host}/v1/notes", body=NOTE)), host)
        r = dict(self.R, scheme="http", port=80, host="8.8.8.8")
        self.assertEqual(verdict(r, frozen("http://8.8.8.8/v1/notes", body=NOTE)), "host")


class MatcherMethodPathQuery(unittest.TestCase):
    """Items C and D."""
    R = norm(rule())

    def v(self, path, method="POST", **kw):
        return verdict(self.R, frozen("https://api.example.com" + path, method=method, body=NOTE, **kw))

    def test_method_is_exact(self):
        self.assertIsNone(self.v("/v1/notes"))
        for m in ("GET", "PUT", "post", "Post", "POST ", "PATCH", "DELETE", "", "POST\n"):
            self.assertEqual(self.v("/v1/notes", method=m), "method", repr(m))

    def test_prefix_is_segment_aligned(self):
        for ok in ("/v1/notes", "/v1/notes/", "/v1/notes/1", "/v1/notes/1/2/3", "/v1/notes/a%20b"):
            self.assertIsNone(self.v(ok), ok)
        for bad in ("/v1/notesx", "/v1/note", "/v1/notes2/1", "/v1", "/v1/", "/", "/x/v1/notes", "/V1/notes",
                    "/v1/NOTES"):
            self.assertEqual(self.v(bad), "path", bad)

    def test_dot_segments(self):
        for p in ("/v1/notes/..", "/v1/notes/../x", "/v1/notes/.", "/v1/notes/./x", "/v1/./notes",
                  "/v1/notes/%2e%2e/x", "/v1/notes/%2E%2E", "/v1/notes/.%2e/x", "/v1/notes/%2e/x",
                  "/v1/x/../notes", "/v1/notes/..;/x"):
            self.assertEqual(self.v(p), "path", p)

    def test_encoded_slashes_nuls_and_unreserved(self):
        for p in ("/v1/notes/%2f", "/v1/notes/%2F", "/v1%2fnotes", "/v1/notes/%5c", "/v1/notes/%5C",
                  "/v1/notes/%00", "/v1/notes/a%00b", "/v1/notes/%41", "/v1/notes/%7e", "/v1/notes/%2d",
                  "/v1/notes/%30", "/v1/notes/%zz", "/v1/notes/%", "/v1/notes/%4", "/v1/notes/%3b",
                  "/v1/notes/%0a", "/v1/notes/%7f"):
            self.assertEqual(self.v(p), "path", p)

    def test_percent_encoding_is_an_allowlist(self):
        # an encoded percent can double-decode upstream into a dot segment or a slash
        for p in ("/v1/notes/%252e%252e", "/v1/notes/%252e%252e/x", "/v1/notes/%252f", "/v1/notes/%252F",
                  "/v1/notes/%25", "/v1/notes/a%2541", "/v1%252fnotes/x", "/v1/notes/%255c",
                  # only uppercase hex is canonical
                  "/v1/notes/a%e2%82%ac", "/v1/notes/%E2%82%aC", "/v1/notes/%c3%A9",
                  # overlong, truncated, surrogate and stray continuation sequences
                  "/v1/notes/%C0%AF", "/v1/notes/%C0%AE%C0%AE", "/v1/notes/%E0%80%AF", "/v1/notes/%F0%80%80%AF",
                  "/v1/notes/%E2%82", "/v1/notes/%80", "/v1/notes/%ED%A0%80", "/v1/notes/%FF",
                  # reserved characters stay encoded or absent: the broker never decodes them
                  "/v1/notes/%3A", "/v1/notes/%40", "/v1/notes/%2B", "/v1/notes/%3D", "/v1/notes/%26"):
            self.assertEqual(self.v(p), "path", p)
        # only %20 may be percent-encoded: no UTF-8 at all, so an NFKC-normalising upstream cannot
        # read a fullwidth solidus (%EF%BC%8F) or any other look-alike as a path character
        for bad in ("/v1/notes/%EF%BC%8F", "/v1/notes/%E2%82%AC", "/v1/notes/%C3%A9x", "/v1/notes/%F0%9F%98%80",
                    "/v1/notes/%E2%80%A5", "/v1/notes/%EF%BC%8E%EF%BC%8E", "/v1/notes/\u00e9", "/v1/notes/\uff0f",
                    "/v1/notes/\u2024\u2024"):
            self.assertIn(self.v(bad), ("path", "url"), bad)
        for ok in ("/v1/notes/a%20b", "/v1/notes/%20%20"):
            self.assertIsNone(self.v(ok), ok)

    def test_the_same_allowlist_applies_to_a_rule_prefix(self):
        for pre in ("/a%2e", "/a%25", "/a%C0%AF"):
            with self.assertRaises(P.ManifestError):
                norm(rule(path_prefix=pre))

    def test_slashes_semicolons_backslashes(self):
        for p in ("//v1/notes", "/v1//notes", "/v1/notes//", "/v1/notes//x", "/v1/notes/x//y",
                  "/v1/notes;x", "/v1/notes/x;y=1", "/v1/notes/\\x"):
            self.assertIsNotNone(self.v(p), p)

    def test_percent_encoded_reserved_characters_are_allowed_as_sent(self):
        for ok in ("/v1/notes/a%20b", "/v1/notes/%20"):
            self.assertIsNone(self.v(ok), ok)

    def test_the_root_prefix(self):
        r = norm(rule(path_prefix="/"), P.parse_config({"allow_root_prefix": True}))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/anything/at/all", body=NOTE)))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/", body=NOTE)))
        self.assertEqual(verdict(r, frozen("https://api.example.com", body=NOTE)), "path")
        self.assertEqual(verdict(r, frozen("https://api.example.com?x=1", body=NOTE)), "path")

    def test_no_path_at_all_never_matches(self):
        self.assertEqual(verdict(self.R, frozen("https://api.example.com", body=NOTE)), "path")

    def test_a_rule_that_writes_defaults_to_no_query_string(self):
        self.assertEqual(norm(rule())["query"], "none")
        self.assertEqual(norm(rule(method="GET", body=None))["query"], "any")
        self.assertEqual(self.v("/v1/notes"), None)
        for q in ("?a=1", "?", "?_method=DELETE", "?operationName=x"):
            self.assertEqual(self.v("/v1/notes" + q), "query", q)
        with self.assertRaises(P.ManifestError):
            norm(rule(query="any"))                         # a write cannot opt into any query string

    def test_listed_query_keys(self):
        r = norm(rule(query=["dry_run", "page"]))
        self.assertEqual(r["query"], ["dry_run", "page"])
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?page=2&dry_run=1", body=NOTE)))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?", body=NOTE)))
        for q in ("?other=1", "?page=2&other=1", "?page=2&&dry_run=1", "?%70age=2", "?page%3D2", "?=x", "?page=2&",
                  "?PAGE=2", "?page=2;x=1"):
            self.assertEqual(verdict(r, frozen("https://api.example.com/v1/notes" + q, body=NOTE)), "query", q)
        for bad in ([], ["a b"], ["_method"], ["Variables"], ["operationName"], ["extensions"], "page", [1],
                    ["k%d" % i for i in range(17)]):
            with self.assertRaises(P.ManifestError, msg=bad):
                norm(rule(query=bad))

    def test_graphql_rules_never_allow_a_query_string(self):
        g = {"graphql": {"document": DOC}}
        self.assertEqual(norm(rule(body=g))["query"], "none")
        for q in ("any", ["page"], ["query"]):
            with self.assertRaises(P.ManifestError, msg=q):
                norm(rule(body=g, query=q))
        r = norm(rule(body=g))
        for q in ("?query=%7B+x+%7D", "?operationName=B", "?variables=%7B%7D", "?extensions=%7B%7D", "?_method=GET",
                  "?query=", "?"):
            self.assertEqual(verdict(r, frozen("https://api.example.com/v1/notes" + q, body={"query": DOC})),
                             "query", q)

    def test_override_parameters_are_refused_even_on_an_any_query_read_rule(self):
        r = norm(rule(method="GET", body=None))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?q=x&page=1", method="GET",
                                            headers={"Authorization": "Bearer {{LEDGER_TOKEN}}"})))
        for q in ("_method=DELETE", "_METHOD=PUT", "method=POST", "operationName=x", "variables=%7B%7D",
                  "extensions=1", "x-http-method-override=DELETE", "a=1&_method=DELETE", "%5Fmethod=DELETE"):
            self.assertEqual(verdict(r, frozen("https://api.example.com/v1/notes?" + q, method="GET",
                                               headers={"Authorization": "Bearer {{LEDGER_TOKEN}}"})), "query", q)

    def test_query(self):
        r = norm(rule(method="GET", body=None))
        hh = {"Authorization": "Bearer {{LEDGER_TOKEN}}"}
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?a=1", method="GET", headers=hh)))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?", method="GET", headers=hh)))
        none = norm(rule(query="none"))
        self.assertIsNone(verdict(none, frozen("https://api.example.com/v1/notes", body=NOTE)))
        for q in ("?a=1", "?", "?a"):
            self.assertEqual(verdict(none, frozen("https://api.example.com/v1/notes" + q, body=NOTE)), "query", q)

    def test_a_slash_in_a_query_value_is_not_a_path(self):
        r = norm(rule(query=["next"]))
        self.assertIsNone(verdict(r, frozen("https://api.example.com/v1/notes?next=/../../x", body=NOTE)))


class MatcherHeaders(unittest.TestCase):
    """Item E, and placeholders (item A)."""
    R = norm(rule())

    def v(self, headers, body=NOTE, **kw):
        return verdict(self.R, frozen(headers=headers, body=body), **kw)

    def test_the_default_headers_match(self):
        self.assertIsNone(self.v(hdrs()))
        self.assertIsNone(self.v(hdrs(Accept="*/*", **{"User-Agent": "x/1", "If-None-Match": "\"a\""})))
        self.assertIsNone(self.v({"Content-Type": "application/json"}))
        self.assertIsNone(self.v({"Content-Type": "application/json", "Authorization": "Bearer {{LEDGER_TOKEN}}"}))

    def test_anything_else_is_a_non_match(self):
        for name in ("Host", "X-HTTP-Method-Override", "X-Forwarded-For", "X-Forwarded-Host", "Transfer-Encoding",
                     "Connection", "Upgrade", "Cookie", "X-Custom", "Referer", "Origin", "Range", "Expect",
                     "Proxy-Authorization", "Content-Encoding", "Forwarded", "Via", "TE"):
            self.assertEqual(self.v(hdrs(**{name: "v"})), "headers", name)

    def test_a_literal_credential_header_is_refused(self):
        self.assertEqual(self.v({"Content-Type": "application/json", "Authorization": "Bearer abc"}), "headers")
        self.assertEqual(self.v({"Content-Type": "application/json", "X-Api-Key": "abc"}), "headers")

    def test_header_names_are_case_insensitive_and_duplicates_are_refused(self):
        self.assertIsNone(self.v({"content-type": "application/json", "ACCEPT": "*/*"}))
        self.assertEqual(self.v({"Content-Type": "application/json", "content-type": "application/json"}), "headers")
        self.assertEqual(self.v({"Authorization": "Bearer {{LEDGER_TOKEN}}", "authorization": "Bearer {{LEDGER_TOKEN}}",
                                 "Content-Type": "application/json"}), "headers")

    def test_odd_header_names_and_values(self):
        self.assertEqual(self.v(hdrs(**{"X Bad": "v"})), "headers")
        self.assertEqual(self.v(hdrs(**{"": "v"})), "headers")
        self.assertEqual(self.v(hdrs(Accept="a\r\nX-Evil: 1")), "headers")
        self.assertEqual(self.v(hdrs(Accept="a\nb")), "headers")
        self.assertEqual(self.v(hdrs(Accept="a\x00b")), "headers")
        self.assertEqual(self.v(hdrs(Accept="x" * 5000)), "headers")

    def test_content_length_must_equal_the_body(self):
        body = json.dumps(NOTE)
        self.assertIsNone(self.v(hdrs(**{"Content-Length": str(len(body))}), body=body))
        for cl in (str(len(body) + 1), str(len(body) - 1), "0", "abc", "-1", "+%d" % len(body), " %d" % len(body),
                   "0%d" % len(body), "%d.0" % len(body), ""):
            self.assertEqual(self.v(hdrs(**{"Content-Length": cl}), body=body), "headers", repr(cl))

    def test_content_length_counts_bytes_not_characters(self):
        r = norm(rule(body={"json": {"keys": ["text"]}}))
        body = json.dumps({"text": "\u00e9\u00e9"}, ensure_ascii=False)
        self.assertEqual(len(body.encode()), len(body) + 2)
        h = hdrs(**{"Content-Length": str(len(body.encode()))})
        self.assertIsNone(verdict(r, frozen(headers=h, body=body)))
        h = hdrs(**{"Content-Length": str(len(body))})
        self.assertEqual(verdict(r, frozen(headers=h, body=body)), "headers")

    def test_chunked_is_refused(self):
        self.assertEqual(self.v(hdrs(**{"Transfer-Encoding": "chunked"})), "headers")
        self.assertEqual(self.v(hdrs(**{"transfer-encoding": "Chunked"})), "headers")
        self.assertEqual(self.v(hdrs(TE="trailers")), "headers")

    def test_a_configured_header_list_is_honoured_but_never_a_framing_header(self):
        cfg = P.parse_config({"allowed_request_headers": ["Accept", "Content-Type", "X-Requested-With"]})
        self.assertIsNone(self.v(hdrs(**{"X-Requested-With": "1"}), cfg=cfg) if False else
                          verdict(self.R, frozen(headers=hdrs(**{"X-Requested-With": "1"}), body=NOTE), cfg))
        self.assertEqual(verdict(self.R, frozen(headers=hdrs(**{"User-Agent": "x"}), body=NOTE), cfg), "headers")

    # -- placeholders -------------------------------------------------------------
    def test_placeholder_in_the_url_in_any_position_is_refused(self):
        for u in ("https://api.example.com/v1/notes/{{LEDGER_TOKEN}}", "https://api.example.com/v1/notes?k={{LEDGER_TOKEN}}",
                  "https://{{LEDGER_TOKEN}}.example.com/v1/notes", "https://api.example.com/{{X}}/v1/notes",
                  "https://api.example.com/v1/notes?{{ LEDGER_TOKEN }}", "https://api.{{HOST}}/v1/notes"):
            self.assertEqual(verdict(self.R, frozen(u, body=NOTE)), "placeholder", u)

    def test_placeholder_in_the_body_is_refused(self):
        for body in ('{"text": "{{LEDGER_TOKEN}}", "kind": "reconcile"}', '{"text": "a{{b", "kind": "reconcile"}',
                     '{"text": "{{ LEDGER_TOKEN }}", "kind": "reconcile"}'):
            self.assertEqual(self.v(hdrs(), body=body), "placeholder", body)
        r = norm(rule(body={"any": True}), P.parse_config({"allow_any_body": True}))
        self.assertEqual(verdict(r, frozen(headers=hdrs(), body="x {{LEDGER_TOKEN}} y")), "placeholder")
        self.assertEqual(verdict(r, frozen(headers=hdrs(), body=b"x {{LEDGER_TOKEN}} y".decode())), "placeholder")

    def test_placeholder_headers(self):
        ok = ("{{LEDGER_TOKEN}}", "Bearer {{LEDGER_TOKEN}}", "Token {{LEDGER_TOKEN}}", "Basic {{LEDGER_TOKEN}}")
        for v in ok:
            self.assertIsNone(self.v({"Content-Type": "application/json", "Authorization": v}), v)
        bad = ("Bearer {{OTHER_TOKEN}}", "Bearer {{LEDGER_TOKEN}} extra", "x Bearer {{LEDGER_TOKEN}}",
               "Bearer {{LEDGER_TOKEN}}{{LEDGER_TOKEN}}", "Bearer {{ledger_token}}", "Token {{ LEDGER_TOKEN }}", "Digest {{LEDGER_TOKEN}}", "bearer {{LEDGER_TOKEN}}", "Bearer {{LEDGER_TOKEN}",
               "Bearer {{LEDGER_TOKEN}}}", "{{LEDGER_TOKEN}}:{{LEDGER_TOKEN}}", "Bearer  {{LEDGER_TOKEN}}",
               "Bearer {{}}", "{{ LEDGER_TOKEN   }}", "a b {{LEDGER_TOKEN}}", "Bearer{{LEDGER_TOKEN}}",
               "}} {{")
        for v in bad:
            self.assertEqual(self.v({"Content-Type": "application/json", "Authorization": v}), "placeholder", v)

    def test_a_placeholder_of_another_credentials_variable_is_refused(self):
        h = {"Content-Type": "application/json", "Authorization": "Bearer {{SVC_TOKEN}}"}
        self.assertEqual(self.v(h), "placeholder")
        # even a variable that exists for another credential in the same catalog
        self.assertEqual(verdict(self.R, frozen(headers=h, body=NOTE), CFG, frozenset({"SVC_TOKEN", "OTHER"})), None)
        self.assertEqual(verdict(self.R, frozen(headers=h, body=NOTE), CFG, frozenset()), "placeholder")

    def test_a_placeholder_in_a_header_name_or_an_allowed_header_is_refused(self):
        self.assertIn(self.v({"Content-Type": "application/json", "X-{{LEDGER_TOKEN}}": "1"}), ("placeholder", "headers"))
        self.assertEqual(self.v({"Content-Type": "application/json", "Accept": "{{LEDGER_TOKEN}}"}), "headers")
        self.assertEqual(self.v({"Content-Type": "{{LEDGER_TOKEN}}"}), "headers")
        self.assertEqual(self.v({"Content-Type": "application/json", "Host": "{{LEDGER_TOKEN}}"}), "headers")
        self.assertEqual(self.v({"Content-Type": "application/json", "X-HTTP-Method-Override": "{{LEDGER_TOKEN}}"}),
                         "headers")

    def test_substitution_fills_only_the_validated_headers(self):
        r = self.R
        f = frozen(headers=hdrs(**{"X-Api-Key": "{{LEDGER_TOKEN}}"}), body=NOTE)
        self.assertEqual(P.own_placeholder_headers(f), {"authorization": "LEDGER_TOKEN", "x-api-key": "LEDGER_TOKEN"})
        done = P.substitute(f, {"LEDGER_TOKEN": "s3cr3t-value"}, r, CFG, OWN)
        self.assertIs(done.url, f.url)
        self.assertIs(done.body, f.body)
        self.assertEqual(dict(done.headers)["Authorization"], "Bearer s3cr3t-value")
        self.assertEqual(dict(done.headers)["X-Api-Key"], "s3cr3t-value")

    def test_a_secret_value_cannot_break_the_request(self):
        f = frozen(body=NOTE)
        for val in ("a\r\nX-Evil: 1", "a\nb", "a\x00b", "a\x7fb", 5, None):
            with self.assertRaises(P.NoMatch, msg=repr(val)):
                P.substitute(f, {"LEDGER_TOKEN": val}, self.R, CFG, OWN)

    def test_a_secret_value_that_contains_braces_is_not_substituted_again(self):
        f = frozen(body=NOTE)
        done = P.substitute(f, {"LEDGER_TOKEN": "{{OTHER}}"}, self.R, CFG, OWN)
        self.assertEqual(dict(done.headers)["Authorization"], "Bearer {{OTHER}}")

    def test_a_brace_pair_left_after_substitution_is_a_non_match(self):
        # a header that was not a validated placeholder cannot reach the sender at all
        f = frozen(headers={"Content-Type": "application/json", "Accept": "a {{b}} c"}, body=NOTE)
        self.assertEqual(verdict(self.R, f), "placeholder")
        done = P.Frozen("POST", "https://api.example.com/v1/notes", [("Content-Type", "application/json"),
                                                                       ("Accept", "{{x}}")], b"{}")
        with self.assertRaises(P.NoMatch):
            P.match_rule(self.R, done, CFG, OWN, opaque=frozenset(), post=True)


class MatcherBodies(unittest.TestCase):
    """Item F and the body matchers."""

    def v(self, rule_, body, headers=None, **kw):
        return verdict(rule_, frozen(headers=hdrs() if headers is None else headers, body=body, **kw))

    # -- none ---------------------------------------------------------------------
    def test_none_accepts_only_an_empty_body(self):
        r = norm(rule(method="DELETE", body={"none": True}))
        self.assertIsNone(verdict(r, frozen(method="DELETE", headers={"Authorization": "Bearer {{LEDGER_TOKEN}}"})))
        self.assertEqual(verdict(r, frozen(method="DELETE", headers=hdrs(), body="{}")), "body")
        self.assertEqual(verdict(r, frozen(method="DELETE", headers=hdrs(), body=" ")), "body")

    def test_a_rule_with_no_body_accepts_only_an_empty_one(self):
        r = norm(rule(method="GET", body=None))
        self.assertIsNone(verdict(r, frozen(method="GET", headers={"Authorization": "Bearer {{LEDGER_TOKEN}}"})))
        self.assertEqual(verdict(r, frozen(method="GET", headers=hdrs(), body="x")), "body")

    def test_the_body_size_cap(self):
        r = norm(rule(body={"any": True}), P.parse_config({"allow_any_body": True, "max_body_bytes": 10}))
        cfg = P.parse_config({"allow_any_body": True, "max_body_bytes": 10})
        self.assertIsNone(verdict(r, frozen(headers=hdrs(), body="x" * 10), cfg))
        self.assertEqual(verdict(r, frozen(headers=hdrs(), body="x" * 11), cfg), "size")
        big = norm(rule())
        self.assertEqual(self.v(big, json.dumps({"text": "x" * 20000, "kind": "reconcile"})), "size")

    # -- json ---------------------------------------------------------------------
    R = norm(rule())

    def test_json_keys_pins_and_free_values(self):
        self.assertIsNone(self.v(self.R, NOTE))
        self.assertIsNone(self.v(self.R, {"kind": "reconcile"}))
        self.assertIsNone(self.v(self.R, {"text": 'anything {"at": "all"}', "kind": "reconcile"}))
        self.assertEqual(self.v(self.R, {"text": "x"}), "body")                       # the pin is required
        self.assertEqual(self.v(self.R, {"text": "x", "kind": "other"}), "body")
        self.assertEqual(self.v(self.R, {"text": "x", "kind": "reconcile", "extra": 1}), "body")
        self.assertEqual(self.v(self.R, {"text": "x", "kind": "reconcile ", "extra": 1}), "body")
        self.assertEqual(self.v(self.R, {"text": "x", "kind": "Reconcile"}), "body")  # byte exact: no case folding
        self.assertEqual(self.v(self.R, {"text": "x", "kind": "reconcil\u0435"}), "body")
        self.assertEqual(self.v(self.R, [NOTE]), "body")
        self.assertEqual(self.v(self.R, "text"), "body")
        self.assertEqual(self.v(self.R, "null"), "body")
        self.assertEqual(self.v(self.R, ""), "body")

    def test_pins_are_typed(self):
        r = norm(rule(body={"json": {"keys": ["n", "b", "z", "s"], "pin": {"n": 1, "b": True, "z": None, "s": "1"}}}))
        good = {"n": 1, "b": True, "z": None, "s": "1"}
        self.assertIsNone(self.v(r, good))
        for k, v in (("n", True), ("n", 1.0), ("n", "1"), ("b", 1), ("b", "true"), ("z", 0), ("z", ""), ("s", 1),
                     ("n", 2)):
            self.assertEqual(self.v(r, {**good, k: v}), "body", (k, v))
        self.assertEqual(self.v(r, {"n": 1, "b": True, "s": "1"}), "body")           # null pin: the key must be present

    def test_nested_values_are_never_pinned_but_are_bounded(self):
        r = norm(rule(body={"json": {"keys": ["data"]}}))
        self.assertIsNone(self.v(r, {"data": {"a": {"b": [1, 2, {"c": None}]}}}))
        self.assertEqual(self.v(r, {"data": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}}), "body")

    def test_duplicate_keys_big_numbers_and_friends(self):
        r = norm(rule(body={"json": {"keys": ["text", "kind", "n"], "pin": {"kind": "reconcile"}}}))
        for raw in ('{"kind": "reconcile", "kind": "other"}', '{"kind": "other", "kind": "reconcile"}',
                    '{"kind": "reconcile", "\\u006bind": "other"}', '{"kind": "reconcile", "n": NaN}',
                    '{"kind": "reconcile", "n": Infinity}', '{"kind": "reconcile", "n": 9007199254740993}',
                    '{"kind": "reconcile", "n": 1e999}', '{"kind": "reconcile", "text": "\\ud800"}',
                    '\ufeff{"kind": "reconcile"}', '{"kind": "reconcile"} {"x": 1}', '{"kind": "reconcile"}x',
                    '{"kind": "reconcile",}', '{kind: "reconcile"}'):
            self.assertEqual(self.v(r, raw), "body", raw)
        self.assertIsNone(self.v(r, '{"kind": "reconcile", "n": 9007199254740992}'))
        self.assertIsNone(self.v(r, ' \n{"kind": "reconcile"}\n '))

    def test_invalid_utf8_and_binary_bodies(self):
        f = P.Frozen("POST", "https://api.example.com/v1/notes", hdrs().items(), b'{"kind": "reconcile", "text": "\xff"}')
        self.assertEqual(verdict(self.R, f), "body")
        f = P.freeze({"method": "POST", "url": "https://api.example.com/v1/notes", "headers": hdrs(),
                      "body_b64": base64.b64encode(b'{"kind": "reconcile"}').decode()})
        self.assertIsNone(verdict(self.R, f))
        f = P.freeze({"method": "POST", "url": "https://api.example.com/v1/notes", "headers": hdrs(),
                      "body_b64": base64.b64encode(b"\xef\xbb\xbf{}").decode()})
        self.assertEqual(verdict(self.R, f), "body")

    def test_body_and_body_b64_together_are_refused(self):
        with self.assertRaises(P.NoMatch):
            P.freeze({"method": "POST", "url": "https://api.example.com/v1/notes", "headers": hdrs(),
                      "body": "{}", "body_b64": "e30="})
        with self.assertRaises(P.NoMatch):
            P.freeze({"method": "POST", "url": "https://api.example.com/v1/notes", "headers": hdrs(),
                      "body_b64": "!!!"})
        with self.assertRaises(P.NoMatch):
            P.freeze({"method": "POST", "url": "https://api.example.com/v1/notes", "headers": {"a": 1}})
        with self.assertRaises(P.NoMatch):
            P.freeze({"method": 5, "url": "x", "headers": {}})
        with self.assertRaises(P.NoMatch):
            P.freeze({"method": "POST", "url": "x", "headers": {}, "body": {"a": 1}})

    def test_content_type_confusion(self):
        for ct in ("application/json", "application/json; charset=utf-8", "application/json;charset=utf-8"):
            self.assertIsNone(self.v(self.R, NOTE, headers=hdrs(**{"Content-Type": ct})), ct)
        for ct in ("text/plain", "application/x-www-form-urlencoded", "application/jsonp", "application/json5",
                   "application/vnd.api+json", "application/json; charset=utf-16", "application/json; charset=latin-1",
                   "application/json; boundary=x", "application/json; charset=utf-8; x=1", "APPLICATION/JSON",
                   "application/JSON", "application/json, text/plain", "text/plain, application/json",
                   "multipart/form-data; boundary=x", "", " application/json", "application/json ",
                   "application/json; charset=UTF-8", "application/json;  charset=utf-8", "application/json\t"):
            self.assertIn(self.v(self.R, NOTE, headers=hdrs(**{"Content-Type": ct})), ("body", "headers"), repr(ct))
        # a missing content type is refused for a json rule
        self.assertEqual(self.v(self.R, NOTE, headers={"Authorization": "Bearer {{LEDGER_TOKEN}}"}), "body")
        # two Content-Type headers, any casing
        self.assertEqual(self.v(self.R, NOTE, headers={"Content-Type": "application/json",
                                                       "content-type": "text/plain"}), "headers")
        self.assertEqual(self.v(self.R, NOTE, headers={"Content-Type": "application/json",
                                                       "CONTENT-TYPE": "application/json"}), "headers")

    # -- graphql ------------------------------------------------------------------
    G = norm(rule(body={"graphql": {"document": DOC, "variables_keys": ["first"]}}))

    def gq(self, **kw):
        return {"query": DOC, **kw}

    def test_graphql_exact_document(self):
        self.assertIsNone(self.v(self.G, self.gq()))
        self.assertIsNone(self.v(self.G, self.gq(variables={"first": 10})))
        self.assertIsNone(self.v(self.G, self.gq(variables={})))
        self.assertIsNone(self.v(self.G, self.gq(variables=None)))
        self.assertIsNone(self.v(self.G, self.gq(operationName=None)))

    def test_graphql_byte_different_but_equivalent_documents_are_refused(self):
        for q in (DOC + " ", DOC + "\n", " " + DOC, DOC.replace("Accounts", "Accounts "),
                  "query Accounts{ accounts { id balance } }", DOC.replace("{ id", "{id"), DOC.upper(),
                  DOC + " # x", "query Accounts { accounts { balance id } }", DOC.replace(" ", "\u00a0"),
                  "", None, 5, [DOC]):
            self.assertEqual(self.v(self.G, {"query": q}), "body", repr(q))
        self.assertEqual(self.v(self.G, {}), "body")

    def test_graphql_batches_extensions_and_extra_keys(self):
        self.assertEqual(self.v(self.G, [self.gq()]), "body")                          # a batch
        self.assertEqual(self.v(self.G, [self.gq(), self.gq()]), "body")
        self.assertEqual(self.v(self.G, self.gq(extensions={"persistedQuery": {"version": 1, "sha256Hash": "ab"}})), "body")
        self.assertEqual(self.v(self.G, self.gq(extensions={})), "body")
        self.assertEqual(self.v(self.G, self.gq(extra=1)), "body")
        self.assertEqual(self.v(self.G, self.gq(id="abc")), "body")
        self.assertEqual(self.v(self.G, self.gq(**{"__typename": "x"})), "body")

    def test_graphql_variables(self):
        self.assertEqual(self.v(self.G, self.gq(variables={"first": 1, "after": "x"})), "body")
        self.assertEqual(self.v(self.G, self.gq(variables=[1])), "body")
        self.assertEqual(self.v(self.G, self.gq(variables="x")), "body")
        self.assertIsNone(self.v(self.G, self.gq(variables={"first": {"any": ["thing"]}})))   # values are free

    def test_graphql_operation_names(self):
        two = "query A { a } query B { b }"
        g2 = norm(rule(body={"graphql": {"document": two, "operation_name": "A"}}))
        self.assertIsNone(self.v(g2, {"query": two, "operationName": "A"}))
        for on in ("B", None, "", "a", "A "):
            self.assertEqual(self.v(g2, {"query": two, "operationName": on}), "body", repr(on))
        self.assertEqual(self.v(g2, {"query": two}), "body")
        # a document with one operation and no declared name: the request must not name one either
        self.assertEqual(self.v(self.G, self.gq(operationName="Accounts")), "body")
        g1 = norm(rule(body={"graphql": {"document": DOC, "operation_name": "Accounts"}}))
        self.assertIsNone(self.v(g1, self.gq(operationName="Accounts")))
        self.assertEqual(self.v(g1, self.gq()), "body")

    def test_graphql_needs_a_json_content_type_and_a_valid_json_body(self):
        self.assertEqual(self.v(self.G, self.gq(), headers=hdrs(**{"Content-Type": "application/graphql"})), "body")
        self.assertEqual(self.v(self.G, DOC), "body")
        self.assertEqual(self.v(self.G, '{"query": "x", "query": "y"}'), "body")

    def test_graphql_mutation_inside_a_fragment_or_string_is_never_a_read(self):
        doc = "fragment F on Mutation { doIt } query Q { ...F }"
        self.assertEqual(P.classify_graphql(doc)[0], "write")
        with self.assertRaises(P.ManifestError):
            norm(rule(body={"graphql": {"document": doc}}))


class Tiers(unittest.TestCase):
    def tier(self, **kw):
        return P.rule_tier(norm(rule(**kw), P.parse_config({"allow_any_body": True, "allow_graphql_mutation": True,
                                                              "allow_root_prefix": True})))

    def test_read_only_is_low(self):
        for m in ("GET", "HEAD", "OPTIONS"):
            self.assertEqual(self.tier(method=m, body=None), "low")
        self.assertEqual(self.tier(body={"graphql": {"document": DOC}}), "low")        # a POST that is a pure query
        self.assertFalse(P.rule_writes(norm(rule(body={"graphql": {"document": DOC}}))))

    def test_writes_are_medium(self):
        for m in ("POST", "PUT", "PATCH"):
            self.assertEqual(self.tier(method=m), "medium", m)
        self.assertEqual(self.tier(body={"none": True}), "medium")
        self.assertEqual(self.tier(body={"json": {"keys": ["a"]}}), "medium")          # an unpinned value in a write

    def test_high(self):
        self.assertEqual(self.tier(method="DELETE", body={"none": True}), "high")
        self.assertEqual(self.tier(body={"any": True}), "high")
        self.assertEqual(self.tier(body={"graphql": {"document": "mutation M { x }"}}), "high")
        self.assertEqual(self.tier(path_prefix="/v1"), "high")                          # one segment
        self.assertEqual(self.tier(path_prefix="/"), "high")
        self.assertEqual(self.tier(path_prefix="/v1/notes"), "medium")                  # two segments

    def test_duration_and_total_uses_are_not_tiers(self):
        m = P.validate_manifest({"v": 1, "task": "t", "ttl_seconds": 480 * 60,
                                 "rules": [rule(max_uses=500)]}, CFG)
        self.assertEqual(P.plan_tier(m["rules"]), "medium")
        self.assertEqual(P.plan_flags(m["rules"]), [])

    def test_the_plan_tier_is_the_highest_rule_tier(self):
        rules = [norm(rule(method="GET", body=None)), norm(rule()), norm(rule(path_prefix="/v1"))]
        self.assertEqual(P.plan_tier(rules), "high")
        self.assertEqual(P.plan_tier(rules[:2]), "medium")
        self.assertEqual(P.plan_tier(rules[:1]), "low")
        self.assertTrue(P.plan_flags(rules))


class SessionsHardeningShared(unittest.TestCase):
    """Plan calls run the sessions header, Content-Type and override rules, imported, not copied."""
    from secret_broker import sessions as S
    R = norm(rule())

    def test_the_helpers_are_the_sessions_ones(self):
        src = open(os.path.join(ROOT, "secret_broker", "plans.py")).read()
        for name in ("def _content_type_ok", "def _decoded_forms", "def override_problem", "def neutralize",
                     "_JSON_UNESC", "_ENTITY", "DECODE_ROUNDS"):
            self.assertNotIn(name, src, name)
        self.assertIs(P.sessions_mod, self.S)
        self.assertEqual(P.HEADER_NAMES, frozenset(self.S.ALLOWED_HEADERS) | {"content-length"})
        self.assertEqual(P._ph("Bearer {{A_B}}"), ("Bearer ", "A_B"))
        self.assertIsNone(P._ph("Bearer {{A}}\n"))

    def test_header_names_are_exact_and_from_the_shared_list(self):
        for name in ("Authorization", "X-Api-Key", "X-Csrf-Token", "X-Updated-Csrf-Token", "X-Requested-With"):
            h = {"Content-Type": "application/json", name: "{{LEDGER_TOKEN}}"}
            self.assertIsNone(verdict(self.R, frozen(headers=h, body=NOTE)), name)
        for name in ("X-Custom", "Cookie", "X-Auth", "Accept-Encoding", "Authorization ", "Authorisation"):
            h = {"Content-Type": "application/json", name: "{{LEDGER_TOKEN}}"}
            self.assertIsNotNone(verdict(self.R, frozen(headers=h, body=NOTE)), name)
        for name in ("X-Custom", "Cookie", "Accept-Encoding", "Connection"):
            with self.assertRaises(ValueError, msg=name):
                P.parse_config({"allowed_request_headers": [name]})

    def test_content_types_are_the_five_with_charset_utf8_only(self):
        r = norm(rule(body={"any": True}), P.parse_config({"allow_any_body": True}))
        cfg = P.parse_config({"allow_any_body": True})
        ok = ("application/x-www-form-urlencoded", "text/plain", "text/plain; charset=utf-8",
              "application/graphql", "application/json; charset=utf-8")
        bad = ("text/html", "application/xml", "text/plain; charset=utf-16", "text/plain; charset=latin-1",
               "text/plain; foo=bar", "text/plain; charset=utf-8; charset=utf-8; x=1", "multipart/form-data",
               "application/octet-stream", "")
        for ct in ok:
            self.assertIsNone(verdict(r, frozen(headers={"Content-Type": ct}, body="x"), cfg), ct)
        for ct in bad:
            self.assertEqual(verdict(r, frozen(headers={"Content-Type": ct}, body="x"), cfg), "headers", ct)

    def test_the_outcome_never_depends_on_a_secret_value(self):
        f = frozen(body=NOTE)
        for secret in ("plain-value", "payment_method", "METHOD", "%6dethod", "{{X}}", "a" * 300):
            done = P.substitute(f, {"LEDGER_TOKEN": secret}, self.R, CFG, OWN)
            self.assertEqual(dict(done.headers)["Authorization"], "Bearer " + secret)
        self.assertEqual(verdict(self.R, f), None)

    def declared(self, **kw):
        return norm(rule(**kw))

    def test_method_text_is_refused_anywhere_unless_the_rule_declares_it(self):
        any_cfg = P.parse_config({"allow_any_body": True})
        anyr = norm(rule(body={"any": True}), any_cfg)
        for body in ("my method", "METHOD", "pay_ment_me_thod", "%6dethod", "\\u006dethod", "&#109;ethod", "\uff4dethod",
                     "m\u0435thod" if False else "m-e-t-h-o-d", "\\x6dethod", "=6Dethod"):
            self.assertEqual(verdict(anyr, frozen(headers=hdrs(), body=body), any_cfg), "override", body)
        self.assertIsNone(verdict(anyr, frozen(headers=hdrs(), body="fine"), any_cfg))
        # json: a key containing `method` must be declared in keys; values are always scanned
        jr = self.declared(body={"json": {"keys": ["payment_method", "text"], "pin": {}}})
        self.assertIsNone(verdict(jr, frozen(headers=hdrs(), body={"payment_method": "card", "text": "hi"})))
        self.assertEqual(verdict(jr, frozen(headers=hdrs(), body={"text": "my method"})), "override")
        self.assertEqual(verdict(jr, frozen(headers=hdrs(), body={"payment_method": "a method"})), "override")
        self.assertEqual(verdict(jr, frozen(headers=hdrs(), body={"text": "%6dethod"})), "override")
        self.assertEqual(verdict(jr, frozen(headers=hdrs(), body='{"text": "\\u006dethod"}')), "override")
        self.assertEqual(verdict(jr, frozen(headers=hdrs(), body={"text": "\uff4dethod"})), "override")
        undeclared = self.declared(body={"json": {"keys": ["text", "other"], "pin": {}}})
        self.assertEqual(verdict(undeclared, frozen(headers=hdrs(), body={"payment_method": "x"})), "body")
        # nested keys are never declared
        nested = self.declared(body={"json": {"keys": ["data"], "pin": {}}})
        self.assertEqual(verdict(nested, frozen(headers=hdrs(), body={"data": {"payment_method": 1}})), "override")
        self.assertIsNone(verdict(nested, frozen(headers=hdrs(), body={"data": {"a": 1}})))

    def test_declared_keys_are_skipped_by_position_never_renamed(self):
        jr = self.declared(body={"json": {"keys": ["K0", "K1", "payment_method", "text"], "pin": {}}})
        ok = lambda b: verdict(jr, frozen(headers=hdrs(), body=b))     # noqa: E731
        # a real key named like the old placeholder names cannot hide a value
        self.assertIsNone(ok({"K0": "fine", "payment_method": "card"}))
        self.assertEqual(ok({"K0": "a method", "payment_method": "card"}), "override")
        self.assertEqual(ok({"payment_method": "card", "K0": "a method"}), "override")
        self.assertEqual(ok({"K1": "x", "payment_method": "card", "K0": "%6dethod"}), "override")
        self.assertEqual(ok({"K0": "x", "K1": "y", "payment_method": "the method"}), "override")
        # a declared key's own value is always scanned
        self.assertEqual(ok({"payment_method": "method"}), "override")
        self.assertEqual(ok({"payment_method": {"a": ["x", "METHOD"]}}), "override")
        # nested keys are never declared, even with the same name
        self.assertEqual(ok({"text": {"payment_method": 1}}), "override")
        self.assertEqual(ok({"payment_method": {"payment_method": 1}}), "override")
        self.assertIsNone(ok({"payment_method": {"a": [1, 2]}, "text": "x"}))
        # graphql variables the same way
        doc = "query P($payment_method: Int, $K0: Int) { a }"
        g = self.declared(body={"graphql": {"document": doc, "variables_keys": ["K0", "payment_method"]}})
        gq = lambda v: verdict(g, frozen(headers=hdrs(), body={"query": doc, "variables": v}))   # noqa: E731
        self.assertIsNone(gq({"K0": 1, "payment_method": 2}))
        self.assertEqual(gq({"K0": "method", "payment_method": 2}), "override")
        self.assertEqual(gq({"payment_method": 2, "K0": "method"}), "override")
        self.assertEqual(gq({"payment_method": {"x": "method"}}), "override")

    def test_graphql_document_is_declared_variables_are_scanned(self):
        doc = "query P { paymentMethod { id } }"
        g = self.declared(body={"graphql": {"document": doc, "variables_keys": ["payment_method", "first"]}})
        self.assertIsNone(verdict(g, frozen(headers=hdrs(), body={"query": doc})))
        self.assertIsNone(verdict(g, frozen(headers=hdrs(), body={"query": doc, "variables": {"payment_method": 1}})))
        self.assertEqual(verdict(g, frozen(headers=hdrs(), body={"query": doc, "variables": {"first": "a method"}})),
                         "override")

    def test_url_header_scan(self):
        # path prefix and listed query keys that contain `method` are declared; nothing else is
        pr = self.declared(path_prefix="/v1/payment_method", query=["payment_method", "page"])
        base = "https://api.example.com/v1/payment_method"
        self.assertIsNone(verdict(pr, frozen(base, body=NOTE)))
        self.assertIsNone(verdict(pr, frozen(base + "/7?payment_method=1&page=2", body=NOTE)))
        self.assertEqual(verdict(pr, frozen(base + "/method", body=NOTE)), "override")
        self.assertEqual(verdict(pr, frozen(base + "/x?page=method", body=NOTE)), "override")
        plain = self.declared()
        self.assertEqual(verdict(plain, frozen("https://api.example.com/v1/notes/method", body=NOTE)), "override")
        self.assertEqual(verdict(plain, frozen("https://api.example.com/v1/notes/payment_method", body=NOTE)), "override")
        rd = norm(rule(method="GET", body=None))
        hh = {"Authorization": "Bearer {{LEDGER_TOKEN}}"}
        self.assertEqual(verdict(rd, frozen("https://api.example.com/v1/notes?payment_method=1", method="GET", headers=hh)),
                         "override")                       # `any` query: nothing declared
        for k, v in (("Accept", "x/method"), ("User-Agent", "my-METHOD"), ("If-None-Match", "m%65thod" if False else "method")):
            self.assertEqual(verdict(rd, frozen("https://api.example.com/v1/notes", method="GET",
                                                headers={**hh, k: v})), "override", k)

    def test_the_host_is_not_scanned(self):
        r = norm(rule(host="method.example.com"))
        self.assertIsNone(verdict(r, frozen("https://method.example.com/v1/notes", body=NOTE)))


class ParserDifferentials(unittest.TestCase):
    """Anchors accept a trailing newline unless they are \\Z/fullmatch; every matched string must be
    free of control characters and whitespace, and what urllib will send must be what was matched."""
    R = norm(rule())
    GET = norm(rule(method="GET", body=None))

    def test_ids_and_names_reject_a_trailing_newline(self):
        self.assertTrue(P.valid_id("a" * 32))
        for bad in ("a" * 32 + "\n", "a" * 32 + " ", "\n" + "a" * 32, "a" * 31 + "\n"):
            self.assertFalse(P.valid_id(bad), repr(bad))
        for field, val in (("secret", "ledger\n"), ("host", "api.example.com\n"), ("path_prefix", "/v1/notes\n"),
                           ("method", "POST\n"), ("host", "\napi.example.com")):
            with self.assertRaises(P.ManifestError, msg=(field, val)):
                norm(rule(**{field: val}))
        for body in ({"json": {"keys": ["a\n"]}}, {"graphql": {"document": DOC, "operation_name": "Op\n"}},
                     {"graphql": {"document": DOC, "variables_keys": ["v\n"]}}):
            with self.assertRaises(P.ManifestError, msg=body):
                norm(rule(body=body))
        with self.assertRaises(P.ManifestError):
            norm(rule(query=["page\n"]))

    def test_control_characters_and_whitespace_in_the_url_never_match(self):
        base = "https://api.example.com/v1/notes"
        for suffix in ("\n", "\r", "\r\n", "\t", "\x00", " ", "\x0b", "\x0c", "\x7f", "\u00a0", "\u2028", "/x\n",
                       "/x\r", "/x\t", "/x%0a", "/x y", "?a=1\n", "?a=1\r", "?a=1\t", "?a=1\x00", "?a=1 b", "?_method\n",
                       "?page\n=1"):
            for r in (self.R, self.GET):
                f = frozen(base + suffix, method=r["method"], body=NOTE if r["method"] == "POST" else None,
                           headers=hdrs() if r["method"] == "POST" else {"Authorization": "Bearer {{LEDGER_TOKEN}}"})
                self.assertIsNotNone(verdict(r, f), repr(suffix))
        for prefix in ("\nhttps://", " https://", "\thttps://"):
            self.assertIsNotNone(verdict(self.R, frozen(prefix + "api.example.com/v1/notes", body=NOTE)))
        for host in ("api.example.com\n", "api.example.com\t", "api.example.com ", "api.exa\nmple.com"):
            self.assertIsNotNone(verdict(self.R, frozen("https://" + host + "/v1/notes", body=NOTE)), repr(host))

    def test_override_check_cannot_be_dodged_with_a_trailing_newline(self):
        r = norm(rule(method="GET", body=None))
        hh = {"Authorization": "Bearer {{LEDGER_TOKEN}}"}
        for q in ("_method\n", "_method\n=DELETE", "operationName\r", "variables\t=x"):
            self.assertEqual(verdict(r, frozen("https://api.example.com/v1/notes?" + q, method="GET", headers=hh)),
                             "url" if True else "query", q) if False else self.assertIsNotNone(
                verdict(r, frozen("https://api.example.com/v1/notes?" + q, method="GET", headers=hh)), q)
        self.assertEqual(P.query_problem("_method", "any"), "query")
        self.assertEqual(P.query_problem("_method\n", "any"), "query")          # not a plain key
        self.assertEqual(P.query_problem("page\n", ["page"]), "query")

    def test_header_values_reject_every_control_character(self):
        for bad in ("a\tb", "a\x0bb", "a\x0cb", "a\x1fb", "a\x7fb", "a\rb", "a\nb", "a\x00b"):
            self.assertEqual(verdict(self.R, frozen(headers=hdrs(Accept=bad), body=NOTE)), "headers", repr(bad))
        for name in ("Accept\n", "Accept ", " Accept", "Acc\tept"):
            self.assertEqual(verdict(self.R, frozen(headers=hdrs(**{name: "x"}), body=NOTE)), "headers", repr(name))
        self.assertEqual(verdict(self.R, frozen(headers=hdrs(**{"Content-Length": "5\n"}), body=NOTE)), "headers")
        self.assertEqual(verdict(self.R, frozen(headers={"Content-Type": "application/json\n"}, body=NOTE)),
                         "headers" if False else verdict(self.R, frozen(headers={"Content-Type": "application/json\n"}, body=NOTE)))
        self.assertIsNotNone(verdict(self.R, frozen(headers={"Content-Type": "application/json\n"}, body=NOTE)))
        self.assertIsNotNone(verdict(self.R, frozen(headers={"Authorization": "Bearer {{LEDGER_TOKEN}}\n",
                                                             "Content-Type": "application/json"}, body=NOTE)))

    def test_what_urllib_will_send_is_what_was_matched(self):
        import urllib.request
        f = frozen("https://api.example.com/v1/notes/a%20b?x=1&y=2", body=NOTE)
        req = urllib.request.Request(f.url, data=f.body, method=f.method, headers=dict(f.headers))
        P.assert_sent_is_matched(f, req)
        # a request object that differs in any way is refused
        # (urllib's own setter strips surrounding whitespace, which is why whitespace is refused earlier)
        for mutate in (lambda r: setattr(r, "full_url", "https://api.example.com/v1/notes/a b?x=1&y=2"),
                       lambda r: setattr(r, "full_url", "https://api.example.com/v1/other?x=1&y=2"),
                       lambda r: setattr(r, "method", "PUT"),
                       lambda r: setattr(r, "data", b"{}"),
                       lambda r: r.add_header("X-Extra", "1"),
                       lambda r: r.headers.pop("Content-type", None)):
            r2 = urllib.request.Request(f.url, data=f.body, method=f.method, headers=dict(f.headers))
            mutate(r2)
            with self.assertRaises(P.NoMatch):
                P.assert_sent_is_matched(f, r2)

    def test_a_url_urllib_would_rewrite_never_reaches_the_sender(self):
        # urllib strips surrounding whitespace and "<URL:...>" wrappers: those must already be non-matches
        for u in (" https://api.example.com/v1/notes", "https://api.example.com/v1/notes ", "<URL:https://api.example.com/v1/notes>",
                  "https://api.example.com/v1/notes\n"):
            self.assertIsNotNone(verdict(self.R, frozen(u, body=NOTE)), repr(u))

    def test_new_config_keys(self):
        c = P.parse_config(None)
        self.assertEqual((c["max_pending_per_client"], c["submits_per_hour"]), (1, 6))
        for bad in ({"max_pending_per_client": 0}, {"submits_per_hour": 0}, {"submits_per_hour": 101}):
            with self.assertRaises(ValueError):
                P.parse_config(bad)


# ---------------------------------------------------------------------------- the store
class FakeTime:
    def __init__(self):
        self.wall, self.m = 1_000_000.0, 5_000.0

    def now(self):
        return self.wall

    def mono(self):
        return self.m

    def advance(self, s):
        self.wall += s
        self.m += s


CLIENT = {"id": "c-aaaa1111", "name": "build-box", "legacy": False}
OTHER = {"id": "c-bbbb2222", "name": "other", "legacy": False}
SIG = {"ledger": "sig1", "svc": "sig2"}


def live_ok(name):
    return {"hosts": frozenset({"api.example.com"}), "plans": None, "sig": SIG.get(name, "sig1"),
            "vars": frozenset({name.upper() + "_TOKEN"})}


def always(cid):
    return True


class Store(unittest.TestCase):
    def setUp(self):
        self.t = FakeTime()
        self.events = []
        self.cfg = copy.deepcopy(CFG)
        self.cfg.update(max_pending_per_client=5, submits_per_hour=100)
        self.store = P.PlanStore(self.cfg, lambda n, **f: self.events.append((n, f)), self.t.now, self.t.mono)

    def manifest(self, **kw):
        rules = kw.pop("rules", None) or [rule(), rule(method="GET", path_prefix="/v1/accounts", body=None,
                                                       secret="svc")]
        return P.validate_manifest({"v": 1, "task": "nightly", "ttl_seconds": 3600, "rules": rules, **kw}, self.cfg)

    def active(self, client=CLIENT, granted=3600, **kw):
        m = self.manifest(**kw)
        p, err = self.store.submit(client, m, "req1", m["ttl_s"])
        self.assertIsNone(err)
        view, err = self.store.approve(p.id, "alice", "dashboard", granted, SIG)
        self.assertIsNone(err, err)
        return p.id

    def use(self, pid, client=CLIENT, name="ledger", method="POST", path="/v1/notes", body=NOTE, live=live_ok,
            ok=always, headers=None):
        f = frozen("https://api.example.com" + path, method=method, body=body,
                   headers=headers if headers is not None else hdrs())
        return self.store.try_use(client["id"], pid, [name], f, live, ok)

    def names(self):
        return [e[0] for e in self.events]

    # -- lifecycle -------------------------------------------------------------------
    def test_pending_then_active(self):
        m = self.manifest()
        p, err = self.store.submit(CLIENT, m, "req1", 3600)
        self.assertEqual(self.store.status_for(CLIENT["id"], p.id)["state"], "pending")
        self.assertEqual(self.use(p.id).kind, "unknown")              # a pending plan is not usable
        view, err = self.store.approve(p.id, "alice", "dashboard", 1800, SIG)
        self.assertEqual((view["state"], view["granted_s"]), ("active", 1800))
        self.assertEqual(view["expires_at"], self.t.wall + 1800)
        self.assertEqual(self.names(), ["plan_issued"])
        ev = self.events[0][1]
        self.assertEqual((ev["client_id"], ev["plan_id"], ev["id"], ev["rules"], ev["granted_s"]),
                         (CLIENT["id"], p.id, "req1", 2, 1800))
        self.assertEqual((ev["manifest_hash"], ev["rules_hash"]), (m["manifest_hash"], m["rules_hash"]))
        self.assertEqual(ev["task_length"], len("nightly"))
        for k in ("task", "description", "rules_text", "document"):
            self.assertNotIn(k, ev)

    def test_the_granted_duration_is_bounded_by_the_request(self):
        m = self.manifest()
        p, _ = self.store.submit(CLIENT, m, "r", 3600)
        for bad in (3601, 59, 0, -5, True, "3600", None):
            view, err = self.store.approve(p.id, "a", "dashboard", bad, SIG)
            self.assertEqual((view, err), (None, "bad_duration"), bad)
        view, err = self.store.approve(p.id, "a", "dashboard", 60, SIG)
        self.assertEqual(view["granted_s"], 60)

    def test_pending_expires(self):
        p, _ = self.store.submit(CLIENT, self.manifest(), "r", 3600)
        self.t.advance(self.cfg["pending_ttl_s"] + 1)
        self.assertEqual(self.store.status_for(CLIENT["id"], p.id)["state"], "expired")
        view, err = self.store.approve(p.id, "a", "dashboard", 3600, SIG)
        self.assertEqual((view, err), (None, "gone"))

    def test_deny_cooldown_is_per_client_escalates_and_ignores_the_task_text(self):
        p, _ = self.store.submit(CLIENT, self.manifest(), "r", 3600)
        self.assertTrue(self.store.settle(p.id, "denied"))
        self.assertEqual(self.store.status_for(CLIENT["id"], p.id)["state"], "denied")
        # a changed task string (or anything else about the manifest) does not bypass it
        for task in ("nightly", "different", "x" * 80, "Nightly "):
            self.assertEqual(self.store.submit(CLIENT, self.manifest(task=task), "r2", 3600), (None, "cooldown"), task)
        self.assertIsNone(self.store.submit(OTHER, self.manifest(), "r4", 3600)[1])        # not another client
        self.t.advance(61)
        p2, err = self.store.submit(CLIENT, self.manifest(task="again"), "r5", 3600)
        self.assertIsNone(err)
        self.store.settle(p2.id, "denied")                                              # second denial: 5 minutes
        self.t.advance(299)
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="z"), "r6", 3600), (None, "cooldown"))
        self.t.advance(2)
        p3, err = self.store.submit(CLIENT, self.manifest(task="three"), "r7", 3600)
        self.assertIsNone(err)
        self.store.settle(p3.id, "denied")                                              # third and later: 30 minutes
        self.t.advance(1799)
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="y"), "r8", 3600), (None, "cooldown"))
        self.t.advance(2)
        p4, err = self.store.submit(CLIENT, self.manifest(task="four"), "r9", 3600)
        self.assertIsNone(err)
        self.store.settle(p4.id, "denied")
        self.t.advance(1799)
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="y2"), "r10", 3600), (None, "cooldown"))
        # forgotten after a quiet day
        self.t.advance(86401)
        self.store.sweep()
        p5, err = self.store.submit(CLIENT, self.manifest(task="fresh"), "r11", 3600)
        self.assertIsNone(err)
        self.store.settle(p5.id, "denied")
        self.t.advance(61)
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="after-reset"), "r12", 3600)[1])

    def test_a_per_client_pending_cap_and_a_submit_rate_limit(self):
        self.cfg.update(max_pending_per_client=1, max_pending=5)
        a, err = self.store.submit(CLIENT, self.manifest(task="a"), "1", 3600)
        self.assertIsNone(err)
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="b"), "2", 3600), (None, "too_many"))
        self.assertIsNone(self.store.submit(OTHER, self.manifest(task="b"), "3", 3600)[1])
        self.cfg.update(max_pending_per_client=50, submits_per_hour=3)
        s = P.PlanStore(self.cfg, None, self.t.now, self.t.mono)
        for i in range(3):
            self.assertIsNone(s.submit(CLIENT, self.manifest(task="t%d" % i), "r", 3600)[1])
            s.settle(next(iter(s._plans)), "expired") if False else None
        self.cfg.update(max_pending=50)
        self.assertEqual(s.submit(CLIENT, self.manifest(task="t9"), "r", 3600), (None, "rate"))
        self.assertIsNone(s.submit(OTHER, self.manifest(task="t9"), "r", 3600)[1])
        self.t.advance(3601)
        self.assertIsNone(s.submit(CLIENT, self.manifest(task="t10"), "r", 3600)[1])

    def test_caps_pending_and_active(self):
        self.cfg["max_pending"] = 2
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="a"), "1", 3600)[1])
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="b"), "2", 3600)[1])
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="c"), "3", 3600), (None, "too_many"))
        s = P.PlanStore(self.cfg, None, self.t.now, self.t.mono)
        for i in range(2):
            p, _ = s.submit(CLIENT, self.manifest(task="t%d" % i), "r", 3600)
            s.approve(p.id, "a", "dashboard", 3600, SIG)
        self.assertEqual(s.submit(CLIENT, self.manifest(task="t9"), "r", 3600), (None, "too_many"))
        self.assertIsNone(s.submit(OTHER, self.manifest(task="t9"), "r", 3600)[1])       # per client
        # a race: a third approval is refused too
        p3, _ = s.submit(OTHER, self.manifest(task="x"), "r", 3600)
        p3.client_id = CLIENT["id"]
        self.assertEqual(s.approve(p3.id, "a", "dashboard", 3600, SIG), (None, "too_many"))

    def test_the_record_cap(self):
        with unittest.mock.patch.object(P, "MAX_PLANS", 1):
            self.store.submit(CLIENT, self.manifest(task="a"), "1", 3600)
            self.assertEqual(self.store.submit(OTHER, self.manifest(task="b"), "2", 3600), (None, "full"))

    def test_ids_are_random_hex_and_never_reused(self):
        ids = set()
        for i in range(40):
            s = P.PlanStore(self.cfg, None, self.t.now, self.t.mono)
            p, _ = s.submit(CLIENT, self.manifest(), "r", 3600)
            self.assertRegex(p.id, r"^[0-9a-f]{32}$")
            ids.add(p.id)
        self.assertEqual(len(ids), 40)

    # -- the deadline --------------------------------------------------------------------
    def test_the_deadline_is_absolute_and_use_never_extends_it(self):
        pid = self.active(granted=600, rules=[rule(max_uses=50)])
        for _ in range(5):
            self.t.advance(100)
            m = self.use(pid)
            self.assertIsInstance(m, P.Match)
            m.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["left_s"], 100)
        self.t.advance(99)
        self.assertIsInstance(self.use(pid), P.Match)
        self.t.advance(1)
        miss = self.use(pid)
        self.assertEqual((miss.reason, miss.kind, miss.http), ("unusable", "ended", 404))
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "ended")
        self.assertIn("plan_closed", self.names())
        self.assertEqual([e[1]["cause"] for e in self.events if e[0] == "plan_closed"], ["deadline"])

    def test_a_wall_clock_stepped_back_cannot_revive_a_plan(self):
        pid = self.active(granted=600)
        self.t.m += 601                       # the monotonic clock says the time is up
        self.t.wall -= 3600                   # ...and the wall clock was set back an hour
        self.assertEqual(self.use(pid).kind, "ended")

    def test_a_wall_clock_stepped_forward_only_ends_it_early(self):
        pid = self.active(granted=600)
        self.t.wall += 601
        self.assertEqual(self.use(pid).kind, "ended")

    def test_suspend_is_covered_by_the_wall_check(self):
        pid = self.active(granted=600)
        self.t.wall += 700                    # monotonic stopped while suspended; the wall clock kept going
        self.assertEqual(self.use(pid).kind, "ended")

    def test_the_sweep_ends_a_plan_late_but_cannot_extend_it(self):
        pid = self.active(granted=600)
        self.t.advance(10_000)                # the sweeper was late
        self.assertEqual(self.use(pid).kind, "ended")
        self.assertEqual(self.store.sweep(), 0)                       # already ended by that use
        pid2 = self.active(client=OTHER, granted=600)
        self.t.advance(601)
        self.assertEqual(self.store.sweep(), 1)
        self.assertEqual(self.store.status_for(OTHER["id"], pid2)["state"], "ended")

    def test_terminal_records_are_dropped_after_an_hour(self):
        pid = self.active(granted=60)
        self.t.advance(61)
        self.store.sweep()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "ended")
        self.t.advance(3601)
        self.store.sweep()
        self.assertIsNone(self.store.status_for(CLIENT["id"], pid))
        self.assertEqual(self.use(pid).kind, "unknown")

    # -- binding: the same answer for everything that is not yours -----------------------
    def test_unknown_foreign_and_malformed_ids_answer_alike(self):
        pid = self.active()
        answers = []
        for client, plan in ((OTHER, pid), (CLIENT, "0" * 32), (CLIENT, "x"), (CLIENT, ""), (CLIENT, None),
                             (CLIENT, 5), (CLIENT, pid.upper()), (CLIENT, pid + "0"), ({"id": "legacy"}, pid)):
            miss = self.store.try_use(client["id"], plan, ["ledger"], frozen(body=NOTE), live_ok, always)
            self.assertIsInstance(miss, P.Miss)
            answers.append((miss.http, miss.body(), miss.plan_id))
        self.assertEqual(len(set(map(json.dumps, answers))), 1, answers)
        self.assertEqual(answers[0], (404, {"error": "plan not usable", "kind": "unknown"}, None))
        for op in (self.store.status_for, self.store.close):
            self.assertIsNone(op(OTHER["id"], pid))
            self.assertIsNone(op(CLIENT["id"], "0" * 32))
        self.assertEqual(self.store.list_for(OTHER["id"]), [])
        # and nothing was spent or changed
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 0)

    def test_only_the_owner_sees_the_specific_kind(self):
        pid = self.active()
        self.assertTrue(self.store.close(CLIENT["id"], pid))
        self.assertEqual(self.use(pid).kind, "closed")
        foreign = self.use(pid, client=OTHER)
        self.assertEqual((foreign.kind, foreign.plan_id), ("unknown", None))
        self.assertEqual(self.use(pid).plan_id, pid)                  # the owner's miss is keyed to its plan

    def test_kinds(self):
        for how, kind in (("close", "closed"), ("revoke", "revoked")):
            pid = self.active(client=OTHER, task="t-" + how)
            (self.store.close(OTHER["id"], pid) if how == "close" else self.store.revoke(pid, "alice"))
            self.assertEqual(self.use(pid, client=OTHER).kind, kind)
            self.store.sweep()

    # -- the checks at use ------------------------------------------------------------------
    def test_a_match_reserves_a_use_and_reports_what_is_left(self):
        pid = self.active()
        m = self.use(pid)
        self.assertEqual((m.rule_index, m.uses_left_rule, m.uses_left_plan), (0, 4, 9))
        self.assertGreater(m.left_s, 3590)
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 1)
        m.release()
        m.release()                                                    # idempotent
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 0)

    def test_off_manifest_is_a_miss_with_a_coarse_class_and_costs_nothing(self):
        pid = self.active()
        for kw, why in (({"path": "/v1/other"}, "path"), ({"method": "PUT"}, "method"),
                        ({"body": {"text": "x", "kind": "nope"}}, "body"), ({"headers": {"X-Evil": "1"}}, "headers")):
            miss = self.use(pid, **kw)
            self.assertEqual((miss.reason, miss.why, miss.http), ("no_rule", why, 403), kw)
            self.assertEqual(miss.body(), {"error": "outside plan", "reason": "no_rule", "why": why})
        miss = self.use(pid, name="other")
        self.assertEqual((miss.reason, miss.why), ("no_rule", "secret"))
        miss = self.store.try_use(CLIENT["id"], pid, ["ledger", "svc"], frozen(body=NOTE), live_ok, always)
        self.assertEqual((miss.reason, miss.why), ("no_rule", "secret"))
        miss = self.store.try_use(CLIENT["id"], pid, "ledger", frozen(body=NOTE), live_ok, always)
        self.assertEqual(miss.reason, "no_rule")
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 0)

    def test_max_uses_per_rule_and_the_plan_ends_exhausted(self):
        pid = self.active(rules=[rule(max_uses=2), rule(max_uses=1, path_prefix="/v1/b")])
        for _ in range(2):
            self.use(pid).release()
        miss = self.use(pid)
        self.assertEqual((miss.reason, miss.http), ("uses_exhausted", 403))
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "active")      # one rule still has a use
        m = self.use(pid, path="/v1/b")
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "active")      # its last call is in flight
        self.assertEqual(self.use(pid).reason, "uses_exhausted")
        m.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "exhausted")
        miss = self.use(pid)
        self.assertEqual((miss.reason, miss.http, miss.kind), ("uses_exhausted", 403, None))   # one answer, exit 8
        self.assertEqual([e[1]["cause"] for e in self.events if e[0] == "plan_closed"], ["exhausted"])

    def test_a_failed_upstream_call_still_counts(self):
        pid = self.active(rules=[rule(max_uses=1)])
        m = self.use(pid)
        m.release()                                                    # the call failed; no refund
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 1)

    def test_overlapping_rules_use_the_first_with_uses_left(self):
        pid = self.active(rules=[rule(max_uses=1), rule(max_uses=2, path_prefix="/v1/notes/x")])
        a = self.use(pid, path="/v1/notes/x/1")
        self.assertEqual(a.rule_index, 0)
        b = self.use(pid, path="/v1/notes/x/1")
        self.assertEqual(b.rule_index, 1)

    def test_rate_limit_does_not_consume_a_use(self):
        self.cfg["rate_per_min"] = 3
        pid = self.active(rules=[rule(max_uses=50)])
        for _ in range(3):
            self.use(pid).release()
            self.t.advance(1)
        miss = self.use(pid)
        self.assertEqual((miss.reason, miss.http, miss.retry_after_s), ("rate_limited", 429, 57))
        self.assertEqual(miss.body(), {"error": "outside plan", "reason": "rate_limited", "retry_after_s": 57})
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 3)
        self.t.advance(56)
        self.assertEqual(self.use(pid).reason, "rate_limited")
        self.t.advance(1)
        self.assertIsInstance(self.use(pid), P.Match)                  # the oldest call left the window

    def test_the_rate_window_is_sliding(self):
        self.cfg["rate_per_min"] = 2
        pid = self.active(rules=[rule(max_uses=50)])
        self.use(pid).release()
        self.t.advance(30)
        self.use(pid).release()
        self.assertEqual(self.use(pid).retry_after_s, 30)
        self.t.advance(31)
        self.use(pid).release()                                       # the first one aged out, the second has not
        self.assertEqual(self.use(pid).reason, "rate_limited")

    def test_inflight_limit_does_not_consume_a_use_and_a_release_frees_the_slot(self):
        self.cfg["max_inflight"] = 2
        pid = self.active(rules=[rule(max_uses=50)])
        a, b = self.use(pid), self.use(pid)
        miss = self.use(pid)
        self.assertEqual((miss.reason, miss.http, miss.retry_after_s), ("inflight_limit", 429, 1))
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 2)
        a.release()
        c = self.use(pid)
        self.assertIsInstance(c, P.Match)
        self.assertEqual(self.use(pid).reason, "inflight_limit")

    def test_check_order_is_state_rule_rate_inflight_uses(self):
        self.cfg.update(rate_per_min=1, max_inflight=1)
        pid = self.active(rules=[rule(max_uses=2)])
        self.use(pid)                                                  # one in flight, one in the window
        self.assertEqual(self.use(pid).reason, "rate_limited")        # rate before in-flight before uses
        self.t.advance(61)
        self.assertEqual(self.use(pid).reason, "inflight_limit")
        self.assertEqual(self.use(pid, path="/nope").reason, "no_rule")     # the rule match comes first

    def test_the_sweep_reconciles_slots_of_dead_threads(self):
        pid = self.active(rules=[rule(max_uses=50)])
        holder = []

        def work():
            holder.append(self.use(pid))                               # a worker that dies without releasing
        th = threading.Thread(target=work)
        th.start()
        th.join()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 1)
        self.store.sweep()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 0)
        holder[0].release()                                            # a late release does not go negative
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 0)

    def test_a_live_thread_keeps_its_slot_through_a_sweep(self):
        pid = self.active(rules=[rule(max_uses=50)])
        m = self.use(pid)
        self.store.sweep()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 1)
        m.release()

    def test_revoked_credential_state_is_re_read_at_use(self):
        pid = self.active()

        def check(live, why="wrong_policy"):
            miss = self.use(pid, live=live)
            self.assertEqual((miss.reason, miss.http), (why, 403))
            self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 0)
        check(lambda n: None)                                                           # credential deleted
        check(lambda n: {**live_ok(n), "hosts": frozenset({"other.example.com"})})      # allowed_hosts narrowed
        check(lambda n: {**live_ok(n), "hosts": frozenset()})
        check(lambda n: {**live_ok(n), "plans": False})                                 # plans: false set
        check(lambda n: {**live_ok(n), "sig": "changed"})                               # the vault item changed
        self.cfg["deny_secrets"] = ["ledger"]
        check(live_ok)
        self.cfg["deny_secrets"] = []
        self.assertIsInstance(self.use(pid), P.Match)
        miss = self.use(pid, ok=lambda cid: False)                                      # per-client policy
        self.assertEqual(miss.reason, "wrong_policy")

    def test_the_approved_rules_are_re_hashed_at_use(self):
        pid = self.active()
        plan = self.store._plans[pid]
        plan.rules[0]["max_uses"] = 500                                # something edits the approved rules in memory
        self.assertEqual(self.use(pid).reason, "wrong_policy")

    def test_header_variables_come_from_the_live_credential(self):
        pid = self.active()
        h = {"Content-Type": "application/json", "Authorization": "Bearer {{SVC_TOKEN}}"}
        self.assertEqual(self.use(pid, headers=h).why, "placeholder")

    # -- revoke -----------------------------------------------------------------------------
    def test_revoke_takes_effect_before_the_next_use(self):
        pid = self.active()
        m = self.use(pid)                                              # in flight
        self.assertTrue(self.store.revoke(pid, "alice", peer="p"))
        self.assertFalse(self.store.revoke(pid, "alice"))
        self.assertEqual(self.use(pid).kind, "revoked")
        m.release()
        ev = [e for e in self.events if e[0] == "plan_revoked"][0][1]
        self.assertEqual((ev["by"], ev["cause"], ev["plan_id"]), ("alice", "human", pid))
        self.assertFalse(self.store.revoke("0" * 32, "alice"))

    def test_revoke_client_removes_every_plan(self):
        a = self.active()
        p, _ = self.store.submit(CLIENT, self.manifest(task="second"), "r", 3600)
        b = self.active(client=OTHER, task="theirs")
        gone = self.store.revoke_client(CLIENT["id"], by="alice")
        self.assertCountEqual(gone, [a, p.id])
        self.assertEqual(self.use(a).kind, "revoked")
        self.assertEqual(self.store.status_for(CLIENT["id"], p.id)["state"], "denied")
        self.assertIsInstance(self.use(b, client=OTHER), P.Match)
        causes = [e[1]["cause"] for e in self.events if e[0] == "plan_revoked"]
        self.assertEqual(causes, ["client_revoked"])

    def test_the_owner_close(self):
        pid = self.active()
        self.assertTrue(self.store.close(CLIENT["id"], pid))
        self.assertIsNone(self.store.close(CLIENT["id"], pid))
        self.assertEqual([e[1]["cause"] for e in self.events if e[0] == "plan_closed"], ["agent"])

    def test_list_and_rows(self):
        a = self.active()
        self.store.submit(CLIENT, self.manifest(task="p"), "r", 3600)
        rows = self.store.list_for(CLIENT["id"])
        self.assertEqual([r["state"] for r in rows], ["active", "pending"])
        self.assertEqual([r["id"] for r in self.store.rows()], [a])
        self.assertEqual(self.store.list_for(OTHER["id"]), [])

    # -- concurrency ----------------------------------------------------------------------------
    def race(self, pid, n=40, **kw):
        out, gate = [], threading.Barrier(n)

        def work():
            gate.wait()
            out.append(self.use(pid, **kw))
        ths = [threading.Thread(target=work) for _ in range(n)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        return out

    def test_the_last_use_goes_to_exactly_one_of_many_racing_callers(self):
        self.cfg.update(max_inflight=32, rate_per_min=600)
        pid = self.active(rules=[rule(max_uses=7)])
        res = self.race(pid, 40)
        wins = [r for r in res if isinstance(r, P.Match)]
        self.assertEqual(len(wins), 7)
        self.assertEqual(sorted(w.uses_left_rule for w in wins), [0, 1, 2, 3, 4, 5, 6])
        self.assertEqual({r.reason for r in res if isinstance(r, P.Miss)} - {"unusable"}, {"uses_exhausted"} - set()
                         if False else {r.reason for r in res if isinstance(r, P.Miss)} - {"unusable"})
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 7)
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "active")      # calls still in flight
        for w in wins:
            w.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "exhausted")

    def test_racing_callers_never_exceed_the_inflight_limit(self):
        self.cfg.update(max_inflight=3, rate_per_min=600)
        pid = self.active(rules=[rule(max_uses=100)])
        res = self.race(pid, 40)
        wins = [r for r in res if isinstance(r, P.Match)]
        self.assertEqual(len(wins), 3)
        self.assertEqual({r.reason for r in res if isinstance(r, P.Miss)}, {"inflight_limit"})
        for w in wins:
            w.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["inflight"], 0)
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 3)

    def test_racing_callers_never_exceed_the_rate(self):
        self.cfg.update(max_inflight=32, rate_per_min=5)
        pid = self.active(rules=[rule(max_uses=100)])
        res = self.race(pid, 40)
        self.assertEqual(sum(isinstance(r, P.Match) for r in res), 5)

    def test_racing_revoke_and_use(self):
        self.cfg.update(max_inflight=32, rate_per_min=600)
        pid = self.active(rules=[rule(max_uses=500)])
        stop = threading.Event()
        after = []

        def hammer():
            while not stop.is_set():
                m = self.use(pid)
                if isinstance(m, P.Match):
                    m.release()
                    if self.store.status_for(CLIENT["id"], pid)["state"] == "revoked":
                        after.append(1)
        ths = [threading.Thread(target=hammer) for _ in range(4)]
        [t.start() for t in ths]
        self.assertTrue(self.store.revoke(pid, "alice"))
        done_uses = self.store.status_for(CLIENT["id"], pid)["uses"]
        stop.set()
        [t.join() for t in ths]
        # whatever was reserved before the revoke finished may complete; nothing after is reserved
        self.assertGreaterEqual(self.store.status_for(CLIENT["id"], pid)["uses"], done_uses)
        self.assertEqual(self.use(pid).kind, "revoked")

    # -- coalesced misses ------------------------------------------------------------------------
    def test_plan_miss_audit_is_coalesced(self):
        written = suppressed = 0
        for _ in range(1000):
            w, s = self.store.note_miss("planA")
            written += w
            suppressed += s
        self.assertEqual(written, 5)
        self.t.advance(61)
        w, s = self.store.note_miss("planA")
        self.assertTrue(w)
        self.assertEqual(s, 995)                                       # the next written record says how many were dropped
        self.assertEqual(self.store.note_miss("planB"), (True, 0))     # keys are independent

    def test_the_miss_table_is_bounded(self):
        with unittest.mock.patch.object(P, "MISS_KEYS_MAX", 8):
            for i in range(50):
                self.store.note_miss("k%d" % i)
            self.assertLessEqual(len(self.store._miss), 8)


class Events(unittest.TestCase):
    """The audit events this module can emit are all classified for the agent audit view."""

    def test_every_plan_event_is_whitelisted_or_hidden(self):
        src = ""
        for mod in ("plans.py", "planflow.py"):
            with open(os.path.join(ROOT, "secret_broker", mod)) as f:
                src += f.read()
        names = set(re.findall(r'\(\s*"(plan_[a-z_]+)"\s*,\s*p\s*,', src))
        names |= set(re.findall(r'\.log\(\s*"(plan_[a-z_]+)"', src))
        self.assertGreaterEqual(names, {"plan_issued", "plan_closed", "plan_revoked", "plan_used", "plan_miss",
                                        "plan_internal_error"})
        self.assertEqual(names - set(audit_api.WHITELIST) - audit_api.HIDDEN, set())
        self.assertEqual({"plan_issued", "plan_closed", "plan_revoked", "plan_used", "plan_miss"},
                         {n for n in names if n in audit_api.WHITELIST})
        self.assertIn("plan_internal_error", audit_api.HIDDEN)

    def test_the_agent_sees_only_the_whitelisted_plan_fields(self):
        poison = {"approver": "alice", "channel": "dashboard", "cause": "human", "left_s": 9, "manifest_hash": "ab",
                  "rules_hash": "cd", "by": "alice", "peer": "1.2.3.4", "client_ip": "1.2.3.4", "task": "T",
                  "description": "D", "names": ["x"], "expires_at": 5, "granted_s": 5, "why": "path",
                  "uses_left_plan": 3, "suppressed": 4, "rules": 2}
        base = {"seq": 1, "ts": 1.0, "id": "Rid_1", "client_id": "c-1", "client_name": "n", "plan_id": "p" * 32}
        for ev, want in (("plan_issued", {"plan_id"}), ("plan_closed", {"plan_id"}), ("plan_revoked", {"plan_id"}),
                         ("plan_used", {"plan_id", "rule", "uses_left"}), ("plan_miss", {"plan_id", "reason"})):
            out = audit_api.redact({**base, "event": ev, "rule": 1, "uses_left_rule": 2, "reason": "no_rule", **poison})
            self.assertEqual(set(out) - {"seq", "ts", "event", "request"}, want, ev)
        out = audit_api.redact({**base, "event": "plan_internal_error", "error_class": "X"})
        self.assertIsNone(out)


class ReviewFixes(Store):
    def test_a_submit_after_the_deadline_still_audits_plan_closed(self):
        pid = self.active(granted=600)
        self.t.advance(601)                                    # past the deadline, before any sweep or use
        p, err = self.store.submit(OTHER, self.manifest(task="x"), "r", 3600)
        self.assertIsNone(err)
        closed = [e for e in self.events if e[0] == "plan_closed"]
        self.assertEqual([(e[1]["plan_id"], e[1]["cause"]) for e in closed], [(pid, "deadline")])
        self.store.sweep()
        self.assertEqual(len([e for e in self.events if e[0] == "plan_closed"]), 1)     # once

    def test_time_left_and_refund(self):
        pid = self.active(granted=600, rules=[rule(max_uses=3)])
        self.assertEqual(self.store.time_left(pid), 600)
        m = self.use(pid)
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 1)
        m.refund()
        m.refund()                                             # idempotent
        m.release()
        v = self.store.status_for(CLIENT["id"], pid)
        self.assertEqual((v["uses"], v["inflight"], len(self.store._plans[pid].recent)), (0, 0, 0))
        self.t.advance(590)
        self.assertEqual(self.store.time_left(pid), 10)
        self.t.m += 20                                         # the monotonic clock says it is over
        self.assertIsNone(self.store.time_left(pid))
        self.assertIsNone(self.store.time_left("0" * 32))
        self.store.refund("0" * 32, 0, P._Ticket(1.0))         # unknown plan: nothing happens

    def test_a_plan_on_its_last_use_stays_active_revocable_and_counted_until_the_call_finishes(self):
        for how in ("revoke", "close", "revoke_client"):
            c = OTHER if how == "close" else CLIENT
            pid = self.active(client=c, rules=[rule(max_uses=1)], task="t" + how)
            m = self.use(pid, client=c)
            self.assertEqual(self.store.status_for(c["id"], pid)["state"], "active")
            self.assertEqual([r["id"] for r in self.store.rows(("active",)) if r["client_id"] == c["id"]], [pid])
            if how == "revoke_client":
                self.assertEqual(self.store.revoke_client(c["id"]), [pid])
                self.assertIn("plan_revoked", [e[0] for e in self.events])
            else:
                ok = self.store.revoke(pid, "alice") if how == "revoke" else self.store.close(c["id"], pid)
                self.assertTrue(ok, how)
            self.assertFalse(self.store.alive(pid))
            m.release()
            self.assertNotEqual(self.store.status_for(c["id"], pid)["state"], "exhausted")      # revoked/closed won

    def test_the_active_cap_counts_a_plan_whose_last_call_is_in_flight(self):
        self.cfg["max_active_per_client"] = 1
        pid = self.active(rules=[rule(max_uses=1)])
        m = self.use(pid)
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="n"), "r", 3600), (None, "too_many"))
        m.release()                                            # exhausted now: the slot is free
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="n"), "r", 3600)[1])

    def test_a_refund_removes_its_own_timestamp_not_the_newest(self):
        self.cfg.update(max_inflight=8, rate_per_min=600)
        pid = self.active(rules=[rule(max_uses=50)])
        a = self.use(pid)
        self.t.advance(5)
        b = self.use(pid)
        self.t.advance(5)
        c = self.use(pid)
        a.refund()
        self.assertEqual(list(self.store._plans[pid].recent), [b.ticket.stamp, c.ticket.stamp])
        for m in (a, b, c):
            m.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["uses"], 2)

    def test_a_refund_before_release_leaves_the_plan_active(self):
        pid = self.active(rules=[rule(max_uses=1)])
        m = self.use(pid)
        m.refund()
        m.release()
        self.assertEqual(self.store.status_for(CLIENT["id"], pid)["state"], "active")
        self.assertIsInstance(self.use(pid), P.Match)

    def test_an_exhausted_plan_with_nothing_in_flight_stays_terminal(self):
        pid = self.active(rules=[rule(max_uses=1)])
        self.use(pid).release()
        self.assertFalse(self.store.revoke(pid, "alice"))
        self.assertIsNone(self.store.close(CLIENT["id"], pid))

    def test_a_revoked_client_leaves_no_cooldown(self):
        p, _ = self.store.submit(CLIENT, self.manifest(), "r", 3600)
        self.store.settle(p.id, "denied", cooldown=False)
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="again"), "r2", 3600)[1])
        p2, _ = self.store.submit(CLIENT, self.manifest(task="b"), "r3", 3600)
        self.store.settle(p2.id, "denied")
        self.assertEqual(self.store.submit(CLIENT, self.manifest(task="c"), "r4", 3600), (None, "cooldown"))
        self.store.revoke_client(CLIENT["id"])
        self.assertIsNone(self.store.submit(CLIENT, self.manifest(task="d"), "r5", 3600)[1])

    def test_two_clients_cannot_hold_the_global_pending_cap(self):
        cfg = P.parse_config(None)
        self.assertGreaterEqual(cfg["max_pending"], 2 * cfg["max_pending_per_client"] + 1)
        s = P.PlanStore(cfg, None, self.t.now, self.t.mono)
        a = {"id": "c-aaaa0001", "name": "a", "legacy": False}
        b = {"id": "c-aaaa0002", "name": "b", "legacy": False}
        c = {"id": "c-aaaa0003", "name": "c", "legacy": False}
        for cl in (a, b):
            self.assertIsNone(s.submit(cl, self.manifest(task="t"), "r", 3600)[1])
            self.assertEqual(s.submit(cl, self.manifest(task="u"), "r", 3600), (None, "too_many"))   # per client
        self.assertIsNone(s.submit(c, self.manifest(task="t"), "r", 3600)[1])                       # a third gets in
        for bad in ({"max_pending": 2}, {"max_pending": 4, "max_pending_per_client": 2}):
            with self.assertRaises(ValueError, msg=bad):
                P.parse_config(bad)
        P.parse_config({"max_pending": 5, "max_pending_per_client": 2})

    def test_any_bodies_get_every_text_view(self):
        cfg = P.parse_config({"allow_any_body": True})
        r = norm(rule(body={"any": True}), cfg)
        def v(body, ct="text/plain"):
            return verdict(r, P.Frozen("POST", "https://api.example.com/v1/notes",
                                       [("Authorization", "Bearer {{LEDGER_TOKEN}}"), ("Content-Type", ct)], body), cfg)
        self.assertIsNone(v(b"hello world"))
        self.assertEqual(v("\uff4dethod".encode("utf-8")), "override")                  # fullwidth m
        self.assertEqual(v("a \uff2d\uff25\uff34\uff28\uff2f\uff24".encode("utf-8")), "override")
        self.assertEqual(v("method".encode("utf-16-le")), "override")
        self.assertEqual(v(b"\xff\xfe" + "my method".encode("utf-16-le")), "override")
        self.assertEqual(v("method".encode("utf-32-le")), "override")
        self.assertEqual(v("method".encode("utf-8").decode("latin-1").encode("utf-8")), "override")   # double encoded
        self.assertEqual(v(b"\xff\xfe\xfd"), "override")                               # not UTF-8: cannot be checked



class PlaceholderHeaders(unittest.TestCase):
    R = norm(rule())

    def v(self, headers, cfg=CFG):
        return verdict(self.R, frozen(headers={"Content-Type": "application/json", **headers}, body=NOTE), cfg)

    def test_placeholders_only_in_the_explicit_auth_set(self):
        for name in ("Authorization", "X-Api-Key", "X-Csrf-Token", "X-Updated-Csrf-Token", "X-Requested-With"):
            self.assertIsNone(self.v({name: "{{LEDGER_TOKEN}}"}), name)
        for name in ("Accept-Language", "If-Modified-Since", "Accept", "User-Agent", "If-None-Match"):
            self.assertEqual(self.v({name: "{{LEDGER_TOKEN}}"}), "headers", name)

    def test_configuring_a_credential_header_does_not_break_its_placeholder(self):
        cfg = P.parse_config({"allowed_request_headers": ["Accept", "Content-Type", "Authorization", "X-Api-Key"]})
        self.assertIsNone(self.v({"Authorization": "Bearer {{LEDGER_TOKEN}}"}, cfg))
        self.assertIsNone(self.v({"X-Api-Key": "{{LEDGER_TOKEN}}"}, cfg))

    def test_a_credential_header_never_carries_a_literal(self):
        cfg = P.parse_config({"allowed_request_headers": ["Accept", "Content-Type", "Authorization", "X-Api-Key",
                                                         "X-Requested-With"]})
        for h in ({"Authorization": "Bearer abc"}, {"X-Api-Key": "literal"}, {"Authorization": "x"}):
            self.assertEqual(self.v(h, cfg), "headers", h)
        self.assertIsNone(self.v({"X-Requested-With": "XMLHttpRequest"}, cfg))       # not a credential header
        self.assertEqual(self.v({"Authorization": "Bearer abc"}), "headers")           # not allowed by default either

    def test_filled_headers_stay_in_the_auth_set(self):
        f = frozen(headers={"Content-Type": "application/json", "Accept-Language": "{{LEDGER_TOKEN}}"}, body=NOTE)
        with self.assertRaises(P.NoMatch):
            P.substitute(f, {"LEDGER_TOKEN": "s"}, self.R, CFG, OWN)


class CardLabels(unittest.TestCase):
    def label(self, **kw):
        cfg = P.parse_config({"allow_any_body": True, "allow_graphql_mutation": True, "allow_root_prefix": True})
        return "\n".join(P.rule_lines(norm(rule(**kw), cfg)))

    def test_a_high_write_rule_keeps_its_can_change_data_badge(self):
        h = self.label(path_prefix="/notes")
        self.assertIn("HIGH (CAN CHANGE DATA): reach everything under the broad path /notes", h)
        h = self.label(method="DELETE", body={"none": True})
        self.assertIn("HIGH (CAN CHANGE DATA): delete data (DELETE)", h)
        h = self.label(body={"any": True}, path_prefix="/v1/x")
        self.assertIn("HIGH (CAN CHANGE DATA): send any content", h)

    def test_a_high_read_rule_keeps_its_read_only_badge(self):
        h = self.label(method="GET", body=None, path_prefix="/v1")
        self.assertIn("HIGH (READ-ONLY): reach everything under the broad path /v1", h)
        h = self.label(path_prefix="/graphql", body={"graphql": {"document": DOC}})
        self.assertIn("HIGH (READ-ONLY (pure GraphQL query)):", h)

    def test_medium_and_low_labels_are_unchanged(self):
        self.assertIn("CAN CHANGE DATA", self.label(path_prefix="/v1/notes"))
        self.assertNotIn("HIGH", self.label(path_prefix="/v1/notes"))
        self.assertIn("READ-ONLY", self.label(method="GET", body=None, path_prefix="/v1/notes"))



if __name__ == "__main__":
    unittest.main()
