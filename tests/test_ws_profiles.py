"""WebSocket profiles (secret_broker/wsprofiles.py, ws_profiles/*.json, `ws-profile` admin commands).

Pure tests (schema, files, registry, rule matcher, deny_verdict) need no broker. The session tests run the real
broker in front of tests/ws_stub.py exactly as test_ws_sessions.py does. No sleeps, no real hosts: example.com / 127.0.0.1.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_credential_request as tcr  # noqa: E402
from test_ws_sessions import WsBase, TOKEN, KEY  # noqa: E402
from secret_broker import wsprofiles as P, wssessions as W, wsprofiles_cli as CLI  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402

READ_TYPES = ("get_states", "get_config", "get_services", "get_panels", "subscribe_events", "unsubscribe_events", "ping",
              "config/entity_registry/list", "config/device_registry/list", "config/area_registry/list",
              "lovelace/config", "lovelace/resources", "auth/current_user", "render_template", "system_log/list")


def good(**over):
    p = {"name": "svc", "description": "A service.", "card_text": "A fixed sentence.",
         "handshake": {"steps": [{"send": {"op": "login", "key": "{{VAR}}"}}, {"expect": {"ok": True}}]}}
    p.update(over)
    return p


def write(path, obj, mode=0o644):
    data = obj if isinstance(obj, bytes) else (obj if isinstance(obj, str) else json.dumps(obj)).encode()
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def bi(name, **over):
    """A built-in profile as a file body (the normalized empties dropped), with changes."""
    p = {k: v for k, v in P.builtin()[0][name].items() if v not in (None, {}, [])}
    p.update(over)
    return p


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pd = os.path.join(self.d, "ws-profiles")
        os.mkdir(self.pd)

    def put(self, name, obj, mode=0o644):
        write(os.path.join(self.pd, name + ".json"), obj, mode)


# ------------------------------------------------------------------------------- built-in profiles
class Builtins(unittest.TestCase):
    def test_all_three_load_and_validate(self):
        bp, be = P.builtin()
        self.assertEqual((sorted(bp), be), (sorted(P.BUILTIN_NAMES), {}))
        for n, p in bp.items():
            self.assertEqual(p["name"], n)
            self.assertTrue(p["card_text"] and p["description"] and p["risk_notes"], n)
            self.assertEqual(P.parse_profile(json.loads(open(os.path.join(P.BUILTIN_DIR, n + ".json")).read()), n), p)

    def test_the_default_keeps_the_old_deny_list_and_adds_the_rules(self):
        p = P.builtin()[0]["home-assistant"]
        self.assertEqual(p["deny_send"], W.PRESET_DENY["home-assistant"])
        self.assertEqual(len(p["deny_send"]), 10)
        self.assertIsNone(p["allow_send"])
        self.assertEqual(W.PRESETS["home-assistant"][1]["send"], {"type": "auth", "access_token": "{{VAR}}"})
        doms = {d for r in p["rules"] for d in (r["match"].get("domain") if isinstance(r["match"].get("domain"), list)
                                                  else [r["match"].get("domain")])}
        self.assertEqual(doms, {"shell_command", "python_script", "hassio", "homeassistant"})

    def test_readonly_allows_only_reads(self):
        p = P.builtin()[0]["home-assistant-readonly"]
        for t in READ_TYPES:
            self.assertIn(t, p["allow_send"])
        for t in ("call_service", "execute_script", "config/entity_registry/update", "lovelace/config/save", "fire_event",
                  "config/area_registry/create", "config/entity_registry/remove"):
            self.assertNotIn(t, p["allow_send"])
        self.assertEqual(p["deny_send"], W.PRESET_DENY["home-assistant"])       # defence in depth: deny wins over allow

    def test_admin_blocks_nothing_and_says_so(self):
        p = P.builtin()[0]["home-assistant-admin"]
        self.assertEqual((p["deny_send"], p["allow_send"], p["rules"]), ([], None, []))
        self.assertIn("UNRESTRICTED", p["card_text"])
        self.assertTrue(p["handshake"])


class Docs(unittest.TestCase):
    def test_the_example_profile_in_the_reference_is_valid_and_behaves(self):
        import re
        text = open(os.path.join(os.path.dirname(__file__), "..", "docs", "reference.md")).read()
        m = re.search(r"\n    (\{\n      \"name\": \"chat-gateway\".*?\n    \})\n", text, re.S)
        self.assertTrue(m)
        prof = P.parse_profile(json.loads("\n".join(ln[4:] for ln in ("    " + m.group(1)).splitlines())), "chat-gateway")
        self.assertEqual(W.deny_verdict('{"type": "post", "channel": "general"}', frozenset(prof["deny_send"]),
                                        frozenset(prof["allow_send"]), prof["rules"]), None)
        self.assertEqual(W.deny_verdict('{"type": "post", "channel": "admin"}', frozenset(), frozenset(prof["allow_send"]),
                                        prof["rules"]), "rule_denied")
        self.assertEqual(W.deny_verdict('{"type": "delete"}', frozenset(), frozenset(prof["allow_send"]), prof["rules"]),
                         "not_allowed")

    def test_the_builtin_table_in_the_reference_matches_the_files(self):
        text = open(os.path.join(os.path.dirname(__file__), "..", "docs", "reference.md")).read()
        for t in P.builtin()[0]["home-assistant-readonly"]["allow_send"]:
            self.assertIn("`" + t + "`", text, t)


# ------------------------------------------------------------------------------- schema
class Schema(unittest.TestCase):
    def ok(self, **over):
        return P.parse_profile(good(**over), "svc")

    def bad(self, **over):
        with self.assertRaises(ValueError, msg=str(over)[:80]):
            P.parse_profile(good(**over), "svc")

    def test_minimal_and_full(self):
        p = P.parse_profile({"name": "min", "description": "d", "card_text": "c"}, "min")
        self.assertEqual((p["handshake"], p["deny_send"], p["allow_send"], p["rules"]), (None, [], None, []))
        full = self.ok(query={"token": "{{VAR}}"}, headers={"Authorization": "Bearer {{VAR}}"},
                       origin="https://app.example.com", subprotocols=["graphql-ws"], deny_send=["a/b", "a/b"],
                       allow_send=["x", "y"], risk_notes=["note"],
                       rules=[{"match": {"type": "t", "n": 5, "b": True, "o": {"k": ["a", "b"]}}, "reason": "why"}])
        self.assertEqual((full["deny_send"], full["allow_send"], full["origin"]), (["a/b"], ["x", "y"], "https://app.example.com"))
        self.assertEqual(full["rules"][0]["action"], "deny")

    def test_every_field_is_checked(self):
        self.bad(extra=1)
        self.bad(**{"é": 1})
        for k in ("name", "description", "card_text"):
            with self.assertRaises(ValueError):
                P.parse_profile({n: v for n, v in good().items() if n != k}, "svc")
        for name in ("Svc", "svc_x", "-svc", "svc-", "a--b", "", "x" * 65, "svc/x", "../svc", "svc\x00", 5, None):
            self.bad(name=name)
        with self.assertRaises(ValueError):
            P.parse_profile(good(name="other"), "svc")                   # the name must be the file's name
        for v in ("", "x" * 201, "tab\there", "café", "new\nline", "‮evil", 5, None, ["a"]):
            self.bad(description=v)
            self.bad(card_text=v)
        for h in ("home-assistant", [], {}, {"steps": []}, {"steps": [{"send": "{{OTHER}}"}]}, {"send": "x", "bogus": 1},
                  {"steps": [{"expect": "{{VAR}}"}]}, {"steps": [{"foo": 1}]}, None):
            self.bad(handshake=h)
        for k, v in (("query", {"a b": "x"}), ("query", {"a": "{{OTHER}}"}), ("query", []), ("query", None),
                     ("headers", {"Host": "x"}), ("headers", {"Cookie": "x"}), ("headers", {"Authorization": 5}),
                     ("origin", "ftp://x"), ("origin", "https://a.example.com\r\nX: y"), ("origin", 5), ("origin", None),
                     ("subprotocols", ["a b"]), ("subprotocols", "x"), ("subprotocols", list("abcdef"))):
            self.bad(**{k: v})
        for k, v in (("deny_send", "x"), ("deny_send", [1]), ("deny_send", [""]), ("deny_send", ["x" * 129]),
                     ("deny_send", ["café"]), ("deny_send", [str(i) for i in range(51)]), ("deny_send", {"a": 1}),
                     ("allow_send", []), ("allow_send", "x"), ("allow_send", [str(i) for i in range(101)]),
                     ("allow_send", [None]), ("risk_notes", "x"), ("risk_notes", [1]), ("risk_notes", ["x"] * 11),
                     ("risk_notes", ["x" * 201]), ("risk_notes", ["a\x00b"])):
            self.bad(**{k: v})

    def test_rules_are_checked(self):
        m = {"type": "call_service"}
        for rules in ("x", {}, [1], [{}], [{"match": m, "bogus": 1}], [{"match": {}}], [{"match": []}], [{"match": "x"}],
                      [{"match": m, "action": "allow"}], [{"match": m, "action": "deny", "reason": "x" * 121}],
                      [{"match": m, "reason": 5}], [{"match": {"a": []}}], [{"match": {"a": [1.5]}}],
                      [{"match": {"a": 1.5}}], [{"match": {"a": None}}], [{"match": {"a": [[1]]}}],
                      [{"match": {"a": ["x"] * 21}}], [{"match": {"a": 2 ** 60}}], [{"match": {"a": ""}}],
                      [{"match": {"": "x"}}], [{"match": {"k%d" % i: 1 for i in range(9)}}],
                      [{"match": {"a": {"b": {"c": {"d": 1}}}}}], [{"match": m}] * 51, [{"match": {"a": "café"}}]):
            self.bad(rules=rules)
        self.ok(rules=[{"match": {"a": {"b": {"c": 1}}}}])                          # three deep is the limit
        self.ok(rules=[{"match": m, "action": "deny"}] * 50)

    def test_a_profile_may_use_VAR_only(self):
        self.bad(handshake={"steps": [{"send": {"t": "{{MY_TOKEN}}"}}]})
        self.ok(query={"t": "{{VAR}}"})

    def test_strict_json(self):
        for text in ('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', "﻿{}", '{"a": "\\ud800"}', "[1] x", "",
                     "[" * 40 + "]" * 40, '{"a": }'):
            with self.assertRaises(ValueError, msg=text[:30]):
                P.strict_loads(text)
        self.assertEqual(P.strict_loads('{"a": [1, {"b": "é"}]}'), {"a": [1, {"b": "é"}]})

    def test_the_error_does_not_echo_an_unknown_field_name_that_is_not_plain(self):
        with self.assertRaises(ValueError) as cm:
            P.parse_profile(good(**{"x\x1b[31m": 1}), "svc")
        self.assertNotIn("\x1b", str(cm.exception))


# ------------------------------------------------------------------------------- files and the directory
class Files(TmpDir):
    def load(self):
        return P.load_dir(self.pd)

    def test_loads_and_ignores_other_files(self):
        self.put("svc", good())
        write(os.path.join(self.pd, "README.txt"), "hello")
        write(os.path.join(self.pd, "svc.json~"), "{")
        profs, errs, derr = self.load()
        self.assertEqual((sorted(profs), errs, derr), (["svc"], {}, None))

    def test_missing_directory_is_empty_not_an_error(self):
        self.assertEqual(P.load_dir(os.path.join(self.d, "nope")), ({}, {}, None))
        self.assertEqual(P.load_dir(None), ({}, {}, None))

    def test_bad_files_are_invalid_individually(self):
        self.put("good-one", good(name="good-one"))
        self.put("dupkey", '{"name": "dupkey", "name": "dupkey", "description": "d", "card_text": "c"}')
        self.put("bom", b"\xef\xbb\xbf" + json.dumps(good(name="bom")).encode())
        self.put("nul", json.dumps(good(name="nul")).encode()[:-1] + b"\x00}")
        self.put("badutf", b'{"name": "badutf", "description": "\xff", "card_text": "c"}')
        self.put("notjson", "{")
        self.put("wrongname", good(name="other"))
        self.put("unknown", good(name="unknown", surprise=1))
        self.put("big", json.dumps(good(name="big", description="x")) + " " * P.MAX_FILE_BYTES)
        self.put("nan", '{"name": "nan", "description": "d", "card_text": "c", "rules": [{"match": {"a": NaN}}]}')
        profs, errs, derr = self.load()
        self.assertEqual(sorted(profs), ["good-one"])
        self.assertEqual(sorted(errs), ["badutf", "big", "bom", "dupkey", "nan", "notjson", "nul", "unknown", "wrongname"])
        self.assertEqual({k: e.label for k, e in errs.items() if k in ("big", "badutf", "bom", "notjson", "unknown")},
                         {"big": "too_large", "badutf": "not_utf8", "bom": "not_json", "notjson": "not_json",
                          "unknown": "invalid"})

    def test_the_size_cap_is_exact(self):
        body = json.dumps(good(name="edge"))
        self.put("edge", body + " " * (P.MAX_FILE_BYTES - len(body)))
        self.put("over", json.dumps(good(name="over")) + " " * P.MAX_FILE_BYTES)
        profs, errs, _ = self.load()
        self.assertEqual((sorted(profs), sorted(errs)), (["edge"], ["over"]))

    def test_a_symlink_is_never_followed(self):
        outside = os.path.join(self.d, "outside.json")
        write(outside, good(name="linked"))
        os.symlink(outside, os.path.join(self.pd, "linked.json"))
        os.mkdir(os.path.join(self.d, "elsewhere"))
        write(os.path.join(self.d, "elsewhere", "viadir.json"), good(name="viadir"))
        os.symlink(os.path.join(self.d, "elsewhere", "viadir.json"), os.path.join(self.pd, "viadir.json"))
        os.symlink(os.path.join(self.d, "elsewhere"), os.path.join(self.pd, "dirlink.json"))
        os.symlink("/etc/passwd", os.path.join(self.pd, "passwd.json"))
        os.symlink(os.path.join(self.d, "missing"), os.path.join(self.pd, "dangling.json"))
        profs, errs, derr = self.load()
        self.assertEqual(profs, {})
        self.assertEqual(sorted(errs), ["dangling", "dirlink", "linked", "passwd", "viadir"])
        self.assertNotIn("root:", repr(errs))                                    # nothing of /etc/passwd is read or shown

    def test_a_symlinked_profiles_directory_itself_is_the_admins_choice(self):
        real = os.path.join(self.d, "real")
        os.mkdir(real)
        write(os.path.join(real, "svc.json"), good())
        link = os.path.join(self.d, "linkdir")
        os.symlink(real, link)
        self.assertEqual(sorted(P.load_dir(link)[0]), ["svc"])

    def test_fifo_and_directory_named_json_do_not_hang_or_load(self):
        os.mkfifo(os.path.join(self.pd, "fifo.json"))
        os.mkdir(os.path.join(self.pd, "dir.json"))
        profs, errs, _ = self.load()
        self.assertEqual((profs, sorted(errs)), ({}, ["dir", "fifo"]))

    def test_world_writable_file_and_directory_are_refused(self):
        self.put("loose", good(name="loose"), mode=0o666)
        self.put("tight", good(name="tight"), mode=0o600)
        profs, errs, derr = self.load()
        self.assertEqual((sorted(profs), sorted(errs), derr), (["tight"], ["loose"], None))
        self.assertEqual(errs["loose"].label, "world_writable")
        os.chmod(self.pd, 0o777)
        try:
            self.assertEqual(self.load()[2].label, "dir_world_writable")
        finally:
            os.chmod(self.pd, 0o755)

    def test_count_cap(self):
        for i in range(P.MAX_FILES + 2):
            self.put("p%03d" % i, good(name="p%03d" % i))
        profs, errs, _ = self.load()
        self.assertEqual(len(profs), P.MAX_FILES)
        self.assertEqual(sorted(errs), ["p100", "p101"])
        self.assertEqual(errs["p100"].label, "too_many")

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_unreadable_directory_is_a_directory_error(self):
        self.put("svc", good())
        os.chmod(self.pd, 0)
        try:
            self.assertEqual(self.load()[2].label, "dir_unreadable")
        finally:
            os.chmod(self.pd, 0o755)

    def test_a_file_where_the_directory_should_be(self):
        write(os.path.join(self.d, "afile"), "x")
        self.assertEqual(P.load_dir(os.path.join(self.d, "afile"))[2].label, "dir_unreadable")


# ------------------------------------------------------------------------------- the registry
class Registry(TmpDir):
    def test_builtins_resolve_and_carry_their_source_and_hash(self):
        r = P.build_registry(self.pd).resolve("home-assistant")
        self.assertEqual((r["source"], len(r["sha256"])), ("built-in", 64))

    def test_an_admin_profile_of_the_same_name_wins(self):
        self.put("home-assistant", good(name="home-assistant", card_text="Mine."))
        reg = P.build_registry(self.pd)
        self.assertEqual((reg.resolve("home-assistant")["card_text"], reg.resolve("home-assistant")["source"]), ("Mine.", "admin"))
        self.assertEqual(reg.overridden(), ["home-assistant"])
        self.assertEqual(reg.resolve("home-assistant-readonly")["source"], "built-in")

    def test_a_broken_override_shadows_the_builtin_instead_of_falling_back(self):
        self.put("home-assistant", '{"name": ')
        reg = P.build_registry(self.pd)
        self.assertEqual(reg.status("home-assistant"), ("invalid", "admin"))
        with self.assertRaises(ValueError) as cm:
            reg.resolve("home-assistant")
        self.assertIn("home-assistant", str(cm.exception))
        self.assertEqual(reg.resolve("home-assistant-admin")["name"], "home-assistant-admin")

    def test_an_unreadable_directory_makes_everything_invalid(self):
        write(os.path.join(self.d, "afile"), "x")
        reg = P.build_registry(os.path.join(self.d, "afile"))
        for n in P.BUILTIN_NAMES:
            with self.assertRaises(ValueError):
                reg.resolve(n)

    def test_the_error_names_the_profile_and_never_the_content(self):
        self.put("leaky", '{"name": "leaky", "description": "SECRET-CANARY-1", "card_text": "c", "bogus-SECRET-CANARY-2": 1}')
        reg = P.build_registry(self.pd)
        with self.assertRaises(ValueError) as cm:
            reg.resolve("leaky")
        self.assertIn("leaky", str(cm.exception))
        self.assertNotIn("CANARY", str(cm.exception))

    def test_names_that_are_not_profile_names_never_reach_the_filesystem(self):
        reg = P.build_registry(self.pd)
        for n in ("../x", "a/b", "A", "x\x00y", "", " x", "x" * 65, 5, None, ["home-assistant"], "home-assistant.json"):
            with self.assertRaises(ValueError, msg=repr(n)):
                reg.resolve(n)

    def test_dir_config(self):
        self.assertEqual(P.parse_dir_config({"ws_profiles_dir": "/x/y"}), "/x/y")
        self.assertEqual(P.parse_dir_config({"audit_log": "/var/b/audit.jsonl"}), "/var/b/ws-profiles")
        self.assertIsNone(P.parse_dir_config({}))
        for bad in ("", 5, ["x"], "a\x00b", "x" * 5000):
            with self.assertRaises(ValueError):
                P.parse_dir_config({"ws_profiles_dir": bad})


# ------------------------------------------------------------------------------- credential setting and overrides
class CredConfig(TmpDir):
    def cfg(self, raw, vars_=("T",), reg=None):
        return W.parse_cred_config(raw, list(vars_), profiles=reg or P.build_registry(self.pd))

    def test_profile_spelling_and_the_older_spelling_are_the_same_profile(self):
        a, b = self.cfg({"profile": "home-assistant"}), self.cfg({"handshake": "home-assistant"})
        self.assertEqual(a, b)
        self.assertEqual(a["deny_send"], W.PRESET_DENY["home-assistant"])
        self.assertEqual(len(a["rules"]), 2)
        self.assertEqual((a["profile"]["name"], a["profile"]["source"]), ("home-assistant", "built-in"))
        self.assertEqual([st["op"] for st in a["steps"]], ["expect", "send", "expect"])

    def test_the_plain_shape_is_unchanged_when_there_is_no_profile(self):
        self.assertEqual(self.cfg({}), {"steps": None, "origin": None, "subprotocols": [], "query": {}, "headers": {},
                                        "deny_send": []})

    def test_unknown_and_invalid_profiles_name_the_profile(self):
        self.put("broken", "{")
        for name, word in (("nope", "not known"), ("broken", "invalid")):
            with self.assertRaises(ValueError) as cm:
                self.cfg({"profile": name})
            self.assertIn(name, str(cm.exception))
            self.assertIn(word, str(cm.exception))
        with self.assertRaises(ValueError):
            self.cfg({"handshake": "nope"})                           # the older spelling: still a clear error
        for bad in ("../x", "A b", 5, "", ["home-assistant"], {"a": 1}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.cfg({"profile": bad})

    def test_profile_and_a_preset_text_together_are_refused(self):
        with self.assertRaises(ValueError):
            self.cfg({"profile": "home-assistant", "handshake": "home-assistant"})

    def test_a_credential_can_add_a_sign_in_field_the_profile_leaves_out_but_not_replace_one(self):
        self.put("svc", good(query={"k": "{{VAR}}"}))
        self.assertEqual(self.cfg({"profile": "svc", "origin": "https://a.example.com"})["origin"], "https://a.example.com")
        for k, v in (("query", {"k": "x"}), ("handshake", {"send": "x"}), ("handshake", {"steps": [{"send": "x"}]})):
            with self.assertRaises(ValueError, msg=k):
                self.cfg({"profile": "svc", **{k: v}} if k != "query" else {"profile": "svc", "query": v})
        self.put("bare", {"name": "bare", "description": "d", "card_text": "c"})
        self.assertEqual(self.cfg({"profile": "bare", "handshake": {"send": "hi"}})["steps"][0]["op"], "send")

    def test_VAR_in_a_profile_needs_a_credential_with_one_variable(self):
        self.put("svc", good())
        self.assertTrue(self.cfg({"profile": "svc"}, vars_=("ONLY",))["steps"])
        with self.assertRaises(ValueError):
            self.cfg({"profile": "svc"}, vars_=("A", "B"))

    def test_extra_denies_add_and_never_remove(self):
        c = self.cfg({"profile": "home-assistant", "deny_send_extra": ["config/x", "supervisor/api"]})
        self.assertEqual(c["deny_send"], W.PRESET_DENY["home-assistant"] + ["config/x"])
        self.assertEqual(c["profile"]["overrides"], ["deny_send_extra"])
        for bad in ([], "x", [1], [""], [str(i) for i in range(51)]):
            with self.assertRaises(ValueError):
                self.cfg({"profile": "home-assistant", "deny_send_extra": bad})

    def test_allow_send_can_only_narrow(self):
        c = self.cfg({"profile": "home-assistant-readonly", "allow_send": ["get_states", "ping", "get_states"]})
        self.assertEqual(c["allow_send"], ["get_states", "ping"])
        with self.assertRaises(ValueError):
            self.cfg({"profile": "home-assistant-readonly", "allow_send": ["get_states", "call_service"]})
        with self.assertRaises(ValueError):
            self.cfg({"profile": "home-assistant-readonly", "allow_send": []})
        # a profile with no allow-list: the credential may add one (everything else becomes refused: stricter)
        self.assertEqual(self.cfg({"profile": "home-assistant", "allow_send": ["get_states"]})["allow_send"], ["get_states"])
        self.assertEqual(self.cfg({"handshake": {"send": "x"}, "allow_send": ["a"]})["allow_send"], ["a"])

    def test_a_deny_send_list_cannot_loosen_a_profile_but_an_explicit_clear_still_can(self):
        with self.assertRaises(ValueError):
            self.cfg({"profile": "home-assistant", "deny_send": ["config/x"]})            # would replace the blocks
        c = self.cfg({"profile": "home-assistant", "deny_send": []})
        self.assertEqual((c["deny_send"], c.get("rules")), ([], None))
        self.assertEqual(c["profile"]["overrides"], ["deny_send_cleared"])
        # the clear does not touch an allow-list
        self.assertEqual(len(self.cfg({"profile": "home-assistant-readonly", "deny_send": []})["allow_send"]), 20)

    def test_the_older_spelling_keeps_its_replace_semantics(self):
        c = self.cfg({"handshake": "home-assistant", "deny_send": ["config/x"]})
        self.assertEqual((c["deny_send"], c.get("rules")), (["config/x"], None))
        self.assertEqual(self.cfg({"handshake": "home-assistant", "deny_send": []})["deny_send"], [])

    def test_extra_with_a_clear_keeps_only_the_extra(self):
        c = self.cfg({"profile": "home-assistant", "deny_send": [], "deny_send_extra": ["a/b"]})
        self.assertEqual(c["deny_send"], ["a/b"])

    def test_the_effective_hash_covers_the_profile_and_the_overrides(self):
        h = lambda raw: self.cfg(raw)["profile"]["sha256"]       # noqa: E731
        base = h({"profile": "home-assistant"})
        self.assertEqual(base, h({"handshake": "home-assistant"}))
        self.assertNotEqual(base, h({"profile": "home-assistant", "deny_send_extra": ["a"]}))
        self.assertNotEqual(base, h({"profile": "home-assistant", "deny_send": []}))
        self.assertNotEqual(base, h({"profile": "home-assistant", "allow_send": ["get_states"]}))
        self.put("home-assistant", bi("home-assistant", rules=[]))
        self.assertNotEqual(base, h({"profile": "home-assistant"}))

    def test_other_keys_are_still_refused(self):
        for bad in ({"nope": 1}, {"profile": "home-assistant", "deny": []}, {"profiles": "x"}):
            with self.assertRaises(ValueError):
                self.cfg(bad)


# ------------------------------------------------------------------------------- the one enforcement function
class Verdict(unittest.TestCase):
    CALL = '{"id": 1, "type": "call_service", "domain": "%s", "service": "%s", "service_data": {"entity_id": "light.a"}}'

    @classmethod
    def setUpClass(cls):
        cls.ha = P.builtin()[0]["home-assistant"]
        cls.ro = P.builtin()[0]["home-assistant-readonly"]

    def v(self, text, prof=None, **kw):
        prof = prof or self.ha
        return W.deny_verdict(text, frozenset(kw.get("deny", prof["deny_send"])), kw.get("allow", prof["allow_send"]),
                              kw.get("rules", prof["rules"]))

    def test_rules_deny_the_dangerous_services_and_allow_the_rest(self):
        for dom, svc in (("shell_command", "x"), ("python_script", "y"), ("hassio", "addon_start"),
                         ("homeassistant", "stop"), ("homeassistant", "restart")):
            self.assertEqual(self.v(self.CALL % (dom, svc)), "rule_denied", (dom, svc))
        for dom, svc in (("light", "turn_on"), ("homeassistant", "turn_on"), ("homeassistant", "reload_all"),
                         ("automation", "trigger")):
            self.assertIsNone(self.v(self.CALL % (dom, svc)), (dom, svc))

    def test_list_values_in_the_frame_are_array_items_checked_one_by_one(self):
        arr = "[" + self.CALL % ("light", "turn_on") + "," + self.CALL % ("shell_command", "x") + "]"
        self.assertEqual(self.v(arr), "rule_denied")
        self.assertIsNone(self.v("[" + self.CALL % ("light", "turn_on") + "]"))

    def test_deny_wins_and_classes(self):
        self.assertEqual(self.v('{"type": "auth/sign_path"}', self.ro), "denied_type")        # in deny AND not in allow
        self.assertEqual(self.v('{"type": "call_service"}', self.ro), "not_allowed")
        self.assertEqual(self.v("nope", self.ro), "not_json")
        self.assertEqual(self.v('{"type": "get_states"}', self.ro), None)
        # deny wins even when the same name is allowed
        self.assertEqual(W.deny_verdict('{"type": "x"}', frozenset({"x"}), frozenset({"x"}), ()), "denied_type")

    def test_allow_list_edge_cases(self):
        allow = frozenset({"get_states", "ping"})
        for text in ('{"id": 1}', '{"type": null}', '{"type": 5}', '{"type": ["ping"]}', '[1]', '"ping"', '5', 'null',
                     '[{"type": "ping"}, {"type": "other"}]', '[{"type": "ping"}, 3]', '[]x', '{"type": "PING"}',
                     '{"type": "ping "}', '{"type": "pin\\u0067x"}'):
            self.assertIn(W.deny_verdict(text, frozenset(), allow, ()), ("not_allowed", "not_json", "denied_type"), text)
        for text in ('{"id": 1, "type": "ping"}', '[{"type": "ping"}, {"type": "get_states"}]', '{"type": "p\\u0069ng"}'):
            self.assertIsNone(W.deny_verdict(text, frozenset(), allow, ()), text)

    def test_parser_differentials_are_refused_under_allow_and_rules(self):
        deep = "[" * 20 + "]" * 20
        evil = ['﻿{"type": "get_states"}', '{"type": "get_states", "type": "call_service"}',
                '{"type": "call_service", "type": "get_states"}', '{"type": NaN}', '{"type": "ping", "x": ' + deep + '}',
                '{"type": "ping", "x": "\\ud800"}', '{"type": "ping"} trailing', '{"type": "ping"}{"type": "x"}',
                '{"type": "ping",}', "{'type': 'ping'}", '{"type": "ping", "id": ' + "9" * 5000 + '}', "", "  ",
                '{"domain": "a", "domain": "shell_command", "type": "call_service"}']
        for text in evil:
            self.assertEqual(W.deny_verdict(text, frozenset(), frozenset({"ping", "get_states"}), ()),
                             "not_json", text[:50])
            self.assertEqual(W.deny_verdict(text, frozenset(), None, self.ha["rules"]), "not_json", text[:50])

    def test_type_confusion_in_rule_values(self):
        def rule(**m):
            return [{"match": m, "action": "deny", "reason": ""}]
        r = rule(type="t", n=1)
        for n in ("1", "1.0", '"1"', "1e0", "10e-1"):
            self.assertEqual(W.deny_verdict('{"type": "t", "n": %s}' % n, frozenset(), None, r), "rule_denied", n)
        for n in ("true", "2", "1.5", "null", "[1]", "{}", '"01"', '"1 "'):
            self.assertIsNone(W.deny_verdict('{"type": "t", "n": %s}' % n, frozenset(), None, r), n)
        rb = rule(type="t", b=True)
        for b in ("true", '"true"'):
            self.assertEqual(W.deny_verdict('{"type": "t", "b": %s}' % b, frozenset(), None, rb), "rule_denied", b)
        for b in ("1", "false", '"True"', "null"):
            self.assertIsNone(W.deny_verdict('{"type": "t", "b": %s}' % b, frozenset(), None, rb), b)
        # a rule value of 1 must not match the boolean true (Python's True == 1)
        self.assertIsNone(W.deny_verdict('{"type": "t", "n": true}', frozenset(), None, r))
        # a list is any-of; a list in the FRAME does not match a scalar rule structurally (the backstop is what catches it)
        rl = rule(type="t", d=["a", "b"])
        self.assertEqual(W.deny_verdict('{"type": "t", "d": "b"}', frozenset(), None, rl), "rule_denied")
        self.assertIsNone(W.deny_verdict('{"type": "t", "d": "c"}', frozenset(), None, rl))
        self.assertEqual(W.deny_verdict('{"type": "t", "d": ["b"]}', frozenset(), None, rl), "rule_denied")   # backstop

    def test_matching_is_exact_and_case_sensitive_but_the_backstop_is_not(self):
        r = [{"match": {"type": "t", "d": "x"}, "action": "deny", "reason": ""}]
        self.assertIsNone(W.deny_verdict('{"type": "t", "d": "y"}', frozenset(), None, r))
        self.assertIsNone(W.deny_verdict('{"type": "t", "D": "y"}', frozenset(), None, r))
        self.assertEqual(W.deny_verdict('{"type": "t", "d": "x"}', frozenset(), None, r), "rule_denied")
        # a server that lower-cases (Home Assistant does for domain and service) still hits the backstop
        self.assertEqual(W.deny_verdict('{"type": "T", "d": "X"}', frozenset(), None, r), "rule_denied")
        self.assertEqual(self.v(self.CALL % ("SHELL_COMMAND", "x")), "rule_denied")
        self.assertEqual(self.v(self.CALL.replace("call_service", "CALL_SERVICE") % ("shell_command", "x")), "rule_denied")
        # escaped spellings decode to the same text
        self.assertEqual(self.v(self.CALL % ("shell\\u005fcommand", "x")), "rule_denied")
        self.assertEqual(self.v(self.CALL % ("shell\\u005Fcommand", "x")), "rule_denied")
        self.assertEqual(self.v((self.CALL % ("shell_command", "x")).replace("call_service", "call\\u005fservice")), "rule_denied")
        # a prefix or suffix still contains the string
        self.assertEqual(self.v(self.CALL % (" shell_command", "x")), "rule_denied")
        self.assertEqual(self.v(self.CALL % ("shell_command ", "x")), "rule_denied")

    def test_nested_objects_match_as_subsets(self):
        r = [{"match": {"type": "call_service", "service_data": {"entity_id": "light.a", "o": {"k": 1}}}, "action": "deny", "reason": ""}]
        hit = '{"type": "call_service", "service_data": {"entity_id": "light.a", "o": {"k": 1, "z": 2}, "q": 3}}'
        self.assertEqual(W.deny_verdict(hit, frozenset(), None, r), "rule_denied")
        miss = '{"type": "call_service", "service_data": {"entity_id": "light.b", "o": {"k": 1}}}'
        self.assertIsNone(W.deny_verdict(miss, frozenset(), None, r))
        self.assertIsNone(W.deny_verdict('{"type": "call_service", "service_data": "light.a"}', frozenset(), None, r))   # no backstop: it has a number
        self.assertIsNone(W.deny_verdict('{"type": "call_service", "service_data": {}}', frozenset(), None, r))

    def test_a_rule_only_profile_is_json_only_and_needs_text_types(self):
        for text in ("plain", '{"type": 5}', '{"type": ["call_service"]}', "{"):
            self.assertIn(self.v(text, deny=[], rules=self.ha["rules"], allow=None), ("not_json", "denied_type"), text)
        self.assertIsNone(self.v('{"no": "type"}', deny=[], rules=self.ha["rules"], allow=None))

    def test_huge_arrays_and_deep_nesting_are_bounded(self):
        many = "[" + ",".join(['{"type": "ping"}'] * 20000) + ',{"type": "call_service", "domain": "shell_command"}]'
        self.assertEqual(self.v(many), "rule_denied")
        fine = "[" + ",".join(['{"type": "ping"}'] * 20000) + "]"
        self.assertIsNone(self.v(fine))
        deep = '{"type": "ping", "x": ' + "[" * 16 + "]" * 16 + "}"
        self.assertIn(self.v(deep), (None, "not_json"))
        self.assertEqual(self.v('{"type": "ping", "x": ' + "[" * 17 + "]" * 17 + "}"), "not_json")

    def test_the_backstop_names_the_rule_not_the_frame(self):
        # every string of the rule appears somewhere: counted as a hit even when the structure says otherwise
        text = '{"type": "other", "note": "call_service shell_command"}'
        self.assertEqual(self.v(text), "rule_denied")
        self.assertIsNone(self.v('{"type": "other", "note": "shell_command"}'))        # only one of the two strings

    def test_rule_helpers(self):
        r = {"match": {"a": ["X", "Z"], "b": {"c": "y"}}, "action": "deny", "reason": ""}
        self.assertEqual(sorted(map(tuple, P.rule_groups(r))), [("x", "z"), ("y",)])
        for m in ({"a": ["X", 2], "b": "y"}, {"a": "x", "d": 3}, {"a": "x", "b": {"c": True}}):
            self.assertIsNone(P.rule_groups({"match": m}), m)       # a number or true/false: structural match only
        self.assertTrue(P.rule_backstop(r, "..x..y.."))
        self.assertFalse(P.rule_backstop(r, "..x.."))


# ------------------------------------------------------------------------------- sessions
class PBase(WsBase):
    """The broker, a stub, and credentials that pick a profile. The admin profile directory is the default one
    (next to the audit log), so the tests also cover that default."""
    explicit_dir = False

    def tweak(self, cfg):
        super().tweak(cfg)
        if self.explicit_dir:
            self.pdir = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, self.pdir, True)
            cfg["ws_profiles_dir"] = self.pdir
        else:
            self.pdir = None
        for name, ws in (("haprof", {"profile": "home-assistant"}), ("harw", {"profile": "home-assistant-readonly"}),
                         ("haadm", {"profile": "home-assistant-admin"}),
                         ("harwn", {"profile": "home-assistant-readonly", "allow_send": ["get_states", "ping"]}),
                         ("haxtra", {"profile": "home-assistant", "deny_send_extra": ["config/entity_registry/remove"]}),
                         ("hacustom", {"profile": "ha-lights"}), ("hacustom2", {"profile": "home-assistant"})):
            item = name.capitalize()
            cfg["_vault"][item] = {"token": TOKEN}
            cfg["secrets"][name] = {"vars": {name.upper() + "_TOKEN": {"item": item, "field": "token"}},
                                    "allowed_hosts": ["127.0.0.1"], "ws": ws}

    def setUp(self):
        self.pdir_made = []
        super().setUp()
        self.pd = self.pdir or os.path.join(os.path.dirname(self.audit), "ws-profiles")
        os.makedirs(self.pd, exist_ok=True)

    def put(self, name, obj, mode=0o644):
        write(os.path.join(self.pd, name + ".json"), obj, mode)

    def tick(self):
        """One sweeper tick; the catalog refresh runs in its own thread, so wait for it, then sweep again."""
        self.broker._catalog_at = 0
        self.broker._sweep_refresh_next = 0
        self.broker._sweeper_tick()
        th = getattr(self.broker, "_sweep_refresh_thread", None)
        if th is not None:
            th.join(10)
        self.broker._sweeper_tick()

    def refresh(self):
        self.broker._catalog_at = 0
        self.broker.refresh_catalog()

    def send_json(self, sid, obj):
        return self.wsend(sid, json.dumps(obj))

    def refused(self, sid, obj, cls):
        n = len(self.stub.received)
        code, text = self.send_json(sid, obj) if not isinstance(obj, str) else self.wsend(sid, obj)
        self.assertEqual((code, json.loads(text)["code"]), (403, "session_refused"), text)
        self.assertEqual(len(self.stub.received), n)                 # nothing reached the server
        self.assertEqual(self.events("ws_session_refused")[-1]["reason_class"], cls)
        return text

    def passes(self, sid, obj):
        n = len(self.stub.received)
        code, text = self.send_json(sid, obj) if not isinstance(obj, str) else self.wsend(sid, obj)
        self.assertEqual(code, 200, text)
        self.stub.wait_frames(n + 1)


class SessionBehaviour(PBase):
    def test_default_profile_relays_reads_and_ordinary_service_calls_and_refuses_the_rules(self):
        sid = self.wopen(cred="haprof")
        self.passes(sid, {"id": 1, "type": "get_states"})
        self.passes(sid, {"id": 2, "type": "call_service", "domain": "light", "service": "turn_on",
                          "service_data": {"entity_id": "light.kitchen"}})
        for dom, svc in (("shell_command", "x"), ("python_script", "y"), ("hassio", "addon_start"),
                         ("homeassistant", "stop"), ("homeassistant", "restart")):
            text = self.refused(sid, {"id": 3, "type": "call_service", "domain": dom, "service": svc}, "rule_denied")
            self.assertNotIn(dom, text)                                # fixed text: nothing of the frame is echoed
        self.refused(sid, {"id": 4, "type": "auth/long_lived_access_token", "client_name": "x"}, "denied_type")
        self.refused(sid, "not json", "not_json")
        self.assertEqual(self.events("ws_session_refused")[-1]["profile"], "home-assistant")
        self.assertEqual(len(self.stub.received), 2)

    def test_readonly_profile_passes_reads_and_refuses_writes(self):
        sid = self.wopen(cred="harw")
        for t in READ_TYPES:
            self.passes(sid, {"id": 1, "type": t})
        n = len(self.stub.received)
        for obj in ({"id": 2, "type": "call_service", "domain": "light", "service": "turn_on"},
                    {"id": 3, "type": "config/entity_registry/update", "entity_id": "light.a", "name": "x"},
                    {"id": 4, "type": "lovelace/config/save", "config": {}}, {"id": 5},
                    [{"id": 6, "type": "get_states"}, {"id": 7, "type": "fire_event", "event_type": "x"}]):
            self.refused(sid, obj, "not_allowed")
        self.refused(sid, {"id": 8, "type": "auth/sign_path", "path": "/x"}, "denied_type")        # deny wins
        self.assertEqual(len(self.stub.received), n)

    def test_parser_differential_frames_are_refused_under_allow_send_and_rules(self):
        for cred, expect in (("harw", {"not_json"}), ("haprof", {"not_json"})):
            sid = self.wopen(cred=cred)
            for frame in ('﻿{"type": "get_states"}', '{"type": "get_states", "type": "call_service"}',
                          '{"type": NaN}', '{"type": "get_states"} x', "", '[{"type": "get_states"}', '{"type": "get_states",}'):
                self.refused(sid, frame, "not_json")
            self.as_client(KEY, "POST", "/v1/requests", {"mode": "session_close", "session": sid})
        sid = self.wopen(cred="haprof")
        for frame in ('{"type": "call_service", "domain": "SHELL_COMMAND", "service": "x"}',
                      '{"type": "call_service", "domain": "shell\\u005fcommand", "service": "x"}',
                      '{"domain": ["shell_command"], "type": "call_service"}',
                      '[{"type": "ping"}, {"type": "call_service", "domain": "hassio", "service": "x"}]'):
            self.refused(sid, frame, "rule_denied")

    def test_admin_profile_blocks_nothing(self):
        sid = self.wopen(cred="haadm")
        self.passes(sid, {"id": 1, "type": "auth/long_lived_access_token", "client_name": "x"})
        self.passes(sid, {"id": 2, "type": "call_service", "domain": "shell_command", "service": "x"})
        self.assertEqual(self.wsend(sid, "plain text")[0], 200)
        self.assertEqual(len(self.stub.wait_frames(3)), 3)

    def test_per_credential_overrides_through_a_real_session(self):
        sid = self.wopen(cred="harwn")
        self.passes(sid, {"id": 1, "type": "get_states"})
        self.refused(sid, {"id": 2, "type": "get_config"}, "not_allowed")                # in the profile, narrowed away
        sid2 = self.wopen(cred="haxtra")
        self.refused(sid2, {"id": 3, "type": "config/entity_registry/remove", "entity_id": "x"}, "denied_type")
        self.passes(sid2, {"id": 4, "type": "config/entity_registry/update", "entity_id": "x"})

    def test_the_audit_log_names_the_profile_and_counts_never_rules_or_frames(self):
        sid = self.wopen(cred="haprof")
        self.refused(sid, {"id": 3, "type": "call_service", "domain": "shell_command", "service": "x"}, "rule_denied")
        ev = self.events("ws_session_opened")[0]
        self.assertEqual((ev["profile"], ev["profile_source"], ev["deny_n"], ev["rule_n"], ev["allow_n"]),
                         ("home-assistant", "built-in", 10, 2, None))
        self.assertEqual(len(ev["profile_sha256"]), 16)
        blob = self.audit_text()
        for s in ("shell_command", "runs shell commands", "call_service"):
            self.assertNotIn(s, blob)
        self.assertNoSecret()

    def test_old_credential_spelling_is_the_profile_of_that_name(self):
        sid = self.wopen(cred="hadeny")                           # {"handshake": "home-assistant"}
        self.refused(sid, {"id": 1, "type": "call_service", "domain": "shell_command", "service": "x"}, "rule_denied")
        self.refused(sid, {"id": 2, "type": "auth/sign_path"}, "denied_type")
        sid2 = self.wopen(cred="ha")                                # {"handshake": "home-assistant", "deny_send": []}
        self.assertEqual(self.wsend(sid2, "not json at all")[0], 200)
        self.passes(sid2, {"id": 5, "type": "call_service", "domain": "shell_command", "service": "x"})


class Card(PBase):
    def test_the_card_shows_the_profile_its_sentence_and_the_counts(self):
        self.wask(cred="haprof")
        page = self.get("/")[1]
        self.assertIn("Profile: <b>home-assistant</b> (built-in)", page)
        self.assertIn(P.builtin()[0]["home-assistant"]["card_text"].replace("&", "&amp;"), page)
        self.assertIn("Message types blocked by the operator: 10; 2 field rule(s)", page)
        self.assertIn("create NEW credentials", page)
        self.assertNotIn("Nothing it sends is filtered", page)

    def test_the_readonly_card_says_allow_list_of_n(self):
        self.wask(cred="harw")
        page = self.get("/")[1]
        self.assertIn("allow-list: only 20 message type(s) may be sent", page)

    def test_the_admin_card_says_unrestricted_and_that_nothing_is_filtered(self):
        self.wask(cred="haadm")
        page = self.get("/")[1]
        self.assertIn("UNRESTRICTED", page)
        self.assertIn("Message types blocked by the operator: 0", page)
        self.assertIn("Nothing it sends is filtered or reviewed.", page)

    def test_the_card_mentions_per_credential_changes(self):
        self.wask(cred="harwn")
        self.assertIn("Changed for this credential by the operator: allow send", self.get("/")[1])

    def test_card_text_is_escaped_not_trusted(self):
        self.put("ha-lights", good(name="ha-lights", card_text='<b>hi</b> & "<script>alert(1)</script>"', handshake=P.builtin()[0]["home-assistant"]["handshake"]))
        self.refresh()
        self.wask(cred="hacustom")
        page = self.get("/")[1]
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<b>hi</b>", page)
        self.assertIn("&lt;b&gt;hi&lt;/b&gt; &amp; &quot;&lt;script&gt;", page)

    def test_a_credential_without_a_profile_shows_only_counts(self):
        self.wask(cred="hadeny")
        page = self.get("/")[1]
        self.assertIn("Profile: <b>home-assistant</b>", page)          # the older spelling is the same profile
        self.wask(cred="plainws")
        self.assertIn("Message types blocked by the operator: 0", self.get("/")[1])


class AdminProfiles(PBase):
    LIGHTS = dict(name="ha-lights", description="Lights only.", card_text="Lights: only light services may be called.",
                  handshake={"steps": [
                      {"expect": {"type": "auth_required"}}, {"send": {"type": "auth", "access_token": "{{VAR}}"}},
                      {"expect": {"type": "auth_ok"}}]},
                  allow_send=["call_service", "get_states"],
                  rules=[{"match": {"type": "call_service", "domain": ["switch", "lock", "cover"]}, "reason": "not a light"},
                         {"match": {"type": "call_service", "service": "turn_off", "service_data": {"entity_id": "light.hall"}}}])

    def test_a_custom_profile_loaded_from_the_default_directory_is_enforced(self):
        self.put("ha-lights", self.LIGHTS)
        self.refresh()
        sid = self.wopen(cred="hacustom")
        self.passes(sid, {"id": 1, "type": "call_service", "domain": "light", "service": "turn_on"})
        self.passes(sid, {"id": 2, "type": "get_states"})
        self.refused(sid, {"id": 3, "type": "call_service", "domain": "lock", "service": "unlock"}, "rule_denied")
        self.refused(sid, {"id": 4, "type": "call_service", "domain": "light", "service": "turn_off",
                           "service_data": {"entity_id": "light.hall", "x": 1}}, "rule_denied")
        self.passes(sid, {"id": 5, "type": "call_service", "domain": "light", "service": "turn_off",
                          "service_data": {"entity_id": "light.porch"}})
        self.refused(sid, {"id": 6, "type": "config/entity_registry/update"}, "not_allowed")

    def test_an_admin_profile_overrides_a_builtin_and_the_override_is_logged(self):
        self.put("home-assistant", bi("home-assistant", rules=[], deny_send=["only/this"], card_text="Mine."))
        self.refresh()
        sid = self.wopen(cred="haprof")
        self.passes(sid, {"id": 1, "type": "call_service", "domain": "shell_command", "service": "x"})
        self.refused(sid, {"id": 2, "type": "only/this"}, "denied_type")
        ev = self.events("ws_profile_override")
        self.assertEqual((ev[-1]["profile"], ev[-1]["winner"]), ("home-assistant", "admin"))
        self.wask(cred="haprof")
        self.assertIn("Mine.", self.get("/")[1])

    def test_an_invalid_profile_makes_its_credentials_invalid_but_the_broker_runs(self):
        self.put("ha-lights", "{ not json")
        self.refresh()
        self.assertNotIn("hacustom", self.broker.cfg["secrets"])
        self.assertIn("harw", self.broker.cfg["secrets"])                                        # the others are fine
        ev = self.events("ws_profile_invalid")
        self.assertEqual([(e["profile"], e["source"]) for e in ev], [("ha-lights", "admin")])
        cat = self.events("catalog_loaded")[-1]
        bad = [b for b in cat["invalid"] if "ha-lights" in b["reason"]]
        self.assertEqual(len(bad), 1)
        self.assertIn("is invalid", bad[0]["reason"])
        self.assertNotIn("not json", json.dumps(cat))
        code, text = self.as_client(KEY, "POST", "/v1/requests",
                                    {"mode": "session", "kind": "ws", "names": ["hacustom"], "url": self.wurl(), "source": "t@box"})
        self.assertNotEqual(code, 202)

    def test_a_missing_profile_is_a_clear_catalog_error(self):
        self.refresh()                                                  # no ha-lights file
        self.assertNotIn("hacustom", self.broker.cfg["secrets"])
        bad = [b for b in self.events("catalog_loaded")[-1]["invalid"] if "ha-lights" in b["reason"]]
        self.assertIn("not known", bad[0]["reason"])

    def test_a_broken_override_of_a_builtin_does_not_fall_back_to_the_looser_one(self):
        self.put("home-assistant", '{"name": "home-assistant"')
        self.refresh()
        self.assertNotIn("haprof", self.broker.cfg["secrets"])
        self.assertNotIn("hadeny", self.broker.cfg["secrets"])                                   # the older spelling too
        self.assertIn("harw", self.broker.cfg["secrets"])

    def test_log_lines_are_once_per_change_and_name_only(self):
        self.put("ha-lights", "{")
        self.refresh()
        self.refresh()
        self.assertEqual(len(self.events("ws_profile_invalid")), 1)
        self.assertEqual(set(self.events("ws_profile_invalid")[0]) - {"seq", "ts", "time", "event", "prev"}, {"profile", "source"})
        self.put("ha-lights", self.LIGHTS)
        self.refresh()
        self.assertEqual(len(self.events("ws_profile_invalid")), 1)
        self.assertIn("hacustom", self.broker.cfg["secrets"])

    def test_an_unreadable_directory_invalidates_every_profile_credential_and_the_broker_still_runs(self):
        os.chmod(self.pd, 0o777)
        try:
            self.refresh()
            for n in ("haprof", "harw", "haadm", "hadeny", "hacustom"):
                self.assertNotIn(n, self.broker.cfg["secrets"], n)
            self.assertIn("plainws", self.broker.cfg["secrets"])
            self.assertEqual(self.events("ws_profile_dir_invalid")[-1]["reason"], "dir_world_writable")
        finally:
            os.chmod(self.pd, 0o755)
        self.refresh()
        self.assertIn("haprof", self.broker.cfg["secrets"])

    def test_a_symlinked_profile_cannot_smuggle_a_file_in(self):
        outside = os.path.join(os.path.dirname(self.pd), "outside.json")
        write(outside, self.LIGHTS)
        os.symlink(outside, os.path.join(self.pd, "ha-lights.json"))
        self.refresh()
        self.assertNotIn("hacustom", self.broker.cfg["secrets"])


class Explicit(PBase):
    explicit_dir = True

    def test_ws_profiles_dir_in_the_settings_is_used(self):
        self.assertNotEqual(self.pd, os.path.join(os.path.dirname(self.audit), "ws-profiles"))
        self.put("ha-lights", AdminProfiles.LIGHTS)
        self.refresh()
        self.assertIn("hacustom", self.broker.cfg["secrets"])
        self.assertEqual(self.broker.ws_profiles.directory, self.pdir)

    def test_a_bad_setting_fails_at_startup(self):
        with self.assertRaises(ValueError):
            P.parse_dir_config({"ws_profiles_dir": 5})


class Binding(PBase):
    """Editing a profile file changes the credential's signature: live sessions end, an open request is refused."""

    def setUp(self):
        super().setUp()
        self.put("ha-lights", AdminProfiles.LIGHTS)
        self.refresh()

    def test_editing_the_file_ends_a_live_session(self):
        sid = self.wopen(cred="hacustom")
        self.assertEqual(self.send_json(sid, {"id": 1, "type": "get_states"})[0], 200)
        self.put("ha-lights", {**AdminProfiles.LIGHTS, "allow_send": ["get_states"]})
        self.tick()
        self.assertEqual(self.send_json(sid, {"id": 2, "type": "get_states"})[0], 410)
        self.assertTrue(self.stub.eof[0].wait(5))

    def test_an_unchanged_file_keeps_it(self):
        sid = self.wopen(cred="hacustom")
        self.put("ha-lights", dict(AdminProfiles.LIGHTS))                 # rewritten, same content
        self.tick()
        self.assertEqual(self.send_json(sid, {"id": 1, "type": "get_states"})[0], 200)

    def test_deleting_or_breaking_the_file_ends_it(self):
        for change in (lambda: os.unlink(os.path.join(self.pd, "ha-lights.json")), lambda: self.put("ha-lights", "{")):
            self.put("ha-lights", AdminProfiles.LIGHTS)
            self.refresh()
            st = self.mkstub()
            sid = self.wopen(cred="hacustom", url=self.wurl(stub=st))
            change()
            self.tick()
            self.assertEqual(self.send_json(sid, {"id": 1, "type": "get_states"})[0], 410)
            self.assertTrue(st.eof[0].wait(5))

    def test_a_file_edited_between_the_card_and_the_approval_is_not_opened(self):
        r = self.wask(cred="hacustom")
        self.put("ha-lights", {**AdminProfiles.LIGHTS, "rules": []})
        self.broker._catalog_at = 0
        self.approve(r["id"])
        self.assertEqual(self.result(r["id"])["error"],
                         "session not opened: the credential changed since the session was approved")
        self.assertEqual(self.stub.requests, [])

    def test_editing_a_builtin_override_or_a_builtin_credential_override_changes_the_signature(self):
        sig = lambda: self.broker._ws_sig(self.broker.cfg["secrets"]["haprof"])        # noqa: E731
        a = sig()
        self.put("home-assistant", bi("home-assistant", card_text="Changed."))
        self.refresh()
        self.assertNotEqual(a, sig())

    def test_the_old_session_still_enforces_what_it_was_approved_with_until_it_ends(self):
        sid = self.wopen(cred="hacustom")
        self.refused(sid, {"id": 1, "type": "config/entity_registry/update"}, "not_allowed")


# ------------------------------------------------------------------------------- agents can never pick a profile
class AgentSafety(PBase):
    def test_a_credential_made_through_the_broker_cannot_carry_a_ws_setting(self):
        final = {"name": "agentmade", "item": "Agentmade", "field": "notes", "kind": "token", "cred_mode": "http",
                 "hosts": ["127.0.0.1"], "vars": {"x": "AGENTMADE_TOKEN"}, "ws": {"profile": "home-assistant-admin"},
                 "profile": "home-assistant-admin", "handshake": "home-assistant"}
        meta = Broker._credential_meta(final, "check")
        self.assertEqual(set(meta), {"name", "vars", "allowed_hosts", "approval", "created"})
        name, entry = Broker._entry("Agentmade", meta)
        self.assertIsNone(entry["_ws"])
        self.assertNotIn("ws", entry)

    def test_a_ws_session_on_a_credential_without_ws_is_refused(self):
        code, text = self.as_client(KEY, "POST", "/v1/requests",
                                    {"mode": "session", "kind": "ws", "names": ["methcred"], "url": self.wurl(), "source": "t@box"})
        self.assertEqual(code, 403, text)

    def test_the_agents_open_request_cannot_carry_a_profile(self):
        for cred, extra in (("haprof", {"profile": "home-assistant-admin"}), ("harw", {"ws": {"profile": "home-assistant-admin"}}),
                            ("haxtra", {"deny_send": []}), ("harwn", {"allow_send": ["x"]}),
                            ("hacustom2", {"handshake": "home-assistant-admin"})):
            code, text = self.as_client(KEY, "POST", "/v1/requests",
                                        {"mode": "session", "kind": "ws", "names": [cred], "url": self.wurl(),
                                         "source": "t@box", **extra})
            self.assertEqual(code, 202, (extra, text))
            rid = json.loads(text)["id"]
            self.post("/decide", {"id": rid, "decision": "deny"})
            want = self.broker.cfg["secrets"][cred]["_ws"]["profile"]["name"]
            self.assertEqual(self.broker._by_id[rid].spec.get("profile"), want, extra)   # the credential's, not the agent's
            self.assertNotIn("home-assistant-admin", json.dumps({k: v for k, v in self.broker._by_id[rid].spec.items()}))


class AgentCredentialFlow(tcr.H):
    """A credential an agent asks for (and a human stores) can never carry a ws setting or a profile name, however
    the request or the form is spelled."""

    def test_ws_and_profile_fields_in_the_request_and_the_form_are_never_stored(self):
        body = {"mode": "credential", "names": ["newapi"], "kind": "token", "purpose": tcr.PURPOSE, "hosts": ["127.0.0.1"],
                "ws": {"profile": "home-assistant-admin"}, "profile": "home-assistant-admin", "handshake": "home-assistant"}
        code, text = self.api("POST", "/v1/requests", body)
        self.assertEqual(code, 202, text)                            # accepted with the extras ignored: they are never stored
        if code == 202:
            rid = json.loads(text)["id"]
            form = {"ws": json.dumps({"profile": "home-assistant-admin"}), "profile": "home-assistant-admin",
                    "ws[profile]": "home-assistant-admin", "handshake": "home-assistant", "deny_send": ""}
            status, page, _ = self.submit(rid, form)
            self.assertEqual(status, 200, page)
            self.assertTrue(self.stored())
            self.assertIsNone(self.broker.cfg["secrets"]["newapi"]["_ws"])
            self.settle(rid)
            raws = [r["broker"] for r in self.broker.backend._data.values() if "newapi" in r.get("broker", "")]
            self.assertEqual(len(raws), 1)
            raw = raws[0]
            for word in ("ws", "profile", "handshake", "home-assistant"):
                self.assertNotIn(word, raw)
            code, text = self.api("POST", "/v1/requests", {"mode": "session", "kind": "ws", "names": ["newapi"],
                                                            "url": "ws://127.0.0.1:1/x", "source": "t@box"})
            self.assertEqual(code, 403, text)
            self.assertIn("not set up for WebSocket", text)
        else:
            self.assertIn(code, (400, 403))

    def test_a_ws_setting_in_stored_metadata_of_an_agent_created_credential_is_not_ours_to_trust(self):
        # the metadata the broker writes for a credential request has exactly these keys: no ws, no profile
        final = {"name": "n", "item": "N", "field": "notes", "kind": "token", "cred_mode": "http", "hosts": ["a.example.com"],
                 "vars": {"x": "N_TOKEN"}, "ws": {"profile": "p"}, "profile": "p"}
        self.assertEqual(set(Broker._credential_meta(final, "alice")), {"name", "vars", "allowed_hosts", "approval", "created"})


# ------------------------------------------------------------------------------- the admin commands
class Cli(TmpDir):
    def run_cli(self, *argv, settings=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                rc = CLI.main(list(argv), lambda path=None: settings or {})
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_validate_exit_codes_and_messages(self):
        a, b, c = (os.path.join(self.pd, n) for n in ("a.json", "b.json", "c.json"))
        write(a, good(name="a"))
        write(b, good(name="b", bogus=1))
        write(c, '{"name": "c", "name": "c"}')
        rc, out, err = self.run_cli("validate", a)
        self.assertEqual((rc, out), (0, f"ok {a}: a\n"))
        rc, out, err = self.run_cli("validate", a, b, c)
        self.assertEqual(rc, 1)
        self.assertIn(f"INVALID {b}: bogus is not a known profile field", out)
        self.assertIn(f"INVALID {c}: not strict JSON (duplicate key)", out)
        self.assertIn(f"ok {a}", out)
        self.assertEqual(self.run_cli("validate", os.path.join(self.pd, "missing.json"))[0], 1)
        self.assertEqual(self.run_cli("validate")[0], 2)                                 # usage
        d = os.path.join(self.pd, "wrongname.json")
        write(d, good(name="other"))
        self.assertIn("name must match the file name", self.run_cli("validate", d)[1])

    def test_validate_names_the_field_for_each_kind_of_error(self):
        cases = (({"card_text": ""}, "card_text"), ({"deny_send": "x"}, "deny_send"), ({"allow_send": []}, "allow_send"),
                 ({"rules": [{"match": {}}]}, "rules[].match"), ({"origin": "ftp://x"}, "origin"),
                 ({"handshake": {"steps": [{"send": "{{NOPE}}"}]}}, "placeholder"), ({"description": "é"}, "description"),
                 ({"risk_notes": "x"}, "risk_notes"), ({"query": {"a b": 1}}, "query"))
        for over, word in cases:
            p = os.path.join(self.pd, "svc.json")
            write(p, good(**over))
            rc, out, _ = self.run_cli("validate", p)
            self.assertEqual(rc, 1, over)
            self.assertIn(word, out, over)

    def test_validate_does_not_print_file_content(self):
        p = os.path.join(self.pd, "svc.json")
        write(p, good(description="SECRET-CANARY-7é"))
        rc, out, err = self.run_cli("validate", p)
        self.assertEqual(rc, 1)
        self.assertNotIn("CANARY", out + err)

    def test_validate_rejects_huge_and_non_utf8_files(self):
        p = os.path.join(self.pd, "svc.json")
        write(p, b"{" + b" " * (P.MAX_FILE_BYTES + 1))
        self.assertIn("larger than 64 KiB", self.run_cli("validate", p)[1])
        write(p, b'{"name": "svc", "description": "\xff"}')
        self.assertIn("not valid UTF-8", self.run_cli("validate", p)[1])

    def test_new_writes_a_valid_starter_and_refuses_to_overwrite(self):
        rc, out, _ = self.run_cli("new", "my-service", "--dir", self.pd)
        self.assertEqual(rc, 0, out)
        path = os.path.join(self.pd, "my-service.json")
        self.assertEqual(self.run_cli("validate", path)[0], 0)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        before = open(path).read()
        rc, out, err = self.run_cli("new", "my-service", "--dir", self.pd)
        self.assertEqual(rc, 1)
        self.assertIn("already exists", err)
        self.assertEqual(open(path).read(), before)

    def test_new_from_a_builtin_copies_it_and_the_copy_validates(self):
        for src in P.BUILTIN_NAMES:
            rc, out, err = self.run_cli("new", "copy-of-" + src, "--from", src, "--dir", self.pd)
            self.assertEqual(rc, 0, err)
            path = os.path.join(self.pd, "copy-of-" + src + ".json")
            self.assertEqual(self.run_cli("validate", path)[0], 0)
            got, orig = json.load(open(path)), P.builtin()[0][src]
            self.assertEqual(got.get("deny_send", []), orig["deny_send"])
            self.assertEqual(got.get("allow_send"), orig["allow_send"])
            self.assertEqual(got.get("rules", []), orig["rules"])
        rc, out, err = self.run_cli("new", "x", "--from", "nope", "--dir", self.pd)
        self.assertEqual(rc, 1)

    def test_new_with_a_builtin_name_says_it_overrides_it(self):
        rc, out, _ = self.run_cli("new", "home-assistant", "--from", "home-assistant", "--dir", self.pd)
        self.assertEqual(rc, 0)
        self.assertIn("replaces the built-in", out)

    def test_new_rejects_bad_names_and_never_leaves_the_directory(self):
        for bad in ("../x", "a/b", "A", "x y", "x" * 65, "x-", ""):
            rc, out, err = self.run_cli("new", bad, "--dir", self.pd)
            self.assertEqual(rc, 1, bad)
        self.assertEqual(os.listdir(self.pd), [])
        self.assertEqual(os.listdir(self.d), ["ws-profiles"])

    def test_new_does_not_follow_a_symlink_at_the_target(self):
        os.symlink(os.path.join(self.d, "elsewhere.json"), os.path.join(self.pd, "linked.json"))
        rc, out, err = self.run_cli("new", "linked", "--dir", self.pd)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(os.path.join(self.d, "elsewhere.json")))

    def test_new_uses_the_directory_from_the_settings(self):
        d2 = os.path.join(self.d, "from-settings")
        rc, out, err = self.run_cli("new", "svc", settings={"ws_profiles_dir": d2})
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.exists(os.path.join(d2, "svc.json")))
        rc, out, err = self.run_cli("new", "svc2", settings={"audit_log": os.path.join(self.d, "audit.jsonl")})
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.exists(os.path.join(self.d, "ws-profiles", "svc2.json")))
        rc, out, err = self.run_cli("new", "svc3", settings={})
        self.assertEqual(rc, 1)
        self.assertIn("no profiles directory", err)

    def test_list_shows_builtins_admin_and_overrides(self):
        self.put("mine", good(name="mine"))
        self.put("home-assistant", good(name="home-assistant"))
        self.put("broken", "{")
        rc, out, err = self.run_cli("list", "--dir", self.pd)
        self.assertEqual(rc, 1)                                           # one is invalid
        lines = {ln.split()[0]: ln for ln in out.splitlines()[1:]}
        self.assertIn("admin", lines["mine"])
        self.assertIn("overrides built-in", lines["home-assistant"])
        self.assertIn("built-in", lines["home-assistant-readonly"])
        self.assertIn("INVALID", lines["broken"])
        os.unlink(os.path.join(self.pd, "broken.json"))
        self.assertEqual(self.run_cli("list", "--dir", self.pd)[0], 0)

    def test_list_flags_a_broken_override_of_a_builtin(self):
        self.put("home-assistant", "{")
        rc, out, _ = self.run_cli("list", "--dir", self.pd)
        self.assertEqual(rc, 1)
        self.assertIn("shadows built-in", out)

    def test_show_prints_the_effective_profile_and_risk_notes(self):
        rc, out, err = self.run_cli("show", "home-assistant-readonly", "--dir", self.pd)
        self.assertEqual(rc, 0, err)
        body = out[out.index("{"):out.rindex("}") + 1]
        self.assertEqual(json.loads(body)["name"], "home-assistant-readonly")
        self.assertIn("allow-list of 20", out)
        self.assertIn("Risk notes:\n  - Only the listed read message types", out)
        self.put("home-assistant-readonly", good(name="home-assistant-readonly", risk_notes=["mine"]))
        rc, out, _ = self.run_cli("show", "home-assistant-readonly", "--dir", self.pd)
        self.assertIn("(admin)", out)
        self.assertIn("  - mine", out)
        rc, out, err = self.run_cli("show", "nope", "--dir", self.pd)
        self.assertEqual(rc, 1)
        self.assertIn("not known", err)
        self.put("bad", "{")
        self.assertEqual(self.run_cli("show", "bad", "--dir", self.pd)[0], 1)
        self.assertEqual(self.run_cli("show", "../x", "--dir", self.pd)[0], 1)

    def put(self, name, obj):
        write(os.path.join(self.pd, name + ".json"), obj)

    def test_python_dash_m_dispatch_and_exit_codes(self):
        env = {"PATH": os.environ["PATH"], "HOME": self.d}
        root = os.path.join(os.path.dirname(__file__), "..")

        def run(*a):
            return subprocess.run([sys.executable, "-m", "secret_broker", "ws-profile", *a], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=60)
        p = run("list", "--dir", self.pd)
        self.assertEqual((p.returncode, p.stdout.split()[0:3]), (0, ["admin", "profiles", "directory:"]))
        self.assertEqual(run("validate", os.path.join(self.d, "none.json")).returncode, 1)
        self.assertEqual(run("bogus").returncode, 2)
        self.assertEqual(run().returncode, 2)


if __name__ == "__main__":
    unittest.main()
