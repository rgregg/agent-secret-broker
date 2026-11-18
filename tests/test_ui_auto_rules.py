"""Auto-approve rules kept in a credential's vault metadata (`auto_rules`) and managed from the Policies tab.

The properties: one validator for config rules and stored rules (so the form and the matcher cannot disagree);
a stored rule belongs to the one credential it is stored on; expired rules never match; creating or revoking a
rule needs the approver's authenticated session, a confirmation tick and a valid shape, and every refusal is a
fixed reason; nothing typed into the form reaches an agent response or the audit log.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_e2e as t  # noqa: E402
import test_grants as tg  # noqa: E402
from secret_broker import audit_api, autorules, sshrules  # noqa: E402
from secret_broker.backends import MemoryBackend  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
from test_auto_rules import Enrolled  # noqa: E402
from test_ssh_rules import NoMeta  # noqa: E402

FUTURE = sshrules.iso(time.time() + 86400 * 30)
PAST = sshrules.iso(time.time() - 3600)
BOX = "c-0a0b0c0d"


def http_rule(**kw):
    return {"id": "r0001", "name": "news", "mode": "http", "host": "api.example.com", "methods": ["GET", "POST"],
            "path_prefix": "/v1", "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None, **kw}


def env_rule(**kw):
    return {"id": "r0002", "name": "nightly", "mode": "env", "argv": ["python3", "report.py"],
            "by": "alice", "at": "2026-11-18T00:00:00Z", "expires_at": None, **kw}


class Parse(unittest.TestCase):
    def test_config_parse_is_unchanged(self):
        r = autorules.parse([{"name": "h", "mode": "http", "secret": "a", "host": "H.example.com"}])[0]
        self.assertEqual((r["host"], r["methods"], r["path_prefix"], r["source"]),
                         ("h.example.com", frozenset({"GET", "HEAD"}), "/", "config"))
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "sudo", "secret": "a"}])
        self.assertIn("auto_approve[0].mode 'sudo' always needs a human", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            autorules.parse([{"name": "x", "mode": "http", "host": "h.example.com"}])
        self.assertIn("exactly one of secret", str(cm.exception))

    def test_stored_http_rule_round_trips(self):
        raw = [http_rule()]
        rules = autorules.parse_stored(raw, "news-key")
        self.assertEqual(rules[0]["source"], "ui")
        self.assertEqual(rules[0]["secrets"], frozenset({"news-key"}))
        self.assertEqual(rules[0]["clients"], frozenset())
        self.assertEqual(autorules.serialize_stored(rules), raw)

    def test_stored_client_list_round_trips_sorted(self):
        raw = [http_rule(clients=[BOX])]
        self.assertEqual(autorules.serialize_stored(autorules.parse_stored(raw, "k")), raw)

    def test_stored_env_rule_round_trips(self):
        raw = [env_rule(expires_at=FUTURE)]
        rules = autorules.parse_stored(raw, "k")
        self.assertEqual(rules[0]["argv"], ("python3", "report.py"))
        self.assertEqual(autorules.serialize_stored(rules), raw)

    def test_stored_rejects_secret_and_secrets(self):
        for key, val in (("secret", "other"), ("secrets", ["other"])):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(**{key: val})], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_rejects_ssh_sign_and_human_only_modes(self):
        for mode in ("ssh_sign", "sudo", "plan", "bogus"):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(mode=mode)], "k")
            self.assertIn("auto_rules[0].mode", str(cm.exception), mode)
        self.assertEqual(len(autorules.parse_stored([http_rule()], "k")), 1)     # positive control

    def test_stored_requires_id_by_and_at(self):
        for key in ("id", "by", "at"):
            raw = http_rule()
            del raw[key]
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([raw], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_bad_times_are_refused(self):
        for key, val in (("at", "yesterday"), ("expires_at", "2026-13-99")):
            with self.assertRaises(ValueError) as cm:
                autorules.parse_stored([http_rule(**{key: val})], "k")
            self.assertIn(f"auto_rules[0].{key}", str(cm.exception))

    def test_stored_duplicate_name_and_id(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(), http_rule(id="r0009", name="NEWS")], "k")
        self.assertIn("used twice", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(), http_rule(name="other")], "k")
        self.assertIn("auto_rules[1].id", str(cm.exception))

    def test_stored_cap_is_50(self):
        many = [http_rule(id=f"r{i:04d}", name=f"n{i}") for i in range(50)]
        self.assertEqual(len(autorules.parse_stored(many, "k")), 50)
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored(many + [http_rule(id="r9999", name="n50")], "k")
        self.assertIn("more than 50", str(cm.exception))

    def test_unknown_key_names_the_field(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored([http_rule(account="ryan")], "k")
        self.assertIn("auto_rules[0].account", str(cm.exception))

    def test_stored_must_be_a_list(self):
        with self.assertRaises(ValueError) as cm:
            autorules.parse_stored({"id": "x"}, "k")
        self.assertIn("auto_rules must be a list", str(cm.exception))
        self.assertEqual(autorules.parse_stored(None, "k"), [])


class SharedMatcher(unittest.TestCase):
    """Cases the HTTP layer refuses before any rule is looked at (an override header) still must not match."""

    def find(self, **spec):
        rules = autorules.parse_stored([http_rule(methods=["GET", "POST"])], "k")
        return autorules.find(rules, "http", ["k"], {"url": "https://api.example.com/v1/x", "method": "GET", **spec},
                              {"id": BOX})

    def test_override_headers_and_parameters_never_match(self):
        self.assertIsNotNone(self.find(headers={}))                                       # control
        for h in ("X-HTTP-Method-Override", "x-method-override", "X-Original-URL", "X-Rewrite-URL"):
            self.assertIsNone(self.find(headers={h: "DELETE"}), h)
        self.assertIsNone(self.find(url="https://api.example.com/v1/x?_method=DELETE"))
        self.assertIsNone(self.find(method="POST", body='{"method": "DELETE"}'))
        self.assertIsNotNone(self.find(method="POST", body='{"payment_method": "card"}'))   # only the name counts


class Expiry(unittest.TestCase):
    SPEC = {"url": "https://api.example.com/v1/x", "method": "GET", "headers": {}}

    def find(self, rule, now=None):
        rules = autorules.parse_stored([rule], "k")
        return autorules.find(rules, "http", ["k"], self.SPEC, {"id": BOX}, now)

    def test_find_skips_expired_and_keeps_unexpired(self):
        self.assertIsNotNone(self.find(http_rule(expires_at=FUTURE)))
        self.assertIsNone(self.find(http_rule(expires_at=PAST)))

    def test_find_uses_the_given_clock(self):
        far = sshrules.to_epoch(FUTURE) + 1
        self.assertIsNone(self.find(http_rule(expires_at=FUTURE), now=far))

    def test_is_expired_ignores_config_rules_and_none(self):
        cfg = autorules.parse([{"name": "h", "mode": "http", "secret": "k", "host": "api.example.com"}])[0]
        self.assertFalse(autorules.is_expired(cfg, time.time() + 10 ** 9))
        stored = autorules.parse_stored([http_rule()], "k")[0]
        self.assertFalse(autorules.is_expired(stored, time.time() + 10 ** 9))


def svc_rule(**kw):
    """A stored rule for the harness's `svc` credential: plain http to the local stub under /x."""
    return http_rule(scheme="http", host="127.0.0.1", methods=["GET", "POST"], path_prefix="/x", **kw)


class Match(Enrolled, t.Harness):
    """A stored rule approves exactly what the same rule in the config approves."""

    def setUp(self):
        super().setUp()
        self.port = self.up.server_address[1]
        self.set_stored(svc_rule())

    def set_stored(self, *raw, name="svc"):
        self.broker.cfg["secrets"][name]["auto_rules"] = autorules.parse_stored(list(raw), name)

    def call(self, method="GET", path="/x", headers=None, body=None, key=None):
        spec = {"mode": "http", "names": ["svc"], "method": method, "url": f"http://127.0.0.1:{self.port}{path}",
                "headers": {"Authorization": "Bearer {{SVC_TOKEN}}", **(headers or {})}}
        if body is not None:
            spec["body"] = body
        code, raw = self.api("POST", "/v1/requests", spec, key=key)
        self.assertEqual(code, 202, raw)
        return json.loads(raw)["id"]

    def approved_without_asking(self, rid):
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        self.assertEqual(json.loads(b)["http"]["status"], 200)
        return self.events("approved")[-1]

    def prompted(self, rid):
        """True when no rule decided this request (the harness's fake phone then answered it)."""
        return not [e for e in self.events("auto_rule_used") if e.get("id") == rid]

    def test_stored_http_rule_approves_like_a_config_rule(self):
        stored = self.approved_without_asking(self.call())
        self.assertEqual((stored["via"], stored["decision_source"], stored["rule_name"]),
                         ("policy", "ui_rule", "news"))
        self.set_stored()                                             # no stored rule now
        self.broker.auto_rules = autorules.parse([
            {"name": "news", "mode": "http", "secret": "svc", "scheme": "http", "host": "127.0.0.1",
             "methods": ["GET", "POST"], "path_prefix": "/x"}])
        config = self.approved_without_asking(self.call())
        self.assertEqual((config["via"], config["decision_source"], config["rule_name"]),
                         ("policy", "config_rule", "news"))
        self.assertEqual(self.notifier.sent, [])

    def test_the_matcher_table_is_shared_with_config_rules(self):
        cases = {
            "percent escape in the path": dict(path="/x%2fy"),
            "dot segment": dict(path="/x/../admin"),
            "GET with a body": dict(body="x=1"),
            "method named in a body": dict(method="POST", body="_method=DELETE"),
            "wrong prefix": dict(path="/xy"),
            "wrong method": dict(method="DELETE"),
        }
        for label, kw in cases.items():
            rid = self.call(**kw)
            self.assertTrue(self.prompted(rid), label)
        self.assertEqual(len(self.notifier.sent), len(cases))
        self.assertEqual(self.approved_without_asking(self.call())["decision_source"], "ui_rule")   # control

    def test_empty_clients_means_an_enrolled_client_and_never_the_legacy_key(self):
        self.assertTrue(self.prompted(self.call(key=t.KEY)))
        self.assertFalse(self.prompted(self.call()))
        self.assertEqual(self.broker.cfg["secrets"]["svc"]["auto_rules"][0]["clients"], frozenset())

    def test_a_rule_pinned_to_one_client_serves_only_that_client(self):
        self.set_stored(svc_rule(clients=["c-0a0b0c0d"]))
        self.assertTrue(self.prompted(self.call()))
        self.set_stored(svc_rule(clients=[self.client.id]))
        self.assertFalse(self.prompted(self.call()))

    def test_a_client_set_to_never_auto_approve_still_prompts(self):
        self.broker.clients_cfg["overrides"][self.client.id] = {"auto_approve_max": "none"}
        self.assertTrue(self.prompted(self.call()))
        self.assertEqual(self.events("auto_rule_used"), [])
        del self.broker.clients_cfg["overrides"][self.client.id]
        self.assertFalse(self.prompted(self.call()))                  # control: the rule works without it

    def test_an_expired_rule_is_ignored_before_any_sweep(self):
        self.set_stored(svc_rule(expires_at=PAST))
        self.assertTrue(self.prompted(self.call()))
        self.set_stored(svc_rule(expires_at=FUTURE))
        self.assertFalse(self.prompted(self.call()))

    def test_usage_is_counted_and_kept_beside_the_audit_log(self):
        self.assertEqual(self.broker.auto_rule_usage.get("svc", "r0001")["uses"], 0)
        self.approved_without_asking(self.call())
        u = self.broker.auto_rule_usage.get("svc", "r0001")
        self.assertEqual(u["uses"], 1)
        self.assertIsNotNone(u["last_used"])
        self.assertTrue(os.path.exists(os.path.join(os.path.dirname(self.broker._audit._path),
                                                    "auto_rules_state.json")))

    def test_the_used_event_names_the_source_and_the_rule_and_is_hidden_from_agents(self):
        self.approved_without_asking(self.call())
        used = self.events("auto_rule_used")[-1]
        self.assertEqual((used["source"], used["rule_id"], used["rule_name"]), ("ui", "r0001", "news"))
        self.assertIn("auto_rule_used", audit_api.HIDDEN)             # the agent API never returns it
        code, body = self.api("GET", "/v1/audit")
        self.assertEqual(code, 200)
        self.assertNotIn("auto_rule_used", body)
        self.assertNotIn("news", body)
        self.assertIn('"approved"', body)                             # control: the audit view is populated

    def test_the_history_says_a_policies_rule_decided(self):
        rid = self.call()
        self.approved_without_asking(rid)
        row, _ = self.broker.history.detail(rid)
        self.assertEqual((row["outcome"], row["rule_name"], row["decision_source"]),
                         ("auto-approved", "news", "ui_rule"))
        page = t.req(self.abase + f"/request/{rid}?fragment=1", headers={"X-authentik-username": "alice"})[1]
        self.assertIn('Policies rule "news" (auto-approved)', page)
        self.assertIn("class='pill ok'>auto-approved", page)           # the pill's class is not clobbered
        self.assertNotIn("configuration rule", page)


class WrongCredential(Enrolled, tg.Base):
    """A rule stored on one credential never approves a request that names another, or a pair."""

    def setUp(self):
        super().setUp()
        raw = {"id": "e0001", "name": "greet", "mode": "env", "argv": ["echo", "hi"], "by": "alice",
               "at": "2026-11-18T00:00:00Z", "expires_at": None}
        self.broker.cfg["secrets"]["svc"]["auto_rules"] = autorules.parse_stored([raw], "svc")

    def env(self, names):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": names, "argv": ["echo", "hi"]})
        self.assertEqual(code, 202, body)
        return json.loads(body)["id"]

    def test_a_rule_on_svc_never_approves_svc_and_other_or_just_other(self):
        self.assertEqual(len(self.notifier.sent), 0)
        self.env(["svc", "other"])
        self.env(["other"])
        self.assertEqual(len(self.notifier.sent), 2)                  # a human was asked both times
        self.assertEqual(self.events("auto_rule_used"), [])
        rid = self.env(["svc"])                                       # control: the rule serves its own credential
        _, b = self.api("GET", f"/v1/requests/{rid}?wait=3")
        self.assertEqual(json.loads(b)["env"], {"SVC_TOKEN": t.SECRET})
        self.assertEqual(self.events("auto_rule_used")[-1]["source"], "ui")


class Loading(unittest.TestCase):
    META = {"name": "k", "vars": {"K": {"item": "Item", "field": "password"}}, "allowed_hosts": ["a.example"]}

    def test_stored_rules_load_onto_the_entry_and_not_into_the_raw_metadata(self):
        _, entry = Broker._entry("Item", {**self.META, "auto_rules": [http_rule()]})
        self.assertEqual(entry["auto_rules"][0]["name"], "news")
        self.assertEqual(entry["auto_rules"][0]["secrets"], frozenset({"k"}))
        self.assertEqual(entry["_meta"]["auto_rules"][0]["name"], "news")      # still the vault's own JSON

    def test_only_for_credentials_that_are_not_ssh_keys(self):
        import test_ssh_rules as tsr
        meta = tsr.Validation.meta(tsr.Validation(), auto_rules=[http_rule()])
        with self.assertRaises(ValueError) as cm:
            Broker._entry("Item", meta)
        self.assertIn("auto_rules only applies to a credential that is not an ssh key", str(cm.exception))
        _, ok = Broker._entry("Item", {**self.META, "auto_rules": [http_rule()]})      # control
        self.assertIn("auto_rules", ok)

    def test_a_malformed_list_names_the_field(self):
        for label, bad in {"host": http_rule(host="not a host"), "mode": http_rule(mode="ssh_sign"),
                           "no id": {k: v for k, v in http_rule().items() if k != "id"}}.items():
            with self.assertRaises(ValueError, msg=label) as cm:
                Broker._entry("Item", {**self.META, "auto_rules": [bad]})
            self.assertIn("auto_rules[0].", str(cm.exception), label)

    def test_a_malformed_list_invalidates_only_that_credential(self):
        def meta(name, item, rules):
            return {**self.META, "name": name, "vars": {"K": {"item": item, "field": "password"}},
                    "auto_rules": rules}
        good, bad = meta("good", "ItemA", [http_rule()]), meta("bad", "ItemB", [{"id": "x"}])

        class Rows(MemoryBackend):
            def catalog(self):
                return [{"item": "ItemA", "meta": good, "auto": None}, {"item": "ItemB", "meta": bad, "auto": None}]
        b = Broker({"approve_base_url": "https://s.example"}, Rows(), FakeNotifier(), None)
        self.assertIn("good", b.cfg["secrets"])
        self.assertNotIn("bad", b.cfg["secrets"])
        self.assertEqual(b._catalog_stats["invalid"], 1)


class Manage(Enrolled, tg.Base):
    """Adding, revoking and expiring stored rules through the Broker methods the Policies tab calls."""
    risk = "high"

    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["secrets"]["svc"]["approval"] = "allow"          # another metadata key a rule write must not clobber

    FIELDS = dict(name="news", mode="http", host="127.0.0.1", scheme="http", methods=["GET", "POST"],
                  path_prefix="/x", argv=[], client="*")

    def add(self, cred="svc", expiry="never", confirm=True, user="alice", **over):
        """`over` overrides the rule's own fields (including its `name`); `cred` is the credential."""
        return self.broker.add_auto_rule(cred, {**self.FIELDS, **over}, expiry, confirm, user, "127.0.0.1", "10.0.0.9")

    def stored(self, name="svc"):
        return self.disk()["secrets"][name].get("auto_rules", [])

    def live(self, name="svc"):
        return self.broker.cfg["secrets"][name].get("auto_rules", [])

    def call(self):
        port = self.up.server_address[1]
        code, raw = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["svc"], "method": "GET", "url": f"http://127.0.0.1:{port}/x",
            "headers": {"Authorization": "Bearer {{SVC_TOKEN}}"}})
        self.assertEqual(code, 202, raw)
        return json.loads(raw)["id"]

    def used(self):
        return len(self.events("auto_rule_used"))

    def seed(self, *raw, name="svc"):
        """Rules already in the vault (as an earlier session left them)."""
        self.broker._persist_auto_rules(name, autorules.parse_stored(list(raw), name), "seed")

    # -- add
    def test_add_http_rule_persists_is_live_and_approves(self):
        res = self.add(expiry="30")
        self.assertEqual((res["status"], res["message"]), ("created", ""))
        [rule] = self.stored()
        self.assertEqual((rule["name"], rule["mode"], rule["host"], rule["methods"], rule["path_prefix"], rule["by"]),
                         ("news", "http", "127.0.0.1", ["GET", "POST"], "/x", "alice"))
        self.assertEqual(rule["scheme"], "http")
        self.assertNotIn("clients", rule)
        self.assertEqual(sshrules.to_epoch(rule["expires_at"]) // 86400, int(time.time() + 30 * 86400) // 86400)
        self.assertEqual(self.live()[0]["id"], rule["id"])
        self.assertEqual(self.disk()["secrets"]["svc"]["approval"], "allow")          # nothing else was clobbered
        ev = self.events("auto_rule_created")[-1]
        self.assertEqual((ev["credential"], ev["rule_id"], ev["rule_name"], ev["rule_mode"], ev["created_by"],
                          ev["channel"], ev["approver_peer"], ev["approver_ip"], ev["rule_host"]),
                         ("svc", rule["id"], "news", "http", "alice", "policies", "127.0.0.1", "10.0.0.9",
                          "127.0.0.1"))
        before = self.used()
        self.call()
        self.assertEqual(self.used(), before + 1)                                     # it is live without a restart
        self.assertEqual(self.events("approved")[-1]["decision_source"], "ui_rule")

    def test_add_env_rule_and_pin_a_client(self):
        res = self.add(name="greet", mode="env", argv=["echo", "hi"], client=self.client.id)
        self.assertEqual(res["status"], "created")
        [rule] = self.stored()
        self.assertEqual((rule["mode"], rule["argv"], rule["clients"]), ("env", ["echo", "hi"], [self.client.id]))
        self.assertNotIn("host", rule)
        self.assertNotIn("rule_host", self.events("auto_rule_created")[-1])
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["echo", "hi"]})
        self.assertEqual(code, 202, body)
        self.assertEqual(self.events("auto_rule_used")[-1]["source"], "ui")

    def refuse(self, reason, **kw):
        before = (self.stored(), self.live())
        res = self.add(**kw)
        self.assertEqual(res["status"], "refused", kw)
        self.assertEqual(self.events("auto_rule_refused")[-1]["reason"], reason, kw)
        self.assertEqual((self.stored(), self.live()), before, kw)                    # nothing written, nothing live
        return res

    def test_every_refusal_has_a_fixed_reason_and_writes_nothing(self):
        self.assertEqual(self.add(name="first")["status"], "created")               # the surface is populated
        self.refuse("not_confirmed", confirm=False)
        self.refuse("invalid", expiry="7")
        self.refuse("invalid", client="c-deadbeef")                                   # not enrolled
        self.refuse("invalid", client="legacy")                                       # the legacy key never matches a rule
        self.refuse("invalid", client="bogus")
        for mode in ("ssh_sign", "sudo", "plan", "bogus", ""):
            self.refuse("invalid", mode=mode)
        self.refuse("invalid", host="not a host")
        self.refuse("invalid", host="")
        self.refuse("invalid", methods=[])
        self.refuse("invalid", methods=["get"])
        self.refuse("invalid", scheme="ftp")
        self.refuse("invalid", path_prefix="/x/../y")
        self.refuse("invalid", mode="env", argv=[])
        self.refuse("invalid", name="")
        self.refuse("duplicate_name", name="FIRST")
        self.assertEqual(len(self.stored()), 1)

    def test_a_revoked_client_cannot_be_chosen(self):
        other = self.mk("gone")
        self.assertEqual(self.add(name="a", client=other.id)["status"], "created")     # control
        self.broker.revoke_client(other.id, "alice")
        self.refuse("invalid", name="b", client=other.id)

    def test_the_message_is_a_fixed_label_and_never_echoes_input(self):
        canary = "S3CR3T-<b>canary"
        for label, kw, field in (
                ("host", dict(host=canary + " bad host", name=canary, path_prefix=canary), "host"),
                ("argv", dict(mode="env", argv=[canary] * 65, name=canary), "argv"),
                ("mode", dict(mode=canary, name=canary, host=canary), "mode")):
            res = self.add(**kw)
            self.assertEqual(res["status"], "refused", label)
            self.assertEqual(res["message"], f"Not a valid value for {field}.", label)
        ev = json.dumps(self.events("auto_rule_refused"))
        self.assertEqual(ev.count('"reason": "invalid"'), 3)                          # the events exist
        self.assertNotIn("S3CR3T", ev)
        self.assertEqual(self.stored(), [])

    def test_the_cap_is_50(self):
        self.seed(*[http_rule(id=f"r{i:04d}", name=f"n{i}") for i in range(50)])
        self.assertEqual(len(self.live()), 50)
        self.refuse("cap", name="one more")

    def test_a_backend_that_cannot_write_metadata_is_refused(self):
        self.broker.backend = NoMeta(self.broker.backend)
        self.refuse("backend")

    def test_ssh_and_unknown_credentials_raise(self):
        for cred in ("deploy", "nope"):
            with self.assertRaises(ValueError, msg=cred):
                self.add(cred=cred)
        self.assertEqual(self.events("auto_rule_created"), [])
        self.assertEqual(self.add()["status"], "created")                             # control

    def test_a_vault_write_failure_activates_nothing_and_says_so(self):
        def boom(*a):
            raise OSError("disk")
        real = self.broker.backend.set_meta
        self.broker.backend.set_meta = boom
        res = self.add()
        self.assertEqual(res["status"], "failed")
        self.assertEqual((self.live(), self.stored()), ([], []))
        self.assertEqual(self.events("auto_rule_change_failed")[-1]["op"], "create")
        self.assertEqual(self.events("auto_rule_created"), [])
        self.broker.backend.set_meta = real
        self.assertEqual(self.add()["status"], "created")                             # control: it works again

    # -- revoke
    def test_revoke_removes_the_rule_and_its_usage(self):
        self.add()
        rid = self.live()[0]["id"]
        self.call()
        self.assertEqual(self.broker.auto_rule_usage.get("svc", rid)["uses"], 1)
        self.assertEqual(self.broker.revoke_auto_rule("svc", rid, "alice", "127.0.0.1", "10.0.0.9"), "revoked")
        self.assertEqual((self.live(), self.stored()), ([], []))
        self.assertNotIn("auto_rules", self.disk()["secrets"]["svc"])
        self.assertEqual(self.broker.auto_rule_usage.get("svc", rid)["uses"], 0)
        ev = self.events("auto_rule_revoked")[-1]
        self.assertEqual((ev["credential"], ev["rule_id"], ev["revoked_by"], ev["channel"]),
                         ("svc", rid, "alice", "policies"))
        before = self.used()
        self.call()
        self.assertEqual(self.used(), before)                                         # no longer approves

    def test_revoke_missing_and_unknown(self):
        self.assertEqual(self.broker.revoke_auto_rule("svc", "nope1234", "alice"), "missing")
        self.assertEqual(self.broker.revoke_auto_rule("nope", "x", "alice"), "missing")
        self.assertEqual(self.broker.revoke_auto_rule("deploy", "x", "alice"), "missing")

    def test_revoke_failure_keeps_the_rule_active(self):
        self.add()
        rid = self.live()[0]["id"]

        def boom(*a):
            raise OSError("disk")
        real = self.broker.backend.set_meta
        self.broker.backend.set_meta = boom
        self.assertEqual(self.broker.revoke_auto_rule("svc", rid, "alice"), "failed")
        self.assertEqual(len(self.live()), 1)
        self.assertEqual(len(self.stored()), 1)
        self.assertEqual(self.events("auto_rule_change_failed")[-1]["op"], "revoke")
        self.assertEqual(self.events("auto_rule_revoked"), [])
        self.broker.backend.set_meta = real
        self.assertEqual(self.broker.revoke_auto_rule("svc", rid, "alice"), "revoked")   # control

    # -- expiry
    def test_expiry_drops_the_rule_and_audits_it_once(self):
        self.seed(http_rule(id="old01", name="old", expires_at=PAST), http_rule(id="new01", name="new",
                                                                                   expires_at=FUTURE))
        self.broker.expire_auto_rules()
        self.broker.expire_auto_rules()
        self.assertEqual([r["id"] for r in self.live()], ["new01"])
        self.assertEqual([r["id"] for r in self.stored()], ["new01"])
        gone = self.events("auto_rule_expired")
        self.assertEqual([(e["credential"], e["rule_id"], e["rule_name"]) for e in gone], [("svc", "old01", "old")])

    def test_a_failed_expiry_write_is_reported_once_and_the_rule_stays_ignored(self):
        self.seed(http_rule(id="old01", name="old", expires_at=PAST))

        def boom(*a):
            raise OSError("disk")
        self.broker.backend.set_meta = boom
        self.broker.expire_auto_rules()
        self.broker.expire_auto_rules()
        self.assertEqual(len(self.events("auto_rule_change_failed")), 1)
        self.assertEqual(self.events("auto_rule_change_failed")[0]["op"], "expire")
        self.assertEqual(self.events("auto_rule_expired"), [])
        self.assertEqual(len(self.live()), 1)                                         # still stored, but never matches
        self.assertIsNone(autorules.find(self.live(), "http", ["svc"], {"url": "http://127.0.0.1/x"}, {"id": BOX}))

    def test_usage_of_rules_that_no_longer_exist_is_pruned(self):
        self.seed(http_rule(id="keep01", name="keep"))
        self.broker.auto_rule_usage.record("svc", "keep01", time.time())
        self.broker.auto_rule_usage.record("svc", "gone01", time.time())
        self.broker.prune_auto_rule_usage()
        self.assertEqual(self.broker.auto_rule_usage.get("svc", "keep01")["uses"], 1)
        self.assertEqual(self.broker.auto_rule_usage.get("svc", "gone01")["uses"], 0)


if __name__ == "__main__":
    unittest.main()
