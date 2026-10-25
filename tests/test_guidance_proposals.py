"""Agent-proposed risk guidance: the agent writes, a human reviews and applies.

The safety properties: a proposal is always HIGH by code with no model call, can never be
auto-approved or decided from a notification button, shows its text only on the approval
card, applies only the entries the human ticked, and leaves no text in any other surface.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import hashlib
import html
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_e2e as t  # noqa: E402  (module import only: no test re-collection)

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()   # test stubs live on 127.0.0.1; no config key does this
from secret_broker import audit_api, proposals, risk  # noqa: E402
from secret_broker.backends import BackendError  # noqa: E402
from secret_broker.broker import Broker  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402

CANARY = "PROPOSAL-CANARY-91c2"
CURRENT = "CURRENT-GUIDANCE-5be1 line one\nline two"
HOSTILE = '<script>alert("x")</script> & <img src=x onerror=1> ' + CANARY
CLI = t.CLI
KEY = t.KEY


def sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


class Stub:
    """An analyzer that must never be called for a proposal."""

    def __init__(self):
        self.calls = []

    def analyze(self, mode, names, spec, guidance=None):
        self.calls.append(("analyze", mode, json.dumps(spec, default=str), guidance))
        return {"summary": "s", "risk": "low"}

    def summarize(self, mode, names, spec):
        self.calls.append(("summarize", mode))
        return "s"


class Base(t.Harness):
    decision = None             # nothing decides on its own
    ttl = 30

    def tweak(self, cfg):
        cfg["secrets"]["svc"]["guidance"] = CURRENT
        cfg["secrets"]["svc"]["approval"] = "allow"
        cfg["risk"] = {"auto_approve_max": "high", "auto_modes": ["http", "env"]}
        cfg["_vault"] = {}
        for n in ("alpha", "beta", "gamma"):
            item = n.title()
            cfg["_vault"][item] = {"token": "v-" + n}
            cfg["secrets"][n] = {"vars": {n.upper() + "_TOKEN": {"item": item, "field": "token"}},
                                 "allowed_hosts": ["127.0.0.1"]}
        cfg["secrets"]["beta"]["guidance"] = "BETA-CURRENT"

    def setUp(self):
        super().setUp()
        self.stub = Stub()
        self.broker.summarizer = self.stub
        # a fake clock: sleeps (write spacing, retry backoff) cost no real time
        self.now, self.sleeps, self.gate = 1000.0, [], None
        self.sleeping = threading.Event()               # set when a backoff sleep starts (it blocks on `gate`)
        self.broker._mono = lambda: self.now
        self.broker._sleep = self._fsleep
        self.broker._jitter = lambda a, b: 0.0

    # -- helpers ---------------------------------------------------------
    def _fsleep(self, d):
        if self.gate is not None:
            self.sleeping.set()
            self.gate.wait(10)
        self.sleeps.append(d)
        self.now += d

    def propose(self, entries, **extra):
        code, body = self.api("POST", "/v1/requests", {"mode": "guidance", "entries": entries, **extra})
        return code, json.loads(body)

    def one(self, text=CANARY, name="alpha"):
        code, r = self.propose([{"name": name, "text": text}])
        self.assertEqual(code, 202, r)
        return r["id"]

    def get(self, path, user="alice"):
        return t.req(self.abase + path, headers={"X-authentik-username": user})

    def post(self, path, user="alice", **form):
        data = urllib.parse.urlencode(form, doseq=True).encode()
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                self.abase + path, data=data, headers={"X-authentik-username": user}, method="POST"),
                timeout=10)
            return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def decide(self, rid, decision="approve", apply=(), **kw):
        form = {"id": rid, "decision": decision, "csrf": self.broker.csrf_token("alice")}
        form.update({f"apply_{i}": "1" for i in apply})
        form.update(kw)
        status, body = self.post("/decide", **form)
        return status, body

    def settle(self, rid):
        self.broker._by_id[rid].done.wait(10)
        return self.broker._by_id[rid]

    def result(self, rid):
        code, body = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(body)

    def guid(self, name):
        return self.broker.cfg["secrets"][name].get("guidance")

    def all_text(self):
        return _fast.read_audit_text(self.audit)


HIDDEN = {
    "zero-width space": "\u200b", "zero-width joiner": "\u200d", "zero-width non-joiner": "\u200c",
    "word joiner": "\u2060", "bom": "\ufeff", "bidi override": "\u202e", "bidi isolate": "\u2066",
    "bidi mark": "\u200f", "tag character": "\U000e0041", "tag cancel": "\U000e007f",
    "variation selector": "\ufe0f", "variation selector supplement": "\U000e0100",
    "private use": "\ue000", "private use plane": "\U000f0000", "unassigned": "\u0378",
    "nbsp": "\u00a0", "en space": "\u2002", "narrow nbsp": "\u202f", "medium math space": "\u205f",
    "ideographic space": "\u3000", "ogham space": "\u1680", "mongolian vowel sep": "\u180e",
    "line separator": "\u2028", "paragraph separator": "\u2029", "nul": "\x00", "escape": "\x1b",
    "del": "\x7f", "c1 control": "\x85", "hangul choseong filler": "\u115f",
    "hangul jungseong filler": "\u1160", "hangul filler": "\u3164", "halfwidth hangul filler": "\uffa0",
    "long combining run": "e" + "\u0301" * 4, "surrogate-ish": "\ud800",
}


class HiddenChars(Base):
    def test_validator_rejects_each_category_with_class_and_offset_not_the_char(self):
        from secret_broker import guidance as g
        for label, ch in HIDDEN.items():
            text = "ab " + ch + " cd"
            with self.assertRaises(g.HiddenCharsError, msg=label) as cm:
                g.validate_text(text)
            msg = str(cm.exception)
            self.assertIn("guidance contains hidden characters", msg, label)
            self.assertRegex(msg, r"at offset \d+", label)
            self.assertNotIn(ch, msg, label)

    def test_plain_accented_curly_quotes_and_short_combining_accepted(self):
        from secret_broker import guidance as g
        for ok in ("plain ASCII\nline\ttab", "caf\u00e9 na\u00efve", "\u201cquoted\u201d \u2019s",
                   "e" + "\u0301" * 3, "\u2014 dash \u2026"):
            self.assertEqual(g.validate_text(ok), ok)

    def test_every_path_uses_the_same_validator(self):
        from secret_broker import guidance as g
        bad = "x\u200by"
        # proposal path: 400, offset named, no text anywhere
        code, r = self.propose([{"name": "alpha", "text": bad + CANARY}])
        self.assertEqual(code, 400)
        self.assertIn("hidden characters (invisible format character at offset 1)", r["error"])
        self.assertNotIn("\u200b", r["error"])
        self.assertEqual(self.broker.pending(), [])
        self.assertNotIn(CANARY, self.all_text())
        # editor path: refused, re-rendered with the error, nothing stored
        status, body = self.post("/policies/guidance", name="alpha", guidance=bad,
                                 csrf=self.broker.csrf_token("alice"))
        self.assertEqual(status, 400)
        self.assertIn("hidden characters", body)
        self.assertIsNone(self.guid("alpha"))
        self.assertNotIn("\u200b", self.all_text())
        # loader path: guidance ignored, credential still valid
        self.broker.backend.set_meta("Alpha", {**self.broker.cfg["secrets"]["alpha"]["_meta"], "guidance": bad})
        self.broker.refresh_catalog()
        sc = self.broker.cfg["secrets"]["alpha"]
        self.assertNotIn("guidance", sc)
        self.assertIn("hidden characters", sc["guidance_invalid"])
        self.assertEqual(self.broker._catalog_stats["invalid"], 0)
        # classification never sees it
        self.assertEqual(g.for_names(self.broker.cfg["secrets"], ["alpha"]), {})
        # all three share one function
        import inspect
        from secret_broker import proposals
        self.assertIn("validate_text", inspect.getsource(proposals.validate_entries))
        self.assertIn("validate_text", inspect.getsource(Broker._guidance_attempt))
        self.assertIn("validate_text", inspect.getsource(g.from_meta))

    def test_editor_page_notes_ignored_guidance(self):
        self.broker.cfg["secrets"]["alpha"]["guidance_invalid"] = "guidance contains hidden characters (x at offset 1)"
        self.assertIn("Stored guidance ignored", self.get("/policies")[1])

    def test_card_warns_about_non_ascii_and_shows_escaped(self):
        rid = self.one("caf\u00e9 \u201cquote\u201d <b>")
        page = self.get("/")[1]
        self.assertIn("Non-ASCII characters: 3 (shown escaped as U+XXXX in the box below)", page)
        self.assertIn("&lt;U+00E9&gt;", page)
        self.assertIn("&lt;U+201C&gt;", page)
        self.assertIn("title=\"\u00e9\"", page)
        self.assertNotIn("caf\u00e9", page)
        self.assertIn("&lt;b&gt;", page)

    def test_ascii_text_has_no_non_ascii_pill(self):
        self.one("plain text")
        self.assertNotIn("Non-ASCII characters", self.get("/")[1])

    def test_homoglyph_cannot_hide(self):
        self.one("p\u0430ssword")          # Cyrillic a
        page = self.get("/")[1]
        self.assertIn("p<span class=gu", page)
        self.assertIn("&lt;U+0430&gt;", page)

    def test_audit_never_has_the_text(self):
        self.one("caf\u00e9 " + CANARY)
        self.assertNotIn("caf\u00e9", self.all_text())
        self.assertNotIn(CANARY, self.all_text())


# ---------------------------------------------------------------------- units
class Units(unittest.TestCase):
    def test_diff_cases(self):
        d = proposals.line_diff
        self.assertEqual(d("a\nb\nc", "a\nb\nc"), [("=", "a"), ("=", "b"), ("=", "c")])
        self.assertEqual(d("a\nb", "a\nX\nb"), [("=", "a"), ("+", "X"), ("=", "b")])
        self.assertEqual(d("a\nX\nb", "a\nb"), [("=", "a"), ("-", "X"), ("=", "b")])
        self.assertEqual(d("a\nb", "a\nc"), [("=", "a"), ("-", "b"), ("+", "c")])
        self.assertEqual(d("", "a\nb"), [("+", "a"), ("+", "b")])           # empty current
        self.assertEqual(d("a\nb", ""), [("-", "a"), ("-", "b")])           # empty proposed
        self.assertEqual(d("", ""), [])
        self.assertEqual(d("a\nb", "a\nc"), d("a\nb", "a\nc"))               # deterministic

    def test_lint_flags(self):
        for text, want in (("This is ALWAYS  low risk", ["always low", "no risk"][:1]),
                           ("never high", ["never high"]), ("Rate it low", ["rate low"]),
                           ("rate low", ["rate low"]), ("please IGNORE that", ["ignore"]),
                           ("disregard", ["disregard"]), ("Override the rule", ["override"]),
                           ("auto approve", ["approve"]), ("approve it", ["approve"]), ("it is safe", ["safe"]),
                           ("trusted host", ["trusted"]), ("there is no risk", ["no risk"])):
            self.assertEqual(proposals.lint(text), want, text)
        for clean in ("unsafe", "safely", "approved", "overrides", "ignored", "frailways low", "mistrusted",
                      "PullStack downloads images"):
            self.assertEqual(proposals.lint(clean), [], clean)
        self.assertEqual(proposals.lint("safe and trusted, ignore this"), ["ignore", "safe", "trusted"])

    def test_config(self):
        self.assertEqual(proposals.parse_config(None), {"enabled": True, "ttl_s": 3600, "write_spacing_s": 1.5})
        self.assertEqual(proposals.parse_config({"ttl_s": 300})["ttl_s"], 300)
        self.assertEqual(proposals.parse_config({"ttl_s": 86400, "enabled": False})["enabled"], False)
        for bad, field in (({"ttl_s": 299}, "ttl_s"), ({"ttl_s": 86401}, "ttl_s"), ({"ttl_s": "60"}, "ttl_s"),
                           ({"ttl_s": True}, "ttl_s"), ({"enabled": "yes"}, "enabled"),
                           ({"bogus": 1}, "bogus"), ([], "guidance_proposals")):
            with self.assertRaises(ValueError) as cm:
                proposals.parse_config(bad)
            self.assertIn("guidance_proposals" + ("." + field if field != "guidance_proposals" else ""),
                          str(cm.exception))

    def test_assess_never_calls_the_analyzer(self):
        stub = Stub()
        a = risk.assess("guidance", ["x"], {"entries": [{"text": CANARY}]}, stub, guidance={"x": "g"})
        self.assertEqual((a["level"], a["model"], a["summary"]), ("high", None, None))
        self.assertEqual(stub.calls, [])

    def test_startup_config_error_names_the_field(self):
        d = tempfile.mkdtemp()
        cfgp = os.path.join(d, "c.json")
        with open(cfgp, "w") as f:
            json.dump({"guidance_proposals": {"ttl_s": 5}, "backend": {"type": "file", "path": cfgp},
                       "approve_base_url": "https://s.example", "allowed_user": "a"}, f)
        p = subprocess.run([sys.executable, "-m", "secret_broker", "--config", cfgp], capture_output=True,
                           text=True, timeout=30, cwd=os.path.join(os.path.dirname(__file__), ".."),
                           env=dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..")))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("guidance_proposals.ttl_s", p.stderr)


# ----------------------------------------------------------------- validation
class Validation(Base):
    def test_unknown_duplicate_count_length_types(self):
        cases = [
            ([{"name": "nope", "text": "x"}], "unknown"),
            ([{"name": "alpha", "text": "x"}, {"name": "alpha", "text": "y"}], "duplicate"),
            ([{"name": "alpha", "text": "x" * 2001}], "at most 2000"),
            ([{"name": "alpha", "text": 5}], "at most 2000"),
            ([{"name": "alpha", "text": None}], "at most 2000"),
            ([{"name": 7, "text": "x"}], "unknown"),
            (["alpha"], "entry must be"),
            ([{"name": "alpha"}], "entry must be"),
            ([{"name": "alpha", "text": "x", "extra": 1}], "entry must be"),
            ([], "1 to 25"),
            ("alpha", "1 to 25"),
            ([{"name": "alpha", "text": "x"}] * 26, "1 to 25"),
        ]
        for entries, msg in cases:
            code, r = self.propose(entries)
            self.assertEqual(code, 400, (entries, r))
            self.assertIn(msg, r["error"])
        self.assertEqual(self.api("POST", "/v1/requests", {"mode": "guidance"})[0], 400)
        self.assertEqual(self.broker.pending(), [])

    def test_exactly_2000_and_empty_text_accepted(self):
        self.assertEqual(self.propose([{"name": "alpha", "text": "x" * 2000}])[0], 202)
        self.assertEqual(self.propose([{"name": "beta", "text": ""}])[0], 202)

    def test_text_is_normalized_like_the_metadata_validator(self):
        rid = self.one("  a\r\nc\td  ")
        self.assertEqual(self.broker._by_id[rid].spec["entries"][0]["text"], "a\nc\td")

    def test_body_cap(self):
        big = [{"name": "alpha", "text": "x" * 2000}] + [{"name": "pad" + str(i), "text": "y" * 2000}
                                                         for i in range(60)]
        code, body = self.api("POST", "/v1/requests", {"mode": "guidance", "entries": big})
        self.assertEqual(code, 413)
        self.assertEqual(self.broker.pending(), [])

    def test_agent_key_required(self):
        code, _ = self.api("POST", "/v1/requests", {"mode": "guidance", "entries": [
            {"name": "alpha", "text": "x"}]}, key="wrong")
        self.assertEqual(code, 401)

    def test_rejection_is_audited_without_text(self):
        self.propose([{"name": "alpha", "text": CANARY}, {"name": "alpha", "text": CANARY}])
        self.assertEqual(len(self.events("rejected")), 1)
        self.assertNotIn(CANARY, self.all_text())

    def test_duplicate_proposal_of_identical_text_is_allowed(self):
        a, b = self.one("same"), self.one("same")
        self.assertNotEqual(a, b)
        self.assertEqual(len(self.broker.pending()), 2)


class Disabled(Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["guidance_proposals"] = {"enabled": False}

    def test_disabled_refuses(self):
        code, r = self.propose([{"name": "alpha", "text": "x"}])
        self.assertEqual(code, 403)
        self.assertIn("disabled", r["error"])
        self.assertEqual(self.broker.pending(), [])
        self.assertFalse(self.api("GET", "/v1/status")[1] and
                         json.loads(self.api("GET", "/v1/status")[1])["features"]["guidance_proposals"])


class Limits(Base):
    def test_default_ttl_and_cap_of_three(self):
        rids = [self.one(f"t{i}") for i in range(3)]
        r = self.broker._by_id[rids[0]]
        self.assertAlmostEqual(r.expires - r.created, 3600, delta=2)
        code, body = self.propose([{"name": "alpha", "text": "fourth"}])
        self.assertEqual(code, 403)
        self.assertIn("too many pending guidance proposals", body["error"])
        # a decided proposal frees a slot
        self.assertEqual(self.decide(rids[0], "deny")[0], 303 if False else 200)
        self.settle(rids[0])
        self.assertEqual(self.propose([{"name": "alpha", "text": "again"}])[0], 202)

    def test_proposals_do_not_block_real_requests_or_cooldown(self):
        for i in range(3):
            self.one(f"t{i}")
        code, _ = self.api("POST", "/v1/requests", {"mode": "env", "names": ["alpha"], "argv": ["echo"]})
        self.assertEqual(code, 202)         # the global pending cap is not used up by proposals
        rid = list(self.broker.pending())[0].id
        self.decide(rid, "deny")
        self.settle(rid)
        code, _ = self.api("POST", "/v1/requests", {"mode": "env", "names": ["alpha"], "argv": ["echo"]})
        self.assertEqual(code, 202)         # denying a proposal starts no cooldown on the credential


class ShortTtl(Base):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["guidance_proposals"] = {"ttl_s": 300}

    def test_configured_ttl(self):
        r = self.broker._by_id[self.one()]
        self.assertAlmostEqual(r.expires - r.created, 300, delta=2)
        self.assertEqual(json.loads(self.api("POST", "/v1/requests", {
            "mode": "guidance", "entries": [{"name": "beta", "text": "z"}]})[1])["expires_in"] in range(295, 301), True)


# ------------------------------------------------------- forced review (safety)
class ForcedReview(Base):
    def test_high_by_code_and_no_model_call(self):
        rid = self.one()
        r = self.broker._by_id[rid]
        self.assertEqual(r.risk["level"], "high")
        self.assertIsNone(r.risk["model"])
        self.assertIsNone(r.summary)
        self.assertEqual(r.status, "pending")
        self.assertEqual(self.stub.calls, [])
        self.assertEqual([c for c in self.stub.calls if CANARY in json.dumps(c)], [])
        ev = self.events("assessed")[0]
        self.assertEqual((ev["risk"], ev["model"]), ("high", None))

    def test_never_auto_approved_under_any_policy(self):
        b = self.broker
        sc = b.cfg["secrets"]["svc"]
        self.assertEqual(sc["approval"], "allow")                       # legacy allow
        self.assertEqual(b.auto_approve_max(), "high")                  # most permissive ceiling
        b.grants.add(["svc"], 60, "any", "alice", "dashboard", "r", mode="guidance")
        b.grants.add(["svc"], 60, "any", "alice", "dashboard", "r", mode="env")
        b.grants.add(["svc"], 60, "any", "alice", "dashboard", "r", mode="http")
        b.grants.add(["svc"], 60, "any", "alice", "dashboard", "r")     # legacy, no mode
        sc["standing"] = [{"id": f"s{m}", "mode": m, "scope": "any", "created_by": "alice",
                           "created_at": "2026-01-01T00:00:00Z"} for m in ("guidance", "env", "http")]
        sc["auto_modes"] = ["http", "env", "guidance", "ssh_sign"]       # even a hostile per-secret list
        b._default_auto_modes = ["http", "env", "guidance"]
        with mock.patch.object(Broker, "_release", side_effect=AssertionError("released")), \
                mock.patch.object(Broker, "_auto_allowed", side_effect=AssertionError("auto")), \
                mock.patch.object(Broker, "_standing_claim", side_effect=AssertionError("standing")), \
                mock.patch.object(Broker, "_ssh_rule_claim", side_effect=AssertionError("rule")):
            code, r = self.propose([{"name": "svc", "text": "ok"}])
            self.assertEqual(code, 202, r)
        self.assertEqual(r["status"], "pending")
        self.assertEqual(self.events("approved"), [])
        self.assertEqual(self.events("grant_used"), [])
        self.assertEqual([e for e in self.records() if e.get("via") == "policy"], [])
        self.assertEqual(self.guid("svc"), CURRENT)

    def test_release_refuses_guidance_even_if_called(self):
        rid = self.one()
        with self.assertRaises(BackendError):
            self.broker._release(self.broker._by_id[rid])

    def test_notification_is_names_only_without_buttons(self):
        self.broker.notifier = FakeNotifier(supports_actions=("approve", "deny"))
        rid = self.one(CANARY)
        n = self.broker.notifier.notifications[0] if hasattr(self.broker.notifier, "notifications") \
            else self.broker._by_id[rid].notification
        n = self.broker._by_id[rid].notification
        self.assertEqual(n.actions, [])
        self.assertIsNone(n.action_token)
        self.assertEqual(self.broker._by_id[rid].offered, frozenset())
        sent = self.broker.notifier.sent
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["context"]["action_token"], None)
        self.assertTrue(sent[0]["message"].startswith("Guidance change proposed for 1 credential"))
        self.assertNotIn(CANARY, json.dumps(sent))
        self.assertNotIn(CANARY, repr(self.broker.notifier.notifications))
        self.assertNotIn("Approve", repr(n))

    def test_notification_text_counts_credentials(self):
        self.one()
        code, r = self.propose([{"name": "alpha", "text": "a"}, {"name": "beta", "text": "b"}])
        msg = self.notifier.sent[-1]["message"]
        self.assertTrue(msg.startswith("Guidance change proposed for 2 credentials"), msg)

    def test_push_and_ha_channels_cannot_decide(self):
        self.broker.notifier = FakeNotifier(supports_actions=("approve", "deny"))
        rid = self.one()
        b = self.broker
        for ch in ("push", "ha"):
            for decision in ("approve", "deny"):
                for tok in ("", "x" * 22, "not-a-token"):
                    code, done = b.decide_via(ch, rid, decision, "u", token=tok, apply={0})
                    self.assertEqual((code, done), (403, None), (ch, decision, tok))
        # a valid token from ANOTHER request does not decide it either
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": ["alpha"], "argv": ["x"]})
        tok = b.notifier.sent[-1]["context"]["action_token"]
        self.assertTrue(tok)
        for decision in ("approve", "deny"):
            self.assertEqual(b.decide_via("push", rid, decision, "u", token=tok)[0], 403)
        self.assertEqual(b._by_id[rid].status, "pending")
        self.assertEqual(self.guid("alpha"), None)

    def test_push_endpoint_cannot_decide(self):
        rid = self.one()
        hdr = {"X-authentik-username": "alice", "X-Requested-With": "asb", "Content-Type": "application/json"}
        for decision in ("approve", "deny"):
            code, _ = t.req(self.abase + "/push/decide", "POST", {"rid": rid, "token": "abcdef", "decision": decision},
                            hdr)
            self.assertEqual(code, 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_decision_refused_is_audited_for_token_channels_only_without_text(self):
        rid = self.one()
        self.broker.decide_via("push", rid, "approve", "u", token="zzz")
        self.assertNotIn(CANARY, self.all_text())

    def test_presence_hold_applies_and_fallback_releases(self):
        self.broker.notifier = FakeNotifier(type_name="ticker")
        self.broker._presence_autostart = False
        self.assertTrue(self.broker.presence_beat("alice", True, "tab1"))
        rid = self.one()
        self.assertEqual(self.broker.notifier.sent, [])             # held while a page is open
        self.assertIn(rid, self.broker._held)
        self.assertEqual(len(self.events("notify_held")), 1)
        self.broker.presence_clock = lambda: time.time() + 120      # fallback_s (60) passed
        self.broker.presence_tick()
        sent = self.broker.notifier.sent
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0]["message"].startswith("Guidance change proposed for 1 credential"))
        self.assertIsNone(sent[0]["context"]["action_token"])

    def test_dashboard_card_has_no_always_or_grant_chips(self):
        rid = self.one()
        for page in (self.get("/")[1], self.get(f"/a/{self.broker._by_id[rid].nonce}")[1]):
            for bad in ("approve_always", "approve_grant_", "Always", "Automatically approve", "approve_ssh",
                        "value=approve>Approve"):
                self.assertNotIn(bad, page)

    def test_always_grant_and_rule_values_are_refused(self):
        rid = self.one()
        for dec in ("approve_always", "approve_grant_15", "approve_grant_60"):
            status, _ = self.decide(rid, dec, apply=(0,))
            self.assertIn(status, (200,))                           # redirect to /?note=bad
            self.assertEqual(self.broker._by_id[rid].status, "pending", dec)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", always=True,
                                                apply={0})[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", ssh_rule={"days": 1},
                                                apply={0})[0], 400)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.guid("alpha"), None)


# ----------------------------------------------------------------- the review card
class Card(Base):
    def card(self, entries, where="dash"):
        code, r = self.propose(entries)
        self.assertEqual(code, 202, r)
        req = self.broker._by_id[r["id"]]
        if where == "dash":
            return r["id"], self.get("/")[1]
        return r["id"], self.get(f"/a/{req.nonce}")[1]

    def test_header_warning_and_entries_on_both_surfaces(self):
        for where in ("dash", "link"):
            rid, page = self.card([{"name": "svc", "text": "NEW svc text"}, {"name": "beta", "text": "BETA-NEW"}],
                                  where)
            self.assertIn("Guidance proposal", page)
            self.assertIn("2 credentials", page)
            self.assertIn("This text tells the risk classifier how to rate requests made with these "
                          "credentials. It can lower ratings. Review each one.", page)
            self.assertIn("Current guidance", page)
            self.assertIn("Proposed guidance", page)
            self.assertIn("CURRENT-GUIDANCE-5be1 line one", page)
            self.assertIn("NEW svc text", page)
            self.assertIn("BETA-CURRENT", page)
            self.assertIn("BETA-NEW", page)
            self.assertIn("Apply this one", page)
            self.assertIn(">Apply selected<", page)
            self.assertIn(">Deny all<", page)
            self.assertIn("HIGH RISK", page)
            self.broker._by_id[rid].status = "denied"               # leave the next surface clean

    def test_nothing_selected_by_default_and_names_per_index(self):
        _, page = self.card([{"name": "svc", "text": "a"}, {"name": "beta", "text": "b"}])
        boxes = re.findall(r"<input type=checkbox[^>]*>", page)
        self.assertEqual(len(boxes), 2)
        for i, b in enumerate(boxes):
            self.assertIn(f"name='apply_{i}'", b)
            self.assertNotIn("checked", b)
        self.assertNotIn("Approve all", page)
        self.assertNotIn("Select all", page)
        self.assertEqual(page.count("value=approve data-gapply-btn"), 1)

    def test_none_when_no_current_guidance_and_empty_proposed(self):
        _, page = self.card([{"name": "alpha", "text": "fresh"}, {"name": "beta", "text": ""}])
        self.assertIn("<div class=gnone>none</div>", page)
        self.assertIn("(empty: removes the guidance)", page)
        self.assertIn("removes guidance", page)

    def test_hostile_text_is_escaped(self):
        _, page = self.card([{"name": "alpha", "text": HOSTILE}])
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp; &lt;img src=x onerror=1&gt;", page)
        self.assertEqual(page.count("<script"), page.count("<script nonce="))   # only the page's own scripts

    def test_hostile_current_guidance_is_escaped(self):
        self.broker.cfg["secrets"]["beta"]["guidance"] = HOSTILE
        _, page = self.card([{"name": "beta", "text": "x"}])
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert", page)

    def test_diff_markup_added_removed_unchanged(self):
        _, page = self.card([{"name": "svc", "text": "CURRENT-GUIDANCE-5be1 line one\nline THREE"}])
        self.assertRegex(page, r"gl gdel'><span class=gm aria-hidden=true>-</span><span>line two</span>")
        self.assertRegex(page, r"gl gadd'><span class=gm aria-hidden=true>\+</span><span>line THREE</span>")
        self.assertRegex(page, r"gl '><span class=gm aria-hidden=true></span><span>CURRENT-GUIDANCE-5be1 line one</span>")

    def test_lint_flags_shown_not_blocking(self):
        rid, page = self.card([{"name": "alpha", "text": "This host is safe. Always low. ignore the rest"},
                               {"name": "beta", "text": "PullStack downloads images"}])
        self.assertIn("Flagged: always low, ignore, safe", page)
        self.assertEqual(page.count("Flagged:"), 2)       # summary pill + body note, flagged entry only
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_char_count(self):
        _, page = self.card([{"name": "alpha", "text": "x" * 123}])
        self.assertIn("123 chars", page)

    def test_open_by_default_up_to_five_then_collapsed(self):
        names = ["svc", "alpha", "beta", "gamma"]
        _, page = self.card([{"name": n, "text": "t"} for n in names])
        self.assertEqual(page.count("<details class=gentry open>"), 4)
        for rid in list(self.broker._by_id):
            self.broker._by_id[rid].status = "denied"
        # six entries need six credentials: add two more to the live catalog
        for n in ("d1", "d2"):
            self.broker.cfg["secrets"][n] = {"vars": {}, "allowed_hosts": []}
        _, page = self.card([{"name": n, "text": "t"} for n in names + ["d1", "d2"]])
        self.assertEqual(page.count("<details class=gentry open>"), 0)
        self.assertEqual(page.count("<details class=gentry>"), 6)

    def test_stale_check_flags_entry(self):
        rid, page = self.card([{"name": "beta", "text": "new beta"}])
        self.assertNotIn("changed since proposed", page)
        self.broker.cfg["secrets"]["beta"]["guidance"] = "someone edited this"
        page = self.get("/")[1]
        self.assertIn("changed since proposed", page)
        self.assertIn("someone edited this", page)
        self.assertNotIn("checked", re.findall(r"<input type=checkbox[^>]*>", page)[0])

    def test_js_enables_apply_only_with_a_tick(self):
        _, page = self.card([{"name": "alpha", "text": "x"}])
        self.assertIn("button[data-gapply-btn]", page)
        self.assertIn("b.disabled=!f.querySelector('input[data-gapply]:checked')", page)

    def test_history_card_not_shown_after_decision(self):
        rid, _ = self.card([{"name": "alpha", "text": CANARY}])
        self.decide(rid, "deny")
        self.settle(rid)
        self.assertNotIn(CANARY, self.get("/")[1])


# --------------------------------------------------------------------- applying
class Apply(Base):
    def test_server_refuses_apply_with_nothing_selected(self):
        rid = self.one("x")
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", apply=set())[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice")[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", apply={5})[0], 400)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", apply={-1})[0], 400)
        status, _ = self.decide(rid, "approve", apply=())
        self.assertEqual(status, 200)                                       # redirect to /?note=bad
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        # the link page too
        nonce = self.broker._by_id[rid].nonce
        status, body = self.post(f"/a/{nonce}", decision="approve")
        self.assertEqual(status, 400)
        self.assertIn("Nothing selected", body)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertIsNone(self.guid("alpha"))

    def test_applies_only_ticked_entries_and_persists(self):
        code, r = self.propose([{"name": "alpha", "text": "ALPHA NEW"}, {"name": "beta", "text": "BETA NEW"},
                                {"name": "gamma", "text": "GAMMA NEW"}])
        rid = r["id"]
        status, _ = self.decide(rid, "approve", apply=(0, 2))
        self.assertEqual(status, 200)
        req = self.settle(rid)
        self.assertEqual(req.status, "approved")
        self.assertEqual(self.guid("alpha"), "ALPHA NEW")
        self.assertEqual(self.guid("gamma"), "GAMMA NEW")
        self.assertEqual(self.guid("beta"), "BETA-CURRENT")                 # not ticked: unchanged
        self.assertEqual(self.guid("svc"), CURRENT)
        # persisted: a new Broker on the same backend sees it, with the vault marker
        b2 = Broker({"approve_base_url": "https://s.example", "allowed_user": "alice"}, self.broker.backend,
                    FakeNotifier(), None)
        self.assertEqual(b2.cfg["secrets"]["alpha"]["guidance"], "ALPHA NEW")
        self.assertEqual(b2.cfg["secrets"]["gamma"]["guidance"], "GAMMA NEW")
        self.assertEqual(b2.cfg["secrets"]["beta"]["guidance"], "BETA-CURRENT")
        disk = self.disk()["secrets"]
        self.assertEqual(disk["alpha"]["guidance"], "ALPHA NEW")
        self.assertEqual(disk["alpha"]["guidance_changed"]["by"], "alice")
        self.assertIn("at", disk["alpha"]["guidance_changed"])
        self.assertNotIn("guidance_changed", disk["beta"])
        # the agent's result: names only
        got = self.result(rid)
        self.assertEqual(got, {"status": "approved", "error": None,
                               "guidance": {"applied": ["alpha", "gamma"], "denied": ["beta"], "failed": []}})
        self.assertEqual(self.result(rid), got)                              # repeatable

    def test_audit_has_hashes_not_text(self):
        rid = self.propose([{"name": "beta", "text": "BETA NEW " + CANARY}, {"name": "alpha", "text": ""}])[1]["id"]
        self.decide(rid, "approve", apply=(0,))
        self.settle(rid)
        ch = self.events("guidance_changed")
        self.assertEqual(len(ch), 1)                                         # one per applied entry
        e = ch[0]
        self.assertEqual((e["secret"], e["user"], e["via"], e["proposal"]), ("beta", "alice", "proposal", rid))
        self.assertEqual(e["length"], len("BETA NEW " + CANARY))
        self.assertEqual(e["old_sha256"], sha12("BETA-CURRENT"))
        self.assertEqual(e["new_sha256"], sha12("BETA NEW " + CANARY))
        self.assertIn("peer", e)
        self.assertIn("client_ip", e)
        self.assertNotIn(CANARY, self.all_text())
        self.assertNotIn("BETA-CURRENT", self.all_text())
        prop = self.events("guidance_proposed")[0]
        self.assertEqual((prop["id"], prop["count"], prop["entry_names"], prop["entry_lengths"],
                          prop["entry_sha256"]),
                         (rid, 2, ["beta", "alpha"], [len("BETA NEW " + CANARY), 0],
                          [sha12("BETA NEW " + CANARY), ""]))
        res = self.events("guidance_proposal_result")[0]
        self.assertEqual((res["applied"], res["denied"], res["failed"]), (1, 1, 0))
        self.assertEqual(res["applied_names"], ["beta"])

    def test_empty_text_removes_guidance(self):
        rid = self.propose([{"name": "beta", "text": ""}])[1]["id"]
        self.decide(rid, "approve", apply=(0,))
        self.settle(rid)
        self.assertIsNone(self.guid("beta"))
        self.assertNotIn("guidance", self.disk()["secrets"]["beta"])
        self.assertEqual(self.events("guidance_changed")[0]["new_sha256"], None)

    def test_failed_entry_reported_others_apply(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"},
                            {"name": "gamma", "text": "G1"}])[1]["id"]
        real = self.broker.backend.set_meta

        def flaky(item, meta):
            if item == "Beta":
                raise BackendError("vault write failed")
            return real(item, meta)
        self.broker.backend.set_meta = flaky
        self.decide(rid, "approve", apply=(0, 1, 2))
        self.settle(rid)
        self.assertEqual(self.guid("alpha"), "A1")
        self.assertEqual(self.guid("gamma"), "G1")
        self.assertEqual(self.guid("beta"), "BETA-CURRENT")
        self.assertEqual(self.result(rid)["guidance"], {"applied": ["alpha", "gamma"], "denied": [],
                                                        "failed": ["beta"]})
        self.assertEqual(len(self.events("guidance_changed")), 2)
        self.assertEqual(len(self.events("guidance_change_failed")), 1)

    def test_entry_removed_from_catalog_is_failed(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}, {"name": "gamma", "text": "G1"}])[1]["id"]
        del self.broker.cfg["secrets"]["alpha"]
        self.decide(rid, "approve", apply=(0, 1))
        self.settle(rid)
        self.assertEqual(self.result(rid)["guidance"]["failed"], ["alpha"])
        self.assertEqual(self.guid("gamma"), "G1")

    def test_link_page_apply(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"}])[1]["id"]
        nonce = self.broker._by_id[rid].nonce
        status, body = self.post(f"/a/{nonce}", decision="approve", apply_1="1")
        self.assertEqual(status, 200)
        self.assertIn("Applying the selected guidance", body)
        self.settle(rid)
        self.assertIsNone(self.guid("alpha"))
        self.assertEqual(self.guid("beta"), "B1")
        d = self.events("decided")[0]
        self.assertEqual(d["channel"], "link")

    def test_decide_guards_apply(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}])[1]["id"]
        self.assertEqual(self.post("/decide", id=rid, decision="approve", apply_0="1")[0], 403)   # no csrf
        self.assertEqual(self.post("/decide", user="mallory", id=rid, decision="approve", apply_0="1",
                                   csrf=self.broker.csrf_token("alice"))[0], 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertIsNone(self.guid("alpha"))

    def test_deny_applies_nothing_and_result_is_all_denied(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"}])[1]["id"]
        self.decide(rid, "deny", apply=(0, 1))                               # ticks are ignored on deny
        self.settle(rid)
        self.assertIsNone(self.guid("alpha"))
        self.assertEqual(self.guid("beta"), "BETA-CURRENT")
        got = self.result(rid)
        self.assertEqual(got["status"], "denied")
        self.assertEqual(got["guidance"], {"applied": [], "denied": ["alpha", "beta"], "failed": []})
        self.assertEqual(self.events("guidance_changed"), [])

    def test_text_dropped_from_memory_after_decision(self):
        rid = self.propose([{"name": "alpha", "text": CANARY}])[1]["id"]
        self.decide(rid, "approve", apply=(0,))
        req = self.settle(rid)
        self.assertNotIn(CANARY, json.dumps(req.spec))
        self.assertEqual(req.spec["entries"][0]["length"], len(CANARY))

    def test_second_decision_is_stale(self):
        rid = self.propose([{"name": "alpha", "text": "A1"}])[1]["id"]
        self.decide(rid, "approve", apply=(0,))
        self.settle(rid)
        self.assertEqual(self.broker.decide_via("dashboard", rid, "approve", "alice", apply={0})[0], 410)


class Expiry(Base):
    def test_expiry_applies_nothing(self):
        rid = self.one(CANARY)
        req = self.broker._by_id[rid]
        _fast.expire(self.broker, rid)
        got = self.result(rid)
        self.assertEqual(got, {"status": "expired", "error": None,
                               "guidance": {"applied": [], "denied": ["alpha"], "failed": []}})
        self.assertIsNone(self.guid("alpha"))
        self.assertNotIn(CANARY, json.dumps(req.spec))
        self.assertEqual(self.events("guidance_proposal_result")[0]["denied"], 1)
        self.assertNotIn(CANARY, self.all_text())


# --------------------------------------------------- agent-visible surfaces
class Surfaces(Base):
    def test_no_text_or_current_guidance_anywhere_the_agent_or_logs_can_see(self):
        code, r = self.propose([{"name": "svc", "text": "NEW " + CANARY}, {"name": "beta", "text": CANARY}])
        rid = r["id"]
        agent = []
        agent.append(self.api("GET", f"/v1/requests/{rid}?wait=0")[1])          # pending result
        agent.append(self.api("GET", "/v1/status")[1])
        agent.append(self.api("GET", "/v1/secrets")[1])
        agent.append(self.api("GET", "/v1/secrets?host=127.0.0.1")[1])
        agent.append(self.api("GET", "/v1/audit?limit=500")[1])
        agent.append(self.api("GET", f"/v1/audit?request={rid}")[1])
        self.decide(rid, "approve", apply=(0,))
        self.settle(rid)
        agent.append(self.api("GET", f"/v1/requests/{rid}?wait=0")[1])
        agent.append(self.api("GET", f"/v1/audit?request={rid}")[1])
        agent.append(self.api("GET", "/v1/audit?limit=500")[1])
        for body in agent:
            for secret in (CANARY, CURRENT.split("\n")[0], "BETA-CURRENT", "CURRENT-GUIDANCE"):
                self.assertNotIn(secret, body)
        # the whole audit log, the history page, the pop-over and the notifications
        self.assertNotIn(CANARY, self.all_text())
        self.assertNotIn("CURRENT-GUIDANCE", self.all_text())
        self.assertNotIn("BETA-CURRENT", self.all_text())
        self.assertNotIn(CANARY, json.dumps(self.notifier.sent))
        dash = self.get("/?view=all")[1]
        detail = self.get(f"/request/{rid}")[1]
        for page in (dash, detail):
            self.assertNotIn(CANARY, page)
            self.assertNotIn("CURRENT-GUIDANCE", page)

    def test_agent_audit_requested_event_exposes_names_and_mode_only(self):
        rid = self.one(CANARY)
        _, body = self.api("GET", f"/v1/audit?request={rid}")
        evs = json.loads(body)["events"]
        names = [e["event"] for e in evs]
        self.assertEqual(names, ["requested"])
        e = evs[0]
        self.assertEqual((e["mode"], e["names"]), ("guidance", ["alpha"]))
        self.assertEqual(set(e) - {"seq", "ts", "event", "request", "source", "peer", "mode", "names"}, set())
        for hidden in ("guidance_proposed", "guidance_proposal_result", "guidance_changed", "assessed"):
            self.assertIn(hidden, audit_api.HIDDEN | {"assessed"})
        self.assertIsNone(audit_api.redact({"event": "guidance_proposed", "id": rid, "entry_names": ["a"],
                                            "entry_sha256": ["abc"], "ts": 1, "seq": 1}))
        self.assertIsNone(audit_api.redact({"event": "guidance_proposal_result", "id": rid, "ts": 1, "seq": 1}))

    def test_history_popover_shows_names_counts_outcome_lengths_hashes(self):
        rid = self.propose([{"name": "alpha", "text": "A" * 40}, {"name": "beta", "text": CANARY}])[1]["id"]
        self.decide(rid, "approve", apply=(0,))
        self.settle(rid)
        status, body = self.get(f"/request/{rid}")
        self.assertEqual(status, 200)
        self.assertIn("guidance", body)
        self.assertIn("alpha", body)
        self.assertIn("40 chars", body)
        self.assertIn(sha12("A" * 40), body)
        self.assertIn("applied", body)
        self.assertIn("denied", body)
        self.assertIn("1 / 1 / 0", body)
        self.assertIn("not retained", body)
        self.assertNotIn(CANARY, body)
        self.assertNotIn("A" * 40, body)
        hist = self.get("/?fragment=1&view=all")[1]
        self.assertIn("guidance proposal (2 credentials)", hist)

    def test_audit_has_no_proposal_text_for_requested_event(self):
        self.one(CANARY)
        req = self.events("requested")[0]
        self.assertEqual(req["mode"], "guidance")
        self.assertNotIn(CANARY, json.dumps(req))


# ------------------------------------------------------------------------- CLI
class Cli(Base):
    def cli(self, *args, stdin=None):
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY)
        return subprocess.run([sys.executable, "-I", CLI, *args], env=env, input=stdin,
                              capture_output=True, text=True, timeout=60)

    def pending_rid(self, wait=10):
        end = time.time() + wait
        while time.time() < end:
            p = self.broker.pending()
            if p:
                return p[-1].id
            time.sleep(0.05)
        self.fail("no pending request")

    def run_propose(self, args, stdin=None, decide=None, rid_after=None):
        """Start `asb guidance propose`, let `decide(rid)` act, return the finished process."""
        env = dict(os.environ, SECRET_BROKER_URL=self.base, SECRET_BROKER_KEY=KEY)
        p = subprocess.Popen([sys.executable, "-I", CLI, "guidance", "propose", *args], env=env,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if stdin is not None:
            p.stdin.write(stdin)
        p.stdin.close()
        p.stdin = None
        rid = self.pending_rid()
        seen = ""
        if decide:
            # a person cannot decide before the command has read its creation response and
            # printed its waiting line; deciding earlier races with that response (flaky)
            end = time.time() + 20
            fd = p.stderr.fileno()
            while "waiting for approval" not in seen and time.time() < end:
                if select.select([fd], [], [], 0.2)[0]:
                    chunk = os.read(fd, 4096)       # raw read: the text wrapper's buffer would hide data
                    if not chunk:
                        break
                    seen += chunk.decode("utf-8", "replace")
            decide(rid)
        out, err = p.communicate(timeout=60)
        return p.returncode, out, seen + err, rid

    def test_propose_file_applied_exit_0(self):
        d = tempfile.mkdtemp()
        f = os.path.join(d, "p.json")
        with open(f, "w") as fh:
            json.dump([{"name": "alpha", "text": "A1"}, {"name": "beta", "text": "B1"}], fh)
        rc, out, err, rid = self.run_propose([f], decide=lambda rid: self.decide(rid, "approve", apply=(0,)))
        self.assertEqual(rc, 0, err)
        self.assertEqual(out.splitlines(), ["applied: alpha", "denied: beta", "failed: -"])
        self.assertIn("waiting for approval on your phone", err)
        self.assertIn("review each entry on the approval page", err)
        self.assertIn(rid, err)
        self.assertEqual(self.guid("alpha"), "A1")
        # status prints the same, repeatably
        s = self.cli("guidance", "status", rid)
        self.assertEqual((s.returncode, s.stdout.splitlines()), (0, ["applied: alpha", "denied: beta", "failed: -"]))

    def test_propose_stdin_wrapped_entries_and_denied_exit_4(self):
        body = json.dumps({"entries": [{"name": "alpha", "text": "A1"}]})
        rc, out, err, rid = self.run_propose(["-"], stdin=body, decide=lambda rid: self.decide(rid, "deny"))
        self.assertEqual(rc, 4, err)
        self.assertEqual(out.splitlines(), ["applied: -", "denied: alpha", "failed: -"], err)
        self.assertEqual(self.cli("guidance", "status", rid).returncode, 4)
        self.assertIsNone(self.guid("alpha"))

    def test_from_dir(self):
        d = tempfile.mkdtemp()
        for n, txt in (("alpha", "from dir A"), ("beta", "")):
            with open(os.path.join(d, n + ".txt"), "w") as fh:
                fh.write(txt)
        with open(os.path.join(d, "README.md"), "w") as fh:
            fh.write("ignored")
        rc, out, err, rid = self.run_propose(["--from-dir", d],
                                             decide=lambda rid: self.decide(rid, "approve", apply=(0, 1)))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.guid("alpha"), "from dir A")
        self.assertIsNone(self.guid("beta"))                                 # empty file removed guidance
        self.assertEqual(out.splitlines()[0], "applied: alpha, beta")

    def test_expired_exit_5(self):
        def expire(rid):
            _fast.expire(self.broker, rid)
        rc, out, err, rid = self.run_propose(["-"], stdin=json.dumps([{"name": "alpha", "text": "x"}]),
                                             decide=expire)
        self.assertEqual(rc, 5, err)
        self.assertIn("denied: alpha", out)

    def test_status_pending_and_unknown(self):
        rid = self.one()
        s = self.cli("guidance", "status", rid)
        self.assertEqual((s.returncode, s.stdout.strip()), (0, "pending"))
        self.assertEqual(self.cli("guidance", "status", "A" * 20).returncode, 3)
        self.assertEqual(self.cli("guidance", "status", "bad id").returncode, 2)
        self.assertEqual(len(self.notifier.sent), 1)                        # status asked for no approval

    def test_usage_errors_and_broker_errors(self):
        self.assertEqual(self.cli("guidance").returncode, 2)
        self.assertEqual(self.cli("guidance", "show").returncode, 2)
        self.assertEqual(self.cli("guidance", "propose").returncode, 2)
        self.assertEqual(self.cli("guidance", "propose", "/nonexistent.json").returncode, 2)
        self.assertEqual(self.cli("guidance", "propose", "-", stdin="not json").returncode, 2)
        self.assertEqual(self.cli("guidance", "propose", "-", stdin="[]").returncode, 2)
        self.assertEqual(self.cli("guidance", "propose", "--from-dir", tempfile.mkdtemp()).returncode, 2)
        p = self.cli("guidance", "propose", "-", stdin=json.dumps([{"name": "nope", "text": "x"}]))
        self.assertEqual(p.returncode, 3)
        self.assertIn("unknown secret name", p.stderr)
        big = json.dumps([{"name": "alpha", "text": "x" * 2000}] * 60)
        self.assertEqual(self.cli("guidance", "propose", "-", stdin=big).returncode, 2)

    def test_help_guide_and_no_show_command(self):
        h = self.cli("help", "guidance").stdout
        self.assertIn("usage: asb guidance propose", h)
        self.assertIn("There is no command to read current guidance", h)
        g = self.cli("guide").stdout
        self.assertIn("asb guidance propose", g)
        self.assertIn("cannot read the current guidance", g)
        self.assertIn("asb guidance", self.cli("--help").stdout)

    def test_unreachable_broker_exit_3(self):
        env = dict(os.environ, SECRET_BROKER_URL="http://127.0.0.1:1", SECRET_BROKER_KEY=KEY)
        p = subprocess.run([sys.executable, "-I", CLI, "guidance", "propose", "-"], env=env,
                           input=json.dumps([{"name": "alpha", "text": "x"}]), capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(p.returncode, 3)


if __name__ == "__main__":
    unittest.main()
