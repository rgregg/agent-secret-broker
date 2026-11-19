"""Suggest guidance: the model call, the prompt (structural facts only), the reply checks, the broker action, the
Policies page and its audit trail."""
import _fast  # noqa: F401  (test-only: fast server shutdown)
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secret_broker import destguard as _destguard  # noqa: E402
_destguard.allow_loopback_for_tests()
from secret_broker import description, keyprovider, riskmodel, summarize  # noqa: E402


class _Resp:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self, *a):
        return json.dumps(self.body).encode()


def _ok(text, finish="stop"):
    return {"choices": [{"message": {"content": text}, "finish_reason": finish}]}


class ChatComplete(unittest.TestCase):
    """summarize.chat_complete: one chat call, a closed reason on failure, never exception text."""

    def call(self, body=None, exc=None, key="k"):
        seen = {}

        def fake(req, timeout=0):
            seen["payload"] = json.loads(req.data)
            seen["timeout"] = timeout
            seen["auth"] = req.get_header("Authorization")
            if exc:
                raise exc
            return _Resp(body)
        with mock.patch("secret_broker.destguard.operator_urlopen", fake):
            got = summarize.chat_complete(keyprovider.as_provider(key), "https://llm.example/v1", "m1",
                                          "SYS", "USER", 300, 30.0)
        return got, seen

    def test_reply_is_returned_with_the_prompt_sent_as_two_messages(self):
        got, seen = self.call(_ok("hello"))
        self.assertEqual(got, ("hello", None))
        self.assertEqual([m["role"] for m in seen["payload"]["messages"]], ["system", "user"])
        self.assertEqual(seen["payload"]["messages"][0]["content"], "SYS")
        self.assertEqual(seen["payload"]["messages"][1]["content"], "USER")
        self.assertEqual((seen["payload"]["model"], seen["payload"]["max_tokens"], seen["timeout"]), ("m1", 300, 30.0))
        self.assertEqual(seen["auth"], "Bearer k")

    def test_failures_become_closed_reasons(self):
        for body, exc, key, want in (
                (None, TimeoutError("S3CR3T-timeout"), "k", "timeout"),
                (None, OSError("S3CR3T-os"), "k", "error"),
                (None, ValueError("S3CR3T-v"), "k", "error"),
                (_ok(""), None, "k", "empty"),
                (_ok("   "), None, "k", "empty"),
                (_ok("cut", "length"), None, "k", "truncated"),
                ({"choices": []}, None, "k", "error"),
                (_ok("x"), None, "", "unavailable")):
            got, _ = self.call(body, exc, key)
            self.assertEqual(got, (None, want), (body, exc, key))


class ModelsExpose(unittest.TestCase):
    def test_chat_classes_complete_through_the_shared_helper(self):
        for cls in (summarize.OpenRouterSummarizer, riskmodel.ChatAnalyzer):
            m = cls("k", "model-a", timeout=4.0)
            self.assertEqual(m.completion_model, "model-a")
            with mock.patch("secret_broker.destguard.operator_urlopen",
                            lambda req, timeout=0: _Resp(_ok("draft"))):
                self.assertEqual(m.complete("s", "u", 100), ("draft", None))

    def test_timeout_is_never_below_the_suggest_floor(self):
        seen = {}

        def fake(req, timeout=0):
            seen["t"] = timeout
            return _Resp(_ok("x"))
        with mock.patch("secret_broker.destguard.operator_urlopen", fake):
            summarize.OpenRouterSummarizer("k", "m", timeout=4.0).complete("s", "u", 10)
            self.assertEqual(seen["t"], summarize.SUGGEST_TIMEOUT)
            summarize.OpenRouterSummarizer("k", "m", timeout=90.0).complete("s", "u", 10)
            self.assertEqual(seen["t"], 90.0)

    def test_floor_analyzer_delegates_and_reports_the_model(self):
        inner = summarize.OpenRouterSummarizer("k", "model-a")
        fa = riskmodel.FloorAnalyzer(inner)
        self.assertEqual(fa.completion_model, "model-a")
        with mock.patch("secret_broker.destguard.operator_urlopen", lambda req, timeout=0: _Resp(_ok("d"))):
            self.assertEqual(fa.complete("s", "u", 10), ("d", None))

    def test_jev_completes_through_its_chat_describer_only(self):
        cfg = {"type": "jev", "api_key_file": "k", "summary_model": "chat-b"}
        fa = riskmodel.build(cfg, lambda p: "key")
        self.assertEqual(fa.completion_model, "chat-b")
        with mock.patch("secret_broker.destguard.operator_urlopen", lambda req, timeout=0: _Resp(_ok("d"))):
            self.assertEqual(fa.complete("s", "u", 10), ("d", None))
        for text in ("deterministic", "none"):
            fa = riskmodel.build({**cfg, "summary_text": text}, lambda p: "key")
            self.assertIsNone(fa.completion_model, text)
            self.assertEqual(fa.complete("s", "u", 10), (None, "unavailable"), text)

    def test_describer_has_it_too(self):
        d = description.Describer("k", "chat-c")
        self.assertEqual(d.completion_model, "chat-c")
        with mock.patch("secret_broker.destguard.operator_urlopen", lambda req, timeout=0: _Resp(_ok("d"))):
            self.assertEqual(d.complete("s", "u", 10), ("d", None))


if __name__ == "__main__":
    unittest.main()
