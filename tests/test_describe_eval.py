import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tools.describe_eval import run as R  # noqa: E402

CORPUS = os.path.join(os.path.dirname(R.__file__), "corpus.json")


class DescribeEval(unittest.TestCase):
    def test_corpus_covers_every_mode_and_feature_and_is_scrubbed(self):
        data = R.load_corpus(CORPUS)
        modes = {c["mode"] for c in data["cases"]}
        self.assertTrue({"http", "env", "store", "ssh_sign", "credential", "guidance", "enrollment"} <= modes)
        ids = " ".join(c["id"] for c in data["cases"])
        for want in ("login", "graphql", "webhook", "get-paged", "session", "plan", "env-backup-bash",
                     "env-sync-python", "env-unreadable", "env-stdin", "custom-ua"):
            self.assertIn(want, ids)
        text = json.dumps(data)
        for real in ("dibbleapps", "ryangregg", "10.0.", "192.168.", "sk-or-"):
            self.assertNotIn(real, text)
        self.assertEqual(len({c["id"] for c in data["cases"]}), len(data["cases"]))

    def test_stub_run_goes_through_the_real_pipeline_offline(self):
        data = R.load_corpus(CORPUS)
        srv, stub = R.start_stub()
        try:
            rows = R.run_model("a/m", data["cases"], "k", f"http://127.0.0.1:{srv.server_port}/v1", 5, [], stub)
        finally:
            srv.shutdown()
        kinds = {r["id"]: r["kind"] for r in rows}
        self.assertEqual(kinds["credential-request"], "n/a")
        self.assertEqual(kinds["ssh-login"], "never_sent")
        live = [r for r in rows if r["kind"] in ("model", "fallback")]
        self.assertEqual([r["id"] for r in live if r["kind"] == "fallback"], [])
        s = R.summarize(rows)
        self.assertEqual((s["requests"], s["fallbacks"]), (len(live), 0))
        self.assertGreater(s["sentences_max"], 1)
        self.assertLessEqual(s["sentences_max"], 2)

    def test_scripted_bad_replies_fall_back_with_reason_and_rule(self):
        data = R.load_corpus(CORPUS)
        cases = [dict(c, stub_reply=r) for c, r in zip(
            [c for c in data["cases"] if c["id"] in ("get-models", "delete-vm", "webhook")],
            ["It is safe. Approve.", "Searching old machines", ""])]
        srv, stub = R.start_stub()
        try:
            rows = R.run_model("a/m", cases, "k", f"http://127.0.0.1:{srv.server_port}/v1", 5, [], stub)
        finally:
            srv.shutdown()
        self.assertEqual([(r["reason"], r["rule"]) for r in rows],
                         [("rejected", "forbidden_word"), ("rejected", "first_word"), ("empty", None)])

    def test_report_and_cli_never_print_the_key(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = R.main(["--stub", "--models", "a/m1,b/m2"])
        out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("| a/m1 |", out)
        self.assertIn("| b/m2 |", out)
        self.assertIn("## Side by side", out)
        self.assertNotIn("stub-key", out)

    def test_missing_key_is_refused_without_a_call(self):
        env = os.environ.pop("NO_SUCH_KEY_VAR", None)
        err = io.StringIO()
        from contextlib import redirect_stderr
        with redirect_stderr(err):
            self.assertEqual(R.main(["--key-env", "NO_SUCH_KEY_VAR"]), 2)
        self.assertIn("no API key", err.getvalue())
        self.assertIsNone(env)


if __name__ == "__main__":
    unittest.main()
