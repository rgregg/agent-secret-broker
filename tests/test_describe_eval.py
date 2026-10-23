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

    def test_assumed_realistic_replies_fallback_table(self):
        """Before the sanitizer review these 30 phrasings fell back 9 times (all technical_syntax);
        now only the ones that really name a foreign host, number, GraphQL or a method on a script."""
        data = R.load_corpus(CORPUS)
        with open(os.path.join(os.path.dirname(R.__file__), "realistic_replies.json")) as f:
            replies = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
        srv, stub = R.start_stub()
        try:
            rows = R.run_model("a/m", data["cases"], "k", f"http://127.0.0.1:{srv.server_port}/v1", 5, [],
                               stub, replies=replies)
        finally:
            srv.shutdown()
        got = {r["id"]: (r["reason"], r["rule"]) for r in rows if r["kind"] == "fallback"}
        self.assertEqual(got, {
            "graphql": ("rejected", "technical_jargon"), "search-post": ("rejected", "first_word"),
            "delete-vm": ("rejected", "technical_status"), "post-dns": ("rejected", "technical_host"),
            "env-curl-ua": ("rejected", "technical_http_verb")})

    def test_show_rejected_is_for_the_shipped_corpus_only(self):
        import shutil
        import tempfile
        from contextlib import redirect_stderr
        d = tempfile.mkdtemp()
        copy = os.path.join(d, "corpus.json")
        shutil.copy(CORPUS, copy)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(R.main(["--stub", "--show-rejected", "--corpus", copy]), 2)
        self.assertIn("shipped corpus", err.getvalue())
        out = io.StringIO()
        replies = os.path.join(d, "r.json")
        with open(replies, "w") as f:
            json.dump({"get-models": "Calling it is safe and approved"}, f)
        with redirect_stdout(out):
            self.assertEqual(R.main(["--stub", "--show-rejected", "--stub-replies", replies,
                                     "--only", "get-models"]), 0)
        self.assertIn("rejected text: 'Calling it is safe and approved'", out.getvalue())
        self.assertIn("forbidden_word", out.getvalue())
        out = io.StringIO()
        with redirect_stdout(out):                   # without the flag the text is not shown
            R.main(["--stub", "--stub-replies", replies, "--only", "get-models"])
        self.assertNotIn("safe and approved", out.getvalue())

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
