"""approve_extra_origins: the approval site may be reached under more than one origin."""
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))
import test_e2e as t  # noqa: E402  (module import only: its tests are not re-collected)
from secret_broker import broker as broker_mod  # noqa: E402
from secret_broker.broker import origin_allowed, parse_extra_origins  # noqa: E402

PRIMARY = "https://secrets.example"
EXTRA = "https://broker.example"


class Parse(unittest.TestCase):
    def test_valid_entries_are_normalised(self):
        self.assertEqual(parse_extra_origins(None), ())
        self.assertEqual(parse_extra_origins([]), ())
        self.assertEqual(parse_extra_origins(["https://Broker.Example", "http://10.0.0.5:8801",
                                              "https://broker.example"]),
                         (("https", "broker.example"), ("http", "10.0.0.5:8801")))

    def test_invalid_entries_name_the_key(self):
        bad = ["https://*.example.com", "*.example.com", "https://host/", "https://host/path",
               "https://host?x=1", "ftp://host", "host", "https://", "https://u:p@host",
               "https://host:0", "https://host:70000", "https://host:", "https://ho st",
               "https://-bad.example", "https://a..b", 5, None, "", "https://höst"]
        for entry in bad:
            with self.assertRaises(ValueError, msg=repr(entry)) as cm:
                parse_extra_origins(["https://ok.example", entry])
            self.assertIn("approve_extra_origins[1]", str(cm.exception))
        for notalist in ("https://broker.example", {"a": 1}, 7):
            with self.assertRaises(ValueError) as cm:
                parse_extra_origins(notalist)
            self.assertIn("approve_extra_origins", str(cm.exception))

    def test_at_most_four(self):
        five = [f"https://h{i}.example" for i in range(5)]
        self.assertEqual(len(parse_extra_origins(five[:4])), 4)
        with self.assertRaises(ValueError) as cm:
            parse_extra_origins(five)
        self.assertIn("approve_extra_origins", str(cm.exception))

    def test_startup_error_is_clear_and_does_not_start(self):
        env = dict(os.environ, BROKER_CONFIG='{"approve_extra_origins": ["https://*.example.com"]}')
        p = subprocess.run([sys.executable, "-m", "secret_broker"], env=env, capture_output=True,
                           text=True, timeout=60, cwd=os.path.dirname(os.path.dirname(__file__)))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("config error: approve_extra_origins[0]", p.stderr)
        self.assertNotIn("Traceback", p.stderr)


class Matching(unittest.TestCase):
    def test_exact_matches_only(self):
        ex = [EXTRA, "http://lan.example:8801"]
        ok = (PRIMARY, EXTRA, "https://BROKER.example", "http://lan.example:8801")
        no = ("https://evil-broker.example", "https://broker.example.evil.com", "http://broker.example",
              "https://broker.example:8443", "https://lan.example:8801", "http://lan.example",
              "http://lan.example:8802", "https://x.broker.example", "https://broker.example/x",
              "https://u@broker.example", "https://broker.example.", "")
        for o in ok:
            self.assertTrue(origin_allowed(o, PRIMARY, ex), o)
        for o in no:
            self.assertFalse(origin_allowed(o, PRIMARY, ex), o)
        self.assertFalse(origin_allowed(EXTRA, PRIMARY, None))
        self.assertFalse(origin_allowed(EXTRA, PRIMARY, ["*.example"]))     # a bad list never widens
        self.assertTrue(origin_allowed(EXTRA, "", [EXTRA]))     # no primary: extras still work


class Site(t.Dashboard):
    def tweak(self, cfg):
        super().tweak(cfg)
        cfg["approve_extra_origins"] = [EXTRA]

    def test_extra_origin_is_accepted_and_others_refused(self):
        rid = self.ask()
        for hdr in ({"Origin": "https://evil-secrets.example"},
                    {"Origin": "https://secrets.example.evil.com"},
                    {"Origin": "https://evil-broker.example"},
                    {"Origin": "https://broker.example.evil.com"},
                    {"Origin": "http://broker.example"},
                    {"Origin": "https://broker.example:8443"},
                    {"Origin": "https://secrets.example:8443"},
                    {"Origin": "null"},
                    {"Origin": EXTRA, "Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.decide(rid, "approve", extra=hdr)[0], 403, hdr)
            self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.decide(rid, "approve", csrf="wrong", extra={"Origin": EXTRA})[0], 403)
        self.assertEqual(self.decide(rid, "approve", extra={"Origin": EXTRA,
                                                            "Sec-Fetch-Site": "same-origin"})[0], 303)
        rid = self.ask(path="/second")
        self.assertEqual(self.decide(rid, "approve", extra={"Origin": PRIMARY})[0], 303)
        rid = self.ask(path="/third")
        self.assertEqual(self.decide(rid, "approve")[0], 303)      # no Origin: today's rule

    def test_links_stay_on_the_primary(self):
        self.ask()
        url = self.notifier.sent[0]["url"]
        self.assertTrue(url.startswith(PRIMARY + "/a/"), url)
        self.assertNotIn("broker.example", url)
        self.assertEqual(urllib.parse.urlsplit(url).netloc, "secrets.example")

    def test_manifest_and_worker_are_origin_relative(self):
        self.assertEqual(broker_mod._MANIFEST["start_url"], "/")
        self.assertEqual(broker_mod._MANIFEST["scope"], "/")
        self.assertNotIn("://", str(broker_mod._MANIFEST["icons"]))
        js = t.req(self.abase + "/sw.js", headers={"X-authentik-username": "alice"})[1]
        self.assertNotIn("secrets.example", js)
        self.assertNotIn("broker.example", js)


if __name__ == "__main__":
    unittest.main()
