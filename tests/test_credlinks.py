"""The one helper that builds links to a credential's page: escaped, only for real names, per request."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import credlinks  # noqa: E402


class Link(unittest.TestCase):
    def tearDown(self):
        credlinks.use(None)

    def test_link_escapes_and_quotes(self):
        self.assertEqual(credlinks.link("a.b-c_d"),
                         "<a class=clink href='/credentials/a.b-c_d'>a.b-c_d</a>")
        self.assertEqual(credlinks.link("a.b-c_d", tab="policies"),
                         "<a class=clink href='/credentials/a.b-c_d?tab=policies'>a.b-c_d</a>")

    def test_invalid_names_are_plain_escaped_text(self):
        for bad in ("<img src=x>", "../x", "a b", "", "x" * 65, "a'b"):
            out = credlinks.link(bad)
            self.assertNotIn("<a", out, bad)
            self.assertNotIn("<img", out, bad)
        self.assertEqual(credlinks.link("<b>"), "&lt;b&gt;")
        self.assertIn("<a", credlinks.link("fine"))                              # control: a valid name links

    def test_names_outside_the_set_are_plain_text(self):
        credlinks.use(frozenset({"a"}))
        self.assertIn("<a", credlinks.link("a"))
        self.assertEqual(credlinks.link("b"), "b")
        self.assertEqual(credlinks.link("b", tab="policies"), "b")

    def test_no_set_means_any_valid_name(self):
        credlinks.use(None)
        self.assertIn("<a", credlinks.link("anything-valid"))

    def test_bad_tab_raises(self):
        with self.assertRaises(ValueError):
            credlinks.link("a", tab="settings")
        with self.assertRaises(ValueError):
            credlinks.link("a", tab="' onclick='x")

    def test_links_joins_in_order(self):
        credlinks.use(frozenset({"a", "c"}))
        out = credlinks.links(["a", "b", "c"])
        self.assertEqual(out.count("<a "), 2)
        self.assertLess(out.index(">a<"), out.index(", b, "))
        self.assertTrue(out.endswith("</a>"))

    def test_the_set_is_per_thread(self):
        credlinks.use(frozenset({"a"}))
        seen = []
        t = threading.Thread(target=lambda: seen.append(credlinks.link("zzz")))
        t.start()
        t.join()
        self.assertIn("<a", seen[0])                                             # another thread is unrestricted
        self.assertEqual(credlinks.link("zzz"), "zzz")                           # this one is restricted


if __name__ == "__main__":
    unittest.main()
