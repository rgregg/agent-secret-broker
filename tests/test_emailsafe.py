"""Email-shaped text on a page (secret_broker/emailsafe.py).

An edge proxy (Cloudflare "Email Address Obfuscation") rewrites anything shaped like an email address in HTML text.
SSH identities and SSO names look like one, so every place the broker puts such text on a page goes through
`emailsafe.text`, and `emailsafe.shield` is the backstop over a finished page. These are the pure tests; the pages
themselves are scanned in test_clients_page.py.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import html
import os
import re
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import emailsafe  # noqa: E402

_SKIP = re.compile(r"<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>|<textarea\b.*?</textarea\s*>"
                   r"|<title\b.*?</title\s*>", re.S | re.I)


def text_nodes(page):
    """The visible text pieces of a page: comments, scripts, styles, textareas and every tag are cut out and
    replaced by a NUL, so two pieces that a tag or comment separates never read as adjacent. This does not
    look at the shield's own markup at all, so it cannot pass because the shield said it had run."""
    return [p for p in re.sub(r"<[^>]*>", "\0", _SKIP.sub("\0", page)).split("\0") if p]


def raw_email_shapes(page):
    """Every `\\w@\\w` that a proxy could match in the text of `page`."""
    return [m.group(0) for node in text_nodes(page) for m in re.finditer(r"\w@\w", node)]


def visible(markup):
    """What a reader sees and copies from `markup`."""
    return html.unescape("".join(text_nodes(markup)))


class Scanner(unittest.TestCase):
    def test_the_scan_finds_a_planted_address_and_ignores_split_ones(self):
        self.assertEqual(raw_email_shapes("<p>mail bob@laptop now</p>"), ["b@l"])
        self.assertEqual(raw_email_shapes("<p>bob<span>@</span>laptop</p>"), [])
        # attributes, scripts and comments are not text
        self.assertEqual(raw_email_shapes("<a title='bob@laptop'>x</a><script>a@b</script><!-- a@b -->"), [])


class Text(unittest.TestCase):
    def test_reads_and_copies_as_the_original(self):
        for s in ("bob@laptop", "alice@host.example", "git@github.com:org/repo.git", "a@b@c", "x @y", "@", "a@"):
            out = emailsafe.text(s)
            self.assertEqual(visible(out), s, s)

    def test_no_text_node_matches_an_address_shape(self):
        out = emailsafe.text("deploy@build-01.example")
        self.assertIn("@", out)                         # positive control: the identity is there
        self.assertEqual(raw_email_shapes(out), [])
        self.assertEqual(raw_email_shapes("deploy@build-01.example"), ["y@b"])   # and the raw form would match

    def test_wrapped_in_the_proxys_opt_out_and_split(self):
        out = emailsafe.text("bob@laptop")
        self.assertEqual(out, "<!--email_off-->bob<span>@</span>laptop<!--/email_off-->")

    def test_text_without_an_address_is_only_escaped(self):
        self.assertEqual(emailsafe.text("plain <b>&"), html.escape("plain <b>&"))
        self.assertEqual(emailsafe.text("a @ b"), "a @ b")

    def test_escapes_what_it_is_given(self):
        out = emailsafe.text("<img src=x onerror=1>@evil\"'")
        self.assertNotIn("<img", out)
        self.assertEqual(visible(out), "<img src=x onerror=1>@evil\"'")

    def test_non_strings_are_shown_as_text(self):
        self.assertEqual(emailsafe.text(None), "None")
        self.assertEqual(emailsafe.text(5), "5")

    def test_hostile_length_stays_linear(self):
        for bad in ("@" * 200000, "a" * 200000, "a@" * 100000, ("a" * 50 + "@" + "b" * 50 + " ") * 5000):
            t0 = time.monotonic()
            out = emailsafe.text(bad)
            self.assertLess(time.monotonic() - t0, 2.0, bad[:8])
            self.assertEqual(raw_email_shapes(out), [])


class Shield(unittest.TestCase):
    PAGE = ("<!doctype html><title>ssh a@b.example</title><style>.x{content:'a@b'}</style>"
            "<p title='bob@laptop' data-x=\"c@d\">hello bob@laptop</p><textarea>t@u</textarea>"
            "<script>var s='e@f';</script><!-- g@h --><span>ok</span>")

    def test_guards_text_nodes_only(self):
        self.assertEqual(raw_email_shapes(self.PAGE), ["b@l"])           # premise: the page has one in text
        out = emailsafe.shield(self.PAGE)
        self.assertEqual(raw_email_shapes(out), [])
        self.assertEqual(visible(out), visible(self.PAGE))
        for kept in ("title='bob@laptop' data-x=\"c@d\"", "<textarea>t@u</textarea>", "var s='e@f';",
                     "<title>ssh a@b.example</title>", ".x{content:'a@b'}", "<!-- g@h -->"):
            self.assertIn(kept, out)                                      # nothing else was touched

    def test_idempotent(self):
        once = emailsafe.shield(self.PAGE)
        self.assertEqual(emailsafe.shield(once), once)
        self.assertEqual(emailsafe.shield(emailsafe.text("bob@laptop")), emailsafe.text("bob@laptop"))

    def test_hostile_length_stays_linear(self):
        page = "<p>" + "@" * 300000 + "</p><p>" + "x" * 300000 + "</p>" + "<b>a@b</b>" * 20000
        t0 = time.monotonic()
        out = emailsafe.shield(page)
        self.assertLess(time.monotonic() - t0, 3.0)
        self.assertEqual(raw_email_shapes(out), [])


if __name__ == "__main__":
    unittest.main()
