"""Helpers for tests that read rendered pages (test-only; not a test module).

Every page passes through `secret_broker.emailsafe`, which splits an `x@y` in text so an address-rewriting edge proxy
cannot match it. A test that wants the text as a reader sees it uses `unshield` (exactly the inverse of the guard),
and a test that wants to prove the guard worked uses `raw_email_shapes` (which does not look at the guard's markup).
"""
import html
import re

_SKIP = re.compile(r"<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>|<textarea\b.*?</textarea\s*>"
                   r"|<title\b.*?</title\s*>", re.S | re.I)


def unshield(page):
    """`page` with the email guard taken back out: what a reader sees and copies, tags still in place."""
    return page.replace("<!--email_off-->", "").replace("<!--/email_off-->", "").replace("<span>@</span>", "@")


def text_nodes(page):
    """The visible text pieces of a page: comments, scripts, styles, textareas and every tag are cut out and
    replaced by a NUL, so two pieces that a tag or comment separates never read as adjacent. This does not
    look at the guard's own markup at all, so it cannot pass because the guard said it had run."""
    return [p for p in re.sub(r"<[^>]*>", "\0", _SKIP.sub("\0", page)).split("\0") if p]


def raw_email_shapes(page):
    """Every `\\w@\\w` that a proxy could match in the text of `page`."""
    return [m.group(0) for node in text_nodes(page) for m in re.finditer(r"\w@\w", node)]


def visible(markup):
    """What a reader sees and copies from `markup`, tags removed."""
    return html.unescape("".join(text_nodes(markup)))
