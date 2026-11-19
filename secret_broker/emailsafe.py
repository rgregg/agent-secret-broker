"""Text that looks like an email address, made safe to put on a page.

SSH identities (`user@host`, `account@server`) and SSO names are shaped like email addresses. An edge proxy in
front of the approval site (Cloudflare "Email Address Obfuscation") rewrites such text in HTML into a script-decoded
placeholder, and the page then shows `[email protected]`. Nothing here depends on that proxy: the text is emitted so
that no single text node contains `x@y`, and it is also wrapped in the proxy's documented opt-out comment.

    <!--email_off-->bob<span>@</span>laptop<!--/email_off-->

An inline `<span>` adds no whitespace and no role, so the text selects, copies and is read by a screen reader exactly
as the original. `text(s)` is for element content (never inside an attribute); it escapes. `shield(page)` applies
the same guard to the text nodes of a finished page, never inside tags, attributes, scripts, styles, textareas, titles
or comments, so a render site nobody thought of is covered too. Both are idempotent and linear in the input length
(split on whitespace first, no backtracking over agent-supplied text).
"""
import html
import re

OPEN, CLOSE = "<!--email_off-->", "<!--/email_off-->"
_WS = re.compile(r"(\s+)")
_AT = re.compile(r"(?<=\S)@(?=\S)")
# What shield() must not look inside: comments, raw-text elements and every tag (so attributes are untouched).
_SKIP = re.compile(r"(<!--.*?-->|<script\b.*?</script\s*>|<style\b.*?</style\s*>|<textarea\b.*?</textarea\s*>"
                   r"|<title\b.*?</title\s*>|<[^>]*>)", re.S | re.I)


def _guard(word):
    if "@" not in word or not _AT.search(word):
        return word
    return OPEN + _AT.sub("<span>@</span>", word) + CLOSE


def _guard_run(s):
    """Guard every whitespace-separated word of already-escaped text."""
    return "".join(_guard(p) if i % 2 == 0 else p for i, p in enumerate(_WS.split(s)))


def text(value):
    """`value` escaped for element content, with any `x@y` word made unmatchable by an address scanner."""
    return _guard_run(html.escape(str(value)))


def shield(page):
    """`page` (HTML) with the text nodes guarded. Markup, attributes and scripts are left as they are."""
    parts = _SKIP.split(page)
    return "".join(p if i % 2 else _guard_run(p) for i, p in enumerate(parts))
