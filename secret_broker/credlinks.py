"""Links to a credential's page, built in one place.

`link(name)` is the only thing outside the credential routes that writes a `/credentials/NAME` href. A name becomes an
anchor only when it is a syntactically valid credential name and, while a request is being rendered, is in the
catalog (`use(names)` is set once at the top of each approval-site request); any other name is shown as plain escaped
text, so a page never links to a credential that has no page and never builds a URL from text it did not check.
"""
import contextvars
import html
import re

_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_TABS = (None, "policies")
_linkable = contextvars.ContextVar("credlinks_linkable", default=None)


def use(names):
    """Set the names that may be linked in the current thread's context (None = any valid name)."""
    _linkable.set(None if names is None else frozenset(names))


def link(name, tab=None, text=None):
    """`name` as an anchor to its page (`tab="policies"`: its Policies sub-tab), or plain escaped text. `text` is
    the label to show instead of the name (also what plain text falls back to)."""
    if tab not in _TABS:
        raise ValueError("tab must be None or 'policies'")
    name = str(name)
    allowed = _linkable.get()
    label = html.escape(name if text is None else str(text))
    if not _NAME.fullmatch(name) or (allowed is not None and name not in allowed):
        return label
    q = "?tab=policies" if tab == "policies" else ""
    return f"<a class=clink href='/credentials/{html.escape(name, quote=True)}{q}'>{label}</a>"


def links(names, tab=None):
    """Several names, each linked, joined with ', '."""
    return ", ".join(link(n, tab) for n in names)
