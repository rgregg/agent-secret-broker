"""The ONE scanner that decides what is a {{placeholder}} in text an agent wrote (a request body, a url, a header).

Only two shapes are placeholders, because they are the only two the broker can fill:
  * {{CREDENTIAL_VAR}}      UPPER_SNAKE, the variable names of a credential (broker._VAR_RE)
  * {{session.Name}}        a value captured earlier in a session
Spaces or tabs just inside the braces are allowed ({{ TOKEN }}). Every other {{...}} -- a Jinja/Handlebars
template such as {{ states('x') }}, {{ now }} or {{ 1 + 1 }} -- is ordinary text and is sent as written.
`{{{{` is an escape for a literal `{{`, so text that WOULD look like a placeholder can still be sent
({{{{TOKEN}} is sent as {{TOKEN}}); a lone `}}` never needs one.

The approval card, the scope checks (neutralize) and the send (fill) all read text through scan(), so they cannot
disagree about what is a placeholder. A literal contains no secret, so a mismatch here could only ever hide
text from a check, never leak a value; sharing the scanner is what rules that out.

Linear in the length of the text: the closing `}}` is searched once per run of openers, never once per opener,
and a candidate name is only examined when it is short.
"""
import re

LIT, PH = "lit", "ph"
# a candidate longer than this is plain text (never a name worth refusing); the real name cap is the caller's
_MAX_CANDIDATE = 256
_NAME = re.compile(r"(?:[A-Z][A-Z0-9_]*|session\.[A-Za-z][A-Za-z0-9_]*)\Z")


def _name(inner):
    """The placeholder name in `inner` (the text between `{{` and `}}`), or None when it is not one."""
    if len(inner) > _MAX_CANDIDATE:
        return None
    name = inner.strip(" \t")
    return name if _NAME.match(name) else None


def scan(text):
    """Yield (LIT, text) and (PH, name, raw) pieces that join back to `text` (an escape `{{{{` yields the
    literal `{{`; `raw` is the placeholder as written, for a caller that leaves an unfilled one in place)."""
    text = text or ""
    i, b, closed = 0, -1, True              # `closed`: False once no `}}` is left anywhere
    while True:
        a = text.find("{{", i)
        if a < 0:
            break
        if text.startswith("{{{{", a):
            yield LIT, text[i:a] + "{{"
            i = a + 4
            continue
        if closed and b < a + 2:            # reuse the closer found for an earlier opener
            b = text.find("}}", a + 2)
            closed = b >= 0
        if not closed:                      # an unclosed opener is text; a later `{{{{` still escapes
            yield LIT, text[i:a + 2]
            i = a + 2
            continue
        name = _name(text[a + 2:b]) if b - a - 2 <= _MAX_CANDIDATE else None   # never copy a long span
        if name is None:
            yield LIT, text[i:a + 2]
            i = a + 2
            continue
        if a > i:
            yield LIT, text[i:a]
        yield PH, name, text[a:b + 2]
        i = b + 2
    if i < len(text):
        yield LIT, text[i:]
