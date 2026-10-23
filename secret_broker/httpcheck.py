"""Character rules for the pieces of an HTTP request an agent writes, and for the same pieces
after a credential has been filled in.

Two stages, with different error styles:
  * TEMPLATE (request creation): the text the agent wrote. Anything wrong is refused with a generic
    sentence that does not echo the text (it may be a payload an attacker chose to be logged).
  * FILLED (just before sending): any credential, captured or other value can contain anything.
    One fixed label ("invalid request", errclass.InvalidRequest) covers every cause, so the
    outcome never depends on a secret's content in a way the agent could read, and no value is
    ever in the error.
"""
import re
import urllib.parse

from .errclass import InvalidRequest

_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}\Z")
# C0 controls, DEL (HTAB is legal inside a header value; nothing else in this range is)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_CTRL_NO_TAB = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_PLACEHOLDER_OK = re.compile(r"^ ?[A-Za-z][A-Za-z0-9_.]{0,80} ?\Z")
GENERIC = "the request contains characters that cannot be sent"


def strip_placeholders(text):
    """`text` with each well-formed {{ NAME }} replaced by a neutral token; ValueError (fixed text)
    when a {{...}} holds anything but a name (a CR/LF or other control inside a placeholder is
    one way to hide text from the approval card)."""
    out, i = [], 0
    while True:
        a = text.find("{{", i)
        b = text.find("}}", a + 2) if a >= 0 else -1
        if a < 0 or b < 0:
            out.append(text[i:])
            return "".join(out)
        inner = text[a + 2:b]
        if not _PLACEHOLDER_OK.match(inner):
            raise ValueError(GENERIC)
        out.append(text[i:a] + "P")
        i = b + 2


def check_url_template(url):
    """The url the agent wrote: no control character, no whitespace outside a placeholder, and no
    placeholder in the scheme or authority (a value must never choose the host or port).
    ValueError (generic) otherwise."""
    if not isinstance(url, str) or not url:
        raise ValueError("bad url")
    plain = strip_placeholders(url)
    if _CTRL.search(plain) or re.search(r"\s", plain) or not plain.isascii():
        raise ValueError(GENERIC)
    u = urllib.parse.urlsplit(url)
    if "{{" in u.netloc or "{{" in (u.scheme or ""):
        raise ValueError(GENERIC)
    bad = False
    try:
        u.port
    except ValueError:
        bad = True
    if bad:
        raise ValueError("bad url")
    return u


def check_header_name(name):
    if not isinstance(name, str) or not _HEADER_TOKEN.match(name):
        raise ValueError(GENERIC)


def check_header_value_template(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError(GENERIC)
    plain = strip_placeholders(value)
    if _CTRL_NO_TAB.search(plain) or not plain.isascii():
        raise ValueError(GENERIC)


def check_headers_template(headers):
    if not isinstance(headers, dict):
        raise ValueError("headers must be an object")
    for k, v in headers.items():
        check_header_name(k)
        check_header_value_template(v)


def check_filled(url, headers, template_netloc):
    """After substitution: the url keeps its template's scheme://authority and holds no control
    character, whitespace or non-ASCII; every header name is a token and every value printable
    ASCII. InvalidRequest (a fixed label, no text) otherwise."""
    if not isinstance(url, str) or _CTRL.search(url) or re.search(r"\s", url) or not url.isascii():
        raise InvalidRequest()
    bad = False
    try:
        u = urllib.parse.urlsplit(url)
        u.port
    except ValueError:      # its text can quote the value: never chained, never raised from here
        bad = True
    if bad:
        raise InvalidRequest()
    if template_netloc is not None and u.netloc != template_netloc:
        raise InvalidRequest()
    for k, v in headers.items():
        if (not isinstance(k, str) or not _HEADER_TOKEN.match(k) or not isinstance(v, str)
                or _CTRL_NO_TAB.search(v) or not v.isascii()):
            raise InvalidRequest()
