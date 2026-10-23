"""The one masker for credential values in anything an upstream sends back.

An upstream can echo a filled header in a different spelling: JSON-escaped (a slash as backslash-slash), URL-encoded,
base64, hex, another case, or one line of a multi-line value (a PEM key). For each secret value this
module masks its raw form and those transformed forms, and each non-empty line of a multi-line value.

* Values shorter than MIN_LEN (4) characters are not masked at all: masking them would corrupt
  ordinary words and numbers in a response. (The broker also holds such short values to no secrecy
  claim: a 3-character secret is guessable anyway.)
* The base64 forms are of the value and of `Bearer <value>` / `Token <value>` as they appear in an
  Authorization header. A base64 substring that starts at another byte alignment than the value is
  not caught (the three alignments would triple the cost for a spelling an upstream rarely produces).
* A body is cut AFTER masking (read `margin` extra bytes first), and a trailing proper prefix of any
  masked form (4 or more characters) at the very end of the cut body is masked too, so a secret that
  straddles the cut cannot leak its first characters.
"""
import base64
import json
import urllib.parse

MIN_LEN = 4
MARK = "***"


def _b64(raw):
    std = base64.b64encode(raw).decode()
    url = base64.urlsafe_b64encode(raw).decode()
    return {std, std.rstrip("="), url, url.rstrip("=")}


def forms_of(value):
    """Every spelling of one secret value that is masked (including the value itself)."""
    if not isinstance(value, str) or len(value) < MIN_LEN:
        return set()
    out, parts = set(), {value, value.rstrip("\r\n")}
    for line in value.splitlines():
        line = line.strip()
        if len(line) >= MIN_LEN:
            parts.add(line)
    for v in parts:
        if len(v) < MIN_LEN:
            continue
        j = json.dumps(v)[1:-1]
        jl = json.dumps(v, ensure_ascii=False)[1:-1]
        out |= {v, j, jl, j.replace("/", "\\/"), jl.replace("/", "\\/"), v.lower(), v.upper(),
                urllib.parse.quote(v), urllib.parse.quote(v, safe=""), urllib.parse.quote_plus(v),
                urllib.parse.quote(v, safe="").lower(), v.encode("utf-8", "replace").hex(),
                v.encode("utf-8", "replace").hex().upper()}
        for prefix in ("", "Bearer ", "Token ", "Basic "):
            out |= _b64((prefix + v).encode("utf-8", "replace"))
    return {f for f in out if len(f) >= MIN_LEN}


class Masker:
    def __init__(self, values):
        forms = set()
        for v in values:
            forms |= forms_of(v)
        self.forms = sorted(forms, key=len, reverse=True)
        self.max_len = max((len(f) for f in self.forms), default=0)

    @property
    def margin(self):
        """Extra bytes to read past a cut so a secret straddling it is seen whole."""
        return 4 * self.max_len + 16

    def mask(self, text):
        for f in self.forms:
            if f in text:
                text = text.replace(f, MARK)
        return text

    def mask_tail(self, text):
        """Mask a trailing proper prefix (4+ chars) of any form at the end of `text`."""
        for f in self.forms:
            for n in range(min(len(f) - 1, len(text)), MIN_LEN - 1, -1):
                if text.endswith(f[:n]):
                    return text[:-n] + MARK
        return text

    def body(self, raw, cut):
        """Decode `raw` bytes (read up to cut + margin), mask, cut to `cut` bytes, then mask a
        straddling tail. Returns text."""
        text = self.mask(raw.decode("utf-8", "replace"))
        enc = text.encode("utf-8")
        if len(enc) > cut:
            text = enc[:cut].decode("utf-8", "ignore")
            text = self.mask_tail(text)
        return text


def mask_values(text, values):
    return Masker(values).mask(text)


def strip_one_newline(value):
    """A credential pasted into a vault field often ends in one newline; that is never part of a header
    or URL value. Exactly one trailing CRLF or LF is removed (fields and the local store keep it)."""
    if not isinstance(value, str):
        return value
    if value.endswith("\r\n"):
        return value[:-2]
    return value[:-1] if value.endswith("\n") else value
