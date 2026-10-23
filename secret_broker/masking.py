"""The one masker for credential values in anything an upstream sends back.

An upstream can echo a filled header in a different spelling: JSON-escaped (a slash as backslash-slash,
\\uXXXX escapes in either case), URL-encoded (once or twice), HTML entities, base64 (at any of the three byte
alignments an embedded occurrence can have), base32, hex, another case, or one line of a multi-line value
(a PEM key). For each secret value this module masks its raw form and those transformed forms.

* The raw value is masked from MIN_LEN (4) characters. DERIVED forms are masked from MIN_DERIVED (8) characters:
  the unambiguous encodings (hex, base64, base32, double URL-encoding) for every value of 4+ characters, and the
  spellings that collide with ordinary text (case folding, JSON, URL and HTML escapes) only for values of 6+, so a
  4-character secret such as `true` or `name` does not corrupt ordinary JSON. Values under 4 characters are never masked.
* Every form is used. Many forms are searched with one compiled prefix tree; beyond OVER_BUDGET (20000) forms the
  response is withheld whole (WITHHELD) rather than masked partly.
* Base64: the value, and `Bearer `/`Token `/`Basic ` + value, are encoded with 0, 1 and 2 unknown bytes before
  them; the leading characters that depend on those bytes and the trailing character of a partial group are
  dropped, in standard and URL-safe alphabets, so the remainder appears wherever the secret does. (Base32 is
  masked at alignment zero only.)
* A body is cut AFTER masking (the caller reads `margin` extra bytes first). A trailing proper PREFIX (4+
  characters) of any form at the end of a cut body is masked, and so is a leading proper SUFFIX (4+) of any
  form at the very start of a body (an upstream that honours a Range request can begin mid-secret).
"""
import base64
import html
import json
import re
import urllib.parse

MIN_LEN = 4
MIN_DERIVED = 8
MIN_DERIVED_SOURCE = 6      # (and the value itself must have at least this many characters)
OVER_BUDGET = 20000       # forms in one response; beyond this the whole response is withheld, never partly masked
TRIE_ABOVE = 150          # more forms than this: one compiled prefix tree instead of a substring test per form
MARK = "***"
WITHHELD = "*** (response withheld: too many credential values to mask it safely)"


def _b64_variants(raw):
    out = set()
    for pad in (0, 1, 2):
        data = b"\x00" * pad + raw
        for enc in (base64.b64encode(data).decode(), base64.urlsafe_b64encode(data).decode()):
            full = enc.rstrip("=")
            if pad == 0:
                out |= {enc, full}                  # the value encoded on its own, padded or not
            part = full[(0, 2, 3)[pad]:]            # drop what depends on the unknown bytes before
            if len(data) % 3:
                part = part[:-1]                    # the last, partial group depends on the bytes that follow
            out.add(part)
    return out


def _uesc(v, upper):
    s = "".join("\\u%04X" % ord(c) if upper else "\\u%04x" % ord(c) for c in v if ord(c) < 0x10000)
    return s


def split_forms(value):
    """(raw_forms, derived_forms) of one secret value. Encodings that cannot be mistaken for ordinary text
    (hex, base64, base32, double URL-encoding) exist for every value of 4+ characters; spellings that
    collide with ordinary text (case folding, single-pass JSON/URL/HTML escapes) only for 6+."""
    if not isinstance(value, str) or len(value) < MIN_LEN:
        return set(), set()
    parts = {value, value.rstrip("\r\n")}
    for line in value.splitlines():
        line = line.strip()
        if len(line) >= MIN_LEN:
            parts.add(line)
    raw, der = set(), set()
    for v in parts:
        if len(v) < MIN_LEN:
            continue
        raw.add(v)
        q = urllib.parse.quote(v, safe="")
        der |= {urllib.parse.quote(q, safe=""), v.encode("utf-8", "replace").hex(),
                v.encode("utf-8", "replace").hex().upper()}
        b32 = base64.b32encode(v.encode("utf-8", "replace")).decode()
        der |= {b32, b32.rstrip("="), b32.lower(), b32.rstrip("=").lower()}
        for prefix in ("", "Bearer ", "Token ", "Basic "):
            der |= _b64_variants((prefix + v).encode("utf-8", "replace"))
        if len(v) >= MIN_DERIVED_SOURCE:
            j = json.dumps(v)[1:-1]
            jl = json.dumps(v, ensure_ascii=False)[1:-1]
            der |= {j, jl, j.replace("/", "\\/"), jl.replace("/", "\\/"), v.lower(), v.upper(),
                    urllib.parse.quote(v), q, urllib.parse.quote_plus(v), q.lower(),
                    _uesc(v, True), _uesc(v, False), html.escape(v), html.escape(v, quote=False),
                    "".join("&#%d;" % ord(c) for c in v), "".join("&#x%x;" % ord(c) for c in v),
                    "".join("&#x%X;" % ord(c) for c in v)}
    return raw, {f for f in der if len(f) >= MIN_DERIVED} - raw


def forms_of(value):
    raw, der = split_forms(value)
    return raw | der


def _trie_pattern(words):
    root = {}
    for w in words:
        d = root
        for c in w:
            d = d.setdefault(c, {})
        d[""] = 1

    def rx(d):
        if "" in d and len(d) == 1:
            return ""
        alts = [re.escape(c) + rx(sub) for c, sub in sorted(d.items()) if c != ""]
        r = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        return "(?:" + r + ")?" if "" in d else r
    return rx(root)


class Masker:
    """Every form of every value is used: nothing is dropped to save time. Cost is bounded by how the
    search is done (a substring test per form for a few forms, one compiled prefix tree for many), and
    beyond OVER_BUDGET forms the response is withheld whole (`over_budget`) rather than masked partially."""

    def __init__(self, values):
        forms, seen = [], set()
        for v in values:
            r, d = split_forms(v)
            for f in sorted(r) + sorted(d):
                if f not in seen:
                    seen.add(f)
                    forms.append(f)
        self.forms = sorted(forms, key=len, reverse=True)
        self.max_len = max((len(f) for f in self.forms), default=0)
        self.over_budget = len(self.forms) > OVER_BUDGET
        self._rx = None
        self._long = []
        if len(self.forms) > TRIE_ABOVE and not self.over_budget:
            short = [f for f in self.forms if len(f) <= 300]
            self._long = [f for f in self.forms if len(f) > 300]
            try:
                self._rx = re.compile(_trie_pattern(short))
            except (re.error, RecursionError, OverflowError):
                self._rx, self._long = None, []

    @property
    def margin(self):
        """Extra bytes to read past a cut so a secret straddling it is seen whole."""
        return 4 * self.max_len + 16

    def mask(self, text):
        if self.over_budget:
            return MARK if text else text
        if self._rx is not None:
            text = self._rx.sub(MARK, text)
            for f in self._long:
                if f in text:
                    text = text.replace(f, MARK)
            return text
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

    def mask_head(self, text):
        """Mask a leading proper suffix (4+ chars) of any form at the very start of `text`."""
        for f in self.forms:
            for n in range(min(len(f) - 1, len(text)), MIN_LEN - 1, -1):
                if text.startswith(f[-n:]):
                    return MARK + text[n:]
        return text

    def body(self, raw, cut):
        """Decode `raw` bytes (read up to cut + margin), mask, cut to `cut` bytes, then mask a
        straddling tail and a leading partial. Returns text."""
        if self.over_budget:
            return WITHHELD
        text = self.mask(raw.decode("utf-8", "replace"))
        text = self.mask_head(text) if self.forms else text
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
