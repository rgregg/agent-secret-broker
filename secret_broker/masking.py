"""The one masker for credential values in anything an upstream sends back.

An upstream can echo a filled header in a different spelling: JSON-escaped (a slash as backslash-slash,
\\uXXXX escapes in either case), URL-encoded (once or twice), HTML entities, base64 (at any of the three byte
alignments an embedded occurrence can have), base32, hex, another case, or one line of a multi-line value
(a PEM key). For each secret value this module masks its raw form and those transformed forms.

* The raw value is masked from MIN_LEN (4) characters. DERIVED forms are masked from MIN_DERIVED (8) characters:
  the unambiguous encodings (hex, base64, base32, double URL-encoding) for every value of 4+ characters, and the
  spellings that collide with ordinary text (case folding, JSON, URL and HTML escapes) only for values of 6+, so a
  4-character secret such as `true` or `name` does not corrupt ordinary JSON. Values under 4 characters are never masked.
* Every form is used, found with plain `str.find`; overlapping and adjacent spans are merged and replaced in one
  pass. Beyond MAX_VALUES / MAX_FORMS / MAX_TOTAL_CHARS / MAX_SPANS the response is withheld whole (WITHHELD),
  never masked partly.
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
import threading
from collections import OrderedDict
import urllib.parse

MIN_LEN = 4
MIN_DERIVED = 8
MIN_DERIVED_SOURCE = 6      # (and the value itself must have at least this many characters)
MAX_VALUES = 200          # secret values in one response's masker
MAX_FORMS = 2000          # forms in one response ...
MAX_TOTAL_CHARS = 400_000     # ... and their summed length; beyond either the response is withheld, never partly masked
MAX_SPANS = 200_000       # occurrences in one text
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


class Masker:
    """Plain, auditable matching: for each form, find ALL its occurrences in the ORIGINAL text with
    `str.find`, merge the overlapping and adjacent spans, replace the merged spans with the mark in one pass.
    Nothing is leftmost-first, so overlapping or nested forms can never leave a fragment behind.

    Bounded work: at most MAX_VALUES values, MAX_FORMS forms and MAX_TOTAL_CHARS summed form length per
    response, and at most MAX_SPANS spans per text. Beyond any of them the response is WITHHELD whole
    (`over_budget`); forms are never dropped. Construction never raises: an empty list is a masker that
    matches nothing, and a failure while building the forms is an over-budget masker."""

    def __init__(self, values):
        self.forms, self.over_budget, self.max_len = [], False, 0
        self._first, self._last = {}, {}
        try:
            vals = [v for v in values if isinstance(v, str) and len(v) >= MIN_LEN]
            vals = list(dict.fromkeys(vals))
            if len(vals) > MAX_VALUES:
                self.over_budget = True
                return
            seen, total = set(), 0
            for v in vals:
                r, d = split_forms(v)
                for f in sorted(r) + sorted(d):
                    if f not in seen:
                        seen.add(f)
                        total += len(f)
                if len(seen) > MAX_FORMS or total > MAX_TOTAL_CHARS:
                    self.over_budget = True
                    return
            self.forms = sorted(seen, key=len, reverse=True)
        except Exception:       # noqa: BLE001 -- fail closed, never raise from construction
            self.forms, self.over_budget = [], True
        self._index()

    def _index(self):
        self.max_len = max((len(f) for f in self.forms), default=0)
        self._first, self._last = {}, {}
        self._short = {f[:k] for f in self.forms for k in (1, 2, 3)}     # every 1 to 3 character start of a form
        for f in self.forms:
            self._first.setdefault(f[:MIN_LEN], []).append(f)
            self._last.setdefault(f[-MIN_LEN:], []).append(f)

    @classmethod
    def from_forms(cls, forms):
        """A masker over exactly these forms (4+ characters each); the seam the property tests use."""
        m = cls([])
        m.forms = sorted({f for f in forms if isinstance(f, str) and len(f) >= MIN_LEN}, key=len, reverse=True)
        m._index()
        return m

    @property
    def margin(self):
        """Extra bytes to read past a cut so a secret straddling it is seen whole."""
        return 4 * self.max_len + 16

    def _spans(self, text):
        """Merged (start, end) spans of every occurrence of every form in `text`; None when over the span budget."""
        spans = []
        for f in self.forms:
            i = text.find(f)
            while i >= 0:
                spans.append((i, i + len(f)))
                if len(spans) > MAX_SPANS:
                    return None
                i = text.find(f, i + 1)
        spans.sort()
        merged = []
        for st, en in spans:
            if merged and st <= merged[-1][1]:          # overlapping or adjacent
                if en > merged[-1][1]:
                    merged[-1] = (merged[-1][0], en)
            else:
                merged.append((st, en))
        return merged

    def mask(self, text):
        if not text:
            return text
        if self.over_budget:
            return MARK
        if not self.forms:
            return text
        spans = self._spans(text)
        if spans is None:
            return MARK
        if not spans:
            return text
        out, pos = [], 0
        for st, en in spans:
            out.append(text[pos:st])
            out.append(MARK)
            pos = en
        out.append(text[pos:])
        return "".join(out)

    def tail_prefix_len(self, text, min_len=MIN_LEN):
        """Length of the longest suffix (`min_len` or more chars, at most 3 below MIN_LEN) of `text` that is a proper
        prefix of some form: the part of a stream that could still turn into a secret when more text arrives (0 when
        there is none)."""
        for k in range(min(len(text), self.max_len - 1), max(1, min_len) - 1, -1):
            tail = text[-k:]
            if k < MIN_LEN:
                if tail in self._short:
                    return k
                continue
            for f in self._first.get(tail[:MIN_LEN], ()):
                if len(f) > k and f.startswith(tail):
                    return k
        return 0

    def mask_tail(self, text):
        """Mask a trailing proper prefix (4+ chars) of any form at the end of `text` (the longest one)."""
        for k in range(min(len(text), self.max_len - 1), MIN_LEN - 1, -1):
            tail = text[-k:]
            for f in self._first.get(tail[:MIN_LEN], ()):
                if len(f) > k and f.startswith(tail):
                    return text[:-k] + MARK
        return text

    def mask_head(self, text):
        """Mask a leading proper suffix (4+ chars) of any form at the very start of `text` (the longest one)."""
        for k in range(min(len(text), self.max_len - 1), MIN_LEN - 1, -1):
            head = text[:k]
            for f in self._last.get(head[-MIN_LEN:], ()):
                if len(f) > k and f.endswith(head):
                    return MARK + text[k:]
        return text

    def body(self, raw, cut):
        """Decode `raw` bytes (read up to cut + margin), mask, mask a leading partial, cut to `cut` bytes, then
        mask a straddling tail. Returns text; WITHHELD when over budget."""
        if self.over_budget:
            return WITHHELD
        text = self.mask(raw.decode("utf-8", "replace"))
        text = self.mask_head(text)
        enc = text.encode("utf-8")
        if len(enc) > cut:
            text = enc[:cut].decode("utf-8", "ignore")
        if len(raw) > cut:
            # the read went past the cut, so the end of what we hold may be the middle of a secret - whether we
            # cut it just now or earlier replacements shrank the text below the cut: mask the longest partial
            text = self.mask_tail(text)
        return text


_CACHE = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_SIZE = 8


def get_masker(values):
    """A Masker for these values, from a small LRU keyed by the set of values (building forms is the costly
    part; the key holds secrets in memory exactly as long as the broker already does)."""
    key = tuple(sorted({v for v in values if isinstance(v, str) and len(v) >= MIN_LEN}))
    with _CACHE_LOCK:
        m = _CACHE.get(key)
        if m is not None:
            _CACHE.move_to_end(key)
            return m
    m = Masker(key)
    with _CACHE_LOCK:
        _CACHE[key] = m
        while len(_CACHE) > _CACHE_SIZE:
            _CACHE.popitem(last=False)
    return m


def mask_values(text, values):
    return get_masker(values).mask(text)


def strip_one_newline(value):
    """A credential pasted into a vault field often ends in one newline; that is never part of a header
    or URL value. Exactly one trailing CRLF or LF is removed (fields and the local store keep it)."""
    if not isinstance(value, str):
        return value
    if value.endswith("\r\n"):
        return value[:-2]
    return value[:-1] if value.endswith("\n") else value
