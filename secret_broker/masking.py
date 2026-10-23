"""The one masker for credential values in anything an upstream sends back.

An upstream can echo a filled header in a different spelling: JSON-escaped (a slash as backslash-slash,
\\uXXXX escapes in either case), URL-encoded (once or twice), HTML entities, base64 (at any of the three byte
alignments an embedded occurrence can have), base32, hex, another case, or one line of a multi-line value
(a PEM key). For each secret value this module masks its raw form and those transformed forms.

* The raw value is masked from MIN_LEN (4) characters. DERIVED forms (case-folded, hex, base64, url, json,
  html, base32) are masked only from MIN_DERIVED (8) characters, and only for values of 6+ characters, so a 4-character secret such as `true` or
  `name` does not corrupt ordinary JSON. Values under 4 characters are never masked.
* At most MAX_FORMS (400) forms are used per response (raw forms first, then derived forms round-robin over the
  values), so a request holding many values costs a bounded amount: one substring test per form.
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
import urllib.parse

MIN_LEN = 4
MIN_DERIVED = 8
MIN_DERIVED_SOURCE = 6      # (and the value itself must have at least this many characters)
MAX_FORMS = 400
MARK = "***"


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
    """(raw_forms, derived_forms) of one secret value."""
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
        if len(v) < MIN_DERIVED_SOURCE:
            continue                        # a short value gets no derived spellings at all (`true`, `name`)
        j = json.dumps(v)[1:-1]
        jl = json.dumps(v, ensure_ascii=False)[1:-1]
        q = urllib.parse.quote(v, safe="")
        der |= {j, jl, j.replace("/", "\\/"), jl.replace("/", "\\/"), v.lower(), v.upper(),
                urllib.parse.quote(v), q, urllib.parse.quote_plus(v), q.lower(), urllib.parse.quote(q, safe=""),
                v.encode("utf-8", "replace").hex(), v.encode("utf-8", "replace").hex().upper(),
                _uesc(v, True), _uesc(v, False), html.escape(v), html.escape(v, quote=False),
                "".join("&#%d;" % ord(c) for c in v), "".join("&#x%x;" % ord(c) for c in v),
                "".join("&#x%X;" % ord(c) for c in v)}
        b32 = base64.b32encode(v.encode("utf-8", "replace")).decode()
        der |= {b32, b32.rstrip("="), b32.lower(), b32.rstrip("=").lower()}
        for prefix in ("", "Bearer ", "Token ", "Basic "):
            der |= _b64_variants((prefix + v).encode("utf-8", "replace"))
    return raw, {f for f in der if len(f) >= MIN_DERIVED} - raw


def forms_of(value):
    raw, der = split_forms(value)
    return raw | der


class Masker:
    def __init__(self, values):
        raws, ders = [], []
        seen = set()
        for v in values:
            r, d = split_forms(v)
            raws.append(r)
            ders.append(sorted(d))
        forms = []
        for r in raws:
            for f in sorted(r):
                if f not in seen:
                    seen.add(f)
                    forms.append(f)
        i = 0
        while len(forms) < MAX_FORMS and any(i < len(d) for d in ders):      # round-robin over the values
            for d in ders:
                if i < len(d) and d[i] not in seen and len(forms) < MAX_FORMS:
                    seen.add(d[i])
                    forms.append(d[i])
            i += 1
        self.forms = sorted(forms[:max(MAX_FORMS, len(raws))], key=len, reverse=True)
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
