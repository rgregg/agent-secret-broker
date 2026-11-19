"""Several values in one vault field.

A Secure Note (or any field) can hold either a JSON object or `KEY=value`
lines (`KEY: value` also works; `#` starts a comment; values may be wrapped
in single or double quotes). A config var then selects one value with
`"key": "CLIENT_SECRET"`.
"""
import json
import re

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s?(.*?)\s*$")


class StructuredError(Exception):
    pass


def _unquote(v):
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _encode(v):
    """Write a value so that parse() reads back exactly v."""
    if v == "" or v == v.strip() and not (len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'"):
        return v
    for q in ('"', "'"):
        if q not in v:
            return q + v + q
    raise StructuredError("value has surrounding space or quotes and both quote kinds")


def is_json(text):
    return text.lstrip().startswith("{")


def parse(text):
    """Return {key: str}. Raises StructuredError if the text is not structured."""
    if is_json(text):
        try:
            obj = json.loads(text)
        except ValueError:      # the parser's text can quote the document: say only that it is not JSON
            raise StructuredError("field is not valid JSON") from None
        if not isinstance(obj, dict):
            raise StructuredError("field JSON must be an object")
        return {str(k): v if isinstance(v, str) else json.dumps(v) for k, v in obj.items()}
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if m:
            out[m.group(1)] = _unquote(m.group(2))
    if not out:
        raise StructuredError("field has no KEY=value lines")
    return out


def entries(text):
    """[(key, value), ...] in the order written, repeats kept (parse() keeps only the last), for a caller that
    must refuse a repeated key. A JSON value that is not a string is returned as it is, not encoded.
    Raises StructuredError (fixed text) if the text is not structured."""
    if is_json(text):
        try:
            pairs = json.loads(text, object_pairs_hook=list)
        except ValueError:
            raise StructuredError("field is not valid JSON") from None
        if not isinstance(pairs, list) or not all(isinstance(p, tuple) for p in pairs):
            raise StructuredError("field JSON must be an object")
        return [(str(k), v) for k, v in pairs]
    out = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if m:
            out.append((m.group(1), _unquote(m.group(2))))
    if not out:
        raise StructuredError("field has no KEY=value lines")
    return out


def get(text, key):
    values = parse(text)
    if key not in values:
        raise StructuredError(f"key {key!r} not found in the field")
    return values[key]


def set_key(text, key, value):
    """Replace the value of an existing key, keeping everything else as it was."""
    if "\n" in value or "\r" in value:
        if not is_json(text):
            raise StructuredError("a multi-line value needs a JSON field")
    if is_json(text):
        obj = json.loads(text)
        if key not in obj:
            raise StructuredError(f"key {key!r} not found in the field")
        obj[key] = value
        return json.dumps(obj, indent=2)
    lines, hit = text.splitlines(), False
    enc = _encode(value)
    for i, line in enumerate(lines):
        m = _LINE.match(line)
        if m and m.group(1) == key:
            # splice at the value's own span; never search the line for the key
            lines[i], hit = line[:m.start(2)] + enc + line[m.end(2):], True
    if not hit:
        raise StructuredError(f"key {key!r} not found in the field")
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def drop_key(text, key):
    """The field text without `key`, everything else as it was. Returns None when no key is left (the caller
    then removes the whole field). StructuredError if the key is not there."""
    if is_json(text):
        try:
            obj = json.loads(text)
        except ValueError:
            raise StructuredError("field is not valid JSON") from None
        if not isinstance(obj, dict) or key not in obj:
            raise StructuredError(f"key {key!r} not found in the field")
        del obj[key]
        return json.dumps(obj, indent=2) if obj else None
    lines, kept, hit = text.splitlines(), [], False
    for line in lines:
        m = _LINE.match(line)
        if m and m.group(1) == key:
            hit = True
            continue
        kept.append(line)
    if not hit:
        raise StructuredError(f"key {key!r} not found in the field")
    if not any(_LINE.match(x) for x in kept if x.strip() and not x.lstrip().startswith("#")):
        return None
    return "\n".join(kept) + ("\n" if text.endswith("\n") else "")
