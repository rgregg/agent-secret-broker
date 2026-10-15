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
        except ValueError as e:
            raise StructuredError(f"field is not valid JSON: {e}") from None
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
