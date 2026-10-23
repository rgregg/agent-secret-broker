"""Request details: the headers and body of an http request (and the script text of
an env request) for the approver.

Two uses, one data shape (`build_view`):
  * the pending card and the /a/<nonce> page show it in a collapsed section;
  * a short-lived store (`DetailsStore`, a small SQLite file next to the audit log)
    keeps it so the history pop-over can show it afterwards.

Rules, all enforced here and nowhere else:
  * what is shown is built from the request spec that will be executed; `{{VAR}}`
    placeholders are shown as typed and never substituted;
  * a credential-like header whose value is not made only of placeholders is
    replaced by `[masked]` BEFORE the view exists, so neither the page nor the
    store ever holds the literal value (there is no reveal);
  * the body is shown only as text (valid UTF-8, text-like content type), capped,
    scrubbed of obvious secret-looking literals; binary or non-text bodies keep
    only the content type and length; JSON is pretty-printed for display only;
  * nothing here is written to the audit log (only a class-name warning when the
    store fails), to notifications, or to any agent-facing endpoint. The store is
    read only by the approver pages.

Everything is untrusted, attacker-influenced text: `html()` escapes it all.
"""
import base64
from decimal import Decimal
import html as _html
import json
import os
import re
import sqlite3
import threading
import time

from . import scripts as scripts_mod

DEFAULTS = {"enabled": True, "retention_days": 7, "max_body_bytes": 2048,
            "max_script_bytes": 4096, "max_store_mb": 20}
MAX_HEADERS = 40
MAX_HEADER_VALUE = 500
MAX_HEADER_NAME = 100
MASKED = "[masked]"
BODY_WITHHELD = "[body withheld: could not be scrubbed safely]"
_PARSE_MAX = 64 * 1024          # JSON is only pretty-printed (for display) up to this size
_SCRUB_MARGIN = 512             # bytes scrubbed beyond the cut, so a secret at the cut is still caught
SWEEP_INTERVAL = 3600

CREDENTIAL_HEADERS = frozenset((
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-api-secret",
    "x-auth-token", "x-access-token"))
_CRED_WORDS = ("token", "secret", "key", "password", "auth", "credential")
_PLACEHOLDER = re.compile(r"\{\{\s*[A-Za-z_][A-Za-z0-9_]*\s*\}\}")
_SCHEMES = frozenset(("bearer", "basic", "token", "digest", "apikey", "negotiate", "bot", "oauth",
                      "hmac", "jwt", "key"))
_CTRL = re.compile("[\x00-\x1f\x7f-\x9f\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u115f\u1160\u3164]")   # controls, bidi, zero-width, invisible fillers
_TEXT_CT = ("json", "xml", "x-www-form-urlencoded", "graphql", "javascript", "yaml", "form-data",
            "csv", "html", "plain", "x-ndjson", "toml", "sql", "markdown")


# -- config ---------------------------------------------------------------------

def parse_config(raw, field="request_details"):
    """Validate the `request_details` object -> normalized dict. Raises ValueError
    naming the offending field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    unknown = sorted(set(raw) - set(DEFAULTS))
    if unknown:
        raise ValueError(f"{field}.{unknown[0]} is not a known setting")
    out = dict(DEFAULTS)
    out.update(raw)
    if not isinstance(out["enabled"], bool):
        raise ValueError(f"{field}.enabled must be true or false")

    def whole(name, lo, hi, what):
        v = out[name]
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"{field}.{name} must be a whole number of {what}, {lo}-{hi}")
    whole("retention_days", 1, 90, "days")
    whole("max_body_bytes", 0, 65536, "bytes")
    whole("max_script_bytes", 0, 32768, "bytes")
    whole("max_store_mb", 1, 1024, "megabytes")
    return out


# -- masking ----------------------------------------------------------------------

def is_credential_header(name):
    n = str(name).strip().lower()
    return n in CREDENTIAL_HEADERS or any(w in n for w in _CRED_WORDS)


def placeholders_only(value):
    """True when `value` is only {{VAR}} placeholders, optionally behind an auth
    scheme word such as `Bearer` (and joined by : ; ,). A literal anywhere else fails."""
    v = str(value).strip()
    head, sep, rest = v.partition(" ")
    if sep and head.lower() in _SCHEMES:
        v = rest.strip()
    if not _PLACEHOLDER.search(v):
        return False
    return _PLACEHOLDER.sub("", v).strip(" \t:;,") == ""


_INVIS = re.compile("[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\u115f\u1160\u3164]")


def _clean(s):
    return _CTRL.sub("?", str(s))


def _headers(raw):
    """([[name, shown value]], total, any_truncated). Masked before anything else."""
    items = list(raw.items()) if isinstance(raw, dict) else []
    out, cut = [], len(items) > MAX_HEADERS
    for name, value in items[:MAX_HEADERS]:
        name = _clean(name)[:MAX_HEADER_NAME]
        value = str(value)
        if is_credential_header(name) and not placeholders_only(value):
            shown = MASKED
        else:
            shown = _clean(value)
            if len(shown) > MAX_HEADER_VALUE:
                shown, cut = shown[:MAX_HEADER_VALUE] + "...", True
        out.append([name, shown])
    return out, len(items), cut


def _content_type(headers):
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if str(k).strip().lower() == "content-type":
            return _clean(v).strip()[:100] or None
    return None


# -- the body -----------------------------------------------------------------------

def _raw_body(spec):
    if spec.get("body_b64") is not None:
        try:
            return base64.b64decode(spec["body_b64"])
        except (ValueError, TypeError):
            return b""
    b = spec.get("body")
    if b is None or b == "":
        return None
    return b.encode("utf-8", "replace") if isinstance(b, str) else json.dumps(b).encode()


def _text_like(ctype):
    t = (ctype or "").lower().split(";")[0].strip()
    return t.startswith("text/") or any(w in t for w in _TEXT_CT)


def _plain_text(s):
    return not any(c < " " and c not in "\t\n\r" for c in s) and "\x7f" not in s


def _body_view(spec, ctype, limit):
    raw = _raw_body(spec)
    if raw is None:
        return None
    total = len(raw)
    if ctype and not _text_like(ctype):
        return {"kind": "binary", "total": total}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"kind": "binary", "total": total}
    if not ctype and not _plain_text(text):
        return {"kind": "binary", "total": total}
    def shown(t):
        """Scrubbed, capped text of `t`; None when the scrubber withholds it."""
        encoded = t.encode("utf-8")
        window = encoded[:limit + _SCRUB_MARGIN].decode("utf-8", "ignore")
        try:
            scrubbed = scripts_mod.scrub(scripts_mod.clean_text(window))
        except Exception:  # noqa: BLE001 -- fail closed
            return None
        if scrubbed == scripts_mod.WITHHELD:
            return None
        return scrubbed.encode("utf-8")[:limit].decode("utf-8", "ignore"), len(encoded) > limit

    pretty, warn = None, []
    if 0 < total <= _PARSE_MAX and (not ctype or "json" in ctype.lower() or text.lstrip()[:1] in "{["):
        pretty, warn = _format_json(text)
    view = {"kind": "text", "total": total, "formatted": False}
    raw = shown(text)
    if raw is None:
        return {"kind": "withheld", "total": total}
    view["text"], view["truncated"] = raw[0], total > limit or raw[1]
    if warn:
        view["warn"] = warn             # shown exactly as sent: formatting would hide or change something
    elif pretty is not None and pretty != text:
        fmt = shown(pretty)
        if fmt is None:
            return {"kind": "withheld", "total": total}
        view.update(raw=raw[0], text=fmt[0], formatted=True, truncated=total > limit or fmt[1])
    return view


def _format_json(text):
    """(pretty text or None, warnings). Warns when formatting would hide something: duplicate
    keys at any depth, numbers that do not survive a round trip exactly, NaN/Infinity. Input
    that does not parse (or nests too deeply) gives (None, [])."""
    flags = set()

    def pairs(items):
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            flags.add("duplicate keys")
        return dict(items)

    def num(lit):
        try:
            f = float(lit)
            if f in (float("inf"), float("-inf")) or Decimal(repr(f)) != Decimal(lit):
                flags.add("unusual numbers")
        except (ValueError, ArithmeticError):
            flags.add("unusual numbers")
        return float(lit) if lit else 0.0

    def integer(lit):
        n = int(lit)
        if abs(n) > 2 ** 53 or lit.startswith("-0"):
            flags.add("unusual numbers")
        return n

    def const(name):
        flags.add("unusual numbers")
        return 0

    try:
        obj = json.loads(text, object_pairs_hook=pairs, parse_float=num, parse_int=integer,
                         parse_constant=const)
        pretty = json.dumps(obj, indent=2, ensure_ascii=False)
    except (ValueError, RecursionError):
        return None, []
    if flags:
        return None, [w for w in ("duplicate keys", "unusual numbers") if w in flags]
    return pretty, []


def build_view(spec, max_body_bytes=2048):
    """The display/retention view of an http spec: headers (masked), content type
    and body. Always returns a dict; `has_content(view)` says whether it has anything to show."""
    headers, total, cut = _headers(spec.get("headers"))
    ctype = _content_type(spec.get("headers"))
    return {"headers": headers, "headers_total": total, "headers_truncated": cut,
            "ctype": ctype, "body": _body_view(spec, ctype, max_body_bytes)}


def has_content(view):
    return bool(view and (view.get("headers") or view.get("body")))


def scripts_view(scripts, max_bytes):
    """The retained form of an env request's (already scrubbed) scripts: the same
    entries, text cut to `max_bytes`. None when there are none."""
    out = []
    for s in scripts or []:
        if "text" in s:
            enc = s["text"].encode("utf-8")
            text = enc[:max_bytes].decode("utf-8", "ignore")
            out.append({"path": s["path"], "size": s["size"], "sha256": s["sha256"], "text": text,
                        "truncated": bool(s.get("truncated")) or len(enc) > max_bytes})
        else:
            out.append(dict(s))
    return out or None


# -- rendering ------------------------------------------------------------------------

def _n(n):
    return f"{n} byte" + ("" if n == 1 else "s")


def html(view):
    """The collapsed 'Request details' block (server-escaped), or '' when empty."""
    if not has_content(view):
        return ""
    def e(t):       # display only: bidi controls and zero-width characters are replaced, what is sent is unchanged
        return _html.escape(_INVIS.sub("?", str(t)))
    parts = []
    if view["headers"]:
        more = view["headers_total"] - len(view["headers"])
        note = [f"{view['headers_total']} header" + ("" if view["headers_total"] == 1 else "s")]
        if more > 0:
            note.append(f"first {len(view['headers'])} shown")
        if view["headers_truncated"] and any(len(v) > MAX_HEADER_VALUE for _, v in view["headers"]):
            note.append(f"long values cut at {MAX_HEADER_VALUE} characters")
        parts.append(f"<p class=note>Headers ({e(', '.join(note))})</p>"
                     "<pre class=reqtext tabindex=0>"
                     + e("\n".join(f"{k}: {v}" for k, v in view["headers"])) + "</pre>")
    b = view.get("body")
    if b:
        ct = f"{e(view['ctype'])}, " if view.get("ctype") else ""
        if b["kind"] == "text":
            bits = [f"{ct}{_n(b['total'])}"]
            if b["truncated"]:
                bits.append(f"truncated, {b['total']} bytes total")
            if b["formatted"]:
                bits.append("formatted for display; the bytes sent are unchanged")
            parts.append(f"<p class=note>Body ({'; '.join(bits)})</p>")
            if b.get("warn"):
                parts.append("<p class=note><b>This JSON has duplicate keys or numbers that would change when "
                             "formatted, so it is shown exactly as sent.</b> "
                             f"Found: {e(', '.join(b['warn']))}.</p>")
            parts.append(f"<pre class=reqtext tabindex=0>{e(b['text'])}</pre>")
            if b.get("raw") is not None:
                parts.append("<details class=asent><summary>Show as sent</summary>"
                             f"<pre class=reqtext tabindex=0>{e(b['raw'])}</pre></details>")
        elif b["kind"] == "withheld":
            parts.append(f"<p class=note>Body ({ct}{_n(b['total'])})</p>"
                         f"<p class=note><i>{e(BODY_WITHHELD)}</i></p>")
        else:
            parts.append(f"<p class=note>Body: {ct or 'content type not given, '}{_n(b['total'])}"
                         " (binary or non-text content is not shown)</p>")
    return ("<details class=reqdetails><summary>Request details</summary>" + "".join(parts)
            + "<p class=note><small>Advisory: this is what the client asked for. Credential-like headers "
              "that are not {{PLACEHOLDERS}} are masked, and obvious secrets in the body are removed.</small></p>"
              "</details>")


CSS = (".reqdetails{margin-top:.5rem}.reqdetails summary{cursor:pointer;color:var(--muted)}"
       ".reqdetails .note{margin:.4rem 0 .2rem}"
       "pre.reqtext{max-height:14rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;"
       "font-family:ui-monospace,monospace;font-size:.78rem;background:var(--card);border:1px solid var(--line);"
       "border-radius:.4rem;padding:.4rem .55rem;margin:.2rem 0}")


# -- the store --------------------------------------------------------------------------

class DetailsStore:
    """Retained views keyed by request id, in a small SQLite file next to the audit
    log (never in the audit log). Rows carry created_at and expires_at; a sweep
    removes expired rows and a total size cap evicts the oldest first. Owner-only
    file. A missing or corrupt file means "no details": every failure is reported
    through `on_event` (class name only) and never raised."""

    def __init__(self, path, cfg, on_event=None, clock=time.time):
        self._path = path
        self._cfg = cfg
        self._log = on_event or (lambda *a, **k: None)
        self._clock = clock
        self._lock = threading.RLock()
        self._stop = threading.Event()

    # -- plumbing
    def _fail(self, op, exc):
        try:
            self._log("request_details_store_error", op=op, error=type(exc).__name__)
        except Exception:  # noqa: BLE001
            pass

    def _connect(self):
        if not os.path.exists(self._path):
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass
        c = sqlite3.connect(self._path, timeout=5)
        try:
            c.execute("PRAGMA secure_delete=ON")
            c.execute("CREATE TABLE IF NOT EXISTS details (id TEXT PRIMARY KEY, created_at REAL NOT NULL, "
                      "expires_at REAL NOT NULL, size INTEGER NOT NULL, data TEXT NOT NULL)")
            c.execute("CREATE INDEX IF NOT EXISTS details_created ON details (created_at)")
        except BaseException:
            c.close()
            raise
        return c

    def _quarantine(self):
        """A file that is not a database: move it aside so the store starts afresh."""
        try:
            os.replace(self._path, self._path + ".corrupt")
        except OSError:
            pass

    def _run(self, op, fn, default=None):
        """Run fn(conn) under the lock; on failure log the class and return `default`.
        A file SQLite cannot read at all is set aside once and the call retried."""
        with self._lock:
            for attempt in (0, 1):
                c = None
                try:
                    c = self._connect()
                    with c:
                        return fn(c)
                except sqlite3.DatabaseError as exc:
                    corrupt = any(w in str(exc) for w in ("not a database", "malformed"))
                    self._fail(op, exc)
                    if c is not None:
                        c.close()
                        c = None
                    if corrupt and attempt == 0:
                        self._quarantine()
                        continue
                    return default
                except Exception as exc:  # noqa: BLE001 -- never raises
                    self._fail(op, exc)
                    return default
                finally:
                    if c is not None:
                        c.close()
            return default

    # -- API
    def put(self, rid, record):
        """Keep `record` (a JSON-able dict) for the retention period; evict the oldest
        rows when the store exceeds its size cap. Returns True when stored."""
        try:
            data = json.dumps(record, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            self._fail("put", exc)
            return False
        now = self._clock()
        size = len(data) + len(rid) + 64
        cap = self._cfg["max_store_mb"] * 1024 * 1024

        def go(c):
            c.execute("INSERT OR REPLACE INTO details VALUES (?,?,?,?,?)",
                      (rid, now, now + self._cfg["retention_days"] * 86400, size, data))
            total = c.execute("SELECT COALESCE(SUM(size),0) FROM details").fetchone()[0]
            while total > cap:
                old = c.execute("SELECT id, size FROM details ORDER BY created_at, rowid LIMIT 50").fetchall()
                if not old:
                    break
                for oid, osz in old:
                    if total <= cap:
                        break
                    c.execute("DELETE FROM details WHERE id=?", (oid,))
                    total -= osz
            return True
        return bool(self._run("put", go, False))

    def get(self, rid):
        """(record, state): state is "ok", "expired", "missing" or "error"."""
        sentinel = object()

        def go(c):
            row = c.execute("SELECT expires_at, data FROM details WHERE id=?", (rid,)).fetchone()
            if row is None:
                return ("missing", None)
            if row[0] <= self._clock():
                return ("expired", None)
            rec = json.loads(row[1])
            return ("ok", rec) if isinstance(rec, dict) else ("error", None)
        out = self._run("get", go, sentinel)
        if out is sentinel:
            return None, "error"
        return out[1], out[0]

    def sweep(self):
        """Delete expired rows; returns how many. Never raises."""
        now = self._clock()

        def go(c):
            n = c.execute("DELETE FROM details WHERE expires_at <= ?", (now,)).rowcount
            return n
        n = self._run("sweep", go, 0) or 0
        if n:
            # reclaim the space; secure_delete already overwrote the removed text
            try:
                with self._lock:
                    c = sqlite3.connect(self._path, timeout=5)
                    try:
                        c.isolation_level = None
                        c.execute("VACUUM")
                    finally:
                        c.close()
            except Exception as exc:  # noqa: BLE001
                self._fail("vacuum", exc)
        return n

    def count(self):
        return self._run("count", lambda c: c.execute("SELECT COUNT(*) FROM details").fetchone()[0], 0)

    def start(self, interval=SWEEP_INTERVAL):
        """Sweep now, then every `interval` seconds, on a daemon thread."""
        def loop():
            while not self._stop.is_set():
                try:
                    self.sweep()
                except Exception:  # noqa: BLE001
                    pass
                self._stop.wait(interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop.set()
