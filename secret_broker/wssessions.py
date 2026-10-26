"""WebSocket sessions: the broker holds a ws:// or wss:// connection so the secret never reaches the agent.

A WebSocket session is an HTTP-session sibling (see sessions.py; it lives in the SAME session table, so
lookup, expiry, the per-client binding, the tombstones, revoke, client revoke and the Clients tab are the
one implementation). An agent asks for one (`asb ws NAME URL`); a human approves ONE card; the broker
connects (through the same destination guard as every outbound call), authenticates with the credential's
operator-configured handshake template, and from then on only relays text frames for the agent
(`asb ws send|recv|close ID`, or the `asb ws ID` line pipe).

Invariants (tests/test_ws_sessions.py):
  * a session is always opened by a human: HIGH by code, no model call, never auto-approved (policy, Always,
    timed grants, SSH rules, `auto_approve_max`), no notification button, decided only on the approval site;
  * what the agent sends once approved is NOT filtered (no message allowlist): the session is the unit of
    approval. It is bounded instead: a fixed TTL (never extended), frame and byte caps in each direction,
    a frame size cap, an idle timeout, one connection, a per-client cap, a rate limit, a bounded receive
    queue that PAUSES reading the socket when full (nothing is dropped silently; `truncated` is reported);
  * the secret exists only inside the broker: the handshake template is evaluated here, the credential
    value is in no response, log, audit record or card, and every text frame handed to the agent is masked by the
    shared masker (masking.py). Binary frames are never shown: the agent gets a marker with the length;
  * the destination is the destination guard's (destguard.DestGuard.connect: resolve once, validate every
    address, connect to the pinned address), and the host and port must be in the credential's
    `allowed_hosts` (destguard.entry_allows; ws is port 80 by default, wss 443). wss verifies the
    certificate for the original host name (SNI = that name) unless the credential says otherwise exactly as
    for http (`tls_fingerprint`, `tls_verify`). No redirect, no environment proxy, no Origin unless the
    credential configures one;
  * no exception text, peer byte or frame content reaches the agent, the audit log or any page: only the
    fixed labels of wsproto.py and errclass.py. The audit log records open, close, refusal, counts and byte
    totals, never frame contents.
"""
import html
import json
import re
import ssl
import threading
import time
import urllib.parse
from collections import deque
import hashlib
import secrets
import urllib.parse

from . import clock as clock_mod
from . import destguard
from . import errclass
from . import httpcheck
from . import masking
from . import sessions as S
from . import wsproto

DEFAULTS = {"enabled": True, "default_ttl_s": 900, "max_ttl_s": 3600, "max_frames": 1000, "max_bytes": 8 << 20,
            "max_frame_bytes": 1 << 20, "idle_s": 300, "max_per_client": 2,
            "recv_queue_frames": 256, "recv_queue_bytes": 4 << 20}
CEIL = {"max_ttl_s": 3600, "max_frames": 100_000, "max_bytes": 256 << 20, "max_frame_bytes": 4 << 20,
        "idle_s": 3600, "max_per_client": 10, "recv_queue_frames": 4096, "recv_queue_bytes": 32 << 20}
FLOOR = {"idle_s": 10, "max_frame_bytes": 1024, "recv_queue_frames": 1, "recv_queue_bytes": 4096}
MAX_URL = 2048
CONNECT_S = 10.0
HANDSHAKE_S = 10.0
HANDSHAKE_TOTAL_S = 60.0         # every sign-in step together
FRAME_DEADLINE_S = 30           # a frame that has started must finish within this (slow-drip peers)
DRAIN_GRACE_S = 60              # a finished connection keeps its unread frames this long
IN_FRAMES_SLACK = 16              # inbound wire frames allowed beyond the cap: the handshake's replies and pings
IN_BYTES_SLACK = 4096
RATE_BURST, RATE_PER_S = 60, 20.0       # agent operations per session
RECV_WAIT_MAX = 25.0
MAX_RECV_INFLIGHT = 2           # concurrent recv calls per session
RECV_MAX_FRAMES = 256
MAX_API_BODY = (4 << 20) + 4096          # a send body: one frame (4 MB at most) and its JSON wrapping
RECV_RESPONSE_BYTES = 4 << 20
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_TARGET_RE = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]{0,2040}\Z")
_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?\Z")
_PROTO_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
HANDSHAKE_KEYS = ("wait", "send", "expect")
PRESET_DENY = {"home-assistant": ["auth/long_lived_access_token", "auth/sign_path"]}   # minting commands
MAX_STEPS = 8
STEP_TIMEOUT_DEFAULT, STEP_TIMEOUT_MAX = 10.0, 30.0
STEP_BYTES_DEFAULT, STEP_BYTES_MAX = 65536, 1 << 20
STEP_SKIP_MAX = 16
HEADER_ALLOW = ("authorization", "sec-websocket-protocol", "origin")   # the only upgrade headers config may set
_QKEY_RE = re.compile(r"^[A-Za-z0-9_.~-]{1,64}\Z")

PRESETS = {
    # Home Assistant: the server speaks first with auth_required, we answer with the token, it says auth_ok.
    "home-assistant": [{"expect": {"type": "auth_required"}},
                       {"send": {"type": "auth", "access_token": "{{VAR}}"}},
                       {"expect": {"type": "auth_ok"}}],
}

REASON = "a WebSocket session always needs a human to approve it; always high"
WARNING = ("The requesting agent asked for this session. If you approve, this client may send ANY text "
           "frames it likes to the server below, authenticated with the stored credential, and read what "
           "comes back, WITHOUT asking you again, until the time runs out or a cap is used. Nothing it "
           "sends is filtered or reviewed, except message types the operator blocked for this credential. "
           "Many servers let a signed-in client create NEW credentials (for example a long-lived access "
           "token): anything it creates outlives this session, is not masked and is not revoked with it. The time limit is fixed from the moment you approve: it is never "
           "extended or renewed. Revoke it any time on the Clients tab.")

# end reasons beyond sessions.ENDED's (registered below so the shared lookups keep working)
S.ENDED.update({
    "idle": ("the WebSocket session ended: it was idle too long; open a new one with `asb ws`",
             "session_expired", 410),
    "peer_closed": ("the WebSocket session ended: the server closed the connection; open a new one with `asb ws`",
                    "session_expired", 410),
    "ws_error": ("the WebSocket session ended: a limit was reached or the connection failed; "
                 "open a new one with `asb ws`", "session_expired", 410)})


# ---------------------------------------------------------------- config
def parse_config(raw, field="ws_sessions"):
    """Validate `ws_sessions` -> the full dict with defaults. None means the defaults. ValueError names the field."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    for k in raw:
        if k not in DEFAULTS:
            raise ValueError(f"{field}.{k} is not a known option")
    out = {**DEFAULTS, **raw}
    if not isinstance(out["enabled"], bool):
        raise ValueError(f"{field}.enabled must be true or false")
    for k in DEFAULTS:
        if k in ("enabled", "default_ttl_s"):
            continue
        lo, hi = FLOOR.get(k, 1), CEIL[k]
        if not S._int(out[k]) or not lo <= out[k] <= hi:
            raise ValueError(f"{field}.{k} must be a whole number from {lo} to {hi}")
    if not S._int(out["default_ttl_s"]) or not S.TTL_FLOOR <= out["default_ttl_s"] <= out["max_ttl_s"]:
        raise ValueError(f"{field}.default_ttl_s must be a whole number of seconds from {S.TTL_FLOOR} "
                         f"up to {field}.max_ttl_s")
    return out


def _walk_strings(v, depth=0):
    if depth > 8:
        raise ValueError("handshake template is nested too deeply")
    if isinstance(v, str):
        yield v
    elif isinstance(v, list):
        for x in v:
            yield from _walk_strings(x, depth + 1)
    elif isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise ValueError("handshake template keys must be text")
            yield k
            yield from _walk_strings(x, depth + 1)
    elif not (v is None or isinstance(v, (bool, int, float))):
        raise ValueError("handshake template values must be JSON")


def _check_placeholders(text, names):
    for ph in S.placeholders(text):
        if ph == "VAR":
            if len(names) != 1:
                raise ValueError("{{VAR}} needs a credential with exactly one variable; name it")
        elif ph not in names:
            raise ValueError("ws config uses a placeholder that is not a variable of this credential")


def _norm_steps(hs, names):
    """The handshake setting -> a normalized list of steps. Three spellings: a preset name; {"steps": [...]};
    or the short {"wait": X, "send": Y, "expect": Z}. A step is {"send": Y} or {"expect": X, "timeout": s,
    "max_bytes": n, "skip": k} (`wait` is a synonym of `expect`)."""
    if isinstance(hs, str):
        if hs not in PRESETS:
            raise ValueError("ws.handshake preset is not known (" + ", ".join(sorted(PRESETS)) + ")")
        raw = PRESETS[hs]
    elif isinstance(hs, dict) and set(hs) == {"steps"}:
        raw = hs["steps"]
    elif isinstance(hs, dict) and hs and set(hs) <= set(HANDSHAKE_KEYS):
        raw = []
        if "wait" in hs:
            raw.append({"expect": hs["wait"]})
        if "send" in hs:
            raw.append({"send": hs["send"]})
        if "expect" in hs:
            raw.append({"expect": hs["expect"]})
    else:
        raise ValueError("ws.handshake must be a preset name, {\"steps\": [...]} or an object with wait, send, expect")
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_STEPS:
        raise ValueError(f"ws.handshake has 1 to {MAX_STEPS} steps")
    try:
        if len(json.dumps(raw)) > 8192:
            raise ValueError("ws.handshake is too large")
    except (TypeError, RecursionError):
        raise ValueError("ws.handshake must be JSON") from None
    steps = []
    for st in raw:
        if not isinstance(st, dict):
            raise ValueError("a handshake step is an object")
        kind = [k for k in ("send", "expect", "wait") if k in st]
        if len(kind) != 1:
            raise ValueError("a handshake step is either send or expect")
        k = kind[0]
        extra = set(st) - {k}
        if k == "send":
            if extra:
                raise ValueError("a send step takes nothing else")
            for text in _walk_strings(st["send"]):
                _check_placeholders(text, names)
            steps.append({"op": "send", "value": json.loads(json.dumps(st["send"]))})
            continue
        if extra - {"timeout", "max_bytes", "skip"}:
            raise ValueError("an expect step takes timeout, max_bytes and skip only")
        m = st[k]
        if not (isinstance(m, dict) and m) and not (isinstance(m, str) and 1 <= len(m) <= 1024):
            raise ValueError("expect is a JSON object (field equality) or a non-empty text (a substring)")
        for text in _walk_strings(m):
            if "{{" in text:
                raise ValueError("only a send step, the query and the headers may hold a placeholder")
        t, mb, sk = (st.get("timeout", STEP_TIMEOUT_DEFAULT), st.get("max_bytes", STEP_BYTES_DEFAULT),
                     st.get("skip", 0))
        if (isinstance(t, bool) or not isinstance(t, (int, float)) or not 0.1 <= t <= STEP_TIMEOUT_MAX
                or not S._int(mb) or not 64 <= mb <= STEP_BYTES_MAX or not S._int(sk) or not 0 <= sk <= STEP_SKIP_MAX):
            raise ValueError("expect timeout is 0.1 to 30 s, max_bytes 64 to 1048576, skip 0 to 16")
        steps.append({"op": "expect", "match": json.loads(json.dumps(m)), "timeout": float(t), "max_bytes": mb,
                      "skip": sk})
    return steps


def parse_cred_config(raw, var_names):
    """The credential's operator `ws` setting -> a normalized dict. ValueError (fixed text) on anything wrong,
    which makes the credential invalid in the catalog: it fails closed. A credential with no `ws` setting can
    not open a WebSocket session at all. Never agent input. Options (all optional):
        "handshake": a preset ("home-assistant"), {"steps": [...]} or {"wait": X, "send": Y, "expect": Z}.
            send step:   {"send": JSON-or-text}      strings inside are filled ({{VAR}}); JSON is encoded
                         by the broker, so a value cannot break out of its string
            expect step: {"expect": X, "timeout": 10, "max_bytes": 65536, "skip": 0}
                         X is a JSON object (every field must be present with an equal value in the parsed
                         text frame) or a text (an exact substring of the frame). No regular expressions.
                         `skip` frames that do not match may be passed over; any other mismatch, a timeout
                         or an oversize reply fails the session open with a fixed error.
            Server first (wait for its greeting) = start with an expect step; client first = start with send.
        "query": {"access_token": "{{VAR}}"}   added to the upgrade URL's query, URL-encoded by the broker
        "headers": {"Authorization": "Bearer {{VAR}}"}   Authorization, Sec-WebSocket-Protocol and Origin only
        "origin": "https://app.example.com", "subprotocols": ["graphql-ws"]
        "deny_send": ["auth/long_lived_access_token"]   outgoing text frames whose JSON `type` is listed are refused
            (non-JSON frames pass). The home-assistant preset blocks the token-minting commands by default;
            `"deny_send": []` clears that.
    The broker owns Host, Upgrade, Connection and every Sec-WebSocket-Key/Version/Extensions header: they are
    never settable. `{{VAR}}` is the credential's only variable (with several, name one: `{{MY_TOKEN}}`)."""
    if not isinstance(raw, dict):
        raise ValueError("ws must be an object")
    for k in raw:
        if k not in ("handshake", "origin", "subprotocols", "query", "headers", "deny_send"):
            raise ValueError(f"ws.{k} is not a known option")
    names = set(var_names)
    out = {"steps": None, "origin": None, "subprotocols": [], "query": {}, "headers": {}, "deny_send": []}
    if "deny_send" in raw:
        ds = raw["deny_send"]
        if (not isinstance(ds, list) or len(ds) > 50
                or not all(isinstance(x, str) and 1 <= len(x) <= 128 for x in ds)):
            raise ValueError("ws.deny_send is a list of up to 50 message type names")
        out["deny_send"] = list(dict.fromkeys(ds))
    elif isinstance(raw.get("handshake"), str):
        out["deny_send"] = list(PRESET_DENY.get(raw["handshake"], []))      # a preset's default; `deny_send: []` clears it
    if raw.get("handshake") is not None:
        out["steps"] = _norm_steps(raw["handshake"], names)
    q = raw.get("query")
    if q is not None:
        if not isinstance(q, dict) or len(q) > 5:
            raise ValueError("ws.query is an object of up to 5 parameters")
        for k, v in q.items():
            if not isinstance(k, str) or not _QKEY_RE.match(k) or not isinstance(v, str) or len(v) > 512:
                raise ValueError("ws.query names are plain words and values are text")
            _check_placeholders(v, names)
        out["query"] = dict(q)
    h = raw.get("headers")
    if h is not None:
        if not isinstance(h, dict) or len(h) > 3:
            raise ValueError("ws.headers is an object of up to 3 headers")
        for k, v in h.items():
            if (not isinstance(k, str) or k.lower() not in HEADER_ALLOW or httpcheck.forbidden(k.lower())
                    or not isinstance(v, str) or not v or len(v) > 1024 or not v.isascii()
                    or any(ord(c) < 32 or ord(c) == 127 for c in v.replace("{{", "").replace("}}", ""))):
                raise ValueError("ws.headers allows only Authorization, Sec-WebSocket-Protocol and Origin, as plain text")
            _check_placeholders(v, names)
        if len({k.lower() for k in h}) != len(h):
            raise ValueError("ws.headers repeats a header")
        out["headers"] = dict(h)
    if raw.get("origin") is not None:
        if not isinstance(raw["origin"], str) or not _ORIGIN_RE.match(raw["origin"]):
            raise ValueError("ws.origin must look like https://host[:port]")
        out["origin"] = raw["origin"]
    if raw.get("subprotocols") is not None:
        sp = raw["subprotocols"]
        if not isinstance(sp, list) or len(sp) > 5 or not all(isinstance(x, str) and _PROTO_RE.match(x) for x in sp):
            raise ValueError("ws.subprotocols must be up to 5 protocol names")
        out["subprotocols"] = list(dict.fromkeys(sp))
    lh = {k.lower() for k in out["headers"]}
    if (out["origin"] and "origin" in lh) or (out["subprotocols"] and "sec-websocket-protocol" in lh):
        raise ValueError("ws.origin/subprotocols and the same header in ws.headers are both set")
    return out


def matches(spec, text):
    """Does a received text frame match an expect step? An object spec matches a JSON object frame holding every
    key with an equal value (nested objects likewise; types must agree); a text spec is an exact substring."""
    if isinstance(spec, str):
        return spec in text
    try:
        got = json.loads(text)
    except (ValueError, RecursionError):
        return False

    def sub(a, b):
        if isinstance(a, dict):
            return isinstance(b, dict) and all(k in b and sub(v, b[k]) for k, v in a.items())
        return type(a) is type(b) and a == b
    return sub(spec, got)


def _qkey(k):
    """A query parameter name as a server may read it: percent-decoded, plus as space, case-folded."""
    return urllib.parse.unquote_plus(k).strip().lower()


def upgrade_parts(wsc, target, values):
    """(request target, origin, subprotocols, extra headers) for the upgrade request: the agent's path and query
    plus the credential's configured query (URL-encoded) and headers, filled here. The result holds the secret
    and goes only to the socket: it is never logged, audited or returned."""
    vals = {k: masking.strip_one_newline(v) for k, v in values.items()}
    if wsc["query"]:
        extra_q = "&".join(urllib.parse.quote(k, safe="") + "=" + urllib.parse.quote(S.fill(v, vals), safe="")
                           for k, v in wsc["query"].items())
        path, _, agent_q = target.partition("?")
        target = path + "?" + extra_q + (("&" + agent_q) if agent_q else "")        # the credential's first: it wins
    origin, protos, extra = wsc["origin"], list(wsc["subprotocols"]), []
    for k, v in wsc["headers"].items():
        val = S.fill(v, vals)
        lk = k.lower()
        if lk == "origin":
            origin = val
        elif lk == "sec-websocket-protocol":
            protos = [x.strip() for x in val.split(",") if x.strip()]
        else:
            extra.append(("Authorization", val))
    return target, origin, protos, extra


def signin_summary(wsc):
    """A short fixed-vocabulary description of how the credential signs in (for the card and the audit log)."""
    bits = []
    if wsc["query"]:
        bits.append("a value in the URL query")
    if wsc["headers"]:
        bits.append("upgrade header(s): " + ", ".join(sorted(k.title() for k in wsc["headers"])))
    n = sum(1 for st in (wsc["steps"] or []) if st["op"] == "send")
    if wsc["steps"]:
        bits.append(f"{len(wsc['steps'])} message step(s)")
    return "; ".join(bits) or "none (no credential is sent)"


def _fill_json(v, values):
    if isinstance(v, str):
        return S.fill(v, values)
    if isinstance(v, list):
        return [_fill_json(x, values) for x in v]
    if isinstance(v, dict):
        return {_fill_json(k, values): _fill_json(x, values) for k, x in v.items()}
    return v


def run_handshake(conn, steps, values):
    """The credential's steps, evaluated here, in order. Raises wsproto.WsError with a fixed label on a mismatch
    (handshake refused), a timeout or an oversize reply: nothing the server said is kept or reported."""
    keep = conn.max_frame
    total_end = time.monotonic() + HANDSHAKE_TOTAL_S        # all steps together, however many and however slow
    try:
        for st in steps:
            if st["op"] == "send":
                msg = _fill_json(st["value"], values)
                conn.write(wsproto.OP_TEXT, (msg if isinstance(msg, str) else json.dumps(msg)).encode("utf-8"))
                continue
            end = min(time.monotonic() + st["timeout"], total_end)
            conn.max_frame = min(keep, st["max_bytes"])
            skipped = 0
            while True:
                m = conn.read_message(lambda mid=False: time.monotonic() > end)
                if m is None:
                    raise wsproto.WsError(wsproto.TIMEOUT)
                if m[0] == "text" and matches(st["match"], m[1]):
                    break
                skipped += 1
                if m[0] == "close" or skipped > st["skip"]:
                    raise wsproto.WsError(wsproto.HANDSHAKE, 1008)
    finally:
        conn.max_frame = keep


# ---------------------------------------------------------------- url
def parse_url(url):
    """`ws://host[:port]/path?query` or wss:// -> (scheme, host, port, target). ValueError with fixed text;
    the agent's text is never repeated. No userinfo, no fragment, no control character or space, ASCII only,
    a conservative request-target alphabet (so nothing can reach the request line but the path and query)."""
    msg = "url must be ws://host[:port]/path or wss://host[:port]/path"
    if not isinstance(url, str) or not url or len(url) > MAX_URL:
        raise ValueError(msg)
    try:
        httpcheck.check_url(url)
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        raise ValueError(msg) from None
    host = (u.hostname or "").lower()
    if (u.scheme not in ("ws", "wss") or "@" in u.netloc or "#" in url or not _HOST_RE.match(host)
            or destguard.legacy_ip_form(host) or (port is not None and not 1 <= port <= 65535)
            or u.netloc.endswith(":")):
        raise ValueError(msg)
    if ";" in u.query:                      # some servers read ; as a parameter separator: no way to smuggle one in
        raise ValueError(msg)
    target = (u.path or "/") + (("?" + u.query) if u.query else "")
    if not _TARGET_RE.match(target):
        raise ValueError(msg)
    return u.scheme, host, port or (443 if u.scheme == "wss" else 80), target


def target_audit(sp):
    """What the human saw, for the operator-only audit events: the agent's path and query (clipped) and its hash.
    It holds nothing the credential adds (the secret is appended later, on the wire only)."""
    import hashlib as _h
    return {"target_clip": sp["target"][:200], "target_sha256": _h.sha256(sp["target"].encode()).hexdigest()[:16]}


def hostport(host, port):
    return f"{host}:{port}"


# ---------------------------------------------------------------- the session
class WsSession(S.Session):
    """A Session whose "calls" are the frames the agent sent and whose state is one connection. The receive
    queue is filled by ONE reader thread and drained by `take`. Everything that touches the queue is under
    `cond` (which shares the session lock)."""

    kind = "ws"

    def __init__(self, sid, pid, client, cred, hp, ttl_s, caps, opened, approver, clock, conn, values, deny_send=()):
        super().__init__(sid, pid, client, cred, [hp], [], ttl_s, caps["max_frames"], opened, "", approver, clock)
        self.clock, self.caps, self.conn = clock, caps, conn
        self.masker = masking.get_masker(values)
        self.masker_lc = masking.get_masker([v.lower() for v in values if isinstance(v, str)])
        self.hold = ""                  # raw text held back: a possible start of a secret that continues in the next message
        self.deny_send = frozenset(deny_send)
        self.recv_inflight = 0
        self.cond = threading.Condition(self.lock)
        self.queue, self.qbytes = deque(), 0
        self.seq = 0
        self.frames_out = self.bytes_out = 0
        self.msgs_in = 0
        self.truncated = False          # the queue was full and reading was paused since the agent last looked
        self.finished = None            # fixed label once the connection is over
        self.finished_at = None
        self.last_activity = opened
        self.tokens, self.tok_at = float(RATE_BURST), opened
        self.thread = None

    # -- reader ----------------------------------------------------------------------
    def start(self):
        self.thread = threading.Thread(target=self._loop, daemon=True, name="ws-reader")
        self.thread.start()

    def _full(self):
        return len(self.queue) >= self.caps["recv_queue_frames"] or self.qbytes >= self.caps["recv_queue_bytes"]

    def _finish(self, label):
        with self.cond:
            if self.finished is None:
                self.finished, self.finished_at = label, self.clock()
                if self.hold:                             # an unfinished possible secret: never delivered, only masked
                    self.hold = ""
                    self.seq += 1
                    self.queue.append(({"type": "text", "data": masking.MARK, "seq": self.seq}, 3))
                    self.qbytes += 3
            self.cond.notify_all()
        self.conn.t.close()

    def _stopped(self, mid=False):
        if self.dead or self.finished is not None:
            return True
        if mid:                         # a frame that has started must finish: enforced here, not only by the sweeper
            fs = self.conn.frame_started
            return fs is not None and self.clock() - fs >= FRAME_DEADLINE_S
        return False

    # -- masking what the server sent --------------------------------------------------------
    def _mask_plain(self, text):
        t = self.masker.mask(text)
        low = t.lower()
        if self.masker_lc.over_budget:
            return masking.MARK
        if len(low) == len(t) and self.masker_lc.forms:     # a differently-cased spelling of the secret
            spans = self.masker_lc._spans(low)
            if spans is None:
                return masking.MARK
            if spans:
                out, pos = [], 0
                for st, en in spans:
                    out += [t[pos:st], masking.MARK]
                    pos = en
                t = "".join(out) + t[pos:]
        return t

    def _mask_one(self, text):
        t = self._mask_plain(text)
        if "%" in t:                                          # a partly percent-encoded spelling
            d = urllib.parse.unquote(t)
            if d != t:
                d2 = self._mask_plain(d)
                if d2 != d:
                    return d2
        return t

    def _mask_message(self, text):
        """Mask one text message. A JSON object or array is parsed and every decoded string and key masked (this sees
        through mixed \\uXXXX escapes); when that changed anything the masked structure is re-serialised, else the
        text is kept exactly as the server sent it. The textual masker runs over the result in every case."""
        if text[:1] in ("{", "["):
            try:
                changed = []

                def walk(v, depth=0):
                    if depth > 64:
                        raise RecursionError
                    if isinstance(v, str):
                        n = self._mask_one(v)
                        if n != v:
                            changed.append(1)
                        return n
                    if isinstance(v, list):
                        return [walk(x, depth + 1) for x in v]
                    if isinstance(v, dict):
                        return {walk(k, depth + 1): walk(x, depth + 1) for k, x in v.items()}
                    return v
                obj = walk(json.loads(text))
                if changed:
                    return self._mask_one(json.dumps(obj, ensure_ascii=False))
            except (ValueError, RecursionError):
                pass
        return self._mask_one(text)

    def stream_mask(self, text):
        """Mask a message in the context of the ones before it, or None when all of it is held back. A server can
        split a secret across messages, so the end of the text that could still become the start of a secret (a
        proper prefix, 4+ characters, of any spelling) is HELD in `self.hold` and joined to the next message; it is
        flushed as a mask at the end of the connection. Sound for any number of pieces; costs only that a message
        that ends in the first 4+ characters of a secret waits for the next one (and, in that case, the two are
        delivered as one)."""
        raw = self.hold + text
        k = self.masker.tail_prefix_len(raw)
        if self.masker_lc.forms and len(raw) == len(raw.lower()):
            k = max(k, self.masker_lc.tail_prefix_len(raw.lower()))
        self.hold = raw[len(raw) - k:] if k else ""
        emit = raw[:len(raw) - k] if k else raw
        if k and not emit:
            return None
        return self._mask_message(emit)

    def _loop(self):
        conn = self.conn
        try:
            while True:
                with self.cond:
                    while not self._stopped() and self._full():
                        self.truncated = True            # backpressure: stop reading, drop nothing
                        self.cond.wait(wsproto.POLL_S)
                    if self._stopped():
                        return
                msg = conn.read_message(self._stopped)
                if msg is None:
                    return
                if msg[0] == "close":
                    try:
                        conn.write(wsproto.OP_CLOSE, b"" if msg[1] == 1005 else msg[1].to_bytes(2, "big"))
                    except wsproto.WsError:
                        pass
                    self._finish(wsproto.CLOSED)
                    return
                if msg[0] == "text":
                    text = self.stream_mask(msg[1])
                    if text is None:
                        continue                          # held back until the next message shows what it is
                    size = len(text.encode("utf-8", "replace"))
                    entry = {"type": "text", "data": text}
                else:
                    size, entry = 0, {"type": "binary", "bytes": msg[1]}
                with self.cond:
                    if self.dead:
                        return
                    self.seq += 1
                    entry["seq"] = self.seq
                    self.queue.append((entry, size))
                    self.qbytes += size
                    self.msgs_in += 1
                    self.last_activity = self.clock()
                    self.cond.notify_all()
        except wsproto.WsError as e:
            if e.code and e.label != wsproto.CLOSED:
                try:
                    conn.write(wsproto.OP_CLOSE, e.code.to_bytes(2, "big"))
                except wsproto.WsError:
                    pass
            self._finish(e.label)
        except Exception:  # noqa: BLE001 -- the reader must never die loudly; the label is fixed
            self._finish(wsproto.CONNECTION)

    # -- agent side ---------------------------------------------------------------------
    def allow(self, now):
        """The per-session operation rate limit (a token bucket on the session clock)."""
        with self.lock:
            self.tokens = min(float(RATE_BURST), self.tokens + max(0.0, now - self.tok_at) * RATE_PER_S)
            self.tok_at = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True

    def take(self, max_n, wait_s):
        """Wait up to wait_s (real seconds) for frames, then return up to max_n of them (and at most
        RECV_RESPONSE_BYTES of text, never fewer than one). -> dict for the agent."""
        end = time.monotonic() + max(0.0, wait_s)
        with self.cond:
            self.last_activity = self.clock()               # an agent that is polling is using the session
            while not self.queue and self.finished is None and not self.dead:
                left = end - time.monotonic()
                if left <= 0 or self.clock() >= self.expires:
                    break
                self.cond.wait(min(left, wsproto.POLL_S))
            if self.dead or self.clock() >= self.expires:
                return None                                 # past the deadline nothing more is handed out
            frames, total = [], 0
            while self.queue and len(frames) < max_n:
                entry, size = self.queue[0]
                if frames and total + size > RECV_RESPONSE_BYTES:
                    break
                self.queue.popleft()
                self.qbytes -= size
                total += size
                frames.append(entry)
            truncated, self.truncated = self.truncated, False
            self.cond.notify_all()              # the reader may resume
            return {"frames": frames, "queued": len(self.queue), "truncated": truncated,
                    "closed": self.finished is not None and not self.queue, "close_reason": self.finished}

    def sweep_reason(self, now):
        """The end reason the sweeper should apply now, or None."""
        with self.lock:
            if self.finished is not None:
                if not self.queue or now - (self.finished_at or now) >= DRAIN_GRACE_S:
                    return "peer_closed" if self.finished == wsproto.CLOSED else "ws_error"
                return None
            fs = self.conn.frame_started
            if fs is not None and now - fs >= FRAME_DEADLINE_S:
                return "ws_error"
            if now - self.last_activity >= self.caps["idle_s"]:
                return "idle"
        return None

    def drop(self, reason="expired"):
        super().drop(reason)
        try:
            self.conn.t.close(self.conn.close_frame(1000 if reason in ("closed", "expired", "idle") else 1008))
        except Exception:  # noqa: BLE001
            pass
        with self.cond:
            self.queue.clear()
            self.qbytes = 0
            self.cond.notify_all()


# ---------------------------------------------------------------- html
def describe_html(req):
    """(what_html, note_html) for the card header. Every value is validated text, escaped anyway; nothing
    the agent wrote is shown as anything but a labelled, escaped path."""
    sp, e = req.spec, html.escape
    plain = sp["scheme"] == "ws"
    pill = (" <span class='pill warn'>plain ws: not encrypted</span>" if plain else "")
    what = (f"<b>WebSocket session</b> with credential <b>{e(req.names[0])}</b>{pill}<br>"
            f"Server: {e(sp['scheme'])}://{e(sp['host'])}:{sp['port']}<br>"
            f"Path and query, as the agent wrote them (unverified): <code>{e(sp['target'])}</code><br>"
            f"Sign-in, set by the operator on this credential: {e(sp.get('signin', ''))}<br>"
            f"Message types blocked by the operator: {sp.get('deny_n', 0)}<br>"
            f"Time limit: {e(S._fmt_ttl(sp['ttl_s']))} from the moment you approve (fixed, never extended)<br>"
            f"Caps: {sp['max_calls']} frames and {sp['max_bytes'] // 1024} KB in each direction, "
            f"one message at most {sp['max_frame_bytes'] // 1024} KB, closed after {sp['idle_s']} s idle<br>"
            "The broker signs in with the credential; the agent never sees it. Text the server sends back is "
            "masked if it contains the credential; binary frames are never shown to the agent.")
    return what, WARNING


def actions_html(broker, req):
    sp = req.spec
    return (
        "<div class=sesbox><small class=muted>You may shorten these; you cannot lengthen them.</small><br>"
        f"<label>Minutes <input type=number name=session_ttl_min step=any min=0.5 "
        f"max='{sp['ttl_s'] / 60:g}' value='{sp['ttl_s'] / 60:g}'></label>"
        f"<label>Max frames <input type=number name=session_max_calls step=1 min=1 "
        f"max='{sp['max_calls']}' value='{sp['max_calls']}'></label></div>"
        "<div class=decide-row><button class='btn approve' name=decision value=approve>Approve session</button>"
        "<button class='btn deny' name=decision value=deny>Deny</button></div>"
        "<p class=scope><small class=muted>Always needs you: no standing approval, grant or Always "
        "covers a session, and no notification button can approve it. Revoke it any time on the "
        "Clients tab.</small></p>")


# ---------------------------------------------------------------- broker mixin
class WsMixin:
    """Methods mixed into Broker (after SessionsMixin). Needs the session machinery, dest_guard, cfg,
    audit/log, _read_env, _tls_policy, _dest_entries, allowed_entries, clients."""

    def _init_ws(self, config):
        self.ws_cfg = parse_config(config.get("ws_sessions"))
        self.ws_ssl_context = self._default_ws_ssl_context      # a test may replace it

    @staticmethod
    def _default_ws_ssl_context(tls):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if tls and (not tls.get("verify", True) or tls.get("fingerprint")):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- validating the open request -----------------------------------------------------
    def _validate_ws_session(self, names, spec, client):
        cfg = self.ws_cfg
        if not cfg["enabled"]:
            raise PermissionError("websocket sessions are disabled")
        if len(names) != 1 or not isinstance(names[0], str):
            raise ValueError("a session uses exactly one credential")
        sc = self.cfg["secrets"].get(names[0])
        if sc is None or self._internal_hit(names):
            if not self._backend_ok:
                raise ValueError("unknown secret name, but the credential backend is not healthy "
                                 "(ask the operator to check `asb status`)")
            raise ValueError("unknown secret name")
        if sc.get("ssh") or not sc.get("allowed_hosts"):
            raise PermissionError("a WebSocket session needs an http credential with allowed hosts")
        if sc.get("_ws") is None:
            raise PermissionError("this credential is not set up for WebSocket sessions (the operator "
                                  "adds a `ws` setting to it)")
        if any(k in spec for k in ("purpose", "hosts", "methods")) and any(spec.get(k) for k in ("purpose", "hosts", "methods")):
            raise ValueError("a WebSocket session takes a url, --ttl and --max-frames only")
        scheme, host, port, target = parse_url(spec.get("url"))
        entries = self.allowed_entries(names[0])
        if (host not in destguard.host_parts(sc["allowed_hosts"]) or self.dest_guard.host_refused(host)
                or not self.dest_guard.port_ok(entries, host, port)):
            raise PermissionError("that host or port is outside this credential's allowed hosts "
                                  "(see `asb list`)")
        reserved = {_qkey(k) for k in sc["_ws"]["query"]}
        if reserved and any(_qkey(part.partition("=")[0]) in reserved for part in target.partition("?")[2].split("&")):
            raise ValueError("a query parameter in that url is set by the credential")
        ttl = spec.get("ttl_s", cfg["default_ttl_s"])
        if not S._int(ttl) or ttl < S.TTL_FLOOR:
            raise ValueError(f"the time limit must be at least {S.TTL_FLOOR} seconds")
        if ttl > cfg["max_ttl_s"]:
            raise ValueError(f"the time limit is at most {S._fmt_ttl(cfg['max_ttl_s'])} on this broker")
        frames = spec.get("max_frames", cfg["max_frames"])
        if not S._int(frames) or not 1 <= frames <= cfg["max_frames"]:
            raise ValueError(f"max frames must be a whole number from 1 to {cfg['max_frames']}")
        cid = client["id"]
        if self._ws_count(cid) >= cfg["max_per_client"]:
            raise PermissionError("too many open WebSocket sessions")
        spec.clear()
        spec.update({"kind": "ws", "scheme": scheme, "host": host, "port": port, "target": target,
                     "hosts": [hostport(host, port)], "methods": [], "ttl_s": ttl, "max_calls": frames,
                     "purpose": "", "max_bytes": cfg["max_bytes"], "max_frame_bytes": cfg["max_frame_bytes"],
                     "idle_s": cfg["idle_s"], "signin": signin_summary(sc["_ws"]),
                     "deny_n": len(sc["_ws"]["deny_send"])})

    def _ws_count(self, cid):
        self.sweep_sessions()
        with self._sess_lock:
            return sum(isinstance(s, WsSession) and s.cid == cid for s in self._sess.values())

    # -- opening (the human approved) -----------------------------------------------------
    def _ws_open(self, req, who):
        """Connect, authenticate, register. Returns the result handed to the agent once. A failure is
        a SessionOpenError with a fixed text; the request settles as failed."""
        sp, cid, now = req.spec, req.client["id"], self.sessions_clock()
        ttl, frames = sp["final"]
        name = req.names[0]
        if not self.clients.is_active(cid):
            raise S.SessionOpenError("this client was revoked")
        sc = self.cfg["secrets"].get(name)
        if sc is None or sc.get("ssh") or not sc.get("allowed_hosts") or sc.get("_ws") is None or self._internal_hit([name]):
            raise S.SessionOpenError("the credential is no longer available for WebSocket sessions")
        host, port = sp["host"], sp["port"]
        entries = self.allowed_entries(name)
        if (host not in destguard.host_parts(sc["allowed_hosts"]) or self.dest_guard.host_refused(host)
                or not self.dest_guard.port_ok(entries, host, port)):
            raise S.SessionOpenError("the host is no longer allowed for this credential")
        if self._ws_count(cid) >= self.ws_cfg["max_per_client"]:
            raise S.SessionOpenError("too many open sessions")
        env = self._read_env(req)                           # audited secret_read; the values stay in this function
        wsc = sc["_ws"]
        var_names = list(env)
        values = {k: masking.strip_one_newline(v) for k, v in env.items()}
        if len(var_names) == 1:
            values["VAR"] = values[var_names[0]]
        tls = self._tls_policy([name])
        cfg = self.ws_cfg
        caps = {"max_frames": frames, "max_bytes": sp["max_bytes"], "max_frame": sp["max_frame_bytes"],
                "idle_s": sp["idle_s"], "recv_queue_frames": cfg["recv_queue_frames"],
                "recv_queue_bytes": cfg["recv_queue_bytes"]}
        sock = None
        try:
            sock = self.dest_guard.connect(host, port, timeout=CONNECT_S, entries=self._dest_entries([name]))
            if sp["scheme"] == "wss":
                ctx = self.ws_ssl_context(tls)
                sock = ctx.wrap_socket(sock, server_hostname=host)      # certificate and name verified for the ORIGINAL host
                pins = tls.get("fingerprint")
                if pins:
                    pins = (pins,) if isinstance(pins, str) else tuple(pins)
                    der = sock.getpeercert(binary_form=True)
                    if not der or hashlib.sha256(der).hexdigest() not in pins:
                        raise ssl.SSLError("pin")
            t = wsproto.Transport(sock)
            hh = host if port == (443 if sp["scheme"] == "wss" else 80) else f"{host}:{port}"
            target, origin, protos, extra = upgrade_parts(wsc, sp["target"], values)
            leftover, _ = wsproto.handshake(t, hh, target, origin, protos, HANDSHAKE_S,
                                            egress=(destguard.EGRESS_MARKER, "1"), extra_headers=extra)
            conn = wsproto.Conn(t, leftover, caps["max_frame"], frames + IN_FRAMES_SLACK, caps["max_bytes"] + IN_BYTES_SLACK,
                                clock=lambda: self.sessions_clock())
            if wsc["steps"]:
                run_handshake(conn, wsc["steps"], values)
        except Exception as e:  # noqa: BLE001 -- class only: the text can hold peer bytes or a filled value
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            label = e.label if isinstance(e, wsproto.WsError) else errclass.classify(e)
            if label == errclass.DENIED:
                label = errclass.CONNECTION         # the agent never learns a guard refusal
            self._log_refusal("c:" + cid, session=None, reason_class="open_" + label.replace(" ", "_"), client_id=cid,
                              client_name=req.client["name"], host=host[:S.MAX_HOST_LOG], _event="ws_session_refused")
            raise S.SessionOpenError("could not connect (" + label + ")") from None
        with self._sess_lock:
            mine = sum(isinstance(s, WsSession) and s.cid == cid for s in self._sess.values())
            if mine >= cfg["max_per_client"] or len(self._sess) >= S.MAX_TOTAL:
                conn.t.close()
                raise S.SessionOpenError("too many open sessions")
            sid = secrets.token_urlsafe(24)
            while any(s.pid == sid[:8] for s in self._sess.values()):
                sid = secrets.token_urlsafe(24)
            s = WsSession(sid, sid[:8], req.client, name, hostport(host, port), ttl, caps, now, who.get("approver"),
                          lambda: self.sessions_clock(), conn,
                          list(env.values()) + list(self.dest_guard.mask_values), wsc["deny_send"])
            self._sess[self._skey(sid)] = s
        s.start()
        self.audit("ws_session_opened", req, session=s.pid, host=hostport(host, port), ttl_s=ttl, max_frames=frames,
                   max_bytes=caps["max_bytes"], max_frame_bytes=caps["max_frame"], idle_s=caps["idle_s"],
                   tls=sp["scheme"] == "wss", handshake=bool(wsc["steps"]), signin=signin_summary(wsc),
                   **target_audit(sp), expires_at=int(clock_mod.now() + ttl),
                   shortened=(ttl, frames) != (sp["ttl_s"], sp["max_calls"]))
        return {"session": {"id": sid, "kind": "ws", "expires_in": ttl, "hosts": [hostport(host, port)], "methods": [],
                            "max_calls": frames, "max_frames": frames, "max_bytes": caps["max_bytes"],
                            "max_frame_bytes": caps["max_frame"], "idle_s": caps["idle_s"]}}

    # -- using ------------------------------------------------------------------------
    def _ws_scope_ok(self, s):
        """Is this session still inside what its credential allows NOW? The same checks as at open, repeated on every
        use and by the sweeper (so a narrowed, removed or retyped credential ends the session). Takes no session lock."""
        try:
            sc = self.cfg["secrets"].get(s.cred)
            if (sc is None or self._internal_hit([s.cred]) or sc.get("ssh") or not sc.get("allowed_hosts")
                    or sc.get("_ws") is None or not self.clients.is_active(s.cid)):
                return False
            host, _, port = s.hosts[0].rpartition(":")
            port = int(port)
            return (host in destguard.host_parts(sc["allowed_hosts"]) and not self.dest_guard.host_refused(host)
                    and self.dest_guard.port_ok(self.allowed_entries(s.cred), host, port))
        except Exception:  # noqa: BLE001 -- fail closed
            return False

    def _ws_get(self, sid, client):
        """The live WsSession for this client, or raises the fixed error. Another client's session, a made-up
        id, an HTTP session's id and a revoked client's are all the same answer."""
        cid = client["id"]
        active = self.clients.is_active(cid)
        with self._sess_lock:
            s, state = self._sess_lookup(sid, cid, self.sessions_clock())
        if s is not None and (not isinstance(s, WsSession) or self._internal_hit([s.cred])):
            s, state = None, "unknown"
        if s is None or not active:
            state = state if active else "unknown"
            if state not in S.ENDED:
                state = "unknown"
            msg, code, http = S.ENDED[state]
            self._log_refusal("c:" + cid, session=None, reason_class=state, client_id=cid, client_name=client["name"],
                              _event="ws_session_refused")
            raise S.SessionError(msg, code, http)
        if not self._ws_scope_ok(s):
            with self._sess_lock:
                if not s.dead:
                    self._sess_end_locked(s, "revoked", self.sessions_clock(), actor="scope_recheck")
            raise S.SessionError(*S.ENDED["revoked"])
        if not s.allow(self.sessions_clock()):
            self._refuse(client, s, "rate", "too many requests; slow down", http=429, _event="ws_session_refused")
        return s

    def _ws_end_if_over(self, s):
        """End the session now when the connection is over and nothing is left to read (audited once)."""
        r = s.sweep_reason(self.sessions_clock())
        if r:
            with self._sess_lock:
                if not s.dead:
                    self._sess_end_locked(s, r, self.sessions_clock())

    def ws_send(self, sid, text, client):
        if not self.ws_cfg["enabled"]:
            raise PermissionError("websocket sessions are disabled")
        s = self._ws_get(sid, client)
        if not isinstance(text, str):
            raise ValueError("a frame is text")
        data = text.encode("utf-8", "strict")
        if len(data) > s.caps["max_frame"]:
            self._refuse(client, s, "frame_size", f"a frame is limited to {s.caps['max_frame'] // 1024} KB",
                         _event="ws_session_refused")
        if s.deny_send and text[:1] in ("{", "[", " ", "\t", "\r", "\n"):
            try:
                obj = json.loads(text)
            except (ValueError, RecursionError):
                obj = None
            for item in (obj if isinstance(obj, list) else [obj]):
                if isinstance(item, dict) and isinstance(item.get("type"), str) and item["type"] in s.deny_send:
                    self._refuse(client, s, "denied_type", "that message type is blocked for this credential",
                                 _event="ws_session_refused")
        with s.lock:
            if s.dead:
                raise S.SessionError(*S.ENDED[s.end_reason if s.end_reason in S.ENDED else "unknown"])
            over = ("frames" if s.frames_out >= s.max_calls else
                    "bytes" if s.bytes_out + len(data) > s.caps["max_bytes"] else None)
            fin = s.finished
            if over is None and fin is None:
                s.frames_out += 1
                s.calls = s.frames_out
                s.bytes_out += len(data)
                s.last_activity = self.sessions_clock()
        if fin is not None:
            self._ws_end_if_over(s)
            raise S.SessionError(*S.ENDED["peer_closed" if fin == wsproto.CLOSED else "ws_error"])
        if over:
            self._refuse(client, s, over + "_cap", f"this session used its {over} allowance for sending; "
                         "open a new one", _event="ws_session_refused")
        try:
            s.conn.write(wsproto.OP_TEXT, data)
        except wsproto.WsError as e:
            s._finish(e.label)
            with s.lock:                            # closed under us by a revoke, close or deadline: say that
                if s.dead:
                    raise S.SessionError(*S.ENDED[s.end_reason if s.end_reason in S.ENDED else "unknown"]) from None
            raise S.SessionError(*S.ENDED["ws_error"]) from None
        with s.lock:
            if s.dead:
                raise S.SessionError(*S.ENDED[s.end_reason if s.end_reason in S.ENDED else "unknown"])
            left_f, left_s = s.max_calls - s.frames_out, max(0, int(s.expires - self.sessions_clock()))
        return {"sent": True, "frames_left": left_f, "expires_in": left_s}

    def ws_recv(self, sid, client, wait=0.0, max_n=RECV_MAX_FRAMES):
        if not self.ws_cfg["enabled"]:
            raise PermissionError("websocket sessions are disabled")
        s = self._ws_get(sid, client)
        try:
            wait = float(wait)
        except (OverflowError, ValueError, TypeError):
            wait = RECV_WAIT_MAX
        wait = min(max(wait if wait == wait else 0.0, 0.0), RECV_WAIT_MAX)
        max_n = min(max(int(max_n), 1), RECV_MAX_FRAMES)
        with s.lock:
            busy = s.recv_inflight >= MAX_RECV_INFLIGHT
            if not busy:
                s.recv_inflight += 1
        if busy:                                    # one agent cannot park many handler threads
            self._refuse(client, s, "concurrency", "too many recv calls at once", http=429, _event="ws_session_refused")
        try:
            out = s.take(max_n, wait)
        finally:
            with s.lock:
                s.recv_inflight -= 1
        if out is None or s.dead:
            with self._sess_lock:
                _, state = self._sess_lookup(sid, client["id"], self.sessions_clock())
            raise S.SessionError(*S.ENDED[state if state in S.ENDED and state != "unknown" else "revoked"])
        if self.sessions_clock() >= s.expires:
            self.sweep_sessions()
        out["expires_in"] = max(0, int(s.expires - self.sessions_clock()))
        out["frames_left"] = max(0, s.max_calls - s.frames_out)
        if out["closed"]:
            self._ws_end_if_over(s)
        return out

    # -- accounting hooks used by sessions.py ---------------------------------------------
    @staticmethod
    def _ws_end_fields(s):
        return {"frames_in": s.conn.frames_in, "frames_out": s.frames_out, "bytes_in": s.conn.bytes_in,
                "bytes_out": s.bytes_out, "messages_in": s.msgs_in, "close_reason": s.finished,
                "host": s.hosts[0]}
