"""A minimal RFC 6455 WebSocket CLIENT over a connected socket (stdlib only), for WebSocket sessions.

What it does and, deliberately, does not do:
  * the opening handshake is one fixed request (no agent-chosen header, no cookie, no extension, no
    compression offered); the answer must be exactly `101` with a matching `Sec-WebSocket-Accept`
    (SHA-1 of our random key + the RFC GUID, compared in constant time), `Upgrade: websocket` and
    `Connection: Upgrade`. Anything else (a redirect, a 200, a missing or wrong Accept, an extension the
    server chose although none was offered, a subprotocol nobody offered, an obs-fold or duplicate
    security header) fails the connection. Nothing is retried and no redirect is followed;
  * every frame we send is masked with a fresh random key; every frame we receive must be unmasked, have
    no reserved bit set, use a defined opcode and the shortest length encoding; control frames are
    at most 125 bytes and never fragmented; a data message may be fragmented, with a bounded number of
    fragments and a bounded total size; text must be valid UTF-8;
  * limits (frame/message size, frames, bytes) are checked from the frame HEADER, before the payload
    is read, so a huge announced length costs nothing;
  * pings are answered with a pong (bounded: the frame cap counts every frame); a close frame is
    answered and ends the connection;
  * a frame that has started must finish within the caller's frame deadline (`frame_started` is
    published so a sweeper can enforce it: a slow-drip peer cannot hold a connection forever);
  * every failure is a WsError carrying a FIXED label (never exception text, never peer bytes).
"""
import base64
import hashlib
import hmac
import os
import re
import select
import socket
import ssl
import threading
import time

from .useragent import USER_AGENT

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0, 1, 2, 8, 9, 10
HEAD_LIMIT = 16384              # response header block
MAX_FRAGMENTS = 256             # wire frames in one data message
POLL_S = 0.5
_OWNED = frozenset(("host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version",
                    "sec-websocket-extensions", "sec-websocket-accept", "sec-websocket-protocol", "origin",
                    "content-length", "transfer-encoding", "cookie"))

# fixed failure labels
HANDSHAKE, PROTOCOL, TOO_LARGE, LIMIT, TIMEOUT, CONNECTION, CLOSED = (
    "handshake refused", "protocol error", "frame too large", "limit reached", "timeout", "connection error",
    "closed")


class WsError(Exception):
    """A failed connection. `label` is one of the fixed texts above; `code` the close code to send (or None)."""

    def __init__(self, label, code=None):
        super().__init__(label)
        self.label, self.code = label, code


def valid_close_code(c):
    return c in (1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011) or 3000 <= c <= 4999


def _mask(data, key):
    n = len(data)
    if not n:
        return b""
    pad = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(pad, "big")).to_bytes(n, "big")


class Transport:
    """A socket that two threads (a reader and the writers) may use: every operation that touches the
    socket's state takes one lock, each for a short bounded time (needed for TLS, whose object is not
    safe for a concurrent read and write)."""

    def __init__(self, sock):
        self.sock = sock
        self.lock = threading.Lock()
        self.is_ssl = isinstance(sock, ssl.SSLSocket)
        self.closed = False

    def recv(self, n, wait=POLL_S):
        """Up to n bytes; b"" at end of stream; None when nothing arrived within `wait`."""
        if self.closed:
            raise OSError("closed")
        try:
            pending = False
            if self.is_ssl:
                with self.lock:                     # (the TLS object is not safe for SSL_pending beside an SSL_write)
                    pending = bool(self.sock.pending())
            if not pending:
                p = select.poll()                   # (not select(): a descriptor number above 1023 would break it)
                p.register(self.sock, select.POLLIN)
                if not p.poll(int(wait * 1000)):
                    return None
            with self.lock:
                self.sock.settimeout(POLL_S)
                return self.sock.recv(n)
        except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
            return None
        except ValueError:                  # select on a socket closed meanwhile
            raise OSError("closed") from None

    def sendall(self, data, timeout):
        if self.closed:
            raise OSError("closed")
        with self.lock:
            if self.closed:                 # closed while we waited for the lock: nothing may go out now
                raise OSError("closed")
            self.sock.settimeout(timeout)
            self.sock.sendall(data)

    def close(self, last=None):
        """Immediate and bounded: an optional last frame is tried only when the lock is free right now
        and only for a fraction of a second; then the socket is shut down and closed."""
        if self.closed:
            return
        self.closed = True
        if last and self.lock.acquire(blocking=False):
            try:
                self.sock.settimeout(0.2)
                self.sock.sendall(last)
            except (OSError, ValueError):
                pass
            finally:
                self.lock.release()
        # socket.socket.shutdown, not SSLSocket.shutdown: the latter drops the TLS object first, and a send racing
        # it could then go out in clear text
        for fn in (lambda: socket.socket.shutdown(self.sock, socket.SHUT_RDWR), self.sock.close):
            try:
                fn()
            except (OSError, ValueError):
                pass


def accept_key(key_b64):
    return base64.b64encode(hashlib.sha1(key_b64 + GUID).digest())


def handshake(t, host_header, target, origin=None, subprotocols=(), deadline_s=10.0, egress=None, extra_headers=()):
    """Perform the opening handshake on `t`. Returns (leftover bytes read past the header block, subprotocol or
    None). `target` and `host_header` are validated by the caller (printable ASCII, no CR/LF); they are
    checked again here and anything unusual raises WsError (fail closed)."""
    for v in (host_header, target, origin or "", *subprotocols, *[x for kv in extra_headers for x in kv]):
        if not isinstance(v, str) or not v.isascii() or any(c in v for c in "\r\n\x00") or any(ord(c) < 32 for c in v):
            raise WsError(HANDSHAKE)
    if not target.startswith("/") or " " in target:
        raise WsError(HANDSHAKE)
    key = base64.b64encode(os.urandom(16))
    lines = [f"GET {target} HTTP/1.1", f"Host: {host_header}", "Upgrade: websocket", "Connection: Upgrade",
             "Sec-WebSocket-Key: " + key.decode(), "Sec-WebSocket-Version: 13"]
    if origin:
        lines.append("Origin: " + origin)
    if not any(k.lower() == "user-agent" for k, _ in extra_headers):
        lines.append("User-Agent: " + USER_AGENT)          # a default only: configured headers win
    if subprotocols:
        lines.append("Sec-WebSocket-Protocol: " + ", ".join(subprotocols))
    for k, v in extra_headers:
        if not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,63}\Z", k) or k.lower() in _OWNED or not v.strip():
            raise WsError(HANDSHAKE)                # the broker owns these; config may not set them
        lines.append(f"{k}: {v}")
    if egress:
        lines.append(f"{egress[0]}: {egress[1]}")
    try:
        t.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"), deadline_s)
    except socket.timeout:
        raise WsError(TIMEOUT) from None
    except OSError:
        raise WsError(CONNECTION) from None
    end = time.monotonic() + deadline_s
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > HEAD_LIMIT:
            raise WsError(HANDSHAKE)
        if time.monotonic() > end:
            raise WsError(TIMEOUT)
        try:
            chunk = t.recv(4096, 0.2)
        except OSError:
            raise WsError(CONNECTION) from None
        if chunk == b"":
            raise WsError(HANDSHAKE)
        if chunk:
            buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if len(head) > HEAD_LIMIT:
        raise WsError(HANDSHAKE)
    rows = head.split(b"\r\n")
    status = rows[0]
    if not (status == b"HTTP/1.1 101" or status.startswith(b"HTTP/1.1 101 ")):
        raise WsError(HANDSHAKE)                            # a redirect, an error page, anything but 101
    hdr = {}
    for row in rows[1:]:
        name, sep, value = row.partition(b":")
        if not sep or not name or name != name.strip() or row[:1] in (b" ", b"\t"):
            raise WsError(HANDSHAKE)                        # obs-fold, a space before the colon, no colon
        try:
            n, v = name.decode("ascii").lower(), value.decode("latin-1").strip()
        except UnicodeDecodeError:
            raise WsError(HANDSHAKE) from None
        if n in hdr and n in ("upgrade", "connection", "sec-websocket-accept", "sec-websocket-protocol",
                              "sec-websocket-extensions", "sec-websocket-version"):
            raise WsError(HANDSHAKE)                        # a duplicated security header
        hdr[n] = v
    if hdr.get("upgrade", "").lower() != "websocket":
        raise WsError(HANDSHAKE)
    if "upgrade" not in [x.strip().lower() for x in hdr.get("connection", "").split(",")]:
        raise WsError(HANDSHAKE)
    got = hdr.get("sec-websocket-accept", "").encode("ascii", "replace")
    if not hmac.compare_digest(got, accept_key(key)):
        raise WsError(HANDSHAKE)
    if "sec-websocket-extensions" in hdr:                   # none was offered: the server may not pick one
        raise WsError(HANDSHAKE)
    proto = hdr.get("sec-websocket-protocol")
    if proto is not None and proto not in subprotocols:
        raise WsError(HANDSHAKE)
    return rest, proto


class Conn:
    """The framing layer of one established connection. `limits`: max_frame (bytes in one message),
    max_frames and max_bytes (received, every wire frame counted). `clock` is the session clock
    (monotonic), used only to stamp `frame_started`."""

    def __init__(self, t, leftover=b"", max_frame=1 << 20, max_frames=1000, max_bytes=8 << 20,
                 send_timeout=10.0, clock=time.monotonic):
        self.t, self.buf = t, bytearray(leftover)
        self.max_frame, self.max_frames, self.max_bytes = max_frame, max_frames, max_bytes
        self.send_timeout, self.clock = send_timeout, clock
        self.frames_in = self.bytes_in = 0
        self.frame_started = None
        self.msg_started = None         # when the first fragment of the message being assembled arrived
        self._last_start = None
        self.sent_close = False

    # -- reading ------------------------------------------------------------------
    def _fill(self, n, stop):
        """Wait until the buffer holds n bytes. False when stop() says to give up; WsError on EOF or a broken socket."""
        while len(self.buf) < n:
            if stop():
                return False
            try:
                chunk = self.t.recv(65536)
            except OSError:
                raise WsError(CONNECTION) from None
            if chunk == b"":
                raise WsError(CLOSED)
            if chunk:
                self.buf += chunk
        return True

    def _take(self, n):
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_frame(self, stop):
        """(fin, opcode, payload) of the next wire frame, or None when stop() became true while waiting
        for the START of a frame. `stop(mid_frame=False)`: once a frame has started, a true stop() ends the
        connection (WsError). Once a frame has started it is read to the end."""
        if not self._fill(1, stop):
            return None
        self.frame_started = self._last_start = self.clock()
        try:
            if not self._fill(2, lambda: stop(True)):
                raise WsError(TIMEOUT)
            b0, b1 = self.buf[0], self.buf[1]
            fin, rsv, op = b0 & 0x80, b0 & 0x70, b0 & 0x0F
            if rsv or op not in (0, 1, 2, 8, 9, 10) or (b1 & 0x80):
                raise WsError(PROTOCOL, 1002)           # reserved bit, undefined opcode, or a masked server frame
            ln, hl = b1 & 0x7F, 2
            if ln == 126:
                if not self._fill(4, lambda: stop(True)):
                    raise WsError(TIMEOUT)
                ln, hl = int.from_bytes(self.buf[2:4], "big"), 4
                if ln < 126:
                    raise WsError(PROTOCOL, 1002)       # not the shortest encoding
            elif ln == 127:
                if not self._fill(10, lambda: stop(True)):
                    raise WsError(TIMEOUT)
                ln, hl = int.from_bytes(self.buf[2:10], "big"), 10
                if ln < 65536 or ln >> 63:
                    raise WsError(PROTOCOL, 1002)
            if op >= 8 and (ln > 125 or not fin):
                raise WsError(PROTOCOL, 1002)
            self.frames_in += 1
            if self.frames_in > self.max_frames:
                raise WsError(LIMIT, 1008)
            if op < 8 and ln > self.max_frame:      # (a control frame is at most 125 bytes whatever a step's size limit)
                raise WsError(TOO_LARGE, 1009)          # decided from the header: the payload is never read
            if self.bytes_in + ln > self.max_bytes:
                raise WsError(LIMIT, 1008)
            if not self._fill(hl + ln, lambda: stop(True)):
                raise WsError(TIMEOUT)
            self._take(hl)
            payload = self._take(ln)
            self.bytes_in += ln
            return bool(fin), op, payload
        finally:
            self.frame_started = None

    def read_message(self, stop):
        """The next complete message: ("text", str) | ("binary", length) | ("close", code) | None (stopped while idle).
        Pings are answered here; pongs are dropped. Raises WsError (fixed label, `.code` = close code to send)."""
        try:
            return self._read_message(stop)
        finally:
            self.msg_started = None

    def _read_message(self, stop):
        kind, parts, size, frags = None, [], 0, 0
        while True:
            fr = self.read_frame(stop)
            if fr is None:
                return None
            fin, op, payload = fr
            if op == OP_PING:
                self.write(OP_PONG, payload)
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                if len(payload) == 1:
                    raise WsError(PROTOCOL, 1002)
                code = int.from_bytes(payload[:2], "big") if payload else 1005
                if payload:
                    if not valid_close_code(code):
                        raise WsError(PROTOCOL, 1002)
                    try:
                        payload[2:].decode("utf-8")
                    except UnicodeDecodeError:
                        raise WsError(PROTOCOL, 1007) from None
                return ("close", code)
            if op in (OP_TEXT, OP_BIN):
                if kind is not None:
                    raise WsError(PROTOCOL, 1002)       # a new message in the middle of a fragmented one
                kind = op
            elif kind is None:
                raise WsError(PROTOCOL, 1002)           # a continuation with nothing to continue
            frags += 1
            if frags == 1 and not fin:
                self.msg_started = self._last_start
            size += len(payload)
            if frags > MAX_FRAGMENTS:
                raise WsError(LIMIT, 1008)
            if size > self.max_frame:
                raise WsError(TOO_LARGE, 1009)
            if kind == OP_TEXT:
                parts.append(payload)
            if fin:
                if kind == OP_BIN:
                    return ("binary", size)
                try:
                    return ("text", b"".join(parts).decode("utf-8"))
                except UnicodeDecodeError:
                    raise WsError(PROTOCOL, 1007) from None

    # -- writing ------------------------------------------------------------------
    def write(self, op, payload=b""):
        if self.sent_close and op != OP_CLOSE:
            raise WsError(CLOSED)                   # nothing but (another) close after our close frame
        if op == OP_CLOSE:
            self.sent_close = True
        if len(payload) > (125 if op >= 8 else self.max_frame):
            raise WsError(TOO_LARGE)
        n = len(payload)
        head = bytes([0x80 | op])
        key = os.urandom(4)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        try:
            self.t.sendall(head + key + _mask(payload, key), self.send_timeout)
        except socket.timeout:
            raise WsError(TIMEOUT) from None
        except OSError:
            raise WsError(CONNECTION) from None

    def close_frame(self, code=1000):
        """The bytes of a close frame (for Transport.close's best-effort last write)."""
        self.sent_close = True
        payload = code.to_bytes(2, "big")
        key = os.urandom(4)
        return bytes([0x88, 0x80 | len(payload)]) + key + _mask(payload, key)
