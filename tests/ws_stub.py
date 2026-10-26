"""Test-only: a local WebSocket server (stdlib) that plays an upstream such as Home Assistant.

It records everything the broker sent (the handshake request, every frame, whether each was masked), can
misbehave on demand (`mode`), and obeys a few text commands so a test can make it speak:
    BIN            send a binary frame            FRAG        send "ab" + "cd" as one fragmented text message
    PING           send a ping (the broker must pong)        ECHO:x   reply with x         CLOSE   close politely
    TOKEN          reply with the token it was given          BIG:n   send one text frame of n bytes
    FLOOD:n        send n text frames "f0".."f{n-1}"          STALL   send half a frame header, then go quiet
    DROP           close the TCP connection without a close frame
Everything else is echoed back as {"echo": <text>}. Port 0 only; no sleeps: tests wait on events.
"""
import base64
import hashlib
import json
import socket
import socketserver
import ssl
import threading

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_of(key):
    return base64.b64encode(hashlib.sha1(key + GUID).digest())


def frame(op, payload=b"", fin=True, mask=False):
    b = bytes([(0x80 if fin else 0) | op])
    n = len(payload)
    m = 0x80 if mask else 0
    if n < 126:
        b += bytes([m | n])
    elif n < 65536:
        b += bytes([m | 126]) + n.to_bytes(2, "big")
    else:
        b += bytes([m | 127]) + n.to_bytes(8, "big")
    return b + payload


class Conn:
    def __init__(self, sock, stub):
        self.sock, self.stub, self.buf = sock, stub, b""

    def read_exact(self, n):
        while len(self.buf) < n:
            c = self.sock.recv(65536)
            if not c:
                raise EOFError
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_head(self):
        while b"\r\n\r\n" not in self.buf:
            c = self.sock.recv(65536)
            if not c:
                raise EOFError
            self.buf += c
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        return head

    def recv_frame(self):
        b0, b1 = self.read_exact(2)
        ln = b1 & 0x7F
        if ln == 126:
            ln = int.from_bytes(self.read_exact(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self.read_exact(8), "big")
        masked = bool(b1 & 0x80)
        key = self.read_exact(4) if masked else b""
        data = self.read_exact(ln)
        if masked:
            data = bytes(c ^ key[i % 4] for i, c in enumerate(data))
        else:
            self.stub.violations.append("unmasked client frame")
        if b0 & 0x70:
            self.stub.violations.append("reserved bit set")
        return bool(b0 & 0x80), b0 & 0x0F, data

    def send(self, raw):
        self.sock.sendall(raw)

    def send_frame(self, op, payload=b"", fin=True):
        self.sock.sendall(frame(op, payload, fin))

    def send_text(self, text):
        self.send_frame(1, text.encode())

    def send_json(self, obj):
        self.send_text(json.dumps(obj))


class WsStub:
    """`auth`: play Home Assistant's handshake (auth_required, wait for auth, auth_ok or auth_invalid).
    `mode`: ok | redirect | http200 | no_accept | bad_accept | extension | bad_protocol | dup_upgrade | folded."""

    def __init__(self, token="HA-TOKEN-CANARY-31337", auth=True, mode="ok", tls=None, handler=None):
        self.token, self.auth, self.mode, self.handler = token, auth, mode, handler
        self.requests = []          # one dict per handshake: {"line", "headers", "raw"}
        self.received = []          # (opcode, payload) of every frame after the handshake, in order
        self.auth_msgs = []
        self.violations = []
        self.sni = []
        self.conns = []
        self.closed = threading.Event()     # a connection ended (EOF seen)
        self.eof = []               # one Event per connection, set when the broker's side closed it
        self.cond = threading.Condition()
        self.connected = threading.Event()
        stub = self
        ctx = None
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            ctx.sni_callback = lambda sock, name, c: stub.sni.append(name)

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                if ctx is not None:
                    try:
                        sock = ctx.wrap_socket(sock, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                stub._serve(Conn(sock, stub))

        class Srv(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
        self.srv = Srv(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        for c in list(self.conns):
            try:
                c.sock.close()
            except OSError:
                pass

    # -- one connection -------------------------------------------------------------------
    def _serve(self, c):
        eof = threading.Event()
        self.conns.append(c)
        self.eof.append(eof)
        try:
            head = c.read_head()
            lines = head.split(b"\r\n")
            hdr = {}
            for row in lines[1:]:
                k, _, v = row.partition(b":")
                hdr[k.decode().lower()] = v.decode().strip()
            self.requests.append({"line": lines[0].decode(), "headers": hdr, "raw": head})
            self.connected.set()
            key = hdr.get("sec-websocket-key", "").encode()
            m = self.mode
            if m == "redirect":
                return c.send(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n")
            if m == "http200":
                return c.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            acc = accept_of(key)
            extra = b""
            if m == "no_accept":
                acc = None
            elif m == "bad_accept":
                acc = accept_of(b"not-the-key")
            elif m == "extension":
                extra = b"Sec-WebSocket-Extensions: permessage-deflate\r\n"
            elif m == "bad_protocol":
                extra = b"Sec-WebSocket-Protocol: chat\r\n"
            elif m == "dup_upgrade":
                extra = b"Upgrade: websocket\r\n"
            resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            if acc is not None:
                resp += b"Sec-WebSocket-Accept: " + acc + b"\r\n"
            if m == "folded":
                resp += b"X-Folded: a\r\n b\r\n"
            c.send(resp + extra + b"\r\n")
            if self.handler:
                return self.handler(c, self)
            self.default(c)
        except (EOFError, OSError, ssl.SSLError):
            pass
        finally:
            eof.set()
            self.closed.set()

    def note(self, op, data):
        with self.cond:
            self.received.append((op, data))
            self.cond.notify_all()

    def wait_frames(self, n, timeout=10):
        with self.cond:
            self.cond.wait_for(lambda: len(self.received) >= n, timeout)
            return list(self.received)

    def default(self, c):
        if self.auth:
            c.send_json({"type": "auth_required", "ha_version": "2099.1.0"})
            fin, op, data = c.recv_frame()
            msg = json.loads(data)
            self.auth_msgs.append(msg)
            if msg.get("type") == "auth" and msg.get("access_token") == self.token:
                c.send_json({"type": "auth_ok", "ha_version": "2099.1.0"})
            else:
                c.send_json({"type": "auth_invalid", "message": "Invalid access token"})
                return
        while True:
            fin, op, data = c.recv_frame()
            if op == 8:
                self.note(8, data)
                try:
                    c.send_frame(8, data)
                except OSError:
                    pass
                return
            if op in (9, 10):
                self.note(op, data)
                if op == 9:
                    c.send_frame(10, data)
                continue
            self.note(op, data)
            self.command(c, data.decode("utf-8", "replace"))

    def command(self, c, t):
        if t == "BIN":
            c.send_frame(2, b"\x00\x01\x02\x03secret?")
        elif t == "FRAG":
            c.send_frame(1, b"ab", fin=False)
            c.send_frame(9, b"mid")             # a ping may sit between fragments
            c.send_frame(0, b"cd", fin=True)
        elif t == "PING":
            c.send_frame(9, b"hi")
        elif t.startswith("ECHO:"):
            c.send_text(t[5:])
        elif t == "CLOSE":
            c.send_frame(8, (1000).to_bytes(2, "big") + b"bye")
        elif t == "TOKEN":
            c.send_text("your token is " + self.token)
        elif t.startswith("BIG:"):
            c.send_frame(1, b"x" * int(t[4:]))
        elif t.startswith("FLOOD:"):
            for i in range(int(t[6:])):
                c.send_text(f"f{i}")
        elif t == "STALL":
            c.send(b"\x81\x7e\x00")              # half of a 16-bit length header, then nothing
        elif t == "DROP":
            c.sock.close()
            raise EOFError
        else:
            c.send_json({"echo": t})
