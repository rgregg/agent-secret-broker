"""Test-only: make stdlib test servers shut down promptly.

`socketserver.BaseServer.serve_forever()` polls for a shutdown request every 0.5 s, so every
`server.shutdown()` in a tearDown costs up to half a second of pure waiting (the suite starts
several servers per test). Polling every 10 ms removes that wait without changing what is served.
Production code is untouched; only the default poll interval used by tests changes.
"""
import socketserver

_orig = socketserver.BaseServer.serve_forever


def _serve_forever(self, poll_interval=0.01):
    return _orig(self, poll_interval)


socketserver.BaseServer.serve_forever = _serve_forever


# -- fake monotonic clock for a module's `time` reference -------------------------------------------------
import time as _time
from unittest import mock as _mock


class FakeMono:
    """The real monotonic clock plus an offset that only moves when a test says so. Deadlines elsewhere in the
    patched module (start-up polling) therefore still expire in real time; only `advance` jumps ahead."""

    def __init__(self):
        self.offset = 0.0

    def advance(self, seconds):
        self.offset += seconds

    def __call__(self):
        return _time.monotonic() + self.offset


class _TimeShim:
    """Stands in for the `time` module inside ONE module: `monotonic` is the fake clock and `sleep` is capped
    at 10 ms (poll loops in the module under test would otherwise sleep for real); the rest is real."""

    def __init__(self, mono):
        self.monotonic = mono

    @staticmethod
    def sleep(seconds):
        _time.sleep(min(seconds, 0.01))

    def __getattr__(self, name):
        return getattr(_time, name)


def patch_mono(testcase, module, mono=None):
    """Make `module.time.monotonic()` read a FakeMono (other modules and the real `time` are untouched)."""
    mono = mono or FakeMono()
    p = _mock.patch.object(module, "time", _TimeShim(mono))
    p.start()
    testcase.addCleanup(p.stop)
    return mono


def expire(broker, rid=None):
    """Expire a pending request NOW, the way the passage of its ttl would: move its deadline into the past and
    run the broker's own expiry pass (which also wakes any long-poll waiting on the request). `rid=None`
    expires every pending request. Replaces sleeping for the ttl."""
    with broker._lock:
        for r in list(broker._by_id.values()):
            if (rid is None or r.id == rid) and r.status == "pending":
                r.expires = _time.time() - 1
        broker._expire_locked()


# -- a raw-socket upstream that records exactly what reaches the wire --------------------------------------
import socket as _socket
import threading as _threading


class RawUpstream:
    """Records every byte of every connection, answers `200 ok` once the headers (and, with `wait_body`, the
    declared body) are in, then reads to EOF so a pipelined second request is still captured. The broker closes
    the connection after the answer, so EOF marks the end of what it sent: nothing here waits for a timer.

    `settled()` is the synchronisation point for assertions: it returns once every connection that was opened
    before the call has been accepted and has ended (a sentinel connection goes through the same accept queue,
    so connections ahead of it are known). `idle` only bounds a connection whose peer never closes."""

    SENTINEL = b"\0settle\0"

    def __init__(self, wait_body=True, idle=5.0):
        self.wait_body, self.idle = wait_body, idle
        self.sock = _socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.raw = []
        self._cv = _threading.Condition()
        self._active = 0
        self._sentinels = 0
        _threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self._cv:
                self._active += 1
            _threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        c.settimeout(self.idle)
        buf, answered = b"", False
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
                if buf.startswith(self.SENTINEL):
                    break
                if not answered and b"\r\n\r\n" in buf:
                    head, _, rest = buf.partition(b"\r\n\r\n")
                    n = 0
                    if self.wait_body:
                        for ln in head.decode("latin-1").split("\r\n")[1:]:
                            k, _, v = ln.partition(":")
                            if k.strip().lower() == "content-length" and v.strip().isdigit():
                                n = int(v)
                    if len(rest) >= n:
                        answered = True
                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except OSError:
            pass
        finally:
            c.close()
            with self._cv:
                if buf.startswith(self.SENTINEL):
                    self._sentinels += 1
                else:
                    self.raw.append(buf)
                self._active -= 1
                self._cv.notify_all()

    def settled(self):
        """Raw bytes of every finished connection (see class doc)."""
        before = self._sentinels
        s = _socket.create_connection(("127.0.0.1", self.port))
        s.sendall(self.SENTINEL)
        s.close()
        with self._cv:
            self._cv.wait_for(lambda: self._sentinels > before and self._active == 0, timeout=self.idle + 5)
            return list(self.raw)

    def clear(self):
        self.settled()
        with self._cv:
            self.raw.clear()

    @property
    def conns(self):
        """Parsed connections: request line, headers, body as framed by Content-Length, leftover bytes."""
        out = []
        for buf in self.settled():
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            hdrs = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
            n = int(hdrs.get("content-length", "0") or 0)
            out.append({"line": lines[0], "headers": hdrs, "body": rest[:n], "extra": rest[n:]})
        return out

    def close(self):
        self.sock.close()


# the real client with its poll sleeps capped (see asb_fastpoll.py)
import os as _os
import sys as _sys

FAST_CLI = [_sys.executable, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "asb_fastpoll.py")]


def wait_until(pred, timeout=10.0, what="condition"):
    """Return as soon as `pred()` is true (checked every millisecond); fail after `timeout`. For waiting on
    another thread's effect without a fixed sleep: the timeout is only ever spent when the test is failing."""
    end = _time.monotonic() + timeout
    while not pred():
        if _time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        _time.sleep(0.001)


import re as _re

_TRANSIENT = _re.compile(r"\((run|_release_and_finish|_run_retry|_refresh_if|_refresh|expire_ssh_rules)\)$")


def quiesce(*brokers, timeout=10.0):
    """Wait for the broker's short-lived background work to finish: queued notification sends, then every
    one-shot worker thread (resolved-notice senders, release/finish, retries). A deterministic stand-in for
    `sleep(0.3)  # let the background work land`. Long-lived loops (servers, sweepers) are not waited for."""
    for b in brokers:
        assert b.flush_notifications(timeout), "notification queue did not drain"
    end = _time.monotonic() + timeout
    while True:
        live = [t for t in _threading.enumerate() if _TRANSIENT.search(t.name) and t is not _threading.current_thread()]
        if not live:
            return
        for t in live:
            t.join(max(0.0, end - _time.monotonic()))
        assert _time.monotonic() < end, f"background threads still running: {[t.name for t in live]}"
