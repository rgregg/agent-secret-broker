"""Read a server's SSH host key for an exec request, and say how it compares with what the key pins.

Why this exists (docs/superpowers/specs/2026-11-20-exec-unpinned-hosts-design.md): `exec` no longer refuses a host
the key has not pinned or whose key changed; it asks a human, showing the fingerprint the server presents. To show
one the broker has to look at the server first. That is a new capability handed to an enrolled agent (it names a
host and a port and the broker connects), so everything here is bounded:

  * the destination goes through the destination guard FIRST (DestGuard.resolve: every address of the name must be
    allowed; loopback, link-local, metadata, the broker's own addresses, IPv4-mapped and similar forms, and
    `destination_deny_cidrs` are refused). The name is resolved ONCE and the connection goes to the validated
    address, so a second DNS answer is never used;
  * what is read is the SSH identification line, then (against that same address, as a literal) the host keys that
    `ssh-keyscan` collects in its key exchange. No authentication happens and no command runs. Nothing the server
    sends (the banner included) is kept except the public keys;
  * a short timeout, one result cached briefly per (host, port) with concurrent callers sharing one probe, and a
    rate limit per client and overall;
  * a failure is a fixed label (LABELS), never the text of an exception or of ssh-keyscan's output. The caller
    decides what the agent sees (it never sees the label or any fingerprint).

`classify` is the pure comparison. The only values taken from a request are the host (a validated plain name) and
the port (an int); neither is ever passed to a shell, and the address handed to ssh-keyscan is a string produced
by `ipaddress`.
"""
import base64
import collections
import binascii
import os
import shutil
import socket
import subprocess
import threading
import time

from . import destguard
from . import sshkey

LABELS = ("unreachable", "not_ssh", "timeout", "refused_destination", "rate_limited", "ssh_unavailable")
STATES = ("pinned", "new", "same_key_elsewhere", "changed")
CONNECT_TIMEOUT_S = 4.0
KEYSCAN_TIMEOUT_S = 4
PROBE_DEADLINE_S = 8.0              # one deadline for the connection and the banner together, however slowly a server drips
MAX_ADDRESSES = 3                   # addresses tried for one name
KEYSCAN_RUN_S = 12                  # ssh-keyscan connects once per key type
PROBE_WAIT_S = 25.0                 # the longest a second caller waits for the first one's probe
MAX_INFLIGHT_PER_CLIENT = 4
CACHE_TTL_S = 30.0
FAIL_TTL_S = 5.0                    # a failure is remembered only long enough to absorb a burst
MAX_KEYS = 8
MAX_FLIGHTS = 64
MAX_KEYSCAN_BYTES = 65536
_BANNER_MAX = 1024
_PREFERENCE = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
               "ssh-rsa")
_SCAN_TYPES = "ed25519,ecdsa,rsa"


def _rank(key_type):
    return _PREFERENCE.index(key_type) if key_type in _PREFERENCE else len(_PREFERENCE)


def _fail(label):
    return {"label": label}


# ---------------------------------------------------------------- the probe

def _read_banner(sock, deadline=None, clock=time.monotonic):
    """True when the server speaks SSH: one of its first lines (RFC 4253 lets a server send others first) begins
    `SSH-`. The bytes are examined and dropped. Raises socket.timeout or OSError. `deadline` bounds the whole read
    (each recv gets what is left), so a server that sends a byte at a time cannot keep the probe waiting."""
    buf = b""
    while len(buf) < _BANNER_MAX:
        if deadline is not None:
            left = deadline - clock()
            if left <= 0:
                raise socket.timeout()
            sock.settimeout(min(CONNECT_TIMEOUT_S, left))
        chunk = sock.recv(256)
        if not chunk:
            return False
        buf += chunk
        lines = buf.split(b"\n")
        if any(ln.startswith(b"SSH-") for ln in lines):
            return True
        if len(lines) > 6:
            return False
    return False


def _parse_scan(stdout):
    """The host keys in ssh-keyscan's output, best first: [{"key_type", "key", "fingerprint"}]. `key` is
    `type base64`, the form a known_hosts line carries after the name. Anything that is not a well-formed key of a
    supported type is dropped (the program's output is untrusted data)."""
    out, seen = [], set()
    for raw in stdout[:MAX_KEYSCAN_BYTES].splitlines()[:50]:
        f = raw.split()
        if len(f) < 3 or f[0].startswith("#") or f[1] not in sshkey._HOSTKEY_TYPES:
            continue
        try:
            blob = base64.b64decode(f[2], validate=True)
        except (ValueError, binascii.Error):
            continue
        if sshkey._blob_type(blob) != f[1]:
            continue
        fp = sshkey.fingerprint(blob)
        if fp in seen:
            continue
        seen.add(fp)
        out.append({"key_type": f[1], "key": f"{f[1]} {f[2]}", "fingerprint": fp})
    out.sort(key=lambda k: _rank(k["key_type"]))
    return out[:MAX_KEYS]


def _binary(cfg, name):
    d = cfg.get("ssh_path")
    path = os.path.join(d, name) if d else shutil.which(name)
    return path if path and os.access(path, os.X_OK) else None


def probe(host, port, cfg, guard, clock=time.monotonic, run=subprocess.run):
    """One uncached, unlimited probe. Returns {"keys": [...best first...], "fingerprint", "key_type", "key",
    "address"} (the first key repeated at the top) or {"label": one of LABELS}. `address` is the validated IP the
    probe connected to. Never raises. `run` is injectable (tests); `clock` is accepted for symmetry with the cache."""
    keyscan = _binary(cfg, "ssh-keyscan")
    if keyscan is None:
        return _fail("ssh_unavailable")
    deadline = clock() + PROBE_DEADLINE_S
    try:
        sock = guard.connect(host, port, timeout=CONNECT_TIMEOUT_S, max_addresses=MAX_ADDRESSES,
                             deadline=time.monotonic() + PROBE_DEADLINE_S)
    except destguard.DestinationRefused:
        return _fail("refused_destination")
    except socket.timeout:
        return _fail("timeout")
    except OSError:
        return _fail("unreachable")
    except Exception:  # noqa: BLE001 -- a probe must always settle on a label
        return _fail("unreachable")
    try:
        try:
            addr = sock.getpeername()[0]
        except (OSError, IndexError, TypeError):
            return _fail("unreachable")
        ip = destguard.parse_ip(addr)
        if ip is None or guard.address_refused(ip, port):         # belt and braces: the connected peer itself
            return _fail("refused_destination")
        try:
            sock.settimeout(CONNECT_TIMEOUT_S)
            if not _read_banner(sock, deadline, clock):
                return _fail("not_ssh")
        except socket.timeout:
            return _fail("timeout")
        except OSError:
            return _fail("not_ssh")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    argv = [keyscan, "-T", str(KEYSCAN_TIMEOUT_S), "-t", _SCAN_TYPES, "-p", str(int(port)), "--", str(ip)]
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C"}
    try:
        res = run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=env,
                  timeout=KEYSCAN_RUN_S)
    except subprocess.TimeoutExpired:
        return _fail("timeout")
    except FileNotFoundError:
        return _fail("ssh_unavailable")
    except (OSError, subprocess.SubprocessError):
        return _fail("unreachable")
    keys = _parse_scan(res.stdout.decode("utf-8", "replace") if isinstance(res.stdout, bytes) else (res.stdout or ""))
    if not keys:
        return _fail("not_ssh")
    return {"keys": keys, **keys[0], "address": str(ip)}


# ---------------------------------------------------------------- rate limit

class RateLimiter:
    """At most `per_client` probes per `window_s` for one client id and `overall` for everyone (sliding window,
    injectable clock). `allow` records the attempt only when it is let through."""

    def __init__(self, per_client, overall, window_s=60.0, clock=time.monotonic):
        self.per_client, self.overall, self.window, self._clock = per_client, overall, window_s, clock
        self._by, self._all = {}, collections.deque()
        self._lock = threading.Lock()

    def allow(self, client_id):
        now = self._clock()
        with self._lock:
            cut = now - self.window
            while self._all and self._all[0] <= cut:
                self._all.popleft()
            q = self._by.setdefault(client_id, collections.deque())
            while q and q[0] <= cut:
                q.popleft()
            if len(q) >= self.per_client or len(self._all) >= self.overall:
                if not q:
                    self._by.pop(client_id, None)
                return False
            q.append(now)
            self._all.append(now)
            return True


class Prober:
    """The broker's probe: limit, cache, single flight, then `probe`. One per broker."""

    def __init__(self, guard, cfg_fn, clock=time.monotonic, run=subprocess.run):
        self.guard, self._cfg, self._clock, self._run = guard, cfg_fn, clock, run
        self._cache, self._flights, self._lock = {}, {}, threading.Lock()
        self._inflight = {}                                   # client id -> probes it has running or waiting
        cfg = cfg_fn()
        self.limiter = RateLimiter(cfg["probe_per_client"], cfg["probe_overall"], clock=clock)

    def reconfigure(self):
        cfg = self._cfg()
        self.limiter.per_client, self.limiter.overall = cfg["probe_per_client"], cfg["probe_overall"]

    def _cached(self, key):
        hit = self._cache.get(key)
        if hit and self._clock() < hit[0]:
            return hit[1]
        return None

    def probe(self, host, port, client_id):
        """The probe result for (host, port) on behalf of `client_id`. A cached result costs the client nothing;
        concurrent callers for one (host, port) wait for the first caller's probe instead of making their own."""
        key = (host, int(port))
        with self._lock:
            got = self._cached(key)
            if got is not None:
                return dict(got)
            flight = self._flights.get(key)
            if flight is None:
                if len(self._flights) >= MAX_FLIGHTS:         # bounded: an agent cannot grow this map
                    return _fail("rate_limited")
                flight = self._flights[key] = [threading.Lock(), 0]
            if self._inflight.get(client_id, 0) >= MAX_INFLIGHT_PER_CLIENT:
                if flight[1] == 0:
                    del self._flights[key]
                return _fail("rate_limited")                  # one client cannot hold every slot
            flight[1] += 1
            self._inflight[client_id] = self._inflight.get(client_id, 0) + 1
        try:
            if not flight[0].acquire(timeout=PROBE_WAIT_S):
                return _fail("rate_limited")
            try:
                with self._lock:
                    got = self._cached(key)
                if got is not None:
                    return dict(got)
                if not self.limiter.allow(client_id):
                    return _fail("rate_limited")
                res = probe(host, key[1], self._cfg(), self.guard, self._clock, self._run)
                ttl = FAIL_TTL_S if "label" in res else CACHE_TTL_S
                with self._lock:
                    self._cache[key] = (self._clock() + ttl, res)
                    if len(self._cache) > 256:                # bounded: drop the expired, then the oldest
                        now = self._clock()
                        for k in [k for k, v in self._cache.items() if v[0] <= now] or list(self._cache)[:64]:
                            self._cache.pop(k, None)
                return dict(res)
            finally:
                flight[0].release()
        finally:                                              # every exit path, an exception included
            with self._lock:
                self._inflight[client_id] -= 1
                if self._inflight[client_id] <= 0:
                    del self._inflight[client_id]
                flight[1] -= 1
                if flight[1] == 0 and self._flights.get(key) is flight:
                    del self._flights[key]


# ---------------------------------------------------------------- classification (pure)

def _name_port(name, host):
    """The port a known_hosts name gives `host` (22 for the bare name, N for `host:N`), or None when the name is
    some other host. Exactly the same host name: a key pinned under another name is no evidence about this one."""
    if name == host:
        return 22
    if name.startswith(host + ":"):
        rest = name[len(host) + 1:]
        if rest.isascii() and rest.isdigit() and 1 <= int(rest) <= 65535:
            return int(rest)
    return None


def host_allowed(allowed_hosts, host):
    """THE rule for "this host name passes the key's host validation": with an `allowed_hosts` list, exact membership
    of the (lower-case) name (`host:port` entries, fingerprint entries and other spellings do not allow a bare name);
    with NO list the key restricts no host, so every name passes and only a pinned `known_hosts` line makes a host
    pinned. Intake, classification and the run all call this one function, so they cannot disagree. The list is host
    validation, not approval policy: nothing here approves anything."""
    if not allowed_hosts:
        return True
    return host in allowed_hosts


def classify(host, port, presented, known_lines, allowed_hosts):
    """How the keys a server presents compare with what a credential pins for `host`:`port`.

    `presented` is a list of SHA256 fingerprints (or one). `known_lines` are the key's known_hosts lines (any
    format sshkey.parse_known_hosts reads); `allowed_hosts` its allowed host names. Returns
    {"state", "pinned_fp", "matches", "fingerprint"}:

      pinned              a line pins this name and port, the key is on it, and the name is allowed;
      changed             a line pins this name and port and NONE of the presented keys is on it;
      same_key_elsewhere  no line for this port, but a presented key is pinned for the SAME name on another port
                          (`matches` is that `host:port`);
      new                 anything else (a key pinned only under a different name counts for nothing; a pinned,
                          matching line for a name that is not allowed is `new` too: allowed_hosts is the gate).

    `fingerprint` is the presented key the state is about (the first one when none is singled out)."""
    pres = [presented] if isinstance(presented, str) else list(presented)
    pres = [p.rstrip("=") for p in pres]
    lines = sshkey.known_host_lines(list(known_lines or []), host, port)
    here = list(sshkey.parse_known_hosts(lines))                   # fingerprints pinned for this name and port
    allowed = host_allowed(allowed_hosts, host)
    first = pres[0] if pres else None
    if here:
        hit = next((p for p in pres if p in here), None)
        if hit is not None and allowed:
            return {"state": "pinned", "pinned_fp": hit, "matches": None, "fingerprint": hit}
        if hit is None:
            return {"state": "changed", "pinned_fp": here[0], "matches": None, "fingerprint": first}
        return {"state": "new", "pinned_fp": None, "matches": None, "fingerprint": hit}
    for fp, names in sshkey.parse_known_hosts(list(known_lines or [])).items():
        if fp not in pres:
            continue
        for n in names:
            p = _name_port(n, host)
            if p is not None and p != port:
                return {"state": "same_key_elsewhere", "pinned_fp": None, "matches": f"{host}:{p}",
                        "fingerprint": fp}
    return {"state": "new", "pinned_fp": None, "matches": None, "fingerprint": first}


def pin_line(host, port, key):
    """The one known_hosts line that trusts exactly `key` (`type base64`) for `host`:`port`."""
    return f"{host if port == 22 else f'[{host}]:{port}'} {key}"


def drop_pin(lines, host, port):
    """`lines` with `host`:`port` removed from every line that names it (a line that named only it goes; a line
    that named others keeps them). Read the way sshkey.known_host_lines reads them; lines it does not understand
    are kept untouched."""
    want = host if port == 22 else f"{host}:{port}"
    out = []
    for line in lines:
        f = str(line).split()
        if len(f) < 3 or f[0].startswith(("#", "@", "|")) or f[1] not in sshkey._HOSTKEY_TYPES:
            out.append(line)
            continue
        keep, hit = [], False
        for n in f[0].split(","):
            m = n.strip().lower()
            if m.startswith("[") and "]:" in m:
                h, _, p = m[1:].partition("]:")
                m = h if p == "22" else f"{h}:{p}"
            if m == want:
                hit = True
            else:
                keep.append(n)
        if not hit:
            out.append(line)
        elif keep:
            out.append(" ".join([",".join(keep)] + f[1:]))
    return out
