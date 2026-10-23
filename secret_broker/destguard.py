"""The destination guard: ONE rule for every outbound call made on an agent's behalf.

Why it exists: the broker sits on a network (often next to its own approval listener) and
connects wherever an approved credential's `allowed_hosts` says. Without a guard an agent
that can get a credential created could point it at the broker itself, the cloud metadata
service or any loopback service, and use the broker as a proxy for requests it must never make.

Rules (see docs/reference.md, threat model):
  * the host name is resolved ONCE (all A and AAAA records); the call is refused if ANY address
    is loopback, link-local (incl. 169.254.169.254), unspecified, multicast, an IPv4-embedding
    form of those (IPv4-mapped, 6to4, NAT64, IPv4-compatible), an address of one of this host's
    own interfaces, or inside `destination_deny_cidrs`;
  * the broker's own listener ports are refused on any private or own address;
  * the connection goes to the validated IP (pinned): Host, SNI and certificate verification stay
    on the original host name, and a second DNS answer can never be used;
  * a non-default port on an IP literal needs an explicit `host:port` entry in allowed_hosts.
RFC 1918 and other private LAN ranges stay allowed: reaching LAN services is the product's purpose.
The refusal text is the fixed class "destination not allowed": no address is ever echoed.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request

REFUSED_TEXT = "destination not allowed"
# Added by the broker to EVERY outbound call (overwriting anything the agent supplied); the
# broker's own listeners refuse any request carrying it. The real SSO proxy never sets it.
EGRESS_MARKER = "X-Secret-Broker-Egress"

BAD_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
                       "metadata.google.internal", "metadata", "instance-data"})

LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

_ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
    "100.100.100.200/32", "192.0.0.192/32", "168.63.129.16/32",   # Alibaba, Oracle, Azure metadata / wireserver
    "::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128",     # AWS IPv6 metadata
    "::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b:1::/48")]   # IPv4-mapped / SIIT / local-use NAT64 as raw v6

# Only ever flipped from Python (the test harness): never read from the JSON config.
_TEST_ALLOW_LOOPBACK = False


def allow_loopback_for_tests(on=True):
    """Test-only switch: brokers built after this call that are not given an explicit guard let
    loopback destinations through (the suite's stub servers live on 127.0.0.1), and trust peers
    on loopback on the approval listener. There is no configuration key for it."""
    global _TEST_ALLOW_LOOPBACK
    _TEST_ALLOW_LOOPBACK = bool(on)


def test_loopback_allowed():
    return _TEST_ALLOW_LOOPBACK


class DestinationRefused(OSError):
    """A destination the guard refuses. The text is fixed; the address is never included."""

    def __init__(self):
        super().__init__(REFUSED_TEXT)


def _embedded(ip):
    """The addresses `ip` is, plus every IPv4 address an IPv6 form embeds."""
    out = [ip]
    if ip.version == 6:
        if ip.ipv4_mapped:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour:
            out.append(ip.sixtofour)
        n = int(ip)
        if n >> 32 == 0:                                    # ::a.b.c.d (IPv4-compatible)
            out.append(ipaddress.IPv4Address(n & 0xFFFFFFFF))
        if n >> 32 == 0x0064ff9b0000000000000000:             # 64:ff9b::/96 (NAT64)
            out.append(ipaddress.IPv4Address(n & 0xFFFFFFFF))
        if ip.teredo:
            out.append(ip.teredo[1])
        if (n >> 32) & 0xFFFFFFFF in (0x00005EFE, 0x02005EFE):    # ISATAP ::5efe:a.b.c.d
            out.append(ipaddress.IPv4Address(n & 0xFFFFFFFF))
    return out


def parse_ip(text):
    """An ip_address for a canonical literal, else None. Scope ids are dropped."""
    try:
        return ipaddress.ip_address(text.split("%", 1)[0] if isinstance(text, str) else text)
    except ValueError:
        return None


def legacy_ip_form(host):
    """True for a name that a resolver would read as an IPv4 address in a non-canonical form
    (2130706433, 0x7f.1, 0177.0.0.1, 127.1): such a host is never a real name and never allowed."""
    if not isinstance(host, str) or not host:
        return False
    if parse_ip(host) is not None:
        return False
    try:
        socket.inet_aton(host)
        return True
    except (OSError, ValueError):
        pass
    return bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host.lower()))


def local_addresses():
    """Every address assigned to one of this host's (or container's) interfaces, read from /proc
    (Linux). Falls back to a bind test per candidate (see _is_local_bind) elsewhere."""
    out = set()
    try:
        last = None
        with open("/proc/net/fib_trie") as f:
            for line in f:
                s = line.strip()
                if s.startswith("|--"):
                    last = s[3:].strip()
                elif "/32 host LOCAL" in s and last:
                    out.add(last)
    except OSError:
        pass
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                h = line.split()[0]
                out.add(str(ipaddress.IPv6Address(int(h, 16))))
    except (OSError, ValueError, IndexError):
        pass
    return out


def _is_local_bind(ip):
    fam = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.bind((str(ip), 0))
        return True
    except OSError:
        return False


class DestGuard:
    def __init__(self, deny_cidrs=(), own_ports=(), resolver=None, local_addrs=None,
                 allow_loopback=False, connector=None):
        self.deny = [ipaddress.ip_network(c, strict=False) for c in deny_cidrs]
        self.own_ports = set(int(p) for p in own_ports)
        self._resolver = resolver or (lambda host, port: [
            ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)])
        self._local_fn = local_addrs or local_addresses
        self.allow_loopback = bool(allow_loopback)
        self._connector = connector or socket.create_connection
        self._lcache = (0.0, frozenset())
        self.strip_headers = ()        # header names deleted from every outbound call (the proxy secret's)
        self.mask_values = ()          # extra values masked in every response (the proxy secret)
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, cfg, **kw):
        """`destination_deny_cidrs` is the only guard setting the JSON config has."""
        cidrs = cfg.get("destination_deny_cidrs") or []
        if not isinstance(cidrs, list):
            raise ValueError("destination_deny_cidrs must be a list of CIDR strings")
        for c in cidrs:
            try:
                ipaddress.ip_network(c, strict=False)
            except (ValueError, TypeError):
                raise ValueError("destination_deny_cidrs: not a CIDR: " + str(c)[:60]) from None
        ports = cfg.get("own_ports")
        if ports is None:
            ports = []
        if (not isinstance(ports, list) or len(ports) > 32
                or not all(isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535 for p in ports)):
            raise ValueError("own_ports must be a list of port numbers (1-65535)")
        kw.setdefault("allow_loopback", _TEST_ALLOW_LOOPBACK)
        kw["own_ports"] = list(kw.get("own_ports") or ()) + ports
        return cls(deny_cidrs=cidrs, **kw)

    # -- own addresses ----------------------------------------------------------------
    def locals(self):
        now = time.monotonic()
        with self._lock:
            at, val = self._lcache
            if now - at > 5.0:
                val = frozenset(str(parse_ip(a)) for a in self._local_fn() if parse_ip(a) is not None)
                self._lcache = (now, val)
            return val

    def is_local(self, ip):
        return str(ip) in self.locals() or (not self.locals() and _is_local_bind(ip))

    def port_ok(self, entries, host, port):
        """destguard.ip_port_ok, except that the test harness' loopback stubs (random ports) pass."""
        if self.allow_loopback:
            ip = parse_ip((host or "").strip("[]"))
            if ip is not None and ip.is_loopback:
                return True
        return ip_port_ok(entries, host, port)

    def register_ports(self, *ports):
        self.own_ports.update(int(p) for p in ports if p)

    # -- the rules --------------------------------------------------------------------
    def address_refused(self, ip, port):
        """True when `ip` (an ipaddress object) may not be connected to on `port`."""
        for a in _embedded(ip):
            if any(a in n for n in _ALWAYS_BLOCKED) and not (self.allow_loopback and a.is_loopback):
                return True
            if not self.allow_loopback and self.is_local(a):
                return True
            if any(a in n for n in self.deny):
                return True
            if port in self.own_ports and not a.is_global and not (self.allow_loopback and a.is_loopback):
                return True
        return False

    def _bad_name(self, h):
        return h in BAD_NAMES and not (self.allow_loopback and h in LOOPBACK_NAMES)

    def host_refused(self, host):
        """Static check of a host name or IP literal (no DNS): loopback-class names and literals."""
        h = (host or "").strip().lower().rstrip(".")
        if not h:
            return True
        if self._bad_name(h) or legacy_ip_form(h):
            return True
        ip = parse_ip(h.strip("[]"))
        if ip is not None:
            return self.address_refused(ip, 0)
        return False

    def resolve(self, host, port):
        """Resolve once and validate every address. Returns the list of IP strings to connect to;
        DestinationRefused when any one of them (or the name itself) is not allowed."""
        h = (host or "").strip().rstrip(".")
        if not h or self._bad_name(h.lower()) or legacy_ip_form(h):
            raise DestinationRefused()
        lit = parse_ip(h.strip("[]"))
        if lit is not None:
            addrs = [str(lit)]
        else:
            try:
                addrs = list(dict.fromkeys(self._resolver(h, port)))
            except OSError:
                raise
            if not addrs:
                raise socket.gaierror(socket.EAI_NONAME, "no address")
        parsed = []
        for a in addrs:
            ip = parse_ip(a)
            if ip is None or self.address_refused(ip, port):
                raise DestinationRefused()
            parsed.append(str(ip))
        return parsed

    # -- connecting -------------------------------------------------------------------
    def connect(self, host, port, timeout=None, source_address=None, entries=None):
        """A socket connected to a validated address of `host`. `entries` (the credential's
        allowed_hosts) enables the rule for IP literals on non-default ports."""
        port = int(port)
        if entries is not None and not self.port_ok(entries, host, port):
            raise DestinationRefused()
        last = None
        for ip in self.resolve(host, port):
            try:
                kw = {"source_address": source_address} if source_address else {}
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT and timeout is not None:
                    return self._connector((ip, port), timeout, **kw)
                return self._connector((ip, port), **kw)
            except OSError as e:
                last = e
        raise last or OSError("connection failed")

    # -- validation time ----------------------------------------------------------------
    def entry_problem(self, entry, from_store=True):
        """None when `entry` (an allowed_hosts item: `host` or `host:port`) is acceptable, else a
        fixed sentence. `from_store`: created through a request (strict: also dotless names)."""
        host, port = split_entry(entry)
        if host is None:
            return "allowed_hosts entries are host names or host:port"
        h = host.lower().rstrip(".")
        if self._bad_name(h) or legacy_ip_form(h):
            return "that host is not allowed as a destination"
        ip = parse_ip(h)
        if ip is not None:
            if self.address_refused(ip, port or 0):
                return "that host is not allowed as a destination"
            return None
        if from_store and "." not in h:
            return "that host is not allowed as a destination (use a fully qualified name)"
        if (h.endswith((".localhost", ".localdomain")) and not self.allow_loopback) or (
                h.endswith(".internal") and h.startswith("metadata")):
            return "that host is not allowed as a destination"
        return None

    # -- urllib plumbing ----------------------------------------------------------------
    def opener(self, tls=None, entries=None):
        return build_opener(self, tls, entries)


_ENTRY_RE = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::([0-9]{1,5}))?$")


def split_entry(entry):
    """`host` or `host:port` -> (host, port or None); (None, None) when it is neither."""
    m = _ENTRY_RE.match(entry) if isinstance(entry, str) else None
    if not m or (m.group(3) is not None and not 1 <= int(m.group(3)) <= 65535):
        return None, None
    return m.group(1), (int(m.group(3)) if m.group(3) else None)


def host_parts(entries):
    """The set of lower-case host names in a list of allowed_hosts entries."""
    return {split_entry(e)[0].lower() for e in entries or () if split_entry(e)[0]}


def ip_port_ok(entries, host, port):
    """The IP-literal rule. A host that is an IP literal may be called on its scheme's default port
    (80 or 443) only if listed bare, and on any other port only if an entry says `host:port`.
    A hostname is not restricted here (its entry is a host match). An entry `host:port` alone
    never allows other ports of that host."""
    h = (host or "").lower().strip("[]")
    ents = [str(e).lower() for e in entries or ()]
    if parse_ip(h) is None:
        return True
    if f"{h}:{port}" in ents:
        return True
    return port in (80, 443) and h in ents


def entry_allows(entries, host, port):
    """True when `host` (and for explicit entries, `port`) is covered by allowed_hosts."""
    h = (host or "").lower()
    ents = [str(e).lower() for e in entries or ()]
    return h in ents or f"{h}:{port}" in ents


# -- connections that connect through the guard -------------------------------------------------
def _factory(base, guard, entries):
    class G(base):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._create_connection = lambda address, timeout=None, source_address=None: guard.connect(
                address[0], address[1], timeout, source_address, entries)
    return G


def _mark(req, strip=()):
    drop = {EGRESS_MARKER.lower(), *(h.lower() for h in strip)}
    for d in (req.headers, req.unredirected_hdrs):
        for k in [k for k in d if k.lower() in drop]:
            del d[k]
    req.add_unredirected_header(EGRESS_MARKER, "1")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: only the originally approved URL is contacted. The 3xx is
    returned to the caller as-is (so a redirect to loopback is never even attempted)."""

    def redirect_request(self, *args, **kwargs):
        return None


def build_opener(guard, tls=None, entries=None):
    """An opener whose every connection goes through `guard`. `tls`: the credential's TLS policy
    (verify false, or a pinned fingerprint). No proxy is ever used, and no redirect followed."""
    plain = _factory(http.client.HTTPConnection, guard, entries)
    https_base = http.client.HTTPSConnection
    ctx = None
    if tls and (not tls.get("verify", True) or tls.get("fingerprint")):
        import hashlib
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pins = tls.get("fingerprint")
        if pins:
            pins = (pins,) if isinstance(pins, str) else tuple(pins)

            class Pinned(http.client.HTTPSConnection):
                def connect(self):
                    super().connect()
                    der = self.sock.getpeercert(binary_form=True)
                    if not der or hashlib.sha256(der).hexdigest() not in pins:
                        self.close()
                        raise ssl.SSLError("server certificate does not match any pinned fingerprint")
            https_base = Pinned
    secure = _factory(https_base, guard, entries)

    class H(urllib.request.HTTPHandler):
        def http_open(self, req):
            _mark(req, guard.strip_headers)
            return self.do_open(plain, req)

    class S(urllib.request.HTTPSHandler):
        def https_open(self, req):
            _mark(req, guard.strip_headers)
            return self.do_open(secure, req, context=self._context)
    sh = S(context=ctx) if ctx is not None else S()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, H(), sh)


# -- operator-configured outbound clients ---------------------------------------------------------
class _OpHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        _mark(req)
        return self.do_open(http.client.HTTPConnection, req)


class _OpHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        _mark(req)
        return self.do_open(http.client.HTTPSConnection, req, context=self._context)


_OP_OPENER = None


def operator_urlopen(req, timeout=None):
    """urlopen for the broker's OWN, operator-configured clients (notification transports, the model
    clients, the local vault CLI): the target is fixed by the operator, so loopback and LAN are allowed,
    but the environment's HTTP(S)_PROXY is never used and the egress marker is set like on every other
    outbound call. (Agent-chosen targets never come through here: they use DestGuard.opener.)"""
    global _OP_OPENER
    if _OP_OPENER is None:
        _OP_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _OpHTTP, _OpHTTPS)
    return _OP_OPENER.open(req, timeout=timeout)
