"""SSH keys held by the broker: parse, sign, and describe what is being signed.

The private key never leaves the broker. A client (`asb ssh-agent`) forwards the
ssh-agent SIGN_REQUEST payload; the broker signs it and returns the signature
blob in ssh-agent wire format.

Only unencrypted OpenSSH-format keys are accepted: the broker is the thing
protecting the key, so a passphrase would have nowhere to come from.
"""
import base64
import re
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

MAX_SIGN_DATA = 262_144     # git SSHSIG signs a hash, userauth data is < 1 KB
SIGN_RSA_SHA2_256, SIGN_RSA_SHA2_512 = 2, 4     # ssh-agent SIGN_REQUEST flags


class SshKeyError(ValueError):
    pass


def _string(b):
    return struct.pack(">I", len(b)) + b


def _mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, "big") if n else b""
    return _string(b)


def load_private(text):
    """Parse an unencrypted OpenSSH/PEM private key. Raises SshKeyError."""
    data = text.encode() if isinstance(text, str) else text
    try:
        key = serialization.load_ssh_private_key(data, password=None)
    except TypeError:
        raise SshKeyError("the key is passphrase-protected; the broker needs an "
                          "unencrypted copy (ssh-keygen -p -N '' -f COPY)") from None
    except (ValueError, Exception) as e:  # noqa: BLE001 -- cryptography raises several types
        raise SshKeyError(f"not an unencrypted OpenSSH private key ({type(e).__name__})") from None
    if not isinstance(key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise SshKeyError("unsupported key type (use ed25519, rsa or ecdsa)")
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise SshKeyError("RSA keys under 2048 bits are refused")
    return key


def public_blob(key):
    """The key in ssh-agent / authorized_keys wire format."""
    pub = key.public_key() if hasattr(key, "public_key") else key
    if isinstance(pub, ed25519.Ed25519PublicKey):
        raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return _string(b"ssh-ed25519") + _string(raw)
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return _string(b"ssh-rsa") + _mpint(n.e) + _mpint(n.n)
    curve = {"secp256r1": "nistp256", "secp384r1": "nistp384", "secp521r1": "nistp521"}[pub.curve.name]
    point = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return _string(b"ecdsa-sha2-" + curve.encode()) + _string(curve.encode()) + _string(point)


def public_line(key):
    """`ssh-ed25519 AAAA...` as stored in broker metadata and authorized_keys."""
    blob = public_blob(key)
    algo = blob[4:4 + struct.unpack(">I", blob[:4])[0]].decode()
    return f"{algo} {base64.b64encode(blob).decode()}"


def blob_from_line(line):
    try:
        return base64.b64decode(line.split()[1], validate=True)
    except (IndexError, ValueError):
        raise SshKeyError("bad public key line") from None


def fingerprint(blob):
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def sign(key, data, flags=0):
    """ssh-agent signature blob: string(algorithm) + string(signature)."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return _string(b"ssh-ed25519") + _string(key.sign(data))
    if isinstance(key, rsa.RSAPrivateKey):
        if flags & SIGN_RSA_SHA2_512:
            name, h = b"rsa-sha2-512", hashes.SHA512()
        elif flags & SIGN_RSA_SHA2_256:
            name, h = b"rsa-sha2-256", hashes.SHA256()
        else:
            raise SshKeyError("legacy ssh-rsa (SHA-1) signatures are refused")
        return _string(name) + _string(key.sign(data, padding.PKCS1v15(), h))
    bits = key.curve.key_size
    h = {256: hashes.SHA256(), 384: hashes.SHA384(), 521: hashes.SHA512()}[bits]
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(h)))
    algo = {256: b"nistp256", 384: b"nistp384", 521: b"nistp521"}[bits]
    return _string(b"ecdsa-sha2-" + algo) + _string(_mpint(r) + _mpint(s))


class _Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def byte(self):
        v = self.b[self.i]
        self.i += 1
        return v

    def string(self):
        n = struct.unpack_from(">I", self.b, self.i)[0]
        v = self.b[self.i + 4:self.i + 4 + n]
        if len(v) != n:
            raise IndexError
        self.i += 4 + n
        return v


def _shown(raw, limit=48):
    """Client-supplied bytes made safe to show an approver: printable ASCII
    only (anything else, newlines included, is escaped), length-limited, quoted."""
    text = "".join(c if " " <= c <= "~" else "?" for c in raw.decode("latin-1"))
    return repr(text[:limit] + ("..." if len(text) > limit else ""))


HOSTBOUND = b"publickey-hostbound-v00@openssh.com"


def parse_userauth(data):
    """Parse the data of an SSH public key login signature, or None.

    {"sid", "user", "service", "method", "hostkey"}: `hostkey` is the server host
    key blob of a host-bound login (OpenSSH 8.9+, method publickey-hostbound-v00)
    and None for plain `publickey` or when that field cannot be read.
    """
    try:
        r = _Reader(data)
        sid = r.string()
        if r.byte() != 50:                  # SSH_MSG_USERAUTH_REQUEST
            return None
        out = {"sid": sid, "user": r.string(), "service": r.string(), "method": r.string(), "hostkey": None}
        if out["method"] == b"publickey":
            return out
        if out["method"] == HOSTBOUND:
            try:
                r.byte()                    # TRUE: a signature follows
                r.string()                  # public key algorithm
                r.string()                  # public key blob
                hk = r.string()
                if r.i == len(data) and _blob_type(hk) in _HOSTKEY_TYPES:
                    out["hostkey"] = hk
            except (IndexError, struct.error):
                pass
            return out
    except (IndexError, struct.error):
        pass
    return None


def describe_data(data, host_known=False):
    """What is being signed, as far as it can be told, for the approval prompt.

    Returns {"kind", "text", "hostkey"}. The data is client-supplied, so this is
    what the bytes *say*, not a promise about the connection they belong to. A
    plain userauth blob carries the account name but not the host; a host-bound
    one (OpenSSH 8.9+ with a server that supports it) names the server host key,
    which the server itself checks. `host_known` drops the "host not shown"
    caveat when the caller shows a server identity instead.
    """
    if data.startswith(b"SSHSIG"):
        try:
            r = _Reader(data[6:])
            ns = _shown(r.string())
            return {"kind": "sshsig", "text": f"sign a message (namespace {ns}, e.g. git commit signing)"}
        except (IndexError, struct.error):
            return {"kind": "sshsig", "text": "sign a message (SSHSIG)"}
    ua = parse_userauth(data)
    if ua:
        user, service = _shown(ua["user"]), _shown(ua["service"])
        text = f"log in over SSH as {user} (service {service}, both client-supplied)"
        if ua["hostkey"]:
            text += f" to server {fingerprint(ua['hostkey'])} ({_blob_type(ua['hostkey'])})"
        elif not host_known:
            text += "; host not shown by SSH"
        return {"kind": "userauth", "text": text, "hostkey": ua["hostkey"]}
    hint = ""
    if len(data) > 4 and struct.unpack(">I", data[:4])[0] == len(data) - 4:
        hint = ", one length-prefixed string"
    return {"kind": "unknown", "hostkey": None,
            "text": f"sign {len(data)} bytes of unrecognised data (not an SSH login or SSHSIG message{hint})"}


# -- server identity ---------------------------------------------------------
BIND_EXT = b"session-bind@openssh.com"
MAX_BINDS = 16                  # per agent connection
_HOSTKEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                  "ecdsa-sha2-nistp521", "ssh-rsa")
_RSA_SIG = {b"rsa-sha2-256": hashes.SHA256(), b"rsa-sha2-512": hashes.SHA512(), b"ssh-rsa": hashes.SHA1()}


def _blob_type(blob):
    try:
        return _Reader(blob).string().decode("ascii")
    except (IndexError, struct.error, UnicodeDecodeError):
        return ""


ACCOUNT_RE = re.compile(r"[\x21-\x7e]{1,64}")     # printable ASCII, no spaces: what a rule may name


def account(data):
    """The account name signed inside SSH login data, or None when `data` is not
    an ssh-connection login or the name is not plain printable ASCII (1-64)."""
    ua = parse_userauth(data)
    if not ua or ua["service"] != b"ssh-connection":
        return None
    try:
        name = ua["user"].decode("ascii")
    except UnicodeDecodeError:
        return None
    return name if ACCOUNT_RE.fullmatch(name) else None


def userauth_session_id(data):
    """The session id a userauth signature covers, or None if `data` is not one."""
    ua = parse_userauth(data)
    return ua["sid"] if ua and 16 <= len(ua["sid"]) <= 64 else None


def verify_bind(hostkey, session_id, sig):
    """Check an OpenSSH session-bind: `sig` is the server host key's signature
    over the session identifier. Returns (fingerprint, key type); raises
    SshKeyError. A valid bind proves the peer ssh talked to holds that host key;
    it says nothing about whether that is the host the user meant."""
    ktype = _blob_type(hostkey)
    if ktype not in _HOSTKEY_TYPES or not 16 <= len(session_id) <= 64:
        raise SshKeyError("unsupported host key or session id")
    try:
        pub = serialization.load_ssh_public_key(ktype.encode() + b" " + base64.b64encode(hostkey))
        r = _Reader(sig)
        algo, raw = r.string(), r.string()
        if r.i != len(sig):
            raise SshKeyError("trailing bytes in signature")
        if isinstance(pub, ed25519.Ed25519PublicKey):
            if algo != b"ssh-ed25519":
                raise SshKeyError("signature algorithm does not match the host key")
            pub.verify(raw, session_id)
        elif isinstance(pub, rsa.RSAPublicKey):
            if algo not in _RSA_SIG:
                raise SshKeyError("signature algorithm does not match the host key")
            pub.verify(raw, session_id, padding.PKCS1v15(), _RSA_SIG[algo])
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if algo != ktype.encode():
                raise SshKeyError("signature algorithm does not match the host key")
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            ir = _Reader(raw)
            rr, ss = ir.string(), ir.string()
            h = {"nistp256": hashes.SHA256(), "nistp384": hashes.SHA384(),
                 "nistp521": hashes.SHA512()}[ktype.rsplit("-", 1)[1]]
            pub.verify(encode_dss_signature(int.from_bytes(rr, "big"), int.from_bytes(ss, "big")),
                       session_id, ec.ECDSA(h))
        else:
            raise SshKeyError("unsupported host key")
    except SshKeyError:
        raise
    except Exception:  # noqa: BLE001 -- bad signature, bad key bytes, short reads
        raise SshKeyError("host key signature does not verify") from None
    return fingerprint(hostkey), ktype


def parse_known_hosts(lines):
    """Plain known_hosts lines -> {fingerprint: [names]}. Hashed (|1|...) names,
    wildcard/negated patterns, @markers and unparseable lines are ignored."""
    out = {}
    for line in lines:
        f = str(line).split()
        if len(f) < 3 or f[0].startswith(("#", "@", "|")) or f[1] not in _HOSTKEY_TYPES:
            continue
        try:
            blob = base64.b64decode(f[2], validate=True)
        except ValueError:
            continue
        if _blob_type(blob) != f[1]:
            continue
        for n in f[0].split(","):
            n = n.strip().lower()
            if n.startswith("[") and "]:" in n:             # [host]:port
                host, _, port = n[1:].partition("]:")
                n = host if port == "22" else f"{host}:{port}"
            if n and not n.startswith(("|", "!")) and not any(c in n for c in "*?"):
                names = out.setdefault(fingerprint(blob), [])
                if n not in names and len(names) < 20:
                    names.append(n)
    return out


def _hop(h):
    out = f"{h['fp']} ({h['type']})"
    if h.get("names"):
        out += " [" + ", ".join(h["names"]) + "]"
    return out + (" (forwarding)" if h.get("forwarding") else "")


def host_lines(host):
    """Plain-text lines describing the server side of an ssh_sign request (the
    caller escapes them). `host` is the request's spec["host"] dict or None."""
    if not host:
        return []
    out = []
    if host.get("fp"):
        label = "Server" if host.get("bound") else "Server (host key in the signed login data)"
        line = f"{label}: {host['fp']} ({host['type']})"
        if host.get("names"):
            line += " - known as " + ", ".join(host["names"])
        out.append(line)
    else:
        why = (" (the connection sent an invalid session bind)" if host.get("bind_invalid") else
               " (the bind is for an earlier hop, not this login)" if host.get("chain_mismatch") else "")
        out.append("Server identity not verified" + why)
    hops = host.get("hops") or []
    if host.get("forwarding"):
        out.append("Agent forwarded through: " + " -> ".join(_hop(h) for h in hops))
    elif len(hops) > 1:
        out.append("Bind chain: " + " -> ".join(_hop(h) for h in hops))
    if host.get("claimed"):
        out.append(f"Destination (claimed by the client): {host['claimed']}")
    if host.get("forwarding"):
        out.append("Agent forwarding: this key may be used from the remote host")
    return out
