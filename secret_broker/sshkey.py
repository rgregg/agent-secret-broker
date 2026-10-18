"""SSH keys held by the broker: parse, sign, and describe what is being signed.

The private key never leaves the broker. A client (`asb ssh-agent`) forwards the
ssh-agent SIGN_REQUEST payload; the broker signs it and returns the signature
blob in ssh-agent wire format.

Only unencrypted OpenSSH-format keys are accepted: the broker is the thing
protecting the key, so a passphrase would have nowhere to come from.
"""
import base64
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
        raise SshKeyError(f"not an unencrypted OpenSSH private key: {str(e)[:80]}") from None
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


def describe_data(data):
    """What is being signed, as far as it can be told, for the approval prompt.

    Returns {"kind", "text"}. The data is client-supplied, so this is what the
    bytes *say*, not a promise about the connection they belong to: an ssh
    userauth blob carries the account name but not the host being logged in to.
    """
    if data.startswith(b"SSHSIG"):
        try:
            r = _Reader(data[6:])
            ns = _shown(r.string())
            return {"kind": "sshsig", "text": f"sign a message (namespace {ns}, e.g. git commit signing)"}
        except (IndexError, struct.error):
            return {"kind": "sshsig", "text": "sign a message (SSHSIG)"}
    try:
        r = _Reader(data)
        r.string()                      # session id
        if r.byte() == 50:              # SSH_MSG_USERAUTH_REQUEST
            user, service, method = _shown(r.string()), _shown(r.string()), r.string()
            if method == b"publickey":
                return {"kind": "userauth",
                        "text": f"log in over SSH as {user} (service {service}, "
                                "both client-supplied); host not shown by SSH"}
    except (IndexError, struct.error):
        pass
    return {"kind": "unknown", "text": f"sign {len(data)} unrecognised bytes"}
