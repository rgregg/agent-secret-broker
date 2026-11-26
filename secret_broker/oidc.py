"""OIDC bearer-token validation for the optional `approver_api` (the macOS approver app).

The broker validates the identity provider's JWT itself: discovery document -> JWKS, RS256 and
ES256 only (never `none`, never HMAC), exact `iss`, `aud`/`azp`, `exp`/`nbf` with 60 s skew, the
configured username claim and optional group. Signing keys are cached by `kid`; an unknown `kid`
triggers one JWKS refetch, at most once per 60 s, so a rotating IdP works and a flood of bogus
`kid`s cannot make the broker hammer the IdP.

A token, or any part of one, never goes into an exception message, a reason or a log line.
"""
import base64
import binascii
import json
import re
import threading
import time
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import destguard, notify

REASONS = ("missing", "malformed", "alg", "signature", "issuer", "audience", "expired", "user",
           "group", "jwks_unavailable")

SKEW = 60                # seconds of clock skew allowed on exp / nbf
REFETCH_INTERVAL = 60    # seconds between JWKS fetches triggered by an unknown kid
FETCH_TIMEOUT = 5
MAX_TOKEN = 8192
CLAIM_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "[::1]")
ALGS = ("RS256", "ES256")
DEFAULT_SCOPES = ["openid", "profile", "offline_access"]
_KEYS = ("issuer", "client_id", "audience", "username_claim", "required_group", "scopes", "actions")


def _url_ok(url):
    """https:// always; http:// only to loopback, and only under the test allowance."""
    if url.startswith("https://") and len(url) > len("https://"):
        return True
    if url.startswith("http://") and destguard.test_loopback_allowed():
        host = url[len("http://"):].split("/", 1)[0]
        if host.startswith("["):
            host = host.split("]", 1)[0] + "]"
        else:
            host = host.rsplit(":", 1)[0] if ":" in host else host
        return host in _LOOPBACK_HOSTS
    return False


def parse_config(raw, allowed_user, field="approver_api"):
    """Validate `approver_api` -> dict, or None when not configured. Raises ValueError naming the
    field. `allowed_user` (the broker's configured approver) rides along for the verifier."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    if not isinstance(allowed_user, str) or not allowed_user:
        raise ValueError(f"{field}: allowed_user must be a non-empty string")
    for k in raw:
        if k not in _KEYS:
            raise ValueError(f"{field}.{k} is not a known option")

    def text(key, default=None, required=False):
        v = raw.get(key, default)
        if v is None and not required:
            return None
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"{field}.{key} must be a non-empty string")
        return v

    issuer = text("issuer", required=True)
    if not _url_ok(issuer):
        raise ValueError(f"{field}.issuer must be an https:// URL")
    client_id = text("client_id", required=True)
    username_claim = text("username_claim", "preferred_username")
    if not CLAIM_RE.match(username_claim):
        raise ValueError(f"{field}.username_claim must be 1-64 chars of A-Za-z0-9_.:-")
    scopes = raw.get("scopes", list(DEFAULT_SCOPES))
    if (not isinstance(scopes, list) or not scopes
            or not all(isinstance(s, str) and s and " " not in s for s in scopes)):
        raise ValueError(f"{field}.scopes must be a list of scope names")
    actions = raw.get("actions")
    return {
        "issuer": issuer,
        "client_id": client_id,
        "audience": text("audience", client_id),
        "username_claim": username_claim,
        "required_group": text("required_group"),
        "scopes": list(scopes),
        "actions": None if actions is None else notify.parse_action_policy(actions, f"{field}.actions"),
        "allowed_user": allowed_user,
    }


def default_fetch_json(url):
    """GET `url` and decode JSON. Operator-configured target: goes through destguard like the
    other operator-configured outbound calls (no proxy, egress marker set)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with destguard.operator_urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return json.loads(r.read(1 << 20))


def _b64d(s):
    """Strict base64url (unpadded). urlsafe_b64decode alone silently drops stray characters."""
    if not isinstance(s, str) or not all(c.isascii() and (c.isalnum() or c in "-_") for c in s):
        raise ValueError("not base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except binascii.Error:
        raise ValueError("not base64url") from None


def _jwk_to_key(jwk):
    """(kind, public key) for a usable RSA or P-256 JWK, else None."""
    try:
        if jwk.get("use") not in (None, "sig"):
            return None
        if jwk["kty"] == "RSA":
            n, e = int.from_bytes(_b64d(jwk["n"]), "big"), int.from_bytes(_b64d(jwk["e"]), "big")
            return "RS256", rsa.RSAPublicNumbers(e, n).public_key()
        if jwk["kty"] == "EC" and jwk.get("crv") == "P-256":
            x, y = int.from_bytes(_b64d(jwk["x"]), "big"), int.from_bytes(_b64d(jwk["y"]), "big")
            return "ES256", ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except (KeyError, ValueError, TypeError):
        pass
    return None


class Verifier:
    def __init__(self, cfg, fetch_json=None, clock=time.time):
        self.cfg = cfg
        self._fetch = fetch_json or default_fetch_json
        self._clock = clock
        self._lock = threading.Lock()
        self._keys = {}              # kid -> (kind, public key)
        self._last_fetch = None      # clock time of the last JWKS attempt

    def refresh(self):
        """Fetch discovery + JWKS and replace the key cache. Never raises; True on success."""
        with self._lock:
            return self._refresh_locked()

    def _refresh_locked(self):
        self._last_fetch = self._clock()
        try:
            disc = self._fetch(self.cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration")
            uri = disc["jwks_uri"]
            if not isinstance(uri, str) or not _url_ok(uri):
                return False
            doc = self._fetch(uri)
            keys = {}
            for jwk in doc["keys"]:
                got = _jwk_to_key(jwk) if isinstance(jwk, dict) else None
                kid = jwk.get("kid") if isinstance(jwk, dict) else None
                if got and isinstance(kid, str):
                    keys[kid] = got
        except Exception:    # noqa: BLE001  (network, JSON, shape: all just "unavailable")
            return False
        self._keys = keys
        return True

    def _key_for(self, kid):
        """-> (key or None, jwks_unavailable). Refetches an unknown kid at most once a minute."""
        with self._lock:
            got = self._keys.get(kid)
            if got:
                return got, False
            now = self._clock()
            if self._last_fetch is None or now - self._last_fetch >= REFETCH_INTERVAL:
                self._refresh_locked()
                got = self._keys.get(kid)
            return got, not self._keys

    def verify(self, token):
        """-> (claims, None) or (None, reason) with reason one of REASONS."""
        if not isinstance(token, str) or not token:
            return None, "missing"
        if len(token) > MAX_TOKEN:
            return None, "malformed"
        try:
            return self._verify(token)
        except (ValueError, RecursionError, TypeError, AttributeError):
            return None, "malformed"

    def _verify(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return None, "malformed"
        try:
            header = json.loads(_b64d(parts[0]))
            sig = _b64d(parts[2])
            raw_claims = _b64d(parts[1])
        except ValueError:
            return None, "malformed"
        if not isinstance(header, dict):
            return None, "malformed"
        alg = header.get("alg")
        if alg not in ALGS:
            return None, "alg"
        kid = header.get("kid")
        if not isinstance(kid, str):
            return None, "malformed"

        key, unavailable = self._key_for(kid)
        if key is None:
            return None, "jwks_unavailable" if unavailable else "signature"
        kind, pub = key
        if kind != alg or not self._signature_ok(pub, alg, (parts[0] + "." + parts[1]).encode(), sig):
            return None, "signature"

        try:
            claims = json.loads(raw_claims)
        except ValueError:
            return None, "malformed"
        if not isinstance(claims, dict):
            return None, "malformed"
        return self._check_claims(claims)

    @staticmethod
    def _signature_ok(pub, alg, data, sig):
        try:
            if alg == "RS256":
                pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
            else:
                if len(sig) != 64:
                    return False
                der = encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                           int.from_bytes(sig[32:], "big"))
                pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def _check_claims(self, claims):
        cfg = self.cfg
        if claims.get("iss") != cfg["issuer"]:
            return None, "issuer"
        aud = claims.get("aud")
        if isinstance(aud, list):       # azp stands in only next to a list aud
            ok = cfg["audience"] in aud or claims.get("azp") == cfg["audience"]
        else:
            ok = aud == cfg["audience"]
        if not ok:
            return None, "audience"
        now = self._clock()
        exp, nbf = claims.get("exp"), claims.get("nbf")
        if not _is_num(exp) or exp < now - SKEW:
            return None, "expired"
        if nbf is not None and (not _is_num(nbf) or nbf > now + SKEW):
            return None, "expired"
        who = claims.get(cfg["username_claim"])
        if not isinstance(who, str) or not who or who != cfg.get("allowed_user"):
            return None, "user"
        group = cfg["required_group"]
        if group is not None:
            groups = claims.get("groups")
            if not isinstance(groups, list) or group not in groups:
                return None, "group"
        return claims, None


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)
