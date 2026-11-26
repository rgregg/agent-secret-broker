"""approver_api OIDC config parsing and JWT verification (no network: fetch_json is injected)."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from secret_broker import destguard, oidc  # noqa: E402

ISSUER = "https://idp.example.com/realms/home"
CLIENT = "asb-approver"
NOW = 1_800_000_000.0


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64int(n, length=None):
    length = length or (n.bit_length() + 7) // 8
    return b64(n.to_bytes(length, "big"))


class Key:
    """One signing key plus its JWK and a token minter."""

    def __init__(self, kid, kind="RS256"):
        self.kid, self.kind = kid, kind
        if kind == "RS256":
            self.priv = rsa.generate_private_key(65537, 2048)
            n = self.priv.public_key().public_numbers()
            self.jwk = {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                        "n": b64int(n.n), "e": b64int(n.e)}
        else:
            self.priv = ec.generate_private_key(ec.SECP256R1())
            n = self.priv.public_key().public_numbers()
            self.jwk = {"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
                        "x": b64int(n.x, 32), "y": b64int(n.y, 32)}

    def sign(self, data):
        if self.kind == "RS256":
            return self.priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
        r, s = decode_dss_signature(self.priv.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def token(self, claims=None, header=None):
        c = {"iss": ISSUER, "aud": CLIENT, "preferred_username": "ryan", "exp": NOW + 600,
             "iat": NOW}
        c.update(claims or {})
        h = {"alg": self.kind, "typ": "JWT", "kid": self.kid}
        h.update(header or {})
        signing = b64(json.dumps(h).encode()) + "." + b64(json.dumps(c).encode())
        return signing + "." + b64(self.sign(signing.encode()))


DISCOVERY = ISSUER + "/.well-known/openid-configuration"
JWKS = ISSUER + "/protocol/certs"


class Env:
    """fetch_json stub keyed by URL, a movable clock and a fetch log."""

    def __init__(self, *keys):
        self.now = NOW
        self.fetched = []
        self.set_keys(*keys)

    def set_keys(self, *keys):
        self.docs = {DISCOVERY: {"issuer": ISSUER, "jwks_uri": JWKS},
                     JWKS: {"keys": [k.jwk for k in keys]}}

    def fetch(self, url):
        self.fetched.append(url)
        d = self.docs[url]
        if isinstance(d, Exception):
            raise d
        return d

    def clock(self):
        return self.now

    def verifier(self, **cfg):
        raw = {"issuer": ISSUER, "client_id": CLIENT}
        raw.update(cfg)
        return oidc.Verifier(oidc.parse_config(raw, "ryan"), fetch_json=self.fetch,
                             clock=self.clock)


class ParseConfigTests(unittest.TestCase):
    def test_parse_none_is_none(self):
        self.assertIsNone(oidc.parse_config(None, "ryan"))

    def test_parse_defaults(self):
        c = oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT}, "ryan")
        self.assertEqual(c["audience"], CLIENT)
        self.assertEqual(c["username_claim"], "preferred_username")
        self.assertEqual(c["scopes"], ["openid", "profile", "offline_access"])
        self.assertIsNone(c["required_group"])
        self.assertIsNone(c["actions"])
        self.assertEqual(c["allowed_user"], "ryan")

    def test_parse_full(self):
        c = oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT, "audience": "x",
                               "username_claim": "email", "required_group": "approvers",
                               "scopes": ["openid"], "actions": {"approve_max_risk": "low"}},
                              "ryan")
        self.assertEqual(c["audience"], "x")
        self.assertEqual(c["actions"], {"approve_max_risk": "low", "deny": True})

    def test_parse_rejects_http_issuer(self):
        with self.assertRaises(ValueError) as cm:
            oidc.parse_config({"issuer": "http://idp.example.com", "client_id": CLIENT}, "ryan")
        self.assertIn("approver_api.issuer", str(cm.exception))

    def test_parse_rejects_unknown_key(self):
        with self.assertRaises(ValueError) as cm:
            oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT, "bogus": 1}, "ryan")
        self.assertIn("approver_api.bogus", str(cm.exception))

    def test_parse_rejects_bad_fields(self):
        for raw, field in (({"issuer": ISSUER}, "approver_api.client_id"),
                           ({"issuer": ISSUER, "client_id": CLIENT, "scopes": "openid"},
                            "approver_api.scopes"),
                           ({"issuer": ISSUER, "client_id": CLIENT, "required_group": 3},
                            "approver_api.required_group"),
                           ({"issuer": ISSUER, "client_id": CLIENT, "actions": {"deny": 1}},
                            "approver_api.actions")):
            with self.assertRaises(ValueError) as cm:
                oidc.parse_config(raw, "ryan")
            self.assertIn(field, str(cm.exception))
        with self.assertRaises(ValueError):
            oidc.parse_config([], "ryan")


class ConfigRulesTests(unittest.TestCase):
    def tearDown(self):
        destguard.allow_loopback_for_tests(False)

    def test_allowed_user_required(self):
        for bad in (None, "", 5):
            with self.assertRaises(ValueError) as cm:
                oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT}, bad)
            self.assertIn("allowed_user", str(cm.exception))

    def test_loopback_http_issuer_only_under_test_allowance(self):
        raw = {"issuer": "http://127.0.0.1:8080/realm", "client_id": CLIENT}
        with self.assertRaises(ValueError):
            oidc.parse_config(raw, "ryan")
        destguard.allow_loopback_for_tests(True)
        self.assertEqual(oidc.parse_config(raw, "ryan")["issuer"], raw["issuer"])
        for host in ("localhost", "[::1]"):
            oidc.parse_config({"issuer": f"http://{host}:1/r", "client_id": CLIENT}, "ryan")
        with self.assertRaises(ValueError):
            oidc.parse_config({"issuer": "http://idp.example.com", "client_id": CLIENT}, "ryan")

    def test_username_claim_must_be_a_short_identifier(self):
        for bad in ("a b", "x" * 65, "a/b", ""):
            with self.assertRaises(ValueError) as cm:
                oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT,
                                   "username_claim": bad}, "ryan")
            self.assertIn("approver_api.username_claim", str(cm.exception))

    def test_http_jwks_uri_makes_refresh_fail(self):
        k = Key("k")
        env = Env(k)
        env.docs[DISCOVERY]["jwks_uri"] = "http://idp.example.com/certs"
        env.docs["http://idp.example.com/certs"] = {"keys": [k.jwk]}
        v = env.verifier()
        self.assertFalse(v.refresh())
        self.assertEqual(v.verify(k.token()), (None, "jwks_unavailable"))
        destguard.allow_loopback_for_tests(True)
        env.docs[DISCOVERY]["jwks_uri"] = "http://127.0.0.1:9/certs"
        env.docs["http://127.0.0.1:9/certs"] = {"keys": [k.jwk]}
        self.assertTrue(v.refresh())

    def test_missing_username_never_matches_a_missing_allowed_user(self):
        k = Key("k")
        env = Env(k)
        cfg = oidc.parse_config({"issuer": ISSUER, "client_id": CLIENT}, "ryan")
        del cfg["allowed_user"]
        v = oidc.Verifier(cfg, fetch_json=env.fetch, clock=env.clock)
        claims = {"preferred_username": None}
        self.assertEqual(v.verify(k.token(claims)), (None, "user"))
        cfg["allowed_user"] = None
        self.assertEqual(v.verify(k.token(claims)), (None, "user"))
        cfg["allowed_user"] = "ryan"
        self.assertEqual(v.verify(k.token({"preferred_username": ""})), (None, "user"))

    def test_hostile_tokens_are_malformed_not_exceptions(self):
        k = Key("k")
        v = Env(k).verifier()
        deep = b"[" * 5000                      # token stays under the cap
        hdr = b64(deep) + "." + b64(b"{}") + ".AA"
        signing = b64(json.dumps({"alg": "RS256", "kid": "k"}).encode()) + "." + b64(deep)
        pay = signing + "." + b64(k.sign(signing.encode()))   # validly signed, hostile payload
        hdr_ok = {"alg": "RS256", "kid": "k"}
        for tok, effects in ((hdr, [RecursionError()]), (pay, [hdr_ok, RecursionError()])):
            self.assertLessEqual(len(tok), oidc.MAX_TOKEN)
            self.assertEqual(v.verify(tok), (None, "malformed"))
            # CPython 3.12's C JSON scanner does not hit RecursionError on <= 6000 levels (it
            # needs ~20000, far over the cap), so force the exception to exercise the catch.
            with mock.patch.object(oidc.json, "loads", side_effect=effects):
                self.assertEqual(v.verify(tok), (None, "malformed"))

    def test_over_cap_token_is_malformed(self):
        self.assertEqual(Env(Key("k")).verifier().verify("a" * (oidc.MAX_TOKEN + 1)),
                         (None, "malformed"))


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa = Key("k-rsa", "RS256")
        cls.ec = Key("k-ec", "ES256")

    def setUp(self):
        self.env = Env(self.rsa, self.ec)

    def check(self, token, want, **cfg):
        claims, reason = self.env.verifier(**cfg).verify(token)
        self.assertEqual(reason, want, claims)
        if want is None:
            self.assertIsInstance(claims, dict)
        else:
            self.assertIsNone(claims)
        return claims

    def test_rs256_and_es256_accepted(self):
        c = self.check(self.rsa.token(), None)
        self.assertEqual(c["preferred_username"], "ryan")
        self.check(self.ec.token(), None)

    def test_reasons_are_the_fixed_words(self):
        self.assertEqual(oidc.REASONS, ("missing", "malformed", "alg", "signature", "issuer",
                                        "audience", "expired", "user", "group",
                                        "jwks_unavailable"))

    def test_alg_none_and_hs256_refused(self):
        for alg in ("none", "HS256"):
            self.check(self.rsa.token(header={"alg": alg}), "alg")

    def test_alg_key_type_mismatch_is_signature(self):
        # an RS256 header naming the EC key must not verify
        self.check(self.ec.token(header={"alg": "RS256"}), "signature")

    def test_tampered_payload_is_signature(self):
        h, _, s = self.rsa.token().split(".")
        evil = b64(json.dumps({"iss": ISSUER, "aud": CLIENT, "preferred_username": "ryan",
                               "exp": NOW + 99999}).encode())
        self.check(h + "." + evil + "." + s, "signature")

    def test_issuer_must_match_exactly(self):
        self.check(self.rsa.token({"iss": ISSUER + "/"}), "issuer")
        self.check(self.rsa.token({"iss": "https://evil.example.com"}), "issuer")

    def test_audience_and_azp(self):
        self.check(self.rsa.token({"aud": "other"}), "audience")
        # azp counts only next to a list aud; a string aud naming someone else is refused
        self.check(self.rsa.token({"aud": "other", "azp": CLIENT}), "audience")
        self.check(self.rsa.token({"aud": ["x", "y"], "azp": CLIENT}), None)
        self.check(self.rsa.token({"aud": ["x", "y"], "azp": "other"}), "audience")
        self.check(self.rsa.token({"aud": ["x", CLIENT]}), None)
        self.check(self.rsa.token({"aud": ["x", "y"]}), "audience")
        self.check(self.rsa.token({"aud": "other"}), None, audience="other")

    def test_expiry_with_60s_skew(self):
        self.check(self.rsa.token({"exp": NOW - 61}), "expired")
        self.check(self.rsa.token({"exp": NOW - 59}), None)
        self.check(self.rsa.token({"nbf": NOW + 61}), "expired")
        self.check(self.rsa.token({"nbf": NOW + 59}), None)
        h, p, _ = self.rsa.token().split(".")
        claims = json.loads(base64.urlsafe_b64decode(p + "=="))
        del claims["exp"]
        signing = h + "." + b64(json.dumps(claims).encode())
        self.check(signing + "." + b64(self.rsa.sign(signing.encode())), "expired")

    def test_user_must_match(self):
        self.check(self.rsa.token({"preferred_username": "mallory"}), "user")
        self.check(self.rsa.token({"email": "ryan"}), None, username_claim="email")
        self.check(self.rsa.token(), "user", username_claim="email")

    def test_group_required_when_set(self):
        self.check(self.rsa.token({"groups": ["approvers"]}), None, required_group="approvers")
        self.check(self.rsa.token({"groups": ["other"]}), "group", required_group="approvers")
        self.check(self.rsa.token(), "group", required_group="approvers")
        self.check(self.rsa.token({"groups": "approvers"}), "group", required_group="approvers")

    def test_malformed(self):
        for bad in ("a.b", "a.b.c.d", "!!!.@@@.###",
                    self.rsa.token().rsplit(".", 1)[0] + ".%%%"):
            self.check(bad, "malformed")
        self.check("", "missing")
        self.check(b64(b"not json") + "." + b64(b"{}") + "." + b64(b"x"), "malformed")
        self.check(b64(b"[]") + "." + b64(b"{}") + "." + b64(b"x"), "malformed")

    def test_jwks_unavailable(self):
        self.env.docs[DISCOVERY] = OSError("boom")
        self.check(self.rsa.token(), "jwks_unavailable")

    def test_refresh_never_raises_and_reports(self):
        self.assertTrue(self.env.verifier().refresh())
        self.env.docs[DISCOVERY] = ValueError("x")
        self.assertFalse(self.env.verifier().refresh())
        self.env.docs[DISCOVERY] = {"issuer": ISSUER}
        self.assertFalse(self.env.verifier().refresh())

    def test_reason_never_carries_the_token(self):
        t = self.rsa.token()
        _, reason = self.env.verifier().verify(t + "x")
        self.assertIn(reason, oidc.REASONS)


class RotationTests(unittest.TestCase):
    def test_unknown_kid_refetches_once_per_minute(self):
        old, new, newer = Key("old"), Key("new", "ES256"), Key("newer")
        env = Env(old)
        v = env.verifier()
        self.assertTrue(v.refresh())
        self.assertEqual(env.fetched.count(JWKS), 1)

        env.set_keys(old, new)                  # the IdP rotates
        env.now += 61
        claims, reason = v.verify(new.token())
        self.assertEqual((reason, claims["preferred_username"]), (None, "ryan"))
        self.assertEqual(env.fetched.count(JWKS), 2)

        env.set_keys(old, new, newer)           # and again, too soon for a refetch
        env.now += 30
        self.assertEqual(v.verify(newer.token()), (None, "signature"))
        self.assertEqual(env.fetched.count(JWKS), 2)

        env.now += 31                           # 61 s after the last fetch
        self.assertIsNone(v.verify(newer.token())[1])
        self.assertEqual(env.fetched.count(JWKS), 3)

    def test_known_kid_never_refetches(self):
        k = Key("k")
        env = Env(k)
        v = env.verifier()
        v.refresh()
        n = len(env.fetched)
        for _ in range(3):
            self.assertIsNone(v.verify(k.token())[1])
        self.assertEqual(len(env.fetched), n)


if __name__ == "__main__":
    unittest.main()
