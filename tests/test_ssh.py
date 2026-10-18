import base64
import importlib.machinery
import importlib.util
import json
import os
import struct
import sys
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import sshkey  # noqa: E402
from test_e2e import KEY, Harness  # noqa: E402


def _openssh(key, password=None):
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, enc).decode()


def _encrypted_pem():
    """A passphrase-protected key made by ssh-keygen (cryptography needs bcrypt to do it)."""
    import shutil
    import subprocess
    import tempfile
    if not shutil.which("ssh-keygen"):
        raise unittest.SkipTest("ssh-keygen not available")
    d = tempfile.mkdtemp()
    f = os.path.join(d, "k")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "pw", "-f", f], check=True)
    with open(f) as fh:
        return fh.read()


def _s(b):
    return struct.pack(">I", len(b)) + b


def _read_string(b, i):
    n = struct.unpack_from(">I", b, i)[0]
    return b[i + 4:i + 4 + n], i + 4 + n


def userauth_blob(user="deploy", service="ssh-connection"):
    return (_s(b"S" * 32) + bytes([50]) + _s(user.encode()) + _s(service.encode())
            + _s(b"publickey") + b"\x01" + _s(b"ssh-ed25519") + _s(b"K" * 51))


class Signing(unittest.TestCase):
    def test_ed25519_signature_verifies(self):
        k = ed25519.Ed25519PrivateKey.generate()
        key = sshkey.load_private(_openssh(k))
        algo, i = _read_string(sshkey.sign(key, b"hello"), 0)
        sig, _ = _read_string(sshkey.sign(key, b"hello"), i)
        self.assertEqual(algo, b"ssh-ed25519")
        k.public_key().verify(sig, b"hello")

    def test_rsa_needs_sha2_flag_and_verifies(self):
        k = rsa.generate_private_key(65537, 2048)
        key = sshkey.load_private(_openssh(k))
        with self.assertRaises(sshkey.SshKeyError):
            sshkey.sign(key, b"x", 0)                       # SHA-1 ssh-rsa is refused
        blob = sshkey.sign(key, b"hello", sshkey.SIGN_RSA_SHA2_512)
        algo, i = _read_string(blob, 0)
        sig, _ = _read_string(blob, i)
        self.assertEqual(algo, b"rsa-sha2-512")
        k.public_key().verify(sig, b"hello", padding.PKCS1v15(), hashes.SHA512())

    def test_ecdsa_signature_verifies(self):
        k = ec.generate_private_key(ec.SECP256R1())
        key = sshkey.load_private(_openssh(k))
        blob = sshkey.sign(key, b"hello")
        algo, i = _read_string(blob, 0)
        inner, _ = _read_string(blob, i)
        r, j = _read_string(inner, 0)
        s_, _ = _read_string(inner, j)
        self.assertEqual(algo, b"ecdsa-sha2-nistp256")
        k.public_key().verify(encode_dss_signature(int.from_bytes(r, "big"), int.from_bytes(s_, "big")),
                              b"hello", ec.ECDSA(hashes.SHA256()))

    def test_public_line_matches_openssh_format(self):
        k = ed25519.Ed25519PrivateKey.generate()
        want = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        self.assertEqual(sshkey.public_line(sshkey.load_private(_openssh(k))), want.decode())
        r = rsa.generate_private_key(65537, 2048)
        want = r.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        self.assertEqual(sshkey.public_line(sshkey.load_private(_openssh(r))), want.decode())

    def test_encrypted_and_garbage_keys_are_rejected(self):
        k = ed25519.Ed25519PrivateKey.generate()
        for bad in (_encrypted_pem(), "not a key"):
            with self.assertRaises(sshkey.SshKeyError):
                sshkey.load_private(bad)

    def test_describe_data(self):
        self.assertIn("'deploy'", sshkey.describe_data(userauth_blob())["text"])
        sshsig = b"SSHSIG" + _s(b"git") + _s(b"") + _s(b"sha512") + _s(b"h" * 64)
        self.assertEqual(sshkey.describe_data(sshsig)["kind"], "sshsig")
        self.assertEqual(sshkey.describe_data(b"junk")["kind"], "unknown")

    def test_client_text_in_the_prompt_is_escaped_and_bounded(self):
        evil = userauth_blob(user="root\nAPPROVED by admin" + "x" * 500, service="a\x1b[2Jb")
        text = sshkey.describe_data(evil)["text"]
        self.assertNotIn("\n", text)
        self.assertNotIn("\x1b", text)
        self.assertLess(len(text), 200)
        self.assertIn("client-supplied", text)


class BitwardenSshItem(unittest.TestCase):
    """The key lives in a native Bitwarden SSH key item (type 5), not a note."""

    def setUp(self):
        self.pem = _openssh(ed25519.Ed25519PrivateKey.generate())
        self.pub = sshkey.public_line(sshkey.load_private(self.pem))

    def test_store_builds_an_ssh_key_item(self):
        from secret_broker.backends import BwBackend
        obj = BwBackend._template("deploy", "private_key", self.pem, "org", "coll",
                                  {"ssh": True, "ssh_public_key": self.pub})
        self.assertEqual(obj["type"], 5)
        self.assertEqual(obj["sshKey"]["privateKey"], self.pem)
        self.assertEqual(obj["sshKey"]["publicKey"], self.pub)
        self.assertEqual(obj["sshKey"]["keyFingerprint"],
                         sshkey.fingerprint(sshkey.blob_from_line(self.pub)))
        self.assertNotIn("secureNote", obj)
        self.assertIsNone(obj["notes"])

    def test_reads_and_updates_the_private_key_field(self):
        from secret_broker.backends import BwBackend
        obj = {"name": "deploy", "type": 5, "sshKey": {"privateKey": "old", "publicKey": self.pub}}
        self.assertEqual(BwBackend._auto_field(obj), "private_key")
        BwBackend._apply(obj, "auto", self.pem, keep_previous=True)
        self.assertEqual(obj["sshKey"]["privateKey"], self.pem)
        self.assertEqual({f["name"]: f["value"] for f in obj["fields"]}["previous_value"], "old")

    def test_existing_bitwarden_ssh_items_are_adopted_as_signing_only(self):
        from secret_broker.backends import _auto_info
        from secret_broker.broker import Broker
        info = _auto_info({"type": 5, "name": "My Key",
                           "sshKey": {"privateKey": self.pem, "publicKey": self.pub + " me@laptop"}})
        meta = Broker._auto_meta("My Key", info)
        self.assertTrue(meta["ssh"])
        self.assertEqual(meta["vars"], {"MY_KEY_SSH_KEY": {"field": "private_key"}})
        name, entry = Broker._entry("My Key", meta)
        self.assertEqual(name, "my-key")
        self.assertTrue(entry["ssh"])
        self.assertIsNone(_auto_info({"type": 5, "sshKey": {"privateKey": self.pem}}))

    def test_ssh_secret_cannot_point_at_a_note(self):
        from secret_broker.broker import Broker
        with self.assertRaises(ValueError):
            Broker._entry("k", {"ssh": True, "ssh_public_key": self.pub,
                                "vars": {"K_SSH_KEY": {"field": "notes"}}})


class BrokerSsh(Harness):
    privkey = ed25519.Ed25519PrivateKey.generate()

    def tweak(self, cfg):
        pem = _openssh(self.privkey)
        cfg["_vault"] = {"Deploykey": {"private_key": pem}}
        cfg["secrets"]["deploy"] = {
            "vars": {"DEPLOY_SSH_KEY": {"item": "Deploykey", "field": "private_key"}},
            "allowed_hosts": [], "ssh": True,
            "ssh_public_key": sshkey.public_line(sshkey.load_private(pem))}

    def sign(self, data, flags=0, names=("deploy",)):
        return self.api("POST", "/v1/requests", {"mode": "ssh_sign", "names": list(names), "flags": flags,
                                                 "data_b64": base64.b64encode(data).decode()})

    def test_discovery_lists_the_public_key_and_no_vars(self):
        _, body = self.api("GET", "/v1/secrets")
        row = next(s for s in json.loads(body)["secrets"] if s["name"] == "deploy")
        self.assertEqual(row["vars"], [])
        self.assertTrue(row["ssh_public_key"].startswith("ssh-ed25519 "))

    def test_approved_sign_returns_a_valid_signature_and_no_key(self):
        code, body = self.sign(userauth_blob())
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        got = json.loads(b)
        self.assertEqual(got["status"], "approved")
        blob = base64.b64decode(got["ssh_signature"])
        _, i = _read_string(blob, 0)
        sig, _ = _read_string(blob, i)
        self.privkey.public_key().verify(sig, userauth_blob())
        with open(self.audit) as f:
            text = f.read()
        self.assertIn('"event": "ssh_signed"', text)
        self.assertIn("log in over SSH as", text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn(got["ssh_signature"], text)
        self.assertIn("log in over SSH", self.notifier.sent[0]["message"])

    def test_ssh_key_cannot_be_released_or_templated(self):
        self.assertEqual(self.create_env(["deploy"])[0], 403)
        code, _ = self.api("POST", "/v1/requests", {
            "mode": "http", "names": ["deploy"], "method": "GET", "url": "http://127.0.0.1/",
            "headers": {"X": "{{DEPLOY_SSH_KEY}}"}})
        self.assertEqual(code, 403)

    def test_sign_rejects_non_ssh_secret_bad_data_and_bad_flags(self):
        self.assertEqual(self.sign(b"x", names=("svc",))[0], 400)
        self.assertEqual(self.sign(b"")[0], 400)
        self.assertEqual(self.sign(b"x", flags=999)[0], 400)
        self.assertEqual(self.sign(b"x" * (sshkey.MAX_SIGN_DATA + 1))[0], 400)

    def test_legacy_rsa_flags_on_an_ed25519_key_still_sign(self):
        code, body = self.sign(b"payload", flags=2)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "approved")

    def test_store_ssh_key_records_the_public_key(self):
        k = ed25519.Ed25519PrivateKey.generate()
        code, body = self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["newkey"], "op": "create", "ssh": True, "value": _openssh(k)})
        self.assertEqual(code, 202)
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "approved")
        meta = self.disk()["secrets"]["newkey"]
        self.assertTrue(meta["ssh"])
        self.assertEqual(meta["ssh_public_key"], sshkey.public_line(sshkey.load_private(_openssh(k))))
        self.assertEqual(meta["allowed_hosts"], [])

    def test_store_ssh_rejects_encrypted_key_and_update_with_other_key(self):
        enc = _encrypted_pem()
        self.assertEqual(self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["k2"], "op": "create", "ssh": True, "value": enc})[0], 400)
        self.assertEqual(self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["deploy"], "op": "update",
            "value": _openssh(ed25519.Ed25519PrivateKey.generate())})[0], 400)

    def test_agent_protocol_end_to_end(self):
        os.environ["SECRET_BROKER_URL"], os.environ["SECRET_BROKER_KEY"] = self.base, KEY
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("SECRET_BROKER_URL", "SECRET_BROKER_KEY")])
        path = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
        loader = importlib.machinery.SourceFileLoader("asb_client", path)
        asb = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_client", loader))
        loader.exec_module(asb)
        ids = asb.agent_reply(bytes([asb.AGENTC_REQUEST_IDENTITIES]))
        self.assertEqual(ids[0], asb.AGENT_IDENTITIES_ANSWER)
        self.assertEqual(struct.unpack_from(">I", ids, 1)[0], 1)
        blob, _ = _read_string(ids, 5)
        data = userauth_blob()
        reply = asb.agent_reply(bytes([asb.AGENTC_SIGN_REQUEST]) + _s(blob) + _s(data) + struct.pack(">I", 0))
        self.assertEqual(reply[0], asb.AGENT_SIGN_RESPONSE)
        sigblob, _ = _read_string(reply, 1)
        _, i = _read_string(sigblob, 0)
        sig, _ = _read_string(sigblob, i)
        self.privkey.public_key().verify(sig, data)
        unknown = asb.agent_reply(bytes([asb.AGENTC_SIGN_REQUEST]) + _s(b"nope") + _s(data) + struct.pack(">I", 0))
        self.assertEqual(unknown, bytes([asb.AGENT_FAILURE]))
        self.assertEqual(asb.agent_reply(bytes([99])), bytes([asb.AGENT_FAILURE]))


class BrokerSshDenied(BrokerSsh):
    decision = "deny"

    def test_denied_sign_returns_failure_to_the_agent(self):
        os.environ["SECRET_BROKER_URL"], os.environ["SECRET_BROKER_KEY"] = self.base, KEY
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("SECRET_BROKER_URL", "SECRET_BROKER_KEY")])
        code, body = self.sign(b"x")
        _, b = self.api("GET", f"/v1/requests/{json.loads(body)['id']}?wait=5")
        self.assertEqual(json.loads(b)["status"], "denied")

    # the inherited approve-path tests do not apply when the phone says no
    test_approved_sign_returns_a_valid_signature_and_no_key = None
    test_legacy_rsa_flags_on_an_ed25519_key_still_sign = None
    test_store_ssh_key_records_the_public_key = None
    test_agent_protocol_end_to_end = None


if __name__ == "__main__":
    unittest.main()
