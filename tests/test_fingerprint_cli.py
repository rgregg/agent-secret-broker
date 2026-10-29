"""`asb fingerprint HOST[:PORT]`: black-box, so it checks the Python client and (through
tools/run_tests_against_rust_cli.py) the Rust one. It needs no broker: a local TLS server with a self-signed
certificate is the whole fixture."""
import datetime
import hashlib
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "asb")


def self_signed():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device.invalid")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert, key


class Fingerprint(unittest.TestCase):
    def serve(self):
        cert, key = self_signed()
        d = tempfile.mkdtemp()
        crt, pem = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(crt, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(pem, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, pem)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        self.addCleanup(srv.close)

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(c, server_side=True):
                        pass
                except (OSError, ssl.SSLError):
                    pass
        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1], hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    def asb(self, *argv):
        return subprocess.run([sys.executable, "-I", CLI, "fingerprint", *argv], capture_output=True, text=True,
                              timeout=60, env={"PATH": os.environ["PATH"], "HOME": tempfile.mkdtemp()})

    def test_prints_the_sha256_of_a_self_signed_certificate(self):
        port, want = self.serve()
        p = self.asb(f"127.0.0.1:{port}")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, f"sha256:{want}\n")
        self.assertIn("tls_fingerprint", p.stderr)

    def test_a_closed_port_says_so_and_prints_nothing(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        p = self.asb(f"127.0.0.1:{port}")
        self.assertEqual((p.returncode, p.stdout), (2, ""))
        self.assertTrue(p.stderr.startswith(f"asb: could not read a certificate from 127.0.0.1:{port}: "), p.stderr)

    def test_a_server_that_does_not_speak_tls_is_not_a_certificate(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def talk():
            c, _ = srv.accept()
            c.sendall(b"SSH-2.0-not-tls\r\n")
            c.close()
        threading.Thread(target=talk, daemon=True).start()
        p = self.asb(f"127.0.0.1:{srv.getsockname()[1]}")
        self.assertEqual((p.returncode, p.stdout), (2, ""))
        self.assertIn("could not read a certificate from", p.stderr)

    def test_a_port_that_is_not_a_number(self):
        p = self.asb("127.0.0.1:https")
        self.assertEqual((p.returncode, p.stdout), (2, ""))
        self.assertIn("could not read a certificate from 127.0.0.1:https: ", p.stderr)

    def test_wrong_argument_count_is_usage(self):
        for argv in ([], ["a", "b"]):
            p = self.asb(*argv)
            self.assertEqual(p.returncode, 2)
            self.assertIn("usage: asb fingerprint", p.stderr)


if __name__ == "__main__":
    unittest.main()
