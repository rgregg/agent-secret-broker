"""`asb ssh-agent` on the wire: the real CLI serving the ssh-agent protocol on a socket, against a real broker.

Black-box (it runs the CLI as a subprocess), so the same tests check the Python client and, through
tools/run_tests_against_rust_cli.py, the Rust one. The unit tests that call `agent_reply` directly cover the Python
functions only; this covers what a real `ssh` would see.
"""
import _fast  # noqa: F401
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_ssh as ts  # noqa: E402
import test_ssh_host as th  # noqa: E402
from secret_broker import sshkey  # noqa: E402

CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client", "asb")
_s = ts._s
FAIL, SUCCESS, IDS, SIGN, SIGNED = 5, 6, 12, 14, 14


def framed(sock, payload):
    sock.sendall(_s(payload))
    head = sock.recv(4)
    n = struct.unpack(">I", head)[0]
    buf = b""
    while len(buf) < n:
        buf += sock.recv(n - len(buf))
    return buf


class WireBase(th.HostBase):
    decision = "approve"

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        os.chmod(self.dir, 0o700)
        self.sock = os.path.join(self.dir, "agent.sock")
        self.home = tempfile.mkdtemp()
        self.env = {"PATH": os.environ["PATH"], "HOME": self.home, "SECRET_BROKER_URL": self.base,
                    "SECRET_BROKER_KEY": th.KEY}

    def start(self, *argv):
        p = subprocess.Popen([sys.executable, "-I", CLI, "ssh-agent", *argv], env=self.env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: p.poll() is None and p.kill())
        return p

    def wait_for(self, path):
        for _ in range(200):
            probe = socket.socket(socket.AF_UNIX)
            try:
                probe.connect(path)
                return
            except OSError:
                time.sleep(0.05)
            finally:
                probe.close()
        self.fail("agent socket never appeared")

    def connect(self):
        p = self.start("--socket", self.sock)
        self.wait_for(self.sock)
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(30)
        c.connect(self.sock)
        self.addCleanup(c.close)
        self.addCleanup(lambda: p.poll() is None and (p.terminate(), p.wait(10)))
        return c

    def blob(self, c):
        ids = framed(c, bytes([11]))
        self.assertEqual(ids[0], IDS)
        self.assertEqual(struct.unpack_from(">I", ids, 1)[0], 1)
        blob, i = ts._read_string(ids, 5)
        comment, _ = ts._read_string(ids, i)
        self.assertEqual(comment, b"broker:deploy")
        return blob

    def sign_request(self, blob, data, flags=0):
        return bytes([13]) + _s(blob) + _s(data) + struct.pack(">I", flags)

    def verify(self, reply, data):
        self.assertEqual(reply[0], SIGNED)
        sigblob, _ = ts._read_string(reply, 1)
        _, i = ts._read_string(sigblob, 0)
        sig, _ = ts._read_string(sigblob, i)
        self.privkey.public_key().verify(sig, data)


class Wire(WireBase):
    def test_lists_the_brokers_key_and_signs_with_it(self):
        c = self.connect()
        blob = self.blob(c)
        self.assertEqual(blob, sshkey.public_blob(self.privkey))
        data = ts.userauth_blob()
        self.verify(framed(c, self.sign_request(blob, data)), data)

    def test_unknown_keys_and_messages_are_plain_failures(self):
        c = self.connect()
        blob = self.blob(c)
        fail = bytes([FAIL])
        self.assertEqual(framed(c, self.sign_request(b"nope", b"data")), fail)
        self.assertEqual(framed(c, bytes([99])), fail)
        self.assertEqual(framed(c, bytes([27]) + _s(b"query")), fail)             # another extension
        self.assertEqual(framed(c, bytes([13])), fail)                            # truncated sign request
        self.assertEqual(framed(c, bytes([27]) + _s(b"session-bind@openssh.com") + _s(b"short")), fail)
        data = ts.userauth_blob()
        self.verify(framed(c, self.sign_request(blob, data)), data)               # and it still works

    def test_binding_is_bounded_and_failing_binds_do_not_kill_the_connection(self):
        c = self.connect()
        host = th.Host()
        wire = host.wire(th.SID_A)
        self.assertEqual(framed(c, wire[:-1]), bytes([FAIL]))                     # missing flag byte
        self.assertEqual(framed(c, wire + b"x"), bytes([FAIL]))                   # trailing byte
        for _ in range(16):
            self.assertEqual(framed(c, wire), bytes([SUCCESS]))
        self.assertEqual(framed(c, wire), bytes([FAIL]))                          # the 17th is refused
        self.assertEqual(len(self.blob(c)), len(sshkey.public_blob(self.privkey)))

    def test_a_wrapped_ssh_command_gets_the_socket_and_its_claim_reaches_the_broker(self):
        host = th.Host()
        blob = sshkey.public_blob(self.privkey)
        msgs = [host.wire(th.SID_A, True).hex(), self.sign_request(blob, th.login(th.SID_A)).hex()]
        script = os.path.join(self.dir, "ssh")          # basename "ssh": the claim comes from the command line
        out = os.path.join(self.dir, "out.json")
        with open(script, "w") as f:
            f.write(f"""#!{sys.executable}
import json, os, socket, struct
c = socket.socket(socket.AF_UNIX)
c.connect(os.environ["SSH_AUTH_SOCK"])
def ex(m):
    c.sendall(struct.pack(">I", len(m)) + m)
    n = struct.unpack(">I", c.recv(4))[0]
    b = b""
    while len(b) < n:
        b += c.recv(n - len(b))
    return b
replies = [ex(bytes.fromhex(m)).hex() for m in {msgs!r}]
open({out!r}, "w").write(json.dumps({{"replies": replies, "sock": os.environ["SSH_AUTH_SOCK"]}}))
""")
        os.chmod(script, 0o755)
        p = self.start("--", script, "-p", "2200", "deploy@web.example.com", "uptime")
        self.assertEqual(p.wait(60), 0, p.stderr.read())
        with open(out) as f:
            got = json.load(f)
        self.assertEqual(bytes.fromhex(got["replies"][0]), bytes([SUCCESS]))
        self.assertEqual(bytes.fromhex(got["replies"][1])[0], SIGNED)
        ev = self.events("requested")[0]
        self.assertEqual((ev["host_fp"], ev["forwarding"], ev["claimed_dest"]),
                         (host.fp, True, "deploy@web.example.com:2200"))
        self.assertFalse(os.path.exists(os.path.dirname(got["sock"])), "the private socket directory is removed")

    def test_the_commands_exit_status_is_the_agents(self):
        p = self.start("--", "sh", "-c", "exit 7")
        self.assertEqual(p.wait(30), 7)

    def test_the_command_sees_a_private_socket(self):
        script = os.path.join(self.dir, "probe.sh")
        with open(script, "w") as f:
            f.write('#!/bin/sh\nls -ld "$(dirname "$SSH_AUTH_SOCK")" | cut -c1-10\nls -l "$SSH_AUTH_SOCK" | cut -c1-10\n')
        os.chmod(script, 0o755)
        p = self.start("--", script)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(out.split(), ["drwx------", "srw-------"])

    def test_the_eval_form_prints_the_assignment_and_cleans_up_on_sigterm(self):
        p = self.start()
        line = p.stdout.readline().strip()
        self.assertTrue(line.startswith("SSH_AUTH_SOCK=") and line.endswith("; export SSH_AUTH_SOCK;"), line)
        path = line[len("SSH_AUTH_SOCK="):-len("; export SSH_AUTH_SOCK;")]
        self.wait_for(path)
        self.assertTrue(stat.S_ISSOCK(os.stat(path).st_mode))
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(10), 0)
        self.assertFalse(os.path.exists(path))
        self.assertFalse(os.path.exists(os.path.dirname(path)))

    def test_usage_errors(self):
        for argv in (["--socket"], ["x"], ["--"], ["--socket", self.sock, "x"]):
            p = subprocess.run([sys.executable, "-I", CLI, "ssh-agent", *argv], env=self.env,
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 2, argv)
            self.assertIn("usage: asb ssh-agent", p.stderr)


class WireDenied(WireBase):
    decision = "deny"

    def test_a_denied_login_is_a_failure_the_client_sees(self):
        c = self.connect()
        blob = self.blob(c)
        self.assertEqual(framed(c, self.sign_request(blob, ts.userauth_blob())), bytes([FAIL]))



if __name__ == "__main__":
    unittest.main()
