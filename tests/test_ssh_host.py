"""Server identity for SSH signatures: claimed destination, session-bind
verification, known_hosts names and the allowed_hosts policy."""
import base64
import importlib.machinery
import importlib.util
import json
import os
import shlex
import struct
import sys
import unittest
import urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_ssh as ts  # noqa: E402
from secret_broker import sshkey  # noqa: E402
from secret_broker.broker import Broker, _describe  # noqa: E402
from test_e2e import KEY, Harness, req  # noqa: E402

_s = ts._s
SID_A, SID_B = bytes(range(32)), bytes(range(100, 132))


def load_client():
    path = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
    loader = importlib.machinery.SourceFileLoader("asb_client_h", path)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_client_h", loader))
    loader.exec_module(mod)
    return mod


asb = load_client()


class Host:
    """A fake SSH server's host key and the messages it produces."""

    def __init__(self, key=None, rsa_flags=sshkey.SIGN_RSA_SHA2_512):
        self.key = key or ed25519.Ed25519PrivateKey.generate()
        self.flags = rsa_flags
        self.blob = sshkey.public_blob(self.key)
        self.fp = sshkey.fingerprint(self.blob)
        self.type = sshkey.public_line(self.key).split()[0]

    def line(self, names):
        return f"{names} {self.type} {base64.b64encode(self.blob).decode()}"

    def bind(self, sid, forwarding=False, sig=None):
        sig = sig if sig is not None else sshkey.sign(self.key, sid, self.flags)
        return {"hostkey_b64": base64.b64encode(self.blob).decode(),
                "session_id_b64": base64.b64encode(sid).decode(),
                "sig_b64": base64.b64encode(sig).decode(), "forwarding": forwarding}

    def wire(self, sid, forwarding=False, sig=None):
        """The SSH_AGENTC_EXTENSION message OpenSSH sends."""
        sig = sig if sig is not None else sshkey.sign(self.key, sid, self.flags)
        return (bytes([27]) + _s(b"session-bind@openssh.com") + _s(self.blob) + _s(sid) + _s(sig)
                + bytes([1 if forwarding else 0]))


def login(sid, user="deploy"):
    return (_s(sid) + bytes([50]) + _s(user.encode()) + _s(b"ssh-connection")
            + _s(b"publickey") + b"\x01" + _s(b"ssh-ed25519") + _s(b"K" * 51))


def hostbound(sid, host, user="deploy"):
    """Login data of OpenSSH 8.9+ host-bound public key auth."""
    return (_s(sid) + bytes([50]) + _s(user.encode()) + _s(b"ssh-connection")
            + _s(b"publickey-hostbound-v00@openssh.com") + b"\x01" + _s(b"ssh-ed25519")
            + _s(b"K" * 51) + _s(host.blob))


class BindVerification(unittest.TestCase):
    def test_every_host_key_type_verifies(self):
        keys = [ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1()),
                ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP521R1()),
                rsa.generate_private_key(65537, 2048)]
        for k in keys:
            h = Host(k)
            fp, typ = sshkey.verify_bind(h.blob, SID_A, sshkey.sign(k, SID_A, sshkey.SIGN_RSA_SHA2_256))
            self.assertEqual((fp, typ), (h.fp, h.type.replace("ssh-rsa", "ssh-rsa")))

    def test_rsa_sha2_512_and_legacy_sha1_signatures(self):
        k = rsa.generate_private_key(65537, 2048)
        h = Host(k)
        sha1 = _s(b"ssh-rsa") + _s(k.sign(SID_A, padding.PKCS1v15(), hashes.SHA1()))
        for sig in (sshkey.sign(k, SID_A, sshkey.SIGN_RSA_SHA2_512), sha1):
            self.assertEqual(sshkey.verify_bind(h.blob, SID_A, sig)[0], h.fp)

    def test_bad_binds_are_errors(self):
        h, other = Host(), Host()
        good = sshkey.sign(h.key, SID_A)
        for hk, sid, sig in (
                (h.blob, SID_B, good),                                  # signed a different session
                (other.blob, SID_A, good),                              # someone else's key
                (h.blob, SID_A, good[:-3]),                             # truncated
                (h.blob, SID_A, good + b"x"),                           # trailing junk
                (h.blob, SID_A, _s(b"ssh-rsa") + good[good.index(b"\0\0\0\x40"):]),   # algo mismatch
                (b"junk", SID_A, good), (h.blob, b"short", good)):
            with self.assertRaises(sshkey.SshKeyError):
                sshkey.verify_bind(hk, sid, sig)

    def test_userauth_session_id(self):
        self.assertEqual(sshkey.userauth_session_id(login(SID_A)), SID_A)
        self.assertIsNone(sshkey.userauth_session_id(b"SSHSIG" + b"x" * 40))
        self.assertIsNone(sshkey.userauth_session_id(b""))


class HostBound(unittest.TestCase):
    def test_every_host_key_type_is_read_from_the_data(self):
        for k in (ed25519.Ed25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1()),
                  ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP521R1()),
                  rsa.generate_private_key(65537, 2048)):
            h = Host(k)
            d = sshkey.describe_data(hostbound(SID_A, h, user="bob"))
            self.assertEqual(d["kind"], "userauth")
            self.assertEqual(d["hostkey"], h.blob)
            self.assertIn("log in over SSH as 'bob'", d["text"])
            self.assertIn(f"to server {h.fp} ({h.type})", d["text"])
            self.assertNotIn("host not shown", d["text"])

    def test_plain_publickey_is_unchanged(self):
        d = sshkey.describe_data(login(SID_A))
        self.assertIsNone(d["hostkey"])
        self.assertEqual(d["text"], "log in over SSH as 'deploy' (service 'ssh-connection', "
                                    "both client-supplied); host not shown by SSH")

    def test_truncated_or_garbage_hostbound_data_has_no_host(self):
        h = Host()
        good = hostbound(SID_A, h)
        for bad in (good[:-1], good[:-len(h.blob) - 4], good + b"x",
                    good[:-len(h.blob)] + b"\0" * len(h.blob)):
            d = sshkey.describe_data(bad)
            self.assertIsNone(d["hostkey"], bad[-8:])
            self.assertEqual(d["kind"], "userauth")
        self.assertEqual(sshkey.describe_data(good[:20])["kind"], "unknown")

    def test_unrecognised_text_is_informative_and_never_raw(self):
        d = sshkey.describe_data(b"\x00\x00\x01\x04" + b"\xff" * 260)
        self.assertEqual(d["kind"], "unknown")
        self.assertIn("264 bytes of unrecognised data (not an SSH login or SSHSIG message", d["text"])
        self.assertNotIn("\xff", d["text"])
        self.assertIn("one length-prefixed string", sshkey.describe_data(_s(b"x" * 10))["text"])
        self.assertNotIn("length-prefixed", sshkey.describe_data(b"abcdefgh")["text"])


class KnownHosts(unittest.TestCase):
    def test_parse(self):
        a, b = Host(), Host(ec.generate_private_key(ec.SECP256R1()))
        out = sshkey.parse_known_hosts([
            a.line("Web.example.com,10.0.0.5"),
            b.line("[git.example.com]:2222"),
            a.line("[web.example.com]:22"),                 # port 22 is the plain name
            a.line("|1|c2FsdA==|aGFzaA=="),                 # hashed: unsupported
            a.line("*.example.com,!bad.example.com,x?y"),   # patterns: ignored
            "@cert-authority *.example.com " + a.type + " " + base64.b64encode(a.blob).decode(),
            "# comment", "", "garbage", "host ssh-ed25519 !!notbase64",
            f"liar {b.type} {base64.b64encode(a.blob).decode()}",   # key type does not match the blob
        ])
        self.assertEqual(out, {a.fp: ["web.example.com", "10.0.0.5"], b.fp: ["git.example.com:2222"]})


class Claims(unittest.TestCase):
    TABLE = [
        ("ssh host", "host:22"), ("ssh -p 2222 bob@host ls -l", "bob@host:2222"),
        ("ssh -l bob -p2222 host", "bob@host:2222"), ("ssh -vvv -i k -l bob host", "bob@host:22"),
        ("ssh alice@host -l bob", "alice@host:22"),
        ("ssh -J j1,j2 u@final", "u@final:22 (via j1+1)"), ("ssh -J u@jump:2222 h", "h:22 (via u@jump:2222)"),
        ("ssh -o HostName=real.example alias", "real.example:22"),
        ("ssh -o 'Port 99' -o User=zed h", "zed@h:99"), ("ssh -o HostKeyAlias=x h", "h:22"),
        ("ssh ssh://u@h:2200/", "u@h:2200"), ("ssh u@::1", "u@[::1]:22"), ("ssh [::1]", "[::1]:22"),
        ("ssh -6 -N -f host -- ls", "host:22"),
        ("scp a.txt u@h:/tmp", "u@h:22"), ("scp -P 2222 h:/x .", "h:2222"), ("scp u@[::1]:x .", "u@[::1]:22"),
        ("scp scp://u@h:2200/x .", "u@h:2200"), ("scp -o Port=7 -r d h:d", "h:7"),
        ("sftp u@h", "u@h:22"), ("sftp -P 22 h:dir", "h:22"), ("sftp sftp://u@h:99/x", "u@h:99"),
        ("rsync -av -e 'ssh -p 2222' src/ u@h:/dst", "u@h:2222"), ("rsync -ave ssh x h:y", "h:22"),
        ("rsync --rsh='ssh -l bob' h:a .", "bob@h:22"),
        ("git clone git@github.com:org/repo.git", "git@github.com:22"),
        ("git clone ssh://git@h:2222/o/r", "git@h:2222"), ("git remote add o git@h:o/r", "git@h:22"),
        # not confident: nothing is sent
        ("ssh", None), ("ssh -N", None), ("ssh -4 'bad host'", None), ("ssh -- -oProxyCommand=x", None),
        ("scp a b", None), ("scp u@h1:x u@h2:y", None), ("sftp", None),
        ("rsync rsync://h/mod x", None), ("rsync a h::mod", None), ("rsync -e 'ssh2 x' h:a .", None),
        ("rsync -e 'ssh -p 99' a b", None),
        ("git push", None), ("git push origin HEAD:main", None), ("git log a@b", None),
        ("git clone git@a:x/y git@b:x/y", None),
        ("curl http://h", None), ("ls h:x", None), ("", None), ("ssh -p notaport h", None), ("ssh -p 99999 h", None),
        ("ssh $(x)", None),
    ]

    def test_table(self):
        for cmd, want in self.TABLE:
            self.assertEqual(asb.claimed_destination(shlex.split(cmd)), want, cmd)

    def test_control_characters_in_a_host_give_no_claim(self):
        for host in ("h\nevil", "h\x1b[2J", "h<b>", "h;x", "h x", "-oFoo=bar", "h" * 1 + "\u202e"):
            self.assertIsNone(asb.claimed_destination(["ssh", host]), repr(host))

    def test_garbage_does_not_raise(self):
        for argv in ([None], ["ssh", None], ["ssh", "-p"], ["rsync", "-e"], ["git", ""], ["scp", "-P"],
                      ["ssh"] + ["-o"] * 5):
            try:
                asb.claimed_destination(argv)
            except (TypeError, AttributeError):
                pass        # non-string argv never happens (subprocess would refuse it)


class AgentExtension(unittest.TestCase):
    def test_session_bind_is_remembered_per_connection(self):
        h = Host()
        conn = {"binds": [], "claim": None}
        self.assertEqual(asb.agent_reply(h.wire(SID_A, True), conn), bytes([asb.AGENT_SUCCESS]))
        self.assertEqual(len(conn["binds"]), 1)
        self.assertTrue(conn["binds"][0]["forwarding"])
        self.assertEqual(base64.b64decode(conn["binds"][0]["session_id_b64"]), SID_A)
        self.assertEqual(asb.agent_reply(h.wire(SID_B), {"binds": [], "claim": None}), bytes([6]))

    def test_everything_else_is_a_plain_failure(self):
        h, fail = Host(), bytes([asb.AGENT_FAILURE])
        conn = {"binds": [], "claim": None}
        ok = h.wire(SID_A)
        self.assertEqual(asb.agent_reply(ok), fail)                              # no connection state
        self.assertEqual(asb.agent_reply(bytes([27]) + _s(b"query"), conn), fail)  # other extension
        self.assertEqual(asb.agent_reply(ok[:-1], conn), fail)                   # missing bool
        self.assertEqual(asb.agent_reply(ok + b"x", conn), fail)                 # trailing byte
        self.assertEqual(asb.agent_reply(ok[:30], conn), fail)                   # truncated string
        self.assertEqual(asb.agent_reply(bytes([27]), conn), fail)
        self.assertEqual(conn["binds"], [])
        for _ in range(asb.MAX_BINDS):
            asb.agent_reply(ok, conn)
        self.assertEqual(asb.agent_reply(ok, conn), fail)                        # bounded
        self.assertEqual(len(conn["binds"]), asb.MAX_BINDS)


class HostBase(Harness):
    privkey = ed25519.Ed25519PrivateKey.generate()
    decision = None
    ssh_hosts = None

    def tweak(self, cfg):
        pem = ts._openssh(self.privkey)
        cfg["_vault"] = {"Deploykey": {"private_key": pem}}
        cfg["secrets"]["deploy"] = {
            "vars": {"DEPLOY_SSH_KEY": {"item": "Deploykey", "field": "private_key"}},
            "allowed_hosts": [], "ssh": True,
            "ssh_public_key": sshkey.public_line(sshkey.load_private(pem))}
        if self.ssh_hosts is not None:
            cfg["secrets"]["deploy"]["ssh_hosts"] = self.ssh_hosts

    def sign(self, data, binds=None, claimed=None):
        for r in self.broker._by_id.values():       # nobody answers here: keep under MAX_PENDING
            if r.status == "pending":
                r.status = "expired"
        body = {"mode": "ssh_sign", "names": ["deploy"], "flags": 0,
                "data_b64": base64.b64encode(data).decode()}
        if binds is not None:
            body["binds"] = binds
        if claimed is not None:
            body["claimed_dest"] = claimed
        return self.api("POST", "/v1/requests", body)

    def card(self, body):
        rid = json.loads(body)["id"]
        r = self.broker._by_id[rid]
        return req(self.abase + f"/a/{r.nonce}", headers={"X-authentik-username": "alice"})[1]

    def refused(self):
        return self.events("ssh_sign_refused")


class Verified(HostBase):
    host = Host()
    ssh_hosts = {"known_hosts": [host.line("web.example.com,10.0.0.5")]}

    def test_verified_and_named(self):
        code, body = self.sign(login(SID_A), [self.host.bind(SID_A)], claimed="deploy@web.example.com:22")
        self.assertEqual(code, 202)
        want = f"Server: {self.host.fp} (ssh-ed25519) - known as web.example.com, 10.0.0.5"
        card = self.card(body)
        self.assertIn(want, card.replace("&#x27;", "'"))
        self.assertIn("Destination (claimed by the client): deploy@web.example.com:22", card)
        self.assertIn("log in over SSH as", card)
        self.assertNotIn("host not shown", card)
        self.assertNotIn("Agent forwarding", card)
        self.assertIn(want, self.notifier.sent[0]["message"])
        self.assertIn("Destination (claimed by the client)", self.notifier.sent[0]["message"])
        ev = self.events("requested")[0]
        self.assertEqual((ev["host_bound"], ev["host_fp"], ev["host_type"], ev["host_name"],
                          ev["claimed_dest"], ev["forwarding"]),
                         (True, self.host.fp, "ssh-ed25519", "web.example.com, 10.0.0.5",
                          "deploy@web.example.com:22", False))

    def test_verified_unnamed_and_forwarding(self):
        other = Host(ec.generate_private_key(ec.SECP256R1()))
        _, body = self.sign(login(SID_A), [other.bind(SID_A, forwarding=True)])
        card = self.card(body)
        self.assertIn(f"Server: {other.fp} (ecdsa-sha2-nistp256)", card)
        self.assertNotIn("known as", card)
        self.assertNotIn("Destination", card)
        self.assertIn("Agent forwarding: this key may be used from the remote host", card)
        self.assertIn("Agent forwarding", self.notifier.sent[0]["message"])
        self.assertTrue(self.events("requested")[0]["forwarding"])

    def test_unbound_with_and_without_claim(self):
        _, body = self.sign(login(SID_A), claimed="a@b.example:22")
        card = self.card(body)
        self.assertIn("Server identity not verified", card)
        self.assertIn("Destination (claimed by the client): a@b.example:22", card)
        _, body = self.sign(login(SID_A))
        card = self.card(body)
        self.assertIn("Server identity not verified", card)
        self.assertNotIn("Destination", card)
        self.assertFalse(self.events("requested")[1]["host_bound"])
        self.assertNotIn("host_fp", {k: v for k, v in self.events("requested")[1].items() if v})

    def test_invalid_signature_is_unbound_not_verified(self):
        bad = self.host.bind(SID_A, sig=sshkey.sign(self.host.key, SID_B))
        junk = {"hostkey_b64": "!!", "session_id_b64": "AA==", "sig_b64": "AA=="}
        for binds in ([bad], [junk], ["x", 5, None], [{}]):
            code, body = self.sign(login(SID_A), binds)
            self.assertEqual(code, 202, binds)
            self.assertIn("Server identity not verified", self.card(body))
        self.assertTrue(all(e["host_bound"] is False for e in self.events("requested")))

    def test_session_mismatch_is_refused(self):
        # a bind (even a genuine one, replayed from another connection) for a different session
        code, body = self.sign(login(SID_B), [self.host.bind(SID_A)])
        self.assertEqual(code, 403)
        self.assertEqual([r["reason"] for r in self.refused()], ["session_mismatch"])
        self.assertEqual(self.events("requested"), [])
        self.assertEqual(self.events("rejected"), [])

    def test_bind_chain_picks_the_matching_session(self):
        hop = Host()
        _, body = self.sign(login(SID_B), [hop.bind(SID_A, True), self.host.bind(SID_B)])
        self.assertIn(f"Server: {self.host.fp}", self.card(body))

    def test_bind_on_non_login_data_is_not_trusted(self):
        sshsig = b"SSHSIG" + _s(b"git") + _s(b"") + _s(b"sha512") + _s(b"h" * 64)
        _, body = self.sign(sshsig, [self.host.bind(SID_A)])
        self.assertNotIn("Server", self.card(body))

    def test_hostile_claim_is_dropped_and_ui_escapes(self):
        for evil in ("<script>alert(1)</script>", "a\nb", "x" * 500, "h:22\"><img src=x>"):
            _, body = self.sign(login(SID_A), claimed=evil)
            card = self.card(body)
            self.assertNotIn("alert(1)", card)
            self.assertNotIn("<img", card)
            self.assertNotIn("claimed by the client", card)
        # defence in depth: even a value that reached the spec is escaped
        class R:
            mode = "ssh_sign"
            spec = {"fingerprint": "SHA256:x", "ssh": {"text": "t"},
                    "host": {"bound": True, "fp": "SHA256:<b>", "type": "t<i>", "names": ["<u>x"],
                             "claimed": "<script>1</script>", "forwarding": True}}
        what, _ = _describe(R)
        for tag in ("<script", "<b>", "<i>", "<u>"):   # `what` has no markup of its own
            self.assertNotIn(tag, what)
        self.assertIn("&lt;script&gt;", what)

    def test_history_detail_shows_the_server(self):
        self.decision = "approve"
        code, body = self.sign(login(SID_A), [self.host.bind(SID_A)], claimed="web.example.com:22")
        rid = json.loads(body)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        import time
        time.sleep(0.5)
        _, page = req(self.abase + f"/request/{rid}?fragment=1", headers={"X-authentik-username": "alice"})
        self.assertIn(self.host.fp, page)
        self.assertIn("known as web.example.com", page)
        self.assertIn("claimed by the client", page)

    def test_summarizer_input_includes_the_host(self):
        from secret_broker import summarize
        _, body = self.sign(login(SID_A), [self.host.bind(SID_A)], claimed="web.example.com:22")
        spec = self.broker._by_id[json.loads(body)["id"]].spec
        text = summarize.describe("ssh_sign", ["deploy"], spec)
        self.assertIn(self.host.fp, text)
        self.assertIn("web.example.com", text)

    def test_ssh_signing_is_always_high(self):
        class Low:
            def analyze(self, *a):
                return {"summary": "fine", "risk": "low", "summary_model": "m"}
        self.broker.summarizer = Low()
        _, body = self.sign(login(SID_A))
        self.assertEqual(self.broker._by_id[json.loads(body)["id"]].risk["level"], "high")


class Chain(HostBase):
    """Session binds form a chain, like OpenSSH's own agent: only the last one is this login."""
    hop, final = Host(), Host(ec.generate_private_key(ec.SECP256R1()))
    ssh_hosts = {"known_hosts": [hop.line("jump.example.com"), final.line("target.example.com")]}

    def test_chain_display_with_forwarding(self):
        _, body = self.sign(login(SID_B), [self.hop.bind(SID_A, True), self.final.bind(SID_B)])
        card = self.card(body)
        self.assertIn(f"Server: {self.final.fp} (ecdsa-sha2-nistp256) - known as target.example.com", card)
        self.assertIn(f"Agent forwarded through: {self.hop.fp} (ssh-ed25519) [jump.example.com] (forwarding) -&gt; "
                      f"{self.final.fp} (ecdsa-sha2-nistp256) [target.example.com]", card)
        self.assertIn("Agent forwarding: this key may be used from the remote host", card)
        self.assertIn("not that it is the host you expect", card)
        self.assertIn("Agent forwarded through", self.notifier.sent[0]["message"])
        self.assertTrue(self.events("requested")[0]["forwarding"])
        self.assertIn("Agent forwarded through", " ".join(self.events("requested")[0]["host_lines"]))

    def test_chain_without_forwarding_is_labelled_a_chain(self):
        _, body = self.sign(login(SID_B), [self.hop.bind(SID_A), self.final.bind(SID_B)])
        card = self.card(body)
        self.assertIn("Bind chain:", card)
        self.assertNotIn("Agent forwarding", card)

    def test_match_against_an_earlier_bind_is_unverified(self):
        _, body = self.sign(login(SID_A), [self.hop.bind(SID_A, True), self.final.bind(SID_B)])
        card = self.card(body)
        self.assertIn("Server identity not verified (the bind is for an earlier hop", card)
        self.assertNotIn("Server:", card)
        self.assertFalse(self.events("requested")[0]["host_bound"])

    def test_a_broken_link_voids_the_chain(self):
        bad = self.hop.bind(SID_A, True, sig=sshkey.sign(self.hop.key, SID_B))
        _, body = self.sign(login(SID_B), [bad, self.final.bind(SID_B)])
        self.assertIn("Server identity not verified", self.card(body))

    def test_chain_length_is_bounded(self):
        binds = [self.hop.bind(SID_A)] * sshkey.MAX_BINDS + [self.final.bind(SID_B)]
        _, body = self.sign(login(SID_B), binds)
        self.assertIn("Server identity not verified", self.card(body))
        binds = [self.hop.bind(SID_A)] * (sshkey.MAX_BINDS - 1) + [self.final.bind(SID_B)]
        _, body = self.sign(login(SID_B), binds)
        self.assertIn(f"Server: {self.final.fp}", self.card(body))


class ChainPolicy(HostBase):
    hop, final, other = Host(), Host(), Host()
    ssh_hosts = {"known_hosts": [hop.line("jump.example.com"), final.line("target.example.com")],
                 "allowed_hosts": ["target.example.com"]}

    def forwarded(self):
        return [self.hop.bind(SID_A, True), self.final.bind(SID_B)]

    def test_forwarded_use_is_refused_by_default(self):
        self.assertEqual(self.sign(login(SID_B), self.forwarded())[0], 403)
        self.assertEqual(self.sign(login(SID_B), [self.final.bind(SID_B)])[0], 202)   # not forwarded: fine
        self.assertEqual([r["reason"] for r in self.refused()], ["host_forwarded"])

    def test_earlier_bind_match_is_refused(self):
        self.assertEqual(self.sign(login(SID_A), [self.final.bind(SID_A), self.final.bind(SID_B)])[0], 403)
        self.assertEqual([r["reason"] for r in self.refused()], ["host_unverified"])


class ChainPolicyAllowForwarded(ChainPolicy):
    ssh_hosts = {**ChainPolicy.ssh_hosts, "allow_forwarded": True,
                 "allowed_hosts": ["target.example.com", "jump.example.com"]}

    def test_all_hops_must_be_allowed(self):
        self.assertEqual(self.sign(login(SID_B), self.forwarded())[0], 202)
        self.assertEqual(self.sign(login(SID_B), [self.other.bind(SID_A, True), self.final.bind(SID_B)])[0], 403)
        self.assertEqual([r["reason"] for r in self.refused()], ["host_not_allowed"])

    # the base class expectations differ when forwarding is allowed
    test_forwarded_use_is_refused_by_default = None


class HostBoundPolicy(HostBase):
    good, bad = Host(), Host()
    ssh_hosts = {"known_hosts": [good.line("web.example.com")], "allowed_hosts": ["web.example.com"]}

    def test_hostbound_enforces_without_a_bind(self):
        code, body = self.sign(hostbound(SID_A, self.good))
        self.assertEqual(code, 202)
        card = self.card(body)
        self.assertIn(f"Server (host key in the signed login data): {self.good.fp} (ssh-ed25519)"
                      " - known as web.example.com", card)
        self.assertEqual(self.sign(hostbound(SID_A, self.bad))[0], 403)
        self.assertEqual(self.sign(login(SID_A))[0], 403)                 # plain publickey: unbound
        self.assertEqual([r["reason"] for r in self.refused()], ["host_not_allowed", "host_unverified"])

    def test_bind_and_signed_host_key_must_agree(self):
        self.assertEqual(self.sign(hostbound(SID_A, self.good), [self.good.bind(SID_A)])[0], 202)
        code, _ = self.sign(hostbound(SID_A, self.good), [self.bad.bind(SID_A)])
        self.assertEqual(code, 403)
        self.assertEqual([r["reason"] for r in self.refused()], ["host_conflict"])


class HostBoundNoPolicy(HostBase):
    def test_conflict_is_refused_even_without_a_policy(self):
        a, b = Host(), Host()
        self.assertEqual(self.sign(hostbound(SID_A, a), [b.bind(SID_A)])[0], 403)
        self.assertEqual(self.refused()[0]["reason"], "host_conflict")

    def test_signed_host_shown_unnamed(self):
        h = Host(ec.generate_private_key(ec.SECP384R1()))
        _, body = self.sign(hostbound(SID_A, h))
        card = self.card(body)
        self.assertIn(f"Server (host key in the signed login data): {h.fp} (ecdsa-sha2-nistp384)", card)
        self.assertIn(f"to server {h.fp}", card)
        self.assertFalse(self.events("requested")[0]["host_bound"])


class Allowed(HostBase):
    good, bad = Host(), Host()
    ssh_hosts = {"known_hosts": [good.line("web.example.com"), bad.line("evil.example.com")],
                 "allowed_hosts": ["web.example.com", "SHA256:" + "A" * 43]}

    def test_matrix(self):
        # verified, name maps to an allowed host
        self.assertEqual(self.sign(login(SID_A), [self.good.bind(SID_A)])[0], 202)
        # verified, but a different server
        self.assertEqual(self.sign(login(SID_A), [self.bad.bind(SID_A)])[0], 403)
        # no bind at all, or one that fails verification: fail closed
        self.assertEqual(self.sign(login(SID_A))[0], 403)
        self.assertEqual(self.sign(login(SID_A), [self.good.bind(SID_A, sig=b"x" * 20)])[0], 403)
        # non-login data (commit signing) cannot be tied to a server
        self.assertEqual(self.sign(b"SSHSIG" + _s(b"git") + _s(b"") + _s(b"sha512") + _s(b"h" * 64))[0], 403)
        self.assertEqual([r["reason"] for r in self.refused()],
                         ["host_not_allowed", "host_unverified", "host_unverified", "host_unverified"])
        self.assertEqual(len(self.events("requested")), 1)

    def test_refusal_text_does_not_list_the_policy(self):
        code, body = self.sign(login(SID_A), [self.bad.bind(SID_A)])
        self.assertEqual(code, 403)
        for leak in ("web.example.com", "SHA256:" + "A" * 43, self.good.fp):
            self.assertNotIn(leak, body)


class AllowedByFingerprint(HostBase):
    host = Host()
    ssh_hosts = {"allowed_hosts": [host.fp]}

    def test_fingerprint_without_known_hosts(self):
        self.assertEqual(self.sign(login(SID_A), [self.host.bind(SID_A)])[0], 202)
        self.assertEqual(self.sign(login(SID_A), [Host().bind(SID_A)])[0], 403)


class NoPolicy(HostBase):
    def test_unset_and_unbound_proceeds(self):
        code, body = self.sign(login(SID_A))
        self.assertEqual(code, 202)
        self.assertIn("Server identity not verified", self.card(body))
        self.assertEqual(self.refused(), [])

    def test_agent_end_to_end_with_bind_and_claim(self):
        os.environ["SECRET_BROKER_URL"], os.environ["SECRET_BROKER_KEY"] = self.base, KEY
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("SECRET_BROKER_URL", "SECRET_BROKER_KEY")])
        self.decision = "approve"
        host = Host()
        # drive the real handler logic through agent_reply with a connection state
        conn = {"binds": [], "claim": "deploy@web.example.com:22"}
        self.assertEqual(asb.agent_reply(host.wire(SID_A, True), conn), bytes([6]))
        ids = asb.agent_reply(bytes([asb.AGENTC_REQUEST_IDENTITIES]), conn)
        blob, _ = ts._read_string(ids, 5)
        data = login(SID_A)
        reply = asb.agent_reply(bytes([asb.AGENTC_SIGN_REQUEST]) + _s(blob) + _s(data) + struct.pack(">I", 0), conn)
        self.assertEqual(reply[0], asb.AGENT_SIGN_RESPONSE)
        ev = self.events("requested")[0]
        self.assertEqual((ev["host_fp"], ev["forwarding"], ev["claimed_dest"]),
                         (host.fp, True, "deploy@web.example.com:22"))


class NoLeaks(HostBase):
    host = Host()
    ssh_hosts = {"known_hosts": [host.line("secretname.internal")], "allowed_hosts": ["secretname.internal"]}

    def test_agent_visible_surfaces_do_not_reveal_the_policy(self):
        self.sign(login(SID_A))                                   # refused: unbound
        self.sign(login(SID_A), [self.host.bind(SID_A)], claimed="secretname.internal:22")
        for path in ("/v1/secrets", "/v1/secrets?host=127.0.0.1", "/v1/status"):
            _, body = self.api("GET", path)
            for leak in ("ssh_hosts", "secretname.internal", self.host.fp, "known_hosts", "allowed_hosts\": [\"s"):
                self.assertNotIn(leak, body, path)
        _, body = self.api("GET", "/v1/secrets")
        row = next(s for s in json.loads(body)["secrets"] if s["name"] == "deploy")
        self.assertEqual(row["allowed_hosts"], [])
        self.assertEqual(sorted(row), ["allowed_hosts", "name", "ssh_public_key", "vars"])

    def test_audit_api_whitelist(self):
        self.decision = "approve"
        code, body = self.sign(login(SID_A), [self.host.bind(SID_A)], claimed="secretname.internal:22")
        rid = json.loads(body)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        self.sign(login(SID_A))                                   # refused
        _, out = self.api("GET", "/v1/audit?limit=200")
        evs = json.loads(out)["events"]
        names = {e["event"] for e in evs}
        self.assertNotIn("ssh_sign_refused", names)
        self.assertNotIn("host_not_allowed", out)
        self.assertNotIn("host_unverified", out)
        req_ev = next(e for e in evs if e["event"] == "requested")
        signed = next(e for e in evs if e["event"] == "ssh_signed")
        for e in (req_ev, signed):
            self.assertEqual(e["host_fp"], self.host.fp)
            self.assertEqual(e["host_name"], "secretname.internal")
            self.assertEqual(e["claimed_dest"], "secretname.internal:22")
            for hidden in ("host_bound", "host_type", "forwarding"):
                self.assertNotIn(hidden, e)


class Config(unittest.TestCase):
    def entry(self, hosts):
        pub = sshkey.public_line(sshkey.load_private(ts._openssh(ed25519.Ed25519PrivateKey.generate())))
        return Broker._entry("k", {"ssh": True, "ssh_public_key": pub, "ssh_hosts": hosts,
                                   "vars": {"K_SSH_KEY": {"field": "private_key"}}})

    def test_valid(self):
        h = Host()
        _, e = self.entry({"known_hosts": [h.line("a")], "allowed_hosts": ["A", "SHA256:abc="]})
        self.assertEqual(e["ssh_hosts"], {"known": {h.fp: ["a"]}, "allowed": ["a", "SHA256:abc"],
                                       "allow_forwarded": False})
        _, e = self.entry({})
        self.assertNotIn("ssh_hosts", e)            # an empty object is no policy

    def test_errors_name_the_field(self):
        for bad, word in (("x", "ssh_hosts must be an object"), ({"allowed": []}, "unknown field 'allowed'"),
                          ({"allowed_hosts": []}, "allowed_hosts needs at least one"),
                          ({"allow_forwarded": "yes"}, "allow_forwarded must be true or false"),
                          ({"allowed_hosts": "a"}, "ssh_hosts.allowed_hosts"),
                          ({"allowed_hosts": ["a"] * 51}, "up to 50"),
                          ({"allowed_hosts": ["a b"]}, "host name or a SHA256"),
                          ({"known_hosts": ["x" * 3000]}, "ssh_hosts.known_hosts"),
                          ({"known_hosts": [1]}, "ssh_hosts.known_hosts"),
                          ({"known_hosts": ["a ssh-ed25519 AAAA"] * 201}, "up to 200")):
            with self.assertRaises(ValueError) as cm:
                self.entry(bad)
            self.assertIn(word, str(cm.exception))

    def test_only_for_ssh_keys(self):
        with self.assertRaises(ValueError) as cm:
            Broker._entry("x", {"allowed_hosts": ["a.example"], "vars": {"X_TOKEN": {"field": "notes"}},
                                "ssh_hosts": {"allowed_hosts": ["a"]}})
        self.assertIn("ssh_hosts", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
