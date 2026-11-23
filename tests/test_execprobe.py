"""execprobe: reading a server's host key for an exec request and comparing it with what the credential pins.

The properties: the destination guard runs before anything is sent (loopback, link-local, metadata, own address,
IPv4-mapped, a name that resolves to ANY forbidden address, deny CIDRs) and the connection goes to the validated
address; the only request values that reach the keyscan program are the port and a validated IP; every failure is a
fixed label; one probe serves concurrent callers and a cached result costs no rate-limit token; the banner is read
and dropped; the classification never lets a key pinned under another name count as evidence.
The real ssh-keyscan against a real sshd is exercised by tests/e2e_remote_exec/.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import destguard, execmode, execprobe, sshkey  # noqa: E402

PUBLIC = "93.184.216.34"          # an address the guard allows (global, not ours)
CANARY = "S3CR3T-banner-canary"


def key_of(kind):
    k = {"ed": lambda: ed25519.Ed25519PrivateKey.generate(),
         "ec": lambda: ec.generate_private_key(ec.SECP256R1()),
         "rsa": lambda: rsa.generate_private_key(65537, 2048)}[kind]()
    blob = sshkey.public_blob(k)
    ktype = sshkey._blob_type(blob)
    return {"type": ktype, "b64": base64.b64encode(blob).decode(), "fp": sshkey.fingerprint(blob),
            "key": f"{ktype} {base64.b64encode(blob).decode()}"}


def line(names, k):
    return f"{names} {k['key']}"


class Sock:
    """What the guard's connector hands back: a peer address and a canned banner."""

    def __init__(self, peer, banner=b"SSH-2.0-OpenSSH_9.6\r\n", exc=None):
        self.peer, self.banner, self.exc, self.closed, self.reads = peer, banner, exc, False, 0

    def getpeername(self):
        return (self.peer, 22)

    def settimeout(self, t):
        self.timeout = t

    def recv(self, n):
        self.reads += 1
        if self.exc:
            raise self.exc
        out, self.banner = self.banner[:n], self.banner[n:]
        return out

    def close(self):
        self.closed = True


class Rig(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="keyscan-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        stub = os.path.join(self.dir, "ssh-keyscan")
        with open(stub, "w") as f:
            f.write("#!/usr/bin/env python3\nimport json, os, sys\nd = os.path.dirname(os.path.abspath(__file__))\n"
                    "open(d + '/calls', 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
                    "m = json.load(open(d + '/mode.json'))\nsys.stdout.write(m.get('out', ''))\nsys.exit(m.get('rc', 0))\n")
        os.chmod(stub, 0o755)
        self.cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir})
        self.resolved = {"nas.example.com": [PUBLIC]}
        self.connected, self.sockets, self.sock_kw = [], [], {}
        self.guard = destguard.DestGuard(resolver=lambda h, p: self.resolved[h], local_addrs=lambda: ["10.9.9.9"],
                                         connector=self.connector)
        self.keys = [key_of("ed")]
        self.scan(self.keys)

    def connector(self, addr, timeout=None, **kw):
        self.connected.append(addr)
        s = Sock(addr[0], **self.sock_kw)
        self.sockets.append(s)
        return s

    def scan(self, keys, rc=0, raw=None):
        out = raw if raw is not None else "".join(f"[{PUBLIC}]:22 {k['key']}\n" for k in keys)
        with open(os.path.join(self.dir, "mode.json"), "w") as f:
            json.dump({"out": out, "rc": rc}, f)

    def calls(self):
        try:
            with open(os.path.join(self.dir, "calls")) as f:
                return [json.loads(x) for x in f]
        except FileNotFoundError:
            return []

    def probe(self, host="nas.example.com", port=22, **kw):
        return execprobe.probe(host, port, self.cfg, self.guard, **kw)


class Classify(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = key_of("ed"), key_of("ed"), key_of("rsa")

    def test_pinned_key_on_an_allowed_host(self):
        got = execprobe.classify("nas", 22, [self.a["fp"]], [line("nas", self.a)], ["nas"])
        self.assertEqual((got["state"], got["pinned_fp"], got["matches"]), ("pinned", self.a["fp"], None))

    def test_port_is_part_of_the_pin(self):
        lines = [line("[nas]:2222", self.a)]
        self.assertEqual(execprobe.classify("nas", 2222, [self.a["fp"]], lines, ["nas"])["state"], "pinned")
        self.assertEqual(execprobe.classify("nas", 22, [self.b["fp"]], lines, ["nas"])["state"], "new")

    def test_a_different_key_for_a_pinned_name_and_port_is_changed(self):
        got = execprobe.classify("nas", 22, [self.b["fp"]], [line("nas", self.a)], ["nas"])
        self.assertEqual((got["state"], got["pinned_fp"], got["fingerprint"], got["matches"]),
                         ("changed", self.a["fp"], self.b["fp"], None))

    def test_any_presented_key_on_the_line_counts_as_pinned(self):
        # the server has an ed25519 and an rsa key; only the rsa one was pinned
        got = execprobe.classify("nas", 22, [self.b["fp"], self.c["fp"]], [line("nas", self.c)], ["nas"])
        self.assertEqual((got["state"], got["fingerprint"]), ("pinned", self.c["fp"]))
        none = execprobe.classify("nas", 22, [self.b["fp"], self.a["fp"]], [line("nas", self.c)], ["nas"])
        self.assertEqual(none["state"], "changed")

    def test_no_line_for_the_name_is_new(self):
        got = execprobe.classify("nas", 22, [self.a["fp"]], [line("other", self.b)], ["nas"])
        self.assertEqual((got["state"], got["pinned_fp"], got["matches"], got["fingerprint"]),
                         ("new", None, None, self.a["fp"]))

    def test_same_key_on_another_port_of_the_same_name(self):
        got = execprobe.classify("nas", 2222, [self.a["fp"]], [line("nas", self.a)], ["nas"])
        self.assertEqual((got["state"], got["matches"]), ("same_key_elsewhere", "nas:22"))
        got = execprobe.classify("nas", 22, [self.a["fp"]], [line("[nas]:2200", self.a)], ["nas"])
        self.assertEqual((got["state"], got["matches"]), ("same_key_elsewhere", "nas:2200"))

    def test_a_key_pinned_for_a_different_host_name_is_not_the_same_key(self):
        # Review focus: only the SAME name on another port. nas2, nas.example.com, a prefix: all unrelated
        lines = [line("nas2", self.a), line("nas.example.com:22", self.a), line("na", self.a), line("[nas2]:2222", self.a),
                 line("nas-x:22", self.a), line("nas2222", self.a), line("nas22", self.a)]
        got = execprobe.classify("nas", 22, [self.a["fp"]], lines, ["nas"])
        self.assertEqual((got["state"], got["matches"]), ("new", None))
        # positive control: the same line under the right name is recognised
        got = execprobe.classify("nas", 22, [self.a["fp"]], lines + [line("nas:2222", self.a)], ["nas"])
        self.assertEqual((got["state"], got["matches"]), ("same_key_elsewhere", "nas:2222"))

    def test_a_pinned_line_for_a_name_that_is_not_allowed_is_not_pinned(self):
        got = execprobe.classify("nas", 22, [self.a["fp"]], [line("nas", self.a)], ["other"])
        self.assertEqual(got["state"], "new")
        self.assertEqual(execprobe.classify("nas", 22, [self.a["fp"]], [line("nas", self.a)], ["nas"])["state"], "pinned")

    def test_hashed_and_wildcard_lines_pin_nothing(self):
        lines = [f"|1|abc|def {self.a['key']}", line("*.example.com", self.a), line("!nas", self.a)]
        self.assertEqual(execprobe.classify("nas", 22, [self.a["fp"]], lines, ["nas"])["state"], "new")

    def test_a_single_fingerprint_string_is_accepted(self):
        self.assertEqual(execprobe.classify("nas", 22, self.a["fp"], [line("nas", self.a)], ["nas"])["state"], "pinned")

    def test_pin_line_and_drop_pin(self):
        self.assertEqual(execprobe.pin_line("nas", 22, self.a["key"]), f"nas {self.a['key']}")
        self.assertEqual(execprobe.pin_line("nas", 2222, self.a["key"]), f"[nas]:2222 {self.a['key']}")
        lines = [line("nas,[nas]:2222", self.a), line("[nas]:22", self.b), line("other", self.c), "# a comment"]
        self.assertEqual(execprobe.drop_pin(lines, "nas", 22), [line("[nas]:2222", self.a), line("other", self.c), "# a comment"])
        self.assertEqual(execprobe.drop_pin(lines, "nas", 2222),
                         [line("nas", self.a), line("[nas]:22", self.b), line("other", self.c), "# a comment"])
        self.assertEqual(execprobe.drop_pin(lines, "gone", 22), lines)


class Probe(Rig):
    def test_reads_the_keys_best_first_and_connects_to_the_validated_address(self):
        rsa_k, ec_k = key_of("rsa"), key_of("ec")
        self.scan([rsa_k, ec_k, self.keys[0]])
        got = self.probe(port=2222)
        self.assertEqual([k["key_type"] for k in got["keys"]], ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"])
        self.assertEqual((got["fingerprint"], got["key"], got["address"]), (self.keys[0]["fp"], self.keys[0]["key"], PUBLIC))
        self.assertEqual(self.connected, [(PUBLIC, 2222)])          # the address the guard validated, never the name
        self.assertTrue(all(s.closed for s in self.sockets))

    def test_the_keyscan_program_gets_only_the_port_and_a_validated_address(self):
        self.probe(port=2222)
        [argv] = self.calls()
        self.assertEqual(argv, ["-T", "4", "-t", "ed25519,ecdsa,rsa", "-p", "2222", "--", PUBLIC])

    def test_a_name_is_never_handed_to_the_program(self):
        self.resolved["nas.example.com"] = [PUBLIC, "93.184.216.35"]
        self.probe()
        [argv] = self.calls()
        self.assertNotIn("nas.example.com", " ".join(argv))
        self.assertEqual(argv[-1], PUBLIC)                          # the very address the banner was read from

    def test_forbidden_destinations_are_refused_before_anything_is_sent(self):
        bad = {"loopback": "127.0.0.1", "link-local": "169.254.169.254", "own address": "10.9.9.9",
               "ipv4-mapped loopback": "::ffff:127.0.0.1", "ipv4-mapped metadata": "::ffff:169.254.169.254",
               "ipv4-mapped public": "::ffff:93.184.216.34", "nat64 loopback": "64:ff9b::7f00:1",
               "v6 loopback": "::1", "v6 link-local": "fe80::1", "unspecified": "0.0.0.0"}
        self.assertNotIn("label", self.probe())                     # positive control: the same path works for a good one
        self.connected.clear()
        for what, addr in bad.items():
            self.resolved["evil.example.com"] = [addr]
            self.assertEqual(self.probe("evil.example.com"), {"label": "refused_destination"}, what)
        self.assertEqual(self.connected, [])

    def test_a_name_with_any_forbidden_address_is_refused_whatever_the_order(self):
        for order in ([PUBLIC, "169.254.169.254"], ["169.254.169.254", PUBLIC], [PUBLIC, "::ffff:10.0.0.1"]):
            self.resolved["rebind.example.com"] = order
            self.assertEqual(self.probe("rebind.example.com"), {"label": "refused_destination"}, order)
        self.assertEqual(self.connected, [])

    def test_metadata_names_and_odd_ip_spellings_are_refused(self):
        for host in ("localhost", "metadata.google.internal", "instance-data", "2130706433", "0x7f.1", "127.1",
                     "127.0.0.1", "169.254.169.254"):
            self.assertEqual(self.probe(host), {"label": "refused_destination"}, host)
        self.assertEqual(self.connected, [])

    def test_deny_cidrs_apply(self):
        self.guard = destguard.DestGuard(deny_cidrs=["93.184.216.0/24"], resolver=lambda h, p: [PUBLIC],
                                         local_addrs=lambda: [], connector=self.connector)
        self.assertEqual(self.probe(), {"label": "refused_destination"})
        self.assertEqual(self.connected, [])

    def test_the_broker_own_ports_are_refused_on_private_addresses(self):
        self.guard = destguard.DestGuard(own_ports=[8080], resolver=lambda h, p: ["10.1.2.3"], local_addrs=lambda: [],
                                         connector=self.connector)
        self.assertEqual(self.probe(port=8080), {"label": "refused_destination"})
        self.assertNotIn("label", self.probe(port=22))              # control: another port on the same address is fine

    def test_every_failure_is_a_fixed_label_and_nothing_else(self):
        want = {}
        # unreachable: refused, no route, no such name
        for exc, label in ((ConnectionRefusedError("S3CR3T-exc"), "unreachable"), (OSError(113, "S3CR3T-route"), "unreachable"),
                           (socket.gaierror(-2, "S3CR3T-dns"), "unreachable"), (socket.timeout("S3CR3T-slow"), "timeout"),
                           (TimeoutError("S3CR3T-slow"), "timeout")):
            def boom(addr, timeout=None, _e=exc, **kw):
                raise _e
            self.guard._connector = boom
            got = self.probe()
            self.assertEqual(got, {"label": label}, repr(exc))
            want[label] = True
        self.assertEqual(set(want), {"unreachable", "timeout"})
        self.guard._connector = self.connector
        # the server answers but is not SSH
        for banner in (b"HTTP/1.1 400 Bad Request\r\n\r\n", b"", b"\x00\x01\x02", b"a\nb\nc\nd\ne\nf\ng\n"):
            self.sock_kw = {"banner": banner}
            self.assertEqual(self.probe(), {"label": "not_ssh"}, banner)
        # the server says nothing
        self.sock_kw = {"exc": socket.timeout("S3CR3T-silent")}
        self.assertEqual(self.probe(), {"label": "timeout"})
        self.sock_kw = {"exc": ConnectionResetError("S3CR3T-reset")}
        self.assertEqual(self.probe(), {"label": "not_ssh"})
        # an SSH banner but no key came out of the key exchange
        self.sock_kw = {}
        self.scan([], rc=1)
        self.assertEqual(self.probe(), {"label": "not_ssh"})
        self.assertTrue(all(s.closed for s in self.sockets))        # no socket was left open on any path

    def test_the_program_timing_out_or_missing_has_a_label(self):
        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1, output=b"S3CR3T-partial")
        self.assertEqual(self.probe(run=slow), {"label": "timeout"})
        self.assertEqual(self.probe(run=lambda argv, **kw: (_ for _ in ()).throw(PermissionError("S3CR3T"))),
                         {"label": "unreachable"})
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir + "-missing"})
        self.assertEqual(execprobe.probe("nas.example.com", 22, cfg, self.guard), {"label": "ssh_unavailable"})
        self.assertNotIn("label", self.probe())                     # control

    def test_hostile_program_output_is_parsed_defensively(self):
        good = key_of("ed")
        other = key_of("ec")
        wrong_type = good["key"].replace("ssh-ed25519", "ssh-rsa", 1)
        raw = "\n".join([
            "# banner S3CR3T-comment", f"{PUBLIC} {wrong_type}", f"{PUBLIC} ssh-ed25519 !!!notbase64!!!",
            f"{PUBLIC} ssh-dss {good['b64']}", f"{PUBLIC} ssh-ed25519", "x", f"{PUBLIC} {good['key']}",
            f"{PUBLIC} {good['key']} trailing comment", f"{PUBLIC} {other['key']}"]) + "\n"
        self.scan([], raw=raw)
        got = self.probe()
        self.assertEqual([k["fingerprint"] for k in got["keys"]], [good["fp"], other["fp"]])
        self.assertNotIn("S3CR3T", json.dumps(got))

    def test_the_connected_peer_is_checked_again(self):
        # whatever the connector returns, a peer the guard would refuse is never read from or scanned
        self.guard._connector = lambda addr, timeout=None, **kw: Sock("169.254.169.254")
        self.assertEqual(self.probe(), {"label": "refused_destination"})
        self.assertEqual(self.calls(), [])

    def test_the_banner_is_read_and_dropped(self):
        self.sock_kw = {"banner": f"SSH-2.0-OpenSSH_9.6 {CANARY}\r\n".encode()}
        got = self.probe()
        self.assertGreater(self.sockets[-1].reads, 0)               # premise: the banner really was read
        self.assertNotIn("label", got)
        self.assertNotIn(CANARY, json.dumps(got))
        self.assertNotIn(CANARY, json.dumps(self.calls()))

    def test_ssh_may_send_other_lines_before_its_identification(self):
        self.sock_kw = {"banner": b"hello\r\nworld\r\nSSH-2.0-x\r\n"}
        self.assertNotIn("label", self.probe())


class Cache(Rig):
    def setUp(self):
        super().setUp()
        self.now = [1000.0]
        self.prober = execprobe.Prober(self.guard, lambda: self.cfg, clock=lambda: self.now[0], run=subprocess.run)

    def test_a_second_request_within_the_ttl_makes_no_connection_and_costs_no_token(self):
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_per_client": 1})
        p = execprobe.Prober(self.guard, lambda: cfg, clock=lambda: self.now[0])
        first = p.probe("nas.example.com", 22, "c-1")
        self.assertNotIn("label", first)
        for _ in range(5):
            self.assertEqual(p.probe("nas.example.com", 22, "c-1"), first)
        self.assertEqual((len(self.connected), len(self.calls())), (1, 1))
        # the one token is spent: a different host is limited, the cached one still answers
        self.resolved["b.example.com"] = [PUBLIC]
        self.assertEqual(p.probe("b.example.com", 22, "c-1"), {"label": "rate_limited"})
        self.assertEqual(p.probe("nas.example.com", 22, "c-1"), first)

    def test_the_cache_expires(self):
        self.prober.probe("nas.example.com", 22, "c-1")
        self.now[0] += execprobe.CACHE_TTL_S - 1
        self.prober.probe("nas.example.com", 22, "c-1")
        self.assertEqual(len(self.connected), 1)
        self.now[0] += 2
        self.prober.probe("nas.example.com", 22, "c-1")
        self.assertEqual(len(self.connected), 2)

    def test_the_port_is_part_of_the_cache_key(self):
        self.prober.probe("nas.example.com", 22, "c-1")
        self.prober.probe("nas.example.com", 2222, "c-1")
        self.assertEqual(self.connected, [(PUBLIC, 22), (PUBLIC, 2222)])

    def test_a_failure_is_cached_briefly(self):
        self.sock_kw = {"banner": b"nope\n"}
        self.assertEqual(self.prober.probe("nas.example.com", 22, "c-1"), {"label": "not_ssh"})
        self.sock_kw = {}
        self.assertEqual(self.prober.probe("nas.example.com", 22, "c-1"), {"label": "not_ssh"})      # still the burst
        self.now[0] += execprobe.FAIL_TTL_S + 1
        self.assertNotIn("label", self.prober.probe("nas.example.com", 22, "c-1"))

    def test_concurrent_requests_for_one_host_make_one_probe(self):
        gate, inside, results = threading.Event(), threading.Event(), []
        base = self.connector

        def slow(addr, timeout=None, **kw):
            inside.set()
            self.assertTrue(gate.wait(10))
            return base(addr, timeout)
        self.guard._connector = slow
        ts = [threading.Thread(target=lambda i=i: results.append(self.prober.probe("nas.example.com", 22, f"c-{i}")))
              for i in range(6)]
        for t in ts:
            t.start()
        self.assertTrue(inside.wait(10))
        gate.set()
        for t in ts:
            t.join(10)
        self.assertEqual(len(results), 6)
        self.assertEqual(len({json.dumps(r, sort_keys=True) for r in results}), 1)
        self.assertNotIn("label", results[0])                       # premise: they all got a real answer
        self.assertEqual((len(self.connected), len(self.calls())), (1, 1))

    def test_the_broker_probe_is_rate_limited_per_client(self):
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_per_client": 2, "probe_overall": 100})
        p = execprobe.Prober(self.guard, lambda: cfg)
        for i in range(2):
            self.resolved[f"h{i}.example.com"] = [PUBLIC]
            self.assertNotIn("label", p.probe(f"h{i}.example.com", 22, "c-1"))
        self.resolved["h9.example.com"] = [PUBLIC]
        self.assertEqual(p.probe("h9.example.com", 22, "c-1"), {"label": "rate_limited"})
        self.assertNotIn("label", p.probe("h9.example.com", 22, "c-2"))
        self.assertEqual(len(self.connected), 3)                        # the limited call connected to nothing


class Cidrs(Rig):
    """`exec.probe_allow_cidrs`: when set, a destination with any address outside it is refused before any connection."""

    def allow(self, *cidrs):
        self.cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_allow_cidrs": list(cidrs)})

    def test_an_address_inside_is_probed_and_one_outside_is_refused_with_nothing_sent(self):
        self.allow("93.184.216.0/24")
        got = self.probe()
        self.assertNotIn("label", got)                                    # positive control: inside the list
        self.assertEqual(self.connected, [(PUBLIC, 22)])
        self.connected.clear()
        for what, addrs in (("outside", ["93.185.0.7"]), ("one of two outside", [PUBLIC, "8.8.8.8"]),
                            ("first outside", ["8.8.8.8", PUBLIC])):
            self.resolved["x.example.com"] = addrs
            self.assertEqual(self.probe("x.example.com"), {"label": "refused_destination"}, what)
        self.assertEqual(self.connected, [])
        self.assertEqual(self.calls()[1:], [])                            # ssh-keyscan never ran for them either

    def test_an_ip_literal_outside_the_list_is_refused(self):
        self.allow("93.184.216.0/24")
        self.assertEqual(self.probe("93.185.0.7"), {"label": "refused_destination"})
        self.assertNotIn("label", self.probe("93.184.216.34"))            # control

    def test_a_dns_name_that_resolves_outside_the_list_is_refused_even_though_the_guard_allows_it(self):
        self.assertNotIn("label", self.probe())                           # without the list the same name is fine
        self.connected.clear()
        self.allow("10.0.0.0/8")
        self.assertEqual(self.probe(), {"label": "refused_destination"})
        self.assertEqual(self.connected, [])

    def test_ipv4_mapped_and_embedded_forms_are_never_inside_a_list_of_plain_ranges(self):
        self.allow("10.0.0.0/8", "93.184.216.0/24")
        for addr in ("::ffff:10.0.0.5", "::ffff:93.184.216.34", "64:ff9b::a00:5", "2002:0a00:0005::1"):
            self.resolved["m.example.com"] = [addr]
            self.assertEqual(self.probe("m.example.com"), {"label": "refused_destination"}, addr)
        self.assertEqual(self.connected, [])
        nets = [__import__("ipaddress").ip_network("10.0.0.0/8")]
        self.assertTrue(execprobe._in_nets("10.0.0.5", nets))
        self.assertFalse(execprobe._in_nets("::ffff:10.0.0.5", nets))     # the unit under it: embedded alone is not enough
        self.assertFalse(execprobe._in_nets("64:ff9b::a00:5", nets))

    def test_unset_is_todays_behavior(self):
        self.assertIsNone(self.cfg["probe_allow_cidrs"])
        self.resolved["far.example.com"] = ["8.8.8.8"]
        self.assertNotIn("label", self.probe("far.example.com"))

    def test_the_name_is_resolved_once_and_the_connection_goes_to_the_checked_literal(self):
        n = []
        base = self.guard._resolver
        self.guard._resolver = lambda h, p: n.append(h) or base(h, p)
        self.allow("93.184.216.0/24")
        self.probe()
        self.assertEqual(n, ["nas.example.com"])                          # one lookup: the connect used the literal
        self.assertEqual(self.connected, [(PUBLIC, 22)])


class Flights(Cache):
    def test_rate_limited_and_failing_probes_leave_no_flight_behind(self):
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_per_client": 1})
        p = execprobe.Prober(self.guard, lambda: cfg, clock=lambda: self.now[0])
        self.assertNotIn("label", p.probe("nas.example.com", 22, "c-1"))
        for i in range(300):                                         # an agent asking about many distinct pairs
            self.resolved[f"h{i}.example.com"] = [PUBLIC]
            self.assertEqual(p.probe(f"h{i}.example.com", 22, "c-1"), {"label": "rate_limited"})
        self.assertEqual(len(self.connected), 1)                     # premise: the limiter, not the cache, answered
        self.assertEqual(p._flights, {})
        # failures (the server is not SSH) and an exception inside the probe leave nothing either
        self.sock_kw = {"banner": b"nope\n"}
        cfg2 = execmode.parse_config({"enabled": True, "ssh_path": self.dir})
        q = execprobe.Prober(self.guard, lambda: cfg2, clock=lambda: self.now[0])
        self.assertEqual(q.probe("nas.example.com", 22, "c-9"), {"label": "not_ssh"})
        self.assertEqual(q._flights, {})
        q.limiter.allow = lambda cid: 1 / 0
        with self.assertRaises(ZeroDivisionError):
            q.probe("h1.example.com", 22, "c-9")
        self.assertEqual(q._flights, {})

    def test_the_flight_map_is_bounded_while_probes_are_in_progress(self):
        gate, results = threading.Event(), []
        base = self.connector
        self.guard._connector = lambda addr, timeout=None, **kw: (gate.wait(10), base(addr, timeout))[1]
        n = execprobe.MAX_FLIGHTS + 20
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_per_client": 1000,
                                     "probe_overall": 5000})
        p = execprobe.Prober(self.guard, lambda: cfg, clock=lambda: self.now[0])
        for i in range(n):
            self.resolved[f"h{i}.example.com"] = [PUBLIC]
        ts = [threading.Thread(target=lambda i=i: results.append(p.probe(f"h{i}.example.com", 22, f"c-{i}"))) for i in range(n)]
        for t in ts:
            t.start()
        for _ in range(500):
            with p._lock:
                if len(p._flights) >= execprobe.MAX_FLIGHTS:
                    break
            threading.Event().wait(0.01)
        with p._lock:
            self.assertEqual(len(p._flights), execprobe.MAX_FLIGHTS)
        gate.set()
        for t in ts:
            t.join(20)
        self.assertEqual(len(results), n)
        self.assertEqual(sum(r == {"label": "rate_limited"} for r in results), 20)
        self.assertEqual(p._flights, {})


class Deadlines(Cache):
    """One client or one hostile server cannot keep the probe, or every slot, busy."""

    def test_a_server_that_drips_its_banner_is_cut_off_by_the_total_deadline(self):
        now = [0.0]

        class Drip(Sock):
            def recv(inner, n):                                   # noqa: N805 -- one byte, three seconds later
                inner.reads += 1
                now[0] += 3.0
                return b"x"
        self.guard._connector = lambda addr, timeout=None, **kw: self.sockets.append(Drip(addr[0])) or self.sockets[-1]
        self.assertEqual(self.probe(clock=lambda: now[0]), {"label": "timeout"})
        self.assertLessEqual(self.sockets[-1].reads, 4)           # 8 s of deadline, 3 s a byte: not 1024 reads
        self.assertGreaterEqual(self.sockets[-1].reads, 2)        # premise: it really was read for a while
        self.assertTrue(self.sockets[-1].closed)
        self.assertEqual(self.calls(), [])

    def test_a_name_with_many_unreachable_addresses_is_tried_a_few_times_only(self):
        self.resolved["many.example.com"] = [f"93.184.216.{i}" for i in range(20, 40)]

        def refuse(addr, timeout=None, **kw):
            self.connected.append(addr)
            raise socket.timeout("S3CR3T-slow")
        self.guard._connector = refuse
        self.assertEqual(self.probe("many.example.com"), {"label": "timeout"})
        self.assertEqual(len(self.connected), execprobe.MAX_ADDRESSES)

    def test_the_guard_deadline_bounds_the_whole_connect(self):
        import time as _t
        calls = []

        def slow(addr, timeout=None, **kw):
            calls.append(timeout)
            raise socket.timeout()
        g = destguard.DestGuard(resolver=lambda h, p: [f"93.184.216.{i}" for i in range(20, 30)], local_addrs=lambda: [],
                                connector=slow)
        with self.assertRaises(socket.timeout):
            g.connect("a.example.com", 22, timeout=4.0, deadline=_t.monotonic() - 1)       # already past: nothing is tried
        self.assertEqual(calls, [])
        with self.assertRaises(socket.timeout):
            g.connect("a.example.com", 22, timeout=4.0, deadline=_t.monotonic() + 3, max_addresses=2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(t <= 3.0 for t in calls), calls)                              # never longer than what is left

    def test_one_client_cannot_hold_every_probe_slot(self):
        gate, results, inside = threading.Event(), {}, threading.Semaphore(0)
        base = self.connector

        def slow(addr, timeout=None, **kw):
            inside.release()
            gate.wait(10)
            return base(addr, timeout)
        self.guard._connector = slow
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "probe_per_client": 1000, "probe_overall": 5000})
        p = execprobe.Prober(self.guard, lambda: cfg, clock=lambda: self.now[0])
        n = execprobe.MAX_INFLIGHT_PER_CLIENT + 3
        for i in range(n):
            self.resolved[f"h{i}.example.com"] = [PUBLIC]
        ts = [threading.Thread(target=lambda i=i: results.__setitem__(i, p.probe(f"h{i}.example.com", 22, "c-1")))
              for i in range(n)]
        for t in ts[:execprobe.MAX_INFLIGHT_PER_CLIENT]:
            t.start()
        for _ in range(execprobe.MAX_INFLIGHT_PER_CLIENT):
            self.assertTrue(inside.acquire(timeout=10))
        for t in ts[execprobe.MAX_INFLIGHT_PER_CLIENT:]:
            t.start()
            t.join(10)                                                # these return at once: no slot for this client
        self.assertEqual(sorted(i for i, r in results.items() if r == {"label": "rate_limited"}),
                         list(range(execprobe.MAX_INFLIGHT_PER_CLIENT, n)))
        other = {}
        self.resolved["other.example.com"] = [PUBLIC]
        t2 = threading.Thread(target=lambda: other.update(r=p.probe("other.example.com", 22, "c-2")))
        t2.start()
        self.assertTrue(inside.acquire(timeout=10))                   # another client still gets its probe
        gate.set()
        for t in ts[:execprobe.MAX_INFLIGHT_PER_CLIENT] + [t2]:
            t.join(10)
        self.assertNotIn("label", other["r"])
        self.assertEqual(p._inflight, {})
        self.assertEqual(p._flights, {})

    def test_a_waiter_for_a_stuck_probe_gives_up(self):
        from unittest import mock
        gate, inside, out = threading.Event(), threading.Event(), {}
        base = self.connector

        def slow(addr, timeout=None, **kw):
            inside.set()
            gate.wait(10)
            return base(addr, timeout)
        self.guard._connector = slow
        t = threading.Thread(target=lambda: self.prober.probe("nas.example.com", 22, "c-1"))
        t.start()
        self.assertTrue(inside.wait(10))
        with mock.patch.object(execprobe, "PROBE_WAIT_S", 0.2):
            out["r"] = self.prober.probe("nas.example.com", 22, "c-2")
        self.assertEqual(out["r"], {"label": "rate_limited"})
        gate.set()
        t.join(10)
        self.assertEqual((self.prober._flights, self.prober._inflight), ({}, {}))


class AllowedGate(unittest.TestCase):
    """classify, the intake check and the run all use execprobe.host_allowed: one rule."""
    CASES = [("nas", ["nas"], True), ("nas", ["nas:2222"], False), ("nas", ["NAS"], False), ("nas", ["nas."], False),
             ("127.0.0.1", ["127.0.0.1"], True), ("127.0.0.1", ["127.0.0.1:22"], False), ("nas", [], True),
             ("nas", None, True), ("nas", ["SHA256:" + "A" * 43], False), ("nas", ["other", "nas"], True)]

    def test_classify_agrees_with_the_gate_for_every_spelling(self):
        k = key_of("ed")
        for host, allowed, want in self.CASES:
            with self.subTest(host=host, allowed=allowed):
                self.assertEqual(execprobe.host_allowed(allowed, host), want)
                got = execprobe.classify(host, 22, [k["fp"]], [line(host, k)], allowed)
                self.assertEqual(got["state"], "pinned" if want else "new")

    def test_the_catalog_loader_lowercases_entries_so_both_sides_see_the_same_names(self):
        from secret_broker.broker import Broker
        got = Broker._ssh_hosts({"allowed_hosts": ["NAS", "Nas.Example.com:2222"]})["allowed"]
        self.assertEqual(got, ["nas", "nas.example.com:2222"])
        self.assertTrue(execprobe.host_allowed(got, "nas"))
        self.assertFalse(execprobe.host_allowed(got, "nas.example.com"))

    def test_the_broker_has_no_second_copy_of_the_rule(self):
        src = open(os.path.join(os.path.dirname(__file__), "..", "secret_broker", "broker.py")).read()
        self.assertGreater(src.count("execprobe_mod.host_allowed("), 1)      # premise: the scan is looking at real uses
        self.assertNotIn('host"] in ((sc.get("ssh_hosts")', src)
        self.assertNotIn('host"] not in ((sc.get("ssh_hosts")', src)


class Limits(unittest.TestCase):
    def test_per_client_and_overall_limits_with_a_sliding_window(self):
        now = [0.0]
        lim = execprobe.RateLimiter(2, 3, window_s=60, clock=lambda: now[0])
        self.assertEqual([lim.allow("a"), lim.allow("a"), lim.allow("a")], [True, True, False])
        self.assertTrue(lim.allow("b"))                              # another client has its own count
        self.assertFalse(lim.allow("c"))                             # the overall limit (3) is spent
        now[0] = 59
        self.assertFalse(lim.allow("a"))
        now[0] = 61                                                  # the window slid past the first three
        self.assertEqual([lim.allow("a"), lim.allow("a"), lim.allow("a")], [True, True, False])

    def test_a_refused_attempt_does_not_use_up_the_overall_budget(self):
        now = [0.0]
        lim = execprobe.RateLimiter(1, 2, clock=lambda: now[0])
        self.assertTrue(lim.allow("a"))
        for _ in range(10):
            self.assertFalse(lim.allow("a"))
        self.assertTrue(lim.allow("b"))                              # one overall token was left for b


if __name__ == "__main__":
    unittest.main()
