"""Security regression: an agent must not be able to use the broker to approve its own requests.

Report 2: an agent could create a credential without a tap, point it at 127.0.0.1 (the broker's own
approval listener), and the listener believed the identity header from ANY peer. The fixes under test:

  * ONE destination guard for every outbound call: resolve once, refuse loopback / link-local /
    unspecified / multicast / own-interface addresses (and every IPv4-embedding form), pin the
    connection to the validated IP, refuse the broker's own listener ports on private addresses,
    and an IP literal on a non-default port needs an explicit host:port entry;
  * credentials created through requests may not name such destinations at all;
  * the approval listener never trusts loopback or the broker's own addresses, defaults to private
    peers only, and refuses a request carrying the broker's egress marker;
  * the CSRF token is bound to an HttpOnly cookie (double submit);
  * the agent's audit view does not reveal the approver.

Every address, name and secret here is fake. Servers are loopback stubs; DNS and connections are
injected, so nothing real is resolved or contacted.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import destguard  # noqa: E402
from secret_broker.backends import FileBackend  # noqa: E402
from secret_broker.broker import Broker, serve  # noqa: E402
from secret_broker.destguard import DestGuard, DestinationRefused  # noqa: E402
from secret_broker.notify import FakeNotifier  # noqa: E402
import test_e2e as t  # noqa: E402

KEY = t.KEY
SECRET = "g00d-guard-secret-4471"
OWN = "10.9.9.9"            # pretend address of one of this host's interfaces


def no_dns(host, port):
    raise socket.gaierror(socket.EAI_NONAME, "no such name")


def strict_guard(names=None, route=None, local=(OWN,), own_ports=(), deny=(), connect_log=None):
    """A strict guard whose DNS and connections are injected. `names`: host -> [addresses] (a list of
    lists answers successive lookups, to model rebinding); `route`: (ip, port) -> real loopback port."""
    names = names or {}
    calls = {}

    def resolver(host, port):
        calls[host] = calls.get(host, 0) + 1
        ans = names[host]
        if ans and isinstance(ans[0], list):
            ans = ans[min(calls[host], len(ans)) - 1]
        return list(ans)

    def connector(address, timeout=None, source_address=None):
        if connect_log is not None:
            connect_log.append(address)
        target = (route or {}).get(address)
        if target is None:
            raise ConnectionRefusedError()
        return socket.create_connection(("127.0.0.1", target), timeout or 5)
    g = DestGuard(deny_cidrs=deny, own_ports=own_ports, resolver=resolver, local_addrs=lambda: set(local),
                  allow_loopback=False, connector=connector)
    g.resolver_calls = calls
    return g


class GuardRules(unittest.TestCase):
    def test_always_refused_addresses(self):
        g = strict_guard()
        for a in ("127.0.0.1", "127.255.255.254", "::1", "169.254.169.254", "169.254.0.1", "fe80::1",
                  "0.0.0.0", "0.1.2.3", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "255.255.255.255",
                  "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0", "64:ff9b::7f00:1",
                  "2002:7f00:1::", "::7f00:1", "100.100.100.200", "fd00:ec2::254", OWN, "::ffff:" + OWN):
            with self.assertRaises(DestinationRefused, msg=a):
                g.resolve(a, 80)

    def test_lan_and_public_are_allowed(self):
        g = strict_guard()
        for a in ("10.0.0.5", "192.168.1.10", "172.16.0.9", "172.31.255.1", "100.64.0.1", "8.8.8.8",
                  "2001:4860:4860::8888", "fd12:3456::1"):
            self.assertEqual(g.resolve(a, 443), [str(destguard.parse_ip(a))], a)

    def test_refusal_text_is_fixed_and_echoes_no_address(self):
        g = strict_guard(names={"x.example": ["127.0.0.1"]})
        with self.assertRaises(DestinationRefused) as cm:
            g.resolve("x.example", 80)
        self.assertEqual(str(cm.exception), "destination not allowed")
        self.assertNotIn("127", repr(cm.exception))

    def test_any_bad_record_refuses_the_name(self):
        g = strict_guard(names={"mixed.example": ["93.184.216.34", "127.0.0.1"],
                                "mixed6.example": ["2001:4860::1", "::1"]})
        for h in ("mixed.example", "mixed6.example"):
            with self.assertRaises(DestinationRefused):
                g.resolve(h, 80)

    def test_dns_rebinding_cannot_defeat_the_guard(self):
        log = []
        g = strict_guard(names={"rebind.example": [["93.184.216.34"], ["127.0.0.1"]]},
                         route={("93.184.216.34", 80): 1}, connect_log=log)
        # the first answer is public: the connection goes to THAT address; the second lookup never happens
        with self.assertRaises(OSError):
            g.connect("rebind.example", 80)              # (the routed port is a closed port: refused)
        self.assertEqual(log, [("93.184.216.34", 80)])
        self.assertEqual(g.resolver_calls["rebind.example"], 1)

    def test_rebinding_to_loopback_on_the_first_lookup_is_refused_without_connecting(self):
        log = []
        g = strict_guard(names={"r.example": [["127.0.0.1"], ["93.184.216.34"]]}, connect_log=log)
        with self.assertRaises(DestinationRefused):
            g.connect("r.example", 80)
        self.assertEqual(log, [])

    def test_own_interface_address_by_name(self):
        g = strict_guard(names={"me.example": [OWN]})
        with self.assertRaises(DestinationRefused):
            g.resolve("me.example", 443)

    def test_own_listener_ports_on_private_addresses(self):
        g = strict_guard(own_ports=(8800, 8801))
        for ip in ("10.1.2.3", "192.168.0.7", "172.17.0.1", "100.64.0.9", "fd00::5"):
            for port in (8800, 8801):
                with self.assertRaises(DestinationRefused, msg=f"{ip}:{port}"):
                    g.resolve(ip, port)
        with self.assertRaises(DestinationRefused):
            g.resolve("::ffff:10.1.2.3", 8801)                    # an IPv4-mapped private address too
        self.assertEqual(g.resolve("10.1.2.3", 8802), ["10.1.2.3"])
        self.assertEqual(g.resolve("8.8.8.8", 8801), ["8.8.8.8"])   # a public address is not this broker

    def test_registered_ports_follow_the_real_listeners(self):
        g = strict_guard()
        g.register_ports(51234)
        with self.assertRaises(DestinationRefused):
            g.resolve("10.0.0.2", 51234)

    def test_legacy_and_odd_ip_spellings_are_refused(self):
        g = strict_guard(names={})
        for h in ("2130706433", "0x7f.1", "0x7f000001", "017700000001", "0177.0.0.1", "127.1", "127.0.1",
                  "0", "localhost", "LOCALHOST", "localhost.", "localhost.localdomain", "ip6-localhost",
                  "metadata.google.internal", ""):
            with self.assertRaises((DestinationRefused, OSError), msg=h):
                g.resolve(h, 80)

    def test_deny_cidrs_are_extra(self):
        g = strict_guard(deny=("10.50.0.0/16", "2001:db8::/32"))
        for a in ("10.50.1.1", "2001:db8::7"):
            with self.assertRaises(DestinationRefused):
                g.resolve(a, 80)
        self.assertEqual(g.resolve("10.51.0.1", 80), ["10.51.0.1"])

    def test_local_addresses_reads_this_host(self):
        if not os.path.exists("/proc/net/fib_trie"):
            self.skipTest("no /proc")
        self.assertIn("127.0.0.1", destguard.local_addresses())

    def test_entry_rules(self):
        g = strict_guard()
        for bad in ("127.0.0.1", "127.0.0.1:8801", "localhost", "localhost.localdomain", "ip6-localhost",
                    "metadata.google.internal", "169.254.169.254", "0.0.0.0", "intranet", "router",
                    "2130706433", "0x7f.1", OWN, "foo.localhost"):
            self.assertIsNotNone(g.entry_problem(bad, True), bad)
        for good in ("api.github.com", "nas.lan", "10.0.0.5", "10.0.0.5:8080", "svc.example.com:8443"):
            self.assertIsNone(g.entry_problem(good, True), good)
        # a human-edited entry may be a dotless LAN name, but never loopback
        self.assertIsNone(g.entry_problem("nas", False))
        self.assertIsNotNone(g.entry_problem("127.0.0.1", False))
        self.assertIsNotNone(g.entry_problem("localhost", False))

    def test_ip_literal_port_rule(self):
        ok = destguard.ip_port_ok
        self.assertTrue(ok(["10.0.0.5"], "10.0.0.5", 80))
        self.assertTrue(ok(["10.0.0.5"], "10.0.0.5", 443))
        self.assertFalse(ok(["10.0.0.5"], "10.0.0.5", 8080))
        self.assertTrue(ok(["10.0.0.5:8080"], "10.0.0.5", 8080))
        self.assertFalse(ok(["10.0.0.5:8080"], "10.0.0.5", 9090))
        self.assertFalse(ok(["10.0.0.5:8080"], "10.0.0.5", 80))   # an explicit port entry is only that port
        self.assertTrue(ok(["nas.lan"], "nas.lan", 8080))          # names are not restricted by port

    def test_config_cannot_turn_the_test_switch_on(self):
        prior = destguard.test_loopback_allowed()
        destguard.allow_loopback_for_tests(False)
        try:
            g = DestGuard.from_config({"destination_allow_loopback_for_tests": True, "allow_loopback": True})
            self.assertFalse(g.allow_loopback)
            with self.assertRaises(DestinationRefused):
                g.resolve("127.0.0.1", 80)
            with self.assertRaises(ValueError):
                DestGuard.from_config({"destination_deny_cidrs": ["not a cidr"]})
            with self.assertRaises(ValueError):
                DestGuard.from_config({"destination_deny_cidrs": "10.0.0.0/8"})
        finally:
            destguard.allow_loopback_for_tests(prior)


class Hit(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _go(self):
        Hit.seen.append({"path": self.path, "headers": dict(self.headers)})
        if self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", self.server.loop_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        raw = json.dumps({"auth": self.headers.get("Authorization")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = do_POST = _go


class StrictHarness(t.Harness):
    """The e2e harness with a STRICT guard: no loopback, injected DNS and connections, and the real
    peer-trust rules. The 'phone' never acts; tests decide through the broker's decision entry."""
    decision = None
    cfg_extra = None
    names = None

    def setUp(self):
        self.cfg_extra = dict(self.cfg_extra or {})
        prior = destguard.test_loopback_allowed()
        destguard.allow_loopback_for_tests(False)
        self.addCleanup(destguard.allow_loopback_for_tests, prior)
        Hit.seen = []
        d = tempfile.mkdtemp()
        vault_path = os.path.join(d, "vault.json")
        self.stub = ThreadingHTTPServer(("127.0.0.1", 0), Hit)
        self.stub.loop_url = "http://127.0.0.1:1/loopback-target"
        threading.Thread(target=self.stub.serve_forever, daemon=True).start()
        self.sport = self.stub.server_address[1]
        cfg = {"approve_base_url": "https://secrets.example", "allowed_user": "alice", "ttl_seconds": 30,
               "secrets": {}}
        cfg.update(self.cfg_extra)
        vault = {"Svc": {"token": SECRET}}
        self.tweak(cfg)
        for item, rec in cfg.pop("_vault", {}).items():
            vault.setdefault(item, {}).update(rec)
        for name, sc in cfg.pop("secrets").items():
            carrier = next(iter(sc["vars"].values()))["item"]
            vault.setdefault(carrier, {})["broker"] = json.dumps({"name": name, **sc})
        with open(vault_path, "w") as f:
            json.dump(vault, f)
        self.connects = []
        self.guard = strict_guard(names=dict(self.names or {}), route=self.route(), connect_log=self.connects)
        self.notifier = FakeNotifier(on_send=lambda url: None)
        self.audit = os.path.join(d, "audit.jsonl")
        self.broker = Broker(cfg, FileBackend(vault_path), self.notifier, self.audit, dest_guard=self.guard)
        self.c, self.a = serve(self.broker, ("127.0.0.1", 0), ("127.0.0.1", 0), KEY)
        # (serve() registers the really bound ports itself)
        self.base = f"http://127.0.0.1:{self.c.server_address[1]}"
        self.abase = f"http://127.0.0.1:{self.a.server_address[1]}"
        self.up = self.stub         # tearDown shuts it down

    def route(self):
        return {}

    def tweak(self, cfg):
        cfg["secrets"]["svc"] = {"vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                                 "allowed_hosts": ["lan.example", "pub.example"]}

    def tearDown(self):
        super().tearDown()

    def call(self, url, headers=None, names=("svc",), method="GET"):
        body = {"mode": "http", "names": list(names), "method": method, "url": url,
                "headers": headers if headers is not None else {"Authorization": "Bearer {{SVC_TOKEN}}"}}
        return self.api("POST", "/v1/requests", body)

    def approve_and_get(self, rid):
        code, req = self.broker.decide_via("dashboard", rid, "approve", "alice")
        self.assertEqual(code, 200)
        req.done.wait(10)
        c, b = self.api("GET", f"/v1/requests/{rid}?wait=5")
        return json.loads(b)

    def run_call(self, url, **kw):
        code, body = self.call(url, **kw)
        if code != 202:
            return code, json.loads(body)
        return 200, self.approve_and_get(json.loads(body)["id"])


class CreationRefusals(StrictHarness):
    """An agent cannot get a credential for a destination it must never reach."""
    BAD = ("127.0.0.1", "127.0.0.1:8801", "localhost", "LocalHost", "localhost.localdomain", "ip6-localhost",
           "metadata.google.internal", "169.254.169.254", "0.0.0.0", "intranet", "2130706433", "0x7f.1",
           "017700000001", OWN, "foo.localhost")

    def test_store_create_refuses_bad_hosts_without_a_tap(self):
        for h in self.BAD:
            code, body = self.api("POST", "/v1/requests", {
                "mode": "store", "names": ["newcred"], "op": "create", "value": "v", "allowed_hosts": [h]})
            self.assertEqual(code, 400, (h, body))
            self.assertIn("not allowed as a destination", body)
            self.assertNotIn(h, json.loads(body)["error"])
        self.assertEqual(self.notifier.sent, [])
        self.assertNotIn("newcred", self.broker.cfg["secrets"])

    def test_credential_request_refuses_bad_hosts(self):
        for h in self.BAD:
            code, body = self.api("POST", "/v1/requests", {
                "mode": "credential", "names": ["newcred"], "kind": "token", "purpose": "x", "hosts": [h]})
            self.assertEqual(code, 400, (h, body))
        self.assertEqual(self.notifier.sent, [])

    def test_a_good_host_still_creates(self):
        code, body = self.api("POST", "/v1/requests", {
            "mode": "store", "names": ["newcred"], "op": "create", "value": "v",
            "allowed_hosts": ["api.example.com", "10.0.0.5:8080"]})
        self.assertEqual(code, 202, body)

    def test_config_entries_that_violate_are_dropped_and_logged(self):
        # a human-edited catalog entry may not name loopback / link-local / own addresses
        raw = json.loads(self.broker.backend._data["Svc"]["broker"])
        raw["allowed_hosts"] = ["127.0.0.1", "169.254.169.254", OWN, "localhost", "lan.example", "nas"]
        self.broker.backend._data["Svc"]["broker"] = json.dumps(raw)
        self.broker.refresh_catalog()
        self.assertEqual(sorted(self.broker.cfg["secrets"]["svc"]["allowed_hosts"]), ["lan.example", "nas"])
        errs = self.events("dest_guard_config_error")
        self.assertEqual(sorted(e["host"] for e in errs), sorted(["127.0.0.1", "169.254.169.254", OWN, "localhost"]))
        self.assertEqual(self.broker.available("127.0.0.1"), [])


class PinnedConnections(StrictHarness):
    names = {"lan.example": ["10.9.8.7"], "pub.example": ["93.184.216.34"], "evil.example": ["127.0.0.1"],
             "rebind.example": [["93.184.216.34"], ["127.0.0.1"]], "mixed.example": ["93.184.216.34", "127.0.0.1"]}

    def route(self):
        return {("10.9.8.7", 80): self.sport, ("10.9.8.7", 8080): self.sport, ("93.184.216.34", 80): self.sport,
                ("93.184.216.34", 8801): self.sport}

    def tweak(self, cfg):
        cfg["secrets"]["svc"] = {"vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
                                 "allowed_hosts": ["lan.example", "pub.example", "evil.example", "rebind.example",
                                                   "mixed.example", "10.9.8.7", "10.9.8.7:8080"]}

    def test_rfc1918_lan_destination_still_works_and_the_marker_is_sent(self):
        code, body = self.call("http://lan.example/x", headers={"Authorization": "Bearer {{SVC_TOKEN}}",
                                                                "X-Secret-Broker-Egress": "0"})
        self.assertEqual(code, 400)             # an agent may not even try to set the marker
        code, got = self.run_call("http://lan.example/x")
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        self.assertEqual(got["http"]["status"], 200)
        self.assertEqual(self.connects, [("10.9.8.7", 80)])
        h = {k.lower(): v for k, v in Hit.seen[0]["headers"].items()}
        self.assertEqual(h["x-secret-broker-egress"], "1")
        self.assertEqual(h["authorization"], "Bearer " + SECRET)

    def test_ip_literal_lan_destination_on_default_port(self):
        code, got = self.run_call("http://10.9.8.7/x")
        self.assertEqual((code, got["status"]), (200, "approved"), got)

    def test_ip_literal_non_default_port_needs_an_explicit_entry(self):
        code, got = self.run_call("http://10.9.8.7:8080/x")        # "10.9.8.7:8080" is listed
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        code, body = self.call("http://10.9.8.7:9090/x")
        self.assertEqual(code, 403)
        self.assertIn("port is not allowed", body)

    def test_the_chain_from_the_report_fails_at_the_destination(self):
        """evil.example is a name the agent got allowed; it resolves to loopback. The human approves
        the call to the approval listener with the approver's header; it fails and never connects."""
        url = f"http://evil.example:{self.a.server_address[1]}/"
        code, got = self.run_call(url, headers={"X-authentik-username": "alice"})
        self.assertEqual((code, got["status"], got["error"]), (200, "failed", "release failed: connection"))
        self.assertEqual(self.connects, [])
        self.assertEqual(self.events("dashboard_viewed"), [])
        self.assertEqual(self.events("egress_marker_refused"), [])
        self.assertNotIn("127.0.0.1", json.dumps(got))
        ev = self.events("http_failed")[-1]
        self.assertEqual((ev["error"], ev["reason_class"]), ("connection", "destination not allowed"))   # real reason: operator only
        agent = self.api("GET", "/v1/audit?limit=300")[1]
        self.assertNotIn("destination", agent)                   # nor in the agent's audit view

    def test_dns_rebinding_between_check_and_connect(self):
        code, got = self.run_call("http://rebind.example/x")
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        self.assertEqual(self.connects, [("93.184.216.34", 80)])        # pinned to the validated address
        self.assertEqual(self.guard.resolver_calls["rebind.example"], 1)

    def test_a_name_with_any_loopback_record_is_refused(self):
        code, got = self.run_call("http://mixed.example/x")
        self.assertEqual(got["error"], "release failed: connection")
        self.assertEqual(self.connects, [])

    def test_own_listener_port_on_a_private_address_is_refused(self):
        for port in (self.a.server_address[1], self.c.server_address[1]):
            code, got = self.run_call(f"http://10.9.8.7:{port}/")
            # either refused at creation (port rule) or at connect (own port): never connected
            self.assertTrue(code == 403 or got["error"] == "release failed: connection", (code, got))
        self.assertEqual(self.connects, [])

    def test_port_spellings_of_the_listeners(self):
        for spelled in ("0%d", "00%d"):
            for port in (self.a.server_address[1], self.c.server_address[1]):
                code, got = self.run_call("http://10.9.8.7:" + spelled % port + "/")
                self.assertTrue(code == 403 or got["status"] == "failed", (code, got))
        self.assertEqual(self.connects, [])

    def test_redirect_to_loopback_is_returned_not_followed(self):
        self.stub.loop_url = f"http://127.0.0.1:{self.a.server_address[1]}/"
        code, got = self.run_call("http://lan.example/redir")
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        self.assertEqual(got["http"]["status"], 302)
        self.assertEqual(self.connects, [("10.9.8.7", 80)])          # no second connection
        self.assertEqual(self.events("dashboard_viewed"), [])

    def test_loopback_spellings_in_the_url_never_reach_a_listener(self):
        urls = ["http://127.0.0.1/", "http://127.0.0.1:%d/" % self.a.server_address[1],
                "http://2130706433/", "http://0x7f.1/", "http://017700000001/", "http://127.1/",
                "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://0/", "http://0.0.0.0/",
                "http://localhost/", "http://LOCALHOST./", "http://169.254.169.254/latest/meta-data/",
                "http://lan.example:80@127.0.0.1/", "http://lan.example@127.0.0.1:%d/" % self.a.server_address[1],
                "http://127.0.0.1#@lan.example/", "http://127.0.0.1%2f@lan.example/", "http://lan.example\\@127.0.0.1/",
                "http://lan.example%00@127.0.0.1/", "http://127.0.0.1:%d\\@lan.example/" % self.a.server_address[1]]
        for u in urls:
            code, body = self.call(u)
            if code == 202:                       # accepted at creation: it must still not connect anywhere bad
                got = self.approve_and_get(json.loads(body)["id"])
                self.assertNotEqual(got["status"], "approved", u)
        for c in self.connects:
            self.assertEqual(c[0], "10.9.8.7")
        self.assertEqual(self.events("dashboard_viewed"), [])
        self.assertEqual(Hit.seen, [])

    def test_no_resolved_address_is_ever_echoed(self):
        self.guard._resolver = lambda h, p: ["127.66.55.44"]
        raw = json.loads(self.broker.backend._data["Svc"]["broker"])
        raw["allowed_hosts"].append("echo.example")
        self.broker.backend._data["Svc"]["broker"] = json.dumps(raw)
        self.broker.refresh_catalog()
        code, got = self.run_call("http://echo.example/x")
        self.assertEqual(got["error"], "release failed: connection")
        everywhere = json.dumps(got) + open(self.audit).read() + json.dumps(self.notifier.sent, default=str)
        self.assertNotIn("127.66.55.44", everywhere)


class ListenerTrust(StrictHarness):
    """Who the approval listener believes."""

    def peer(self, addr, cfg=None):
        self.broker.cfg.pop("approval_trusted_peers", None)
        self.broker.cfg.pop("approval_trust_any_peer", None)
        self.broker.cfg.update(cfg or {})
        return self.broker.peer_trusted(addr)

    def test_unset_fails_closed_for_everyone(self):
        for a in ("10.1.2.3", "192.168.1.5", "172.18.0.4", "100.64.0.9", "fd12::9", "127.0.0.1", OWN, "8.8.8.8"):
            self.assertFalse(self.peer(a), a)
        self.assertFalse(self.broker.listener_open())

    def test_cgnat_peers_work_when_listed(self):
        cfg = {"approval_trusted_peers": ["100.64.0.0/10"]}
        self.assertTrue(self.peer("100.100.1.2", cfg))
        self.assertFalse(self.peer("192.168.1.2", cfg))
        self.assertFalse(self.peer("127.0.0.1", cfg))

    def test_explicit_cidrs_never_include_loopback_or_own(self):
        cfg = {"approval_trusted_peers": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", OWN + "/32"]}
        self.assertFalse(self.peer("127.0.0.1", cfg))
        self.assertFalse(self.peer("::1", cfg))
        self.assertFalse(self.peer(OWN, cfg))
        self.assertTrue(self.peer("10.1.2.3", cfg))
        self.assertFalse(self.peer("192.168.1.2", cfg))
        wide = {"approval_trusted_peers": ["0.0.0.0/0", "::/0"]}
        self.assertFalse(self.peer("127.0.0.1", wide))
        self.assertFalse(self.peer(OWN, wide))
        self.assertTrue(self.peer("8.8.8.8", wide))

    def test_trust_any_peer_is_the_only_way_back(self):
        self.assertTrue(self.peer("127.0.0.1", {"approval_trust_any_peer": True}))
        self.assertFalse(self.peer("127.0.0.1", {"approval_trust_any_peer": "yes"}))   # only a real true

    def test_startup_error_and_warnings(self):
        self.assertTrue(any("CLOSED" in e for e in self.broker.trust_errors()))
        self.broker.cfg["approval_trusted_peers"] = ["127.0.0.0/8", OWN + "/32"]
        self.assertTrue(any("loopback" in w for w in self.broker.trust_warnings()))
        self.assertTrue(any("only check" in w for w in self.broker.trust_warnings()))
        self.assertEqual(self.broker.trust_errors(), [])
        self.broker.cfg["approval_trust_any_peer"] = True
        self.assertTrue(any("ANY peer" in w for w in self.broker.trust_warnings()))

    def test_error_is_logged_at_startup_and_the_broker_still_runs(self):
        self.assertTrue([e for e in self.events("config_error") if "CLOSED" in e["error"]])
        self.assertEqual(self.api("GET", "/v1/status")[0], 200)

    def test_real_listener_refuses_a_loopback_peer(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r, timeout=10)
        self.assertEqual(cm.exception.code, 403)
        self.assertEqual(self.events("dashboard_viewed"), [])
        self.assertTrue(self.events("approval_forbidden"))


class EgressMarker(StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True}       # take the peer rule out of the picture

    def test_a_request_with_the_marker_is_refused_on_both_listeners(self):
        for base, path in ((self.abase, "/"), (self.base, "/v1/status")):
            r = urllib.request.Request(base + path, headers={"X-authentik-username": "alice",
                                                             "X-Client-Key": KEY, "X-Secret-Broker-Egress": "1"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(r, timeout=10)
            self.assertEqual(cm.exception.code, 403)
            r = urllib.request.Request(base + path, headers={"X-authentik-username": "alice", "X-Client-Key": KEY,
                                                             "x-secret-broker-egress": "0"})
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(r, timeout=10)
        self.assertEqual(self.events("dashboard_viewed"), [])
        self.assertTrue(self.events("egress_marker_refused"))

    def test_without_the_marker_the_listener_answers(self):
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        self.assertEqual(urllib.request.urlopen(r, timeout=10).status, 200)

    def test_the_whole_chain_through_a_guard_that_lets_the_address_through(self):
        """Even if DNS or routing sends the call to the approval listener, the marker the broker adds
        to every outbound call makes the listener refuse it: nothing is decided, no token is read."""
        self.guard._resolver = lambda h, p: ["93.184.216.34"]
        self.guard._connector = lambda addr, timeout=None, source_address=None: socket.create_connection(
            ("127.0.0.1", self.a.server_address[1]), 5)
        raw = json.loads(self.broker.backend._data["Svc"]["broker"])
        raw["allowed_hosts"] = ["pub.example"]
        self.broker.backend._data["Svc"]["broker"] = json.dumps(raw)
        self.broker.refresh_catalog()
        code, got = self.run_call("http://pub.example/", headers={"X-authentik-username": "alice"})
        self.assertEqual((code, got["status"]), (200, "approved"), got)
        self.assertEqual(got["http"]["status"], 403)              # the listener said no
        self.assertNotIn("csrf", got["http"]["body"])
        self.assertEqual(self.events("dashboard_viewed"), [])
        self.assertTrue(self.events("egress_marker_refused"))


class CsrfCookie(StrictHarness):
    cfg_extra = {"approval_trust_any_peer": True}

    def get(self, path, cookie=None, user="alice"):
        h = {"X-authentik-username": user}
        if cookie:
            h["Cookie"] = cookie
        r = urllib.request.Request(self.abase + path, headers=h)
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.read().decode(), resp.headers.get_all("Set-Cookie") or []

    def post(self, path, form, cookie=None, user="alice"):
        h = {"X-authentik-username": user}
        if cookie:
            h["Cookie"] = cookie
        r = urllib.request.Request(self.abase + path, data=urllib.parse.urlencode(form).encode(), headers=h,
                                   method="POST")
        try:
            return urllib.request.urlopen(r, timeout=10).status
        except urllib.error.HTTPError as e:
            return e.code

    def token_and_cookie(self, user="alice"):
        body, cookies = self.get("/", user=user)
        self.assertEqual(len(cookies), 1)
        c = cookies[0]
        self.assertIn("HttpOnly", c)
        self.assertIn("SameSite=Strict", c)
        self.assertTrue(c.startswith("sb_csrf="))
        tok = urllib.parse.parse_qs("x=" + body.split("name=csrf value='")[1].split("'")[0])["x"][0]
        return tok, c.split(";")[0]

    def pending_card(self):
        code, body = self.api("POST", "/v1/requests", {"mode": "env", "names": ["svc"], "argv": ["true"]})
        return json.loads(body)["id"]

    def test_cookie_is_issued_on_the_dashboard_and_reused(self):
        self.pending_card()
        tok, cookie = self.token_and_cookie()
        body, cookies = self.get("/", cookie=cookie)
        self.assertEqual(cookies, [])                            # a valid cookie is not re-issued
        self.assertIn(tok, body)                                  # and the token is stable for that browser

    def test_decision_needs_token_and_cookie(self):
        rid = self.pending_card()
        tok, cookie = self.token_and_cookie()
        self.assertEqual(self.post("/decide", {"id": rid, "decision": "deny", "csrf": tok}), 403)   # no cookie
        self.assertEqual(self.post("/decide", {"id": rid, "decision": "deny", "csrf": "x" * 64}, cookie), 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")
        self.assertEqual(self.post("/decide", {"id": rid, "decision": "deny", "csrf": tok}, cookie), 200)
        self.assertEqual(self.broker._by_id[rid].status, "denied")

    def test_a_token_scraped_from_a_page_is_useless_with_another_cookie(self):
        rid = self.pending_card()
        tok, cookie = self.token_and_cookie()
        _, other = self.token_and_cookie()                       # another browser's cookie
        self.assertNotEqual(cookie, other)
        self.assertEqual(self.post("/decide", {"id": rid, "decision": "deny", "csrf": tok}, other), 403)
        forged = "sb_csrf=" + "0" * 32 + "." + "0" * 32
        self.assertEqual(self.post("/decide", {"id": rid, "decision": "deny", "csrf": tok}, forged), 403)
        self.assertEqual(self.broker._by_id[rid].status, "pending")

    def test_cookie_is_bound_to_the_user(self):
        cookie, nonce = self.broker.csrf_cookie_new("alice")
        self.assertEqual(self.broker.csrf_cookie_nonce("alice", cookie), nonce)
        self.assertIsNone(self.broker.csrf_cookie_nonce("bob", cookie))
        self.assertNotEqual(self.broker.csrf_token("alice", nonce), self.broker.csrf_token("bob", nonce))
        with self.assertRaises(ValueError):
            self.broker.csrf_token("alice")          # outside the test harness a nonce is required

    def test_the_cookie_value_never_appears_in_a_page(self):
        self.pending_card()
        tok, cookie = self.token_and_cookie()
        body, _ = self.get("/", cookie=cookie)
        self.assertNotIn(cookie.split("=", 1)[1], body)


class AgentAuditViewHidesTheApprover(t.Harness):
    def test_approver_and_identity_header_are_not_in_the_agent_view(self):
        code, body = self.create_env()
        rid = json.loads(body)["id"]
        self.api("GET", f"/v1/requests/{rid}?wait=5")
        code, text = self.api("GET", "/v1/audit?limit=200")
        self.assertEqual(code, 200)
        self.assertNotIn("alice", text)
        self.assertNotIn("X-authentik-username", text)
        self.assertNotIn(self.user, text)
        ev = [e for e in json.loads(text)["events"] if e["event"] == "approved"]
        self.assertEqual(ev[0]["approver"], "human")
        # the human's own history keeps the name
        self.assertIn('"approver": "alice"', open(self.audit).read())


if __name__ == "__main__":
    unittest.main()
