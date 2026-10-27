"""The broker names itself on its own outbound requests instead of sending urllib's default, which
Cloudflare and others block. An explicit header on a request is never overridden."""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import os
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from secret_broker import destguard, wsproto  # noqa: E402
from secret_broker.destguard import DestGuard  # noqa: E402
from secret_broker.useragent import USER_AGENT  # noqa: E402


class Echo(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Echo.seen.append(self.headers.get_all("User-Agent"))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class UserAgent(unittest.TestCase):
    def setUp(self):
        Echo.seen = []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/"

    def guard(self):
        return DestGuard(allow_loopback=True)

    def test_the_default_names_the_tool(self):
        self.assertRegex(USER_AGENT, r"^agent-secret-broker/[A-Za-z0-9]+ \(\+https://github\.com/rgregg/agent-secret-broker\)$")
        self.assertNotIn("urllib", USER_AGENT)

    def test_agent_chosen_requests_send_it(self):
        self.guard().opener().open(urllib.request.Request(self.url), timeout=5).read()
        self.assertEqual(Echo.seen, [[USER_AGENT]])

    def test_operator_clients_send_it(self):
        destguard.operator_urlopen(urllib.request.Request(self.url), timeout=5).read()
        self.assertEqual(Echo.seen, [[USER_AGENT]])

    def test_a_header_the_request_carries_wins_in_any_case(self):
        for k in ("User-Agent", "user-agent", "USER-AGENT"):
            Echo.seen = []
            self.guard().opener().open(urllib.request.Request(self.url, headers={k: "mine/1"}), timeout=5).read()
            self.assertEqual(Echo.seen, [["mine/1"]], k)

    def test_websocket_handshake_sends_it_unless_config_sets_one(self):
        class Sink:
            def __init__(self):
                self.out = b""

            def sendall(self, data, deadline):
                self.out += data
                raise wsproto.WsError("stop")       # only the request we send matters here

        def sent(extra=()):
            t = Sink()
            with self.assertRaises(wsproto.WsError):
                wsproto.handshake(t, "example.com", "/ws", extra_headers=extra)
            return t.out.decode()

        self.assertEqual(sent().count(f"User-Agent: {USER_AGENT}\r\n"), 1)
        mine = sent((("User-Agent", "mine/1"),))
        self.assertIn("User-Agent: mine/1\r\n", mine)
        self.assertNotIn(USER_AGENT, mine)


if __name__ == "__main__":
    unittest.main()
