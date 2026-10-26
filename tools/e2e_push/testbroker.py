#!/usr/bin/env python3
"""Hermetic broker for the Chrome push rig: file vault, real web push, identity-injecting proxy.

Starts, all on 127.0.0.1 of THIS machine:
  * a throwaway broker (python -m secret_broker, file backend, fresh VAPID keys, webpush notifier,
    approve_base_url http://localhost:PORT) started through the loopback test launcher
  * a stub upstream (echoes the request)
  * a tiny reverse proxy on PORT that adds the SSO identity header, so a browser needs no login.
    PORT is what an ssh -R tunnel exposes to the Mac as http://localhost:PORT (a secure context).

Nothing here touches a production broker or any credential. Run: python testbroker.py [--port N]
Prints one JSON line (ready) with the ports and the client key, then waits for SIGTERM/SIGINT.
"""
import argparse
import http.client
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
USER = "e2e"
HDR = "X-authentik-username"


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        b = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_POST = do_GET

    def log_message(self, *a):
        pass


def make_proxy(listen_port, target_port):
    class P(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_any(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            h = {k: v for k, v in self.headers.items()
                 if k.lower() not in ("host", HDR.lower(), "connection", "accept-encoding")}
            h[HDR] = USER
            c = http.client.HTTPConnection("127.0.0.1", target_port, timeout=60)
            try:
                c.request(self.command, self.path, body=body, headers=h)
                r = c.getresponse()
                data = r.read()
                self.send_response(r.status)
                for k, v in r.getheaders():
                    if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:  # noqa: BLE001
                self.send_error(502, str(e)[:80])
            finally:
                c.close()

        do_GET = do_POST = do_PUT = do_DELETE = handle_any

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", listen_port), P)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18931, help="proxy port (= the localhost port on the Mac)")
    ap.add_argument("--root", default=None, help="scratch dir (default: a new temp dir)")
    ap.add_argument("--sw-file", default=None,
                    help="serve this file as the service worker instead of the built-in one (experiments)")
    args = ap.parse_args()
    root = args.root or tempfile.mkdtemp(prefix="asb-e2e-broker-")
    os.makedirs(root, exist_ok=True)
    os.chmod(root, 0o700)
    cport, aport = free_port(), free_port()
    up = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    key = secrets.token_urlsafe(24)
    open(os.path.join(root, "client_key"), "w").write(key)
    os.chmod(os.path.join(root, "client_key"), 0o600)
    vault = {"Svc": {"token": "e2e-fake-secret-value"}}
    vault["Svc"]["broker"] = json.dumps({
        "name": "svc", "vars": {"SVC_TOKEN": {"item": "Svc", "field": "token"}},
        "allowed_hosts": ["127.0.0.1"]})
    vpath = os.path.join(root, "vault.json")
    json.dump(vault, open(vpath, "w"))
    cfg = {
        "backend": {"type": "file", "path": vpath},
        "client_key_file": os.path.join(root, "client_key"),
        "approve_base_url": f"http://localhost:{args.port}",
        "allowed_user": USER, "identity_header": HDR,
        "approval_trusted_peers": ["127.0.0.1/32"],
        "client_port": cport, "approval_port": aport, "ttl_seconds": 600,
        "audit_log": os.path.join(root, "audit.jsonl"),
        "risk": {"auto_approve_max": "low"},
        "notify": [{"type": "webpush"}],
        "webpush": {"subject": "mailto:e2e@example.invalid"},
        "notify_presence": {"enabled": False},
    }
    cpath = os.path.join(root, "config.json")
    json.dump(cfg, open(cpath, "w"), indent=1)
    env = {"PATH": os.environ["PATH"], "PYTHONPATH": REPO, "BIND": "127.0.0.1", "PYTHONUNBUFFERED": "1",
           "HOME": root}
    log = open(os.path.join(root, "broker.log"), "ab")
    proc = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "launcher.py"), cpath, args.sw_file or ""],
                            env=env, stdout=log, stderr=log, cwd=root)
    import urllib.request
    end = time.time() + 30
    while time.time() < end:
        if proc.poll() is not None:
            sys.exit("broker died: see " + os.path.join(root, "broker.log"))
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{cport}/v1/status", headers={"X-Client-Key": key}), timeout=3).read()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.2)
    else:
        proc.kill()
        sys.exit("broker did not start")
    open(os.path.join(root, "testbroker.pid"), "w").write(str(os.getpid()))
    proxy = make_proxy(args.port, aport)
    print(json.dumps({"ready": True, "root": root, "proxy_port": args.port, "client_port": cport,
                      "approval_port": aport, "upstream_port": up.server_address[1],
                      "client_key": key, "pid": proc.pid, "base": f"http://localhost:{args.port}"}), flush=True)

    def stop(*a):
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        os._exit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while proc.poll() is None:
        time.sleep(0.5)
    sys.exit("broker exited")


if __name__ == "__main__":
    main()
