"""Local reproduction harness for the request description path (display only).

Starts a stub OpenRouter-compatible chat server on 127.0.0.1 that returns scripted
replies, runs realistic requests through the real ``Describer`` and prints which
ones fall back to the deterministic "auto:" line and why. No network beyond
loopback; no key is used.  Run: ``python -m tools.describe_probe``
"""
import http.server
import json
import threading
import time

from secret_broker import description as D
from secret_broker import scripts as scripts_mod

BACKUP_SH = "#!/bin/sh\nrsync -a /srv/data/ backup:/mnt/backup/\n"
CHECK_SH = "#!/bin/sh\ncurl -s localhost:8080/health\n"


def _script(path, text):
    import hashlib
    return {"path": path, "text": text, "size": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}


def http_(method, url, body=None, headers=None):
    s = {"method": method, "url": url, "headers": headers or {"Authorization": "Bearer {{TOKEN}}"}}
    if body is not None:
        s["body"] = body
    return ("http", s)


# (label, (mode, spec), scripted model reply).  The replies are what a chat model
# plausibly writes under the current prompt.
CASES = [
    ("GET models", http_("GET", "https://api.openai.com/v1/models"),
     "Retrieving a list of models from OpenAI"),
    ("login POST to a controller", http_("POST", "https://unifi.example.com/api/auth/login",
                                         '{"username":"claude","password":"{{PW}}"}'),
     "Logging in to the UniFi controller"),
    ("login POST, model says Authenticating", http_("POST", "https://unifi.example.com/api/auth/login",
                                                    '{"username":"claude","password":"{{PW}}"}'),
     "Authenticating with the UniFi controller"),
    ("login POST, model says Requesting a session", http_("POST", "https://unifi.example.com/api/login", "{}"),
     "Requesting a session from the UniFi controller"),
    ("POST that mentions API", http_("POST", "https://api.cloudflare.com/client/v4/zones/z/dns_records", "{}"),
     "Adding a DNS record using the Cloudflare API"),
    ("POST search (read-like)", http_("POST", "https://photos.example.com/api/search/metadata", "{}"),
     "Searching a photo library"),
    ("DELETE with 'only'", http_("DELETE", "https://h.example.com/api/old/1"),
     "Deleting only the oldest backup"),
    ("PUT 'Setting'", http_("PUT", "https://h.example.com/api/light/1", "{}"), "Setting a light brightness"),
    ("PATCH 'Adjusting'", http_("PATCH", "https://h.example.com/api/light/1", "{}"),
     "Adjusting the brightness of a light"),
    ("POST 'Muting'", http_("POST", "https://h.example.com/api/mute", "{}"), "Muting a speaker"),
    ("POST 'Joining'", http_("POST", "https://h.example.com/api/rooms/1/join", "{}"),
     "Joining a chat room in Slack"),
    ("POST 'Connecting'", http_("POST", "https://h.example.com/api/connect", "{}"),
     "Connecting a device to the network"),
    ("POST 'Waking'", http_("POST", "https://h.example.com/api/wake", "{}"), "Waking a computer"),
    ("POST 'Requesting' (credential-like)", http_("POST", "https://h.example.com/api/tokens", "{}"),
     "Requesting a new access token from GitHub"),
    ("POST with CI/CD", http_("POST", "https://h.example.com/api/ci", "{}"), "Starting a CI/CD pipeline run"),
    ("POST with Node.js name", http_("POST", "https://h.example.com/api/x", "{}"),
     "Restarting a Node.js service"),
    ("POST with 3-digit number", http_("POST", "https://h.example.com/api/x", "{}"),
     "Creating 200 test records"),
    ("POST numbered '2FA'", http_("POST", "https://h.example.com/api/x", "{}"),
     "Enabling two-factor sign-in for an account"),
    ("POST says 'a script that checks'", http_("POST", "https://h.example.com/api/x", "{}"),
     "Running a task that checks server status"),
    ("POST 'Sending a message' w/ reading", http_("POST", "https://h.example.com/api/x", "{}"),
     "Sending a message after reading the inbox"),
    ("POST 'a token' w/ hyphen word", http_("POST", "https://h.example.com/api/x", "{}"),
     "Re-sending a message in Slack"),
    ("env backup script", ("env", {"argv": ["./backup.sh"], "scripts": [_script("./backup.sh", BACKUP_SH)]}),
     "Running a backup script"),
    ("env read-only script", ("env", {"argv": ["./check.sh"], "scripts": [_script("./check.sh", CHECK_SH)]}),
     "Checking the health of a local service"),
    ("env script, two sentences", ("env", {"argv": ["./backup.sh"], "scripts": [_script("./backup.sh", BACKUP_SH)]}),
     "Running a backup script. It copies the data folder to the backup server."),
    ("env with ssh to host", ("env", {"argv": ["ssh", "root@host", "uptime"]}),
     "Checking how long a server has been running"),
    ("env docker compose up", ("env", {"argv": ["docker", "compose", "up", "-d"]}),
     "Starting the containers in a stack"),
    ("env python script", ("env", {"argv": ["python3", "sync.py"]}), "Syncing photos to a server"),
    ("env curl with custom UA", ("env", {"argv": ["curl", "-A", "my-agent/1.0", "https://x.example.com/a"]}),
     "Fetching a web page"),
    ("store create", ("store", {"op": "create", "item": "gh", "field": "token", "value": "v"}),
     "Saving a new credential"),
    ("store update", ("store", {"op": "update", "item": "gh", "field": "token", "value": "v"}),
     "Updating a saved credential"),
    ("ssh sign", ("ssh_sign", {"ssh": {"text": "login"}}), "Logging in to a server over SSH"),
    ("model empty reply", http_("GET", "https://h.example.com/a"), ""),
    ("model None content", http_("GET", "https://h.example.com/a"), None),
    ("model too long (170 chars)", http_("GET", "https://h.example.com/a"),
     "Retrieving " + "a very detailed list " * 8),
    ("model says UNCLEAR", http_("POST", "https://h.example.com/api/x", "{}"),
     "Unclear what this request does"),
    ("GET with 'API'", http_("GET", "https://h.example.com/a"), "Calling the Home Assistant API"),
    ("GET with 'request'", http_("GET", "https://h.example.com/a"), "Checking a pending request"),
    ("GET with 'allow'", http_("GET", "https://h.example.com/a"), "Listing the firewall allow rules"),
    ("GET Wi-Fi", http_("GET", "https://h.example.com/a"), "Listing Wi-Fi networks"),
    ("GET 'e.g.'", http_("GET", "https://h.example.com/a"), "Listing devices, e.g. phones"),
    ("GET with SHOUTING", http_("GET", "https://h.example.com/a"), "Listing DHCP leases on the router"),
    ("GET 'AWS'", http_("GET", "https://h.example.com/a"), "Listing AWS buckets"),
    ("GET 'UNIFI'", http_("GET", "https://h.example.com/a"), "Listing UNIFI clients"),
    ("GET with slash", http_("GET", "https://h.example.com/a"), "Reading the read/write status of a disk"),
    ("GET prompt echo", http_("GET", "https://h.example.com/a"),
     "Retrieving a list of models from OpenAI"),
    ("GET ends with period", http_("GET", "https://h.example.com/a"), "Listing the cameras."),
]


class _Stub(http.server.BaseHTTPRequestHandler):
    script = []          # [(text|None, finish_reason, delay)]
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        type(self).seen.append(body)
        text, finish, delay = type(self).script.pop(0) if type(self).script else ("x", "stop", 0)
        if delay:
            time.sleep(delay)
        out = json.dumps({"choices": [{"message": {"content": text}, "finish_reason": finish}],
                          "usage": {"cost": 0.0001}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def start_stub():
    handler = type("H", (_Stub,), {"script": [], "seen": []})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler


def run(cases=CASES, **describer_kw):
    srv, h = start_stub()
    try:
        d = D.Describer("stub-key", base_url=f"http://127.0.0.1:{srv.server_port}/v1",
                        max_per_minute=10_000, **describer_kw)
        rows = []
        for label, (mode, spec), reply in cases:
            h.script.append((reply, "stop", 0))
            got = d.describe(mode, ["x"], dict(spec))
            rows.append((label, reply, got))
        return rows
    finally:
        srv.shutdown()


def burst(n=8, delay=0.4, **kw):
    """n descriptions at once against a slow stub: returns the list of reasons (None = model)."""
    srv, h = start_stub()
    try:
        h.script.extend([("Retrieving a list of models", "stop", delay)] * n)
        d = D.Describer("stub-key", base_url=f"http://127.0.0.1:{srv.server_port}/v1", **kw)
        out = []

        def one():
            out.append(d.describe("http", ["x"], {"method": "GET", "url": "https://h.example.com/a",
                                                 "headers": {}})["reason"])
        ts = [threading.Thread(target=one) for _ in range(n)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        return out
    finally:
        srv.shutdown()


def cut_off():
    """A reply cut off at max_tokens (reasoning used the budget) and an empty reply."""
    srv, h = start_stub()
    try:
        d = D.Describer("stub-key", base_url=f"http://127.0.0.1:{srv.server_port}/v1")
        spec = {"method": "GET", "url": "https://h.example.com/a", "headers": {}}
        h.script.extend([("Retrieving a li", "length", 0), ("", "length", 0), ("  ", "stop", 0)])
        return [d.describe("http", ["x"], dict(spec))["reason"] for _ in range(3)], h.seen[0]["max_tokens"]
    finally:
        srv.shutdown()


def main():
    rows = run()
    bad = 0
    for label, reply, got in rows:
        if got["source"] != "model":
            bad += 1
            print(f"FALLBACK {got['reason']:<9} {(got.get('rule') or '-'):<15} {label}  <- {reply!r}")
    print(f"{bad} of {len(rows)} fell back")
    print("burst of 8 at once (concurrency 4):", sorted(map(str, burst())))
    print("cut off / empty replies (reason, max_tokens sent):", cut_off())


if __name__ == "__main__":
    main()
