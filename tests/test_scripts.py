"""Script contents for env-mode requests: client detection, integrity, broker
validation, the card, audit, scrubbing and the classifier / description input."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from secret_broker import audit_api, description, history, riskmodel, scripts as S, summarize  # noqa: E402
import test_e2e  # noqa: E402

CLI = os.path.join(HERE, "..", "client", "asb")


def load_client():
    loader = importlib.machinery.SourceFileLoader("asb_client", CLI)
    spec = importlib.util.spec_from_loader("asb_client", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


A = load_client()


class Files(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.cwd = os.getcwd()
        os.chdir(self.d)

    def tearDown(self):
        os.chdir(self.cwd)

    def write(self, name, data, mode=0o644):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)
        return p

    def paths(self, argv):
        return [e.get("path") or "stdin" for e in A.find_scripts(argv)]


class Detection(Files):
    def test_interpreter_and_script(self):
        p = self.write("deploy.sh", "#!/bin/sh\necho hi\n")
        self.write("sync.py", "print(1)\n")
        for argv in (["bash", "deploy.sh"], ["sh", "deploy.sh", "arg"], ["zsh", "-e", "deploy.sh"],
                     ["bash", "-x", "-o", "pipefail", "deploy.sh"], ["/bin/bash", "deploy.sh"],
                     ["dash", "--", "deploy.sh"], ["bash", "-eu", "deploy.sh"]):
            self.assertEqual(self.paths(argv), [p], argv)
        sp = os.path.join(self.d, "sync.py")
        for argv in (["python3", "sync.py"], ["python3.12", "-u", "sync.py"], ["python", "-W", "ignore", "sync.py"],
                     ["node", "-r", "dotenv/config", "sync.py"], ["ruby", "sync.py"], ["perl", "-w", "sync.py"],
                     ["php", "sync.py"], ["deno", "run", "-A", "sync.py"], ["bun", "run", "sync.py"],
                     ["bun", "sync.py"], ["awk", "-f", "sync.py", "data"], ["sed", "-f", "sync.py", "data"]):
            self.assertEqual(self.paths(argv), [sp], argv)

    def test_wrappers_are_skipped(self):
        p = self.write("deploy.sh", "#!/bin/sh\n")
        for argv in (["env", "A=1", "B=2", "bash", "deploy.sh"], ["env", "-u", "X", "bash", "deploy.sh"],
                     ["sudo", "-u", "root", "bash", "deploy.sh"], ["nohup", "bash", "deploy.sh"],
                     ["time", "bash", "deploy.sh"], ["timeout", "30", "bash", "deploy.sh"],
                     ["timeout", "-s", "KILL", "30", "bash", "deploy.sh"],
                     ["nice", "-n", "5", "bash", "deploy.sh"], ["nice", "-5", "bash", "deploy.sh"],
                     ["stdbuf", "-oL", "bash", "deploy.sh"], ["exec", "bash", "deploy.sh"],
                     ["command", "bash", "deploy.sh"],
                     ["nohup", "nice", "-n", "5", "env", "A=1", "timeout", "9", "bash", "deploy.sh"]):
            self.assertEqual(self.paths(argv), [p], argv)

    def test_inline_code_reads_no_file(self):
        self.write("deploy.sh", "#!/bin/sh\n")
        self.assertEqual(self.paths(["bash", "-c", "./deploy.sh"]), [os.path.join(self.d, "deploy.sh")])  # a shell string
        for argv in (["python3", "-c", "import x"],
                     ["python3", "-m", "http.server"], ["python3", "-m", "mod", "deploy.sh"],
                     ["node", "-e", "1"], ["node", "--eval", "1"], ["ruby", "-e", "1"], ["perl", "-e", "1"],
                     ["perl", "-ne", "print"], ["php", "-r", "1;"], ["deno", "eval", "1"],
                     ["awk", "{print}", "deploy.sh"], ["sed", "s/a/b/", "deploy.sh"], ["sed", "-n", "p"]):
            self.assertEqual(self.paths(argv), [], argv)

    def test_executable_script_itself(self):
        p = self.write("run.sh", "#!/bin/bash\necho\n", 0o755)
        q = self.write("noshebang", "echo hi\n", 0o755)
        self.assertEqual(self.paths(["./run.sh"]), [p])
        self.assertEqual(self.paths(["sudo", "./run.sh", "--flag"]), [p])
        self.assertEqual(self.paths([p]), [p])
        self.assertEqual(self.paths(["./noshebang"]), [q])           # with or without a shebang
        self.assertEqual(self.paths(["./nothere"]), [])              # not found, and not an interpreter

    def test_path_lookup_needs_a_shebang(self):
        bindir = os.path.join(self.d, "bin")
        os.mkdir(bindir)
        self.write("bin/tool.sh", "#!/bin/sh\necho\n", 0o755)
        self.write("bin/plain", "just text\n", 0o755)
        with mock.patch.dict(os.environ, {"PATH": bindir}):
            self.assertEqual(self.paths(["tool.sh"]), [os.path.join(bindir, "tool.sh")])
            self.assertEqual(self.paths(["plain"]), [])
        self.assertEqual(self.paths(["ls", "-l"]), [])               # a compiled program: nothing

    def test_binary_missing_permission(self):
        self.write("blob.py", b"\x00\x01\x02binary")
        e = A.find_scripts(["python3", "blob.py"])
        self.assertEqual(e, [{"path": os.path.join(self.d, "blob.py"), "unreadable": "binary"}])
        self.assertEqual(A.find_scripts(["bash", "gone.sh"]),
                         [{"path": os.path.join(self.d, "gone.sh"), "unreadable": "missing"}])
        self.assertEqual(A.find_scripts(["./blob.py"]), [])          # not executable text; not reported
        if os.getuid() != 0:
            p = self.write("secret.sh", "x", 0o000)
            self.assertEqual(A.find_scripts(["bash", "secret.sh"]), [{"path": p, "unreadable": "permission"}])
        os.mkdir("adir")
        self.assertEqual(A.find_scripts(["bash", "adir"]), [])

    def test_refused_paths(self):
        home = tempfile.mkdtemp()
        for sub in (".ssh", "tokens", ".config/secret-broker"):
            os.makedirs(os.path.join(home, sub))
            with open(os.path.join(home, sub, "x.sh"), "w") as f:
                f.write("TOPSECRET\n")
        with mock.patch.dict(os.environ, {"HOME": home}):
            for sub in (".ssh", "tokens", ".config/secret-broker"):
                for argv in (["bash", os.path.join(home, sub, "x.sh")], ["bash", f"~/{sub}/x.sh"]):
                    e = A.find_scripts(argv)
                    self.assertEqual(len(e), 1)
                    self.assertEqual(e[0]["unreadable"], "refused", argv)
                    self.assertNotIn("TOPSECRET", json.dumps(e))
            for argv in (["bash", "/proc/self/environ"], ["bash", "/sys/kernel/x"], ["bash", "/dev/zero"]):
                self.assertEqual(A.find_scripts(argv)[0]["unreadable"], "refused", argv)

    def test_symlink_is_resolved_once_and_refusal_checks_the_target(self):
        real = self.write("real.sh", "#!/bin/sh\necho\n")
        os.symlink(real, "link.sh")
        e = A.find_scripts(["bash", "link.sh"])
        self.assertEqual(e[0]["path"], real)                          # the resolved path is recorded
        home = tempfile.mkdtemp()
        os.makedirs(os.path.join(home, ".ssh"))
        key = os.path.join(home, ".ssh", "id")
        with open(key, "w") as f:
            f.write("PRIVATE")
        os.symlink(key, "innocent.sh")
        with mock.patch.dict(os.environ, {"HOME": home}):
            e = A.find_scripts(["bash", "innocent.sh"])
        self.assertEqual(e[0]["unreadable"], "refused")
        self.assertNotIn("PRIVATE", json.dumps(e))

    def test_size_caps_and_hash_of_whole_file(self):
        body = ("echo line\n" * 5000).encode()                       # 50 KB
        p = self.write("big.sh", body)
        e = A.find_scripts(["bash", "big.sh"])[0]
        self.assertTrue(e["truncated"])
        self.assertLessEqual(len(e["text"].encode()), 32 * 1024)
        self.assertEqual(e["size"], len(body))
        self.assertEqual(e["sha256"], hashlib.sha256(body).hexdigest())
        huge = ("# pad\n" * 60000).encode()                          # 360 KB: head only
        self.write("huge.sh", huge)
        e = A.find_scripts(["bash", "huge.sh"])[0]
        self.assertTrue(e["truncated"])
        self.assertEqual(e["sha256"], hashlib.sha256(huge).hexdigest())
        self.assertLessEqual(len(e["text"].encode()), 32 * 1024)
        self.write("small.sh", "echo\n")
        self.assertFalse(A.find_scripts(["bash", "small.sh"])[0]["truncated"])
        with mock.patch.object(A, "SCRIPT_HASH_MAX", 3):
            self.assertEqual(A.find_scripts(["bash", "small.sh"])[0]["unreadable"], "too_large")
        self.assertTrue(p)

    def test_utf8_cut_and_replacement(self):
        self.write("u.sh", ("\u00e9" * 20000).encode())              # 40 KB of 2-byte characters
        e = A.find_scripts(["bash", "u.sh"])[0]
        self.assertNotIn("\ufffd", e["text"])
        self.write("bad.sh", b"echo \xff\xfe ok\n")                  # a stray byte is still text
        self.assertIn("text", A.find_scripts(["bash", "bad.sh"])[0])

    def test_stdin_markers(self):
        self.write("x.sh", "echo\n")
        for argv in (["bash", "-s"], ["sh", "-s", "arg"], ["python3", "-"], ["bash", "-"], ["bash"],
                     ["python3"], ["sh", "/dev/stdin"], ["bash", "-s", "--", "x"], ["sudo", "bash", "-s"]):
            self.assertEqual(A.find_scripts(argv), [{"stdin": True}], argv)

    def test_three_file_cap_and_dedupe(self):
        for n in "abcde":
            self.write(f"{n}.awk", "{print}\n")
        argv = ["awk"]
        for n in "abcde":
            argv += ["-f", f"{n}.awk"]
        self.assertEqual(len(A.find_scripts(argv)), 3)
        self.assertEqual(len(A.find_scripts(["awk", "-f", "a.awk", "-f", "a.awk"])), 1)

    def test_control_chars_in_path_are_sanitized(self):
        self.write("we\x1bird\u202e.sh", "echo\n")
        e = A.find_scripts(["bash", "we\x1bird\u202e.sh"])[0]
        self.assertNotRegex(e["path"], "[\x00-\x1f\u202e]")
        S.validate([e])                                              # and the broker accepts it


# ------------------------------------------------------------------ integrity

class FakeBroker(BaseHTTPRequestHandler):
    """Just enough broker for the CLI: records the request, approves it, and may
    run a hook (to edit a script) between the request and the approval."""
    seen = []
    hook = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        FakeBroker.seen.append(json.loads(self.rfile.read(n)))
        self._send(202, {"id": "abc", "status": "pending", "expires_in": 30})

    def do_GET(self):
        if FakeBroker.hook:
            FakeBroker.hook()
        self._send(200, {"status": "approved", "env": {"SVC_TOKEN": "supersecretvalue"}})


class Integrity(Files):
    def setUp(self):
        super().setUp()
        FakeBroker.seen, FakeBroker.hook = [], None
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeBroker)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def run_asb(self, *argv):
        env = dict(os.environ, SECRET_BROKER_URL=f"http://127.0.0.1:{self.srv.server_address[1]}",
                   SECRET_BROKER_KEY="k")
        return subprocess.run([sys.executable, "-I", CLI, "svc", "--", *argv], env=env,
                              capture_output=True, text=True, timeout=30, cwd=self.d)

    def test_unchanged_script_runs_and_is_sent(self):
        self.write("job.sh", "#!/bin/sh\ntouch ran.flag\n")
        p = self.run_asb("sh", "job.sh")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.d, "ran.flag")))
        sent = FakeBroker.seen[0]
        self.assertEqual(sent["scripts"][0]["path"], os.path.join(self.d, "job.sh"))
        self.assertIn("touch ran.flag", sent["scripts"][0]["text"])

    def test_changed_after_approval_exits_6_and_runs_nothing(self):
        path = self.write("job.sh", "#!/bin/sh\ntouch ran.flag\n")

        def edit():
            with open(path, "a") as f:
                f.write("rm -rf /tmp/never\n")
        FakeBroker.hook = edit
        p = self.run_asb("sh", "job.sh")
        self.assertEqual(p.returncode, 6)
        self.assertIn(f"asb: script {path} changed after it was reviewed", p.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.d, "ran.flag")))
        self.assertNotIn("supersecretvalue", p.stdout + p.stderr)

    def test_deleted_script_counts_as_changed(self):
        path = self.write("job.sh", "#!/bin/sh\ntouch ran.flag\n")
        FakeBroker.hook = lambda: os.unlink(path)
        self.assertEqual(self.run_asb("sh", "job.sh").returncode, 6)

    def test_no_scripts_key_for_plain_commands(self):
        p = self.run_asb("echo", "hi")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("scripts", FakeBroker.seen[0])

    def test_exit_code_documented(self):
        for topic in ("guide", "help"):
            args = [topic] if topic == "guide" else [topic, "run"]
            out = subprocess.run([sys.executable, "-I", CLI, *args], capture_output=True, text=True).stdout
            self.assertRegex(out, r"(?s)exits? 6\b.*|6 env.*changed")
            self.assertIn("changed", out)


# ------------------------------------------------------------ broker validation

GOOD = {"path": "/srv/deploy.sh", "size": 12, "sha256": "a" * 64, "text": "echo hi\n", "truncated": False}


class Validation(unittest.TestCase):
    def test_accepts_the_three_shapes(self):
        out = S.validate([GOOD, {"path": "/x/y", "unreadable": "binary"}, {"stdin": True}])
        self.assertEqual(len(out), 3)
        self.assertEqual(S.validate(None), [])
        self.assertEqual(S.validate([]), [])

    def test_rejects_malformed(self):
        bad = [
            "x", {}, [GOOD] * 4, [1], [{"stdin": False}], [{"stdin": 1}], [{"stdin": True, "path": "/x"}],
            [{**GOOD, "extra": 1}], [{k: v for k, v in GOOD.items() if k != "text"}],
            [{**GOOD, "path": ""}], [{**GOOD, "path": "x" * 301}], [{**GOOD, "path": "a\nb"}],
            [{**GOOD, "path": 5}], [{**GOOD, "size": -1}], [{**GOOD, "size": "9"}], [{**GOOD, "size": True}],
            [{**GOOD, "size": 1.5}], [{**GOOD, "sha256": "abc"}], [{**GOOD, "sha256": "g" * 64}],
            [{**GOOD, "text": 5}], [{**GOOD, "text": "x" * (S.MAX_TEXT + 1)}],
            [{**GOOD, "truncated": "no"}], [{**GOOD, "truncated": 1}],
            [{"path": "/x", "unreadable": "weird"}], [{"path": "/x", "unreadable": True}],
            [{"path": "/x", "unreadable": "binary", "text": "t"}], [{"unreadable": "binary"}],
        ]
        for b in bad:
            with self.assertRaises(ValueError, msg=repr(b)[:80]):
                S.validate(b)

    def test_text_is_cleaned(self):
        out = S.validate([{**GOOD, "text": "a\x00b\x1b[31m\tc\r\nd\u202ee\x7f"}])[0]["text"]
        self.assertEqual(out, "ab[31m\tc\nde")

    def test_sha_is_normalised(self):
        self.assertEqual(S.validate([{**GOOD, "sha256": "AB" * 32}])[0]["sha256"], "ab" * 32)


class Scrubbing(unittest.TestCase):
    def test_secret_looking_values_are_redacted(self):
        secret = "Zk9sd2VyUXRXZXJ0eTEyMzQ1Njc4OWFiY2RlZg"
        cases = [
            f"TOKEN={secret}", f'export API_TOKEN="{secret}"', f"curl -H 'Authorization: Bearer {secret}' x",
            f"password=hunter2xyz", f"db_password: 'correct-horse'", "AKIAABCDEFGHIJKLMNOP",
            "ghp_" + "a1B2c3D4e5" * 4, "github_pat_" + "A" * 30, "xoxb-1234567890-abcdefghij",
            "sk-" + "a1b2c3d4" * 4, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
            "curl https://user:pa55w0rd@host/x", "curl -u admin:secret123 https://h/",
            "-H 'X-Api-Key: abcdef0123456789'",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
        ]
        for c in cases:
            out = S.scrub(c)
            self.assertIn("[redacted]", out, c)
            for frag in (secret, "hunter2xyz", "correct-horse", "AKIAABCDEFGHIJKLMNOP", "pa55w0rd",
                         "secret123", "abcdef0123456789", "MIIEabc"):
                self.assertNotIn(frag, out, c)

    def test_variables_and_ordinary_text_survive(self):
        keep = ['curl -H "Authorization: Bearer $TOKEN" https://api/x', "TOKEN=$(cat /run/x)", "TOKEN=${VAR}",
                "password=$PASS", "echo hello world", "token_file=/etc/token", "KEY={{SVC_TOKEN}}",
                "# deploy script v1.2", "rm -rf build/", "sha256sum file"]
        for k in keep:
            self.assertEqual(S.scrub(k), k)

    def test_idempotent(self):
        t = S.scrub("password=abcdefgh and token=Zk9sd2VyUXRXZXJ0eTEyMzQ1")
        self.assertEqual(S.scrub(t), t)

    def test_validate_scrubs_before_storage(self):
        out = S.validate([{**GOOD, "text": "export TOKEN=Zk9sd2VyUXRXZXJ0eTEyMzQ1Njc4\n"}])
        self.assertNotIn("Zk9sd2Vy", out[0]["text"])


# ------------------------------------------------------------ broker end to end

SCRIPT_TEXT = "#!/bin/sh\ncurl -s https://api.example.com/status\n"
SHA = hashlib.sha256(SCRIPT_TEXT.encode()).hexdigest()


def entry(**kw):
    e = {"path": "/srv/job.sh", "size": len(SCRIPT_TEXT), "sha256": SHA, "text": SCRIPT_TEXT, "truncated": False}
    e.update(kw)
    return e


class BrokerScripts(test_e2e.Harness):
    decision = None             # leave requests pending so cards can be read

    def post(self, scripts, mode="env", **extra):
        body = {"mode": mode, "names": ["svc"], "argv": ["sh", "/srv/job.sh"], "scripts": scripts}
        if mode == "http":
            body.update(method="GET", url="http://127.0.0.1/x")
        body.update(extra)
        return self.api("POST", "/v1/requests", body)

    def test_bad_shapes_are_400(self):
        for bad in ("x", [entry(sha256="zz")], [entry(), entry(), entry(), entry()], [{"stdin": 0}],
                    [entry(extra=1)], [entry(text=7)]):
            self.assertEqual(self.post(bad)[0], 400, bad)
        self.assertEqual(self.post([entry()], mode="http")[0], 400)       # env only
        self.assertEqual(self.post([], mode="http")[0], 400)
        self.assertEqual(self.post([entry()])[0], 202)

    def test_stored_on_request_and_card_shows_it(self):
        code, body = self.post([entry(), {"path": "/srv/b.bin", "unreadable": "binary"}, {"stdin": True}])
        self.assertEqual(code, 202, body)
        req = next(iter(self.broker._by_id.values()))
        self.assertEqual(len(req.spec["scripts"]), 3)
        nonce = req.nonce
        r = urllib.request.Request(self.abase + f"/a/{nonce}", headers={"X-authentik-username": "alice"})
        page = urllib.request.urlopen(r, timeout=10).read().decode()
        self.assertIn("<details class=scripts><summary>Script contents (reported by the client)</summary>", page)
        self.assertIn("/srv/job.sh", page)
        self.assertIn(SHA[:12], page)
        self.assertIn("curl -s https://api.example.com/status", page)
        self.assertIn("Script could not be read: binary", page)
        self.assertIn("Script is read from standard input and cannot be shown", page)
        r = urllib.request.Request(self.abase + "/", headers={"X-authentik-username": "alice"})
        dash = urllib.request.urlopen(r, timeout=10).read().decode()
        self.assertIn("Script contents (reported by the client)", dash)

    def test_hostile_text_is_escaped(self):
        hostile = ("<script>alert(1)</script>\n<img src=x onerror=alert(2)>\n" + "A" * 30000
                   + "\x1b[2J\x07</pre><details open>")
        code, _ = self.post([entry(text=hostile, path="/x/<b>evil</b>.sh")])
        self.assertEqual(code, 202)
        req = next(iter(self.broker._by_id.values()))
        page = test_e2e.req(self.abase + f"/a/{req.nonce}", headers={"X-authentik-username": "alice"})[1]
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<b>evil</b>", page)
        self.assertNotIn("\x1b", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertEqual(page.count("</pre>"), 1)
        self.assertEqual(page.count("<details open>"), 0)

    def test_text_never_in_notifications_or_audit(self):
        marker = "UNIQUE_SCRIPT_BODY_MARKER_42"
        code, _ = self.post([entry(text=f"#!/bin/sh\n# {marker}\necho ok\n"),
                             {"path": "/srv/other.sh", "unreadable": "missing"}, {"stdin": True}])
        self.assertEqual(code, 202)
        self.assertNotIn(marker, json.dumps(self.notifier.sent, default=str))
        with open(self.audit) as f:
            log = f.read()
        self.assertNotIn(marker, log)
        ev = self.events("requested")[0]
        self.assertEqual(ev["script_paths"], ["/srv/job.sh", "/srv/other.sh"])
        self.assertEqual(ev["script_sha256"], [SHA, ""])
        self.assertEqual(ev["script_sizes"], [len(SCRIPT_TEXT), -1])
        self.assertEqual(ev["script_markers"], ["missing", "stdin"])
        self.assertNotIn("text", ev)

    def test_audit_api_whitelist_carries_the_new_fields_only(self):
        rec = {"event": "requested", "id": "r1", "seq": 1, "ts": 1.0, "names": ["svc"], "mode": "env", "argv": ["sh", "j"],
               "script_paths": ["/a.sh"], "script_sha256": [SHA], "script_sizes": [5],
               "script_markers": ["stdin"], "script_text": "SHOULD NOT SHOW", "scripts": [{"text": "x"}]}
        out = audit_api.redact(rec)
        self.assertEqual(out["script_paths"], ["/a.sh"])
        self.assertEqual(out["script_sha256"], [SHA])
        self.assertEqual(out["script_sizes"], [5])
        self.assertEqual(out["script_markers"], ["stdin"])
        self.assertNotIn("script_text", out)
        self.assertNotIn("scripts", out)
        out = audit_api.redact({**rec, "script_sizes": ["x", True, 3]})
        self.assertEqual(out["script_sizes"], [3])

    def test_history_has_path_size_sha_only(self):
        self.post([entry()])
        h = history.History(self.audit)
        h.refresh()
        row = next(iter(h._rows.values()))
        self.assertEqual(row["scripts"], [{"path": "/srv/job.sh", "size": len(SCRIPT_TEXT), "sha": SHA[:12]}])
        self.assertNotIn("curl -s", json.dumps(row))


# --------------------------------------------------- classifier and description

BIG = {"argv": ["bash", "deploy.sh"], "scripts": [
    {"path": "/home/u/deploy.sh", "size": 9000, "sha256": "b" * 64, "text": "echo start\n" * 800,
     "truncated": True}]}


class ModelInput(unittest.TestCase):
    def test_caps_markers_and_names(self):
        spec = {"argv": ["bash", "a.sh"], "scripts": [
            {"path": "/p/q/a.sh", "size": 20000, "sha256": "c" * 64, "text": "x" * 20000, "truncated": False},
            {"path": "/p/b.sh", "size": 20000, "sha256": "d" * 64, "text": "y" * 20000, "truncated": False},
            {"path": "/p/c.bin", "unreadable": "binary"}, {"stdin": True}]}
        f = riskmodel.request_fields("env", ["svc"], spec, 400, True, 4000)
        sc = f["scripts"]
        self.assertEqual(sc[0]["name"], "a.sh")
        self.assertNotIn("/p/q", json.dumps(sc))
        self.assertEqual(len(sc[0]["text"]), 4000)
        self.assertTrue(sc[0]["text_truncated"])
        self.assertEqual(sc[0]["sha256_prefix"], "c" * 12)
        self.assertEqual(len(sc[1]["text"]), 2000)                       # total cap 6000
        self.assertEqual(sc[2]["unreadable"], "binary")
        self.assertTrue(sc[3]["stdin"])
        self.assertLessEqual(sum(len(s.get("text", "")) for s in sc), 6000)

    def test_no_scripts_no_key_and_send_content_false(self):
        self.assertNotIn("scripts", riskmodel.request_fields("env", ["x"], {"argv": ["ls"]}))
        f = riskmodel.request_fields("env", ["x"], BIG, send_content=False)
        self.assertEqual(f["scripts"][0]["text"], "<not shown>")
        self.assertEqual(f["command"], "<not shown>")

    def test_scrubbed_before_model(self):
        spec = {"argv": ["bash", "a.sh"], "scripts": [
            {"path": "/a.sh", "size": 5, "sha256": "e" * 64,
             "text": "TOKEN=Zk9sd2VyUXRXZXJ0eTEyMzQ1Njc4\ncurl -H 'Authorization: Bearer abcdefghijklmnopqrstuv'\n",
             "truncated": False}]}
        blob = json.dumps(riskmodel.request_fields("env", ["x"], spec))
        self.assertNotIn("Zk9sd2Vy", blob)
        self.assertNotIn("abcdefghijklmnopqrstuv", blob)
        self.assertIn("[redacted]", blob)

    def test_jev_payload_adds_script_rubric_only_with_scripts(self):
        a = riskmodel.JevAnalyzer("K", summary_mode="none")
        plain = a.payload("env", ["x"], {"argv": ["ls"]})
        withs = a.payload("env", ["x"], BIG)
        ins = lambda p: p["questions"]["risk"]["instructions"]  # noqa: E731
        self.assertNotIn("SCRIPTS.", ins(plain))
        self.assertTrue(ins(withs).startswith(riskmodel.RUBRIC))
        self.assertIn(riskmodel.SCRIPT_RUBRIC, ins(withs))
        self.assertEqual(len(withs["state"]["request"]["scripts"][0]["text"]), 4000)
        small = riskmodel.JevAnalyzer("K", summary_mode="none", max_script_chars=100)
        self.assertEqual(len(small.payload("env", ["x"], BIG)["state"]["request"]["scripts"][0]["text"]), 100)
        self.assertLess(len(json.dumps(withs)), 32000)

    def test_deterministic_summary_ignores_script_text(self):
        s = riskmodel.deterministic_summary("env", ["x"], BIG)
        self.assertEqual(s, "auto: run bash deploy.sh")

    def test_config_validation(self):
        base = {"type": "jev", "api_key_file": "/k"}
        riskmodel.validate_config({**base, "max_script_chars": 0})
        riskmodel.validate_config({**base, "max_script_chars": 4000})
        for bad in (-1, "4000", True, 1.5, riskmodel.MAX_SCRIPT_CHARS_LIMIT + 1):
            with self.assertRaises(ValueError, msg=bad):
                riskmodel.validate_config({**base, "max_script_chars": bad})
        fa = riskmodel.build({**base, "max_script_chars": 77, "summary_text": "none"}, lambda p: "key")
        self.assertEqual(fa.inner._max_script, 77)

    def test_legacy_openrouter_describe_text(self):
        t = summarize.describe("env", ["x"], BIG, 300, True)
        self.assertIn("script (untrusted file contents):", t)
        self.assertEqual(json.loads(t.split("script (untrusted file contents): ")[1])["text"].count("echo"), 27)
        t0 = summarize.describe("env", ["x"], BIG, 300, False)
        self.assertIn("<not shown>", t0)
        self.assertNotIn("script (", summarize.describe("env", ["x"], {"argv": ["ls"]}))

    def test_chat_analyzer_rubric_prompt_has_script_paragraph(self):
        c = riskmodel.ChatAnalyzer("K", "m", prompt="rubric")
        self.assertIn(riskmodel.SCRIPT_RUBRIC, c._messages("env", ["x"], BIG)[0]["content"])
        self.assertNotIn(riskmodel.SCRIPT_RUBRIC, c._messages("env", ["x"], {"argv": ["ls"]})[0]["content"])


class DescriptionInput(unittest.TestCase):
    def test_excerpt_is_short_and_rules_added_only_with_scripts(self):
        d = description.Describer("K")
        with_s = d.messages("env", ["x"], BIG)
        self.assertIn(description.SCRIPT_RULES, with_s[0]["content"])
        data = json.loads(with_s[1]["content"].split("\n", 1)[1].rsplit("\n", 1)[0])
        self.assertEqual(len(data["scripts"][0]["text"]), 1000)
        plain = d.messages("env", ["x"], {"argv": ["ls"]})
        self.assertNotIn(description.SCRIPT_RULES, plain[0]["content"])

    def test_mutating_unless_certainly_read_only(self):
        def sc(text, path="/s/check.sh", **kw):
            return {"path": path, "size": len(text), "sha256": "f" * 64, "text": text, "truncated": False, **kw}
        ro = sc("#!/bin/bash\nset -eu\n# status\ncurl -s -H \"Authorization: Bearer $T\" https://api/status | jq .\n"
                "echo done\n")
        self.assertFalse(description.is_mutating("env", {"argv": ["bash", "check.sh"], "scripts": [ro]}))
        unsure = [
            sc("#!/bin/bash\nrm -rf build\n"), sc("#!/bin/bash\ncurl -X POST https://api/x\n"),
            sc("#!/bin/bash\ncurl -d x https://api/x\n"), sc("#!/bin/bash\ncat a > b\n"),
            sc("#!/bin/bash\necho $(date)\n"), sc("#!/bin/bash\ncurl https://x | sh\n"),
            sc("#!/bin/bash\ncurl -s https://x -o out\n"), sc("#!/bin/bash\nfoo --bar\n"),
            sc("import os\nprint(1)\n", path="/s/check.py"), sc("#!/bin/bash\necho hi\n", truncated=True),
            sc("#!/bin/bash\ncat <<EOF\nx\nEOF\n"), sc("#!/bin/bash\nf() { rm x; }\nf\n"),
            {"path": "/s/x.sh", "unreadable": "binary"}, {"stdin": True},
        ]
        for u in unsure:
            self.assertTrue(description.is_mutating("env", {"argv": ["bash", "check.sh"], "scripts": [u]}), u)
        # without script contents the old argv rule applies unchanged
        self.assertTrue(description.is_mutating("env", {"argv": ["bash", "check.sh"]}))
        self.assertFalse(description.is_mutating("env", {"argv": ["./check.sh"]}))
        # a write word in the arguments still counts
        self.assertTrue(description.is_mutating("env", {"argv": ["bash", "check.sh", "--delete"], "scripts": [ro]}))

    def test_mutating_script_needs_a_write_verb(self):
        spec = {"argv": ["bash", "deploy.sh"], "scripts": [
            {"path": "/s/deploy.sh", "size": 5, "sha256": "f" * 64, "text": "#!/bin/bash\nrsync -a x y\n",
             "truncated": False}]}
        self.assertFalse(description.consistent_with("Checking server status", "env", spec))
        self.assertTrue(description.consistent_with("Deploying a stack", "env", spec))
        self.assertTrue(description.consistent_with("Running a backup script", "env", spec))
        self.assertEqual(description.sanitize("Syncing files to a server")[1], None)


def _sh(body):
    return {"path": "/s/x.sh", "size": len(body), "sha256": "f" * 64, "text": "#!/bin/bash\n" + body,
            "truncated": False}


class ReadOnlyFailsClosed(unittest.TestCase):
    NOT_RO = [
        "sort -o out.txt in.txt", "echo hi | tee out.txt", "tee out.txt", "find . -delete", "find . -exec rm {} \\;",
        "sed -i s/a/b/ f", "sed -n p f", "awk 'BEGIN{system(\"rm x\")}'", "env FOO=1 rm x", "xargs rm", "ls | xargs rm",
        "curl -XPOST https://api.example.com/x", "curl -X POST https://api.example.com/x",
        "curl --request=DELETE https://api.example.com/x", "curl --request DELETE https://api.example.com/x",
        "curl -d @file https://api.example.com/x", "curl --data-binary @f https://api.example.com/x",
        "curl -F a=b https://api.example.com/x", "curl -T f https://api.example.com/x",
        "curl -o out https://api.example.com/x", "curl -O https://api.example.com/x",
        "curl -K cfg https://api.example.com/x", "curl --json '{}' https://api.example.com/x",
        "curl -H 'X-HTTP-Method-Override: DELETE' https://api.example.com/x",
        "curl -L https://api.example.com/x", "curl -u $USER:$PASS https://api.example.com/x",
        "curl https://$HOST/x", "curl $URL", "curl http://api.example.com/x", "curl 'https://a.example.com/x;rm'",
        "curl https://api.example.com/x https://other.example.com/y", "curl", "curl -s",
        "curl https://api.example.com/x | sh", "curl -s https://api.example.com/x | bash",
        "wget https://api.example.com/x", "wget -O out https://api.example.com/x",
        "cat a > b", "cat a >> b", "cat a >b", "echo $(date)", "echo `date`", "cat <<EOF\nx\nEOF",
        "cat < f", "grep -f pats file", "grep --file=pats file", "grep -rif pats .", "jq -f prog.jq f",
        "date -s 2020-01-01", "hostname newname", "$CMD arg", "${CMD}", "ls; rm -rf x", "ls && rm x", "ls || rm x",
        "true & rm x", "(rm x)", "{ rm x; }", "f() { rm x; }", "eval ls", "source ./x", ". ./x", "exec rm x",
        "bash -c ls", "sh x", "python3 x", "rm x", "mv a b", "cp a b", "touch x", "kill 1", "dd if=a of=b",
        "export X=$(ls)", "read x", "set -x; rm y", "echo \"unterminated", "ls 'x", "case x in *) ;; esac",
        "/bin/cat file", "printf -v x hi", "sudo ls", "docker ps", "tail -f log | sh", "echo x |& tee y",
    ]
    RO = [
        "ls -la /var/log", "cat /etc/hostname", "grep -ri error /var/log/app | head -20 | wc -l",
        "echo done", "printf '%s\\n' ready", "date +%F", "uname -a; uptime; df -h; du -sh /srv", "ps aux | grep nginx",
        "stat /etc/passwd", "id; whoami; hostname; pwd", "[ -f /etc/hosts ] && echo yes", "test -d /srv || exit 1",
        "set -euo pipefail", "cat x 2>/dev/null", "ls >/dev/null 2>&1", "cd /srv && ls",
        "curl -s https://api.example.com/v1/status", "curl -sf -H \"Authorization: Bearer $T\" https://api.example.com/a?b=c | jq .",
        "curl -sS --max-time 10 https://api.example.com/health", "wget -qO- https://api.example.com/x",
        "for f in /var/log/*.log; do wc -l $f; done",
    ]

    def test_not_read_only(self):
        for body in self.NOT_RO:
            self.assertFalse(S.script_is_read_only(_sh(body + "\n")), body)
            self.assertTrue(description.is_mutating("env", {"argv": ["bash", "x.sh"], "scripts": [_sh(body + "\n")]}), body)

    def test_certainly_read_only(self):
        for body in self.RO:
            self.assertTrue(S.script_is_read_only(_sh(body + "\n")), body)

    def test_one_bad_line_anywhere_poisons_the_script(self):
        self.assertFalse(S.script_is_read_only(_sh("ls\n# fine\necho ok\nsort -o f f\nls\n")))
        self.assertFalse(S.script_is_read_only(_sh("ls \\\n  ; rm x\n")))
        self.assertFalse(S.script_is_read_only(_sh("if ls; then rm x; fi\n")))

    def test_pathological_script_is_not_slow_or_read_only(self):
        t0 = time.monotonic()
        self.assertFalse(S.script_is_read_only(_sh("echo " + "'" * 30001)))
        self.assertFalse(S.script_is_read_only(_sh("ls;" * 10000 + "rm x")))
        self.assertLess(time.monotonic() - t0, 2)


class ScrubberIsLinear(unittest.TestCase):
    def timed(self, text):
        t0 = time.monotonic()
        out = S.scrub(text)
        dt = time.monotonic() - t0
        self.assertLess(dt, 1.0, repr(text[:30]))
        return out

    def test_pathological_inputs_finish_quickly(self):
        n = 32 * 1024
        cases = ["password" * 4000, ("a_" * 16000) + "token", ("Ab0_-" * 7000), "secret=" * 4500, "secret = '" * 3000,
                 "token " + " " * 30000, "bearer " * 4500, "sk-" * 10000, "eyJ" * 10000, "ghp_" * 8000,
                 "AKIA" * 8000, "://" * 10000, " -u a:" * 5000, "-----BEGIN PRIVATE KEY-----" * 1200,
                 "\"'" * 16000, "auth" + "a" * 32000, ("x" * 60 + "token=") * 500, "token=" + "A" * 32000,
                 "password=" + "'\"" * 16000, "api_key" + "_" * 32000, "a=" * 16000]
        for c in cases:
            out = self.timed(c[:n])
            self.assertIsInstance(out, str)

    def test_realistic_redaction_still_works(self):
        out = S.scrub("TOKEN=Zk9sd2VyUXRXZXJ0eTEyMzQ1\ncurl -H 'Authorization: Bearer abcdefghijklmnopqrstuv' x\n"
                      "password = 'hunter2xyz'\ncurl https://u:pa55w0rd@h/x\n-----BEGIN PRIVATE KEY-----\nMIIE\n"
                      "-----END PRIVATE KEY-----\necho done\n")
        for frag in ("Zk9sd2Vy", "abcdefghijklmnopqrstuv", "hunter2xyz", "pa55w0rd", "MIIE"):
            self.assertNotIn(frag, out)
        self.assertIn("echo done", out)
        self.assertIn("TOKEN=" + S.REDACTED, out)

    def test_budget_exceeded_withholds_everything(self):
        text = "echo before\nTOKEN=Zk9sd2VyUXRXZXJ0eTEyMzQ1\n" * 50
        self.assertEqual(S.scrub(text, budget=-1), S.WITHHELD)
        with mock.patch.object(S, "BUDGET_S", -1):
            out = S.validate([{**GOOD, "text": text}])[0]["text"]
        self.assertEqual(out, S.WITHHELD)
        self.assertNotIn("echo before", out)
        self.assertEqual(S.scrub(S.WITHHELD), S.WITHHELD)
        self.assertEqual(S.scrub("x" * (2 * S.MAX_TEXT + 1)), S.WITHHELD)

    def test_hit_cap_bounds_work(self):
        # (updated: reaching the hit cap now withholds the whole text instead of partial scrubbing)
        out = self.timed("TOKEN=Zk9sd2VyUXRXZXJ0eTEyMzQ1\n" * 1000)
        self.assertEqual(out, S.WITHHELD)


class ScrubHardening(unittest.TestCase):
    BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"

    def test_private_key_variants_never_leave_body(self):
        b = self.BODY
        cases = [
            f"-----BEGIN PRIVATE KEY-----\n{b}\n",                                   # no END at all
            f"-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY",               # END line cut
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{b}\n-----END OPENSSH PRIVATE KEY-----\n",
            f"-----BEGIN PRIVATE KEY-----\n{b}\n" + "x\n" * 9000 + "-----END PRIVATE KEY-----\n",
            f"-----BEGIN PRIVATE KEY-----\n{b}\n" + "y" * 20000 + "\n-----END PRIVATE KEY-----\n",
            f"-----BEGIN RSA PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n",
            f"-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\n-----BEGIN PRIVATE KEY-----\n{b}2\n",
        ]
        for c in cases:
            out = S.scrub(c)
            self.assertNotIn(b[:20], out, c[:60])
            self.assertNotIn(b[-20:], out, c[:60])
            self.assertEqual(S.scrub(out), out)            # idempotent
        # text after a closed key block is kept
        out = S.scrub(f"-----BEGIN PRIVATE KEY-----\n{b}\n-----END PRIVATE KEY-----\necho done\n")
        self.assertIn("echo done", out)

    def test_invalid_span_fails_closed(self):
        with self.assertRaises(S._Budget):
            S._apply("abc", [(2, 1)])
        with self.assertRaises(S._Budget):
            S._apply("abc", [(0, 9)])
        with mock.patch.object(S, "_private_key_spans", return_value=[(5, 2)]):
            self.assertEqual(S.scrub("-----BEGIN PRIVATE KEY-----\nabc"), S.WITHHELD)

    def test_caps_withhold(self):
        key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        self.assertEqual(S.scrub(key * (S.MAX_KEYS + 1)), S.WITHHELD)
        self.assertNotEqual(S.scrub(key * S.MAX_KEYS), S.WITHHELD)
        self.assertEqual(S.scrub("curl https://u:pa55word1@h/\n" * (S.MAX_HITS + 5)), S.WITHHELD)
        self.assertEqual(S.scrub("curl -u adm:pa55word1 h\n" * (S.MAX_HITS + 5)), S.WITHHELD)
        self.assertEqual(S.scrub("ghp_" + "a" * 40 + "\n" * 1 + ("ghp_" + "b" * 40 + "\n") * (S.MAX_HITS + 5)),
                         S.WITHHELD)
        self.assertEqual(S.scrub("password=hunter22x\n" * (S.MAX_HITS + 5)), S.WITHHELD)
        # non-matching keyword hits are not "real matches"
        self.assertEqual(S.scrub("auth\n" * (S.MAX_HITS * 3)), "auth\n" * (S.MAX_HITS * 3))

    def test_long_values_leave_no_tail(self):
        jwt = "eyJ" + "a" * 297 + "." + "b" * 300 + "." + "c" * 250
        ghp = "ghp_" + "Z9" * 75
        for tok, tail in ((jwt, "c" * 20), (ghp, "Z9Z9Z9")):
            out = S.scrub(f"X {tok} Y")
            self.assertEqual(out, "X [redacted] Y")
        self.assertEqual(S.scrub("sk-" + "q" * 400), "[redacted]")
        self.assertEqual(S.scrub("password=" + "w" * 350), "password=[redacted]")
        self.assertNotIn("p" * 10, S.scrub("curl https://u:" + "p" * 300 + "@h/"))


class ReadOnlyHardening(unittest.TestCase):
    def ro(self, body):
        return S.script_is_read_only(_sh(body + "\n"))

    def test_abbreviated_and_unlisted_flags_rejected(self):
        for body in ("date --se=2020-01-01", "date -s 2020-01-01", "date -uo", "date --set 1", "date -f x",
                     "date foo", "hostname newname", "hostname -F f", "hostname -b x", "hostname --fq",
                     "printf -v x hi", "printf", "ls --col=always", "ls --time-style=x",
                     "cat --nu x", "cat --vers", "head --lines=1 x", "tail -f x", "tail --foll x",
                     "grep --file=x y", "grep --exclude-from=x y z", "grep -f x y", "grep --ex x y",
                     "grep -rf x .", "wc --files0-from=x", "wc --fi x", "du --files0-from=x", "ps --sort x",
                     "stat --format=x y", "uname --ker", "jq --from-file x", "jq -f x", "jq --arg"[:5] + "x",
                     "id --gr", "df --out", "uptime --pre"):
            self.assertFalse(self.ro(body), body)

    def test_normal_use_still_passes(self):
        for body in ("date +%F", "date -u +%s", "date", "date -R", "hostname", "hostname -s", "printf '%s\\n' hi",
                     "ls -la /srv", "ls -lh", "cat -n x", "head -n 5 x", "head -5 x", "tail -n5 x",
                     "grep -rin foo .", "grep -A3 foo x", "grep --ignore-case foo x", "wc -l x",
                     "du -sh .", "df -h", "ps aux", "ps -ef", "stat -c %s x", "uname -a", "id -u",
                     "uptime -p", "jq -r .a x.json", "echo -n hi", "whoami", "pwd"):
            self.assertTrue(self.ro(body), body)

    def test_command_prefix_assignments_rejected(self):
        for body in ("PATH=/tmp/x cat f", "LD_PRELOAD=/tmp/x.so ls", "X=1 ls", "IFS=: cat f", "FOO=bar",
                     "PATH=/tmp/x\nls", "if PATH=/x ls; then echo hi; fi", "while X=1 ls; do echo hi; done",
                     "BASH_ENV=/tmp/e cat f", "GIT_SSH_COMMAND=x ls", "https_proxy=x curl -s https://a.example/x",
                     "for PATH in a b; do ls; done"):
            self.assertFalse(self.ro(body), body)
        self.assertTrue(self.ro("for f in a b; do ls $f; done"))


if __name__ == "__main__":
    unittest.main()


# -- argv detection: broker and client share one table; hardening cases -------------
NEST5 = ["env", "-S", "env -S 'env -S \"env -S \\\"env -S \\\\\\\"bash x.sh\\\\\\\"\\\"\"'"]
X = ["x.sh"]
# (argv, script paths both sides must report, understood?)
DETECT_TABLE = (
    # honest simple commands that qualify
    (["cat", "/etc/hostname"], [], True),
    (["curl", "-s", "https://example.com/health"], [], True),
    (["bash", "deploy.sh"], ["deploy.sh"], True),
    (["sudo", "-u", "app", "python3", "sync.py"], ["sync.py"], True),
    (["timeout", "30", "bash", "x.sh"], X, True),
    (["sh", "-c", "echo hi && date"], [], True),
    (["bash", "-c", "echo hi"], [], True),
    (["/usr/bin/curl", "https://e.com"], [], True),
    (["/usr/bin/./cat", "f"], [], True),
    (["./run.sh"], ["./run.sh"], True),
    (["/opt/tools/run"], ["/opt/tools/run"], True),
    (["deploy.sh"], ["deploy.sh"], True),
    (["sed", "-f", "p.sed", "in"], ["p.sed"], True),
    (["bash"], ["-"], True),
    (["bash", "-s"], ["-"], True),
    # (a) the allowlist: only programs that cannot run other commands
    (["ls", "-l", "/tmp/x.py"], [], True),
    (["grep", "-rn", "foo", "src/"], [], True),
    (["grep", "-f", "pats", "x"], [], False),
    (["grep", "--file=pats", "x"], [], False),
    (["curl", "-K", "cfg", "https://e.com"], [], False),
    (["curl", "--config", "cfg", "https://e.com"], [], False),
    (["curl", "-T", "f", "https://e.com"], [], False),
    (["curl", "-sSo", "out", "https://e.com"], [], False),
    (["curl", "-O", "https://e.com/x"], [], False),
    (["curl", "--output=x", "https://e.com"], [], False),
    (["curl", "-d", "@body.json", "https://e.com"], [], False),
    (["curl", "-H", "X-A: b", "-s", "https://e.com"], [], True),
    (["wget", "-qO-", "https://e.com"], [], False),
    (["wget", "-q", "https://e.com"], [], False),
    (["sort", "-o", "out", "in"], [], False),
    (["sort", "--compress-program=sh", "in"], [], False),
    (["sort", "-n", "in"], [], True),
    (["uniq", "in", "out"], [], False),
    (["openssl", "x509", "-engine", "e"], [], False),
    (["openssl", "x509", "-in", "c.pem"], [], False),
    (["/tmp/cat", "x"], ["/tmp/cat"], True),
    (["/usr/bin/git", "status"], [], False),
    # programs that can run commands are never on the allowlist
    (["git", "status"], [], False),
    (["git", "-c", "alias.x=!sh x.sh", "x"], [], False),
    (["find", ".", "-exec", "sh", "x.sh", "{}", ";"], [], False),
    (["make", "deploy"], [], False),
    (["npm", "run", "x"], [], False),
    (["tar", "--to-command=sh", "-xf", "a.tar"], [], False),
    (["sqlite3", "db", ".shell cmd"], [], False),
    (["docker", "compose", "up"], [], False),
    (["ssh", "host", "ls"], [], False),
    (["mytool", "run.sh"], [], False),
    (["mytool"], [], False),
    # (b) interpreters
    (["python3", "-c", "print(1)"], [], False),
    (["python3", "-m", "http.server"], [], False),
    (["node", "-e", "1"], [], False),
    (["node", "-r", "./evil.js", "x.js"], [], False),
    (["perl", "-MEvil", "x.pl"], [], False),
    (["bash", "--rcfile", "r", "-c", "echo"], [], False),
    (["sed", "s/a/b/"], [], False),
    (["sed", "-f", "p.sed", "-e", "e id"], [], False),
    (["awk", "{print}"], [], False),
    (["python3", "-u", "a/b.py"], ["a/b.py"], True),
    (["python3.12", "x.py"], ["x.py"], True),
    (["fish", "-c", "echo hi"], [], False),
    # shell strings: restricted shell, every segment understood
    (["sh", "-c", "echo hi; date | wc -l"], [], True),
    (["sh", "-c", "echo hi 2>&1"], [], True),
    (["sh", "-c", "echo 'a b' && bash x.sh"], X, True),
    (["sh", "-c", "echo hi\nbash x.sh"], [], False),
    (["sh", "-c", "echo hi # c"], [], False),
    (["sh", "-c", "echo `id`"], [], False),
    (["sh", "-c", "echo $(id)"], [], False),
    (["sh", "-c", "echo $HOME"], [], False),
    (["sh", "-c", "echo ${HOME}"], [], False),
    (["sh", "-c", "echo \\x"], [], False),
    (["sh", "-c", "cat <<EOF"], [], False),
    (["sh", "-c", "cat <(id)"], [], False),
    (["sh", "-c", "echo hi > f"], [], False),
    (["sh", "-c", "echo hi &"], [], False),
    (["sh", "-c", "if true; then echo; fi"], [], False),
    (["sh", "-c", "for i in 1; do echo; done"], [], False),
    (["sh", "-c", "echo a; { echo b; }"], [], False),
    (["sh", "-c", "echo {a,b}"], [], False),
    (["sh", "-c", "(echo a)"], [], False),
    (["sh", "-c", "A=1 echo a"], [], False),
    (["sh", "-c", "! echo a"], [], False),
    (["sh", "-c", "echo a; git status"], [], False),
    (["sh", "-c", "echo 'unterminated"], [], False),
    (["sh", "-c", "./*.sh"], [], False),
    (["sh", "-c"], [], False),
    # (c) wrappers
    (["env", "LANG=C", "node", "app.js"], ["app.js"], True),
    (["env", "BASH_ENV=x.sh", "bash", "-c", "echo"], [], False),
    (["env", "LD_PRELOAD=x.so", "cat", "f"], [], False),
    (["env", "-i", "-0", "-v", "--ignore-environment", "bash", "x.sh"], [], False),
    (["env", "-u", "FOO", "--unset=BAR", "--unset", "Z", "bash", "x.sh"], X, True),
    (["env", "-C", "/tmp", "bash", "x.sh"], [], False),
    (["env", "--chdir=/tmp", "bash", "x.sh"], [], False),
    (["env", "--bogus", "bash", "x.sh"], [], False),
    (["env", "-z", "bash", "x.sh"], [], False),
    (["env", "-S", "bash x.sh"], [], False),
    (["env", "-Sbash x.sh"], [], False),
    (["env", "--split-string=bash x.sh"], [], False),
    (["env", "--split-string", "bash x.sh"], [], False),
    (["env", "--split", "bash x.sh"], [], False),
    (["env", "-iS", "bash x.sh"], [], False),
    (["env", "-S", "LANG=C TZ=UTC bash x.sh", "extra"], [], False),
    (["env", "-S", "env -S 'bash x.sh'"], [], False),
    (["env", "-S", "sh -c 'echo hi'"], [], False),
    (["env", "-S", "sh -c 'echo \\n hi'"], [], False),
    (["env", "-S", "sh -c \"echo $X\""], [], False),
    (["env", "-S", "bash \\_x.sh"], [], False),
    (["env", "-S", "bash x.sh # c"], [], False),
    (["env", "-S", "bash 'unbalanced"], [], False),
    (["env", "-S"], [], False),
    (NEST5, [], False),
    (["env", "-S", "env -S 'env -S \"bash x.sh\"'"], [], False),
    (["/usr/bin/env", "bash", "x.sh"], X, True),
    (["/tmp/env", "bash", "x.sh"], ["/tmp/env"], True),
    # path prefix tricks
    (["/usr/bin/../../tmp/x.sh"], [], False),
    (["/usr/bin/../bin/ls"], [], False),
    (["/usr/bin/ls\n"], [], False),
    (["/usr/bin/a\0b"], [], False),
    (["//usr/bin/x"], ["//usr/bin/x"], True),
    (["/usr/bin/../../tmp/python3", "x.py"], [], False),
    # new wrappers: script operand, inline, unknown option
    (["xargs", "-n", "1", "bash", "x.sh"], [], False),
    (["xargs", "-I", "{}", "echo", "{}"], [], False),
    (["xargs", "-0", "cat"], [], False),
    (["xargs", "bash"], [], False),
    (["xargs", "--bogus", "cat"], [], False),
    (["busybox", "sh", "x.sh"], [], False),
    (["busybox", "sed", "-f", "p.sed"], [], False),
    (["busybox", "sh", "-c", "echo"], [], False),
    (["busybox", "ls"], [], False),
    (["busybox", "nc", "u"], [], False),
    (["strace", "-o", "t.out", "-f", "bash", "x.sh"], [], False),
    (["strace", "--bogus", "bash", "x.sh"], [], False),
    (["ltrace", "-o", "t.out", "bash", "x.sh"], [], False),
    (["nsenter", "-t", "1", "bash", "x.sh"], [], False),
    (["unshare", "-n", "bash", "x.sh"], [], False),
    (["unshare", "-m", "bash", "x.sh"], [], False),
    (["unshare", "--propagation", "private", "-n", "bash", "x.sh"], [], False),
    (["taskset", "0x1", "bash", "x.sh"], [], False),
    (["taskset", "-c", "0-3", "bash", "x.sh"], [], False),
    (["taskset", "-p", "0x1", "99"], [], False),
    (["flock", "/tmp/l", "bash", "x.sh"], [], False),
    (["flock", "-w", "5", "-n", "/tmp/l", "cat", "f"], [], False),
    (["flock", "-c", "bash x.sh", "/tmp/l"], [], False),
    (["flock", "-c", "echo hi", "/tmp/l"], [], False),
    (["flock", "-c", "echo hi\nid", "/tmp/l"], [], False),
    (["flock", "--bogus", "/tmp/l", "cat"], [], False),
    (["flock", "/tmp/l"], [], False),
    (["su", "-c", "bash x.sh", "root"], [], False),
    (["su", "root", "-c", "bash x.sh"], [], False),
    (["su", "-lc", "bash x.sh", "root"], [], False),
    (["su", "-l", "-c", "echo hi", "root"], [], False),
    (["su", "-s", "/bin/bash", "-c", "echo hi", "root"], [], False),
    (["su", "-sc", "/tmp/evil", "root"], [], False),
    (["su", "-s", "/tmp/evil", "-c", "echo hi", "root"], [], False),
    (["su", "-c", "echo hi\nbash x.sh", "root"], [], False),
    (["su", "-c", "echo hi; bash x.sh", "root"], [], False),
    (["su", "--bogus", "-c", "echo", "root"], [], False),
    (["su", "-Z", "-c", "echo", "root"], [], False),
    (["su", "root"], [], False),
    (["su"], [], False),
    (["su", "-c", "echo 'oops", "root"], [], False),
    (["chroot", "/jail", "bash", "x.sh"], [], False),
    (["runuser", "-u", "u", "--", "bash", "x.sh"], [], False),
    (["runuser", "u", "-c", "bash x.sh"], [], False),
    (["runuser", "-u", "u", "--", "cat", "f"], [], False),
    (["runuser", "-u", "u", "--bogus", "cat"], [], False),
    (["setpriv", "--reuid", "1", "bash", "x.sh"], [], False),
    (["setpriv", "--reuid=1", "cat", "f"], [], False),
    (["setpriv", "--bogus", "cat"], [], False),
    (["numactl", "--cpunodebind", "0", "bash", "x.sh"], [], False),
    (["numactl", "--bogus", "cat"], [], False),
    (["ionice", "-c", "3", "bash", "x.sh"], [], False),
    (["nice", "-n", "5", "bash", "x.sh"], X, True),
    (["nice", "-5", "bash", "x.sh"], [], False),
    (["nohup", "bash", "x.sh"], X, True),
    (["sudo", "-E", "bash", "x.sh"], [], False),
    (["sudo", "-s", "bash", "x.sh"], [], False),
    (["sudo", "-D", "/tmp", "bash", "x.sh"], [], False),
    (["sudo", "-e", "f"], [], False),
    (["doas", "-u", "u", "bash", "x.sh"], X, True),
    (["time", "-p", "bash", "x.sh"], [], False),
    (["command", "-v", "foo"], [], False),
    (["watch", "-n", "5", "bash", "x.sh"], [], False),
    (["watch", "-n", "5", "bash x.sh"], [], False),
    (["watch", "-n", "5", "date"], [], False),
    (["watch", "a", "b"], [], False),
    (["watch", "echo hi", "bash x.sh"], [], False),
    (["watch", "echo hi", "; bash", "x.sh"], [], False),
    (["watch", "-x", "bash", "x.sh"], [], False),
    (["watch", "--bogus", "date"], [], False),
    (["watch", "echo $HOME"], [], False),
    (["script", "-c", "bash x.sh", "/dev/null"], [], False),
    (["script", "-qc", "echo hi", "/dev/null"], [], False),
    (["script", "-q", "/dev/null"], [], False),
    (["script", "--bogus", "-c", "echo"], [], False),
    (["parallel", "-j", "2", "bash", "x.sh", "{}", ":::", "a", "b"], [], False),
    (["parallel", "bash x.sh a ::: a b"], [], False),
    (["parallel", "echo", ":::", "a/b.sh"], [], False),
    (["parallel", "--bogus", "echo"], [], False),
    (["parallel", "{}", ":::", "./x.sh"], [], False),
    (["parallel", ":::", "a"], [], False),
    # round 3: empty commands, env assignments allowlist, positive flag allowlists
    (["nice"], [], False),
    (["nohup"], [], False),
    (["sudo", "-n"], [], False),
    (["xargs"], [], False),
    (["xargs", "nice"], [], False),
    (["xargs", "env"], [], False),
    (["xargs", "sh", "-c", "echo"], [], False),
    (["xargs", "cat"], [], False),
    (["xargs", "-0", "-n", "1", "wc", "-l"], [], False),
    (["xargs", "grep", "-f", "x"], [], False),
    (["env", "-S", ""], [], False),
    (["env", "-i"], [], True),
    (["env", "-u", "A"], [], True),
    (["env", "A=1"], [], False),
    (["env", "LANG=C"], [], False),
    (["env", "nice"], [], False),
    (["env", "-u", "FOO", "nice", "-n", "1"], [], False),
    (["FOO=1", "bash", "x.sh"], [], False),
    (["LANG=C", "bash", "x.sh"], [], False),
    (["env", "FOO=1", "bash", "x.sh"], [], False),
    (["env", "LD_PRELOAD=/tmp/x.so", "cat", "f"], [], False),
    (["env", "ZDOTDIR=/tmp/z", "zsh", "x.sh"], [], False),
    (["env", "LANG=$HOME", "bash", "x.sh"], [], False),
    (["env", "LANG=a`id`", "bash", "x.sh"], [], False),
    (["env", "LANG=a\nb", "bash", "x.sh"], [], False),
    (["env", "HTTP_PROXY=http://p", "curl", "https://e.com"], [], False),
    (["env", "LC_ALL=C", "TZ=UTC", "CI=1", "bash", "x.sh"], X, True),
    (["sh", "-c", "LANG=C bash x.sh"], X, True),
    (["sh", "-c", "FOO=1 bash x.sh"], [], False),
    (["sh", "-c", "LANG=C"], [], False),
    (["curl", "-sS", "https://example.com/health"], [], True),
    (["curl", "-fsSL", "--max-time", "5", "--retry", "2", "https://e.com"], [], True),
    (["curl", "--max-time=5", "--connect-timeout", "2", "https://e.com"], [], True),
    (["curl", "-X", "GET", "-H", "Accept: x", "https://e.com"], [], True),
    (["curl", "-X", "POST", "https://e.com"], [], False),
    (["curl", "-H", "X: a\nb", "https://e.com"], [], False),
    (["curl", "-H", "@hdrs", "https://e.com"], [], False),
    (["curl", "-w", "%{url}", "-o", "/tmp/x", "https://e.com"], [], False),
    (["curl", "-w", "%{url}", "https://e.com"], [], False),
    (["curl", "--write-out", "x", "https://e.com"], [], False),
    (["curl", "--etag-save", "f", "https://e.com"], [], False),
    (["curl", "--hsts", "f", "https://e.com"], [], False),
    (["curl", "--alt-svc", "f", "https://e.com"], [], False),
    (["curl", "-k", "https://e.com"], [], False),
    (["curl", "--insecure", "https://e.com"], [], False),
    (["curl", "-D", "f", "https://e.com"], [], False),
    (["curl", "-c", "jar", "https://e.com"], [], False),
    (["curl", "-b", "jar", "https://e.com"], [], False),
    (["curl", "-d", "x", "https://e.com"], [], False),
    (["curl", "--data-binary", "@f", "https://e.com"], [], False),
    (["curl", "-F", "a=@f", "https://e.com"], [], False),
    (["curl", "--trace", "f", "https://e.com"], [], False),
    (["curl", "--stderr", "f", "https://e.com"], [], False),
    (["curl", "--libcurl", "f", "https://e.com"], [], False),
    (["curl", "-s", "file:///etc/passwd"], [], False),
    (["curl", "-s", "@urls"], [], False),
    (["curl", "-s", "https://u:p@e.com"], [], False),
    (["curl", "-s"], [], True),
    (["wget", "-qO-", "https://e.com"], [], False),
    (["openssl", "version"], [], False),
    (["openssl", "x509", "-out", "f"], [], False),
    (["ls", "-l", "/tmp"], [], True),
    (["ls", "-lah1tr"], [], True),
    (["ls", "--color=always"], [], False),
    (["ls", "-Z"], [], False),
    (["grep", "-invcEFwxrHhlq", "pat", "f"], [], True),
    (["grep", "-e", "pat", "f"], [], True),
    (["grep", "--include=*.sh", "x", "."], [], False),
    (["cat", "-n", "f"], [], True),
    (["cat", "--bogus"], [], False),
    (["head", "-n", "5", "f"], [], True),
    (["head", "-5", "f"], [], True),
    (["head", "-n5", "f"], [], True),
    (["tail", "-f", "f"], [], True),
    (["tail", "-n", "x", "f"], [], False),
    (["wc", "-l", "f"], [], True),
    (["wc", "--files0-from=f"], [], False),
    (["echo", "-n", "hi"], [], True),
    (["echo", "-x", "hi"], [], False),
    (["printf", "%s\\n", "a"], [], True),
    (["date", "+%Y-%m-%d"], [], True),
    (["date", "-u", "+%s"], [], True),
    (["date", "-R"], [], True),
    (["date", "--utc"], [], True),
    (["date", "-I"], [], True),
    (["date"], [], True),
    (["date", "-d", "tomorrow"], [], False),
    (["date", "-s", "2020-01-01"], [], False),
    (["date", "-f", "f"], [], False),
    (["date", "now"], [], False),
    (["uname", "-a"], [], True),
    (["uptime", "-p"], [], True),
    (["df", "-h"], [], True),
    (["du", "-sh", "/tmp"], [], True),
    (["du", "--files0-from=f"], [], False),
    (["ps", "aux"], [], True),
    (["ps", "-ef"], [], True),
    (["ps", "-o", "pid"], [], False),
    (["id", "-u"], [], True),
    (["whoami"], [], True),
    (["whoami", "x"], [], False),
    (["hostname"], [], True),
    (["hostname", "newname"], [], False),
    (["pwd"], [], True),
    (["stat", "-c", "%s", "f"], [], True),
    (["stat", "--printf=x", "f"], [], False),
    (["jq", "-r", ".a", "f.json"], [], True),
    (["jq", "-rc", ".a[]"], [], True),
    (["jq", "-f", "prog.jq"], [], False),
    (["jq", "--from-file", "prog.jq"], [], False),
    (["jq", "-L", "dir", ".a"], [], False),
    (["jq", "--seq", ".a"], [], False),
    (["jq", "--rawfile", "a", "f", "."], [], False),
    (["jq", "--slurpfile", "a", "f", "."], [], False),
    (["jq", "--argfile", "a", "f", "."], [], False),
    (["jq", "include \"x\"; .a"], [], False),
    (["jq", "input_filename"], [], False),
    (["jq", "$ENV.PATH"], [], False),
    (["jq", "env"], [], False),
    (["ping", "-c", "3", "example.com"], [], True),
    (["ping", "-c", "3", "-f", "example.com"], [], False),
    (["dig", "+short", "example.com"], [], True),
    (["dig", "-f", "file"], [], False),
    (["nslookup", "example.com"], [], True),
    (["sha256sum", "f"], [], True),
    (["md5sum", "-b", "f"], [], True),
    (["md5sum", "--check", "f"], [], False),
    (["sort", "-n", "-r", "f"], [], True),
    (["sort", "-k", "2,2", "-t", ",", "f"], [], True),
    (["sort", "-o", "f", "g"], [], False),
    (["sort", "--output=f", "g"], [], False),
    (["sort", "--files0-from=f"], [], False),
    (["sort", "-T", "/tmp", "f"], [], False),
    (["sort", "--temporary-directory=/tmp", "f"], [], False),
    (["uniq", "-c", "f"], [], True),
    (["uniq", "in", "out"], [], False),
    (["test", "-f", "x"], [], True),
    (["test", "-n", "a", "-a", "b", "=", "b"], [], True),
    (["test", "--help"], [], False),
    (["true"], [], True),
    (["true", "x"], [], False),
    (["false"], [], True),
    # round 4: the understood wrappers are a short fixed list; every other launcher prompts
    (["env", "-i", "-0", "bash", "x.sh"], X, True),
    (["env", "-u", "FOO", "--unset=BAR", "--ignore-environment", "bash", "x.sh"], X, True),
    (["env", "-C", "/tmp", "bash", "x.sh"], [], False),
    (["env", "-v", "bash", "x.sh"], [], False),
    (["env", "-S", "bash x.sh"], [], False),
    (["env", "LANG=C", "bash", "x.sh"], X, True),
    (["env", "LANG=/bin/sh", "bash", "x.sh"], [], False),
    (["env", "LANG=a b", "bash", "x.sh"], [], False),
    (["env", "LANG=a$b", "bash", "x.sh"], [], False),
    (["sudo", "-n", "-H", "-u", "app", "bash", "x.sh"], X, True),
    (["sudo", "--user=app", "--non-interactive", "bash", "x.sh"], X, True),
    (["sudo", "-E", "bash", "x.sh"], [], False),
    (["sudo", "-i", "bash", "x.sh"], [], False),
    (["sudo", "-e", "f"], [], False),
    (["sudo", "LANG=C", "bash", "x.sh"], [], False),
    (["doas", "-n", "-u", "u", "cat", "f"], [], True),
    (["doas", "-s", "cat", "f"], [], False),
    (["nohup", "bash", "x.sh"], X, True),
    (["time", "bash", "x.sh"], X, True),
    (["time", "-p", "bash", "x.sh"], [], False),
    (["timeout", "-s", "KILL", "-k", "5", "30", "bash", "x.sh"], X, True),
    (["timeout", "--preserve-status", "--foreground", "30", "cat", "f"], [], True),
    (["timeout", "-v", "30", "cat", "f"], [], False),
    (["nice", "-n", "5", "bash", "x.sh"], X, True),
    (["nice", "-5", "bash", "x.sh"], [], False),
    (["stdbuf", "-oL", "-e", "0", "bash", "x.sh"], X, True),
    (["exec", "bash", "x.sh"], X, True),
    (["exec", "-a", "n", "bash", "x.sh"], [], False),
    (["command", "bash", "x.sh"], X, True),
    (["command", "-v", "foo"], [], False),
    (["xargs", "-I{}", "sh", "x.sh", "{}"], [], False),
    (["xargs", "-I", "sh", "sh", "x.sh"], [], False),
    (["xargs", "cat"], [], False),
    (["parallel", "-I", "{}", "sh", "x.sh", "{}", ":::", "a"], [], False),
    (["parallel", "{= s/a/b/ =}", ":::", "a"], [], False),
    (["parallel", "echo", ":::", "a"], [], False),
    (["watch", "date"], [], False),
    (["script", "-c", "date", "/dev/null"], [], False),
    (["flock", "/tmp/l", "cat", "f"], [], False),
    (["su", "-c", "date", "root"], [], False),
    (["runuser", "-u", "u", "--", "cat", "f"], [], False),
    (["setpriv", "--reuid", "1", "cat", "f"], [], False),
    (["nsenter", "-t", "1", "cat", "f"], [], False),
    (["unshare", "-n", "cat", "f"], [], False),
    (["chroot", "/j", "cat", "f"], [], False),
    (["numactl", "-N", "0", "cat", "f"], [], False),
    (["busybox", "cat", "f"], [], False),
    (["strace", "cat", "f"], [], False),
    (["ltrace", "cat", "f"], [], False),
    (["taskset", "0x1", "cat", "f"], [], False),
    (["ionice", "-c", "3", "cat", "f"], [], False),
    (["chrt", "-r", "1", "cat", "f"], [], False),
    (["setsid", "cat", "f"], [], False),
    (["setsid", "bash", "x.sh"], [], False),
    # assignment-shaped argv[0] is understood only inside env and shell strings
    (["FOO=1", "x.sh"], [], False),
    (["LANG=C", "cat", "f"], [], False),
    (["./x=1"], ["./x=1"], True),
    (["sh", "-c", "LANG=C cat f"], [], True),
    (["sh", "-c", "LANG=/bin/sh cat f"], [], False),
    (["sh", "-c", "LANG=C"], [], False),
    (["sh", "-c", "FOO=1 cat f"], [], False),
    # arguments that are not strings / empty
    (["env"], [], True),
    ([], [], False),
)


class ArgvDetectionShared(unittest.TestCase):
    def test_table_broker(self):
        for argv, paths, ok in DETECT_TABLE:
            self.assertEqual(S.argv_understood(argv), ok, argv)
            if ok:
                self.assertEqual(S.argv_runs_script(argv), paths, argv)

    def test_table_client_agrees(self):
        for argv, paths, ok in DETECT_TABLE:
            self.assertEqual(A._analyze(argv), S._analyze(argv), argv)
            self.assertEqual(A.argv_understood(argv), ok, argv)
            self.assertEqual(A.argv_runs_script(argv), S.argv_runs_script(argv), argv)
            if ok:
                self.assertEqual(A.argv_runs_script(argv), paths, argv)

    def test_shared_source_identical(self):
        def block(path):
            with open(path, encoding="utf-8") as f:
                t = f.read()
            a, b = t.index("# --- shared-detection:begin"), t.index("# --- shared-detection:end ---")
            return t[a:b]
        self.assertEqual(block(CLI), block(os.path.join(HERE, "..", "secret_broker", "scripts.py")))

    def test_not_understood_means_not_visible(self):
        for argv, paths, ok in DETECT_TABLE:
            full = [{"path": p, "size": 1, "sha256": "a" * 64, "text": "x", "truncated": False}
                    for p in paths if p != "-"]
            if not ok or "-" in paths:
                self.assertTrue(S.script_not_visible(argv, full), argv)
            else:
                self.assertFalse(S.script_not_visible(argv, full), argv)

    def test_nesting_limit(self):
        self.assertFalse(S.argv_understood(["env", "-S", "bash x.sh"]))        # no -S handling at all
        self.assertFalse(S.argv_understood(NEST5))

    def test_depth_limits(self):
        self.assertEqual(S._shell_string("echo hi", 1), ([], True))
        self.assertEqual(S._shell_string("echo hi", S.MAX_SPLIT_DEPTH + 1), ([], False))
        self.assertTrue(S.argv_understood(["sh", "-c", "sh -c 'echo hi'"]))
        self.assertTrue(S.argv_understood(["sudo", "-n", "sh", "-c", "env LANG=C cat f"]))
        self.assertFalse(S.argv_understood(["env"] * 40 + ["cat"]))   # wrapper chain limit

    def test_non_list_input(self):
        self.assertFalse(S.argv_understood("bash x.sh"))
        self.assertEqual(S.argv_runs_script("bash x.sh"), [])
        self.assertFalse(S.argv_understood(["bash", 3]))

    def test_unknown_programs_prompt_even_without_operands(self):
        for prog in ("git", "docker", "make", "npm", "kubectl", "terraform", "ansible", "helm", "aws", "gh",
                     "systemctl", "tar", "rsync", "find", "ffmpeg", "psql", "nc", "ssh", "scp", "cargo",
                     "wget", "openssl"):
            self.assertFalse(S.argv_understood([prog, "status"]), prog)
            self.assertTrue(S.script_not_visible([prog, "status"], []), prog)

    def test_allowlist_programs_understood(self):
        samples = {"cat": ["f"], "ls": ["-l", "d"], "head": ["-n", "3", "f"], "tail": ["-n", "3", "f"],
                   "wc": ["-l", "f"], "grep": ["-i", "p", "f"], "egrep": ["p", "f"], "fgrep": ["p", "f"],
                   "echo": ["hi"], "printf": ["%s", "a"], "date": ["+%s"], "uname": ["-a"], "uptime": [],
                   "df": ["-h"], "du": ["-sh", "d"], "ps": ["aux"], "id": ["-u"], "whoami": [],
                   "hostname": [], "pwd": [], "stat": ["f"], "jq": [".a", "f"], "curl": ["-s", "https://e.com"],
                   "ping": ["-c", "1", "h"], "dig": ["h"], "nslookup": ["h"], "sha256sum": ["f"],
                   "md5sum": ["f"], "sort": ["-n", "f"], "uniq": ["f"], "test": ["-f", "f"], "true": [],
                   "false": []}
        self.assertEqual(set(samples), set(S.PLAIN_PROGRAMS))
        for prog, args in samples.items():
            self.assertTrue(S.argv_understood([prog] + args), prog)

    def test_removed_launchers_never_understood(self):
        for w in ("xargs parallel watch script flock su runuser setpriv nsenter unshare chroot numactl busybox "
                  "strace ltrace taskset ionice chrt setsid").split():
            for tail in ([], ["cat", "f"], ["bash", "x.sh"], ["-c", "date"], ["sh", "x.sh", "{}"]):
                self.assertFalse(S.argv_understood([w] + tail), (w, tail))
                self.assertTrue(S.script_not_visible([w] + tail, [{"path": "x.sh", "size": 1, "sha256": "a" * 64,
                                                                    "text": "x", "truncated": False}]), (w, tail))
        self.assertEqual(set(S.SCRIPT_WRAPPERS), set("sudo doas nohup time timeout nice stdbuf exec command".split()))

    def test_empty_command_after_wrapper(self):
        for argv in (["nice"], ["sudo", "-n"], ["env", "-S", ""], ["timeout", "5"], ["env", "LANG=C"]):
            self.assertFalse(S.argv_understood(argv), argv)
        self.assertTrue(S.argv_understood(["env"]))

class PathMatching(unittest.TestCase):
    def e(self, path, **kw):
        return {"path": path, "size": 1, "sha256": "a" * 64, "text": "x", "truncated": False, **kw}

    def test_absolute_equal_after_normalisation(self):
        sc = [self.e("/home/u/deploy.sh")]
        self.assertFalse(S.script_not_visible(["bash", "/home/u/deploy.sh"], sc))
        self.assertFalse(S.script_not_visible(["bash", "/home/u/./d/../deploy.sh"], sc))
        self.assertTrue(S.script_not_visible(["bash", "/other/deploy.sh"], sc))

    def test_basename_collision_rejected_with_cwd(self):
        sc = [self.e("/other/dir/deploy.sh")]
        self.assertTrue(S.script_not_visible(["./deploy.sh"], sc, "/home/u"))
        self.assertTrue(S.script_not_visible(["bash", "deploy.sh"], sc, "/home/u"))
        self.assertFalse(S.script_not_visible(["./deploy.sh"], sc, "/other/dir"))
        self.assertFalse(S.script_not_visible(["bash", "../dir/deploy.sh"], sc, "/other/x"))

    def test_relative_without_cwd_needs_path_boundary(self):
        sc = [self.e("/other/dir/deploy.sh")]
        self.assertFalse(S.script_not_visible(["bash", "dir/deploy.sh"], sc))
        self.assertFalse(S.script_not_visible(["bash", "deploy.sh"], sc))      # whole trailing component
        self.assertTrue(S.script_not_visible(["bash", "ir/deploy.sh"], sc))    # not at a boundary
        self.assertTrue(S.script_not_visible(["bash", "eploy.sh"], sc))
        self.assertTrue(S.script_not_visible(["bash", "../dir/deploy.sh"], sc))

    def test_ambiguity_is_fine_and_no_match_is_not_visible(self):
        sc = [self.e("/a/deploy.sh"), self.e("/b/deploy.sh")]
        self.assertFalse(S.script_not_visible(["bash", "deploy.sh"], sc))
        self.assertTrue(S.script_not_visible(["bash", "deploy.sh"], [self.e("/a/other.sh")]))

    def test_given_path_counts(self):
        sc = [self.e("/real/target.sh", given="/home/u/link.sh")]
        self.assertFalse(S.script_not_visible(["bash", "/home/u/link.sh"], sc))
        self.assertFalse(S.script_not_visible(["bash", "link.sh"], sc, "/home/u"))
        self.assertTrue(S.script_not_visible(["bash", "link.sh"], sc, "/elsewhere"))

    def test_cwd_validation(self):
        self.assertIsNone(S.validate_cwd(None))
        self.assertEqual(S.validate_cwd("/home/u"), "/home/u")
        for bad in ("home/u", "", "/a\0b", "/a\nb", "/" + "x" * 300, 5, ["/a"]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                S.validate_cwd(bad)

    def test_given_validated(self):
        out = S.validate([self.e("/a/b.sh", given="/c/d.sh")])
        self.assertEqual(out[0]["given"], "/c/d.sh")
        with self.assertRaises(ValueError):
            S.validate([{"stdin": True, "given": "/x"}])
        with self.assertRaises(ValueError):
            S.validate([self.e("/a/b.sh", given="a\x00b")])


class HonestClientStaysVisible(Files):
    def test_entry_from_client_matches_broker(self):
        os.mkdir(os.path.join(self.d, "sub"))
        self.write("sub/run.sh", b"#!/bin/sh\necho hi\n")
        os.symlink(os.path.join(self.d, "sub", "run.sh"), os.path.join(self.d, "link.sh"))
        for argv in (["bash", "sub/run.sh"], ["./sub/run.sh"], ["bash", "link.sh"], ["bash", "./sub/../sub/run.sh"],
                     ["env", "-i", "bash", "sub/run.sh"], ["env", "LANG=C", "bash", os.path.join(self.d, "link.sh")],
                     ["sh", "-c", "echo a && bash sub/run.sh"], ["sh", "-c", "LANG=C bash sub/run.sh"],
                     ["sudo", "-u", "app", "timeout", "30", "bash", "sub/run.sh"],
                     ["nohup", "bash", "link.sh"]):
            entries = A.find_scripts(argv)
            self.assertTrue(entries, argv)
            self.assertFalse(S.script_not_visible(argv, S.validate(entries), self.d), argv)
            self.assertFalse(S.script_not_visible(argv, S.validate(entries)), argv)
            # an entry for a different file does not satisfy it
            other = [{**entries[0], "path": "/elsewhere/run.sh", **({"given": "/elsewhere/l.sh"} if "given" in entries[0] else {})}]
            self.assertTrue(S.script_not_visible(argv, S.validate(other), self.d), argv)
