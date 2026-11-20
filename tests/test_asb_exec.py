"""`asb exec`: ask the broker to run one command or script over SSH and print what comes back.

Black-box: every test runs the CLI as a subprocess (`python -I client/asb ARGS`) against a stub broker whose answers the
test scripts, so tools/run_tests_against_rust_cli.py runs the same tests against the Rust binary. The stub follows the
wire contract in docs/superpowers/plans/2026-11-19-remote-exec.md (Task 7); there is no real broker with `exec` here, so
nothing below shows the two ends agreeing, only that this end does what the contract says.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

CLI = os.path.join(os.path.dirname(__file__), "..", "client", "asb")
ID = "r" * 32
PENDING = {"id": ID, "status": "pending", "expires_in": 300}
RUNNING = {"status": "running"}


def released(stdout="", stderr="", code=0, label=None, truncated=False):
    return {"status": "released", "exit_code": code, "stdout": stdout, "stderr": stderr, "truncated": truncated,
            "label": label}


class Stub:
    """A broker for `exec`: POST /v1/requests records the body and answers `post`; each GET answers the next of `gets`."""

    def __init__(self, gets, post=(202, PENDING), get_code=200):
        self.bodies, self.gets, self.post, self.get_code, self.seen = [], list(gets), post, get_code, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                outer.seen.append(("POST", self.path))
                outer.bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.reply(*outer.post)

            def do_GET(self):
                outer.seen.append(("GET", self.path))
                self.reply(outer.get_code, outer.gets.pop(0) if len(outer.gets) > 1 else outer.gets[0])

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="asb-exec-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stubs = []

    def stub(self, gets, **kw):
        s = Stub(gets, **kw)
        self.stubs.append(s)
        self.addCleanup(s.close)
        return s

    def asb(self, stub, *argv):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("SECRET_BROKER", "ASB_"))}
        env.update(HOME=self.tmp, XDG_STATE_HOME=os.path.join(self.tmp, "state"), SECRET_BROKER_URL=stub.url,
                   SECRET_BROKER_KEY="stub-key")
        return subprocess.run([sys.executable, "-I", CLI, *argv], env=env, capture_output=True, text=True, timeout=60)

    def run_ok(self, *argv, gets=(released("ok\n"),)):
        s = self.stub(list(gets))
        p = self.asb(s, "exec", *argv)
        return s, p

    def body(self, *argv):
        s, p = self.run_ok(*argv)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(s.bodies), 1)
        b = dict(s.bodies[0])
        self.assertIn("source", b)
        del b["source"]
        return b

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return path


class Request(Base):
    def test_the_request_body_is_exactly_the_wire_contract(self):
        self.assertEqual(
            self.body("agent-ssh", "nas", "--user", "ryan", "--port", "2222", "--timeout", "30", "--",
                      "systemctl", "status", "nginx"),
            {"mode": "exec", "names": ["agent-ssh"], "host": "nas", "user": "ryan", "port": 2222, "timeout_s": 30,
             "command": "systemctl status nginx"})

    def test_what_you_did_not_give_is_not_sent(self):
        # no guessed user (the local name is not the remote one), no port or timeout: the broker has the defaults
        self.assertEqual(self.body("k", "nas", "--", "uptime"),
                         {"mode": "exec", "names": ["k"], "host": "nas", "command": "uptime"})

    def test_it_posts_once_and_polls_the_request_it_was_given(self):
        s, p = self.run_ok("k", "nas", "--", "uptime", gets=[RUNNING, released("up\n")])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(s.seen[0], ("POST", "/v1/requests"))
        self.assertTrue(all(m == "GET" and path.startswith(f"/v1/requests/{ID}?wait=") for m, path in s.seen[1:]))
        self.assertEqual(len([1 for m, _ in s.seen if m == "POST"]), 1)

    def test_help_after_the_dashes_belongs_to_the_command(self):
        b = self.body("k", "nas", "--", "ls", "--help")
        self.assertEqual(b["command"], "ls --help")


class Quoting(Base):
    """The words after `--` are joined with shell-quote rules (secret_broker/execmode.rebuild must give the same text)."""

    TABLE = [
        (["ls", "-l", "/var/log"], "ls -l /var/log"),
        (["echo", "a b"], "echo 'a b'"),
        (["echo", ""], "echo ''"),
        (["echo", "it's"], "echo 'it'\"'\"'s'"),
        (["echo", "'"], "echo ''\"'\"''"),
        (["echo", "a;b", "c|d", "$HOME", "`x`", "x\\y", "a&b", "a>b", "(x)", "*", "?", "[x]", "{x}", "~", "!", "#"],
         "echo 'a;b' 'c|d' '$HOME' '`x`' 'x\\y' 'a&b' 'a>b' '(x)' '*' '?' '[x]' '{x}' '~' '!' '#'"),
        (["echo", "a\nb", "a\tb"], "echo 'a\nb' 'a\tb'"),
        (["echo", "na\u00efve", "\u65e5\u672c"], "echo 'na\u00efve' '\u65e5\u672c'"),
        (["a_B-1", "x@y%z+w=v:u,t./s"], "a_B-1 x@y%z+w=v:u,t./s"),
        (["sh", "-c", "a | b"], "sh -c 'a | b'"),
        (["echo", "a  b"], "echo 'a  b'"),
    ]

    def test_table(self):
        for words, want in self.TABLE:
            with self.subTest(words=words):
                self.assertEqual(self.body("k", "nas", "--", *words)["command"], want)

    def test_one_word_with_spaces_stays_one_argument(self):
        # `-- "ls -l"` is a program called "ls -l", as in `ssh host ls\ -l`; use `sh -c` or --script for shell text
        self.assertEqual(self.body("k", "nas", "--", "ls -l")["command"], "'ls -l'")


class Result(Base):
    def test_output_goes_to_the_matching_streams_and_the_exit_code_is_the_remote_one(self):
        for code in (0, 1, 7, 127, 255):
            with self.subTest(code=code):
                s, p = self.run_ok("k", "nas", "--", "x", gets=[RUNNING, released("to out\n", "to err\n", code)])
                self.assertEqual((p.stdout, p.returncode), ("to out\n", code))
                self.assertEqual(p.stderr, "asb: waiting for approval...\nto err\n")

    def test_output_is_not_rewritten(self):
        out = "no newline, \u00e9 and a tab\t"
        s, p = self.run_ok("k", "nas", "--", "x", gets=[released(out)])
        self.assertEqual(p.stdout, out)

    def test_a_request_already_approved_does_not_say_it_waits(self):
        s = self.stub([released("x")], post=(202, {**PENDING, "status": "approved"}))
        p = self.asb(s, "exec", "k", "nas", "--", "x")
        self.assertEqual((p.returncode, p.stderr), (0, ""))

    def test_a_failure_label_is_exit_3_and_keeps_what_was_captured(self):
        s, p = self.run_ok("k", "nas", "--", "x", gets=[released("partial\n", "", None, "timeout")])
        self.assertEqual((p.returncode, p.stdout), (3, "partial\n"))
        self.assertIn("asb: exec failed: timeout\n", p.stderr)

    def test_every_documented_label_is_printed_as_it_is(self):
        for label in ("host_key_mismatch", "host_not_pinned", "connect_failed", "auth_failed", "timeout", "output_cap",
                      "ssh_unavailable", "internal"):
            with self.subTest(label=label):
                s, p = self.run_ok("k", "nas", "--", "x", gets=[released("", "", None, label)])
                self.assertEqual(p.returncode, 3)
                self.assertIn(f"asb: exec failed: {label}\n", p.stderr)

    def test_a_label_that_is_not_a_fixed_word_is_never_echoed(self):
        s, p = self.run_ok("k", "nas", "--", "x", gets=[released("", "", None, "bad\x1b[31m token S3CR3T-" + "A" * 40)])
        self.assertEqual(p.returncode, 3)
        self.assertNotIn("\x1b", p.stderr)
        self.assertNotIn("S3CR3T", p.stderr)
        self.assertIn("asb: exec failed:", p.stderr)

    def test_an_answer_with_neither_an_exit_code_nor_a_label_is_a_broker_error(self):
        s, p = self.run_ok("k", "nas", "--", "x", gets=[{"status": "released"}])
        self.assertEqual(p.returncode, 3)
        self.assertEqual(p.stdout, "")

    def test_truncated_output_says_so_on_stderr_only(self):
        s, p = self.run_ok("k", "nas", "--", "x", gets=[released("cut", "", 0, None, True)])
        self.assertEqual((p.returncode, p.stdout), (0, "cut"))
        self.assertIn("asb: output was truncated", p.stderr)

    def test_complete_output_does_not_say_truncated(self):
        s, p = self.run_ok("k", "nas", "--", "x", gets=[released("all", "", 0, None, False)])
        self.assertNotIn("truncated", p.stderr)

    def test_denied_and_expired_use_the_existing_exit_codes(self):
        for status, code in (("denied", 4), ("expired", 5)):
            with self.subTest(status=status):
                s, p = self.run_ok("k", "nas", "--", "x", gets=[{"status": status}])
                self.assertEqual((p.returncode, p.stdout), (code, ""))
                self.assertIn(f"request {status}", p.stderr)

    def test_a_request_denied_at_once_exits_4(self):
        s = self.stub([], post=(202, {"id": ID, "status": "denied", "error": "policy"}))
        p = self.asb(s, "exec", "k", "nas", "--", "x")
        self.assertEqual(p.returncode, 4)
        self.assertIn("policy", p.stderr)
        self.assertEqual([m for m, _ in s.seen], ["POST"])

    def test_a_refusal_at_the_door_is_exit_3_with_the_broker_words(self):
        s = self.stub([], post=(403, {"error": "exec is not enabled for this client"}))
        p = self.asb(s, "exec", "k", "nas", "--", "x")
        self.assertEqual((p.returncode, p.stdout), (3, ""))
        self.assertIn("exec is not enabled for this client", p.stderr)

    def test_an_unknown_request_while_polling_ends_with_exit_3(self):
        s = self.stub([{"error": "unknown request"}], get_code=404)
        p = self.asb(s, "exec", "k", "nas", "--", "x")
        self.assertEqual(p.returncode, 3)
        self.assertIn("unknown request", p.stderr)

    def test_the_broker_cannot_reach_the_terminal_through_an_error(self):
        s = self.stub([], post=(400, {"error": "bad \x1b[31m S3CR3T-" + "B" * 40}))
        p = self.asb(s, "exec", "k", "nas", "--", "x")
        self.assertEqual(p.returncode, 3)
        self.assertNotIn("\x1b", p.stderr)
        self.assertNotIn("S3CR3T", p.stderr)


class Script(Base):
    def test_a_script_file_is_sent_as_text_with_its_interpreter(self):
        path = self.write("s.sh", "echo hi\nuname -a\n")
        self.assertEqual(self.body("k", "nas", "--script", path),
                         {"mode": "exec", "names": ["k"], "host": "nas",
                          "script": {"text": "echo hi\nuname -a\n", "interpreter": "sh"}})

    def test_bash_is_an_interpreter_and_travels_with_the_other_options(self):
        path = self.write("s.sh", "echo hi\n")
        self.assertEqual(self.body("k", "nas", "--user", "u", "--port", "22", "--timeout", "5", "--script", path,
                                   "--interpreter", "bash"),
                         {"mode": "exec", "names": ["k"], "host": "nas", "user": "u", "port": 22, "timeout_s": 5,
                          "script": {"text": "echo hi\n", "interpreter": "bash"}})

    def test_a_script_is_never_sent_as_a_command(self):
        path = self.write("s.sh", "echo hi\n")
        self.assertNotIn("command", self.body("k", "nas", "--script", path))

    def test_the_exact_bytes_arrive_tabs_and_unicode_included(self):
        text = "#!/bin/sh\n\techo 'caf\u00e9 \u65e5\u672c'\n\n"
        path = self.write("s.sh", text)
        self.assertEqual(self.body("k", "nas", "--script", path)["script"]["text"], text)

    def test_32_kib_exactly_is_sent_and_one_byte_more_is_refused_before_anything_is_sent(self):
        ok = self.write("ok.sh", "a" * 32768)
        self.assertEqual(len(self.body("k", "nas", "--script", ok)["script"]["text"]), 32768)
        big = self.write("big.sh", "a" * 32769)
        s, p = self.run_ok("k", "nas", "--script", big)
        self.assertEqual(p.returncode, 2)
        self.assertIn("32 KiB", p.stderr)
        self.assertEqual(s.seen, [])

    def test_a_file_the_broker_would_refuse_is_refused_here_and_nothing_is_sent(self):
        cases = {"nul": b"echo\x00hi\n", "escape": b"echo \x1b[31m\n", "carriage return": b"echo hi\r\n",
                 "delete": b"echo \x7f\n", "c1": "echo \u0085\n".encode(), "bidi": "echo \u202e\n".encode(),
                 "zero width": "echo \u200b\n".encode(), "replacement": "echo \ufffd\n".encode(),
                 "non-ascii space": "echo\u00a0hi\n".encode(),
                 "not utf-8": b"echo \xff\xfe\n", "empty": b""}
        for name, data in cases.items():
            with self.subTest(name):
                s, p = self.run_ok("k", "nas", "--script", self.write("bad.sh", data))
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertEqual(s.seen, [])
                self.assertNotIn("\x1b", p.stderr)

    def test_a_script_file_that_cannot_be_read_is_a_usage_error(self):
        s, p = self.run_ok("k", "nas", "--script", os.path.join(self.tmp, "missing.sh"))
        self.assertEqual(p.returncode, 2)
        self.assertEqual(s.seen, [])
        s, p = self.run_ok("k", "nas", "--script", self.tmp)             # a directory
        self.assertEqual(p.returncode, 2)

    def test_a_script_and_a_command_together_are_refused(self):
        path = self.write("s.sh", "echo hi\n")
        s, p = self.run_ok("k", "nas", "--script", path, "--", "ls")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(s.seen, [])

    def test_an_interpreter_other_than_sh_or_bash_is_refused(self):
        path = self.write("s.sh", "echo hi\n")
        for interp in ("zsh", "python3", "/bin/sh", ""):
            with self.subTest(interp):
                s, p = self.run_ok("k", "nas", "--script", path, "--interpreter", interp)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(s.seen, [])

    def test_an_interpreter_without_a_script_is_refused(self):
        s, p = self.run_ok("k", "nas", "--interpreter", "bash", "--", "ls")
        self.assertEqual(p.returncode, 2)
        self.assertEqual(s.seen, [])


class Usage(Base):
    def refused(self, *argv):
        s, p = self.run_ok(*argv)
        self.assertEqual(p.returncode, 2, (argv, p.stderr))
        self.assertEqual(s.seen, [], argv)
        return p

    def test_missing_pieces_show_the_help(self):
        for argv in ([], ["k"], ["k", "nas"], ["k", "nas", "--"], ["k", "nas", "--user", "u"]):
            with self.subTest(argv):
                self.assertIn("usage: asb exec NAME HOST", self.refused(*argv).stderr)

    def test_a_flag_where_the_name_or_host_belongs_is_named_as_such(self):
        self.assertIn("looks like a flag", self.refused("-x", "nas", "--", "ls").stderr)
        self.assertIn("looks like a flag", self.refused("k", "-oProxyCommand=x", "--", "ls").stderr)

    def test_exactly_one_credential(self):
        self.assertIn("exactly one credential", self.refused("a,b", "nas", "--", "ls").stderr)

    def test_bad_numbers_and_users_are_refused_before_sending(self):
        for flag, vals in (("--port", ["0", "65536", "-1", "abc", "", "22.5", "\u0662\u0662"]),
                           ("--timeout", ["0", "601", "-5", "abc", "", "1e2"]),
                           ("--user", ["", "a b", "x" * 65, "caf\u00e9", "a\nb"])):
            for v in vals:
                with self.subTest(flag=flag, value=v):
                    self.refused("k", "nas", flag, v, "--", "ls")

    def test_the_limits_themselves_are_accepted(self):
        b = self.body("k", "nas", "--port", "65535", "--timeout", "600", "--user", "u" * 64, "--", "ls")
        self.assertEqual((b["port"], b["timeout_s"], len(b["user"])), (65535, 600, 64))

    def test_a_flag_with_no_value_or_an_unknown_flag_is_refused(self):
        self.refused("k", "nas", "--user")
        self.refused("k", "nas", "--bogus", "x", "--", "ls")
        self.refused("k", "nas", "-o", "ProxyCommand=x", "--", "ls")

    def test_a_command_the_broker_would_refuse_is_refused_here(self):
        self.refused("k", "nas", "--", "echo", "a" * 4097)
        self.refused("k", "nas", "--", "echo", "\x1b[31m")
        self.refused("k", "nas", "--", "echo", "\u202e")
        self.refused("k", "nas", "--", "echo", "\r")

    def test_tab_and_newline_are_allowed_in_a_command_and_the_length_limit_is_on_the_sent_text(self):
        self.body("k", "nas", "--", "echo", "a\tb\nc")
        self.body("k", "nas", "--", "echo", "a" * 4090)            # "echo " + 4090 = 4095
        self.refused("k", "nas", "--", "'" * 1366)                 # each quote grows to 5 characters: over the limit

    def test_help_flags(self):
        s = self.stub([released()])
        p = self.asb(s, "exec", "--help")
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: asb exec NAME HOST", p.stdout)
        p = self.asb(s, "help", "exec")
        self.assertEqual(p.returncode, 0)
        self.assertIn("usage: asb exec NAME HOST", p.stdout)
        p = self.asb(s, "exec", "k", "nas", "--user", "u", "-h")
        self.assertIn("usage: asb exec NAME HOST", p.stdout)
        self.assertEqual(s.seen, [])

    def test_the_guide_and_the_command_list_mention_exec(self):
        s = self.stub([released()])
        guide = self.asb(s, "guide").stdout
        self.assertIn("asb exec", guide)
        self.assertIn("any command you would otherwise ssh for", guide)
        self.assertIn("asb exec", self.asb(s, "--help").stdout)
        self.assertIn("sudo, exec, store", self.asb(s, "nonsense").stderr)


class ExecmodeInSync(unittest.TestCase):
    """Imports client/asb's quoting, so it is Python-internal (tests/rust_cli_python_internal.txt); the Rust side is
    held to the same table by the black-box Quoting test above and by its own unit test."""

    def load(self):
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("asb_exec_src", CLI)
        mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("asb_exec_src", loader))
        loader.exec_module(mod)
        return mod

    def test_the_client_quoting_is_the_brokers_rebuild_once_the_broker_has_it(self):
        try:
            from secret_broker import execmode
        except ImportError:
            self.skipTest("secret_broker/execmode.py is not on this branch yet; run this again after merging "
                          "the broker branch: the two must agree on every simple argv")
        asb = self.load()
        for words, _ in Quoting.TABLE:
            text = asb.exec_join(words)
            self.assertEqual(text, execmode.rebuild(words), words)
            if execmode.parse_simple(text) is not None:                 # shell syntax inside a word is quoted away
                self.assertEqual(execmode.parse_simple(text), words, words)

    def test_exec_join_matches_shlex_quote_for_every_word(self):
        import shlex
        asb = self.load()
        words = ["", "a", "a b", "it's", "$x", "`x`", "a\\b", "~", "caf\u00e9", "a=b", "@%+=:,./-_", "x;y", "\n", "'", "''"]
        for w in words:
            self.assertEqual(asb.exec_join([w]), shlex.quote(w), w)


if __name__ == "__main__":
    unittest.main()
