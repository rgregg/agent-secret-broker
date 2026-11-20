"""execrun: the SSH runner, against stub `ssh`, `ssh-agent` and `ssh-add` programs (tests/fake_ssh/stub.py), and
the broker's use of it (release thread, `running` status, audit events, notifications, output handling).

The properties: the ssh option list is fixed and nothing from a request becomes an option; the key travels only
on ssh-add's stdin (never argv, an environment, a file); the temporary directory and the private agent are gone
after success, failure, timeout and a crash; concurrent runs share nothing; output is capped and masked; every
failure is a fixed label; the run slots bound concurrency; no output or command text reaches the audit log or a
notification. The real OpenSSH is exercised by tests/e2e_remote_exec/.
"""
import _fast  # noqa: F401  (test-only: prompt server shutdown, fake-clock helpers)
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import test_exec_intake as ti  # noqa: E402
from test_exec_intake import _OMIT  # noqa: E402
from secret_broker import execmode, execrun, masking  # noqa: E402

STUB = os.path.join(os.path.dirname(__file__), "fake_ssh", "stub.py")
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nS3CR3T-KEY-body-0123456789abcdef\n-----END OPENSSH PRIVATE KEY-----\n"
LINE = "nas.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBase64LookingBlobForTheStubOnly0123456789ab"
# the option list of the design, spelled out here independently of execrun.FIXED_OPTIONS
DESIGN_OPTIONS = ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                  "-o", "UserKnownHostsFile=<known_hosts>", "-o", "GlobalKnownHostsFile=/dev/null",
                  "-o", "VerifyHostKeyDNS=no", "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no",
                  "-o", "PreferredAuthentications=publickey", "-o", "PubkeyAuthentication=yes",
                  "-o", "NumberOfPasswordPrompts=0", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                  "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no", "-o", "ControlMaster=no",
                  "-o", "ControlPath=none", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
                  "-o", "PermitLocalCommand=no", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
                  "-o", "ServerAliveInterval=15", "-o", "IdentityFile=/dev/null"]


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


class FireNow:
    """A timer that fires the moment it starts: the timeout elapses with no waiting."""

    def __init__(self, interval, fn):
        self.fn, self.daemon = fn, False

    def start(self):
        self.fn()

    def cancel(self):
        pass


class Rig(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="stubs-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.base = os.path.join(self.dir, "work")
        for name in ("ssh", "ssh-agent", "ssh-add"):
            dst = os.path.join(self.dir, name)
            shutil.copy(STUB, dst)
            os.chmod(dst, 0o755)
        self.conf = {}
        self.cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir})
        self.addCleanup(self.reap)

    def reap(self):
        for c in self.calls("ssh-agent"):
            if "pid" in c and alive(c["pid"]):
                os.kill(c["pid"], 9)

    def configure(self, **tools):
        self.conf.update(tools)
        with open(os.path.join(self.dir, "config.json"), "w") as f:
            json.dump(self.conf, f)

    def calls(self, tool=None, **match):
        try:
            with open(os.path.join(self.dir, "calls.jsonl")) as f:
                rows = [json.loads(line) for line in f]
        except FileNotFoundError:
            rows = []
        return [r for r in rows if (tool is None or r["tool"] == tool) and all(r.get(k) == v for k, v in match.items())]

    def ssh_call(self):
        [c] = [r for r in self.calls("ssh") if r.get("phase") != "end"]
        return c

    def spec(self, **kw):
        s = {"host": "nas.example.com", "user": "ryan", "port": 22, "timeout_s": 60, "command": "uptime", **kw}
        if "script" in kw:
            s.pop("command")
        return s

    def run_(self, spec=None, key=KEY, lines=(LINE,), mask=lambda s: s, cfg=None, **kw):
        kw.setdefault("workdir_base", self.base)
        return execrun.run(spec or self.spec(), key.encode(), list(lines), cfg or self.cfg, mask, **kw)

    def gone(self):
        """No private directory is left, and every agent that was started is dead."""
        left = os.listdir(self.base) if os.path.isdir(self.base) else []
        self.assertEqual(left, [], "the private directory must be removed")
        pids = [c["pid"] for c in self.calls("ssh-agent") if "pid" in c]
        deadline = time.monotonic() + 10
        for pid in pids:                                       # SIGTERM is delivered asynchronously: wait for it, bounded
            while os.path.exists(f"/proc/{pid}") and time.monotonic() < deadline:
                pass
            # gone entirely, not merely dead: the agent is our child and must have been reaped (no zombie)
            self.assertFalse(os.path.exists(f"/proc/{pid}"), f"agent {pid} is still running or was not reaped")
        return pids


class Options(Rig):
    def test_the_fixed_option_list_and_the_request_slots(self):
        res = self.run_()
        self.assertEqual((res["exit_code"], res["label"]), (0, None))
        call = self.ssh_call()
        known = next(a.split("=", 1)[1] for a in call["argv"] if a.startswith("UserKnownHostsFile="))
        want = [a.replace("<known_hosts>", known) for a in DESIGN_OPTIONS] + [
            "-l", "ryan", "-p", "22", "--", "nas.example.com", "uptime"]
        self.assertEqual(call["argv"], want)

    def test_a_connect_address_adds_one_hostname_option_and_only_a_real_ip_is_accepted(self):
        self.run_(connect_ip="93.184.216.34")
        argv = self.ssh_call()["argv"]
        self.assertEqual(argv[argv.index("-l") - 2:argv.index("-l")], ["-o", "HostName=93.184.216.34"])
        self.assertEqual(argv[-2:], ["nas.example.com", "uptime"])                    # the name is still what ssh looks up
        self.run_(connect_ip="::1")
        self.assertIn("HostName=::1", [c for c in self.calls("ssh") if c.get("phase") != "end"][1]["argv"])
        n = len([c for c in self.calls("ssh") if c.get("phase") != "end"])
        for bad in ("evil.example.com", "-oProxyCommand=x", "1.2.3.4,5.6.7.8", "1.2.3.4 -x", ""):
            res = self.run_(connect_ip=bad)
            self.assertEqual((res["label"], res["exit_code"]), ("internal", None), bad)
        self.assertEqual(len([c for c in self.calls("ssh") if c.get("phase") != "end"]), n)   # none of them ran

    def test_option_looking_values_change_no_option(self):
        base = self.run_()
        prefix = lambda c: c["argv"][:c["argv"].index("-l")]   # noqa: E731
        base_prefix = [a for a in prefix(self.ssh_call()) if not a.startswith("UserKnownHostsFile=")]
        evil = {"host": "-oProxyCommand=evil", "user": "-oProxyCommand=evil2", "command": "-oProxyCommand=evil3 x",
                "port": 2222}
        self.run_(self.spec(**evil))
        calls = [r for r in self.calls("ssh") if r.get("phase") != "end"]
        self.assertEqual(len(calls), 2)                        # positive control: both ran
        argv = calls[1]["argv"]
        self.assertEqual([a for a in prefix(calls[1]) if not a.startswith("UserKnownHostsFile=")], base_prefix)
        i = argv.index("-l")
        self.assertEqual(argv[i:], ["-l", "-oProxyCommand=evil2", "-p", "2222", "--", "-oProxyCommand=evil",
                                    "'-oProxyCommand=evil3' x"])
        self.assertEqual(sum(a.startswith("-oProxy") for a in argv), 2)       # only in their own slots (the command is quoted)
        self.assertEqual(base["exit_code"], 0)

    def test_the_command_that_ssh_receives_is_the_classified_text(self):
        cases = [("echo   'a b'  \"c\"", "echo 'a b' c", ""), ("ls | wc -l ; id", "ls | wc -l ; id", ""),
                 ("ls /tmp/а", "ls '/tmp/а'", "")]
        for typed, sent, _ in cases:
            self.run_(self.spec(command=typed))
        got = [r["argv"][-1] for r in self.calls("ssh") if r.get("phase") != "end"]
        self.assertEqual(got, [c[1] for c in cases])
        self.assertTrue(all(r["stdin"] == "" for r in self.calls("ssh") if r.get("phase") != "end"))

    def test_a_script_goes_on_stdin_byte_for_byte(self):
        text = "set -e\necho '$HOME' | cat\né\n"
        self.run_(self.spec(script={"text": text, "interpreter": "bash"}))
        c = self.ssh_call()
        self.assertEqual((c["argv"][-1], c["stdin"]), ("bash -s", text))

    def test_the_environment_is_minimal_and_holds_no_broker_secret(self):
        os.environ["S3CR3T_BROKER_TOKEN"] = "S3CR3T-ENV-VALUE"
        self.addCleanup(os.environ.pop, "S3CR3T_BROKER_TOKEN", None)
        os.environ["SSH_ASKPASS"] = "/bin/evil"
        self.addCleanup(os.environ.pop, "SSH_ASKPASS", None)
        self.run_()
        self.assertTrue(self.calls())
        for c in self.calls():
            self.assertNotIn("S3CR3T_BROKER_TOKEN", c["env"], c["tool"])
            self.assertNotIn("SSH_ASKPASS", c["env"], c["tool"])
            self.assertLessEqual(set(c["env"]), {"PATH", "HOME", "LANG", "LC_ALL", "SSH_AUTH_SOCK"}, c["tool"])
        self.assertIn("SSH_AUTH_SOCK", self.ssh_call()["env"])


class KeyHandling(Rig):
    def test_the_key_reaches_ssh_add_on_stdin_and_nowhere_else(self):
        self.run_()
        [add] = self.calls("ssh-add")
        self.assertEqual(add["stdin"], KEY)                    # positive control: the key was delivered
        self.assertEqual(add["argv"], ["-"])
        self.assertTrue(add["sock_exists"])
        for c in self.calls():
            blob = json.dumps({k: v for k, v in c.items() if k not in ("stdin",)})
            self.assertNotIn("S3CR3T-KEY", blob, c["tool"])
        ssh = self.ssh_call()
        self.assertNotIn("S3CR3T-KEY", ssh["stdin"])
        self.assertFalse(ssh["secret_in_dir"])
        self.assertTrue(ssh["dir_listing"])                    # the directory had files: the scan looked at something

    def test_known_hosts_is_generated_from_the_pinned_lines_and_the_directory_is_private(self):
        self.run_(lines=[LINE, "[nas.example.com]:2222 ssh-ed25519 AAAA2"])
        c = self.ssh_call()
        self.assertEqual(c["known_hosts"], LINE + "\n[nas.example.com]:2222 ssh-ed25519 AAAA2\n")
        self.assertEqual((c["known_hosts_mode"], c["dir_mode"]), ("0o600", "0o700"))
        self.assertTrue(c["sock_exists"])
        self.assertIn("known_hosts", c["dir_listing"])


class Cleanup(Rig):
    def test_nothing_is_left_after_success(self):
        self.run_()
        self.assertEqual(len(self.gone()), 1)                  # an agent really ran, and is dead

    def test_nothing_is_left_after_a_failure(self):
        self.configure(ssh={"rc": 255, "stderr": "ssh: connect to host x port 22: Connection refused\n"})
        res = self.run_()
        self.assertEqual(res["label"], "connect_failed")
        self.assertEqual(len(self.gone()), 1)

    def test_nothing_is_left_after_a_timeout(self):
        import subprocess
        self.configure(ssh={"hang": True})
        started = []

        def popen(*a, **k):
            p = subprocess.Popen(*a, **k)
            started.append(p.pid)
            return p
        res = self.run_(timer_cls=FireNow, popen=popen)
        self.assertEqual((res["label"], res["exit_code"]), ("timeout", None))
        self.gone()
        self.assertEqual(len(started), 1)                      # positive control: ssh really was started
        deadline = time.monotonic() + 10
        while alive(started[0]) and time.monotonic() < deadline:
            pass
        self.assertFalse(alive(started[0]))

    def test_nothing_is_left_after_a_crash_in_the_runner(self):
        def boom(*a, **k):
            raise RuntimeError("S3CR3T-in-exception")
        res = self.run_(popen=boom)
        self.assertEqual(res["label"], "internal")
        self.assertNotIn("S3CR3T", json.dumps(res))
        self.assertEqual(len(self.gone()), 1)

    def test_nothing_is_left_when_loading_the_key_fails(self):
        self.configure(**{"ssh-add": {"rc": 1}})
        res = self.run_()
        self.assertEqual(res["label"], "internal")
        self.assertEqual(self.calls("ssh"), [])                # ssh was never started without the key
        self.assertEqual(len(self.gone()), 1)

    def test_concurrent_runs_share_no_socket_directory_or_agent(self):
        self.configure(ssh={"wait_for": "go"})
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.run_())) for _ in range(2)]
        for t in threads:
            t.start()
        deadline = time.monotonic() + 20
        while len([f for f in os.listdir(self.dir) if f.startswith("started-")]) < 2:
            self.assertLess(time.monotonic(), deadline, "both runs must be inside ssh at once")
        open(os.path.join(self.dir, "go"), "w").close()
        for t in threads:
            t.join(20)
        self.assertEqual([r["exit_code"] for r in results], [0, 0])
        ssh = [c for c in self.calls("ssh") if c.get("phase") != "end"]
        self.assertEqual(len(ssh), 2)
        self.assertEqual(len({c["env"]["SSH_AUTH_SOCK"] for c in ssh}), 2)
        self.assertEqual(len({c["dir"] for c in ssh}), 2)
        self.assertEqual(len({c["pid"] for c in self.calls("ssh-agent")}), 2)
        self.assertEqual(len(self.gone()), 2)


class Output(Rig):
    def test_output_is_returned_decoded_with_the_exit_status(self):
        self.configure(ssh={"stdout": "out é\n", "stderr": "err\n", "rc": 3})
        res = self.run_()
        self.assertEqual((res["exit_code"], res["stdout"], res["stderr"], res["truncated"], res["label"]),
                         (3, "out é\n", "err\n", False, None))
        self.assertIsInstance(res["duration_ms"], int)

    def test_over_the_cap_is_cut_flagged_and_stopped(self):
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "max_output_bytes": 1024})
        self.configure(ssh={"flood_bytes": 2_000_000})
        res = self.run_(cfg=cfg)
        self.assertEqual((res["label"], res["truncated"], res["exit_code"]), ("output_cap", True, None))
        self.assertEqual(len(res["stdout"]), 1024)
        self.gone()
        # positive control: the same cap with output under it is whole
        self.configure(ssh={"stdout": "x" * 1024})
        res = self.run_(cfg=cfg)
        self.assertEqual((res["label"], res["truncated"], len(res["stdout"])), (None, False, 1024))

    def test_each_stream_has_its_own_cap(self):
        cfg = execmode.parse_config({"enabled": True, "ssh_path": self.dir, "max_output_bytes": 1024})
        self.configure(ssh={"stdout": "o" * 1000, "stderr": "e" * 1000})
        res = self.run_(cfg=cfg)
        self.assertEqual((len(res["stdout"]), len(res["stderr"]), res["truncated"]), (1000, 1000, False))
        self.configure(ssh={"stdout": "o" * 10, "stderr": "e" * 1025})
        res = self.run_(cfg=cfg)
        self.assertEqual((res["label"], len(res["stderr"])), ("output_cap", 1024))

    def test_credential_values_are_masked_in_both_streams(self):
        value = "S3CR3T-OUT-VALUE-1234"
        self.configure(ssh={"stdout": f"a {value} b\n", "stderr": f"c {value}\n"})
        shown = self.run_(mask=lambda s: s)
        self.assertIn(value, shown["stdout"] + shown["stderr"])         # control: the stub did print it
        masker = masking.Masker((value,))
        res = self.run_(mask=masker.mask)
        self.assertNotIn(value, json.dumps(res))
        self.assertIn(masking.MARK, res["stdout"])
        self.assertIn(masking.MARK, res["stderr"])

    def test_invalid_utf8_is_replaced(self):
        self.configure(ssh={"stdout": "ok", "stdout_hex": "ff6fc3a9fe", "stderr_hex": "80"})
        res = self.run_()
        self.assertEqual(res["stdout"], "ok\ufffdo\u00e9\ufffd")          # valid bytes kept, invalid ones replaced
        self.assertEqual(res["stderr"], "\ufffd")


class Sweep(Rig):
    def test_a_start_up_sweep_ends_a_leftover_agent_and_removes_its_directory(self):
        import subprocess
        os.makedirs(self.base)
        leftover = os.path.join(self.base, "x-left")
        os.mkdir(leftover)
        agent = subprocess.Popen([os.path.join(self.dir, "ssh-agent"), "-D", "-a", os.path.join(leftover, "a")],
                                 stdout=subprocess.PIPE)
        agent.stdout.readline()
        with open(os.path.join(leftover, "agent.pid"), "w") as f:
            f.write(str(agent.pid))
        os.mkdir(os.path.join(self.base, "x-empty"))
        innocent = subprocess.Popen(["sleep", "30"])                     # a pid file naming something else is not killed
        os.mkdir(os.path.join(self.base, "x-other"))
        with open(os.path.join(self.base, "x-other", "agent.pid"), "w") as f:
            f.write(str(innocent.pid))
        self.addCleanup(innocent.kill)
        self.assertIsNone(agent.poll())                                     # premise: it is running
        execrun.sweep(self.base)
        agent.wait(10)
        self.assertEqual(os.listdir(self.base), [])
        self.assertIsNone(innocent.poll())
        execrun.sweep(os.path.join(self.dir, "nowhere"))                    # a missing directory is fine


class Labels(Rig):
    def label(self, stderr, rc=255, **kw):
        self.configure(ssh={"rc": rc, "stderr": stderr, "stdout": "S3CR3T-partial"})
        return self.run_(**kw)

    def test_each_ssh_failure_is_its_fixed_label_and_its_words_are_dropped(self):
        for stderr, want in (
                ("@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.\n",
                 "host_key_mismatch"),
                ("Host key for [x]:22 has changed and you have requested strict checking.\nHost key verification failed.\n",
                 "host_key_mismatch"),
                ("No ED25519 host key is known for x and you have requested strict checking.\n"
                 "Host key verification failed.\n", "host_not_pinned"),
                ("ryan@x: Permission denied (publickey).\n", "auth_failed"),
                ("ssh: connect to host x port 22: Connection refused\n", "connect_failed"),
                ("ssh: Could not resolve hostname x: Name or service not known\n", "connect_failed"),
                ("kex_exchange_identification: Connection closed by remote host\n", "connect_failed")):
            res = self.label(stderr)
            self.assertEqual((res["label"], res["exit_code"], res["stdout"], res["stderr"]), (want, None, "", ""), stderr)
            self.assertIn(res["label"], execmode.LABELS)
            self.assertNotIn("S3CR3T", json.dumps(res))

    def test_the_remote_commands_own_255_is_not_an_ssh_failure(self):
        res = self.label("my own error\n")
        self.assertEqual((res["label"], res["exit_code"], res["stderr"]), (None, 255, "my own error\n"))
        res = self.label("Permission denied (publickey).\n", rc=1)           # not 255: ssh does not exit 1 on its own failures
        self.assertEqual((res["label"], res["exit_code"]), (None, 1))

    def test_no_pinned_line_means_no_connection_at_all(self):
        res = self.run_(lines=[])
        self.assertEqual((res["label"], res["exit_code"]), ("host_not_pinned", None))
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.run_()["label"], None)                          # control: with a line it connects
        self.assertTrue(self.calls("ssh"))

    def test_missing_binaries(self):
        for gone in ("ssh", "ssh-agent", "ssh-add"):
            os.remove(os.path.join(self.dir, gone))
            res = self.run_()
            self.assertEqual((res["label"], res["exit_code"]), ("ssh_unavailable", None), gone)
            shutil.copy(STUB, os.path.join(self.dir, gone))
            os.chmod(os.path.join(self.dir, gone), 0o755)
        self.assertEqual(self.run_()["label"], None)
        os.remove(os.path.join(self.dir, "ssh"))
        res = self.run_(cfg=execmode.parse_config({"enabled": True, "ssh_path": os.path.join(self.dir, "nowhere")}))
        self.assertEqual(res["label"], "ssh_unavailable")

    def test_the_timeout_label_only_when_the_timer_really_killed_it(self):
        class LateFire(FireNow):
            """Fires only when cancelled, i.e. after the run is over: a timer that lost the race."""

            def start(self):
                pass

            def cancel(self):
                self.fn()
        res = self.run_(timer_cls=LateFire)
        self.assertEqual((res["label"], res["exit_code"]), (None, 0))
        self.configure(ssh={"hang": True})
        self.assertEqual(self.run_(timer_cls=FireNow)["label"], "timeout")      # control: an early timer does kill


class Brokered(ti.ExecBase):
    """The broker around the runner: release thread, status, events, notifications."""

    def tweak(self, cfg):
        super().tweak(cfg)
        self.stubs = tempfile.mkdtemp(prefix="stubs-")
        self.addCleanup(shutil.rmtree, self.stubs, True)
        for name in ("ssh", "ssh-agent", "ssh-add"):
            shutil.copy(STUB, os.path.join(self.stubs, name))
            os.chmod(os.path.join(self.stubs, name), 0o755)
        self.conf = {"ssh": {"stdout": "S3CR3T-OUTPUT line\n", "stderr": "warn\n", "rc": 0}}
        self.write_conf()

    def write_conf(self):
        with open(os.path.join(self.stubs, "config.json"), "w") as f:
            json.dump(self.conf, f)

    def setUp(self):
        super().setUp()
        del self.broker._exec_run                              # the real runner, not the intake tests' fake
        self.enable(ssh_path=self.stubs)
        self.broker.auto_rules = __import__("secret_broker.autorules", fromlist=["x"]).parse([{
            "name": "uptime", "mode": "exec", "secret": "deploy", "host": "nas.example.com", "account": "ryan",
            "argv": ["uptime"]}])

    def calls(self, tool):
        try:
            with open(os.path.join(self.stubs, "calls.jsonl")) as f:
                return [json.loads(x) for x in f if json.loads(x)["tool"] == tool]
        except FileNotFoundError:
            return []

    def run_once(self, **body):
        code, b = self.ask(**body)
        self.assertEqual(code, 202, b)
        req = self.broker._by_id[json.loads(b)["id"]]
        req.done.wait(20)
        return req

    def test_a_policy_release_runs_ssh_and_delivers_the_result_once(self):
        req = self.run_once()
        self.assertEqual(req.status, "approved")
        got = self.poll(req.id)
        self.assertEqual(got, {"status": "released", "exit_code": 0, "stdout": "S3CR3T-OUTPUT line\n",
                               "stderr": "warn\n", "truncated": False, "label": None})
        self.assertEqual(self.poll(req.id), {"status": "released"})
        [add] = self.calls("ssh-add")
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", add["stdin"])              # the vault key, on stdin
        ssh = [c for c in self.calls("ssh") if c.get("phase") != "end"][0]
        self.assertEqual(ssh["argv"][-7:], ["-l", "ryan", "-p", "22", "--", "nas.example.com", "uptime"])

    def test_events_carry_counts_and_a_label_but_never_output_or_the_command(self):
        req = self.run_once()
        self.poll(req.id)
        [start] = self.events("exec_started")
        [fin] = self.events("exec_finished")
        self.assertEqual(start["id"], req.id)
        self.assertEqual((fin["exit_code"], fin["stdout_bytes"], fin["stderr_bytes"], fin["truncated"], fin["label"]),
                         (0, len("S3CR3T-OUTPUT line\n"), len("warn\n"), False, None))
        self.assertIsInstance(fin["duration_ms"], int)
        self.assertEqual((fin["host"], fin["account"]), ("nas.example.com", "ryan"))
        raw = open(self.audit).read()
        self.assertIn("exec_finished", raw)                                   # positive control
        self.assertNotIn("S3CR3T-OUTPUT", raw)
        self.assertNotIn("BEGIN OPENSSH", raw)
        self.assertEqual(self.notifier.sent, [])                              # auto-approved: nothing was sent at all

    def test_nothing_from_the_output_reaches_a_notification(self):
        self.broker.auto_rules = []
        rid = self.pending(command="uptime")
        self.decide(rid, "approve")
        self.broker._by_id[rid].done.wait(20)
        self.assertEqual(self.poll(rid)["stdout"], "S3CR3T-OUTPUT line\n")
        self.assertTrue(self.notifier.sent)                                   # a human was asked: control
        self.assertNotIn("S3CR3T-OUTPUT", json.dumps(self.notifier.sent))
        self.assertNotIn("S3CR3T-OUTPUT", open(self.audit).read())

    def test_the_key_value_is_masked_if_the_command_echoes_it(self):
        pem = self.broker.backend.get("Deploykey", "private_key")
        body = pem.strip().splitlines()[1]
        self.conf["ssh"]["stdout"] = f"leak: {body}\n"
        self.write_conf()
        req = self.run_once()
        got = self.poll(req.id)
        self.assertNotIn(body, got["stdout"])
        self.assertIn("***", got["stdout"])

    def test_a_failure_is_a_label_and_a_released_result(self):
        self.conf["ssh"] = {"rc": 255, "stderr": "Permission denied (publickey).\n"}
        self.write_conf()
        req = self.run_once()
        self.assertEqual(self.poll(req.id), {"status": "released", "exit_code": None, "stdout": "", "stderr": "",
                                             "truncated": False, "label": "auth_failed"})
        self.assertEqual(self.events("exec_finished")[-1]["label"], "auth_failed")

    def test_the_pin_is_checked_again_when_it_runs(self):
        req = self.pending_for_run()
        self.broker.cfg["secrets"]["deploy"]["ssh_hosts"] = {"known": {}, "allowed": [], "allow_forwarded": False}
        self.broker.cfg["secrets"]["deploy"]["_meta"] = {**self.broker.cfg["secrets"]["deploy"]["_meta"], "ssh_hosts": {}}
        self.assertEqual(self.broker._exec_run(req)["label"], "host_not_pinned")
        self.assertEqual(self.calls("ssh"), [])

    def pending_for_run(self):
        self.broker.auto_rules = []
        return self.broker._by_id[self.pending()]

    def test_running_then_released_for_a_human_approval(self):
        self.broker.auto_rules = []
        self.conf["ssh"]["wait_for"] = "go"
        self.write_conf()
        rid = self.pending()
        self.decide(rid, "approve")
        deadline = time.monotonic() + 20
        while not [f for f in os.listdir(self.stubs) if f.startswith("started-")]:
            self.assertLess(time.monotonic(), deadline)
        self.assertEqual(self.poll(rid), {"status": "running"})
        open(os.path.join(self.stubs, "go"), "w").close()
        self.broker._by_id[rid].done.wait(20)
        self.assertEqual(self.poll(rid)["exit_code"], 0)

    def test_the_run_slots_bound_concurrency(self):
        self.enable(ssh_path=self.stubs, max_concurrent=1, max_pending_per_client=20)
        self.settle_auto = False                               # post all three, then let them race for the slot
        self.conf["ssh"]["sleep"] = 0.15
        self.write_conf()
        reqs = []
        for _ in range(3):
            code, b = self.ask()
            self.assertEqual(code, 202, b)
            reqs.append(self.broker._by_id[json.loads(b)["id"]])
        for r in reqs:
            r.done.wait(30)
        spans = sorted((c["t0"], c["t1"]) for c in self.calls("ssh") if c.get("phase") == "end")
        self.assertEqual(len(spans), 3)
        for (_, a_end), (b_start, _) in zip(spans, spans[1:]):
            self.assertLessEqual(a_end, b_start, "with one slot two ssh runs must never overlap")

    def test_more_slots_let_runs_overlap(self):
        self.enable(ssh_path=self.stubs, max_concurrent=3, max_pending_per_client=20)
        self.settle_auto = False                               # do not wait for a run that waits for us
        self.conf["ssh"]["wait_for"] = "go"
        self.write_conf()
        reqs = []
        for _ in range(3):
            code, b = self.ask()
            reqs.append(self.broker._by_id[json.loads(b)["id"]])
        deadline = time.monotonic() + 20
        while len([f for f in os.listdir(self.stubs) if f.startswith("started-")]) < 3:
            self.assertLess(time.monotonic(), deadline, "three runs must be inside ssh at once")
        open(os.path.join(self.stubs, "go"), "w").close()
        for r in reqs:
            r.done.wait(30)
        self.assertEqual([r.status for r in reqs], ["approved"] * 3)

    def test_the_history_popover_keeps_the_command_and_the_result(self):
        req = self.run_once(command="uptime")
        self.poll(req.id)
        page = self.get(f"/request/{req.id}")[1]
        self.assertIn("Remote command", page)
        self.assertIn("uptime", page)
        self.assertIn("S3CR3T-OUTPUT line", page)                             # the approver sees the output here, as designed
        self.assertIn("Exit status 0", page)
        self.assertIn("nas.example.com", page)


if __name__ == "__main__":
    unittest.main()
