#!/usr/bin/env python3
"""End-to-end test of remote exec (request mode `exec`) against REAL OpenSSH.

    tests/e2e_remote_exec/run.sh        (runs this in a throwaway container; the usual way)
    python tests/e2e_remote_exec/driver.py   (runs it here, if OpenSSH is installed: no root needed)

What runs: the real broker (in this process) with its real client API, a real unprivileged `sshd` on a loopback
port (its own host key, authorized_keys holding the broker's key), and the real `ssh`, `ssh-agent` and `ssh-add`
that the broker drives. The agent is this script, speaking the client HTTP API; the "phone" is this script
deciding through Broker.decide_via, the call the approval page makes.

Checks: a rule-approved read of a command returns its output with no human; exit status and stderr come back; a
script runs from stdin after a human approval; a host key that differs from the pin (a rekeyed server) is a
`changed` request for a human, never a command that runs unasked; a host or port the key does not pin prompts, and
"approve once" persists nothing while "remember" makes the next call an ordinary pinned one; a server whose key
changes between the card and the connection fails closed (`host_key_mismatch`) and the command does not run;
a timeout and an output cap are reported by label; the key is never on any process's command line or environment
while a command runs, and no ssh-agent or private directory is left; `ssh_agent: off` refuses agent signing; the
audit log holds counts and labels, never output.

Without OpenSSH (sshd, ssh, ssh-agent, ssh-add, ssh-keygen) it SKIPS, saying why, and exits 0, unless
ASB_E2E_REQUIRE=1 (set by the Dockerfile and CI), which makes a skip a failure.
"""
import base64
import json
import os
import secrets as pysecrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

TOOLS = ("ssh", "ssh-agent", "ssh-add", "ssh-keygen")


def find_sshd():
    for p in (shutil.which("sshd"), "/usr/sbin/sshd", "/usr/local/sbin/sshd"):
        if p and os.access(p, os.X_OK):
            return p
    return None


class Failure(Exception):
    pass


def skip(why):
    print(f"SKIP: remote exec end-to-end test not run: {why}")
    sys.exit(1 if os.environ.get("ASB_E2E_REQUIRE") == "1" else 0)


class E2E:
    def __init__(self):
        self.failures, self.passed = [], 0
        self.dir = tempfile.mkdtemp(prefix="asb-e2e-exec-")
        self.me = subprocess.run(["id", "-un"], capture_output=True, text=True, check=True).stdout.strip()

    # -- environment ----------------------------------------------------------------------------
    def start_sshd(self):
        d = self.dir
        run = lambda *c: subprocess.run(c, check=True, capture_output=True)  # noqa: E731
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/hostkey")
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/wrong_hostkey")
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{d}/brokerkey")
        shutil.copy(f"{d}/brokerkey.pub", f"{d}/authorized_keys")
        os.chmod(f"{d}/authorized_keys", 0o600)
        self.sshds = {}
        self.sshd, self.port = self.spawn_sshd("hostkey")

    def spawn_sshd(self, hostkey, port=None):
        """A real unprivileged sshd on a loopback port presenting `hostkey` (a file name in the work directory)."""
        import socket
        d = self.dir
        if port is None:
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.close()
        conf = f"{d}/sshd_config_{port}"
        with open(conf, "w") as f:
            f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/{hostkey}\n"
                    f"AuthorizedKeysFile {d}/authorized_keys\nPidFile {d}/sshd_{port}.pid\nUsePAM no\n"
                    "PasswordAuthentication no\nKbdInteractiveAuthentication no\nStrictModes no\nLogLevel ERROR\n")
        # an absolute -f: sshd re-executes itself for every connection
        proc = subprocess.Popen([self.sshd_bin, "-D", "-f", conf, "-E", f"{d}/sshd_{port}.log"])
        self.sshds[port] = proc
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), 1).close()
                return proc, port
            except OSError:
                if proc.poll() is not None:
                    break
        raise Failure("sshd did not start: " + open(f"{d}/sshd_{port}.log").read()[-500:])

    def restart_sshd(self, port, hostkey):
        """Stop the sshd on `port` and start one there presenting `hostkey` (a server that was rekeyed)."""
        proc = self.sshds.pop(port)
        proc.terminate()
        proc.wait(10)
        proc, _ = self.spawn_sshd(hostkey, port)
        if port == self.port:
            self.sshd = proc

    def fingerprint(self, which="hostkey"):
        out = subprocess.run(["ssh-keygen", "-lf", f"{self.dir}/{which}.pub"], capture_output=True, text=True, check=True)
        return out.stdout.split()[1]

    def host_line(self, which="hostkey", port=None):
        key = open(f"{self.dir}/{which}.pub").read().split()
        return f"[127.0.0.1]:{port or self.port} {key[0]} {key[1]}"

    def start_broker(self):
        from secret_broker import clients as clients_mod
        from secret_broker import destguard, execmode, sshkey
        destguard.allow_loopback_for_tests()
        from secret_broker.backends import FileBackend
        from secret_broker.broker import Broker, serve
        from secret_broker.notify import FakeNotifier
        pem = open(f"{self.dir}/brokerkey").read()
        self.pem_body = pem.strip().splitlines()[1]
        meta = {"name": "deploy", "vars": {"DEPLOY_SSH_KEY": {"item": "Deploykey", "field": "private_key"}},
                "allowed_hosts": [], "ssh": True,
                "ssh_public_key": sshkey.public_line(sshkey.load_private(pem)),
                "ssh_hosts": {"known_hosts": [self.host_line()], "allowed_hosts": ["127.0.0.1"]}}
        vault = f"{self.dir}/vault.json"
        with open(vault, "w") as f:
            json.dump({"Deploykey": {"private_key": pem, "broker": json.dumps(meta)}}, f)
        cfg = {"approve_base_url": "https://secrets.example", "allowed_user": "alice", "ttl_seconds": 120,
               "secrets": {}}
        self.audit_path = f"{self.dir}/audit.jsonl"
        self.broker = Broker(cfg, FileBackend(vault), FakeNotifier(), self.audit_path)
        # `localhost` is 127.0.0.1 here (a container resolves it to ::1 as well, which the guard's test-only loopback
        # switch does not pass; the sshd listens on 127.0.0.1 only). Same device as tests/test_e2e.py.
        real_resolver = self.broker.dest_guard._resolver
        self.broker.dest_guard._resolver = lambda h, p: ["127.0.0.1"] if h.lower() == "localhost" else real_resolver(h, p)
        client, approval = serve(self.broker, ("127.0.0.1", 0), ("127.0.0.1", 0), "legacy-" + pysecrets.token_urlsafe(16))
        self.servers = (client, approval)
        self.base = f"http://127.0.0.1:{client.server_address[1]}"
        secret = "asbc1_" + pysecrets.token_urlsafe(32)
        with mock.patch.object(clients_mod, "SUBMIT_HOUR", (999, 999)):
            code, out, _ = self.broker.clients.submit("the-agent", clients_mod.hash_secret(secret), "e2e@box", "127.0.0.1")
        assert code == 202, (code, out)
        status, _ = self.broker.decide_enrollment(out["id"], "approve", "the-agent", "alice")
        assert status == "approved", status
        self.agent_key = secret
        self.agent_id = next(r["id"] for r in self.broker.clients.rows() if r["name"] == "the-agent")
        self.broker.exec_cfg = execmode.parse_config({"enabled": True, "clients": [self.agent_id],
                                                      "max_output_bytes": 4096, "max_seconds": 30})
        from secret_broker import autorules
        self.broker.auto_rules = autorules.parse([
            {"name": f"{n} on the test host", "mode": "exec", "secret": "deploy", "host": "127.0.0.1",
             "account": self.me, "port": self.port, "argv": argv, "clients": [self.agent_id]}
            for n, argv in (("echo", ["echo"]), ("sh", ["sh", "-c"]), ("sleep", ["sleep"]), ("touch", ["touch"]))])

    # -- the agent's side ------------------------------------------------------------------------
    def api(self, method, path, body=None):
        r = urllib.request.Request(self.base + path, method=method, headers={
            "X-Client-Key": self.agent_key, "Content-Type": "application/json"},
            data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def exec_(self, command=None, script=None, port=None, host="127.0.0.1", timeout_s=20, approve=False, wait=True):
        body = {"mode": "exec", "names": ["deploy"], "host": host, "user": self.me, "port": port or self.port,
                "timeout_s": timeout_s, "source": "e2e"}
        if script is not None:
            body["script"] = {"text": script, "interpreter": "sh"}
        else:
            body["command"] = command
        code, got = self.api("POST", "/v1/requests", body)
        if code != 202:
            return code, got
        rid = got["id"]
        if approve:
            self.check(self.broker.decide_via("dashboard", rid, "approve", "alice")[0] == 200, "human approval accepted")
        if not wait:
            return 202, {"id": rid}
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            _, res = self.api("GET", f"/v1/requests/{rid}?wait=5")
            if res.get("status") not in ("pending", "running"):
                return 200, {**res, "id": rid}
        raise Failure("no result within 60 s")

    # -- checks ----------------------------------------------------------------------------------
    def check(self, ok, what):
        if ok:
            self.passed += 1
            print(f"  ok   {what}")
        else:
            self.failures.append(what)
            print(f"  FAIL {what}")

    def eq(self, got, want, what):
        self.check(got == want, f"{what}" + ("" if got == want else f"  (got {got!r}, want {want!r})"))

    def agents_running(self):
        out = subprocess.run(["pgrep", "-u", str(os.getuid()), "-x", "ssh-agent"], capture_output=True, text=True)
        return sorted(out.stdout.split())

    def scan_processes_for(self, needle):
        """PIDs whose command line or environment holds `needle` (readable ones only)."""
        hits = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            for part in ("cmdline", "environ"):
                try:
                    with open(f"/proc/{pid}/{part}", "rb") as f:
                        if needle in f.read():
                            hits.append((pid, part))
                except OSError:
                    pass
        return hits

    def scenarios(self):
        print(f"OpenSSH: {subprocess.run(['ssh', '-V'], capture_output=True, text=True).stderr.strip()}")
        before = self.agents_running()

        code, r = self.exec_("echo hello   'big world'")
        self.eq((code, r.get("exit_code"), r.get("stdout"), r.get("label")), (200, 0, "hello big world\n", None),
                "a rule-approved command runs on the real sshd and returns its output")
        self.eq(self.broker.notifier.sent, [], "no human was asked")

        code, r = self.exec_("sh -c 'echo to-out; echo to-err 1>&2; exit 7'")
        self.eq((r.get("exit_code"), r.get("stdout"), r.get("stderr")), (7, "to-out\n", "to-err\n"),
                "exit status and stderr come back separately")

        code, r = self.exec_(script="echo from-script\nread x || true\nexit 3\n", approve=True)
        self.eq((r.get("exit_code"), r.get("stdout")), (3, "from-script\n"), "a script runs from stdin after a human approval")
        sha = self.broker._by_id[r["id"]].spec["script"]["text"]
        self.check(sha.startswith("echo from-script"), "the script that ran is the one that was approved")

        marker = f"{self.dir}/ran-marker"
        code, r = self.exec_(f"touch {marker}")
        self.eq((r.get("exit_code"), os.path.exists(marker)), (0, True), "(control) a command that touches a file does")
        os.remove(marker)

        self.unpinned_scenarios(marker)

        code, r = self.exec_("sleep 30", timeout_s=1)
        self.eq((r.get("label"), r.get("exit_code")), ("timeout", None), "a timeout is reported by label")

        code, r = self.exec_("sh -c 'yes | head -c 200000'")
        self.eq((r.get("label"), r.get("truncated"), len(r.get("stdout", ""))), ("output_cap", True, 4096),
                "output over the cap is cut and reported")

        # the key must not be on any process's command line or environment while a command runs
        probe = {}
        t = threading.Thread(target=lambda: probe.update(r=self.exec_("sleep 4")[1]))
        t.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and len(self.agents_running()) <= len(before):
            pass
        self.check(len(self.agents_running()) > len(before), "a private ssh-agent runs during the command")
        env_marker = subprocess.Popen(["sleep", "4"], env={**os.environ, "ASB_PROBE": self.pem_body})
        self.check(bool(self.scan_processes_for(self.pem_body.encode())),
                   "(control) the process scan does find a planted key line")
        self.eq(sorted(set(self.scan_processes_for(self.pem_body.encode())) - {(str(env_marker.pid), "environ")}), [],
                "the private key is on no process's command line or environment while a command runs")
        env_marker.kill()
        t.join(30)
        self.eq(probe.get("r", {}).get("exit_code"), 0, "(control) the long command still finished")

        deadline = time.monotonic() + 10
        while self.agents_running() != before and time.monotonic() < deadline:
            pass
        self.eq(self.agents_running(), before, "no ssh-agent is left behind")
        left = os.listdir(f"{self.dir}/exec") if os.path.isdir(f"{self.dir}/exec") else []
        self.eq(left, [], "no private directory is left behind")

        raw = open(self.audit_path).read()
        self.check('"exec_finished"' in raw and "hello big world" not in raw and "from-script" not in raw
                   and self.pem_body not in raw, "the audit log has the run's counts and labels, never output or the key")

        # the agent-signing path
        self.broker.cfg["secrets"]["deploy"]["ssh_agent"] = "off"
        code, r = self.api("POST", "/v1/requests", {"mode": "ssh_sign", "names": ["deploy"], "flags": 0,
                                                    "data_b64": base64.b64encode(b"x" * 40).decode()})
        self.eq(code, 403, "ssh_agent: off refuses agent signing for the key")
        code, r = self.exec_("echo still-works")
        self.eq(r.get("stdout"), "still-works\n", "exec on the same key is unaffected")

    def decide(self, rid, choice=None, confirm=False, decision="approve"):
        return self.broker.decide_via("dashboard", rid, decision, "alice", exec_host=choice, confirm_replace=confirm)[0]

    def wait_result(self, rid):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            _, res = self.api("GET", f"/v1/requests/{rid}?wait=5")
            if res.get("status") not in ("pending", "running"):
                return res
        raise Failure("no result within 60 s")

    def hosts_meta(self):
        return json.dumps(self.broker.cfg["secrets"]["deploy"]["_meta"]["ssh_hosts"], sort_keys=True)

    def unpinned_scenarios(self, marker):
        broker = self.broker
        probe_cache = broker._exec_prober._cache
        known = lambda: broker.cfg["secrets"]["deploy"]["_meta"]["ssh_hosts"]["known_hosts"]  # noqa: E731
        good_pin = list(known())

        # 1. a rekeyed server: the pinned line is not the key the server presents -> `changed`, asked, not run
        meta = broker.cfg["secrets"]["deploy"]["_meta"]
        meta["ssh_hosts"]["known_hosts"] = [self.host_line("wrong_hostkey")]
        probe_cache.clear()
        code, r = self.exec_(f"touch {marker}", wait=False)
        self.eq(code, 202, "a pinned host whose key differs is a request, not a refusal")
        sp = broker._by_id[r["id"]].spec
        self.eq((sp["host_state"], sp["presented_fp"], sp["pinned_fp"]),
                ("changed", self.fingerprint("hostkey"), self.fingerprint("wrong_hostkey")),
                "the card carries the server's real fingerprint and the pinned one")
        self.eq((broker._by_id[r["id"]].status, os.path.exists(marker)), ("pending", False),
                "a changed key waits for a human and the command does not run")
        self.eq(self.decide(r["id"], "remember"), 400, "remember is refused for a changed key")
        self.eq(self.decide(r["id"], "replace", confirm=False), 400, "replace without the confirmation is refused")
        self.eq(self.decide(r["id"], "replace", confirm=True), 200, "replace with the confirmation is accepted")
        res = self.wait_result(r["id"])
        self.eq((res.get("exit_code"), os.path.exists(marker)), (0, True), "after replace the command runs on the real sshd")
        self.eq(known(), [self.host_line()], "the pinned line is now the key the server presents (old line replaced)")
        os.remove(marker)
        ev = [e for e in open(self.audit_path).read().splitlines() if '"exec_host_replaced"' in e]
        self.check(len(ev) == 1 and self.fingerprint("wrong_hostkey") in ev[0] and self.fingerprint("hostkey") in ev[0],
                   "replace is audited with both fingerprints")
        code, r = self.exec_("echo back")
        self.eq(r.get("stdout"), "back\n", "(control) the replaced pin makes the next call an ordinary rule-approved one")

        # 2. a key that changes between the card and the connection fails closed
        probe_cache.clear()
        code, r = self.exec_(f"touch {marker}", wait=False, host="localhost")
        if code != 202:
            raise Failure(f"a request for a name that resolves to the test sshd was refused: {code} {r} "
                          f"probe events: {[e for e in open(self.audit_path).read().splitlines() if 'exec_probe' in e][-2:]}")
        sp = broker._by_id[r["id"]].spec
        self.eq(sp.get("host_state"), "new", "a name the key does not allow is a `new` request")
        self.eq(sp.get("presented_fp"), self.fingerprint("hostkey"), "its card shows the key the server presents")
        self.restart_sshd(self.port, "wrong_hostkey")
        self.eq(self.decide(r["id"]), 200, "the human approves once")
        res = self.wait_result(r["id"])
        self.eq((res.get("label"), res.get("exit_code"), os.path.exists(marker)), ("host_key_mismatch", None, False),
                "a server key that changed after the card was shown fails closed; the command does not run")
        self.restart_sshd(self.port, "hostkey")
        probe_cache.clear()

        # 3. a new name: approve once runs it and persists nothing
        before = self.hosts_meta()
        code, r = self.exec_(f"touch {marker}", wait=False, host="localhost")
        self.eq(broker._by_id[r["id"]].spec.get("host_state"), "new", "an unpinned host prompts")
        self.eq(self.decide(r["id"]), 200, "approve once")
        res = self.wait_result(r["id"])
        self.eq((res.get("exit_code"), os.path.exists(marker)), (0, True), "the approved-once command ran on the shown key")
        os.remove(marker)
        self.eq(self.hosts_meta(), before, "approve once persisted nothing")
        code, r = self.exec_("echo x", host="localhost", wait=False)
        self.eq(broker._by_id[r["id"]].spec.get("host_state"), "new", "(control) it still prompts next time")
        broker._by_id[r["id"]].status = "expired"          # (a denial would start the broker's per-credential cooldown)

        # 4. remember: the next call is an ordinary pinned request
        code, r = self.exec_("echo remembered", host="localhost", wait=False)
        self.eq(self.decide(r["id"], "remember"), 200, "approve and remember")
        res = self.wait_result(r["id"])
        self.eq(res.get("stdout"), "remembered\n", "it ran")
        self.check(any(ln.startswith(f"[localhost]:{self.port} ") for ln in known()) and "localhost" in
                   broker.cfg["secrets"]["deploy"]["_meta"]["ssh_hosts"]["allowed_hosts"],
                   "the line and the allowed host were written to the key's metadata")
        code, r = self.exec_("echo pinned-now", host="localhost", wait=False)
        self.check("host_state" not in broker._by_id[r["id"]].spec, "a later request to that host is an ordinary pinned one")
        broker._by_id[r["id"]].status = "expired"          # (a denial would start the broker's per-credential cooldown)

        # 5. the same key on another port
        proc2, port2 = self.spawn_sshd("hostkey")
        code, r = self.exec_("echo p2", wait=False, port=port2)
        sp = broker._by_id[r["id"]].spec
        self.eq((sp.get("host_state"), sp.get("same_as")), ("same_key_elsewhere", f"127.0.0.1:{self.port}"),
                "the same key on another port is recognised as such")
        self.eq(self.decide(r["id"], "remember"), 200, "remember the new port")
        res = self.wait_result(r["id"])
        self.eq(res.get("stdout"), "p2\n", "it ran on the second sshd")
        self.check(self.host_line("hostkey", port2) in known(), "the bracketed line for the new port was added")
        self.sshds.pop(port2).terminate()

        known_now = known()
        self.check(known_now.count(self.host_line()) == 1, "no pinned line was duplicated")
        meta["ssh_hosts"]["known_hosts"] = good_pin + [ln for ln in known_now if ln not in good_pin]

        # 6. a forbidden destination is never probed or connected to
        broker.dest_guard.allow_loopback = False
        probe_cache.clear()
        code, r = self.exec_("echo x", host="localhost")
        self.eq(code, 403, "with the guard on, a loopback destination is refused at intake")
        broker.dest_guard.allow_loopback = True

    def run(self):
        self.sshd_bin = find_sshd()
        missing = [t for t in TOOLS if not shutil.which(t)] + ([] if self.sshd_bin else ["sshd"])
        if missing:
            skip("OpenSSH programs not found: " + ", ".join(missing))
        try:
            self.start_sshd()
            self.start_broker()
            self.scenarios()
        except Failure as e:
            self.failures.append(str(e))
            print(f"  FAIL {e}")
        finally:
            for s in getattr(self, "servers", ()):
                s.shutdown()
            for proc in getattr(self, "sshds", {}).values():
                proc.terminate()
            shutil.rmtree(self.dir, ignore_errors=True)
        print(f"{self.passed} checks passed, {len(self.failures)} failed")
        sys.exit(1 if self.failures else 0)


if __name__ == "__main__":
    E2E().run()
