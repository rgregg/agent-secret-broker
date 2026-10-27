#!/usr/bin/env python3
"""End-to-end test of the root helper with REAL root and REAL sudo.

    tests/e2e_root_exec/run.sh        (runs this inside a throwaway container; the way to use it)

It creates a user, writes /etc/sudoers.d and /etc/secret-broker, installs a root-owned helper, and edits file
modes. Run it ONLY in a disposable container or VM. It refuses to start unless ASB_E2E_DISPOSABLE=1 (the
Dockerfile and the CI job set it) and it is root.

What runs: the real broker (in this process) with its real client API and approval pages on loopback, the real
`asb-root-exec` binary installed as root, real sudo with the one NOPASSWD rule, and the real `asb` client run as an
unprivileged `agent` user. The "phone" is this script approving or denying through the approval page's HTTP
endpoint, the same call the browser makes.
"""
import json
import os
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

HELPER_DEST = "/usr/local/sbin/asb-root-exec"
CONFIG_DIR = "/etc/secret-broker"
CONFIG = f"{CONFIG_DIR}/root-exec.json"
SUDOERS = "/etc/sudoers.d/asb-root-exec"
# Root-owned, and every directory above must be root-owned and closed to group/other writes, or the helper (rightly)
# refuses to run a script from it. /opt is group-writable on some images (GitHub's runners), so use the helper's
# own directory chain, which has to be trusted for the helper to start at all.
WORK = "/usr/local/sbin/asb-e2e"       # the client copy and a trusted script live here
AGENT = "agent"
AGENT_HOME = f"/home/{AGENT}"
AGENT_CWD = f"{AGENT_HOME}/work"
PYTHON = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else shutil.which("python3")


def real(path):
    return os.path.realpath(path)


def sh(*cmd, check=True, **kw):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


class Failure(Exception):
    pass


def main():
    if os.environ.get("ASB_E2E_DISPOSABLE") != "1":
        sys.exit("refusing to run: this edits /etc and creates users. Use tests/e2e_root_exec/run.sh "
                 "(a throwaway container), or set ASB_E2E_DISPOSABLE=1 in a disposable VM.")
    if os.geteuid() != 0:
        sys.exit("must run as root (inside the disposable container or VM)")
    E2E().run()


class E2E:
    def __init__(self):
        self.failures = []
        self.passed = 0
        self.seen = []                    # sudo requests the broker received: argv, cwd, invoker, source
        self.policy = "approve"           # what the "phone" does: approve | deny | ignore
        self.handled = set()

    # -- environment ------------------------------------------------------------------------------
    def setup(self):
        if sh("id", "-u", AGENT, check=False).returncode != 0:
            sh("useradd", "-m", "-s", "/bin/sh", AGENT)
        os.makedirs(AGENT_CWD, exist_ok=True)
        shutil.chown(AGENT_CWD, AGENT, AGENT)
        os.makedirs(WORK, exist_ok=True)
        os.chmod(WORK, 0o755)
        shutil.copy(os.path.join(ROOT, "client", "asb"), f"{WORK}/asb")
        os.chmod(f"{WORK}/asb", 0o755)
        with open(f"{WORK}/ok.sh", "w") as f:       # a script root owns: allowed by the script rules
            f.write("#!/bin/sh\necho script-ran-as-$(id -u)\n")
        os.chmod(f"{WORK}/ok.sh", 0o755)

        helper = os.environ.get("ASB_E2E_HELPER") or "/opt/asb-root-exec.build"
        if not os.path.exists(helper):
            sys.exit(f"no helper binary at {helper}: build it (cargo build --release -p asb-root-exec) and set ASB_E2E_HELPER")
        os.makedirs(os.path.dirname(HELPER_DEST), exist_ok=True)
        sh("install", "-o", "root", "-g", "root", "-m", "0755", helper, HELPER_DEST)
        os.makedirs(CONFIG_DIR, exist_ok=True)
        os.chmod(CONFIG_DIR, 0o755)

        with open(SUDOERS, "w") as f:
            f.write(f"{AGENT} ALL=(root) NOPASSWD: {HELPER_DEST}\n")
        os.chmod(SUDOERS, 0o440)
        sh("visudo", "-cf", SUDOERS)

        self.start_broker()

    def start_broker(self):
        import tempfile
        from secret_broker import clients as clients_mod
        from secret_broker import destguard, sudomode
        destguard.allow_loopback_for_tests()      # the approval page trusts loopback peers; this driver is that peer
        from secret_broker.backends import FileBackend
        from secret_broker.broker import Broker, serve
        from secret_broker.notify import FakeNotifier

        d = tempfile.mkdtemp()
        vault = os.path.join(d, "vault.json")
        with open(vault, "w") as f:
            json.dump({}, f)
        cfg = {"approve_base_url": "https://secrets.example", "allowed_user": "alice", "ttl_seconds": 120, "secrets": {}}
        self.audit_path = os.path.join(d, "audit.jsonl")
        self.broker = Broker(cfg, FileBackend(vault), FakeNotifier(), self.audit_path)
        c, a = serve(self.broker, ("127.0.0.1", 0), ("127.0.0.1", 0), "legacy-" + pysecrets.token_urlsafe(16))
        self.servers = (c, a)
        self.base = f"http://127.0.0.1:{c.server_address[1]}"
        self.abase = f"http://127.0.0.1:{a.server_address[1]}"

        def enroll(name):
            secret = "asbc1_" + pysecrets.token_urlsafe(32)
            with mock.patch.object(clients_mod, "SUBMIT_HOUR", (999, 999)):
                code, out, _ = self.broker.clients.submit(name, clients_mod.hash_secret(secret), "e2e@box", "127.0.0.1")
            assert code == 202, (code, out)
            status, _ = self.broker.decide_enrollment(out["id"], "approve", name, "alice")
            assert status == "approved", status
            cid = next(r["id"] for r in self.broker.clients.rows() if r["name"] == name)
            return cid, secret

        self.helper_id, self.helper_key = enroll("root-helper")
        self.agent_id, self.agent_key = enroll("the-agent")
        self.broker.sudo_cfg = sudomode.parse_config({"enabled": True, "clients": [self.helper_id]})
        self.write_config()
        threading.Thread(target=self.phone, daemon=True).start()

    def write_config(self, mode=None, allow=None, mod=0o600, url=None):
        cfg = {"url": url or self.base, "key": self.helper_key}
        if mode is not None:
            cfg["mode"] = mode
        if allow is not None:
            cfg["allow"] = allow
        with open(CONFIG, "w") as f:
            json.dump(cfg, f)
        os.chown(CONFIG, 0, 0)
        os.chmod(CONFIG, mod)

    # -- the "phone": decides through the approval page's HTTP endpoint ---------------------------
    def phone(self):
        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoFollow)
        while True:
            time.sleep(0.05)
            for rid, r in list(self.broker._by_id.items()):
                if r.mode != "sudo" or r.status != "pending" or rid in self.handled:
                    continue
                self.handled.add(rid)
                self.seen.append({"id": rid, "argv": list(r.spec["argv"]), "cwd": r.spec.get("cwd"),
                                  "invoker": r.spec.get("invoker"), "source": r.source})
                if self.policy == "ignore":
                    continue
                form = {"id": rid, "decision": self.policy, "csrf": self.broker.csrf_token("alice")}
                try:
                    opener.open(urllib.request.Request(
                        self.abase + "/decide", data=urllib.parse.urlencode(form).encode(),
                        headers={"X-authentik-username": "alice"}, method="POST"), timeout=10)
                except urllib.error.HTTPError:
                    pass                    # a redirect after deciding comes back as an HTTPError

    # -- running as the agent -----------------------------------------------------------------------
    def asb(self, words, cwd=AGENT_CWD, env=None, timeout=60):
        e = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": AGENT_HOME, "LANG": "C.UTF-8", **(env or {})}
        return subprocess.run([PYTHON, f"{WORK}/asb", "sudo", "--", *words], cwd=cwd, env=e, capture_output=True,
                              text=True, timeout=timeout, user=AGENT, group=AGENT, extra_groups=[])

    def as_agent(self, *cmd, env=None):
        e = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": AGENT_HOME, **(env or {})}
        return subprocess.run(list(cmd), cwd=AGENT_CWD, env=e, capture_output=True, text=True, timeout=60,
                              user=AGENT, group=AGENT, extra_groups=[])

    def reset(self, policy="approve", **config):
        self.policy = policy
        self.seen.clear()
        self.write_config(**config)

    def wait_seen(self, n=1, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end and len(self.seen) < n:
            time.sleep(0.05)
        return self.seen

    def audit_events(self, rid):
        with open(self.audit_path) as f:
            return [json.loads(line)["event"] for line in f if f'"{rid}"' in line]

    def dump_audit(self):
        """On a failure, show what the broker recorded for the requests this scenario made."""
        ids = {s["id"] for s in self.seen}
        with open(self.audit_path) as f:
            for line in f:
                rec = json.loads(line)
                if rec.get("id") in ids:
                    keep = {k: rec[k] for k in ("event", "status", "error", "via", "approver", "reason") if k in rec}
                    print(f"      audit: {keep}")

    # -- checks ---------------------------------------------------------------------------------------
    def check(self, cond, what, detail=""):
        if not cond:
            raise Failure(f"{what}{(': ' + str(detail)) if detail else ''}")

    def case(self, fn):
        name = fn.__name__
        try:
            fn()
        except Failure as e:
            self.failures.append((name, str(e)))
            print(f"FAIL  {name}: {e}")
            self.dump_audit()
        except Exception as e:   # noqa: BLE001 -- a broken scenario is a failure, not a crash of the run
            self.failures.append((name, f"{type(e).__name__}: {e}"))
            print(f"ERROR {name}: {type(e).__name__}: {e}")
        else:
            self.passed += 1
            print(f"ok    {name}")
        finally:
            os.chmod(HELPER_DEST, 0o755)

    # -- scenarios -------------------------------------------------------------------------------------
    def run(self):
        self.setup()
        ID, BASH, ENV = real("/usr/bin/id"), real("/usr/bin/bash"), real("/usr/bin/env")
        e = self

        def approved_runs_as_root():
            e.reset(allow=[ID])
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 0 and p.stdout.strip() == "0", "approved command should run as uid 0", (p.returncode, p.stdout, p.stderr))
            seen = e.wait_seen()
            e.check(len(seen) == 1, "exactly one request reached the broker", seen)
            s = seen[0]
            e.check(s["argv"] == [ID, "-u"], "the broker was shown the resolved path and args", s["argv"])
            e.check(s["cwd"] == AGENT_CWD and s["invoker"] == AGENT, "cwd and invoker recorded", s)
            e.check(s["source"].startswith(f"{AGENT}@"), "source names the local user", s["source"])
            time.sleep(0.2)
            ev = e.audit_events(s["id"])
            e.check({"requested", "assessed", "approved", "delivered"} <= set(ev), "audit trail of the request", ev)

        def denied_runs_nothing():
            e.reset(policy="deny", allow=[ID])
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 4 and p.stdout.strip() == "", "a denied command exits 4 and prints nothing", (p.returncode, p.stdout, p.stderr))

        def not_on_the_allow_list_never_reaches_the_phone():
            e.reset(allow=[])
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 10, "not allowed -> exit 10", (p.returncode, p.stderr))
            e.check("allow-list" in p.stderr, "says why", p.stderr)
            time.sleep(0.3)
            e.check(e.seen == [], "no request was created", e.seen)

        def no_policy_keys_means_nothing_runs():
            e.reset()
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 10 and e.seen == [], "default policy refuses everything", (p.returncode, p.stderr, e.seen))

        def allow_all_runs_any_program_but_keeps_the_other_checks():
            e.reset(mode="allow_all")
            p = e.asb(["/usr/bin/whoami"])
            e.check(p.returncode == 0 and p.stdout.strip() == "root", "allow_all runs an unlisted program", (p.returncode, p.stdout, p.stderr))
            e.reset(mode="allow_all")
            p = e.asb([ENV, "id"])
            e.check(p.returncode == 10 and "wrapper" in p.stderr, "wrappers are still refused under allow_all", (p.returncode, p.stderr))

        def the_commands_environment_is_scrubbed():
            PRINTENV = real("/usr/bin/printenv")
            e.reset(allow=[PRINTENV])
            p = e.asb([PRINTENV], env={"AGENT_SECRET": "leak-me", "LD_PRELOAD": "/tmp/evil.so", "BASH_ENV": "/tmp/evil",
                                  "PYTHONPATH": "/tmp/evil", "TERM": "xterm"})
            e.check(p.returncode == 0, "printenv ran", (p.returncode, p.stderr))
            got = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
            for bad in ("AGENT_SECRET", "LD_PRELOAD", "BASH_ENV", "PYTHONPATH"):
                e.check(bad not in got, f"{bad} must not reach the root command", got)
            e.check(got.get("HOME") == "/root" and got.get("USER") == "root", "root's own HOME and USER", got)
            e.check(got.get("PATH", "").startswith("/usr/local/sbin"), "a fixed PATH", got.get("PATH"))
            e.check(got.get("SUDO_USER") == AGENT, "SUDO_USER passed for information", got)
            extra = set(got) - {"PATH", "HOME", "USER", "LOGNAME", "LANG", "TERM", "SUDO_USER"}
            e.check(not extra, "only the documented variables", extra)

        def the_working_directory_is_inherited():
            e.reset(allow=[real("/usr/bin/pwd") if os.path.exists("/usr/bin/pwd") else real("/bin/pwd")])
            pwd = real("/usr/bin/pwd") if os.path.exists("/usr/bin/pwd") else real("/bin/pwd")
            p = e.asb([pwd])
            e.check(p.returncode == 0 and p.stdout.strip() == AGENT_CWD, "runs in the agent's directory", (p.returncode, p.stdout, p.stderr))
            e.check(e.wait_seen()[0]["cwd"] == AGENT_CWD, "and the card said so")

        def a_link_in_the_agents_directory_shows_as_the_real_file():
            e.reset(allow=[ID])
            os.symlink(ID, f"{AGENT_CWD}/innocent-ls") if not os.path.lexists(f"{AGENT_CWD}/innocent-ls") else None
            p = e.asb(["./innocent-ls", "-u"])
            e.check(p.returncode == 0 and p.stdout.strip() == "0", "runs", (p.returncode, p.stdout, p.stderr))
            e.check(e.wait_seen()[0]["argv"][0] == ID, "the broker saw the real path, not the link", e.seen)

        def a_script_the_agent_wrote_is_refused_and_one_root_owns_is_not():
            with open(f"{AGENT_CWD}/evil.sh", "w") as f:
                f.write("#!/bin/sh\necho pwned-$(id -u)\n")
            os.chmod(f"{AGENT_CWD}/evil.sh", 0o755)
            shutil.chown(f"{AGENT_CWD}/evil.sh", AGENT, AGENT)
            e.reset(allow=[BASH])
            p = e.asb([BASH, "evil.sh"])
            e.check(p.returncode == 10 and "pwned" not in p.stdout, "the agent's script is refused", (p.returncode, p.stdout, p.stderr))
            time.sleep(0.3)
            e.check(e.seen == [], "and never reached the phone", e.seen)
            p = e.asb([BASH, f"{WORK}/ok.sh"])
            e.check(p.returncode == 0 and p.stdout.strip() == "script-ran-as-0", "a root-owned script runs as root", (p.returncode, p.stdout, p.stderr))

        def inline_code_is_allowed_but_stdin_and_options_are_not():
            e.reset(allow=[BASH])
            p = e.asb([BASH, "-c", "id -u"])
            e.check(p.returncode == 0 and p.stdout.strip() == "0", "bash -c runs", (p.returncode, p.stdout, p.stderr))
            for words in ([BASH], [BASH, "-s"], [BASH, "-lc", "id -u"], [BASH, "--rcfile", f"{WORK}/ok.sh", f"{WORK}/ok.sh"]):
                e.seen.clear()
                p = e.asb(words)
                e.check(p.returncode == 10, f"{words[1:]} is refused", (p.returncode, p.stdout, p.stderr))
                time.sleep(0.2)
                e.check(e.seen == [], f"{words[1:]} never reached the phone", e.seen)

        def the_agent_cannot_read_the_helpers_key_or_config():
            e.reset(allow=[ID])
            p = e.as_agent("cat", CONFIG)
            e.check(p.returncode != 0 and e.helper_key not in p.stdout, "agent cannot read the config", (p.returncode, p.stdout))

        def the_agent_cannot_sudo_anything_else():
            p = e.as_agent("sudo", "-n", "/usr/bin/id")
            e.check(p.returncode != 0 and "uid=0" not in p.stdout, "no passwordless sudo beyond the helper", (p.returncode, p.stdout, p.stderr))

        def running_the_helper_directly_gives_no_way_around_the_approval():
            e.reset(policy="deny", allow=[ID])
            p = e.as_agent("sudo", "-n", HELPER_DEST, "--", ID, "-u")
            e.check(p.returncode == 4 and p.stdout.strip() == "", "calling the helper directly still asks, and a denial runs nothing", (p.returncode, p.stdout, p.stderr))
            p = e.as_agent(HELPER_DEST, "--", ID, "-u")
            e.check(p.returncode == 2 and "must run as root" in p.stderr, "not as root: refused", (p.returncode, p.stderr))

        def the_agents_own_broker_key_cannot_ask_for_root():
            code = ("import json,os,urllib.request,urllib.error\n"
                    "r=urllib.request.Request(os.environ['U']+'/v1/requests',data=json.dumps({'mode':'sudo','argv':['/usr/bin/id']}).encode(),"
                    "headers={'X-Client-Key':os.environ['K'],'Content-Type':'application/json'})\n"
                    "try:\n  urllib.request.urlopen(r); print('ALLOWED')\nexcept urllib.error.HTTPError as e: print(e.code, e.read().decode())\n")
            p = e.as_agent(PYTHON, "-c", code, env={"U": e.base, "K": e.agent_key})
            e.check(p.stdout.startswith("403") and "ALLOWED" not in p.stdout, "the agent's key is refused for sudo", (p.stdout, p.stderr))

        def the_helper_refuses_to_run_if_it_or_its_config_could_be_changed():
            e.reset(allow=[ID])
            os.chmod(HELPER_DEST, 0o777)
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 10 and "writable" in p.stderr and e.seen == [], "a writable helper binary", (p.returncode, p.stderr, e.seen))
            os.chmod(HELPER_DEST, 0o755)
            e.write_config(allow=[ID], mod=0o644)
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 10 and "chmod 600" in p.stderr and e.seen == [], "a group/other-readable config", (p.returncode, p.stderr, e.seen))

        def an_unreachable_broker_runs_nothing():
            e.reset(allow=[ID], url="http://127.0.0.1:1")
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 3 and p.stdout.strip() == "", "no broker, no root", (p.returncode, p.stdout, p.stderr))

        def an_allow_entry_that_is_a_link_stops_the_helper():
            link = f"{WORK}/id-link"
            if not os.path.lexists(link):
                os.symlink(ID, link)
            e.reset(allow=[link])
            p = e.asb([ID, "-u"])
            e.check(p.returncode == 10 and "not a real path" in p.stderr and e.seen == [], "a symlinked allow entry is refused", (p.returncode, p.stderr))

        for fn in (approved_runs_as_root, denied_runs_nothing, not_on_the_allow_list_never_reaches_the_phone,
                   no_policy_keys_means_nothing_runs, allow_all_runs_any_program_but_keeps_the_other_checks,
                   the_commands_environment_is_scrubbed, the_working_directory_is_inherited,
                   a_link_in_the_agents_directory_shows_as_the_real_file,
                   a_script_the_agent_wrote_is_refused_and_one_root_owns_is_not,
                   inline_code_is_allowed_but_stdin_and_options_are_not,
                   the_agent_cannot_read_the_helpers_key_or_config, the_agent_cannot_sudo_anything_else,
                   running_the_helper_directly_gives_no_way_around_the_approval,
                   the_agents_own_broker_key_cannot_ask_for_root,
                   the_helper_refuses_to_run_if_it_or_its_config_could_be_changed,
                   an_unreachable_broker_runs_nothing, an_allow_entry_that_is_a_link_stops_the_helper):
            self.case(fn)

        total = self.passed + len(self.failures)
        print(f"\n{self.passed}/{total} scenarios passed")
        for name, why in self.failures:
            print(f"  FAILED {name}: {why}")
        for s in self.servers:
            s.shutdown()
        sys.exit(1 if self.failures else 0)


if __name__ == "__main__":
    main()
