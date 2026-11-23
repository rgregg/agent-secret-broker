#!/usr/bin/env python3
"""Mutation spot-check for the root-exec security logic: do the tests fail when the code is wrong?

    python tools/mutation_check.py                 # every mutation (about 5 minutes; needs cargo)
    python tools/mutation_check.py P2,R3           # only these ids

For each entry below it breaks ONE security-critical line in a throwaway git worktree of HEAD, runs the tests that
should notice, and restores the line. KILLED is what you want (a test failed). SURVIVED means no test pins that
behaviour: add one. BAD-ANCHOR means the line was refactored and the entry needs updating (it is reported loudly so
a stale entry cannot pass for a clean result). Exits non-zero if anything survived or an anchor is stale.

Commit first: it mutates a copy of HEAD, not your working tree. Entries marked "e2e" can only be caught by the
container end-to-end test (tests/e2e_root_exec/run.sh); they run it when docker is available and are reported as
SKIPPED, not failed, when it is not.
"""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = [sys.executable, "-m", "unittest", "test_sudo_mode", "test_asb_sudo", "test_user_agent"]
PYX = [sys.executable, "-m", "unittest", "test_execprobe", "test_exec_unpinned", "test_exec_intake", "test_execrun",
       "test_exec_rules", "test_execmode"]
RS = ["cargo", "test", "--workspace", "--locked"]

# (id, file, exact text, replacement, runner, what it protects)
MUTATIONS = [
 ("P1","secret_broker/sudomode.py",'if (client or {}).get("legacy") or cid not in cfg["clients"]:','if False:',"py","only listed clients may ask"),
 ("P2","secret_broker/sudomode.py",'if not cfg["enabled"]:','if False:',"py","off by default"),
 ("P3","secret_broker/broker.py",'if req.mode in ("guidance", "credential", "plan", "session", "sudo"):\n            # no buttons','if req.mode in ("guidance", "credential", "plan", "session"):\n            # no buttons',"py","no notification buttons"),
 ("P4","secret_broker/broker.py",'if req is not None and req.mode == "sudo" and (','if req is not None and req.mode == "nope" and (',"py","grants/always refused"),
 ("P5","secret_broker/risk.py",'''    if mode == "sudo":
        # a root command: high by code, no model sees it (the command is untrusted text and the human reads it)
        return {"level": "high"''','''    if mode == "sudo":
        # a root command: high by code, no model sees it (the command is untrusted text and the human reads it)
        return {"level": "low"''',"py","always HIGH"),
 ("P6","secret_broker/broker.py",'return {"approved": True}','return {"approved": False}',"py","approval result"),
 ("P7","secret_broker/broker.py",'rec.update(sudo_mod.audit_fields(req.spec))','pass',"py","audit keeps the command"),
 ("P8","secret_broker/sudomode.py",'        bad = guidance_mod.hidden_problem(a)\n        if bad:','        bad = None\n        if bad:',"py","hidden chars refused"),
 ("P9","secret_broker/sudomode.py",'if user not in TARGET_USERS:','if False:',"py","root only"),
 ("P10","secret_broker/history.py",'x.replace("\\n", "<U+000A>").replace("\\t", "<U+0009>") if isinstance(x, str) else x','x if isinstance(x, str) else x',"py","history shows newlines"),
 ("P11","secret_broker/sudomode.py",'''html.escape(ch) if ord(ch) < 128 and ch not in "\\n\\t" else''','''html.escape(ch) if ord(ch) < 128 else''',"py","card shows newlines"),
 ("P12","secret_broker/broker.py",'or match.mode in ("guidance", "credential", "plan", "session", "sudo")):','or match.mode in ("guidance", "credential", "plan", "session")):',"py","token cannot decide"),
 ("P13","secret_broker/broker.py",'for r in self._by_id.values()) >= self.sudo_cfg["max_pending_per_client"]:','for r in self._by_id.values()) > self.sudo_cfg["max_pending_per_client"]:',"py","pending cap"),
 ("P15","secret_broker/destguard.py",'opener.addheaders = [("User-Agent", USER_AGENT)]','pass',"py","User-Agent default"),
 ("P16","client/asb",'return subprocess.run(["sudo", "-n", helper, "--"] + cmd).returncode','return subprocess.run(["sudo", helper, "--"] + cmd).returncode',"py","asb sudo uses sudo -n"),
 ("R1","crates/asb-root-exec/src/trust.rs",'& 0o022 != 0','& 0o002 != 0',"rs","group-writable refused"),
 ("R2","crates/asb-root-exec/src/lib.rs",'if list.iter().any(|p| p == real) {','if true {',"rs","allow-list enforced"),
 ("R3","crates/asb-root-exec/src/lib.rs",'if again != resolved {','if false {',"rs","re-check the program after approval"),
 ("R4","crates/asb-root-exec/src/lib.rs",'!= args {','== args && false {',"rs","re-check the script after approval"),
 ("R5","crates/asb-root-exec/src/lib.rs",'''    let shown = resolved
        .real
        .to_str()''','''    let shown = resolved
        .shown
        .to_str()''',"rs","show the real path"),
 ("R6","crates/asb-root-exec/src/lib.rs",'.env_clear()','',"rs","environment cleared"),
 ("R7","crates/asb-client/src/lib.rs",'Status::Approved if polled.approved => return Ok(()),','Status::Approved => return Ok(()),',"rs","approval needs the flag"),
 ("R8","crates/asb-client/src/lib.rs",'if !id_ok {','if false {',"rs","request id validated"),
 ("R9","crates/asb-root-exec/src/scriptcheck.rs",'if first.starts_with(\'-\') {','if false {',"rs","no options before the script"),
 ("R10","crates/asb-root-exec/src/scriptcheck.rs",'if bases.iter().any(|b| WRAPPERS.contains(&b.as_str())) {','if false {',"rs","wrappers refused"),
 ("R11","crates/asb-root-exec/src/lib.rs",'if &real != p {','if false {',"rs","allow entries must be real paths"),
 ("R12","crates/asb-root-exec/src/resolve.rs",'check_chain(&real, trusted_uid, Kind::Program, trust_root)?;','',"rs","program trust check"),
 ("R13","crates/asb-root-exec/src/lib.rs",'trust::check_chain(&path, policy.trusted_uid, Kind::Secret, &policy.trust_root)','Ok::<(), String>(())',"rs","config file trust check"),
 ("R14","crates/asb-root-exec/src/trust.rs",'Kind::Secret if bits & 0o077 != 0 =>','Kind::Secret if bits & 0o007 != 0 =>',"rs","config must be 0600"),
 ("R15","crates/asb-root-exec/src/main.rs",'if unsafe { libc::geteuid() } != 0 {','if false {',"e2e","helper must run as root"),
 ("R16","crates/asb-root-exec/src/scriptcheck.rs",'if code.starts_with(\'-\') || code.starts_with(\'+\') {','if false {',"rs","inline code must be next word"),
 ("R17","crates/asb-root-exec/src/scriptcheck.rs",'!POSITIONAL_AFTER_CODE.contains(&interpreter.as_str())','false',"rs","switches after inline code"),
 ("R18","crates/asb-root-exec/src/scriptcheck.rs",'file_args(args, 1, cwd, trusted_uid, trust_root, &mut out)?;','',"rs","file arguments trusted"),

 # remote exec for unpinned and changed hosts (runner "pyx": tests/test_execprobe.py, test_exec_unpinned.py, ...)
 ("X1","secret_broker/execprobe.py",'sock = guard.connect(a, port, timeout=CONNECT_TIMEOUT_S, deadline=hard)','sock = socket.create_connection((a, port), CONNECT_TIMEOUT_S)',"pyx","the probe goes through the destination guard"),
 ("X2","secret_broker/execprobe.py",'if ip is None or guard.address_refused(ip, port):','if ip is None:',"pyx","the connected peer is checked again"),
 ("X3","secret_broker/execprobe.py",'if hit is not None and allowed:','if hit is not None:',"pyx","a pinned line for a name that is not allowed is not pinned"),
 ("X4","secret_broker/execprobe.py",'if name.startswith(host + ":"):','if name.startswith(host):',"pyx","same key elsewhere means the same host name"),
 ("X5","secret_broker/execprobe.py",'if hit is None:\n            return {"state": "changed"','if False:\n            return {"state": "changed"',"pyx","a different key for a pinned name and port is changed"),
 ("X6","secret_broker/execprobe.py",'if not allowed_hosts:\n        return True','if not allowed_hosts:\n        return False',"pyx","no allowed list: a pinned line is enough"),
 ("X7","secret_broker/broker.py",'pinned_fp=cls["pinned_fp"], same_as=cls["matches"])\n        self._exec_unpinned_pending(req)','pinned_fp=cls["pinned_fp"], same_as=cls["matches"])\n        self._assess_and_route(req)',"pyx","an unpinned host reaches only a human"),
 ("X8","secret_broker/broker.py",'if exec_host == "remember" and (st == "changed" or self._exec_remember_why(req) is not None):','if exec_host == "remember" and self._exec_remember_why(req) is not None:',"pyx","no plain remember for a changed key"),
 ("X9","secret_broker/broker.py",'or confirm_replace is not True','or False',"pyx","replace needs its confirmation tick"),
 ("X10","secret_broker/broker.py",'or (match.mode == "exec" and match.spec.get("host_state"))):','):',"pyx","no token channel decides an unpinned host"),
 ("X11","secret_broker/broker.py",'elif req is not None and exec_host is not None:','elif False:',"pyx","a host choice on another request claims nothing"),
 ("X12","secret_broker/broker.py",'            pinned = [execprobe_mod.pin_line(sp["host"], sp["port"], sp["presented_key"])]','            pinned = pinned + [execprobe_mod.pin_line(sp["host"], sp["port"], sp["presented_key"])]',"pyx","the connection pins exactly the key on the card"),
 ("X13","secret_broker/broker.py",'if req.exec_choice is None or not exec_mod.host_fields_ok(sp):','if False:',"pyx","the run needs a person's decision"),
 ("X14","secret_broker/broker.py",'addrs = self.dest_guard.resolve(sp["host"], sp["port"])','addrs = ["93.184.216.34"]',"pyx","the destination is checked again at connect time"),
 ("X16","secret_broker/broker.py",'elif allowed and host not in allowed:       # only a list that already exists grows','elif host not in allowed:       # only a list that already exists grows',"pyx","remember never creates an allowed list"),
 ("X17","secret_broker/broker.py",'                if expect_fp not in old_fps:\n                    raise ValueError("the pinned key changed since the card was shown")','                pass',"pyx","replace only replaces the line the human saw"),
 ("X18","secret_broker/execprobe.py",'if flight[1] == 0 and self._flights.get(key) is flight:','if False:',"pyx","probe flight entries are always cleaned up"),
 ("X19","secret_broker/execprobe.py",'if self._inflight.get(client_id, 0) >= MAX_INFLIGHT_PER_CLIENT:','if False:',"pyx","one client cannot hold every probe slot"),
 ("X20","secret_broker/execmode.py",'and _key_fingerprint(sp["presented_key"]) == sp["presented_fp"]','and True',"pyx","the fingerprint shown is the fingerprint of the key pinned"),
 ("X21","secret_broker/execrun.py",'f"HostKeyAlias={_known_name(spec)}"','f"HostKeyAlias={spec[\'host\']}"',"pyx","the alias names the host and port in full"),

 # the background host check, the failed-check card, probe_allow_cidrs and replace
 ("X22","secret_broker/broker.py",'elif req is not None and req.mode == "exec" and approve and req.spec.get("probe") != "ready":','elif False:',"pyx","nothing is approved before the host check is done"),
 ("X23","secret_broker/execmode.py",'if sp.get("probe") != "ready" or st not in HOST_STATES:','if False:',"pyx","a failed or unfinished check offers no approve, remember or replace"),
 ("X24","secret_broker/broker.py",'            sp.update(probe="failed", host_state="probe_failed", probe_label=label)\n','            sp.update(probe="failed", host_state="probe_failed", probe_label=label)\n            req.status = "denied"\n',"pyx","a failed check on an unpinned host looks like any pending request to the agent"),
 ("X25","secret_broker/broker.py",'threading.Thread(target=self._exec_probe_job, args=(req,), daemon=True).start()','self._exec_probe_job(req)',"pyx","the probe never runs on the request thread"),
 ("X26","secret_broker/execprobe.py",'if nets and not all(_in_nets(a, nets) for a in addrs):','if False:',"pyx","probe_allow_cidrs refuses a destination outside the list"),
 ("X27","secret_broker/broker.py",'            if replace:                                 # a changed host is allowed by definition: never add, and refuse','            if False:                                 # a changed host is allowed by definition: never add, and refuse',"pyx","replace never appends to allowed_hosts"),
 ("X28","secret_broker/broker.py",'                if allowed and host not in allowed:     # if the list was edited between the card and the click','                if False:     # if the list was edited between the card and the click',"pyx","replace refuses a host the list no longer allows (write)"),
 ("X29","secret_broker/broker.py",'                                       or not execprobe_mod.host_allowed(','                                       or False and execprobe_mod.host_allowed(',"pyx","replace refuses a host the list no longer allows (decision)"),
 ("X30","secret_broker/broker.py",'        if sp.get("pinned_at_intake"):\n            with self._lock:','        if False:\n            with self._lock:',"pyx","a pinned host whose check fails ends with connect_failed"),
]

def main():
    only = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else None
    todo = [m for m in MUTATIONS if only is None or m[0] in only]
    tmp = tempfile.mkdtemp(prefix="asb-mutation-")
    wt = os.path.join(tmp, "wt")
    subprocess.run(["git", "worktree", "add", "-q", "--detach", wt, "HEAD"], cwd=REPO, check=True)
    env = {**os.environ, "CARGO_TARGET_DIR": os.path.join(tmp, "target")}
    bad, skipped = [], []
    try:
        for mid, rel, old, new, runner, what in todo:
            path = os.path.join(wt, rel)
            src = open(path).read()
            if src.count(old) != 1:
                print(f"{mid:4} BAD-ANCHOR   {what} ({rel}: {src.count(old)} matches)", flush=True)
                bad.append(mid)
                continue
            open(path, "w").write(src.replace(old, new))
            if runner == "e2e" and not shutil.which("docker"):
                open(path, "w").write(src)
                skipped.append(mid)
                print(f"{mid:4} SKIPPED      {what} (needs docker for the end-to-end test)", flush=True)
                continue
            try:
                if runner == "e2e":
                    r = subprocess.run([os.path.join(wt, "tests", "e2e_root_exec", "run.sh")], cwd=wt,
                                       capture_output=True, text=True, timeout=900)
                elif runner in ("py", "pyx"):
                    r = subprocess.run(PY if runner == "py" else PYX, cwd=os.path.join(wt, "tests"), capture_output=True, text=True, timeout=300)
                else:
                    r = subprocess.run(RS, cwd=wt, capture_output=True, text=True, timeout=500, env=env)
            finally:
                open(path, "w").write(src)
            result = "KILLED" if r.returncode != 0 else "SURVIVED"
            if runner == "rs" and r.returncode != 0 and "error[" in r.stderr and "test result" not in r.stdout:
                result = "COMPILE-ERROR"      # the mutation did not build: it proves nothing, fix the entry
            if result != "KILLED":
                bad.append(mid)
            print(f"{mid:4} {result:12} {what}", flush=True)
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", wt], cwd=REPO)
        shutil.rmtree(tmp, ignore_errors=True)
    killed = len(todo) - len(bad) - len(skipped)
    print(f"\n{killed} of {len(todo)} mutations killed"
          + (f"; skipped (no docker): {', '.join(skipped)}" if skipped else "")
          + (f"; need attention: {', '.join(bad)}" if bad else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
