#!/usr/bin/env python3
"""Mutation spot-check for the root-exec security logic: do the tests fail when the code is wrong?

    python tools/mutation_check.py                 # every mutation (about 5 minutes; needs cargo)
    python tools/mutation_check.py P2,R3           # only these ids

For each entry below it breaks ONE security-critical line in a throwaway git worktree of HEAD, runs the tests that
should notice, and restores the line. KILLED is what you want (a test failed). SURVIVED means no test pins that
behaviour: add one. BAD-ANCHOR means the line was refactored and the entry needs updating (it is reported loudly so
a stale entry cannot pass for a clean result). Exits non-zero if anything survived or an anchor is stale.

Commit first: it mutates a copy of HEAD, not your working tree. R15 (the helper must run as root) and a few others
are caught only by the end-to-end test (tests/e2e_root_exec/run.sh), which this script does not run.
"""
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = [sys.executable, "-m", "unittest", "test_sudo_mode", "test_asb_sudo", "test_user_agent"]
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
 ("R15","crates/asb-root-exec/src/main.rs",'if unsafe { libc::geteuid() } != 0 {','if false {',"rs","helper must run as root"),
 ("R16","crates/asb-root-exec/src/scriptcheck.rs",'if code.starts_with(\'-\') || code.starts_with(\'+\') {','if false {',"rs","inline code must be next word"),
 ("R17","crates/asb-root-exec/src/scriptcheck.rs",'!POSITIONAL_AFTER_CODE.contains(&interpreter.as_str())','false',"rs","switches after inline code"),
 ("R18","crates/asb-root-exec/src/scriptcheck.rs",'file_args(args, 1, cwd, trusted_uid, trust_root, &mut out)?;','',"rs","file arguments trusted"),
]

def main():
    only = set(sys.argv[1].split(",")) if len(sys.argv) > 1 else None
    todo = [m for m in MUTATIONS if only is None or m[0] in only]
    tmp = tempfile.mkdtemp(prefix="asb-mutation-")
    wt = os.path.join(tmp, "wt")
    subprocess.run(["git", "worktree", "add", "-q", "--detach", wt, "HEAD"], cwd=REPO, check=True)
    env = {**os.environ, "CARGO_TARGET_DIR": os.path.join(tmp, "target")}
    bad = []
    try:
        for mid, rel, old, new, runner, what in todo:
            path = os.path.join(wt, rel)
            src = open(path).read()
            if src.count(old) != 1:
                print(f"{mid:4} BAD-ANCHOR   {what} ({rel}: {src.count(old)} matches)", flush=True)
                bad.append(mid)
                continue
            open(path, "w").write(src.replace(old, new))
            try:
                if runner == "py":
                    r = subprocess.run(PY, cwd=os.path.join(wt, "tests"), capture_output=True, text=True, timeout=300)
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
    print(f"\n{len(todo) - len(bad)} of {len(todo)} mutations killed" + (f"; need attention: {', '.join(bad)}" if bad else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
