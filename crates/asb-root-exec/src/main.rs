use asb_client::clean;
use asb_proto::exit;
use asb_root_exec::{exec, prepare, trust, Context, Policy};
use std::io::Write;

fn die(code: i32, msg: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "asb-root-exec: {}", clean(msg, 300));
    std::process::exit(code)
}

fn main() {
    // While we hold the broker key: no core dumps, no ptrace. The command gets a plain umask.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    unsafe {
        libc::umask(0o022);
    }
    if unsafe { libc::geteuid() } != 0 {
        die(exit::USAGE, "must run as root (through sudo)");
    }
    let policy = Policy::production();

    // This binary itself must be something the agent cannot have replaced.
    match std::env::current_exe().and_then(std::fs::canonicalize) {
        Ok(exe) => {
            if let Err(m) = trust::check_chain(
                &exe,
                policy.trusted_uid,
                trust::Kind::Program,
                &policy.trust_root,
            ) {
                die(exit::REFUSED_LOCALLY, &m)
            }
        }
        Err(e) => die(exit::REFUSED_LOCALLY, &format!("cannot locate myself: {e}")),
    }

    let mut args = Vec::new();
    for a in std::env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => args.push(s),
            Err(_) => die(exit::USAGE, "arguments must be valid UTF-8"),
        }
    }
    let cwd = std::env::current_dir()
        .unwrap_or_else(|e| die(exit::REFUSED_LOCALLY, &format!("no working directory: {e}")));
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let ctx = Context::from_env(|k| std::env::var(k).ok(), cwd, hostname.trim());

    let plan = match prepare(&policy, &args, &ctx, |m| {
        let _ = writeln!(std::io::stderr(), "asb-root-exec: {m}");
    }) {
        Ok(p) => p,
        Err(f) => die(f.code, &f.message),
    };
    let err = exec(&plan);
    die(
        exit::EXEC_FAILED,
        &format!("could not start the approved command: {err}"),
    )
}
