//! Interpreters run files the approval card does not show. `bash /home/ryan/deploy.sh` approved as root
//! would run whatever that file holds when it runs, and the agent can rewrite a file it owns after you
//! approve. So when the command is an interpreter (or a wrapper that starts one), the first operand that is
//! an existing file must be trusted (see `trust`) or the command is refused before the broker is asked.
//!
//! This is a heuristic, not a parser of every interpreter's command line. It errs towards refusing; its
//! limits are listed in docs/root-exec.md.

use crate::trust::{check_chain, Kind};
use std::fs;
use std::path::Path;

/// Programs that run a script file named on their command line.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "ash",
    "fish",
    "csh",
    "tcsh",
    "perl",
    "ruby",
    "node",
    "nodejs",
    "deno",
    "bun",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "expect",
    "pwsh",
    "Rscript",
    "julia",
    "groovy",
    "osascript",
];
/// Programs that start another command: the file operand may belong to the command they start.
const WRAPPERS: &[&str] = &[
    "env", "nice", "nohup", "timeout", "time", "stdbuf", "ionice", "setsid", "xargs", "chroot",
    "flock", "strace", "watch", "unshare", "nsenter", "runuser", "su", "doas", "sudo", "busybox",
];
/// An option that puts the code on the command line (so it is in the shown argv, with no file to read).
const INLINE: &[&str] = &[
    "-c",
    "-e",
    "-E",
    "-m",
    "-r",
    "-p",
    "--eval",
    "--command",
    "--exec",
];

fn base(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn is_python(name: &str) -> bool {
    name.strip_prefix("python")
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name) || is_python(name)
}

fn is_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "fish" | "csh" | "tcsh"
    )
}

/// `Ok` when there is nothing to check or the file the interpreter will read is trusted.
/// `names` are the program's names (as found, and as resolved): either may identify it.
pub fn check(
    names: &[&Path],
    args: &[String],
    cwd: &Path,
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<(), String> {
    let bases: Vec<String> = names.iter().map(|p| base(p)).collect();
    let wrapper = bases.iter().any(|b| WRAPPERS.contains(&b.as_str()));
    let interp = bases.iter().any(|b| is_interpreter(b));
    if !wrapper && !interp {
        return Ok(());
    }
    let shell = bases.iter().any(|b| is_shell(b));
    for arg in args {
        if arg.starts_with('-') && arg.len() > 1 {
            let cluster_c = shell && !arg.starts_with("--") && arg[1..].contains('c');
            if (interp && !wrapper) && (INLINE.contains(&arg.as_str()) || cluster_c) {
                return Ok(()); // the code is in argv, which the human is shown
            }
            continue;
        }
        let path = if Path::new(arg).is_absolute() {
            Path::new(arg).to_path_buf()
        } else {
            cwd.join(arg)
        };
        // follows symlinks: a link to a file is a file
        if fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
            let real = fs::canonicalize(&path).map_err(|e| format!("{arg}: {e}"))?;
            return check_chain(&real, trusted_uid, Kind::Script, trust_root)
                .map_err(|m| format!("{m}; the agent could change this script after you approve it, so it will not run as root"));
        }
    }
    Ok(())
}
