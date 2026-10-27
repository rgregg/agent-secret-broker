//! Interpreters run files the approval card does not show. `bash /home/ryan/deploy.sh` approved as root
//! would run whatever that file holds when it runs, and the agent can rewrite a file it owns after you
//! approve. Parsing every interpreter's command line to find the file is a game that cannot be won (each has
//! options that load modules, read stdin or take their code from elsewhere), so this does not try. For a
//! command that is an interpreter it allows exactly two forms and refuses everything else:
//!
//! * `INTERP SCRIPT [ARGS...]`: SCRIPT is the first argument, not an option, and an existing file that is
//!   trusted (see `trust`). It is shown to you, and run, as its resolved real path. ARGS are the script's own
//!   arguments: the trusted script decides what to do with them.
//! * `INTERP -c CODE [ARGS...]`: the interpreter's one exact inline-code flag first, so the code is in the
//!   command you read.
//!
//! That leaves no way to add `-m`, `-r`, `--rcfile`, `-s`, `-i`, `-`, a version flag followed by a file, or
//! any other option ahead of the script. A lone `--version`/`--help` is allowed. A wrapper (`env`, `nice`,
//! `timeout`, `xargs`, ...) starts a command this check cannot see, so wrappers are refused.
//!
//! Only programs this list knows are interpreters are checked. Anything else that can run other commands or
//! read files (`find -exec`, `git`, `make`, editors, pagers, `awk -f`) is as powerful as its text, and the
//! card is the control for those. See docs/root-exec.md.

use crate::trust::{check_chain, Kind};
use std::fs;
use std::path::Path;

/// Programs that run a script file named on their command line (names have trailing version digits and dots
/// removed first: `python3.11` is `python`, `perl5.36` is `perl`).
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
    "python",
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
    "guile",
    "racket",
    "ts-node",
];
/// Programs that start another command, which this check cannot see: refused.
const WRAPPERS: &[&str] = &[
    "env", "nice", "nohup", "timeout", "time", "stdbuf", "ionice", "setsid", "xargs", "chroot",
    "flock", "strace", "watch", "unshare", "nsenter", "runuser", "su", "doas", "sudo", "busybox",
    "parallel", "script", "xvfb-run",
];
/// An option that only prints something and exits, allowed only as the sole argument.
const INFO: &[&str] = &["--version", "-version", "--help", "-V"];

fn norm(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_string()
}

/// The one exact flag that makes this interpreter take its program from the next argument.
fn inline_flags(interpreter: &str) -> &'static [&'static str] {
    match interpreter {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "fish" | "csh" | "tcsh" | "python"
        | "guile" => &["-c"],
        "perl" => &["-e", "-E"],
        "ruby" | "lua" | "luajit" | "Rscript" | "julia" | "groovy" | "osascript" | "racket" => {
            &["-e"]
        }
        "node" | "nodejs" | "bun" | "ts-node" => &["-e", "--eval"],
        "php" => &["-r"],
        "pwsh" => &["-c", "-Command"],
        _ => &[],
    }
}

/// What to change in the arguments, or why the command is refused. `names` are the program's names (as found
/// and as resolved): either may identify it. Returns `(index into args, resolved real path)` for the script
/// the interpreter will read; the caller substitutes it so what is shown is what runs.
pub fn check(
    names: &[&Path],
    args: &[String],
    cwd: &Path,
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<Vec<(usize, String)>, String> {
    let bases: Vec<String> = names.iter().map(|p| norm(p)).collect();
    if bases.iter().any(|b| WRAPPERS.contains(&b.as_str())) {
        return Err("a wrapper command (env, nice, timeout, xargs, ...) starts another command that cannot be shown to you; run that command directly".into());
    }
    let Some(interpreter) = bases.iter().find(|b| INTERPRETERS.contains(&b.as_str())) else {
        return Ok(vec![]);
    };
    let Some(first) = args.first() else {
        return Err("an interpreter with no script would read its program from standard input, which cannot be shown to you".into());
    };
    if args.len() == 1 && INFO.contains(&first.as_str()) {
        return Ok(vec![]);
    }
    if inline_flags(interpreter).contains(&first.as_str()) {
        return Ok(vec![]); // the code is the next argument, which you are shown
    }
    if first.starts_with('-') {
        return Err(format!(
            "an interpreter option ({}) before the script is refused: allowed forms are `{interpreter} SCRIPT [ARGS]` and `{interpreter} {} CODE`",
            first.chars().take(24).collect::<String>(),
            inline_flags(interpreter).first().copied().unwrap_or("(no inline form)"),
        ));
    }
    let path = if Path::new(first).is_absolute() {
        Path::new(first).to_path_buf()
    } else {
        cwd.join(first)
    };
    // follows symlinks: a link to a file is a file
    if !fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
        return Err("the interpreter's first argument is not an existing file (it could be created after you approve)".into());
    }
    let real = fs::canonicalize(&path).map_err(|e| format!("{first}: {e}"))?;
    check_chain(&real, trusted_uid, Kind::Script, trust_root)
        .map_err(|m| format!("{m}; the agent could change this file after you approve it, so it will not run as root"))?;
    let real = real
        .to_str()
        .ok_or("the script path is not valid UTF-8")?
        .to_string();
    Ok(vec![(0, real)])
}
