//! Interpreters run files the approval card does not show. `bash /home/ryan/deploy.sh` approved as root
//! would run whatever that file holds when it runs, and the agent can rewrite a file it owns after you
//! approve. Parsing every interpreter's command line to find the file is a game that cannot be won (each has
//! options that load modules, read stdin or take their code from elsewhere), so this does not try. For a
//! command that is an interpreter it allows exactly two forms and refuses everything else:
//!
//! * `INTERP SCRIPT [ARGS...]`: SCRIPT is the first argument, not an option, and an existing file that is
//!   trusted (see `trust`). It is shown to you, and run, as its resolved real path. Any later argument that
//!   names an existing file must be trusted too (a runner such as `pdb` executes its argument as code).
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
    "pypy",
    "perl",
    "ruby",
    "jruby",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ts-node",
    "php",
    "php-cgi",
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
];
/// Programs that start another command, which this check cannot see: refused.
const WRAPPERS: &[&str] = &[
    "env",
    "nice",
    "nohup",
    "timeout",
    "time",
    "stdbuf",
    "ionice",
    "setsid",
    "xargs",
    "chroot",
    "flock",
    "strace",
    "watch",
    "unshare",
    "nsenter",
    "runuser",
    "su",
    "doas",
    "sudo",
    "busybox",
    "parallel",
    "script",
    "xvfb-run",
    "taskset",
    "chrt",
    "setpriv",
    "capsh",
    "sg",
    "systemd-run",
    "ltrace",
    "valgrind",
    "gdb",
    "faketime",
    "fakeroot",
    "firejail",
    "bwrap",
    "proot",
    "ssh",
    "rlwrap",
    "sshpass",
    "torsocks",
    "proxychains",
    "eatmydata",
    "numactl",
    "cpulimit",
    "prlimit",
    "setarch",
    "linux32",
    "linux64",
    "unbuffer",
    "pkexec",
    "newgrp",
    "start-stop-daemon",
];
/// Interpreters that take every word after `-c CODE` as a plain argument, never as an option.
const POSITIONAL_AFTER_CODE: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "python"];
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

/// If `arg` names an existing file (following symlinks), check that the agent cannot change it and return its
/// resolved real path; `None` when it is not a file.
fn trusted_file(
    arg: &str,
    cwd: &Path,
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<Option<String>, String> {
    let path = if Path::new(arg).is_absolute() {
        Path::new(arg).to_path_buf()
    } else {
        cwd.join(arg)
    };
    if !fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
        return Ok(None);
    }
    let real = fs::canonicalize(&path).map_err(|e| format!("{arg}: {e}"))?;
    check_chain(&real, trusted_uid, Kind::Script, trust_root)
        .map_err(|m| format!("{m}; the agent could change this file after you approve it, so it will not run as root"))?;
    real.to_str()
        .map(|s| Some(s.to_string()))
        .ok_or_else(|| "a file path is not valid UTF-8".to_string())
}

/// Every later argument that names an existing file must be trusted too, and is shown and run as its resolved
/// path. A trusted runner (`pdb`, `cProfile`, `trace`) executes its argument as code, and inline code may
/// `source` or `import` what it is handed, so a file argument is not just data.
fn file_args(
    args: &[String],
    from: usize,
    cwd: &Path,
    uid: u32,
    root: &Path,
    out: &mut Vec<(usize, String)>,
) -> Result<(), String> {
    for (i, a) in args.iter().enumerate().skip(from) {
        if a.starts_with('-') {
            continue;
        }
        if let Some(real) = trusted_file(a, cwd, uid, root)? {
            out.push((i, real));
        }
    }
    Ok(())
}

/// What to change in the arguments, or why the command is refused. `names` are the program's names (as found
/// and as resolved): either may identify it. Returns `(index into args, resolved real path)` for each file the
/// interpreter will read or be handed; the caller substitutes them so what is shown is what runs.
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
    let mut out = Vec::new();
    if inline_flags(interpreter).contains(&first.as_str()) {
        // the code is the next argument, which you are shown
        let Some(code) = args.get(1) else {
            return Err("the inline-code flag has no code after it".into());
        };
        // Shells keep parsing options after `-c` (`bash -c -x 'echo hi'` runs the word after `-x`), so a word
        // that starts like an option is not clearly the code; `-` alone is read from stdin by some interpreters.
        if code.starts_with('-') || code.starts_with('+') {
            return Err(
                "the word after the inline-code flag starts like an option, so it is not clearly the code"
                    .into(),
            );
        }
        // After the code, shells and Python treat every remaining word as a plain argument. Perl, Ruby, Node,
        // PHP, Lua and the rest keep parsing switches (`perl -e CODE -MEvil`, `node -e CODE --require x`), so
        // any later switch is refused for them.
        if !POSITIONAL_AFTER_CODE.contains(&interpreter.as_str())
            && args[2..].iter().any(|a| a.starts_with('-'))
        {
            return Err(
                "an option after the inline code is refused: this interpreter would still parse it"
                    .into(),
            );
        }
        file_args(args, 2, cwd, trusted_uid, trust_root, &mut out)?;
        return Ok(out);
    }
    if first.starts_with('-') {
        return Err(format!(
            "an interpreter option ({}) before the script is refused: allowed forms are `{interpreter} SCRIPT [ARGS]` and `{interpreter} {} CODE`",
            first.chars().take(24).collect::<String>(),
            inline_flags(interpreter).first().copied().unwrap_or("(no inline form)"),
        ));
    }
    match trusted_file(first, cwd, trusted_uid, trust_root)? {
        Some(real) => out.push((0, real)),
        None => return Err("the interpreter's first argument is not an existing file (it could be created after you approve)".into()),
    }
    file_args(args, 1, cwd, trusted_uid, trust_root, &mut out)?;
    Ok(out)
}
