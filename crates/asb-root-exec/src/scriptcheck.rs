//! Interpreters run files the approval card does not show. `bash /home/ryan/deploy.sh` approved as root
//! would run whatever that file holds when it runs, and the agent can rewrite a file it owns after you
//! approve. So when the command is an interpreter (or a wrapper that starts one):
//!
//! * every operand that is an existing file must be trusted (see `trust`), not only the first, or the
//!   command is refused before the broker is asked;
//! * each such operand is replaced by its resolved real path, in what you are shown and in what runs, so a
//!   symlink cannot show one file and run another;
//! * an interpreter with no script file and no inline code would read its program from standard input, or
//!   from a file that does not exist yet, and is refused.
//!
//! This is a heuristic, not a parser of every interpreter's command line. It errs towards refusing; its limits
//! are listed in docs/root-exec.md.

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
/// Programs that start another command: that command (or the interpreter it starts) is what must be checked.
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
/// Options that only print something and exit.
const INFO: &[&str] = &["--version", "-version", "--help", "-V", "-h"];
const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "csh", "tcsh",
];

fn norm(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_string()
}

struct Ctx<'a> {
    cwd: &'a Path,
    trusted_uid: u32,
    trust_root: &'a Path,
}

impl Ctx<'_> {
    /// If `arg` names an existing file, check it and return its resolved path.
    fn file(&self, arg: &str) -> Result<Option<String>, String> {
        let path = if Path::new(arg).is_absolute() {
            Path::new(arg).to_path_buf()
        } else {
            self.cwd.join(arg)
        };
        // follows symlinks: a link to a file is a file
        if !fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
            return Ok(None);
        }
        let real = fs::canonicalize(&path).map_err(|e| format!("{arg}: {e}"))?;
        check_chain(&real, self.trusted_uid, Kind::Script, self.trust_root).map_err(|m| {
            format!("{m}; the agent could change this file after you approve it, so it will not run as root")
        })?;
        real.to_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| format!("{arg}: path is not valid UTF-8"))
    }
}

/// Scan an interpreter's arguments from `start`: every existing-file operand is checked and replaced.
fn interpreter(
    args: &[String],
    start: usize,
    shell: bool,
    cx: &Ctx,
    out: &mut Vec<(usize, String)>,
) -> Result<(), String> {
    let mut found = false;
    for (i, arg) in args.iter().enumerate().skip(start) {
        if arg == "-" {
            return Err(
                "it would read its program from standard input, which cannot be shown to you"
                    .into(),
            );
        }
        if let Some(flags) = arg.strip_prefix('-') {
            if INFO.contains(&arg.as_str()) {
                return Ok(());
            }
            // a shell's short-option cluster with `c` (`-c`, `-lc`, `-ec`) takes its code from the next word
            if INLINE.contains(&arg.as_str())
                || (shell && !flags.starts_with('-') && flags.contains('c'))
            {
                return Ok(()); // the code is in argv, which the human is shown
            }
            continue;
        }
        if let Some(real) = cx.file(arg)? {
            out.push((i, real));
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err("it names no script file and no inline code (it would read standard input, or a file that does not exist yet)".into())
    }
}

/// What to change in the arguments, or why the command is refused. `names` are the program's names (as found
/// and as resolved): either may identify it. Returns `(index into args, resolved real path)` for each file
/// operand the interpreter will read; the caller substitutes them so what is shown is what runs.
pub fn check(
    names: &[&Path],
    args: &[String],
    cwd: &Path,
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<Vec<(usize, String)>, String> {
    let cx = Ctx {
        cwd,
        trusted_uid,
        trust_root,
    };
    let bases: Vec<String> = names.iter().map(|p| norm(p)).collect();
    let is = |list: &[&str]| bases.iter().any(|b| list.contains(&b.as_str()));
    let mut out = Vec::new();
    if is(WRAPPERS) {
        for (i, arg) in args.iter().enumerate() {
            if arg.starts_with('-') {
                continue;
            }
            if INTERPRETERS.contains(&norm(Path::new(arg)).as_str()) {
                let shell = SHELLS.contains(&norm(Path::new(arg)).as_str());
                interpreter(args, i + 1, shell, &cx, &mut out)?;
                return Ok(out);
            }
            if let Some(real) = cx.file(arg)? {
                out.push((i, real)); // the wrapper starts this file directly
            }
        }
    } else if is(INTERPRETERS) {
        interpreter(args, 0, is(SHELLS), &cx, &mut out)?;
    }
    Ok(out)
}
