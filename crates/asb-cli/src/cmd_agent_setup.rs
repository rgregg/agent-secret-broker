//! `asb agent-setup`: install, update or remove the broker's instruction block in a coding agent's instruction file.
//! Local only (no broker). A port of `run_agent_setup` and its helpers in client/asb, including the safety checks:
//! resolved paths, ownership, a backup of anything it changes, and exclusive, symlink-proof temp and backup files.

use crate::difflib::unified_diff;
use crate::exit::{die, NOT_FOUND, R, USAGE};
use crate::pyfmt::repr;
use crate::text_gen::{self, AGENT_BLOCK_BODY, AGENT_BLOCK_VERSION, AGENT_MARK};
use std::collections::VecDeque;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const AGENT_NAMES: [&str; 3] = ["claude", "codex", "copilot"];

fn agent_block(eol: &str) -> String {
    let mut lines = vec![
        format!("<!-- {AGENT_MARK} begin v{AGENT_BLOCK_VERSION} -->"),
        "<!-- managed by `asb agent-setup`; edits between the markers are replaced -->".to_string(),
    ];
    lines.extend(AGENT_BLOCK_BODY.split('\n').map(String::from));
    lines.push(format!("<!-- {AGENT_MARK} end -->"));
    lines.join(eol)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Every `<!--\s*asb:agent-setup\b` (non-overlapping), as the start offset of each.
fn any_marks(text: &str) -> usize {
    let (mut count, mut rest) = (0, text);
    while let Some(i) = rest.find("<!--") {
        let after = &rest[i + 4..];
        let trimmed = after.trim_start();
        if let Some(tail) = trimmed.strip_prefix(AGENT_MARK) {
            if !tail.chars().next().is_some_and(is_word) {
                count += 1;
                rest = tail;
                continue;
            }
        }
        rest = after;
    }
    count
}

/// `<!-- asb:agent-setup begin v(\d+) -->`: (start, end, version) of each.
fn begins(text: &str) -> Vec<(usize, usize, u64)> {
    let head = format!("<!-- {AGENT_MARK} begin v");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = text[from..].find(&head) {
        let start = from + i;
        let digits_at = start + head.len();
        let n = text[digits_at..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        let end_marker = " -->";
        if n > 0 && text[digits_at + n..].starts_with(end_marker) {
            let end = digits_at + n + end_marker.len();
            out.push((
                start,
                end,
                text[digits_at..digits_at + n].parse().unwrap_or(0),
            ));
            from = end;
        } else {
            from = start + 1;
        }
    }
    out
}

/// `<!-- asb:agent-setup end -->`: (start, end) of each.
fn ends(text: &str) -> Vec<(usize, usize)> {
    let marker = format!("<!-- {AGENT_MARK} end -->");
    text.match_indices(&marker)
        .map(|(i, m)| (i, i + m.len()))
        .collect()
}

/// (start, end, version) of the marked block, or `None`; an error if it is damaged.
fn find_block(text: &str) -> Result<Option<(usize, usize, u64)>, String> {
    let marks = any_marks(text);
    let (bs, es) = (begins(text), ends(text));
    if marks == 0 && bs.is_empty() && es.is_empty() {
        return Ok(None);
    }
    if marks != bs.len() + es.len() {
        return Err(format!(
            "a marker line is malformed (expected exactly '<!-- {AGENT_MARK} begin vN -->' and '<!-- {AGENT_MARK} end -->')"
        ));
    }
    if bs.len() > 1 || es.len() > 1 {
        return Err("more than one begin/end marker (duplicated block)".into());
    }
    if !bs.is_empty() && es.is_empty() {
        return Err("begin marker without an end marker".into());
    }
    if !es.is_empty() && bs.is_empty() {
        return Err("end marker without a begin marker".into());
    }
    let (b, e) = (bs[0], es[0]);
    if e.0 < b.1 {
        return Err("end marker comes before the begin marker".into());
    }
    Ok(Some((b.0, e.1, b.2)))
}

/// New text and a status word. Text outside the markers is preserved byte for byte.
fn apply_block(text: &str, remove: bool) -> Result<(String, String), String> {
    let found = find_block(text)?;
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    if remove {
        let Some((s, e, _)) = found else {
            return Ok((text.to_string(), "absent".into()));
        };
        let mut tail = &text[e..];
        for nl in ["\r\n", "\n"] {
            if let Some(t) = tail.strip_prefix(nl) {
                tail = t;
                break;
            }
        }
        let mut head = &text[..s];
        if tail.trim().is_empty() && head.ends_with(&format!("{eol}{eol}")) {
            head = &head[..head.len() - eol.len()]; // drop the blank separator install added
        }
        return Ok((format!("{head}{tail}"), "removed".into()));
    }
    let block = agent_block(eol);
    if let Some((s, e, v)) = found {
        let new = format!("{}{}{}", &text[..s], block, &text[e..]);
        if new == text {
            return Ok((text.to_string(), "unchanged".into()));
        }
        return Ok((new, format!("updated (v{v} -> v{AGENT_BLOCK_VERSION})")));
    }
    if text.is_empty() {
        return Ok((format!("{block}{eol}"), "installed".into()));
    }
    let sep = if text.ends_with(['\n', '\r']) {
        ""
    } else {
        eol
    };
    Ok((format!("{text}{sep}{eol}{block}{eol}"), "installed".into()))
}

/// `os.path.realpath`: symlinks resolved as far as they exist, the rest kept as written. Unlike Python's, it FAILS
/// when it cannot finish (a link loop or too many hops, an unreadable link): a path-safety check must not go on
/// with a half-resolved path.
fn realpath(path: &Path) -> Result<PathBuf, String> {
    let mut pending: VecDeque<OsString> = VecDeque::new();
    let mut result = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        std::env::current_dir().unwrap_or_default()
    };
    for c in path.components() {
        if let Component::Normal(n) = c {
            pending.push_back(n.to_os_string());
        } else if c == Component::ParentDir {
            pending.push_back("..".into());
        }
    }
    let mut hops = 0;
    while let Some(name) = pending.pop_front() {
        if name == ".." {
            result.pop();
            continue;
        }
        let next = result.join(&name);
        match fs::symlink_metadata(&next) {
            Ok(m) if m.file_type().is_symlink() => {
                hops += 1;
                if hops > 40 {
                    return Err(format!(
                        "too many levels of symbolic links resolving {}",
                        path.display()
                    ));
                }
                let target = fs::read_link(&next).map_err(|e| {
                    format!("cannot read the link {}: {}", next.display(), strerror(&e))
                })?;
                if target.is_absolute() {
                    result = PathBuf::from("/");
                }
                let mut front: Vec<OsString> = Vec::new();
                for c in target.components() {
                    match c {
                        Component::Normal(n) => front.push(n.to_os_string()),
                        Component::ParentDir => front.push("..".into()),
                        _ => {}
                    }
                }
                for n in front.into_iter().rev() {
                    pending.push_front(n);
                }
            }
            _ => result = next,
        }
    }
    Ok(result)
}

fn abspath(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn strerror(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        // SAFETY: strerror returns a pointer to a static NUL-terminated message.
        Some(n) => unsafe {
            std::ffi::CStr::from_ptr(libc::strerror(n))
                .to_string_lossy()
                .into_owned()
        },
        None => e.to_string(),
    }
}

fn access(path: &Path, mode: libc::c_int) -> bool {
    CString::new(path.as_os_str().as_bytes()).is_ok_and(|c| {
        // SAFETY: `c` is a valid NUL-terminated path.
        unsafe { libc::access(c.as_ptr(), mode) == 0 }
    })
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn which(name: &str, path_var: Option<&str>) -> bool {
    let dirs = path_var.unwrap_or("/bin:/usr/bin").to_string();
    dirs.split(':').any(|d| {
        let p = Path::new(if d.is_empty() { "." } else { d }).join(name);
        p.is_file() && access(&p, libc::X_OK)
    })
}

/// (config dir that shows the agent is installed, instruction file path)
fn agent_targets(
    agent: &str,
    scope: &str,
    home: &str,
    cwd: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> (String, String) {
    let join = |a: &str, b: &str| format!("{a}/{b}");
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty());
    match agent {
        "claude" => {
            if scope == "user" {
                return (
                    join(home, ".claude"),
                    join(&join(home, ".claude"), "CLAUDE.md"),
                );
            }
            let (top, alt) = (
                join(cwd, "CLAUDE.md"),
                join(&join(cwd, ".claude"), "CLAUDE.md"),
            );
            let lexists = |p: &str| fs::symlink_metadata(p).is_ok();
            let used = if !lexists(&top) && lexists(&alt) {
                alt
            } else {
                top
            };
            (cwd.to_string(), used)
        }
        "codex" => {
            let base = nonempty("CODEX_HOME").unwrap_or_else(|| join(home, ".codex"));
            if scope == "user" {
                return (base.clone(), join(&base, "AGENTS.md"));
            }
            (cwd.to_string(), join(cwd, "AGENTS.md"))
        }
        _ => {
            let base = nonempty("COPILOT_HOME").unwrap_or_else(|| join(home, ".copilot"));
            if scope == "user" {
                return (base.clone(), join(&base, "copilot-instructions.md"));
            }
            (
                cwd.to_string(),
                join(&join(cwd, ".github"), "copilot-instructions.md"),
            )
        }
    }
}

fn detect_agents(
    scope: &str,
    home: &str,
    cwd: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for a in AGENT_NAMES {
        let (_, path) = agent_targets(a, scope, home, cwd, env);
        let user_cfg = agent_targets(a, "user", home, cwd, env).0;
        let why = if Path::new(&user_cfg).is_dir() {
            Some(format!("config dir {user_cfg}"))
        } else if which(a, env("PATH").as_deref()) {
            Some(format!("'{a}' on PATH"))
        } else if scope == "project" && fs::symlink_metadata(&path).is_ok() {
            Some(format!("existing {path}"))
        } else {
            None
        };
        if let Some(why) = why {
            found.push((a.to_string(), why));
        }
    }
    found
}

struct Plan {
    agent: String,
    path: String,
    real: PathBuf,
    old: String,
    new: String,
    status: String,
    error: Option<String>,
    exists: bool,
    backup: Option<PathBuf>,
}

/// Read-only planning.
fn plan_target(
    agent: &str,
    path: &str,
    remove: bool,
    create_ok: bool,
    scope: &str,
    cwd: &str,
) -> Plan {
    let (real, resolve_error) = match realpath(Path::new(path)) {
        Ok(p) => (p, None),
        Err(e) => (PathBuf::from(path), Some(e)),
    };
    let mut r = Plan {
        agent: agent.into(),
        path: path.into(),
        real: real.clone(),
        old: String::new(),
        new: String::new(),
        status: String::new(),
        error: None,
        exists: false,
        backup: None,
    };
    let result: Result<(), String> = (|| {
        if let Some(e) = resolve_error {
            return Err(e);
        }
        if scope == "project" {
            let root = realpath(Path::new(cwd))?;
            if !real.starts_with(&root) {
                return Err(format!(
                    "resolves to {}, outside the project directory {}; refusing to follow it",
                    real.display(),
                    root.display()
                ));
            }
        }
        if real.exists() {
            let md = fs::metadata(&real).map_err(|e| strerror(&e))?;
            if !md.is_file() {
                return Err(format!("{} is not a regular file", real.display()));
            }
            let parent = real.parent().unwrap_or(Path::new("."));
            if scope == "user"
                && fs::metadata(parent).map(|m| m.uid()).unwrap_or(u32::MAX) != euid()
            {
                return Err(format!(
                    "directory of {} is not owned by you; refusing",
                    real.display()
                ));
            }
            r.exists = true;
            let mut raw = Vec::new();
            fs::File::open(&real)
                .and_then(|mut f| f.read_to_end(&mut raw))
                .map_err(|e| format!("cannot read: {}", strerror(&e)))?;
            r.old = String::from_utf8(raw)
                .map_err(|_| "not valid UTF-8 text; leaving it alone".to_string())?;
        } else if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("dangling symlink".into());
        } else {
            let parent = real.parent().unwrap_or(Path::new("."));
            if remove {
                r.status = "absent (no file)".into();
                r.new = r.old.clone();
                return Ok(());
            }
            if !create_ok && !parent.is_dir() {
                r.status =
                    format!("skipped (directory does not exist; use --agent {agent} to create it)");
                r.new = r.old.clone();
                return Ok(());
            }
        }
        let (new, status) = apply_block(&r.old, remove)?;
        r.new = new;
        r.status = status;
        if r.new != r.old {
            if r.exists {
                let writable = fs::metadata(&real)
                    .map(|m| m.permissions().mode() & 0o222 != 0)
                    .unwrap_or(false);
                if !writable || !access(&real, libc::W_OK) {
                    return Err("file is read-only; not changed".into());
                }
            } else {
                let mut d = real.parent().map(Path::to_path_buf).unwrap_or_default();
                while !d.as_os_str().is_empty() && !d.is_dir() {
                    d = d.parent().map(Path::to_path_buf).unwrap_or_default();
                }
                let probe = if d.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    d.clone()
                };
                if scope == "user"
                    && fs::metadata(&probe).map(|m| m.uid()).unwrap_or(u32::MAX) != euid()
                {
                    return Err(format!("{} is not owned by you; refusing", d.display()));
                }
                if !access(&probe, libc::W_OK) {
                    return Err(format!(
                        "cannot create file: {} is not writable",
                        d.display()
                    ));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        r.error = Some(e);
    }
    r
}

fn local_stamp() -> String {
    // SAFETY: localtime_r and strftime write only into the buffers passed to them.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        let mut buf = [0u8; 32];
        let n = libc::strftime(
            buf.as_mut_ptr().cast(),
            buf.len(),
            c"%Y%m%d%H%M%S".as_ptr(),
            &tm,
        );
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

/// Backup (if the file exists) and replace atomically. The resolved target is written; temp and backup files are
/// created exclusively and never follow a symlink.
fn write_target(r: &mut Plan) -> std::io::Result<()> {
    let real = r.real.clone();
    let dir = real.parent().unwrap_or(Path::new(".")).to_path_buf();
    fs::create_dir_all(&dir)?;
    let mut mode = 0o644;
    if r.exists {
        mode = fs::metadata(&real)?.permissions().mode() & 0o7777;
        let stamp = local_stamp();
        let mut n = 1;
        let (bak, mut out) = loop {
            let bak = PathBuf::from(format!(
                "{}.asb-bak-{stamp}{}",
                real.display(),
                if n > 1 {
                    format!("-{n}")
                } else {
                    String::new()
                }
            ));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&bak)
            {
                Ok(f) => break (bak, f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1, // a planted symlink too: O_EXCL never follows it
                Err(e) => return Err(e),
            }
        };
        let mut src = Vec::new();
        fs::File::open(&real)?.read_to_end(&mut src)?;
        out.write_all(&src)?;
        out.set_permissions(fs::Permissions::from_mode(mode))?;
        out.sync_all()?;
        r.backup = Some(bak);
    }
    let base = real
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let mut random = [0u8; 8];
    let (tmp, mut f) = loop {
        fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let suffix: String = random.iter().map(|b| (b'a' + b % 26) as char).collect();
        let tmp = dir.join(format!("{base}.asb-tmp-{suffix}"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    };
    let result = (|| {
        f.write_all(r.new.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, &real)
    })();
    if tmp.symlink_metadata().is_ok() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn run(args: &[String]) -> R {
    let help = || text_gen::help("agent-setup").unwrap_or_default();
    let (mut agent, mut scope, mut dry, mut remove) =
        (None::<String>, "user".to_string(), false, false);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--dry-run" => dry = true,
            "--remove" => remove = true,
            "-h" | "--help" => {
                println!("{}", help());
                return Ok(0);
            }
            "--agent" | "--scope" if i + 1 < args.len() => {
                if a == "--agent" {
                    agent = Some(args[i + 1].clone());
                } else {
                    scope = args[i + 1].clone();
                }
                i += 1;
            }
            _ => {
                return Err(die(
                    format!("unexpected argument {}\n{}", repr(a), help()),
                    USAGE,
                ))
            }
        }
        i += 1;
    }
    if agent
        .as_deref()
        .is_some_and(|a| !AGENT_NAMES.contains(&a) && a != "all")
    {
        return Err(die("--agent must be claude, codex, copilot or all", USAGE));
    }
    if scope != "user" && scope != "project" {
        return Err(die("--scope must be user or project", USAGE));
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let env = |k: &str| std::env::var(k).ok();
    let (names, explicit): (Vec<String>, bool) = match &agent {
        None => {
            let det = detect_agents(&scope, &home, &cwd, &env);
            if det.is_empty() {
                eprintln!("asb: no coding agent found (looked for Claude Code, Codex, GitHub Copilot: config directories and programs on PATH); name one with --agent");
                return Ok(NOT_FOUND);
            }
            for (a, why) in &det {
                println!("found {a}: {why}");
            }
            (det.into_iter().map(|(a, _)| a).collect(), false)
        }
        Some(a) if a == "all" => (AGENT_NAMES.iter().map(|s| s.to_string()).collect(), true),
        Some(a) => (vec![a.clone()], true),
    };
    let mut plans: Vec<Plan> = names
        .iter()
        .map(|a| {
            plan_target(
                a,
                &agent_targets(a, &scope, &home, &cwd, &env).1,
                remove,
                explicit,
                &scope,
                &cwd,
            )
        })
        .collect();
    for (a, p) in names.iter().zip(&plans) {
        if a == "codex" && scope == "user" {
            let ov = Path::new(&p.path)
                .parent()
                .unwrap_or(Path::new(""))
                .join("AGENTS.override.md");
            if ov.exists() && fs::metadata(&ov).map(|m| m.len()).unwrap_or(0) > 0 {
                println!("note: {} is non-empty and takes precedence over AGENTS.md; Codex will not read the block there", ov.display());
            }
        }
    }
    let mut bad = false;
    for p in &plans {
        let mut label = format!("{} ({scope}): {}", p.agent, p.path);
        if realpath(Path::new(&p.path)).ok().as_deref()
            != Some(abspath(Path::new(&p.path)).as_path())
        {
            label += &format!(" -> {}", p.real.display());
        }
        if let Some(err) = &p.error {
            bad = true;
            eprintln!("{label}: REFUSED: {err}");
            if err.contains("marker") {
                eprintln!(
                    "  fix or delete the damaged asb:agent-setup marker lines by hand, then re-run"
                );
            }
            continue;
        }
        let changed = p.new != p.old;
        println!(
            "{label}: {}{}",
            p.status,
            if dry && changed { " (dry run)" } else { "" }
        );
        if dry && changed {
            let from = if p.exists {
                format!("a/{}", p.path)
            } else {
                "/dev/null".to_string()
            };
            println!(
                "{}",
                unified_diff(&p.old, &p.new, &from, &format!("b/{}", p.path)).join("\n")
            );
        }
    }
    if bad {
        eprintln!("asb: nothing was written");
        return Ok(USAGE);
    }
    if !dry {
        for p in &mut plans {
            if p.new != p.old {
                // the plan checked this path a moment ago: refuse if it now leads somewhere else (a swapped link)
                if realpath(Path::new(&p.path)).ok().as_deref() != Some(p.real.as_path()) {
                    return Err(die(
                        format!(
                            "{} changed while it was being checked; nothing more was written",
                            p.path
                        ),
                        USAGE,
                    ));
                }
                if let Err(e) = write_target(p) {
                    return Err(die(
                        format!("cannot write {}: {}", p.path, strerror(&e)),
                        USAGE,
                    ));
                }
                if let Some(b) = &p.backup {
                    println!("backup: {}", b.display());
                }
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_update_and_remove_round_trip_on_plain_text() {
        let (installed, st) = apply_block("# mine\n", false).unwrap();
        assert_eq!(st, "installed");
        assert!(installed.starts_with("# mine\n\n<!-- asb:agent-setup begin v1 -->"));
        assert_eq!(apply_block(&installed, false).unwrap().1, "unchanged");
        let (removed, st) = apply_block(&installed, true).unwrap();
        assert_eq!((removed.as_str(), st.as_str()), ("# mine\n", "removed"));
        assert_eq!(apply_block("# mine\n", true).unwrap().1, "absent");
    }

    #[test]
    fn crlf_files_keep_their_line_endings() {
        let (installed, _) = apply_block("a\r\nb\r\n", false).unwrap();
        assert!(!installed.contains("\n\n") && installed.contains("\r\n"));
        assert!(
            installed.replace("\r\n", "").find('\n').is_none(),
            "no bare newline was added"
        );
    }

    #[test]
    fn damaged_markers_are_refused_not_guessed() {
        for bad in [
            "<!-- asb:agent-setup begin v1 -->\nno end",
            "<!-- asb:agent-setup end -->\nno begin",
            "<!-- asb:agent-setup begin vX -->",
            "<!-- asb:agent-setup end -->\n<!-- asb:agent-setup begin v1 -->",
        ] {
            assert!(apply_block(bad, false).is_err(), "{bad}");
        }
        let doubled = format!("{0}\n{0}", agent_block("\n"));
        assert!(apply_block(&doubled, false)
            .unwrap_err()
            .contains("duplicated"));
    }

    #[test]
    fn realpath_fails_on_a_symlink_loop_instead_of_returning_half_an_answer() {
        let dir = std::env::temp_dir().join(format!("asb-realpath-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a"), dir.join("b"));
        let _ = fs::remove_file(&a);
        let _ = fs::remove_file(&b);
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let err = realpath(&a).unwrap_err();
        assert!(err.contains("symbolic links"), "{err}");
        // and a plan for it is refused with that reason
        let plan = plan_target("claude", a.to_str().unwrap(), false, true, "user", "/");
        assert!(
            plan.error
                .as_deref()
                .is_some_and(|e| e.contains("symbolic links")),
            "{:?}",
            plan.error
        );
        // an ordinary chain still resolves, and a missing tail is kept as written
        let (target, link) = (dir.join("real"), dir.join("link"));
        let _ = fs::remove_file(&link);
        fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(realpath(&link).unwrap(), fs::canonicalize(&target).unwrap());
        assert_eq!(
            realpath(&dir.join("missing/file")).unwrap(),
            fs::canonicalize(&dir).unwrap().join("missing/file")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn splitlines_of_the_block_text_is_stable() {
        // the embedded body is the Python client's, byte for byte (tests/test_cli_text_sync.py keeps it so)
        assert!(AGENT_BLOCK_BODY.starts_with("## Credentials (asb)"));
        assert_eq!(AGENT_BLOCK_VERSION, 1);
    }
}
