//! The "your agent instructions are out of date" notice and the `agent instructions:` line of `asb version`: the port
//! of `installed_agent_blocks`, `maybe_agent_notice` and `agent_instructions_state` in client/asb.
//!
//! Local only: it reads the instruction files `asb agent-setup` writes (never writes one, sends nothing anywhere) and
//! says something only for a well-formed block whose version is lower than the one this asb writes. A missing file,
//! no block, a damaged block, an unreadable, huge or non-UTF-8 file or a block that is current (or newer) is silence.

use crate::cmd_agent_setup::{agent_targets, euid, find_block, realpath, AGENT_NAMES};
use crate::text_gen::AGENT_BLOCK_VERSION;
use crate::update_notice::{due, is_silenced, now, record_path, switched_off};
use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// An instruction file is small; a bigger one is not read at all.
const READ_MAX: u64 = 256 * 1024;

static DONE: AtomicBool = AtomicBool::new(false);

/// A path for a terminal with control and bidi/format characters shown as `\xNN` or `\uNNNN`, so a hostile directory
/// name cannot move the cursor, recolour the line or hide text. The same rule as `_escape_path` in client/asb.
pub fn escape_path(path: &str) -> String {
    let mut out = String::new();
    for ch in path.chars() {
        let o = ch as u32;
        let bad = o < 32
            || (0x7f..=0x9f).contains(&o)
            || matches!(o, 0x2028 | 0x2029 | 0xfeff)
            || (0x200b..=0x200f).contains(&o)
            || (0x202a..=0x202e).contains(&o)
            || (0x2066..=0x2069).contains(&o);
        if !bad {
            out.push(ch);
        } else if o < 256 {
            out.push_str(&format!("\\x{o:02x}"));
        } else {
            out.push_str(&format!("\\u{o:04x}"));
        }
    }
    out
}

/// The version of the well-formed block in `path`, or `None` for anything that is not one.
fn block_version(path: &str, project_root: Option<&Path>) -> Option<u64> {
    let real = realpath(Path::new(path)).ok()?;
    if let Some(root) = project_root {
        if !real.starts_with(root) {
            return None; // a project file may not lead out of the project, as for agent-setup
        }
    } else if std::fs::metadata(real.parent()?).ok()?.uid() != euid() {
        return None; // a user file's directory must be yours
    }
    let md = std::fs::metadata(&real).ok()?;
    if !md.is_file() || md.len() > READ_MAX {
        return None;
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&real)
        .ok()?;
    let mut raw = Vec::new();
    f.take(READ_MAX + 1).read_to_end(&mut raw).ok()?;
    if raw.len() as u64 > READ_MAX {
        return None;
    }
    let text = String::from_utf8(raw).ok()?;
    find_block(&text).ok().flatten().map(|b| b.2)
}

/// `(path, version)` of each instruction file with a well-formed block: the three user-scope files, then the three
/// project-scope ones for `cwd`, once per resolved file.
pub fn installed_blocks(
    home: &str,
    cwd: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, u64)> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let root = realpath(Path::new(cwd)).ok();
    for scope in ["user", "project"] {
        for agent in AGENT_NAMES {
            let path = agent_targets(agent, scope, home, cwd, env).1;
            let Ok(real) = realpath(Path::new(&path)) else {
                continue;
            };
            if !seen.insert(real) {
                continue;
            }
            let project_root = if scope == "project" {
                match &root {
                    Some(r) => Some(r.as_path()),
                    None => continue,
                }
            } else {
                None
            };
            if let Some(v) = block_version(&path, project_root) {
                found.push((path, v));
            }
        }
    }
    found
}

fn installed_here() -> Vec<(String, u64)> {
    let home = std::env::var("HOME").unwrap_or_default();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    installed_blocks(&home, &cwd, &|k| std::env::var(k).ok())
}

/// The blocks written by an older asb than this one.
pub fn stale(found: &[(String, u64)]) -> Vec<(String, u64)> {
    found
        .iter()
        .filter(|(_, v)| *v < u64::from(AGENT_BLOCK_VERSION))
        .cloned()
        .collect()
}

/// The notice for a non-empty list of stale files: at most three named, then a count.
pub fn notice_text(stale: &[(String, u64)]) -> String {
    let mut shown: Vec<String> = stale
        .iter()
        .take(3)
        .map(|(p, v)| format!("{} has v{v}", escape_path(p)))
        .collect();
    if stale.len() > 3 {
        shown.push(format!("and {} more", stale.len() - 3));
    }
    format!(
        "asb: your agent instructions are out of date ({}, this asb writes v{AGENT_BLOCK_VERSION}). \
         Ask the human to run `asb agent-setup`; agents: do not edit your own instruction files.",
        shown.join(", ")
    )
}

/// The value of the `agent instructions:` line of `asb version`. Reads the files; never writes anything.
pub fn state_text() -> String {
    let found = installed_here();
    let old = stale(&found);
    if !old.is_empty() {
        let items: Vec<String> = old
            .iter()
            .map(|(p, v)| format!("{} (v{v}, current v{AGENT_BLOCK_VERSION})", escape_path(p)))
            .collect();
        return format!("out of date: {}: run asb agent-setup", items.join(", "));
    }
    if found.is_empty() {
        "not installed".into()
    } else {
        "up to date".into()
    }
}

/// Tell the user, on stderr and at most once a day, that a block `asb agent-setup` wrote is older than this asb's.
/// Called wherever the update notice is; off wherever it is.
pub fn maybe_notice() {
    if DONE.load(Ordering::SeqCst) || is_silenced() || switched_off() {
        return;
    }
    DONE.store(true, Ordering::SeqCst);
    let old = stale(&installed_here());
    if old.is_empty() {
        return;
    }
    if let Some(path) = record_path("agent-notice") {
        if due(&path, now()) {
            use std::io::Write;
            let _ = writeln!(std::io::stderr(), "{}", notice_text(&old));
            // a closed stderr is not an error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn block(v: u32, eol: &str) -> String {
        [
            format!("<!-- asb:agent-setup begin v{v} -->"),
            "body".to_string(),
            "<!-- asb:agent-setup end -->".to_string(),
        ]
        .join(eol)
            + eol
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("asb-agent-notice-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn found(home: &Path, cwd: &Path) -> Vec<(String, u64)> {
        installed_blocks(home.to_str().unwrap(), cwd.to_str().unwrap(), &|_| {
            None::<String>
        })
    }

    fn put(path: &Path, text: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn the_decision_is_lower_only_and_silent_for_anything_else() {
        let cur = AGENT_BLOCK_VERSION;
        let d = tmp("decision");
        let (home, proj) = (d.join("home"), d.join("proj"));
        fs::create_dir_all(&proj).unwrap();
        let file = home.join(".claude").join("CLAUDE.md");
        let versions = |text: &str| {
            put(&file, text);
            let all = found(&home, &proj);
            (all.clone(), stale(&all))
        };
        let (all, old) = versions(&block(cur - 1, "\n"));
        assert_eq!((all.len(), old.len()), (1, 1)); // lower: stale
        assert_eq!(old[0].1, u64::from(cur - 1));
        let (all, old) = versions(&block(cur, "\n"));
        assert_eq!((all.len(), old.len()), (1, 0)); // equal: found, not stale
        let (all, old) = versions(&block(cur + 1, "\n"));
        assert_eq!((all.len(), old.len()), (1, 0)); // higher: not stale
        let (all, old) = versions(&block(cur - 1, "\r\n"));
        assert_eq!((all.len(), old.len()), (1, 1)); // CRLF
        for damaged in [
            "<!-- asb:agent-setup begin v1 -->\nbody\n",
            "body\n<!-- asb:agent-setup end -->\n",
            &(block(1, "\n") + &block(1, "\n")),
            "<!-- asb:agent-setup begin vX -->\nbody\n<!-- asb:agent-setup end -->\n",
        ] {
            let (all, _) = versions(damaged);
            assert!(all.is_empty(), "{damaged:?}");
        }
        let (all, _) = versions("# no block\n");
        assert!(all.is_empty());
        let (all, _) = versions(&(block(1, "\n") + &"x".repeat(300_000))); // huge
        assert!(all.is_empty());
        put(&file, &block(1, "\n")); // control: the same block, small, is found
        assert_eq!(found(&home, &proj).len(), 1);
        fs::write(
            &file,
            [&[0xffu8, 0xfe][..], block(1, "\n").as_bytes()].concat(),
        )
        .unwrap();
        assert!(found(&home, &proj).is_empty()); // not UTF-8
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap(); // not a regular file
        assert!(found(&home, &proj).is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn symlinks_follow_agent_setups_rules() {
        let d = tmp("links");
        let (home, proj) = (d.join("home"), d.join("proj"));
        fs::create_dir_all(&proj).unwrap();
        let target = d.join("dotfiles").join("CLAUDE.md");
        put(&target, &block(1, "\n"));
        fs::create_dir_all(home.join(".claude")).unwrap();
        std::os::unix::fs::symlink(&target, home.join(".claude").join("CLAUDE.md")).unwrap();
        assert_eq!(found(&home, &proj).len(), 1); // a user file may be a link
        std::os::unix::fs::symlink(&target, proj.join("CLAUDE.md")).unwrap();
        assert_eq!(found(&home, &proj).len(), 1); // a project link out of the project is not followed
        fs::remove_file(proj.join("CLAUDE.md")).unwrap();
        put(&proj.join("CLAUDE.md"), &block(1, "\n"));
        assert_eq!(found(&home, &proj).len(), 2); // control: inside the project is read
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn at_most_three_are_named_and_paths_are_escaped() {
        let one = vec![("/p\x1b[31m\u{202e}x".to_string(), 1)];
        let t = notice_text(&one);
        assert_eq!(
            t,
            format!(
                "asb: your agent instructions are out of date (/p\\x1b[31m\\u202ex has v1, this asb writes v{AGENT_BLOCK_VERSION}). \
                 Ask the human to run `asb agent-setup`; agents: do not edit your own instruction files."
            )
        );
        let five: Vec<(String, u64)> = (1..=5).map(|i| (format!("/f{i}"), 1)).collect();
        let t = notice_text(&five);
        assert!(t.contains("/f1 has v1, /f2 has v1, /f3 has v1, and 2 more, this asb writes"));
        assert!(!t.contains("/f4"));
    }
}
