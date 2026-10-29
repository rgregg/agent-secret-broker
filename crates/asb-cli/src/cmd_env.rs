//! `asb NAME -- command`: env mode. The broker injects the credential into the command's environment after the
//! human approves; the output comes back with the value masked. Before asking, the command line is searched for the
//! script file(s) it will run, so the approval card can show them (best effort: the agent is the client and can run
//! something else; the broker decides whether it understood the command). Nothing here executes the script.

use crate::analyse::{analyse, is_interpreter_call, py_normpath};
use crate::approval::obtain;
use crate::exit::{die, R, SCRIPT_CHANGED};
use crate::pyfmt::repr;
use crate::util::{check_name, die_help, universal_newlines};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

const SCRIPT_MAX_FILES: usize = 3;
const SCRIPT_TEXT_BYTES: usize = 32 * 1024; // text sent per script
const SCRIPT_HASH_MAX: u64 = 64 * 1024 * 1024; // larger files are not hashed: unreadable too_large
const SCRIPT_REFUSED: [&str; 6] = [
    "~/tokens",
    "~/.ssh",
    "~/.config/secret-broker",
    "/proc",
    "/sys",
    "/dev",
];
const LAUNCHERS: [&str; 29] = [
    "env", "sudo", "doas", "nohup", "time", "timeout", "nice", "stdbuf", "exec", "command",
    "setsid", "chrt", "taskset", "ionice", "xargs", "busybox", "strace", "ltrace", "nsenter",
    "unshare", "flock", "su", "runuser", "setpriv", "chroot", "numactl", "watch", "parallel",
    "script",
];

fn expanduser(p: &str) -> String {
    match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => match std::env::var("HOME") {
            Ok(home) if !home.is_empty() => format!("{home}{rest}"),
            _ => p.to_string(),
        },
        _ => p.to_string(),
    }
}

/// `os.path.abspath(os.path.expanduser(p))`.
fn abspath(p: &str) -> String {
    let p = expanduser(p);
    if p.starts_with('/') {
        py_normpath(&p)
    } else {
        let cwd = std::env::current_dir()
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_default();
        py_normpath(&format!("{cwd}/{p}"))
    }
}

fn refused(path: &str) -> bool {
    SCRIPT_REFUSED.iter().any(|r| {
        let base = expanduser(r);
        path == base || path.starts_with(&format!("{}/", base.trim_end_matches('/')))
    })
}

/// Python's `str.isprintable` for one character, without the Unicode tables for unassigned code points (a path shows
/// such a character as itself instead of `?`; nothing depends on it).
fn printable(c: char) -> bool {
    let cf = matches!(c as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890 | 0x891 | 0x8e2 | 0x180e | 0x200b..=0x200f
        | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff | 0xfff9..=0xfffb);
    let private = matches!(c as u32, 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd);
    !(c.is_control() || cf || private || (c.is_whitespace() && c != ' '))
}

fn printable_path(path: &str) -> String {
    path.chars()
        .map(|c| {
            if printable(c)
                && !"\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}"
                    .contains(c)
            {
                c
            } else {
                '?'
            }
        })
        .take(300)
        .collect()
}

/// `shutil.which`: the first executable regular file called `name` on `$PATH`.
fn which(name: &str) -> Option<String> {
    let usable = |p: &Path| {
        p.is_file()
            && std::ffi::CString::new(p.to_string_lossy().as_bytes())
                // SAFETY: a valid NUL-terminated path.
                .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
    };
    if name.contains('/') {
        return usable(Path::new(name)).then(|| name.to_string());
    }
    let path = std::env::var("PATH").unwrap_or_else(|_| "/bin:/usr/bin".into());
    path.split(':')
        .map(|d| Path::new(if d.is_empty() { "." } else { d }).join(name))
        .find(|p| usable(p))
        .map(|p| p.to_string_lossy().into_owned())
}

fn looks_text(b: &[u8]) -> bool {
    if b.contains(&0) {
        return false;
    }
    let s = String::from_utf8_lossy(b);
    let (bad, total) = (
        s.chars().filter(|c| *c == '\u{fffd}').count(),
        s.chars().count(),
    );
    total == 0 || bad * 10 <= total * 3
}

/// `bytes.decode("utf-8", "ignore")`: invalid sequences are dropped, a real U+FFFD stays.
fn decode_ignore(mut b: &[u8]) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(b) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let (good, rest) = b.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or(""));
                match e.error_len() {
                    Some(n) => b = &rest[n..],
                    None => return out, // a character cut off at the end
                }
            }
        }
    }
}

fn entry(pairs: &[(&str, Value)], extra: &Option<String>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert((*k).into(), v.clone());
    }
    if let Some(g) = extra {
        m.insert("given".into(), json!(g));
    }
    Value::Object(m)
}

/// An entry for one script, or `None` to ignore it (not a file / not a script worth reporting). `path` is the path
/// as named in the command; one realpath is applied.
fn read_script(path: &str, require_text: bool, via_path_lookup: bool) -> Option<Value> {
    let absolute = abspath(path);
    // Python's realpath keeps a path it cannot finish (a link loop); the stat below then fails and reports it missing
    let real = crate::cmd_agent_setup::realpath(Path::new(&absolute))
        .unwrap_or_else(|_| Path::new(&absolute).to_path_buf());
    let real = real.to_string_lossy().into_owned();
    let shown = printable_path(&real);
    let given = printable_path(&py_normpath(&absolute));
    let extra = (given != shown).then_some(given);
    let unreadable = |why: &str, with_extra: bool| {
        Some(entry(
            &[("path", json!(shown)), ("unreadable", json!(why))],
            if with_extra { &extra } else { &None },
        ))
    };
    if refused(&absolute) || refused(&real) {
        return unreadable("refused", true);
    }
    let st = match std::fs::metadata(&real) {
        Ok(st) => st,
        Err(e) => {
            return match e.raw_os_error() {
                Some(libc::ENOENT) => {
                    if require_text {
                        None
                    } else {
                        unreadable("missing", false)
                    }
                }
                Some(libc::EACCES | libc::EPERM) => unreadable("permission", true),
                _ => unreadable("missing", true),
            }
        }
    };
    if !st.is_file() {
        return None; // directory, device, fifo: nothing to read
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&real);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            return match e.raw_os_error() {
                Some(libc::EACCES | libc::EPERM) => unreadable("permission", true),
                _ => unreadable("missing", true),
            }
        }
    };
    let mut head = Vec::new();
    let _ = (&mut file)
        .take((SCRIPT_TEXT_BYTES + 4) as u64)
        .read_to_end(&mut head);
    let text_part = &head[..head.len().min(SCRIPT_TEXT_BYTES)];
    let is_text = looks_text(text_part);
    if require_text && (!is_text || (via_path_lookup && !text_part.starts_with(b"#!"))) {
        return None; // a compiled program: nothing to show, not worth a marker
    }
    if st.size() > SCRIPT_HASH_MAX {
        return unreadable("too_large", true);
    }
    if !is_text {
        return unreadable("binary", true);
    }
    let mut hash = Sha256::new();
    hash.update(&head);
    let mut total = head.len();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                hash.update(&buf[..n]);
                total += n;
            }
        }
    }
    Some(entry(
        &[
            ("path", json!(shown)),
            ("size", json!(total)),
            ("sha256", json!(hex(&hash.finalize()))),
            ("text", json!(decode_ignore(text_part))),
            ("truncated", json!(total > SCRIPT_TEXT_BYTES)),
        ],
        &extra,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or("")
}

/// Script entries for the `scripts` field of an env-mode request (none when the command runs no script we can find).
/// Reads files, never executes anything. What counts as a script is decided by the analyser's rules (the broker
/// applies the same ones to the argv it receives).
fn find_scripts(argv: &[String]) -> Vec<Value> {
    let first = analyse(argv);
    let (mut items, understood, cmd) = (first.items, first.understood, first.cmd);
    let mut entries: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut add = |e: Option<Value>| {
        let Some(e) = e else { return };
        let key = match e.get("path").and_then(Value::as_str) {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => "stdin".to_string(),
        };
        if seen.contains(&key) || entries.len() >= SCRIPT_MAX_FILES {
            return;
        }
        seen.push(key);
        entries.push(e);
    };
    if items.is_empty()
        && !understood
        && LAUNCHERS.contains(&basename(argv.first().map(String::as_str).unwrap_or("")))
    {
        // a launcher the broker does not understand: still show the script it appears to run
        for k in 1..argv.len() {
            items = analyse(&argv[k..]).items;
            if !items.is_empty() {
                break;
            }
        }
    }
    for (p, strict) in &items {
        if p == "-" || p == "/dev/stdin" || p == "/proc/self/fd/0" || p.starts_with("/dev/fd/") {
            add(Some(json!({"stdin": true})));
        } else if let Some(found) = (!p.contains('/') && *strict).then(|| which(p)).flatten() {
            add(read_script(&found, true, true)); // a bare name on PATH
        } else {
            add(read_script(p, *strict, false));
        }
    }
    if items.is_empty()
        && !cmd.is_empty()
        && !cmd[0].contains('/')
        && !is_interpreter_call(&cmd[0], &cmd[1..])
    {
        // a bare name that is a script found on PATH (a courtesy: the broker does not require it)
        if let Some(hit) = which(&cmd[0]) {
            add(read_script(&hit, true, true));
        }
    }
    entries
}

fn script_digest(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hash.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(hex(&hash.finalize()))
}

/// The path of the first reported script whose content differs now, else `None`.
fn changed_script(entries: &[Value]) -> Option<String> {
    entries.iter().find_map(|e| {
        let want = e.get("sha256")?.as_str()?;
        let path = e.get("path")?.as_str()?;
        (script_digest(path).as_deref() != Some(want)).then(|| path.to_string())
    })
}

fn mask(text: &str, values: &[String]) -> String {
    let mut sorted: Vec<&String> = values.iter().collect();
    sorted.sort_by_key(|v| std::cmp::Reverse(v.chars().count()));
    let mut text = text.to_string();
    for v in sorted {
        if v.chars().count() >= 6 {
            text = text.replace(v.as_str(), "***");
        }
    }
    text
}

/// The env-mode request for running `cmd`, and the script entries it carries.
fn env_payload(names: &[String], cmd: &[String]) -> (Map<String, Value>, Vec<Value>) {
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("env"));
    payload.insert("names".into(), json!(names));
    payload.insert("argv".into(), json!(cmd));
    if let Ok(cwd) = std::env::current_dir() {
        let cwd = cwd.to_string_lossy().into_owned();
        if cwd.starts_with('/')
            && cwd.chars().count() <= 300
            && !cwd.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
        {
            payload.insert("cwd".into(), json!(cwd)); // lets the broker resolve relative script operands
        }
    }
    // script detection is a courtesy; it never blocks a request
    let scripts = std::panic::catch_unwind(|| find_scripts(cmd)).unwrap_or_default();
    if !scripts.is_empty() {
        payload.insert("scripts".into(), Value::Array(scripts.clone()));
    }
    (payload, scripts)
}

pub fn run(argv: &[String]) -> R {
    let i = argv.iter().position(|a| a == "--").unwrap_or(0); // the dispatcher sends env mode here only with a `--`
    let cmd = &argv[i + 1..];
    if i != 1 || cmd.is_empty() {
        return Err(die_help("run"));
    }
    let names: Vec<String> = argv[0].split(',').map(String::from).collect();
    for n in &names {
        check_name(n, "NAME")?;
    }
    let (payload, scripts) = env_payload(&names, cmd);
    let answer = obtain(payload, "waiting for approval on your phone...")?;
    let env: Vec<(String, String)> = answer["env"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), crate::pyfmt::py_str(v)))
                .collect()
        })
        .unwrap_or_default();
    if let Some(moved) = changed_script(&scripts) {
        // advisory: catches an edit between the request and the run, nothing more
        return Err(die(
            format!("script {moved} changed after it was reviewed"),
            SCRIPT_CHANGED,
        ));
    }
    let child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::inherit())
        .output()
        .map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            };
            die(
                format!(
                    "cannot run {}: {}",
                    repr(&cmd[0]),
                    crate::util::os_error(&e)
                ),
                code,
            )
        })?;
    let values: Vec<String> = env.into_iter().map(|(_, v)| v).collect();
    let show = |bytes: &[u8]| {
        mask(
            &universal_newlines(&String::from_utf8_lossy(bytes)),
            &values,
        )
    };
    {
        use std::io::Write;
        let _ = std::io::stdout().write_all(show(&child.stdout).as_bytes());
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().write_all(show(&child.stderr).as_bytes());
    }
    Ok(crate::cmd_ssh_agent::exit_code(child.status))
}
