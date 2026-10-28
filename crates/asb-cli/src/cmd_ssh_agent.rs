//! `asb ssh-agent`: a local ssh-agent whose keys stay in the broker; each login asks the human.

use crate::approval::obtain_with;
use crate::broker;
use crate::exit::{die, R, USAGE};
use crate::ssh_claim::claimed_destination;
use crate::util::{base64, base64_decode, die_help};
use asb_client::Client;
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const AGENT_FAILURE: u8 = 5;
const AGENTC_REQUEST_IDENTITIES: u8 = 11;
const AGENT_IDENTITIES_ANSWER: u8 = 12;
const AGENTC_SIGN_REQUEST: u8 = 13;
const AGENT_SIGN_RESPONSE: u8 = 14;
const AGENT_SUCCESS: u8 = 6;
const AGENTC_EXTENSION: u8 = 27;
const BIND_EXT: &[u8] = b"session-bind@openssh.com";
const MAX_BINDS: usize = 16; // per agent connection

/// `n` length-prefixed strings from the front of `b`, then whatever is left.
fn strings(mut b: &[u8], n: usize) -> Option<(Vec<&[u8]>, &[u8])> {
    let mut out = Vec::new();
    for _ in 0..n {
        let head = b.get(..4)?;
        let ln = u32::from_be_bytes(head.try_into().ok()?) as usize;
        let item = b.get(4..4 + ln)?;
        out.push(item);
        b = &b[4 + ln..];
    }
    Some((out, b))
}

fn s(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// Python's `b[a:z]`: out-of-range ends are clamped, never an error.
fn sl(b: &[u8], a: usize, z: usize) -> &[u8] {
    let z = z.min(b.len());
    if a >= z {
        &[]
    } else {
        &b[a..z]
    }
}

/// `int.from_bytes(b, "big")` of up to 4 bytes (empty is 0).
fn be(b: &[u8]) -> usize {
    b.iter().fold(0usize, |acc, &x| acc << 8 | x as usize)
}

#[derive(Default)]
struct Conn {
    binds: Vec<Value>,
    claim: Option<String>,
    overflow: bool,
}

fn identities(client: &Client) -> Option<Vec<(String, Vec<u8>)>> {
    let (code, r) = broker::call(client, "/v1/secrets", None, 40).ok()?;
    if code != 200 {
        return Some(vec![]);
    }
    let mut out = Vec::new();
    for sec in r.get("secrets")?.as_array()? {
        let Some(key) = sec
            .get("ssh_public_key")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty())
        else {
            continue;
        };
        let name = sec.get("name")?.as_str()?.to_string();
        if let Some(blob) = key.split_whitespace().nth(1).and_then(base64_decode) {
            out.push((name, blob));
        }
    }
    Some(out)
}

/// Answer one ssh-agent request. Anything unsupported is a plain failure.
fn reply(client: &Client, msg: &[u8], conn: &mut Conn) -> Vec<u8> {
    let fail = vec![AGENT_FAILURE];
    answer(client, msg, conn).unwrap_or(fail)
}

fn answer(client: &Client, msg: &[u8], conn: &mut Conn) -> Option<Vec<u8>> {
    let fail = Some(vec![AGENT_FAILURE]);
    let (kind, body) = (*msg.first()?, &msg[1..]);
    match kind {
        AGENTC_EXTENSION => {
            let (name, rest) = strings(body, 1)?;
            if name[0] != BIND_EXT {
                return fail; // OpenSSH carries on without the extension
            }
            if conn.binds.len() >= MAX_BINDS {
                conn.overflow = true; // the broker then treats the whole chain as invalid
                return fail;
            }
            let (parts, rest) = strings(rest, 3)?;
            if rest.len() != 1 || rest[0] > 1 {
                return fail;
            }
            // The broker verifies the signature; the agent only remembers the bind.
            conn.binds.push(json!({
                "hostkey_b64": base64(parts[0]),
                "session_id_b64": base64(parts[1]),
                "sig_b64": base64(parts[2]),
                "forwarding": rest[0] == 1,
            }));
            Some(vec![AGENT_SUCCESS])
        }
        AGENTC_REQUEST_IDENTITIES => {
            let ids = identities(client)?;
            let mut out = vec![AGENT_IDENTITIES_ANSWER];
            out.extend((ids.len() as u32).to_be_bytes());
            for (name, blob) in &ids {
                out.extend(s(blob));
                out.extend(s(format!("broker:{name}").as_bytes()));
            }
            Some(out)
        }
        AGENTC_SIGN_REQUEST => {
            let n = be(sl(body, 0, 4));
            let blob = sl(body, 4, 4 + n);
            let rest = sl(body, 4 + n, usize::MAX);
            let m = be(sl(rest, 0, 4));
            let data = sl(rest, 4, 4 + m);
            let flags = be(sl(rest, 4 + m, 8 + m));
            let name = identities(client)?
                .into_iter()
                .find(|(_, b)| b == blob)
                .map(|(nm, _)| nm);
            let Some(name) = name else { return fail };
            let mut req = Map::new();
            req.insert("mode".into(), json!("ssh_sign"));
            req.insert("names".into(), json!([name]));
            req.insert("flags".into(), json!(flags));
            req.insert("data_b64".into(), json!(base64(data)));
            if !conn.binds.is_empty() {
                req.insert("binds".into(), Value::Array(conn.binds.clone()));
            }
            if conn.overflow {
                req.insert("bind_overflow".into(), json!(true));
            }
            if let Some(c) = conn.claim.as_ref().filter(|c| !c.is_empty()) {
                req.insert("claimed_dest".into(), json!(c));
            }
            // a denial or timeout is said on stderr by `obtain`, and the answer is a plain failure
            let r = obtain_with(client, req, "waiting for approval on your phone...").ok()?;
            let sig = base64_decode(r.get("ssh_signature")?.as_str()?)?;
            let mut out = vec![AGENT_SIGN_RESPONSE];
            out.extend(s(&sig));
            Some(out)
        }
        _ => fail,
    }
}

fn read_exact_or_eof(conn: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    conn.read_exact(&mut buf).ok()?;
    Some(buf)
}

fn read_msg(conn: &mut UnixStream) -> Option<Vec<u8>> {
    let head = read_exact_or_eof(conn, 4)?;
    let n = u32::from_be_bytes(head.try_into().ok()?) as usize;
    if 0 < n && n <= 1_000_000 {
        read_exact_or_eof(conn, n)
    } else {
        None
    }
}

fn serve(listener: UnixListener, client: Arc<Client>, claim: Option<String>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let (client, claim) = (client.clone(), claim.clone());
        std::thread::spawn(move || {
            let mut conn = Conn {
                claim,
                ..Conn::default()
            };
            while let Some(msg) = read_msg(&mut stream) {
                let answer = reply(&client, &msg, &mut conn);
                if stream.write_all(&s(&answer)).is_err() {
                    return;
                }
            }
        });
    }
}

static TERM: AtomicBool = AtomicBool::new(false);
static INT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_term(_: libc::c_int) {
    TERM.store(true, Ordering::SeqCst);
}
extern "C" fn on_int(_: libc::c_int) {
    INT.store(true, Ordering::SeqCst);
}

/// Python's `os.path.abspath(os.path.expanduser(p))`.
fn abspath(p: &str) -> PathBuf {
    let expanded = match p.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            format!(
                "{}{rest}",
                std::env::var("HOME").unwrap_or_else(|_| "~".into())
            )
        }
        _ => p.to_string(),
    };
    let joined = if expanded.starts_with('/') {
        PathBuf::from(&expanded)
    } else {
        std::env::current_dir().unwrap_or_default().join(&expanded)
    };
    let mut out = PathBuf::from("/");
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(x) => out.push(x),
            _ => {}
        }
    }
    out
}

pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => c,
        (None, Some(sig)) => 256 - sig, // Python's negative return code, as an exit status
        _ => 1,
    }
}

pub fn run(argv: &[String]) -> R {
    let (mut rest, mut sock) = (argv, None);
    if rest.first().map(String::as_str) == Some("--socket") {
        if rest.len() < 2 {
            return Err(die_help("ssh-agent"));
        }
        sock = Some(rest[1].clone());
        rest = &rest[2..];
    }
    match rest.first().map(String::as_str) {
        None => {}
        Some("--") if rest.len() >= 2 => {}
        _ => return Err(die_help("ssh-agent")),
    }
    let cmd = rest.get(1..).unwrap_or_default();
    run_agent(cmd, sock.as_deref())
}

fn run_agent(cmd: &[String], socket_path: Option<&str>) -> R {
    broker::ignore_sigpipe();
    let client = Arc::new(broker::client()?);
    let (path, dir): (PathBuf, Option<PathBuf>) = match socket_path {
        Some(p) => {
            // A fixed, long-lived socket (a systemd user service, say). The directory must already exist and be
            // ours alone; a stale socket from a dead agent is replaced, a live one is an error.
            let path = abspath(p);
            let parent = path.parent().unwrap_or(Path::new("/")).to_path_buf();
            let st = match std::fs::metadata(&parent) {
                Ok(m) if m.is_dir() => m,
                _ => {
                    return Err(die(
                        format!("{} is not a directory", parent.display()),
                        USAGE,
                    ));
                }
            };
            // SAFETY: getuid has no preconditions.
            if st.uid() != unsafe { libc::getuid() } || st.mode() & 0o022 != 0 {
                return Err(die(
                    format!(
                        "{} must be owned by you and not writable by others",
                        parent.display()
                    ),
                    USAGE,
                ));
            }
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if !meta.file_type().is_socket() {
                    return Err(die(
                        format!(
                            "{} exists and is not a socket; not replacing it",
                            path.display()
                        ),
                        USAGE,
                    ));
                }
                if UnixStream::connect(&path).is_ok() {
                    return Err(die(
                        format!("an agent is already listening on {}", path.display()),
                        USAGE,
                    ));
                }
                let _ = std::fs::remove_file(&path);
            }
            (path, None)
        }
        None => {
            // 0700: only this user can reach the socket
            let mut template = std::env::temp_dir()
                .join("asb-agent-XXXXXX")
                .into_os_string()
                .into_encoded_bytes();
            template.push(0);
            // SAFETY: the template is a writable NUL-terminated buffer, which mkdtemp edits in place.
            let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
            if made.is_null() {
                return Err(die(
                    "cannot create a temporary directory for the agent socket",
                    1,
                ));
            }
            template.pop();
            let d = PathBuf::from(String::from_utf8_lossy(&template).into_owned());
            (d.join("agent.sock"), Some(d))
        }
    };
    // SAFETY: umask only changes this process's file creation mask.
    let old_umask = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(&path);
    unsafe { libc::umask(old_umask) };
    let listener =
        listener.map_err(|e| die(format!("cannot listen on {}: {e}", path.display()), 1))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

    // SAFETY: the handlers only store to atomic flags.
    unsafe {
        libc::signal(libc::SIGTERM, on_term as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_int as *const () as libc::sighandler_t);
    }
    let claim = if cmd.is_empty() {
        None
    } else {
        claimed_destination(cmd)
    };
    {
        let client = client.clone();
        std::thread::spawn(move || serve(listener, client, claim));
    }
    let result = drive(cmd, socket_path.is_some(), &path);
    match &dir {
        Some(d) => {
            let _ = std::fs::remove_dir_all(d);
        }
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
    result
}

/// Hold the agent open until the wrapped command ends, or (with no command) until told to stop.
fn drive(cmd: &[String], fixed: bool, path: &Path) -> R {
    let stopped = || -> Option<i32> {
        if TERM.load(Ordering::SeqCst) {
            Some(0) // a clean stop for systemd
        } else if INT.load(Ordering::SeqCst) {
            Some(130)
        } else {
            None
        }
    };
    let nap = |ms| std::thread::sleep(Duration::from_millis(ms));
    if cmd.is_empty() {
        if fixed {
            eprintln!("asb: ssh-agent listening on {}", path.display());
        } else {
            println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", path.display());
            let _ = std::io::stdout().flush();
        }
        loop {
            if let Some(code) = stopped() {
                return Ok(code);
            }
            nap(50);
        }
    }
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .env("SSH_AUTH_SOCK", path)
        .spawn()
        .map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                127
            } else {
                126
            };
            die(
                format!(
                    "cannot run {}: {}",
                    crate::pyfmt::repr(&cmd[0]),
                    crate::util::os_error(&e)
                ),
                code,
            )
        })?;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Ok(exit_code(status));
        }
        if let Some(code) = stopped() {
            if code == 130 {
                // Ctrl-C reached the child too: give it a moment to leave on its own
                let until = Instant::now() + Duration::from_millis(250);
                while Instant::now() < until && matches!(child.try_wait(), Ok(None)) {
                    nap(10);
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            return Ok(code);
        }
        nap(20);
    }
}
