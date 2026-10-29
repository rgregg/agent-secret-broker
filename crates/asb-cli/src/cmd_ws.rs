//! `asb ws`: a WebSocket session the broker holds open; send, recv, close, and a line pipe. The credential
//! never reaches this process.

use crate::approval::obtain;
use crate::broker;
use crate::cmd_http::is_session_id;
use crate::cmd_session::parse_ttl;
use crate::exit::{die, Die, BROKER, ENDED, R, REFUSED, USAGE};
use crate::pyfmt::{json_dumps, py_str, repr, srv, truthy};
use crate::util::{check_name, universal_newlines};
use asb_client::Client;
use serde_json::{json, Map, Value};
use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const WS_ID_ENV: &str = "ASB_WS_SESSION";
const WS_MAX_SEND: usize = 4 << 20;

fn help() -> String {
    crate::text_gen::help("ws").unwrap_or_default().to_string()
}

fn usage(msg: &str) -> Die {
    die(format!("{msg}\n{}", help()), USAGE)
}

/// (exit code, message) for a broker answer that is not a success.
fn ws_rc(code: u16, r: &Value) -> (i32, String) {
    let msg = broker::error_text(r, &format!("broker returned {code}"));
    match r.get("code").and_then(Value::as_str) {
        Some("session_unknown" | "session_expired") => (ENDED, msg),
        Some("session_refused") => (REFUSED, msg),
        _ => (BROKER, msg),
    }
}

fn ws_post(client: &Client, path: &str, body: &Value, timeout_s: u64) -> Result<Value, Die> {
    let (code, r) = broker::call(client, path, Some(body), timeout_s)?;
    if code != 200 {
        let (rc, msg) = ws_rc(code, &r);
        return Err(die(msg, rc));
    }
    Ok(r)
}

fn is_bad(c: char) -> bool {
    matches!(c as u32,
        0x00..=0x08 | 0x0b..=0x1f | 0x7f..=0x9f | 0x61c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
}

/// Server text for a terminal: newlines become spaces (one frame, one line); other control characters and the
/// bidirectional override characters are removed.
fn ws_clean(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
        .chars()
        .filter(|c| !is_bad(*c))
        .collect()
}

fn ws_print(frames: &Value) {
    let mut out = std::io::stdout();
    for f in frames.as_array().map(Vec::as_slice).unwrap_or_default() {
        if f.get("type").and_then(Value::as_str) == Some("text") {
            let data = f.get("data").map(py_str).unwrap_or_default();
            let _ = writeln!(out, "{}", ws_clean(&data));
        } else {
            let n = f
                .get("bytes")
                .and_then(|b| b.as_i64().or_else(|| b.as_f64().map(|x| x as i64)))
                .unwrap_or(0);
            eprintln!("asb: binary frame ({n} bytes) not shown");
        }
    }
    let _ = out.flush();
}

fn ws_notes(r: &Value) {
    if truthy(&r["truncated"]) {
        eprintln!(
            "asb: the broker's receive buffer filled and it paused reading (nothing was dropped); collect frames more often"
        );
    }
}

fn closed_note(r: &Value) {
    let why = if truthy(&r["close_reason"]) {
        py_str(&r["close_reason"])
    } else {
        "closed".into()
    };
    eprintln!("asb: the connection is closed ({})", srv(&why, 160));
}

/// (session id, remaining positionals): the first positional when it is an id and there are `need_more` more
/// after it, else `$ASB_WS_SESSION`.
fn ws_session_id(pos: &[String], need_more: usize) -> Result<(String, Vec<String>), Die> {
    if pos.len() > need_more && is_session_id(&pos[0]) {
        return Ok((pos[0].clone(), pos[1..].to_vec()));
    }
    let env = std::env::var(WS_ID_ENV).unwrap_or_default();
    let env = env.trim();
    if !env.is_empty() {
        if !is_session_id(env) {
            return Err(die(
                format!("{WS_ID_ENV} is not a session id (the one `asb ws NAME URL` printed)"),
                USAGE,
            ));
        }
        return Ok((env.to_string(), pos.to_vec()));
    }
    Err(usage(&format!(
        "a session id is needed (the one `asb ws NAME URL` printed, or export {WS_ID_ENV}=ID)"
    )))
}

type Flags = Vec<(String, String)>;

/// (positionals, flags). Flags take a value unless listed in `bools`.
fn ws_flags(
    argv: &[String],
    allowed: &[&str],
    bools: &[&str],
) -> Result<(Vec<String>, Flags), Die> {
    let (mut pos, mut flags, mut i) = (vec![], Flags::new(), 0);
    while i < argv.len() {
        let a = argv[i].as_str();
        if bools.contains(&a) {
            flags.push((a.into(), String::new()));
            i += 1;
        } else if allowed.contains(&a) {
            if i + 1 >= argv.len() {
                return Err(usage(&format!("{a} needs a value")));
            }
            if flags.iter().any(|(k, _)| k == a) {
                return Err(die(format!("{a} given twice"), USAGE));
            }
            flags.push((a.into(), argv[i + 1].clone()));
            i += 2;
        } else if a.starts_with('-') && a != "-" && !is_session_id(a) {
            // (an id may start with "-")
            return Err(usage(&format!("unexpected argument {}", repr(a))));
        } else {
            pos.push(a.to_string());
            i += 1;
        }
    }
    Ok((pos, flags))
}

fn fl<'a>(flags: &'a Flags, k: &str) -> Option<&'a str> {
    flags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

/// A number from `lo` to `hi`; a whole number when `integer`.
fn ws_number(text: &str, what: &str, lo: u32, hi: u32, integer: bool) -> Result<f64, Die> {
    let bad = || die(format!("{what} must be a number from {lo} to {hi}"), USAGE);
    let v = if integer {
        if text.is_ascii() && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            text.parse::<f64>().ok()
        } else {
            None
        }
    } else {
        text.trim().parse::<f64>().ok()
    };
    match v {
        Some(v) if !v.is_nan() && (lo as f64..=hi as f64).contains(&v) => Ok(v),
        _ => Err(bad()),
    }
}

pub fn run(argv: &[String]) -> R {
    let Some(sub) = argv.first().map(String::as_str) else {
        return Err(die(help(), USAGE));
    };
    match sub {
        "send" => {
            let (pos, _) = ws_flags(&argv[1..], &[], &[])?;
            let (sid, rest) = ws_session_id(&pos, 1)?;
            if rest.len() != 1 {
                return Err(usage("usage: asb ws send [ID] TEXT|-"));
            }
            let text = if rest[0] == "-" {
                let mut raw = Vec::new();
                let _ = std::io::stdin().read_to_end(&mut raw);
                let t = universal_newlines(&String::from_utf8_lossy(&raw));
                t.strip_suffix('\n').map(String::from).unwrap_or(t)
            } else {
                rest[0].clone()
            };
            if text.len() > WS_MAX_SEND {
                return Err(die("a frame is limited to 4 MB", USAGE));
            }
            let client = broker::client()?;
            let r = ws_post(
                &client,
                "/v1/ws/send",
                &json!({"session": sid, "text": text}),
                40,
            )?;
            eprintln!(
                "sent ({} frames left, {}s left)",
                py_str(&r["frames_left"]),
                py_str(&r["expires_in"])
            );
            Ok(0)
        }
        "recv" => {
            let (pos, f) = ws_flags(&argv[1..], &["--wait", "--max"], &["--json"])?;
            let (sid, rest) = ws_session_id(&pos, 0)?;
            if !rest.is_empty() {
                return Err(usage(
                    "usage: asb ws recv [ID] [--wait S] [--max N] [--json]",
                ));
            }
            let wait = ws_number(fl(&f, "--wait").unwrap_or("0"), "--wait", 0, 25, false)?;
            let mx = ws_number(fl(&f, "--max").unwrap_or("256"), "--max", 1, 256, true)?;
            let client = broker::client()?;
            let body = json!({"session": sid, "wait": wait, "max": mx as i64});
            let r = ws_post(&client, "/v1/ws/recv", &body, wait as u64 + 20)?;
            if fl(&f, "--json").is_some() {
                println!("{}", json_dumps(&r, None));
                return Ok(0);
            }
            ws_print(&r["frames"]);
            ws_notes(&r);
            if truthy(&r["queued"]) {
                eprintln!("asb: {} more frames waiting", py_str(&r["queued"]));
            }
            if truthy(&r["closed"]) {
                closed_note(&r);
                return Ok(if truthy(&r["frames"]) { 0 } else { ENDED });
            }
            Ok(0)
        }
        "close" => {
            let (pos, _) = ws_flags(&argv[1..], &[], &[])?;
            let (sid, rest) = ws_session_id(&pos, 0)?;
            if !rest.is_empty() {
                return Err(usage("usage: asb ws close [ID]"));
            }
            let client = broker::client()?;
            let body = json!({"mode": "session_close", "session": sid});
            let (code, r) = broker::call(&client, "/v1/requests", Some(&body), 40)?;
            if code == 200 {
                println!("closed");
                return Ok(0);
            }
            let (rc, msg) = ws_rc(code, &r);
            Err(die(msg, rc))
        }
        _ => {
            let (pos, f) = ws_flags(argv, &["--ttl", "--max-frames", "--linger"], &["--close"])?;
            let has = |k: &str| fl(&f, k).is_some();
            if pos.len() == 2 && !(has("--linger") || has("--close")) {
                return open(&pos[0], &pos[1], &f);
            }
            if pos.len() > 1 || has("--ttl") || has("--max-frames") {
                return Err(usage(
                    "usage: asb ws NAME URL [--ttl 15m] [--max-frames N]  |  asb ws [ID] [--linger S] [--close]",
                ));
            }
            let (sid, _) = ws_session_id(&pos, 0)?;
            let linger = ws_number(fl(&f, "--linger").unwrap_or("2"), "--linger", 0, 300, false)?;
            pipe(&sid, linger, has("--close"))
        }
    }
}

fn open(name: &str, url: &str, f: &Flags) -> R {
    check_name(name, "NAME")?;
    if !(url.starts_with("ws://") || url.starts_with("wss://")) || url.chars().count() > 2048 {
        return Err(usage(
            "URL must be ws://host[:port]/path or wss://host[:port]/path",
        ));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("session"));
    payload.insert("kind".into(), json!("ws"));
    payload.insert("names".into(), json!([name]));
    payload.insert("url".into(), json!(url));
    if let Some(t) = fl(f, "--ttl") {
        let plain =
            t.is_ascii() && !t.is_empty() && t.len() <= 6 && t.bytes().all(|b| b.is_ascii_digit());
        let secs = if plain {
            t.parse().unwrap_or(0)
        } else {
            parse_ttl(t)?
        };
        payload.insert("ttl_s".into(), json!(secs));
    }
    if let Some(n) = fl(f, "--max-frames") {
        let v = ws_number(n, "--max-frames", 1, 100_000, true)?;
        payload.insert("max_frames".into(), json!(v as i64));
    }
    let r = obtain(
        payload,
        "waiting for the human to approve the WebSocket session...",
    )?;
    let s = &r["session"];
    println!("{}", py_str(&s["id"]));
    let frames = s.get("max_frames").unwrap_or(&s["max_calls"]);
    eprintln!(
        "asb: WebSocket session open for {}s (fixed: no extension or renewal), up to {} frames each way, {}; export {WS_ID_ENV}=ID to leave the id off the other commands",
        py_str(&s["expires_in"]),
        py_str(frames),
        py_str(&s["hosts"][0])
    );
    Ok(0)
}

struct Shared {
    rc: AtomicI32,
    msg: Mutex<Option<String>>,
    done: AtomicBool,
    stop: AtomicBool,
    last: Mutex<Instant>,
}

impl Shared {
    fn touch(&self) {
        *self.last.lock().unwrap() = Instant::now();
    }
    fn idle(&self) -> f64 {
        self.last.lock().unwrap().elapsed().as_secs_f64()
    }
}

/// Line relay: every stdin line is one text frame to the server; every text frame from the server is one stdout
/// line. Leaves after `linger` seconds without a frame in either direction once stdin has ended, or when the
/// server closes the connection.
fn pipe(sid: &str, linger: f64, close_at_end: bool) -> R {
    broker::ignore_sigpipe();
    let client = Arc::new(broker::client()?);
    let st = Arc::new(Shared {
        rc: AtomicI32::new(0),
        msg: Mutex::new(None),
        done: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        last: Mutex::new(Instant::now()),
    });
    {
        // Detached on purpose: it may sit in a blocking stdin read when the relay is over.
        let (client, st, sid) = (client.clone(), st.clone(), sid.to_string());
        std::thread::spawn(move || {
            writer(&client, &st, &sid);
            st.done.store(true, Ordering::SeqCst);
            st.touch();
        });
    }
    while !st.stop.load(Ordering::SeqCst) {
        let done = st.done.load(Ordering::SeqCst);
        let left = if done { linger - st.idle() } else { 10.0 };
        if done && left <= 0.0 {
            break;
        }
        let wait = if done { left.clamp(0.2, 10.0) } else { 10.0 };
        let body = json!({"session": sid, "wait": wait, "max": 256});
        let (code, r) = broker::call(&client, "/v1/ws/recv", Some(&body), 40)?;
        if code != 200 {
            let (rc, msg) = ws_rc(code, &r);
            return Err(die(msg, rc));
        }
        if truthy(&r["frames"]) {
            st.touch();
        }
        ws_print(&r["frames"]);
        ws_notes(&r);
        if truthy(&r["closed"]) {
            closed_note(&r);
            let rc = st.rc.load(Ordering::SeqCst);
            return Ok(if truthy(&r["frames"]) || rc == 0 {
                0
            } else {
                rc
            });
        }
    }
    if let Some(m) = st.msg.lock().unwrap().take() {
        eprintln!("asb: {m}");
    }
    let rc = st.rc.load(Ordering::SeqCst);
    if close_at_end && rc == 0 {
        let body = json!({"mode": "session_close", "session": sid});
        broker::call(&client, "/v1/requests", Some(&body), 40)?;
    }
    Ok(rc)
}

fn writer(client: &Client, st: &Shared, sid: &str) {
    let mut input = std::io::stdin().lock();
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match input.read_until(b'\n', &mut raw) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let chunk = universal_newlines(&String::from_utf8_lossy(&raw));
        for line in chunk.split('\n') {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                continue;
            }
            if st.stop.load(Ordering::SeqCst) {
                return;
            }
            match broker::call(
                client,
                "/v1/ws/send",
                Some(&json!({"session": sid, "text": line})),
                40,
            ) {
                // `call` already said why: the broker is unreachable
                Err(Die(rc)) => {
                    st.rc.store(rc, Ordering::SeqCst);
                    st.stop.store(true, Ordering::SeqCst);
                    return;
                }
                Ok((code, r)) => {
                    st.touch();
                    if code != 200 {
                        let (rc, msg) = ws_rc(code, &r);
                        st.rc.store(rc, Ordering::SeqCst);
                        *st.msg.lock().unwrap() = Some(msg);
                        st.stop.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            }
        }
    }
}
