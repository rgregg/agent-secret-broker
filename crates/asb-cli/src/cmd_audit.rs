//! `asb audit`: what happened to my requests (the broker's redacted view of its audit log).

use crate::broker;
use crate::exit::{die, NOT_FOUND, R, USAGE};
use crate::pyfmt::{json_dumps, py_str, srv};
use crate::util::{die_help, urlencode};
use asb_client::Client;
use serde_json::Value;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

const FLAGS: [(&str, &str); 9] = [
    ("--request", "request"),
    ("--event", "event"),
    ("--secret", "secret"),
    ("--since", "since"),
    ("--until", "until"),
    ("--source", "source"),
    ("--limit", "limit"),
    ("--before", "before"),
    ("--after", "after"),
];
const SKIP: [&str; 4] = ["seq", "ts", "event", "request"];

/// One human line: time, event, short request id, then the event's fields.
fn audit_line(ev: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(map) = ev.as_object() {
        for (k, v) in map {
            if SKIP.contains(&k.as_str()) || v.is_null() {
                continue;
            }
            let text = match v {
                Value::Array(items) => items.iter().map(py_str).collect::<Vec<_>>().join(","),
                Value::Bool(b) => if *b { "yes" } else { "no" }.to_string(),
                other => py_str(other),
            };
            parts.push(format!("{k}={text}"));
        }
    }
    let ts: String = py_str(&ev["ts"]).chars().take(19).collect();
    // `(ev.get("request") or "-")[:8]`
    let request = if ev.get("request").is_some_and(crate::pyfmt::truthy) {
        py_str(&ev["request"])
    } else {
        "-".into()
    };
    let request: String = request.chars().take(8).collect();
    format!(
        "{ts}Z  {:<16} {:<8}  {}",
        py_str(&ev["event"]),
        request,
        parts.join(" ")
    )
}

fn audit_get(client: &Client, path: &str) -> Result<Value, crate::exit::Die> {
    let (code, r) = broker::call(client, path, None, 30)?;
    if code == 400 {
        return Err(die(
            srv(
                &r.get("error")
                    .map(py_str)
                    .unwrap_or_else(|| "bad request".into()),
                160,
            ),
            USAGE,
        ));
    }
    if code != 200 {
        return Err(die(
            broker::error_text(&r, &format!("broker returned {code}")),
            crate::exit::BROKER,
        ));
    }
    Ok(r)
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

pub fn run(argv: &[String]) -> R {
    if argv.first().map(String::as_str) == Some("verify") {
        if argv.len() > 1 {
            return Err(die_help("audit"));
        }
        let client = broker::client()?;
        let r = audit_get(&client, "/v1/audit/verify")?;
        if crate::pyfmt::truthy(&r["ok"]) {
            println!(
                "audit log ok: {} events, hash chain intact",
                py_str(&r["events"])
            );
            return Ok(0);
        }
        eprintln!(
            "audit log BROKEN: chain fails at seq {} ({} events checked)",
            py_str(&r["first_bad_seq"]),
            py_str(&r["events"])
        );
        return Ok(NOT_FOUND);
    }
    let (mut flags, mut as_json, mut tail, mut i): (Vec<(String, String)>, bool, bool, usize) =
        (vec![], false, false, 0);
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--json" {
            as_json = true;
        } else if a == "--tail" {
            tail = true;
        } else if let (Some((_, name)), true) =
            (FLAGS.iter().find(|(f, _)| *f == a), i + 1 < argv.len())
        {
            set(&mut flags, name, &argv[i + 1]);
            i += 1;
        } else {
            return Err(die(
                format!(
                    "unexpected argument {}\n{}",
                    crate::pyfmt::repr(a),
                    crate::text_gen::help("audit").unwrap_or_default()
                ),
                USAGE,
            ));
        }
        i += 1;
    }
    if tail && (has(&flags, "request") || has(&flags, "before") || has(&flags, "after")) {
        return Err(die(
            "--tail follows the whole log; combine it with --event/--secret/--source only",
            USAGE,
        ));
    }
    if tail && !has(&flags, "limit") {
        flags.push(("limit".into(), "20".into()));
    }
    let client = broker::client()?;
    let qs = |extra: &[(&str, &str)]| {
        let mut all = flags.clone();
        for (k, v) in extra {
            set(&mut all, k, v);
        }
        format!("/v1/audit?{}", urlencode(&all))
    };
    if !tail {
        let r = audit_get(&client, &qs(&[]))?;
        let events = r["events"].as_array().cloned().unwrap_or_default();
        if as_json {
            println!("{}", json_dumps(&r, Some(2)));
        } else {
            let ordered: Vec<&Value> =
                if get(&flags, "request").is_some_and(|v| !v.is_empty()) || has(&flags, "after") {
                    events.iter().collect()
                } else {
                    events.iter().rev().collect()
                };
            for ev in ordered {
                println!("{}", audit_line(ev));
            }
            let next = &r["next"];
            if crate::pyfmt::truthy(&r["truncated"]) || !next.is_null() {
                let arrow = if has(&flags, "after")
                    || get(&flags, "request").is_some_and(|v| !v.is_empty())
                {
                    "--after"
                } else {
                    "--before"
                };
                if next.is_null() {
                    eprintln!("asb: older history is not indexed");
                } else {
                    eprintln!(
                        "asb: more events available; continue with {arrow} {}",
                        py_str(next)
                    );
                }
            }
        }
        return Ok(if events.is_empty() { NOT_FOUND } else { 0 });
    }
    // Ctrl-C ends the follow quietly with exit 0, as `KeyboardInterrupt` does in the Python client
    // SAFETY: the handler only stores to an atomic flag.
    unsafe { libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t) };
    let mut last: Option<Value> = None;
    let mut out = std::io::stdout();
    loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let (r, newest_first) = match &last {
            None => (audit_get(&client, &qs(&[]))?, true),
            Some(seq) => (
                audit_get(
                    &client,
                    &qs(&[("after", &py_str(seq)), ("order", "asc"), ("limit", "500")]),
                )?,
                false,
            ),
        };
        let mut events = r["events"].as_array().cloned().unwrap_or_default();
        if newest_first {
            events.reverse();
        }
        for ev in &events {
            let _ = writeln!(
                out,
                "{}",
                if as_json {
                    json_dumps(ev, None)
                } else {
                    audit_line(ev)
                }
            );
            let _ = out.flush();
            last = Some(ev["seq"].clone());
        }
        for _ in 0..40 {
            // 2 s in slices, so Ctrl-C is noticed promptly (a plain sleep would resume after the signal)
            if INTERRUPTED.load(Ordering::SeqCst) {
                return Ok(0);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn has(flags: &[(String, String)], key: &str) -> bool {
    flags.iter().any(|(n, _)| n == key)
}

fn get(flags: &[(String, String)], key: &str) -> Option<String> {
    flags.iter().find(|(n, _)| n == key).map(|(_, v)| v.clone())
}

fn set(flags: &mut Vec<(String, String)>, key: &str, value: &str) {
    match flags.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value.to_string(),
        None => flags.push((key.to_string(), value.to_string())),
    }
}
