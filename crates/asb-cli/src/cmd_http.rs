//! `asb http`: the broker makes the call itself (optionally inside a session or under a plan).

use crate::approval::{obtain, plan_id, run_plan_http};
use crate::exit::{die, HTTP_ERROR, R, USAGE};
use crate::pyfmt::{py_str, repr};
use crate::util::{check_name, die_help, read_body};
use serde_json::{json, Map, Value};
use std::io::Write;

/// `^[A-Za-z0-9_-]{32}\Z`
pub fn is_session_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn all_in(s: &str, min: usize, max: usize, ok: impl Fn(u8) -> bool) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(ok)
}

/// `\$(\.[A-Za-z0-9_-]{1,64}|\[[0-9]{1,4}\]){1,12}`
fn is_json_path(arg: &str) -> bool {
    let Some(mut rest) = arg.strip_prefix('$') else {
        return false;
    };
    let mut segments = 0;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('.') {
            let n = r
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
                .count();
            if !(1..=64).contains(&n) {
                return false;
            }
            rest = &r[n..];
        } else if let Some(r) = rest.strip_prefix('[') {
            let n = r.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=4).contains(&n) || r.as_bytes().get(n) != Some(&b']') {
                return false;
            }
            rest = &r[n + 1..];
        } else {
            return false;
        }
        segments += 1;
    }
    (1..=12).contains(&segments)
}

/// Validate a `--capture` expression locally (the broker checks again).
pub fn check_capture(text: &str) -> Result<String, crate::exit::Die> {
    let (name, expr) = text.split_once('=').unwrap_or((text, ""));
    let (kind, arg) = expr.split_once(':').unwrap_or((expr, ""));
    let name_ok = name.len() <= 32
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    let ok = name_ok
        && match kind {
            "header" => all_in(arg, 1, 64, |b| b.is_ascii_alphanumeric() || b == b'-'),
            "cookie" => all_in(arg, 1, 64, |b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
            }),
            "json" => is_json_path(arg),
            _ => false,
        };
    if !ok {
        return Err(die(
            "bad --capture: use NAME=header:X-CSRF-Token, NAME=cookie:NAME or NAME=json:$.a.b[0] (only dotted keys and array indexes)",
            USAGE,
        ));
    }
    Ok(text.to_string())
}

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// Python `str.strip()` for the ASCII whitespace that matters here.
fn strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace())
}

pub fn run(argv: &[String]) -> R {
    if argv.len() < 4 {
        return Err(die_help("http"));
    }
    check_name(&argv[1], "NAME")?;
    let names: Vec<Value> = argv[1]
        .split(',')
        .map(|n| Value::String(n.to_string()))
        .collect();
    let (method, url) = (&argv[2], &argv[3]);
    let mut rest = &argv[4..];
    let (mut headers, mut body): (Map<String, Value>, Vec<(&str, Value)>) = (Map::new(), vec![]);
    let (mut session, mut caps, mut plan): (Option<String>, Vec<String>, Option<String>) =
        (None, vec![], None);
    while let Some(flag) = rest.first() {
        let arg = rest.get(1);
        match (flag.as_str(), arg) {
            ("--session", Some(v)) => {
                if !is_session_id(v) {
                    return Err(die(
                        "--session needs the session id printed by `asb session open`",
                        USAGE,
                    ));
                }
                session = Some(v.clone());
            }
            ("--capture", Some(v)) => caps.push(check_capture(v)?),
            ("-H", Some(v)) => {
                let (k, val) = v.split_once(':').unwrap_or((v, ""));
                headers.insert(strip(k).to_string(), Value::String(strip(val).to_string()));
            }
            ("-d", Some(v)) => body = read_body(v)?,
            ("--plan", Some(v)) => plan = Some(v.clone()),
            _ => return Err(die(format!("unexpected argument {}", repr(flag)), USAGE)),
        }
        rest = &rest[2..];
    }
    if plan.is_none() && session.is_none() {
        plan = env_nonempty("ASB_PLAN")
            .map(|p| strip(&p).to_string())
            .filter(|p| !p.is_empty())
            .or(plan);
    }
    if plan.is_some() && session.is_some() {
        return Err(die(
            "a call uses a session or a plan, not both (unset ASB_SESSION or ASB_PLAN)",
            USAGE,
        ));
    }
    if plan.is_some() && !caps.is_empty() {
        return Err(die(
            "--capture needs --session; a plan call has no captured values",
            USAGE,
        ));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("http"));
    payload.insert("names".into(), Value::Array(names.clone()));

    let response = if let Some(plan) = plan {
        // a plan call: the method goes as typed in ASCII uppercase (the broker matches it exactly)
        let m = if method.is_ascii() {
            method.to_ascii_uppercase()
        } else {
            method.clone()
        };
        payload.insert("method".into(), Value::String(m));
        payload.insert("url".into(), Value::String(url.clone()));
        payload.insert("headers".into(), Value::Object(headers));
        for (k, v) in body {
            payload.insert(k.into(), v);
        }
        plan_id(&plan)?;
        run_plan_http(payload, &plan)?
    } else {
        if session.is_none() {
            if let Some(s) = env_nonempty("ASB_SESSION") {
                let s = strip(&s).to_string(); // keeps the id out of the process list
                if !is_session_id(&s) {
                    return Err(die(
                        "ASB_SESSION is not a session id (the one `asb session open` printed)",
                        USAGE,
                    ));
                }
                session = Some(s);
            }
        }
        if !caps.is_empty() && session.is_none() {
            return Err(die("--capture needs --session (or ASB_SESSION)", USAGE));
        }
        payload.insert("method".into(), Value::String(method.clone()));
        payload.insert("url".into(), Value::String(url.clone()));
        payload.insert("headers".into(), Value::Object(headers));
        for (k, v) in body {
            payload.insert(k.into(), v);
        }
        if let Some(s) = &session {
            if names.len() != 1 {
                return Err(die("a session uses exactly one credential", USAGE));
            }
            payload.insert("session".into(), Value::String(s.clone()));
            payload.insert("capture".into(), json!(caps));
        }
        let full = obtain(payload, "calling inside the session...")?;
        if let Some(si) = full.get("session").filter(|s| crate::pyfmt::truthy(s)) {
            let join = |v: &Value| {
                v.as_array()
                    .map(|a| a.iter().map(py_str).collect::<Vec<_>>().join(","))
                    .unwrap_or_default()
            };
            let mut note = format!(
                "asb: session: {} calls left, {}s left",
                py_str(&si["calls_left"]),
                py_str(&si["expires_in"])
            );
            if si.get("captured").is_some_and(crate::pyfmt::truthy) {
                note += &format!("; captured {}", join(&si["captured"]));
            }
            if si.get("missing").is_some_and(crate::pyfmt::truthy) {
                note += &format!("; NOT captured (not found) {}", join(&si["missing"]));
            }
            eprintln!("{note}");
        }
        full["http"].clone()
    };
    let status = response["status"].as_i64().unwrap_or(0);
    eprintln!("HTTP {status}");
    let mut out = std::io::stdout();
    let _ = out.write_all(py_str(&response["body"]).as_bytes());
    let _ = out.flush();
    Ok(if status < 400 { 0 } else { HTTP_ERROR })
}
