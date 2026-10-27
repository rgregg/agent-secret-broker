//! `asb guidance propose|status`: propose risk guidance for the human to review.

use crate::approval::status_exit;
use crate::broker;
use crate::exit::{die, EXPIRED, R, USAGE};
use crate::pyfmt::{json_dumps, py_str, srv};
use crate::util::{check_name, die_help, source, universal_newlines};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::time::{Duration, Instant};

const MAX_GUIDANCE_BODY: usize = 100 * 1024; // what the broker accepts for one proposal

fn is_status_id(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Entries from `propose` arguments: FILE|- (a JSON list or `{"entries": [...]}`) or `--from-dir DIR` (NAME.txt files).
fn entries(argv: &[String]) -> Result<Value, crate::exit::Die> {
    if argv.len() == 2 && argv[0] == "--from-dir" {
        let mut files: Vec<String> = match std::fs::read_dir(&argv[1]) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|f| f.ends_with(".txt"))
                .collect(),
            Err(e) => {
                return Err(die(
                    format!("cannot read {}: {}", argv[1], crate::util::os_error(&e)),
                    USAGE,
                ))
            }
        };
        files.sort();
        let mut out = Vec::new();
        for f in files {
            let name = &f[..f.len() - 4];
            check_name(name, "NAME")?;
            let text = std::fs::read(std::path::Path::new(&argv[1]).join(&f))
                .map_err(|e| {
                    die(
                        format!("cannot read {f}: {}", crate::util::os_error(&e)),
                        USAGE,
                    )
                })
                .and_then(|b| {
                    String::from_utf8(b)
                        .map_err(|_| die(format!("cannot read {f}: not valid UTF-8"), USAGE))
                })?;
            out.push(json!({"name": name, "text": universal_newlines(&text)}));
        }
        if out.is_empty() {
            return Err(die(format!("no NAME.txt files in {}", argv[1]), USAGE));
        }
        return Ok(Value::Array(out));
    }
    if argv.len() != 1 || (argv[0].starts_with('-') && argv[0] != "-") {
        return Err(die_help("guidance"));
    }
    let raw = if argv[0] == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map(|_| s)
    } else {
        std::fs::read_to_string(&argv[0])
    };
    let data: Value = raw
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str(&universal_newlines(&t)).map_err(|e| e.to_string()))
        .map_err(|e| die(format!("cannot read the proposal: {e}"), USAGE))?;
    let entries = if data.is_object() {
        data.get("entries").cloned().unwrap_or(Value::Null)
    } else {
        data
    };
    match &entries {
        Value::Array(a) if !a.is_empty() => Ok(entries),
        _ => Err(die(
            "the proposal must be a list of {\"name\", \"text\"} or {\"entries\": [...]}",
            USAGE,
        )),
    }
}

fn print_guidance(res: &Value) {
    for k in ["applied", "denied", "failed"] {
        let names = res
            .get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().map(py_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        println!(
            "{k}: {}",
            if names.is_empty() {
                "-".to_string()
            } else {
                names
            }
        );
    }
}

/// Exit code for a finished proposal: 0 if something was applied.
fn exit_for(r: &Value) -> i32 {
    let status = r.get("status").map(py_str).unwrap_or_default();
    if status == "approved" {
        let applied = r
            .get("guidance")
            .and_then(|g| g.get("applied"))
            .is_some_and(crate::pyfmt::truthy);
        return if applied { 0 } else { crate::exit::BROKER };
    }
    status_exit(&status)
}

pub fn run(argv: &[String]) -> R {
    if argv.first().map(String::as_str) == Some("status") {
        if argv.len() != 2 || !is_status_id(&argv[1]) {
            return Err(die_help("guidance"));
        }
        let client = broker::client()?;
        let (code, r) = broker::call(
            &client,
            &format!("/v1/requests/{}?wait=0", argv[1]),
            None,
            15,
        )?;
        if code != 200 {
            return Err(die(
                broker::error_text(&r, &format!("broker returned {code}")),
                crate::exit::BROKER,
            ));
        }
        let status = r.get("status").map(py_str).unwrap_or_default();
        if !["approved", "denied", "expired", "failed"].contains(&status.as_str()) {
            println!("pending"); // undecided, or being applied: not an error
            return Ok(0);
        }
        print_guidance(r.get("guidance").unwrap_or(&Value::Null));
        return Ok(exit_for(&r));
    }
    if argv.first().map(String::as_str) != Some("propose") {
        return Err(die_help("guidance"));
    }
    let entries = entries(&argv[1..])?;
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("guidance"));
    payload.insert("entries".into(), entries);
    payload.insert("source".into(), json!(source()));
    let payload = Value::Object(payload);
    if json_dumps(&payload, None).len() > MAX_GUIDANCE_BODY {
        return Err(die(
            format!("the proposal is larger than {MAX_GUIDANCE_BODY} bytes"),
            USAGE,
        ));
    }
    let client = broker::client()?;
    let (code, r) = broker::call(&client, "/v1/requests", Some(&payload), 40)?;
    if code != 202 {
        return Err(die(
            broker::error_text(&r, &format!("broker returned {code}")),
            crate::exit::BROKER,
        ));
    }
    eprintln!("asb: proposal {} sent", py_str(&r["id"]));
    let status = py_str(&r["status"]);
    if ["denied", "expired", "failed"].contains(&status.as_str()) {
        let why = r
            .get("error")
            .filter(|e| crate::pyfmt::truthy(e))
            .map(|e| srv(&py_str(e), 160))
            .unwrap_or_else(|| srv(&status, 160));
        return Err(die(why, status_exit(&status)));
    }
    eprintln!("asb: waiting for approval on your phone... review each entry on the approval page (the human ticks the ones to apply)");
    let deadline = Instant::now()
        + Duration::from_secs_f64(r["expires_in"].as_f64().unwrap_or(0.0).max(0.0) + 15.0);
    let id = py_str(&r["id"]);
    while Instant::now() < deadline {
        let (_, r2) = broker::call(&client, &format!("/v1/requests/{id}?wait=25"), None, 40)?;
        let s = r2.get("status").map(py_str).unwrap_or_default();
        if ["approved", "denied", "expired", "failed"].contains(&s.as_str()) {
            print_guidance(r2.get("guidance").unwrap_or(&Value::Null));
            return Ok(exit_for(&r2));
        }
    }
    Err(die("timed out waiting for approval", EXPIRED))
}
