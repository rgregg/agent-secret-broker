//! The "ask a human and wait" flow every approved command shares, and the plan vocabulary `http --plan` needs.

use crate::broker;
use crate::exit::{die, Die, BROKER, DENIED, ENDED, EXPIRED, REFUSED, SLOW_DOWN, USAGE};
use crate::pyfmt::{py_str, safe_text, srv};
use crate::util::source;
use asb_client::Client;
use serde_json::{json, Map, Value};
use std::time::{Duration, Instant};

pub fn status_exit(status: &str) -> i32 {
    match status {
        "denied" => DENIED,
        "expired" => EXPIRED,
        _ => BROKER,
    }
}

/// Exit for a broker answer that carries a session error code; returns normally if it has none.
pub fn session_die(r: &Value) -> Result<(), Die> {
    match r.get("code").and_then(Value::as_str) {
        Some("session_unknown" | "session_expired") => {
            Err(die(broker::error_text(r, "session ended"), ENDED))
        }
        Some("session_refused") => Err(die(broker::error_text(r, "session call refused"), REFUSED)),
        _ => Ok(()),
    }
}

/// POST `payload` as a request, wait for the human, and return the approved answer.
pub fn obtain(payload: Map<String, Value>, waiting: &str) -> Result<Value, Die> {
    let client = broker::client()?;
    obtain_with(&client, payload, waiting)
}

pub fn obtain_with(
    client: &Client,
    mut payload: Map<String, Value>,
    waiting: &str,
) -> Result<Value, Die> {
    payload.insert("source".into(), Value::String(source()));
    let (code, r) = broker::call(client, "/v1/requests", Some(&Value::Object(payload)), 40)?;
    if code != 202 {
        session_die(&r)?;
        return Err(die(
            broker::error_text(&r, &format!("broker returned {code}")),
            BROKER,
        ));
    }
    let status = py_str(&r["status"]);
    if matches!(status.as_str(), "denied" | "expired" | "failed") {
        let why = broker::error_text(&r, &status);
        return Err(die(why, status_exit(&status)));
    }
    eprintln!("asb: {waiting}");
    let expires = r["expires_in"].as_f64().unwrap_or(0.0).max(0.0);
    let deadline = Instant::now() + Duration::from_secs_f64(expires + 15.0);
    let id = py_str(&r["id"]);
    while Instant::now() < deadline {
        let (_, r2) = broker::call(client, &format!("/v1/requests/{id}?wait=25"), None, 40)?;
        let status = r2.get("status").map(py_str).unwrap_or_default();
        if status == "approved" {
            return Ok(r2);
        }
        if matches!(
            status.as_str(),
            "denied" | "expired" | "failed" | "released"
        ) {
            let err = match r2.get("error") {
                Some(e) if crate::pyfmt::truthy(e) => format!(": {}", srv(&py_str(e), 160)),
                _ => String::new(),
            };
            return Err(die(format!("request {status}{err}"), status_exit(&status)));
        }
    }
    Err(die("timed out waiting for approval", EXPIRED))
}

// ---- plan vocabulary ------------------------------------------------------------------------------

const PLAN_KINDS: [&str; 5] = ["ended", "exhausted", "closed", "revoked", "unknown"];

/// A plan id from an argument or ASB_PLAN: 32 lowercase hex digits, else a usage error.
pub fn plan_id(v: &str) -> Result<String, Die> {
    if v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(v.to_string())
    } else {
        Err(die(
            "a plan id is 32 lowercase hex digits (printed by `asb plan submit`)",
            USAGE,
        ))
    }
}

/// Exit for a broker answer that is not success, in the plan vocabulary. Only fixed words from the broker are printed,
/// and only as printable ASCII.
pub fn plan_refusal(code: u16, r: &Value) -> Die {
    let empty = json!({});
    let r = if r.is_object() { r } else { &empty };
    let err = srv(
        &r.get("error")
            .map(py_str)
            .unwrap_or_else(|| format!("broker returned {code}")),
        160,
    );
    let error = r.get("error").and_then(Value::as_str);
    if code == 404 && error == Some("plan not usable") {
        let kind = r
            .get("kind")
            .and_then(Value::as_str)
            .filter(|k| PLAN_KINDS.contains(k))
            .unwrap_or("unknown");
        let hint = match kind {
            "ended" => "its deadline passed",
            "exhausted" => "every use was spent",
            "closed" => "it was closed",
            "revoked" => "a human revoked it",
            _ => "it is unknown here, was never approved, or the broker restarted",
        };
        return die(
            format!("plan not usable (kind: {kind}): {hint}. Stop; submit a new plan, which needs the human again."),
            ENDED,
        );
    }
    if code == 429 && error == Some("outside plan") {
        let retry = r.get("retry_after_s").and_then(Value::as_i64).unwrap_or(1);
        let reason = safe_text(
            &r.get("reason")
                .map(py_str)
                .unwrap_or_else(|| "limit".into()),
            160,
        );
        return die(
            format!("slow down: {reason}; retry after {retry} s"),
            SLOW_DOWN,
        );
    }
    if code == 403 && error == Some("outside plan") {
        let why = match r.get("why") {
            Some(w) if crate::pyfmt::truthy(w) => format!(", why: {}", safe_text(&py_str(w), 160)),
            _ => String::new(),
        };
        let reason = safe_text(
            &r.get("reason")
                .map(py_str)
                .unwrap_or_else(|| "no_rule".into()),
            160,
        );
        return die(
            format!("refused: this call is outside the plan (reason: {reason}{why}). No prompt was sent. Make the call without --plan to ask the human."),
            REFUSED,
        );
    }
    die(err, BROKER)
}

/// POST an http request that names a plan, and return the response object.
pub fn run_plan_http(mut payload: Map<String, Value>, plan: &str) -> Result<Value, Die> {
    let client = broker::client()?;
    payload.insert("plan".into(), Value::String(plan_id(plan)?));
    payload.insert("source".into(), Value::String(source()));
    let (code, r) = broker::call(&client, "/v1/requests", Some(&Value::Object(payload)), 60)?;
    if code != 202 {
        return Err(plan_refusal(code, &r));
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let id = py_str(&r["id"]);
    while Instant::now() < deadline {
        let (_, r2) = broker::call(&client, &format!("/v1/requests/{id}?wait=25"), None, 40)?;
        let status = r2.get("status").map(py_str).unwrap_or_default();
        if status == "approved" {
            return Ok(r2["http"].clone());
        }
        if matches!(
            status.as_str(),
            "denied" | "expired" | "failed" | "released"
        ) {
            let err = match r2.get("error") {
                Some(e) if crate::pyfmt::truthy(e) => format!(": {}", srv(&py_str(e), 160)),
                _ => String::new(),
            };
            return Err(die(format!("request {status}{err}"), status_exit(&status)));
        }
    }
    Err(die("timed out waiting for the call", EXPIRED))
}
