//! Talking to the broker for the CLI: where the config comes from, one JSON call, and the "ask a human and wait"
//! flow every approved command shares. The messages and exit codes are the Python client's.

use crate::exit::{die, Die, BROKER};
use crate::pyfmt::srv;
use asb_client::{Client, Config, Error};
use serde_json::Value;
use std::time::Duration;

pub const USER_AGENT: &str = "asb/1 (+https://github.com/rgregg/agent-secret-broker)";

/// `SECRET_BROKER_URL` and `SECRET_BROKER_KEY`, else `~/.config/secret-broker/client.json`.
pub fn config() -> Result<Config, Die> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (url, key) = match (env("SECRET_BROKER_URL"), env("SECRET_BROKER_KEY")) {
        (Some(u), Some(k)) => (u, k),
        _ => from_file().ok_or_else(|| {
            die(
                "no broker config (set SECRET_BROKER_URL/KEY or ~/.config/secret-broker/client.json)",
                crate::exit::USAGE,
            )
        })?,
    };
    Ok(Config {
        url: url.trim_end_matches('/').to_string(),
        key,
    })
}

fn from_file() -> Option<(String, String)> {
    let home = std::env::var("HOME").ok()?;
    let text = std::fs::read_to_string(format!("{home}/.config/secret-broker/client.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some((
        v.get("url")?.as_str()?.to_string(),
        v.get("key")?.as_str()?.to_string(),
    ))
}

pub fn client() -> Result<Client, Die> {
    Ok(Client::with_user_agent(config()?, USER_AGENT))
}

/// One call to the broker. A GET when `body` is `None`, else a POST. `Err` (after saying why) if the broker cannot
/// be reached; otherwise the HTTP status and parsed body, whatever the status.
pub fn call(
    client: &Client,
    path: &str,
    body: Option<&Value>,
    timeout_s: u64,
) -> Result<(u16, Value), Die> {
    client
        .json(path, body, Duration::from_secs(timeout_s))
        .map_err(|e| match e {
            Error::Unreachable(m) => die(format!("cannot reach broker: {m}"), BROKER),
            other => die(format!("cannot reach broker: {other}"), BROKER),
        })
}

/// The `error` text of a broker answer, cleaned for a terminal; `fallback` if it has none.
pub fn error_text(r: &Value, fallback: &str) -> String {
    match r.get("error") {
        Some(Value::String(s)) if !s.is_empty() => srv(s, 160),
        _ => srv(fallback, 160),
    }
}
