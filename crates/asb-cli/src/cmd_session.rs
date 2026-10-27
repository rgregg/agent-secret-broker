//! `asb session open|close|status`: a time-boxed multi-call permission for login-and-cookie flows.

use crate::approval::{obtain, session_die};
use crate::broker;
use crate::cmd_http::is_session_id;
use crate::exit::{die, BROKER, R, USAGE};
use crate::pyfmt::{py_str, repr};
use crate::util::{check_name, die_help};
use serde_json::{json, Map, Value};

const SESSION_METHODS: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

/// `^[0-9]{1,6}[smh]$` to seconds.
fn parse_ttl(text: &str) -> Result<u64, crate::exit::Die> {
    let bad = || die("--ttl must be a number with a unit: 90s, 15m or 1h", USAGE);
    let unit = text.chars().last().ok_or_else(bad)?;
    let digits = &text[..text.len() - 1];
    if !(1..=6).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = digits.parse().map_err(|_| bad())?;
    match unit {
        's' => Ok(n),
        'm' => Ok(n * 60),
        'h' => Ok(n * 3600),
        _ => Err(bad()),
    }
}

fn join(v: &Value) -> String {
    v.as_array()
        .map(|a| a.iter().map(py_str).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

pub fn run(argv: &[String]) -> R {
    let help = || crate::text_gen::help("session").unwrap_or_default();
    let sub = match argv.first().map(String::as_str) {
        Some(s @ ("open" | "close" | "status")) => s,
        _ => return Err(die_help("session")),
    };
    let rest = &argv[1..];
    if sub == "close" || sub == "status" {
        if rest.len() != 1 || !is_session_id(&rest[0]) {
            return Err(die(
                format!("usage: asb session {sub} ID\n{}", help()),
                USAGE,
            ));
        }
        let client = broker::client()?;
        let (code, r) = if sub == "close" {
            let body = json!({"mode": "session_close", "session": rest[0]});
            let (code, r) = broker::call(&client, "/v1/requests", Some(&body), 40)?;
            if code == 200 {
                println!("closed");
                return Ok(0);
            }
            (code, r)
        } else {
            let (code, r) = broker::call(&client, &format!("/v1/sessions/{}", rest[0]), None, 15)?;
            if code == 200 {
                println!(
                    "time left: {}s, calls left: {} of {}",
                    py_str(&r["expires_in"]),
                    py_str(&r["calls_left"]),
                    py_str(&r["max_calls"])
                );
                println!(
                    "hosts: {}  methods: {}",
                    join(&r["hosts"]),
                    join(&r["methods"])
                );
                return Ok(0);
            }
            (code, r)
        };
        session_die(&r)?;
        return Err(die(
            broker::error_text(&r, &format!("broker returned {code}")),
            BROKER,
        ));
    }
    if rest.is_empty() {
        return Err(die_help("session"));
    }
    check_name(&rest[0], "NAME")?;
    let name = &rest[0];
    let rest = &rest[1..];
    let (mut opts, mut hosts): (Vec<(String, String)>, Vec<String>) = (vec![], vec![]);
    let mut i = 0;
    while i < rest.len() {
        let k = rest[i].as_str();
        if !["--for", "--host", "--methods", "--ttl", "--max-calls"].contains(&k)
            || i + 1 >= rest.len()
        {
            return Err(die(
                format!("unexpected argument {}\n{}", repr(k), help()),
                USAGE,
            ));
        }
        let v = &rest[i + 1];
        if k == "--host" {
            hosts.extend(v.split(',').filter(|h| !h.is_empty()).map(String::from));
        } else if opts.iter().any(|(key, _)| key == k) {
            return Err(die(format!("{k} given twice"), USAGE));
        } else {
            opts.push((k.to_string(), v.clone()));
        }
        i += 2;
    }
    let get = |k: &str| {
        opts.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.as_str())
    };
    let purpose = get("--for").unwrap_or("");
    if purpose.trim().is_empty() {
        return Err(die(
            format!("--for \"what it is for\" is required\n{}", help()),
            USAGE,
        ));
    }
    if purpose.chars().count() > 300 {
        return Err(die("--for is limited to 300 characters", USAGE));
    }
    if hosts.is_empty() {
        return Err(die(
            format!(
                "at least one --host is required (a session is limited to specific hosts)\n{}",
                help()
            ),
            USAGE,
        ));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("session"));
    payload.insert("names".into(), json!([name]));
    payload.insert("purpose".into(), json!(purpose));
    payload.insert("hosts".into(), json!(hosts));
    if let Some(m) = get("--methods") {
        let methods: Vec<String> = m
            .split(',')
            .map(|x| x.trim().to_uppercase())
            .filter(|x| !x.is_empty())
            .collect();
        if methods.is_empty()
            || methods
                .iter()
                .any(|x| !SESSION_METHODS.contains(&x.as_str()))
        {
            return Err(die(
                format!("--methods must be some of {}", SESSION_METHODS.join(",")),
                USAGE,
            ));
        }
        payload.insert("methods".into(), json!(methods));
    }
    if let Some(t) = get("--ttl") {
        payload.insert("ttl_s".into(), json!(parse_ttl(t)?));
    }
    if let Some(n) = get("--max-calls") {
        let ok = n.is_ascii() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit());
        let value = if ok {
            n.parse::<u64>().ok().filter(|v| (1..=100_000).contains(v))
        } else {
            None
        };
        let Some(value) = value else {
            return Err(die(
                "--max-calls must be a whole number of at least 1",
                USAGE,
            ));
        };
        payload.insert("max_calls".into(), json!(value));
    }
    let r = obtain(payload, "waiting for the human to approve the session...")?;
    let s = &r["session"];
    println!("{}", py_str(&s["id"]));
    eprintln!(
        "asb: session open for {}s (fixed: no extension or renewal), up to {} calls, hosts {}, methods {}",
        py_str(&s["expires_in"]),
        py_str(&s["max_calls"]),
        join(&s["hosts"]),
        join(&s["methods"])
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::parse_ttl;

    #[test]
    fn ttl_is_a_number_with_a_unit() {
        assert_eq!(parse_ttl("90s").unwrap(), 90);
        assert_eq!(parse_ttl("15m").unwrap(), 900);
        assert_eq!(parse_ttl("1h").unwrap(), 3600);
        for bad in ["", "15", "m", "1d", "1234567s", "-5m", "1.5h", " 5m"] {
            assert!(parse_ttl(bad).is_err(), "{bad:?}");
        }
    }
}
