//! The command dispatcher, in the same order and with the same messages as `main()` in client/asb.

use crate::broker;
use crate::exit::{die, Die, BROKER, NOT_FOUND, R, USAGE};
use crate::pyfmt::{json_dumps, py_str, quote, repr, truthy};
use crate::text_gen::{self, DOC, GUIDE, HELP_TOPICS};
use serde_json::Value;

pub fn run(argv: &[String]) -> i32 {
    match dispatch(argv) {
        Ok(code) => code,
        Err(Die(code)) => code,
    }
}

fn dispatch(argv: &[String]) -> R {
    if argv.is_empty() || argv[0] == "-h" || argv[0] == "--help" {
        println!("{DOC}");
        return Ok(0);
    }
    let cmd = argv[0].as_str();
    if cmd == "guide" {
        println!("{GUIDE}");
        return Ok(0);
    }
    if cmd == "help" {
        return help(argv.get(1).map(String::as_str));
    }
    if cmd != "run" && text_gen::help(cmd).is_some() {
        // Flags are never credential names or values: --help anywhere before an http body/header value, or
        // anywhere for the commands without free text (and for `sudo`, only before its `--`).
        let rest = &argv[1..];
        let scan: &[String] = if cmd == "http" {
            &rest[..rest.len().min(3)]
        } else if cmd == "sudo" {
            &rest[..rest.iter().position(|a| a == "--").unwrap_or(rest.len())]
        } else {
            rest
        };
        if scan.iter().any(|a| a == "-h" || a == "--help") {
            println!("{}", text_gen::help(cmd).unwrap_or_default());
            return Ok(0);
        }
    }
    match cmd {
        "list" => list(&argv[1..]),
        "status" => status(&argv[1..]),
        "which" => which(argv),
        _ if argv.iter().any(|a| a == "--") || is_known(cmd) => unported(cmd),
        _ => Err(die(
            format!(
                "unknown command {}.\ncommands: list, which, status, audit, http, session, ws, plan, sudo, store, update, request-credential, guidance, enroll, ssh-agent, fingerprint, help, guide; or: asb NAME -- command\nstart with `asb guide`",
                repr(cmd)
            ),
            USAGE,
        )),
    }
}

fn is_known(cmd: &str) -> bool {
    [
        "agent-setup",
        "plan",
        "ssh-agent",
        "store",
        "update",
        "request-credential",
        "session",
        "ws",
        "sudo",
        "enroll",
        "fingerprint",
        "audit",
        "guidance",
        "http",
    ]
    .contains(&cmd)
}

/// A command the Rust CLI has not taken over yet (see docs/proposals/rust-cli.md for the order).
fn unported(cmd: &str) -> R {
    let what = if is_known(cmd) {
        format!("`asb {cmd}`")
    } else {
        "running a command with a credential".to_string()
    };
    Err(die(
        format!("{what} is not in the Rust CLI yet; use the Python client/asb"),
        USAGE,
    ))
}

fn help(topic: Option<&str>) -> R {
    match topic {
        None => println!("{DOC}"),
        Some(t) => match text_gen::help(t) {
            Some(text) => println!("{text}"),
            None => {
                let topics: Vec<&str> = HELP_TOPICS
                    .iter()
                    .copied()
                    .filter(|k| *k != "run")
                    .collect();
                return Err(die(
                    format!("no help for {}; commands: {}", repr(t), topics.join(", ")),
                    USAGE,
                ));
            }
        },
    }
    Ok(0)
}

/// `die(HELP[topic])`: the help text becomes the error message.
fn die_help(topic: &str) -> Die {
    die(text_gen::help(topic).unwrap_or_default(), USAGE)
}

fn broker_error(code: u16, r: &Value) -> Die {
    die(
        broker::error_text(r, &format!("broker returned {code}")),
        BROKER,
    )
}

fn list(rest: &[String]) -> R {
    let json = match rest {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return Err(die_help("list")),
    };
    let client = broker::client()?;
    let (code, r) = broker::call(&client, "/v1/secrets", None, 40)?;
    if code != 200 {
        return Err(broker_error(code, &r));
    }
    let secrets = r
        .get("secrets")
        .and_then(Value::as_array)
        .ok_or_else(|| die("the broker's answer has no secrets list", BROKER))?;
    if json {
        println!("{}", json_dumps(&r["secrets"], Some(2)));
        return Ok(0);
    }
    if secrets.is_empty() {
        eprintln!("asb: no credentials are configured");
        return Ok(NOT_FOUND);
    }
    eprintln!("NAME\tVARS\tHOSTS   (columns; use --json for scripts)");
    for s in secrets {
        println!(
            "{}\t{}\t{}",
            py_str(&s["name"]),
            join(&s["vars"]),
            join(&s["allowed_hosts"])
        );
    }
    Ok(0)
}

/// `','.join(x)` for a JSON list of strings.
fn join(v: &Value) -> String {
    v.as_array()
        .map(|a| a.iter().map(py_str).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

fn status(rest: &[String]) -> R {
    let json = match rest {
        [] => false,
        [flag] if flag == "--json" => true,
        _ => return Err(die_help("status")),
    };
    let client = broker::client()?;
    let (code, r) = broker::call(&client, "/v1/status", None, 15)?;
    if code != 200 {
        return Err(broker_error(code, &r));
    }
    if json {
        println!("{}", json_dumps(&r, Some(2)));
        return Ok(0);
    }
    let (c, b) = (&r["catalog"], &r["backend"]);
    let uptime = r["uptime_s"].as_f64().unwrap_or(0.0) as i64;
    let (d, rem) = (uptime / 86400, uptime % 86400);
    let (h, rem) = (rem / 3600, rem % 3600);
    let up = format!(
        "{}{}h {}m",
        if d > 0 {
            format!("{d}d ")
        } else {
            String::new()
        },
        h,
        rem / 60
    );
    println!(
        "version:  {} (built {})",
        py_str(&r["version"]),
        py_str(&r["build_time"])
    );
    println!("uptime:   {} (since {})", up, py_str(&r["started_at"]));
    let loaded = if truthy(&c["loaded_at"]) {
        py_str(&c["loaded_at"])
    } else {
        "never".to_string()
    };
    println!(
        "catalog:  {} secrets, {} invalid, {} adopted (loaded {})",
        py_str(&c["count"]),
        py_str(&c["invalid"]),
        py_str(&c["adopted"]),
        loaded
    );
    println!(
        "backend:  {} {}",
        py_str(&b["type"]),
        if truthy(&b["ok"]) { "ok" } else { "FAILING" }
    );
    let notifiers = join(&r["notifiers"]);
    println!(
        "notify:   {}",
        if notifiers.is_empty() {
            "none".to_string()
        } else {
            notifiers.replace(',', ", ")
        }
    );
    Ok(0)
}

fn which(argv: &[String]) -> R {
    if argv.len() != 2 {
        return Err(die_help("which"));
    }
    let target = &argv[1];
    check_name(target, "HOST")?;
    let client = broker::client()?;
    let param = if target.contains("://") {
        "url"
    } else {
        "host"
    };
    let (code, r) = broker::call(
        &client,
        &format!("/v1/secrets?{param}={}", quote(target)),
        None,
        40,
    )?;
    if code != 200 {
        return Err(broker_error(code, &r));
    }
    let secrets = r["secrets"].as_array().cloned().unwrap_or_default();
    for s in &secrets {
        println!("{}\t{}", py_str(&s["name"]), join(&s["vars"]));
    }
    if secrets.is_empty() {
        eprintln!(
            "asb: no credential available for {}. See `asb list`, or add one with `asb store` (`asb guide`).",
            py_str(&r["host"])
        );
        return Ok(NOT_FOUND);
    }
    Ok(0)
}

/// A flag where a name should be is a mistake worth saying so about.
pub fn check_name(name: &str, what: &str) -> Result<(), Die> {
    if name.starts_with('-') {
        return Err(die(
            format!("{what} {} looks like a flag, not a credential name (see `asb list`; `asb help` for usage)", repr(name)),
            USAGE,
        ));
    }
    Ok(())
}
