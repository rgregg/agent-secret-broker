//! `asb store`, `asb update` and `asb request-credential`: putting a credential in the vault, or asking the human to.

use crate::approval::obtain;
use crate::exit::{die, R, USAGE};
use crate::pyfmt::{py_str, repr};
use crate::util::{check_name, die_help, flag, parse_flags, read_value};
use serde_json::{json, Map, Value};

pub fn store_or_update(argv: &[String]) -> R {
    if argv.len() < 2 {
        return Err(die_help(&argv[0]));
    }
    let ssh = argv[2..].iter().any(|a| a == "--ssh") && argv[0] == "store";
    let argv: Vec<String> = if ssh {
        argv.iter().filter(|a| *a != "--ssh").cloned().collect()
    } else {
        argv.to_vec()
    };
    check_name(&argv[1], "NAME")?;
    let op = if argv[0] == "store" {
        "create"
    } else {
        "update"
    };
    let allowed: &[(&str, &str)] = if op == "update" {
        &[("--var", "var")]
    } else {
        &[
            ("--field", "field"),
            ("--item", "item"),
            ("--var", "var"),
            ("--hosts", "hosts"),
        ]
    };
    let f = parse_flags(&argv[2..], allowed)?;
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("store"));
    payload.insert("names".into(), json!([argv[1]]));
    payload.insert("op".into(), json!(op));
    payload.insert("value".into(), Value::String(read_value()?));
    if ssh {
        payload.insert("ssh".into(), json!(true));
    }
    for k in ["field", "item", "var"] {
        if let Some(v) = flag(&f, k).filter(|v| !v.is_empty()) {
            payload.insert(k.into(), json!(v));
        }
    }
    if op == "create" {
        let hosts = flag(&f, "hosts").unwrap_or("");
        if hosts.is_empty() && !ssh {
            return Err(die(
                format!(
                    "store needs --hosts (the hosts this credential may be used against)\n{}",
                    crate::text_gen::help("store").unwrap_or_default()
                ),
                USAGE,
            ));
        }
        let list: Vec<&str> = hosts.split(',').filter(|h| !h.is_empty()).collect();
        payload.insert("allowed_hosts".into(), json!(list));
    }
    let r = obtain(payload, "waiting for approval on your phone...")?;
    let s = &r["stored"];
    println!(
        "stored: {} ({}) -> item {} field {}",
        py_str(&s["name"]),
        py_str(&s["op"]),
        repr(&py_str(&s["item"])),
        py_str(&s["field"])
    );
    Ok(0)
}

pub fn request_credential(argv: &[String]) -> R {
    let help = || crate::text_gen::help("request-credential").unwrap_or_default();
    if argv.is_empty() {
        return Err(die_help("request-credential"));
    }
    check_name(&argv[0], "NAME")?;
    let rest = &argv[1..];
    let (mut opts, mut hosts): (Vec<(String, String)>, Vec<String>) = (vec![], vec![]);
    let mut i = 0;
    while i < rest.len() {
        let k = rest[i].as_str();
        if !["--kind", "--for", "--host", "--var", "--mode"].contains(&k) || i + 1 >= rest.len() {
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
    let kind = get("--kind");
    if !matches!(kind, Some("token" | "login")) {
        return Err(die(
            format!("--kind must be token or login\n{}", help()),
            USAGE,
        ));
    }
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
    let mode = get("--mode").unwrap_or("http");
    if !matches!(mode, "http" | "env") {
        return Err(die("--mode must be http or env", USAGE));
    }
    if mode == "http" && hosts.is_empty() {
        return Err(die(
            format!("--mode http needs at least one --host (use --mode env for a credential with no host)\n{}", help()),
            USAGE,
        ));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("credential"));
    payload.insert("names".into(), json!([argv[0]]));
    payload.insert("kind".into(), json!(kind));
    payload.insert("purpose".into(), json!(purpose));
    payload.insert("hosts".into(), json!(hosts));
    payload.insert("cred_mode".into(), json!(mode));
    if let Some(v) = get("--var").filter(|v| !v.is_empty()) {
        payload.insert("var".into(), json!(v));
    }
    let r = obtain(
        payload,
        "waiting for the human to enter the credential on the approval page (you will not see the value)...",
    )?;
    println!("stored: {}", py_str(&r["stored"]["name"]));
    eprintln!("asb: see `asb list` for its variables and hosts");
    Ok(0)
}
