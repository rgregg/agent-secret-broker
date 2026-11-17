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
    let keys = argv[2..].iter().any(|a| a == "--keys");
    let help = |c: &str| crate::text_gen::help(c).unwrap_or_default();
    if keys && argv[0] != "store" {
        return Err(die(
            format!(
                "--keys applies to store (change one key with update NAME --var KEY)\n{}",
                help("update")
            ),
            USAGE,
        ));
    }
    if keys && ssh {
        return Err(die(
            format!("--keys does not apply to an ssh key\n{}", help("store")),
            USAGE,
        ));
    }
    let argv: Vec<String> = if ssh || keys {
        argv.iter()
            .filter(|a| *a != "--ssh" && *a != "--keys")
            .cloned()
            .collect()
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
        &[
            ("--var", "var"),
            ("--add-host", "add_host"),
            ("--remove-host", "remove_host"),
        ]
    } else {
        &[
            ("--field", "field"),
            ("--item", "item"),
            ("--var", "var"),
            ("--hosts", "hosts"),
        ]
    };
    let f = parse_flags(&argv[2..], allowed)?;
    if op == "update" && (flag(&f, "add_host").is_some() || flag(&f, "remove_host").is_some()) {
        let list = |k: &str| -> Vec<String> {
            flag(&f, k)
                .unwrap_or("")
                .split(',')
                .filter(|h| !h.is_empty())
                .map(String::from)
                .collect()
        };
        let (add, remove) = (list("add_host"), list("remove_host"));
        if flag(&f, "var").is_some() || (add.is_empty() && remove.is_empty()) {
            return Err(die_help("update"));
        }
        let payload = json!({"mode": "store", "names": [argv[1]], "op": "update",
                             "add_hosts": add, "remove_hosts": remove});
        let r = obtain(
            payload.as_object().cloned().unwrap_or_default(),
            "waiting for approval...",
        )?;
        let hosts: Vec<String> = r["stored"]["hosts"]
            .as_array()
            .map(|a| a.iter().map(py_str).collect())
            .unwrap_or_default();
        println!(
            "updated: {} may now be used against {}",
            py_str(&r["stored"]["name"]),
            hosts.join(", ")
        );
        return Ok(0);
    }
    if keys && flag(&f, "var").is_some() {
        return Err(die(
            format!(
                "--keys names the variables itself (one per key); leave out --var\n{}",
                help("store")
            ),
            USAGE,
        ));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("store"));
    payload.insert("names".into(), json!([argv[1]]));
    payload.insert("op".into(), json!(op));
    payload.insert("value".into(), Value::String(read_value()?));
    if ssh {
        payload.insert("ssh".into(), json!(true));
    }
    if keys {
        payload.insert("keys".into(), json!(true));
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
    let r = obtain(payload, "waiting for approval...")?;
    let s = &r["stored"];
    println!(
        "stored: {} ({}) -> item {} field {}",
        py_str(&s["name"]),
        py_str(&s["op"]),
        repr(&py_str(&s["item"])),
        py_str(&s["field"])
    );
    if let Some(vars) = s["vars"].as_array().filter(|v| !v.is_empty()) {
        let names: Vec<String> = vars.iter().map(py_str).collect();
        eprintln!("asb: variables: {}", names.join(", "));
    }
    Ok(0)
}

/// `--ws`: `home-assistant` (the preset), `off` (an existing credential only: JSON null) or a file holding the
/// JSON object. A setup holds placeholders, never a value; the broker validates it before anyone is asked.
fn read_ws_setup(arg: &str, new: bool) -> Result<Value, crate::exit::Die> {
    if arg == "home-assistant" {
        return Ok(json!(arg));
    }
    if arg == "off" {
        if new {
            return Err(die(
                "--ws off applies to an existing credential (a new one starts without WebSocket sessions)",
                USAGE,
            ));
        }
        return Ok(Value::Null);
    }
    let text = std::fs::read_to_string(arg).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidData {
            return die(format!("--ws: {arg} is not valid JSON"), USAGE); // not UTF-8, as Python reports it
        }
        let msg = e.to_string();
        let msg = msg.split(" (os error").next().unwrap_or(&msg).to_string();
        die(format!("--ws: cannot read {arg}: {msg}"), USAGE)
    })?;
    let ws: Value = serde_json::from_str(&text)
        .map_err(|_| die(format!("--ws: {arg} is not valid JSON"), USAGE))?;
    if !ws.is_object() {
        return Err(die("--ws: the file must hold a JSON object", USAGE));
    }
    Ok(ws)
}

pub fn request_credential(argv: &[String]) -> R {
    let help = || crate::text_gen::help("request-credential").unwrap_or_default();
    if argv.is_empty() {
        return Err(die_help("request-credential"));
    }
    check_name(&argv[0], "NAME")?;
    let rest = &argv[1..];
    let (mut opts, mut hosts): (Vec<(String, String)>, Vec<String>) = (vec![], vec![]);
    let (mut i, mut replace) = (0, false);
    while i < rest.len() {
        let k = rest[i].as_str();
        if k == "--replace" {
            if replace {
                return Err(die("--replace given twice", USAGE));
            }
            replace = true;
            i += 1;
            continue;
        }
        if !["--kind", "--for", "--host", "--var", "--mode", "--ws"].contains(&k)
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
    let mut ws: Option<Value> = None;
    if let Some(arg) = get("--ws") {
        if replace {
            return Err(die(
                format!(
                    "--replace changes only the value: it takes no --ws\n{}",
                    help()
                ),
                USAGE,
            ));
        }
        let setup = read_ws_setup(arg, get("--kind").is_some())?;
        if get("--kind").is_none() {
            if !hosts.is_empty() || get("--mode").is_some() || get("--var").is_some() {
                return Err(die(
                    format!(
                        "--ws for an existing credential takes only --for: its hosts, mode and variables stay\n{}",
                        help()
                    ),
                    USAGE,
                ));
            }
            let mut payload = Map::new();
            payload.insert("mode".into(), json!("credential"));
            payload.insert("names".into(), json!([argv[0]]));
            payload.insert("ws_change".into(), json!(true));
            payload.insert("ws".into(), setup);
            payload.insert("purpose".into(), json!(purpose));
            obtain(
                payload,
                "waiting for the human to review the WebSocket setup on the approval page...",
            )?;
            println!("ws updated: {}", argv[0]);
            return Ok(0);
        }
        ws = Some(setup);
    }
    if replace {
        if !hosts.is_empty() || get("--kind").is_some() || get("--mode").is_some() {
            return Err(die(
                format!(
                    "--replace changes only the value: it takes no --kind, --host or --mode\n{}",
                    help()
                ),
                USAGE,
            ));
        }
        let mut payload = Map::new();
        payload.insert("mode".into(), json!("credential"));
        payload.insert("names".into(), json!([argv[0]]));
        payload.insert("replace".into(), json!(true));
        payload.insert("purpose".into(), json!(purpose));
        if let Some(v) = get("--var").filter(|v| !v.is_empty()) {
            payload.insert("var".into(), json!(v));
        }
        obtain(
            payload,
            "waiting for the human to enter the new value on the approval page (you will not see it)...",
        )?;
        println!("replaced: {}", argv[0]);
        return Ok(0);
    }
    let kind = get("--kind");
    if !matches!(kind, Some("token" | "login")) {
        return Err(die(
            format!("--kind must be token or login\n{}", help()),
            USAGE,
        ));
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
    if let Some(setup) = ws {
        payload.insert("ws".into(), setup);
    }
    let r = obtain(
        payload,
        "waiting for the human to enter the credential on the approval page (you will not see the value)...",
    )?;
    println!("stored: {}", py_str(&r["stored"]["name"]));
    eprintln!("asb: see `asb list` for its variables and hosts");
    Ok(0)
}
