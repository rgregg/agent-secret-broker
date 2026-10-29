//! `asb plan submit|status|list|close`: one human approval for an unattended job's exact calls.

use crate::approval::{plan_id, plan_refusal, status_exit};
use crate::broker;
use crate::exit::{die, EXPIRED, NOT_FOUND, R};
use crate::pyfmt::{json_dumps, py_str, safe_text, srv, truthy};
use crate::util::{die_help, source};
use serde_json::{json, Value};
use std::io::Read;
use std::time::{Duration, Instant};

const PLAN_BODY_LIMIT: usize = 64 * 1024;

fn plan_when(v: &Value) -> String {
    let s = v.as_f64().map(|f| f as i64).unwrap_or(0);
    if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

fn join(v: &Value, sep: &str) -> String {
    v.as_array()
        .map(|a| a.iter().map(py_str).collect::<Vec<_>>().join(sep))
        .unwrap_or_default()
}

fn plan_print(v: &Value) {
    println!("plan:    {}", py_str(&v["id"]));
    println!("state:   {}", py_str(&v["status"]));
    if v.get("left_s").is_some_and(truthy) || py_str(&v["status"]) == "active" {
        println!("left:    {}", plan_when(&v["left_s"]));
    }
    println!(
        "uses:    {} / {}",
        py_str(&v["uses"]["used"]),
        py_str(&v["uses"]["max"])
    );
    println!("secrets: {}", join(&v["secrets"], ", "));
    if let Some(rules) = v.get("rules").and_then(Value::as_array) {
        for (i, r) in rules.iter().enumerate() {
            println!(
                "  {}. {} {} {} body={} used {}/{}",
                i + 1,
                py_str(&r["secret"]),
                py_str(&r["method"]),
                py_str(&r["url"]),
                py_str(&r["body"]),
                py_str(&r["uses"]),
                py_str(&r["max_uses"])
            );
        }
    }
}

pub fn run(argv: &[String]) -> R {
    let sub = match argv.first().map(String::as_str) {
        Some(s @ ("submit" | "status" | "list" | "close")) => s,
        _ => return Err(die_help("plan")),
    };
    let as_json = argv[1..].iter().any(|a| a == "--json");
    let mut rest: Vec<String> = argv[1..]
        .iter()
        .filter(|a| *a != "--json")
        .cloned()
        .collect();
    let client = broker::client()?;
    if sub == "submit" {
        let mut wait = true;
        if rest.iter().any(|a| a == "--no-wait") {
            wait = false;
            rest.retain(|a| a != "--no-wait");
        }
        rest.retain(|a| a != "--wait");
        if rest.len() != 1 {
            return Err(die_help("plan"));
        }
        let mut raw = Vec::new();
        let limit = (PLAN_BODY_LIMIT + 1) as u64;
        let read = if rest[0] == "-" {
            std::io::stdin().take(limit).read_to_end(&mut raw)
        } else {
            std::fs::File::open(&rest[0]).and_then(|f| f.take(limit).read_to_end(&mut raw))
        };
        if read.is_err() {
            return Err(die("cannot read the manifest file", crate::exit::USAGE));
        }
        if raw.len() > PLAN_BODY_LIMIT {
            return Err(die(
                format!("the manifest is larger than {PLAN_BODY_LIMIT} bytes"),
                crate::exit::USAGE,
            ));
        }
        let manifest: Value = String::from_utf8(raw)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .ok_or_else(|| die("the manifest is not valid JSON", crate::exit::USAGE))?;
        let (code, r) = broker::call(
            &client,
            "/v1/plans",
            Some(&json!({"manifest": manifest, "source": source()})),
            40,
        )?;
        if code != 202 {
            return Err(plan_refusal(code, &r));
        }
        if !wait {
            println!("{}", py_str(&r["plan"]));
            eprintln!("asb: pending; the human must approve it on the approval page");
            return Ok(0);
        }
        eprintln!("asb: waiting for the human to read and approve the plan...");
        let end = Instant::now()
            + Duration::from_secs_f64(r["expires_in"].as_f64().unwrap_or(0.0).max(0.0) + 15.0);
        let id = py_str(&r["id"]);
        while Instant::now() < end {
            let (_, r2) = broker::call(&client, &format!("/v1/requests/{id}?wait=25"), None, 40)?;
            let st = r2.get("status").map(py_str).unwrap_or_default();
            if st == "approved" && r2.get("plan").is_some_and(Value::is_object) {
                let pl = &r2["plan"];
                println!("{}", py_str(&pl["plan"]));
                eprintln!(
                    "asb: approved for {}, until {}; after that, submit a new plan",
                    plan_when(&pl["granted_s"]),
                    safe_text(&py_str(&pl["expires_at"]), 160)
                );
                return Ok(0);
            }
            if ["denied", "expired", "failed", "released"].contains(&st.as_str()) {
                let err = match r2.get("error") {
                    Some(e) if truthy(e) => format!(": {}", srv(&py_str(e), 160)),
                    _ => String::new(),
                };
                return Err(die(format!("plan {st}{err}"), status_exit(&st)));
            }
        }
        return Err(die("timed out waiting for approval", EXPIRED));
    }
    if sub == "list" {
        if !rest.is_empty() {
            return Err(die_help("plan"));
        }
        let (code, r) = broker::call(&client, "/v1/plans", None, 40)?;
        if code != 200 {
            return Err(plan_refusal(code, &r));
        }
        if as_json {
            println!("{}", json_dumps(&r["plans"], Some(2)));
            return Ok(0);
        }
        let plans = r["plans"].as_array().cloned().unwrap_or_default();
        if plans.is_empty() {
            eprintln!("asb: no plans");
            return Ok(NOT_FOUND);
        }
        eprintln!("ID\tSTATE\tLEFT\tUSES\tSECRETS");
        for v in &plans {
            println!(
                "{}\t{}\t{}\t{}/{}\t{}",
                py_str(&v["id"]),
                py_str(&v["status"]),
                plan_when(&v["left_s"]),
                py_str(&v["uses"]["used"]),
                py_str(&v["uses"]["max"]),
                join(&v["secrets"], ",")
            );
        }
        return Ok(0);
    }
    if rest.len() != 1 {
        return Err(die_help("plan"));
    }
    let pid = plan_id(&rest[0])?;
    if sub == "status" {
        let (code, r) = broker::call(&client, &format!("/v1/plans/{pid}"), None, 40)?;
        if code != 200 {
            return Err(plan_refusal(code, &r));
        }
        if as_json {
            println!("{}", json_dumps(&r, Some(2)));
        } else {
            plan_print(&r);
        }
        return Ok(0);
    }
    let (code, r) = broker::call(
        &client,
        &format!("/v1/plans/{pid}/close"),
        Some(&json!({})),
        40,
    )?;
    if code != 200 {
        return Err(plan_refusal(code, &r));
    }
    println!("closed: {pid}");
    Ok(0)
}
