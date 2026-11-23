//! `asb exec NAME HOST [flags] -- command...` or `--script FILE`: the broker runs it over SSH and returns the output.
//! A port of `run_exec` in client/asb (the specification). The quoting (`quote`, `join`) must stay in step with
//! `rebuild` in secret_broker/execmode.py: the broker classifies the text this sends, so a word quoted differently
//! here would be classified as something the person did not type. tests/fixtures/cli/exec.json holds what Python
//! computes for both pure functions.

use crate::approval::status_exit;
use crate::broker;
use crate::exit::{die, Die, BROKER, EXPIRED, R, USAGE};
use crate::pyfmt::{py_str, srv, truthy};
use crate::util::{check_name, die_help, os_error, parse_flags, source, strerror};
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const MAX_COMMAND: usize = 4096; // characters of the text that is sent
const MAX_SCRIPT: usize = 32 * 1024; // bytes
const MAX_TIMEOUT: u64 = 600;
const LABELS: [&str; 8] = [
    "host_key_mismatch",
    "host_not_pinned",
    "connect_failed",
    "auth_failed",
    "timeout",
    "output_cap",
    "ssh_unavailable",
    "internal",
];

/// Characters a reviewer cannot see but a model reads (the same list as `_EXEC_HIDDEN` in client/asb).
const HIDDEN: [(u32, u32); 20] = [
    (0xA0, 0xA0),
    (0xAD, 0xAD),
    (0x61C, 0x61C),
    (0x115F, 0x1160),
    (0x1680, 0x1680),
    (0x180E, 0x180E),
    (0x2000, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x3000, 0x3000),
    (0x3164, 0x3164),
    (0xD800, 0xDFFF),
    (0xE000, 0xF8FF),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF9, 0xFFFD),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
    (0xF0000, 0x10FFFF),
];

/// One word as the broker's grammar reads it back (`shlex.quote`): bare when it is only safe characters, else in single
/// quotes with each `'` written as `'"'"'`.
pub fn quote(word: &str) -> String {
    let safe = |b: u8| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b);
    if !word.is_empty() && word.bytes().all(safe) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\"'\"'"))
    }
}

pub fn join(words: &[String]) -> String {
    words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ")
}

/// A fixed phrase for the first character the broker would refuse in command or script text.
pub fn text_problem(text: &str) -> Option<&'static str> {
    for ch in text.chars() {
        let o = ch as u32;
        if (o < 0x20 && ch != '\t' && ch != '\n') || (0x7F..=0x9F).contains(&o) {
            return Some("a control character (only tab and newline are allowed)");
        }
        if HIDDEN.iter().any(|&(lo, hi)| (lo..=hi).contains(&o)) {
            return Some("a hidden or look-alike character");
        }
    }
    None
}

fn number(text: &str, what: &str, lo: u64, hi: u64) -> Result<u64, Die> {
    let ok = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    match text.parse::<u64>() {
        Ok(n) if ok && (lo..=hi).contains(&n) => Ok(n),
        _ => Err(die(
            format!("{what} must be a whole number from {lo} to {hi}"),
            USAGE,
        )),
    }
}

fn user_ok(u: &str) -> bool {
    (1..=64).contains(&u.len()) && u.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// POST the request, wait for the human, then for the run. Returns the released answer.
fn wait(mut payload: Map<String, Value>, timeout_s: u64) -> Result<Value, Die> {
    let client = broker::client()?;
    payload.insert("source".into(), Value::String(source()));
    let (code, mut r) = broker::call(&client, "/v1/requests", Some(&Value::Object(payload)), 40)?;
    if code != 202 {
        return Err(die(
            broker::error_text(&r, &format!("broker returned {code}")),
            BROKER,
        ));
    }
    let id = r.get("id").and_then(Value::as_str).map(String::from);
    let expires = r
        .get("expires_in")
        .and_then(Value::as_f64)
        .filter(|e| *e > 0.0)
        .map(|e| e.min(86400.0))
        .unwrap_or(300.0);
    let mut deadline = Instant::now() + Duration::from_secs_f64(expires + 15.0);
    let (mut first, mut running) = (true, false);
    loop {
        let status = r.get("status").map(py_str).unwrap_or_default();
        if status == "released" {
            return Ok(r);
        }
        if matches!(status.as_str(), "denied" | "expired" | "failed") {
            let why = if first {
                broker::error_text(&r, &status)
            } else {
                match r.get("error") {
                    Some(e) if truthy(e) => format!("request {status}: {}", srv(&py_str(e), 160)),
                    _ => format!("request {status}"),
                }
            };
            return Err(die(why, status_exit(&status)));
        }
        if first && status != "approved" && status != "running" {
            // a request the broker approved by policy is not waiting for anyone
            eprintln!("asb: waiting for approval...");
        }
        if (status == "running" || status == "approved") && !running {
            // the human has answered: now the command's own time
            running = true;
            deadline = deadline.max(Instant::now() + Duration::from_secs(timeout_s + 60));
        }
        let Some(rid) = id.as_deref().filter(|_| Instant::now() < deadline) else {
            return Err(die("timed out waiting for the command", EXPIRED));
        };
        let (code, next) = broker::call(&client, &format!("/v1/requests/{rid}?wait=25"), None, 40)?;
        if code != 200 {
            return Err(die(
                broker::error_text(&next, &format!("broker returned {code}")),
                BROKER,
            ));
        }
        r = next;
        first = false;
    }
}

pub fn run(argv: &[String]) -> R {
    let (head, words) = match argv.iter().position(|a| a == "--") {
        Some(i) => (&argv[..i], Some(&argv[i + 1..])),
        None => (argv, None),
    };
    if head.len() < 2 || words.is_some_and(|w| w.is_empty()) {
        return Err(die_help("exec"));
    }
    let (name, host) = (&head[0], &head[1]);
    check_name(name, "NAME")?;
    check_name(host, "HOST")?;
    if name.contains(',') {
        return Err(die("exec uses exactly one credential (an SSH key)", USAGE));
    }
    let allowed = [
        ("--user", "user"),
        ("--port", "port"),
        ("--timeout", "timeout"),
        ("--script", "script"),
        ("--interpreter", "interpreter"),
    ];
    let flags = parse_flags(&head[2..], &allowed)?;
    let get = |k: &str| flags.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let script = get("script");
    if script.is_none() == words.is_none() {
        return Err(die_help("exec"));
    }
    if get("interpreter").is_some() && script.is_none() {
        return Err(die("--interpreter goes with --script", USAGE));
    }
    let mut payload = Map::new();
    payload.insert("mode".into(), json!("exec"));
    payload.insert("names".into(), json!([name]));
    payload.insert("host".into(), json!(host));
    if let Some(u) = get("user") {
        if !user_ok(u) {
            return Err(die(
                "--user must be 1 to 64 printable ASCII characters without spaces",
                USAGE,
            ));
        }
        payload.insert("user".into(), json!(u));
    } else {
        // the local login name by default: the account on the host is usually the same
        match std::env::var("USER") {
            Ok(u) if user_ok(&u) && !u.starts_with('-') => {
                payload.insert("user".into(), json!(u));
            }
            _ => {
                return Err(die(
                    "no --user given and $USER is not a usable account name: pass --user NAME",
                    USAGE,
                ))
            }
        }
    }
    if let Some(p) = get("port") {
        payload.insert("port".into(), json!(number(p, "--port", 1, 65535)?));
    }
    let mut timeout_s = 60;
    if let Some(t) = get("timeout") {
        timeout_s = number(t, "--timeout", 1, MAX_TIMEOUT)?;
        payload.insert("timeout_s".into(), json!(timeout_s));
    }
    if let Some(words) = words {
        let text = join(words);
        if text.chars().count() > MAX_COMMAND {
            return Err(die(
                format!("the command is longer than {MAX_COMMAND} characters"),
                USAGE,
            ));
        }
        if let Some(p) = text_problem(&text) {
            return Err(die(format!("the command contains {p}"), USAGE));
        }
        payload.insert("command".into(), json!(text));
    } else if let Some(path) = script {
        let interpreter = get("interpreter").unwrap_or("sh");
        if interpreter != "sh" && interpreter != "bash" {
            return Err(die("--interpreter must be sh or bash", USAGE));
        }
        let mut data = Vec::new();
        let read = std::fs::File::open(path)
            .and_then(|f| f.take(MAX_SCRIPT as u64 + 1).read_to_end(&mut data));
        if let Err(e) = read {
            let why = e
                .raw_os_error()
                .map(strerror)
                .unwrap_or_else(|| os_error(&e));
            return Err(die(format!("cannot read the script: {why}"), USAGE));
        }
        if data.len() > MAX_SCRIPT {
            return Err(die("the script is longer than 32 KiB", USAGE));
        }
        let Ok(text) = String::from_utf8(data) else {
            return Err(die("the script is not UTF-8 text", USAGE));
        };
        if let Some(p) = text_problem(&text) {
            return Err(die(format!("the script contains {p}"), USAGE));
        }
        if text.trim().is_empty() {
            return Err(die("the script is empty", USAGE));
        }
        payload.insert(
            "script".into(),
            json!({"text": text, "interpreter": interpreter}),
        );
    }
    let r = wait(payload, timeout_s)?;
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    if let Some(s) = r
        .get("stdout")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let _ = out.write_all(s.as_bytes());
        let _ = out.flush();
    }
    if let Some(s) = r
        .get("stderr")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let _ = err.write_all(s.as_bytes());
        let _ = err.flush();
    }
    if let Some(label) = r.get("label").filter(|l| !l.is_null()) {
        let shown = label
            .as_str()
            .filter(|l| LABELS.contains(l))
            .unwrap_or("unknown");
        return Err(die(format!("exec failed: {shown}"), BROKER));
    }
    let Some(code) = r.get("exit_code").and_then(Value::as_i64) else {
        return Err(die(
            "the broker's answer has neither an exit code nor a failure",
            BROKER,
        ));
    };
    if r.get("truncated") == Some(&Value::Bool(true)) {
        eprintln!("asb: output was truncated at the broker's cap");
    }
    Ok((code & 0xFF) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/cli/exec.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn quoting_matches_every_case_python_computed() {
        let g = golden();
        let cases = g["quote"].as_array().unwrap();
        assert!(cases.len() > 600);
        for c in cases {
            let words: Vec<String> = c[0]
                .as_array()
                .unwrap()
                .iter()
                .map(|w| w.as_str().unwrap().to_string())
                .collect();
            assert_eq!(join(&words), c[1].as_str().unwrap(), "{words:?}");
        }
    }

    #[test]
    fn refused_characters_match_every_case_python_computed() {
        let g = golden();
        let cases = g["problem"].as_array().unwrap();
        assert!(cases.len() > 12000);
        for c in cases {
            let text = c[0].as_str().unwrap();
            assert_eq!(text_problem(text), c[1].as_str(), "{text:?}");
        }
    }

    #[test]
    fn quoting_table() {
        let t = |w: &[&str], want: &str| {
            let words: Vec<String> = w.iter().map(|s| s.to_string()).collect();
            assert_eq!(join(&words), want, "{w:?}");
        };
        t(&["ls", "-l", "/var/log"], "ls -l /var/log");
        t(&["echo", "a b"], "echo 'a b'");
        t(&["echo", ""], "echo ''");
        t(&["echo", "it's"], "echo 'it'\"'\"'s'");
        t(&["echo", "'"], "echo ''\"'\"''");
        t(
            &["echo", "a;b", "$HOME", "`x`", "x\\y"],
            "echo 'a;b' '$HOME' '`x`' 'x\\y'",
        );
        t(&["echo", "a\nb"], "echo 'a\nb'");
        t(&["echo", "naïve"], "echo 'naïve'");
        t(&["a_B-1", "x@y%z+w=v:u,t./s"], "a_B-1 x@y%z+w=v:u,t./s");
        t(&["sh", "-c", "a | b"], "sh -c 'a | b'");
    }

    #[test]
    fn numbers_are_ascii_digits_in_range() {
        assert_eq!(number("22", "--port", 1, 65535).unwrap(), 22);
        assert_eq!(number("65535", "--port", 1, 65535).unwrap(), 65535);
        for bad in [
            "",
            "0",
            "65536",
            "-1",
            "+1",
            "1.5",
            "٢٢",
            "99999999999999999999999",
            " 1",
        ] {
            assert!(number(bad, "--port", 1, 65535).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn users_are_printable_ascii_without_spaces() {
        assert!(user_ok("ryan") && user_ok("a.b-c_d@x") && user_ok(&"u".repeat(64)));
        for bad in ["", "a b", "é", "a\nb", &"u".repeat(65)] {
            assert!(!user_ok(bad), "{bad:?}");
        }
    }
}
