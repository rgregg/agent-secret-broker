//! The "an update is available" notice and `asb version`: the port of `maybe_update_notice` and `run_version` in
//! client/asb (see docs/superpowers/specs/2026-11-19-client-update-notice-design.md).
//!
//! The broker sends one thing, `latest_client_version`, and it is untrusted: only a string that passes the version
//! grammar (the one secret_broker/clientver.py parses) is used. The link and every word printed are this crate's own.

use crate::broker::CLI_VERSION;
use crate::exit::R;
use crate::text_gen::{RELEASE_URL, UPDATE_STEPS};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NOTICE_EVERY_S: i64 = 86400;

static DONE: AtomicBool = AtomicBool::new(false);
static OFF: AtomicBool = AtomicBool::new(false);

/// This command shows the update state itself (`status`, `version`): no notice from it.
pub fn silence() {
    OFF.store(true, Ordering::SeqCst);
}

/// The numbers of a bounded digits-and-dots version: 1 to 4 fields of 1 to 4 ASCII digits. Anything else is `None`.
pub fn version_tuple(v: &str) -> Option<Vec<u32>> {
    let fields: Vec<&str> = v.split('.').collect();
    if fields.is_empty() || fields.len() > 4 {
        return None;
    }
    fields
        .iter()
        .map(|f| {
            if (1..=4).contains(&f.len()) && f.bytes().all(|b| b.is_ascii_digit()) {
                f.parse().ok()
            } else {
                None
            }
        })
        .collect()
}

/// `Some(true)` when `expected` is a valid version newer than `have`; `None` when either is not a version. Numeric,
/// with missing trailing fields counting as 0.
pub fn update_available(have: &str, expected: &str) -> Option<bool> {
    let (mut a, mut b) = (version_tuple(have)?, version_tuple(expected)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a < b)
}

fn state_path() -> Option<PathBuf> {
    let base = match std::env::var("XDG_STATE_HOME") {
        Ok(x) if std::path::Path::new(&x).is_absolute() => PathBuf::from(x),
        _ => PathBuf::from(std::env::var("HOME").ok()?)
            .join(".local")
            .join("state"),
    };
    Some(base.join("asb").join("update-notice"))
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a record written at `last` (text of the state file) leaves a notice due at `now`.
fn due_after(record: &str, now: i64) -> bool {
    match record.trim().parse::<i64>() {
        Ok(last) => !(0 <= now - last && now - last < NOTICE_EVERY_S),
        Err(_) => true,
    }
}

/// True, and recorded, when no notice was shown in the last day. False when one was, or when the record cannot be
/// written (a read-only home would otherwise print it on every call). Never fails.
fn due(path: &std::path::Path, now: i64) -> bool {
    if let Ok(text) = std::fs::read_to_string(path) {
        let head: String = text.chars().take(40).collect();
        if !due_after(&head, now) {
            return false;
        }
    }
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")))?;
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, format!("{now}\n"))?;
        std::fs::rename(&tmp, path)
    };
    write().is_ok()
}

fn switched_off() -> bool {
    !matches!(
        std::env::var("ASB_NO_UPDATE_CHECK").as_deref(),
        Err(_) | Ok("") | Ok("0")
    )
}

/// The two lines printed on stderr for a validated `expected` version.
pub fn notice_text(expected: &str) -> String {
    format!(
        "asb: an update is available (you have {CLI_VERSION}, this broker expects {expected}): {RELEASE_URL}\n\
         asb: agent: do not update on your own. Tell the human and ask first; if they agree, follow `asb version` \
         (download only from that page, verify the .sha256, keep a backup). Never pipe a download into a shell."
    )
}

/// Tell the user, on stderr and at most once a day, that the broker expects a newer asb. The only thing taken from
/// `answer` is a `latest_client_version` that passes the version grammar.
pub fn maybe_notice(answer: &Value) {
    if DONE.load(Ordering::SeqCst) || OFF.load(Ordering::SeqCst) || switched_off() {
        return;
    }
    let Some(expected) = answer.get("latest_client_version").and_then(Value::as_str) else {
        return;
    };
    if update_available(CLI_VERSION, expected) != Some(true) {
        return;
    }
    DONE.store(true, Ordering::SeqCst);
    if let Some(path) = state_path() {
        if due(&path, now_s()) {
            eprintln!("{}", notice_text(expected));
        }
    }
}

/// `asb version`: this client's version, the broker's expected one and whether to update. One status question; it
/// never fails because the broker cannot be asked.
pub fn run(rest: &[String]) -> R {
    if !rest.is_empty() {
        return Err(crate::util::die_help("version"));
    }
    silence();
    let (mut expected, mut broker) = (None, "not reachable".to_string());
    // a failed call has already said why on stderr (`die` prints); the answer below says "not reachable"
    if let Ok(client) = crate::broker::client() {
        if let Ok((200, r)) = crate::broker::call(&client, "/v1/status", None, 15) {
            let v = r
                .get("latest_client_version")
                .and_then(Value::as_str)
                .filter(|v| version_tuple(v).is_some())
                .map(str::to_string);
            broker = match &v {
                Some(v) => format!("expects {v}"),
                None => "does not say".to_string(),
            };
            expected = v;
        }
    }
    let newer = expected
        .as_deref()
        .and_then(|e| update_available(CLI_VERSION, e));
    let update = match (newer, expected.as_deref()) {
        (None, _) | (_, None) => "unknown".to_string(),
        (Some(true), Some(e)) => format!("available ({CLI_VERSION} -> {e})"),
        (Some(false), _) => "none needed".to_string(),
    };
    println!(
        "asb:      {CLI_VERSION}\nbroker:   {broker}\nupdate:   {update}\nrelease:  {RELEASE_URL}"
    );
    if newer == Some(true) {
        println!("\n{UPDATE_STEPS}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn grammar_is_the_brokers() {
        for ok in [
            "1",
            "1.1",
            "2.10.3",
            "1.2.3.4",
            "0.0",
            "9999.9999.9999.9999",
        ] {
            assert!(version_tuple(ok).is_some(), "{ok}");
        }
        for bad in [
            "",
            "x",
            "1.",
            ".1",
            "1..2",
            "1.2.3.4.5",
            "99999",
            "1.99999",
            " 1.1",
            "1.1 ",
            "1.1\n",
            "v1",
            "1.1\x1b[31m",
            "-1",
            "+1",
            "https://evil.example/x",
            "१.१",
            "1_0",
            &"9".repeat(40),
            &format!("1{}", ".1".repeat(300)),
        ] {
            assert!(version_tuple(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_version_in_the_user_agent_is_the_one_in_the_notice() {
        assert!(crate::broker::USER_AGENT.starts_with(&format!("asb/{CLI_VERSION} ")));
        assert!(version_tuple(CLI_VERSION).is_some());
    }

    #[test]
    fn comparison_is_numeric_and_pads_with_zeros() {
        assert_eq!(update_available("1.9", "1.10"), Some(true));
        assert_eq!(update_available("1.10", "1.9"), Some(false));
        assert_eq!(update_available("1", "1.1"), Some(true));
        assert_eq!(update_available("1.1", "1.1"), Some(false));
        assert_eq!(update_available("1.1.0", "1.1"), Some(false));
        assert_eq!(update_available("1.1", "1.1.0.1"), Some(true));
        assert_eq!(update_available("2", "1.1"), Some(false));
        assert_eq!(update_available("1.1", "x"), None);
        assert_eq!(update_available("dev", "1.1"), None);
    }

    #[test]
    fn a_record_is_due_after_a_day_or_when_unreadable() {
        let now = 1_000_000_000;
        assert!(!due_after(&format!("{}\n", now - 10), now));
        assert!(!due_after(&format!("{}", now - NOTICE_EVERY_S + 1), now));
        assert!(due_after(&format!("{}", now - NOTICE_EVERY_S), now));
        assert!(due_after(&format!("{}", now + 5), now)); // from the future: the clock moved
        assert!(due_after("garbage", now));
        assert!(due_after("", now));
    }

    #[test]
    fn the_state_file_is_written_once_and_a_bad_dir_is_silent() {
        let dir = std::env::temp_dir().join(format!("asb-notice-{}", std::process::id()));
        let path = dir.join("sub").join("update-notice");
        assert!(due(&path, 5_000_000)); // control: a writable place says due and records it
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "5000000\n");
        assert!(!due(&path, 5_000_001)); // now recorded
        assert!(due(&path, 5_000_000 + NOTICE_EVERY_S)); // and due again after a day
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, "a file").unwrap();
        assert!(!due(&blocker.join("x").join("update-notice"), 5_000_000)); // cannot write: not due, no panic
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_notice_text_has_only_the_validated_version_and_our_own_link() {
        let t = notice_text("9.0");
        assert!(t.starts_with(&format!(
            "asb: an update is available (you have {CLI_VERSION}, this broker expects 9.0): {RELEASE_URL}\n"
        )));
        assert_eq!(
            RELEASE_URL,
            "https://github.com/rgregg/agent-secret-broker/releases/latest"
        );
        for w in [
            "Tell the human and ask first",
            "asb version",
            "Never pipe a download into a shell",
        ] {
            assert!(t.contains(w), "{w}");
        }
        assert_eq!(t.lines().count(), 2);
        // the steps an agent follows
        for w in [
            "only after the human says yes",
            ".sha256",
            "command -v asb",
            "backup",
            "(no curl | sh)",
        ] {
            assert!(UPDATE_STEPS.contains(w), "{w}");
        }
        // hostile answers never reach `notice_text`: they fail the grammar
        let hostile = json!({"latest_client_version": "https://evil.example/x"});
        assert!(version_tuple(hostile["latest_client_version"].as_str().unwrap()).is_none());
    }
}
