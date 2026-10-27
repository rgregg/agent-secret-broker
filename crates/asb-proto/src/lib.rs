//! Wire types and limits for the broker's client API, for the parts the Rust tools use.
//!
//! The contract is `docs/reference.md` and the JSON in `tests/fixtures/sudo/`, which the Python
//! broker's tests check too. Requests are strict (they are what we send); responses ignore unknown
//! fields so a newer broker does not break an older tool.

use serde::{Deserialize, Serialize};

/// Most arguments a `sudo` request may carry.
pub const MAX_ARGS: usize = 64;
/// Longest single argument, in characters.
pub const MAX_ARG_CHARS: usize = 4096;
/// Longest whole command, in characters.
pub const MAX_TOTAL_CHARS: usize = 16384;

/// Exit codes shared with the `asb` CLI (see `asb guide`).
pub mod exit {
    pub const USAGE: i32 = 2;
    pub const BROKER: i32 = 3;
    pub const DENIED: i32 = 4;
    pub const EXPIRED: i32 = 5;
    /// Refused locally, before or after asking: an unsafe command path, config or binary.
    pub const REFUSED_LOCALLY: i32 = 10;
    /// Approved, but the command could not be started.
    pub const EXEC_FAILED: i32 = 11;
}

/// `POST /v1/requests` with `mode: "sudo"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoRequest {
    pub mode: String,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    pub user: String,
    pub invoker: Option<String>,
    pub source: String,
}

impl SudoRequest {
    pub fn new(
        argv: Vec<String>,
        cwd: Option<String>,
        invoker: Option<String>,
        source: String,
    ) -> Self {
        SudoRequest {
            mode: "sudo".into(),
            argv,
            cwd,
            user: "root".into(),
            invoker,
            source,
        }
    }

    /// The broker's own argument checks, so a request it would refuse fails here, before the network.
    pub fn check(&self) -> Result<(), String> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGS {
            return Err(format!("a command is 1 to {MAX_ARGS} words"));
        }
        if self.argv[0].is_empty() {
            return Err("the command name is empty".into());
        }
        let total: usize = self.argv.iter().map(|a| a.chars().count()).sum();
        if self.argv.iter().any(|a| a.chars().count() > MAX_ARG_CHARS) || total > MAX_TOTAL_CHARS {
            return Err(format!(
                "an argument is longer than {MAX_ARG_CHARS} characters, or the command is longer than {MAX_TOTAL_CHARS} in total"
            ));
        }
        if self.argv.iter().any(|a| {
            a.chars()
                .any(|c| matches!(c, '\u{0}'..='\u{8}' | '\u{b}'..='\u{1f}' | '\u{7f}'))
        }) {
            return Err("the command contains a control character".into());
        }
        Ok(())
    }
}

/// The broker's answer to creating a request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Created {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    pub expires_in: i64,
}

/// The broker's answer to polling a request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Polled {
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    /// Present and true only on the one poll that delivers a `sudo` approval.
    #[serde(default)]
    pub approved: bool,
}

/// Where a request stands, from its `status` word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
    Failed,
    Released,
    Unknown,
}

impl Status {
    pub fn parse(word: &str) -> Status {
        match word {
            "pending" => Status::Pending,
            "approved" => Status::Approved,
            "denied" => Status::Denied,
            "expired" => Status::Expired,
            "failed" => Status::Failed,
            "released" => Status::Released,
            _ => Status::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = format!(
            "{}/../../tests/fixtures/sudo/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
    }

    #[test]
    fn the_request_fixture_is_exactly_what_we_send() {
        let want: serde_json::Value = serde_json::from_str(&fixture("request.json")).unwrap();
        let req: SudoRequest = serde_json::from_value(want.clone()).unwrap();
        assert_eq!(serde_json::to_value(&req).unwrap(), want);
        assert!(req.check().is_ok());
    }

    #[test]
    fn the_response_fixtures_parse() {
        let c: Created = serde_json::from_str(&fixture("created.json")).unwrap();
        assert_eq!((c.status.as_str(), c.expires_in), ("pending", 300));
        let p: Polled = serde_json::from_str(&fixture("approved.json")).unwrap();
        assert!(p.approved && Status::parse(&p.status) == Status::Approved);
        let p: Polled = serde_json::from_str(&fixture("denied.json")).unwrap();
        assert!(!p.approved && Status::parse(&p.status) == Status::Denied);
        let p: Polled = serde_json::from_str(&fixture("released.json")).unwrap();
        assert!(!p.approved && Status::parse(&p.status) == Status::Released);
    }

    #[test]
    fn unknown_response_fields_are_ignored_but_unknown_request_fields_are_not() {
        let p: Polled = serde_json::from_str(r#"{"status":"pending","future":1}"#).unwrap();
        assert_eq!(p.status, "pending");
        let bad = r#"{"mode":"sudo","argv":["a"],"cwd":null,"user":"root","invoker":null,"source":"s","extra":1}"#;
        assert!(serde_json::from_str::<SudoRequest>(bad).is_err());
    }

    #[test]
    fn check_matches_the_brokers_limits() {
        let mk = |argv: Vec<String>| SudoRequest::new(argv, None, None, "s".into());
        assert!(mk(vec![]).check().is_err());
        assert!(mk(vec!["".into()]).check().is_err());
        assert!(mk(vec!["a\0b".into()]).check().is_err());
        assert!(mk(vec!["a".into(); MAX_ARGS + 1]).check().is_err());
        assert!(mk(vec!["x".repeat(MAX_ARG_CHARS + 1)]).check().is_err());
        assert!(mk(vec!["x".repeat(MAX_ARG_CHARS); 5]).check().is_err());
        assert!(mk(vec!["line one\nline two\tx".into()]).check().is_ok());
    }
}
