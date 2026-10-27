//! Client for the broker's HTTP API: the config file, calls, and waiting for a human.
//!
//! Fails closed. The only way `approve_sudo` returns `Ok` is a poll that says `approved` AND
//! carries `"approved": true`; an unreachable broker, a refusal, a denial, an expiry, an
//! unexpected status or a malformed answer are all errors.

use asb_proto::{exit, Created, Polled, Status, SudoRequest};
use std::time::{Duration, Instant};

#[cfg(feature = "mock")]
pub mod mock;

/// How long one poll may hold open on the broker (`?wait=`), and the HTTP timeout around it.
const POLL_WAIT_S: u64 = 25;
const POLL_TIMEOUT: Duration = Duration::from_secs(40);
const CALL_TIMEOUT: Duration = Duration::from_secs(40);
/// Slack after the request's own expiry before we give up waiting.
const EXPIRY_SLACK_S: i64 = 15;
/// Consecutive failed polls tolerated (a flaky network must not waste a human's approval).
const POLL_RETRIES: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub url: String,
    pub key: String,
}

impl Config {
    /// Parse `{"url": "https://...", "key": "..."}`. The key is never part of an error message.
    pub fn parse(text: &str) -> Result<Config, String> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "config is not valid JSON".to_string())?;
        let field = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let url = field("url").ok_or("config needs a \"url\"")?;
        let key = field("key").ok_or("config needs a \"key\"")?;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err("config url must start with https:// (or http:// for a local test)".into());
        }
        Ok(Config {
            url: url.trim_end_matches('/').to_string(),
            key,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The broker could not be reached.
    Unreachable(String),
    /// The broker answered with an error status; `message` is its (cleaned) text.
    Refused {
        status: u16,
        message: String,
    },
    /// The broker said something this client does not accept; treated as a refusal.
    Protocol(String),
    Denied,
    Expired,
    Failed(String),
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Denied => exit::DENIED,
            Error::Expired => exit::EXPIRED,
            _ => exit::BROKER,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable(m) => write!(f, "cannot reach broker: {m}"),
            Error::Refused { status, message } => write!(f, "broker refused ({status}): {message}"),
            Error::Protocol(m) => write!(f, "unexpected answer from broker: {m}"),
            Error::Denied => write!(f, "denied"),
            Error::Expired => write!(f, "expired before anyone answered"),
            Error::Failed(m) => write!(f, "failed: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Text from the network, made safe to print on a terminal: control characters become `?`, and it
/// is cut to `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub struct Client {
    cfg: Config,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(cfg: Config) -> Client {
        // No redirects: the key header must only ever go to the configured broker.
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .user_agent(concat!(
                "asb-client/",
                env!("CARGO_PKG_VERSION"),
                " (+https://github.com/rgregg/agent-secret-broker)"
            ))
            .build();
        Client { cfg, agent }
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<(u16, String), Error> {
        let url = format!("{}{}", self.cfg.url, path);
        let req = self
            .agent
            .request(method, &url)
            .timeout(timeout)
            .set("X-Client-Key", &self.cfg.key)
            .set("Content-Type", "application/json");
        let out = match body {
            Some(b) => req.send_string(b),
            None => req.call(),
        };
        match out {
            Ok(resp) => {
                let code = resp.status();
                Ok((
                    code,
                    resp.into_string()
                        .map_err(|e| Error::Protocol(clean(&e.to_string(), 120)))?,
                ))
            }
            Err(ureq::Error::Status(code, resp)) => {
                Ok((code, resp.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(t)) => Err(Error::Unreachable(clean(&t.to_string(), 160))),
        }
    }

    fn refusal(code: u16, body: &str) -> Error {
        let msg = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.as_str())
                    .map(|s| clean(s, 160))
            })
            .unwrap_or_else(|| "no reason given".into());
        Error::Refused {
            status: code,
            message: msg,
        }
    }

    /// Create a `sudo` request.
    pub fn create_sudo(&self, req: &SudoRequest) -> Result<Created, Error> {
        let body = serde_json::to_string(req).map_err(|e| Error::Protocol(e.to_string()))?;
        let (code, text) = self.call("POST", "/v1/requests", Some(&body), CALL_TIMEOUT)?;
        if code != 202 {
            return Err(Self::refusal(code, &text));
        }
        let created: Created =
            serde_json::from_str(&text).map_err(|_| Error::Protocol("bad create answer".into()))?;
        let id_ok = !created.id.is_empty()
            && created.id.len() <= 64
            && created
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !id_ok {
            return Err(Error::Protocol("bad request id".into()));
        }
        Ok(created)
    }

    /// Create a `sudo` request and wait for the human. `Ok(())` only on a clean approval.
    /// `note` gets progress lines for the caller to show.
    pub fn approve_sudo(&self, req: &SudoRequest, mut note: impl FnMut(&str)) -> Result<(), Error> {
        let created = self.create_sudo(req)?;
        match Status::parse(&created.status) {
            // An approval can land before the create call has returned (a fast approver, a busy broker), so the
            // answer may already say `deciding` or `approved`. The approval itself is only delivered by a poll,
            // so go and collect it.
            Status::Pending | Status::Deciding | Status::Approved => {}
            Status::Denied => return Err(Error::Denied),
            Status::Expired => return Err(Error::Expired),
            Status::Failed => {
                return Err(Error::Failed(clean(
                    created.error.as_deref().unwrap_or("failed"),
                    160,
                )))
            }
            Status::Released | Status::Unknown => {
                return Err(Error::Protocol(format!(
                    "unexpected status {} for a new request",
                    clean(&created.status, 40)
                )))
            }
        }
        note("waiting for approval on your phone...");
        let deadline = Instant::now()
            + Duration::from_secs((created.expires_in.max(0) + EXPIRY_SLACK_S) as u64);
        let path = format!("/v1/requests/{}?wait={}", created.id, POLL_WAIT_S);
        let mut failures = 0;
        while Instant::now() < deadline {
            let (code, text) = match self.call("GET", &path, None, POLL_TIMEOUT) {
                Ok(r) => r,
                Err(e) => {
                    failures += 1;
                    if failures > POLL_RETRIES {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            if code != 200 {
                return Err(Self::refusal(code, &text));
            }
            failures = 0;
            let polled: Polled = serde_json::from_str(&text)
                .map_err(|_| Error::Protocol("bad poll answer".into()))?;
            match Status::parse(&polled.status) {
                Status::Pending | Status::Deciding => continue,
                Status::Approved if polled.approved => return Ok(()),
                Status::Approved => {
                    return Err(Error::Protocol("approved without an approval".into()))
                }
                Status::Denied => return Err(Error::Denied),
                Status::Expired => return Err(Error::Expired),
                Status::Failed => {
                    return Err(Error::Failed(clean(
                        polled.error.as_deref().unwrap_or("failed"),
                        160,
                    )))
                }
                Status::Released => {
                    return Err(Error::Protocol(
                        "this approval was already collected".into(),
                    ))
                }
                Status::Unknown => {
                    return Err(Error::Protocol(format!(
                        "unknown status {}",
                        clean(&polled.status, 40)
                    )))
                }
            }
        }
        Err(Error::Expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_and_never_echoes_the_key() {
        let c = Config::parse(r#"{"url":"https://asb.example/","key":"asbc1_SECRET"}"#).unwrap();
        assert_eq!(c.url, "https://asb.example");
        for bad in [
            r#"{"url":"https://x"}"#,
            r#"{"key":"k"}"#,
            r#"{"url":"ftp://x","key":"asbc1_SECRET"}"#,
            "nope",
        ] {
            let e = Config::parse(bad).unwrap_err();
            assert!(!e.contains("asbc1_SECRET"), "{e}");
        }
    }

    #[test]
    fn clean_strips_terminal_control_characters() {
        assert_eq!(clean("ok\x1b[31mred\nline", 100), "ok?[31mred?line");
        assert_eq!(clean("abcdef", 3), "abc");
    }
}
