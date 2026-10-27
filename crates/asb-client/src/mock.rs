//! A scripted fake broker for tests: it answers each incoming request with the next canned reply
//! and records what it was sent. Plain HTTP on loopback; one request per connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub key: Option<String>,
    pub user_agent: Option<String>,
    pub body: String,
}

pub struct MockBroker {
    pub url: String,
    seen: Arc<Mutex<Vec<Recorded>>>,
}

impl MockBroker {
    /// Start serving `replies` (status, JSON text) in order. A request after the script is
    /// exhausted gets a 500.
    pub fn start(replies: Vec<(u16, String)>) -> MockBroker {
        Self::start_hooked(replies, |_| {})
    }

    /// Like `start`, and `before_reply(n)` runs just before the n-th (0-based) reply is sent, so a test
    /// can change the world while the client is "waiting for the human".
    pub fn start_hooked(
        replies: Vec<(u16, String)>,
        before_reply: impl Fn(usize) + Send + 'static,
    ) -> MockBroker {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (log, mut script) = (seen.clone(), replies.into_iter());
        thread::spawn(move || {
            for (n, stream) in listener.incoming().flatten().enumerate() {
                let (code, body) = script
                    .next()
                    .unwrap_or((500, r#"{"error":"mock script exhausted"}"#.into()));
                handle(stream, &log, code, &body, || before_reply(n));
            }
        });
        MockBroker { url, seen }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }
}

fn handle(
    mut stream: TcpStream,
    log: &Arc<Mutex<Vec<Recorded>>>,
    code: u16,
    reply: &str,
    before_reply: impl FnOnce(),
) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let (mut key, mut ua, mut len) = (None, None, 0usize);
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "x-client-key" => key = Some(v.trim().to_string()),
                "user-agent" => ua = Some(v.trim().to_string()),
                "content-length" => len = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut body = vec![0u8; len];
    let _ = reader.read_exact(&mut body);
    log.lock().unwrap().push(Recorded {
        method,
        path,
        key,
        user_agent: ua,
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    before_reply();
    let out = format!(
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    let _ = stream.write_all(out.as_bytes());
}
