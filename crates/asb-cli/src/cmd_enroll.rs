//! `asb enroll`: get this machine its own broker credential, approved by a human who sees the same code.

use crate::exit::{die, BROKER, DENIED, EXPIRED, R, USAGE};
use crate::pyfmt::{json_dumps, py_str, quote, repr, safe_text, srv, truthy};
use crate::util::hostname;
use asb_client::{anonymous_json, Client, Config};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::time::{Duration, Instant};

const CLIENT_JSON: &str = "~/.config/secret-broker/client.json";
const CLIENT_SECRET_PREFIX: &str = "asbc1_";

/// sha256 of the secret, domain separated. Must equal `secret_broker.clients.hash_secret`.
fn enroll_hash(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"asb-client-secret-v1\0");
    h.update(secret.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The confirmation code (XXXX-XXXX) both this terminal and the approval card show, derived from the hash. Must equal
/// `secret_broker.clients.confirm_code`.
fn enroll_code(secret_hash: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"asb-enroll-code-v1\0");
    h.update(secret_hash.as_bytes());
    let digest = h.finalize();
    // the first 8 characters of the RFC 4648 base32 of the digest: its first 5 bytes
    const T: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let n = digest[..5]
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | *b as u64);
    let s: String = (0..8)
        .map(|i| T[((n >> (35 - 5 * i)) & 31) as usize] as char)
        .collect();
    format!("{}-{}", &s[..4], &s[4..])
}

fn name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[1..].iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        })
}

fn urlsafe_b64_nopad(data: &[u8]) -> String {
    crate::util::base64(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

fn home_path() -> String {
    CLIENT_JSON.replacen('~', &std::env::var("HOME").unwrap_or_default(), 1)
}

fn local_stamp() -> String {
    // SAFETY: localtime_r and strftime write only into the buffers passed to them.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        let mut buf = [0u8; 32];
        let n = libc::strftime(
            buf.as_mut_ptr().cast(),
            buf.len(),
            c"%Y%m%d%H%M%S".as_ptr(),
            &tm,
        );
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

fn write_client_json(path: &str, cfg: &Value) -> std::io::Result<()> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let tmp = format!("{path}.tmp{}", std::process::id());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(format!("{}\n", json_dumps(cfg, Some(2))).as_bytes())?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn default_name() -> String {
    let host = hostname();
    let first = host.split('.').next().unwrap_or("").to_lowercase();
    let mut out = String::new();
    let mut in_run = false;
    for c in first.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('-');
            in_run = true;
        }
    }
    let name: String = out.trim_matches(['-', '.']).chars().take(32).collect();
    if name_ok(&name) {
        name
    } else {
        "client".to_string()
    }
}

pub fn run(argv: &[String]) -> R {
    let help = || crate::text_gen::help("enroll").unwrap_or_default();
    let (mut name, mut url, mut force) = (None::<String>, None::<String>, false);
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--force" {
            force = true;
            i += 1;
        } else if (a == "--name" || a == "--url") && i + 1 < argv.len() {
            if a == "--name" {
                name = Some(argv[i + 1].clone());
            } else {
                url = Some(argv[i + 1].clone());
            }
            i += 2;
        } else {
            return Err(die(
                format!("unexpected argument {}\n{}", repr(a), help()),
                USAGE,
            ));
        }
    }
    let path = home_path();
    let old: Option<Value> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object);
    let old_get = |k: &str| {
        old.as_ref()
            .and_then(|o| o.get(k))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let env_url = std::env::var("SECRET_BROKER_URL")
        .ok()
        .filter(|v| !v.is_empty());
    let url = url
        .filter(|u| !u.is_empty())
        .or(env_url)
        .or_else(|| old_get("url"))
        .unwrap_or_default();
    let url = url.trim_end_matches('/').to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(die(
            format!(
                "no broker url: pass --url https://broker.example/ or set SECRET_BROKER_URL\n{}",
                help()
            ),
            USAGE,
        ));
    }
    let name = name.unwrap_or_else(default_name);
    if !name_ok(&name) {
        return Err(die(
            "--name must be 1-32 lowercase letters, digits, - _ . and start with a letter or digit",
            USAGE,
        ));
    }
    if old_get("key").is_some() && !force {
        return Err(die(
            format!("{CLIENT_JSON} already holds a key; enrolling would replace it. Run with --force to do it (the old file is first copied to client.json.bak-<time>), or use another HOME."),
            USAGE,
        ));
    }
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .map_err(|e| die(format!("no random source: {e}"), USAGE))?;
    let secret = format!("{CLIENT_SECRET_PREFIX}{}", urlsafe_b64_nopad(&random));
    let h = enroll_hash(&secret);
    let code = enroll_code(&h);
    let claim: String = format!(
        "{}@{}",
        std::env::var("USER").unwrap_or_else(|_| "?".into()),
        hostname()
    )
    .chars()
    .map(|c| {
        if c.is_ascii_alphanumeric() || "@._:+()[]-".contains(c) {
            c
        } else {
            '_'
        }
    })
    .take(120)
    .collect();
    let ua = crate::broker::USER_AGENT;
    let post = json!({"name": name, "hash": h, "claim": claim});
    let (status, r) =
        match anonymous_json(&url, ua, "/v1/enroll", Some(&post), Duration::from_secs(20)) {
            Ok(v) => v,
            Err(class) => return Err(die(format!("cannot reach the broker ({class})"), BROKER)),
        };
    if status != 202 || !r.get("id").is_some_and(Value::is_string) {
        let why = r
            .get("error")
            .filter(|e| truthy(e))
            .map(|e| srv(&py_str(e), 160))
            .unwrap_or_else(|| srv(&format!("HTTP {status}"), 160));
        return Err(die(
            format!("the broker refused the enrollment: {why}"),
            BROKER,
        ));
    }
    if r.get("code").and_then(Value::as_str) != Some(code.as_str()) {
        return Err(die(
            "the broker returned a different confirmation code; not continuing",
            BROKER,
        ));
    }
    eprintln!("asb: enrollment requested as {}.", repr(&name));
    eprintln!("asb: confirmation code: {code}");
    eprintln!("asb: waiting for the human to approve the card with this same code on the approval page (deny it if the code differs or you did not start this)...");
    let int = |k: &str, default: i64| {
        r.get(k)
            .and_then(Value::as_i64)
            .filter(|v| *v != 0)
            .unwrap_or(default)
    };
    let deadline = Instant::now() + Duration::from_secs((int("expires_in", 600) + 15) as u64);
    let id = py_str(&r["id"]);
    let (mut errors, mut approved) = (0, None::<Value>);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(int("interval", 2).clamp(1, 10) as u64));
        let polled = anonymous_json(
            &url,
            ua,
            &format!("/v1/enroll/{}", quote(&id)),
            None,
            Duration::from_secs(20),
        );
        let (st, p) = match polled {
            Ok((st, p)) if ![429, 500, 502, 503, 504].contains(&st) => (st, p),
            _ => {
                errors += 1;
                if errors > 15 {
                    return Err(die("lost contact with the broker while waiting", BROKER));
                }
                continue;
            }
        };
        errors = 0;
        if st != 200 {
            return Err(die("the broker no longer knows this enrollment", BROKER));
        }
        match p.get("status").and_then(Value::as_str) {
            Some("denied") => return Err(die("enrollment denied", DENIED)),
            Some("expired") => {
                return Err(die("enrollment expired before anyone approved it", EXPIRED))
            }
            Some("approved") => {
                approved = Some(p);
                break;
            }
            _ => {}
        }
    }
    let Some(p) = approved else {
        return Err(die("timed out waiting for approval", EXPIRED));
    };
    let mut backup = None::<String>;
    if let Some(old) = &old {
        let b = format!("{path}.bak-{}", local_stamp());
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&b)
            .map_err(|e| die(format!("cannot write {b}: {e}"), USAGE))?;
        let _ = f.write_all(format!("{}\n", json_dumps(old, Some(2))).as_bytes());
        backup = Some(b);
    }
    let mut new: Map<String, Value> = old
        .as_ref()
        .and_then(|o| o.as_object().cloned())
        .unwrap_or_default();
    new.insert("url".into(), json!(url));
    new.insert("key".into(), json!(secret));
    write_client_json(&path, &Value::Object(new))
        .map_err(|e| die(format!("cannot write {path}: {e}"), USAGE))?;
    // prove the new credential works before calling this done; otherwise put the old file back
    let probe = Client::with_user_agent(
        Config {
            url: url.clone(),
            key: secret.clone(),
        },
        ua,
    );
    let ok = matches!(
        probe.json("/v1/status", None, Duration::from_secs(20)),
        Ok((200, _))
    );
    if !ok {
        match &backup {
            Some(b) => {
                let _ = std::fs::copy(b, &path);
                let _ = std::fs::set_permissions(
                    &path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                );
            }
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }
        return Err(die("the broker approved the enrollment but rejected the new key; client.json was not changed", BROKER));
    }
    let shown = p
        .get("name")
        .filter(|n| truthy(n))
        .map(py_str)
        .unwrap_or(name.clone());
    let cid = p
        .get("client_id")
        .filter(|n| truthy(n))
        .map(py_str)
        .unwrap_or_else(|| "?".into());
    println!(
        "enrolled: {} ({})",
        safe_text(&shown, 40),
        safe_text(&cid, 16)
    );
    let saved = backup
        .as_ref()
        .map(|b| {
            format!(
                " (the previous file is saved as {})",
                std::path::Path::new(b)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            )
        })
        .unwrap_or_default();
    eprintln!("asb: wrote {CLIENT_JSON}{saved}. Nothing was printed that you need to keep.");
    if std::env::var("SECRET_BROKER_KEY").is_ok_and(|v| !v.is_empty()) {
        eprintln!("asb: the SECRET_BROKER_KEY environment variable is set and overrides client.json; unset it to use this machine's own credential.");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_code_match_the_python_client() {
        // values produced by client/asb: enroll_hash("asbc1_test-secret") and enroll_code of it
        assert_eq!(
            enroll_hash("asbc1_test-secret"),
            "c13a9649a1198bd605b79c459f551d8536c02cc564c9ec39556ce6b0dc5f7a3c"
        );
        assert_eq!(enroll_code(&enroll_hash("asbc1_test-secret")), "J2CS-OUVQ");
    }

    #[test]
    fn names_follow_the_enrollment_rule() {
        for ok in ["a", "build-box", "x_1.2", "0abc"] {
            assert!(name_ok(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a b", &"a".repeat(33)] {
            assert!(!name_ok(bad), "{bad:?}");
        }
    }
}
