//! Small helpers several commands share, each a port of the Python function of the same name.

use crate::exit::{die, Die, USAGE};
use crate::pyfmt::repr;
use crate::text_gen;
use std::io::{Read, Write};

/// `die(HELP[topic])`: the help text becomes the error message.
pub fn die_help(topic: &str) -> Die {
    die(text_gen::help(topic).unwrap_or_default(), USAGE)
}

/// A flag where a name should be is a mistake worth saying so about.
pub fn check_name(name: &str, what: &str) -> Result<(), Die> {
    if name.starts_with('-') {
        return Err(die(
            format!(
                "{what} {} looks like a flag, not a credential name (see `asb list`; `asb help` for usage)",
                repr(name)
            ),
            USAGE,
        ));
    }
    Ok(())
}

/// `parse_flags`: `--flag value` pairs from `allowed` (flag, key); anything else is a usage error.
pub fn parse_flags(
    argv: &[String],
    allowed: &[(&str, &str)],
) -> Result<Vec<(String, String)>, Die> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let key = allowed.iter().find(|(flag, _)| *flag == argv[i]);
        match (key, argv.get(i + 1)) {
            (Some((_, name)), Some(value)) => {
                match out.iter_mut().find(|(k, _)| k == name) {
                    Some(slot) => slot.1 = value.clone(), // as a dict would: the first position is kept
                    None => out.push((name.to_string(), value.clone())),
                }
            }
            _ => {
                return Err(die(
                    format!("unexpected argument {}", repr(&argv[i])),
                    USAGE,
                ))
            }
        }
        i += 2;
    }
    Ok(out)
}

/// `urllib.parse.urlencode(pairs)`: `quote_plus` on keys and values, joined with `&`.
pub fn urlencode(pairs: &[(String, String)]) -> String {
    let plus = |s: &str| crate::pyfmt::quote(s).replace("%20", "+");
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", plus(k), plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Python's text-mode read translates `\r\n` and a lone `\r` to `\n`.
pub fn universal_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

pub fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The machine's host name.
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for 256 bytes and the call writes at most that many, NUL-terminated.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    if !ok {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// `user@host`: what the broker shows as the client's own (unverified) claim.
pub fn source() -> String {
    format!(
        "{}@{}",
        std::env::var("USER").unwrap_or_else(|_| "?".into()),
        hostname()
    )
}

/// Standard base64 with padding.
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

const MAX_BODY: usize = 5_000_000;

/// `-d BODY | -d @file | -d @-`: the fields to merge into the request. UTF-8 is sent as text (so `{{VAR}}`
/// placeholders are filled in); anything else as base64, passed through untouched.
pub fn read_body(arg: &str) -> Result<Vec<(&'static str, serde_json::Value)>, Die> {
    use serde_json::Value;
    let Some(path) = arg.strip_prefix('@') else {
        return Ok(vec![("body", Value::String(arg.to_string()))]);
    };
    let mut raw = Vec::new();
    let read = if arg == "@-" {
        std::io::stdin().read_to_end(&mut raw)
    } else {
        std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut raw))
    };
    if let Err(e) = read {
        return Err(die(format!("cannot read body: {}", os_error(&e)), USAGE));
    }
    if raw.len() > MAX_BODY {
        return Err(die(
            format!("body is {} bytes; limit is {MAX_BODY}", raw.len()),
            USAGE,
        ));
    }
    Ok(match String::from_utf8(raw) {
        Ok(text) => vec![("body", Value::String(text))],
        Err(e) => vec![("body_b64", Value::String(base64(e.as_bytes())))],
    })
}

/// An I/O error as Python's `OSError` prints it: `[Errno 2] No such file or directory: 'path'` without the path.
pub fn os_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => format!("[Errno {n}] {}", strerror(n)),
        None => e.to_string(),
    }
}

fn strerror(n: i32) -> String {
    // SAFETY: strerror returns a pointer to a static NUL-terminated message.
    unsafe {
        std::ffi::CStr::from_ptr(libc::strerror(n))
            .to_string_lossy()
            .into_owned()
    }
}

/// The credential value: stdin (a pipe), or a hidden prompt on a terminal. Never an argument, so it cannot end up in
/// shell history or `ps`.
pub fn read_value() -> Result<String, Die> {
    // SAFETY: isatty only inspects a file descriptor.
    let value = if unsafe { libc::isatty(0) } == 1 {
        prompt_hidden("value (hidden): ")
    } else {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| die(format!("cannot read stdin: {e}"), USAGE))?;
        s
    };
    let value = value.trim_end_matches(['\r', '\n']).to_string();
    if value.is_empty() {
        return Err(die("no value on stdin", USAGE));
    }
    Ok(value)
}

/// `getpass`: the prompt and the typed line go through the terminal, with echo off.
fn prompt_hidden(prompt: &str) -> String {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok();
    let fd = std::os::fd::AsRawFd::as_raw_fd(
        tty.as_ref()
            .unwrap_or(&std::fs::File::open("/dev/stdin").expect("stdin")),
    );
    // SAFETY: termios calls on a valid, open terminal descriptor; the saved state is restored before returning.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) == 0 {
            let old = t;
            t.c_lflag &= !libc::ECHO;
            libc::tcsetattr(fd, libc::TCSAFLUSH, &t);
            Some(old)
        } else {
            None
        }
    };
    let mut err = std::io::stderr();
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    if let Some(old) = saved {
        // SAFETY: restores the attributes read above on the same descriptor.
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &old) };
    }
    let _ = writeln!(err);
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0xff, 0xfe, 0xfd, 0xfc]), "//79/A==");
    }

    #[test]
    fn parse_flags_takes_pairs_and_rejects_the_rest() {
        let argv: Vec<String> = ["--var", "A", "--var", "B"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let f = parse_flags(&argv, &[("--var", "var")]).unwrap();
        assert_eq!(
            flag(&f, "var"),
            Some("B"),
            "a repeated flag keeps the last, as a dict would"
        );
        assert!(parse_flags(
            &["--nope".to_string(), "x".to_string()],
            &[("--var", "var")]
        )
        .is_err());
        assert!(parse_flags(&["--var".to_string()], &[("--var", "var")]).is_err());
    }
}
