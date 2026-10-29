//! Python-compatible formatting, so the Rust CLI prints the same bytes the Python one does: `json.dumps`,
//! `urllib.parse.quote`, `repr(str)`, and the broker-text sanitisers.

use serde_json::Value;

/// `json.dumps(value, indent=indent)` with Python's defaults: `ensure_ascii`, insertion-ordered keys, `", "`/`": "`.
pub fn json_dumps(v: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    dump(v, indent, 0, &mut out);
    out
}

fn dump(v: &Value, indent: Option<usize>, level: usize, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => dump_str(s, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                separator(i, indent, level + 1, out);
                dump(item, indent, level + 1, out);
            }
            close(indent, level, ']', out);
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, item)) in map.iter().enumerate() {
                separator(i, indent, level + 1, out);
                dump_str(k, out);
                out.push_str(": ");
                dump(item, indent, level + 1, out);
            }
            close(indent, level, '}', out);
        }
    }
}

fn separator(i: usize, indent: Option<usize>, level: usize, out: &mut String) {
    match indent {
        Some(n) => {
            if i > 0 {
                out.push(',');
            }
            out.push('\n');
            out.push_str(&" ".repeat(n * level));
        }
        None => {
            if i > 0 {
                out.push_str(", ");
            }
        }
    }
}

fn close(indent: Option<usize>, level: usize, bracket: char, out: &mut String) {
    if let Some(n) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(n * level));
    }
    out.push(bracket);
}

fn dump_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `urllib.parse.quote(s, safe="")`: everything but letters, digits and `_.-~` is %-encoded as UTF-8.
pub fn quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `repr(s)` for a `str`, as it appears in Python's error messages.
pub fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `str(value)` for a JSON value, for use inside an f-string.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => json_dumps(other, None),
    }
}

/// Python truthiness of a JSON value (`x or default`).
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Server-supplied text for a terminal: printable ASCII only, cut to `n` characters.
pub fn safe_text(text: &str, n: usize) -> String {
    text.chars()
        .map(|c| {
            if (32..127).contains(&(c as u32)) {
                c
            } else {
                '?'
            }
        })
        .take(n)
        .collect()
}

/// Text the broker sent, for a terminal: printable ASCII, and any run of 20 or more token-like characters is
/// replaced by `***` (defence in depth: a broker's error must not carry a credential into an agent's transcript).
pub fn srv(text: &str, n: usize) -> String {
    let clean = safe_text(text, 400);
    let is_token = |c: char| c.is_ascii_alphanumeric() || "_+/=.~-".contains(c);
    let (mut out, mut run) = (String::new(), String::new());
    for c in clean.chars().chain(std::iter::once('\0')) {
        if is_token(c) {
            run.push(c);
            continue;
        }
        out.push_str(&if run.chars().count() >= 20 {
            "***".to_string()
        } else {
            run.clone()
        });
        run.clear();
        if c != '\0' {
            out.push(c);
        }
    }
    out.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_dumps_matches_pythons_indent_2() {
        let v = json!({"name": "svc", "vars": ["A", "B"], "empty": [], "none": null, "n": 3, "ok": true, "o": {}});
        assert_eq!(
            json_dumps(&v, Some(2)),
            "{\n  \"name\": \"svc\",\n  \"vars\": [\n    \"A\",\n    \"B\"\n  ],\n  \"empty\": [],\n  \"none\": null,\n  \"n\": 3,\n  \"ok\": true,\n  \"o\": {}\n}"
        );
        assert_eq!(json_dumps(&json!([1, "a"]), None), "[1, \"a\"]");
    }

    #[test]
    fn json_dumps_escapes_like_ensure_ascii() {
        // the expected text is what Python prints for json.dumps("é😀\n\"\\\x01\x7f")
        let got = json_dumps(&json!("é\u{1F600}\n\"\\\u{1}\u{7f}"), None);
        assert_eq!(got, r#""\u00e9\ud83d\ude00\n\"\\\u0001\u007f""#);
    }

    #[test]
    fn quote_matches_urllib() {
        assert_eq!(quote("api.example.com"), "api.example.com");
        assert_eq!(
            quote("https://x/a b?c=é"),
            "https%3A%2F%2Fx%2Fa%20b%3Fc%3D%C3%A9"
        );
        assert_eq!(quote("a~b_c-d.e"), "a~b_c-d.e");
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr("foo"), "'foo'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(repr("a\"b'c"), "'a\"b\\'c'");
        assert_eq!(repr("a\nb\\"), "'a\\nb\\\\'");
    }

    #[test]
    fn srv_masks_long_token_runs_and_strips_non_ascii() {
        assert_eq!(
            srv("bad token abcdefghijklmnopqrstuvwxyz here", 160),
            "bad token *** here"
        );
        assert_eq!(srv("short abc123", 160), "short abc123");
        assert_eq!(srv("caf\u{e9}\u{1b}[31m", 160), "caf??[31m");
        assert_eq!(srv(&"a".repeat(25), 160), "***");
    }

    #[test]
    fn python_str_and_truthiness() {
        assert_eq!(py_str(&json!(null)), "None");
        assert_eq!(py_str(&json!(true)), "True");
        assert!(
            !truthy(&json!(""))
                && !truthy(&json!(null))
                && truthy(&json!("x"))
                && !truthy(&json!(0))
        );
    }
}
