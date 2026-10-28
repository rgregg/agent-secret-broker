//! The destination a wrapped command line *claims* it will connect to (`user@host:port`), for the approval card.
//! Unverified by construction (ssh_config can rename hosts, a script can do anything): the broker shows it as
//! "claimed by the client". A port of `claimed_destination` in client/asb, held to its output by
//! tests/fixtures/cli/ssh_claim.json. Never runs anything.
//!
//! One deliberate difference: a port written with Unicode digits (`２２`) or a number Python's `int()` would take
//! in some other exotic spelling gives no claim here. Fewer claims is the safe direction.

use std::collections::BTreeSet;

const SSH_VAL: &str = "BbcDEeFIiJLlmOopQRSWw";
const SCP_VAL: &str = "cDFiJloPS";
const SFTP_VAL: &str = "BbcDFiJloPRSs";

/// (user, host, port) as the Python tuples carry them: `None` and `""` differ and both are kept.
type Target = (Option<String>, String, Option<String>);
type Opts = Vec<(char, String)>;

fn partition(s: &str, sep: &str) -> (String, String, String) {
    match s.find(sep) {
        Some(i) => (s[..i].into(), sep.into(), s[i + sep.len()..].into()),
        None => (s.into(), String::new(), String::new()),
    }
}

fn rpartition(s: &str, sep: &str) -> (String, String, String) {
    match s.rfind(sep) {
        Some(i) => (s[..i].into(), sep.into(), s[i + sep.len()..].into()),
        None => (String::new(), String::new(), s.into()),
    }
}

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `^[A-Za-z0-9_][A-Za-z0-9._-]*\Z`
fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    it.next().is_some_and(word_char) && it.all(|c| word_char(c) || c == '.' || c == '-')
}

/// `_HOST_RE`: a name, or something made of hex digits, `:` and `.` that has a colon in it.
fn host_ok(h: &str) -> bool {
    is_name(h)
        || (h.contains(':')
            && h.chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.'))
}

/// Python's `int(text)` for the spellings that make sense for a port.
pub fn port_number(text: &str) -> Option<u32> {
    let t = text.trim();
    let t = t.strip_prefix(['+']).unwrap_or(t);
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let digits: String = t.chars().filter(|c| *c != '_').collect();
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    if trimmed.len() > 6 {
        return Some(u32::MAX);
    }
    Some(if trimmed.is_empty() {
        0
    } else {
        trimmed.parse().ok()?
    })
}

fn first_n(s: String, n: usize) -> String {
    s.chars().take(n).collect()
}

fn fmt(user: Option<&str>, host: &str, port: Option<&str>, jump: Option<&str>) -> Option<String> {
    let user = user.filter(|u| !u.is_empty());
    if host.is_empty() || !host_ok(host) || user.is_some_and(|u| !is_name(u)) {
        return None;
    }
    let port = port_number(port?)?;
    if !(0 < port && port < 65536) {
        return None;
    }
    let h = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let mut out = format!(
        "{}{h}:{port}",
        user.map(|u| format!("{u}@")).unwrap_or_default()
    );
    if let Some(j) = jump.filter(|j| !j.is_empty()) {
        out.push_str(&format!(" (via {j})"));
    }
    Some(first_n(out, 200))
}

/// `[user@]host | ssh://[user@]host[:port][/..]` to (user, host, port).
fn split_target(t: &str) -> Target {
    let url = ["ssh://", "scp://", "sftp://"]
        .iter()
        .any(|p| t.starts_with(p));
    let mut t = t.to_string();
    if url {
        let after = partition(&t, "://").2;
        t = partition(&after, "/").0;
    }
    let mut user = None;
    if t.contains('@') {
        let (u, _, rest) = rpartition(&t, "@");
        user = Some(u);
        t = rest;
    }
    let host;
    let mut port = None;
    if let Some(inner) = t.strip_prefix('[') {
        let (h, _, rest) = partition(inner, "]");
        host = h;
        if let Some(p) = rest.strip_prefix(':') {
            if !p.is_empty() {
                port = Some(p.to_string());
            }
        }
    } else if url && t.matches(':').count() == 1 {
        let (h, _, p) = partition(&t, ":");
        host = h;
        port = Some(p);
    } else {
        host = t;
    }
    (user.filter(|u| !u.is_empty()), host, port)
}

fn jump_note(jump: Option<&str>) -> Option<String> {
    let hops: Vec<&str> = jump
        .unwrap_or("")
        .split(',')
        .filter(|h| !h.is_empty())
        .collect();
    let ok = |h: &&str| {
        h.chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._:[]%-".contains(c))
    };
    if hops.is_empty() || !hops.iter().all(ok) {
        return None;
    }
    let extra = if hops.len() > 1 {
        format!("+{}", hops.len() - 1)
    } else {
        String::new()
    };
    Some(format!("{}{extra}", hops[0]))
}

/// `-o Key=Value` / `-o 'Key Value'` to the first value per lower-cased key (first wins, like ssh).
fn o_value(opts: &Opts, key: &str) -> Option<String> {
    for (c, v) in opts {
        if *c == 'o' {
            let spaced = v.replacen('=', " ", 1);
            let (k, _, val) = partition(&spaced, " ");
            if k.trim().to_lowercase() == key {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

fn first(opts: &Opts, c: char) -> Option<String> {
    opts.iter().find(|(k, _)| *k == c).map(|(_, v)| v.clone())
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

fn build(
    user: Option<String>,
    host: &str,
    port: Option<String>,
    opts: &Opts,
    jump_opt: Option<String>,
) -> Option<String> {
    let host = nonempty(o_value(opts, "hostname")).unwrap_or_else(|| host.to_string());
    let user = nonempty(user).or_else(|| nonempty(o_value(opts, "user")));
    let port = nonempty(port)
        .or_else(|| nonempty(o_value(opts, "port")))
        .unwrap_or_else(|| "22".into());
    let jump = nonempty(jump_opt).or_else(|| nonempty(o_value(opts, "proxyjump")));
    fmt(
        user.as_deref(),
        &host,
        Some(&port),
        jump_note(jump.as_deref()).as_deref(),
    )
}

/// Split ssh-style args into (options, operands).
fn walk(args: &[String], val_opts: &str) -> (Opts, Vec<String>) {
    let (mut opts, mut ops, mut i) = (Opts::new(), Vec::new(), 0);
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            ops.extend(args[i..].iter().cloned());
            break;
        }
        let chars: Vec<char> = a.chars().collect();
        if chars.len() > 1 && chars[0] == '-' {
            for j in 1..chars.len() {
                if val_opts.contains(chars[j]) {
                    let attached: String = chars[j + 1..].iter().collect();
                    let v = if !attached.is_empty() {
                        attached
                    } else {
                        i += 1;
                        args.get(i - 1).cloned().unwrap_or_default()
                    };
                    opts.push((chars[j], v));
                    break;
                }
            }
            continue;
        }
        ops.push(a.clone());
    }
    (opts, ops)
}

/// `ssh [options] [user@]host [command]`: the first operand is the destination.
fn ssh_claim(args: &[String]) -> Option<String> {
    let (mut opts, mut i) = (Opts::new(), 0);
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            break;
        }
        let chars: Vec<char> = a.chars().collect();
        if !(chars.len() > 1 && chars[0] == '-') {
            i -= 1;
            break;
        }
        for j in 1..chars.len() {
            if SSH_VAL.contains(chars[j]) {
                let attached: String = chars[j + 1..].iter().collect();
                if !attached.is_empty() {
                    opts.push((chars[j], attached));
                } else if i < args.len() {
                    opts.push((chars[j], args[i].clone()));
                    i += 1;
                }
                break;
            }
        }
    }
    let target = args.get(i)?;
    let (user, host, port) = split_target(target);
    build(
        nonempty(user).or_else(|| first(&opts, 'l')),
        &host,
        nonempty(port).or_else(|| first(&opts, 'p')),
        &opts,
        first(&opts, 'J'),
    )
}

/// (remote shell command string, operands) for an rsync command line.
fn rsync_args(args: &[String]) -> (String, Vec<String>) {
    let (mut rsh, mut ops, mut i) = ("ssh".to_string(), Vec::new(), 0);
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if let Some(v) = a.strip_prefix("--rsh=") {
            rsh = v.to_string();
        } else if a == "--rsh" && i < args.len() {
            rsh = args[i].clone();
            i += 1;
        } else if a.starts_with('-') && !a.starts_with("--") && a.ends_with('e') && i < args.len() {
            rsh = args[i].clone(); // -e CMD, or a cluster ending in e (-ae CMD)
            i += 1;
        } else if !a.starts_with('-') {
            ops.push(a.clone());
        }
    }
    (rsh, ops)
}

/// A `[user@]host:path` or `scp://...` operand of scp, sftp or rsync.
fn remote_operand(a: &str) -> Option<Target> {
    if ["scp://", "sftp://", "ssh://"]
        .iter()
        .any(|p| a.starts_with(p))
    {
        let t = split_target(a);
        return if t.1.is_empty() { None } else { Some(t) };
    }
    if ["rsync://", "-", "/", ".", "~"]
        .iter()
        .any(|p| a.starts_with(p))
    {
        return None;
    }
    let head = partition(a, "/").0;
    let (user, rest) = if head.contains('@') {
        let (u, _, r) = partition(a, "@");
        (Some(u), r)
    } else {
        (None, a.to_string())
    };
    if let Some(inner) = rest.strip_prefix('[') {
        let (host, _, after) = partition(inner, "]");
        return after.starts_with(':').then_some((user, host, None));
    }
    if partition(&rest, "/").0.contains("::") {
        return None; // host::module is an rsync daemon, not ssh
    }
    let (host, sep, _path) = partition(&rest, ":");
    (!sep.is_empty() && !host.contains('/')).then_some((user, host, None))
}

/// Python's `shlex.split` (POSIX mode, no comments). `None` where it raises `ValueError`.
fn shlex_split(s: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = s.chars().collect();
    let (mut words, mut i) = (Vec::new(), 0);
    loop {
        while i < chars.len() && " \t\r\n".contains(chars[i]) {
            i += 1;
        }
        if i >= chars.len() {
            return Some(words);
        }
        let mut token = String::new();
        while i < chars.len() && !" \t\r\n".contains(chars[i]) {
            let c = chars[i];
            i += 1;
            match c {
                '\\' => {
                    token.push(*chars.get(i)?);
                    i += 1;
                }
                '\'' => {
                    let end = chars[i..].iter().position(|x| *x == '\'')? + i;
                    token.extend(&chars[i..end]);
                    i = end + 1;
                }
                '"' => loop {
                    let x = *chars.get(i)?;
                    i += 1;
                    if x == '"' {
                        break;
                    }
                    if x == '\\' {
                        let n = *chars.get(i)?;
                        i += 1;
                        if n != '"' && n != '\\' {
                            token.push('\\');
                        }
                        token.push(n);
                    } else {
                        token.push(x);
                    }
                },
                other => token.push(other),
            }
        }
        words.push(token);
    }
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or("")
}

/// The `user@host:port` the command line says it will connect to, or `None` when that cannot be told confidently.
pub fn claimed_destination(argv: &[String]) -> Option<String> {
    let prog = base_name(argv.first()?);
    let args = &argv[1..];
    match prog {
        "ssh" => ssh_claim(args),
        "scp" | "sftp" | "rsync" => {
            let (sopts, ops): (Opts, Vec<String>) = if prog == "rsync" {
                let (rsh, ops) = rsync_args(args);
                let words = shlex_split(&rsh)?;
                if words.is_empty() || base_name(&words[0]) != "ssh" {
                    return None;
                }
                (walk(&words[1..], SSH_VAL).0, ops)
            } else {
                let (opts, ops) = walk(args, if prog == "scp" { SCP_VAL } else { SFTP_VAL });
                (
                    opts.into_iter()
                        .map(|(c, v)| (if c == 'P' { 'p' } else { c }, v))
                        .collect(),
                    ops,
                )
            };
            let mut targets: BTreeSet<Target> = BTreeSet::new();
            if prog == "sftp" {
                if let Some(op) = ops.first() {
                    targets.insert(remote_operand(op).unwrap_or_else(|| split_target(op)));
                }
            } else {
                targets.extend(ops.iter().filter_map(|o| remote_operand(o)));
            }
            if targets.len() != 1 {
                return None; // nothing remote, or several different hosts
            }
            let (user, host, port) = targets.into_iter().next()?;
            build(
                nonempty(user).or_else(|| first(&sopts, 'l')),
                &host,
                nonempty(port).or_else(|| first(&sopts, 'p')),
                &sopts,
                first(&sopts, 'J'),
            )
        }
        "git" => {
            let mut cands: BTreeSet<Target> = BTreeSet::new();
            for a in args {
                if a.starts_with("ssh://") {
                    cands.insert(split_target(a));
                } else if partition(a, ":").0.contains('@')
                    && !["-", "/", "."].iter().any(|p| a.starts_with(p))
                {
                    if let Some(t) = remote_operand(a) {
                        cands.insert(t);
                    }
                }
            }
            if cands.len() != 1 {
                return None;
            }
            let (user, host, port) = cands.into_iter().next()?;
            fmt(
                user.as_deref(),
                &host,
                Some(&nonempty(port).unwrap_or_else(|| "22".into())),
                None,
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn matches_every_golden_case_recorded_from_python() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/cli/ssh_claim.json"
        );
        let cases: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(cases.len() > 2000);
        let mut bad = Vec::new();
        for c in &cases {
            let argv: Vec<String> = c["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let want = c["claim"].as_str().map(String::from);
            let got = claimed_destination(&argv);
            if got != want {
                bad.push(format!("{argv:?}: want {want:?}, got {got:?}"));
            }
        }
        assert!(
            bad.is_empty(),
            "{} differ, first: {:#?}",
            bad.len(),
            &bad[..bad.len().min(10)]
        );
    }

    #[test]
    fn shlex_matches_python_on_the_cases_that_matter() {
        let w = |s| shlex_split(s);
        assert_eq!(
            w("ssh -p 22"),
            Some(vec!["ssh".into(), "-p".into(), "22".into()])
        );
        assert_eq!(
            w(r#"a "b \" c" 'd e' f\ g"#),
            Some(vec![
                "a".into(),
                "b \" c".into(),
                "d e".into(),
                "f g".into()
            ])
        );
        assert_eq!(w(r#""a\x""#), Some(vec![r"a\x".into()]));
        assert_eq!(w(r#"x """#), Some(vec!["x".into(), "".into()]));
        assert_eq!(w("'open"), None);
        assert_eq!(w("trailing\\"), None);
    }
}
