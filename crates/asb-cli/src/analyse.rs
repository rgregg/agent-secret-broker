//! Which script files does a command run, and is the whole command one we positively understand? A port of the
//! "shared-detection" block of client/asb (`_analyze` and what it calls), which secret_broker/scripts.py carries an
//! identical copy of: the broker applies the same rules to the argv it receives. Held to Python's answers by
//! tests/fixtures/cli/analyse.json (tools/gen_cli_golden.py), so "ported" means "reproduces Python".
//!
//! PRINCIPLE: a command is "understood" only when it is positively recognised; anything else (a parse doubt, an
//! unknown option on a wrapper, unusual shell syntax, a program that can run other programs) is NOT understood and
//! the broker prompts for it. Nothing here runs anything.
//!
//! Python's `$` also matches before a final newline; `rx` keeps that (`\n?\z`) so the patterns accept what they did.

use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

const MAX_SPLIT_DEPTH: usize = 4; // nested env -S / shell strings examined before giving up
const MAX_HOPS: usize = 32; // wrapper commands skipped before giving up
const SYSTEM_BIN: [&str; 4] = ["/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"];
const SCRIPT_EXT: [&str; 9] = [
    ".sh", ".py", ".js", ".rb", ".pl", ".php", ".ps1", ".lua", ".R",
];

/// A Python pattern as a compiled `Regex`: a trailing `$` becomes "end, or before one final newline".
fn rx(pattern: &str) -> Regex {
    let p = match pattern.strip_suffix('$') {
        Some(head) => format!(r"{head}\n?\z"),
        None => pattern.to_string(),
    };
    Regex::new(&p).unwrap_or_else(|e| panic!("bad pattern {pattern}: {e}"))
}

const PLAIN_NUM: &str = r"^\d+(?:\.\d+)?$";
const PLAIN_URL: &str = r"^https?://[^\s@]+$";
const PLAIN_HOST: &str = r"^[A-Za-z0-9._:@+=-]+$";

type Operand = fn(&[String]) -> bool;

/// One program's allow-list of plain read-only options (exact spellings; anything else is not understood).
/// short: flag letters (may be clustered); valued: short options with a value pattern; long / longv: long flags /
/// long options with a value pattern; exact: other whole tokens.
struct Plain {
    short: &'static str,
    valued: Vec<(char, Option<Regex>)>,
    long: &'static [&'static str],
    longv: Vec<(&'static str, Regex)>,
    exact: &'static [&'static str],
    digits: bool,
    max_operands: Option<usize>,
    operand: Option<Operand>,
}

impl Plain {
    fn new() -> Plain {
        Plain {
            short: "",
            valued: vec![],
            long: &[],
            longv: vec![],
            exact: &[],
            digits: false,
            max_operands: None,
            operand: None,
        }
    }
    fn short(mut self, s: &'static str) -> Self {
        self.short = s;
        self
    }
    fn valued(mut self, v: &[(char, Option<&str>)]) -> Self {
        self.valued = v.iter().map(|(c, p)| (*c, p.map(rx))).collect();
        self
    }
    fn long(mut self, l: &'static [&'static str]) -> Self {
        self.long = l;
        self
    }
    fn longv(mut self, l: &[(&'static str, &str)]) -> Self {
        self.longv = l.iter().map(|(n, p)| (*n, rx(p))).collect();
        self
    }
    fn exact(mut self, e: &'static [&'static str]) -> Self {
        self.exact = e;
        self
    }
    fn digits(mut self) -> Self {
        self.digits = true;
        self
    }
    fn max(mut self, n: usize) -> Self {
        self.max_operands = Some(n);
        self
    }
    fn operand(mut self, f: Operand) -> Self {
        self.operand = Some(f);
        self
    }
}

fn all_match(ops: &[String], p: &'static str, cell: &'static OnceLock<Regex>) -> bool {
    let re = cell.get_or_init(|| rx(p));
    ops.iter().all(|o| re.is_match(o))
}

fn host_operands(ops: &[String]) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    all_match(ops, PLAIN_HOST, &R)
}

fn url_operands(ops: &[String]) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    all_match(ops, PLAIN_URL, &R)
}

fn alpha_operands(ops: &[String]) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    all_match(ops, r"^[A-Za-z]+$", &R)
}

fn plus_operands(ops: &[String]) -> bool {
    ops.iter().all(|o| o.starts_with('+'))
}

fn jq_filter_ok(ops: &[String]) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| rx(r"\b(?:input_filename|ENV|env|include|import|get_search_list)\b"));
    ops.first().is_none_or(|first| !re.is_match(first))
}

fn plain_programs() -> &'static HashMap<&'static str, Plain> {
    static T: OnceLock<HashMap<&'static str, Plain>> = OnceLock::new();
    T.get_or_init(|| {
        let n = Some(PLAIN_NUM);
        let mut m: HashMap<&'static str, Plain> = HashMap::new();
        m.insert("cat", Plain::new().short("nbsvAET"));
        m.insert("ls", Plain::new().short("lahtr1AFRSdisL"));
        m.insert(
            "head",
            Plain::new()
                .short("qv")
                .valued(&[('n', n), ('c', n)])
                .digits(),
        );
        m.insert(
            "tail",
            Plain::new()
                .short("qvfF")
                .valued(&[('n', Some(r"^[+]?\d+$")), ('c', Some(r"^[+]?\d+$"))])
                .digits(),
        );
        m.insert("wc", Plain::new().short("lwcmL"));
        for name in ["grep", "egrep", "fgrep"] {
            m.insert(
                name,
                Plain::new().short("invcEFwxrRHhlLqsoaI").valued(&[
                    ('e', None),
                    ('m', n),
                    ('A', n),
                    ('B', n),
                    ('C', n),
                ]),
            );
        }
        m.insert("echo", Plain::new().short("neE"));
        m.insert("printf", Plain::new());
        m.insert(
            "date",
            Plain::new()
                .short("uRI")
                .long(&["--utc", "--rfc-email"])
                .max(1)
                .operand(plus_operands),
        );
        m.insert("uname", Plain::new().short("asnrvmpio"));
        m.insert("uptime", Plain::new().short("ps"));
        m.insert("df", Plain::new().short("hHTikPla"));
        m.insert(
            "du",
            Plain::new()
                .short("shackmbx")
                .valued(&[('d', Some(r"^\d+$"))]),
        );
        m.insert(
            "ps",
            Plain::new()
                .short("aefulwAxHjLm")
                .valued(&[('p', Some(r"^[\d,]+$"))])
                .operand(alpha_operands),
        );
        m.insert("id", Plain::new().short("ugGnrz").max(1));
        m.insert("whoami", Plain::new().max(0));
        m.insert("hostname", Plain::new().short("sfiI").max(0));
        m.insert("pwd", Plain::new().short("LP").max(0));
        m.insert("stat", Plain::new().short("L").valued(&[('c', None)]));
        m.insert(
            "jq",
            Plain::new()
                .short("rcesnSCMajR")
                .long(&[
                    "--raw-output",
                    "--compact-output",
                    "--exit-status",
                    "--slurp",
                    "--null-input",
                    "--sort-keys",
                    "--tab",
                    "--join-output",
                ])
                .operand(jq_filter_ok),
        );
        m.insert(
            "ping",
            Plain::new()
                .short("n46q")
                .valued(&[
                    ('c', Some(r"^\d+$")),
                    ('W', n),
                    ('w', Some(r"^\d+$")),
                    ('i', n),
                ])
                .max(1)
                .operand(host_operands),
        );
        m.insert(
            "dig",
            Plain::new()
                .short("46x")
                .valued(&[('t', Some(r"^[A-Za-z]+$")), ('p', Some(r"^\d+$"))])
                .operand(host_operands),
        );
        m.insert("nslookup", Plain::new().operand(host_operands));
        m.insert("sha256sum", Plain::new().short("bt"));
        m.insert("md5sum", Plain::new().short("bt"));
        m.insert(
            "sort",
            Plain::new()
                .short("nrubdfghMVsc")
                .valued(&[('k', Some(r"^[\d.,nrb]+$")), ('t', Some(r"^.$"))]),
        );
        m.insert("uniq", Plain::new().short("cdui").max(1));
        m.insert(
            "test",
            Plain::new().exact(&[
                "-e", "-f", "-d", "-r", "-w", "-x", "-s", "-z", "-n", "-L", "-h", "-eq", "-ne",
                "-lt", "-le", "-gt", "-ge", "-a", "-o",
            ]),
        );
        m.insert("true", Plain::new().max(0));
        m.insert("false", Plain::new().max(0));
        m.insert(
            "curl",
            Plain::new()
                .short("sSfLI")
                .valued(&[('H', Some(r"^[^\n\r@]+$")), ('X', Some(r"^(?:GET|HEAD)$"))])
                .long(&["--silent", "--show-error", "--fail", "--location", "--head"])
                .longv(&[
                    ("--max-time", PLAIN_NUM),
                    ("--connect-timeout", PLAIN_NUM),
                    ("--retry", r"^\d+$"),
                    ("--header", r"^[^\n\r@]+$"),
                    ("--request", r"^(?:GET|HEAD)$"),
                ])
                .operand(url_operands),
        );
        m
    })
}

fn val_ok(rx: Option<&Regex>, v: &str) -> bool {
    !v.contains('\0') && rx.is_none_or(|r| r.is_match(v))
}

fn digits_flag(a: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^-\d+\z").unwrap())
        .is_match(a)
}

fn plain_ok(name: &str, args: &[String]) -> bool {
    let Some(sp) = plain_programs().get(name) else {
        return false;
    };
    let (mut operands, mut i, mut opts) = (Vec::<String>::new(), 0, true);
    while i < args.len() {
        let a = &args[i];
        if a.contains('\0') {
            return false;
        }
        if opts && a == "--" {
            opts = false;
            i += 1;
        } else if opts && a.starts_with("--") {
            let (nm, eq, val) = match a.split_once('=') {
                Some((n, v)) => (n, true, v),
                None => (a.as_str(), false, ""),
            };
            if sp.long.contains(&nm) && !eq {
                i += 1;
            } else if let Some((_, pat)) = sp.longv.iter().find(|(n, _)| *n == nm) {
                let v = if eq {
                    i += 1;
                    val.to_string()
                } else if i + 1 < args.len() {
                    i += 2;
                    args[i - 1].clone()
                } else {
                    return false;
                };
                if !val_ok(Some(pat), &v) {
                    return false;
                }
            } else {
                return false;
            }
        } else if opts && a.starts_with('-') && a.chars().count() > 1 {
            i += 1;
            if sp.exact.contains(&a.as_str()) || (sp.digits && digits_flag(a)) {
                continue;
            }
            let chars: Vec<char> = a.chars().collect();
            let mut j = 1;
            while j < chars.len() {
                let c = chars[j];
                if sp.short.contains(c) {
                    j += 1;
                } else if let Some((_, pat)) = sp.valued.iter().find(|(k, _)| *k == c) {
                    let rest: String = chars[j + 1..].iter().collect();
                    let v = if !rest.is_empty() {
                        rest
                    } else if i < args.len() {
                        i += 1;
                        args[i - 1].clone()
                    } else {
                        return false;
                    };
                    if !val_ok(pat.as_ref(), &v) {
                        return false;
                    }
                    break;
                } else {
                    return false;
                }
            }
        } else {
            operands.push(a.clone());
            i += 1;
        }
    }
    if sp.max_operands.is_some_and(|m| operands.len() > m) {
        return false;
    }
    sp.operand.is_none_or(|f| f(&operands))
}

/// A wrapper's recognised options. s: flags, sv: options taking a value, so: optional attached value (rest of the
/// cluster), l/lv: long flags / long options with a value. An option not listed means the command is not understood.
#[derive(Default)]
struct Wrapper {
    s: &'static str,
    sv: &'static str,
    so: &'static str,
    l: &'static [&'static str],
    lv: &'static [&'static str],
    pos: usize,
    pos_unless: &'static [&'static str],
    digits: bool,
    dash: bool,
    chdir: &'static [&'static str],
}

fn wrappers() -> &'static HashMap<&'static str, Wrapper> {
    static T: OnceLock<HashMap<&'static str, Wrapper>> = OnceLock::new();
    T.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(
            "sudo",
            Wrapper {
                s: "nH",
                sv: "u",
                l: &["--non-interactive", "--set-home"],
                lv: &["--user"],
                ..Wrapper::default()
            },
        );
        m.insert(
            "doas",
            Wrapper {
                s: "n",
                sv: "u",
                ..Wrapper::default()
            },
        );
        m.insert("nohup", Wrapper::default());
        m.insert("time", Wrapper::default());
        m.insert(
            "timeout",
            Wrapper {
                sv: "sk",
                l: &["--preserve-status", "--foreground"],
                lv: &["--signal", "--kill-after"],
                pos: 1,
                ..Wrapper::default()
            },
        );
        m.insert(
            "nice",
            Wrapper {
                sv: "n",
                lv: &["--adjustment"],
                ..Wrapper::default()
            },
        );
        m.insert(
            "stdbuf",
            Wrapper {
                sv: "ioe",
                lv: &["--input", "--output", "--error"],
                ..Wrapper::default()
            },
        );
        m.insert("exec", Wrapper::default());
        m.insert("command", Wrapper::default());
        m
    })
}

fn env_opts() -> &'static Wrapper {
    static T: OnceLock<Wrapper> = OnceLock::new();
    T.get_or_init(|| Wrapper {
        s: "i0",
        sv: "u",
        l: &["--ignore-environment", "--null"],
        lv: &["--unset"],
        ..Wrapper::default()
    })
}

fn env_names(name: &str) -> bool {
    const PLAIN: [&str; 17] = [
        "LANG",
        "LANGUAGE",
        "TZ",
        "TERM",
        "COLUMNS",
        "LINES",
        "NO_COLOR",
        "CLICOLOR",
        "FORCE_COLOR",
        "CI",
        "DEBUG",
        "VERBOSE",
        "TERM_PROGRAM",
        "PYTHONUNBUFFERED",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONIOENCODING",
        "NODE_NO_WARNINGS",
    ];
    PLAIN.contains(&name)
        || name.strip_prefix("LC_").is_some_and(|r| {
            !r.is_empty() && r.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
}

/// `None` when `word` is not NAME=value; else whether it is an allowed assignment (an allowlisted NAME, and a value
/// with no `$`, backslash, backtick, newline, `/`, space or tab).
fn assignment(word: &str) -> Option<bool> {
    let (name, value) = word.split_once('=')?;
    let mut it = name.chars();
    let first = it.next()?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !it.all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(env_names(name) && !value.chars().any(|c| "$\\`\n\r\0/ \t".contains(c)))
}

const SHELL_RESERVED: [&str; 21] = [
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "function", "select", "time", "{", "}", "!", "[[", "coproc", "in",
];

const SHELLS: &str = r"(?:ba|z|da|k|a|c|tc)?sh|fish";

struct Interp {
    name: Regex,
    valued: &'static [&'static str],
    inline: &'static [&'static str],
    stdin: &'static [&'static str],
}

fn interpreters() -> &'static Vec<Interp> {
    static T: OnceLock<Vec<Interp>> = OnceLock::new();
    T.get_or_init(|| {
        let i = |pat: &str, valued, inline, stdin| Interp {
            name: rx(&format!("^(?:{pat})$")),
            valued,
            inline,
            stdin,
        };
        vec![
            i(
                SHELLS,
                &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"],
                &["-c"],
                &["-s"],
            ),
            i(
                r"python(?:\d+(?:\.\d+)*)?",
                &["-W", "-X", "-Q"],
                &["-c", "-m"],
                &[],
            ),
            i(
                "node|nodejs",
                &["-r", "--require", "--import", "--loader", "--input-type"],
                &["-e", "--eval", "-p", "--print"],
                &[],
            ),
            i("ruby", &["-I", "-r", "-C", "-x"], &["-e"], &[]),
            i("perl", &["-I", "-M", "-m"], &["-e", "-E"], &[]),
            i("php", &["-d", "-c", "-z"], &["-r"], &[]),
            i(
                "pwsh|powershell",
                &[],
                &["-c", "-command", "-encodedcommand", "-e"],
                &[],
            ),
            i("lua|luajit", &["-l"], &["-e"], &[]),
            i("Rscript", &[], &["-e"], &[]),
        ]
    })
}

fn script_file_flags(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "php" => &["-f"],
        "awk" | "gawk" => &["-f", "--file"],
        "mawk" => &["-f"],
        "sed" => &["-f", "--file"],
        "pwsh" | "powershell" => &["-file", "-f"],
        _ => return None,
    })
}

fn is_awk_like(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(r"^(?:awk|gawk|mawk|sed)$"))
        .is_match(name)
}

fn is_runner(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(r"^(?:deno|bun)$")).is_match(name)
}

fn is_shell_name(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(&format!("^(?:{SHELLS})$")))
        .is_match(name)
}

/// What the arguments of a recognised interpreter say it will run.
#[derive(Debug, PartialEq)]
enum Found {
    File(Vec<String>),
    Inline(Option<String>),
    Stdin,
    Nothing,
    Unknown,
}

fn loader_opts(name: &str) -> &'static [&'static str] {
    match name {
        "node" | "nodejs" => &[
            "-r",
            "--require",
            "--import",
            "--loader",
            "--experimental-loader",
        ],
        "ruby" => &["-r", "-I"],
        "perl" => &["-M", "-m", "-I"],
        "php" => &["-d", "-c", "-z"],
        "lua" | "luajit" => &["-l"],
        _ if is_shell_name(name) => &["--rcfile", "--init-file"],
        _ => &[],
    }
}

fn chars_prefix2(a: &str) -> String {
    a.chars().take(2).collect()
}

fn perl_inline() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(r"^-[A-Za-z]*[eE]$"))
}

fn is_cluster(a: &str) -> bool {
    // ^-[A-Za-z]+$
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(r"^-[A-Za-z]+$")).is_match(a)
}

fn script_args(name: &str, args: &[String], loaders: bool) -> Option<Found> {
    let spec = interpreters().iter().find(|x| x.name.is_match(name));
    let is_awk = is_awk_like(name);
    if spec.is_none() && !is_awk && !is_runner(name) {
        return None;
    }
    let lo: &[&str] = if loaders { loader_opts(name) } else { &[] };
    if is_runner(name) {
        // deno run [opts] file | deno eval ... | bun [run] file
        let sub = args.first().map(String::as_str).unwrap_or("");
        if sub == "eval" {
            return Some(Found::Inline(None));
        }
        let rest = if sub == "run" || sub == "x" {
            &args[1..]
        } else {
            args
        };
        for a in rest {
            if a == "-" {
                return Some(Found::Stdin);
            }
            if !a.starts_with('-') {
                return Some(Found::File(vec![a.clone()]));
            }
        }
        return Some(Found::Nothing);
    }
    if is_awk {
        let (mut files, mut i, mut inline) = (Vec::<String>::new(), 0, false);
        let ffl = script_file_flags(name)
            .or_else(|| script_file_flags("awk"))
            .unwrap_or(&[]);
        while i < args.len() {
            let a = &args[i];
            if ffl.contains(&a.as_str()) && i + 1 < args.len() {
                files.push(args[i + 1].clone());
                i += 2;
                continue;
            }
            if let Some(v) = a.strip_prefix("--file=") {
                files.push(v.to_string());
            } else if ["-e", "--expression", "--source"].contains(&a.as_str())
                || a.starts_with("--expression=")
                || a.starts_with("--source=")
            {
                inline = true;
                if ["-e", "--expression", "--source"].contains(&a.as_str()) {
                    i += 1;
                }
            } else if a.starts_with('-') && a != "-" {
                // an option we do not interpret
            } else if files.is_empty() && !inline {
                return Some(Found::Inline(None)); // the program text is the first operand
            } else {
                break;
            }
            i += 1;
        }
        if !files.is_empty() && inline {
            return Some(Found::Unknown);
        }
        return Some(if !files.is_empty() {
            Found::File(files)
        } else if inline {
            Found::Inline(None)
        } else {
            Found::Nothing
        });
    }
    let spec = spec?;
    let short_inline: BTreeSet<char> = spec
        .inline
        .iter()
        .filter(|f| f.chars().count() == 2)
        .filter_map(|f| f.chars().nth(1))
        .collect();
    let short_stdin: BTreeSet<char> = spec
        .stdin
        .iter()
        .filter(|f| f.chars().count() == 2)
        .filter_map(|f| f.chars().nth(1))
        .collect();
    let ffl = script_file_flags(name).unwrap_or(&[]);
    let next = |i: usize| args.get(i + 1).cloned();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let a_len = a.chars().count();
        if !lo.is_empty()
            && (lo.contains(&a.as_str())
                || lo.contains(&a.split('=').next().unwrap_or(""))
                || (a_len > 2 && !a.starts_with("--") && lo.contains(&chars_prefix2(a).as_str())))
        {
            return Some(Found::Unknown); // loads code that is not a reported script
        }
        if a == "--" {
            return Some(match next(i) {
                Some(f) => Found::File(vec![f]),
                None => Found::Nothing,
            });
        }
        if a == "-" {
            return Some(Found::Stdin);
        }
        if ffl.contains(&a.as_str()) && i + 1 < args.len() {
            return Some(Found::File(vec![args[i + 1].clone()]));
        }
        if spec.inline.contains(&a.as_str()) || spec.inline.contains(&a.to_lowercase().as_str()) {
            return Some(Found::Inline(next(i)));
        }
        if spec.stdin.contains(&a.as_str()) {
            return Some(Found::Stdin);
        }
        if spec.valued.contains(&a.as_str()) {
            i += 2;
            continue;
        }
        if name == "perl" && perl_inline().is_match(a) {
            return Some(Found::Inline(None));
        }
        if is_cluster(a) && a_len > 2 && name != "perl" {
            let letters: BTreeSet<char> = a.chars().skip(1).collect();
            if !short_inline.is_disjoint(&letters) {
                return Some(Found::Inline(next(i)));
            }
            if !short_stdin.is_disjoint(&letters) {
                return Some(Found::Stdin);
            }
        } else if a.starts_with('-') || a.starts_with('+') {
            if name == "perl" && (a.starts_with("-e") || a.starts_with("-E")) {
                return Some(Found::Inline(None));
            }
            if name.starts_with("python") && (a.starts_with("-c") || a.starts_with("-m")) {
                return Some(Found::Inline(None));
            }
        } else {
            return Some(Found::File(vec![a.clone()]));
        }
        i += 1;
    }
    Some(Found::Nothing)
}

type Seen = BTreeSet<String>;
type Vals = Vec<(String, String)>;

fn canon_long(nm: &str, spec: &Wrapper) -> Option<String> {
    let names: BTreeSet<&str> = spec.l.iter().chain(spec.lv.iter()).copied().collect();
    if names.contains(nm) {
        return Some(nm.to_string());
    }
    if nm.chars().count() <= 2 {
        return None;
    }
    let hits: Vec<&&str> = names.iter().filter(|n| n.starts_with(nm)).collect();
    (hits.len() == 1).then(|| hits[0].to_string())
}

/// Parse the option at `args[i]`: the index after it, or `None` when not recognised.
fn parse_one(
    args: &[String],
    i: usize,
    spec: &Wrapper,
    seen: &mut Seen,
    vals: &mut Vals,
) -> Option<usize> {
    let a = &args[i];
    if a.starts_with("--") {
        let (nm, eq, val) = match a.split_once('=') {
            Some((n, v)) => (n, true, v),
            None => (a.as_str(), false, ""),
        };
        let canon = canon_long(nm, spec)?;
        seen.insert(canon.clone());
        if spec.lv.contains(&canon.as_str()) {
            if eq {
                vals.push((canon, val.to_string()));
                return Some(i + 1);
            }
            if i + 1 >= args.len() {
                return None;
            }
            vals.push((canon, args[i + 1].clone()));
            return Some(i + 2);
        }
        return Some(i + 1);
    }
    if spec.digits && digits_flag(a) {
        return Some(i + 1);
    }
    let chars: Vec<char> = a.chars().collect();
    let (mut j, nxt) = (1, i + 1);
    while j < chars.len() {
        let c = chars[j];
        let key = format!("-{c}");
        seen.insert(key.clone());
        if spec.sv.contains(c) {
            let rest: String = chars[j + 1..].iter().collect();
            if !rest.is_empty() {
                vals.push((key, rest));
                return Some(nxt);
            }
            if nxt >= args.len() {
                return None;
            }
            vals.push((key, args[nxt].clone()));
            return Some(nxt + 1);
        }
        if spec.so.contains(c) {
            vals.push((key, chars[j + 1..].iter().collect()));
            return Some(nxt);
        }
        if !spec.s.contains(c) {
            return None;
        }
        j += 1;
    }
    Some(nxt)
}

/// (operands, seen options), or `None` when an option is not recognised (or the wrapper changes the
/// directory/filesystem the command runs in).
fn parse_opts(args: &[String], spec: &Wrapper) -> Option<(Vec<String>, Seen)> {
    let (mut i, mut seen, mut vals) = (0, Seen::new(), Vals::new());
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if a == "-" && spec.dash {
            seen.insert("-".into());
            i += 1;
        } else if a.starts_with('-') && a.chars().count() > 1 {
            i = parse_one(args, i, spec, &mut seen, &mut vals)?;
        } else {
            break;
        }
    }
    if !spec.chdir.is_empty()
        && (spec.chdir.contains(&"*") || spec.chdir.iter().any(|c| seen.contains(*c)))
    {
        return None;
    }
    Some((args[i..].to_vec(), seen))
}

/// env's options and VAR=value words skipped: (command argv, splits used), or (`None`, splits) when something is not
/// recognised. An -S/--split-string value is split with shlex and parsing carries on over the pieces; a value with a
/// backslash, $, # or newline (GNU env's own escapes and comments) is refused.
fn env_unwrap(args: &[String], mut splits: usize) -> (Option<Vec<String>>, usize) {
    let mut args = args.to_vec();
    let (mut i, mut done, mut seen, mut vals) = (0, false, Seen::new(), Vals::new());
    while i < args.len() {
        let a = args[i].clone();
        if !done && a == "--" {
            done = true;
            i += 1;
        } else if !done && a == "-" {
            i += 1;
        } else if !done && a.starts_with('-') && a.chars().count() > 1 {
            let n0 = vals.len();
            let Some(next) = parse_one(&args, i, env_opts(), &mut seen, &mut vals) else {
                return (None, splits);
            };
            i = next;
            if env_opts().chdir.iter().any(|c| seen.contains(*c)) {
                return (None, splits);
            }
            for (k, v) in vals[n0..].iter().cloned() {
                if k == "-S" || k == "--split-string" {
                    splits += 1;
                    if v.chars().any(|c| "\\$#\n\r\0".contains(c)) {
                        return (None, splits);
                    }
                    let Some(pieces) = crate::ssh_claim::shlex_split(&v) else {
                        return (None, splits);
                    };
                    let mut joined = pieces;
                    joined.extend(args[i..].iter().cloned());
                    args = joined;
                    i = 0;
                }
            }
        } else {
            match assignment(&a) {
                None => break,
                Some(false) => return (None, splits),
                Some(true) => i += 1,
            }
        }
    }
    (Some(args[i..].to_vec()), splits)
}

type Item = (String, bool);

pub(crate) fn py_normpath(p: &str) -> String {
    let mut initial = usize::from(p.starts_with('/'));
    if initial == 1 && p.starts_with("//") && !p.starts_with("///") {
        initial = 2;
    }
    let mut comps: Vec<&str> = Vec::new();
    for c in p.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if c != ".." || (initial == 0 && comps.is_empty()) || comps.last() == Some(&"..") {
            comps.push(c);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let out = format!("{}{}", "/".repeat(initial), comps.join("/"));
    if out.is_empty() {
        ".".into()
    } else {
        out
    }
}

fn bad_path(p: &str) -> bool {
    p.contains('\0')
        || p.contains('\n')
        || p.split('/').any(|c| c == "..")
        || p.contains(['*', '?', '['])
}

fn in_system_bin(p: &str) -> bool {
    !bad_path(p) && p.starts_with('/') && {
        let n = py_normpath(p);
        SYSTEM_BIN.iter().any(|b| n.starts_with(b))
    }
}

/// A restricted shell command line: (scripts, understood). Anything beyond plain words, quotes, `&&` `||` `;` `|` and a
/// lone `2>&1` is not understood; every command in it must itself be understood.
fn shell_string(s: Option<&str>, depth: usize) -> (Vec<Item>, bool) {
    let Some(s) = s else {
        return (vec![], false);
    };
    if depth > MAX_SPLIT_DEPTH {
        return (vec![], false);
    }
    if s.contains(['\n', '\r', '#', '`', '$', '\\', '\0'])
        || s.contains("<<")
        || s.contains("<(")
        || s.contains(">(")
    {
        return (vec![], false);
    }
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    let mut segs: Vec<Vec<String>> = vec![vec![]];
    let (mut word, mut i): (Option<Vec<char>>, usize) = (None, 0);
    let flush = |word: &mut Option<Vec<char>>, segs: &mut Vec<Vec<String>>| {
        if let Some(w) = word.take() {
            segs.last_mut().unwrap().push(w.into_iter().collect());
        }
    };
    while i < n {
        let c = chars[i];
        if c == ' ' || c == '\t' {
            flush(&mut word, &mut segs);
            i += 1;
        } else if c == '\'' || c == '"' {
            let Some(rel) = chars[i + 1..].iter().position(|x| *x == c) else {
                return (vec![], false);
            };
            let j = i + 1 + rel;
            let w = word.get_or_insert_with(Vec::new);
            w.extend(&chars[i + 1..j]);
            i = j + 1;
        } else if "&|;".contains(c) {
            let two: String = chars[i..(i + 2).min(n)].iter().collect();
            if two == ";;" || two == "|&" || (c == '&' && two != "&&") {
                return (vec![], false);
            }
            flush(&mut word, &mut segs);
            segs.push(vec![]);
            i += if two == "&&" || two == "||" { 2 } else { 1 };
        } else if c == '<' || c == '>' {
            let ok = c == '>'
                && word.as_deref() == Some(&['2'][..])
                && chars[i..].starts_with(&['>', '&', '1'])
                && (i + 3 == n || " \t&|;".contains(chars[i + 3]));
            if ok {
                word = None;
                i += 3;
            } else {
                return (vec![], false);
            }
        } else if "(){}".contains(c) {
            return (vec![], false);
        } else {
            word.get_or_insert_with(Vec::new).push(c);
            i += 1;
        }
    }
    flush(&mut word, &mut segs);
    let (mut out, mut ok) = (Vec::<Item>::new(), true);
    for seg in segs {
        let mut seg = seg.as_slice();
        while let Some(first) = seg.first() {
            match assignment(first) {
                None => break,
                Some(false) => return (out, false),
                Some(true) => seg = &seg[1..],
            }
        }
        if seg.is_empty() || SHELL_RESERVED.contains(&seg[0].as_str()) {
            return (out, false);
        }
        let a = analyse_at(seg, depth + 1);
        let fresh: Vec<Item> = a
            .items
            .iter()
            .filter(|x| !out.contains(x))
            .cloned()
            .collect();
        out.extend(fresh);
        ok = ok && a.understood;
    }
    (out, ok)
}

/// What `_analyze` found: the script files (path, strict) a command runs, whether the whole command is understood,
/// and the command left after unwrapping (empty when the unwrapping gave up). `strict` marks argv[0] itself being the
/// script (a client may skip a compiled program); "-" is code read from stdin.
#[derive(Debug, Default)]
pub struct Analysis {
    pub items: Vec<Item>,
    pub understood: bool,
    pub cmd: Vec<String>,
}

pub fn analyse(argv: &[String]) -> Analysis {
    analyse_at(argv, 0)
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or("")
}

fn analyse_at(argv: &[String], depth: usize) -> Analysis {
    let mut out: Vec<Item> = Vec::new();
    fn add(out: &mut Vec<Item>, p: &str, strict: bool) {
        let item = (p.to_string(), strict);
        if !out.contains(&item) {
            out.push(item);
        }
    }
    let stop = |out: Vec<Item>| Analysis {
        items: out,
        understood: false,
        cmd: vec![],
    };
    let (mut cmd, mut hops, mut splits) = (argv.to_vec(), 0usize, 0usize);
    let (a0, args, name, simple) = loop {
        if cmd.is_empty() {
            return stop(out); // nothing left to run: not understood
        }
        hops += 1;
        if hops > MAX_HOPS || depth + splits > MAX_SPLIT_DEPTH {
            return stop(out);
        }
        let a0 = cmd[0].clone();
        let args = cmd[1..].to_vec();
        if bad_path(&a0) {
            return stop(out);
        }
        if assignment(&a0).is_some() {
            return stop(out); // only env and shell strings may assign
        }
        let name = basename(&a0).to_string();
        let simple = !a0.contains('/') || in_system_bin(&a0); // a bare name or a standard system path
        if simple && name == "env" {
            let (nxt, s) = env_unwrap(&args, splits);
            splits = s;
            let Some(nxt) = nxt else {
                return stop(out);
            };
            if depth + splits > MAX_SPLIT_DEPTH {
                return stop(out);
            }
            if nxt.is_empty() {
                // a bare `env` (plain options only) just prints the environment
                let plain =
                    hops == 1 && depth == 0 && splits == 0 && !args.iter().any(|a| a.contains('='));
                return Analysis {
                    items: out,
                    understood: plain,
                    cmd: vec![],
                };
            }
            cmd = nxt;
            continue;
        }
        if simple {
            if let Some(spec) = wrappers().get(name.as_str()) {
                let Some((mut rest, seen)) = parse_opts(&args, spec) else {
                    return stop(out);
                };
                if !spec.pos_unless.iter().any(|o| seen.contains(*o)) {
                    if rest.len() < spec.pos {
                        return stop(out);
                    }
                    rest = rest[spec.pos..].to_vec();
                }
                cmd = rest;
                continue;
            }
        }
        break (a0, args, name, simple);
    };
    let finish = |out: Vec<Item>, understood: bool, cmd: &[String]| Analysis {
        items: out,
        understood,
        cmd: cmd.to_vec(),
    };
    let found = if !a0.contains('/') || a0.starts_with('/') {
        script_args(&name, &args, true)
    } else {
        None
    };
    if let Some(found) = found {
        match found {
            Found::Stdin => {
                add(&mut out, "-", false);
                return finish(out, true, &cmd);
            }
            Found::Nothing
                if !["sed", "awk", "gawk", "mawk"]
                    .iter()
                    .any(|p| name.starts_with(p)) =>
            {
                add(&mut out, "-", false);
                return finish(out, true, &cmd);
            }
            Found::File(paths) => {
                for p in &paths {
                    add(&mut out, p, false);
                }
                return finish(out, true, &cmd);
            }
            Found::Inline(payload) if is_sh_name(&name) => {
                let (found2, good) = shell_string(payload.as_deref(), depth + 1);
                for (p, strict) in &found2 {
                    add(&mut out, p, *strict);
                }
                return finish(out, good, &cmd);
            }
            Found::Unknown => {
                // still report the script file(s), if any
                if let Some(Found::File(paths)) = script_args(&name, &args, false) {
                    for q in &paths {
                        add(&mut out, q, false);
                    }
                }
            }
            _ => {}
        }
        return finish(out, false, &cmd); // other inline code, unknown options, bare sed/awk
    }
    if SCRIPT_EXT.iter().any(|e| a0.ends_with(e)) || (a0.contains('/') && !in_system_bin(&a0)) {
        add(&mut out, &a0, true); // the command is itself a script file
        return finish(out, true, &cmd);
    }
    if simple && plain_programs().contains_key(name.as_str()) {
        let ok = plain_ok(&name, &args);
        return finish(out, ok, &cmd);
    }
    finish(out, false, &cmd)
}

fn is_sh_name(name: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| rx(r"^(?:ba|z|da|k|a)?sh$")).is_match(name)
}

/// `_script_args` for callers outside the analysis (is this name an interpreter?).
pub fn is_interpreter_call(name: &str, args: &[String]) -> bool {
    script_args(name, args, true).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn matches_every_golden_case_recorded_from_python() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/cli/analyse.json"
        );
        let cases: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(cases.len() > 5000);
        let mut bad = Vec::new();
        for c in &cases {
            let argv = strings(&c["argv"]);
            let items: Vec<(String, bool)> = c["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_bool().unwrap()))
                .collect();
            let (ok, cmd) = (c["ok"].as_bool().unwrap(), strings(&c["cmd"]));
            let got = analyse(&argv);
            if (got.items.clone(), got.understood, got.cmd.clone())
                != (items.clone(), ok, cmd.clone())
            {
                bad.push(format!(
                    "{argv:?}\n   want {items:?} ok={ok} cmd={cmd:?}\n   got  {:?} ok={} cmd={:?}",
                    got.items, got.understood, got.cmd
                ));
            }
        }
        assert!(
            bad.is_empty(),
            "{} of {} differ, first:\n{}",
            bad.len(),
            cases.len(),
            bad[..bad.len().min(8)].join("\n")
        );
    }

    #[test]
    fn normpath_is_pythons() {
        for (p, want) in [
            ("/usr/bin/../bin/ls", "/usr/bin/ls"),
            ("//bin/x", "//bin/x"),
            ("///bin/x", "/bin/x"),
            ("a/../..", ".."),
            ("", "."),
            ("/..", "/"),
            ("./a//b/./c/", "a/b/c"),
        ] {
            assert_eq!(py_normpath(p), want, "{p}");
        }
    }
}
