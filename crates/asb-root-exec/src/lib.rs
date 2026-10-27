//! `asb-root-exec`: run a command as root only after the broker's human approves it.
//!
//! Installed root-owned and named in ONE passwordless sudoers rule; the agent runs
//! `asb-root-exec -- CMD ARGS...` through sudo. This crate does everything except the final exec,
//! so it can be tested without being root: `prepare` checks, asks the broker and returns a `Plan`;
//! `exec` replaces the process. Fails closed at every step; see docs/proposals/root-exec.md.

pub mod resolve;
pub mod trust;

use asb_client::{clean, Client, Config};
use asb_proto::{exit, SudoRequest};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use trust::Kind;

pub const CONFIG_PATH: &str = "/etc/secret-broker/root-exec.json";
/// The only places a bare command name is looked up, and the PATH the command runs with.
pub const SECURE_PATH: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// What the helper trusts. `production()` is the only policy the binary uses; tests build their own.
#[derive(Debug, Clone)]
pub struct Policy {
    pub trusted_uid: u32,
    pub trust_root: PathBuf,
    pub config_path: PathBuf,
    pub secure_path: Vec<PathBuf>,
    pub home: PathBuf,
}

impl Policy {
    pub fn production() -> Policy {
        Policy {
            trusted_uid: 0,
            trust_root: PathBuf::from("/"),
            config_path: PathBuf::from(CONFIG_PATH),
            secure_path: SECURE_PATH.iter().map(PathBuf::from).collect(),
            home: PathBuf::from("/root"),
        }
    }
}

/// Facts about the caller, read once from the environment sudo left us.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub cwd: PathBuf,
    /// `SUDO_USER`, if it is a plausible user name. Shown to the human as unverified.
    pub invoker: Option<String>,
    pub hostname: String,
    pub lang: Option<String>,
    pub term: Option<String>,
}

fn all_of(s: &str, extra: &[char], max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

pub fn valid_invoker(s: &str) -> bool {
    let first = s.chars().next();
    s.len() <= 32
        && matches!(first, Some('a'..='z' | '_'))
        && s.chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
}

impl Context {
    /// Build from an environment lookup, the working directory and the hostname.
    pub fn from_env(get: impl Fn(&str) -> Option<String>, cwd: PathBuf, hostname: &str) -> Context {
        let host: String = hostname
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .take(60)
            .collect();
        Context {
            cwd,
            invoker: get("SUDO_USER").filter(|u| valid_invoker(u)),
            hostname: if host.is_empty() {
                "unknown".into()
            } else {
                host
            },
            lang: get("LANG").filter(|v| all_of(v, &['_', '.', '@', '-'], 40)),
            term: get("TERM").filter(|v| all_of(v, &['.', '_', '+', '-'], 40)),
        }
    }
}

/// A failure: what to print and which code to exit with.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub code: i32,
    pub message: String,
}

fn fail(code: i32, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

/// Everything needed to start the approved command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The file executed (symlinks resolved, trusted).
    pub program: PathBuf,
    /// argv[0]: the same real path the human saw.
    pub arg0: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

/// The only environment the command gets.
pub fn child_env(policy: &Policy, ctx: &Context) -> Vec<(String, String)> {
    let path = policy
        .secure_path
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let mut env = vec![
        ("PATH".to_string(), path),
        ("HOME".to_string(), policy.home.display().to_string()),
        ("USER".to_string(), "root".to_string()),
        ("LOGNAME".to_string(), "root".to_string()),
        (
            "LANG".to_string(),
            ctx.lang.clone().unwrap_or_else(|| "C".to_string()),
        ),
    ];
    if let Some(t) = &ctx.term {
        env.push(("TERM".to_string(), t.clone()));
    }
    if let Some(u) = &ctx.invoker {
        env.push(("SUDO_USER".to_string(), u.clone()));
    }
    env
}

fn resolve_command(
    policy: &Policy,
    argv0: &str,
    ctx: &Context,
) -> Result<resolve::Resolved, Failure> {
    resolve::resolve(
        argv0,
        &ctx.cwd,
        &policy.secure_path,
        policy.trusted_uid,
        &policy.trust_root,
    )
    .map_err(|m| fail(exit::REFUSED_LOCALLY, m))
}

fn load_config(policy: &Policy) -> Result<Config, Failure> {
    let path = std::fs::canonicalize(&policy.config_path).map_err(|e| {
        fail(
            exit::REFUSED_LOCALLY,
            format!("{}: {e}", policy.config_path.display()),
        )
    })?;
    trust::check_chain(&path, policy.trusted_uid, Kind::Secret, &policy.trust_root)
        .map_err(|m| fail(exit::REFUSED_LOCALLY, m))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| fail(exit::REFUSED_LOCALLY, format!("{}: {e}", path.display())))?;
    Config::parse(&text)
        .map_err(|m| fail(exit::REFUSED_LOCALLY, format!("{}: {m}", path.display())))
}

/// Check, ask the broker, and return what to run. `args` is everything after the program name and
/// must start with `--`. `note` receives progress lines.
pub fn prepare(
    policy: &Policy,
    args: &[String],
    ctx: &Context,
    note: impl FnMut(&str),
) -> Result<Plan, Failure> {
    let (dashes, command) = args
        .split_first()
        .ok_or_else(|| fail(exit::USAGE, "usage: asb-root-exec -- COMMAND [ARGS...]"))?;
    if dashes != "--" || command.is_empty() {
        return Err(fail(
            exit::USAGE,
            "usage: asb-root-exec -- COMMAND [ARGS...]",
        ));
    }
    let cfg = load_config(policy)?;
    let cwd = ctx
        .cwd
        .to_str()
        .filter(|c| c.starts_with('/'))
        .ok_or_else(|| {
            fail(
                exit::REFUSED_LOCALLY,
                "the working directory is not a plain absolute path",
            )
        })?
        .to_string();

    // Resolve first, so the human is shown the file that will run: the real path, symlinks followed.
    // Showing the name that was typed or found would let a link planted somewhere the agent can write
    // (`~/ls` -> `/bin/rm`) pass for something else. The same path is the process's argv[0].
    let resolved = resolve_command(policy, &command[0], ctx)?;
    let shown = resolved
        .real
        .to_str()
        .ok_or_else(|| fail(exit::REFUSED_LOCALLY, "the command path is not valid UTF-8"))?
        .to_string();
    let mut argv = vec![shown.clone()];
    argv.extend(command[1..].iter().cloned());

    let source: String = format!(
        "{}@{}",
        ctx.invoker.as_deref().unwrap_or("root"),
        ctx.hostname
    )
    .chars()
    .take(80)
    .collect();
    let request = SudoRequest::new(argv.clone(), Some(cwd), ctx.invoker.clone(), source);
    request.check().map_err(|m| fail(exit::USAGE, m))?;

    Client::new(cfg)
        .approve_sudo(&request, note)
        .map_err(|e| fail(e.exit_code(), clean(&e.to_string(), 200)))?;

    // The human may have taken minutes. Run only the file they approved: look again.
    let again = resolve_command(policy, &command[0], ctx)?;
    if again != resolved {
        return Err(fail(
            exit::REFUSED_LOCALLY,
            "the command changed while waiting for approval",
        ));
    }
    Ok(Plan {
        program: resolved.real,
        arg0: shown,
        args: argv[1..].to_vec(),
        env: child_env(policy, ctx),
    })
}

/// The process to start for a plan: the resolved file, the shown argv[0], a cleared environment.
///
/// No `current_dir`: the command inherits the working directory this process already has, which is the
/// directory the human was shown (sudo preserves the caller's). Changing directory by path after the
/// approval would let the agent swap what that path means while the human decides.
pub fn build_command(plan: &Plan) -> Command {
    let mut c = Command::new(&plan.program);
    c.arg0(&plan.arg0)
        .args(&plan.args)
        .env_clear()
        .envs(plan.env.iter().cloned());
    c
}

/// Replace this process with the command. Only returns on failure.
pub fn exec(plan: &Plan) -> std::io::Error {
    build_command(plan).exec()
}
