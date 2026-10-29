//! `asb sudo -- command`: run a command as root through the root helper, after a human approves it.

use crate::exit::{die, R, USAGE};
use crate::util::die_help;

const ROOT_EXEC: &str = "/usr/local/sbin/asb-root-exec";

pub fn run(argv: &[String]) -> R {
    if argv.first().map(String::as_str) == Some("--") && argv.len() > 1 {
        // sudoers allows only the installed path, so overriding it cannot escalate
        let helper = std::env::var("ASB_ROOT_EXEC")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| ROOT_EXEC.to_string());
        return match std::process::Command::new("sudo")
            .arg("-n")
            .arg(&helper)
            .arg("--")
            .args(&argv[1..])
            .status()
        {
            Ok(status) => Ok(status.code().unwrap_or_else(|| {
                use std::os::unix::process::ExitStatusExt;
                128 + status.signal().unwrap_or(0)
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(die("sudo is not installed on this machine", USAGE))
            }
            Err(e) => Err(die(format!("cannot run sudo: {e}"), USAGE)),
        };
    }
    Err(die_help("sudo"))
}
