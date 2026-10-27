//! Turn the command's first word into the exact file that will run, before the broker is asked,
//! so what the human approves is what runs.

use crate::trust::{check_chain, Kind};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The absolute path the name resolved to, before following symlinks. Used only to find the file and
    /// to notice if the lookup changes; never shown to the human, because a link can say anything.
    pub shown: PathBuf,
    /// The file that is actually executed, shown to the human and passed as argv[0]: `shown` with
    /// symlinks resolved, and trusted.
    pub real: PathBuf,
}

/// A bare name is looked up in `secure_path` only (never the caller's PATH); a name with a slash is
/// taken relative to `cwd`. Fails unless the result is a trusted program (see `trust`).
pub fn resolve(
    argv0: &str,
    cwd: &Path,
    secure_path: &[PathBuf],
    trusted_uid: u32,
    trust_root: &Path,
) -> Result<Resolved, String> {
    let shown = if argv0.contains('/') {
        let p = Path::new(argv0);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        }
    } else {
        secure_path
            .iter()
            .map(|d| d.join(argv0))
            .find(|c| {
                fs::metadata(c)
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            })
            .ok_or_else(|| format!("{argv0}: not found in the secure PATH"))?
    };
    let real = fs::canonicalize(&shown).map_err(|e| format!("{}: {e}", shown.display()))?;
    check_chain(&real, trusted_uid, Kind::Program, trust_root)?;
    Ok(Resolved { shown, real })
}
