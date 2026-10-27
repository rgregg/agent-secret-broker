//! "Could the agent change this?" checks. A root helper must not run, or believe, anything the
//! unprivileged user can write: the file and every directory above it must belong to the trusted
//! uid and be closed to group and other writes.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A program to run: a regular file with an execute bit.
    Program,
    /// A script an interpreter will run: a regular file (no execute bit needed) that the agent cannot write.
    Script,
    /// A secrets file: a regular file closed to group and other entirely.
    Secret,
}

/// `path` must already be canonical (symlinks resolved), so each component is checked as it is.
///
/// The walk goes up to and including `trust_root` (always `/` in production; a test uses its own
/// temp directory). A path outside `trust_root` is refused.
pub fn check_chain(
    path: &Path,
    trusted_uid: u32,
    kind: Kind,
    trust_root: &Path,
) -> Result<(), String> {
    if !path.starts_with(trust_root) {
        return Err(format!("{} is outside the trusted tree", path.display()));
    }
    let leaf = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !leaf.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let bits = leaf.permissions().mode();
    match kind {
        Kind::Program if bits & 0o111 == 0 => {
            return Err(format!("{} is not executable", path.display()))
        }
        Kind::Secret if bits & 0o077 != 0 => {
            return Err(format!(
                "{} must not be readable or writable by group or others (chmod 600)",
                path.display()
            ))
        }
        _ => {}
    }
    for p in path.ancestors() {
        let md = fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if md.uid() != trusted_uid {
            return Err(format!("{} is not owned by the trusted user", p.display()));
        }
        if md.permissions().mode() & 0o022 != 0 {
            return Err(format!("{} is writable by group or others", p.display()));
        }
        if p == trust_root {
            break;
        }
    }
    Ok(())
}
