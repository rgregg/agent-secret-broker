//! Exit codes (the same contract as the Python client and `asb guide`) and the way a command ends early.

pub const NOT_FOUND: i32 = 1;
pub const USAGE: i32 = 2;
pub const BROKER: i32 = 3;
#[allow(dead_code)]
pub const DENIED: i32 = 4;
#[allow(dead_code)]
pub const EXPIRED: i32 = 5;
#[allow(dead_code)]
pub const SCRIPT_CHANGED: i32 = 6;
#[allow(dead_code)]
pub const ENDED: i32 = 7;
#[allow(dead_code)]
pub const REFUSED: i32 = 8;
#[allow(dead_code)]
pub const SLOW_DOWN: i32 = 9;
#[allow(dead_code)]
pub const HTTP_ERROR: i32 = 22;

/// A command that has already said why and wants the process to exit with this code.
#[derive(Debug)]
pub struct Die(pub i32);

/// What every command returns: the exit code, or `Die` for an early exit.
pub type R = Result<i32, Die>;

/// `asb: <msg>` on stderr, and the exit code to return with `Err(die(..))`.
pub fn die(msg: impl std::fmt::Display, code: i32) -> Die {
    eprintln!("asb: {msg}");
    Die(code)
}
