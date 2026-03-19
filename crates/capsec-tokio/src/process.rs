//! Async capability-gated subprocess execution.
//!
//! Drop-in async replacements for `tokio::process` functions that require a
//! capability token.

use capsec_core::cap::Cap;
use capsec_core::error::CapSecError;
use capsec_core::has::Has;
use capsec_core::permission::Spawn;
use std::process::Output;
use tokio::process::Command;

/// Creates a new async `Command` for the given program.
/// Requires [`Spawn`] permission.
///
/// Returns a `tokio::process::Command` that can be further configured before execution.
pub fn command(program: &str, cap: &impl Has<Spawn>) -> Command {
    let _proof: Cap<Spawn> = cap.cap_ref();
    Command::new(program)
}

/// Runs a program with arguments and returns its output.
/// Requires [`Spawn`] permission.
pub async fn run(
    program: &str,
    args: &[&str],
    cap: &impl Has<Spawn>,
) -> Result<Output, CapSecError> {
    {
        let _proof: Cap<Spawn> = cap.cap_ref();
    }
    Ok(Command::new(program).args(args).output().await?)
}
