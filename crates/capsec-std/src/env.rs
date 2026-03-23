//! Capability-gated environment variable access.
//!
//! Drop-in replacements for `std::env` functions that require a capability token.

use capsec_core::cap::Cap;
use capsec_core::cap_provider::CapProvider;
use capsec_core::error::CapSecError;
use capsec_core::permission::{EnvRead, EnvWrite};

/// Reads an environment variable.
/// Requires [`EnvRead`] permission.
pub fn var(key: &str, cap: &impl CapProvider<EnvRead>) -> Result<String, CapSecError> {
    let _proof: Cap<EnvRead> = cap.provide_cap(key)?;
    Ok(std::env::var(key)?)
}

/// Returns an iterator of all environment variables.
/// Requires [`EnvRead`] permission.
pub fn vars(cap: &impl CapProvider<EnvRead>) -> Result<std::env::Vars, CapSecError> {
    let _proof: Cap<EnvRead> = cap.provide_cap("*")?;
    Ok(std::env::vars())
}

/// Sets an environment variable.
/// Requires [`EnvWrite`] permission.
///
/// # Safety note
///
/// In Rust edition 2024, `std::env::set_var` is `unsafe` because it's not
/// thread-safe. This wrapper encapsulates that unsafety.
///
/// # Thread safety
///
/// `std::env::set_var` is not thread-safe. Even though `Cap<EnvWrite>` can be
/// cloned and transferred across threads via `make_send()`, calling this
/// function concurrently from multiple threads is undefined behavior. The
/// capability system tracks *permission*, not *exclusivity* — synchronization
/// is the caller's responsibility.
///
/// # Errors
///
/// The underlying `std::env::set_var` is infallible (panics on failure).
/// The `Err` path only triggers from `CapProvider` scope checks.
pub fn set_var(
    key: impl AsRef<std::ffi::OsStr>,
    value: impl AsRef<std::ffi::OsStr>,
    cap: &impl CapProvider<EnvWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<EnvWrite> = cap.provide_cap(&key.as_ref().to_string_lossy())?;
    unsafe {
        std::env::set_var(key, value);
    }
    Ok(())
}
