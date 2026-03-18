//! Capability-gated environment variable access.
//!
//! Drop-in replacements for `std::env` functions that require a capability token.

use capsec_core::cap::Cap;
use capsec_core::has::Has;
use capsec_core::permission::{EnvRead, EnvWrite};

/// Reads an environment variable.
/// Requires [`EnvRead`] permission.
pub fn var(key: &str, cap: &impl Has<EnvRead>) -> Result<String, std::env::VarError> {
    let _proof: Cap<EnvRead> = cap.cap_ref();
    std::env::var(key)
}

/// Returns an iterator of all environment variables.
/// Requires [`EnvRead`] permission.
pub fn vars(cap: &impl Has<EnvRead>) -> std::env::Vars {
    let _proof: Cap<EnvRead> = cap.cap_ref();
    std::env::vars()
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
pub fn set_var(
    key: impl AsRef<std::ffi::OsStr>,
    value: impl AsRef<std::ffi::OsStr>,
    cap: &impl Has<EnvWrite>,
) {
    let _proof: Cap<EnvWrite> = cap.cap_ref();
    unsafe {
        std::env::set_var(key, value);
    }
}
