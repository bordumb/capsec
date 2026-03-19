//! # capsec-tokio
//!
//! Async capability-gated wrappers for [tokio](https://tokio.rs/) — the async
//! counterpart to [`capsec-std`](https://crates.io/crates/capsec-std).
//!
//! Every function mirrors a `tokio` function but requires a capability token
//! proving the caller has the appropriate permission. The capability proof is
//! scoped before the first `.await` to keep returned futures `Send`.
//!
//! ## Modules
//!
//! Enable via feature flags:
//!
//! - `fs` — async filesystem operations (`tokio::fs`)
//! - `net` — async network operations (`tokio::net`)
//! - `process` — async subprocess execution (`tokio::process`)
//! - `full` — all of the above

#[cfg(feature = "fs")]
pub mod file;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "process")]
pub mod process;
