//! # capsec — Compile-Time Capability-Based Security for Rust
//!
//! `capsec` enforces the principle of least privilege at the type level.
//! Functions declare their I/O capabilities via trait bounds, and the compiler
//! ensures they cannot exceed them.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use capsec::prelude::*;
//!
//! fn main() {
//!     let root = capsec::root();
//!     let fs_cap = root.grant::<FsRead>();
//!     let data = load_data("/tmp/data.csv", &fs_cap).unwrap();
//! }
//!
//! fn load_data(path: &str, cap: &impl Has<FsRead>) -> Result<String, capsec::CapSecError> {
//!     capsec::fs::read_to_string(path, cap)
//! }
//! ```
//!
//! ## Architecture
//!
//! This is a facade crate that re-exports from three internal crates:
//!
//! - **`capsec-core`** — capability tokens, permission traits, composition
//! - **`capsec-macro`** — `#[requires]`, `#[deny]`, `#[main]`, and `#[context]` proc macros
//! - **`capsec-std`** — capability-gated `std` wrappers

//  Re-exports from capsec-core

pub use capsec_core::cap::{Cap, SendCap};
pub use capsec_core::error::CapSecError;
pub use capsec_core::has::Has;
pub use capsec_core::permission::{
    Ambient, EnvRead, EnvWrite, FsAll, FsRead, FsWrite, NetAll, NetBind, NetConnect, Permission,
    Spawn, Subsumes,
};
pub use capsec_core::root::{CapRoot, root, try_root};

#[cfg(debug_assertions)]
pub use capsec_core::root::test_root;

pub use capsec_core::attenuate::{Attenuated, DirScope, HostScope, Scope};

pub use capsec_core::runtime::{Revoker, RuntimeCap, RuntimeSendCap, TimedCap, TimedSendCap};

pub use capsec_core::prescript::{
    ApproverA, ApproverB, DualKeyCap, DualKeySendCap, LogEntry, LoggedCap, LoggedSendCap,
};

/// Creates a `CapRoot` and passes it to the given closure.
///
/// This is a convenience entry point. Panics if `root()` has already been called.
pub fn run<T>(f: impl FnOnce(CapRoot) -> T) -> T {
    let root = root();
    f(root)
}

//  Re-exports from capsec-macro

pub use capsec_macro::{context, deny, main, permission, requires};

//  Capability-gated std wrappers

/// Capability-gated filesystem operations. See [`capsec_std::fs`].
pub mod fs {
    pub use capsec_std::file::{ReadFile, WriteFile};
    pub use capsec_std::fs::*;
}

/// Capability-gated network operations. See [`capsec_std::net`].
pub mod net {
    pub use capsec_std::net::*;
}

/// Capability-gated environment variable access. See [`capsec_std::env`].
pub mod env {
    pub use capsec_std::env::*;
}

/// Capability-gated subprocess execution. See [`capsec_std::process`].
pub mod process {
    pub use capsec_std::process::*;
}

//  Async capability-gated tokio wrappers (optional)

/// Async capability-gated wrappers for tokio. Requires the `tokio` feature.
///
/// ```toml
/// capsec = { version = "0.1", features = ["tokio"] }
/// ```
#[cfg(feature = "tokio")]
pub mod tokio {
    /// Task spawning with capability transfer.
    pub mod task {
        pub use capsec_tokio::task::*;
    }
    /// Async capability-gated filesystem operations.
    pub mod fs {
        pub use capsec_tokio::file::{AsyncReadFile, AsyncWriteFile};
        pub use capsec_tokio::fs::*;
    }
    /// Async capability-gated network operations.
    pub mod net {
        pub use capsec_tokio::net::*;
    }
    /// Async capability-gated subprocess execution.
    pub mod process {
        pub use capsec_tokio::process::*;
    }
}

/// Common imports for working with capsec.
///
/// ```
/// use capsec::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        Ambient, ApproverA, ApproverB, Attenuated, Cap, CapRoot, CapSecError, DirScope, DualKeyCap,
        EnvRead, EnvWrite, FsAll, FsRead, FsWrite, Has, HostScope, LoggedCap, NetAll, NetBind,
        NetConnect, Permission, Revoker, RuntimeCap, Spawn, Subsumes, TimedCap,
    };
}
