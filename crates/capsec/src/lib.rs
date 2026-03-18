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
//! - **`capsec-macro`** — `#[requires]` and `#[deny]` proc macros
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

#[cfg(any(test, feature = "test-support"))]
pub use capsec_core::root::test_root;

pub use capsec_core::attenuate::{Attenuated, DirScope, HostScope, Scope};

//  Re-exports from capsec-macro

pub use capsec_macro::{deny, requires};

//  Capability-gated std wrappers

/// Capability-gated filesystem operations. See [`capsec_std::fs`].
pub mod fs {
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

/// Common imports for working with capsec.
///
/// ```
/// use capsec::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        Ambient, Attenuated, Cap, CapRoot, CapSecError, DirScope, EnvRead, EnvWrite, FsAll, FsRead,
        FsWrite, Has, HostScope, NetAll, NetBind, NetConnect, Permission, Spawn, Subsumes,
    };
}
