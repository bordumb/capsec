//! # capsec-core
//!
//! Zero-cost capability tokens and permission traits for compile-time
//! capability-based security in Rust.
//!
//! This crate provides the foundational types that the rest of the `capsec`
//! ecosystem builds on:
//!
//! - [`Permission`](permission::Permission) — marker trait for capability categories
//! - [`Cap<P>`](cap::Cap) — zero-sized proof token that the holder has permission `P`
//! - [`Has<P>`](has::Has) — trait for checking and composing capabilities
//! - [`CapRoot`](root::CapRoot) — the singleton root of all capability grants
//! - [`Attenuated<P, S>`](attenuate::Attenuated) — scope-restricted capabilities
//! - [`CapSecError`](error::CapSecError) — error types for scope violations and I/O
//!
//! All capability types are zero-sized at runtime. The security model is enforced
//! entirely through the type system — no runtime overhead.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use capsec_core::root::test_root;
//! use capsec_core::permission::{FsRead, NetConnect};
//! use capsec_core::has::Has;
//!
//! // Create a capability root (use test_root in tests)
//! let root = test_root();
//!
//! // Grant individual capabilities
//! let fs_cap = root.grant::<FsRead>();
//! let net_cap = root.grant::<NetConnect>();
//!
//! // Functions declare what they need via Has<P> bounds
//! fn needs_both(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) {
//!     let _ = fs.cap_ref();
//!     let _ = net.cap_ref();
//! }
//!
//! needs_both(&fs_cap, &net_cap);
//! ```

pub mod attenuate;
pub mod cap;
pub mod error;
pub mod has;
pub mod permission;
pub mod prescript;
pub mod root;
pub mod runtime;

/// Re-export of the seal token module for use by `#[capsec::permission]` macro.
/// Do not use directly.
#[doc(hidden)]
pub use permission::__private;
