//! # capsec-std
//!
//! Capability-gated wrappers around the Rust standard library.
//!
//! Every function in this crate mirrors a `std` function but requires a capability
//! token proving the caller has the appropriate permission. For example,
//! [`fs::read`] requires `&impl CapProvider<FsRead>`.
//!
//! This is the enforcement layer of `capsec` — by using these wrappers instead of
//! raw `std` calls, you get compile-time verification that your code only exercises
//! the capabilities it declares.

pub mod env;
pub mod file;
pub mod fs;
pub mod net;
pub mod process;
