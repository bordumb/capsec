//! Formal verification and property-based tests for capsec's permission lattice.
//!
//! This crate mirrors capsec-core's compile-time permission model at runtime
//! and verifies soundness properties via proptest and TOML sync tests.
//!
//! **No Cargo dependency on capsec-core** — reads source files as plain text
//! for sync validation.

pub mod runtime_mirror;
