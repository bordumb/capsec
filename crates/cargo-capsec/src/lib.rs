//! # cargo-capsec
//!
//! Static capability audit for Rust — find out what your code can do to the outside world.
//!
//! `cargo-capsec` scans Rust source code and produces a **capability map**: every function,
//! in every crate in your workspace, that exercises ambient authority over the filesystem,
//! network, environment, or process table. No annotations required. No code changes. Point
//! it at a repo and it tells you what's happening.
//!
//! ## Architecture
//!
//! The audit pipeline has five stages:
//!
//! 1. **[`discovery`]** — enumerate workspace crates via `cargo metadata`
//! 2. **[`parser`]** — parse `.rs` files into structured ASTs with [`syn`]
//! 3. **[`authorities`]** — match calls against a registry of known ambient authority patterns
//! 4. **[`detector`]** — orchestrate matching with import expansion and deduplication
//! 5. **[`reporter`]** — format findings as text, JSON, or SARIF
//!
//! Supporting modules:
//!
//! - **[`config`]** — `.capsec.toml` parsing for custom authorities, allow rules, and crate-level deny
//! - **[`baseline`]** — diff findings against previous runs to detect new capabilities
//!
//! ## Programmatic usage
//!
//! ```no_run
//! use cargo_capsec::parser::parse_source;
//! use cargo_capsec::detector::Detector;
//!
//! let source = r#"
//!     use std::fs;
//!     fn load() { let _ = fs::read("data.bin"); }
//! "#;
//!
//! let parsed = parse_source(source, "example.rs").unwrap();
//! let detector = Detector::new();
//! let findings = detector.analyse(&parsed, "my-crate", "0.1.0", &[]);
//!
//! for f in &findings {
//!     println!("[{}] {} in {}()", f.category.label(), f.call_text, f.function);
//! }
//! ```

pub mod authorities;
pub mod baseline;
pub mod config;
pub mod cross_crate;
pub mod deep;
pub mod detector;
pub mod discovery;
pub mod export_map;
pub mod parser;
pub mod reporter;
