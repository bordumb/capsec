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
//! - `rt` — task spawning with capability transfer (`task::spawn_with`)
//! - `fs` — async filesystem operations (`tokio::fs`)
//! - `net` — async network operations (`tokio::net`)
//! - `process` — async subprocess execution (`tokio::process`)
//! - `full` — all of the above
//!
//! # Capsec + Tokio Guide
//!
//! There are three common patterns for using capabilities in async code,
//! depending on whether you're spawning tasks and how many capabilities
//! you need.
//!
//! ## Pattern 1: Scoped proof (no spawn)
//!
//! When your async code runs on the current task (no `tokio::spawn`), pass
//! capabilities by reference. The scope-before-await pattern inside each
//! wrapper keeps futures `Send` automatically.
//!
//! ```no_run
//! use capsec_core::cap_provider::CapProvider;
//! use capsec_core::permission::FsRead;
//!
//! async fn handle_request(cap: &impl CapProvider<FsRead>) {
//!     let data = capsec_tokio::fs::read("/tmp/config.toml", cap).await.unwrap();
//!     // ...
//! }
//! ```
//!
//! ## Pattern 2: `spawn_with` (single capability)
//!
//! When spawning a task that needs one capability, use
//! `task::spawn_with`. It converts `Cap<P>` to `SendCap<P>` for you —
//! no need to call `.make_send()` manually.
//!
//! ```no_run
//! use capsec_core::permission::FsRead;
//!
//! # async fn example(root: capsec_core::root::CapRoot) {
//! let cap = root.grant::<FsRead>();
//!
//! let handle = capsec_tokio::task::spawn_with(cap, |cap| async move {
//!     capsec_tokio::fs::read("/tmp/data.bin", &cap).await.unwrap()
//! });
//!
//! let data = handle.await.unwrap();
//! # }
//! ```
//!
//! ## Pattern 3: `Arc` context (multiple capabilities)
//!
//! When a spawned task needs multiple capabilities, use
//! `#[capsec::context(send)]` to create a `Send`-safe context struct,
//! wrap it in `Arc`, and clone for each task.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! // The `send` flag generates SendCap<P> fields instead of Cap<P>
//! #[capsec_macro::context(send)]
//! struct AppCtx {
//!     fs: capsec_core::permission::FsRead,
//!     net: capsec_core::permission::NetConnect,
//! }
//!
//! # async fn example(root: capsec_core::root::CapRoot) {
//! let ctx = Arc::new(AppCtx::new(&root));
//!
//! let ctx2 = Arc::clone(&ctx);
//! tokio::spawn(async move {
//!     let data = capsec_tokio::fs::read("/tmp/data", &*ctx2).await.unwrap();
//! });
//!
//! let ctx3 = Arc::clone(&ctx);
//! tokio::spawn(async move {
//!     let stream = capsec_tokio::net::tcp_connect("127.0.0.1:8080", &*ctx3).await.unwrap();
//! });
//! # }
//! ```

#[cfg(feature = "fs")]
pub mod file;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "process")]
pub mod process;
#[cfg(feature = "rt")]
pub mod task;
