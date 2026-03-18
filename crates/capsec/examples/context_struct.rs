//! Example: Context Struct pattern
//!
//! Demonstrates bundling capabilities into a single struct to reduce
//! parameter count at intermediate layers.
//!
//! Instead of threading 3+ individual `Cap<P>` parameters through every
//! function, group them into a context struct and pass that. Leaf functions
//! still take `&impl Has<P>` — the struct is for intermediate layers only.
//!
//! Key concepts:
//! - Context structs are ZSTs (all fields are zero-sized caps)
//! - Pass `&ctx.field` to leaf functions that take `&impl Has<P>`
//! - For multi-threaded contexts, use `SendCap<P>` fields instead
//!
//! See also: `domain_wrapper.rs` for hiding caps entirely, and
//! `layered_app.rs` for combining both patterns.

use capsec::prelude::*;

// ─── The Context Struct ──────────────────────────────────────────

/// Bundles the capabilities this application needs.
///
/// All fields are `Cap<P>` — zero-sized types. This struct itself
/// is zero-sized at runtime. No allocation, no overhead.
#[allow(dead_code)] // fields shown for completeness — not all used in this demo
struct AppCaps {
    fs_read: Cap<FsRead>,
    fs_write: Cap<FsWrite>,
    net: Cap<NetConnect>,
    env: Cap<EnvRead>,
}

// ─── Intermediate layer: receives the context ────────────────────

/// Orchestrates the application workflow.
///
/// Takes one `&AppCaps` instead of four separate capability parameters.
/// Extracts specific caps when calling leaf functions.
fn run_app(caps: &AppCaps) {
    // Read config path from environment, then load the config file
    let config_path = get_config_path(&caps.env);
    let config = load_file(&config_path, &caps.fs_read);

    // Process (pure — no caps needed)
    let processed = config.to_uppercase();

    // Write output
    save_output("/tmp/capsec-demo-output.txt", &processed, &caps.fs_write);

    // Report (would connect to a metrics server in a real app)
    println!("Would send {} bytes to metrics server", processed.len());
    // In real code: send_metrics("metrics:9090", &processed, &caps.net);
}

// ─── Leaf functions: take `&impl Has<P>`, not the context ────────

/// Reads an environment variable.
///
/// Takes `&impl Has<EnvRead>` — doesn't know about AppCaps.
/// This keeps the function reusable and auditable: `grep Has<EnvRead>`
/// finds every function that reads env vars.
fn get_config_path(cap: &impl Has<EnvRead>) -> String {
    capsec::env::var("APP_CONFIG", cap).unwrap_or_else(|_| "/etc/app/config.toml".into())
}

/// Reads a file from disk.
///
/// Takes `&impl Has<FsRead>` — minimum required capability.
fn load_file(path: &str, cap: &impl Has<FsRead>) -> String {
    capsec::fs::read_to_string(path, cap).unwrap_or_else(|_| "# default config".into())
}

/// Writes data to a file.
///
/// Takes `&impl Has<FsWrite>` — cannot read files.
fn save_output(path: &str, data: &str, cap: &impl Has<FsWrite>) {
    if let Err(e) = capsec::fs::write(path, data.as_bytes(), cap) {
        eprintln!("Warning: could not write {path}: {e}");
    }
}

// ─── Entry point ─────────────────────────────────────────────────

fn main() {
    let root = capsec::root();

    // Build the context struct — this is the single place where
    // capabilities are granted and grouped.
    let caps = AppCaps {
        fs_read: root.grant::<FsRead>(),
        fs_write: root.grant::<FsWrite>(),
        net: root.grant::<NetConnect>(),
        env: root.grant::<EnvRead>(),
    };

    // One parameter instead of four through the call stack.
    run_app(&caps);

    println!("Done. The context struct reduced 4 cap params to 1.");
}
