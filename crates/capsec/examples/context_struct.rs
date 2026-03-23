//! Example: Context Struct pattern with `#[capsec::context]`
//!
//! Demonstrates bundling capabilities into a single struct to reduce
//! parameter count at intermediate layers. The `#[capsec::context]` macro
//! generates `Has<P>` implementations so the struct can be passed directly
//! to any capsec-gated function.
//!
//! Key concepts:
//! - `#[capsec::context]` generates Cap fields, constructor, and Has impls
//! - Context structs are ZSTs (all fields are zero-sized caps)
//! - Pass `&ctx` directly to leaf functions that take `&impl CapProvider<P>`
//! - For multi-threaded contexts, use `#[capsec::context(send)]`

use capsec::prelude::*;

// ─── The Context Struct ──────────────────────────────────────────

/// Bundles the capabilities this application needs.
/// The macro generates Cap<P> fields, a `new(root)` constructor,
/// and Has<P> impls for each permission.
#[capsec::context]
struct AppCtx {
    fs_read: FsRead,
    fs_write: FsWrite,
    net: NetConnect,
    env: EnvRead,
}

// ─── Intermediate layer: receives the context ────────────────────

/// Orchestrates the application workflow.
/// Takes one `&AppCtx` instead of four separate capability parameters.
/// The context satisfies Has<P> for each permission, so it can be
/// passed directly to leaf functions.
fn run_app(ctx: &AppCtx) {
    let config_path = get_config_path(ctx); // ctx satisfies Has<EnvRead>
    let config = load_file(&config_path, ctx); // ctx satisfies Has<FsRead>

    let processed = config.to_uppercase();

    save_output("/tmp/capsec-demo-output.txt", &processed, ctx); // ctx satisfies Has<FsWrite>

    println!("Would send {} bytes to metrics server", processed.len());
}

// ─── Leaf functions: take `&impl CapProvider<P>`, not the context ────────

fn get_config_path(cap: &impl CapProvider<EnvRead>) -> String {
    capsec::env::var("APP_CONFIG", cap).unwrap_or_else(|_| "/etc/app/config.toml".into())
}

fn load_file(path: &str, cap: &impl CapProvider<FsRead>) -> String {
    capsec::fs::read_to_string(path, cap).unwrap_or_else(|_| "# default config".into())
}

fn save_output(path: &str, data: &str, cap: &impl CapProvider<FsWrite>) {
    if let Err(e) = capsec::fs::write(path, data.as_bytes(), cap) {
        eprintln!("Warning: could not write {path}: {e}");
    }
}

// ─── Entry point ─────────────────────────────────────────────────

#[capsec::main]
fn main(root: CapRoot) {
    let ctx = AppCtx::new(&root);

    // One parameter instead of four through the call stack.
    run_app(&ctx);

    println!("Done. The #[capsec::context] macro eliminated all boilerplate.");
}
