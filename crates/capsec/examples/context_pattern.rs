//! Example: Sub-contexts for least privilege
//!
//! Shows how to define narrow context structs for different subsystems.
//! Each context carries only the permissions its subsystem needs —
//! the compiler enforces the boundary.

use capsec::prelude::*;

// ─── Narrow contexts per subsystem ──────────────────────────────

/// Ingest subsystem: can read files but not write them.
#[capsec::context]
struct IngestCtx {
    fs: FsRead,
}

/// Output subsystem: can write files and connect to the network.
#[capsec::context]
struct OutputCtx {
    fs: FsWrite,
    net: NetConnect,
}

// ─── Subsystem functions ────────────────────────────────────────

/// Reads input data. Cannot write files or connect to the network.
fn ingest(path: &str, ctx: &IngestCtx) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, ctx)
}

/// Writes output. Cannot read files.
fn publish(path: &str, data: &str, ctx: &OutputCtx) -> Result<(), CapSecError> {
    capsec::fs::write(path, data.as_bytes(), ctx)
}

/// Pure transformation — no context, no I/O.
fn transform(data: &str) -> String {
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!("  > {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ─── Entry point ────────────────────────────────────────────────

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // Each subsystem gets exactly the authority it needs.
    let ingest_ctx = IngestCtx::new(&root);
    let output_ctx = OutputCtx::new(&root);

    let raw = ingest("/etc/hostname", &ingest_ctx)?;
    let processed = transform(&raw);
    publish("/tmp/capsec-context-demo.txt", &processed, &output_ctx)?;

    // The compiler prevents:
    // - ingest() from writing files (IngestCtx has no FsWrite)
    // - publish() from reading files (OutputCtx has no FsRead)
    // - transform() from doing any I/O (no context at all)

    println!("Processed {} bytes -> {} bytes", raw.len(), processed.len());
    Ok(())
}
