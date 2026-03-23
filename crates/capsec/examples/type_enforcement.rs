//! Example: Type-enforced capabilities
//!
//! The same app from `audit_only.rs`, rewritten with capsec types.
//! Every I/O operation requires a capability token — the compiler enforces
//! that functions can only do what their signature declares.
//!
//! Key concepts shown here:
//! - `#[capsec::main]` — injects the capability root automatically
//! - Convenience methods (`root.fs_read()`) — discoverable via IDE autocomplete
//! - `&impl CapProvider<P>` — function bounds that declare required permissions
//! - `capsec::fs::*`, `capsec::net::*`, `capsec::process::*` — drop-in
//!   replacements for std that require a capability argument
//!
//! Try removing a capability parameter from a function signature — the
//! compiler will reject the call inside the function body.

use capsec::prelude::*;
use std::io::Write;

/// Reads configuration from disk.
/// The `Has<FsRead>` bound makes the filesystem access visible in the signature.
fn load_config(path: &str, cap: &impl CapProvider<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}

/// Writes a result file to disk.
/// Requires `FsWrite` — cannot read files, only write them.
fn save_result(path: &str, data: &str, cap: &impl CapProvider<FsWrite>) -> Result<(), CapSecError> {
    capsec::fs::write(path, data.as_bytes(), cap)
}

/// Opens a TCP connection and sends data.
/// Requires `NetConnect` — cannot bind a listener or do filesystem I/O.
fn send_report(
    addr: &str,
    data: &str,
    cap: &impl CapProvider<NetConnect>,
) -> Result<(), CapSecError> {
    let mut stream = capsec::net::tcp_connect(addr, cap)?;
    stream.write_all(data.as_bytes())?;
    Ok(())
}

/// Spawns a subprocess to run cleanup.
/// Requires `Spawn` — the most dangerous permission, isolated to just this function.
fn run_cleanup(dir: &str, cap: &impl CapProvider<Spawn>) -> Result<(), CapSecError> {
    let output = capsec::process::run("rm", &["-rf", dir], cap)?;
    if !output.status.success() {
        eprintln!("cleanup failed");
    }
    Ok(())
}

/// Pure computation — no capability parameter, no I/O possible.
fn process_data(input: &str) -> String {
    input.to_uppercase()
}

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // Convenience methods — no turbofish needed
    let fs_read = root.fs_read();
    let fs_write = root.fs_write();
    let net_cap = root.net_connect();
    let spawn_cap = root.spawn();

    // Each function receives only the capability it needs.
    let config = load_config("/etc/app/config.toml", &fs_read)?;
    let result = process_data(&config);
    save_result("/tmp/result.txt", &result, &fs_write)?;
    send_report("telemetry.example.com:8080", &result, &net_cap)?;
    run_cleanup("/tmp/scratch", &spawn_cap)?;

    Ok(())
}
