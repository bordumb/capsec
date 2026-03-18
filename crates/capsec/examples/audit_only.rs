//! Example: Audit-only adoption
//!
//! This small app uses `std::fs` and `std::net` directly — no capsec types.
//! Run `cargo capsec audit` against this file to see what it finds.
//!
//! ```bash
//! cargo capsec audit --path crates/capsec/examples/audit_only.rs
//! ```
//!
//! Expected output (abbreviated):
//!
//! ```text
//!   FS    examples/audit_only.rs:24:5    std::fs::read_to_string   load_config()
//!   FS    examples/audit_only.rs:30:5    std::fs::write            save_result()
//!   NET   examples/audit_only.rs:37:5    TcpStream::connect        send_report()
//!   PROC  examples/audit_only.rs:47:5    Command::new              run_cleanup()
//! ```
//!
//! This is the first step in adopting capsec: understand what your code does
//! before changing anything. See `type_enforcement.rs` for the next step.

use std::io::Write;

/// Reads configuration from disk.
/// `cargo capsec audit` flags this: FS / read / medium-risk.
fn load_config(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| "default_config".into())
}

/// Writes a result file to disk.
/// `cargo capsec audit` flags this: FS / write / high-risk.
fn save_result(path: &str, data: &str) {
    std::fs::write(path, data).expect("failed to write result");
}

/// Opens a TCP connection and sends data.
/// `cargo capsec audit` flags this: NET / connect / high-risk.
fn send_report(addr: &str, data: &str) {
    if let Ok(mut stream) = std::net::TcpStream::connect(addr) {
        let _ = stream.write_all(data.as_bytes());
    }
}

/// Spawns a subprocess to run cleanup.
/// `cargo capsec audit` flags this: PROC / spawn / critical-risk.
fn run_cleanup(dir: &str) {
    let output = std::process::Command::new("rm")
        .args(["-rf", dir])
        .output()
        .expect("failed to run cleanup");

    if !output.status.success() {
        eprintln!("cleanup failed");
    }
}

fn main() {
    // Every function here exercises ambient authority — the signatures
    // don't reveal it, and the compiler doesn't enforce any boundaries.
    let config = load_config("/etc/app/config.toml");
    save_result("/tmp/result.txt", &config);
    send_report("telemetry.example.com:8080", &config);
    run_cleanup("/tmp/scratch");

    println!("Done. Now run `cargo capsec audit` to see what this code does.");
}
