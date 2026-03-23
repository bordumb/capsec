//! Example: Incremental migration
//!
//! Shows how to adopt capsec gradually — some functions use capsec types,
//! others still use `std` directly. Both the audit tool and the type system
//! work together during migration.
//!
//! Migration strategy:
//! 1. Run `cargo capsec audit` to find all I/O (audit_only.rs shows this)
//! 2. Convert high-risk functions first (this example)
//! 3. Leave low-risk or stable code for later
//! 4. Run `cargo capsec audit --diff` on PRs to prevent new ambient I/O

use capsec::prelude::*;

// ─── Already migrated ───────────────────────────────────────────────

/// This function has been migrated to capsec.
/// The `Has<FsRead>` bound makes the filesystem access explicit.
fn load_config(path: &str, cap: &impl CapProvider<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}

/// Also migrated — network access is now visible in the type signature.
fn send_metrics(
    addr: &str,
    data: &str,
    cap: &impl CapProvider<NetConnect>,
) -> Result<(), CapSecError> {
    let mut stream = capsec::net::tcp_connect(addr, cap)?;
    std::io::Write::write_all(&mut stream, data.as_bytes())?;
    Ok(())
}

// ─── Not yet migrated ───────────────────────────────────────────────

/// This function still uses `std::fs` directly — it works fine, but
/// `cargo capsec audit` will flag it.
fn save_cache(path: &str, data: &str) {
    std::fs::write(path, data).expect("cache write failed");
}

/// Also not yet migrated. `cargo capsec audit` flags env var access.
fn get_log_level() -> String {
    std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into())
}

// ─── Pure functions need no migration ────────────────────────────────

/// Pure computation — no I/O, no capability needed, nothing to migrate.
fn format_report(config: &str, level: &str) -> String {
    format!("[{level}] config loaded: {}", config.len())
}

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // Convenience methods for migrated functions
    let fs_read = root.fs_read();
    let net_cap = root.net_connect();

    // Migrated: capabilities enforced at compile time.
    let config = load_config("/etc/app/config.toml", &fs_read)?;

    // Not yet migrated: still uses ambient authority.
    let level = get_log_level();
    save_cache("/tmp/app.cache", &config);

    // Pure: no migration needed.
    let report = format_report(&config, &level);

    // Migrated: network access is explicit.
    send_metrics("metrics.example.com:9090", &report, &net_cap)?;

    println!("{report}");
    Ok(())
}
