//! Example: Scoped capabilities with Attenuated<P, S>
//!
//! Demonstrates how to combine capability tokens with scope restrictions.
//! Attenuation narrows *where* a capability can act — a `Cap<FsRead>` can
//! read any file, but an `Attenuated<FsRead, DirScope>` can only read files
//! within a specific directory tree.
//!
//! capsec treats capability (do you have permission?) and scope (is this
//! target allowed?) as orthogonal concerns. The two-check pattern is:
//!
//! 1. **Scope check** — `scoped.check(path)?` verifies the target is in bounds
//! 2. **Capability check** — `capsec::fs::read(path, &cap)?` verifies permission
//!
//! Both must pass before I/O happens. This keeps capsec-std wrappers simple
//! (`&impl Has<P>`) while still supporting fine-grained restrictions.

use capsec::prelude::*;

/// Reads a file, but only if it's within the allowed directory.
///
/// This function demonstrates the two-check pattern:
/// - The `Attenuated` scope check rejects paths outside the allowed dir
/// - The `Has<FsRead>` capability check proves filesystem read permission
fn read_scoped(
    path: &str,
    scope: &Attenuated<FsRead, DirScope>,
    cap: &impl Has<FsRead>,
) -> Result<String, CapSecError> {
    // Step 1: scope gate — is this path within bounds?
    scope.check(path)?;

    // Step 2: capability gate — do we have FsRead permission?
    capsec::fs::read_to_string(path, cap)
}

/// A more compact pattern: keep the raw cap alongside the scoped one.
///
/// Since Cap<P> is Clone, you can clone before attenuating to keep
/// an unscoped copy for passing to capsec-std functions.
fn read_from_dir(
    path: &str,
    raw_cap: &impl Has<FsRead>,
    scope: &Attenuated<FsRead, DirScope>,
) -> Result<String, CapSecError> {
    scope.check(path)?;
    capsec::fs::read_to_string(path, raw_cap)
}

/// Network example: restrict connections to specific hosts.
fn connect_scoped(
    addr: &str,
    scope: &Attenuated<NetConnect, HostScope>,
    cap: &impl Has<NetConnect>,
) -> Result<std::net::TcpStream, CapSecError> {
    scope.check(addr)?;
    capsec::net::tcp_connect(addr, cap)
}

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // Grant capabilities
    let fs_cap = root.fs_read();
    let net_cap = root.net_connect();

    // Clone before attenuating — attenuation consumes the cap
    let fs_for_scope = fs_cap.clone();
    let net_for_scope = net_cap.clone();

    // Create scoped capabilities
    let fs_scope = fs_for_scope.attenuate(DirScope::new("/tmp")?);
    let net_scope = net_for_scope.attenuate(HostScope::new(["api.example.com"]));

    // Allowed: /tmp is within scope
    match read_scoped("/tmp/capsec-demo.txt", &fs_scope, &fs_cap) {
        Ok(data) => println!("Read {} bytes from /tmp", data.len()),
        Err(e) => println!("Expected: {e}"),
    }

    // Blocked by scope: /etc is outside DirScope("/tmp")
    match read_scoped("/etc/hostname", &fs_scope, &fs_cap) {
        Ok(_) => println!("This should not happen"),
        Err(e) => println!("Blocked by scope (expected): {e}"),
    }

    // Blocked by scope: evil.com is not in HostScope
    match connect_scoped("evil.com:8080", &net_scope, &net_cap) {
        Ok(_) => println!("This should not happen"),
        Err(e) => println!("Blocked by scope (expected): {e}"),
    }

    // The compact pattern works too
    match read_from_dir("/tmp/capsec-demo.txt", &fs_cap, &fs_scope) {
        Ok(data) => println!("Compact pattern: {} bytes", data.len()),
        Err(e) => println!("Expected: {e}"),
    }

    println!("Scoped capabilities demo complete.");
    Ok(())
}
