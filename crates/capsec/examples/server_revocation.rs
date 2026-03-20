//! Example: Revocable capabilities for server initialization
//!
//! Demonstrates the "grant for startup, revoke after init" pattern.
//! Network capabilities are granted for connection pool setup, then
//! revoked to prevent runtime escalation.

use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Grant NetConnect and wrap in a revocable capability
    let net_cap = root.grant::<NetConnect>();
    let (runtime_cap, revoker) = RuntimeCap::new(net_cap);

    println!("=== Server Initialization ===");

    // 2. During startup: try_cap() succeeds, proving we have permission
    let cap = runtime_cap.try_cap()?;
    println!("[startup] NetConnect capability active — initializing connection pool");
    println!("[startup] Cap<NetConnect> obtained, pool created (simulated)");
    drop(cap); // We only needed the cap to prove permission

    // 3. Startup complete — revoke to prevent new connections at runtime
    println!("\n=== Initialization Complete — Revoking ===");
    revoker.revoke();
    println!("[revoke] Revoker::revoke() called — no new connections allowed");

    // 4. After revocation: try_cap() returns Err(Revoked)
    println!("\n=== Runtime Phase ===");
    match runtime_cap.try_cap() {
        Ok(_) => println!("[runtime] This should not happen"),
        Err(e) => println!("[runtime] try_cap() returned: {e}"),
    }

    // 5. Clones are also revoked — they share the same flag
    let clone = runtime_cap.clone();
    match clone.try_cap() {
        Ok(_) => println!("[clone] This should not happen"),
        Err(e) => println!("[clone] Cloned cap also blocked: {e}"),
    }

    println!("\n=== Demo Complete ===");
    println!("Server is locked down — network capabilities revoked after init.");

    Ok(())
}
