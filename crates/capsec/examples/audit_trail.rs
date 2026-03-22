//! Example: Audited capability access with LoggedCap
//!
//! Demonstrates how LoggedCap records every capability exercise attempt
//! in an append-only audit log. Implements Saltzer & Schroeder's
//! "compromise recording" design principle.

use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Grant FsRead and wrap in a LoggedCap for audit trail
    let logged_cap = LoggedCap::new(root.fs_read());

    println!("=== Audited Capability Access ===");
    println!("[start] Log entries: {}", logged_cap.entry_count());

    // 2. Exercise the capability — each try_cap() is logged
    let cap = logged_cap.try_cap()?;
    let data = capsec::fs::read("/dev/null", &cap)?;
    println!("[read] Read {} bytes from /dev/null", data.len());

    // 3. Exercise again
    let cap = logged_cap.try_cap()?;
    let _ = capsec::fs::read("/dev/null", &cap)?;
    println!("[read] Read /dev/null again");

    // 4. Inspect the audit log
    println!("\n=== Audit Log ({} entries) ===", logged_cap.entry_count());
    for (i, entry) in logged_cap.entries().iter().enumerate() {
        println!(
            "  [{}] permission={}, granted={}, elapsed={:?}",
            i,
            entry.permission,
            entry.granted,
            entry.timestamp.elapsed()
        );
    }

    // 5. Clone shares the same log
    let clone = logged_cap.clone();
    let _ = clone.try_cap()?;
    println!(
        "\n[clone] After clone exercise: {} total entries (shared log)",
        logged_cap.entry_count()
    );

    println!("\n=== Demo Complete ===");
    println!("Every capability exercise is recorded for compliance.");

    Ok(())
}
