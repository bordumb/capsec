//! Example: Two-person authorization with DualKeyCap
//!
//! Demonstrates Saltzer & Schroeder's "separation of privilege" principle:
//! a capability that requires two independent approvals before it can be
//! exercised. No single entity can unlock the capability alone.

use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Grant FsWrite and wrap in a DualKeyCap
    let (dual_cap, approver_a, approver_b) = DualKeyCap::new(root.fs_write());

    println!("=== Dual-Key Authorization ===");

    // 2. Before any approvals: try_cap() fails
    match dual_cap.try_cap() {
        Ok(_) => println!("[pre] This should not happen"),
        Err(e) => println!("[pre] No approvals yet: {e}"),
    }

    // 3. First approval (e.g., from a manager)
    approver_a.approve();
    println!("\n[approve] Approver A approved (manager)");
    println!(
        "[status] A approved: {}, B approved: {}",
        approver_a.is_approved(),
        approver_b.is_approved()
    );

    // Still fails — need both
    match dual_cap.try_cap() {
        Ok(_) => println!("[partial] This should not happen"),
        Err(e) => println!("[partial] Only one approval: {e}"),
    }

    // 4. Second approval (e.g., from security officer)
    approver_b.approve();
    println!("\n[approve] Approver B approved (security officer)");
    println!(
        "[status] A approved: {}, B approved: {}",
        approver_a.is_approved(),
        approver_b.is_approved()
    );

    // 5. Now try_cap() succeeds
    let cap = dual_cap.try_cap()?;
    println!("\n[granted] Dual-key authorization complete!");

    let path = std::env::temp_dir().join("capsec-dual-auth-demo.txt");
    capsec::fs::write(&path, "authorized write", &cap)?;
    println!("[write] Wrote to {}", path.display());

    // Clean up
    std::fs::remove_file(&path).ok();

    println!("\n=== Demo Complete ===");
    println!("Both authorities approved before write access was granted.");

    Ok(())
}
