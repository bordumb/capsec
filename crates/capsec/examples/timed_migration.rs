//! Example: Time-bounded write access for migrations
//!
//! Demonstrates granting temporary FsWrite permission for a migration window.
//! After the TTL expires, write access is automatically blocked.

use capsec::prelude::*;
use std::time::Duration;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Grant FsWrite and wrap in a timed capability (200ms window)
    let fs_cap = root.grant::<FsWrite>();
    let timed_cap = TimedCap::new(fs_cap, Duration::from_millis(200));

    println!("=== Migration Window Open (200ms) ===");
    println!("[start] remaining: {:?}", timed_cap.remaining());

    // 2. Write a temp file within the window
    let path = std::env::temp_dir().join("capsec-migration-demo.txt");
    let cap = timed_cap.try_cap()?;
    capsec::fs::write(&path, "migration data", &cap)?;
    println!("[write] Wrote migration file: {}", path.display());
    println!("[write] remaining: {:?}", timed_cap.remaining());

    // 3. Sleep past expiry
    println!("\n=== Waiting for TTL to expire... ===");
    std::thread::sleep(Duration::from_millis(250));
    println!("[expired] remaining: {:?}", timed_cap.remaining());

    // 4. After expiry: try_cap() returns Err(Expired)
    println!("\n=== Post-Expiry Phase ===");
    match timed_cap.try_cap() {
        Ok(_) => println!("[post] This should not happen"),
        Err(e) => println!("[post] try_cap() returned: {e}"),
    }

    // Clean up
    std::fs::remove_file(&path).ok();
    println!("\n=== Demo Complete ===");
    println!("Migration window closed — write access expired automatically.");

    Ok(())
}
