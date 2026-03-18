//! Example: Async context with `#[capsec::context(send)]`
//!
//! Shows how to use capability contexts in async/threaded code.
//! The `send` variant uses `SendCap<P>` fields, making the context
//! `Send + Sync` so it can be wrapped in `Arc` and shared across tasks.

use capsec::CapSecError;
use std::sync::Arc;

/// A Send + Sync context for async use.
/// The `send` option generates `SendCap<P>` fields instead of `Cap<P>`.
#[capsec::context(send)]
struct AppCtx {
    fs: FsRead,
}

/// Simulates handling a request. The context is shared via Arc.
async fn handle_request(id: usize, ctx: &AppCtx) -> Result<(), CapSecError> {
    let data = capsec::fs::read_to_string("/etc/hostname", ctx)?;
    println!("[task {id}] hostname: {}", data.trim());
    Ok(())
}

#[capsec::main]
#[tokio::main]
async fn main(root: CapRoot) {
    let ctx = Arc::new(AppCtx::new(&root));

    let mut handles = Vec::new();
    for i in 0..3 {
        let ctx = ctx.clone();
        handles.push(tokio::spawn(async move {
            handle_request(i, &ctx).await.ok();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    println!("All tasks complete.");
}
