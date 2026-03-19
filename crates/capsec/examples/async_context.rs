//! Example: Async context with `#[capsec::context(send)]`
//!
//! Shows how to use capability contexts in async/threaded code.
//! The `send` variant uses `SendCap<P>` fields, making the context
//! `Send + Sync` so it can be wrapped in `Arc` and shared across tasks.
//!
//! Run with: `cargo run --example async_context --features tokio`

#[cfg(feature = "tokio")]
mod inner {
    use capsec::CapSecError;
    use std::sync::Arc;

    #[capsec::context(send)]
    struct AppCtx {
        fs: FsRead,
    }

    async fn handle_request(id: usize, ctx: &AppCtx) -> Result<(), CapSecError> {
        let data = capsec::tokio::fs::read_to_string("/etc/hostname", ctx).await?;
        println!("[task {id}] hostname: {}", data.trim());
        Ok(())
    }

    #[capsec::main]
    #[tokio::main]
    pub async fn run(root: capsec::CapRoot) {
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
}

#[cfg(feature = "tokio")]
fn main() {
    inner::run();
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("This example requires the `tokio` feature:");
    eprintln!("  cargo run --example async_context --features tokio");
}
