# capsec-tokio

Async capability-gated wrappers around `tokio::fs`, `tokio::net`, and `tokio::process`.

This is the async counterpart to [`capsec-std`](https://crates.io/crates/capsec-std). Every function mirrors a `tokio` function but requires a capability token proving the caller has permission. The capability proof is scoped before the first `.await` to keep returned futures `Send`.

You probably want to depend on the `capsec` facade crate with the `tokio` feature instead of using this directly:

```toml
capsec = { version = "0.1", features = ["tokio"] }
```

## Capsec + Tokio Guide

There are three common patterns for using capabilities in async code.

### Pattern 1: Scoped proof (no spawn)

When your async code runs on the current task (no `tokio::spawn`), pass capabilities by reference. The scope-before-await pattern inside each wrapper keeps futures `Send` automatically.

```rust,ignore
async fn handle_request(cap: &impl Has<FsRead>) {
    let data = capsec::tokio::fs::read("/tmp/config.toml", cap).await?;
    // use data...
}
```

### Pattern 2: `spawn_with` (single capability)

When spawning a task that needs one capability, use `capsec_tokio::task::spawn_with`. It converts `Cap<P>` to `SendCap<P>` for you — no need to call `.make_send()` manually.

```rust,ignore
let cap = root.grant::<FsRead>();

let handle = capsec::tokio::task::spawn_with(cap, |cap| async move {
    capsec::tokio::fs::read("/tmp/data.bin", &cap).await.unwrap()
});

let data = handle.await?;
```

### Pattern 3: `Arc` context (multiple capabilities)

When a spawned task needs multiple capabilities, use `#[capsec::context(send)]` to create a `Send`-safe context struct, wrap it in `Arc`, and clone for each task.

```rust,ignore
#[capsec::context(send)]
struct AppCtx {
    fs: FsRead,
    net: NetConnect,
}

let ctx = Arc::new(AppCtx::new(&root));

let ctx2 = Arc::clone(&ctx);
tokio::spawn(async move {
    let data = capsec::tokio::fs::read("/tmp/data", &*ctx2).await?;
});
```

## Modules

Enable via feature flags (`full` enables all):

| Module | Feature | Permission required | What it wraps |
|--------|---------|-------------------|---------------|
| `task` | `rt` | — | `tokio::spawn` — capability-aware task spawning |
| `fs` | `fs` | `FsRead` / `FsWrite` | `tokio::fs` — read, write, delete, rename, copy, open, create |
| `net` | `net` | `NetConnect` / `NetBind` | `tokio::net` — TCP connect, TCP/UDP bind |
| `process` | `process` | `Spawn` | `tokio::process` — Command::new, run |
| `file` | `fs` | — | `AsyncReadFile` / `AsyncWriteFile` restricted file handles |

## File handles

`open()` returns `AsyncReadFile` (implements `AsyncRead + AsyncSeek`, not `AsyncWrite`).
`create()` returns `AsyncWriteFile` (implements `AsyncWrite + AsyncSeek`, not `AsyncRead`).

This enforces the capability boundary beyond the function call — a file opened with `FsRead` cannot be written to.

## License

Apache-2.0
