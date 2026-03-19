# capsec-tokio

Async capability-gated wrappers around `tokio::fs`, `tokio::net`, and `tokio::process`.

This is the async counterpart to [`capsec-std`](https://crates.io/crates/capsec-std). Every function mirrors a `tokio` function but requires a capability token proving the caller has permission. The capability proof is scoped before the first `.await` to keep returned futures `Send`.

You probably want to depend on the `capsec` facade crate with the `tokio` feature instead of using this directly:

```toml
capsec = { version = "0.1", features = ["tokio"] }
```

## Example

```rust,ignore
use capsec::prelude::*;

#[capsec::context(send)]
struct AppCtx {
    fs: FsRead,
}

async fn load_config(ctx: &AppCtx) -> Result<String, CapSecError> {
    capsec::tokio::fs::read_to_string("/etc/app/config.toml", ctx).await
}
```

## Modules

Enable via feature flags (`full` enables all):

| Module | Feature | Permission required | What it wraps |
|--------|---------|-------------------|---------------|
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
