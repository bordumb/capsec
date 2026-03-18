# capsec

Compile-time capability-based security for Rust.

This is the facade crate — it re-exports everything from `capsec-core`, `capsec-macro`, and `capsec-std` under a single dependency. This is the crate you should depend on.

## Install

```bash
cargo add capsec
```

## Quick start

```rust,ignore
use capsec::prelude::*;

#[capsec::context]
struct AppCtx {
    fs: FsRead,
    net: NetConnect,
}

#[capsec::main]
fn main(root: CapRoot) {
    let ctx = AppCtx::new(&root);
    let data = load_data("/tmp/data.csv", &ctx).unwrap();
}

// Leaf functions take &impl Has<P> — works with raw caps AND context structs
fn load_data(path: &str, cap: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}
```

## What's re-exported

| From | What you get |
|------|-------------|
| `capsec-core` | `Cap`, `SendCap`, `Has`, `Permission`, `CapRoot`, `FsRead`, `NetConnect`, etc. |
| `capsec-macro` | `#[capsec::requires]`, `#[capsec::deny]`, `#[capsec::main]`, `#[capsec::context]` |
| `capsec-std` | `capsec::fs`, `capsec::net`, `capsec::env`, `capsec::process` |

Also provides:
- `capsec::run(|root| { ... })` — convenience entry point
- `capsec::prelude::*` — common imports

## Testing

Use `capsec::test_root()` (requires the `test-support` feature) to bypass the singleton check in tests:

```toml
[dev-dependencies]
capsec = { version = "0.1", features = ["test-support"] }
```

## License

Apache-2.0
