# capsec

Compile-time capability-based security for Rust.

This is the facade crate — it re-exports everything from `capsec-core`, `capsec-macro`, and `capsec-std` under a single dependency. This is the crate you should depend on.

## Install

```bash
cargo add capsec

# Or from source:
cargo install --path crates/capsec
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

// Leaf functions take &impl CapProvider<P> — works with raw caps, context structs, AND scoped caps
fn load_data(path: &str, cap: &impl CapProvider<FsRead>) -> Result<String, CapSecError> {
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

`test_root()` bypasses the singleton check and is available in debug/test builds (`#[cfg(debug_assertions)]`). It cannot be enabled in release builds — there is no feature flag:

```rust,ignore
#[cfg(test)]
mod tests {
    use capsec::test_root;

    #[test]
    fn my_test() {
        let root = test_root();
        let cap = root.fs_read();
        // ...
    }
}
```

## License

Apache-2.0
