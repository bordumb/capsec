# capsec-std

Capability-gated wrappers around `std::fs`, `std::net`, `std::env`, and `std::process`.

This is the enforcement layer of [capsec](https://github.com/bordumb/capsec). Every function mirrors a `std` function but requires a capability token proving the caller has permission. You probably want to depend on the `capsec` facade crate instead of using this directly.

## Example

```rust,ignore
use capsec_core::root::test_root;
use capsec_core::permission::FsRead;

let root = test_root();
let cap = root.grant::<FsRead>();

// This works — we have a Cap<FsRead>:
let data = capsec_std::fs::read("/tmp/data.bin", &cap).unwrap();

// This won't compile — NetConnect can't satisfy Has<FsRead>:
// let net = root.grant::<NetConnect>();
// let data = capsec_std::fs::read("/tmp/data.bin", &net);
```

## Modules

| Module | Permission required | What it wraps |
|--------|-------------------|---------------|
| `fs` | `FsRead` / `FsWrite` | `std::fs` — read, write, delete, rename, copy |
| `net` | `NetConnect` / `NetBind` | `std::net` — TCP connect, TCP/UDP bind |
| `env` | `EnvRead` / `EnvWrite` | `std::env` — var, vars, set_var |
| `process` | `Spawn` | `std::process` — Command::new, run |

## License

Apache-2.0
