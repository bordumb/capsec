# capsec-core

Zero-cost capability tokens and permission traits for compile-time capability-based security in Rust.

This is the foundation crate of the [capsec](https://github.com/bordumb/capsec) ecosystem. You probably want to depend on the `capsec` facade crate instead of using this directly.

## What's in here

- **`Permission`** — sealed marker trait for capability categories (`FsRead`, `NetConnect`, `Spawn`, etc.)
- **`Cap<P>`** — zero-sized proof token that the holder has permission `P`
- **`SendCap<P>`** — thread-safe variant of `Cap<P>` (`Send + Sync`)
- **`Has<P>`** — trait bound for declaring capability requirements. Open for implementation — custom context structs can implement `Has<P>` to delegate capability access.
- **`CapRoot`** — singleton factory for granting capabilities, with convenience methods (`fs_read()`, `net_connect()`, etc.)
- **`Attenuated<P, S>`** — scope-restricted capabilities (`DirScope`, `HostScope`)

All types are zero-sized at runtime. No overhead.

Security is maintained because `Cap::new()` is `pub(crate)` — no external code can forge a `Cap<P>` in safe Rust. The `Permission` trait remains sealed.

## Example

```rust,ignore
use capsec_core::root::test_root;
use capsec_core::permission::FsRead;
use capsec_core::has::Has;

let root = test_root();

// Turbofish or convenience method — both work:
let cap = root.grant::<FsRead>();
let cap = root.fs_read();

fn needs_fs(cap: &impl Has<FsRead>) {
    // can only be called with proof of FsRead permission
}

needs_fs(&cap);
```

## License

Apache-2.0
