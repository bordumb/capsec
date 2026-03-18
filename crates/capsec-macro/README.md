# capsec-macro

Procedural macros for the [capsec](https://github.com/bordumb/capsec) capability-based security system.

You probably want to depend on the `capsec` facade crate instead of using this directly — it re-exports these macros.

## Macros

### `#[capsec::requires(...)]`

Declares a function's capability requirements. **This macro is documentation-only** — it does not enforce anything at compile time. Actual enforcement comes from the `Has<P>` trait bounds on the function's capability parameter. The macro makes the intent explicit for tooling and human readers.

```rust,ignore
#[capsec::requires(fs::read, net::connect)]
fn sync_data(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) -> Result<()> {
    // ...
}
```

### `#[capsec::deny(...)]`

Marks a function as capability-free. The `cargo capsec check` lint tool will flag any ambient authority call inside it.

```rust,ignore
#[capsec::deny(all)]
fn pure_transform(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}
```

## Supported permissions

`fs::read`, `fs::write`, `fs::all`, `net::connect`, `net::bind`, `net::all`, `env::read`, `env::write`, `spawn`, `all`

## License

MIT OR Apache-2.0
