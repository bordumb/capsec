# capsec-macro

Procedural macros for the [capsec](https://github.com/bordumb/capsec) capability-based security system.

You probably want to depend on the `capsec` facade crate instead of using this directly — it re-exports these macros.

## Macros

### `#[capsec::main]`

Injects `CapRoot` creation into a function entry point. Removes the first `CapRoot` parameter and prepends `let root = capsec::root();` to the body.

```rust,ignore
#[capsec::main]
fn main(root: CapRoot) {
    let fs = root.fs_read();
    // ...
}
```

When combining with `#[tokio::main]`, place `#[capsec::main]` above:

```rust,ignore
#[capsec::main]
#[tokio::main]
async fn main(root: CapRoot) { ... }
```

### `#[capsec::context]`

Transforms a struct with permission-type fields into a capability context. Generates `Cap<P>` fields, a `new(root)` constructor, and `Has<P>` impls for each field.

```rust,ignore
#[capsec::context]
struct AppCtx {
    fs: FsRead,
    net: NetConnect,
}

// Generated: AppCtx::new(&root), impl Has<FsRead> for AppCtx, impl Has<NetConnect> for AppCtx
```

For async/threaded code, use the `send` variant to generate `SendCap<P>` fields:

```rust,ignore
#[capsec::context(send)]
struct AsyncCtx {
    fs: FsRead,
}
// AsyncCtx is Send + Sync, can be wrapped in Arc
```

### `#[capsec::requires(...)]`

Declares and validates a function's capability requirements.

With `impl Has<P>` bounds, the compiler already enforces the trait bounds — the macro emits only a `#[doc]` attribute:

```rust,ignore
#[capsec::requires(fs::read, net::connect)]
fn sync_data(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) -> Result<()> {
    // ...
}
```

With concrete context types, use `on = param` to emit a compile-time assertion that the parameter type implements `Has<P>`:

```rust,ignore
#[capsec::requires(fs::read, net::connect, on = ctx)]
fn sync_data(config: &Config, ctx: &AppCtx) -> Result<()> {
    // ...
}
```

With generic type parameters, `on = param` auto-generates `Has<P>` bounds — write your requirements once in the attribute, and the macro adds the `where` clause:

```rust,ignore
// You write:
#[capsec::requires(fs::read, net::connect, on = ctx)]
fn sync_data<C>(config: &Config, ctx: &C) -> Result<()> {
    // ...
}

// Macro generates: where C: Has<FsRead> + Has<NetConnect>
```

### `#[capsec::deny(...)]`

Marks a function as capability-free. `cargo capsec audit` will promote any ambient authority call inside a `#[deny]` function to **critical** risk.

```rust,ignore
#[capsec::deny(all)]
fn pure_transform(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}
```

## Supported permissions

`fs::read`, `fs::write`, `fs::all`, `net::connect`, `net::bind`, `net::all`, `env::read`, `env::write`, `spawn`, `all`

## License

Apache-2.0
