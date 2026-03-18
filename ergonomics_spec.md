# Ergonomics Spec: Making capsec Painless

**Status:** Draft
**Authors:** capsec maintainers
**Date:** 2026-03-18

---

## Problem

capsec's type-system enforcement is sound. Adopting it is not painless. There are three layers of friction, each compounding the one before it:

### Friction 1: Entry-point ceremony

Creating capabilities requires turbofish syntax and multi-step setup:

```rust
fn main() {
    let root = capsec::root();                    // step 1: get root
    let fs_cap = root.grant::<FsRead>();          // step 2: turbofish grant
    let net_cap = root.grant::<NetConnect>();      // step 3: another turbofish
    let config = load_config("app.toml", &fs_cap);
}
```

`grant::<FsRead>()` is not discoverable via IDE autocomplete, not obvious to Rust newcomers, and requires importing each permission type by name.

### Friction 2: The coloring problem

Every function between `main()` and the leaf I/O call must thread capability parameters through its signature. This is the "function coloring" burden:

```rust
fn application_logic(
    config: &str,
    fs_cap: &impl Has<FsRead>,       // must carry this...
    write_cap: &impl Has<FsWrite>,    // ...and this...
    net_cap: &impl Has<NetConnect>,   // ...and this
) -> Result<(), CapSecError> {
    let data = load_data("input.csv", fs_cap)?;
    let result = transform(&data);
    save_output(&result, write_cap)?;
    notify_service(&result, net_cap)?;
    Ok(())
}
```

A function 5 levels deep in the call stack needs capability parameters it doesn't use directly, just to forward them. This is the same pain as manual dependency injection without a container. It scales linearly with the number of permission categories your app touches.

### Friction 3: Pattern confusion

New users face three adoption patterns (audit-only, type enforcement, incremental migration) and no guidance on which one to pick. The examples show the patterns but don't reduce the ceremony of any of them.

---

## Design Principles

1. **Zero ceremony for the common case.** A small app with 2-3 I/O categories should need ~5 lines of capsec setup, not 15.
2. **Capability threading should be invisible.** A function in the middle of the call stack should accept a single context reference, not N separate capability parameters.
3. **Leaf functions stay generic.** Functions that do actual I/O should still accept `&impl Has<P>`, so they work with raw caps, context structs, and any future capability holder.
4. **No security regression.** Convenience must not weaken the type-system guarantees. Unsealing `Has<P>` is safe because `Cap::new()` remains `pub(crate)` — there is no safe-code path to forging a capability token (see Security section).
5. **Additive, not breaking.** Every change is backwards-compatible. `root.grant::<FsRead>()` continues to work.

---

## Proposal: Three Layers

Each layer is independently useful. Together they eliminate all three friction sources.

### Layer 1: Convenience methods on `CapRoot`

**Solves:** Friction 1 (turbofish, discoverability)

Add named methods directly on `CapRoot` for every built-in permission:

```rust
impl CapRoot {
    pub fn fs_read(&self) -> Cap<FsRead>         { self.grant() }
    pub fn fs_write(&self) -> Cap<FsWrite>       { self.grant() }
    pub fn fs_all(&self) -> Cap<FsAll>           { self.grant() }
    pub fn net_connect(&self) -> Cap<NetConnect>  { self.grant() }
    pub fn net_bind(&self) -> Cap<NetBind>       { self.grant() }
    pub fn net_all(&self) -> Cap<NetAll>         { self.grant() }
    pub fn env_read(&self) -> Cap<EnvRead>       { self.grant() }
    pub fn env_write(&self) -> Cap<EnvWrite>     { self.grant() }
    pub fn spawn(&self) -> Cap<Spawn>            { self.grant() }
    pub fn ambient(&self) -> Cap<Ambient>        { self.grant() }
}
```

**Before:**
```rust
let fs_cap = root.grant::<FsRead>();
```

**After:**
```rust
let fs_cap = root.fs_read();
```

Benefits:
- IDE autocomplete shows all available permissions after `root.`
- No turbofish syntax for the common case
- Self-documenting: `root.fs_read()` reads as intent
- `grant::<P>()` still works for tuples and advanced use cases

**Files changed:** `capsec-core/src/root.rs`
**Effort:** S

### Layer 2: `capsec::run()` and `#[capsec::main]`

**Solves:** Friction 1 (boilerplate root creation)

#### `capsec::run()`

A functional entry point that handles root creation:

```rust
// In capsec/src/lib.rs
pub fn run<T>(f: impl FnOnce(CapRoot) -> T) -> T {
    let root = root();
    f(root)
}
```

Usage:
```rust
fn main() {
    capsec::run(|root| {
        let fs = root.fs_read();
        let config = load_config("app.toml", &fs).unwrap();
    });
}
```

#### `#[capsec::main]`

Attribute macro that injects root creation:

```rust
#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = AppCtx::new(&root);
    start_app(&ctx)?;
    Ok(())
}
```

Expands to:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = capsec::root();
    let ctx = AppCtx::new(&root);
    start_app(&ctx)?;
    Ok(())
}
```

The macro:
1. Extracts the first parameter (must be `CapRoot` or `capsec::CapRoot`)
2. Removes it from the function signature
3. Prepends `let {param_name} = capsec::root();` to the body
4. Preserves the return type and all other attributes

#### Stacking with `#[tokio::main]`

Rust proc macro attributes execute **bottom-up**. When combining `#[capsec::main]` with `#[tokio::main]`, the order matters:

```rust
// CORRECT — #[capsec::main] runs first (bottom-up), removes the root param,
// then #[tokio::main] wraps the result in a runtime block.
#[tokio::main]
#[capsec::main]
async fn main(root: CapRoot) { ... }
```

```rust
// WRONG — #[tokio::main] runs first, transforms the async fn into a
// synchronous fn with a runtime block. #[capsec::main] then sees a
// parameterless main() and fails or produces wrong code.
#[capsec::main]
#[tokio::main]
async fn main(root: CapRoot) { ... }
```

The macro should detect `async fn` with zero parameters (indicating `#[tokio::main]` already ran) and emit a clear error:

```
error: #[capsec::main] must be placed below #[tokio::main], not above it.
       Proc macro attributes execute bottom-up.

       Correct:
         #[tokio::main]
         #[capsec::main]
         async fn main(root: CapRoot) { ... }
```

**Files changed:** `capsec-macro/src/lib.rs`, `capsec/src/lib.rs`
**Effort:** M

### Layer 3: `#[capsec::context]` — the capability context macro

**Solves:** Friction 2 (the coloring problem)

This is the primary ergonomic improvement. A user defines a plain struct listing the permissions they need. The macro generates:
- A constructor that grants all capabilities from a `CapRoot`
- `Has<P>` implementations for each permission, so the struct can be passed directly to any capsec-gated function

#### User writes:

```rust
#[capsec::context]
pub struct AppCtx {
    fs: FsRead,
    write: FsWrite,
    net: NetConnect,
}
```

#### Macro generates:

```rust
pub struct AppCtx {
    fs: Cap<FsRead>,
    write: Cap<FsWrite>,
    net: Cap<NetConnect>,
}

impl AppCtx {
    pub fn new(root: &CapRoot) -> Self {
        Self {
            fs: root.grant::<FsRead>(),
            write: root.grant::<FsWrite>(),
            net: root.grant::<NetConnect>(),
        }
    }
}

impl Has<FsRead> for AppCtx {
    fn cap_ref(&self) -> Cap<FsRead> {
        self.fs.cap_ref()
    }
}

impl Has<FsWrite> for AppCtx {
    fn cap_ref(&self) -> Cap<FsWrite> {
        self.write.cap_ref()
    }
}

impl Has<NetConnect> for AppCtx {
    fn cap_ref(&self) -> Cap<NetConnect> {
        self.net.cap_ref()
    }
}
```

#### The experience:

```rust
#[capsec::context]
pub struct AppCtx {
    fs: FsRead,
    write: FsWrite,
    net: NetConnect,
}

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = AppCtx::new(&root);
    application_logic(&ctx)?;
    Ok(())
}

// ONE parameter, not three. Works at any call depth.
fn application_logic(ctx: &AppCtx) -> Result<(), CapSecError> {
    let data = load_data("input.csv", ctx)?;       // ctx satisfies Has<FsRead>
    let result = transform(&data);
    save_output(&result, ctx)?;                     // ctx satisfies Has<FsWrite>
    notify_service(&result, ctx)?;                  // ctx satisfies Has<NetConnect>
    Ok(())
}

// Leaf functions still use &impl Has<P> — they work with raw caps AND context structs.
fn load_data(path: &str, cap: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}
```

#### Async / threaded apps: `#[capsec::context(send)]`

`Cap<P>` is `!Send + !Sync` by default. For apps using tokio, actix, or threads, the macro supports a `send` option that uses `SendCap<P>` instead:

```rust
#[capsec::context(send)]
pub struct AppCtx {
    fs: FsRead,
    net: NetConnect,
}
```

Generates:

```rust
pub struct AppCtx {
    fs: SendCap<FsRead>,
    net: SendCap<NetConnect>,
}

impl AppCtx {
    pub fn new(root: &CapRoot) -> Self {
        Self {
            fs: root.grant::<FsRead>().make_send(),
            net: root.grant::<NetConnect>().make_send(),
        }
    }
}

impl Has<FsRead> for AppCtx {
    fn cap_ref(&self) -> Cap<FsRead> {
        self.fs.as_cap()
    }
}

// ... etc
```

Now `AppCtx` is `Send + Sync` and can be wrapped in `Arc<AppCtx>` for shared state:

```rust
#[tokio::main]
#[capsec::main]
async fn main(root: CapRoot) {
    let ctx = Arc::new(AppCtx::new(&root));

    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        handle_request(&*ctx_clone).await;
    });
}
```

#### Sub-contexts for least privilege

The context pattern does NOT encourage over-granting. Users can define narrow contexts for different subsystems:

```rust
#[capsec::context]
struct IngestCtx {
    fs: FsRead,           // can read, not write
}

#[capsec::context]
struct OutputCtx {
    fs: FsWrite,          // can write, not read
    net: NetConnect,      // can connect
}

fn ingest(ctx: &IngestCtx) -> Result<Data, CapSecError> { ... }
fn publish(ctx: &OutputCtx) -> Result<(), CapSecError> { ... }
```

The compiler enforces the boundary: `ingest()` cannot write files, `publish()` cannot read them. Each subsystem gets exactly the authority it needs.

#### Interaction with scoping/attenuation

The context is for *threading capabilities through call stacks*. It is not a replacement for `Attenuated` scoping. When you need path-restricted or host-restricted capabilities, extract the raw cap:

```rust
fn scoped_read(ctx: &AppCtx) -> Result<String, CapSecError> {
    let raw_cap: Cap<FsRead> = ctx.cap_ref();
    let scoped = raw_cap.attenuate(DirScope::new("/var/data")?);
    scoped.check("/var/data/input.csv")?;
    capsec::fs::read_to_string("/var/data/input.csv", &raw_cap)
}
```

This is an intentional design boundary. Context bundles authority; scoping restricts it.

#### Compile-time validation of field types

The macro must validate that every field type is a known permission type. `Permission` is sealed — the set of valid types is fixed and exhaustive (`FsRead`, `FsWrite`, `FsAll`, `NetConnect`, `NetBind`, `NetAll`, `EnvRead`, `EnvWrite`, `Spawn`, `Ambient`). The macro checks each field's type path against this set at expansion time.

If a user writes a non-permission type:

```rust
#[capsec::context]
struct Bad {
    x: String,
}
```

The macro emits a clear `compile_error!` at the field's span:

```
error: field `x` has type `String`, which is not a capsec permission type.
       Expected one of: FsRead, FsWrite, FsAll, NetConnect, NetBind,
       NetAll, EnvRead, EnvWrite, Spawn, Ambient

  --> src/main.rs:4:5
   |
4  |     x: String,
   |     ^^^^^^^^^
```

Without this validation, the generated `root.grant::<String>()` would fail with a generic `String: Permission is not satisfied` error pointing at macro-generated code — confusing and unhelpful. The validation catches the mistake at the user's source location with an actionable message.

**Tuple permission types are not supported in context structs.** While capsec supports `Cap<(FsRead, NetConnect)>` as a tuple permission, the context macro accepts only single permission types per field. Users who want multiple permissions use separate fields — this is clearer and produces one-to-one `Has<P>` impls per field:

```rust
// Correct — one permission per field
#[capsec::context]
struct Ctx {
    fs: FsRead,
    net: NetConnect,
}

// Not supported — tuple field type
#[capsec::context]
struct Ctx {
    combo: (FsRead, NetConnect),  // compile error
}
```

Tuple syntax would require the macro to destructure the type, generate `Cap<(A, B)>`, and emit `Has<P>` impls for both inner types from a single field. This is more complex to implement and harder to read. Flat fields are simpler, and the generated code is trivially auditable. Tuple support can be added in a future version if there's demand.

**Files changed:** `capsec-macro/src/lib.rs`, `capsec-core/src/has.rs`
**Effort:** L

---

## Required Change: Unsealing `Has<P>`

### What and why

`Has<P>` currently has a sealed supertrait (`capsec_core::has::sealed::Sealed<P>`). This prevents any type outside `capsec-core` from implementing `Has<P>`. The `#[capsec::context]` macro generates `impl Has<P> for UserStruct` in user code, which the sealed trait blocks.

**The seal must be removed** for the context macro to work. This means changing:

```rust
// Before
pub trait Has<P: Permission>: sealed::Sealed<P> {
    fn cap_ref(&self) -> Cap<P>;
}
```

to:

```rust
// After
pub trait Has<P: Permission> {
    fn cap_ref(&self) -> Cap<P>;
}
```

### Security analysis

The `Has<P>` trait requires implementors to return a `Cap<P>` from `cap_ref()`. `Cap::new()` is `pub(crate)` — only code inside `capsec-core` can construct a capability token. This is the security boundary.

**Why unsealing `Has<P>` is safe:**

With `Has<P>` unsealed, external code can `impl Has<FsRead> for MyContext`. To satisfy the trait, the implementor must return a `Cap<FsRead>` from `cap_ref()`. There are exactly two ways to obtain a `Cap<P>`:

1. **Legitimately, via `CapRoot::grant()`** — the implementor already holds the authority and is delegating it. This is the context pattern working as designed.
2. **Via `unsafe` code** — `transmute`, `zeroed`, `MaybeUninit`, or raw pointer tricks can forge a `Cap<P>`. All of these require an `unsafe` block, which places them outside capsec's safe-Rust threat model. The audit tool (`cargo capsec audit`) flags `unsafe` blocks and FFI.

There is no safe-code path to constructing a `Cap<P>` outside of `capsec-core`. Therefore, there is no safe-code path to implementing `Has<P>` maliciously. The sealed trait was defense-in-depth on top of this already-airtight boundary. Removing it enables the context pattern without opening any new forgery vector in safe Rust.

**The divergence case:**

With `Has<P>` unsealed, someone could write a diverging implementation:

```rust
struct Fake;
impl Has<FsRead> for Fake {
    fn cap_ref(&self) -> Cap<FsRead> { panic!("forgery") }
}
```

This compiles, but it's not a useful attack. The `cap_ref()` call panics (or loops) before any I/O executes. And crucially, someone who can modify the codebase to add this impl could just call `std::fs::read()` directly — it's not an escalation of authority. Nevertheless, we harden the wrappers as belt-and-suspenders (see below).

### Mitigation: Type-witnessed proof in capsec-std wrappers

As defense-in-depth against diverging `cap_ref()` implementations, capsec-std wrappers should use a type-annotated binding that forces `cap_ref()` to actually return before any I/O executes.

Currently, capsec-std wrappers call `cap_ref()` and discard the result:

```rust
// Current — called but result discarded
pub fn read(path: impl AsRef<Path>, cap: &impl Has<FsRead>) -> Result<Vec<u8>, CapSecError> {
    let _ = cap.cap_ref();
    Ok(std::fs::read(path)?)
}
```

Change every wrapper to use a type-annotated binding:

```rust
// Proposed — type witness forces cap_ref() to actually return
pub fn read(path: impl AsRef<Path>, cap: &impl Has<FsRead>) -> Result<Vec<u8>, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::read(path)?)
}
```

The `_proof: Cap<FsRead>` binding is zero-cost (ZST), but it forces `cap_ref()` to return a value of the correct type. A diverging `Has<P>` impl (`panic!()` or `loop {}`) fires *before* the I/O call, never after. This is a belt-and-suspenders guarantee: the primary security gate is `Cap::new()` being `pub(crate)`, and this ensures that even non-useful divergence attacks are caught loudly.

**Implementation note:** Every proof binding must use the **concrete permission type**, not an inferred generic. Writing `let _proof = cap.cap_ref()` compiles but loses the type witness entirely — the compiler infers the type without enforcing it. The explicit `: Cap<FsRead>` annotation is the whole point. For `copy()`, which takes two capability parameters, both must be witnessed:

```rust
pub fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    read_cap: &impl Has<FsRead>,
    write_cap: &impl Has<FsWrite>,
) -> Result<u64, CapSecError> {
    let _read_proof: Cap<FsRead> = read_cap.cap_ref();
    let _write_proof: Cap<FsWrite> = write_cap.cap_ref();
    Ok(std::fs::copy(from, to)?)
}
```

This change is applied to **all 20 functions** across `capsec-std/src/{fs,net,env,process}.rs`.

### Test changes

| Test | Current | After |
|------|---------|-------|
| `sealed_has_no_external_impl` | Fails to compile | **Remove** — external impls are now allowed by design |
| `has_forgery_panic` | Fails to compile | **Remove** — same reason |
| `has_forgery_loop` | Fails to compile | **Remove** |
| `has_forgery_god_mode` | Fails to compile | **Remove** |
| `has_forgery_process_exit` | Fails to compile | **Remove** |
| `has_forgery_capsec_std_fs` | Fails to compile | **Remove** |
| `has_forgery_capsec_std_env` | Fails to compile | **Remove** |

These tests verified the `Sealed<P>` supertrait, which is being intentionally removed. They should be replaced with a new test that documents the `Cap::new()` security boundary:

```rust
// cap_new_is_private.rs (already exists, keep it)
// Verifies that Cap::new() is pub(crate) — the real security gate
```

And a new **runtime** test verifying the context pattern:

```rust
#[test]
fn context_struct_satisfies_has() {
    struct TestCtx { fs: Cap<FsRead> }
    impl Has<FsRead> for TestCtx {
        fn cap_ref(&self) -> Cap<FsRead> { self.fs.cap_ref() }
    }

    let root = test_root();
    let ctx = TestCtx { fs: root.grant::<FsRead>() };
    // Passes: TestCtx satisfies Has<FsRead>
    fn needs_fs(_: &impl Has<FsRead>) {}
    needs_fs(&ctx);
}
```

### Permission trait stays sealed

`Permission` remains sealed via its own `sealed::Sealed` supertrait. External crates still cannot invent new permission types. Only the `Has<P>` delegation is opened.

---

## Before/After: Full Comparison

### Before (current)

```rust
use capsec::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = capsec::root();
    let fs_read = root.grant::<FsRead>();
    let fs_write = root.grant::<FsWrite>();
    let net = root.grant::<NetConnect>();

    let config = load_config("app.toml", &fs_read)?;
    let result = process(&config);
    save_result(&result, &fs_write)?;
    send_report(&result, &net)?;
    Ok(())
}

fn load_config(p: &str, c: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(p, c)
}

// 5 levels deep — must carry all 3 caps
fn deep_function(
    data: &str,
    fc: &impl Has<FsRead>,
    wc: &impl Has<FsWrite>,
    nc: &impl Has<NetConnect>,
) -> Result<(), CapSecError> {
    let more = capsec::fs::read_to_string("extra.txt", fc)?;
    capsec::fs::write("output.txt", &more, wc)?;
    let mut s = capsec::net::tcp_connect("metrics:9090", nc)?;
    Ok(())
}
```

### After (with all three layers)

```rust
use capsec::prelude::*;

#[capsec::context]
struct Ctx {
    read: FsRead,
    write: FsWrite,
    net: NetConnect,
}

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Ctx::new(&root);
    let config = load_config("app.toml", &ctx)?;
    let result = process(&config);
    save_result(&result, &ctx)?;
    send_report(&result, &ctx)?;
    Ok(())
}

fn load_config(p: &str, c: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(p, c)
}

// 5 levels deep — ONE parameter
fn deep_function(ctx: &Ctx) -> Result<(), CapSecError> {
    let more = capsec::fs::read_to_string("extra.txt", ctx)?;
    capsec::fs::write("output.txt", &more, ctx)?;
    let mut s = capsec::net::tcp_connect("metrics:9090", ctx)?;
    Ok(())
}
```

Lines of setup: **5 instead of 7.** Parameters threaded through call stack: **1 instead of 3.** And the gap widens as the app grows — a function touching 5 I/O categories goes from 5 cap parameters to 1 context reference.

---

## Implementation Plan

### Phase 1: Unseal `Has<P>` and harden wrappers (prerequisite for Layer 3)

| Step | File | Change |
|------|------|--------|
| 1a | `capsec-core/src/has.rs` | Remove `sealed::Sealed<P>` supertrait from `Has<P>` |
| 1b | `capsec-core/src/has.rs` | Remove `mod sealed` block and all `impl Sealed<P>` |
| 1c | `capsec-core/src/has.rs` | Remove `#[allow(private_bounds)]` attribute |
| 1d | `capsec-core/src/has.rs` | Add `impl<P: Permission> Has<P> for SendCap<P>` |
| 1e | `capsec-std/src/fs.rs` | Change all `let _ = cap.cap_ref()` to `let _proof: Cap<P> = cap.cap_ref()` |
| 1f | `capsec-std/src/net.rs` | Same `_proof` change |
| 1g | `capsec-std/src/env.rs` | Same `_proof` change |
| 1h | `capsec-std/src/process.rs` | Same `_proof` change |
| 1i | `capsec-tests/tests/compile_fail/` | Remove 7 forgery/sealing compile-fail tests + `.stderr` files |
| 1j | `capsec-tests/tests/type_system.rs` | Add runtime test for context-pattern delegation |
| 1k | `README.md` | Update Security Model section: note `Has<P>` is open for delegation, `Cap::new()` is the boundary |

### Phase 2: Layer 1 — Convenience methods

| Step | File | Change |
|------|------|--------|
| 2a | `capsec-core/src/root.rs` | Add named methods to `CapRoot` |
| 2b | `capsec-core/src/root.rs` | Add tests for each convenience method |

### Phase 3: Layer 2 — `capsec::run()` and `#[capsec::main]`

| Step | File | Change |
|------|------|--------|
| 3a | `capsec/src/lib.rs` | Add `pub fn run<T>(f: impl FnOnce(CapRoot) -> T) -> T` |
| 3b | `capsec-macro/src/lib.rs` | Add `#[capsec::main]` proc macro (with async stacking-order detection) |
| 3c | `capsec/src/lib.rs` | Re-export `main` macro |
| 3d | `capsec-tests/` | Add test for `run()` and `#[capsec::main]` |
| 3e | `capsec/tests/compile_fail/` | Add test: `#[capsec::main]` above `#[tokio::main]` emits ordering error |

### Phase 4: Layer 3 — `#[capsec::context]`

| Step | File | Change |
|------|------|--------|
| 4a | `capsec-macro/src/lib.rs` | Add `#[capsec::context]` proc macro with field-type validation against known permission set |
| 4b | `capsec-macro/src/lib.rs` | Support `#[capsec::context(send)]` variant |
| 4c | `capsec/src/lib.rs` | Re-export `context` macro |
| 4d | `capsec-tests/` | Add tests: context satisfies Has<P>, send variant is Send+Sync |
| 4e | `capsec/tests/compile_fail/` | Add test: context with wrong permission type emits clear error at field span |

### Phase 5: Upgrade `#[capsec::requires]` to emit assertions

| Step | File | Change |
|------|------|--------|
| 5a | `capsec-macro/src/lib.rs` | Modify `#[requires]` to parse `on = param` and emit `const _: ()` trait-bound check |
| 5b | `capsec-macro/src/lib.rs` | Skip assertion for `impl Has<P>` params (already enforced by compiler) |
| 5c | `capsec-macro/src/lib.rs` | Emit `compile_error!` when concrete types present but `on` is missing |
| 5d | `capsec-macro/src/lib.rs` | Update `#[requires]` doc comments |
| 5e | `capsec-macro/README.md` | Update docs: `#[requires]` now validates, not just documents |
| 5f | `capsec/tests/compile_fail/` | Add test: `#[requires(fs::read, on = ctx)]` where ctx type lacks `Has<FsRead>` fails |
| 5g | `capsec/tests/compile_fail/` | Add test: `#[requires(fs::read)]` with concrete params and no `on` emits error |
| 5h | `capsec-tests/` | Add test: `#[requires(fs::read, on = ctx)]` on fn accepting context struct compiles |
| 5i | `capsec-tests/` | Add test: `#[requires(fs::read)]` on fn with `impl Has<FsRead>` compiles (no `on` needed) |

### Phase 6: Examples and docs

| Step | File | Change |
|------|------|--------|
| 6a | `crates/capsec/examples/type_enforcement.rs` | Rewrite using `#[capsec::main]` + convenience methods |
| 6b | `crates/capsec/examples/incremental_migration.rs` | Rewrite using `#[capsec::main]` |
| 6c | `crates/capsec/examples/context_pattern.rs` | **New** — full example of `#[capsec::context]` with sub-contexts |
| 6d | `crates/capsec/examples/async_context.rs` | **New** — `#[capsec::context(send)]` with tokio |
| 6e | `README.md` | Update "After capsec" section to show context pattern |
| 6f | `capsec-macro/README.md` | Document `#[capsec::main]`, `#[capsec::context]`, and `#[requires]` assertion behavior |
| 6g | `capsec/README.md` | Update facade README with new macros |
| 6h | `CONTRIBUTING.md` | Add section on the context pattern |

---

## Migration & Compatibility

All changes are **additive**. No existing API is removed or changed:

| Existing API | Status |
|---|---|
| `root.grant::<P>()` | Unchanged — still works |
| `Has<P>` trait bounds on functions | Unchanged — still works |
| `Cap<P>`, `SendCap<P>` | Unchanged |
| `capsec::fs::*`, `capsec::net::*`, etc. | Unchanged — accept `&impl Has<P>` which context structs satisfy |
| `Attenuated`, `DirScope`, `HostScope` | Unchanged |
| `#[capsec::requires]`, `#[capsec::deny]` | **Changed** — `#[requires]` now emits compile-time assertions (see below) |

The breaking changes are:

1. **Removal of `Has<P>` sealing.** Code that relied on the compile-time guarantee that `Has<P>` can only be implemented within capsec-core will find that guarantee removed. This is a security-model documentation change, not an API change. The `Cap::new()` boundary is unchanged.

2. **`#[requires]` now validates.** Functions annotated with `#[requires(fs::read)]` will now fail to compile if no parameter implements `Has<FsRead>`. Previously this was documentation-only. Any function where the `#[requires]` annotation didn't match the actual parameters will break. This is intentional — the annotation was lying.

---

## Layer 4: `#[capsec::requires]` Becomes Assertive

### The missing link

Currently `#[capsec::requires(fs::read)]` emits only a `#[doc]` attribute. It documents intent but validates nothing — a function annotated with `#[requires(fs::read)]` can have zero capability parameters and the code compiles fine. This makes `#[requires]` a decorative comment.

With `#[capsec::context]`, the situation becomes actively misleading. A function accepting `ctx: &AppCtx` can be annotated with `#[requires(fs::read)]` even if `AppCtx` doesn't implement `Has<FsRead>`. Nothing catches the mismatch.

### The fix

`#[requires]` should emit a compile-time trait-bound assertion for each declared permission. The behavior depends on the function signature:

**Case 1: `impl Has<P>` bounds present.** The compiler already enforces the trait bound. The macro emits only the `#[doc]` attribute — no additional assertion needed. This is the existing capsec-std pattern and requires no `on` keyword.

```rust
// impl bounds — compiler already enforces, no assertion needed
#[capsec::requires(fs::read)]
fn load(path: &str, cap: &impl Has<FsRead>) -> Result<String> { ... }
```

**Case 2: Concrete context type — user specifies `on = param_name`.** Proc macros operate on the AST via `syn`, before type resolution. The macro cannot determine which parameter implements `Has<P>` — it sees token trees, not resolved types. Attempting to infer the "right" parameter by heuristic (e.g., "first non-primitive type") is brittle and produces confusing errors when wrong.

Instead, the user explicitly names the capability parameter using `on`:

```rust
#[capsec::requires(fs::read, net::connect, on = ctx)]
fn sync_data(config: &Config, ctx: &AppCtx) -> Result<()> {
    // ...
}
```

The macro parses `on = ctx`, finds the parameter named `ctx` in the function signature, extracts its type (`AppCtx`), and emits a `const` assertion block:

```rust
#[doc = "capsec::requires(FsRead, NetConnect)"]
fn sync_data(config: &Config, ctx: &AppCtx) -> Result<()> {
    const _: () = {
        fn _assert_has_fs_read<T: capsec::Has<capsec::FsRead>>() {}
        fn _assert_has_net_connect<T: capsec::Has<capsec::NetConnect>>() {}
        fn _check() {
            _assert_has_fs_read::<AppCtx>();
            _assert_has_net_connect::<AppCtx>();
        }
    };

    // ... original body
}
```

If `AppCtx` doesn't implement `Has<FsRead>`, the compile fails with a clear trait-bound error — the same kind of error capsec already produces for wrong-cap-type mistakes.

**Case 3: No `impl` bounds and no `on` keyword.** The macro emits a `compile_error!`:

```
error: #[capsec::requires] on a function with concrete parameter types requires
       `on = <param>` to identify the capability parameter.
       Example: #[capsec::requires(fs::read, on = ctx)]
```

This is zero heuristics, zero ambiguity. The `on` keyword is self-documenting and matches the existing capsec convention where the capability parameter is explicitly named in every function signature.

### What this completes

The three macro layers now form a closed system:

| Macro | Role |
|-------|------|
| `#[capsec::context]` | **Generates** `Has<P>` impls on a context struct |
| `#[capsec::requires]` | **Validates** that a function's parameters satisfy the declared permissions |
| `#[capsec::deny]` | **Flags** (via audit tool) functions that should have zero I/O |

The context macro generates the impls. The requires macro validates they exist. Without the requires upgrade, there's a gap between declaration and enforcement that the context pattern makes wider.

---

## Decisions (Resolved)

1. **Default `send` or `local`:** Default to `Cap<P>` (`!Send`). Matches capsec's explicit opt-in philosophy. The async world is the majority case for web services but the minority case for CLI tools, data pipelines, and the kind of code most likely to adopt capsec first. Use `#[capsec::context(send)]` for async. Document the async pattern prominently.

2. **`Has<P>` for `SendCap<P>`:** Yes. Add `impl<P: Permission> Has<P> for SendCap<P>`. Without it, the send context macro generates `.as_cap()` calls inside `cap_ref()` — unnecessary indirection. Direct `Has<P>` on `SendCap<P>` is cleaner.

3. **Field visibility:** Private fields + generated accessor methods. Public fields would let users extract a `Cap<P>` and pass it around independently of the context, which isn't wrong but defeats the "single context reference" ergonomic goal. Users who need a raw cap can call `ctx.cap_ref()` via the `Has<P>` impl.

4. **Context inheritance / composition:** Not in v1. Flat structs with permission fields only. Composition is a "nice problem to have" after people are actually using the context pattern. Can be added later without breaking changes.

5. **Macro name:** `#[capsec::context]`. It's what the pattern is called in the DI literature. `cap_bundle` sounds like a marketing term. `grants` is ambiguous with `CapRoot::grant()`.
