# capsec

[![CI](https://github.com/bordumb/capsec/actions/workflows/ci.yml/badge.svg)](https://github.com/bordumb/capsec/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/capsec.svg)](https://crates.io/crates/capsec)
[![docs.rs](https://docs.rs/capsec/badge.svg)](https://docs.rs/capsec)

Rust guarantees memory safety — capsec guarantees behavioral safety.

### Quick Start

```bash
# See what your code and dependencies actually do (zero config, zero code changes):
cargo install cargo-capsec
cargo capsec audit
```

---

`cargo audit` checks CVEs. `cargo vet` checks trust. Neither tells you what the code actually *does*. Nothing stops your CSV parser from opening a TCP socket to phone home telemetry.

capsec fills that gap with three layers:

1. **`cargo capsec audit`** — a static audit tool that scans your code and reports every I/O call. Drop it into CI and know exactly what your dependencies do.
2. **Compile-time type system** — functions declare their I/O permissions via `Has<P>` trait bounds, and the compiler rejects anything that exceeds them. Zero runtime cost.
3. **Runtime capability control** — `RuntimeCap` (revocable) and `TimedCap` (expiring) wrap static capabilities with runtime validity checks for dynamic scenarios like server init or migration windows.

The audit tool finds the problems. The type system prevents them at compile time. Runtime caps handle the cases where permissions need to change dynamically.

---

## cargo-capsec — Static Capability Audit

Scans Rust source for ambient authority (filesystem, network, env, process) and reports what your code — and your dependencies — can do to the outside world. Zero config, zero code changes.

### Install

```bash
cargo install cargo-capsec

# Or from source:
cargo install --path crates/cargo-capsec
```

### Run

```bash
cargo capsec audit
```

```
my-app v0.1.0
─────────────
  FS    src/config.rs:8:5     fs::read_to_string     load_config()
  NET   src/api.rs:15:9       TcpStream::connect     fetch_data()
  PROC  src/deploy.rs:42:17   Command::new           run_migration()

Summary
───────
  Crates with findings: 1
  Total findings:       3
  Categories:           FS: 1  NET: 1  ENV: 0  PROC: 1
  1 critical-risk findings
```

### Add to CI

```yaml
# .github/workflows/capsec.yml
name: Capability Audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-capsec
      - run: cargo capsec audit --fail-on high --quiet
```

New high-risk I/O in a PR? CI fails. No new I/O? CI passes. Teams can adopt incrementally with `--baseline` and `--diff` to only flag *new* findings.

To see it in action, you can reference these:
* [CI/CD](https://github.com/bordumb/capsec/blob/main/.github/workflows/ci.yml#L57)
* [Pre-Commit Hook](https://github.com/bordumb/capsec/blob/main/.pre-commit-config.yaml#L32)

---

## capsec — Compile-Time Capability Enforcement

The audit tool tells you what your code does. The type system controls what it's *allowed* to do.

### Before capsec

Any function can do anything. The signature lies — it looks pure, but it reads files and opens sockets:

```rust
// This function signature says nothing about I/O.
// But inside, it reads from disk and phones home over the network.
pub fn process_csv(input: &[u8]) -> Vec<Vec<String>> {
    let config = std::fs::read_to_string("/etc/app/config.toml")
        .unwrap_or_default();

    if let Ok(mut stream) = std::net::TcpStream::connect("telemetry.example.com:8080") {
        stream.write_all(input).ok();
    }

    parse(input, &config)
}
```

The Rust compiler is perfectly happy with this. Clippy won't flag it. Nothing prevents it.

### After capsec

Functions declare their I/O requirements in the type signature. The compiler enforces them:

```rust
use capsec::prelude::*;

// Define a context with exactly the permissions your app needs.
// The macro generates Cap fields, constructor, and Has<P> impls.
#[capsec::context]
struct AppCtx {
    fs: FsRead,
    net: NetConnect,
}

// Leaf functions take &impl Has<P> — works with raw caps AND context structs.
pub fn load_config(path: &str, cap: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}

// Intermediate functions take a single context reference — not N separate caps.
pub fn app_logic(ctx: &AppCtx) -> Result<String, CapSecError> {
    load_config("/etc/app/config.toml", ctx)  // ctx satisfies Has<FsRead>
}

// #[capsec::main] injects the capability root automatically.
#[capsec::main]
fn main(root: CapRoot) {
    let ctx = AppCtx::new(&root);
    let config = app_logic(&ctx).unwrap();
}
```

Every capability traces back to `CapRoot`. If a function uses capsec wrappers (like `capsec::fs::read_to_string`) without being given a `Cap<FsRead>`, the code doesn't compile. The audit tool catches code that bypasses capsec wrappers entirely — calling `std::fs` directly, using FFI, or hiding I/O behind re-exports.

### What the compiler actually says

**Wrong capability type** — passing a `Cap<NetConnect>` where `Cap<FsRead>` is required:

```rust
let net_cap = root.grant::<NetConnect>();
let _ = capsec::fs::read_to_string("/etc/passwd", &net_cap);
```

```
error[E0277]: the trait bound `Cap<NetConnect>: Has<FsRead>` is not satisfied
 --> src/main.rs:4:55
  |
4 |     let _ = capsec::fs::read_to_string("/etc/passwd", &net_cap);
  |             --------------------------                ^^^^^^^^ the trait `Has<FsRead>` is not implemented for `Cap<NetConnect>`
  |             |
  |             required by a bound introduced by this call
```

**Missing capability** — calling a capsec function without providing a token at all:

```rust
let _ = capsec::fs::read_to_string("/etc/passwd");
```

```
error[E0061]: this function takes 2 arguments but 1 argument was supplied
 --> src/main.rs:2:13
  |
2 |     let _ = capsec::fs::read_to_string("/etc/passwd");
  |             ^^^^^^^^^^^^^^^^^^^^^^^^^^--------------- argument #2 of type `&_` is missing
  |
help: provide the argument
  |
2 |     let _ = capsec::fs::read_to_string("/etc/passwd", /* cap */);
  |                                                     +++++++++++
```

**Cross-category violation** — `FsAll` subsumes `FsRead` and `FsWrite`, but not `NetConnect`:

```rust
let fs_all = root.grant::<FsAll>();
needs_net(&fs_all);  // fn needs_net(_: &impl Has<NetConnect>) {}
```

```
error[E0277]: the trait bound `Cap<FsAll>: Has<NetConnect>` is not satisfied
 --> src/main.rs:3:15
  |
3 |     needs_net(&fs_all);
  |     --------- ^^^^^^^ the trait `Has<NetConnect>` is not implemented for `Cap<FsAll>`
  |     |
  |     required by a bound introduced by this call
```

These are real `rustc` errors — no custom error framework, no runtime panics. The Rust compiler does the enforcement.

### What this gives you

| | Before | After |
|--|--------|-------|
| Can any function read files? | Yes | Only if it has `Cap<FsRead>` |
| Can any function open sockets? | Yes | Only if it has `Cap<NetConnect>` |
| Can you audit who has what access? | Grep and pray | Grep for `Has<FsRead>` |
| Runtime cost? | N/A | Zero — all types are erased at compile time |

### Security model

capsec protects against **cooperative safe Rust** — code that uses capsec wrappers cannot exceed its declared permissions, and the compiler enforces this at zero runtime cost.

The `Has<P>` trait is open for implementation — custom context structs can implement it to delegate capability access. Security is maintained because `Cap::new()` is `pub(crate)`: no external code can forge a `Cap<P>` in safe Rust. The `Permission` trait remains sealed — external crates cannot invent new permission types.

What capsec **does not** protect against:

- **`unsafe` code** that forges capability tokens via `transmute`, `MaybeUninit`, or pointer tricks. The type system is sound only within safe Rust. (The adversarial test suite in `capsec-tests/tests/type_system.rs` documents these attacks and confirms they require `unsafe`.)
- **Direct `std` calls** that bypass capsec wrappers. A function can always call `std::fs::read()` without a capability token — the compiler won't stop it. This is where `cargo capsec audit` comes in: it detects these calls statically.
- **FFI and inline assembly** that interact with the OS directly. The audit tool flags `extern` blocks but cannot reason about what foreign code does.

The three layers are complementary: the **type system** enforces boundaries within code that opts in, the **audit tool** surfaces code that hasn't opted in yet, and **runtime caps** handle dynamic permission lifecycles. No single layer is complete alone — together they provide defense in depth.

capsec ships with a 74-test adversarial security suite that documents every known evasion vector and attack surface — unsafe forgery, `std` bypass, FFI escape hatches, context delegation attacks, and more. Most security tools don't catalog their own weaknesses. capsec does, so you know exactly what's covered and what isn't. See [`capsec-tests/tests/type_system.rs`](crates/capsec-tests/tests/type_system.rs) and [`capsec-tests/tests/audit_evasion.rs`](crates/capsec-tests/tests/audit_evasion.rs).

---

## Runtime Capability Control

Static `Cap<P>` tokens are permanent — once granted, they're valid forever. For scenarios where permissions should be temporary or revocable, capsec provides runtime capability wrappers.

### Revocable capabilities

Grant network access for server startup, then revoke it so no new connections can be made at runtime:

```rust
use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    // Wrap a capability with a revocation handle
    let (runtime_cap, revoker) = RuntimeCap::new(root.net_connect());

    // During startup: try_cap() returns a real Cap<NetConnect>
    let cap = runtime_cap.try_cap()?;
    init_connection_pool(&cap);

    // After init: revoke — no new connections possible
    revoker.revoke();

    // Now try_cap() returns Err(CapSecError::Revoked)
    assert!(runtime_cap.try_cap().is_err());
    Ok(())
}
```

Runtime caps compose with the context pattern — wrap individual capabilities for revocation while keeping your context ergonomics:

```rust
#[capsec::context]
struct ServerCtx {
    fs: FsRead,
    net: NetConnect,
}

// Grant static fs access + revocable net access
let ctx = ServerCtx::new(&root);              // static caps for the context
let (net_rt, revoker) = RuntimeCap::new(root.net_connect());  // revocable net cap

// Use ctx for Has<FsRead> bounds, net_rt.try_cap()? for revocable net access
```

### Time-bounded capabilities

Grant temporary write access for a migration window:

```rust
use capsec::prelude::*;
use std::time::Duration;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let timed_cap = TimedCap::new(root.fs_write(), Duration::from_secs(30));

    // Within the window: try_cap() succeeds
    let cap = timed_cap.try_cap()?;
    capsec::fs::write("/tmp/migration.txt", "data", &cap)?;

    // After TTL: try_cap() returns Err(CapSecError::Expired)
    // timed_cap.remaining() returns Duration::ZERO
    Ok(())
}
```

### Audited capabilities

`LoggedCap<P>` records every `try_cap()` invocation in an append-only audit log — implementing Saltzer & Schroeder's *compromise recording* principle ([The Protection of Information in Computer Systems](https://www.cs.virginia.edu/~evans/cs551/saltzer/), 1975, Design Principle #8):

```rust
use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let logged_cap = LoggedCap::new(root.fs_read());

    // Every exercise is recorded
    let cap = logged_cap.try_cap()?;
    capsec::fs::read("/dev/null", &cap)?;

    // Inspect the audit trail
    for entry in logged_cap.entries() {
        println!("{}: {} (granted={})",
            entry.permission, entry.timestamp.elapsed().as_micros(), entry.granted);
    }
    Ok(())
}
```

### Dual-key authorization

`DualKeyCap<P>` requires two independent approvals before `try_cap()` succeeds — implementing Saltzer & Schroeder's *separation of privilege* principle (Design Principle #5: "a mechanism that requires two keys to unlock it is more robust than one that allows access to the presenter of only a single key"):

```rust
use capsec::prelude::*;

#[capsec::main]
fn main(root: CapRoot) -> Result<(), Box<dyn std::error::Error>> {
    let (dual_cap, approver_a, approver_b) = DualKeyCap::new(root.fs_write());

    // Distribute handles to separate subsystems
    // Neither alone can exercise the capability
    approver_a.approve();  // manager approves
    approver_b.approve();  // security officer approves

    // Only now does try_cap() succeed
    let cap = dual_cap.try_cap()?;
    capsec::fs::write("/tmp/authorized.txt", "data", &cap)?;
    Ok(())
}
```

### Key properties

- `RuntimeCap`, `TimedCap`, `LoggedCap`, and `DualKeyCap` do **not** implement `Has<P>` — fallibility is explicit via `try_cap()` at every call site
- All are `!Send` by default — use `make_send()` to opt into cross-thread transfer
- Cloning a `RuntimeCap` shares the revocation flag — revoking one revokes all clones
- Cloning a `LoggedCap` shares the audit log — entries from any clone appear in the same log
- `Revoker` is `Send + Sync + Clone` — revoke from any thread
- `ApproverA` / `ApproverB` are `Send + Sync` but **not** `Clone` — move-only to enforce separation of privilege

### How capsec compares

| Tool | Approach | Layer |
|------|----------|-------|
| **capsec** | Compile-time types + runtime caps (revocable, timed, audited, dual-key) + static audit | Source-level, cooperative |
| **[cap-std](https://github.com/bytecodealliance/cap-std)** | Runtime capability handles (ambient authority removal) | OS-level, WASI-oriented |
| **[cargo-scan](https://github.com/AlfredoSystems/cargo-scan)** | Static analysis of dangerous API usage | Source-level, research prototype |
| **[cargo-cgsec](https://github.com/nicholasgasior/cargo-cgsec)** | Call graph capability analysis (Capslock port) | Source-level, audit only |

`cap-std` operates at a different layer — it replaces OS-level file descriptors with capability handles at runtime, targeting WASI sandboxing. capsec works at the type level with zero runtime cost and no OS support required. The two are complementary: you could use `cap-std` handles inside capsec-gated functions.

`cargo-scan` (from UC San Diego) performs similar static analysis to `cargo capsec audit`. capsec adds the type-system enforcement layer and ships as a single workspace with both tools integrated.

`cargo-cgsec` is a Rust port of Google's Capslock, funded by the Rust Foundation. It performs call graph analysis to identify capability usage — audit only, no enforcement or runtime layer. capsec covers the same audit surface via `cargo capsec audit` and adds compile-time type enforcement and runtime capability control.

---

## Academic foundations

capsec's design draws from three foundational papers in capability-based security:

- **Dennis & Van Horn (1966)** — [Programming Semantics for Multiprogrammed Computations](https://dl.acm.org/doi/10.1145/365230.365252). Introduced capability lists (C-lists), unforgeable capability tokens, and spheres of protection. capsec's `Cap<P>` is a direct descendant of their capability concept; `Cap::new()` being `pub(crate)` enforces unforgeability in software the way their hardware enforced it in the supervisor.

- **Saltzer & Schroeder (1975)** — [The Protection of Information in Computer Systems](https://www.cs.virginia.edu/~evans/cs551/saltzer/). Defined the eight design principles for protection mechanisms. capsec implements six: economy of mechanism (zero-sized types), fail-safe defaults (no cap = no access), least privilege (the core mission), open design (open source + adversarial test suite), separation of privilege (`DualKeyCap`), and compromise recording (`LoggedCap`). The two partially met — complete mediation and least common mechanism — are inherent limitations of a library-level approach.

- **Melicher et al. (2017)** — [A Capability-Based Module System for Authority Control](https://www.cs.cmu.edu/~aldrich/papers/ecoop17modules.pdf) (ECOOP 2017). Formalized non-transitive authority in the Wyvern language, proving that a module's authority can be determined by inspecting only its interface. capsec achieves the same property: `Has<P>` bounds make a function's authority visible in its signature, and `Attenuated<P, S>` / runtime cap types that don't implement `Has<P>` enforce non-transitivity.

---

## License

Apache-2.0
