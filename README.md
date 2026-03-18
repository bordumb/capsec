# capsec

Capability-based security tooling for Rust.

Rust guarantees memory safety. It does not guarantee your CSV parser isn't opening a TCP socket to phone home telemetry. `cargo audit` checks CVEs. `cargo vet` checks trust. Nothing tells you what the code actually *does*.

capsec fills that gap with two tools:

- **`cargo-capsec`** — a static audit tool that scans your code and reports every I/O call. Drop it into CI and know exactly what your dependencies do.
- **`capsec`** — a type system that enforces I/O permissions at compile time. Functions declare what they need, and the compiler rejects anything that exceeds it.

The audit tool finds the problems. The type system enforces the fix.

---

## cargo-capsec — Static Capability Audit

Scans Rust source for ambient authority (filesystem, network, env, process) and reports what your code — and your dependencies — can do to the outside world. Zero config, zero code changes.

### Install

```bash
cargo install cargo-capsec
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
* [CI/CD](https://github.com/bordumb/capsec/blob/main/.github/workflows/ci.yml#L49-L56)
* [Pre-Commit Hook](https://github.com/bordumb/capsec/blob/main/.pre-commit-config.yaml#L35-L40)

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

// This function CANNOT do I/O — it has no capability token.
// Adding std::fs::read() here would require a Cap<FsRead> parameter,
// which the compiler would demand.
pub fn process_csv(input: &[u8]) -> Vec<Vec<String>> {
    parse(input)
}

// This function declares it needs filesystem read access.
// The caller must provide proof via a Cap<FsRead> token.
pub fn load_config(path: &str, cap: &impl Has<FsRead>) -> Result<String, CapSecError> {
    capsec::fs::read_to_string(path, cap)
}

// In main — the single point of authority:
fn main() {
    let root = capsec::root();
    let fs_cap = root.grant::<FsRead>();

    let config = load_config("/etc/app/config.toml", &fs_cap).unwrap();
    let result = process_csv(input); // no cap needed — pure computation
}
```

Every capability traces back to `root.grant()`. If a dependency tries to read files without being given a `Cap<FsRead>`, the code doesn't compile.

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

---

## License

MIT OR Apache-2.0
