# capsec

Capability-based security tooling for Rust.

## What's in here

| Crate | What it does |
|-------|-------------|
| [`cargo-capsec`](crates/cargo-capsec/) | Static audit tool. Scans Rust source for ambient authority (filesystem, network, env, process) and reports what your code — and your dependencies — can do to the outside world. Zero config, zero code changes. |

## Quick start

```bash
# Install from source
cargo install --path crates/cargo-capsec

# Audit your workspace
cargo capsec audit

# JSON output for CI
cargo capsec audit --format json

# Fail CI on high-risk findings
cargo capsec audit --fail-on high

# SARIF for GitHub Code Scanning
cargo capsec audit --format sarif > capsec.sarif
```

## Why

Rust guarantees memory safety. It does not guarantee your CSV parser isn't opening a TCP socket to phone home telemetry. `cargo audit` checks CVEs. `cargo vet` checks trust. Nothing tells you what the code actually *does*.

`cargo capsec audit` answers that question.

## Roadmap

- [x] `cargo-capsec` — static capability audit (shipped)
- [ ] `capsec-core` — compile-time capability tokens (`Cap<P>`, `Has<P>` trait bounds)
- [ ] `capsec-macro` — `#[requires(fs::read)]` and `#[deny(all)]` proc macros
- [ ] `capsec-std` — capability-gated wrappers for `std::fs`, `std::net`, `std::env`, `std::process`

The audit tool finds the problems. The type system crates let you enforce the fix.

## License

MIT OR Apache-2.0
