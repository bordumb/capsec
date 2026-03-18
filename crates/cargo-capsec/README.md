# cargo-capsec

Static capability audit for Rust — find out what your code can do to the outside world.

## What it does

`cargo-capsec` scans Rust source code and reports every function that exercises ambient authority: filesystem access, network connections, environment variable reads, process spawning. Point it at a workspace and it tells you what's happening — no annotations or code changes required.

## Installation

From crates.io:

```bash
cargo install cargo-capsec
```

From source:

```bash
cargo install --path crates/cargo-capsec
```

## Quick start

```bash
# Audit your workspace
cargo capsec audit

# JSON output for CI
cargo capsec audit --format json

# Only show high-risk and critical findings
cargo capsec audit --min-risk high

# Fail CI if any critical findings
cargo capsec audit --fail-on critical

# Save baseline, then diff on next run
cargo capsec audit --baseline
cargo capsec audit --diff

# Skip known-good crates
cargo capsec audit --skip my-cli,xtask

# Only scan specific crates
cargo capsec audit --only my-core,my-sdk

# SARIF output for GitHub Code Scanning
cargo capsec audit --format sarif > capsec.sarif

# Suppress output, exit code only (for CI)
cargo capsec audit --quiet --fail-on high
```

## Output example

```
my-app v0.1.0
─────────────
  FS    src/main.rs:8:5      fs::read_to_string     main()
  FS    src/main.rs:22:9     fs::write              save_output()
  NET   src/api.rs:15:9      TcpStream::connect     fetch_data()
  ENV   src/config.rs:3:5    env::var               load_config()

Summary
───────
  Crates with findings: 1
  Total findings:       4
  Categories:           FS: 2  NET: 1  ENV: 1  PROC: 0
```

## Configuration

Create `.capsec.toml` in your workspace root:

```toml
[analysis]
exclude = ["tests/**", "benches/**"]

# Custom authority patterns
[[authority]]
path = ["my_crate", "secrets", "fetch"]
category = "net"
risk = "critical"
description = "Fetches secrets from vault"

# Suppress known-good findings
[[allow]]
crate = "tracing"
reason = "Logging framework, reviewed"
```

## `#[capsec::deny]` enforcement

The audit tool honors `#[capsec::deny(...)]` annotations. Any ambient authority call inside a `#[deny]`-annotated function is promoted to **critical** risk and tagged as a deny violation:

```
my-app v0.1.0
─────────────
  DENY  src/parser.rs:42:9  std::fs::read  in #[deny(all)] function parse_config()

Summary
───────
  1 deny violation (ambient authority in #[deny] function)
  1 critical-risk findings
```

Use `--fail-on critical` in CI to catch deny violations alongside other critical findings.

## Limitations

- **Use aliases**: `use std::fs::read as r; r(...)` — the import is flagged, but the bare aliased call may not be detected in all cases.
- **Method call matching is contextual**: `.output()`, `.spawn()`, `.status()` only flag when `Command::new` is in the same function. `.send_to()` requires `UdpSocket::bind`. Other method names not matched.
- **Proc macro generated code** is not visible to the analysis. This is inherent to syntax-level tooling — `cargo expand` support is on the roadmap.
- **No data flow analysis**: Dead code will be flagged.
- **FFI**: `extern` blocks are detected but individual libc calls aren't categorized.

## License

Apache-2.0
