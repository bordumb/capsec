# cargo-capsec

Static capability audit for Rust — find out what your code can do to the outside world.

`cargo-capsec` scans Rust source code and reports every function that exercises ambient authority: filesystem access, network connections, environment variable reads, process spawning, and FFI calls. No annotations or code changes required.

## Installation

```bash
cargo install cargo-capsec
```

## Commands

### `cargo capsec init` — Bootstrap for existing codebases

```bash
cargo capsec init                          # generate .capsec.toml + baseline
cargo capsec init --ci github              # + GitHub Actions workflow
cargo capsec init --ci gitlab              # + GitLab CI config
cargo capsec init --interactive            # guided setup
cargo capsec init --report                 # show migration priority ranking
```

Runs a full audit, generates a `.capsec.toml` with allow rules for all existing findings, saves a baseline, and optionally sets up CI. Adopt in 30 seconds — then catch regressions.

### `cargo capsec audit` — Scan for ambient authority

```bash
# Basic scan (workspace crates only)
cargo capsec audit

# Cross-crate propagation (workspace + dependencies)
cargo capsec audit --include-deps

# Full dependency tree analysis
cargo capsec audit --include-deps --dep-depth 0

# MIR-based deep analysis (requires nightly + capsec-driver)
cargo capsec audit --deep --include-deps

# Supply-chain view (only dependency findings)
cargo capsec audit --deps-only

# Output formats
cargo capsec audit --format text           # default, color-coded terminal output
cargo capsec audit --format json           # structured JSON for scripts
cargo capsec audit --format sarif          # SARIF for GitHub Code Scanning

# Filtering
cargo capsec audit --min-risk high         # only high + critical
cargo capsec audit --only my-core,my-sdk   # specific crates
cargo capsec audit --skip my-cli,xtask     # exclude crates

# CI integration
cargo capsec audit --fail-on high --quiet  # exit 1 on high-risk, no output

# Baselines
cargo capsec audit --baseline              # save current findings
cargo capsec audit --diff                  # show changes since baseline
cargo capsec audit --diff --fail-on high   # fail only on NEW high-risk findings
```

#### Output example

```
my-app v0.1.0
─────────────
  FS    src/config.rs:8:5     fs::read_to_string     load_config()
  NET   src/api.rs:15:9       reqwest::get            fetch_data()
        ↳ Cross-crate: reqwest::get() → TcpStream::connect [NET]
  FFI   src/db.rs:31:9        rusqlite::execute       query()
        ↳ Cross-crate: rusqlite::execute() → sqlite3_exec [FFI]
  PROC  src/deploy.rs:42:17   Command::new           run_migration()
  VIA   src/main.rs:5:9       load_config()          main()

Summary
───────
  Crates with findings: 1
  Total findings:       5
  Categories:           FS: 1  NET: 1  ENV: 0  PROC: 1  FFI: 1
  2 critical-risk findings
```

#### Analysis modes

| Mode | Flag | What it scans | Speed |
|------|------|---------------|-------|
| Workspace only | *(default)* | Your code | Fast |
| Cross-crate | `--include-deps` | Your code + dependency source (syntactic) | Medium |
| Deep | `--deep --include-deps` | Everything via MIR (sees through macros, FFI wrappers) | Slow (nightly) |

### `cargo capsec diff` — Compare crate versions

```bash
cargo capsec diff serde_json@1.0.130 serde_json@1.0.133
cargo capsec diff tokio@1.37.0 tokio@1.38.0 --format json
cargo capsec diff my-dep@0.4.0 my-dep@0.5.0 --fail-on-new
```

Shows what ambient authority was added or removed between two versions of a crate. Useful for reviewing Dependabot PRs or evaluating upgrades.

```
serde_json 1.0.130 → 1.0.133
─────────────────────────────
+ NET  src/de.rs:142:9  TcpStream::connect  fetch_schema()
- FS   src/io.rs:88:5   fs::read            old_loader()

Summary: 1 added, 1 removed, 1 unchanged
```

### `cargo capsec compare` — Compare different crates

```bash
cargo capsec compare ureq@2.12.1 reqwest@0.12.12
```

Side-by-side capability profiles for making informed dependency choices.

```
ureq v2.12.1                   reqwest v0.12.12
──────────                     ────────────────
FS:   0                        FS:   3
NET:  4                        NET:  18
ENV:  1                        ENV:  4
PROC: 0                        PROC: 0
FFI:  0                        FFI:  12
Total: 5                       Total: 37
```

### `cargo capsec check-deny` — Verify `#[capsec::deny]` annotations

```bash
cargo capsec check-deny
```

Checks that functions annotated with `#[capsec::deny(fs)]` or `#[capsec::deny(all)]` don't contain ambient authority calls. Any violation is promoted to critical risk.

### `cargo capsec badge` — Generate shields.io badge

```bash
cargo capsec badge              # markdown badge
cargo capsec badge --json       # shields.io endpoint JSON
```

## Configuration (`.capsec.toml`)

```toml
# Exclude directories from scanning
[analysis]
exclude = ["tests/**", "benches/**", "examples/**"]

# Crate-level deny — all ambient authority is a violation
[deny]
categories = ["all"]

# Custom authority patterns for project-specific I/O
[[authority]]
path = ["my_crate", "secrets", "fetch"]
category = "net"
risk = "critical"
description = "Fetches secrets from vault"

# Suppress known-good findings
[[allow]]
crate = "tracing"
reason = "Logging framework, reviewed"

[[allow]]
crate = "my-app"
function = "load_config"
reason = "Known FS access, reviewed"

# Classify crates as pure (no I/O) or resource (has I/O)
[[classify]]
crate = "my-parser"
classification = "pure"
```

## Deep analysis (`--deep`)

The `--deep` flag uses a custom Rust compiler driver (`capsec-driver`) that walks MIR after macro expansion and type resolution. This catches:

- FFI calls hidden behind macros (e.g., `git2`'s `try_call!()` → `libgit2_sys`)
- Authority exercised through trait dispatch
- Generic instantiations that resolve to I/O functions

Requires nightly:

```bash
cd crates/capsec-deep && cargo install --path .
cargo capsec audit --deep --include-deps
```

See [`crates/capsec-deep/README.md`](../capsec-deep/README.md) for architecture details.

## Cross-crate propagation

With `--include-deps`, capsec builds an **export map** for each dependency: which functions exercise ambient authority. When your workspace code calls those functions, the finding propagates transitively:

```
your_code::handler() → reqwest::get() → TcpStream::connect [NET]
```

This works across:
- Registry dependencies (crates.io)
- Workspace member dependencies (topological ordering)
- FFI boundaries (extern function declarations)
- Multiple hops (`A → B → C → std::fs::read`)

## Limitations

- **Dynamic dispatch** (`dyn Trait`) — cannot statically resolve which implementation runs
- **C/C++ internals** — sees FFI call boundaries but not what foreign code does inside
- **Inline assembly** — `asm!()` blocks are opaque
- **Runtime-loaded code** — `dlopen`/`libloading` is invisible to static analysis

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Text | `--format text` | Terminal, human review |
| JSON | `--format json` | Scripts, dashboards, CI pipelines |
| SARIF | `--format sarif` | GitHub Code Scanning, VS Code SARIF Viewer |

## License

Apache-2.0
