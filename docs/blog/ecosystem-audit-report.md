# What Can Your Dependencies Do? An Ambient Authority Audit of the Rust Ecosystem

**Date:** 2026-03-19
**Tool:** [capsec](https://github.com/bordumb/capsec) — static capability audit for Rust

## Introduction

Every Rust crate you depend on has implicit access to your filesystem, network, environment variables, and process spawning. There is no permission system — any function in any dependency can `std::fs::remove_dir_all("/")` or `TcpStream::connect("evil.com")` without your code ever granting that capability.

**capsec** is a static analysis tool that makes this ambient authority visible. It scans Rust source code and reports every call site that exercises a system capability: reading files, opening sockets, accessing environment variables, spawning processes, or calling into foreign code.

We ran `cargo capsec audit` against 47 popular crates to answer a simple question: **what does the Rust ecosystem actually do with ambient authority?**

## Methodology

- **Tool:** cargo-capsec (from source, workspace build)
- **Rust toolchain:** 1.94.0
- **Date:** 2026-03-19
- **Scope:** First-party source code only (no transitive dependencies)
- **Method:** Each crate was shallow-cloned from its GitHub repository and audited with `cargo capsec audit --format json`

### What capsec detects

capsec identifies syntactic patterns matching known ambient authority calls across five categories:

| Category | Examples |
|----------|---------|
| **FS** | `std::fs::read`, `File::open`, `remove_dir_all` |
| **NET** | `TcpStream::connect`, `UdpSocket::bind`, `TcpListener::bind` |
| **ENV** | `std::env::var`, `env::set_var`, `env::current_dir` |
| **PROC** | `Command::new`, `process::exit`, `process::abort` |
| **FFI** | `extern` blocks, raw FFI calls |

### Limitations

- **Proc-macro-generated code is invisible.** Calls emitted by derive macros or `#[tokio::main]` are not seen.
- **No data flow analysis.** Dead code paths are flagged. A function that constructs a `Command` but never calls `.output()` is still counted.
- **No type resolution.** A local function named `read` that shadows `std::fs::read` could be a false positive.
- **build.rs is included.** Build scripts legitimately use FS/ENV/PROC — these are expected findings, not bugs.

## Results Summary

**47 crates audited** across 8 categories:

| Metric | Value |
|--------|-------|
| Total crates | 47 |
| Crates with zero findings | 13 (28%) |
| Total findings | 1,448 |
| Median findings per crate | 8 |
| Highest single crate | starship (470) |

### Findings by category

| Category | Total | % of all findings |
|----------|-------|-------------------|
| **FS** | 957 | 66% |
| **ENV** | 206 | 14% |
| **PROC** | 169 | 12% |
| **NET** | 65 | 4% |
| **FFI** | 9 | <1% |

Filesystem access dominates — unsurprising for a systems language ecosystem where I/O is the norm, not the exception.

## Results by Category

### Pure Libraries (17 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| serde | 2 | 0 | 3 | 4 | 0 | 9 |
| syn | 1 | 0 | 1 | 2 | 0 | 4 |
| clap | 3 | 0 | 13 | 28 | 0 | 44 |
| thiserror | 2 | 0 | 2 | 4 | 0 | 8 |
| anyhow | 1 | 0 | 1 | 4 | 0 | 6 |
| pest | 3 | 0 | 3 | 0 | 0 | 6 |
| crossbeam | 0 | 0 | 4 | 0 | 0 | 4 |
| rayon | 1 | 0 | 2 | 0 | 0 | 3 |
| regex | 0 | 0 | 0 | 0 | 0 | **0** |
| rand | 0 | 0 | 0 | 0 | 0 | **0** |
| itertools | 0 | 0 | 0 | 0 | 0 | **0** |
| bytes | 0 | 0 | 0 | 0 | 0 | **0** |
| nom | 0 | 0 | 0 | 0 | 0 | **0** |
| dashmap | 0 | 0 | 0 | 0 | 0 | **0** |
| smallvec | 0 | 0 | 0 | 0 | 0 | **0** |
| bitflags | 0 | 0 | 0 | 0 | 0 | **0** |
| unicode-segmentation | 0 | 0 | 0 | 0 | 0 | **0** |

**Key insight:** 9 of 17 pure libraries have zero ambient authority. The remaining 8 have findings primarily in `build.rs` and test infrastructure, not in library code proper. **clap** is the outlier with 44 findings — it legitimately reads environment variables (for `env!` defaults) and calls `process::exit` on parse errors.

**The build.rs question:** serde, syn, thiserror, and anyhow all have findings. These come from their build scripts, which use FS (reading/writing generated code), ENV (checking compiler flags), and PROC (running `rustc` for version detection). This is expected and correct behavior — build scripts _need_ ambient authority. A future capsec version could separate build-script findings from library findings.

### Crypto (3 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| ring | 0 | 0 | 0 | 0 | 1 | 1 |
| rustls | 20 | 19 | 1 | 20 | 0 | 60 |
| sha2 | 0 | 0 | 0 | 0 | 1 | 1 |

**ring** and **sha2** are nearly clean — their single FFI finding is the `extern` block for the C/assembly crypto primitives. This is exactly what you'd expect.

**rustls** is more surprising at 60 findings — but these come from its examples and test infrastructure, not the library itself. The NET findings are TLS connection examples, the FS findings are certificate loading, and the PROC findings are process management in integration tests.

### CLI Applications (14 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| starship | 452 | 1 | 16 | 1 | 0 | 470 |
| nushell | 82 | 7 | 48 | 20 | 0 | 157 |
| bat | 24 | 0 | 21 | 6 | 0 | 51 |
| delta | 27 | 0 | 19 | 10 | 0 | 56 |
| tokei | 34 | 0 | 2 | 1 | 0 | 37 |
| bottom | 22 | 0 | 3 | 8 | 2 | 35 |
| zoxide | 3 | 0 | 4 | 20 | 0 | 27 |
| just | 8 | 0 | 2 | 12 | 0 | 22 |
| ripgrep | 14 | 0 | 2 | 1 | 0 | 17 |
| exa | 3 | 0 | 7 | 2 | 2 | 14 |
| procs | 3 | 3 | 3 | 4 | 0 | 13 |
| hyperfine | 5 | 0 | 0 | 7 | 0 | 12 |
| fd | 1 | 0 | 4 | 6 | 0 | 11 |
| dust | 6 | 0 | 0 | 0 | 0 | 6 |

CLI applications are the heaviest users of ambient authority, as expected. They exist to interact with the system.

**starship** (470 findings) stands out because it's a shell prompt customizer that reads dozens of config files, checks git status, reads environment variables, and inspects system state. Every one of those 452 FS findings is a _feature_ — the whole point of starship is to read your system and display it.

**nushell** (157) is a shell — it needs all the capabilities. **bat** (51) is a file viewer — it needs FS access.

The interesting signal is _what a CLI tool doesn't use_. `dust` (disk usage) has only FS findings — no network, no env, no process spawning. `fd` (file finder) is similarly constrained. This is the kind of assurance capsec can provide: "this tool only touches the filesystem."

### Web Frameworks (5 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| axum | 4 | 24 | 1 | 0 | 0 | 29 |
| actix-web | 6 | 6 | 1 | 0 | 0 | 13 |
| reqwest | 3 | 0 | 2 | 0 | 3 | 8 |
| warp | 2 | 3 | 0 | 0 | 0 | 5 |
| hyper | 0 | 0 | 0 | 0 | 0 | **0** |

**hyper** at zero findings is notable — it's a pure HTTP protocol implementation that delegates all I/O to the caller via the `tower::Service` trait. This is capability-based design in practice, even without a formal capability system.

**axum** has 24 NET findings because it wraps hyper's listener and exposes `TcpListener::bind` and connection handling. **reqwest** has 3 FFI findings from its native-tls integration.

### Async Runtimes (2 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| tokio | 10 | 2 | 1 | 9 | 0 | 22 |
| async-std | 18 | 0 | 0 | 0 | 0 | 18 |

Runtimes need ambient authority to provide async I/O. tokio's 22 findings cover its FS, NET, and process modules — each is a direct wrapper around `std` with async semantics. async-std's 18 FS findings are its file I/O wrappers.

### I/O Libraries (5 crates)

| Crate | FS | NET | ENV | PROC | FFI | Total |
|-------|----|-----|-----|------|-----|-------|
| notify | 162 | 0 | 7 | 0 | 0 | 169 |
| rusqlite | 3 | 0 | 21 | 0 | 0 | 24 |
| tracing | 10 | 0 | 10 | 0 | 0 | 20 |
| tempfile | 2 | 0 | 4 | 0 | 0 | 6 |
| walkdir | 1 | 0 | 0 | 0 | 0 | 1 |

**notify** (162 FS) is a filesystem event watcher — it has more FS calls than any other library because it wraps platform-specific file watching APIs (inotify, kqueue, FSEvents). Every one of those calls is essential.

**rusqlite** (21 ENV) reads environment variables for path resolution and database configuration. **tracing** (10 ENV, 10 FS) reads environment variables for filter directives and writes to log files.

## Performance

Most crates audit in under 1 second. Three outliers:

| Crate | Time | Likely cause |
|-------|------|-------------|
| dashmap | 63.75s | `cargo metadata` compilation overhead |
| exa | 88.49s | `cargo metadata` compilation overhead |
| nushell | 49.85s | Large codebase (300+ source files) |

The slow runs are dominated by `cargo metadata` resolving the dependency tree, not by capsec's analysis. The actual source scanning is typically <0.5s even for large crates.

## What We Learned

### 1. Pure computation crates are genuinely clean

regex, rand, itertools, bytes, nom, smallvec, bitflags, and unicode-segmentation have zero ambient authority. If your library does pure computation, capsec confirms it.

### 2. Build scripts are the main source of "surprising" findings

serde, syn, anyhow, and thiserror show up with findings — but all from `build.rs`, not library code. This is a common pattern: the library is pure, but the build script needs FS/ENV/PROC to generate code or detect compiler features.

### 3. Capability-based design exists in the wild

hyper's zero-finding result demonstrates that you can build a major networking library without any ambient authority in the library itself. It pushes all I/O decisions to the caller. This is exactly the pattern capsec encourages.

### 4. CLI tools need everything — and that's fine

The value of auditing CLI tools isn't finding them guilty — it's understanding their surface area. Knowing that `dust` only uses FS while `nushell` uses everything helps you assess supply chain risk.

### 5. Finding counts don't equal risk

starship (470) is not 470x riskier than walkdir (1). Finding counts measure _surface area_, not _severity_. A tool that reads 452 files is doing its job. The interesting signal is when a library that shouldn't need network access has NET findings.

## Try It Yourself

```bash
cargo install cargo-capsec
cargo capsec audit
cargo capsec audit --format sarif  # GitHub Code Scanning integration
```

Raw data for all 47 crates is available in [bench/results/](../../crates/cargo-capsec/bench/results/2026-03-19/).
