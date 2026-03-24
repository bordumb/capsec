# capsec-deep

MIR-based deep analysis driver for capsec. Uses `rustc`'s Mid-level IR to detect ambient authority usage that syntactic analysis misses — macro-expanded FFI calls, trait dispatch, and generic instantiation.

## Requirements

- Nightly Rust toolchain (pinned in `rust-toolchain.toml`)
- `rustc-dev` and `llvm-tools` components

## Install

```bash
cd crates/capsec-deep
cargo install --path .
```

This installs the `capsec-driver` binary, which `cargo capsec audit --deep` invokes automatically.

## How it works

`capsec-driver` is a custom Rust compiler driver. When invoked via `RUSTC_WRAPPER`, it intercepts every crate compilation, runs the normal compiler pipeline through type checking, then walks the MIR of every function looking for:

- **Authority calls** — `std::fs::*`, `std::net::*`, `std::env::*`, `std::process::*` resolved through the full type system (including macro expansion)
- **FFI calls** — any call to a `DefKind::ForeignFn` item (catches `-sys` crate wrappers like `libgit2-sys`, `sqlite3-sys`)

Findings are written as JSONL to a temp file, which the main `cargo-capsec` CLI reads, merges with syntactic findings, and feeds into the cross-crate export map system for transitive propagation.

## Architecture

```mermaid
flowchart TD
    A["cargo capsec audit --deep"] --> B["cargo check\n(RUSTC_WRAPPER=capsec-driver)"]
    B --> C["capsec-driver replaces rustc\nfor each crate"]
    C --> D["after_analysis callback"]
    D --> E["Walk MIR BasicBlocks\nTerminatorKind::Call"]
    E --> F["Extract callee DefId\ntcx.def_path_str()"]
    F --> G{Classify call}
    G -->|"std::fs, std::net,\nstd::env, std::process"| H["Authority finding\n(FS/NET/ENV/PROC)"]
    G -->|"tcx.is_foreign_item()"| I["FFI finding"]
    G -->|"No match"| J["Skip"]
    H --> K["Write JSONL to\n$CAPSEC_DEEP_OUTPUT"]
    I --> K
    K --> L["cargo-capsec reads JSONL\nbuilds export maps"]
    L --> M["Phase 2: workspace scan\nwith MIR export maps injected"]
    M --> N["Unified cross-crate\ntransitive findings"]
```

## Standalone testing

```bash
# Test on a single file
CAPSEC_DEEP_DEBUG=1 cargo run -- --edition 2024 tests/fixtures/simple_fs.rs

# Test FFI detection through macros
CAPSEC_DEEP_DEBUG=1 cargo run -- --edition 2024 tests/fixtures/macro_ffi.rs
```

## Excluded from workspace

This crate requires nightly and is listed in the workspace `exclude` list. It builds independently and does not affect `cargo test --workspace` or `cargo check --workspace` on stable.
