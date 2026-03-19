# cargo-capsec wild crate benchmark

Runs `cargo capsec audit` against popular open-source Rust crates to measure signal quality and catch edge cases before release.

## Quick start

```bash
# Install cargo-capsec from source first
cargo install --path crates/cargo-capsec

# Run all crates
python crates/cargo-capsec/bench/audit_wild.py

# Run a subset
python crates/cargo-capsec/bench/audit_wild.py --only serde,ripgrep
```

Results go to `results/<date>/` with a `latest` symlink.

## What it measures

- **Does it crash?** Any panic, hang, or parse error on real-world code is a launch blocker.
- **Signal quality:** Are findings plausible? Pure libraries should have near-zero findings. CLI apps should show FS/PROC. Web frameworks should show NET.
- **Performance:** Wall-clock time per crate. Should complete in seconds, not minutes.

## Target crates

Defined in `crates.toml`. Four categories:

| Category | Expected findings | Examples |
|----------|------------------|----------|
| pure-library | Zero or near-zero | serde, regex, rand |
| cli-app | FS + PROC heavy | ripgrep, bat, fd, just |
| web | NET heavy | axum |
| io-library | Mixed I/O | — |

## Interpreting results

A finding means "this code calls a function that exercises ambient authority." It does NOT mean "this code is doing something wrong." A file search tool reading files is correct behavior — capsec surfaces it so you can make an informed decision.

**Good signal:** pure libraries have 0 findings, CLI apps have FS/PROC findings in expected locations.

**Bad signal:** pure libraries have many findings (false positives), or CLI apps have 0 findings (false negatives).

## Caveats

- Proc-macro-generated code is invisible to the scanner
- No data flow analysis — dead code is flagged
- Only first-party code is scanned (not dependencies, unless `--include-deps` is passed)
- Shallow clones may miss workspace members in non-standard layouts
