# Compile-Fail Tests

capsec uses [trybuild](https://github.com/dtolnay/trybuild) to verify that invalid code is **rejected at compile time**. These tests prove security guarantees like `Cap<P>` being unforgeable, `!Send`, and sealed.

## How it works

Each `.rs` file in `crates/capsec/tests/compile_fail/` is a standalone program that **must fail to compile**. Each has a matching `.stderr` file containing the **exact** expected compiler error output.

trybuild compiles each `.rs` file, captures stderr, and compares it byte-for-byte against the `.stderr` snapshot. If they don't match, the test fails.

## When `.stderr` files need updating

The `.stderr` snapshots are **tied to the exact rustc version**. Different compiler versions produce different error messages (extra hints, changed wording, different spans). This means:

- Bumping the Rust toolchain version in `rust-toolchain.toml` **will likely break** the compile-fail tests.
- The `.stderr` files must be regenerated after any toolchain version change.

## How to update `.stderr` files

After changing the toolchain version (or adding/modifying a compile-fail test):

```bash
TRYBUILD=overwrite cargo test -p capsec --test compile_tests
```

This runs all compile-fail tests and overwrites the `.stderr` files with the actual compiler output. **Review the diff** before committing — make sure each test still fails for the right reason (e.g., "trait `Send` is not implemented" not "unresolved import").

## Pinned toolchain

The project uses `rust-toolchain.toml` in the repo root to pin the exact rustc version. This ensures local dev and CI produce identical compiler output, so `.stderr` snapshots match everywhere.

If CI fails with stderr mismatches but local tests pass (or vice versa), it means the toolchain versions diverged. Fix by ensuring `rust-toolchain.toml` is respected in both environments.

## Adding a new compile-fail test

1. Create `crates/capsec/tests/compile_fail/your_test_name.rs` with code that should **not** compile.
2. Run:
   ```bash
   cargo test -p capsec --test compile_tests
   ```
   It will fail and print the actual compiler error.
3. Accept the snapshot:
   ```bash
   TRYBUILD=overwrite cargo test -p capsec --test compile_tests
   ```
4. Review the generated `.stderr` file — confirm the error is the one you intended to test.
5. Commit both the `.rs` and `.stderr` files.

## Current tests

| Test | Guarantee |
|------|-----------|
| `cap_new_not_accessible` | `Cap::new()` is private — no external forgery |
| `wrong_capability_rejected` | `Cap<FsRead>` can't satisfy `Has<NetConnect>` |
| `cap_is_not_send` | `Cap<P>` is `!Send` |
| `cap_is_not_sync` | `Cap<P>` is `!Sync` |
| `sealed_permission_no_external_impl` | Can't implement `Permission` outside capsec-core |
| `no_cross_category_satisfaction` | `Cap<FsAll>` can't satisfy `Has<NetConnect>` |
| `subsumption_not_reversed` | `Cap<FsRead>` can't satisfy `Has<FsAll>` |
| `capsec_std_requires_cap` | `capsec::fs::*` requires a capability argument |
| `capsec_std_wrong_cap` | `capsec::fs::*` rejects wrong capability type |
| `sendcap_cannot_grant_wrong_perm` | `SendCap` doesn't escalate permissions across threads |
