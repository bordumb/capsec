# capsec-proof

Property-based tests and sync checks for capsec's permission lattice.

This crate has **no Cargo dependency on capsec-core** — it mirrors the permission model at runtime and reads capsec-core source files as plain text for validation. This independence means the proofs can't be accidentally invalidated by changes to the crate they're verifying.

## What it tests

### Property tests (proptest)

4 property-based tests in `tests/proptest_lattice.rs`, each generating 256+ random permission pairs:

| Test | Property |
|------|----------|
| `no_escalation` | Non-subsuming permissions in a tuple can't grant access beyond their individual subsumption ranges |
| `no_cross_category_leakage` | Permissions from different categories never subsume each other (unless Ambient) |
| `ambient_completeness` | `Ambient` subsumes every permission |
| `subsumption_correctness` | If `a` subsumes `b` and they're distinct, either `a` is Ambient or they share a category |

### Sync tests

5 tests in `tests/sync_perms_toml.rs` that verify `proofs/perms.toml` (the source of truth) matches the actual Rust source code:

| Test | What it checks |
|------|---------------|
| `perms_toml_variants_match_runtime_mirror` | TOML permission list matches `PermKind::ALL` |
| `perms_toml_subsumes_match_runtime_mirror` | TOML subsumption entries match `subsumes()` function |
| `perms_toml_matches_has_rs_ambient_macro` | TOML variants match `impl_ambient!()` args in `has.rs` |
| `perms_toml_matches_has_rs_tuple_macros` | TOML variants match `impl_tuple_has_first!/second!` args |
| `perms_toml_matches_permission_rs_subsumes_impls` | TOML subsumption entries match `impl Subsumes<>` in `permission.rs` |

If someone adds a permission to capsec-core but forgets to update `perms.toml`, these tests catch it.

### Unit tests

8 unit tests in `src/runtime_mirror.rs` covering the runtime mirror's `subsumes()`, `category()`, and `same_category()` functions.

## Running

```bash
# All tests (17 total: 8 unit + 4 proptest + 5 sync)
cargo test -p capsec-proof

# Just proptests
cargo test -p capsec-proof --test proptest_lattice

# Just sync tests
cargo test -p capsec-proof --test sync_perms_toml

# More proptest cases
PROPTEST_CASES=10000 cargo test -p capsec-proof --test proptest_lattice
```

## Relationship to Lean proofs

This crate tests the same 4 invariants as the Lean 4 proofs in `proofs/`. The difference:

- **Proptest**: checks random samples — fast, catches most issues, but can theoretically miss edge cases
- **Lean proofs**: exhaustive — covers every possible input by construction, verified by a type-theoretic kernel

Both are driven by the same `proofs/perms.toml` source of truth.

## Architecture

```
crates/capsec-proof/
├── src/
│   ├── lib.rs                  # Crate root
│   └── runtime_mirror.rs       # PermKind enum, subsumes(), category()
├── tests/
│   ├── proptest_lattice.rs     # 4 property-based soundness tests
│   └── sync_perms_toml.rs      # 5 TOML ↔ Rust source sync tests
└── Cargo.toml                  # publish = false, no capsec-core dep
```
