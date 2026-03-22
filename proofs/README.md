# Formal Verification of capsec's Permission Lattice

Machine-verified soundness proofs for capsec's permission model, written in [Lean 4](https://lean-lang.org/).

## What is proved

Four properties of capsec's permission lattice are verified by Lean's kernel — if `lake build` succeeds, the proofs are correct. No trust in tests, no sampling, no fuzzing. The kernel checks every logical step.

| Theorem | What it proves | File |
|---------|---------------|------|
| `no_escalation_*` (6 theorems) | Peer permissions don't subsume each other. `FsRead` cannot grant `FsWrite`. Children don't subsume parents. | `Capsec/Soundness.lean` |
| `no_cross_leak_*` (4 theorems) | Filesystem permissions cannot grant network access (and vice versa). No cross-category leakage unless Ambient. | `Capsec/Soundness.lean` |
| `ambient_complete` | `Ambient` grants every permission — the "god token" property. | `Capsec/Soundness.lean` |
| `subsumption_sound` | If `Subsumes a b` holds, then `Has [a] b` holds — subsumption implies capability access. | `Capsec/Soundness.lean` |

Plus 3 bonus tuple composition theorems proving that holding a pair `[a, b]` grants both `a` and `b`.

## How it works

```
proofs/perms.toml              ← Single source of truth (10 permissions, 4 subsumption edges)
    │
    ├─→ scripts/gen_perm.py    → Capsec/Perm.lean  (auto-generated: Perm type, Subsumes relation)
    │
    ├─→ Capsec/Has.lean        (hand-written: Has judgment with 4 constructors)
    │
    └─→ Capsec/Soundness.lean  (hand-written: 13+ theorems, machine-verified)
```

- **`perms.toml`** defines the permission lattice — the same data drives both the Lean proofs and the Rust sync tests in `capsec-proof`.
- **`gen_perm.py`** generates `Perm.lean` from the TOML, including a `DecidableRel Subsumes` instance that enables `by decide` tactics.
- **`Has.lean`** models capsec-core's `Has<P>` trait as a Lean proposition with 4 constructors: `direct`, `subsumes`, `ambient`, `tuple`.
- **`Soundness.lean`** proves the theorems. Each proof is checked by Lean's type-theoretic kernel.

## Quick start

```bash
# Install Lean 4 (if not already installed)
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y

# Build and verify all proofs
cd proofs && lake build

# Regenerate Perm.lean from perms.toml (after changing permissions)
python3 scripts/gen_perm.py

# Verbose build (shows each file being checked)
lake build -v
```

A successful `lake build` **is** the verification. Lean's kernel rejects any file with an incorrect proof — there is no way to produce a `.olean` output for an unproven theorem.

## Relationship to Rust tests

The Lean proofs verify the same 4 invariants as the Rust proptest suite in `crates/capsec-proof/`:

| Property | Lean proof | Rust proptest |
|----------|-----------|---------------|
| No escalation | `no_escalation_*` theorems | `no_escalation` (256+ random cases) |
| No cross-category leakage | `no_cross_leak_*` theorems | `no_cross_category_leakage` |
| Ambient completeness | `ambient_complete` | `ambient_completeness` |
| Subsumption correctness | `subsumption_sound` | `subsumption_correctness` |

The difference: proptests check random samples and can miss edge cases. Lean proofs are exhaustive — they cover every possible input by construction.

Additionally, 5 sync tests in `crates/capsec-proof/tests/sync_perms_toml.rs` verify that `perms.toml` matches the actual Rust source in `capsec-core`. If someone adds a permission to Rust but forgets to update `perms.toml`, the sync tests fail.

## Academic foundations

This verification approach draws from:

- **Dennis & Van Horn (1966)** — the original capability model with C-lists and unforgeable tokens
- **Saltzer & Schroeder (1975)** — the design principles (least privilege, fail-safe defaults) that the permission lattice encodes
- **Melicher et al. (2017)** — authority safety in Wyvern's capability-based module system, proving that module authority is determinable from interfaces alone

The Lean `Has` judgment directly models capsec-core's `Has<P>` trait, and the `Subsumes` relation models the `Subsumes<P>` trait. The theorems prove that the Rust type-system enforcement is sound: no combination of capabilities can grant access beyond what the lattice permits.

## File structure

```
proofs/
├── perms.toml              # Source of truth: permissions, subsumption, categories
├── lakefile.lean            # Lean 4 build configuration
├── lean-toolchain           # Pinned Lean version (v4.16.0)
├── Capsec.lean              # Root module (imports Perm, Has, Soundness)
├── Capsec/
│   ├── Perm.lean            # AUTO-GENERATED — Perm type, Subsumes relation, DecidableRel
│   ├── Has.lean             # Has judgment (4 constructors)
│   └── Soundness.lean       # 13+ machine-verified theorems
├── scripts/
│   └── gen_perm.py          # Codegen: perms.toml → Perm.lean
└── README.md                # This file
```

## Modifying the permission lattice

If you add or change permissions in `capsec-core/src/permission.rs`:

1. Update `proofs/perms.toml` to match
2. Run `python3 proofs/scripts/gen_perm.py` to regenerate `Perm.lean`
3. Run `cd proofs && lake build` — if the new lattice breaks a soundness property, the build fails
4. Run `cargo test -p capsec-proof` — sync tests verify TOML matches Rust source

CI runs both automatically.
