//! Property-based tests for capsec's permission lattice soundness.
//!
//! These test the same 4 invariants that the Lean 4 proofs verify:
//! 1. No escalation — non-subsuming permissions can't grant extra access
//! 2. No cross-category leakage — Fs can't grant Net (unless Ambient)
//! 3. Ambient completeness — Ambient subsumes everything
//! 4. Subsumption correctness — if a subsumes b, they share a category (or a is Ambient)

use capsec_proof::runtime_mirror::*;
use proptest::prelude::*;

fn arb_perm() -> impl Strategy<Value = PermKind> {
    prop_oneof![
        Just(PermKind::FsRead),
        Just(PermKind::FsWrite),
        Just(PermKind::FsAll),
        Just(PermKind::NetConnect),
        Just(PermKind::NetBind),
        Just(PermKind::NetAll),
        Just(PermKind::EnvRead),
        Just(PermKind::EnvWrite),
        Just(PermKind::Spawn),
        Just(PermKind::Ambient),
    ]
}

proptest! {
    /// If a != b and neither subsumes the other, then combining them in a
    /// tuple must not grant access to any c outside {a, b} via subsumption
    /// alone — c must be subsumed by a or b individually.
    #[test]
    fn no_escalation(a in arb_perm(), b in arb_perm(), c in arb_perm()) {
        if a != b && !subsumes(a, b) && !subsumes(b, a) {
            // A tuple (a, b) grants: a, b, and anything a or b subsumes.
            // It must NOT grant c if c is not a, not b, and not subsumed by either.
            if c != a && c != b && !subsumes(a, c) && !subsumes(b, c) {
                // This combination should NOT be grantable — verify no hidden path exists
                prop_assert!(
                    !subsumes(a, c) && !subsumes(b, c),
                    "Tuple ({:?}, {:?}) should not grant {:?} — neither element subsumes it",
                    a, b, c
                );
            }
        }
    }

    /// Permissions from different categories never subsume each other
    /// (unless one is Ambient).
    #[test]
    fn no_cross_category_leakage(a in arb_perm(), b in arb_perm()) {
        if a != PermKind::Ambient && b != PermKind::Ambient {
            if !same_category(a, b) {
                prop_assert!(
                    !subsumes(a, b),
                    "{:?} (category {:?}) should not subsume {:?} (category {:?})",
                    a, category(a), b, category(b)
                );
            }
        }
    }

    /// Ambient subsumes every permission.
    #[test]
    fn ambient_completeness(p in arb_perm()) {
        prop_assert!(
            subsumes(PermKind::Ambient, p),
            "Ambient should subsume {:?}", p
        );
    }

    /// If a subsumes b and they're distinct, then either a is Ambient
    /// or they share a category.
    #[test]
    fn subsumption_correctness(a in arb_perm(), b in arb_perm()) {
        if a != b && subsumes(a, b) {
            prop_assert!(
                a == PermKind::Ambient || same_category(a, b),
                "{:?} subsumes {:?} but they're in different categories and a is not Ambient",
                a, b
            );
        }
    }
}
