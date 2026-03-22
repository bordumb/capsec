//! Runtime mirror of capsec-core's compile-time permission model.
//!
//! This module provides a runtime `PermKind` enum that mirrors the 10 built-in
//! permission types from `capsec-core::permission`. Used by proptests and sync
//! tests to verify lattice soundness without a Cargo dependency on capsec-core.

/// Runtime representation of a capsec permission type.
///
/// Variants are in the same order as `proofs/perms.toml` and
/// `capsec-core/src/permission.rs` struct declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermKind {
    FsRead,
    FsWrite,
    FsAll,
    NetConnect,
    NetBind,
    NetAll,
    EnvRead,
    EnvWrite,
    Spawn,
    Ambient,
}

impl PermKind {
    /// All 10 permission variants in declaration order.
    pub const ALL: [PermKind; 10] = [
        PermKind::FsRead,
        PermKind::FsWrite,
        PermKind::FsAll,
        PermKind::NetConnect,
        PermKind::NetBind,
        PermKind::NetAll,
        PermKind::EnvRead,
        PermKind::EnvWrite,
        PermKind::Spawn,
        PermKind::Ambient,
    ];

    /// Returns the name of this permission as it appears in Rust source.
    pub fn name(self) -> &'static str {
        match self {
            PermKind::FsRead => "FsRead",
            PermKind::FsWrite => "FsWrite",
            PermKind::FsAll => "FsAll",
            PermKind::NetConnect => "NetConnect",
            PermKind::NetBind => "NetBind",
            PermKind::NetAll => "NetAll",
            PermKind::EnvRead => "EnvRead",
            PermKind::EnvWrite => "EnvWrite",
            PermKind::Spawn => "Spawn",
            PermKind::Ambient => "Ambient",
        }
    }
}

/// Returns the category of a permission.
pub fn category(p: PermKind) -> &'static str {
    match p {
        PermKind::FsRead | PermKind::FsWrite | PermKind::FsAll => "Filesystem",
        PermKind::NetConnect | PermKind::NetBind | PermKind::NetAll => "Network",
        PermKind::EnvRead | PermKind::EnvWrite => "Environment",
        PermKind::Spawn => "Process",
        PermKind::Ambient => "Ambient",
    }
}

/// Returns `true` if `a` and `b` belong to the same category.
pub fn same_category(a: PermKind, b: PermKind) -> bool {
    category(a) == category(b)
}

/// Returns `true` if permission `a` subsumes permission `b`.
///
/// Mirrors the `Subsumes` trait impls in `capsec-core/src/permission.rs`:
/// - Reflexivity: every permission subsumes itself
/// - FsAll => FsRead, FsWrite
/// - NetAll => NetConnect, NetBind
/// - Ambient => everything
pub fn subsumes(a: PermKind, b: PermKind) -> bool {
    if a == b {
        return true; // reflexivity
    }
    matches!(
        (a, b),
        (PermKind::FsAll, PermKind::FsRead)
            | (PermKind::FsAll, PermKind::FsWrite)
            | (PermKind::NetAll, PermKind::NetConnect)
            | (PermKind::NetAll, PermKind::NetBind)
            | (PermKind::Ambient, _)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_count() {
        assert_eq!(PermKind::ALL.len(), 10);
    }

    #[test]
    fn reflexive_subsumption() {
        for p in PermKind::ALL {
            assert!(subsumes(p, p), "{:?} should subsume itself", p);
        }
    }

    #[test]
    fn fs_subsumption() {
        assert!(subsumes(PermKind::FsAll, PermKind::FsRead));
        assert!(subsumes(PermKind::FsAll, PermKind::FsWrite));
        assert!(!subsumes(PermKind::FsRead, PermKind::FsAll));
        assert!(!subsumes(PermKind::FsWrite, PermKind::FsAll));
    }

    #[test]
    fn net_subsumption() {
        assert!(subsumes(PermKind::NetAll, PermKind::NetConnect));
        assert!(subsumes(PermKind::NetAll, PermKind::NetBind));
        assert!(!subsumes(PermKind::NetConnect, PermKind::NetAll));
        assert!(!subsumes(PermKind::NetBind, PermKind::NetAll));
    }

    #[test]
    fn ambient_completeness() {
        for p in PermKind::ALL {
            assert!(
                subsumes(PermKind::Ambient, p),
                "Ambient should subsume {:?}",
                p
            );
        }
    }

    #[test]
    fn no_reverse_subsumption() {
        assert!(!subsumes(PermKind::FsRead, PermKind::FsWrite));
        assert!(!subsumes(PermKind::NetConnect, PermKind::NetBind));
        assert!(!subsumes(PermKind::EnvRead, PermKind::EnvWrite));
    }

    #[test]
    fn no_cross_category() {
        assert!(!subsumes(PermKind::FsAll, PermKind::NetConnect));
        assert!(!subsumes(PermKind::NetAll, PermKind::FsRead));
        assert!(!subsumes(PermKind::FsRead, PermKind::Spawn));
        assert!(!subsumes(PermKind::Spawn, PermKind::EnvRead));
    }

    #[test]
    fn categories_correct() {
        assert_eq!(category(PermKind::FsRead), "Filesystem");
        assert_eq!(category(PermKind::NetConnect), "Network");
        assert_eq!(category(PermKind::EnvRead), "Environment");
        assert_eq!(category(PermKind::Spawn), "Process");
        assert_eq!(category(PermKind::Ambient), "Ambient");
        assert!(same_category(PermKind::FsRead, PermKind::FsAll));
        assert!(!same_category(PermKind::FsRead, PermKind::NetConnect));
    }
}
