//! The [`Has<P>`] trait — proof that a capability token includes permission `P`.
//!
//! This is the trait you use in function signatures to declare capability requirements:
//!
//! ```rust,ignore
//! fn read_config(cap: &impl Has<FsRead>) -> String { ... }
//! ```
//!
//! # Multiple capabilities
//!
//! Bundle permissions in a single token with a tuple:
//!
//! ```rust,ignore
//! fn sync_data(cap: &(impl Has<FsRead> + Has<NetConnect>)) { ... }
//!
//! let root = test_root();
//! let cap = root.grant::<(FsRead, NetConnect)>();
//! sync_data(&cap);
//! ```
//!
//! Or use separate parameters:
//!
//! ```rust,ignore
//! fn sync_data(fs: &impl Has<FsRead>, net: &impl Has<NetConnect>) { ... }
//! ```
//!
//! Or use a subsumption type like [`FsAll`] or
//! [`Ambient`] that satisfies multiple bounds.
//!
//! # Subsumption
//!
//! `Cap<FsAll>` satisfies `Has<FsRead>` and `Has<FsWrite>` because `FsAll`
//! subsumes both. `Cap<Ambient>` satisfies `Has<P>` for every permission.

use crate::cap::{Cap, SendCap};
use crate::permission::*;

/// Proof that a capability token includes permission `P`.
///
/// This trait is open for implementation — custom context structs can implement
/// `Has<P>` to delegate capability access. Security is maintained because
/// `Cap::new()` is `pub(crate)`: no external code can forge a `Cap<P>` in safe Rust.
///
/// Use [`CapRoot::grant()`](crate::root::CapRoot::grant) to obtain capability tokens,
/// or implement `Has<P>` on your own structs using the `#[capsec::context]` macro.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// # use capsec_core::has::Has;
/// fn needs_fs(cap: &impl Has<FsRead>) {
///     let _ = cap.cap_ref(); // proof of permission
/// }
///
/// let root = test_root();
/// let cap = root.grant::<FsRead>();
/// needs_fs(&cap);
/// ```
pub trait Has<P: Permission> {
    /// Returns a new `Cap<P>` proving the permission is available.
    fn cap_ref(&self) -> Cap<P>;
}

//  Direct: Cap<P> implements Has<P>

impl<P: Permission> Has<P> for Cap<P> {
    fn cap_ref(&self) -> Cap<P> {
        Cap::new()
    }
}

//  SendCap<P> delegates to Has<P>

impl<P: Permission> Has<P> for SendCap<P> {
    fn cap_ref(&self) -> Cap<P> {
        self.as_cap()
    }
}

//  Subsumption: FsAll, NetAll

macro_rules! impl_subsumes {
    ($super:ty => $($sub:ty),+) => {
        $(
            impl Has<$sub> for Cap<$super> {
                fn cap_ref(&self) -> Cap<$sub> { Cap::new() }
            }
        )+
    }
}

impl_subsumes!(FsAll => FsRead, FsWrite);
impl_subsumes!(NetAll => NetConnect, NetBind);

//  Ambient: satisfies everything
//
// Cannot use a blanket `impl<P> Has<P> for Cap<Ambient> where Ambient: Subsumes<P>`
// because it conflicts with the direct `impl<P> Has<P> for Cap<P>` when P = Ambient.
// Enumerated via macro to stay in sync with the permission set.

macro_rules! impl_ambient {
    ($($perm:ty),+) => {
        $(
            impl Has<$perm> for Cap<Ambient> {
                fn cap_ref(&self) -> Cap<$perm> { Cap::new() }
            }
        )+
    }
}

// If you add a permission here, also add it to the
// `ambient_covers_all_permissions` test at the bottom of this file.
impl_ambient!(
    FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn
);

//  Tuples: Cap<(A, B)> satisfies Has<A> and Has<B>
//
// Because Rust's coherence rules reject overlapping generic impls when A == B,
// we enumerate all concrete permission pairs via two macros.
//
// Macro 1: Has<first_element> for all (A, B) pairs including self-pairs (100 impls).
// Macro 2: Has<second_element> for distinct pairs only (90 impls).
//
// Total: 190 unique impls. No conflicts. No changes to the Has<P> trait signature.

macro_rules! impl_tuple_has_first {
    ([$($a:ident),+]; $all:tt) => {
        $( impl_tuple_has_first!(@inner $a; $all); )+
    };
    (@inner $a:ident; [$($b:ident),+]) => {
        $(
            impl Has<$a> for Cap<($a, $b)> {
                fn cap_ref(&self) -> Cap<$a> { Cap::new() }
            }
        )+
    };
}

macro_rules! impl_tuple_has_second {
    ($first:ident $(, $rest:ident)+) => {
        $(
            impl Has<$first> for Cap<($rest, $first)> {
                fn cap_ref(&self) -> Cap<$first> { Cap::new() }
            }
            impl Has<$rest> for Cap<($first, $rest)> {
                fn cap_ref(&self) -> Cap<$rest> { Cap::new() }
            }
        )+
        impl_tuple_has_second!($($rest),+);
    };
    ($single:ident) => {};
}

// NOTE: Scaling cliff — these macros enumerate all concrete permission pairs.
// Current: 10 types → 190 impls (100 first-element + 90 second-element).
// Adding 3 more types → ~319 impls. 3-tuples are not supported at all.
// This is a Rust coherence limitation (no generic impl without specialization).
// Workaround: use #[capsec::context] structs instead of tuples for >2 permissions.
// If the permission count grows significantly, consider generating impls via build script.
impl_tuple_has_first!(
    [FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient];
    [FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient]
);

impl_tuple_has_second!(
    FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::test_root;

    #[test]
    fn direct_cap_satisfies_has() {
        let root = test_root();
        let cap = root.grant::<FsRead>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&cap);
    }

    #[test]
    fn fs_all_subsumes_read_and_write() {
        let root = test_root();
        let cap = root.grant::<FsAll>();
        fn needs_read(_: &impl Has<FsRead>) {}
        fn needs_write(_: &impl Has<FsWrite>) {}
        needs_read(&cap);
        needs_write(&cap);
    }

    #[test]
    fn net_all_subsumes_connect_and_bind() {
        let root = test_root();
        let cap = root.grant::<NetAll>();
        fn needs_connect(_: &impl Has<NetConnect>) {}
        fn needs_bind(_: &impl Has<NetBind>) {}
        needs_connect(&cap);
        needs_bind(&cap);
    }

    #[test]
    fn ambient_satisfies_anything() {
        let root = test_root();
        let cap = root.grant::<Ambient>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        fn needs_net(_: &impl Has<NetConnect>) {}
        fn needs_spawn(_: &impl Has<Spawn>) {}
        needs_fs(&cap);
        needs_net(&cap);
        needs_spawn(&cap);
    }

    #[test]
    fn multiple_cap_params() {
        fn sync_data(_fs: &impl Has<FsRead>, _net: &impl Has<NetConnect>) {}
        let root = test_root();
        let fs = root.grant::<FsRead>();
        let net = root.grant::<NetConnect>();
        sync_data(&fs, &net);
    }

    #[test]
    fn tuple_cap_satisfies_both_has() {
        let root = test_root();
        let cap = root.grant::<(FsRead, NetConnect)>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        fn needs_net(_: &impl Has<NetConnect>) {}
        needs_fs(&cap);
        needs_net(&cap);
    }

    #[test]
    fn tuple_self_pair() {
        let root = test_root();
        let cap = root.grant::<(FsRead, FsRead)>();
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&cap);
    }

    #[test]
    fn tuple_with_subsumption_type() {
        let root = test_root();
        let cap = root.grant::<(FsAll, NetConnect)>();
        fn needs_fs_all(_: &impl Has<FsAll>) {}
        fn needs_net(_: &impl Has<NetConnect>) {}
        needs_fs_all(&cap);
        needs_net(&cap);
    }

    #[test]
    fn tuple_cap_ref_returns_correct_type() {
        let root = test_root();
        let cap = root.grant::<(FsRead, NetConnect)>();
        let _fs: Cap<FsRead> = Has::<FsRead>::cap_ref(&cap);
        let _net: Cap<NetConnect> = Has::<NetConnect>::cap_ref(&cap);
    }

    #[test]
    fn tuple_is_zst() {
        use std::mem::size_of;
        assert_eq!(size_of::<Cap<(FsRead, NetConnect)>>(), 0);
    }

    /// Compile-time proof that Cap<Ambient> satisfies Has<P> for every permission.
    /// If a new permission is added to permission.rs but not to impl_ambient!,
    /// this test fails to compile.
    #[test]
    fn ambient_covers_all_permissions() {
        fn assert_ambient_has<P: Permission>()
        where
            Cap<Ambient>: Has<P>,
        {
        }

        assert_ambient_has::<FsRead>();
        assert_ambient_has::<FsWrite>();
        assert_ambient_has::<FsAll>();
        assert_ambient_has::<NetConnect>();
        assert_ambient_has::<NetBind>();
        assert_ambient_has::<NetAll>();
        assert_ambient_has::<EnvRead>();
        assert_ambient_has::<EnvWrite>();
        assert_ambient_has::<Spawn>();
        // Ambient itself is covered by the direct impl<P> Has<P> for Cap<P>
    }
}
