//! The [`Permission`] trait and all built-in permission types.
//!
//! Permissions are zero-sized marker types that encode what kind of I/O a
//! capability token grants. Built-in permissions cover filesystem, network,
//! environment, and process operations. Library authors can define custom
//! permissions using `#[capsec::permission]`.
//!
//! # Built-in permissions
//!
//! | Type | Category | What it grants |
//! |------|----------|----------------|
//! | [`FsRead`] | Filesystem | Read files, list directories, check metadata |
//! | [`FsWrite`] | Filesystem | Write, create, delete files and directories |
//! | [`FsAll`] | Filesystem | All filesystem operations (subsumes `FsRead` + `FsWrite`) |
//! | [`NetConnect`] | Network | Open outbound TCP/UDP connections |
//! | [`NetBind`] | Network | Bind listeners and sockets to local ports |
//! | [`NetAll`] | Network | All network operations (subsumes `NetConnect` + `NetBind`) |
//! | [`EnvRead`] | Environment | Read environment variables |
//! | [`EnvWrite`] | Environment | Modify or remove environment variables |
//! | [`Spawn`] | Process | Execute subprocesses |
//! | [`Ambient`] | Everything | Full ambient authority — the "god token" |
//!
//! # Custom permissions
//!
//! Use `#[capsec::permission]` to define domain-specific permissions:
//!
//! ```rust,ignore
//! #[capsec::permission]
//! pub struct DbRead;
//!
//! #[capsec::permission(subsumes = [DbRead])]
//! pub struct DbAll;
//! ```
//!
//! # Tuples
//!
//! Two permissions can be bundled via a tuple: `(FsRead, NetConnect)` is itself
//! a `Permission`, and `Cap<(FsRead, NetConnect)>` satisfies both `Has<FsRead>`
//! and `Has<NetConnect>`. All 2-tuple combinations of built-in permissions are
//! supported.
//!
//! # Subsumption
//!
//! Some permissions imply others. [`FsAll`] subsumes both [`FsRead`] and [`FsWrite`],
//! meaning a `Cap<FsAll>` can be used anywhere a `Cap<FsRead>` is required.
//! [`Ambient`] subsumes everything.

/// Marker trait for all capability permissions.
///
/// Every permission type is a zero-sized struct that implements this trait.
/// Built-in permissions are defined in this module. Custom permissions can be
/// defined using the `#[capsec::permission]` derive macro, which generates the
/// required seal token.
///
/// # Direct implementation
///
/// Do not implement this trait manually. Use `#[capsec::permission]` instead.
/// The `__CapsecSeal` associated type is `#[doc(hidden)]` and may change
/// without notice.
pub trait Permission: 'static {
    /// Seal token preventing manual implementation. Do not use directly.
    #[doc(hidden)]
    type __CapsecSeal: __private::SealToken;
}

//  Filesystem

/// Permission to read files, list directories, and check metadata.
pub struct FsRead;

/// Permission to write, create, rename, and delete files and directories.
pub struct FsWrite;

/// Permission for all filesystem operations. Subsumes [`FsRead`] and [`FsWrite`].
pub struct FsAll;

//  Network

/// Permission to open outbound TCP and UDP connections.
pub struct NetConnect;

/// Permission to bind TCP listeners and UDP sockets to local ports.
pub struct NetBind;

/// Permission for all network operations. Subsumes [`NetConnect`] and [`NetBind`].
pub struct NetAll;

//  Environment

/// Permission to read environment variables.
pub struct EnvRead;

/// Permission to modify or remove environment variables.
pub struct EnvWrite;

//  Process

/// Permission to spawn and execute subprocesses via `std::process::Command`.
pub struct Spawn;

//  Ambient

/// Full ambient authority — grants every permission.
///
/// This is the "god token." A `Cap<Ambient>` satisfies any `Has<P>` bound.
/// Use sparingly and only at the capability root.
pub struct Ambient;

//  Permission impls

impl Permission for FsRead {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for FsWrite {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for FsAll {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for NetConnect {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for NetBind {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for NetAll {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for EnvRead {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for EnvWrite {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for Spawn {
    type __CapsecSeal = __private::SealProof;
}
impl Permission for Ambient {
    type __CapsecSeal = __private::SealProof;
}

//  Tuple permissions

impl<A: Permission, B: Permission> Permission for (A, B) {
    type __CapsecSeal = __private::SealProof;
}

//  Subsumption

/// Indicates that `Self` implies permission `P`.
///
/// When `Super: Subsumes<Sub>`, a `Cap<Super>` can satisfy `Has<Sub>`.
/// For example, `FsAll: Subsumes<FsRead>` means `Cap<FsAll>` works
/// anywhere `Has<FsRead>` is required.
pub trait Subsumes<P: Permission>: Permission {}

impl Subsumes<FsRead> for FsAll {}
impl Subsumes<FsWrite> for FsAll {}
impl Subsumes<NetConnect> for NetAll {}
impl Subsumes<NetBind> for NetAll {}
impl<P: Permission> Subsumes<P> for Ambient {}

//  Seal token — prevents manual Permission implementation.
//  The #[capsec::permission] macro generates the correct seal.
//  The private field on SealProof prevents external construction —
//  only `__capsec_seal()` can create one, and it's #[doc(hidden)].

#[doc(hidden)]
pub mod __private {
    /// Proof token that a permission was registered via the capsec derive macro.
    ///
    /// Has a private field — cannot be constructed outside this module.
    /// Use `__capsec_seal()` (generated by `#[capsec::permission]`) instead.
    pub struct SealProof(());

    /// Trait bound for the seal associated type.
    pub trait SealToken {}
    impl SealToken for SealProof {}

    /// Creates a seal proof. Only called by `#[capsec::permission]` generated code.
    #[doc(hidden)]
    pub const fn __capsec_seal() -> SealProof {
        SealProof(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn all_permissions_are_zst() {
        assert_eq!(size_of::<FsRead>(), 0);
        assert_eq!(size_of::<FsWrite>(), 0);
        assert_eq!(size_of::<FsAll>(), 0);
        assert_eq!(size_of::<NetConnect>(), 0);
        assert_eq!(size_of::<NetBind>(), 0);
        assert_eq!(size_of::<NetAll>(), 0);
        assert_eq!(size_of::<EnvRead>(), 0);
        assert_eq!(size_of::<EnvWrite>(), 0);
        assert_eq!(size_of::<Spawn>(), 0);
        assert_eq!(size_of::<Ambient>(), 0);
    }

    // Compile-time proof that subsumption relationships hold:
    fn _assert_subsumes<Super: Subsumes<Sub>, Sub: Permission>() {}

    #[test]
    fn tuple_permission_is_zst() {
        assert_eq!(size_of::<(FsRead, NetConnect)>(), 0);
    }

    #[test]
    fn subsumption_relationships() {
        _assert_subsumes::<FsAll, FsRead>();
        _assert_subsumes::<FsAll, FsWrite>();
        _assert_subsumes::<NetAll, NetConnect>();
        _assert_subsumes::<NetAll, NetBind>();
        _assert_subsumes::<Ambient, FsRead>();
        _assert_subsumes::<Ambient, NetConnect>();
        _assert_subsumes::<Ambient, Spawn>();
    }
}
