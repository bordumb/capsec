//! The sealed [`Permission`] trait and all built-in permission types.
//!
//! Permissions are zero-sized marker types that encode what kind of I/O a
//! capability token grants. They form a sealed hierarchy — external crates
//! cannot define new permissions, ensuring the set is auditable.
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

/// Marker trait for all capability permissions. Sealed to prevent external implementation.
///
/// Every permission type is a zero-sized struct that implements this trait.
/// The sealed pattern ensures that only the permissions defined in this crate
/// can be used as capability tokens — external crates cannot forge new permissions.
pub trait Permission: sealed::Sealed + 'static {}

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

impl Permission for FsRead {}
impl Permission for FsWrite {}
impl Permission for FsAll {}
impl Permission for NetConnect {}
impl Permission for NetBind {}
impl Permission for NetAll {}
impl Permission for EnvRead {}
impl Permission for EnvWrite {}
impl Permission for Spawn {}
impl Permission for Ambient {}

//  Tuple permissions

impl<A: Permission, B: Permission> Permission for (A, B) {}

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

//  Sealed

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::FsRead {}
    impl Sealed for super::FsWrite {}
    impl Sealed for super::FsAll {}
    impl Sealed for super::NetConnect {}
    impl Sealed for super::NetBind {}
    impl Sealed for super::NetAll {}
    impl Sealed for super::EnvRead {}
    impl Sealed for super::EnvWrite {}
    impl Sealed for super::Spawn {}
    impl Sealed for super::Ambient {}
    impl<A: Sealed, B: Sealed> Sealed for (A, B) {}
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
