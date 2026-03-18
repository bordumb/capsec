//! The capability root — the single point where ambient authority enters the system.
//!
//! [`CapRoot`] is the factory for all capability tokens. It exists so that capability
//! creation is explicit and traceable — grep for `capsec::root()` to find every point
//! where authority enters your application.
//!
//! # Singleton
//!
//! Only one `CapRoot` can exist per process. [`root()`] panics if called twice;
//! [`try_root()`] returns `None` on the second call. This ensures a single point
//! of authority even in large applications.
//!
//! # Testing
//!
//! `test_root()` bypasses the singleton check and is available under `#[cfg(test)]`
//! or the `test-support` feature flag. Use it in unit tests to avoid singleton
//! conflicts across parallel test threads.

use crate::cap::Cap;
use crate::permission::*;
use std::sync::atomic::{AtomicBool, Ordering};

static ROOT_CREATED: AtomicBool = AtomicBool::new(false);

/// The root of all capabilities. Only one can exist per process.
///
/// `CapRoot` has full ambient authority — it can [`grant`](CapRoot::grant) any
/// permission. It exists to make authority explicit: every capability in your
/// program traces back to a `CapRoot::grant` call.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// let root = test_root();
/// let fs_cap = root.grant::<FsRead>();
/// ```
pub struct CapRoot {
    _private: (),
}

/// Creates the singleton capability root. Panics if called more than once.
///
/// Use [`try_root`] for a non-panicking alternative. In tests, use `test_root`.
pub fn root() -> CapRoot {
    if ROOT_CREATED.swap(true, Ordering::SeqCst) {
        panic!("capsec::root() called more than once — use try_root() or test_root() instead");
    }
    CapRoot { _private: () }
}

/// Creates the singleton capability root, returning `None` if already created.
///
/// Non-panicking alternative to [`root()`].
pub fn try_root() -> Option<CapRoot> {
    if ROOT_CREATED.swap(true, Ordering::SeqCst) {
        None
    } else {
        Some(CapRoot { _private: () })
    }
}

/// Creates a capability root for testing. Bypasses the singleton check.
///
/// Available under `#[cfg(test)]` and the `test-support` feature flag.
/// Can be called multiple times without panicking — essential for parallel tests.
#[cfg(any(test, feature = "test-support"))]
pub fn test_root() -> CapRoot {
    CapRoot { _private: () }
}

impl CapRoot {
    /// Grants a capability token for permission `P`.
    ///
    /// The returned `Cap<P>` is a zero-sized proof that the holder has permission `P`.
    /// This is the only way to obtain a capability token.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use capsec_core::root::test_root;
    /// # use capsec_core::permission::{FsRead, NetConnect};
    /// let root = test_root();
    ///
    /// // Individual capabilities:
    /// let fs_cap = root.grant::<FsRead>();
    /// let net_cap = root.grant::<NetConnect>();
    ///
    /// // Or bundle multiple permissions in one token:
    /// let combo = root.grant::<(FsRead, NetConnect)>();
    /// ```
    pub fn grant<P: Permission>(&self) -> Cap<P> {
        Cap::new()
    }

    /// Grants a `Cap<FsRead>` for filesystem read access.
    pub fn fs_read(&self) -> Cap<FsRead> {
        self.grant()
    }

    /// Grants a `Cap<FsWrite>` for filesystem write access.
    pub fn fs_write(&self) -> Cap<FsWrite> {
        self.grant()
    }

    /// Grants a `Cap<FsAll>` for full filesystem access.
    pub fn fs_all(&self) -> Cap<FsAll> {
        self.grant()
    }

    /// Grants a `Cap<NetConnect>` for outbound network connections.
    pub fn net_connect(&self) -> Cap<NetConnect> {
        self.grant()
    }

    /// Grants a `Cap<NetBind>` for binding network listeners.
    pub fn net_bind(&self) -> Cap<NetBind> {
        self.grant()
    }

    /// Grants a `Cap<NetAll>` for full network access.
    pub fn net_all(&self) -> Cap<NetAll> {
        self.grant()
    }

    /// Grants a `Cap<EnvRead>` for reading environment variables.
    pub fn env_read(&self) -> Cap<EnvRead> {
        self.grant()
    }

    /// Grants a `Cap<EnvWrite>` for writing environment variables.
    pub fn env_write(&self) -> Cap<EnvWrite> {
        self.grant()
    }

    /// Grants a `Cap<Spawn>` for subprocess execution.
    pub fn spawn(&self) -> Cap<Spawn> {
        self.grant()
    }

    /// Grants a `Cap<Ambient>` with full ambient authority.
    pub fn ambient(&self) -> Cap<Ambient> {
        self.grant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::has::Has;

    #[test]
    fn test_root_works() {
        let root = test_root();
        let _cap = root.grant::<FsRead>();
    }

    #[test]
    fn test_root_can_be_called_multiple_times() {
        let _r1 = test_root();
        let _r2 = test_root();
        let _r3 = test_root();
    }

    #[test]
    fn grant_produces_zst() {
        let root = test_root();
        let cap = root.grant::<FsRead>();
        assert_eq!(std::mem::size_of_val(&cap), 0);
    }

    #[test]
    fn convenience_methods_return_correct_types() {
        let root = test_root();
        fn check_fs_read(_: &impl Has<FsRead>) {}
        fn check_fs_write(_: &impl Has<FsWrite>) {}
        fn check_fs_all(_: &impl Has<FsAll>) {}
        fn check_net_connect(_: &impl Has<NetConnect>) {}
        fn check_net_bind(_: &impl Has<NetBind>) {}
        fn check_net_all(_: &impl Has<NetAll>) {}
        fn check_env_read(_: &impl Has<EnvRead>) {}
        fn check_env_write(_: &impl Has<EnvWrite>) {}
        fn check_spawn(_: &impl Has<Spawn>) {}
        fn check_ambient(_: &impl Has<Ambient>) {}

        check_fs_read(&root.fs_read());
        check_fs_write(&root.fs_write());
        check_fs_all(&root.fs_all());
        check_net_connect(&root.net_connect());
        check_net_bind(&root.net_bind());
        check_net_all(&root.net_all());
        check_env_read(&root.env_read());
        check_env_write(&root.env_write());
        check_spawn(&root.spawn());
        check_ambient(&root.ambient());
    }

    #[test]
    fn convenience_equivalent_to_grant() {
        let root = test_root();
        // Both produce ZSTs of the same type
        let _a: Cap<FsRead> = root.fs_read();
        let _b: Cap<FsRead> = root.grant();
        assert_eq!(std::mem::size_of_val(&_a), std::mem::size_of_val(&_b));
    }
}
