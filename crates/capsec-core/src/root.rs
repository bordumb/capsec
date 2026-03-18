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
//! [`test_root()`] bypasses the singleton check and is available under `#[cfg(test)]`
//! or the `test-support` feature flag. Use it in unit tests to avoid singleton
//! conflicts across parallel test threads.

use crate::cap::Cap;
use crate::permission::Permission;
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
/// Use [`try_root`] for a non-panicking alternative. In tests, use [`test_root`].
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
    /// let fs_cap = root.grant::<FsRead>();
    /// let net_cap = root.grant::<NetConnect>();
    /// ```
    pub fn grant<P: Permission>(&self) -> Cap<P> {
        Cap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::FsRead;

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
}
