//! The zero-sized capability token [`Cap<P>`] and its thread-safe variant [`SendCap<P>`].
//!
//! `Cap<P>` is the core proof type in capsec. Holding a `Cap<FsRead>` proves you
//! have permission to read files. It is:
//!
//! - **Zero-sized** — no runtime cost, erased at compilation
//! - **Unconstructible externally** — `Cap::new()` is `pub(crate)`, so only
//!   [`CapRoot::grant`](crate::root::CapRoot::grant) can create them
//! - **`!Send + !Sync`** — scoped to the creating thread by default
//!
//! Use [`make_send`](Cap::make_send) to explicitly opt into cross-thread transfer
//! when needed (e.g., for `tokio::spawn`).

use crate::permission::Permission;
use std::marker::PhantomData;

/// A zero-sized capability token proving the holder has permission `P`.
///
/// Cannot be constructed outside of `capsec-core` — only
/// [`CapRoot::grant`](crate::root::CapRoot::grant) can create one.
/// `!Send` and `!Sync` by default to scope capabilities to the granting thread.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// let root = test_root();
/// let cap = root.grant::<FsRead>();
/// // cap is a proof token — zero bytes at runtime
/// assert_eq!(std::mem::size_of_val(&cap), 0);
/// ```
#[must_use = "capability tokens are proof of permission — discarding one wastes a grant"]
pub struct Cap<P: Permission> {
    _phantom: PhantomData<P>,
    // PhantomData<*const ()> makes Cap !Send + !Sync
    _not_send: PhantomData<*const ()>,
}

impl<P: Permission> Cap<P> {
    /// Creates a new capability token. Only callable within `capsec-core`.
    pub(crate) fn new() -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
        }
    }

    /// Creates a new capability token for use by `#[capsec::permission]` generated code.
    ///
    /// This constructor is public so that derive macros can create `Cap<P>` for
    /// user-defined permission types from external crates. Requires both the
    /// `SealProof` type bound AND a `SealProof` value (which can only be obtained
    /// via `__capsec_seal()`).
    ///
    /// Do not call directly — use `#[capsec::permission]` instead.
    #[doc(hidden)]
    pub fn __capsec_new_derived(_seal: crate::__private::SealProof) -> Self
    where
        P: Permission<__CapsecSeal = crate::__private::SealProof>,
    {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
        }
    }

    /// Converts this capability into a [`SendCap`] that can cross thread boundaries.
    ///
    /// This is an explicit opt-in — you're acknowledging that this capability
    /// will be used in a multi-threaded context (e.g., passed into `tokio::spawn`).
    #[must_use = "make_send consumes the original Cap and returns a SendCap"]
    pub fn make_send(self) -> SendCap<P> {
        SendCap {
            _phantom: PhantomData,
        }
    }
}

impl<P: Permission> Clone for Cap<P> {
    fn clone(&self) -> Self {
        Cap::new()
    }
}

/// A thread-safe capability token that can be sent across threads.
///
/// Created explicitly via [`Cap::make_send`]. Unlike `Cap<P>`, this implements
/// `Send + Sync`, making it usable with `std::thread::spawn`, `tokio::spawn`,
/// `Arc`, etc.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// let root = test_root();
/// let send_cap = root.grant::<FsRead>().make_send();
///
/// std::thread::spawn(move || {
///     let _cap = send_cap.as_cap();
///     // use cap in this thread
/// }).join().unwrap();
/// ```
#[must_use = "capability tokens are proof of permission — discarding one wastes a grant"]
pub struct SendCap<P: Permission> {
    _phantom: PhantomData<P>,
}

// SAFETY: SendCap is explicitly opted into cross-thread transfer via make_send().
// The capability token is a ZST proof type with no mutable state.
unsafe impl<P: Permission> Send for SendCap<P> {}
unsafe impl<P: Permission> Sync for SendCap<P> {}

impl<P: Permission> SendCap<P> {
    /// Creates a new send-capable token for use by `#[capsec::permission]` generated code.
    ///
    /// Do not call directly — use `#[capsec::permission]` instead.
    #[doc(hidden)]
    pub fn __capsec_new_send_derived(_seal: crate::__private::SealProof) -> Self
    where
        P: Permission<__CapsecSeal = crate::__private::SealProof>,
    {
        Self {
            _phantom: PhantomData,
        }
    }

    /// Returns a new `Cap<P>` from this send-capable token.
    ///
    /// This creates a fresh `Cap` (not a reference cast) — safe because
    /// both types are zero-sized proof tokens.
    pub fn as_cap(&self) -> Cap<P> {
        Cap::new()
    }
}

impl<P: Permission> Clone for SendCap<P> {
    fn clone(&self) -> Self {
        SendCap {
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::FsRead;
    use std::mem::size_of;

    #[test]
    fn cap_is_zst() {
        assert_eq!(size_of::<Cap<FsRead>>(), 0);
    }

    #[test]
    fn sendcap_is_zst() {
        assert_eq!(size_of::<SendCap<FsRead>>(), 0);
    }

    #[test]
    fn cap_is_cloneable() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let _cap2 = cap.clone();
    }

    #[test]
    fn sendcap_crosses_threads() {
        let root = crate::root::test_root();
        let send_cap = root.grant::<FsRead>().make_send();

        std::thread::spawn(move || {
            let _cap = send_cap.as_cap();
        })
        .join()
        .unwrap();
    }
}
