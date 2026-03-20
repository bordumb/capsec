//! Runtime-revocable and time-bounded capability tokens.
//!
//! [`RuntimeCap<P>`] wraps a static [`Cap<P>`](crate::cap::Cap) with a shared
//! revocation flag. [`TimedCap<P>`] wraps a `Cap<P>` with an expiry deadline.
//! Unlike `Cap<P>`, neither type implements [`Has<P>`](crate::has::Has) — callers
//! must use [`try_cap()`](RuntimeCap::try_cap) and handle the fallible result explicitly.
//!
//! A [`Revoker`] handle is returned alongside each `RuntimeCap` and can be used
//! to invalidate the capability at any time from any thread.

use crate::cap::Cap;
use crate::error::CapSecError;
use crate::permission::Permission;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A revocable capability token proving the holder has permission `P`.
///
/// Created via [`RuntimeCap::new`], which consumes a [`Cap<P>`] as proof of
/// possession and returns a `(RuntimeCap<P>, Revoker)` pair.
///
/// `!Send + !Sync` by default — use [`make_send`](RuntimeCap::make_send) for
/// cross-thread transfer. Cloning shares the same revocation state: revoking
/// one clone revokes all of them.
pub struct RuntimeCap<P: Permission> {
    _phantom: PhantomData<P>,
    // PhantomData<*const ()> makes RuntimeCap !Send + !Sync
    _not_send: PhantomData<*const ()>,
    active: Arc<AtomicBool>,
}

impl<P: Permission> RuntimeCap<P> {
    /// Creates a revocable capability by consuming a [`Cap<P>`] as proof of possession.
    ///
    /// Returns a `(RuntimeCap<P>, Revoker)` pair. The `Revoker` can invalidate
    /// this capability (and all its clones) from any thread.
    pub fn new(_cap: Cap<P>) -> (Self, Revoker) {
        let active = Arc::new(AtomicBool::new(true));
        let revoker = Revoker {
            active: Arc::clone(&active),
        };
        let cap = Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            active,
        };
        (cap, revoker)
    }

    /// Attempts to obtain a [`Cap<P>`] from this revocable capability.
    ///
    /// Returns `Ok(Cap<P>)` if still active, or `Err(CapSecError::Revoked)` if
    /// the associated [`Revoker`] has been invoked.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if self.active.load(Ordering::Acquire) {
            Ok(Cap::new())
        } else {
            Err(CapSecError::Revoked)
        }
    }

    /// Advisory check — returns `true` if the capability has not been revoked.
    ///
    /// The result is immediately stale; do not use for control flow.
    /// Always use [`try_cap`](RuntimeCap::try_cap) for actual access.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Converts this capability into a [`RuntimeSendCap`] that can cross thread boundaries.
    ///
    /// This is an explicit opt-in — you're acknowledging that this capability
    /// will be used in a multi-threaded context.
    pub fn make_send(self) -> RuntimeSendCap<P> {
        RuntimeSendCap {
            _phantom: PhantomData,
            active: self.active,
        }
    }
}

impl<P: Permission> Clone for RuntimeCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            active: Arc::clone(&self.active),
        }
    }
}

/// A handle that can revoke its associated [`RuntimeCap`] (and all clones).
///
/// `Revoker` is `Send + Sync` and `Clone` — multiple owners can hold revokers
/// to the same capability, and any of them can revoke it from any thread.
/// Revocation is idempotent: calling [`revoke`](Revoker::revoke) multiple times
/// is safe and has no additional effect.
pub struct Revoker {
    active: Arc<AtomicBool>,
}

impl Revoker {
    /// Revokes the associated capability. All subsequent calls to
    /// [`RuntimeCap::try_cap`] (and clones) will return `Err(CapSecError::Revoked)`.
    ///
    /// Idempotent — calling multiple times is safe.
    pub fn revoke(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Returns `true` if the capability has been revoked.
    pub fn is_revoked(&self) -> bool {
        !self.active.load(Ordering::Acquire)
    }
}

impl Clone for Revoker {
    fn clone(&self) -> Self {
        Self {
            active: Arc::clone(&self.active),
        }
    }
}

/// A thread-safe revocable capability token.
///
/// Created via [`RuntimeCap::make_send`]. Unlike [`RuntimeCap`], this implements
/// `Send + Sync`, making it usable with `std::thread::spawn`, `tokio::spawn`, etc.
pub struct RuntimeSendCap<P: Permission> {
    _phantom: PhantomData<P>,
    active: Arc<AtomicBool>,
}

// SAFETY: RuntimeSendCap is explicitly opted into cross-thread transfer via make_send().
// The inner Arc<AtomicBool> is already Send+Sync; PhantomData<P> is Send+Sync when P is.
// Permission types are marker traits (ZSTs) that are always Send+Sync.
unsafe impl<P: Permission> Send for RuntimeSendCap<P> {}
unsafe impl<P: Permission> Sync for RuntimeSendCap<P> {}

impl<P: Permission> RuntimeSendCap<P> {
    /// Attempts to obtain a [`Cap<P>`] from this revocable capability.
    ///
    /// Returns `Ok(Cap<P>)` if still active, or `Err(CapSecError::Revoked)` if
    /// the associated [`Revoker`] has been invoked.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if self.active.load(Ordering::Acquire) {
            Ok(Cap::new())
        } else {
            Err(CapSecError::Revoked)
        }
    }

    /// Advisory check — returns `true` if the capability has not been revoked.
    ///
    /// The result is immediately stale; do not use for control flow.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

impl<P: Permission> Clone for RuntimeSendCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            active: Arc::clone(&self.active),
        }
    }
}

/// A time-bounded capability token proving the holder has permission `P`.
///
/// Created via [`TimedCap::new`], which consumes a [`Cap<P>`] and a TTL duration.
/// After the TTL elapses, [`try_cap()`](TimedCap::try_cap) returns
/// `Err(CapSecError::Expired)`.
///
/// `!Send + !Sync` by default — use [`make_send`](TimedCap::make_send) for
/// cross-thread transfer. Cloning copies the same expiry instant.
pub struct TimedCap<P: Permission> {
    _phantom: PhantomData<P>,
    // PhantomData<*const ()> makes TimedCap !Send + !Sync
    _not_send: PhantomData<*const ()>,
    expires_at: Instant,
}

impl<P: Permission> TimedCap<P> {
    /// Creates a time-bounded capability by consuming a [`Cap<P>`] as proof of possession.
    ///
    /// The capability expires after `ttl` has elapsed from the moment of creation.
    pub fn new(_cap: Cap<P>, ttl: Duration) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            expires_at: Instant::now() + ttl,
        }
    }

    /// Attempts to obtain a [`Cap<P>`] from this timed capability.
    ///
    /// Returns `Ok(Cap<P>)` if the TTL has not elapsed, or `Err(CapSecError::Expired)`
    /// if the capability has expired.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if Instant::now() < self.expires_at {
            Ok(Cap::new())
        } else {
            Err(CapSecError::Expired)
        }
    }

    /// Advisory check — returns `true` if the capability has not yet expired.
    ///
    /// The result is immediately stale; do not use for control flow.
    /// Always use [`try_cap`](TimedCap::try_cap) for actual access.
    pub fn is_active(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Returns the remaining duration before expiry.
    ///
    /// Returns [`Duration::ZERO`] if the capability has already expired.
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Converts this capability into a [`TimedSendCap`] that can cross thread boundaries.
    ///
    /// This is an explicit opt-in — you're acknowledging that this capability
    /// will be used in a multi-threaded context.
    pub fn make_send(self) -> TimedSendCap<P> {
        TimedSendCap {
            _phantom: PhantomData,
            expires_at: self.expires_at,
        }
    }
}

impl<P: Permission> Clone for TimedCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            expires_at: self.expires_at,
        }
    }
}

/// A thread-safe time-bounded capability token.
///
/// Created via [`TimedCap::make_send`]. Unlike [`TimedCap`], this implements
/// `Send + Sync`, making it usable with `std::thread::spawn`, `tokio::spawn`, etc.
pub struct TimedSendCap<P: Permission> {
    _phantom: PhantomData<P>,
    expires_at: Instant,
}

// SAFETY: TimedSendCap is explicitly opted into cross-thread transfer via make_send().
// Instant is Send+Sync; PhantomData<P> is Send+Sync when P is.
// Permission types are marker traits (ZSTs) that are always Send+Sync.
unsafe impl<P: Permission> Send for TimedSendCap<P> {}
unsafe impl<P: Permission> Sync for TimedSendCap<P> {}

impl<P: Permission> TimedSendCap<P> {
    /// Attempts to obtain a [`Cap<P>`] from this timed capability.
    ///
    /// Returns `Ok(Cap<P>)` if the TTL has not elapsed, or `Err(CapSecError::Expired)`
    /// if the capability has expired.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if Instant::now() < self.expires_at {
            Ok(Cap::new())
        } else {
            Err(CapSecError::Expired)
        }
    }

    /// Advisory check — returns `true` if the capability has not yet expired.
    ///
    /// The result is immediately stale; do not use for control flow.
    pub fn is_active(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Returns the remaining duration before expiry.
    ///
    /// Returns [`Duration::ZERO`] if the capability has already expired.
    pub fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

impl<P: Permission> Clone for TimedSendCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            expires_at: self.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::FsRead;
    use std::mem::size_of;

    #[test]
    fn runtime_cap_try_cap_succeeds_when_active() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (rcap, _revoker) = RuntimeCap::new(cap);
        assert!(rcap.try_cap().is_ok());
    }

    #[test]
    fn runtime_cap_try_cap_fails_after_revocation() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (rcap, revoker) = RuntimeCap::new(cap);
        revoker.revoke();
        assert!(matches!(rcap.try_cap(), Err(CapSecError::Revoked)));
    }

    #[test]
    fn revoker_is_idempotent() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (_rcap, revoker) = RuntimeCap::new(cap);
        revoker.revoke();
        revoker.revoke(); // should not panic
        assert!(revoker.is_revoked());
    }

    #[test]
    fn revoker_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Revoker>();
    }

    #[test]
    fn runtime_send_cap_crosses_threads() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (rcap, _revoker) = RuntimeCap::new(cap);
        let send_cap = rcap.make_send();

        std::thread::spawn(move || {
            assert!(send_cap.try_cap().is_ok());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn runtime_send_cap_revocation_crosses_threads() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (rcap, revoker) = RuntimeCap::new(cap);
        let send_cap = rcap.make_send();

        revoker.revoke();

        std::thread::spawn(move || {
            assert!(matches!(send_cap.try_cap(), Err(CapSecError::Revoked)));
        })
        .join()
        .unwrap();
    }

    #[test]
    fn cloned_runtime_cap_shares_revocation() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (rcap, revoker) = RuntimeCap::new(cap);
        let rcap2 = rcap.clone();

        revoker.revoke();

        assert!(matches!(rcap.try_cap(), Err(CapSecError::Revoked)));
        assert!(matches!(rcap2.try_cap(), Err(CapSecError::Revoked)));
    }

    #[test]
    fn runtime_cap_is_small() {
        assert!(size_of::<RuntimeCap<FsRead>>() <= 2 * size_of::<usize>());
    }

    #[test]
    fn timed_cap_succeeds_before_expiry() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let tcap = TimedCap::new(cap, Duration::from_secs(60));
        assert!(tcap.try_cap().is_ok());
    }

    #[test]
    fn timed_cap_fails_after_expiry() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let tcap = TimedCap::new(cap, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(tcap.try_cap(), Err(CapSecError::Expired)));
    }

    #[test]
    fn timed_cap_remaining_decreases() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let tcap = TimedCap::new(cap, Duration::from_secs(60));
        let r1 = tcap.remaining();
        std::thread::sleep(Duration::from_millis(10));
        let r2 = tcap.remaining();
        assert!(r2 < r1);
    }

    #[test]
    fn timed_cap_remaining_is_zero_after_expiry() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let tcap = TimedCap::new(cap, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(tcap.remaining(), Duration::ZERO);
    }
}
