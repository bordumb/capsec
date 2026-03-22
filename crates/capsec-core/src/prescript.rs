//! Capability prescripts: audit-trail and dual-authorization wrappers.
//!
//! [`LoggedCap<P>`] wraps a [`Cap<P>`](crate::cap::Cap) with an append-only audit log
//! that records every [`try_cap()`](LoggedCap::try_cap) invocation.
//! [`DualKeyCap<P>`] wraps a `Cap<P>` with a dual-authorization gate that requires
//! two independent approvals before [`try_cap()`](DualKeyCap::try_cap) succeeds.
//!
//! Neither type implements [`Has<P>`](crate::has::Has) — callers must use `try_cap()`
//! and handle the fallible result explicitly.
//!
//! These types implement Saltzer & Schroeder's "prescript" concept — actions
//! triggered before capability exercise — specifically Design Principle #5
//! (Separation of Privilege) and #8 (Compromise Recording).

use crate::cap::Cap;
use crate::error::CapSecError;
use crate::permission::Permission;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ============================================================================
// LogEntry
// ============================================================================

/// A record of a single capability exercise attempt.
///
/// Created automatically by [`LoggedCap::try_cap`] and stored in the
/// shared audit log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Monotonic timestamp of the exercise attempt.
    pub timestamp: Instant,
    /// The permission type name (via [`std::any::type_name`]).
    pub permission: &'static str,
    /// Whether the capability was granted (`true`) or denied (`false`).
    pub granted: bool,
}

// ============================================================================
// LoggedCap<P>
// ============================================================================

/// An audited capability token that logs every exercise attempt.
///
/// Created via [`LoggedCap::new`], which consumes a [`Cap<P>`] as proof of
/// possession. Every call to [`try_cap`](LoggedCap::try_cap) appends a
/// [`LogEntry`] to the shared audit log.
///
/// `!Send + !Sync` by default — use [`make_send`](LoggedCap::make_send) for
/// cross-thread transfer. Cloning shares the same audit log: entries from
/// any clone appear in the same log.
pub struct LoggedCap<P: Permission> {
    _phantom: PhantomData<P>,
    _not_send: PhantomData<*const ()>,
    log: Arc<Mutex<Vec<LogEntry>>>,
}

impl<P: Permission> LoggedCap<P> {
    /// Creates an audited capability by consuming a [`Cap<P>`] as proof of possession.
    pub fn new(_cap: Cap<P>) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Attempts to obtain a [`Cap<P>`] and records the attempt in the audit log.
    ///
    /// Always succeeds (since `LoggedCap` wraps a `Cap<P>` directly). The
    /// `granted` field in the log entry is always `true`.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        let entry = LogEntry {
            timestamp: Instant::now(),
            permission: std::any::type_name::<P>(),
            granted: true,
        };
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.push(entry);
        Ok(Cap::new())
    }

    /// Advisory check — always returns `true` for `LoggedCap`.
    pub fn is_active(&self) -> bool {
        true
    }

    /// Returns a cloned snapshot of the audit log.
    pub fn entries(&self) -> Vec<LogEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.clone()
    }

    /// Returns the number of entries in the audit log.
    pub fn entry_count(&self) -> usize {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.len()
    }

    /// Converts this capability into a [`LoggedSendCap`] that can cross thread boundaries.
    pub fn make_send(self) -> LoggedSendCap<P> {
        LoggedSendCap {
            _phantom: PhantomData,
            log: self.log,
        }
    }
}

impl<P: Permission> Clone for LoggedCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            log: Arc::clone(&self.log),
        }
    }
}

// ============================================================================
// LoggedSendCap<P>
// ============================================================================

/// A thread-safe audited capability token.
///
/// Created via [`LoggedCap::make_send`]. Unlike [`LoggedCap`], this implements
/// `Send + Sync`, making it usable with `std::thread::spawn`, `tokio::spawn`, etc.
pub struct LoggedSendCap<P: Permission> {
    _phantom: PhantomData<P>,
    log: Arc<Mutex<Vec<LogEntry>>>,
}

// SAFETY: LoggedSendCap is explicitly opted into cross-thread transfer via make_send().
// The inner Arc<Mutex<Vec<LogEntry>>> is already Send+Sync.
unsafe impl<P: Permission> Send for LoggedSendCap<P> {}
unsafe impl<P: Permission> Sync for LoggedSendCap<P> {}

impl<P: Permission> LoggedSendCap<P> {
    /// Attempts to obtain a [`Cap<P>`] and records the attempt in the audit log.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        let entry = LogEntry {
            timestamp: Instant::now(),
            permission: std::any::type_name::<P>(),
            granted: true,
        };
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.push(entry);
        Ok(Cap::new())
    }

    /// Advisory check — always returns `true`.
    pub fn is_active(&self) -> bool {
        true
    }

    /// Returns a cloned snapshot of the audit log.
    pub fn entries(&self) -> Vec<LogEntry> {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.clone()
    }

    /// Returns the number of entries in the audit log.
    pub fn entry_count(&self) -> usize {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        log.len()
    }
}

impl<P: Permission> Clone for LoggedSendCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            log: Arc::clone(&self.log),
        }
    }
}

// ============================================================================
// DualKeyCap<P>
// ============================================================================

/// A dual-authorization capability requiring two independent approvals.
///
/// Created via [`DualKeyCap::new`], which consumes a [`Cap<P>`] and returns
/// a `(DualKeyCap<P>, ApproverA, ApproverB)` triple. Both approvers must call
/// [`approve()`](ApproverA::approve) before [`try_cap()`](DualKeyCap::try_cap)
/// will succeed.
///
/// Implements Saltzer & Schroeder's Separation of Privilege principle:
/// no single entity can exercise the capability alone.
///
/// `!Send + !Sync` by default — use [`make_send`](DualKeyCap::make_send) for
/// cross-thread transfer. Cloning shares the same approval state.
pub struct DualKeyCap<P: Permission> {
    _phantom: PhantomData<P>,
    _not_send: PhantomData<*const ()>,
    approvals: Arc<AtomicU8>,
}

impl<P: Permission> DualKeyCap<P> {
    /// Creates a dual-authorization capability by consuming a [`Cap<P>`].
    ///
    /// Returns a `(DualKeyCap<P>, ApproverA, ApproverB)` triple. Distribute
    /// the approver handles to separate subsystems to enforce separation of
    /// privilege.
    pub fn new(_cap: Cap<P>) -> (Self, ApproverA, ApproverB) {
        let approvals = Arc::new(AtomicU8::new(0));
        let cap = Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            approvals: Arc::clone(&approvals),
        };
        let a = ApproverA {
            approvals: Arc::clone(&approvals),
        };
        let b = ApproverB { approvals };
        (cap, a, b)
    }

    /// Attempts to obtain a [`Cap<P>`] from this dual-authorization capability.
    ///
    /// Returns `Ok(Cap<P>)` if both approvers have called [`approve()`](ApproverA::approve),
    /// or `Err(CapSecError::InsufficientApprovals)` if not.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if self.approvals.load(Ordering::Acquire) == 3 {
            Ok(Cap::new())
        } else {
            Err(CapSecError::InsufficientApprovals)
        }
    }

    /// Advisory check — returns `true` if both approvals have been granted.
    pub fn is_active(&self) -> bool {
        self.approvals.load(Ordering::Acquire) == 3
    }

    /// Converts this capability into a [`DualKeySendCap`] that can cross thread boundaries.
    pub fn make_send(self) -> DualKeySendCap<P> {
        DualKeySendCap {
            _phantom: PhantomData,
            approvals: self.approvals,
        }
    }
}

impl<P: Permission> Clone for DualKeyCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            _not_send: PhantomData,
            approvals: Arc::clone(&self.approvals),
        }
    }
}

// ============================================================================
// DualKeySendCap<P>
// ============================================================================

/// A thread-safe dual-authorization capability token.
///
/// Created via [`DualKeyCap::make_send`]. Unlike [`DualKeyCap`], this implements
/// `Send + Sync`.
pub struct DualKeySendCap<P: Permission> {
    _phantom: PhantomData<P>,
    approvals: Arc<AtomicU8>,
}

// SAFETY: DualKeySendCap is explicitly opted into cross-thread transfer via make_send().
// The inner Arc<AtomicU8> is already Send+Sync.
unsafe impl<P: Permission> Send for DualKeySendCap<P> {}
unsafe impl<P: Permission> Sync for DualKeySendCap<P> {}

impl<P: Permission> DualKeySendCap<P> {
    /// Attempts to obtain a [`Cap<P>`] from this dual-authorization capability.
    pub fn try_cap(&self) -> Result<Cap<P>, CapSecError> {
        if self.approvals.load(Ordering::Acquire) == 3 {
            Ok(Cap::new())
        } else {
            Err(CapSecError::InsufficientApprovals)
        }
    }

    /// Advisory check — returns `true` if both approvals have been granted.
    pub fn is_active(&self) -> bool {
        self.approvals.load(Ordering::Acquire) == 3
    }
}

impl<P: Permission> Clone for DualKeySendCap<P> {
    fn clone(&self) -> Self {
        Self {
            _phantom: PhantomData,
            approvals: Arc::clone(&self.approvals),
        }
    }
}

// ============================================================================
// ApproverA / ApproverB
// ============================================================================

/// First approval handle for a [`DualKeyCap`].
///
/// `Send + Sync` so it can be passed to another thread or subsystem.
/// **Not `Clone`** — each approver handle is unique to enforce separation
/// of privilege. Distribute `ApproverA` and `ApproverB` to different
/// principals.
pub struct ApproverA {
    approvals: Arc<AtomicU8>,
}

impl ApproverA {
    /// Records approval from the first authority. Idempotent.
    pub fn approve(&self) {
        self.approvals.fetch_or(0b01, Ordering::Release);
    }

    /// Returns `true` if this approver has already approved.
    pub fn is_approved(&self) -> bool {
        self.approvals.load(Ordering::Acquire) & 0b01 != 0
    }
}

/// Second approval handle for a [`DualKeyCap`].
///
/// `Send + Sync` so it can be passed to another thread or subsystem.
/// **Not `Clone`** — each approver handle is unique to enforce separation
/// of privilege.
pub struct ApproverB {
    approvals: Arc<AtomicU8>,
}

impl ApproverB {
    /// Records approval from the second authority. Idempotent.
    pub fn approve(&self) {
        self.approvals.fetch_or(0b10, Ordering::Release);
    }

    /// Returns `true` if this approver has already approved.
    pub fn is_approved(&self) -> bool {
        self.approvals.load(Ordering::Acquire) & 0b10 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::FsRead;
    use std::mem::size_of;

    // ====== LoggedCap tests ======

    #[test]
    fn logged_cap_try_cap_succeeds() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        assert!(lcap.try_cap().is_ok());
    }

    #[test]
    fn logged_cap_records_entry() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let _ = lcap.try_cap();
        let entries = lcap.entries();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].permission.contains("FsRead"));
        assert!(entries[0].granted);
    }

    #[test]
    fn logged_cap_multiple_entries() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let _ = lcap.try_cap();
        let _ = lcap.try_cap();
        let _ = lcap.try_cap();
        assert_eq!(lcap.entry_count(), 3);
    }

    #[test]
    fn logged_cap_entries_snapshot() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let _ = lcap.try_cap();
        let snapshot = lcap.entries();
        let _ = lcap.try_cap();
        // Snapshot should still have 1 entry, live log has 2
        assert_eq!(snapshot.len(), 1);
        assert_eq!(lcap.entry_count(), 2);
    }

    #[test]
    fn logged_send_cap_crosses_threads() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let send_cap = lcap.make_send();

        std::thread::spawn(move || {
            assert!(send_cap.try_cap().is_ok());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn cloned_logged_cap_shares_log() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let lcap2 = lcap.clone();

        let _ = lcap.try_cap();
        let _ = lcap2.try_cap();

        assert_eq!(lcap.entry_count(), 2);
        assert_eq!(lcap2.entry_count(), 2);
    }

    #[test]
    fn logged_cap_is_small() {
        assert!(size_of::<LoggedCap<FsRead>>() <= 2 * size_of::<usize>());
    }

    #[test]
    fn logged_cap_entry_has_correct_permission_name() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let lcap = LoggedCap::new(cap);
        let _ = lcap.try_cap();
        let entries = lcap.entries();
        assert!(entries[0].permission.contains("FsRead"));
    }

    // ====== DualKeyCap tests ======

    #[test]
    fn dual_key_try_cap_fails_without_approvals() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, _a, _b) = DualKeyCap::new(cap);
        assert!(matches!(
            dcap.try_cap(),
            Err(CapSecError::InsufficientApprovals)
        ));
    }

    #[test]
    fn dual_key_try_cap_fails_with_one_approval() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, _b) = DualKeyCap::new(cap);
        a.approve();
        assert!(matches!(
            dcap.try_cap(),
            Err(CapSecError::InsufficientApprovals)
        ));
    }

    #[test]
    fn dual_key_try_cap_succeeds_with_both_approvals() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, b) = DualKeyCap::new(cap);
        a.approve();
        b.approve();
        assert!(dcap.try_cap().is_ok());
    }

    #[test]
    fn dual_key_approval_order_irrelevant() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, b) = DualKeyCap::new(cap);
        b.approve();
        a.approve();
        assert!(dcap.try_cap().is_ok());
    }

    #[test]
    fn dual_key_approve_is_idempotent() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, _b) = DualKeyCap::new(cap);
        a.approve();
        a.approve(); // should not panic
        // Still needs B
        assert!(matches!(
            dcap.try_cap(),
            Err(CapSecError::InsufficientApprovals)
        ));
    }

    #[test]
    fn dual_key_approvers_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ApproverA>();
        assert_send_sync::<ApproverB>();
    }

    #[test]
    fn dual_key_send_cap_crosses_threads() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, b) = DualKeyCap::new(cap);
        a.approve();
        b.approve();
        let send_cap = dcap.make_send();

        std::thread::spawn(move || {
            assert!(send_cap.try_cap().is_ok());
        })
        .join()
        .unwrap();
    }

    #[test]
    fn dual_key_approval_crosses_threads() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, b) = DualKeyCap::new(cap);

        a.approve();

        std::thread::spawn(move || {
            b.approve();
        })
        .join()
        .unwrap();

        assert!(dcap.try_cap().is_ok());
    }

    #[test]
    fn cloned_dual_key_shares_approval() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        let (dcap, a, b) = DualKeyCap::new(cap);
        let dcap2 = dcap.clone();

        a.approve();
        b.approve();

        assert!(dcap.try_cap().is_ok());
        assert!(dcap2.try_cap().is_ok());
    }

    #[test]
    fn dual_key_cap_is_small() {
        assert!(size_of::<DualKeyCap<FsRead>>() <= 2 * size_of::<usize>());
    }
}
