//! Type system attacks against capsec.
//!
//! Each test attempts to forge, escalate, or bypass capability tokens.
//!
//! ## Has<P> trait — open for delegation
//!
//! `Has<P>` is now open so user-defined context structs can implement it.
//! Security is maintained because `Cap::new()` is `pub(crate)` — no external
//! code can forge a `Cap<P>` in safe Rust.

use capsec_core::cap::{Cap, SendCap};
use capsec_core::has::Has;
use capsec_core::permission::*;
use capsec_core::root::test_root;

// ============================================================================
// C. UNSAFE ATTACKS (expected to work — not real bugs, but documenting)
// ============================================================================

#[test]
fn transmute_forgery_works_with_unsafe() {
    // Cap<FsRead> is a ZST, so transmuting () to it is sound
    let forged: Cap<FsRead> = unsafe { std::mem::transmute(()) };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

#[test]
fn maybe_uninit_forgery_works_with_unsafe() {
    let forged: Cap<FsRead> =
        unsafe { std::mem::MaybeUninit::<Cap<FsRead>>::uninit().assume_init() };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

#[test]
fn ptr_read_forgery_works_with_unsafe() {
    let forged: Cap<FsRead> = unsafe { std::ptr::read(&() as *const () as *const Cap<FsRead>) };
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forged);
}

// ============================================================================
// D. SENDCAP CROSS-THREAD BEHAVIOR
// ============================================================================

/// Proves that make_send() is a genuine opt-in gate, not an accidental
/// escalation path. The flow is:
///   1. Grant Cap<FsRead> on the main thread
///   2. Convert to SendCap via make_send() (explicit opt-in)
///   3. Move SendCap into a spawned thread
///   4. Recover a Cap<FsRead> via as_cap() on the worker thread
///   5. Use that cap to satisfy a Has<FsRead> bound
///
/// The recovered cap is fully usable — it satisfies Has<FsRead> — and it
/// carries only the original permission (FsRead), not anything broader.
#[test]
fn sendcap_cross_thread_roundtrip_is_usable() {
    let root = test_root();
    let cap = root.grant::<FsRead>();

    // Explicit opt-in: Cap -> SendCap
    let send_cap = cap.make_send();

    let handle = std::thread::spawn(move || {
        // Recover a Cap<FsRead> on this thread
        let worker_cap = send_cap.as_cap();

        // The recovered cap satisfies Has<FsRead>
        fn needs_fs_read(cap: &impl Has<FsRead>) -> bool {
            // Prove it's real by calling cap_ref
            let _proof: Cap<FsRead> = cap.cap_ref();
            true
        }
        assert!(needs_fs_read(&worker_cap));

        // Use it with capsec-std for a real I/O operation
        let result = capsec_std::fs::read("/dev/null", &worker_cap);
        assert!(
            result.is_ok(),
            "Cap recovered via as_cap() should work with capsec-std"
        );
    });

    handle.join().expect("worker thread panicked");
}

/// Proves SendCap does NOT escalate: a SendCap<FsRead> yields Cap<FsRead>
/// on the other thread, not Cap<Ambient> or anything else. The cap can only
/// satisfy the original permission bound.
#[test]
fn sendcap_does_not_escalate_across_threads() {
    let root = test_root();
    let send_cap = root.grant::<FsRead>().make_send();

    let handle = std::thread::spawn(move || {
        let worker_cap = send_cap.as_cap();

        // FsRead works
        fn needs_fs_read(_cap: &impl Has<FsRead>) {}
        needs_fs_read(&worker_cap);

        // NetConnect does NOT work — would be a compile error:
        // fn needs_net(_cap: &impl Has<NetConnect>) {}
        // needs_net(&worker_cap);

        // Ambient does NOT work — would be a compile error:
        // fn needs_ambient(_cap: &impl Has<Ambient>) {}
        // needs_ambient(&worker_cap);
    });

    handle.join().expect("worker thread panicked");
}

/// Proves SendCap::clone preserves the permission type too.
#[test]
fn sendcap_clone_across_threads() {
    let root = test_root();
    let send_cap = root.grant::<(FsRead, NetConnect)>().make_send();

    // Clone the SendCap so both threads can use it
    let send_cap2 = send_cap.clone();

    let h1 = std::thread::spawn(move || {
        let cap = send_cap.as_cap();
        fn needs_fs(_: &impl Has<FsRead>) {}
        needs_fs(&cap);
    });

    let h2 = std::thread::spawn(move || {
        let cap = send_cap2.as_cap();
        fn needs_net(_: &impl Has<NetConnect>) {}
        needs_net(&cap);
    });

    h1.join().unwrap();
    h2.join().unwrap();
}

// ============================================================================
// E. ATTENUATED MOVE SEMANTICS
// ============================================================================

/// Proves that .attenuate() consumes the original Cap<P> via move semantics.
/// After attenuating, the original cap is no longer available — the only way
/// to use the permission is through the Attenuated wrapper's scope check.
///
/// This is a key security property: attenuation is irreversible. You can't
/// call .attenuate() to create a scoped cap and then keep using the unscoped
/// original.
#[test]
fn attenuate_consumes_original_cap() {
    use capsec_core::attenuate::{Attenuated, DirScope};

    let root = test_root();
    let cap = root.grant::<FsRead>();

    // Attenuate consumes `cap` (move)
    let _scoped: Attenuated<FsRead, DirScope> = cap.attenuate(DirScope::new("/tmp").unwrap());

    // `cap` is now moved — the lines below would be compile errors:
    // fn needs_fs(_cap: &impl Has<FsRead>) {}
    // needs_fs(&cap);  // ERROR: use of moved value `cap`
    //
    // let _ = cap.clone();  // ERROR: use of moved value `cap`
    //
    // let _ = cap.attenuate(DirScope::new("/tmp").unwrap());  // ERROR: moved
}

/// Same test for HostScope — move semantics don't depend on scope type.
#[test]
fn attenuate_with_hostscope_consumes_cap() {
    use capsec_core::attenuate::{Attenuated, HostScope};

    let root = test_root();
    let cap = root.grant::<NetConnect>();

    let _scoped: Attenuated<NetConnect, HostScope> =
        cap.attenuate(HostScope::new(["api.example.com"]));

    // `cap` is moved — would be a compile error to use it:
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&cap);  // ERROR: use of moved value
}

/// Proves you can still use a cloned cap after attenuating the original.
/// This is correct behavior: the clone is independent. If the caller wants
/// to prevent this, they should not clone before attenuating.
#[test]
fn clone_before_attenuate_keeps_unscoped_copy() {
    use capsec_core::attenuate::DirScope;

    let root = test_root();
    let cap = root.grant::<FsRead>();
    let backup = cap.clone(); // Clone BEFORE attenuating

    // Attenuate consumes the original
    let _scoped = cap.attenuate(DirScope::new("/tmp").unwrap());

    // The clone is still usable — this is expected, not a bug.
    // The security model relies on not cloning before attenuating.
    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&backup);
}

// ============================================================================
// F. ATTACKS THAT CORRECTLY FAIL
// ============================================================================

/// Proves that Cap::clone doesn't violate any invariant.
/// Cloning a legitimate cap produces another legitimate cap — this is fine.
#[test]
fn clone_does_not_escalate() {
    let root = test_root();
    let cap = root.grant::<FsRead>();
    let cloned = cap.clone();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&cloned); // OK: same permission

    // A cloned FsRead cap STILL can't satisfy Has<NetConnect>
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&cloned); // ERROR
}

/// Proves make_send doesn't escalate permissions.
#[test]
fn send_cap_preserves_permission_type() {
    let root = test_root();
    let cap = root.grant::<FsRead>();
    let send = cap.make_send();
    let back = send.as_cap();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&back);

    // SendCap<FsRead>.as_cap() returns Cap<FsRead>, not Cap<Ambient>
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&back); // ERROR
}

/// Proves subsumption is directional.
#[test]
fn subsumption_only_goes_one_way() {
    let root = test_root();
    let fs_all = root.grant::<FsAll>();

    fn needs_read(_cap: &impl Has<FsRead>) {}
    fn needs_write(_cap: &impl Has<FsWrite>) {}
    needs_read(&fs_all); // OK: FsAll subsumes FsRead
    needs_write(&fs_all); // OK: FsAll subsumes FsWrite

    // But FsRead does NOT subsume FsAll
    // (This would be a compile error if uncommented)
    // let fs_read = root.grant::<FsRead>();
    // fn needs_all(_cap: &impl Has<FsAll>) {}
    // needs_all(&fs_read); // ERROR
}

/// Proves cross-category subsumption doesn't exist.
#[test]
fn no_cross_category_leak() {
    let root = test_root();
    let fs_all = root.grant::<FsAll>();

    fn needs_fs(_cap: &impl Has<FsRead>) {}
    needs_fs(&fs_all); // OK

    // FsAll does NOT satisfy NetConnect
    // (This would be a compile error if uncommented)
    // fn needs_net(_cap: &impl Has<NetConnect>) {}
    // needs_net(&fs_all); // ERROR
}

// ============================================================================
// G. CONTEXT DELEGATION (Has<P> is open for user structs)
// ============================================================================

/// User-defined struct with a Cap<FsRead> field can implement Has<FsRead>
/// and pass to functions requiring that capability.
#[test]
fn context_struct_satisfies_has() {
    struct MyContext {
        fs: Cap<FsRead>,
    }

    impl Has<FsRead> for MyContext {
        fn cap_ref(&self) -> Cap<FsRead> {
            self.fs.cap_ref()
        }
    }

    let root = test_root();
    let ctx = MyContext {
        fs: root.grant::<FsRead>(),
    };

    fn needs_fs(_: &impl Has<FsRead>) {}
    needs_fs(&ctx);
}

/// SendCap<P> satisfies Has<P> via the blanket impl.
#[test]
fn sendcap_satisfies_has() {
    let root = test_root();
    let send_cap: SendCap<FsRead> = root.grant::<FsRead>().make_send();

    fn needs_fs(_: &impl Has<FsRead>) {}
    needs_fs(&send_cap);
}

/// SendCap<P>.cap_ref() returns a valid Cap<P>.
#[test]
fn sendcap_has_delegation_runtime() {
    let root = test_root();
    let send_cap: SendCap<FsRead> = root.grant::<FsRead>().make_send();

    let _proof: Cap<FsRead> = send_cap.cap_ref();
}

// ============================================================================
// H. CAPSEC::RUN
// ============================================================================

#[test]
fn capsec_run_provides_root() {
    // Can't use capsec::run() because it calls the singleton root().
    // Instead test the pattern directly.
    let root = test_root();
    let _cap = root.fs_read();
}

// ============================================================================
// I. CONTEXT MACRO
// ============================================================================

#[capsec_macro::context]
struct TestCtx {
    fs: FsRead,
    net: NetConnect,
}

#[test]
fn context_macro_satisfies_has() {
    let root = test_root();
    let ctx = TestCtx::new(&root);

    fn needs_fs(_: &impl Has<FsRead>) {}
    fn needs_net(_: &impl Has<NetConnect>) {}
    needs_fs(&ctx);
    needs_net(&ctx);
}

#[test]
fn context_macro_works_with_capsec_std() {
    let root = test_root();
    let ctx = TestCtx::new(&root);

    let result = capsec_std::fs::read("/dev/null", &ctx);
    assert!(result.is_ok());
}

#[capsec_macro::context(send)]
struct SendCtx {
    fs: FsRead,
}

#[test]
fn send_context_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SendCtx>();
}

#[test]
fn send_context_satisfies_has() {
    let root = test_root();
    let ctx = SendCtx::new(&root);

    fn needs_fs(_: &impl Has<FsRead>) {}
    needs_fs(&ctx);
}

// ============================================================================
// J. REQUIRES WITH ON = PARAM
// ============================================================================

#[capsec_macro::requires(fs::read, on = ctx)]
fn fn_with_requires_on(ctx: &TestCtx) {
    let _: Cap<FsRead> = ctx.cap_ref();
}

#[test]
fn requires_on_compiles_with_valid_context() {
    let root = test_root();
    let ctx = TestCtx::new(&root);
    fn_with_requires_on(&ctx);
}

#[capsec_macro::requires(fs::read)]
fn fn_with_requires_impl(cap: &impl Has<FsRead>) {
    let _: Cap<FsRead> = cap.cap_ref();
}

#[test]
fn requires_impl_still_works() {
    let root = test_root();
    let cap = root.fs_read();
    fn_with_requires_impl(&cap);
}

// ============================================================================
// K. RESTRICTED FILE HANDLES
// ============================================================================

#[test]
fn open_returns_readable_file() {
    let root = test_root();
    let cap = root.fs_read();
    let mut file = capsec_std::fs::open("/dev/null", &cap).unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buf).unwrap();
}

#[test]
fn create_returns_writable_file() {
    let root = test_root();
    let cap = root.fs_write();
    let path = std::env::temp_dir().join("capsec-test-create");
    let mut file = capsec_std::fs::create(&path, &cap).unwrap();
    std::io::Write::write_all(&mut file, b"test").unwrap();
    std::fs::remove_file(&path).ok();
}

// ============================================================================
// L. FORGERY DEFENSE — proving the _proof pattern stops diverging Has<P> impls
// ============================================================================
//
// The _proof pattern (`let _proof: Cap<P> = cap.cap_ref()`) forces cap_ref()
// to evaluate and return before any I/O executes. If an external impl of
// Has<P> diverges (panic, loop, process::exit), the divergence fires at the
// _proof line — the I/O on the next line never runs.
//
// This is the enforcement mechanism that makes open Has<P> safe: you can
// implement the trait, but you can't skip the proof extraction.

/// A malicious Has<FsRead> impl that panics instead of returning a Cap.
struct PanicForge;

impl Has<FsRead> for PanicForge {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!("forged capability — this should fire before I/O");
    }
}

/// Proves: a diverging Has<P> impl (panic) fires BEFORE std::fs::read executes.
/// If the _proof pattern were missing or incorrect, the I/O would run first.
#[test]
#[should_panic(expected = "forged capability")]
fn forged_has_impl_panics_before_io_executes() {
    let _ = capsec_std::fs::read("/dev/null", &PanicForge);
}

// ============================================================================
// M. RUNTIME CAPS
// ============================================================================

#[test]
fn runtime_cap_try_cap_returns_valid_cap_for_capsec_std() {
    use capsec_core::runtime::RuntimeCap;

    let root = test_root();
    let cap = root.grant::<FsRead>();
    let (rcap, _revoker) = RuntimeCap::new(cap);

    let cap = rcap.try_cap().expect("should be active");
    let result = capsec_std::fs::read("/dev/null", &cap);
    assert!(
        result.is_ok(),
        "try_cap() → Cap<P> should work with capsec-std"
    );
}

#[test]
fn revoked_runtime_cap_prevents_io() {
    use capsec_core::error::CapSecError;
    use capsec_core::runtime::RuntimeCap;

    let root = test_root();
    let cap = root.grant::<FsRead>();
    let (rcap, revoker) = RuntimeCap::new(cap);

    revoker.revoke();
    assert!(matches!(rcap.try_cap(), Err(CapSecError::Revoked)));
}

#[test]
fn timed_cap_try_cap_returns_valid_cap() {
    use capsec_core::runtime::TimedCap;
    use std::time::Duration;

    let root = test_root();
    let cap = root.grant::<FsRead>();
    let tcap = TimedCap::new(cap, Duration::from_secs(60));

    let cap = tcap.try_cap().expect("should be active");
    fn needs_fs(_: &impl Has<FsRead>) {}
    needs_fs(&cap);
}

#[test]
fn runtime_cap_with_tuple_permission() {
    use capsec_core::runtime::RuntimeCap;

    let root = test_root();
    let cap = root.grant::<(FsRead, NetConnect)>();
    let (rcap, _revoker) = RuntimeCap::new(cap);

    let cap = rcap.try_cap().expect("should be active");
    fn needs_fs(_: &impl Has<FsRead>) {}
    fn needs_net(_: &impl Has<NetConnect>) {}
    needs_fs(&cap);
    needs_net(&cap);
}

#[test]
fn runtime_cap_with_subsumption() {
    use capsec_core::runtime::RuntimeCap;

    let root = test_root();
    let cap = root.grant::<FsAll>();
    let (rcap, _revoker) = RuntimeCap::new(cap);

    let cap = rcap.try_cap().expect("should be active");
    fn needs_fs_read(_: &impl Has<FsRead>) {}
    needs_fs_read(&cap); // FsAll subsumes FsRead
}

/// A malicious Has<FsRead> impl that loops forever instead of returning a Cap.
///
/// Cannot be tested directly (would hang the test runner), but the behavior is
/// correct: LoopForge::cap_ref() never returns, so the I/O call on the next
/// line of the wrapper function is never reached.
///
/// This struct exists to document the behavior and prove it compiles —
/// confirming that Has<P> being open does not enable I/O bypass via divergence.
#[allow(dead_code)]
struct LoopForge;

#[allow(dead_code)]
impl Has<FsRead> for LoopForge {
    fn cap_ref(&self) -> Cap<FsRead> {
        loop {} // diverges — I/O never executes
    }
}
