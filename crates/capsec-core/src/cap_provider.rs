//! The [`CapProvider<P>`] trait — unified capability access with optional scope enforcement.
//!
//! `CapProvider<P>` generalizes [`Has<P>`](crate::has::Has) to support both unscoped
//! capabilities (which always succeed) and scoped capabilities
//! ([`Attenuated<P, S>`](crate::attenuate::Attenuated)) which check the target against
//! a scope before granting access.

use crate::cap::Cap;
use crate::error::CapSecError;
use crate::permission::Permission;

/// A type that can provide a capability token for permission `P`, possibly
/// after performing a scope check against the target.
pub trait CapProvider<P: Permission> {
    /// Provides a `Cap<P>` for the given target, or returns an error if the
    /// target is outside the capability's scope.
    fn provide_cap(&self, target: &str) -> Result<Cap<P>, CapSecError>;
}

// We cannot use a blanket `impl<T: Has<P>> CapProvider<P> for T` because
// Rust's coherence rules can't prove Attenuated won't impl Has in the future.
// Instead, we require types to impl CapProvider explicitly.
// The #[capsec::context] macro and built-in types all get impls.
// For user-defined Has<P> impls, provide a convenience macro.

/// Implement `CapProvider<P>` for a type that already implements `Has<P>`.
///
/// Since `Has<P>` is infallible, the implementation always returns `Ok`
/// and ignores the target string.
///
/// # Example
///
/// ```rust,ignore
/// struct MyCtx { cap: Cap<FsRead> }
/// impl Has<FsRead> for MyCtx { fn cap_ref(&self) -> Cap<FsRead> { self.cap.clone() } }
/// capsec_core::impl_cap_provider_for_has!(MyCtx, FsRead);
/// ```
#[macro_export]
macro_rules! impl_cap_provider_for_has {
    ($ty:ty, $perm:ty) => {
        impl $crate::cap_provider::CapProvider<$perm> for $ty {
            fn provide_cap(
                &self,
                _target: &str,
            ) -> Result<$crate::cap::Cap<$perm>, $crate::error::CapSecError> {
                Ok(<Self as $crate::has::Has<$perm>>::cap_ref(self))
            }
        }
    };
}

// ── Built-in impls: Cap<P>, SendCap<P> ─────────────────────────────

impl<P: Permission> CapProvider<P> for Cap<P> {
    fn provide_cap(&self, _target: &str) -> Result<Cap<P>, CapSecError> {
        Ok(Cap::new())
    }
}

impl<P: Permission> CapProvider<P> for crate::cap::SendCap<P> {
    fn provide_cap(&self, _target: &str) -> Result<Cap<P>, CapSecError> {
        Ok(Cap::new())
    }
}

// ── Subsumption ─────────────────────────────────────────────────────

macro_rules! impl_cap_provider_subsumes {
    ($super:ty => $($sub:ty),+) => {
        $(
            impl CapProvider<$sub> for Cap<$super> {
                fn provide_cap(&self, _target: &str) -> Result<Cap<$sub>, CapSecError> {
                    Ok(Cap::new())
                }
            }
        )+
    }
}

use crate::permission::*;

impl_cap_provider_subsumes!(FsAll => FsRead, FsWrite);
impl_cap_provider_subsumes!(NetAll => NetConnect, NetBind);

// ── Ambient ─────────────────────────────────────────────────────────

macro_rules! impl_cap_provider_ambient {
    ($($perm:ty),+) => {
        $(
            impl CapProvider<$perm> for Cap<Ambient> {
                fn provide_cap(&self, _target: &str) -> Result<Cap<$perm>, CapSecError> {
                    Ok(Cap::new())
                }
            }
        )+
    }
}

impl_cap_provider_ambient!(
    FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn
);

// ── Tuples ──────────────────────────────────────────────────────────

macro_rules! impl_cap_provider_tuple_first {
    ([$($a:ident),+]; $all:tt) => {
        $( impl_cap_provider_tuple_first!(@inner $a; $all); )+
    };
    (@inner $a:ident; [$($b:ident),+]) => {
        $(
            impl CapProvider<$a> for Cap<($a, $b)> {
                fn provide_cap(&self, _target: &str) -> Result<Cap<$a>, CapSecError> {
                    Ok(Cap::new())
                }
            }
        )+
    };
}

macro_rules! impl_cap_provider_tuple_second {
    ($first:ident $(, $rest:ident)+) => {
        $(
            impl CapProvider<$first> for Cap<($rest, $first)> {
                fn provide_cap(&self, _target: &str) -> Result<Cap<$first>, CapSecError> {
                    Ok(Cap::new())
                }
            }
            impl CapProvider<$rest> for Cap<($first, $rest)> {
                fn provide_cap(&self, _target: &str) -> Result<Cap<$rest>, CapSecError> {
                    Ok(Cap::new())
                }
            }
        )+
        impl_cap_provider_tuple_second!($($rest),+);
    };
    ($single:ident) => {};
}

impl_cap_provider_tuple_first!(
    [FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient];
    [FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient]
);

impl_cap_provider_tuple_second!(
    FsRead, FsWrite, FsAll, NetConnect, NetBind, NetAll, EnvRead, EnvWrite, Spawn, Ambient
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_provides() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>();
        assert!(cap.provide_cap("/any").is_ok());
    }

    #[test]
    fn sendcap_provides() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsRead>().make_send();
        assert!(cap.provide_cap("/any").is_ok());
    }

    #[test]
    fn subsumption_provides() {
        let root = crate::root::test_root();
        let cap = root.grant::<FsAll>();
        let result: Result<Cap<FsRead>, _> = cap.provide_cap("/any");
        assert!(result.is_ok());
    }

    #[test]
    fn ambient_provides() {
        let root = crate::root::test_root();
        let cap = root.grant::<Ambient>();
        let result: Result<Cap<FsRead>, _> = cap.provide_cap("/any");
        assert!(result.is_ok());
    }

    #[test]
    fn tuple_provides() {
        let root = crate::root::test_root();
        let cap = root.grant::<(FsRead, NetConnect)>();
        assert!(CapProvider::<FsRead>::provide_cap(&cap, "/any").is_ok());
        assert!(CapProvider::<NetConnect>::provide_cap(&cap, "host").is_ok());
    }
}
