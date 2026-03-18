//! Scope-restricted capabilities via [`Attenuated<P, S>`].
//!
//! Attenuation narrows a capability's reach. A `Cap<FsRead>` grants permission to
//! read any file; an `Attenuated<FsRead, DirScope>` grants permission to read files
//! only within a specific directory tree.
//!
//! # Built-in scopes
//!
//! - [`DirScope`] — restricts filesystem operations to a directory subtree
//! - [`HostScope`] — restricts network operations to a set of allowed hosts

use crate::cap::Cap;
use crate::error::CapSecError;
use crate::permission::Permission;
use std::path::{Path, PathBuf};

/// A restriction that narrows the set of targets a capability can act on.
///
/// Implement this trait to define custom scopes. The [`check`](Scope::check) method
/// returns `Ok(())` if the target is within scope, or an error if not.
pub trait Scope: 'static {
    /// Checks whether `target` is within this scope.
    ///
    /// Returns `Ok(())` if allowed, `Err(CapSecError::OutOfScope)` if not.
    fn check(&self, target: &str) -> Result<(), CapSecError>;
}

/// A capability that has been narrowed to a specific scope.
///
/// Created via [`Cap::attenuate`]. The attenuated capability can only act on
/// targets that pass the scope's [`check`](Scope::check) method.
///
/// # Example
///
/// ```rust,ignore
/// # use capsec_core::root::test_root;
/// # use capsec_core::permission::FsRead;
/// # use capsec_core::attenuate::DirScope;
/// let root = test_root();
/// let scoped = root.grant::<FsRead>().attenuate(DirScope::new("/tmp").unwrap());
/// assert!(scoped.check("/tmp/data.txt").is_ok());
/// assert!(scoped.check("/etc/passwd").is_err());
/// ```
pub struct Attenuated<P: Permission, S: Scope> {
    _cap: Cap<P>,
    scope: S,
}

impl<P: Permission> Cap<P> {
    /// Narrows this capability to a specific scope.
    ///
    /// Consumes the original `Cap<P>` and returns an `Attenuated<P, S>` that
    /// can only act on targets within the scope.
    pub fn attenuate<S: Scope>(self, scope: S) -> Attenuated<P, S> {
        Attenuated { _cap: self, scope }
    }
}

impl<P: Permission, S: Scope> Attenuated<P, S> {
    /// Checks whether `target` is within this capability's scope.
    pub fn check(&self, target: &str) -> Result<(), CapSecError> {
        self.scope.check(target)
    }
}

/// Restricts filesystem operations to a directory subtree.
///
/// Paths are canonicalized before comparison to prevent `../` traversal attacks.
/// If the target path cannot be canonicalized (e.g., it doesn't exist yet),
/// the check fails conservatively.
///
/// # Example
///
/// ```
/// # use capsec_core::attenuate::{DirScope, Scope};
/// let scope = DirScope::new("/tmp").unwrap();
/// // Note: check will fail if /tmp/data.txt doesn't exist (canonicalization)
/// ```
pub struct DirScope {
    root: PathBuf,
}

impl DirScope {
    /// Creates a new directory scope rooted at the given path.
    ///
    /// The root path is canonicalized to prevent bypass via symlinks or `..` components.
    /// Returns an error if the root path does not exist or cannot be resolved.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CapSecError> {
        let canonical = root.as_ref().canonicalize().map_err(CapSecError::Io)?;
        Ok(Self { root: canonical })
    }
}

impl Scope for DirScope {
    fn check(&self, target: &str) -> Result<(), CapSecError> {
        let target_path = Path::new(target);
        let canonical = target_path.canonicalize().map_err(CapSecError::Io)?;

        if canonical.starts_with(&self.root) {
            Ok(())
        } else {
            Err(CapSecError::OutOfScope {
                target: target.to_string(),
                scope: self.root.display().to_string(),
            })
        }
    }
}

/// Restricts network operations to a set of allowed host prefixes.
///
/// Targets are matched by string prefix — `"api.example.com"` matches
/// both `"api.example.com:443"` and `"api.example.com/path"`.
///
/// # Example
///
/// ```
/// # use capsec_core::attenuate::{HostScope, Scope};
/// let scope = HostScope::new(["api.example.com", "cdn.example.com"]);
/// assert!(scope.check("api.example.com:443").is_ok());
/// assert!(scope.check("evil.com:8080").is_err());
/// ```
pub struct HostScope {
    allowed: Vec<String>,
}

impl HostScope {
    /// Creates a new host scope allowing the given host prefixes.
    pub fn new(hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed: hosts.into_iter().map(Into::into).collect(),
        }
    }
}

impl Scope for HostScope {
    fn check(&self, target: &str) -> Result<(), CapSecError> {
        let matches = self.allowed.iter().any(|h| {
            if target.starts_with(h.as_str()) {
                // After the prefix, the next character must be a boundary
                // (end-of-string, ':', or '/') to prevent "api.example.com.evil.com"
                // from matching "api.example.com".
                matches!(target.as_bytes().get(h.len()), None | Some(b':' | b'/'))
            } else {
                false
            }
        });
        if matches {
            Ok(())
        } else {
            Err(CapSecError::OutOfScope {
                target: target.to_string(),
                scope: format!("allowed hosts: {:?}", self.allowed),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_scope_allows_matching() {
        let scope = HostScope::new(["api.example.com", "cdn.example.com"]);
        assert!(scope.check("api.example.com:443").is_ok());
        assert!(scope.check("cdn.example.com/resource").is_ok());
    }

    #[test]
    fn host_scope_rejects_non_matching() {
        let scope = HostScope::new(["api.example.com"]);
        assert!(scope.check("evil.com:8080").is_err());
    }

    #[test]
    fn dir_scope_rejects_traversal() {
        // Create a scope for a real directory
        let scope = DirScope::new("/tmp").unwrap();
        // Trying to escape via ../
        let result = scope.check("/tmp/../etc/passwd");
        // This should either fail (if /etc/passwd doesn't exist for canonicalization)
        // or succeed only if the canonical path is under /tmp (which it won't be)
        if let Ok(()) = result {
            panic!("Should not allow path traversal outside scope");
        }
    }

    #[test]
    fn attenuated_cap_checks_scope() {
        let root = crate::root::test_root();
        let cap = root.grant::<crate::permission::NetConnect>();
        let scoped = cap.attenuate(HostScope::new(["api.example.com"]));
        assert!(scoped.check("api.example.com:443").is_ok());
        assert!(scoped.check("evil.com").is_err());
    }
}
