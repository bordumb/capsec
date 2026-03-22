//! Error types for the capsec capability system.

/// Errors that can occur when using capsec capabilities.
///
/// Most commonly seen when an [`Attenuated`](crate::attenuate::Attenuated) capability
/// rejects an operation that falls outside its scope.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CapSecError {
    /// The target of a capability operation is outside the granted scope.
    ///
    /// For example, trying to read `/etc/passwd` with a `DirScope` restricted to `/tmp`.
    #[error("capability target '{target}' is outside scope: {scope}")]
    OutOfScope {
        /// The path or address that was rejected.
        target: String,
        /// Description of the allowed scope.
        scope: String,
    },

    /// An I/O error from the underlying `std` operation.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The capability was revoked via its associated `Revoker`.
    #[error("capability has been revoked")]
    Revoked,

    /// The capability has expired (TTL elapsed).
    #[error("capability has expired")]
    Expired,

    /// The capability requires multiple approvals, but not all have been granted.
    #[error("capability requires dual-key approval, but approvals are insufficient")]
    InsufficientApprovals,
}
