//! Task spawning with capability transfer.
//!
//! [`spawn_with`] is a convenience wrapper around [`tokio::spawn`] that handles
//! the `Cap<P>` → `SendCap<P>` conversion automatically. Without it, users
//! must manually call `.make_send()` before spawning — a common source of
//! confusing `!Send` compiler errors.
//!
//! # Example
//!
//! ```no_run
//! use capsec_core::permission::FsRead;
//!
//! # async fn example(root: capsec_core::root::CapRoot) {
//! let cap = root.grant::<FsRead>();
//!
//! let handle = capsec_tokio::task::spawn_with(cap, |cap| async move {
//!     capsec_tokio::fs::read("/tmp/data.bin", &cap).await.unwrap()
//! });
//!
//! let data = handle.await.unwrap();
//! # }
//! ```

use capsec_core::cap::{Cap, SendCap};
use capsec_core::permission::Permission;
use std::future::Future;

/// Spawns a tokio task with a capability, handling the `Send` conversion.
///
/// Takes a `Cap<P>` (which is `!Send`), converts it to a `SendCap<P>`, and
/// passes it into the closure that produces the spawned future. This removes
/// the need to manually call `.make_send()`.
///
/// # Example
///
/// ```no_run
/// use capsec_core::permission::FsRead;
///
/// # async fn example(root: capsec_core::root::CapRoot) {
/// let cap = root.grant::<FsRead>();
///
/// let handle = capsec_tokio::task::spawn_with(cap, |cap| async move {
///     capsec_tokio::fs::read("/tmp/data.bin", &cap).await.unwrap()
/// });
///
/// let data = handle.await.unwrap();
/// # }
/// ```
pub fn spawn_with<P, F, Fut, T>(cap: Cap<P>, f: F) -> tokio::task::JoinHandle<T>
where
    P: Permission,
    F: FnOnce(SendCap<P>) -> Fut + Send + 'static,
    Fut: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let send_cap = cap.make_send();
    tokio::spawn(f(send_cap))
}
