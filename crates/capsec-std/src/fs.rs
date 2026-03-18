//! Capability-gated filesystem operations.
//!
//! Drop-in replacements for `std::fs` functions that require a capability token
//! proving the caller has filesystem permission.
//!
//! # Example
//!
//! ```no_run
//! # use capsec_core::root::test_root;
//! # use capsec_core::permission::FsRead;
//! # use capsec_core::has::Has;
//! let root = test_root();
//! let cap = root.grant::<FsRead>();
//! let data = capsec_std::fs::read("/tmp/data.bin", &cap).unwrap();
//! ```

use capsec_core::cap::Cap;
use capsec_core::error::CapSecError;
use capsec_core::has::Has;
use capsec_core::permission::{FsRead, FsWrite};
use std::path::Path;

/// Reads the entire contents of a file into a byte vector.
/// Requires [`FsRead`] permission.
pub fn read(path: impl AsRef<Path>, cap: &impl Has<FsRead>) -> Result<Vec<u8>, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::read(path)?)
}

/// Reads the entire contents of a file into a string.
/// Requires [`FsRead`] permission.
pub fn read_to_string(
    path: impl AsRef<Path>,
    cap: &impl Has<FsRead>,
) -> Result<String, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::read_to_string(path)?)
}

/// Returns an iterator over the entries within a directory.
/// Requires [`FsRead`] permission.
pub fn read_dir(
    path: impl AsRef<Path>,
    cap: &impl Has<FsRead>,
) -> Result<std::fs::ReadDir, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::read_dir(path)?)
}

/// Returns metadata about a file or directory.
/// Requires [`FsRead`] permission.
pub fn metadata(
    path: impl AsRef<Path>,
    cap: &impl Has<FsRead>,
) -> Result<std::fs::Metadata, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::metadata(path)?)
}

/// Writes bytes to a file, creating it if it doesn't exist, truncating if it does.
/// Requires [`FsWrite`] permission.
pub fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    cap: &impl Has<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::write(path, contents)?)
}

/// Creates all directories in the given path if they don't exist.
/// Requires [`FsWrite`] permission.
pub fn create_dir_all(path: impl AsRef<Path>, cap: &impl Has<FsWrite>) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::create_dir_all(path)?)
}

/// Deletes a file.
/// Requires [`FsWrite`] permission.
pub fn remove_file(path: impl AsRef<Path>, cap: &impl Has<FsWrite>) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::remove_file(path)?)
}

/// Recursively deletes a directory and all its contents.
/// Requires [`FsWrite`] permission.
pub fn remove_dir_all(path: impl AsRef<Path>, cap: &impl Has<FsWrite>) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::remove_dir_all(path)?)
}

/// Renames a file or directory.
/// Requires [`FsWrite`] permission.
pub fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    cap: &impl Has<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::rename(from, to)?)
}

/// Copies a file. Requires both [`FsRead`] and [`FsWrite`] permissions
/// (passed as separate capability tokens).
pub fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    read_cap: &impl Has<FsRead>,
    write_cap: &impl Has<FsWrite>,
) -> Result<u64, CapSecError> {
    let _read_proof: Cap<FsRead> = read_cap.cap_ref();
    let _write_proof: Cap<FsWrite> = write_cap.cap_ref();
    Ok(std::fs::copy(from, to)?)
}

/// Opens a file for reading. Returns a `std::fs::File`.
/// Requires [`FsRead`] permission.
pub fn open(path: impl AsRef<Path>, cap: &impl Has<FsRead>) -> Result<std::fs::File, CapSecError> {
    let _proof: Cap<FsRead> = cap.cap_ref();
    Ok(std::fs::File::open(path)?)
}

/// Creates or truncates a file for writing. Returns a `std::fs::File`.
/// Requires [`FsWrite`] permission.
pub fn create(
    path: impl AsRef<Path>,
    cap: &impl Has<FsWrite>,
) -> Result<std::fs::File, CapSecError> {
    let _proof: Cap<FsWrite> = cap.cap_ref();
    Ok(std::fs::File::create(path)?)
}
