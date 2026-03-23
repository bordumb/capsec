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
//! # use capsec_core::cap_provider::CapProvider;
//! let root = test_root();
//! let cap = root.grant::<FsRead>();
//! let data = capsec_std::fs::read("/tmp/data.bin", &cap).unwrap();
//! ```

use crate::file::{ReadFile, WriteFile};
use capsec_core::cap::Cap;
use capsec_core::cap_provider::CapProvider;
use capsec_core::error::CapSecError;
use capsec_core::permission::{FsRead, FsWrite};
use std::path::Path;

/// Reads the entire contents of a file into a byte vector.
/// Requires [`FsRead`] permission.
pub fn read(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<Vec<u8>, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::read(path)?)
}

/// Reads the entire contents of a file into a string.
/// Requires [`FsRead`] permission.
pub fn read_to_string(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<String, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::read_to_string(path)?)
}

/// Returns an iterator over the entries within a directory.
/// Requires [`FsRead`] permission.
pub fn read_dir(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<std::fs::ReadDir, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::read_dir(path)?)
}

/// Returns metadata about a file or directory.
/// Requires [`FsRead`] permission.
pub fn metadata(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<std::fs::Metadata, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::metadata(path)?)
}

/// Writes bytes to a file, creating it if it doesn't exist, truncating if it does.
/// Requires [`FsWrite`] permission.
pub fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::write(path, contents)?)
}

/// Creates all directories in the given path if they don't exist.
/// Requires [`FsWrite`] permission.
pub fn create_dir_all(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::create_dir_all(path)?)
}

/// Deletes a file.
/// Requires [`FsWrite`] permission.
pub fn remove_file(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::remove_file(path)?)
}

/// Recursively deletes a directory and all its contents.
/// Requires [`FsWrite`] permission.
pub fn remove_dir_all(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(std::fs::remove_dir_all(path)?)
}

/// Renames a file or directory.
/// Requires [`FsWrite`] permission.
///
/// Both source and destination paths are checked against the capability's scope.
pub fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&from.as_ref().to_string_lossy())?;
    let _proof2: Cap<FsWrite> = cap.provide_cap(&to.as_ref().to_string_lossy())?;
    Ok(std::fs::rename(from, to)?)
}

/// Copies a file. Requires both [`FsRead`] and [`FsWrite`] permissions
/// (passed as separate capability tokens).
///
/// The read capability is checked against the source path, and the write
/// capability is checked against the destination path.
pub fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    read_cap: &impl CapProvider<FsRead>,
    write_cap: &impl CapProvider<FsWrite>,
) -> Result<u64, CapSecError> {
    let _read_proof: Cap<FsRead> = read_cap.provide_cap(&from.as_ref().to_string_lossy())?;
    let _write_proof: Cap<FsWrite> = write_cap.provide_cap(&to.as_ref().to_string_lossy())?;
    Ok(std::fs::copy(from, to)?)
}

/// Opens a file for reading. Returns a [`ReadFile`] that implements `Read` + `Seek`
/// but NOT `Write`, enforcing the capability boundary beyond the function call.
/// Requires [`FsRead`] permission.
pub fn open(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<ReadFile, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(ReadFile::new(std::fs::File::open(path)?))
}

/// Creates or truncates a file for writing. Returns a [`WriteFile`] that implements
/// `Write` + `Seek` but NOT `Read`, enforcing the capability boundary beyond the function call.
/// Requires [`FsWrite`] permission.
pub fn create(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<WriteFile, CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(WriteFile::new(std::fs::File::create(path)?))
}
