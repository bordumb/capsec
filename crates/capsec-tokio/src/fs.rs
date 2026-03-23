//! Async capability-gated filesystem operations.
//!
//! Drop-in async replacements for `tokio::fs` functions that require a
//! capability token proving the caller has filesystem permission.

use crate::file::{AsyncReadFile, AsyncWriteFile};
use capsec_core::cap::Cap;
use capsec_core::cap_provider::CapProvider;
use capsec_core::error::CapSecError;
use capsec_core::permission::{FsRead, FsWrite};
use std::path::Path;

/// Reads the entire contents of a file into a byte vector.
/// Requires [`FsRead`] permission.
pub async fn read(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<Vec<u8>, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::read(path).await?)
}

/// Reads the entire contents of a file into a string.
/// Requires [`FsRead`] permission.
pub async fn read_to_string(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<String, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::read_to_string(path).await?)
}

/// Returns an async iterator over the entries within a directory.
/// Requires [`FsRead`] permission.
pub async fn read_dir(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<tokio::fs::ReadDir, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::read_dir(path).await?)
}

/// Returns metadata about a file or directory.
/// Requires [`FsRead`] permission.
pub async fn metadata(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<std::fs::Metadata, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::metadata(path).await?)
}

/// Writes bytes to a file, creating it if it doesn't exist, truncating if it does.
/// Requires [`FsWrite`] permission.
pub async fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::write(path, contents).await?)
}

/// Creates all directories in the given path if they don't exist.
/// Requires [`FsWrite`] permission.
pub async fn create_dir_all(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::create_dir_all(path).await?)
}

/// Deletes a file.
/// Requires [`FsWrite`] permission.
pub async fn remove_file(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::remove_file(path).await?)
}

/// Recursively deletes a directory and all its contents.
/// Requires [`FsWrite`] permission.
pub async fn remove_dir_all(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(tokio::fs::remove_dir_all(path).await?)
}

/// Renames a file or directory.
/// Requires [`FsWrite`] permission.
///
/// Both source and destination paths are checked against the capability's scope.
pub async fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<(), CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&from.as_ref().to_string_lossy())?;
    let _proof2: Cap<FsWrite> = cap.provide_cap(&to.as_ref().to_string_lossy())?;
    Ok(tokio::fs::rename(from, to).await?)
}

/// Copies a file. Requires both [`FsRead`] and [`FsWrite`] permissions.
///
/// The read capability is checked against the source path, and the write
/// capability is checked against the destination path.
pub async fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    read_cap: &impl CapProvider<FsRead>,
    write_cap: &impl CapProvider<FsWrite>,
) -> Result<u64, CapSecError> {
    let _read_proof: Cap<FsRead> = read_cap.provide_cap(&from.as_ref().to_string_lossy())?;
    let _write_proof: Cap<FsWrite> = write_cap.provide_cap(&to.as_ref().to_string_lossy())?;
    Ok(tokio::fs::copy(from, to).await?)
}

/// Opens a file for reading. Returns an [`AsyncReadFile`] that implements
/// `AsyncRead` + `AsyncSeek` but NOT `AsyncWrite`.
/// Requires [`FsRead`] permission.
pub async fn open(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsRead>,
) -> Result<AsyncReadFile, CapSecError> {
    let _proof: Cap<FsRead> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(AsyncReadFile::new(tokio::fs::File::open(path).await?))
}

/// Creates or truncates a file for writing. Returns an [`AsyncWriteFile`] that
/// implements `AsyncWrite` + `AsyncSeek` but NOT `AsyncRead`.
/// Requires [`FsWrite`] permission.
pub async fn create(
    path: impl AsRef<Path>,
    cap: &impl CapProvider<FsWrite>,
) -> Result<AsyncWriteFile, CapSecError> {
    let _proof: Cap<FsWrite> = cap.provide_cap(&path.as_ref().to_string_lossy())?;
    Ok(AsyncWriteFile::new(tokio::fs::File::create(path).await?))
}
