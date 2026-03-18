//! Restricted file handles that enforce capability boundaries.
//!
//! Unlike `std::fs::File` which implements both `Read` and `Write`,
//! these wrappers only expose the I/O trait matching the permission
//! used to obtain them.
//!
//! - [`ReadFile`] — returned by [`open()`](crate::fs::open), implements `Read` + `Seek`
//! - [`WriteFile`] — returned by [`create()`](crate::fs::create), implements `Write` + `Seek`

use std::fs::File;
use std::io::{self, Read, Seek, Write};

/// A file handle that only supports reading.
///
/// Returned by [`capsec::fs::open()`](crate::fs::open). Implements `Read`
/// and `Seek`, but NOT `Write`.
///
/// Wraps a `std::fs::File` internally. Zero overhead beyond the File itself.
pub struct ReadFile(File);

impl ReadFile {
    pub(crate) fn new(file: File) -> Self {
        Self(file)
    }
}

impl Read for ReadFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for ReadFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

/// A file handle that only supports writing.
///
/// Returned by [`capsec::fs::create()`](crate::fs::create). Implements `Write`
/// and `Seek`, but NOT `Read`.
///
/// Wraps a `std::fs::File` internally. Zero overhead beyond the File itself.
pub struct WriteFile(File);

impl WriteFile {
    pub(crate) fn new(file: File) -> Self {
        Self(file)
    }
}

impl Write for WriteFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Seek for WriteFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}
