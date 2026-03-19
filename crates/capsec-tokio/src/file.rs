//! Restricted async file handles that enforce capability boundaries.
//!
//! Unlike `tokio::fs::File` which implements both `AsyncRead` and `AsyncWrite`,
//! these wrappers only expose the async I/O trait matching the permission
//! used to obtain them.
//!
//! - [`AsyncReadFile`] — returned by [`open()`](crate::fs::open), implements `AsyncRead` + `AsyncSeek`
//! - [`AsyncWriteFile`] — returned by [`create()`](crate::fs::create), implements `AsyncWrite` + `AsyncSeek`

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

/// An async file handle that only supports reading.
///
/// Returned by [`capsec_tokio::fs::open()`](crate::fs::open). Implements
/// `AsyncRead` and `AsyncSeek`, but NOT `AsyncWrite`.
pub struct AsyncReadFile(tokio::fs::File);

impl AsyncReadFile {
    pub(crate) fn new(file: tokio::fs::File) -> Self {
        Self(file)
    }
}

impl AsyncRead for AsyncReadFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncSeek for AsyncReadFile {
    fn start_seek(self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.get_mut().0).start_seek(position)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.get_mut().0).poll_complete(cx)
    }
}

/// An async file handle that only supports writing.
///
/// Returned by [`capsec_tokio::fs::create()`](crate::fs::create). Implements
/// `AsyncWrite` and `AsyncSeek`, but NOT `AsyncRead`.
pub struct AsyncWriteFile(tokio::fs::File);

impl AsyncWriteFile {
    pub(crate) fn new(file: tokio::fs::File) -> Self {
        Self(file)
    }
}

impl AsyncWrite for AsyncWriteFile {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl AsyncSeek for AsyncWriteFile {
    fn start_seek(self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.get_mut().0).start_seek(position)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Pin::new(&mut self.get_mut().0).poll_complete(cx)
    }
}
