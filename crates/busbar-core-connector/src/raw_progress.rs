// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual unbuffered socket writes, before TLS or compatibility adapters can retain bytes.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use busbar_contract::response_delivery::{CarrierFault, CarrierProgress, CarrierProgressReader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Progress(Mutex<CarrierProgress>);

impl CarrierProgressReader for Progress {
    fn snapshot(&self) -> CarrierProgress {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A genuine raw carrier with privately owned mutation. Only concrete unbuffered production
/// factories construct this wrapper; arbitrary buffered AsyncWrite implementations cannot opt in.
pub struct RawCarrier<S> {
    inner: S,
    progress: Arc<Progress>,
}

impl<S> RawCarrier<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            progress: Arc::new(Progress(Mutex::new(CarrierProgress {
                accepted_plaintext: 0,
                written_plaintext: 0,
                complete_records_plaintext: 0,
                fault: None,
            }))),
        }
    }

    /// Observation of this exact carrier, retained across outer errors and after writer disposal.
    #[must_use]
    pub fn progress(&self) -> Arc<dyn CarrierProgressReader> {
        self.progress.clone()
    }

    fn failed(&self) -> bool {
        self.progress.snapshot().fault.is_some()
    }

    fn fault(&self, fault: CarrierFault) {
        self.progress
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fault
            .get_or_insert(fault);
    }

    fn error(&self, error: &io::Error) {
        if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            self.fault(CarrierFault::Io);
        }
    }

    fn before_write(&self, length: usize) -> io::Result<()> {
        let progress = self.progress.snapshot();
        if progress.fault.is_some() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if u64::try_from(length)
            .ok()
            .and_then(|length| progress.written_plaintext.checked_add(length))
            .is_none()
        {
            self.fault(CarrierFault::Limit);
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(())
    }

    fn wrote(&self, result: Poll<io::Result<usize>>, offered: usize) -> Poll<io::Result<usize>> {
        match result {
            Poll::Ready(Ok(0)) if offered != 0 => {
                self.fault(CarrierFault::WriteZero);
                Poll::Ready(Err(io::ErrorKind::WriteZero.into()))
            }
            Poll::Ready(Ok(n)) if n > offered => {
                self.fault(CarrierFault::Integrity);
                Poll::Ready(Err(io::ErrorKind::InvalidData.into()))
            }
            Poll::Ready(Ok(n)) => {
                let mut progress = self
                    .progress
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                // before_write checked the whole offered prefix, so the actual smaller prefix fits.
                let next = progress.written_plaintext + n as u64;
                progress.accepted_plaintext = next;
                progress.written_plaintext = next;
                progress.complete_records_plaintext = next;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(error)) => {
                self.error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn operation(&self, result: Poll<io::Result<()>>) -> Poll<io::Result<()>> {
        if let Poll::Ready(Err(error)) = &result {
            self.error(error);
        }
        result
    }
}

/// Install observation at the actual TCP socket, before any buffer or TLS wrapping.
#[must_use]
pub fn tcp(stream: tokio::net::TcpStream) -> RawCarrier<tokio::net::TcpStream> {
    RawCarrier::new(stream)
}

/// Install observation at an actual Unix-domain socket, before any buffer or TLS wrapping.
#[cfg(unix)]
#[must_use]
pub fn unix(stream: tokio::net::UnixStream) -> RawCarrier<tokio::net::UnixStream> {
    RawCarrier::new(stream)
}

impl<S: AsyncRead + Unpin> AsyncRead for RawCarrier<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        this.operation(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RawCarrier<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.before_write(bytes.len()) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        this.wrote(result, bytes.len())
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(length) = bufs.iter().try_fold(0usize, |n, b| n.checked_add(b.len())) else {
            this.fault(CarrierFault::Limit);
            return Poll::Ready(Err(io::ErrorKind::OutOfMemory.into()));
        };
        if let Err(error) = this.before_write(length) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.wrote(result, length)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        this.operation(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.operation(result)
    }
}

/// Explicit test carrier; never available to production assembly.
#[cfg(test)]
pub(crate) fn test_io(
    io: Box<dyn busbar_contract::transport::wire::RawIo>,
    storage: busbar_contract::storage::StorageSource,
) -> busbar_contract::transport::wire::ConnectionIo {
    use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
    let io = RawCarrier::new(io.compat());
    let progress = io.progress();
    busbar_contract::transport::wire::ConnectionIo {
        io: Box::new(io.compat()),
        progress,
        storage,
    }
}

#[cfg(test)]
#[path = "tests/raw_progress_tests.rs"]
mod tests;
