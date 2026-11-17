// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Preserve crypto-owned write evidence across every outer TLS poll result.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::crypto::tls::write_progress::{
    self as crypto, WriteProgress, WriteTrackingFault, WriteTrackingLimits,
};
use busbar_contract::response_delivery::{CarrierFault, CarrierProgress, CarrierProgressReader};
use busbar_contract::storage::StorageCredit;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Field order covers cancellation: destroy the future and all TLS backing before its credit.
pub(super) struct FundedHandshake<F> {
    future: Option<F>,
    credit: Option<StorageCredit>,
}

pub(super) struct FundedStream<S> {
    stream: S,
    credit: StorageCredit,
}

impl<S> FundedStream<S> {
    pub(super) fn stream(&self) -> &S {
        &self.stream
    }
    #[cfg(test)]
    pub(super) fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

pub(super) fn handshake<F>(
    credit: StorageCredit,
    create: impl FnOnce() -> F,
) -> FundedHandshake<F> {
    let mut owner = FundedHandshake {
        future: None,
        credit: Some(credit),
    };
    owner.future = Some(create());
    owner
}

impl<F, S> Future for FundedHandshake<F>
where
    F: Future<Output = io::Result<S>> + Unpin,
{
    type Output = io::Result<FundedStream<S>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(future) = self.future.as_mut() else {
            return Poll::Ready(Err(io::Error::other(
                "TLS handshake polled after completion",
            )));
        };
        let outcome = match Pin::new(future).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(outcome) => outcome,
        };
        // The future can retain partial state even after an error; retire it before the refund.
        drop(self.future.take());
        let Some(credit) = self.credit.take() else {
            return Poll::Ready(Err(io::Error::other("TLS handshake lost storage custody")));
        };
        Poll::Ready(outcome.map(|stream| FundedStream { stream, credit }))
    }
}

struct Snapshot(Mutex<CarrierProgress>);

impl CarrierProgressReader for Snapshot {
    fn snapshot(&self) -> CarrierProgress {
        match self.0.lock() {
            Ok(value) => *value,
            Err(poisoned) => {
                let mut value = poisoned.into_inner();
                value.fault.get_or_insert(CarrierFault::Integrity);
                *value
            }
        }
    }
}

fn progress(value: WriteProgress) -> CarrierProgress {
    CarrierProgress {
        accepted_plaintext: value.accepted_plaintext,
        written_plaintext: value.written_plaintext,
        complete_records_plaintext: value.complete_records_plaintext,
        fault: value.fault.map(|fault| match fault {
            WriteTrackingFault::Limit => CarrierFault::Limit,
            WriteTrackingFault::Integrity => CarrierFault::Integrity,
            WriteTrackingFault::WriteZero => CarrierFault::WriteZero,
            WriteTrackingFault::Encryption => CarrierFault::Encryption,
            WriteTrackingFault::Unsupported => CarrierFault::Unsupported,
            WriteTrackingFault::Io => CarrierFault::Io,
        }),
    }
}

/// Exclusive TLS writer. Neither its mutable session nor its raw carrier can escape.
pub(super) struct TrackedTls<IO> {
    stream: tokio_rustls::TlsStream<IO>,
    observation: Arc<Snapshot>,
    // Declared last so TLS record and handshake backing is gone before capacity returns.
    _credit: StorageCredit,
}

impl<IO> TrackedTls<IO> {
    pub(super) fn new(
        funded: FundedStream<impl Into<tokio_rustls::TlsStream<IO>>>,
        plan: crypto::OutputStoragePlan,
    ) -> io::Result<(Self, Arc<dyn CarrierProgressReader>)> {
        let mut funded = FundedStream {
            stream: funded.stream.into(),
            credit: funded.credit,
        };
        let limits = WriteTrackingLimits {
            max_pending_records: plan.limits().pending_records.get(),
        };
        match &mut funded.stream {
            tokio_rustls::TlsStream::Client(client) => crypto::enable(client.get_mut().1, limits),
            tokio_rustls::TlsStream::Server(server) => crypto::enable(server.get_mut().1, limits),
        }
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let initial = crypto::snapshot(funded.stream.get_ref().1)
            .ok_or_else(|| io::Error::other("TLS write tracking did not enable"))?;
        let observation = Arc::new(Snapshot(Mutex::new(progress(initial))));
        let reader: Arc<dyn CarrierProgressReader> = observation.clone();
        Ok((
            Self {
                stream: funded.stream,
                observation,
                _credit: funded.credit,
            },
            reader,
        ))
    }

    fn publish(&self) {
        let mut stored = match self.observation.0.lock() {
            Ok(value) => value,
            Err(poisoned) => {
                let mut value = poisoned.into_inner();
                value.fault.get_or_insert(CarrierFault::Integrity);
                value
            }
        };
        if let Some(current) = crypto::snapshot(self.stream.get_ref().1) {
            let mut current = progress(current);
            current.fault = stored.fault.or(current.fault);
            *stored = current;
        } else {
            stored.fault.get_or_insert(CarrierFault::Integrity);
        }
    }
}

impl<IO> Drop for TrackedTls<IO> {
    fn drop(&mut self) {
        self.publish();
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for TrackedTls<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        self.publish();
        result
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TrackedTls<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        self.publish();
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, slices);
        self.publish();
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_flush(cx);
        self.publish();
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream).poll_shutdown(cx);
        self.publish();
        result
    }
}
