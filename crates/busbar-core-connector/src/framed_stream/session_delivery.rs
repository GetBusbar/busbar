// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The existing session's sole wire owner. No write result above TLS is treated as a receipt.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::response_delivery::{CarrierProgressReader, ResponseStop, WireClass};
use busbar_contract::storage::StorageSource;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{storage, Act, Actions};
use crate::response_delivery::{DeliveryControl, DeliveryLedger, WireEvent};

/// Response ownership and its genuine carrier observation, moved together across an upgrade.
pub struct Delivery {
    pub(super) ledger: DeliveryLedger,
    reader: Arc<dyn CarrierProgressReader>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Delivery")
            .field("ledger", &self.ledger)
            .finish_non_exhaustive()
    }
}

impl Delivery {
    /// Bind the already-funded ledger to the reader supplied by the actual raw/security factory.
    pub fn new(ledger: DeliveryLedger, reader: Arc<dyn CarrierProgressReader>) -> Self {
        Self { ledger, reader }
    }

    /// Move the exact owner and reader into the next admitted transport; no counter reset.
    pub fn into_parts(self) -> (DeliveryLedger, Arc<dyn CarrierProgressReader>) {
        (self.ledger, self.reader)
    }

    pub(super) fn writer_retired(mut self) {
        self.ledger
            .retire_carrier(self.reader.snapshot(), ResponseStop::CarrierRetired);
    }

    fn sample(&mut self) -> io::Result<()> {
        self.ledger.observe(self.reader.snapshot()).map_err(error)
    }
}

pub(super) fn error(reason: ResponseStop) -> io::Error {
    let kind = match reason {
        ResponseStop::Capacity => io::ErrorKind::OutOfMemory,
        ResponseStop::Deadline => io::ErrorKind::TimedOut,
        ResponseStop::Integrity => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::BrokenPipe,
    };
    io::Error::new(kind, "native response delivery stopped")
}

/// Option permits explicit writer disposal before freezing failure, or a move-only upgrade.
pub(super) struct DeliveryIo<S> {
    io: Option<S>,
    delivery: Option<Delivery>,
    source: StorageSource,
}

impl<S> DeliveryIo<S> {
    pub(super) fn new(io: S, delivery: Delivery, source: StorageSource) -> Self {
        Self {
            io: Some(io),
            delivery: Some(delivery),
            source,
        }
    }

    pub(super) fn ledger(&mut self) -> &mut DeliveryLedger {
        &mut self.delivery.as_mut().expect("live delivery owner").ledger
    }

    /// A complete callback is validated before its first write, including records after CLOSE.
    pub(super) fn prepare(&mut self, acts: &Actions) -> Result<(), ResponseStop> {
        let mut events = storage::Items::new(&self.source).map_err(|_| ResponseStop::Capacity)?;
        let mut terminal = false;
        let mut shutdown = false;
        for act in acts.iter() {
            if terminal {
                return Err(ResponseStop::Integrity);
            }
            if shutdown && matches!(act, Act::Write(_) | Act::WirePart { .. }) {
                return Err(ResponseStop::Integrity);
            }
            let event = match act {
                // Legacy byte-only output has no response attribution and cannot establish payload.
                Act::Write(bytes) if !bytes.is_empty() => Some(WireEvent::Part {
                    stream: 0,
                    class: WireClass::Control,
                    len: bytes.len(),
                }),
                Act::WirePart {
                    stream,
                    class,
                    bytes,
                } => Some(WireEvent::Part {
                    stream: *stream,
                    class: *class,
                    len: bytes.len(),
                }),
                Act::WireEnd {
                    stream,
                    requirement,
                } => {
                    shutdown |= *requirement == super::CompletionRequirement::Shutdown;
                    Some(WireEvent::End {
                        stream: *stream,
                        requirement: *requirement,
                    })
                }
                Act::Abort(stream) => Some(WireEvent::Abort { stream: *stream }),
                Act::Quiescent(stream) => Some(WireEvent::Quiescent { stream: *stream }),
                Act::Close { .. } | Act::Upgrade { .. } => {
                    terminal = true;
                    None
                }
                _ => None,
            };
            if let Some(event) = event {
                events.push(event).map_err(|_| ResponseStop::Capacity)?;
            }
        }
        self.ledger().prepare_batch(events.as_slice())?.commit();
        Ok(())
    }

    pub(super) fn poll_control(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryControl> {
        self.ledger().poll_control(cx)
    }

    pub(super) fn complete_flush(&mut self, prefix: u64) -> io::Result<()> {
        self.ledger().complete_flush(prefix).map_err(error)
    }

    pub(super) fn complete_shutdown(&mut self, prefix: u64) -> io::Result<()> {
        self.ledger().complete_shutdown(prefix).map_err(error)
    }

    pub(super) fn into_parts(mut self) -> (S, Delivery) {
        (
            self.io.take().expect("live writer"),
            self.delivery.take().expect("live delivery"),
        )
    }

    fn sample<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match self.delivery.as_mut().expect("live delivery").sample() {
            Ok(()) => result,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S> Drop for DeliveryIo<S> {
    fn drop(&mut self) {
        // The single session owns all polls. Dispose the only writer before its final observation.
        drop(self.io.take());
        if let Some(delivery) = self.delivery.take() {
            delivery.writer_retired();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DeliveryIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(this.io.as_mut().expect("live writer")).poll_read(cx, buf);
        this.sample(result)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DeliveryIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(this.io.as_mut().expect("live writer")).poll_write(cx, bytes);
        this.sample(result)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(this.io.as_mut().expect("live writer")).poll_flush(cx);
        this.sample(result)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(this.io.as_mut().expect("live writer")).poll_shutdown(cx);
        this.sample(result)
    }
}

#[cfg(test)]
#[path = "../tests/session_delivery_tests.rs"]
mod tests;
