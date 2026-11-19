// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED CONNECTION'S ONE WRITER. Every byte a session writes to its connection goes
//! through here, and only through here: the transport's answer is handed to the delivery driver
//! ([`DeliveryLedger::answer`], the same driver the dial uses), which checks it whole and queues its
//! parts as one run; this writer then gives the queue to the connection, flushes, and tells the
//! driver what the connection's own carrier reports the operating system accepted. A write's return
//! value is never treated as a receipt.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::response_delivery::{CarrierProgressReader, ResponseStop};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Act, Actions, Span};
use crate::outbound::delivery::{Breach, Reason};
use crate::outbound::records::Out;
use crate::outbound::wire::{Fault, Outcome};
use crate::response_delivery::{DeliveryControl, DeliveryLedger};

/// The connection's delivery state and the reader of its genuine carrier, moved together across an
/// upgrade: the entries, the counters with no reset, and the reader.
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
    /// Bind the connection's ledger to the reader supplied by its actual raw/security factory.
    pub fn new(ledger: DeliveryLedger, reader: Arc<dyn CarrierProgressReader>) -> Self {
        Self { ledger, reader }
    }

    /// Move the ledger and the reader into the next transport's session; no counter is reset. The
    /// adopting side calls [`DeliveryLedger::adopt`] with the upgraded request's stream.
    pub fn into_parts(self) -> (DeliveryLedger, Arc<dyn CarrierProgressReader>) {
        (self.ledger, self.reader)
    }

    /// The writer is gone: every answer still open has its verdict, from the carrier's last reading.
    pub(super) fn writer_retired(mut self) {
        self.ledger
            .retire(self.reader.snapshot(), Reason::CallerGone);
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

fn timed_out() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

/// The connection and its delivery state. `Option` permits disposing the writer before the verdicts
/// are frozen, and the move-only hand-over of an upgrade.
pub(super) struct DeliveryIo<S> {
    io: Option<S>,
    delivery: Option<Delivery>,
}

impl<S> DeliveryIo<S> {
    pub(super) fn new(io: S, delivery: Delivery) -> Self {
        Self {
            io: Some(io),
            delivery: Some(delivery),
        }
    }

    pub(super) fn ledger(&mut self) -> &mut DeliveryLedger {
        &mut self.delivery.as_mut().expect("live delivery owner").ledger
    }

    /// ONE ANSWER of the transport, handed to the driver: every stream a `STREAM_HEAD` of it announces
    /// is opened in its place, the caller's resets are noted, then the whole answer is checked and its
    /// parts queued as one run. Nothing is written here.
    ///
    /// # Errors
    /// The [`Fault`]: nothing of the answer was queued and nothing of it will be written.
    pub(super) fn answered(&mut self, acts: &Actions) -> Result<Outcome, Fault> {
        let ledger = self.ledger();
        let mut heads: smallvec::SmallVec<[u64; 4]> = smallvec::SmallVec::new();
        for act in acts.iter() {
            if let Act::Head { stream, .. } = act {
                heads.push(*stream);
            }
        }
        let mut announced = 0;
        let mut items: smallvec::SmallVec<[Out; 16]> = smallvec::SmallVec::new();
        let mut spans: smallvec::SmallVec<[Option<Span>; 16]> = smallvec::SmallVec::new();
        for act in acts.iter() {
            match act {
                Act::Head { stream, .. } => {
                    ledger.announced(*stream)?;
                    announced += 1;
                    continue;
                }
                // L2: a stream is open from its STREAM_HEAD on, not from the start of the answer that
                // carries it.
                Act::WirePart { stream, .. } | Act::WireEnd { stream, .. }
                    if *stream != 0 && heads[announced..].contains(stream) =>
                {
                    return Err(Fault::Output(Breach::L2));
                }
                Act::Reset { stream, .. } => ledger.caller_reset(*stream),
                _ => {}
            }
            if let Some((item, span)) = act.driven() {
                items.push(item);
                spans.push(span);
            }
        }
        ledger.answer(&items, |index| {
            spans[index].map_or(&[][..], |span| acts.bytes(span))
        })
    }

    pub(super) fn poll_control(&mut self, cx: &mut Context<'_>) -> Poll<DeliveryControl> {
        self.ledger().poll_control(cx)
    }

    pub(super) fn into_parts(mut self) -> (S, Delivery) {
        (
            self.io.take().expect("live writer"),
            self.delivery.take().expect("live delivery"),
        )
    }
}

impl<S: AsyncWrite + Unpin> DeliveryIo<S> {
    /// Give the connection everything queued, front to back, by `deadline`: each byte the connection
    /// takes is wiped from the queue at once, and a partial write resumes at the first byte it did not
    /// take.
    pub(super) async fn write_out(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        let Self { io, delivery } = self;
        let io = io.as_mut().expect("live writer");
        let ledger = &mut delivery.as_mut().expect("live delivery owner").ledger;
        let written = tokio::time::timeout_at(deadline, async {
            loop {
                let unwritten = ledger.unwritten();
                if unwritten.is_empty() {
                    return Ok(());
                }
                let written = io.write(unwritten).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                ledger.took(written);
            }
        })
        .await
        .unwrap_or_else(|_| Err(timed_out()));
        if written.is_err() {
            // No unwritten byte waits for the connection's drop.
            ledger.discard();
        }
        written
    }

    /// Flush the connection by `deadline`, then tell the driver what its carrier reports: only after
    /// a flush that succeeded can an answer be `whole`.
    pub(super) async fn flush(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        let Self { io, delivery } = self;
        let io = io.as_mut().expect("live writer");
        tokio::time::timeout_at(deadline, io.flush())
            .await
            .unwrap_or_else(|_| Err(timed_out()))?;
        let delivery = delivery.as_mut().expect("live delivery owner");
        delivery
            .ledger
            .flushed(delivery.reader.snapshot())
            .map_err(error)
    }

    /// Shut the connection's write side down by `deadline` (an `END_SHUTDOWN`, a graceful `CLOSE`):
    /// an answer that ends by closing is `whole` only once this succeeded.
    pub(super) async fn shut(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        let Self { io, delivery } = self;
        let io = io.as_mut().expect("live writer");
        tokio::time::timeout_at(deadline, io.shutdown())
            .await
            .unwrap_or_else(|_| Err(timed_out()))?;
        delivery
            .as_mut()
            .expect("live delivery owner")
            .ledger
            .shut_down();
        Ok(())
    }

    /// Everything queued goes out, flushed: [`Self::write_out`] then [`Self::flush`].
    pub(super) async fn deliver(&mut self, deadline: tokio::time::Instant) -> io::Result<()> {
        self.write_out(deadline).await?;
        self.flush(deadline).await
    }
}

impl<S> Drop for DeliveryIo<S> {
    fn drop(&mut self) {
        // The one session owns every poll. Dispose the only writer before the last reading of its
        // carrier, then freeze what is still open.
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
        Pin::new(self.get_mut().io.as_mut().expect("live writer")).poll_read(cx, buf)
    }
}

#[cfg(test)]
#[path = "../tests/session_delivery_tests.rs"]
mod tests;
