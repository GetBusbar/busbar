// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTED CONNECTION'S ONE WRITER. Every byte a session writes to its connection goes
//! through here, and only through here: the transport's answer is handed to the delivery driver
//! ([`DeliveryLedger::answer`], the same driver the dial uses), which checks it whole and places its
//! parts as one run; this writer then gives the run to the connection straight from the session's
//! own output buffer (charged to the connection's storage account: no copy of an answer byte is
//! made), flushes, and tells the driver what the connection's own carrier reports the operating
//! system accepted. A write's return value is never treated as a receipt.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::response_delivery::{CarrierProgressReader, ResponseStop};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Act, Actions, Span};
use crate::outbound::delivery::{Breach, Reason};
use crate::outbound::records::Out;
use crate::outbound::wire::{Checked, Fault};
use crate::response_delivery::{DeliveryControl, DeliveryLedger};

/// One answer the driver checked and placed: what it asks of the connection, and where each of its
/// driven items' bytes are in the session's output buffer. No byte of it is held here: the buffer
/// keeps them, charged, until [`DeliveryIo::write_out`] gave them to the connection.
pub(super) struct Answered {
    checked: Checked,
    spans: smallvec::SmallVec<[Option<Span>; 16]>,
}

impl Answered {
    /// The answer has bytes for the connection.
    pub(super) fn wrote(&self) -> bool {
        self.checked.outcome.wrote
    }
}

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
    /// parts placed as one run. Nothing is written or copied here: `acts` keeps the bytes until
    /// [`Self::write_out`] gave them.
    ///
    /// # Errors
    /// The [`Fault`]: nothing of the answer was placed and nothing of it will be written.
    pub(super) fn answered(&mut self, acts: &Actions) -> Result<Answered, Fault> {
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
        let checked = ledger.answer(&items, |index| {
            spans[index].map_or(&[][..], |span| acts.bytes(span))
        })?;
        Ok(Answered { checked, spans })
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
    /// Give the connection the run of `answered`, front to back, by `deadline`, read straight from
    /// `acts` (the session's own charged buffer, the one the answer was checked from): a partial
    /// write resumes at the first byte it did not take, and each write the connection took is
    /// counted as it returns. The caller clears `acts` only after this, however it ended.
    pub(super) async fn write_out(
        &mut self,
        answered: &Answered,
        acts: &Actions,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        let Self { io, delivery } = self;
        let io = io.as_mut().expect("live writer");
        let ledger = &mut delivery.as_mut().expect("live delivery owner").ledger;
        let written = {
            let mut giving = ledger.give(&answered.checked, |index| {
                answered.spans[index].map_or(&[][..], |span| acts.bytes(span))
            });
            let pieces = std::mem::take(&mut giving.pieces);
            tokio::time::timeout_at(deadline, async {
                for piece in pieces {
                    let mut rest = piece;
                    while !rest.is_empty() {
                        let took = io.write(rest).await?;
                        if took == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                        giving.took(took);
                        rest = &rest[took..];
                    }
                }
                Ok(())
            })
            .await
            .unwrap_or_else(|_| Err(timed_out()))
        };
        if written.is_err() {
            // The rest of the run is never given; the session wipes its buffer.
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

    /// The answer's run goes out, flushed: [`Self::write_out`] then [`Self::flush`].
    pub(super) async fn deliver(
        &mut self,
        answered: &Answered,
        acts: &Actions,
        deadline: tokio::time::Instant,
    ) -> io::Result<()> {
        self.write_out(answered, acts, deadline).await?;
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
