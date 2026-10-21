// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM LEG OF A HELD SESSION (ARCHITECT rulings, row 132, "pairing"): the connection
//! table's composed open over a datagram framer's need, for the unit its walk serves
//! (`OpenDesc::unit`), whose caller leg the root registered under that unit key
//! ([`crate::Connector::pair`]).
//!
//! The open runs under the one egress walk, in this order: the dialling association begins and
//! answers its own description; ONE exchange carries it as its body to the walk's target, over the
//! framer that serves the target's scheme, with the walk's auth fields and member, judged and
//! pinned as every dial is ([`crate::Connector`]'s dial); the far end's head is the reader's, as any
//! answer's is. A success answer's body is the far end's description: it settles the association
//! (every candidate it advertises judged before any byte goes there), the upstream's lines must
//! mirror the caller's, and the leg is attached to the session's [`Pairing`]; from then on a read
//! is the leg's channel messages and a write goes to its channel. Any other answer is relayed whole
//! as the far end's status and nothing is attached: no partial bridge survives a failed open.
//!
//! The whole composed open is bounded by the open's `timeout_ms`: an association not keyed by then
//! answers [`ConnError::Timeout`]. A failed association fails the read; the session's end closes
//! the pairing, which closes both legs once.

use std::collections::VecDeque;
use std::future::Future as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use busbar_contract::conn::{ConnError, Piece, PieceKind};
use busbar_contract::ids::StreamId;

use crate::datagram::{Across, DatagramFraming, Leg, LegSink, Pairing};
use crate::framer::Got;
use crate::udp::{ReadyPort, MAX_DATAGRAM};

/// The most datagrams one drive reads before it yields.
const READS_PER_DRIVE: usize = 256;
/// The channel messages a leg holds for a reader that has not read them, at which it stops
/// draining its port (back-pressure: the far end's own reliability holds what it sent until the
/// reader catches up); a message the association already yielded is never dropped.
const MAX_READY: usize = 1024;
/// The most bytes of the far end's description the open buffers before its end.
const MAX_DESCRIPTION: usize = 64 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Take the next channel message a reader has not read into `buf`: how many bytes, and whether
/// they end the message. The rest of a message longer than `buf` stays first in line.
pub(crate) fn take_ready(
    ready: &Mutex<VecDeque<(Vec<u8>, bool)>>,
    buf: &mut [u8],
) -> Option<(usize, bool)> {
    // The lock is let go before the rest is put back: held through an `if let`, the put-back's
    // second lock on the same thread would never be granted.
    let next = lock(ready).pop_front();
    let (bytes, end) = next?;
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    if n < bytes.len() {
        lock(ready).push_front((bytes[n..].to_vec(), end));
    }
    Some((n, end && n == bytes.len()))
}

/// Where the composed open stands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The exchange is in flight: `ok` once its head said whether it succeeded; the body so far.
    Exchanging { ok: Option<bool>, answer: Vec<u8> },
    /// The far end answered and the leg is attached: reads are its channel messages.
    Running,
    /// The leg is over.
    Over,
}

/// The upstream association and its own port: the [`LegSink`] the caller's line frames cross into.
pub(crate) struct UpstreamLeg {
    framing: Mutex<Option<DatagramFraming>>,
    port: ReadyPort,
    /// Channel messages for the reader: the bytes and whether they end the message.
    ready: Mutex<VecDeque<(Vec<u8>, bool)>>,
    /// The channel stream a write goes to: the first channel the leg named.
    channel: Mutex<Option<u64>>,
    /// The read buffer one drive reads datagrams into.
    recv: Mutex<Vec<u8>>,
    timer: Mutex<Option<Pin<Box<tokio::time::Sleep>>>>,
}

impl UpstreamLeg {
    /// Send what the association owes the port; a send that would block drops the datagram.
    fn flush(&self, f: &mut DatagramFraming) {
        while let Some((to, d)) = f.poll_send() {
            let _ = self.port.send_to(&d, to);
        }
    }

    /// Take what the leg's association yielded through the pairing: line frames go across, the
    /// channel heads name the write channel, the channel messages wait for the reader, every one
    /// of them, an empty message as an empty message. A channel's end is no message; a channel
    /// that FAILED fails the leg (its reason is never the reader's payload).
    ///
    /// # Errors
    ///
    /// [`ConnError::Fault`]: a channel of the leg failed.
    fn take(&self, pairing: &Pairing, pieces: Vec<Got>, now: Instant) -> Result<(), ConnError> {
        for g in pairing.sort(Leg::Upstream, pieces, now) {
            if g.fields {
                lock(&self.channel).get_or_insert(g.stream);
                continue;
            }
            if g.failed && g.stream != 0 {
                return Err(ConnError::Fault);
            }
            if g.stream == 0 || g.ends_stream() {
                continue;
            }
            lock(&self.ready).push_back((g.bytes, g.end_of_frame));
        }
        Ok(())
    }

    /// Read every datagram waiting on the port, keep the association's clock, flush, and arm the
    /// next wake. `Err` once the association failed or was closed.
    fn drive(
        &self,
        pairing: &Pairing,
        cx: &mut Context<'_>,
        due: Option<Instant>,
    ) -> Result<(), ConnError> {
        let now = Instant::now();
        let mut pieces = Vec::new();
        {
            let mut held = lock(&self.framing);
            let f = held.as_mut().ok_or(ConnError::Closed)?;
            let mut buf = lock(&self.recv);
            // BACK-PRESSURE: at the queue's bound the port is not drained; the reader's next read
            // takes a message and drives again.
            let room = MAX_READY.saturating_sub(lock(&self.ready).len());
            for _ in 0..READS_PER_DRIVE {
                if pieces.len() >= room {
                    break;
                }
                match self.port.poll_recv_from(cx, &mut buf) {
                    Poll::Ready(Ok((n, from))) => {
                        let y = f
                            .datagram(from, &buf[..n], now)
                            .map_err(|_| ConnError::Fault)?;
                        pieces.extend(y.pieces);
                    }
                    // A per-datagram error (an unreachable far end reported back): the port stands.
                    Poll::Ready(Err(_)) => {}
                    Poll::Pending => break,
                }
            }
            if f.deadline().is_some_and(|d| d <= now) {
                let y = f.timeout(now).map_err(|_| ConnError::Fault)?;
                pieces.extend(y.pieces);
            }
            self.flush(f);
            let wake = [f.deadline(), due.filter(|_| !f.presented())]
                .into_iter()
                .flatten()
                .min();
            let mut timer = lock(&self.timer);
            match wake {
                Some(at) => {
                    let _entered = crate::io::enter_process_runtime();
                    if tokio::runtime::Handle::try_current().is_ok() {
                        let at = tokio::time::Instant::from_std(at);
                        let t = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
                        t.as_mut().reset(at);
                        if t.as_mut().poll(cx).is_ready() {
                            cx.waker().wake_by_ref();
                        }
                    }
                }
                None => *timer = None,
            }
        }
        self.take(pairing, pieces, now)
    }
}

impl LegSink for UpstreamLeg {
    fn line(&self, across: Across, now: Instant) {
        let mut held = lock(&self.framing);
        let Some(f) = held.as_mut() else {
            return;
        };
        // A line frame's emit yields no channel message the reader waits on; a failed emit drops
        // the frame (a line is never queued) and the next read meets the failure.
        let _ = f.emit(
            across.stream,
            &across.bytes,
            across.end_of_frame,
            false,
            now,
        );
        self.flush(f);
    }

    fn close(&self) {
        // Dropping the association finishes its framing.
        drop(lock(&self.framing).take());
        lock(&self.ready).clear();
    }
}

/// A held session's upstream leg, as the connection table holds it.
pub(crate) struct Dialled {
    leg: Arc<UpstreamLeg>,
    pairing: Arc<Pairing>,
    phase: Mutex<Phase>,
    /// The composed open's bound: the association must be keyed by then.
    due: Option<Instant>,
    /// A message being written, gathered until its end.
    gather: Mutex<Vec<u8>>,
}

impl Dialled {
    /// The leg over `framing` (begun, its description sent as the exchange's body) on `port`, for
    /// `pairing`, bounded by `due`.
    pub(crate) fn new(
        framing: DatagramFraming,
        port: ReadyPort,
        pairing: Arc<Pairing>,
        due: Option<Instant>,
    ) -> Self {
        Dialled {
            leg: Arc::new(UpstreamLeg {
                framing: Mutex::new(Some(framing)),
                port,
                ready: Mutex::new(VecDeque::new()),
                channel: Mutex::new(None),
                recv: Mutex::new(vec![0_u8; MAX_DATAGRAM]),
                timer: Mutex::new(None),
            }),
            pairing,
            phase: Mutex::new(Phase::Exchanging {
                ok: None,
                answer: Vec::new(),
            }),
            due,
            gather: Mutex::new(Vec::new()),
        }
    }

    /// Whether the exchange is still in flight (its pieces are read off the exchange's line).
    pub(crate) fn exchanging(&self) -> bool {
        matches!(*lock(&self.phase), Phase::Exchanging { .. })
    }

    /// One piece the exchange answered, judged: `Some(piece)` for the reader, `None` when the
    /// piece was the host's (the far end's description) and the reader reads on.
    ///
    /// # Errors
    ///
    /// A description that does not settle the association, or lines that do not mirror the
    /// caller's: the open fails and nothing is attached.
    pub(crate) fn exchanged(&self, piece: Piece, bytes: &[u8]) -> Result<Option<Piece>, ConnError> {
        let mut phase = lock(&self.phase);
        let Phase::Exchanging { ok, answer } = &mut *phase else {
            return Ok(Some(piece));
        };
        match (piece.kind, *ok) {
            // The head is the reader's: it carries the far end's status, as any answer's does.
            (PieceKind::Fields, None) => {
                if piece.status.is_some() || piece.end {
                    *ok = Some(
                        piece.status
                            == Some(busbar_contract::transport::wire::WireStatusClass::Success),
                    );
                }
                Ok(Some(piece))
            }
            // A refused exchange is relayed whole: the dialect renders the far end's status.
            (_, Some(false)) => {
                if piece.kind == PieceKind::Completion {
                    *phase = Phase::Over;
                    drop(phase);
                    self.pairing.close();
                }
                Ok(Some(piece))
            }
            (PieceKind::Body, Some(true)) => {
                if answer.len().saturating_add(bytes.len()) > MAX_DESCRIPTION {
                    // Past its bound the description settles nothing: the open fails, and
                    // nothing is attached.
                    *phase = Phase::Over;
                    drop(phase);
                    self.pairing.close();
                    self.leg.close();
                    return Err(ConnError::Refused);
                }
                answer.extend_from_slice(bytes);
                Ok(None)
            }
            (PieceKind::Completion, Some(true)) => {
                let description = std::mem::take(answer);
                *phase = Phase::Over;
                drop(phase);
                self.settle(&description)?;
                *lock(&self.phase) = Phase::Running;
                Ok(None)
            }
            _ => Ok(Some(piece)),
        }
    }

    /// The far end's description settles the association; its lines must mirror the caller's.
    fn settle(&self, description: &[u8]) -> Result<(), ConnError> {
        let now = Instant::now();
        let pieces = {
            let mut held = lock(&self.leg.framing);
            let f = held.as_mut().ok_or(ConnError::Closed)?;
            let y = f
                .rendezvous(description, now)
                .map_err(|_| ConnError::Fault)?;
            self.leg.flush(f);
            y.pieces
        };
        self.leg.take(&self.pairing, pieces, now)?;
        let leg: Arc<dyn LegSink> = Arc::clone(&self.leg) as Arc<dyn LegSink>;
        if self.pairing.attach(leg).is_err() {
            self.leg.close();
            self.pairing.close();
            return Err(ConnError::Refused);
        }
        Ok(())
    }

    /// A read once the leg runs: the next channel message, or Pending with `waker` woken when the
    /// port or the clock has more.
    ///
    /// # Errors
    ///
    /// The leg closed, its association failed, or it was not keyed within the open's bound.
    pub(crate) fn read(&self, waker: &Waker, buf: &mut [u8]) -> Result<Piece, ConnError> {
        if *lock(&self.phase) == Phase::Over {
            return Err(ConnError::Closed);
        }
        let mut cx = Context::from_waker(waker);
        loop {
            if let Some((n, end)) = take_ready(&self.leg.ready, buf) {
                return Ok(Piece {
                    kind: PieceKind::Body,
                    stream: StreamId(0),
                    len: n,
                    end,
                    status: None,
                    status_code: None,
                    status_namespace: None,
                    retry_after_secs: None,
                    fault: None,
                    reason: None,
                    declared_len: None,
                });
            }
            let keyed = lock(&self.leg.framing)
                .as_ref()
                .is_some_and(DatagramFraming::presented);
            if !keyed && self.due.is_some_and(|d| Instant::now() >= d) {
                return Err(ConnError::Timeout);
            }
            if let Err(e) = self.leg.drive(&self.pairing, &mut cx, self.due) {
                *lock(&self.phase) = Phase::Over;
                self.pairing.close();
                return Err(e);
            }
            if lock(&self.leg.ready).is_empty() {
                return Err(ConnError::Pending);
            }
        }
    }

    /// A write once the leg runs: gathered until `end`, then one message on the leg's channel.
    ///
    /// # Errors
    ///
    /// The leg is not running yet ([`ConnError::Pending`]), or it closed, or names no channel.
    pub(crate) fn write(&self, bytes: &[u8], end: bool, text: bool) -> Result<usize, ConnError> {
        match &*lock(&self.phase) {
            Phase::Running => {}
            Phase::Exchanging { .. } => return Err(ConnError::Pending),
            Phase::Over => return Err(ConnError::Closed),
        }
        let mut gather = lock(&self.gather);
        // A message is bounded as a write is (THE DESIGN §5, writes are back-pressured): one
        // gathered past the bound is refused, and what was gathered of it is let go.
        if gather.len().saturating_add(bytes.len()) > crate::compose::WRITE_BUFFER_BYTES {
            gather.clear();
            return Err(ConnError::Refused);
        }
        gather.extend_from_slice(bytes);
        if !end {
            return Ok(bytes.len());
        }
        let message = std::mem::take(&mut *gather);
        drop(gather);
        let stream = (*lock(&self.leg.channel)).ok_or(ConnError::Pending)?;
        let now = Instant::now();
        let pieces = {
            let mut held = lock(&self.leg.framing);
            let f = held.as_mut().ok_or(ConnError::Closed)?;
            let y = f
                .emit(stream, &message, true, text, now)
                .map_err(|_| ConnError::Fault)?;
            self.leg.flush(f);
            y.pieces
        };
        self.leg.take(&self.pairing, pieces, now)?;
        Ok(bytes.len())
    }

    /// Whether a read would answer now (a message waits, or the leg is over).
    pub(crate) fn ready(&self, waker: &Waker) -> bool {
        if !lock(&self.leg.ready).is_empty() || *lock(&self.phase) == Phase::Over {
            return true;
        }
        if self.exchanging() {
            return false;
        }
        let mut cx = Context::from_waker(waker);
        self.leg.drive(&self.pairing, &mut cx, self.due).is_err()
            || !lock(&self.leg.ready).is_empty()
    }

    /// The session's connection closed: the pairing closes, and with it both legs, once.
    pub(crate) fn close(&self) {
        *lock(&self.phase) = Phase::Over;
        self.pairing.close();
        self.leg.close();
    }
}

/// THE EXCHANGE BODY OF A COMPOSED OPEN (row 132, the ARCHITECT ticket ruling, item 4): what goes
/// to the far end beside the dialling association's own `description`.
///
/// - An open with no body sends the description as the whole body.
/// - An open with a body states its head's `content-type` as `multipart/form-data` with a
///   `boundary`, and its body is the form's leading parts, ending with the opened header block of
///   the part that carries the description. The exchange body is that body, the description, and
///   the form's closing delimiter.
///
/// The connector frames the form and names no part: the opener's body names them.
///
/// # Errors
///
/// [`ConnError::Refused`] for a body under any other content type, a form with no boundary, or a
/// description that holds the form's delimiter.
pub(crate) fn composed_body(
    fields: &[(&str, &[u8])],
    body: &[u8],
    description: &[u8],
) -> Result<Vec<u8>, ConnError> {
    if body.is_empty() {
        return Ok(description.to_vec());
    }
    let boundary = fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
        .and_then(form_boundary)
        .ok_or(ConnError::Refused)?;
    let delimiter = [b"\r\n--", boundary.as_bytes()].concat();
    if description
        .windows(delimiter.len())
        .any(|w| w == delimiter.as_slice())
    {
        return Err(ConnError::Refused);
    }
    Ok([body, description, &delimiter, b"--\r\n"].concat())
}

/// The `boundary` of a `multipart/form-data` content type (RFC 7578, RFC 2046 section 5.1.1),
/// unquoted; `None` for any other content type, or one with no usable boundary.
fn form_boundary(content_type: &str) -> Option<String> {
    let mut params = content_type.split(';');
    if !params
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    let boundary = params.find_map(|p| {
        let (name, value) = p.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| value.trim().trim_matches('"').to_string())
    })?;
    // RFC 2046: 1 to 70 characters from the boundary alphabet.
    let fits = (1..=70).contains(&boundary.len())
        && boundary
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b));
    fits.then_some(boundary)
}

#[cfg(test)]
#[path = "tests/dialled_compose_tests.rs"]
mod compose_tests;

#[cfg(test)]
#[path = "tests/dialled_tests.rs"]
mod tests;
