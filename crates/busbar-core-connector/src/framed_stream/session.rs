// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE MIN-3 TRANSPORT SESSION, DRIVEN BY THE ONE TASK THAT OWNS IT (IF §8.7, §11.3, §12.22, §13).
//!
//! A framer is a transport instance's `TransportPort`; one `TransportSession` frames one connection. Core
//! owns the socket: [`drive`] reads it and hands the bytes to `ingest`, sends core's pieces with `emit`,
//! calls `timer` at the WAKE_AT the framer asked for, obeys PAUSE/RESUME, and hands an UPGRADE back to its
//! caller with the connection. What the connector owes the framer beyond that, and checks here:
//!
//! * **The answer grammar the adapter cannot judge** (§11.3, charged to C1): STREAM_FULL only in an `emit`
//!   answer and only for that emit's stream (or the stream its STREAM_OPENED names); STREAM_WRITABLE only in
//!   an `ingest` or `timer` answer; an `emit(E_CLOSE)` answer is WRITE* then at most one CLOSE; a ROLE_CLIENT
//!   `emit(0, E_HEAD)` answers STREAM_OPENED; datagram answers have no place in a byte-stream session. A
//!   breach charges the instance (`Instance::charge`: quarantine, audit `plugin_fault`) and ends the session.
//! * **The per-stream `held` bit** (round 16): STREAM_FULL holds the stream and arms its stall deadline
//!   (`limits.stream_stall_ms`, [`super::StreamHolds`]); while held, core calls no `emit` for it and pulls
//!   nothing from the feed behind it, while its siblings flow; STREAM_WRITABLE or the stream's end releases
//!   it; at the deadline core calls `emit(stream, E_RESET, RESET_STALLED)`, ends the feed as for a peer reset
//!   and counts `transport_stream_stalled_total`.
//! * **Core's own refusals** (round 9): a stream core ends with no plane able to render it is
//!   `emit(stream, E_REFUSE, status | E_REFUSE_HEAD_SENT?, core text)`; the framer maps it to its wire.
//! * **Core's own close** (round 16): when core ends a live session (drain, revoke, timeout, capacity, a
//!   violation, done) it calls `emit(0, E_CLOSE, CR_*)` exactly once, writes the answer under the write
//!   timeout (the shutdown grace for CR_DRAIN), applies its CLOSE (absent = graceful), and only then drops the
//!   handle; never after the framer answered CLOSE, after EOF, after a socket failure, or to a quarantined
//!   instance (counted instead).
//! * **ALPN by role** (round 9): a listener serving an instance advertises its `alpn(ROLE_SERVER)`, a dial through it offers its `alpn(ROLE_CLIENT)`; never one list for
//!   both.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::outbound::delivery::Reason;
use crate::outbound::records::{self, Out};
use crate::outbound::wire::Fault;
use crate::response_delivery::{DeliveryControl, DeliveryLedger, ResponseHandles};
use busbar_contract::response_delivery::{CarrierProgressReader, ResponseKey, ResponseStop};
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::records::RecErr;
use busbar_plugin_abi::transport as wire;
use busbar_ports::transport::{ConnIn, EmitParts, TransportOut, TransportPort, TransportSession};
use busbar_ports::PortError;
use foldhash::HashMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::StreamHolds;

#[path = "session_delivery.rs"]
mod delivery;
#[path = "session_storage.rs"]
mod storage;
pub use delivery::Delivery;
use delivery::DeliveryIo;
pub use storage::{Name, Payload, Span};

/// A complete callback answer whose backing charge follows its consumer: what it asks of core, in order,
/// and the socket bytes its WIRE_PART records name, held in the session's one output buffer.
/// Both are the session's own, kept across answers and always cleared together, so no span outlives
/// the bytes it names.
#[derive(Debug)]
pub struct Actions {
    items: storage::Items<Act>,
    out: storage::Output,
}

impl Actions {
    pub(crate) fn new(
        source: &busbar_contract::storage::StorageSource,
    ) -> Result<Self, busbar_contract::storage::StorageDenied> {
        Ok(Self {
            items: storage::Items::new(source)?,
            out: storage::Output::new(source)?,
        })
    }

    /// An action that carries no socket bytes (those go through [`Self::part`]).
    pub(crate) fn push(&mut self, act: Act) -> Result<(), busbar_contract::storage::StorageDenied> {
        debug_assert!(!matches!(act, Act::WirePart { .. }));
        self.items.push(act)
    }

    /// WIRE_PART: the borrowed bytes appended to the output buffer, the action naming them (their
    /// stream and their class, [`records::WIRE_PAYLOAD`] or [`records::WIRE_CONTROL`]) pushed.
    pub(crate) fn part(
        &mut self,
        stream: u64,
        class: u32,
        bytes: &[u8],
    ) -> Result<(), busbar_contract::storage::StorageDenied> {
        let bytes = self.out.append(bytes)?;
        self.items.push(Act::WirePart {
            stream,
            class,
            bytes,
        })
    }

    /// Every action goes and every byte held is wiped.
    pub(crate) fn clear(&mut self) {
        self.items.clear();
        self.out.clear();
    }

    pub(crate) fn last_mut(&mut self) -> Option<&mut Act> {
        self.items.last_mut()
    }

    /// The socket bytes were handed to the connection's queue: this copy of them is wiped now, and
    /// the actions stay to be taken in order.
    fn handed_over(&mut self) {
        self.out.clear();
    }

    /// The actions, taken out in order. Their socket bytes were queued for the connection by the
    /// delivery driver already; the caller clears the buffer when it is done, however it stops.
    fn drain(&mut self) -> std::vec::Drain<'_, Act> {
        self.items.drain()
    }

    /// Read the captured actions in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Act] {
        self.items.as_slice()
    }

    /// The bytes a WIRE_PART's span names.
    #[must_use]
    pub fn bytes(&self, span: Span) -> &[u8] {
        self.out.unwritten(span)
    }
}

impl std::ops::Deref for Actions {
    type Target = [Act];
    fn deref(&self) -> &[Act] {
        self.as_slice()
    }
}

/// A breach of the per-call answer grammar (count, order, place): `RecErr::Size`, as the adapter's own
/// grammar breaches are.
const GRAMMAR: FaultReason = FaultReason::BadRecords(RecErr::Size);

/// The bytes one socket read takes while a burst of input is arriving.
const READ_CHUNK: usize = 16 * 1024;

/// The bytes the session task holds in itself for a read when no burst buffer is made: a small request
/// fits whole, so a connection waiting for its first byte, or between requests, holds no heap block.
const FIRST_READ: usize = 512;

/// The neutral status core refuses a stream with when the feed behind it ends before the stream does.
const FEED_GONE_STATUS: u32 = 500;

/// The text that refusal carries (core text, never plugin text, I2).
const FEED_GONE_TEXT: &str = "the exchange feeding this stream ended before the stream did";

/// What one transport answer asks of core, owned: a `TransportOut` borrows the framer's buffer, and the
/// session task acts on it only after the call returned. Socket bytes are copied into the session's one
/// output buffer ([`Actions`]) and named by a [`Span`]; bytes for the plane keep their own [`Payload`].
///
/// THE ONE OUTPUT MODEL (transport 2.0): the only record that carries connection bytes is
/// [`Act::WirePart`]. There is no plain write, no abort or quiescent fact, no pause or resume: a
/// failed stream is its [`Act::WireEnd`], and the engine stops reading the connection itself.
#[derive(Debug)]
pub enum Act {
    /// SESSION: what `begin` states the session is (whether it carries several streams at once, and
    /// the windows it then holds the engine's inbound body to).
    Session(records::Session),
    /// STREAM_BUSY: the head of an `emit(0, E_HEAD)` was not taken; nothing opened, nothing written.
    Busy,
    /// NO_NEW_STREAMS: the far end is closing; open streams finish, none may open.
    NoNewStreams,
    /// WIRE_PART: bytes for the connection, in order, held in the session's charged output buffer.
    WirePart {
        /// The stream the bytes belong to; 0 is the connection itself.
        stream: u64,
        /// [`records::WIRE_PAYLOAD`] or [`records::WIRE_CONTROL`].
        class: u32,
        /// The bytes.
        bytes: Span,
    },
    /// WIRE_SEALED: the engine writes these bytes of a sealed value here (a dialled request's head).
    WireSealed(records::WireSealed),
    /// WIRE_END: nothing more will name this stream.
    WireEnd {
        /// The stream whose output ended.
        stream: u64,
        /// END_FLUSH, END_SHUTDOWN or END_FAILED.
        how: u32,
        /// END_NO_BODY or 0 on a successful end; an opaque diagnostic on END_FAILED.
        arg: u32,
    },
    /// CLOSE: close the connection (`abort` = without flushing).
    Close {
        /// CLOSE_ABORT rather than CLOSE_GRACEFUL.
        abort: bool,
    },
    /// WAKE_AT: call `timer` at this host `mono` time (nanoseconds).
    Wake(u64),
    /// UPGRADE + LEFTOVER: hand the connection to `protocol`'s transport with the bytes read past the head.
    Upgrade {
        /// The protocol named (e.g. `websocket`).
        protocol: Name,
        /// The bytes the framer read past the head.
        leftover: Payload,
    },
    /// STREAM_HEAD: a stream's head records.
    Head {
        /// The stream.
        stream: u64,
        /// SH_END_STREAM: no body follows.
        end_stream: bool,
        /// The nested head records, as written.
        head: Payload,
    },
    /// STREAM_BODY.
    Body {
        /// The stream.
        stream: u64,
        /// MSG_* for a message stream, 0 for a byte stream.
        flags: u32,
        /// The body bytes.
        bytes: Payload,
    },
    /// STREAM_END.
    End(u64),
    /// STREAM_RESET: the far end reset the stream.
    Reset {
        /// The stream.
        stream: u64,
        /// The wire's code.
        code: u32,
        /// [`records::RESET_NOT_PROCESSED`] when the far end states it did not act on the stream.
        flags: u32,
    },
    /// STREAM_TRAILERS.
    Trailers {
        /// The stream.
        stream: u64,
        /// The PAIR records, as written.
        pairs: Payload,
    },
    /// STREAM_OPENED: the id the framer gave the stream a ROLE_CLIENT `emit(0, E_HEAD)` opened.
    Opened(u64),
    /// STREAM_FULL, accepted: the stream is held.
    Full(u64),
    /// STREAM_WRITABLE for a held stream: it is released.
    Writable(u64),
}

impl Act {
    /// The item the delivery driver reads for this act, and where its bytes are. Heads, trailers,
    /// timers, upgrades and flow records are not the driver's.
    pub(crate) fn driven(&self) -> Option<(Out, Option<Span>)> {
        Some(match self {
            Self::Session(session) => (Out::Session(*session), None),
            Self::Opened(stream) => (Out::Opened(*stream), None),
            Self::Busy => (Out::Busy, None),
            Self::NoNewStreams => (Out::NoNewStreams, None),
            Self::WirePart {
                stream,
                class,
                bytes,
            } => (
                Out::Part {
                    part: records::WirePart {
                        stream: *stream,
                        class: *class,
                        _r: 0,
                    },
                    // A part past the record's own bound is no part of this model: the driver reads
                    // the zero as L1.
                    len: u32::try_from(bytes.len()).unwrap_or(0),
                },
                Some(*bytes),
            ),
            Self::WireSealed(sealed) => (Out::Sealed(*sealed), None),
            Self::WireEnd { stream, how, arg } => (
                Out::End(records::WireEnd {
                    stream: *stream,
                    how: *how,
                    arg: *arg,
                }),
                None,
            ),
            Self::Body { stream, bytes, .. } => (
                Out::Body {
                    stream: *stream,
                    len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
                },
                None,
            ),
            Self::End(stream) => (Out::Ended(*stream), None),
            Self::Reset {
                stream,
                code,
                flags,
            } => (
                Out::Reset(records::StreamReset {
                    stream: *stream,
                    code: *code,
                    flags: *flags,
                }),
                None,
            ),
            Self::Close { .. } => (Out::Close, None),
            Self::Wake(_)
            | Self::Upgrade { .. }
            | Self::Head { .. }
            | Self::Trailers { .. }
            | Self::Full(_)
            | Self::Writable(_) => return None,
        })
    }
}

/// The call an answer is the answer to, as far as its grammar depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Called {
    Begin,
    Ingest,
    /// `emit` on `stream` (0 for a ROLE_CLIENT E_HEAD that opens one), with its piece.
    Emit {
        stream: u64,
        piece: u32,
    },
    Timer,
    /// `emit(0, E_CLOSE, ..)`.
    Close,
}

/// The connector's side of the answer grammar and of the held streams, with no port in it: every
/// `TransportOut` of one call goes through [`Answers::take`], then [`Answers::finish`] judges the whole
/// answer and returns what it asks of core.
pub(crate) struct Answers {
    holds: StreamHolds,
    called: Called,
    now: Instant,
    acts: Actions,
    source: busbar_contract::storage::StorageSource,
    capacity_failed: bool,
    /// `begin`'s answer stated the session (SESSION, once).
    stated: bool,
    /// This answer is STREAM_BUSY: the head was not taken.
    busy: bool,
    /// STREAM_FULL streams of this answer, judged at its end (STREAM_OPENED may come later in it).
    full: FullStreams,
    opened: Option<u64>,
    /// An `emit(E_CLOSE)` answer already carried its CLOSE.
    closing: bool,
    broke: Option<FaultReason>,
    /// The answers of one gathered turn (a stall's resets, then a due timer) go into the one array: the
    /// next answer's start keeps what is there.
    gathering: bool,
    /// This answer carried a CLOSE (kept as the CLOSE is taken, so the judgement reads no list).
    closed: bool,
}

/// The STREAM_FULL streams one answer named, as far as the answer's judgement needs them: whether there
/// was one, the first, and whether any other differed from it (no list is kept).
#[derive(Default)]
struct FullStreams {
    first: Option<u64>,
    mixed: bool,
}

impl FullStreams {
    fn push(&mut self, stream: u64) {
        match self.first {
            None => self.first = Some(stream),
            Some(first) => self.mixed |= first != stream,
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    /// Whether any stream named is not `mine`.
    fn any_but(&self, mine: Option<u64>) -> bool {
        self.mixed || self.first.is_some_and(|first| Some(first) != mine)
    }
}

impl Answers {
    fn with_source(
        stall_ms: Option<u32>,
        now: Instant,
        source: busbar_contract::storage::StorageSource,
    ) -> Result<Self, busbar_contract::storage::StorageDenied> {
        Ok(Self {
            holds: StreamHolds::new(stall_ms),
            called: Called::Begin,
            now,
            acts: Actions::new(&source)?,
            full: FullStreams::default(),
            source,
            capacity_failed: false,
            stated: false,
            busy: false,
            opened: None,
            closing: false,
            broke: None,
            gathering: false,
            closed: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(stall_ms: Option<u32>, now: Instant) -> Self {
        use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
        Self::with_source(
            stall_ms,
            now,
            ProcessAdmission::new(1).connection_storage(AdmissionClass::Data),
        )
        .expect("test source")
    }

    /// The next answer is `called`'s, at `now`.
    pub(crate) fn start(&mut self, called: Called, now: Instant) {
        self.called = called;
        self.now = now;
        if !self.gathering {
            self.acts.clear();
        }
        self.closed = false;
        self.full.clear();
        self.opened = None;
        self.busy = false;
        self.closing = false;
        self.broke = None;
        self.capacity_failed = false;
    }

    fn breach(&mut self) {
        self.broke.get_or_insert(GRAMMAR);
    }

    /// One record of the answer, in order. After a breach the rest is ignored.
    pub(crate) fn take(&mut self, out: &TransportOut<'_>) {
        if self.capture(out).is_err() {
            self.capacity_failed = true;
        }
    }

    fn capture(
        &mut self,
        out: &TransportOut<'_>,
    ) -> Result<(), busbar_contract::storage::StorageDenied> {
        if self.broke.is_some() || self.capacity_failed {
            return Ok(());
        }
        if self.called == Called::Close {
            // The E_CLOSE answer grammar: parts (and the end marks of the streams the close ends),
            // then at most one CLOSE, and nothing after it.
            match *out {
                TransportOut::WirePart {
                    stream,
                    payload,
                    bytes,
                } if !self.closing => self.acts.part(
                    stream,
                    records::WirePart::stated(stream, payload).class,
                    bytes,
                )?,
                TransportOut::WireEnd { stream, how, arg } if !self.closing => {
                    self.acts.push(Act::WireEnd { stream, how, arg })?;
                }
                TransportOut::Close { abort } if !self.closing => {
                    self.closing = true;
                    self.acts.push(Act::Close { abort })?;
                    self.closed = true;
                }
                _ => self.breach(),
            }
            return Ok(());
        }
        match *out {
            TransportOut::WirePart {
                stream,
                payload,
                bytes,
            } => self.acts.part(
                stream,
                records::WirePart::stated(stream, payload).class,
                bytes,
            )?,
            TransportOut::WireSealed {
                stream,
                slot,
                offset,
                len,
            } => self.acts.push(Act::WireSealed(records::WireSealed::stated(
                stream, slot, offset, len,
            )))?,
            TransportOut::WireEnd { stream, how, arg } => {
                self.acts.push(Act::WireEnd { stream, how, arg })?;
            }
            // SESSION is `begin`'s statement and nothing else's, exactly once.
            TransportOut::Session {
                multiplex,
                stream_window,
                conn_window,
            } => {
                if self.called == Called::Begin && !self.stated {
                    self.stated = true;
                    self.acts.push(Act::Session(records::Session::stated(
                        multiplex,
                        stream_window,
                        conn_window,
                    )))?;
                } else {
                    self.breach();
                }
            }
            // STREAM_BUSY answers an `emit` whose pieces include E_HEAD on stream 0, alone (the
            // driver checks "alone").
            TransportOut::StreamBusy => match self.called {
                Called::Emit { stream: 0, piece }
                    if piece & wire::E_HEAD != 0 && !self.busy && self.opened.is_none() =>
                {
                    self.busy = true;
                    self.acts.push(Act::Busy)?;
                }
                _ => self.breach(),
            },
            TransportOut::NoNewStreams => self.acts.push(Act::NoNewStreams)?,
            TransportOut::Close { abort } => {
                self.acts.push(Act::Close { abort })?;
                self.closed = true;
            }
            TransportOut::WakeAt(ns) => self.acts.push(Act::Wake(ns))?,
            TransportOut::Upgrade { protocol } => self.acts.push(Act::Upgrade {
                protocol: Name::copy(&self.source, protocol)?,
                leftover: Payload::copy(&self.source, &[])?,
            })?,
            TransportOut::Leftover(bytes) => match self.acts.last_mut() {
                Some(Act::Upgrade { leftover, .. }) => leftover.append(bytes)?,
                _ => self.breach(),
            },
            TransportOut::StreamHead {
                stream,
                end_stream,
                head,
            } => self.acts.push(Act::Head {
                stream,
                end_stream,
                head: Payload::copy(&self.source, head.rest())?,
            })?,
            TransportOut::StreamBody {
                stream,
                flags,
                bytes,
            } => self.acts.push(Act::Body {
                stream,
                flags,
                bytes: Payload::copy(&self.source, bytes)?,
            })?,
            TransportOut::StreamEnd(stream) => self.acts.push(Act::End(stream))?,
            TransportOut::StreamReset {
                stream,
                code,
                not_processed,
            } => {
                self.holds.release(stream);
                self.acts.push(Act::Reset {
                    stream,
                    code,
                    flags: records::StreamReset::stated(stream, code, not_processed).flags,
                })?;
            }
            TransportOut::StreamTrailers { stream, pairs } => self.acts.push(Act::Trailers {
                stream,
                pairs: Payload::copy(&self.source, pairs.rest())?,
            })?,
            TransportOut::StreamOpened(stream) => {
                if self.busy || self.opened.replace(stream).is_some() {
                    self.breach();
                } else {
                    self.acts.push(Act::Opened(stream))?;
                }
            }
            TransportOut::StreamFull(stream) => match self.called {
                Called::Emit { piece, .. } if piece != wire::E_CONSUMED => {
                    self.full.push(stream);
                }
                _ => self.breach(),
            },
            TransportOut::StreamWritable(stream) => match self.called {
                Called::Ingest | Called::Timer => {
                    if self.holds.release(stream) {
                        self.acts.push(Act::Writable(stream))?;
                    }
                }
                _ => self.breach(),
            },
            // SEND_TO, SECURE, RENDEZVOUS, ICE_TERMS, ICE_CANDIDATE, PATH_BIND: datagram answers, which a
            // byte-stream session cannot carry.
            _ => self.breach(),
        }
        Ok(())
    }

    /// The whole answer judged: what it asks of core stays in the session's own array, in order; or the breach.
    pub(crate) fn finish(&mut self) -> Result<(), FaultReason> {
        if self.capacity_failed {
            self.acts.clear();
            self.full.clear();
            return Err(GRAMMAR);
        }
        if let Some(reason) = self.broke.take() {
            self.acts.clear();
            self.full.clear();
            return Err(reason);
        }
        // `begin` states the session, exactly once (both roles): the driver reads the windows and
        // whether several streams are carried from it, never from a protocol name.
        if self.called == Called::Begin && !self.stated {
            self.acts.clear();
            self.full.clear();
            return Err(GRAMMAR);
        }
        if let Called::Emit { stream, piece } = self.called {
            // A head on stream 0 is answered STREAM_OPENED, or STREAM_BUSY and nothing held.
            let opens = stream == 0 && piece & wire::E_HEAD != 0;
            if (opens && self.opened.is_none() && !self.busy)
                || (self.busy && !self.full.is_empty())
            {
                self.acts.clear();
                self.full.clear();
                return Err(GRAMMAR);
            }
            let mine = if stream == 0 {
                self.opened
            } else {
                Some(stream)
            };
            if self.full.any_but(mine) {
                self.acts.clear();
                self.full.clear();
                return Err(GRAMMAR);
            }
            let ends = matches!(piece, wire::E_END | wire::E_RESET | wire::E_REFUSE);
            if ends {
                // The stream's end releases it: nothing more is emitted on it.
                self.holds.release(stream);
            } else if let (Some(held), false) = (mine, self.full.is_empty()) {
                self.holds.hold(held, self.now);
                if self.acts.push(Act::Full(held)).is_err() {
                    self.capacity_failed = true;
                    self.acts.clear();
                    return Err(GRAMMAR);
                }
            }
        }
        self.full.clear();
        Ok(())
    }

    pub(crate) fn is_held(&self, stream: u64) -> bool {
        self.holds.is_held(stream)
    }

    pub(crate) fn next_stall(&self) -> Option<Instant> {
        self.holds.next_deadline()
    }

    pub(crate) fn take_stalled(&mut self, now: Instant) -> &[u64] {
        self.holds.take_stalled(now)
    }

    pub(crate) fn stalled(&self) -> &[u64] {
        self.holds.stalled()
    }
}

/// Why a [`TransportConn`] call ended the session (the handle is dropped, which cancels the session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The host's admitted callback storage could not retain the complete answer; no prefix is emitted.
    Capacity,
    /// The framer broke the per-call answer grammar (§11.3): its instance was charged (quarantine, audit
    /// `plugin_fault`).
    Fault(FaultReason),
    /// The call itself failed (REFUSED, FAILED, FAULT, quarantined, deadline): the port's own error.
    Port(PortError),
    /// Core asked for something the session no longer takes (a call after it was over, an `emit` on a held
    /// stream, E_CLOSE through `emit`, a refusal status outside 400..=599): nothing was called.
    Misuse(&'static str),
}

/// Where a session's calls go. Production has the one form, a port and its handle; the tests script the
/// answers (no trait: there is one production implementation).
enum Backend {
    Port {
        port: Arc<dyn TransportPort>,
        handle: TransportSession,
    },
    #[cfg(test)]
    Script(tests::Script),
}

/// One live transport session: the port, its handle, and the connector's checks around every call.
pub struct TransportConn {
    backend: Option<Backend>,
    answers: Answers,
    /// The framer answered CLOSE.
    framer_closed: bool,
    /// EOF was ingested.
    peer_closed: bool,
    /// The socket failed.
    lost: bool,
    /// E_CLOSE was sent; the handle remains owned until its output is flushed or abandoned.
    core_closed: bool,
}

impl std::fmt::Debug for TransportConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConn")
            .field("live", &self.backend.is_some())
            .finish_non_exhaustive()
    }
}

/// A call's port method, with its arguments.
#[derive(Clone, Copy)]
pub(crate) enum Call<'a> {
    Ingest(&'a [u8]),
    Emit {
        stream: u64,
        piece: u32,
        arg: u32,
        /// The bytes of credit an `E_CONSUMED` gives, else 0.
        credit: u64,
        bytes: &'a [u8],
    },
    Timer,
}

impl TransportConn {
    /// The delivery driver refused the answer whole: nothing of it was written. A breach of the
    /// output model charges the instance like every grammar breach and ends the session; the queue's
    /// own refusal (no memory for the run) charges nobody.
    fn reject_output(&mut self, fault: Fault) -> Ended {
        if !fault.charged() {
            self.backend = None;
            return Ended::Capacity;
        }
        tracing::error!(
            fault = ?fault,
            "transport_fault: the session broke a rule of the output model; nothing of that answer is written"
        );
        match self.backend.take() {
            Some(Backend::Port { handle, .. }) => {
                let _ = handle.instance().charge(GRAMMAR);
            }
            #[cfg(test)]
            Some(Backend::Script(script)) => script.charged(GRAMMAR),
            None => {}
        }
        Ended::Fault(GRAMMAR)
    }
    /// The immutable admitted connection account; upgrades retain this origin rather than
    /// constructing another process budget or selecting a class from protocol input.
    #[must_use]
    pub fn storage(&self) -> &busbar_contract::storage::StorageSource {
        &self.answers.source
    }

    /// `begin` the framer's session on a connection (`conn`: role, flags, the negotiated ALPN, SNI, peer,
    /// local, the peer certificate, leftover, head, `mono_ns`), holding streams under `stall_ms`
    /// (`limits.stream_stall_ms`, `None` = the default). `storage` is the original trusted listener
    /// or dial account, required before any callback copy. Returns the session and its funded answer.
    pub fn begin(
        port: Arc<dyn TransportPort>,
        conn: &ConnIn<'_>,
        stall_ms: Option<u32>,
        now: Instant,
        storage: busbar_contract::storage::StorageSource,
    ) -> Result<Self, Ended> {
        let mut answers =
            Answers::with_source(stall_ms, now, storage).map_err(|_| Ended::Capacity)?;
        answers.start(Called::Begin, now);
        let handle = port
            .begin(conn, &mut |out| answers.take(&out))
            .map_err(Ended::Port)?;
        let mut session = Self {
            backend: Some(Backend::Port { port, handle }),
            answers,
            framer_closed: false,
            peer_closed: false,
            lost: false,
            core_closed: false,
        };
        session.judged()?;
        Ok(session)
    }

    #[cfg(test)]
    pub(crate) fn scripted(script: tests::Script, stall_ms: Option<u32>, now: Instant) -> Self {
        Self::scripted_as(script, stall_ms, now, true)
    }

    /// A scripted session has no `begin`: its first actions state what `begin` would have (a session
    /// that carries several streams with the reference windows, or one that carries one stream).
    #[cfg(test)]
    pub(crate) fn scripted_as(
        script: tests::Script,
        stall_ms: Option<u32>,
        now: Instant,
        multiplex: bool,
    ) -> Self {
        let mut answers = Answers::new(stall_ms, now);
        answers.stated = true;
        let session = if multiplex {
            records::Session::stated(true, 1 << 20, 4 << 20)
        } else {
            records::Session::stated(false, 0, 0)
        };
        answers
            .acts
            .push(Act::Session(session))
            .expect("test session");
        Self {
            backend: Some(Backend::Script(script)),
            answers,
            framer_closed: false,
            peer_closed: false,
            lost: false,
            core_closed: false,
        }
    }

    /// The session's own answer array: what the last answer (or a gathered turn) asks of core, until the
    /// driver drains it. It is made with the session, cleared per answer, grown in place, freed with it.
    pub fn actions(&mut self) -> &mut Actions {
        &mut self.answers.acts
    }

    /// Whether the session still takes calls.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.backend.is_some() && !self.framer_closed && !self.lost && !self.core_closed
    }

    /// Whether `stream` is held (core must not `emit` on it, nor pull its feed).
    #[must_use]
    pub fn is_held(&self, stream: u64) -> bool {
        self.answers.is_held(stream)
    }

    /// The soonest stall deadline of a held stream.
    #[must_use]
    pub fn next_stall(&self) -> Option<Instant> {
        self.answers.next_stall()
    }

    /// Bytes read from the connection; empty = EOF (after which core never sends E_CLOSE).
    pub fn ingest(&mut self, bytes: &[u8], now: Instant) -> Result<&mut Actions, Ended> {
        if bytes.is_empty() {
            self.peer_closed = true;
        }
        self.call(Called::Ingest, Call::Ingest(bytes), now)
    }

    /// The WAKE_AT the framer asked for has passed.
    pub fn timer(&mut self, now: Instant) -> Result<&mut Actions, Ended> {
        self.call(Called::Timer, Call::Timer, now)
    }

    /// Core sends `piece` on `stream`: exactly one of E_HEAD, E_BODY, E_TRAILERS, E_END, E_RESET or
    /// E_REFUSE, with its bytes (E_END and E_RESET carry none). A held stream takes only E_RESET and
    /// E_REFUSE, which end it. The port's call takes the piece as a set and one entry per
    /// byte-carrying piece ([`parts_of`]): one piece here is a set of one.
    pub fn emit(
        &mut self,
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: &[u8],
        now: Instant,
    ) -> Result<&mut Actions, Ended> {
        if piece == wire::E_CLOSE {
            return Err(Ended::Misuse("E_CLOSE goes through TransportConn::close"));
        }
        if piece == wire::E_CONSUMED {
            return Err(Ended::Misuse(
                "E_CONSUMED goes through TransportConn::consumed",
            ));
        }
        if !matches!(
            piece,
            wire::E_HEAD
                | wire::E_BODY
                | wire::E_TRAILERS
                | wire::E_END
                | wire::E_RESET
                | wire::E_REFUSE
        ) {
            return Err(Ended::Misuse("an emit of no one piece"));
        }
        if matches!(piece, wire::E_END | wire::E_RESET) && !bytes.is_empty() {
            return Err(Ended::Misuse("an end or a reset carries no bytes"));
        }
        if self.answers.is_held(stream) && !matches!(piece, wire::E_RESET | wire::E_REFUSE) {
            return Err(Ended::Misuse("an emit on a held stream"));
        }
        let call = Call::Emit {
            stream,
            piece,
            arg,
            credit: 0,
            bytes,
        };
        self.call(Called::Emit { stream, piece }, call, now)
    }

    /// The reader of `stream` took `count` inbound body bytes: `emit(stream, E_CONSUMED)` with the
    /// count in the call's `credit`. Only for a session that stated S_MULTIPLEX (the delivery driver
    /// says when, and how much: `Wire::taken`, `Wire::over`); a session with one stream is given no
    /// credit, the engine stops reading its connection instead.
    pub fn consumed(
        &mut self,
        stream: u64,
        count: u64,
        now: Instant,
    ) -> Result<&mut Actions, Ended> {
        if count == 0 {
            return Err(Ended::Misuse("a credit of no bytes"));
        }
        let call = Call::Emit {
            stream,
            piece: wire::E_CONSUMED,
            arg: 0,
            credit: count,
            bytes: &[],
        };
        self.call(
            Called::Emit {
                stream,
                piece: wire::E_CONSUMED,
            },
            call,
            now,
        )
    }

    /// Core ends `stream` refused with no plane able to render it: `emit(stream, E_REFUSE, status |
    /// E_REFUSE_HEAD_SENT?, text)`. `status` is neutral, 400..=599; `text` is core's own.
    pub fn refuse(
        &mut self,
        stream: u64,
        status: u32,
        head_sent: bool,
        text: &str,
        now: Instant,
    ) -> Result<&mut Actions, Ended> {
        if !(400..=599).contains(&status) {
            return Err(Ended::Misuse("a refusal status outside 400..=599"));
        }
        let arg = status
            | if head_sent {
                wire::E_REFUSE_HEAD_SENT
            } else {
                0
            };
        self.emit(stream, wire::E_REFUSE, arg, text.as_bytes(), now)
    }

    /// Every held stream whose stall deadline has passed at `now` is reset with
    /// `emit(stream, E_RESET, RESET_STALLED)`. Returns those streams, ascending (the caller ends each feed as for
    /// a peer reset and counts `transport_stream_stalled_total`), and what the answers asked of core.
    pub fn stall(&mut self, now: Instant) -> Result<(&[u64], &mut Actions), Ended> {
        let count = self.answers.take_stalled(now).len();
        self.answers.acts.clear();
        self.answers.gathering = true;
        let mut reset = Ok(());
        for at in 0..count {
            let stream = self.answers.stalled()[at];
            if let Err(ended) = self.emit(stream, wire::E_RESET, wire::RESET_STALLED, &[], now) {
                reset = Err(ended);
                break;
            }
        }
        self.answers.gathering = false;
        reset?;
        let Answers { holds, acts, .. } = &mut self.answers;
        Ok((holds.stalled(), acts))
    }

    /// [`Self::timer`], its answer added to what the turn already gathered (a stall's resets).
    fn timer_gathered(&mut self, now: Instant) -> Result<(), Ended> {
        self.answers.gathering = true;
        let answered = self.timer(now).map(|_| ());
        self.answers.gathering = false;
        answered
    }

    /// The socket failed: nothing more can be written, so no E_CLOSE will be sent.
    pub fn mark_lost(&mut self) {
        self.lost = true;
        self.backend = None;
    }

    /// Core ends the live session itself with `reason` (CR_*): `emit(0, E_CLOSE, reason)`, once. `None` = not
    /// sent, because the framer already answered CLOSE, EOF was ingested, the socket failed, or the instance
    /// is quarantined (the caller counts it). Either way the session takes no further call; the caller
    /// writes the answer's bytes, applies its CLOSE, and then drops this value.
    pub fn close(&mut self, reason: u32, now: Instant) -> Result<Option<&mut Actions>, Ended> {
        if self.core_closed || self.framer_closed {
            return Ok(None);
        }
        let quarantined = match &self.backend {
            Some(Backend::Port { handle, .. }) => !handle.instance().is_live(),
            #[cfg(test)]
            Some(Backend::Script(script)) => script.quarantined,
            None => true,
        };
        if quarantined || self.peer_closed || self.lost {
            self.backend = None;
            return Ok(None);
        }
        let call = Call::Emit {
            stream: 0,
            piece: wire::E_CLOSE,
            arg: reason,
            credit: 0,
            bytes: &[],
        };
        self.call(Called::Close, call, now)?;
        self.core_closed = true;
        Ok(Some(&mut self.answers.acts))
    }

    fn call(
        &mut self,
        called: Called,
        call: Call<'_>,
        now: Instant,
    ) -> Result<&mut Actions, Ended> {
        if !self.is_live() {
            return Err(Ended::Misuse("a call after the session was over"));
        }
        let Self {
            backend, answers, ..
        } = self;
        let Some(live) = backend.as_mut() else {
            return Err(Ended::Misuse("a call after the session was over"));
        };
        answers.start(called, now);
        let sink = &mut |out: TransportOut<'_>| answers.take(&out);
        let answered = match live {
            Backend::Port { port, handle } => match call {
                Call::Ingest(bytes) => port.ingest(handle, bytes, sink),
                Call::Emit {
                    stream,
                    piece,
                    arg,
                    credit,
                    bytes,
                } => port.emit(
                    handle,
                    stream,
                    piece,
                    arg,
                    credit,
                    parts_of(piece, bytes),
                    sink,
                ),
                Call::Timer => port.timer(handle, sink),
            },
            #[cfg(test)]
            Backend::Script(script) => script.answer(call, sink),
        };
        if let Err(error) = answered {
            self.backend = None;
            return Err(Ended::Port(error));
        }
        self.judged()?;
        Ok(&mut self.answers.acts)
    }

    /// The answer just taken, judged; a breach charges the instance and ends the session.
    fn judged(&mut self) -> Result<(), Ended> {
        match self.answers.finish() {
            Ok(()) => {
                if self.answers.closed {
                    self.framer_closed = true;
                }
                Ok(())
            }
            Err(_) if self.answers.capacity_failed => {
                self.backend = None;
                Err(Ended::Capacity)
            }
            Err(reason) => {
                match self.backend.take() {
                    Some(Backend::Port { handle, .. }) => {
                        let _ = handle.instance().charge(reason);
                    }
                    #[cfg(test)]
                    Some(Backend::Script(script)) => script.charged(reason),
                    None => {}
                }
                Err(Ended::Fault(reason))
            }
        }
    }
}

/// ONE PIECE AS THE PORT'S PARTS: `emit` takes a piece set and one entry per byte-carrying piece, in
/// the contract's fixed order. A head, a body and trailers carry their bytes in their own entry; an
/// end's entry is empty; a reset, a close and a credit carry none.
///
/// REFUSE-TEXT: the contract gives E_REFUSE one entry, core's own text. The port's `EmitParts` has no
/// field for it yet (the patch is `for-others/ports-refuse-text.patch`), so the refusal goes with its
/// status and without the text: the stream is refused all the same, never served. When the field
/// lands, the E_REFUSE arm below names it and nothing else changes.
fn parts_of(piece: u32, bytes: &[u8]) -> EmitParts<'_> {
    let mut parts = EmitParts::default();
    match piece {
        wire::E_HEAD => parts.head = Some(bytes),
        wire::E_BODY => parts.body = Some(bytes),
        wire::E_TRAILERS => parts.trailers = Some(bytes),
        wire::E_END => parts.end = Some(&[]),
        wire::E_REFUSE => parts.refuse = Some(bytes),
        _ => {}
    }
    parts
}

/// The session counters the connector keeps for the kernel's recorder.
#[derive(Debug, Default)]
pub struct SessionCounters {
    /// `transport_stream_stalled_total`: streams reset with E_RESET(RESET_STALLED).
    pub stalled: AtomicU64,
    /// E_CLOSE calls not made because the session was already over (CLOSE answered, EOF, a lost socket,
    /// a quarantined instance).
    pub close_skipped: AtomicU64,
}

/// One piece core sends on a stream (§8.7 `emit`): E_HEAD, E_BODY, E_TRAILERS, E_END, E_RESET or E_REFUSE.
#[derive(Debug)]
pub struct Piece {
    /// E_*.
    pub piece: u32,
    /// The piece's argument (SH_END_STREAM, MSG_*, a reset code, a refusal status).
    pub arg: u32,
    /// The piece's bytes (head records, body, PAIR records, core text).
    pub bytes: Payload,
}

/// Core's side of one stream: its pieces, in order. A ROLE_SERVER session's core attaches one for each
/// stream the framer opened (STREAM_HEAD); a ROLE_CLIENT session's core attaches one with `stream` 0 whose
/// first piece is the E_HEAD that opens the stream, and `opened` learns the id the framer gave it. While the
/// stream is held its receiver is not polled, so the sender's bounded channel fills and core's producer
/// waits: that is how backpressure reaches the far end's own window.
#[derive(Debug)]
pub struct Feed {
    /// The stream (0 = open a new one, ROLE_CLIENT).
    pub stream: u64,
    /// The pieces.
    pub pieces: mpsc::Receiver<Piece>,
    /// ROLE_CLIENT: told the opened stream's id.
    pub opened: Option<oneshot::Sender<u64>>,
}

/// A reserved registration command, sent in original host-head order before exposing a response.
pub struct RegisterResponse {
    /// The original admitted response identity; host stream numbers are never reused.
    pub key: ResponseKey,
    /// Receipt of the actual bounded ledger admission, including scoped finalizer handles.
    pub admitted: oneshot::Sender<Result<ResponseHandles, ResponseStop>>,
}
impl std::fmt::Debug for RegisterResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterResponse")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// What the framer handed core for a stream, owned, in order.
#[derive(Debug)]
pub enum Inbound {
    /// STREAM_HEAD.
    Head {
        /// The stream.
        stream: u64,
        /// No body follows.
        end_stream: bool,
        /// The nested head records.
        head: Payload,
    },
    /// STREAM_BODY.
    Body {
        /// The stream.
        stream: u64,
        /// MSG_* or 0.
        flags: u32,
        /// The bytes.
        bytes: Payload,
    },
    /// STREAM_END.
    End(u64),
    /// STREAM_TRAILERS.
    Trailers {
        /// The stream.
        stream: u64,
        /// The PAIR records.
        pairs: Payload,
    },
    /// STREAM_RESET: the far end reset the stream; its feed is dropped.
    Reset {
        /// The stream.
        stream: u64,
        /// The wire's code.
        code: u32,
    },
    /// Core reset the stream at its stall deadline (E_RESET(RESET_STALLED)): end the feeding exchange as for a
    /// peer reset. Its feed is dropped.
    Stalled(u64),
}

/// What [`drive`] is given beside the session and the connection.
#[derive(Debug)]
pub struct Wiring {
    /// The connection's delivery driver and its answers' owners: empty for a fresh connection, the
    /// ledger handed over for an adopted upgrade.
    pub delivery: DeliveryLedger,
    /// Dedicated bounded admission queue, independent of held or full body feeds.
    pub registrations: mpsc::Receiver<RegisterResponse>,
    /// Feeds core attaches as streams appear (and, ROLE_CLIENT, as it opens them).
    pub feeds: mpsc::Receiver<Feed>,
    /// Where the framer's stream items go. When it is full the task stops reading the connection.
    pub inbound: mpsc::Sender<Inbound>,
    /// Core ends the session with this CR_* reason; a dropped sender is CR_NORMAL.
    pub close: oneshot::Receiver<u32>,
    /// The conn's write timeout.
    pub write_timeout: Duration,
    /// The shutdown grace, which bounds the E_CLOSE(CR_DRAIN) flush instead.
    pub drain_grace: Duration,
    /// The counters.
    pub counters: Arc<SessionCounters>,
    /// The list the housekeeping tick walks to take back idle read blocks (the listener's); `None`
    /// keeps a read block, once made, until the connection ends.
    pub read_holders: Option<Arc<ReadHolders>>,
}

/// How a driven session ended.
#[derive(Debug)]
pub enum Outcome<S> {
    /// The framer answered CLOSE; its bytes were written and the connection closed.
    Closed,
    /// The peer closed the connection and no stream was left.
    PeerClosed,
    /// Core ended the session with this CR_* reason (E_CLOSE sent, or skipped and counted).
    CoreClosed(u32),
    /// The socket failed.
    Lost(std::io::Error),
    /// A call failed, or the framer broke the answer grammar (its instance charged).
    Ended(Ended),
    /// The framer answered UPGRADE to an `emit(E_HEAD)` of H_STATUS(101) (§12.27): the connection, the
    /// session (which still owns the response until the next transport's `begin` returns OK), the protocol
    /// and the leftover bytes go back to core (boxed: every other outcome is small, and an upgrade
    /// ends a session once).
    Upgraded(Box<Upgrade<S>>),
}

/// What an UPGRADE hands back to core ([`Outcome::Upgraded`]).
#[derive(Debug)]
pub struct Upgrade<S> {
    /// Original progress and response ownership survive the transport handoff.
    pub delivery: Delivery,
    /// The HTTP session.
    pub conn: TransportConn,
    /// The connection.
    pub io: S,
    /// The protocol named.
    pub protocol: Name,
    /// The bytes read past the head.
    pub leftover: Payload,
}

impl<S> Outcome<S> {
    /// Dispose an unadopted upgrade's exact writer before freezing its failed delivery facts.
    /// Other outcomes have already disposed their writer inside the original session owner.
    pub fn retire(self) {
        if let Self::Upgraded(upgrade) = self {
            let Upgrade {
                delivery, io, conn, ..
            } = *upgrade;
            drop(conn);
            drop(io);
            delivery.writer_retired();
        }
    }
}

/// One stream core feeds.
struct Slot {
    pieces: mpsc::Receiver<Piece>,
    held: bool,
    head_sent: bool,
}

/// Core's feeds, by stream, and the ROLE_CLIENT openings waiting for their first piece.
#[derive(Default)]
struct Slots {
    by_stream: HashMap<u64, Slot>,
    opening: VecDeque<(mpsc::Receiver<Piece>, Option<oneshot::Sender<u64>>)>,
}

/// The next piece of a stream that is not held (`None` = that feed ended), or of the first opening.
enum Next {
    Piece(u64, Option<Piece>),
    Opening(Option<Piece>),
}

fn next_piece(slots: &mut Slots) -> impl std::future::Future<Output = Next> + '_ {
    poll_fn(move |cx| {
        for (stream, slot) in &mut slots.by_stream {
            if slot.held {
                continue;
            }
            if let Poll::Ready(piece) = slot.pieces.poll_recv(cx) {
                return Poll::Ready(Next::Piece(*stream, piece));
            }
        }
        if let Some((pieces, _)) = slots.opening.front_mut() {
            if let Poll::Ready(piece) = pieces.poll_recv(cx) {
                return Poll::Ready(Next::Opening(piece));
            }
        }
        Poll::Pending
    })
}

/// What applying an answer leaves the loop to do.
enum Flow {
    Go,
    /// The framer answered a graceful CLOSE: its bytes are out, flushed, and the write side shut.
    Closed,
    /// The framer answered CLOSE_ABORT.
    Aborted,
    /// The delivery driver refused the answer whole: nothing of it was written.
    Rejected(Fault),
    Lost(std::io::Error),
    /// A call the answer made necessary (a credit) ended the session.
    Ended(Ended),
    Upgrade(Name, Payload),
}

/// The loop's state beside the session.
struct Task {
    slots: Slots,
    pending: VecDeque<Inbound>,
    wake_at: Option<Instant>,
    /// An answer's bytes were flushed to the socket since the read rooms were last wiped.
    flushed: bool,
    /// The connection's write side was shut down (an END_SHUTDOWN, a graceful CLOSE).
    shut: bool,
}

impl Task {
    fn new() -> Self {
        Self {
            slots: Slots::default(),
            pending: VecDeque::new(),
            wake_at: None,
            flushed: false,
            shut: false,
        }
    }

    /// ONE ANSWER, APPLIED. The delivery driver takes it first, whole: checked against the output
    /// model, then its parts queued for the connection as one run (a breach queues nothing). The run
    /// goes to the connection and is flushed; only then are the answer's other acts taken in order
    /// (stream items queued for core, the timer, an end that closes, a CLOSE, an UPGRADE). However it
    /// ends, the session's output buffer is wiped before it returns.
    async fn apply<S: AsyncWrite + Unpin>(
        &mut self,
        acts: &mut Actions,
        io: &mut DeliveryIo<S>,
        write_timeout: Duration,
        clock: &mut Option<(Instant, u64)>,
    ) -> Flow {
        if acts.is_empty() {
            return Flow::Go;
        }
        let flow = self.apply_acts(acts, io, write_timeout, clock).await;
        acts.clear();
        flow
    }

    async fn apply_acts<S: AsyncWrite + Unpin>(
        &mut self,
        acts: &mut Actions,
        io: &mut DeliveryIo<S>,
        write_timeout: Duration,
        clock: &mut Option<(Instant, u64)>,
    ) -> Flow {
        let outcome = match io.answered(acts) {
            Ok(outcome) => outcome,
            Err(fault) => return Flow::Rejected(fault),
        };
        // One copy of the answer's bytes from here on: the connection's queue.
        acts.handed_over();
        let deadline = tokio::time::Instant::from_std(wake_clock(clock).0) + write_timeout;
        if outcome.wrote {
            if let Err(error) = io.deliver(deadline).await {
                return Flow::Lost(error);
            }
            self.flushed = true;
        }
        for act in acts.drain() {
            match act {
                // The driver's: checked, queued, written and recorded above.
                Act::Session(_)
                | Act::Busy
                | Act::NoNewStreams
                | Act::WirePart { .. }
                | Act::WireSealed(_)
                | Act::Opened(_) => {}
                Act::WireEnd { stream, how, .. } => {
                    // Nothing more is emitted on a stream whose output ended.
                    self.slots.by_stream.remove(&stream);
                    if how == records::END_SHUTDOWN && !self.shut {
                        if let Err(error) = io.shut(deadline).await {
                            return Flow::Lost(error);
                        }
                        self.shut = true;
                    }
                }
                Act::Close { abort } => {
                    if abort {
                        return Flow::Aborted;
                    }
                    if !self.shut {
                        if let Err(error) = io.shut(deadline).await {
                            return Flow::Lost(error);
                        }
                        self.shut = true;
                    }
                    return Flow::Closed;
                }
                Act::Wake(ns) => {
                    let (now, mono) = wake_clock(clock);
                    self.wake_at = Some(now + Duration::from_nanos(ns.saturating_sub(mono)));
                }
                Act::Upgrade { protocol, leftover } => return Flow::Upgrade(protocol, leftover),
                Act::Head {
                    stream,
                    end_stream,
                    head,
                } => self.pending.push_back(Inbound::Head {
                    stream,
                    end_stream,
                    head,
                }),
                Act::Body {
                    stream,
                    flags,
                    bytes,
                } => self.pending.push_back(Inbound::Body {
                    stream,
                    flags,
                    bytes,
                }),
                Act::End(stream) => self.pending.push_back(Inbound::End(stream)),
                Act::Trailers { stream, pairs } => {
                    self.pending.push_back(Inbound::Trailers { stream, pairs });
                }
                Act::Reset { stream, code, .. } => {
                    self.slots.by_stream.remove(&stream);
                    self.pending.push_back(Inbound::Reset { stream, code });
                }
                Act::Full(stream) => {
                    if let Some(slot) = self.slots.by_stream.get_mut(&stream) {
                        slot.held = true;
                    }
                }
                Act::Writable(stream) => {
                    if let Some(slot) = self.slots.by_stream.get_mut(&stream) {
                        slot.held = false;
                    }
                }
            }
        }
        Flow::Go
    }

    /// Whether nothing is left for this session to carry after EOF.
    fn idle(&self) -> bool {
        self.slots.by_stream.is_empty() && self.slots.opening.is_empty() && self.pending.is_empty()
    }
}

/// The session's last answer applied, and then every credit the driver says is owed for a stream that
/// is over (`emit(E_CONSUMED)`, whose own answer is applied in turn).
async fn applied<S: AsyncWrite + Unpin>(
    task: &mut Task,
    conn: &mut TransportConn,
    io: &mut DeliveryIo<S>,
    write_timeout: Duration,
    clock: &mut Option<(Instant, u64)>,
) -> Flow {
    loop {
        match task.apply(conn.actions(), io, write_timeout, clock).await {
            Flow::Go => {}
            flow => return flow,
        }
        let mut gave = false;
        while let Some((stream, count)) = io.ledger().take_owed() {
            if !conn.is_live() {
                continue;
            }
            let (now, _) = wake_clock(clock);
            if let Err(ended) = conn.consumed(stream, count, now) {
                return Flow::Ended(ended);
            }
            gave = true;
            break;
        }
        if !gave {
            return Flow::Go;
        }
    }
}

/// The session ended on a call: what the record of every answer still open says of it.
fn retire_for<S>(io: &mut DeliveryIo<S>, ended: &Ended) {
    match ended {
        Ended::Fault(_) => io.ledger().faulted(),
        Ended::Port(_) => io.ledger().gone(Reason::Protocol),
        // The engine's own stops: its storage refused the answer, or it asked what no session takes.
        Ended::Capacity | Ended::Misuse(_) => io.ledger().gone(Reason::Cancelled),
    }
}

/// The session ended on `ended`: every open answer has its verdict before the outcome is built.
fn over<S>(io: &mut DeliveryIo<S>, ended: Ended) -> Outcome<S> {
    retire_for(io, &ended);
    Outcome::Ended(ended)
}

/// How the loop ends for a flow that is not [`Flow::Go`]. Every answer still open has its verdict
/// frozen here, with the reason the session ended for, before the connection is let go.
fn finished<S>(flow: Flow, mut conn: TransportConn, mut io: DeliveryIo<S>) -> Outcome<S> {
    match flow {
        // The transport closed the session with these answers unfinished.
        Flow::Go | Flow::Closed | Flow::Aborted => {
            io.ledger().gone(Reason::Protocol);
            Outcome::Closed
        }
        Flow::Rejected(fault) => {
            if fault.charged() {
                io.ledger().faulted();
            } else {
                io.ledger().gone(Reason::Cancelled);
            }
            Outcome::Ended(conn.reject_output(fault))
        }
        // The writer is dropped first, then the carrier's last reading freezes what is open
        // (`caller_gone`): see `DeliveryIo`'s drop.
        Flow::Lost(error) => {
            conn.mark_lost();
            Outcome::Lost(error)
        }
        Flow::Ended(ended) => over(&mut io, ended),
        Flow::Upgrade(protocol, leftover) => {
            let (io, delivery) = io.into_parts();
            Outcome::Upgraded(Box::new(Upgrade {
                delivery,
                conn,
                io,
                protocol,
                leftover,
            }))
        }
    }
}

/// THE WAKE'S CLOCK: the session clock's one reading for this wake (the OS instant and the host's
/// `mono` taken together), read the first time the wake asks and kept for the rest of it.
fn wake_clock(at: &mut Option<(Instant, u64)>) -> (Instant, u64) {
    *at.get_or_insert_with(crate::off_path::framing::session_clock)
}

/// Core closes the session with `reason`: E_CLOSE once (or skipped and counted), its bytes written under
/// the write timeout (the drain grace for CR_DRAIN), its CLOSE applied; the handle drops when `conn` does,
/// after the bytes are out. Every answer still open then has its verdict: `shutdown` for a drain,
/// `cancelled` when core ended the session for its own reason.
async fn close_by_core<S: AsyncWrite + Unpin>(
    mut conn: TransportConn,
    mut io: DeliveryIo<S>,
    reason: u32,
    write_timeout: Duration,
    drain_grace: Duration,
    counters: &SessionCounters,
    clock: &mut Option<(Instant, u64)>,
) -> Outcome<S> {
    let limit = if reason == wire::CR_DRAIN {
        drain_grace.min(write_timeout)
    } else {
        write_timeout
    };
    let gone = if reason == wire::CR_DRAIN {
        Reason::Shutdown
    } else {
        Reason::Cancelled
    };
    let (now, _) = wake_clock(clock);
    let deadline = tokio::time::Instant::from_std(now) + limit;
    match conn.close(reason, now) {
        Ok(Some(_)) => {}
        Ok(None) => {
            counters.close_skipped.fetch_add(1, Ordering::Relaxed);
            io.ledger().gone(gone);
            return Outcome::CoreClosed(reason);
        }
        Err(ended) => return over(&mut io, ended),
    }
    // The goodbye goes through the driver like every answer: a breach writes nothing of it.
    let answered = io.answered(conn.actions());
    let abort = conn
        .actions()
        .iter()
        .any(|act| matches!(act, Act::Close { abort: true }));
    // Its bytes are in the connection's queue now (or refused): the session's buffer is wiped.
    conn.actions().clear();
    if let Err(fault) = answered {
        return finished(Flow::Rejected(fault), conn, io);
    }
    // An early return drops `io`: the writer first, then the verdicts from the carrier's last reading.
    if let Err(error) = io.write_out(deadline).await {
        return Outcome::Lost(error);
    }
    if !abort {
        if let Err(error) = io.flush(deadline).await {
            return Outcome::Lost(error);
        }
        if let Err(error) = io.shut(deadline).await {
            return Outcome::Lost(error);
        }
    }
    io.ledger().gone(gone);
    drop(conn);
    Outcome::CoreClosed(reason)
}

/// THE SESSION TASK: drives `conn` (already begun; its actions hold the begin answer) over `io` until
/// the framer closes, the peer closes with nothing left to carry, core closes it, the socket fails, a
/// call fails, the transport breaks the output model, or the framer upgrades the connection.
///
/// ONE MECHANISM, BOTH ROLES: an accepted connection's output is driven by the delivery driver the dial
/// uses (`wiring.delivery`, in the answering role). The session calls the transport and owns the
/// socket; the driver checks every answer, queues its bytes, and says what was delivered.
pub async fn drive<S>(
    conn: TransportConn,
    io: S,
    progress: Arc<dyn CarrierProgressReader>,
    mut wiring: Wiring,
) -> Outcome<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = conn;
    let mut io = DeliveryIo::new(io, Delivery::new(wiring.delivery, progress));
    let mut task = Task::new();
    // Nothing is made for reading until bytes arrive: see `ReadRoom`.
    let mut room = ReadRoom::new(conn.storage().clone(), wiring.read_holders.take());
    let mut eof = false;
    let mut feeds_open = true;
    let mut registrations_open = true;

    let mut clock = None;
    match applied(
        &mut task,
        &mut conn,
        &mut io,
        wiring.write_timeout,
        &mut clock,
    )
    .await
    {
        Flow::Go => {}
        flow => return finished(flow, conn, io),
    }

    loop {
        // THE WAKE'S CLOCK: one reading per pass of the loop (a pass is one wake), taken the first
        // time the pass needs it. Before the wait only the close below reads it, and it returns.
        let mut clock = None;
        if eof && task.idle() {
            while let Ok(feed) = wiring.feeds.try_recv() {
                attach(&mut task.slots, feed);
            }
            if task.idle() && !io.ledger().has_responses() {
                // Dropping `io` freezes what is left (`caller_gone`).
                return Outcome::PeerClosed;
            }
        }
        if !feeds_open && task.idle() && !eof && !io.ledger().has_responses() {
            return close_by_core(
                conn,
                io,
                wire::CR_NORMAL,
                wiring.write_timeout,
                wiring.drain_grace,
                &wiring.counters,
                &mut clock,
            )
            .await;
        }
        // The answer's bytes are out: what the reads wrote is wiped now, before the wait.
        if std::mem::take(&mut task.flushed) {
            room.wipe_used();
        }
        room.answer_release(!task.idle() || io.ledger().has_responses());
        // The soonest of: the framer's timer, a held stream's stall, and a stream the engine reset
        // whose end mark the transport still owes.
        let deadline = [
            task.wake_at,
            conn.next_stall(),
            io.ledger().next_overdue(wiring.write_timeout),
        ]
        .into_iter()
        .flatten()
        .min();
        let sleep_until = deadline.map(tokio::time::Instant::from_std);
        // The engine stops reading the connection itself: while core has not taken what was read, and
        // while a session with one stream holds body its reader is behind on.
        let can_read = io.ledger().reads_socket() && task.pending.is_empty() && !eof;
        let can_feed = !task.slots.by_stream.is_empty() || !task.slots.opening.is_empty();
        let step = tokio::select! {
            biased;
            reason = &mut wiring.close => Step::Close(reason.unwrap_or(wire::CR_NORMAL)),
            registration = wiring.registrations.recv(), if registrations_open => {
                match registration {
                    Some(registration) => {
                        // The answer's owner is bound to the stream the transport announced; an
                        // answer on a stream it never opened is refused.
                        let admitted = io.ledger().admit_announced(registration.key);
                        if let Err(Ok(handles)) = registration.admitted.send(admitted) {
                            // The receipt never reached a producer or a reader: the answer is
                            // stopped like any other, by its own handle.
                            handles.cancel.cancel(ResponseStop::Cancelled);
                        }
                    }
                    None => registrations_open = false,
                }
                Step::Again
            },
            event = next_io(&mut io, &mut room, &mut conn, &mut clock, can_read, sleep_until) => event,
            permit = wiring.inbound.reserve(), if !task.pending.is_empty() => match permit {
                Ok(permit) => match task.pending.pop_front() {
                    Some(item) => {
                        let took = match &item {
                            Inbound::Body { stream, bytes, .. } => Some((*stream, bytes.len() as u64)),
                            _ => None,
                        };
                        permit.send(item);
                        took.map_or(Step::Again, |(stream, len)| Step::Took(stream, len))
                    }
                    None => Step::Again,
                },
                Err(_) => Step::Close(wire::CR_NORMAL),
            },
            feed = wiring.feeds.recv(), if feeds_open => match feed {
                Some(feed) => {
                    attach(&mut task.slots, feed);
                    Step::Again
                }
                None => {
                    feeds_open = false;
                    Step::Again
                }
            },
            next = next_piece(&mut task.slots), if can_feed => Step::Feed(next),
        };
        let step = match step {
            Step::Again => continue,
            step => step,
        };
        let (now, _) = wake_clock(&mut clock);
        let answered = match step {
            Step::Again => continue,
            Step::Close(reason) => {
                return close_by_core(
                    conn,
                    io,
                    reason,
                    wiring.write_timeout,
                    wiring.drain_grace,
                    &wiring.counters,
                    &mut clock,
                )
                .await;
            }
            // Core's reader took inbound body: on a session that multiplexes, the credit that reopens
            // the stream's window is given when the driver says it is due.
            Step::Took(stream, len) => match io.ledger().taken(stream, len) {
                Some(count) if conn.is_live() => conn.consumed(stream, count, now).map(|_| ()),
                _ => continue,
            },
            // The owner stops its answer: E_RESET, unless the transport already ended the stream. The
            // verdict is still what the socket took; the transport owes the stream's end mark.
            Step::Control(DeliveryControl::Cancel { stream, reason }) => {
                task.slots.by_stream.remove(&stream);
                if io.ledger().stop(stream, reason, now) && conn.is_live() {
                    conn.emit(stream, wire::E_RESET, 0, &[], now).map(|_| ())
                } else {
                    continue;
                }
            }
            Step::Tick => {
                // A stream the engine reset has no end mark after the write timeout: the engine closes
                // the connection, which is the one way left to make its verdict final.
                if io.ledger().overdue(now, wiring.write_timeout) {
                    return close_by_core(
                        conn,
                        io,
                        wire::CR_NORMAL,
                        wiring.write_timeout,
                        wiring.drain_grace,
                        &wiring.counters,
                        &mut clock,
                    )
                    .await;
                }
                // One turn's answers, gathered in the session's array: the stall's resets, then a due timer's.
                conn.actions().clear();
                let mut gathered = false;
                if conn.next_stall().is_some_and(|due| due <= now) {
                    match conn.stall(now) {
                        Ok((stalled, _)) => {
                            for &stream in stalled {
                                io.ledger().stalled(stream, now);
                                task.slots.by_stream.remove(&stream);
                                task.pending.push_back(Inbound::Stalled(stream));
                                wiring.counters.stalled.fetch_add(1, Ordering::Relaxed);
                            }
                            gathered = true;
                        }
                        Err(ended) => return over(&mut io, ended),
                    }
                }
                if task.wake_at.is_some_and(|due| due <= now) {
                    task.wake_at = None;
                    let timed = if gathered {
                        conn.timer_gathered(now)
                    } else {
                        conn.timer(now).map(|_| ())
                    };
                    if let Err(ended) = timed {
                        return over(&mut io, ended);
                    }
                }
                Ok(())
            }
            // Ingested in the read itself, the bytes already wiped (EOF ingested as no bytes).
            Step::Read(Ok(ingested)) => {
                eof |= ingested.eof;
                ingested.answered
            }
            Step::Read(Err(error)) => {
                conn.mark_lost();
                return Outcome::Lost(error);
            }
            Step::Feed(Next::Piece(stream, Some(piece))) => {
                if io.ledger().takes_pieces(stream) {
                    emit_piece(&mut conn, &mut task.slots, io.ledger(), stream, &piece, now)
                } else {
                    // The stream's output is over (its end mark, a reset), or the transport never
                    // announced it: nothing is emitted on it.
                    task.slots.by_stream.remove(&stream);
                    continue;
                }
            }
            Step::Feed(Next::Piece(stream, None)) => {
                // Core's feed ended before the stream did: end it refused, in core's words. The
                // owner's answer was cut: its record is what stood, never `whole`.
                let head_sent = task
                    .slots
                    .by_stream
                    .remove(&stream)
                    .is_some_and(|slot| slot.head_sent);
                if !io.ledger().takes_pieces(stream) {
                    continue;
                }
                io.ledger().cut(stream);
                io.ledger().emitting(stream, wire::E_REFUSE, 0);
                conn.refuse(stream, FEED_GONE_STATUS, head_sent, FEED_GONE_TEXT, now)
                    .map(|_| ())
            }
            Step::Feed(Next::Opening(piece)) => open_stream(&mut conn, &mut task.slots, piece, now),
        };
        if let Err(ended) = answered {
            return over(&mut io, ended);
        }
        match applied(
            &mut task,
            &mut conn,
            &mut io,
            wiring.write_timeout,
            &mut clock,
        )
        .await
        {
            Flow::Go => {}
            flow => return finished(flow, conn, io),
        }
    }
}

/// One turn of the loop.
enum Step {
    Again,
    Close(u32),
    Tick,
    Read(std::io::Result<Ingested>),
    Feed(Next),
    Control(DeliveryControl),
    /// Core took this many inbound body bytes of this stream.
    Took(u64, u64),
}

/// One socket read, already handed to the framer.
struct Ingested {
    /// The read found the end of the stream (it was ingested as no bytes).
    eof: bool,
    /// The framer's answer to the ingest.
    answered: Result<(), Ended>,
}

/// THE ONE KEEP-OR-RELEASE DECISION (owner's ruling: keep while active, release when idle), taken
/// for each connection that holds a read block, at the housekeeping tick ([`ReadHolders::walk`]):
/// keep it if bytes arrived since the previous tick, otherwise ask the connection to let it go
/// (which it does unless a request is still in flight). So a block lives one to two ticks after its
/// connection goes quiet; nothing is armed per request and the request path does no timer work.
fn keep_read_block(bytes_since_last_tick: bool) -> bool {
    bytes_since_last_tick
}

/// The connections of one listener that hold a read block now, for the housekeeping tick to walk
/// (only those: a connection without a block is not in it). Each entry is the connection's own
/// [`ReadKeep`]; the connection adds it when it makes a block and the walk removes it when it asks
/// for the block back, or when the connection is gone.
#[derive(Default)]
pub struct ReadHolders {
    held: std::sync::Mutex<Vec<Arc<ReadKeep>>>,
}

/// What the tick and one connection share about its read block.
#[derive(Default)]
pub struct ReadKeep {
    /// Bytes arrived since the previous tick (set by each read, taken by the walk).
    active: std::sync::atomic::AtomicBool,
    /// The walk asked for the block back.
    release: std::sync::atomic::AtomicBool,
    /// The connection's task, woken to act on `release`.
    wake: futures::task::AtomicWaker,
}

impl std::fmt::Debug for ReadHolders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadHolders")
            .field("holding", &self.len())
            .finish()
    }
}

impl std::fmt::Debug for ReadKeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadKeep").finish_non_exhaustive()
    }
}

impl ReadHolders {
    /// THE HOUSEKEEPING TICK'S WALK: each holder is kept or asked to let its block go
    /// ([`keep_read_block`]); entries of connections that are gone are dropped. No lock is held
    /// while a connection is woken. Returns how many were asked.
    pub fn walk(&self) -> usize {
        let mut held = std::mem::take(
            &mut *self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut asked = 0;
        held.retain(|keep| {
            if Arc::strong_count(keep) == 1 {
                return false;
            }
            if keep_read_block(keep.active.swap(false, Ordering::AcqRel)) {
                return true;
            }
            keep.release.store(true, Ordering::Release);
            keep.wake.wake();
            asked += 1;
            false
        });
        let mut now = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Whoever registered during the walk is kept after the walked list, in one array.
        held.append(&mut *now);
        *now = held;
        asked
    }

    fn hold(&self, keep: &Arc<ReadKeep>) {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::clone(keep));
    }

    /// How many connections hold a read block now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether no connection holds a read block.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// WHERE THE SESSION READS (owner's allocation ruling). Nothing is made at accept: a read goes into
/// [`FIRST_READ`] bytes the task holds in itself, never zero-filled (the reader writes them). When one
/// read fills them, input is arriving in a burst and a [`READ_CHUNK`] block is made for the reads
/// that follow (charged to the connection's account first; never zero-filled: the read is lent its
/// spare capacity, a fixed slice, so the block can never reallocate and free an unwiped copy; a
/// block the account cannot fund is not made and the reads stay small). The block is kept across
/// requests and let go by [`keep_read_block`] alone, at the housekeeping tick of the listener's
/// [`ReadHolders`]; a session given none keeps it until the connection ends.
///
/// THE WIPE: each room records how far reads have written into it since its last wipe (a read that
/// does not return counts the whole room). [`ReadRoom::wipe_used`] zeroes exactly that, in one block
/// store per room; the session calls it after the answer's bytes are flushed, off the request's
/// path. Releasing the block, the end of the connection and dropping the task wipe what is left.
struct ReadRoom {
    first: [MaybeUninit<u8>; FIRST_READ],
    first_used: usize,
    block: Option<ReadBlock>,
    /// Where the block is registered for the tick, and this connection's entry (made with its
    /// first block, reused for later ones).
    holders: Option<Arc<ReadHolders>>,
    keep: Option<Arc<ReadKeep>>,
    storage: busbar_contract::storage::StorageSource,
}

/// The read block and its charge; the block drops (wiped first) before the charge is let go.
struct ReadBlock {
    bytes: Vec<u8>,
    used: usize,
    _credit: busbar_contract::storage::StorageCredit,
}

/// One block store over what a read wrote, then the barrier that keeps the store.
fn wipe_read(bytes: &mut [MaybeUninit<u8>]) {
    bytes.fill(MaybeUninit::new(0));
    zeroize::optimization_barrier(&*bytes);
}

impl ReadRoom {
    fn new(
        storage: busbar_contract::storage::StorageSource,
        holders: Option<Arc<ReadHolders>>,
    ) -> Self {
        Self {
            first: [MaybeUninit::uninit(); FIRST_READ],
            first_used: 0,
            block: None,
            holders,
            keep: None,
            storage,
        }
    }

    /// The block is in the tick's list (once per block, not per request): marked active now.
    fn register(&mut self) {
        let Some(holders) = &self.holders else {
            return;
        };
        let keep = self.keep.get_or_insert_with(Arc::default);
        keep.release.store(false, Ordering::Release);
        keep.active.store(true, Ordering::Release);
        holders.hold(keep);
    }

    /// Bytes arrived: the tick keeps the block.
    fn mark_active(&self) {
        if let Some(keep) = &self.keep {
            keep.active.store(true, Ordering::Relaxed);
        }
    }

    /// Whether the tick asked for the block back (the task's waker registered for it first).
    fn release_asked(&self, cx: &mut std::task::Context<'_>) -> bool {
        match (&self.block, &self.keep) {
            (Some(_), Some(keep)) => {
                keep.wake.register(cx.waker());
                keep.release.load(Ordering::Acquire)
            }
            _ => false,
        }
    }

    /// The tick asked for the block back: it goes, wiped first, unless a request is still in
    /// flight, in which case it is registered again for the next tick.
    fn answer_release(&mut self, in_flight: bool) {
        let asked = self
            .keep
            .as_ref()
            .is_some_and(|keep| keep.release.swap(false, Ordering::AcqRel));
        if !asked || self.block.is_none() {
            return;
        }
        if in_flight {
            self.register();
        } else {
            self.release();
        }
    }

    /// A read block, charged before it is made; `None` when the account or the allocator says no.
    fn make_block(&self) -> Option<ReadBlock> {
        let credit = self.storage.try_reserve(READ_CHUNK).ok()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(READ_CHUNK).ok()?;
        (bytes.capacity() <= credit.len()).then_some(ReadBlock {
            bytes,
            used: 0,
            _credit: credit,
        })
    }

    /// Every byte a read wrote since the last wipe is zeroed, one block store per room.
    fn wipe_used(&mut self) {
        if let Some(used) = self.first.get_mut(..self.first_used) {
            wipe_read(used);
        }
        self.first_used = 0;
        if let Some(block) = &mut self.block {
            if let Some(used) = block.bytes.spare_capacity_mut().get_mut(..block.used) {
                wipe_read(used);
            }
            block.used = 0;
        }
    }

    /// The block is let go, wiped first.
    fn release(&mut self) {
        self.wipe_used();
        self.block = None;
    }

    /// One read, ingested by `conn` at the wake's clock (EOF ingested as no bytes).
    fn poll_ingest<S: AsyncRead + Unpin>(
        &mut self,
        io: &mut S,
        conn: &mut TransportConn,
        clock: &mut Option<(Instant, u64)>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<Ingested>> {
        let in_block = self.block.is_some();
        let (lent, used) = match &mut self.block {
            Some(block) => (
                &mut block.bytes.spare_capacity_mut()[..READ_CHUNK],
                &mut block.used,
            ),
            None => (&mut self.first[..], &mut self.first_used),
        };
        let room = lent.len();
        let before = *used;
        // Until the read returns, all of the room counts as written: a reader that unwinds
        // leaves the whole of it to the wipe.
        *used = room;
        let mut read = ReadBuf::uninit(lent);
        let polled = Pin::new(&mut *io).poll_read(cx, &mut read);
        let outcome = match polled {
            Poll::Ready(Ok(())) => {
                let bytes = read.filled();
                let (now, _) = wake_clock(clock);
                Poll::Ready(Ok((bytes.len(), conn.ingest(bytes, now).map(|_| ()))))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        };
        *used = before.max(read.initialized().len());
        match outcome {
            Poll::Ready(Ok((0, answered))) => {
                self.release();
                Poll::Ready(Ok(Ingested {
                    eof: true,
                    answered,
                }))
            }
            Poll::Ready(Ok((read, answered))) => {
                self.mark_active();
                if read == room && !in_block {
                    self.block = self.make_block();
                    if self.block.is_some() {
                        self.register();
                    }
                }
                Poll::Ready(Ok(Ingested {
                    eof: false,
                    answered,
                }))
            }
            Poll::Ready(Err(error)) => {
                self.release();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The end of the task, however it ends: what reads wrote is wiped before the memory goes.
impl Drop for ReadRoom {
    fn drop(&mut self) {
        self.wipe_used();
    }
}

async fn next_io<S: AsyncRead + Unpin>(
    io: &mut DeliveryIo<S>,
    room: &mut ReadRoom,
    conn: &mut TransportConn,
    clock: &mut Option<(Instant, u64)>,
    can_read: bool,
    deadline: Option<tokio::time::Instant>,
) -> Step {
    let mut sleep = std::pin::pin!(deadline.map(tokio::time::sleep_until));
    poll_fn(|cx| {
        if let Poll::Ready(control) = io.poll_control(cx) {
            return Poll::Ready(Step::Control(control));
        }
        if sleep
            .as_mut()
            .as_pin_mut()
            .is_some_and(|sleep| std::future::Future::poll(sleep, cx).is_ready())
        {
            return Poll::Ready(Step::Tick);
        }
        // The housekeeping tick asked for the read block back: the loop answers it.
        if room.release_asked(cx) {
            return Poll::Ready(Step::Again);
        }
        if can_read {
            room.poll_ingest(io, conn, clock, cx).map(Step::Read)
        } else {
            Poll::Pending
        }
    })
    .await
}

fn attach(slots: &mut Slots, feed: Feed) {
    if feed.stream == 0 {
        slots.opening.push_back((feed.pieces, feed.opened));
    } else {
        slots.by_stream.insert(
            feed.stream,
            Slot {
                pieces: feed.pieces,
                held: false,
                head_sent: false,
            },
        );
    }
}

/// A piece on a stream that is not held. The delivery driver is told what the engine asks before the
/// transport is: a body's bytes, an end, a refusal, a reset (what L5 and L6 are judged against).
fn emit_piece(
    conn: &mut TransportConn,
    slots: &mut Slots,
    ledger: &mut DeliveryLedger,
    stream: u64,
    piece: &Piece,
    now: Instant,
) -> Result<(), Ended> {
    ledger.emitting(stream, piece.piece, piece.bytes.len() as u64);
    conn.emit(stream, piece.piece, piece.arg, &piece.bytes, now)?;
    if matches!(piece.piece, wire::E_END | wire::E_RESET | wire::E_REFUSE) {
        slots.by_stream.remove(&stream);
    } else if let Some(slot) = slots.by_stream.get_mut(&stream) {
        if piece.piece == wire::E_HEAD {
            slot.head_sent = true;
        }
        slot.held = conn.is_held(stream);
    }
    Ok(())
}

/// The first piece of a ROLE_CLIENT opening: `emit(0, E_HEAD, ..)`, whose answer names the new stream. The
/// feed is then kept under that id and its opener told.
fn open_stream(
    conn: &mut TransportConn,
    slots: &mut Slots,
    piece: Option<Piece>,
    now: Instant,
) -> Result<(), Ended> {
    let Some((pieces, opened)) = slots.opening.pop_front() else {
        conn.actions().clear();
        return Ok(());
    };
    let Some(piece) = piece else {
        // The opener gave up before sending its head: nothing was opened.
        conn.actions().clear();
        return Ok(());
    };
    if piece.piece != wire::E_HEAD {
        return Err(Ended::Misuse(
            "a stream opening whose first piece is not E_HEAD",
        ));
    }
    conn.emit(0, wire::E_HEAD, piece.arg, &piece.bytes, now)?;
    let id = conn.actions().iter().find_map(|act| match act {
        Act::Opened(id) => Some(*id),
        _ => None,
    });
    if let Some(id) = id {
        slots.by_stream.insert(
            id,
            Slot {
                pieces,
                held: conn.is_held(id),
                head_sent: true,
            },
        );
        if let Some(opened) = opened {
            let _ = opened.send(id);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/transport_session_tests.rs"]
mod tests;
