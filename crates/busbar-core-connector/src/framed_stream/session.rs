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
//! * **ALPN by role** (round 9): a listener serving an instance advertises its `alpn(ROLE_SERVER)`
//!   ([`server_alpn`]), a dial through it offers its `alpn(ROLE_CLIENT)` ([`client_alpn`]); never one list for
//!   both.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::response_delivery::{DeliveryControl, DeliveryLedger, ResponseHandles};
use busbar_contract::response_delivery::{
    CarrierProgressReader, CompletionRequirement, ResponseKey, ResponseStop, WireClass,
};
use busbar_contract::secure::{SecureVec, Tail};
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::records::RecErr;
use busbar_plugin_abi::transport as wire;
use busbar_ports::transport::{ConnIn, TransportOut, TransportPort, TransportSession};
use busbar_ports::PortError;
use foldhash::HashMap;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use super::StreamHolds;

#[path = "session_delivery.rs"]
mod delivery;
#[path = "session_storage.rs"]
mod storage;
pub use delivery::Delivery;
use delivery::DeliveryIo;
pub use storage::{Name, Payload};
/// A complete callback answer whose backing charge follows its consumer.
pub type Actions = storage::Items<Act>;

/// A breach of the per-call answer grammar (count, order, place): `RecErr::Size`, as the adapter's own
/// grammar breaches are.
const GRAMMAR: FaultReason = FaultReason::BadRecords(RecErr::Size);

/// The bytes one socket read takes.
const READ_CHUNK: usize = 16 * 1024;

/// The neutral status core refuses a stream with when the feed behind it ends before the stream does.
const FEED_GONE_STATUS: u32 = 500;

/// The text that refusal carries (core text, never plugin text, I2).
const FEED_GONE_TEXT: &str = "the exchange feeding this stream ended before the stream did";

/// The protocol ids a listener serving `port`'s instance advertises: its `alpn(ROLE_SERVER)`, in order,
/// for [`crate::compose::Accept::alpn`].
#[must_use]
pub fn server_alpn(port: &dyn TransportPort) -> Vec<Vec<u8>> {
    protocol_ids(port.alpn(wire::ROLE_SERVER))
}

/// The protocol ids a dial through `port`'s instance offers: its `alpn(ROLE_CLIENT)`, in order, for
/// [`crate::compose::Dial::alpn`].
#[must_use]
pub fn client_alpn(port: &dyn TransportPort) -> Vec<Vec<u8>> {
    protocol_ids(port.alpn(wire::ROLE_CLIENT))
}

fn protocol_ids(ids: &[Box<str>]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        out.push(Vec::from(id.as_bytes()));
    }
    out
}

/// What one transport answer asks of core, owned: a `TransportOut` borrows the framer's buffer, and the
/// session task acts on it only after the call returned.
#[derive(Debug)]
pub enum Act {
    /// WRITE: bytes for the socket, in order.
    Write(Payload),
    /// Serializer-attributed ordered wire bytes, retaining their charged backing.
    WirePart {
        /// Host response stream, or zero for connection control.
        stream: u64,
        /// Actual serializer payload/control classification.
        class: WireClass,
        /// The charged serialized bytes.
        bytes: Payload,
    },
    /// A finite response wire prefix requiring an actual carrier operation.
    WireEnd {
        /// The host response stream whose serialized output ended.
        stream: u64,
        /// The actual carrier operation needed for this finite prefix.
        requirement: CompletionRequirement,
    },
    /// Protocol abort; its opaque protocol code grants no host reason authority.
    Abort(u64),
    /// The serializer cannot publish further bytes for this response.
    Quiescent(u64),
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
    /// PAUSE: stop reading the connection.
    Pause,
    /// RESUME: read it again.
    Resume,
    /// STREAM_FULL, accepted: the stream is held.
    Full(u64),
    /// STREAM_WRITABLE for a held stream: it is released.
    Writable(u64),
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
    provenance: bool,
    /// STREAM_FULL streams of this answer, judged at its end (STREAM_OPENED may come later in it).
    full: storage::Items<u64>,
    opened: Option<u64>,
    /// An `emit(E_CLOSE)` answer already carried its CLOSE.
    closing: bool,
    broke: Option<FaultReason>,
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
            full: storage::Items::new(&source)?,
            source,
            capacity_failed: false,
            provenance: false,
            opened: None,
            closing: false,
            broke: None,
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
        self.acts.clear();
        self.full.clear();
        self.opened = None;
        self.closing = false;
        self.broke = None;
        self.capacity_failed = false;
    }

    fn breach(&mut self) {
        self.broke.get_or_insert(GRAMMAR);
    }

    /// One record of the answer, in order. After a breach the rest is ignored.
    pub(crate) fn take(&mut self, out: TransportOut<'_>) {
        if self.capture(out).is_err() {
            self.capacity_failed = true;
        }
    }

    fn capture(
        &mut self,
        out: TransportOut<'_>,
    ) -> Result<(), busbar_contract::storage::StorageDenied> {
        if self.broke.is_some() || self.capacity_failed {
            return Ok(());
        }
        if self.provenance && matches!(out, TransportOut::Write(_)) {
            self.breach();
            return Ok(());
        }
        if self.called == Called::Close {
            match out {
                TransportOut::Write(bytes) if !self.closing => {
                    self.acts
                        .push(Act::Write(Payload::copy(&self.source, bytes)?))?;
                }
                TransportOut::Close { abort } if !self.closing => {
                    self.closing = true;
                    self.acts.push(Act::Close { abort })?;
                }
                TransportOut::WirePart {
                    stream,
                    class,
                    bytes,
                } if !self.closing => self.acts.push(Act::WirePart {
                    stream,
                    class,
                    bytes: Payload::copy(&self.source, bytes)?,
                })?,
                TransportOut::WireEnd {
                    stream,
                    requirement,
                } if !self.closing => self.acts.push(Act::WireEnd {
                    stream,
                    requirement,
                })?,
                TransportOut::ResponseAbort { stream, .. } if !self.closing => {
                    self.acts.push(Act::Abort(stream))?
                }
                TransportOut::ResponseQuiescent(stream) if !self.closing => {
                    self.acts.push(Act::Quiescent(stream))?
                }
                _ => self.breach(),
            }
            return Ok(());
        }
        if matches!(
            self.called,
            Called::Emit {
                piece: wire::E_DELIVERY_SETTLED,
                ..
            }
        ) && !matches!(out, TransportOut::ResponseQuiescent(_))
        {
            self.breach();
            return Ok(());
        }
        match out {
            TransportOut::WirePart {
                stream,
                class,
                bytes,
            } => self.acts.push(Act::WirePart {
                stream,
                class,
                bytes: Payload::copy(&self.source, bytes)?,
            })?,
            TransportOut::WireEnd {
                stream,
                requirement,
            } => self.acts.push(Act::WireEnd {
                stream,
                requirement,
            })?,
            TransportOut::ResponseAbort { stream, .. } => self.acts.push(Act::Abort(stream))?,
            TransportOut::ResponseQuiescent(stream) => self.acts.push(Act::Quiescent(stream))?,
            TransportOut::Write(bytes) => self
                .acts
                .push(Act::Write(Payload::copy(&self.source, bytes)?))?,
            TransportOut::Close { abort } => self.acts.push(Act::Close { abort })?,
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
            TransportOut::StreamReset { stream, code } => {
                self.holds.release(stream);
                self.acts.push(Act::Reset { stream, code })?;
            }
            TransportOut::StreamTrailers { stream, pairs } => self.acts.push(Act::Trailers {
                stream,
                pairs: Payload::copy(&self.source, pairs.rest())?,
            })?,
            TransportOut::StreamOpened(stream) => {
                if self.opened.replace(stream).is_some() {
                    self.breach();
                } else {
                    self.acts.push(Act::Opened(stream))?;
                }
            }
            TransportOut::Pause => self.acts.push(Act::Pause)?,
            TransportOut::Resume => self.acts.push(Act::Resume)?,
            TransportOut::StreamFull(stream) => match self.called {
                Called::Emit { piece, .. }
                    if !matches!(piece, wire::E_RELEASE | wire::E_DELIVERY_SETTLED) =>
                {
                    self.full.push(stream)?
                }
                _ => self.breach(),
            },
            TransportOut::StreamWritable(stream) => match self.called {
                Called::Ingest
                | Called::Timer
                | Called::Emit {
                    piece: wire::E_RELEASE,
                    ..
                } => {
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

    /// The whole answer judged: what it asks of core, in order, or the breach.
    pub(crate) fn finish(&mut self) -> Result<Actions, FaultReason> {
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
        if let Called::Emit { stream, piece } = self.called {
            if stream == 0 && piece == wire::E_HEAD && self.opened.is_none() {
                self.acts.clear();
                self.full.clear();
                return Err(GRAMMAR);
            }
            let mine = if stream == 0 {
                self.opened
            } else {
                Some(stream)
            };
            if self.full.iter().any(|full| Some(*full) != mine) {
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
        self.acts.take().map_err(|_| {
            self.capacity_failed = true;
            GRAMMAR
        })
    }

    pub(crate) fn is_held(&self, stream: u64) -> bool {
        self.holds.is_held(stream)
    }

    pub(crate) fn next_stall(&self) -> Option<Instant> {
        self.holds.next_deadline()
    }

    pub(crate) fn take_stalled(&mut self, now: Instant) -> Vec<u64> {
        self.holds.take_stalled(now)
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
        bytes: &'a [u8],
    },
    Timer,
}

impl TransportConn {
    fn reject_output(&mut self, reason: ResponseStop) -> Ended {
        if reason == ResponseStop::Capacity {
            self.backend = None;
            return Ended::Capacity;
        }
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
    ) -> Result<(Self, Actions), Ended> {
        let mut answers =
            Answers::with_source(stall_ms, now, storage).map_err(|_| Ended::Capacity)?;
        answers.provenance = port.facts() & wire::FB_WIRE_PROVENANCE != 0;
        answers.start(Called::Begin, now);
        let handle = port
            .begin(conn, &mut |out| answers.take(out))
            .map_err(Ended::Port)?;
        let mut session = Self {
            backend: Some(Backend::Port { port, handle }),
            answers,
            framer_closed: false,
            peer_closed: false,
            lost: false,
            core_closed: false,
        };
        let acts = session.judged()?;
        Ok((session, acts))
    }

    #[cfg(test)]
    pub(crate) fn scripted(script: tests::Script, stall_ms: Option<u32>, now: Instant) -> Self {
        Self {
            backend: Some(Backend::Script(script)),
            answers: Answers::new(stall_ms, now),
            framer_closed: false,
            peer_closed: false,
            lost: false,
            core_closed: false,
        }
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
    pub fn ingest(&mut self, bytes: &[u8], now: Instant) -> Result<Actions, Ended> {
        if bytes.is_empty() {
            self.peer_closed = true;
        }
        self.call(Called::Ingest, Call::Ingest(bytes), now)
    }

    /// The WAKE_AT the framer asked for has passed.
    pub fn timer(&mut self, now: Instant) -> Result<Actions, Ended> {
        self.call(Called::Timer, Call::Timer, now)
    }

    /// Core sends `piece` on `stream` (E_HEAD, E_BODY, E_TRAILERS, E_END, E_RESET or E_REFUSE). A held stream
    /// takes only E_RESET and E_REFUSE, which end it.
    pub fn emit(
        &mut self,
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: &[u8],
        now: Instant,
    ) -> Result<Actions, Ended> {
        if piece == wire::E_CLOSE {
            return Err(Ended::Misuse("E_CLOSE goes through TransportConn::close"));
        }
        if matches!(piece, wire::E_RELEASE | wire::E_DELIVERY_SETTLED)
            && (arg != 0 || !bytes.is_empty())
        {
            return Err(Ended::Misuse("delivery controls carry no protocol payload"));
        }
        if self.answers.is_held(stream)
            && !matches!(
                piece,
                wire::E_RESET | wire::E_REFUSE | wire::E_RELEASE | wire::E_DELIVERY_SETTLED
            )
        {
            return Err(Ended::Misuse("an emit on a held stream"));
        }
        let call = Call::Emit {
            stream,
            piece,
            arg,
            bytes,
        };
        self.call(Called::Emit { stream, piece }, call, now)
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
    ) -> Result<Actions, Ended> {
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
    pub fn stall(&mut self, now: Instant) -> Result<(Vec<u64>, Actions), Ended> {
        let stalled = self.answers.take_stalled(now);
        let mut acts = Actions::new(&self.answers.source).map_err(|_| Ended::Capacity)?;
        for &stream in &stalled {
            acts.append(self.emit(stream, wire::E_RESET, wire::RESET_STALLED, &[], now)?)
                .map_err(|_| Ended::Capacity)?;
        }
        Ok((stalled, acts))
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
    pub fn close(&mut self, reason: u32, now: Instant) -> Result<Option<Actions>, Ended> {
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
            bytes: &[],
        };
        let acts = self.call(Called::Close, call, now)?;
        self.core_closed = true;
        Ok(Some(acts))
    }

    fn call(&mut self, called: Called, call: Call<'_>, now: Instant) -> Result<Actions, Ended> {
        let settlement = matches!(
            called,
            Called::Emit {
                piece: wire::E_DELIVERY_SETTLED,
                ..
            }
        );
        if !self.is_live()
            && !(settlement && self.backend.is_some() && !self.lost && !self.core_closed)
        {
            return Err(Ended::Misuse("a call after the session was over"));
        }
        let Self {
            backend, answers, ..
        } = self;
        let Some(live) = backend.as_mut() else {
            return Err(Ended::Misuse("a call after the session was over"));
        };
        answers.start(called, now);
        let sink = &mut |out: TransportOut<'_>| answers.take(out);
        let answered = match live {
            Backend::Port { port, handle } => match call {
                Call::Ingest(bytes) => port.ingest(handle, bytes, sink),
                Call::Emit {
                    stream,
                    piece,
                    arg,
                    bytes,
                } => port.emit(handle, stream, piece, arg, bytes, sink),
                Call::Timer => port.timer(handle, sink),
            },
            #[cfg(test)]
            Backend::Script(script) => script.answer(call, sink),
        };
        if let Err(error) = answered {
            self.backend = None;
            return Err(Ended::Port(error));
        }
        self.judged()
    }

    /// The answer just taken, judged; a breach charges the instance and ends the session.
    fn judged(&mut self) -> Result<Actions, Ended> {
        match self.answers.finish() {
            Ok(acts) => {
                if acts.iter().any(|act| matches!(act, Act::Close { .. })) {
                    self.framer_closed = true;
                }
                Ok(acts)
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
    /// Required funded response ledger, created from the same trusted account with explicit bounds.
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
    /// and the leftover bytes go back to core.
    Upgraded {
        /// Original progress and response ownership survive the transport handoff.
        delivery: Delivery,
        /// The HTTP session.
        conn: TransportConn,
        /// The connection.
        io: S,
        /// The protocol named.
        protocol: Name,
        /// The bytes read past the head.
        leftover: Payload,
    },
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
    Closed,
    Aborted,
    Rejected(ResponseStop),
    Lost(std::io::Error),
    Upgrade(Name, Payload),
}

/// The loop's state beside the session.
struct Task {
    slots: Slots,
    pending: VecDeque<Inbound>,
    reading: bool,
    wake_at: Option<Instant>,
}

impl Task {
    /// The answer's acts, in order: socket writes now, stream items queued for core.
    async fn apply<S: AsyncWrite + Unpin>(
        &mut self,
        acts: Actions,
        io: &mut DeliveryIo<S>,
        write_timeout: Duration,
    ) -> Flow {
        let mut prefix = io.ledger().adopted_prefix();
        if let Err(reason) = io.prepare(&acts) {
            return Flow::Rejected(reason);
        }
        let mut wrote = false;
        let deadline = tokio::time::Instant::now() + write_timeout;
        for act in acts {
            match act {
                Act::Write(mut bytes) | Act::WirePart { mut bytes, .. } => {
                    prefix += bytes.len() as u64; // checked by whole-answer preparation
                    if let Err(error) = write_bounded(io, &mut bytes, deadline).await {
                        return Flow::Lost(error);
                    }
                    wrote = true;
                }
                Act::WireEnd { requirement, .. } => {
                    if let Err(error) = finish_prefix(io, prefix, requirement, deadline).await {
                        return Flow::Lost(error);
                    }
                    wrote = false;
                }
                Act::Abort(_) => {}
                Act::Quiescent(stream) => {
                    // Only succeeds for stopped responses whose indivisible bytes have settled.
                    let _ = io.ledger().settle_stopped(stream);
                }
                Act::Close { abort } => {
                    if !abort {
                        if let Err(error) =
                            finish_prefix(io, prefix, CompletionRequirement::Shutdown, deadline)
                                .await
                        {
                            return Flow::Lost(error);
                        }
                    }
                    return if abort { Flow::Aborted } else { Flow::Closed };
                }
                Act::Wake(ns) => {
                    let (now, mono) = crate::off_path::framing::session_clock();
                    self.wake_at = Some(now + Duration::from_nanos(ns.saturating_sub(mono)));
                }
                Act::Upgrade { protocol, leftover } => {
                    if wrote {
                        if let Err(error) = flush_bounded(io, deadline).await {
                            return Flow::Lost(error);
                        }
                    }
                    return Flow::Upgrade(protocol, leftover);
                }
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
                Act::Reset { stream, code } => {
                    self.slots.by_stream.remove(&stream);
                    self.pending.push_back(Inbound::Reset { stream, code });
                }
                // Bound to its feed by the emit that opened it.
                Act::Opened(_) => {}
                Act::Pause => self.reading = false,
                Act::Resume => self.reading = true,
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
        if wrote {
            if let Err(error) = flush_bounded(io, deadline).await {
                return Flow::Lost(error);
            }
        }
        Flow::Go
    }

    /// Whether nothing is left for this session to carry after EOF.
    fn idle(&self) -> bool {
        self.slots.by_stream.is_empty() && self.slots.opening.is_empty() && self.pending.is_empty()
    }
}

fn timed_out() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::TimedOut)
}

async fn write_bounded<S: AsyncWrite + Unpin>(
    io: &mut S,
    bytes: &mut Payload,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    tokio::time::timeout_at(deadline, async {
        while !bytes.is_empty() {
            let written = io.write(bytes.as_slice()).await?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            bytes.consume(written);
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err(timed_out()))
}

async fn flush_bounded<S: AsyncWrite + Unpin>(
    io: &mut S,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    tokio::time::timeout_at(deadline, io.flush())
        .await
        .unwrap_or_else(|_| Err(timed_out()))
}

async fn shut_bounded<S: AsyncWrite + Unpin>(
    io: &mut S,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    tokio::time::timeout_at(deadline, io.shutdown())
        .await
        .unwrap_or_else(|_| Err(timed_out()))
}

async fn finish_prefix<S: AsyncWrite + Unpin>(
    io: &mut DeliveryIo<S>,
    prefix: u64,
    requirement: CompletionRequirement,
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    flush_bounded(io, deadline).await?;
    io.complete_flush(prefix)?;
    if requirement == CompletionRequirement::Shutdown {
        shut_bounded(io, deadline).await?;
        io.complete_shutdown(prefix)?;
    }
    Ok(())
}

/// Core closes the session with `reason`: E_CLOSE once (or skipped and counted), its bytes written under
/// the write timeout (the drain grace for CR_DRAIN), its CLOSE applied; the handle drops when `conn` does,
/// after the bytes are out.
async fn close_by_core<S: AsyncWrite + Unpin>(
    mut conn: TransportConn,
    io: &mut DeliveryIo<S>,
    reason: u32,
    write_timeout: Duration,
    drain_grace: Duration,
    counters: &SessionCounters,
) -> Ended2 {
    let limit = if reason == wire::CR_DRAIN {
        drain_grace.min(write_timeout)
    } else {
        write_timeout
    };
    let deadline = tokio::time::Instant::now() + limit;
    let (now, _) = crate::off_path::framing::session_clock();
    let acts = match conn.close(reason, now) {
        Ok(Some(acts)) => acts,
        Ok(None) => {
            counters.close_skipped.fetch_add(1, Ordering::Relaxed);
            return Ended2::Core(reason);
        }
        Err(ended) => return Ended2::Ended(ended),
    };
    let mut prefix = io.ledger().adopted_prefix();
    if let Err(reason) = io.prepare(&acts) {
        return Ended2::Ended(conn.reject_output(reason));
    }
    let mut abort = false;
    for act in acts {
        match act {
            Act::Write(mut bytes) | Act::WirePart { mut bytes, .. } => {
                prefix += bytes.len() as u64;
                if let Err(error) = write_bounded(io, &mut bytes, deadline).await {
                    return Ended2::Lost(error);
                }
            }
            Act::WireEnd { requirement, .. } => {
                if let Err(error) = finish_prefix(io, prefix, requirement, deadline).await {
                    return Ended2::Lost(error);
                }
            }
            Act::Close { abort: hard } => abort = hard,
            _ => {}
        }
    }
    if !abort {
        if let Err(error) = flush_bounded(io, deadline).await {
            return Ended2::Lost(error);
        }
        if let Err(error) = shut_bounded(io, deadline).await {
            return Ended2::Lost(error);
        }
        if let Err(error) = io
            .complete_flush(prefix)
            .and_then(|()| io.complete_shutdown(prefix))
        {
            return Ended2::Lost(error);
        }
    }
    drop(conn);
    Ended2::Core(reason)
}

/// [`close_by_core`]'s result, before the outcome is built.
enum Ended2 {
    Core(u32),
    Ended(Ended),
    Lost(std::io::Error),
}

impl<S> From<Ended2> for Outcome<S> {
    fn from(e: Ended2) -> Self {
        match e {
            Ended2::Core(reason) => Outcome::CoreClosed(reason),
            Ended2::Ended(ended) => Outcome::Ended(ended),
            Ended2::Lost(error) => Outcome::Lost(error),
        }
    }
}

/// THE SESSION TASK: drives `conn` (already begun; `first` = its begin answer) over `io` until the framer
/// closes, the peer closes with nothing left to carry, core closes it, the socket fails, a call fails, or the
/// framer upgrades the connection.
pub async fn drive<S>(
    conn: TransportConn,
    first: Actions,
    io: S,
    progress: Arc<dyn CarrierProgressReader>,
    mut wiring: Wiring,
) -> Outcome<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = conn;
    let mut io = DeliveryIo::new(
        io,
        Delivery::new(wiring.delivery, progress),
        conn.storage().clone(),
    );
    let mut task = Task {
        slots: Slots::default(),
        pending: VecDeque::new(),
        reading: true,
        wake_at: None,
    };
    // The fixed read scratch is reserved before allocation and retained for the whole driver.
    // StreamHolds, feed maps and the inbound deque remain separate accounting boundaries.
    let storage = conn.answers.source.clone();
    let _scratch_credit = match storage.try_reserve(READ_CHUNK) {
        Ok(credit) => credit,
        Err(_) => return Outcome::Ended(Ended::Capacity),
    };
    let mut buf = match SecureVec::with_capacity(READ_CHUNK) {
        Ok(buf) if buf.capacity() <= READ_CHUNK => buf,
        _ => return Outcome::Ended(Ended::Capacity),
    };
    let mut eof = false;
    let mut feeds_open = true;
    let mut registrations_open = true;

    match task.apply(first, &mut io, wiring.write_timeout).await {
        Flow::Go => {}
        Flow::Closed => {
            return finish_closed(
                &mut conn,
                &mut task,
                &mut io,
                &wiring.inbound,
                wiring.drain_grace,
            )
            .await
        }
        Flow::Aborted => return Outcome::Closed,
        Flow::Rejected(reason) => return Outcome::Ended(conn.reject_output(reason)),
        Flow::Lost(error) => {
            conn.mark_lost();
            return Outcome::Lost(error);
        }
        Flow::Upgrade(protocol, leftover) => {
            let (io, delivery) = io.into_parts();
            return Outcome::Upgraded {
                delivery,
                conn,
                io,
                protocol,
                leftover,
            };
        }
    }

    loop {
        if eof && task.idle() {
            while let Ok(feed) = wiring.feeds.try_recv() {
                attach(&mut task.slots, feed);
            }
            if task.idle() && !io.ledger().has_responses() {
                return Outcome::PeerClosed;
            }
        }
        if !feeds_open && task.idle() && !eof && !io.ledger().has_responses() {
            return close_by_core(
                conn,
                &mut io,
                wire::CR_NORMAL,
                wiring.write_timeout,
                wiring.drain_grace,
                &wiring.counters,
            )
            .await
            .into();
        }
        let deadline = match (task.wake_at, conn.next_stall()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let sleep_until = tokio::time::Instant::from_std(
            deadline.unwrap_or_else(|| crate::off_path::framing::session_clock().0),
        );
        let can_read = task.reading && task.pending.is_empty() && !eof;
        let can_feed = !task.slots.by_stream.is_empty() || !task.slots.opening.is_empty();
        let step = tokio::select! {
            biased;
            reason = &mut wiring.close => Step::Close(reason.unwrap_or(wire::CR_NORMAL)),
            registration = wiring.registrations.recv(), if registrations_open => {
                match registration {
                    Some(registration) => {
                        let admitted = io.ledger().admit(registration.key);
                        let stream = registration.key.stream;
                        if registration.admitted.send(admitted).is_err() {
                            let _ = io.ledger().stop(stream, ResponseStop::Cancelled);
                            // The ACK never exposed a producer or reader. Retire that absent
                            // input explicitly; protocol cancellation/quiescence still run normally.
                            let _ = io.ledger().input_retired(stream);
                        }
                    }
                    None => registrations_open = false,
                }
                Step::Again
            },
            event = next_io(&mut io, &mut buf, can_read, deadline.map(|_| sleep_until)) => event,
            permit = wiring.inbound.reserve(), if !task.pending.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(item) = task.pending.pop_front() {
                        permit.send(item);
                    }
                    Step::Again
                }
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
        let (now, _) = crate::off_path::framing::session_clock();
        let mut settlement = None;
        let answered = match step {
            Step::Again => continue,
            Step::Close(reason) => {
                return close_by_core(
                    conn,
                    &mut io,
                    reason,
                    wiring.write_timeout,
                    wiring.drain_grace,
                    &wiring.counters,
                )
                .await
                .into();
            }
            Step::Control(DeliveryControl::Release { stream }) => {
                conn.emit(stream, wire::E_RELEASE, 0, &[], now)
            }
            Step::Control(DeliveryControl::Cancel { stream, reason }) => {
                task.slots.by_stream.remove(&stream);
                if io.ledger().stop(stream, reason).is_err() {
                    return Outcome::Lost(delivery::error(ResponseStop::Integrity));
                }
                conn.emit(stream, wire::E_RESET, 0, &[], now)
            }
            Step::Control(DeliveryControl::Settled { stream }) => {
                settlement = Some(stream);
                conn.emit(stream, wire::E_DELIVERY_SETTLED, 0, &[], now)
            }
            Step::Tick => {
                let mut acts = match Actions::new(&conn.answers.source) {
                    Ok(acts) => acts,
                    Err(_) => return Outcome::Ended(Ended::Capacity),
                };
                if conn.next_stall().is_some_and(|due| due <= now) {
                    match conn.stall(now) {
                        Ok((stalled, more)) => {
                            for stream in stalled {
                                task.slots.by_stream.remove(&stream);
                                task.pending.push_back(Inbound::Stalled(stream));
                                wiring.counters.stalled.fetch_add(1, Ordering::Relaxed);
                            }
                            if acts.append(more).is_err() {
                                return Outcome::Ended(Ended::Capacity);
                            }
                        }
                        Err(ended) => return Outcome::Ended(ended),
                    }
                }
                if task.wake_at.is_some_and(|due| due <= now) {
                    task.wake_at = None;
                    match conn.timer(now) {
                        Ok(more) => {
                            if acts.append(more).is_err() {
                                return Outcome::Ended(Ended::Capacity);
                            }
                        }
                        Err(ended) => return Outcome::Ended(ended),
                    }
                }
                Ok(acts)
            }
            Step::Read(Ok(0)) => {
                eof = true;
                conn.ingest(&[], now)
            }
            Step::Read(Ok(n)) => {
                let answered = conn.ingest(&buf[..n], now);
                buf.clear();
                answered
            }
            Step::Read(Err(error)) => {
                conn.mark_lost();
                return Outcome::Lost(error);
            }
            Step::Feed(Next::Piece(stream, Some(piece))) => {
                emit_piece(&mut conn, &mut task.slots, stream, &piece, now)
            }
            Step::Feed(Next::Piece(stream, None)) => {
                // Core's feed ended before the stream did: end it refused, in core's words.
                let head_sent = task
                    .slots
                    .by_stream
                    .remove(&stream)
                    .is_some_and(|slot| slot.head_sent);
                conn.refuse(stream, FEED_GONE_STATUS, head_sent, FEED_GONE_TEXT, now)
            }
            Step::Feed(Next::Opening(piece)) => open_stream(&mut conn, &mut task.slots, piece, now),
        };
        let acts = match answered {
            Ok(acts) => acts,
            Err(ended) => return Outcome::Ended(ended),
        };
        match task.apply(acts, &mut io, wiring.write_timeout).await {
            Flow::Go => {}
            Flow::Closed => {
                return finish_closed(
                    &mut conn,
                    &mut task,
                    &mut io,
                    &wiring.inbound,
                    wiring.drain_grace,
                )
                .await
            }
            Flow::Aborted => return Outcome::Closed,
            Flow::Rejected(reason) => return Outcome::Ended(conn.reject_output(reason)),
            Flow::Lost(error) => {
                conn.mark_lost();
                return Outcome::Lost(error);
            }
            Flow::Upgrade(protocol, leftover) => {
                let (io, delivery) = io.into_parts();
                return Outcome::Upgraded {
                    delivery,
                    conn,
                    io,
                    protocol,
                    leftover,
                };
            }
        }
        if let Some(stream) = settlement {
            if let Err(reason) = io.ledger().settled_ack(stream) {
                return Outcome::Lost(delivery::error(reason));
            }
            // Input may still be running; never manufacture EOF to force retirement.
            let _ = io.ledger().retire_response(stream);
        }
    }
}

/// Framer CLOSE ends ordinary callbacks, but actual response input/settlement joins outlive it.
/// The existing shutdown grace bounds this final retention; expiration retires the sole writer.
async fn finish_closed<S: AsyncWrite + Unpin>(
    conn: &mut TransportConn,
    task: &mut Task,
    io: &mut DeliveryIo<S>,
    inbound: &mpsc::Sender<Inbound>,
    grace: Duration,
) -> Outcome<S> {
    let finished = tokio::time::timeout(grace, async {
        loop {
            if !io.ledger().has_responses() { return Outcome::Closed; }
            let control = tokio::select! {
                biased;
                control = poll_fn(|cx| {
                    if let Poll::Ready(control) = io.poll_control(cx) { return Poll::Ready(Some(control)); }
                    io.ledger().poll_idle(cx).map(|()| None)
                }) => control,
                permit = inbound.reserve(), if !task.pending.is_empty() => {
                    match permit {
                        Ok(permit) => if let Some(item) = task.pending.pop_front() { permit.send(item); },
                        Err(_) => return Outcome::Lost(delivery::error(ResponseStop::Cancelled)),
                    }
                    continue;
                }
            };
            let Some(control) = control else { return Outcome::Closed; };
            match control {
                DeliveryControl::Settled { stream } => {
                    let acts = match conn.emit(stream, wire::E_DELIVERY_SETTLED, 0, &[], Instant::now()) {
                        Ok(acts) => acts,
                        Err(ended) => return Outcome::Ended(ended),
                    };
                    if let Err(reason) = io.prepare(&acts) { return Outcome::Ended(conn.reject_output(reason)); }
                    if let Err(reason) = io.ledger().settled_ack(stream) { return Outcome::Lost(delivery::error(reason)); }
                    let _ = io.ledger().retire_response(stream);
                }
                DeliveryControl::Cancel { stream, reason } => {
                    let _ = io.ledger().stop(stream, reason);
                    if io.ledger().settle_stopped(stream).is_err() { return Outcome::Lost(delivery::error(reason)); }
                }
                DeliveryControl::Release { .. } => return Outcome::Lost(delivery::error(ResponseStop::Protocol)),
            }
        }
    }).await;
    finished.unwrap_or_else(|_| Outcome::Lost(timed_out()))
}

/// One turn of the loop.
enum Step {
    Again,
    Close(u32),
    Tick,
    Read(std::io::Result<usize>),
    Feed(Next),
    Control(DeliveryControl),
}

async fn next_io<S: AsyncRead + Unpin>(
    io: &mut DeliveryIo<S>,
    buf: &mut SecureVec,
    can_read: bool,
    deadline: Option<tokio::time::Instant>,
) -> Step {
    let sleep = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now));
    tokio::pin!(sleep);
    poll_fn(|cx| {
        if let Poll::Ready(control) = io.poll_control(cx) {
            return Poll::Ready(Step::Control(control));
        }
        let had_responses = io.ledger().has_responses();
        if io.ledger().poll_idle(cx).is_ready() && had_responses {
            return Poll::Ready(Step::Again);
        }
        if deadline.is_some() && std::future::Future::poll(sleep.as_mut(), cx).is_ready() {
            return Poll::Ready(Step::Tick);
        }
        if can_read {
            poll_read_secure(io, buf, cx).map(Step::Read)
        } else {
            Poll::Pending
        }
    })
    .await
}

/// A cancelled or pending read leaves no plaintext in the lent scratch region.
#[cfg(test)]
async fn read_secure<S: AsyncRead + Unpin>(
    io: &mut S,
    buf: &mut SecureVec,
) -> std::io::Result<usize> {
    poll_fn(|cx| poll_read_secure(io, buf, cx)).await
}

fn poll_read_secure<S: AsyncRead + Unpin>(
    io: &mut S,
    buf: &mut SecureVec,
    cx: &mut std::task::Context<'_>,
) -> Poll<std::io::Result<usize>> {
    let mut pending = false;
    let read = buf.read_into(READ_CHUNK, Tail::Wipe, |bytes| {
        let mut read = ReadBuf::new(bytes);
        match Pin::new(&mut *io).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => Ok(read.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => {
                pending = true;
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }
    });
    if pending {
        Poll::Pending
    } else {
        Poll::Ready(read.unwrap_or_else(|_| Err(std::io::ErrorKind::OutOfMemory.into())))
    }
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

/// A piece on a stream that is not held.
fn emit_piece(
    conn: &mut TransportConn,
    slots: &mut Slots,
    stream: u64,
    piece: &Piece,
    now: Instant,
) -> Result<Actions, Ended> {
    let acts = conn.emit(stream, piece.piece, piece.arg, &piece.bytes, now)?;
    if matches!(piece.piece, wire::E_END | wire::E_RESET | wire::E_REFUSE) {
        slots.by_stream.remove(&stream);
    } else if let Some(slot) = slots.by_stream.get_mut(&stream) {
        if piece.piece == wire::E_HEAD {
            slot.head_sent = true;
        }
        slot.held = conn.is_held(stream);
    }
    Ok(acts)
}

/// The first piece of a ROLE_CLIENT opening: `emit(0, E_HEAD, ..)`, whose answer names the new stream. The
/// feed is then kept under that id and its opener told.
fn open_stream(
    conn: &mut TransportConn,
    slots: &mut Slots,
    piece: Option<Piece>,
    now: Instant,
) -> Result<Actions, Ended> {
    let Some((pieces, opened)) = slots.opening.pop_front() else {
        return Actions::new(&conn.answers.source).map_err(|_| Ended::Capacity);
    };
    let Some(piece) = piece else {
        // The opener gave up before sending its head: nothing was opened.
        return Actions::new(&conn.answers.source).map_err(|_| Ended::Capacity);
    };
    if piece.piece != wire::E_HEAD {
        return Err(Ended::Misuse(
            "a stream opening whose first piece is not E_HEAD",
        ));
    }
    let acts = conn.emit(0, wire::E_HEAD, piece.arg, &piece.bytes, now)?;
    let id = acts.iter().find_map(|act| match act {
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
    Ok(acts)
}

#[cfg(test)]
#[path = "../tests/transport_session_tests.rs"]
mod tests;
