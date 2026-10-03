// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO TRANSPORT ROLES (TRANSPORT-STACK, owner-approved 2026-09-27; spec #3): a transport plugin
//! is a [`Carrier`] or a [`Framer`], never both, and never names another transport.
//!
//! * A **CARRIER** moves bytes: it listens, accepts, dials a [`Dest`], reads, writes, flushes and
//!   closes connections, and reports what it knows about a connection's two ends
//!   ([`CarrierFacts`]). It is POLL-shaped: every method answers at once, `Pending` registering the
//!   caller's waker (the HOT lowering hands it a token and the host's waker instead).
//! * A **FRAMER** gives bytes a shape: it is a sans-IO state machine with no socket and no waker. The
//!   host opens a framing state per connection, INGESTS the bytes the carrier read (it answers the
//!   frames they complete and the bytes the far side is owed), EMITS a frame as the bytes that carry
//!   it, and renders an envelope, a refusal and a close in its own wire's bytes. An upgrade moves the
//!   byte stream: [`Framer::detach`] gives back the bytes it held unconsumed, and the framer the
//!   stream moves to [`Framer::adopt`]s them.
//!
//! The ROLE is not declared twice: it is derived from what the plugin composes over ([`role_of`]) —
//! a transport that composes over nothing opens its own connections, so it is a carrier; one that
//! composes over a layer frames that layer's bytes, so it is a framer.
//!
//! Core stacks a connection as `carrier -> [connection security, when the binding says so] ->
//! framer`, and moves the byte stream on an upgrade; no transport holds, dials or names another.
//! Connection security is core's alone (#40(b); TLS never crosses the ABI): no method here hands a
//! plugin key or certificate material — [`ConnFacts`] is what the handshake established, as facts.
//!
//! These traits are the LINKED source of truth. The HOT lane (`abi::hot::transport`) is their
//! mechanical `#[repr(C)]` lowering, one slot per method, so a dropped-in carrier or framer and a
//! linked one are driven through the same methods.

use std::task::{Context, Poll};

use super::wire::{CertFacts, CloseReason, Encode, TransportError, WireStatusClass};
use crate::ids::StreamId;
use crate::plugin::Plugin;

/// Which role a transport plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Role {
    /// Opens connections and moves their bytes.
    Carrier,
    /// Frames the bytes of a connection a carrier opened.
    Framer,
}

/// A transport's role, from the layers it declares it composes over (`TransportMeta::COMPOSES_OVER`):
/// none is a carrier, any is a framer.
#[must_use]
pub const fn role_of(composes_over: &[&str]) -> Role {
    if composes_over.is_empty() {
        Role::Carrier
    } else {
        Role::Framer
    }
}

/// A transport's ROW: every constant it declares about itself (`TransportMeta`), as one value — what
/// the composition root reads, the same value whichever door the transport came in by. A linked
/// transport's row is [`TransportRow::of`] its type; a dropped-in one's is read off its decl, field
/// for field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportRow {
    /// The registry key.
    pub key: &'static str,
    /// The layers it composes over; its role follows ([`TransportRow::role`]).
    pub composes_over: &'static [&'static str],
    /// The selector forms it evaluates on arriving bytes.
    pub selector_forms: &'static [crate::grammar::SelectorForm],
    /// The selector forms it evaluates when dialling out.
    pub egress_selector_forms: &'static [crate::grammar::SelectorForm],
    /// The signalling-to-session binding it declares.
    pub handoff: Option<super::wire::Handoff>,
    /// How it delimits what arrives.
    pub framing: super::wire::Framing,
    /// It carries sessions.
    pub session: bool,
    /// A session on it caches its principal.
    pub session_bound: bool,
    /// What opens a session's first unit.
    pub unit0_trigger: Option<super::wire::Unit0Trigger>,
    /// The layers it can upgrade in-band to.
    pub upgrades_to: &'static [&'static str],
    /// What tells it a frame opens a challenge-response exchange.
    pub handshake_trigger: Option<super::wire::HandshakeTrigger>,
    /// The transport fact keys it writes.
    pub transport_facts: &'static [&'static str],
    /// It reads inside the payload.
    pub decodes_payload: bool,
    /// Which frame carries its status, where it reports one.
    pub status_at: Option<super::wire::StatusAt>,
    /// The numbering its statuses are spelled in, where it reports one.
    pub status_namespace: Option<&'static str>,
    /// EVERY SCHEME THE ENTRY ANSWERS FOR, each with what the root reads per scheme
    /// (`TransportMeta::CLAIMS`). The root registers one row per claim, all pointing at this entry.
    pub claims: &'static [Claim],
}

/// ONE CLAIM of a transport entry (ARCHITECT 2026-09-27, TRANSPORT-STACK (A)): a scheme the entry
/// answers for, and everything the root reads per scheme. One entry carries one or more claims — a
/// carrier or a single-wire framer carries one, a framer that frames several wires carries one per
/// wire — and each claim is registered as a row of its own, pointing at the one entry. How one claim rides another inside the plugin is the plugin's own business and never
/// appears here: what the entry composes over stays the ENTRY's ([`TransportRow::composes_over`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    /// The scheme, which is the key the row is registered under.
    pub key: &'static str,
    /// It carries sessions.
    pub session: bool,
    /// A session on it caches its principal.
    pub session_bound: bool,
    /// What opens a session's first unit.
    pub unit0_trigger: Option<super::wire::Unit0Trigger>,
    /// Which frame carries its status, where it reports one: the status leg a fee is settled on.
    pub status_at: Option<super::wire::StatusAt>,
    /// The numbering its statuses are spelled in, where it reports one.
    pub status_namespace: Option<&'static str>,
    /// The transport fact keys it writes.
    pub transport_facts: &'static [&'static str],
    /// The selector forms it evaluates on arriving bytes.
    pub selector_forms: &'static [crate::grammar::SelectorForm],
}

impl TransportRow {
    /// The row of the linked transport `T`, read off its declaration.
    #[must_use]
    pub const fn of<T: super::TransportMeta>() -> Self {
        Self {
            key: T::KEY,
            composes_over: T::COMPOSES_OVER,
            selector_forms: T::SELECTOR_FORMS,
            egress_selector_forms: T::EGRESS_SELECTOR_FORMS,
            handoff: T::HANDOFF,
            framing: T::FRAMING,
            session: T::SESSION,
            session_bound: T::SESSION_BOUND,
            unit0_trigger: T::UNIT0_TRIGGER,
            upgrades_to: T::UPGRADES_TO,
            handshake_trigger: T::HANDSHAKE_TRIGGER,
            transport_facts: T::TRANSPORT_FACTS,
            decodes_payload: T::DECODES_PAYLOAD,
            status_at: T::STATUS_CLASS,
            status_namespace: T::STATUS_NAMESPACE,
            claims: T::CLAIMS,
        }
    }

    /// Its role ([`role_of`] its composes-over list).
    #[must_use]
    pub const fn role(&self) -> Role {
        role_of(self.composes_over)
    }
}

/// Where a carrier dials: an address it resolves itself, or a program it starts and speaks to over
/// the program's own standard input and output. Already admitted by the host (the verified destination is
/// the host's; this is what reaching it takes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest<'a> {
    /// A network authority, `host:port`.
    Authority(&'a str),
    /// An absolute program path, its argument vector and the whole of its environment.
    Program {
        /// The absolute path of the program.
        program: &'a str,
        /// The arguments, in order, without the program name.
        args: &'a [&'a str],
        /// The environment the program starts with, and nothing else.
        env: &'a [(&'a str, &'a str)],
    },
}

/// What a carrier knows about one connection's two ends.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct CarrierFacts {
    /// The far end, as the carrier spells it.
    pub peer: String,
    /// The local port the connection arrived on; `0` on one that was dialled or has no port.
    pub local_port: u16,
}

/// What connection security established on a connection, as facts (never material): the name the
/// dialler offered, the protocol the two ends agreed, and what the far end's certificate says.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConnFacts {
    /// The server name offered during the handshake.
    pub sni: Option<String>,
    /// The protocol the handshake agreed.
    pub alpn: Option<String>,
    /// What the far end's presented certificate says about its holder.
    pub peer_cert: Option<CertFacts>,
    /// The claim the host resolved this connection to — the dialled target's scheme, or the claim
    /// the accepting binding resolved; `None` is the entry's first claim.
    pub claim: Option<String>,
}

/// Which end of a connection a framing state is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Side {
    /// The end that accepted the connection.
    Accept,
    /// The end that dialled it.
    Dial,
}

/// Where a framer's dial goes, read off the address the destination spells: the carrier authority
/// to dial, whether the target asks for connection security, and the name that security checks the
/// far end against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    /// The carrier authority, `host:port`.
    pub authority: String,
    /// The target asks for the bytes to be secured before they leave this node.
    pub secure: bool,
    /// The name a presented certificate is checked against, where the target names one.
    pub server_name: Option<String>,
}

/// One piece of a frame a framer completed: the stream it belongs to, its bytes, whether it ends the
/// frame, and the status the frame reports where the framer's wire reports one. The status is read
/// in the numbering the framer declares (`TransportMeta::STATUS_NAMESPACE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framed<'a> {
    /// The stream the frame arrived on (`StreamId(0)` on a wire with one).
    pub stream: StreamId,
    /// The bytes.
    pub bytes: &'a [u8],
    /// This piece completes the frame.
    pub end_of_frame: bool,
    /// The status class the frame carries.
    pub status: Option<WireStatusClass>,
    /// The exact status number the frame carries, in the declared numbering.
    pub status_code: Option<u32>,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: Option<u64>,
    /// The bytes belong to a TEXT message, not a binary one
    /// ([`crate::abi::transport::PIECE_TEXT`]; read above the ABI as `FrameMeta::text`).
    pub text: bool,
}

impl<'a> Framed<'a> {
    /// A frame piece with no status: `bytes` on `stream`.
    #[must_use]
    pub const fn plain(stream: StreamId, bytes: &'a [u8], end_of_frame: bool) -> Self {
        Self {
            stream,
            bytes,
            end_of_frame,
            status: None,
            status_code: None,
            retry_after_secs: None,
            text: false,
        }
    }

    /// The same piece, stated as part of a TEXT message (`true`) or a binary one.
    #[must_use]
    pub const fn text(mut self, text: bool) -> Self {
        self.text = text;
        self
    }
}

/// THE HOST'S CLOCK, as a framer call sees it (the design's one clock, which also drives every
/// plugin's tick; the framer's clock comes from the connector's poll context): the host's monotonic
/// reading, which every deadline is stated against, and its wall time. A framer reads no clock of
/// its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HostTime {
    /// Nanoseconds on the host's monotonic clock.
    pub monotonic_nanos: u64,
    /// The host's wall time, nanoseconds since the Unix epoch.
    pub unix_nanos: u64,
}

/// Where a framer puts what a call produced: bytes owed to the far side, frame pieces for the layer
/// above, the end of the connection's frames, and the next instant it must be called at — and where
/// it reads the host's time.
pub trait FramerOut {
    /// Bytes for the far side, in order.
    fn send(&mut self, bytes: &[u8]);
    /// A frame piece for the layer above, in order.
    fn frame(&mut self, piece: Framed<'_>);
    /// No frame follows on this connection.
    fn end(&mut self);
    /// The host's time at this call.
    fn now(&self) -> HostTime;
    /// The monotonic instant the host must call [`Framer::tick`] for this state at, the latest
    /// statement winning; `None` = no deadline.
    fn wake_at(&mut self, monotonic_nanos: Option<u64>);
}

/// Where a framer puts the bytes a rendering produced.
pub trait BytesOut {
    /// Bytes, in order.
    fn put(&mut self, bytes: &[u8]);
}

impl BytesOut for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// A poll's answer.
pub type CarrierPoll<T> = Poll<Result<T, TransportError>>;

/// THE CARRIER ROLE: opens connections and moves their bytes (module docs). Connections and
/// listeners are the carrier's own opaque handles. No method blocks: a method that cannot progress
/// answers `Pending` and wakes `cx`'s waker once it may.
pub trait Carrier: Plugin + Send + Sync + 'static {
    /// Open a listener on `bind`, answering at once with its handle and the address actually bound.
    ///
    /// # Errors
    ///
    /// The address is not admissible or cannot be bound.
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError>;

    /// The next connection off `listener`, with its far end.
    fn poll_accept(&self, listener: u64, cx: &mut Context<'_>) -> CarrierPoll<(u64, String)>;

    /// BEGIN reaching `dest`, answering at once with the connection's handle. The opening completes
    /// under [`Self::poll_flush`], which answers the dial's refusal if it failed; reads and writes
    /// wait for it.
    ///
    /// # Errors
    ///
    /// `dest` is not a destination this carrier can reach.
    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError>;

    /// The next bytes of `conn` into `buf` (non-empty); `Ready(Ok(0))` is the clean end.
    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<usize>;

    /// Take some of `bytes` for `conn`: how many (`1..=len` for a non-empty offer).
    fn poll_write(&self, conn: u64, cx: &mut Context<'_>, bytes: &[u8]) -> CarrierPoll<usize>;

    /// Every byte `conn` took is on the wire — and, for a dialled connection, it is open.
    fn poll_flush(&self, conn: u64, cx: &mut Context<'_>) -> CarrierPoll<()>;

    /// Close `conn` for `reason` and release its handle; idempotent (an unknown handle is closed).
    /// Wakes a read or write parked on it, which sees it closed.
    fn poll_close(&self, conn: u64, cx: &mut Context<'_>, reason: CloseReason) -> CarrierPoll<()>;

    /// What the carrier knows about `conn`'s two ends; `None` for an unknown handle.
    fn arrival(&self, conn: u64) -> Option<CarrierFacts>;
}

/// THE FRAMER ROLE: a sans-IO framing state machine (module docs). A framing state is the framer's
/// own opaque handle; every method answers at once, and nothing here reads a socket or a clock.
pub trait Framer: Plugin + Send + Sync + 'static {
    /// Where a dial to `target` — the upstream address as the destination spells it — goes.
    ///
    /// # Errors
    ///
    /// `target` is not an address this framer's wire can reach.
    fn locate(&self, target: &str) -> Result<Located, TransportError>;

    /// Open a framing state for one connection's `side` (`target` is the dialled address, empty on
    /// an accepted connection), putting the bytes the far side is owed first — an opening handshake —
    /// into `out`.
    ///
    /// # Errors
    ///
    /// The framer cannot frame this connection.
    fn open(
        &self,
        side: Side,
        target: &str,
        facts: &ConnFacts,
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError>;

    /// Take `bytes` the carrier read for `state` (`end` = the carrier's clean end follows them),
    /// putting every frame piece they complete and every byte the far side is owed into `out`.
    ///
    /// # Errors
    ///
    /// The bytes broke this framer's wire; the state is closed.
    fn ingest(
        &self,
        state: u64,
        bytes: &[u8],
        end: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError>;

    /// Put the bytes that carry `bytes` on `stream` into `out`. `end_of_frame` marks the last piece
    /// of the frame; `text` says the frame is a TEXT message, not a binary one
    /// ([`crate::abi::transport::EMIT_TEXT`]), for a wire whose messages are one or the other (a
    /// wire that draws no such line ignores it).
    ///
    /// # Errors
    ///
    /// The frame cannot be carried on this state (framing, or a closed state), or a text frame is
    /// not UTF-8.
    fn emit(
        &self,
        state: u64,
        stream: StreamId,
        bytes: &[u8],
        end_of_frame: bool,
        text: bool,
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError>;

    /// Render an outbound envelope (`fields`, post-decoration) and `body` as this framer's wire
    /// bytes, into `out`.
    ///
    /// # Errors
    ///
    /// The envelope names something this wire cannot express.
    fn encode_envelope(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        out: &mut dyn BytesOut,
    ) -> Result<(), Encode>;

    /// Render a refusal the host already wrote (`bytes`) for bytes that never reached a plane — for
    /// `stream`, or the whole connection when `None` — into `out`. The state is closed after it.
    ///
    /// # Errors
    ///
    /// The state is closed.
    fn refusal(
        &self,
        state: u64,
        stream: Option<StreamId>,
        bytes: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<(), TransportError>;

    /// Close `state` for `reason`, putting the bytes a close is owed on this wire into `out`, and
    /// release it. Idempotent.
    fn close(&self, state: u64, reason: CloseReason, out: &mut dyn FramerOut);

    /// THE UPGRADE, source side: give up `state`, putting the bytes it holds and has not consumed
    /// into `out` (they belong to whatever the stream moves to), and release it.
    ///
    /// # Errors
    ///
    /// This state cannot hand its stream on (a closed state, or one mid-message).
    fn detach(&self, state: u64, out: &mut dyn BytesOut) -> Result<(), TransportError>;

    /// THE UPGRADE, target side: take over a byte stream another framer gave up, with the bytes it
    /// held (`leftover`), as `side`; answers the new framing state, putting the bytes the far side is
    /// owed into `out`.
    ///
    /// # Errors
    ///
    /// The stream is not one this framer can take over.
    fn adopt(
        &self,
        side: Side,
        facts: &ConnFacts,
        leftover: &[u8],
        out: &mut dyn FramerOut,
    ) -> Result<u64, TransportError>;

    /// A deadline `state` stated through [`FramerOut::wake_at`] has come: run what was waiting on
    /// it — a keep-alive ping, or the far end's missed answer to one — putting what it produced
    /// into `out`.
    ///
    /// # Errors
    ///
    /// The state is closed, or what was waiting failed it (a keep-alive the far end never
    /// answered).
    fn tick(&self, state: u64, out: &mut dyn FramerOut) -> Result<(), TransportError>;
}

#[cfg(test)]
#[path = "tests/stack_tests.rs"]
mod tests;
