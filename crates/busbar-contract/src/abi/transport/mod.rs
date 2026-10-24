// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S ABI (`BUSBAR-1.6.0.md` THE DESIGN, the connections and plugin ABI sections): its version, its
//! table, the `in`/`out` of every op, its Statement tail and its cancel vocabulary.
//!
//! TRANSPORT IS ONE KIND, BIDIRECTIONAL. A transport plays one of two ROLES, stated in its tail
//! ([`TransportTail::role`]):
//!
//! * a **CARRIER** listens, accepts, dials, reads and writes a byte stream (kind ops `0..=7`);
//! * a **FRAMER** is a sans-IO state machine over a carrier's bytes (kind ops `8..=17`): no socket,
//!   no waker, no clock of its own (the host hands it the clock in every call), and no auth service
//!   (the kernel makes the one outbound auth call before `encode`).
//!
//! THE SOCKET IS THE HOST'S. A framer that composes over nothing (an empty
//! [`TransportTail::composes_over`]) frames directly over the socket the connector holds; a framer
//! that names claims composes over them. A carrier composes over nothing, always: it is the bottom
//! of its stack.
//!
//! Direction is a usage mode, never a kind: the same carrier accepts and dials, the same framer
//! runs on either side ([`SIDE_ACCEPT`] / [`SIDE_DIAL`]). A plugin of ANY kind declares what it needs
//! as `(transport, auth)` per direction ([`crate::abi::host::conn::connector::Need`]); the kernel's
//! connector builds every connection as carrier → \[connection security\] → framer. Connection
//! security is core-only and never crosses this table: a framer is told only what the handshake
//! established, as facts ([`ConnFacts`]).
//!
//! THE TABLE. Every slot is a mechanism [`Op`] and every slot is non-NULL (a NULL slot refuses the
//! load). A transport fills the slots of the role it does not play with a stub that answers
//! [`crate::abi::mechanism::call::Outcome::Refused`]; the SDK supplies it.
//!
//! PER-CONNECTION TOKEN SPACE (the mechanism's ticket table exempts transport). A carrier
//! connection and a framing state are each named by a plugin-minted `u64` token (`conn`, `framing`,
//! `listener`), not by a ticket: there is no capacity cap on them and they are outside
//! `max_inflight`. Only `wake` is shared.
//!
//! TWO TICKETS PER CONNECTION. A connection is full-duplex, so the host holds TWO tickets for
//! it: a READ side (`read`, `accept` on a listener) and a WRITE side (`write`, `flush`, `shut`), each
//! with at most one op in flight. A PENDING op resumes, and a `cancel` addresses, exactly one side's
//! ticket; the other side is untouched. `dial` and `listen` run on the ticket of the op that asked.
//!
//! FRAMER OUTPUT goes into HOST buffers ([`FramerSink`]): bytes owed to the far side into `wire`,
//! frame bytes into `frame`, frame pieces (offsets into `frame`) into `pieces`. A framer that fills a
//! buffer answers READY with [`YIELD_MORE`] and the host calls the same op again once it has
//! drained them. That RE-CALL CARRIES NO NEW BYTES (an `ingest` or `emit` of length `0`): the bytes
//! of the first call were taken whole, and the re-call answers only what the first could not hold,
//! continuing where it stopped. A framer that answers any byte or piece twice is wrong. A framer op
//! never pends.
//!
//! A STREAM'S OWN BACKPRESSURE. A framer that queues a stream's emitted bytes until the far end is
//! ready for them (a multiplexed wire whose peer grants room stream by stream) answers an `emit`
//! that brings the queue to its high-water mark with [`YIELD_STREAM_FULL`]: the bytes were taken,
//! and the host emits nothing more on that stream, holding whatever feeds it (not-ready, with a
//! wake), until the framer hands a [`PIECE_WRITABLE`] piece on the stream (its queue drained below
//! the low-water mark) or the stream's end or failure piece. A host that keeps emitting past the
//! mark is the framer's to bound: it may fail the stream. This is the stream's, never the
//! connection's: [`YIELD_MORE`] still means only that a host buffer filled.
//!
//! STREAMS END BY FLAG. A frame is one or more pieces on one stream; the last carries
//! [`PIECE_END_OF_FRAME`]. A stream's frames END with a piece carrying [`PIECE_END`] (with
//! [`PIECE_END_OF_FRAME`], and no bytes); a stream that FAILED ends instead with a piece carrying
//! [`PIECE_STREAM_FAILED`] and [`PIECE_END_OF_FRAME`], its bytes the reason (never secret material).
//! Nothing else ends a stream: an EMPTY piece is an empty frame (a wire's empty message, text or
//! binary), never the stream's end. A failed stream fails alone: its siblings on the connection
//! carry on. [`YIELD_ENDED`] ends the CONNECTION, never one stream.
//!
//! FIELDS BY PIECE. A frame whose pieces carry [`PIECE_FIELDS`] is a FIELD BLOCK, never payload: the
//! far end's HEAD (a response's head fields, a call's initial metadata) is ONE such frame, the
//! stream's FIRST, carrying the status where the wire reports one there; it is framed even when no
//! field is left in it (an EMPTY fields piece, with [`PIECE_END_OF_FRAME`], is an empty head, never
//! the stream's end), so the head always precedes the first payload piece and a later fields frame
//! is the far end's fields after its body (trailers). The block's bytes are [`fields`]' rendering;
//! hop-by-hop fields never enter it: the framer drops them. A pseudo-field (`:method`, `:path`,
//! `:authority`, `:status`) never does either: on an ACCEPTED stream the request's method, target
//! and authority are typed [`HeadSlots`], a dialled answer's reason phrase too, and the answer's
//! number is the piece's own `code`.
//!
//! EVERY REQUEST-PATH RESULT IS IN A HOST BUFFER (memory class (i)): a carrier's addresses and read
//! bytes, a framer's wire bytes, frame bytes and pieces. The short-buffer rule is stated once,
//! on [`OutHead`](crate::abi::mechanism::call::OutHead); this kind's cases:
//!
//! * `arrival` and `locate` have the short path (`locate`'s authority and name are one
//!   multi-dimension answer).
//! * `listen` and `accept` have NO short path: the host passes `addr_cap`/`peer_cap >=`
//!   [`MAX_ADDR`] and an over-cap `*_written` is FAULT.
//! * `read` and `write` have no short path, and PARTIAL I/O IS NOT A SHORT BUFFER: a FAILED read or
//!   write MAY report the bytes it already moved in `len` (at most `cap`).
//! * A framer's full sink is BACKPRESSURE, not a short buffer: READY with [`YIELD_MORE`], and the
//!   host calls again once it has drained the sink.
//!
//! The tokens an `out` carries (`listener`, `conn`, `framing`) are names, not results.
//!
//! A CARRIER MOVES BYTES OVER THE HOST'S HANDLES. It opens, binds, accepts, reads, writes, shuts
//! and spawns through the host's I/O table (`abi::host::io`, `io.*`): it never holds a descriptor,
//! and the host opens only what it admitted for the dial that asked. Its frames: a carrier carried
//! as ITSELF (a need over its own claim, no framer above it) delimits them with
//! [`READ_END_OF_FRAME`] and [`WRITE_END_OF_FRAME`]; under a framer, its bytes are a stream.
//!
//! WHAT THE HOT-LANE `TransportDecl` BECOMES (a mechanical re-heading):
//!
//! | `TransportDecl` / slot table | here |
//! |---|---|
//! | `abi`, `size`, `version` | the door's magic, mechanism version, `kind_abi` and [`crate::abi::mechanism::door::KindTailHead::size`] |
//! | `key` | the Statement's `claims[0]` (the entry's own claim; the Statement holds every claimed scheme's name) |
//! | `composes_over` | [`TransportTail::composes_over`]; [`TransportTail::role`] states the role outright |
//! | `selector_forms`, `egress_selector_forms`, `transport_facts`, `status_namespace`, `session`, `session_bound`, `unit0_trigger`, `status_at` | per claim, [`Claim`] |
//! | `handoff_*`, `upgrades_to`, `handshake_frame_kind`, `handshake_max_steps` | [`TransportTail`] |
//! | (none: new here) | [`TransportTail::fault_rows`], each claim's breaker reading of its numbering; [`FramePiece::fault`] |
//! | `framing`, `decodes_payload` | [`TransportTail::framing`], [`FACT_DECODES_PAYLOAD`] |
//! | `claims` | the Statement's `claims` (the names) and [`TransportTail::claim_rows`] (each name's row, by index) |
//! | `init` + `WireSettings` + `WireWaker` | lifecycle `open` (settings blob, host tables with `wake`); the settings a transport reads are declared in [`TransportTail::settings`] |
//! | `CarrierSlots` (8) | kind ops `0..=7` |
//! | `FramerSlots` (10) | kind ops `8..=17`; `FramerOut`'s callbacks become [`FramerSink`] host buffers |
//!
//! ```
//! use std::mem::{offset_of, size_of};
//! use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
//! use busbar_contract::abi::transport::{slot, Ops, KIND_SLOTS, SLOTS};
//! // Kind op `k` is at slot index LIFECYCLE_SLOTS + k, contiguous after the lifecycle head.
//! let order = [
//!     (slot::LISTEN, offset_of!(Ops, listen)),
//!     (slot::ACCEPT, offset_of!(Ops, accept)),
//!     (slot::DIAL, offset_of!(Ops, dial)),
//!     (slot::READ, offset_of!(Ops, read)),
//!     (slot::WRITE, offset_of!(Ops, write)),
//!     (slot::FLUSH, offset_of!(Ops, flush)),
//!     (slot::SHUT, offset_of!(Ops, shut)),
//!     (slot::ARRIVAL, offset_of!(Ops, arrival)),
//!     (slot::LOCATE, offset_of!(Ops, locate)),
//!     (slot::BEGIN, offset_of!(Ops, begin)),
//!     (slot::INGEST, offset_of!(Ops, ingest)),
//!     (slot::EMIT, offset_of!(Ops, emit)),
//!     (slot::ENCODE, offset_of!(Ops, encode)),
//!     (slot::REFUSE, offset_of!(Ops, refuse)),
//!     (slot::FINISH, offset_of!(Ops, finish)),
//!     (slot::DETACH, offset_of!(Ops, detach)),
//!     (slot::ADOPT, offset_of!(Ops, adopt)),
//!     (slot::TIMER, offset_of!(Ops, timer)),
//! ];
//! assert_eq!(order.len() as u32, KIND_SLOTS);
//! for (k, (index, offset)) in order.into_iter().enumerate() {
//!     assert_eq!(index, LIFECYCLE_SLOTS + k as u32);
//!     assert_eq!(offset, size_of::<OpsHead>() + 8 * k);
//! }
//! assert_eq!(SLOTS, LIFECYCLE_SLOTS + KIND_SLOTS);
//! assert_eq!(size_of::<Ops>(), size_of::<OpsHead>() + 8 * KIND_SLOTS as usize);
//! ```

pub mod check;
pub mod datagram;
pub mod fields;
pub mod route;

pub use datagram::{
    DatagramLane, DatagramPath, DatagramRoute, DatagramYield, KeyingMaterial, RendezvousTerms,
    FINGERPRINT_BYTES, HANDSHAKE_ANSWERS, HANDSHAKE_INITIATES, HANDSHAKE_NONE, LANE_CLEAR,
    LANE_RENDEZVOUS, LANE_SECURED, MAX_KEYING_BYTES, MAX_ROUTES, PATH_REQUEST_BIND,
    PATH_REQUEST_NONE, PATH_REQUEST_REBIND,
};

/// THE AUTH POINTS a transport offers and calls its bound auth at (THE DESIGN, "Auth points
/// and guest lists", step 1): defined once in `abi::auth`, referred to here, never redefined.
pub use super::auth::{
    AuthPoint, AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER,
};

use super::mechanism::call::{AbiStr, Field, InHead, Op, OutHead, Span};
use super::mechanism::check::{contract, OpContract};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The transport kind's ABI version: new in 1.6.0 (v1.5.5 had no transport kind ABI), so it ships `1`.
pub const ABI_VERSION: u32 = 1;

/// The transport kind's generation as the Rust face states it (`Plugin::abi`): [`ABI_VERSION`]
/// itself, defined here and nowhere else, so a bump of the kind's version moves it and there is no
/// second number to fall behind (THE DESIGN, the ABI folders: an ABI version constant lives under `abi/`).
pub const TRANSPORT_ABI: crate::transport::AbiVersion =
    crate::transport::AbiVersion(ABI_VERSION as u16);

// The Rust face is a `u16`: a kind version that outgrew it would truncate, so it refuses to build.
const _: () = assert!(ABI_VERSION <= u16::MAX as u32);

/// [`crate::abi::mechanism::call::InHead::op`] of each transport op, in table order: kind op `k` is
/// [`LIFECYCLE_SLOTS`]` + k`.
pub mod slot {
    use super::LIFECYCLE_SLOTS;

    /// Carrier: bind a listener.
    pub const LISTEN: u32 = LIFECYCLE_SLOTS;
    /// Carrier: accept one connection.
    pub const ACCEPT: u32 = LIFECYCLE_SLOTS + 1;
    /// Carrier: dial a destination.
    pub const DIAL: u32 = LIFECYCLE_SLOTS + 2;
    /// Carrier: read bytes.
    pub const READ: u32 = LIFECYCLE_SLOTS + 3;
    /// Carrier: write bytes.
    pub const WRITE: u32 = LIFECYCLE_SLOTS + 4;
    /// Carrier: flush.
    pub const FLUSH: u32 = LIFECYCLE_SLOTS + 5;
    /// Carrier: shut a connection down.
    pub const SHUT: u32 = LIFECYCLE_SLOTS + 6;
    /// Carrier: the far end and local port of an accepted connection.
    pub const ARRIVAL: u32 = LIFECYCLE_SLOTS + 7;
    /// Framer: the authority, offered name and secure bit of a target.
    pub const LOCATE: u32 = LIFECYCLE_SLOTS + 8;
    /// Framer: begin framing a connection.
    pub const BEGIN: u32 = LIFECYCLE_SLOTS + 9;
    /// Framer: bytes from the far side.
    pub const INGEST: u32 = LIFECYCLE_SLOTS + 10;
    /// Framer: bytes for the far side, on one stream.
    pub const EMIT: u32 = LIFECYCLE_SLOTS + 11;
    /// Framer: render an envelope (fields + body).
    pub const ENCODE: u32 = LIFECYCLE_SLOTS + 12;
    /// Framer: render a refusal.
    pub const REFUSE: u32 = LIFECYCLE_SLOTS + 13;
    /// Framer: close the framing.
    pub const FINISH: u32 = LIFECYCLE_SLOTS + 14;
    /// Framer: hand back the unconsumed bytes (an upgrade).
    pub const DETACH: u32 = LIFECYCLE_SLOTS + 15;
    /// Framer: adopt a connection another framer detached.
    pub const ADOPT: u32 = LIFECYCLE_SLOTS + 16;
    /// Framer: a deadline the framer asked for passed.
    pub const TIMER: u32 = LIFECYCLE_SLOTS + 17;
}

/// How many kind ops the table holds after the lifecycle.
pub const KIND_SLOTS: u32 = 18;
/// How many slots the whole table holds ([`OpsHead::slots`]).
pub const SLOTS: u32 = LIFECYCLE_SLOTS + KIND_SLOTS;

/// The transport kind's ops table: the lifecycle, then the carrier's eight ops, then the framer's
/// ten.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Ops {
    /// The lifecycle.
    pub head: OpsHead,
    /// [`slot::LISTEN`]: in [`ListenIn`], out [`ListenOut`].
    pub listen: Option<Op>,
    /// [`slot::ACCEPT`]: in [`AcceptIn`], out [`AcceptOut`].
    pub accept: Option<Op>,
    /// [`slot::DIAL`]: in [`DialIn`], out [`ConnOut`].
    pub dial: Option<Op>,
    /// [`slot::READ`]: in [`ReadIn`], out [`IoOut`] (`len` 0 = the end).
    pub read: Option<Op>,
    /// [`slot::WRITE`]: in [`WriteIn`], out [`IoOut`] (how many it took).
    pub write: Option<Op>,
    /// [`slot::FLUSH`]: in [`ConnIn`], out [`OutHead`].
    pub flush: Option<Op>,
    /// [`slot::SHUT`]: in [`ShutIn`], out [`OutHead`].
    pub shut: Option<Op>,
    /// [`slot::ARRIVAL`]: in [`ArrivalIn`], out [`ArrivalOut`]; FAILED for an unknown connection.
    pub arrival: Option<Op>,
    /// [`slot::LOCATE`]: in [`LocateIn`], out [`LocateOut`].
    pub locate: Option<Op>,
    /// [`slot::BEGIN`]: in [`BeginIn`], out [`FramerOut`] (writes `framing`).
    pub begin: Option<Op>,
    /// [`slot::INGEST`]: in [`IngestIn`], out [`FramerOut`].
    pub ingest: Option<Op>,
    /// [`slot::EMIT`]: in [`EmitIn`], out [`FramerOut`].
    pub emit: Option<Op>,
    /// [`slot::ENCODE`]: in [`EncodeIn`], out [`FramerOut`]; a refusal to render is FAILED with the
    /// reason in `head.error`.
    pub encode: Option<Op>,
    /// [`slot::REFUSE`]: in [`RefuseIn`], out [`FramerOut`].
    pub refuse: Option<Op>,
    /// [`slot::FINISH`]: in [`FinishIn`], out [`FramerOut`].
    pub finish: Option<Op>,
    /// [`slot::DETACH`]: in [`FramingIn`], out [`FramerOut`] (the unconsumed bytes in `frame`).
    pub detach: Option<Op>,
    /// [`slot::ADOPT`]: in [`AdoptIn`], out [`FramerOut`] (writes `framing`).
    pub adopt: Option<Op>,
    /// [`slot::TIMER`]: in [`FramingIn`], out [`FramerOut`].
    pub timer: Option<Op>,
}

// ── the op contracts ─────────────────────────────────────────────────────────────────────────────

/// The largest address `listen` or `accept` may write: the host's `addr_cap`/`peer_cap` is at
/// least this (those ops have no short path).
pub const MAX_ADDR: u64 = 256;

/// Every kind op's contract, in slot order. Carrier I/O pends on its side's ticket (read or write) under the carrier's idle timeout ([`DeadlineClass::Connection`]); `listen` is boot-time and off-path. A
/// framer is sans-IO: every framer op is request-path, never pends, and runs under the stream's
/// deadline.
#[rustfmt::skip]
pub const CONTRACTS: [OpContract; KIND_SLOTS as usize] = [
    contract!(LISTEN, false, true, ListenIn, ListenOut, Call),
    contract!(ACCEPT, true, true, AcceptIn, AcceptOut, Connection),
    contract!(DIAL, true, true, DialIn, ConnOut, Connection),
    contract!(READ, true, true, ReadIn, IoOut, Connection),
    contract!(WRITE, true, true, WriteIn, IoOut, Connection),
    contract!(FLUSH, true, true, ConnIn, OutHead, Connection),
    contract!(SHUT, true, true, ShutIn, OutHead, Connection),
    contract!(ARRIVAL, true, false, ArrivalIn, ArrivalOut, Call),
    contract!(LOCATE, true, false, LocateIn, LocateOut, Call),
    contract!(BEGIN, true, false, BeginIn, FramerOut, Stream),
    contract!(INGEST, true, false, IngestIn, FramerOut, Stream),
    contract!(EMIT, true, false, EmitIn, FramerOut, Stream),
    contract!(ENCODE, true, false, EncodeIn, FramerOut, Stream),
    contract!(REFUSE, true, false, RefuseIn, FramerOut, Stream),
    contract!(FINISH, true, false, FinishIn, FramerOut, Stream),
    contract!(DETACH, true, false, FramingIn, FramerOut, Stream),
    contract!(ADOPT, true, false, AdoptIn, FramerOut, Stream),
    contract!(TIMER, true, false, FramingIn, FramerOut, Stream),
];

// ── the cancel vocabulary ────────────────────────────────────────────────────────────────────────

/// [`crate::abi::mechanism::lifecycle::CancelOut::disposition`]: the cancelled carrier op had not
/// started; nothing moved.
pub const CANCEL_NOTHING_MOVED: u32 = 1;
/// The cancelled carrier op moved some bytes; the connection is no longer usable and the host shuts
/// it with [`CLOSE_TRANSPORT_FAILED`].
pub const CANCEL_PARTIAL: u32 = 2;
/// The cancelled op had completed before the cancel landed; its result stands.
pub const CANCEL_COMPLETED: u32 = 3;

// ── the vocabulary codes ─────────────────────────────────────────────────────────────────────────

/// [`TransportTail::role`]: a carrier.
pub const ROLE_CARRIER: u32 = 1;
/// [`TransportTail::role`]: a framer.
pub const ROLE_FRAMER: u32 = 2;

/// [`TransportTail::framing`]: an ordered byte stream.
pub const FRAMING_STREAM: u32 = 0;
/// [`TransportTail::framing`]: datagrams.
pub const FRAMING_DATAGRAM: u32 = 1;

/// [`TransportTail::facts`]: the framer adds no signed field after the kernel's auth call
/// (RED-tested at the kernel).
pub const FACT_SIGNS_NOTHING_AFTER_AUTH: u32 = 1;
/// [`TransportTail::facts`]: the framer decodes the payload.
pub const FACT_DECODES_PAYLOAD: u32 = 2;

/// THE OFFERED-POINTS RECORD: the key under which a transport's Statement `extensions` states
/// the auth points it offers (THE DESIGN, "Auth points and guest lists"; the blob's bytes are
/// [`crate::abi::mechanism::extensions`]'s keyed entries, so no layout changes). The value is four
/// bytes, a little-endian [`AuthPoints`] set of [`POINT_PEER`] | [`POINT_HEAD`] |
/// [`POINT_HEAD_BODY`]; another length or bit refuses the load ([`check::check_offered_points`]).
/// A transport that states no record offers `{Head, HeadBody}`, the request points 1.5.5's chain
/// was called at. Boot refuses a line whose auth needs a point its transport does not offer.
pub const EXT_OFFERED_POINTS: &str = "offered-points";

/// `side`: the accepting end.
pub const SIDE_ACCEPT: u32 = 0;
/// `side`: the dialing end.
pub const SIDE_DIAL: u32 = 1;
/// `side`: the accepting end of ONE STREAM whose connection and head the host's own framer carries
/// (ARCHITECT 4l, 2026-10-05: one listener port carries every claim's streams, so a claim's framer
/// frames the stream, not the connection). Its one stream is stream `1`. `begin` takes the stream's
/// target and its head fields ([`BeginIn::fields`]); `ingest` takes the stream's body bytes and
/// yields each message as a piece that ends its frame (no piece ends the stream: the host's framer
/// knows where its body ended); `emit` takes one message's bytes (`end_of_frame` = it ends) and yields the
/// stream's body bytes in `wire`; `refuse` and `finish` yield the stream's CLOSING FIELD BLOCK in
/// `wire`, as field lines (`name: value` CRLF each), which the host sends verbatim: after a head as
/// its trailers, before one as the fields of an answer that is nothing else. `finish` states the
/// stream's final status ([`FinishIn::final_status`]).
pub const SIDE_ACCEPT_STREAM: u32 = 2;

/// Close reason: normal.
pub const CLOSE_NORMAL: u32 = 0;
/// Close reason: the far end closed.
pub const CLOSE_PEER_CLOSED: u32 = 1;
/// Close reason: drain.
pub const CLOSE_DRAIN: u32 = 2;
/// Close reason: poisoned.
pub const CLOSE_POISONED: u32 = 3;
/// Close reason: revoked.
pub const CLOSE_REVOKED: u32 = 4;
/// Close reason: timeout.
pub const CLOSE_TIMEOUT: u32 = 5;
/// Close reason: the carrier failed.
pub const CLOSE_TRANSPORT_FAILED: u32 = 6;
/// Close reason: capacity exhausted.
pub const CLOSE_CAPACITY_EXHAUSTED: u32 = 7;

/// Status class: none stated.
pub const STATUS_NONE: u8 = 0;
/// Status class: success.
pub const STATUS_SUCCESS: u8 = 1;
/// Status class: the caller's fault.
pub const STATUS_CALLER_FAULT: u8 = 2;
/// Status class: the far end's fault.
pub const STATUS_FAR_END_FAULT: u8 = 3;
/// Status class: other.
pub const STATUS_OTHER: u8 = 4;

/// Fault reading: none stated — no reading, the status table decides. On a frame piece that table
/// is the framer's own fault table, and an answer it covers with no reading is read as the
/// caller's (nothing is recorded against the destination): a framer that states no fault table
/// never trips anything. On a plane's `OnPieceOut::fault` it is the transport's reading of the
/// same answer that stands.
pub const FAULT_NONE: u8 = 0;
/// Fault reading: the caller's own fault. The destination is healthy and nothing is recorded.
pub const FAULT_CALLER: u8 = 1;
/// Fault reading: a transient fault of the destination. Its cell counts it toward a trip, and the
/// piece's `retry_after_secs`, where stated, floors the cooldown.
pub const FAULT_TRANSIENT: u8 = 2;
/// Fault reading: the destination itself is down for every caller (its credential or its account
/// was refused), so every pool's cell for it trips at once.
pub const FAULT_HARD: u8 = 3;
/// Fault reading: the destination is HEALTHY. It answered; the breaker records a SUCCESS against
/// it whatever the answer's status (a well-formed protocol error from a reachable destination, as
/// 1.5.5 counted it: "the backend was reachable and answered"). The answer is relayed as it came.
pub const FAULT_HEALTHY: u8 = 4;

/// [`Claim::status_at`]: no status.
pub const STATUS_AT_NONE: u8 = 0;
/// [`Claim::status_at`]: the first frame carries the status.
pub const STATUS_AT_FIRST_FRAME: u8 = 1;
/// [`Claim::status_at`]: the terminal frame carries the status.
pub const STATUS_AT_TERMINAL: u8 = 2;

/// [`Claim::unit0_trigger`]: none.
pub const UNIT0_NONE: u8 = 0;
/// [`Claim::unit0_trigger`]: the first bytes.
pub const UNIT0_FIRST_BYTES: u8 = 1;
/// [`Claim::unit0_trigger`]: the first line.
pub const UNIT0_FIRST_LINE: u8 = 2;
/// [`Claim::unit0_trigger`]: the first message.
pub const UNIT0_FIRST_MESSAGE: u8 = 3;
/// [`Claim::unit0_trigger`]: the first datagram.
pub const UNIT0_FIRST_DATAGRAM: u8 = 4;
/// [`Claim::unit0_trigger`]: an upgrade.
pub const UNIT0_UPGRADE: u8 = 5;
/// [`Claim::unit0_trigger`]: a handshake.
pub const UNIT0_HANDSHAKE: u8 = 6;

/// [`Claim::flags`]: the scheme is the secure form of its wire (the host secures the connection).
/// BUSBAR-1.6.0.md #50: a transport declares each scheme it serves, its secure form among them, and
/// a provider's base URL selects the claim its scheme names. A claim without this bit is plaintext.
pub const CLAIM_SECURE: u32 = 1;

/// [`SettingDecl::kind`]: `0`/`1`.
pub const SETTING_FLAG: u32 = 1;
/// [`SettingDecl::kind`]: an unsigned integer.
pub const SETTING_COUNT: u32 = 2;
/// [`SettingDecl::kind`]: text.
pub const SETTING_TEXT: u32 = 3;

/// [`Destination::kind`]: an authority.
pub const DEST_AUTHORITY: u32 = 0;
/// [`Destination::kind`]: a program the carrier runs.
pub const DEST_PROGRAM: u32 = 1;

/// [`FramePiece::flags`]: the piece completes its frame.
pub const PIECE_END_OF_FRAME: u16 = 1;
/// [`FramePiece::flags`]: `code` is present.
pub const PIECE_HAS_CODE: u16 = 2;
/// [`FramePiece::flags`]: `retry_after_secs` is present.
pub const PIECE_HAS_RETRY_AFTER: u16 = 4;
/// [`FramePiece::flags`]: the stream FAILED; the piece's bytes are the reason. Always with
/// [`PIECE_END_OF_FRAME`]: it is the stream's last piece.
pub const PIECE_STREAM_FAILED: u16 = 8;

/// [`FramePiece::flags`]: the piece's bytes are a FIELD BLOCK (the far end's head or its trailers),
/// never payload. Never with [`PIECE_STREAM_FAILED`].
pub const PIECE_FIELDS: u16 = 16;

/// [`FramePiece::flags`], with [`PIECE_FIELDS`]: the piece's first byte CONTINUES a line an earlier
/// piece of the block began (a sink too small for the block split it mid-line). A fields piece
/// without it starts a line.
pub const PIECE_CONTINUED: u16 = 32;

/// [`FramePiece::flags`]: the piece's bytes belong to a TEXT message, not a binary one, on a wire
/// whose messages are one or the other (ws's TEXT and BINARY opcodes). Absent means binary, the
/// meaning every framer that never sets it keeps. On every piece of a text message, an EMPTY text
/// message's one piece too; never on a field block, a failed stream's reason or a stream's
/// [`PIECE_END`]. The host reads it into `FrameMeta::text`, the bit's one home above the ABI.
pub const PIECE_TEXT: u16 = 64;

/// [`FramePiece::flags`]: the stream ENDS whole here; no piece of it follows. The ONLY way a
/// stream ends whole (an empty piece without it is an empty frame, never the end). Always with
/// [`PIECE_END_OF_FRAME`] and on an EMPTY piece (`len == 0`): an end that carried bytes would make
/// them a message the end swallows. Never with [`PIECE_STREAM_FAILED`] (a failed stream's piece
/// ends it failed), [`PIECE_FIELDS`] (an empty fields piece is an empty head) or [`PIECE_TEXT`].
pub const PIECE_END: u16 = 128;

/// [`FramePiece::flags`]: the stream is WRITABLE again: the queue an `emit` answered with
/// [`YIELD_STREAM_FULL`] drained below the framer's low-water mark, and the host may emit on the
/// stream again. Always an EMPTY piece, with no other flag: it ends no frame and no stream.
pub const PIECE_WRITABLE: u16 = 256;

/// [`FramePiece::flags`], with [`PIECE_FIELDS`]: `declared_len` is present, the body length the
/// message's head declared on the wire. Never on any other piece.
pub const PIECE_HAS_DECLARED_LEN: u16 = 512;

/// The size of one [`FramePiece`], in bytes: the stride of [`FramerSink::pieces`].
/// [`TransportTail::frame_piece_size`] states it, so a framer built against another piece layout
/// is refused at load, never read wrong.
pub const FRAME_PIECE_SIZE: u32 = 48;

/// [`EmitIn::flags`]: the bytes are a TEXT message, not a binary one, on a wire whose messages are
/// one or the other (ws sends them under its TEXT opcode); read on the call that completes the
/// frame. Absent means binary. The outbound twin of [`PIECE_TEXT`].
pub const EMIT_TEXT: u32 = 1;

/// [`WriteIn::flags`]: the bytes complete a FRAME of the carrier's own wire, for a carrier that
/// delimits frames itself (a carrier carried as itself, with no framer above it). A carrier that
/// carries an undelimited byte stream ignores it.
pub const WRITE_END_OF_FRAME: u32 = 1;

/// [`IoOut::flags`] on a `read`: the bytes complete a FRAME of the carrier's own wire. A carrier
/// whose wire is an undelimited byte stream sets it on every read: each read is a frame, the
/// degenerate case. A frame longer than the host's buffer comes in several reads, the last one
/// carrying it.
pub const READ_END_OF_FRAME: u32 = 1;

/// [`FramerYield::flags`]: no frame follows on this connection.
pub const YIELD_ENDED: u32 = 1;
/// [`FramerYield::flags`]: a buffer filled; call the same op again once drained.
pub const YIELD_MORE: u32 = 2;
/// [`FramerYield::flags`]: `next_deadline_ns` is set; call [`slot::TIMER`] then.
pub const YIELD_HAS_DEADLINE: u32 = 4;
/// [`FramerYield::flags`], on `emit` only: the bytes were taken and the stream's queue is at its
/// high-water mark; emit nothing more on it until a [`PIECE_WRITABLE`] piece or its last piece.
pub const YIELD_STREAM_FULL: u32 = 8;

// ── the Statement tail ───────────────────────────────────────────────────────────────────────────

/// One claim's ROW: the per-scheme facts of the scheme the Statement's `claims` names at the same
/// index (the name itself is stated only there). The first claim is the entry's own. Two entries
/// claiming one scheme refuse boot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Claim {
    /// Its selector forms, one code byte each (the transport vocabulary's numbering).
    pub selector_forms: AbiStr,
    /// Its outbound selector forms, one code byte each.
    pub egress_selector_forms: AbiStr,
    /// Its transport fact keys.
    pub facts: *const AbiStr,
    /// How many.
    pub facts_len: usize,
    /// Its status numbering (absent = none).
    pub status_namespace: AbiStr,
    /// `1` = it carries sessions.
    pub session: u8,
    /// `1` = a session on it caches its principal.
    pub session_bound: u8,
    /// What opens a session's first unit (`UNIT0_*`).
    pub unit0_trigger: u8,
    /// Which frame carries its status (`STATUS_AT_*`).
    pub status_at: u8,
    /// [`CLAIM_SECURE`], or `0`; any other bit refuses the load ([`check::check_claims`]). Zero is a
    /// PLAINTEXT scheme: a claim that does not state it is never taken for a secure one (it was the
    /// row's alignment padding, read `0` by every plugin built before it was named).
    pub flags: u32,
}

impl Claim {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `Claim { …, ..Claim::ZERO }` so a field appended later reads as not
    /// declared.
    pub const ZERO: Self = Self {
        selector_forms: AbiStr::ZERO,
        egress_selector_forms: AbiStr::ZERO,
        facts: std::ptr::null(),
        facts_len: 0,
        status_namespace: AbiStr::ZERO,
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at: 0,
        _reserved: 0,
    };
}

/// HOW THE TRANSPORT CLAIM ROW IS MADE (status row 194): from [`Claim::EMPTY`], its plain fields
/// set directly and each list by its setter, to items that live for the program.
impl Claim {
    /// Nothing stated: every string absent, every list empty, every number zero.
    pub const EMPTY: Claim = Claim {
        selector_forms: AbiStr::ABSENT,
        egress_selector_forms: AbiStr::ABSENT,
        facts: std::ptr::null(),
        facts_len: 0,
        status_namespace: AbiStr::ABSENT,
        session: 0,
        session_bound: 0,
        unit0_trigger: 0,
        status_at: 0,
        _reserved: 0,
    };

    abi_lists! {
        facts, facts_len: AbiStr => facts_ptr, with_facts, with_raw_facts;
    }
}

/// One status-table row: a code range of a claim's numbering and the class it means. The breaker
/// reads classes only, never a code band (the design's connections section).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StatusRow {
    /// Index into [`TransportTail::claim_rows`] (and so into the Statement's `claims`).
    pub claim: u32,
    /// The lowest code, inclusive.
    pub lo: u32,
    /// The highest code, inclusive.
    pub hi: u32,
    /// The class (`STATUS_*`).
    pub class: u32,
}

impl StatusRow {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `StatusRow { …, ..StatusRow::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        claim: 0,
        lo: 0,
        hi: 0,
        class: 0,
    };
}

/// One fault-table row: a code range of a claim's numbering and the fault reading it means to the
/// breaker (`FAULT_*`). The framer reads its own table to fill [`FramePiece::fault`]; the host reads
/// the piece's reading and never a code band. A separate table from the status rows on purpose: the
/// status class is the fee decision's leg and is never bent to serve the breaker.
///
/// A claim that states status rows states fault rows too, or the load is refused
/// ([`check::check_fault_cover`]): an answer the framer can class it can also read for the breaker.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FaultRow {
    /// Index into [`TransportTail::claim_rows`] (and so into the Statement's `claims`).
    pub claim: u32,
    /// The lowest code, inclusive.
    pub lo: u32,
    /// The highest code, inclusive.
    pub hi: u32,
    /// The fault reading (`FAULT_CALLER` | `FAULT_TRANSIENT` | `FAULT_HARD` | `FAULT_HEALTHY`).
    pub fault: u32,
}

impl FaultRow {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `FaultRow { …, ..FaultRow::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        claim: 0,
        lo: 0,
        hi: 0,
        fault: 0,
    };
}

/// One customer setting the transport reads, at its 1.5.5 path (the connector deals the value to
/// the plugin's `validate`/`open`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SettingDecl {
    /// The setting's config path.
    pub path: AbiStr,
    /// `SETTING_*`.
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// Its default, as text.
    pub default: AbiStr,
}

impl SettingDecl {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `SettingDecl { …, ..SettingDecl::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        path: AbiStr::ZERO,
        kind: 0,
        _reserved: 0,
        default: AbiStr::ZERO,
    };
}

/// THE TRANSPORT'S STATEMENT TAIL: static facts, `'static` data.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransportTail {
    /// The tail head.
    pub head: KindTailHead,
    /// [`ROLE_CARRIER`] | [`ROLE_FRAMER`]; a carrier's `composes_over` is empty.
    pub role: u32,
    /// `FRAMING_*`.
    pub framing: u32,
    /// `FACT_*` bits; any other bit refuses the load.
    pub facts: u32,
    /// The most handshake steps before the first unit.
    pub handshake_max_steps: u32,
    /// The claims a framer composes over (empty = directly over the host's socket); empty for a
    /// carrier.
    pub composes_over: *const AbiStr,
    /// How many.
    pub composes_over_len: usize,
    /// Each claimed scheme's row: row `i` describes the Statement's `claims[i]`, the ONE place the
    /// scheme names are stated (signed, and byte-compared at admit).
    pub claim_rows: *const Claim,
    /// How many (at least one; exactly the Statement's `claims_len`).
    pub claim_rows_len: usize,
    /// The claims a connection may upgrade to.
    pub upgrades_to: *const AbiStr,
    /// How many.
    pub upgrades_to_len: usize,
    /// The handoff's source claim (absent = no handoff).
    pub handoff_from: AbiStr,
    /// The handoff's target claim.
    pub handoff_to: AbiStr,
    /// The fact that binds the handoff.
    pub handoff_binding_fact: AbiStr,
    /// The frame kind that triggers the handshake (absent = none).
    pub handshake_frame_kind: AbiStr,
    /// The status table.
    pub status_rows: *const StatusRow,
    /// How many.
    pub status_rows_len: usize,
    /// The customer settings it reads.
    pub settings: *const SettingDecl,
    /// How many.
    pub settings_len: usize,
    /// The fault table (appended: a tail that predates it reads NULL/`0`, no fault table).
    pub fault_rows: *const FaultRow,
    /// How many.
    pub fault_rows_len: usize,
    /// [`FRAME_PIECE_SIZE`] as the plugin was built: the stride it writes [`FramerSink::pieces`]
    /// at. The loader refuses a transport whose number is not the host's (a tail that predates the
    /// word states `0`), naming the rebuild.
    pub frame_piece_size: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

impl TransportTail {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `TransportTail { …, ..TransportTail::ZERO }` so a field appended later
    /// reads as not declared.
    pub const ZERO: Self = Self {
        head: KindTailHead::ZERO,
        role: 0,
        framing: 0,
        facts: 0,
        handshake_max_steps: 0,
        composes_over: std::ptr::null(),
        composes_over_len: 0,
        claim_rows: std::ptr::null(),
        claim_rows_len: 0,
        upgrades_to: std::ptr::null(),
        upgrades_to_len: 0,
        handoff_from: AbiStr::ZERO,
        handoff_to: AbiStr::ZERO,
        handoff_binding_fact: AbiStr::ZERO,
        handshake_frame_kind: AbiStr::ZERO,
        status_rows: std::ptr::null(),
        status_rows_len: 0,
        settings: std::ptr::null(),
        settings_len: 0,
        fault_rows: std::ptr::null(),
        fault_rows_len: 0,
        frame_piece_size: 0,
        _reserved: 0,
    };
}

/// HOW THE TRANSPORT KIND TAIL IS MADE (status row 194): from [`TransportTail::EMPTY`], its plain
/// fields set directly and each list by its setter, to items that live for the program.
impl TransportTail {
    /// Nothing stated: every string absent, every list empty, every number zero; the head
    /// sized to the whole tail.
    pub const EMPTY: TransportTail = TransportTail {
        head: KindTailHead {
            size: core::mem::size_of::<TransportTail>() as u32,
            _reserved: 0,
        },
        role: 0,
        framing: 0,
        facts: 0,
        handshake_max_steps: 0,
        composes_over: std::ptr::null(),
        composes_over_len: 0,
        claim_rows: std::ptr::null(),
        claim_rows_len: 0,
        upgrades_to: std::ptr::null(),
        upgrades_to_len: 0,
        handoff_from: AbiStr::ABSENT,
        handoff_to: AbiStr::ABSENT,
        handoff_binding_fact: AbiStr::ABSENT,
        handshake_frame_kind: AbiStr::ABSENT,
        status_rows: std::ptr::null(),
        status_rows_len: 0,
        settings: std::ptr::null(),
        settings_len: 0,
        fault_rows: std::ptr::null(),
        fault_rows_len: 0,
        frame_piece_size: 0,
        _reserved: 0,
    };

    abi_lists! {
        composes_over, composes_over_len: AbiStr
            => composes_over_ptr, with_composes_over, with_raw_composes_over;
        claim_rows, claim_rows_len: Claim => claim_rows_ptr, with_claim_rows, with_raw_claim_rows;
        upgrades_to, upgrades_to_len: AbiStr
            => upgrades_to_ptr, with_upgrades_to, with_raw_upgrades_to;
        status_rows, status_rows_len: StatusRow
            => status_rows_ptr, with_status_rows, with_raw_status_rows;
        settings, settings_len: SettingDecl => settings_ptr, with_settings, with_raw_settings;
        fault_rows, fault_rows_len: FaultRow
            => fault_rows_ptr, with_fault_rows, with_raw_fault_rows;
    }
}

// ── shared shapes ────────────────────────────────────────────────────────────────────────────────

/// A carrier's destination, borrowed for the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Destination {
    /// [`DEST_AUTHORITY`] | [`DEST_PROGRAM`].
    pub kind: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The authority ([`DEST_AUTHORITY`]).
    pub authority: AbiStr,
    /// The program's absolute path ([`DEST_PROGRAM`]).
    pub program: AbiStr,
    /// Its arguments.
    pub args: *const AbiStr,
    /// How many.
    pub args_len: usize,
    /// Its whole environment.
    pub env: *const Field,
    /// How many.
    pub env_len: usize,
}

/// What connection security established, as facts: never key or certificate material. Each string
/// absent when not established; the three certificate facts are present together.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnFacts {
    /// `size_of::<ConnFacts>()` at construction.
    pub size: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The name offered to the far end.
    pub offered_name: AbiStr,
    /// The protocol agreed in the handshake.
    pub agreed_protocol: AbiStr,
    /// The far end's certificate subject.
    pub peer_subject: AbiStr,
    /// The far end's certificate issuer.
    pub peer_issuer: AbiStr,
    /// The far end's certificate fingerprint (absent = no certificate).
    pub peer_fingerprint: AbiStr,
    /// The claim the connection resolved to (absent = the entry's first claim).
    pub claim: AbiStr,
    /// The host's own certificate, DER, for a framer that states its fingerprint to the far end in
    /// a session description; absent when the secure layer presents none. Public: the certificate's
    /// key never crosses. A tail addition (pre-tag v1).
    pub local_certificate: AbiStr,
}

impl ConnFacts {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `ConnFacts { …, ..ConnFacts::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self {
        size: 0,
        _reserved: 0,
        offered_name: AbiStr::ZERO,
        agreed_protocol: AbiStr::ZERO,
        peer_subject: AbiStr::ZERO,
        peer_issuer: AbiStr::ZERO,
        peer_fingerprint: AbiStr::ZERO,
        claim: AbiStr::ZERO,
        local_certificate: AbiStr::ZERO,
    };
}

/// One frame piece a framer produced, in [`FramerSink::pieces`]; its bytes are
/// `frame[offset..offset + len]`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramePiece {
    /// The stream.
    pub stream: u64,
    /// Offset into [`FramerSink::frame`].
    pub offset: u64,
    /// How many bytes.
    pub len: u64,
    /// The exact status number, in the claim's numbering.
    pub code: u32,
    /// `STATUS_*`.
    pub status_class: u8,
    /// `FAULT_*`: the framer's fault reading of `code`, from its own fault table
    /// ([`TransportTail::fault_rows`]); [`FAULT_NONE`] where it states none. Lives in what was
    /// alignment padding, so the piece did not grow.
    pub fault: u8,
    /// `PIECE_*` bits (a `u16`: room past the first eight).
    pub flags: u16,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: u64,
    /// With [`PIECE_HAS_DECLARED_LEN`], on a head's field block: the body length the message's
    /// head declared on the wire, as the framer read it. A statement, never a count of the body
    /// bytes the pieces carry; the field block itself never holds it. A tail addition (pre-tag v1).
    pub declared_len: u64,
}

impl FramePiece {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `FramePiece { …, ..FramePiece::ZERO }` so a field appended later reads
    /// as not declared.
    pub const ZERO: Self = Self {
        stream: 0,
        offset: 0,
        len: 0,
        code: 0,
        status_class: 0,
        fault: 0,
        flags: 0,
        retry_after_secs: 0,
        declared_len: 0,
    };
}

/// A byte range of a host buffer a piece's bytes were written into; `len == 0` = absent. A
/// [`HeadSlots`] slot is one of these, a range of [`FramerSink::frame`] a framer wrote.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameSpan {
    /// Offset into the buffer.
    pub offset: u64,
    /// How many bytes.
    pub len: u64,
}

impl FrameSpan {
    /// THE EMPTY DECLARATION: every field zero (NULL lists, empty strings, no flags). A plugin
    /// builds its value as `FrameSpan { …, ..FrameSpan::ZERO }` so a field appended later reads as
    /// not declared.
    pub const ZERO: Self = Self { offset: 0, len: 0 };
}

// The piece's size and its flags' place are fixed: a framer built against another layout is refused
// at compile time, never read wrong at run time; one built against another contract states another
// `frame_piece_size` and is refused at load.
const _: () = assert!(core::mem::size_of::<FramePiece>() == FRAME_PIECE_SIZE as usize);
const _: () = assert!(core::mem::offset_of!(FramePiece, fault) == 29);
const _: () = assert!(core::mem::offset_of!(FramePiece, flags) == 30);

/// The HOST buffers every framer op writes into, and the host's clock at the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramerSink {
    /// Bytes owed to the far side.
    pub wire: *mut u8,
    /// Its capacity.
    pub wire_cap: usize,
    /// Frame bytes for the layer above.
    pub frame: *mut u8,
    /// Its capacity.
    pub frame_cap: usize,
    /// Frame pieces.
    pub pieces: *mut FramePiece,
    /// Its capacity, in pieces.
    pub pieces_cap: usize,
    /// The host's monotonic clock, nanoseconds.
    pub now_monotonic_ns: u64,
    /// The host's wall clock, nanoseconds since the Unix epoch.
    pub now_unix_ns: u64,
    /// Each stream's head typed slots ([`HeadSlots`]).
    pub heads: *mut HeadSlots,
    /// Its capacity, in heads.
    pub heads_cap: usize,
}

/// A STREAM'S HEAD TYPED SLOTS: what a head says that is never a field. A framer yields at most
/// ONE per stream, in the same answer as that stream's first [`PIECE_FIELDS`] frame (the ordinary
/// fields; a pseudo-field such as `:path` never enters a field block, and hop-by-hop fields, `te`
/// among them, are dropped). Each slot's bytes are in [`FramerSink::frame`].
///
/// * An ACCEPTED stream ([`SIDE_ACCEPT`]) fills `method`, `target` and, where the caller named one,
///   `authority`: the kernel fills the plane's `ArriveIn::method` and target from these slots, never
///   by reading bytes.
/// * A DIALLED stream ([`SIDE_DIAL`]) fills `reason` only: the far end's reason phrase exactly as
///   it was sent (HTTP/1), where the wire has one; a wire without one (HTTP/2) yields no slots.
///
/// The answer's number is never a slot: it is the head piece's [`FramePiece::code`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeadSlots {
    /// The stream.
    pub stream: u64,
    /// The method (`GET`, `POST`, ...); with `target`, or both absent.
    pub method: FrameSpan,
    /// The target: the path and query the caller asked for; with `method`, or both absent.
    pub target: FrameSpan,
    /// The authority the caller named; absent when it named none.
    pub authority: FrameSpan,
    /// The far end's reason phrase, exactly as sent; absent when it sent none.
    pub reason: FrameSpan,
}

/// What a framer op wrote into its [`FramerSink`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramerYield {
    /// Bytes written to `wire`.
    pub wire_len: u64,
    /// Bytes written to `frame`.
    pub frame_len: u64,
    /// Pieces written to `pieces`.
    pub pieces_len: u32,
    /// `YIELD_*` bits.
    pub flags: u32,
    /// With [`YIELD_HAS_DEADLINE`]: the monotonic instant to call [`slot::TIMER`] at.
    pub next_deadline_ns: u64,
    /// Head slots written to `heads`.
    pub heads_len: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

// ── carrier ins and outs ─────────────────────────────────────────────────────────────────────────

/// `listen`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ListenIn {
    /// The head.
    pub head: InHead,
    /// The bind address.
    pub bind: AbiStr,
    /// HOST buffer for the bound address.
    pub addr_buf: *mut u8,
    /// Its capacity.
    pub addr_cap: usize,
}

/// `listen`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ListenOut {
    /// The head.
    pub head: OutHead,
    /// The listener token.
    pub listener: u64,
    /// Bytes of `addr_buf` written (no short path: at most `addr_cap`).
    pub addr_written: u64,
}

/// `accept`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AcceptIn {
    /// The head.
    pub head: InHead,
    /// The listener.
    pub listener: u64,
    /// HOST buffer for the far end's address.
    pub peer_buf: *mut u8,
    /// Its capacity.
    pub peer_cap: usize,
}

/// `accept`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AcceptOut {
    /// The head.
    pub head: OutHead,
    /// The connection token.
    pub conn: u64,
    /// Bytes of `peer_buf` written (no short path: at most `peer_cap`).
    pub peer_written: u64,
}

/// `dial`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DialIn {
    /// The head.
    pub head: InHead,
    /// The destination.
    pub dest: *const Destination,
    /// THE SUPERVISION KEY of the member this dial runs a program for, opaque: minted fresh for
    /// each member and kept while the member's program is unchanged across re-declarations, so a
    /// carrier that supervises what it runs resets its supervision exactly when the member is new.
    /// `0` = no member identity (an authority dial, or a program no member runs). Appended.
    pub supervision_key: u64,
}

/// `dial`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnOut {
    /// The head.
    pub head: OutHead,
    /// The connection token.
    pub conn: u64,
}

/// `read`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadIn {
    /// The head.
    pub head: InHead,
    /// The connection.
    pub conn: u64,
    /// HOST buffer.
    pub buf: *mut u8,
    /// Its capacity.
    pub cap: usize,
}

/// `write`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WriteIn {
    /// The head.
    pub head: InHead,
    /// The connection.
    pub conn: u64,
    /// The bytes.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
    /// `WRITE_*` bits: [`WRITE_END_OF_FRAME`].
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `read`'s and `write`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoOut {
    /// The head.
    pub head: OutHead,
    /// Bytes read (`0` = the end) or taken.
    pub len: u64,
    /// `READ_*` bits on a `read`: [`READ_END_OF_FRAME`]. `0` on a `write`.
    pub flags: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `flush`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ConnIn {
    /// The head.
    pub head: InHead,
    /// The connection.
    pub conn: u64,
}

/// `shut`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ShutIn {
    /// The head.
    pub head: InHead,
    /// The connection.
    pub conn: u64,
    /// `CLOSE_*`.
    pub reason: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

/// `arrival`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArrivalIn {
    /// The head.
    pub head: InHead,
    /// The connection.
    pub conn: u64,
    /// HOST buffer for the far end's address.
    pub peer_buf: *mut u8,
    /// Its capacity.
    pub peer_cap: usize,
}

/// `arrival`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ArrivalOut {
    /// The head.
    pub head: OutHead,
    /// Bytes of `peer_buf` written.
    pub peer_written: u64,
    /// Short answer: the bytes `peer_buf` needs.
    pub peer_needed: u64,
    /// The local port.
    pub local_port: u32,
    /// Alignment padding.
    pub _reserved: u32,
}

// ── framer ins and outs ──────────────────────────────────────────────────────────────────────────

/// `locate`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LocateIn {
    /// The head.
    pub head: InHead,
    /// The target.
    pub target: AbiStr,
    /// HOST buffer for the authority.
    pub authority_buf: *mut u8,
    /// Its capacity.
    pub authority_cap: usize,
    /// HOST buffer for the name offered to the far end.
    pub name_buf: *mut u8,
    /// Its capacity.
    pub name_cap: usize,
    /// HOST buffer for the protocols the framer offers in the connection-security handshake
    /// (ALPN), in the handshake's own ProtocolNameList encoding: each id as one length byte and
    /// its bytes, most preferred first.
    pub alpn_buf: *mut u8,
    /// Its capacity.
    pub alpn_cap: usize,
    /// `1` = answer the protocol offer an ACCEPTING listener makes in the handshake, for a listener
    /// framed by this entry (`target` may be empty: a listener names no far end); `0` = the
    /// offer a dial to `target` makes, as before. THE ALPN OFFER IS THE FRAMER'S on both sides
    /// (`BUSBAR-1.6.0.md` l.477-478), and the two may differ (v1.5.5's client offered `h2,
    /// http/1.1`, its listener `http/1.1` alone). A tail addition (pre-tag v1).
    pub accept: u32,
    /// Alignment padding.
    pub _accept_reserved: u32,
    /// HOST buffer for THE FRAMER'S OWN HEAD LINES on a request to `target`: the field lines its
    /// wire adds to an outgoing head that does not state them (a default it would otherwise write
    /// at `encode`). The host adds each the request does not carry to the head BEFORE the auth
    /// kind signs it, so the auth signs the complete head and nothing is added after it (THE
    /// DESIGN section 6, step 5); the framer then writes the head as handed and adds no line of
    /// its own. Field lines, `name: value` CRLF each. Appended: a framer that predates it states
    /// none, and adds its defaults at `encode` as before.
    pub defaults_buf: *mut u8,
    /// Its capacity.
    pub defaults_cap: usize,
}

/// `locate`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LocateOut {
    /// The head.
    pub head: OutHead,
    /// Bytes of `authority_buf` written.
    pub authority_written: u64,
    /// Short answer: the bytes `authority_buf` needs.
    pub authority_needed: u64,
    /// Bytes of `name_buf` written.
    pub name_written: u64,
    /// Short answer: the bytes `name_buf` needs.
    pub name_needed: u64,
    /// `1` = the target asks for connection security.
    pub secure: u32,
    /// `1` = a name is offered (`name_written` bytes); `0` = none.
    pub has_name: u32,
    /// Bytes of `alpn_buf` written: the framer's protocol offer (`0` = it offers none, and the
    /// handshake carries no ALPN). The connector offers exactly these, in this order, and tells
    /// the framer which one was agreed in [`ConnFacts::agreed_protocol`]. A target without
    /// connection security has no handshake: there an offer of exactly ONE protocol is the protocol
    /// the framer speaks by prior knowledge, and the connector hands it back as agreed.
    pub alpn_written: u64,
    /// Short answer: the bytes `alpn_buf` needs.
    pub alpn_needed: u64,
    /// Bytes of `defaults_buf` written ([`LocateIn::defaults_buf`]); `0` = the framer adds no line.
    pub defaults_written: u64,
    /// Short answer: the bytes `defaults_buf` needs.
    pub defaults_needed: u64,
}

/// Every framer op's `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramerOut {
    /// The head.
    pub head: OutHead,
    /// What the op wrote into its sink.
    pub yielded: FramerYield,
    /// `begin`/`adopt`: the new framing token; other ops leave it.
    pub framing: u64,
    /// A datagram framer's routes, path request and rendezvous terms ([`datagram`]); all zero from
    /// a stream framer. A tail addition (pre-tag v1).
    pub datagram: DatagramYield,
}

/// `begin`'s `in` (the framer's `open`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BeginIn {
    /// The head.
    pub head: InHead,
    /// [`SIDE_ACCEPT`] | [`SIDE_DIAL`] | [`SIDE_ACCEPT_STREAM`].
    pub side: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The target ([`SIDE_ACCEPT_STREAM`]: the stream's path and query).
    pub target: AbiStr,
    /// What connection security established.
    pub facts: *const ConnFacts,
    /// The sink.
    pub sink: FramerSink,
    /// [`SIDE_DIAL`]: the dial's OPENING head fields (the bound auth's fields and the request's
    /// own, in order), for a framer whose wire carries them on its connection's opening (an
    /// upgrade request) rather than on a message; a framer that renders them per message takes them
    /// in `encode` too and ignores these (ARCHITECT Q-L5B-WS-DIAL 2026-10-03). A tail addition.
    /// [`SIDE_ACCEPT_STREAM`]: the stream's head fields, as the caller sent them.
    pub fields: *const Field,
    /// How many.
    pub fields_len: usize,
    /// The datagram lane ([`datagram`]): NULL for a stream framer. A tail addition (pre-tag v1).
    pub lane: *const DatagramLane,
}

/// `ingest`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IngestIn {
    /// The head.
    pub head: InHead,
    /// The framing.
    pub framing: u64,
    /// The bytes from the far side.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
    /// `1` = the far side ended.
    pub end: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The sink.
    pub sink: FramerSink,
    /// The datagram lane ([`datagram`]): NULL for a stream framer. A tail addition (pre-tag v1).
    pub lane: *const DatagramLane,
}

/// `emit`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EmitIn {
    /// The head.
    pub head: InHead,
    /// The framing.
    pub framing: u64,
    /// The stream.
    pub stream: u64,
    /// The bytes for the far side.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
    /// `1` = they complete the frame.
    pub end_of_frame: u32,
    /// `EMIT_*` bits: [`EMIT_TEXT`].
    pub flags: u32,
    /// The sink.
    pub sink: FramerSink,
    /// The monotonic instant this stream's ATTEMPT must be over by, response body included: one
    /// clock from the attempt's start (before the dial, so a slow connect spends it too) to the
    /// body's end, as 1.5.5's `limits.upstream_request_timeout_secs` was. Read on the stream's
    /// first `emit`. The production caller (the kernel's egress walk, and the plane driver that
    /// starts an attempt) ALWAYS stamps it at attempt start; `0` is only the standalone fallback,
    /// where the framer counts its own configured timeout from that first `emit`.
    pub deadline_ns: u64,
    /// The datagram lane ([`datagram`]): NULL for a stream framer. A tail addition (pre-tag v1).
    pub lane: *const DatagramLane,
    /// THE ANSWER'S STATUS (INBOUND-LISTEN, `BUSBAR-1.6.0.md` l.4913): on an ACCEPTED stream's FIRST
    /// emit, the one carrying the answer's head (its bytes `encode` rendered), the status the answer
    /// carries, in the numbering of the claim the stream arrived on; a status that asks the far end
    /// to switch protocols hands the connection to the claimed upgrade framer ([`slot::DETACH`]).
    /// `0` on every other emit, where a stated status is refused
    /// ([`check::check_emit_status`]). Never a `:status` field. A tail addition (pre-tag v1).
    pub status: u32,
    /// Alignment padding.
    pub _status_reserved: u32,
}

/// `encode`'s `in`. The rendered bytes go into `sink.wire`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EncodeIn {
    /// The head.
    pub head: InHead,
    /// The envelope fields.
    pub fields: *const Field,
    /// How many.
    pub fields_len: usize,
    /// The body.
    pub body: *const u8,
    /// Its length.
    pub body_len: usize,
    /// The sink.
    pub sink: FramerSink,
    /// The request's method, a head word (the same name as the head slots'); absent = none. A
    /// framer whose wire has no head words ignores it.
    pub method: AbiStr,
    /// The request's target (path and query), a head word; absent = none.
    pub target: AbiStr,
}

/// `refuse`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RefuseIn {
    /// The head.
    pub head: InHead,
    /// The framing.
    pub framing: u64,
    /// The stream (with `has_stream`).
    pub stream: u64,
    /// `0` = the refusal is for the whole connection.
    pub has_stream: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The refusal bytes.
    pub bytes: *const u8,
    /// How many.
    pub len: usize,
    /// The sink.
    pub sink: FramerSink,
    /// The refusal's neutral status number, in the space of the plane kind's refusal status
    /// ([`crate::abi::plane::RefusalIn::status`]): the transport maps it to its own wire, where
    /// `bytes` do not state one in the wire's own terms. `0` = none stated. Appended (OWNER
    /// R-addendum 2026-09-30: the refusal carries a neutral status number the transport maps to
    /// its wire).
    pub status: u32,
    /// Alignment padding.
    pub _reserved2: u32,
    /// `1` = a response head already went out on this stream, set by the host, which sent it; the
    /// framer then writes the refusal as closing lines only. `0` = no head went out (and always on
    /// a refusal for the whole connection): the refusal is the whole answer, and the framer writes
    /// head lines only here, for an answer that is its closing lines alone. Appended (Q128 grpc
    /// L1): a framer cannot tell from its own state whether the host answered the head.
    pub head_sent: u32,
    /// Alignment padding.
    pub _reserved3: u32,
}

/// `finish`'s `in` (the framer's `close`).
///
/// THE FINAL STATUS (ARCHITECT 4l, 2026-10-05): on a framing begun on [`SIDE_ACCEPT_STREAM`], the
/// close is the stream's last answer, and the four `final_*` fields state how it ended, as the unit
/// stated it: `final_status` in the numbering of the claim the stream arrived on (a number the
/// claim's status rows cover; `0` where the unit stated none and the claim's numbering has one for
/// success), its message and its details as byte ranges of `final_bytes`, each empty where the
/// unit stated none. The framer renders them on its own wire, verbatim; the host renders nothing.
/// The same names and shape as the plane's `OnPieceOut` final tail. Any other framing's close
/// carries the four zeroed. A tail addition (pre-tag v1).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FinishIn {
    /// The head.
    pub head: InHead,
    /// The framing.
    pub framing: u64,
    /// `CLOSE_*`.
    pub reason: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The sink.
    pub sink: FramerSink,
    /// The status the stream ended with, in its claim's numbering.
    pub final_status: u32,
    /// Alignment padding.
    pub _final_reserved: u32,
    /// The status's message, a range of `final_bytes`; empty = none.
    pub final_message: Span,
    /// The status's details, a range of `final_bytes`, passed through as stated; empty = none.
    pub final_details: Span,
    /// The bytes `final_message` and `final_details` index (host memory, valid for the call).
    pub final_bytes: *const u8,
    /// How many.
    pub final_bytes_len: usize,
    /// The datagram lane ([`datagram`]): NULL for a stream framer. A tail addition (pre-tag v1).
    pub lane: *const DatagramLane,
}

/// `detach`'s and `timer`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FramingIn {
    /// The head.
    pub head: InHead,
    /// The framing.
    pub framing: u64,
    /// The sink.
    pub sink: FramerSink,
    /// The datagram lane ([`datagram`]): NULL for a stream framer. A tail addition (pre-tag v1).
    pub lane: *const DatagramLane,
}

/// `adopt`'s `in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AdoptIn {
    /// The head.
    pub head: InHead,
    /// [`SIDE_ACCEPT`] | [`SIDE_DIAL`].
    pub side: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// What connection security established.
    pub facts: *const ConnFacts,
    /// The bytes the previous framer did not consume.
    pub leftover: *const u8,
    /// How many.
    pub leftover_len: usize,
    /// The sink.
    pub sink: FramerSink,
}

// THE SDK's VIEW OF THE TRANSPORT TABLE (`abi::sdk::door`): each kind op's `in`/`out`, stated
// next to the table, so `plugin_door!` refuses a transport plugin that wires a kind op to
// another op's structs. Every struct named here is plain data (integers, raw pointers,
// `AbiStr`, nested plain structs): every bit pattern is a valid value, which is what
// `AbiIn`/`AbiOut` promise.
//
// SAFETY (all below): `#[repr(C)]`, leading with `InHead`/`OutHead`, plain data only.
unsafe impl super::sdk::door::AbiIn for ListenIn {}
unsafe impl super::sdk::door::AbiIn for AcceptIn {}
unsafe impl super::sdk::door::AbiIn for DialIn {}
unsafe impl super::sdk::door::AbiIn for ReadIn {}
unsafe impl super::sdk::door::AbiIn for WriteIn {}
unsafe impl super::sdk::door::AbiIn for ConnIn {}
unsafe impl super::sdk::door::AbiIn for ShutIn {}
unsafe impl super::sdk::door::AbiIn for ArrivalIn {}
unsafe impl super::sdk::door::AbiIn for LocateIn {}
unsafe impl super::sdk::door::AbiIn for BeginIn {}
unsafe impl super::sdk::door::AbiIn for IngestIn {}
unsafe impl super::sdk::door::AbiIn for EmitIn {}
unsafe impl super::sdk::door::AbiIn for EncodeIn {}
unsafe impl super::sdk::door::AbiIn for RefuseIn {}
unsafe impl super::sdk::door::AbiIn for FinishIn {}
unsafe impl super::sdk::door::AbiIn for FramingIn {}
unsafe impl super::sdk::door::AbiIn for AdoptIn {}
unsafe impl super::sdk::door::AbiOut for ListenOut {}
unsafe impl super::sdk::door::AbiOut for AcceptOut {}
unsafe impl super::sdk::door::AbiOut for ConnOut {}
unsafe impl super::sdk::door::AbiOut for IoOut {}
unsafe impl super::sdk::door::AbiOut for ArrivalOut {}
unsafe impl super::sdk::door::AbiOut for LocateOut {}
unsafe impl super::sdk::door::AbiOut for FramerOut {}

super::sdk::door::slot_structs!(
    /// Each transport kind op's `in`/`out` for [`plugin_door!`](crate::plugin_door), per [`Ops`]'
    /// docs. A plugin wiring a slot to another op's structs does not compile:
    ///
    /// ```compile_fail,E0271
    /// use busbar_contract::abi::transport::{AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut};
    /// use busbar_contract::abi::transport::{BeginIn, ConnIn, ConnOut, DialIn, EmitIn, EncodeIn};
    /// use busbar_contract::abi::transport::{FinishIn, FramerOut, FramingIn, IngestIn, IoOut};
    /// use busbar_contract::abi::transport::{ListenIn, ListenOut, LocateIn, LocateOut, OutHead};
    /// use busbar_contract::abi::transport::{ReadIn, RefuseIn, ShutIn, WriteIn};
    /// use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    /// use busbar_contract::abi::mechanism::lifecycle::*;
    /// use busbar_contract::abi::sdk::door::Slot;
    /// # use std::ffi::c_void;
    /// # macro_rules! ready { ($n:ident, $i:ty, $o:ty) => {
    /// #     struct $n;
    /// #     impl Slot for $n { type In = $i; type Out = $o;
    /// #         fn call(_: *mut c_void, _: &$i, _: &mut $o) -> Outcome { Outcome::Ready } }
    /// # } }
    /// # ready!(V, ValidateIn, OutHead); ready!(Op_, OpenIn, OpenOut); ready!(Rf, RefreshIn, OutHead);
    /// # ready!(Rt, GenIn, OutHead); ready!(Tk, TickIn, TickOut); ready!(Dr, DriveIn, OutHead);
    /// # ready!(Cn, CancelIn, CancelOut); ready!(Rl, ReleaseIn, OutHead); ready!(Cl, InHead, OutHead);
    /// # ready!(Accept, AcceptIn, AcceptOut); ready!(Dial, DialIn, ConnOut);
    /// # ready!(Read, ReadIn, IoOut); ready!(Write, WriteIn, IoOut); ready!(Flush, ConnIn, OutHead);
    /// # ready!(Shut, ShutIn, OutHead); ready!(Arrival, ArrivalIn, ArrivalOut);
    /// # ready!(Locate, LocateIn, LocateOut); ready!(Begin, BeginIn, FramerOut);
    /// # ready!(Ingest, IngestIn, FramerOut); ready!(Emit, EmitIn, FramerOut);
    /// # ready!(Encode, EncodeIn, FramerOut); ready!(Refuse, RefuseIn, FramerOut);
    /// # ready!(Finish, FinishIn, FramerOut); ready!(Detach, FramingIn, FramerOut);
    /// # ready!(Adopt, AdoptIn, FramerOut); ready!(Timer, FramingIn, FramerOut);
    /// ready!(Listen, AcceptIn, AcceptOut); // `accept`'s structs on `listen`: refused
    /// busbar_contract::plugin_door! {
    ///     ops: busbar_contract::abi::transport::Ops,
    ///     statement: busbar_contract::abi::sdk::door::statement("wrong", "0", 1),
    ///     lifecycle: { validate: V, open: Op_, refresh: Rf, retire: Rt, tick: Tk, drive: Dr,
    ///                  cancel: Cn, release: Rl, close: Cl },
    ///     kind_ops: {
    ///         listen: Listen, accept: Accept, dial: Dial, read: Read, write: Write, flush: Flush,
    ///         shut: Shut, arrival: Arrival, locate: Locate, begin: Begin, ingest: Ingest,
    ///         emit: Emit, encode: Encode, refuse: Refuse, finish: Finish, detach: Detach,
    ///         adopt: Adopt, timer: Timer
    ///     },
    /// }
    /// # fn main() { let _ = door(); }
    /// ```
    ///
    /// With `Listen` reading [`ListenIn`] and writing [`ListenOut`] the same plugin compiles
    /// (`abi/sdk/tests/door_tests.rs`, `a_transport_plugin_wires_every_kind_op`).
    Ops {
        slot::LISTEN => ListenIn, ListenOut;
        slot::ACCEPT => AcceptIn, AcceptOut;
        slot::DIAL => DialIn, ConnOut;
        slot::READ => ReadIn, IoOut;
        slot::WRITE => WriteIn, IoOut;
        slot::FLUSH => ConnIn, OutHead;
        slot::SHUT => ShutIn, OutHead;
        slot::ARRIVAL => ArrivalIn, ArrivalOut;
        slot::LOCATE => LocateIn, LocateOut;
        slot::BEGIN => BeginIn, FramerOut;
        slot::INGEST => IngestIn, FramerOut;
        slot::EMIT => EmitIn, FramerOut;
        slot::ENCODE => EncodeIn, FramerOut;
        slot::REFUSE => RefuseIn, FramerOut;
        slot::FINISH => FinishIn, FramerOut;
        slot::DETACH => FramingIn, FramerOut;
        slot::ADOPT => AdoptIn, FramerOut;
        slot::TIMER => FramingIn, FramerOut;
    }
);

#[cfg(test)]
#[path = "../tests/transport_kind_tests.rs"]
mod tests;
