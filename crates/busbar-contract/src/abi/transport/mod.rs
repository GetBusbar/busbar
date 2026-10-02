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
//! STREAMS END BY PIECE. A frame is one or more pieces on one stream; the last carries
//! [`PIECE_END_OF_FRAME`]. A stream's frames END with an EMPTY piece (length `0`) carrying
//! [`PIECE_END_OF_FRAME`]; a stream that FAILED ends instead with a piece carrying
//! [`PIECE_STREAM_FAILED`] and [`PIECE_END_OF_FRAME`], its bytes the reason (never secret material).
//! A failed stream fails alone: its siblings on the connection carry on. [`YIELD_ENDED`] ends the
//! CONNECTION, never one stream.
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
//! WHAT THE HOT-LANE `TransportDecl` BECOMES (a mechanical re-heading):
//!
//! | `TransportDecl` / slot table | here |
//! |---|---|
//! | `abi`, `size`, `version` | the door's magic, mechanism version, `kind_abi` and [`crate::abi::mechanism::door::KindTailHead::size`] |
//! | `key` | the Statement's `claims[0]` (the entry's own claim; the Statement holds every claimed scheme's name) |
//! | `composes_over` | [`TransportTail::composes_over`]; [`TransportTail::role`] states the role outright |
//! | `selector_forms`, `egress_selector_forms`, `transport_facts`, `status_namespace`, `session`, `session_bound`, `unit0_trigger`, `status_at` | per claim, [`Claim`] |
//! | `handoff_*`, `upgrades_to`, `handshake_frame_kind`, `handshake_max_steps` | [`TransportTail`] |
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
pub mod fields;
pub mod route;

/// THE AUTH POINTS a transport offers and calls its bound auth at (THE DESIGN, "Auth points
/// and guest lists", step 1): defined once in `abi::auth`, referred to here, never redefined.
pub use super::auth::{
    AuthPoint, AuthPoints, POINT_FRAME, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER,
};

use super::mechanism::call::{AbiStr, Field, InHead, Op, OutHead};
use super::mechanism::check::{contract, OpContract};
use super::mechanism::door::KindTailHead;
use super::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};

/// The transport kind's ABI version: new in 1.6.0 (v1.5.5 had no transport kind ABI), so it ships `1`.
pub const ABI_VERSION: u32 = 1;

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

/// `side`: the accepting end.
pub const SIDE_ACCEPT: u32 = 0;
/// `side`: the dialing end.
pub const SIDE_DIAL: u32 = 1;

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

/// [`FramerYield::flags`]: no frame follows on this connection.
pub const YIELD_ENDED: u32 = 1;
/// [`FramerYield::flags`]: a buffer filled; call the same op again once drained.
pub const YIELD_MORE: u32 = 2;
/// [`FramerYield::flags`]: `next_deadline_ns` is set; call [`slot::TIMER`] then.
pub const YIELD_HAS_DEADLINE: u32 = 4;

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
    /// Alignment padding.
    pub _reserved: u32,
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
    /// Alignment padding.
    pub _reserved: u8,
    /// `PIECE_*` bits (a `u16`: room past the first eight).
    pub flags: u16,
    /// How long the far side asked to be left alone, in seconds.
    pub retry_after_secs: u64,
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

// The piece's size and its flags' place are fixed: a framer built against another layout is refused
// at compile time, never read wrong at run time.
const _: () = assert!(core::mem::size_of::<FramePiece>() == 40);
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
}

/// `read`'s and `write`'s `out`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoOut {
    /// The head.
    pub head: OutHead,
    /// Bytes read (`0` = the end) or taken.
    pub len: u64,
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
    /// the framer which one was agreed in [`ConnFacts::agreed_protocol`].
    pub alpn_written: u64,
    /// Short answer: the bytes `alpn_buf` needs.
    pub alpn_needed: u64,
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
}

/// `begin`'s `in` (the framer's `open`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BeginIn {
    /// The head.
    pub head: InHead,
    /// [`SIDE_ACCEPT`] | [`SIDE_DIAL`].
    pub side: u32,
    /// Alignment padding.
    pub _reserved: u32,
    /// The target.
    pub target: AbiStr,
    /// What connection security established.
    pub facts: *const ConnFacts,
    /// The sink.
    pub sink: FramerSink,
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
    /// Alignment padding.
    pub _reserved: u32,
    /// The sink.
    pub sink: FramerSink,
    /// The monotonic instant this stream's ATTEMPT must be over by, response body included: one
    /// clock from the attempt's start (before the dial, so a slow connect spends it too) to the
    /// body's end, as 1.5.5's `limits.upstream_request_timeout_secs` was. Read on the stream's
    /// first `emit`. The production caller (the kernel's egress walk, and the plane driver that
    /// starts an attempt) ALWAYS stamps it at attempt start; `0` is only the standalone fallback,
    /// where the framer counts its own configured timeout from that first `emit`.
    pub deadline_ns: u64,
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
}

/// `finish`'s `in` (the framer's `close`).
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
