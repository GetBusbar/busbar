// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S ANSWER VALIDATORS, which live beside the shapes they judge: one pure `check_<op>` per answer, built from the shared helpers in
//! [`crate::abi::mechanism::check`]. The dispatcher turns an `Err` into FAULT.
//!
//! * `arrival` and `locate` have the short path (`locate`'s authority and name are one
//!   multi-dimension answer); `listen`, `accept` and `read` do not: their lengths are at most the
//!   capacity, and the host's `addr_cap`/`peer_cap` is at least [`MAX_ADDR`].
//! * A framer has no short path either: a full sink is READY with [`YIELD_MORE`] (backpressure).
//! * The tail and every list element it names are checked at load.

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::route::{
    FieldPredicate, RouteMatch, FIELD_PRESENT, FIELD_VALUE_PREFIX, METHOD_ANY, PATH_CONTAINS,
    PATH_EXACT,
};
use super::{
    slot, AcceptIn, AdoptIn, ArrivalIn, BeginIn, EncodeIn, FramerSink, FramingIn, IngestIn,
    ListenIn, LocateIn, ReadIn, RefuseIn, WriteIn,
};
use super::{
    AcceptOut, ArrivalOut, Claim, ConnFacts, EmitIn, FaultRow, FinishIn, FramePiece, FrameSpan,
    FramerOut, HeadSlots, IoOut, ListenOut, LocateOut, SettingDecl, StatusRow, TransportTail,
    CANCEL_COMPLETED, CANCEL_NOTHING_MOVED, FACT_DECODES_PAYLOAD, FACT_SIGNS_NOTHING_AFTER_AUTH,
    FAULT_CALLER, FAULT_HEALTHY, FRAMING_DATAGRAM, FRAMING_STREAM, MAX_ADDR, PIECE_CONTINUED,
    PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN,
    PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, ROLE_CARRIER,
    ROLE_FRAMER, SETTING_FLAG, SETTING_TEXT, STATUS_AT_TERMINAL, STATUS_OTHER, STATUS_SUCCESS,
    UNIT0_HANDSHAKE, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
use super::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use super::{
    DatagramRoute, DatagramYield, KeyingMaterial, RendezvousTerms, FINGERPRINT_BYTES,
    HANDSHAKE_ANSWERS, HANDSHAKE_NONE, LANE_CLEAR, LANE_SECURED, MAX_KEYING_BYTES, MAX_ROUTES,
    PATH_REQUEST_BIND, PATH_REQUEST_NONE, PATH_REQUEST_REBIND,
};
use crate::abi::mechanism::call::{AbiStr, Outcome};
use crate::abi::mechanism::check::{
    bits, bounded, code, fault, first, listed, range, reported, result, results, texts, within,
    Dim, MAX_BYTES,
};
use crate::abi::mechanism::decl::{abi_answers, abi_op};
use crate::abi::mechanism::lifecycle::{slot as life, CancelOut};

/// The most frame pieces one framer answer may produce.
pub const MAX_PIECES: u64 = 4096;
/// The most claims one transport entry may make.
pub const MAX_CLAIMS: u64 = 1024;

/// `listen`: no short path; the bound address fits `addr_cap`.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_listen(out: &ListenOut, addr_cap: u64) -> Result<(), Fault> {
    within(out.addr_written, addr_cap, "listen.addr_written")
}

/// `accept`: no short path; the far end's address fits `peer_cap`.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_accept(out: &AcceptOut, peer_cap: u64) -> Result<(), Fault> {
    within(out.peer_written, peer_cap, "accept.peer_written")
}

/// `arrival`: the far end's address, under the short-buffer rule.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_arrival(outcome: Outcome, out: &ArrivalOut, peer_cap: u64) -> Result<(), Fault> {
    match result(
        outcome,
        out.peer_written,
        out.peer_needed,
        peer_cap,
        MAX_ADDR,
        "arrival.peer",
    ) {
        Ok(_) => Ok(()),
        Err(f) => Err(f),
    }
}

/// `read`/`write`: no short path; at most the buffer's capacity or the bytes offered. Partial I/O
/// is not a short buffer: a FAILED read or write MAY report the bytes it already moved (the short-buffer rule
/// carve-outs, beside backpressure, in this kind's module doc).
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_io(out: &IoOut, cap: u64) -> Result<(), Fault> {
    if out.flags & !super::READ_END_OF_FRAME != 0 {
        return Err(fault(Rule::UnknownCode, "io.flags"));
    }
    within(out.len, cap, "io.len")
}

/// `locate`: authority, name and protocol offer under the short-buffer rule; `has_name` and
/// `secure` are flags, and no name means nothing written or needed for it. The offer (`alpn`, the
/// bytes written into the host's `alpn_buf`) is [`check_alpn`]'s.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_locate(
    outcome: Outcome,
    out: &LocateOut,
    authority_cap: u64,
    name_cap: u64,
    alpn_cap: u64,
    alpn: &[u8],
    defaults_cap: u64,
) -> Result<(), Fault> {
    code(u64::from(out.secure), 0, 1, "locate.secure")?;
    code(u64::from(out.has_name), 0, 1, "locate.has_name")?;
    if out.has_name == 0 && (out.name_written | out.name_needed) != 0 {
        return Err(fault(Rule::Contradiction, "locate.name_without_has_name"));
    }
    results(
        outcome,
        "locate",
        &[
            Dim {
                written: out.authority_written,
                needed: out.authority_needed,
                cap: authority_cap,
                max: MAX_BYTES,
                field: "locate.authority",
            },
            Dim {
                written: out.name_written,
                needed: out.name_needed,
                cap: name_cap,
                max: MAX_BYTES,
                field: "locate.name",
            },
            Dim {
                written: out.alpn_written,
                needed: out.alpn_needed,
                cap: alpn_cap,
                max: MAX_ALPN_BYTES,
                field: "locate.alpn",
            },
            Dim {
                written: out.defaults_written,
                needed: out.defaults_needed,
                cap: defaults_cap,
                max: MAX_BYTES,
                field: "locate.defaults",
            },
        ],
    )?;
    if outcome == Outcome::Ready {
        check_alpn(alpn)?;
    }
    Ok(())
}

/// The most bytes one protocol offer may take (a TLS ProtocolNameList is at most `2^16 - 1`).
pub const MAX_ALPN_BYTES: u64 = 0xffff;

/// A protocol offer in the handshake's ProtocolNameList encoding: it partitions exactly into ids,
/// each one length byte (`1..=255`) and that many bytes.
///
/// # Errors
///
/// [`Rule::Missing`] for an empty id; [`Rule::SpanOutOfBounds`] for a length that runs past the
/// end.
pub fn check_alpn(offer: &[u8]) -> Result<(), Fault> {
    let mut at = 0usize;
    while at < offer.len() {
        let n = usize::from(offer[at]);
        if n == 0 {
            return Err(fault(Rule::Missing, "locate.alpn.id"));
        }
        if at + 1 + n > offer.len() {
            return Err(fault(Rule::SpanOutOfBounds, "locate.alpn.id"));
        }
        at += 1 + n;
    }
    Ok(())
}

/// The protocol the handshake agreed, against the framer's offer: none agreed, or one of the
/// offered ids exactly. The connector checks it before it hands the framer
/// [`ConnFacts::agreed_protocol`].
///
/// # Errors
///
/// [`check_alpn`]'s rules for a malformed offer; [`Rule::Contradiction`] for an agreed protocol the
/// framer never offered.
pub fn check_agreed(offer: &[u8], agreed: &[u8]) -> Result<(), Fault> {
    check_alpn(offer)?;
    if agreed.is_empty() {
        return Ok(());
    }
    let mut at = 0usize;
    while at < offer.len() {
        let n = usize::from(offer[at]);
        if &offer[at + 1..at + 1 + n] == agreed {
            return Ok(());
        }
        at += 1 + n;
    }
    Err(fault(Rule::Contradiction, "facts.agreed_protocol"))
}

abi_op! {
    /// Every framer answer: what it wrote fits its sink (no short path: a full sink is
    /// [`YIELD_MORE`]); the flags are known; a deadline is stated exactly when flagged; FAILED wrote
    /// nothing; every piece lies inside the frame bytes written and carries known codes.
    ///
    /// # Errors
    ///
    /// The rule the answer breaks.
    pub fn check_framer(
        outcome: Outcome,
        out: &FramerOut,
        pieces: &[FramePiece],
        wire_cap: u64,
        frame_cap: u64,
        pieces_cap: u64,
    ) as "framer", FRAMER_RULES for out: FramerOut {
        within(yielded.wire_len, wire_cap) as "framer.wire_len";
        within(yielded.frame_len, frame_cap) as "framer.frame_len";
        within(yielded.pieces_len, pieces_cap.min(MAX_PIECES)) as "framer.pieces_len";
        bits(yielded.flags, YIELD_ENDED | YIELD_MORE | YIELD_HAS_DEADLINE | YIELD_STREAM_FULL) as "framer.flags";
        deny((out.yielded.flags & YIELD_HAS_DEADLINE != 0) != (out.yielded.next_deadline_ns != 0), Contradiction, "framer.next_deadline_ns");
        deny(outcome == Outcome::Failed && (out.yielded.wire_len | out.yielded.frame_len | u64::from(out.yielded.pieces_len)) != 0, Contradiction, "framer.failed_wrote");
        then framer_pieces(out, pieces);
    }
}

/// Every piece a framer reported, read only up to its stated count ([`check_piece`]).
fn framer_pieces(out: &FramerOut, pieces: &[FramePiece]) -> Result<(), Fault> {
    let y = &out.yielded;
    first(pieces, u64::from(y.pieces_len), "framer.pieces")?
        .iter()
        .try_for_each(|p| check_piece(p, y.frame_len))
}

abi_op! {
    /// One frame piece: inside the frame bytes written, with known flags in a coherent set and
    /// known codes.
    fn check_piece(p: &FramePiece, frame_len: u64) as "framer.piece", PIECE_RULES for p: FramePiece {
        then range(p.offset, p.len, frame_len, "framer.piece.bytes");
        bits(flags, PIECE_END_OF_FRAME | PIECE_HAS_CODE | PIECE_HAS_RETRY_AFTER | PIECE_STREAM_FAILED | PIECE_FIELDS | PIECE_CONTINUED | PIECE_TEXT | PIECE_END | PIECE_HAS_DECLARED_LEN | PIECE_WRITABLE);
        // A writable piece is a signal about the stream, never part of a frame: empty, alone.
        deny(p.flags & PIECE_WRITABLE != 0 && (p.len != 0 || p.flags != PIECE_WRITABLE), Contradiction, "framer.piece.writable_not_alone");
        // Text is a fact about a message, an empty one too: a field block, a failed stream's
        // reason and a stream's end are none.
        deny(p.flags & PIECE_TEXT != 0 && p.flags & (PIECE_FIELDS | PIECE_STREAM_FAILED | PIECE_END) != 0, Contradiction, "framer.piece.text_not_message");
        // A stream's end is its own empty piece: bytes on it would be a message the end swallows,
        // and a failed stream or a field block is never the whole end.
        when(p.flags & PIECE_END != 0) {
            deny(p.len != 0, Contradiction, "framer.piece.end_with_bytes");
            deny(p.flags & (PIECE_FIELDS | PIECE_STREAM_FAILED | PIECE_CONTINUED) != 0, Contradiction, "framer.piece.end_not_payload");
        }
        deny(p.flags & PIECE_CONTINUED != 0 && p.flags & PIECE_FIELDS == 0, Contradiction, "framer.piece.continued_not_fields");
        // A declared body length is a head's statement: a field block carries it, nothing else.
        deny(p.flags & PIECE_HAS_DECLARED_LEN != 0 && p.flags & PIECE_FIELDS == 0, Contradiction, "framer.piece.declared_len_not_fields");
        // A field block is never a failure's reason.
        deny(p.flags & PIECE_FIELDS != 0 && p.flags & PIECE_STREAM_FAILED != 0, Contradiction, "framer.piece.fields_failed");
        // An empty piece is a whole frame (an empty message, or the stream's end; a writable
        // piece aside), so it completes its frame; a failed stream's piece is its last, so it
        // does too.
        deny(((p.len == 0 && p.flags != PIECE_WRITABLE) || p.flags & PIECE_STREAM_FAILED != 0) && p.flags & PIECE_END_OF_FRAME == 0, Contradiction, "framer.piece.end_without_end_of_frame");
        code(status_class, 0u8, STATUS_OTHER);
        code(fault, 0u8, FAULT_HEALTHY);
        // The fault reading is a reading OF the piece's code: a piece with no code reads none.
        deny(p.fault != 0 && p.flags & PIECE_HAS_CODE == 0, Contradiction, "framer.piece.fault_without_code");
    }
}

abi_op! {
    /// A datagram framer's answer ([`super::datagram`]), after [`check_framer`] passed: at most
    /// `routes_cap` (and [`MAX_ROUTES`]) routes, each one nonempty datagram inside the wire bytes
    /// written, to a nonzero path, on [`LANE_CLEAR`] or [`LANE_SECURED`] (a rendezvous is never sent);
    /// a FAILED answer routes nothing and asks for nothing; at most one path request, its paths named
    /// exactly as its kind needs; rendezvous terms either absent whole or carrying all four
    /// credentials and a [`FINGERPRINT_BYTES`] fingerprint inside the frame bytes written.
    ///
    /// A stream framer's zeroed yield passes.
    ///
    /// # Errors
    ///
    /// The rule the answer breaks.
    pub fn check_datagram(
        outcome: Outcome,
        out: &FramerOut,
        routes: &[DatagramRoute],
        routes_cap: u64,
    ) as "datagram", DATAGRAM_RULES for out: FramerOut {
        within(datagram.routes_len, routes_cap.min(MAX_ROUTES)) as "datagram.routes_len";
        deny(outcome == Outcome::Failed && (out.datagram.routes_len != 0 || out.datagram.request != PATH_REQUEST_NONE), Contradiction, "datagram.failed_routed");
        then datagram_routes(out, routes);
        code(datagram.request, PATH_REQUEST_NONE, PATH_REQUEST_REBIND) as "datagram.request";
        deny(!request_paths_named(&out.datagram), Contradiction, "datagram.request.paths");
        then check_terms(&out.datagram.terms, out.yielded.frame_len);
    }
}

/// Every route a datagram framer reported, read only up to its stated count
/// ([`check_datagram_route`]).
fn datagram_routes(out: &FramerOut, routes: &[DatagramRoute]) -> Result<(), Fault> {
    first(
        routes,
        u64::from(out.datagram.routes_len),
        "datagram.routes",
    )?
    .iter()
    .try_for_each(|r| check_datagram_route(r, out.yielded.wire_len))
}

abi_op! {
    /// One datagram route: a nonempty datagram inside the wire bytes written, to a nonzero path,
    /// on a known lane.
    fn check_datagram_route(r: &DatagramRoute, wire_len: u64) as "datagram.route", DATAGRAM_ROUTE_RULES for r: DatagramRoute {
        deny(r.len == 0, Missing, "datagram.route.len");
        then range(r.offset, r.len, wire_len, "datagram.route.bytes");
        deny(r.path == 0, Missing, "datagram.route.path");
        code(lane, LANE_CLEAR, LANE_SECURED);
    }
}

/// Whether a path request names exactly the paths its kind needs.
const fn request_paths_named(d: &DatagramYield) -> bool {
    match d.request {
        PATH_REQUEST_BIND => d.request_from == 0 && d.request_to != 0,
        PATH_REQUEST_REBIND => {
            d.request_from != 0 && d.request_to != 0 && d.request_from != d.request_to
        }
        _ => d.request_from == 0 && d.request_to == 0,
    }
}

/// Rendezvous terms: absent whole, or every credential nonempty and the fingerprint exactly
/// [`FINGERPRINT_BYTES`], each inside the first `frame_len` bytes of the frame.
///
/// # Errors
///
/// The rule the terms break.
pub fn check_terms(t: &RendezvousTerms, frame_len: u64) -> Result<(), Fault> {
    code(
        u64::from(t.role),
        u64::from(HANDSHAKE_NONE),
        u64::from(HANDSHAKE_ANSWERS),
        "datagram.terms.role",
    )?;
    let spans = [
        (t.local_user, "datagram.terms.local_user"),
        (t.local_secret, "datagram.terms.local_secret"),
        (t.remote_user, "datagram.terms.remote_user"),
        (t.remote_secret, "datagram.terms.remote_secret"),
        (t.peer_fingerprint, "datagram.terms.peer_fingerprint"),
    ];
    if t.role == HANDSHAKE_NONE {
        for (s, field) in spans
            .into_iter()
            .chain([(t.candidates, "datagram.terms.candidates")])
        {
            if s != FrameSpan::default() {
                return Err(fault(Rule::SpanNotAbsent, field));
            }
        }
        return Ok(());
    }
    for (s, field) in spans {
        if s.len == 0 {
            return Err(fault(Rule::Missing, field));
        }
        range(s.offset, s.len, frame_len, field)?;
    }
    range(
        t.candidates.offset,
        t.candidates.len,
        frame_len,
        "datagram.terms.candidates",
    )?;
    if t.peer_fingerprint.len != FINGERPRINT_BYTES {
        return Err(fault(
            Rule::Contradiction,
            "datagram.terms.peer_fingerprint.len",
        ));
    }
    Ok(())
}

abi_op! {
    /// The keying-material item a host presents: its own size, a nonzero profile, and
    /// `1..=`[`MAX_KEYING_BYTES`] bytes behind a non-NULL pointer.
    ///
    /// # Errors
    ///
    /// The rule the item breaks.
    pub fn check_keying(k: &KeyingMaterial) as "keying", KEYING_RULES for k: KeyingMaterial {
        deny(k.size as usize != core::mem::size_of::<KeyingMaterial>(), Foreign, "keying.size");
        deny(k.profile == 0, Missing, "keying.profile");
        deny(k.len == 0, Missing, "keying.len");
        deny(k.len as u64 > MAX_KEYING_BYTES, OverMax, "keying.len");
        deny(k.bytes.is_null(), NullWithCount, "keying.bytes");
    }
}

/// [`check_keying`] over the keying item a call lends (status rows 159 and 194): the same rules,
/// read where it is lent. #1471 seals the `Lent` and keeps this name, so a transport checks the
/// item it was lent with `check_keying_lent(&k)` before and after.
///
/// # Errors
///
/// As [`check_keying`].
pub fn check_keying_lent(k: &crate::abi::sdk::Lent<'_, KeyingMaterial>) -> Result<(), Fault> {
    check_keying(k.get())
}

/// The lifecycle `cancel`'s disposition: on READY, one of the transport's three (`0` = unwritten is
/// FAULT); on any other outcome the op did not answer a disposition, and it must be unwritten.
///
/// # Errors
///
/// [`Rule::UnknownCode`] for a READY disposition outside the three; [`Rule::Contradiction`] for
/// a disposition written on another outcome.
pub const fn check_cancel(outcome: Outcome, disposition: u32) -> Result<(), Fault> {
    if !matches!(outcome, Outcome::Ready) {
        if disposition != 0 {
            return Err(fault(Rule::Contradiction, "cancel.disposition"));
        }
        return Ok(());
    }
    code(
        disposition as u64,
        CANCEL_NOTHING_MOVED as u64,
        CANCEL_COMPLETED as u64,
        "cancel.disposition",
    )
}

/// A framer answer's field blocks, over the frame bytes it wrote (`frame`, the first `frame_len`
/// bytes of the sink): a pseudo-field (a line whose name starts with `:`) never enters a block;
/// the request's method, target and authority are [`HeadSlots`] slots. A line starts after every
/// CR LF (also one split across two pieces), and at the first byte of a fields piece that does not
/// carry [`PIECE_CONTINUED`].
/// Run after [`check_framer`] passed.
///
/// # Errors
///
/// [`Rule::Foreign`] for a pseudo-field; [`Rule::SpanOutOfBounds`] for a piece outside `frame`.
pub fn check_framer_fields(pieces: &[FramePiece], frame: &[u8]) -> Result<(), Fault> {
    const FIELD: &str = "framer.piece.pseudo_field";
    for p in pieces.iter().filter(|p| p.flags & PIECE_FIELDS != 0) {
        let bytes = usize::try_from(p.offset)
            .ok()
            .zip(usize::try_from(p.len).ok())
            .and_then(|(at, len)| frame.get(at..at.checked_add(len)?))
            .ok_or(fault(Rule::SpanOutOfBounds, "framer.piece.bytes"))?;
        if p.flags & PIECE_CONTINUED == 0 && bytes.first() == Some(&b':') {
            return Err(fault(Rule::Foreign, FIELD));
        }
        // A CR LF split across pieces: the LF opens this one and the next line follows it.
        if bytes.starts_with(b"\n:") || bytes.windows(3).any(|w| w == b"\r\n:") {
            return Err(fault(Rule::Foreign, FIELD));
        }
    }
    Ok(())
}

/// A framer answer's head slots (`heads`, the host's buffer of `heads_cap`): at most the
/// capacity; one per stream; each slot inside the frame bytes written; a method and a target
/// present together or both absent.
///
/// # Errors
///
/// The rule the slots break.
pub fn check_head_slots(out: &FramerOut, heads: &[HeadSlots], heads_cap: u64) -> Result<(), Fault> {
    let y = &out.yielded;
    let n = u64::from(y.heads_len);
    within(n, heads_cap, "framer.heads_len")?;
    let heads = first(heads, n, "framer.heads")?;
    for (i, h) in heads.iter().enumerate() {
        if heads[..i].iter().any(|e| e.stream == h.stream) {
            return Err(fault(Rule::Contradiction, "framer.head.stream_twice"));
        }
        let span = |s: FrameSpan, field| range(s.offset, s.len, y.frame_len, field);
        span(h.method, "framer.head.method")?;
        span(h.target, "framer.head.target")?;
        span(h.authority, "framer.head.authority")?;
        span(h.reason, "framer.head.reason")?;
        if (h.method.len == 0) != (h.target.len == 0) {
            return Err(fault(
                Rule::Contradiction,
                "framer.head.method_without_target",
            ));
        }
    }
    Ok(())
}

/// Connection facts: the size is the struct's own.
///
/// # Errors
///
/// [`Rule::Foreign`].
pub const fn check_facts(facts: &ConnFacts) -> Result<(), Fault> {
    if facts.size as usize != core::mem::size_of::<ConnFacts>() {
        return Err(fault(Rule::Foreign, "facts.size"));
    }
    Ok(())
}

abi_op! {
    /// The Statement tail, at load: the role is exactly one of carrier or framer, and a carrier composes
    /// over nothing (a framer with an empty `composes_over` frames directly over the host's socket);
    /// framing and fact bits are known; one to [`MAX_CLAIMS`]
    /// claim rows; no list is counted with a NULL pointer. The lists' elements: [`check_claims`] (and
    /// each row's [`check_claim_facts`]), [`check_composes_over`], [`check_upgrades_to`],
    /// [`check_status_rows`], [`check_fault_rows`], [`check_fault_cover`], [`check_settings`].
    ///
    /// # Errors
    ///
    /// The rule the tail breaks.
    pub fn check_tail(t: &TransportTail) as "tail", TAIL_RULES for t: TransportTail {
        deny((t.role == ROLE_CARRIER) == (t.role == ROLE_FRAMER), NotExactlyOne, "tail.role");
        deny(t.role == ROLE_CARRIER && t.composes_over_len != 0, Contradiction, "tail.composes_over");
        code(framing, FRAMING_STREAM, FRAMING_DATAGRAM);
        bits(facts, FACT_SIGNS_NOTHING_AFTER_AUTH | FACT_DECODES_PAYLOAD);
        deny(t.claim_rows_len == 0, Missing, "tail.claim_rows");
        deny(t.claim_rows_len as u64 > MAX_CLAIMS, OverMax, "tail.claim_rows");
        then listed(t.composes_over, t.composes_over_len, "tail.composes_over");
        then listed(t.claim_rows, t.claim_rows_len, "tail.claim_rows");
        then listed(t.upgrades_to, t.upgrades_to_len, "tail.upgrades_to");
        then listed(t.status_rows, t.status_rows_len, "tail.status_rows");
        then listed(t.settings, t.settings_len, "tail.settings");
        then listed(t.fault_rows, t.fault_rows_len, "tail.fault_rows");
        // Every tail list is bounded and aligned before a reader builds a slice over it.
        then bounded(t.composes_over, t.composes_over_len, "tail.composes_over");
        then bounded(t.claim_rows, t.claim_rows_len, "tail.claim_rows");
        then bounded(t.upgrades_to, t.upgrades_to_len, "tail.upgrades_to");
        then bounded(t.status_rows, t.status_rows_len, "tail.status_rows");
        then bounded(t.settings, t.settings_len, "tail.settings");
        then bounded(t.fault_rows, t.fault_rows_len, "tail.fault_rows");
        text(handoff_from);
        text(handoff_to);
        text(handoff_binding_fact);
        text(handshake_frame_kind);
    }
}

/// Every claim row: no string or list counted with a NULL pointer, its fact-key list bounded and
/// aligned, the session bits `0`/`1` and the trigger and status-frame codes known. (A row's scheme name is the Statement's; see
/// [`check_claim_rows`].)
///
/// # Errors
///
/// The rule a claim breaks.
pub fn check_claims(claims: &[Claim]) -> Result<(), Fault> {
    claims.iter().try_for_each(check_claim)
}

abi_op! {
    /// One claim row, as [`check_claims`] states.
    fn check_claim(c: &Claim) as "claim", CLAIM_RULES for c: Claim {
        text(selector_forms);
        text(egress_selector_forms);
        text(status_namespace);
        then listed(c.facts, c.facts_len, "claim.facts");
        // Bounded and aligned before the host builds the slice [`check_claim_facts`] reads.
        then bounded(c.facts, c.facts_len, "claim.facts");
        code(session, 0u8, 1u8);
        code(session_bound, 0u8, 1u8);
        code(unit0_trigger, 0u8, UNIT0_HANDSHAKE);
        code(status_at, 0u8, STATUS_AT_TERMINAL);
    }
}

/// THE ONE SOURCE OF CLAIM NAMES, at admit: a transport's tail has exactly one row per scheme its
/// Statement claims (row `i` describes `claims[i]`), so no claim is named in two places.
///
/// # Errors
///
/// [`Rule::Contradiction`] at `tail.claim_rows` when the counts differ.
pub const fn check_claim_rows(statement_claims_len: usize, t: &TransportTail) -> Result<(), Fault> {
    if t.claim_rows_len != statement_claims_len {
        return Err(fault(Rule::Contradiction, "tail.claim_rows"));
    }
    Ok(())
}

/// The claims a framer composes over: no name counted with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn check_composes_over(names: &[AbiStr]) -> Result<(), Fault> {
    texts(names, "composes_over.name")
}

/// The claims a connection may upgrade to: no name counted with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn check_upgrades_to(names: &[AbiStr]) -> Result<(), Fault> {
    texts(names, "upgrades_to.name")
}

/// One claim's transport fact keys: no key counted with a NULL pointer.
///
/// # Errors
///
/// [`Rule::NullWithCount`].
pub fn check_claim_facts(keys: &[AbiStr]) -> Result<(), Fault> {
    texts(keys, "claim.fact")
}

/// Every status row: names a claim, `lo <= hi`, and a class that is stated.
///
/// # Errors
///
/// The rule a row breaks.
pub fn check_status_rows(rows: &[StatusRow], claims_len: u64) -> Result<(), Fault> {
    rows.iter()
        .try_for_each(|r| check_status_row(r, claims_len))
}

abi_op! {
    /// One status row, as [`check_status_rows`] states.
    fn check_status_row(r: &StatusRow, claims_len: u64) as "status_row", STATUS_ROW_RULES for r: StatusRow {
        index(claim, claims_len);
        deny(r.lo > r.hi, Contradiction, "status_row.lo_hi");
        code(class, STATUS_SUCCESS, STATUS_OTHER);
    }
}

/// A stream's FINAL STATUS on its close ([`FinishIn`], ARCHITECT 4l): `final_status` is a number the
/// status rows of `claim` (the claim the stream arrived on) cover, or `0` on a claim stating no
/// numbering; `final_message` and `final_details` lie inside `final_bytes` (or are empty), and a
/// stated byte range has the bytes behind it. The host judges its own close before the crossing:
/// a status the claim's numbering does not have is never handed to the framer.
///
/// # Errors
///
/// The rule the close breaks.
pub fn check_final_status(i: &FinishIn, rows: &[StatusRow], claim: u32) -> Result<(), Fault> {
    let mut numbered = rows.iter().filter(|r| r.claim == claim).peekable();
    let covered = if numbered.peek().is_none() {
        i.final_status == 0
    } else {
        numbered.any(|r| (r.lo..=r.hi).contains(&i.final_status))
    };
    if !covered {
        return Err(fault(Rule::UnknownCode, "finish.final_status"));
    }
    if i.final_bytes.is_null() && i.final_bytes_len != 0 {
        return Err(fault(Rule::NullWithCount, "finish.final_bytes"));
    }
    let bound = i.final_bytes_len as u64;
    for (s, field) in [
        (i.final_message, "finish.final_message"),
        (i.final_details, "finish.final_details"),
    ] {
        if s.len == 0 {
            continue;
        }
        range(u64::from(s.offset), u64::from(s.len), bound, field)?;
    }
    Ok(())
}

/// An `emit`'s STATUS ([`EmitIn::status`], INBOUND-LISTEN, `BUSBAR-1.6.0.md` l.4913): stated on
/// the emit that carries an ACCEPTED stream's answer head (`answers_head`), and on no other. The
/// framer refuses the emit that breaks it, before any byte of it reaches the wire.
///
/// # Errors
///
/// The rule the emit breaks.
pub fn check_emit_status(i: &EmitIn, answers_head: bool) -> Result<(), Fault> {
    if i._status_reserved != 0 {
        return Err(fault(Rule::UnknownCode, "emit._status_reserved"));
    }
    match (answers_head, i.status) {
        (true, 0) => Err(fault(Rule::Missing, "emit.status")),
        (false, s) if s != 0 => Err(fault(Rule::Contradiction, "emit.status")),
        _ => Ok(()),
    }
}

/// Every fault row: names a claim, `lo <= hi`, and a fault reading that is stated (never
/// `FAULT_NONE`: a code the table does not cover already reads none).
///
/// # Errors
///
/// The rule a row breaks.
pub fn check_fault_rows(rows: &[FaultRow], claims_len: u64) -> Result<(), Fault> {
    rows.iter().try_for_each(|r| check_fault_row(r, claims_len))
}

abi_op! {
    /// One fault row, as [`check_fault_rows`] states.
    fn check_fault_row(r: &FaultRow, claims_len: u64) as "fault_row", FAULT_ROW_RULES for r: FaultRow {
        index(claim, claims_len);
        deny(r.lo > r.hi, Contradiction, "fault_row.lo_hi");
        code(fault, FAULT_CALLER, FAULT_HEALTHY);
    }
}

/// A claim that classes its answers classes them for the breaker too: every claim named by a status
/// row is named by at least one fault row. A framer that states status rows and no fault table
/// would have every failure it reports read as the caller's, and the destination behind it would
/// never trip, so the load is refused rather than served blind.
///
/// # Errors
///
/// [`Rule::Missing`] at `tail.fault_rows` for the first claim with status rows and no fault row.
pub fn check_fault_cover(status: &[StatusRow], faults: &[FaultRow]) -> Result<(), Fault> {
    for r in status {
        if !faults.iter().any(|f| f.claim == r.claim) {
            return Err(fault(Rule::Missing, "tail.fault_rows"));
        }
    }
    Ok(())
}

/// Every setting: a path and a known kind.
///
/// # Errors
///
/// The rule a setting breaks.
pub fn check_settings(settings: &[SettingDecl]) -> Result<(), Fault> {
    settings.iter().try_for_each(check_setting)
}

abi_op! {
    /// One setting, as [`check_settings`] states.
    fn check_setting(s: &SettingDecl) as "setting", SETTING_RULES for s: SettingDecl {
        deny(s.path.len == 0, Missing, "setting.path");
        text(path);
        text(default);
        code(kind, SETTING_FLAG, SETTING_TEXT);
    }
}

/// The auth points a transport offers, read from its Statement's `extensions`
/// ([`super::EXT_OFFERED_POINTS`]): `{Head, HeadBody}` when it states no record; else exactly four
/// bytes of [`POINT_PEER`] | [`POINT_HEAD`] | [`POINT_HEAD_BODY`] bits.
///
/// # Errors
///
/// The record is not four bytes ([`Rule::Foreign`]) or names another bit ([`Rule::UnknownCode`]).
pub fn check_offered_points(extensions: &[u8]) -> Result<AuthPoints, Fault> {
    let Some(value) = crate::abi::mechanism::extensions::get(extensions, super::EXT_OFFERED_POINTS)
    else {
        return Ok(AuthPoints(POINT_HEAD | POINT_HEAD_BODY));
    };
    let bits = <[u8; 4]>::try_from(value)
        .map(u32::from_le_bytes)
        .map_err(|_| fault(Rule::Foreign, "offered_points.len"))?;
    if bits & !(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY) != 0 {
        return Err(fault(Rule::UnknownCode, "offered_points.unknown_flags"));
    }
    Ok(AuthPoints(bits))
}

/// The most field predicates one route may carry.
pub const MAX_ROUTE_FIELDS: u64 = 32;

abi_op! {
    /// A route's shape, before its strings are read: a method set inside the vocabulary and not empty, a
    /// known path form, and its path and predicate list well-formed pointers.
    ///
    /// # Errors
    ///
    /// The rule the route breaks.
    pub fn check_route(r: &RouteMatch) as "route", ROUTE_RULES for r: RouteMatch {
        deny(r.methods == 0, Missing, "route.methods");
        bits(methods, METHOD_ANY);
        code(path_form, PATH_EXACT, PATH_CONTAINS);
        text(path);
        then listed(r.fields, r.fields_len, "route.fields");
        deny(r.fields_len as u64 > MAX_ROUTE_FIELDS, OverMax, "route.fields");
    }
}

/// Every field predicate's shape: a known op and well-formed strings.
///
/// # Errors
///
/// The rule the first bad predicate breaks.
pub fn check_route_fields(fields: &[FieldPredicate]) -> Result<(), Fault> {
    fields.iter().try_for_each(check_route_field)
}

abi_op! {
    /// One field predicate, as [`check_route_fields`] states.
    fn check_route_field(f: &FieldPredicate) as "route.field", ROUTE_FIELD_RULES for f: FieldPredicate {
        code(op, FIELD_PRESENT, FIELD_VALUE_PREFIX);
        text(name);
        text(value);
    }
}

/// A route's CONTENT, read: a method set inside the vocabulary and not empty, a known path form, a
/// path that is not empty; an exact, pattern or prefix path that starts with `/`; a pattern that
/// keeps the syntax; field names that are non-empty lower-case tokens; a value on a value-prefix
/// predicate and none on a presence predicate. The kernel runs it on every line it seals into a
/// guest list, so a route no request can match is refused at boot, never mounted.
///
/// # Errors
///
/// The rule the route breaks.
pub fn check_route_view(r: &super::route::RouteView<'_>) -> Result<(), Fault> {
    use super::route::{pattern_segments, PATH_PATTERN, PATH_PREFIX};
    if r.methods == 0 {
        return Err(fault(Rule::Missing, "route.methods"));
    }
    bits(u64::from(r.methods), u64::from(METHOD_ANY), "route.methods")?;
    code(
        u64::from(r.path_form),
        u64::from(PATH_EXACT),
        u64::from(PATH_CONTAINS),
        "route.path_form",
    )?;
    if r.path.is_empty() {
        return Err(fault(Rule::Missing, "route.path"));
    }
    if matches!(r.path_form, PATH_EXACT | PATH_PATTERN | PATH_PREFIX) && !r.path.starts_with('/') {
        return Err(fault(Rule::UnknownCode, "route.path"));
    }
    if r.path_form == PATH_PATTERN && pattern_segments(r.path).is_none() {
        return Err(fault(Rule::UnknownCode, "route.path.pattern"));
    }
    for (op, name, value) in &r.fields {
        let token = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
        if !token {
            return Err(fault(Rule::UnknownCode, "route.field.name"));
        }
        if (*op == FIELD_PRESENT) != value.is_empty() {
            return Err(fault(Rule::Contradiction, "route.field.value"));
        }
    }
    Ok(())
}

/// A framer answer: its pieces over the host's `sink.pieces`, every cap from the op's `sink`; a
/// field block's bytes are the only frame bytes read ([`check_framer_fields`]).
///
/// # Safety
/// `sink` is the op's own `in`: each of its buffers is the host's, of its stated capacity.
unsafe fn framer(outcome: Outcome, o: &FramerOut, sink: FramerSink) -> Result<(), Fault> {
    let pieces_cap = sink.pieces_cap as u64;
    // SAFETY: `sink.pieces` is the host's own buffer of `pieces_cap` `FramePiece`s, named by this
    // op's `in`.
    let pieces = unsafe {
        reported(
            sink.pieces.cast_const(),
            u64::from(o.yielded.pieces_len),
            pieces_cap,
            "framer.pieces_len",
        )
    }?;
    check_framer(
        outcome,
        o,
        pieces,
        sink.wire_cap as u64,
        sink.frame_cap as u64,
        pieces_cap,
    )?;
    // Only a field block's bytes are read here; payload never is.
    if pieces.iter().any(|p| p.flags & PIECE_FIELDS != 0) {
        // SAFETY: `sink.frame` is the host's own buffer of `frame_cap` bytes; `check_framer` held
        // `frame_len` within it.
        let frame = unsafe {
            reported(
                sink.frame.cast_const(),
                o.yielded.frame_len,
                sink.frame_cap as u64,
                "framer.frame_len",
            )
        }?;
        check_framer_fields(pieces, frame)?;
    }
    let heads_cap = sink.heads_cap as u64;
    // SAFETY: `sink.heads` is the host's own buffer of `heads_cap` `HeadSlots`s (NULL with a
    // capacity of `0` on a host that takes none).
    let heads = unsafe {
        reported(
            sink.heads.cast_const(),
            u64::from(o.yielded.heads_len),
            heads_cap,
            "framer.heads_len",
        )
    }?;
    check_head_slots(o, heads, heads_cap)
}

// THE TRANSPORT KIND'S ANSWERS (`check_answer`), each op's frames in the order the loader reads
// them. `dial`, `flush`, `shut` and the other lifecycle answers state no rule beyond the
// mechanism's, and pass here.
abi_answers! {
    cx: ();
    slot::LISTEN => listen(out ListenOut, in ListenIn) |_, i, o, _| {
        check_listen(o, i.addr_cap as u64)
    }
    slot::ACCEPT => accept(out AcceptOut, in AcceptIn) |_, i, o, _| {
        check_accept(o, i.peer_cap as u64)
    }
    slot::READ => read(out IoOut, in ReadIn) |_, i, o, _| {
        check_io(o, i.cap as u64)
    }
    slot::WRITE => write(out IoOut, in WriteIn) |_, i, o, _| {
        check_io(o, i.len as u64)
    }
    slot::ARRIVAL => arrival(out ArrivalOut, in ArrivalIn) |outcome, i, o, _| {
        check_arrival(outcome, o, i.peer_cap as u64)
    }
    slot::LOCATE => locate(in LocateIn, out LocateOut) |outcome, i, o, _| {
        let offer: &[u8] = if outcome == Outcome::Ready {
            // SAFETY: `alpn_buf` is the host's own buffer of `alpn_cap` bytes, named by this
            // op's `in`.
            unsafe {
                reported(i.alpn_buf.cast_const(), o.alpn_written, i.alpn_cap as u64, "locate.alpn")
            }?
        } else {
            &[]
        };
        check_locate(
            outcome,
            o,
            i.authority_cap as u64,
            i.name_cap as u64,
            i.alpn_cap as u64,
            offer,
            i.defaults_cap as u64,
        )
    }
    // SAFETY (each framer op below): `check_answer`'s contract; the sink is the op's own `in`.
    slot::BEGIN => begin(in BeginIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::INGEST => ingest(in IngestIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::EMIT => emit(in EmitIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::ENCODE => encode(in EncodeIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::REFUSE => refuse(in RefuseIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::FINISH => finish(in FinishIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::DETACH | slot::TIMER => framing(in FramingIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    slot::ADOPT => adopt(in AdoptIn, out FramerOut) |outcome, i, o, _| {
        unsafe { framer(outcome, o, i.sink) }
    }
    life::CANCEL => cancel(out CancelOut) |outcome, _, o, _| {
        check_cancel(outcome, o.disposition)
    }
}

#[cfg(test)]
#[path = "../tests/transport_check_tests.rs"]
mod tests;
