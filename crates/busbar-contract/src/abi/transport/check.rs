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

use super::{
    AcceptOut, ArrivalOut, Claim, ConnFacts, FinishIn, FramePiece, FrameSpan, FramerOut, HeadSlots,
    IoOut, ListenOut, LocateOut, SettingDecl, StatusRow, TransportTail, CANCEL_COMPLETED,
    CANCEL_NOTHING_MOVED, FACT_DECODES_PAYLOAD, FACT_SIGNS_NOTHING_AFTER_AUTH, FRAMING_DATAGRAM,
    FRAMING_STREAM, MAX_ADDR, PIECE_CONTINUED, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE,
    PIECE_HAS_RETRY_AFTER, PIECE_STREAM_FAILED, PIECE_TEXT, PIECE_WRITABLE, ROLE_CARRIER,
    ROLE_FRAMER, SETTING_FLAG, SETTING_TEXT, STATUS_AT_TERMINAL, STATUS_OTHER, STATUS_SUCCESS,
    UNIT0_HANDSHAKE, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
use super::{
    DatagramRoute, KeyingMaterial, RendezvousTerms, FINGERPRINT_BYTES, HANDSHAKE_ANSWERS,
    HANDSHAKE_NONE, LANE_CLEAR, LANE_SECURED, MAX_KEYING_BYTES, MAX_ROUTES, PATH_REQUEST_BIND,
    PATH_REQUEST_NONE, PATH_REQUEST_REBIND,
};
use crate::abi::mechanism::call::{AbiStr, Outcome};
use crate::abi::mechanism::check::{
    bits, bounded, code, fault, first, index, listed, range, result, results, text, texts, within,
    Dim, MAX_BYTES,
};

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
) -> Result<(), Fault> {
    let y = &out.yielded;
    let n = u64::from(y.pieces_len);
    within(y.wire_len, wire_cap, "framer.wire_len")?;
    within(y.frame_len, frame_cap, "framer.frame_len")?;
    within(n, pieces_cap.min(MAX_PIECES), "framer.pieces_len")?;
    bits(
        u64::from(y.flags),
        u64::from(YIELD_ENDED | YIELD_MORE | YIELD_HAS_DEADLINE | YIELD_STREAM_FULL),
        "framer.flags",
    )?;
    if (y.flags & YIELD_HAS_DEADLINE != 0) != (y.next_deadline_ns != 0) {
        return Err(fault(Rule::Contradiction, "framer.next_deadline_ns"));
    }
    if outcome == Outcome::Failed && (y.wire_len | y.frame_len | n) != 0 {
        return Err(fault(Rule::Contradiction, "framer.failed_wrote"));
    }
    for p in first(pieces, n, "framer.pieces")? {
        range(p.offset, p.len, y.frame_len, "framer.piece.bytes")?;
        bits(
            u64::from(p.flags),
            u64::from(
                PIECE_END_OF_FRAME
                    | PIECE_HAS_CODE
                    | PIECE_HAS_RETRY_AFTER
                    | PIECE_STREAM_FAILED
                    | PIECE_FIELDS
                    | PIECE_CONTINUED
                    | PIECE_TEXT
                    | PIECE_WRITABLE,
            ),
            "framer.piece.flags",
        )?;
        // A writable piece is a signal about the stream, never part of a frame: empty, alone.
        if p.flags & PIECE_WRITABLE != 0 && (p.len != 0 || p.flags != PIECE_WRITABLE) {
            return Err(fault(
                Rule::Contradiction,
                "framer.piece.writable_not_alone",
            ));
        }
        // Text is a fact about a message's bytes: an empty piece, a field block and a failed
        // stream's reason carry none.
        if p.flags & PIECE_TEXT != 0
            && (p.len == 0 || p.flags & (PIECE_FIELDS | PIECE_STREAM_FAILED) != 0)
        {
            return Err(fault(Rule::Contradiction, "framer.piece.text_not_message"));
        }
        if p.flags & PIECE_CONTINUED != 0 && p.flags & PIECE_FIELDS == 0 {
            return Err(fault(
                Rule::Contradiction,
                "framer.piece.continued_not_fields",
            ));
        }
        // A field block is never a failure's reason.
        if p.flags & PIECE_FIELDS != 0 && p.flags & PIECE_STREAM_FAILED != 0 {
            return Err(fault(Rule::Contradiction, "framer.piece.fields_failed"));
        }
        // An empty piece is a stream's end (a writable piece aside), so it completes its frame; a
        // failed stream's piece is its last, so it does too.
        let ends = p.len == 0 && p.flags != PIECE_WRITABLE;
        if (ends || p.flags & PIECE_STREAM_FAILED != 0) && p.flags & PIECE_END_OF_FRAME == 0 {
            return Err(fault(
                Rule::Contradiction,
                "framer.piece.end_without_end_of_frame",
            ));
        }
        code(
            u64::from(p.status_class),
            0,
            u64::from(STATUS_OTHER),
            "framer.piece.status_class",
        )?;
    }
    Ok(())
}

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
) -> Result<(), Fault> {
    let d = &out.datagram;
    let y = &out.yielded;
    let n = u64::from(d.routes_len);
    within(n, routes_cap.min(MAX_ROUTES), "datagram.routes_len")?;
    if outcome == Outcome::Failed && (n != 0 || d.request != PATH_REQUEST_NONE) {
        return Err(fault(Rule::Contradiction, "datagram.failed_routed"));
    }
    for r in first(routes, n, "datagram.routes")? {
        if r.len == 0 {
            return Err(fault(Rule::Missing, "datagram.route.len"));
        }
        range(r.offset, r.len, y.wire_len, "datagram.route.bytes")?;
        if r.path == 0 {
            return Err(fault(Rule::Missing, "datagram.route.path"));
        }
        code(
            u64::from(r.lane),
            u64::from(LANE_CLEAR),
            u64::from(LANE_SECURED),
            "datagram.route.lane",
        )?;
    }
    code(
        u64::from(d.request),
        u64::from(PATH_REQUEST_NONE),
        u64::from(PATH_REQUEST_REBIND),
        "datagram.request",
    )?;
    let named = match d.request {
        PATH_REQUEST_BIND => d.request_from == 0 && d.request_to != 0,
        PATH_REQUEST_REBIND => {
            d.request_from != 0 && d.request_to != 0 && d.request_from != d.request_to
        }
        _ => d.request_from == 0 && d.request_to == 0,
    };
    if !named {
        return Err(fault(Rule::Contradiction, "datagram.request.paths"));
    }
    check_terms(&d.terms, y.frame_len)
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

/// The keying-material item a host presents: its own size, a nonzero profile, and
/// `1..=`[`MAX_KEYING_BYTES`] bytes behind a non-NULL pointer.
///
/// # Errors
///
/// The rule the item breaks.
pub fn check_keying(k: &KeyingMaterial) -> Result<(), Fault> {
    if k.size as usize != core::mem::size_of::<KeyingMaterial>() {
        return Err(fault(Rule::Foreign, "keying.size"));
    }
    if k.profile == 0 {
        return Err(fault(Rule::Missing, "keying.profile"));
    }
    if k.len == 0 {
        return Err(fault(Rule::Missing, "keying.len"));
    }
    if k.len as u64 > MAX_KEYING_BYTES {
        return Err(fault(Rule::OverMax, "keying.len"));
    }
    if k.bytes.is_null() {
        return Err(fault(Rule::NullWithCount, "keying.bytes"));
    }
    Ok(())
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

/// The Statement tail, at load: the role is exactly one of carrier or framer, and a carrier composes
/// over nothing (a framer with an empty `composes_over` frames directly over the host's socket);
/// framing and fact bits are known; one to [`MAX_CLAIMS`]
/// claim rows; no list is counted with a NULL pointer. The lists' elements: [`check_claims`],
/// [`check_status_rows`], [`check_settings`].
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &TransportTail) -> Result<(), Fault> {
    if (t.role == ROLE_CARRIER) == (t.role == ROLE_FRAMER) {
        return Err(fault(Rule::NotExactlyOne, "tail.role"));
    }
    if t.role == ROLE_CARRIER && t.composes_over_len != 0 {
        return Err(fault(Rule::Contradiction, "tail.composes_over"));
    }
    code(
        u64::from(t.framing),
        u64::from(FRAMING_STREAM),
        u64::from(FRAMING_DATAGRAM),
        "tail.framing",
    )?;
    bits(
        u64::from(t.facts),
        u64::from(FACT_SIGNS_NOTHING_AFTER_AUTH | FACT_DECODES_PAYLOAD),
        "tail.facts",
    )?;
    if t.claim_rows_len == 0 {
        return Err(fault(Rule::Missing, "tail.claim_rows"));
    }
    if t.claim_rows_len as u64 > MAX_CLAIMS {
        return Err(fault(Rule::OverMax, "tail.claim_rows"));
    }
    listed(t.composes_over, t.composes_over_len, "tail.composes_over")?;
    listed(t.claim_rows, t.claim_rows_len, "tail.claim_rows")?;
    listed(t.upgrades_to, t.upgrades_to_len, "tail.upgrades_to")?;
    listed(t.status_rows, t.status_rows_len, "tail.status_rows")?;
    listed(t.settings, t.settings_len, "tail.settings")?;
    // Every tail list is bounded and aligned before a reader builds a slice over it.
    bounded(t.composes_over, t.composes_over_len, "tail.composes_over")?;
    bounded(t.claim_rows, t.claim_rows_len, "tail.claim_rows")?;
    bounded(t.upgrades_to, t.upgrades_to_len, "tail.upgrades_to")?;
    bounded(t.status_rows, t.status_rows_len, "tail.status_rows")?;
    bounded(t.settings, t.settings_len, "tail.settings")?;
    text(t.handoff_from, "tail.handoff_from")?;
    text(t.handoff_to, "tail.handoff_to")?;
    text(t.handoff_binding_fact, "tail.handoff_binding_fact")?;
    text(t.handshake_frame_kind, "tail.handshake_frame_kind")
}

/// Every claim row: no string or list counted with a NULL pointer, the session bits `0`/`1` and
/// the trigger and status-frame codes known. (A row's scheme name is the Statement's; see
/// [`check_claim_rows`].)
///
/// # Errors
///
/// The rule a claim breaks.
pub fn check_claims(claims: &[Claim]) -> Result<(), Fault> {
    for c in claims {
        text(c.selector_forms, "claim.selector_forms")?;
        text(c.egress_selector_forms, "claim.egress_selector_forms")?;
        text(c.status_namespace, "claim.status_namespace")?;
        listed(c.facts, c.facts_len, "claim.facts")?;
        code(u64::from(c.session), 0, 1, "claim.session")?;
        code(u64::from(c.session_bound), 0, 1, "claim.session_bound")?;
        code(
            u64::from(c.unit0_trigger),
            0,
            u64::from(UNIT0_HANDSHAKE),
            "claim.unit0_trigger",
        )?;
        code(
            u64::from(c.status_at),
            0,
            u64::from(STATUS_AT_TERMINAL),
            "claim.status_at",
        )?;
    }
    Ok(())
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
    for r in rows {
        index(r.claim, claims_len, "status_row.claim")?;
        if r.lo > r.hi {
            return Err(fault(Rule::Contradiction, "status_row.lo_hi"));
        }
        code(
            u64::from(r.class),
            u64::from(STATUS_SUCCESS),
            u64::from(STATUS_OTHER),
            "status_row.class",
        )?;
    }
    Ok(())
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

/// Every setting: a path and a known kind.
///
/// # Errors
///
/// The rule a setting breaks.
pub fn check_settings(settings: &[SettingDecl]) -> Result<(), Fault> {
    for s in settings {
        if s.path.len == 0 {
            return Err(fault(Rule::Missing, "setting.path"));
        }
        text(s.path, "setting.path")?;
        text(s.default, "setting.default")?;
        code(
            u64::from(s.kind),
            u64::from(SETTING_FLAG),
            u64::from(SETTING_TEXT),
            "setting.kind",
        )?;
    }
    Ok(())
}

/// The most field predicates one route may carry.
pub const MAX_ROUTE_FIELDS: u64 = 32;

/// A route's shape, before its strings are read: a method set inside the vocabulary and not empty, a
/// known path form, and its path and predicate list well-formed pointers.
///
/// # Errors
///
/// The rule the route breaks.
pub fn check_route(r: &super::route::RouteMatch) -> Result<(), Fault> {
    use super::route::{METHOD_ANY, PATH_CONTAINS, PATH_EXACT};
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
    text(r.path, "route.path")?;
    listed(r.fields, r.fields_len, "route.fields")?;
    if r.fields_len as u64 > MAX_ROUTE_FIELDS {
        return Err(fault(Rule::OverMax, "route.fields"));
    }
    Ok(())
}

/// Every field predicate's shape: a known op and well-formed strings.
///
/// # Errors
///
/// The rule the first bad predicate breaks.
pub fn check_route_fields(fields: &[super::route::FieldPredicate]) -> Result<(), Fault> {
    use super::route::{FIELD_PRESENT, FIELD_VALUE_PREFIX};
    for f in fields {
        code(
            u64::from(f.op),
            u64::from(FIELD_PRESENT),
            u64::from(FIELD_VALUE_PREFIX),
            "route.field.op",
        )?;
        text(f.name, "route.field.name")?;
        text(f.value, "route.field.value")?;
    }
    Ok(())
}

/// A route's CONTENT, read: a path that is not empty; an exact, pattern or prefix path that starts
/// with `/`; a pattern that keeps the syntax; field names that are non-empty lower-case tokens; a
/// value on a value-prefix predicate and none on a presence predicate.
///
/// # Errors
///
/// The rule the route breaks.
pub fn check_route_view(r: &super::route::RouteView<'_>) -> Result<(), Fault> {
    use super::route::{pattern_segments, FIELD_PRESENT, PATH_EXACT, PATH_PATTERN, PATH_PREFIX};
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

#[cfg(test)]
#[path = "../tests/transport_check_tests.rs"]
mod tests;
