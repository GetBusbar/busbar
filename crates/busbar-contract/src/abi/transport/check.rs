// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S ANSWER VALIDATORS (ARCHITECT rulings "answer validators live with the
//! shape", M-SB, P1-P3): one pure `check_<op>` per answer, built from the shared helpers in
//! [`crate::abi::mechanism::check`]. The dispatcher turns an `Err` into FAULT.
//!
//! * `arrival` and `locate` have the short path (M-SB; `locate`'s authority and name are one
//!   multi-dimension answer, the M-SB refinement); `listen`, `accept` and `read` do not
//!   (P1): their lengths are at most the capacity, and the host's `addr_cap`/`peer_cap` is at least
//!   [`MAX_ADDR`].
//! * A framer has no short path either: a full sink is READY with [`YIELD_MORE`] (backpressure).
//! * The tail and every list element it names are checked at load (P3).

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{
    AcceptOut, ArrivalOut, Claim, ConnFacts, FramePiece, FramerOut, IoOut, ListenOut, LocateOut,
    SettingDecl, StatusRow, TransportTail, CANCEL_COMPLETED, CANCEL_NOTHING_MOVED,
    FACT_DECODES_PAYLOAD, FACT_SIGNS_NOTHING_AFTER_AUTH, FRAMING_DATAGRAM, FRAMING_STREAM,
    MAX_ADDR, PIECE_END_OF_FRAME, PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER, ROLE_CARRIER, ROLE_FRAMER,
    SETTING_FLAG, SETTING_TEXT, STATUS_AT_TERMINAL, STATUS_OTHER, STATUS_SUCCESS, UNIT0_HANDSHAKE,
    YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};
use crate::abi::mechanism::call::{AbiStr, Outcome};
use crate::abi::mechanism::check::{
    bits, code, fault, first, index, listed, range, result, results, within, Dim, MAX_BYTES,
};

/// The most frame pieces one framer answer may produce.
pub const MAX_PIECES: u64 = 4096;
/// The most claims one transport entry may make.
pub const MAX_CLAIMS: u64 = 256;

fn text(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    listed(s.ptr, s.len, field)
}

/// `listen`: no short path (P1); the bound address fits `addr_cap`.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_listen(out: &ListenOut, addr_cap: u64) -> Result<(), Fault> {
    within(out.addr_written, addr_cap, "listen.addr_written")
}

/// `accept`: no short path (P1); the far end's address fits `peer_cap`.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_accept(out: &AcceptOut, peer_cap: u64) -> Result<(), Fault> {
    within(out.peer_written, peer_cap, "accept.peer_written")
}

/// `arrival`: the far end's address, under M-SB.
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

/// `read`/`write`: no short path; at most the buffer's capacity or the bytes offered.
///
/// # Errors
///
/// The rule the answer breaks.
pub const fn check_io(out: &IoOut, cap: u64) -> Result<(), Fault> {
    within(out.len, cap, "io.len")
}

/// `locate`: authority and name under M-SB; `has_name` and `secure` are flags, and no name means
/// nothing written or needed for it.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_locate(
    outcome: Outcome,
    out: &LocateOut,
    authority_cap: u64,
    name_cap: u64,
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
        ],
    )?;
    Ok(())
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
        u64::from(YIELD_ENDED | YIELD_MORE | YIELD_HAS_DEADLINE),
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
            u64::from(PIECE_END_OF_FRAME | PIECE_HAS_CODE | PIECE_HAS_RETRY_AFTER),
            "framer.piece.flags",
        )?;
        code(
            u64::from(p.status_class),
            0,
            u64::from(STATUS_OTHER),
            "framer.piece.status_class",
        )?;
    }
    Ok(())
}

/// The lifecycle `cancel`'s disposition: one of the transport's three (`0` = unwritten).
///
/// # Errors
///
/// [`Rule::UnknownCode`].
pub const fn check_cancel(disposition: u32) -> Result<(), Fault> {
    code(
        disposition as u64,
        CANCEL_NOTHING_MOVED as u64,
        CANCEL_COMPLETED as u64,
        "cancel.disposition",
    )
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

/// The Statement tail, at load: the role is exactly one of carrier or framer and agrees with
/// `composes_over` (empty = carrier); framing and fact bits are known; one to [`MAX_CLAIMS`]
/// claims; no list is counted with a NULL pointer. The lists' elements: [`check_claims`],
/// [`check_status_rows`], [`check_settings`].
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &TransportTail) -> Result<(), Fault> {
    if (t.role == ROLE_CARRIER) == (t.role == ROLE_FRAMER) {
        return Err(fault(Rule::NotExactlyOne, "tail.role"));
    }
    if (t.role == ROLE_CARRIER) != (t.composes_over_len == 0) {
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
    if t.claims_len == 0 {
        return Err(fault(Rule::Missing, "tail.claims"));
    }
    if t.claims_len as u64 > MAX_CLAIMS {
        return Err(fault(Rule::OverMax, "tail.claims"));
    }
    listed(t.composes_over, t.composes_over_len, "tail.composes_over")?;
    listed(t.claims, t.claims_len, "tail.claims")?;
    listed(t.upgrades_to, t.upgrades_to_len, "tail.upgrades_to")?;
    listed(t.status_rows, t.status_rows_len, "tail.status_rows")?;
    listed(t.settings, t.settings_len, "tail.settings")?;
    text(t.handoff_from, "tail.handoff_from")?;
    text(t.handoff_to, "tail.handoff_to")?;
    text(t.handoff_binding_fact, "tail.handoff_binding_fact")?;
    text(t.handshake_frame_kind, "tail.handshake_frame_kind")
}

/// Every claim: a key, no string or list counted with a NULL pointer, the session bits `0`/`1`
/// and the trigger and status-frame codes known.
///
/// # Errors
///
/// The rule a claim breaks.
pub fn check_claims(claims: &[Claim]) -> Result<(), Fault> {
    for c in claims {
        if c.key.len == 0 {
            return Err(fault(Rule::Missing, "claim.key"));
        }
        text(c.key, "claim.key")?;
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

#[cfg(test)]
#[path = "../tests/transport_check_tests.rs"]
mod tests;
