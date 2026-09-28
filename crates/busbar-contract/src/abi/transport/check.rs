// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT KIND'S ANSWER VALIDATORS (ARCHITECT ruling "answer validators live with the
//! shape"): one pure `check_<op>` per answer, u64 arithmetic, no statics. The dispatcher calls them
//! on every answer and turns an `Err` into FAULT; no host re-implements them.
//!
//! THE RULES:
//!
//! * a needed byte count is at most `u32::MAX` and a needed element count at most its hard max;
//! * FAILED with a non-zero length that fits its capacity is FAULT (it would waste the one re-call);
//! * a count never exceeds its capacity where the op has no re-call (a read, a framer's sink);
//! * an "exactly one of" field with none or several set is FAULT, and so is an unknown bit or code;
//! * a count above zero with a NULL pointer is FAULT;
//! * a frame piece lies inside the frame bytes written, with checked arithmetic.

use super::{
    AcceptOut, ArrivalOut, ConnFacts, FramePiece, FramerOut, IoOut, ListenOut, LocateOut,
    TransportTail, CANCEL_COMPLETED, CANCEL_NOTHING_MOVED, CANCEL_PARTIAL, FACT_DECODES_PAYLOAD,
    FACT_SIGNS_NOTHING_AFTER_AUTH, FRAMING_DATAGRAM, FRAMING_STREAM, PIECE_END_OF_FRAME,
    PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER, ROLE_CARRIER, ROLE_FRAMER, STATUS_OTHER, YIELD_ENDED,
    YIELD_HAS_DEADLINE, YIELD_MORE,
};
use crate::abi::mechanism::call::Outcome;

/// The most frame pieces one framer answer may produce.
pub const MAX_PIECES: u64 = 4096;
/// The most claims one transport entry may make.
pub const MAX_CLAIMS: u64 = 256;

/// Why an answer is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A needed byte count above `u32::MAX`, or a needed element count above its hard max.
    OverMax,
    /// FAILED with a non-zero length that fits its capacity.
    WastedRecall,
    /// A count above its capacity where the op has no re-call.
    OverCap,
    /// A count above zero with a NULL pointer.
    NullWithCount,
    /// An "exactly one of" field with none or several set.
    NotExactlyOne,
    /// An unknown bit or code.
    UnknownCode,
    /// A frame piece outside the frame bytes written.
    PieceOutOfFrame,
    /// A list the answer must carry is empty.
    Missing,
}

/// A length the plugin may answer as NEEDED (`len > cap` asks for one re-call): it is at most
/// `max`, and FAILED never carries one that fits.
fn needed(outcome: Outcome, len: u64, cap: u64, max: u64) -> Result<(), Fault> {
    if len > max {
        return Err(Fault::OverMax);
    }
    if outcome == Outcome::Failed && len != 0 && len <= cap {
        return Err(Fault::WastedRecall);
    }
    Ok(())
}

/// A length with no re-call: at most its capacity.
fn within(len: u64, cap: u64) -> Result<(), Fault> {
    if len > cap {
        return Err(Fault::OverCap);
    }
    Ok(())
}

fn flag(v: u32) -> Result<(), Fault> {
    if v > 1 {
        return Err(Fault::UnknownCode);
    }
    Ok(())
}

fn listed<T>(ptr: *const T, len: usize) -> Result<(), Fault> {
    if len > 0 && ptr.is_null() {
        return Err(Fault::NullWithCount);
    }
    Ok(())
}

const BYTES: u64 = u32::MAX as u64;

/// `listen`: the bound address fits `addr_cap` or is a needed size.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_listen(outcome: Outcome, out: &ListenOut, addr_cap: u64) -> Result<(), Fault> {
    needed(outcome, out.addr_len, addr_cap, BYTES)
}

/// `accept`: the far end's address fits `peer_cap` or is a needed size.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_accept(outcome: Outcome, out: &AcceptOut, peer_cap: u64) -> Result<(), Fault> {
    needed(outcome, out.peer_len, peer_cap, BYTES)
}

/// `arrival`: the far end's address fits `peer_cap` or is a needed size.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_arrival(outcome: Outcome, out: &ArrivalOut, peer_cap: u64) -> Result<(), Fault> {
    needed(outcome, out.peer_len, peer_cap, BYTES)
}

/// `read` and `write`: at most the buffer's capacity (a read) or the bytes offered (a write); a
/// FAILED answer moved nothing.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_io(outcome: Outcome, out: &IoOut, cap: u64) -> Result<(), Fault> {
    within(out.len, cap)?;
    if outcome == Outcome::Failed && out.len != 0 {
        return Err(Fault::WastedRecall);
    }
    Ok(())
}

/// `locate`: the authority and the offered name fit their buffers or are needed sizes (`u64::MAX`
/// name = none); `secure` is `0`/`1`.
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
    needed(outcome, out.authority_len, authority_cap, BYTES)?;
    if out.name_len != u64::MAX {
        needed(outcome, out.name_len, name_cap, BYTES)?;
    }
    flag(out.secure)
}

/// Every framer answer: what it wrote fits its sink (a framer has no re-call: a full sink is
/// [`YIELD_MORE`]); the flags are known; a deadline is stated exactly when flagged; every piece
/// lies inside the frame bytes written; FAILED wrote nothing.
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
    within(y.wire_len, wire_cap)?;
    within(y.frame_len, frame_cap)?;
    within(u64::from(y.pieces_len), pieces_cap.min(MAX_PIECES))?;
    if y.flags & !(YIELD_ENDED | YIELD_MORE | YIELD_HAS_DEADLINE) != 0 {
        return Err(Fault::UnknownCode);
    }
    if (y.flags & YIELD_HAS_DEADLINE != 0) != (y.next_deadline_ns != 0) {
        return Err(Fault::UnknownCode);
    }
    if outcome == Outcome::Failed && (y.wire_len | y.frame_len | u64::from(y.pieces_len)) != 0 {
        return Err(Fault::WastedRecall);
    }
    let n = usize::try_from(y.pieces_len).map_err(|_| Fault::OverCap)?;
    let written = pieces.get(..n).ok_or(Fault::OverCap)?;
    for p in written {
        let end = p.offset.checked_add(p.len).ok_or(Fault::PieceOutOfFrame)?;
        if end > y.frame_len {
            return Err(Fault::PieceOutOfFrame);
        }
        if p.flags & !(PIECE_END_OF_FRAME | PIECE_HAS_CODE | PIECE_HAS_RETRY_AFTER) != 0
            || p.status_class > STATUS_OTHER
        {
            return Err(Fault::UnknownCode);
        }
    }
    Ok(())
}

/// The lifecycle `cancel`'s disposition: one of the transport's three.
///
/// # Errors
///
/// [`Fault::UnknownCode`] for any other number, `0` (unwritten) included.
pub const fn check_cancel(disposition: u32) -> Result<(), Fault> {
    match disposition {
        CANCEL_NOTHING_MOVED | CANCEL_PARTIAL | CANCEL_COMPLETED => Ok(()),
        _ => Err(Fault::UnknownCode),
    }
}

/// Connection facts: the size is the struct's own.
///
/// # Errors
///
/// [`Fault::UnknownCode`] for a size that is not `size_of::<ConnFacts>()`.
pub fn check_facts(facts: &ConnFacts) -> Result<(), Fault> {
    if facts.size as usize != core::mem::size_of::<ConnFacts>() {
        return Err(Fault::UnknownCode);
    }
    Ok(())
}

/// The Statement tail, at load: the role is exactly one of carrier or framer and agrees with
/// `composes_over` (empty = carrier); framing and fact bits are known; at least one claim, at most
/// [`MAX_CLAIMS`]; no list is counted with a NULL pointer.
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &TransportTail) -> Result<(), Fault> {
    let carrier = t.role == ROLE_CARRIER;
    let framer = t.role == ROLE_FRAMER;
    if carrier == framer {
        return Err(Fault::NotExactlyOne);
    }
    if carrier != (t.composes_over_len == 0) {
        return Err(Fault::NotExactlyOne);
    }
    if t.framing != FRAMING_STREAM && t.framing != FRAMING_DATAGRAM {
        return Err(Fault::UnknownCode);
    }
    if t.facts & !(FACT_SIGNS_NOTHING_AFTER_AUTH | FACT_DECODES_PAYLOAD) != 0 {
        return Err(Fault::UnknownCode);
    }
    if t.claims_len == 0 {
        return Err(Fault::Missing);
    }
    if t.claims_len as u64 > MAX_CLAIMS {
        return Err(Fault::OverMax);
    }
    listed(t.composes_over, t.composes_over_len)?;
    listed(t.claims, t.claims_len)?;
    listed(t.upgrades_to, t.upgrades_to_len)?;
    listed(t.status_rows, t.status_rows_len)?;
    listed(t.settings, t.settings_len)
}

#[cfg(test)]
#[path = "../tests/transport_check_tests.rs"]
mod tests;
