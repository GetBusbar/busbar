// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ANSWER VALIDATORS (ARCHITECT ruling "answer validators live with the shape"):
//! one pure `check_<op>` per answer, u64 arithmetic, no statics. The dispatcher calls them on every
//! answer and turns an `Err` into FAULT; no host re-implements them.
//!
//! THE RULES:
//!
//! * a needed byte count is at most `u32::MAX` and a needed element count at most its hard max;
//! * FAILED with a non-zero length that fits its capacity is FAULT (it would waste the one re-call);
//! * `on_piece`'s reply bytes stream (`more`), so `emitted` never exceeds `reply_cap`;
//! * an absent span ([`SPAN_ABSENT`]) has `len == 0`; any other span lies inside the arena bytes
//!   written, with checked arithmetic;
//! * an index names an entry of the tail list it indexes; a code or bit is a known one;
//! * exactly one section is the declaring one;
//! * a count above zero with a NULL pointer is FAULT.
//!
//! When any buffer of an answer is reported too small, the answer is a request for the one
//! re-call and its elements are not judged: the plugin wrote nothing that the host reads.

use super::{
    ArriveOut, OnPieceOut, OutField, PlaneSnapshot, PlaneTail, RecordWrite, RefusalOut, Section,
    ServeOut, Span, UnitCount, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL, EMIT_DONE,
    EMIT_TO_FAR_END, INGRESS_ACCEPT_LOOP, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, INGRESS_SUBSCRIPTION, MARK_GATE_REJECTED, PRINCIPAL_OPTIONAL,
    RECORD_DELETE, RECORD_PUT, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED,
    SHAPE_PIECEWISE, SPAN_ABSENT, TAIL_FALLBACK, UNITS_REPORTED,
};
use crate::abi::mechanism::call::Outcome;

/// The most unit counts one answer may carry.
pub const MAX_UNITS: u64 = 64;
/// The most head fields one answer may carry.
pub const MAX_FIELDS: u64 = 1024;
/// The most record writes one answer may carry.
pub const MAX_RECORDS: u64 = 1024;
/// The most claims or admin routes one snapshot may carry.
pub const MAX_ROUTES: u64 = 1024;

const BYTES: u64 = u32::MAX as u64;

/// Why an answer is FAULT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// A needed byte count above `u32::MAX`, or a needed element count above its hard max.
    OverMax,
    /// FAILED with a non-zero length that fits its capacity.
    WastedRecall,
    /// A count above its capacity where the op has no re-call.
    OverCap,
    /// An absent span with a non-zero length.
    SpanNotAbsent,
    /// A span outside the arena bytes written.
    SpanOutOfArena,
    /// An index past the end of the list it indexes.
    IndexOutOfRange,
    /// An unknown bit or code.
    UnknownCode,
    /// An "exactly one of" with none or several.
    NotExactlyOne,
    /// A count above zero with a NULL pointer.
    NullWithCount,
    /// A snapshot for another generation, or of a foreign size.
    WrongSnapshot,
}

/// The capacities the host gave one call, from its `in` (`0` for a buffer the op has none of).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    /// `reply_cap`.
    pub reply: u64,
    /// `units_cap`.
    pub units: u64,
    /// `records_cap`.
    pub records: u64,
    /// `fields_cap`.
    pub fields: u64,
    /// `arena_cap`.
    pub arena: u64,
}

/// The tail's list lengths an answer's indices are judged against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bounds {
    /// `op_classes_len`.
    pub op_classes: u64,
    /// `dialects_len`.
    pub dialects: u64,
    /// `billable_classes_len`.
    pub billable_classes: u64,
    /// `record_kinds_len`.
    pub record_kinds: u64,
}

impl Bounds {
    /// The bounds a tail states.
    #[must_use]
    pub fn of(t: &PlaneTail) -> Self {
        Self {
            op_classes: t.op_classes_len as u64,
            dialects: t.dialects_len as u64,
            billable_classes: t.billable_classes_len as u64,
            record_kinds: t.record_kinds_len as u64,
        }
    }
}

/// One buffer's length: `Ok(true)` = written (fits), `Ok(false)` = a needed size (one re-call).
fn buffer(outcome: Outcome, len: u64, cap: u64, max: u64) -> Result<bool, Fault> {
    if len > max {
        return Err(Fault::OverMax);
    }
    if outcome == Outcome::Failed && len != 0 && len <= cap {
        return Err(Fault::WastedRecall);
    }
    Ok(len <= cap)
}

fn index(i: u32, len: u64) -> Result<(), Fault> {
    if u64::from(i) >= len {
        return Err(Fault::IndexOutOfRange);
    }
    Ok(())
}

fn span(s: Span, arena_len: u64) -> Result<(), Fault> {
    if s.offset == SPAN_ABSENT {
        return if s.len == 0 {
            Ok(())
        } else {
            Err(Fault::SpanNotAbsent)
        };
    }
    let end = u64::from(s.offset)
        .checked_add(u64::from(s.len))
        .ok_or(Fault::SpanOutOfArena)?;
    if end > arena_len {
        return Err(Fault::SpanOutOfArena);
    }
    Ok(())
}

fn first<T>(buf: &[T], len: u64) -> Result<&[T], Fault> {
    let n = usize::try_from(len).map_err(|_| Fault::OverCap)?;
    buf.get(..n).ok_or(Fault::OverCap)
}

fn units(buf: &[UnitCount], len: u64, b: &Bounds) -> Result<(), Fault> {
    for u in first(buf, len)? {
        index(u.class, b.billable_classes)?;
        if u.source > UNITS_REPORTED {
            return Err(Fault::UnknownCode);
        }
    }
    Ok(())
}

fn fields(buf: &[OutField], len: u64, arena_len: u64) -> Result<(), Fault> {
    for f in first(buf, len)? {
        span(f.name, arena_len)?;
        span(f.value, arena_len)?;
    }
    Ok(())
}

fn records(buf: &[RecordWrite], len: u64, arena_len: u64, b: &Bounds) -> Result<(), Fault> {
    for r in first(buf, len)? {
        index(r.kind, b.record_kinds)?;
        if r.op != RECORD_PUT && r.op != RECORD_DELETE {
            return Err(Fault::UnknownCode);
        }
        span(r.key, arena_len)?;
        span(r.value, arena_len)?;
    }
    Ok(())
}

/// `arrive`: the indices name tail entries, the principal need is known, the expected units fit
/// `units_cap` (or are a needed count) and name billable classes.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_arrive(
    outcome: Outcome,
    out: &ArriveOut,
    units_buf: &[UnitCount],
    units_cap: u64,
    b: &Bounds,
) -> Result<(), Fault> {
    let written = buffer(outcome, u64::from(out.units_len), units_cap, MAX_UNITS)?;
    if outcome != Outcome::Ready {
        return Ok(());
    }
    if out.principal_need > PRINCIPAL_OPTIONAL {
        return Err(Fault::UnknownCode);
    }
    index(out.op_class, b.op_classes)?;
    index(out.dialect, b.dialects)?;
    if written {
        units(units_buf, u64::from(out.units_len), b)?;
    }
    Ok(())
}

/// `on_piece`: `emitted` within `reply_cap` (the reply is pushed piecewise: a full buffer is `more`), `more`
/// and the flags known, every other buffer written or a needed size, and — when all were written —
/// every unit, field and record write valid against the tail and the arena.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_on_piece(
    outcome: Outcome,
    out: &OnPieceOut,
    bufs: (&[UnitCount], &[RecordWrite], &[OutField]),
    caps: &Caps,
    b: &Bounds,
) -> Result<(), Fault> {
    if out.emitted > caps.reply {
        return Err(Fault::OverCap);
    }
    if out.more > 1 || out.flags & !(EMIT_TO_FAR_END | EMIT_DONE) != 0 {
        return Err(Fault::UnknownCode);
    }
    if outcome == Outcome::Failed && out.emitted != 0 {
        return Err(Fault::WastedRecall);
    }
    let u = buffer(outcome, u64::from(out.units_len), caps.units, MAX_UNITS)?;
    let r = buffer(
        outcome,
        u64::from(out.records_len),
        caps.records,
        MAX_RECORDS,
    )?;
    let f = buffer(outcome, u64::from(out.fields_len), caps.fields, MAX_FIELDS)?;
    let a = buffer(outcome, out.arena_len, caps.arena, BYTES)?;
    if !(u && r && f && a) || outcome != Outcome::Ready {
        return Ok(());
    }
    units(bufs.0, u64::from(out.units_len), b)?;
    records(bufs.1, u64::from(out.records_len), out.arena_len, b)?;
    fields(bufs.2, u64::from(out.fields_len), out.arena_len)
}

/// `refusal` and `serve` share their reply: body, fields and arena, each written or a needed size.
fn reply(
    outcome: Outcome,
    emitted: u64,
    fields_len: u32,
    arena_len: u64,
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    let e = buffer(outcome, emitted, caps.reply, BYTES)?;
    let f = buffer(outcome, u64::from(fields_len), caps.fields, MAX_FIELDS)?;
    let a = buffer(outcome, arena_len, caps.arena, BYTES)?;
    if !(e && f && a) || outcome != Outcome::Ready {
        return Ok(());
    }
    fields(fields_buf, u64::from(fields_len), arena_len)
}

/// `refusal`: the marker is `0` or [`MARK_GATE_REJECTED`]; the reply is valid.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_refusal(
    outcome: Outcome,
    out: &RefusalOut,
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    if out.marker != 0 && out.marker != MARK_GATE_REJECTED {
        return Err(Fault::UnknownCode);
    }
    reply(
        outcome,
        out.emitted,
        out.fields_len,
        out.arena_len,
        fields_buf,
        caps,
    )
}

/// `serve`: the reply is valid.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_serve(
    outcome: Outcome,
    out: &ServeOut,
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    reply(
        outcome,
        out.emitted,
        out.fields_len,
        out.arena_len,
        fields_buf,
        caps,
    )
}

/// The lifecycle `cancel`'s disposition: one of the plane's three.
///
/// # Errors
///
/// [`Fault::UnknownCode`] for any other number, `0` (unwritten) included.
pub const fn check_cancel(disposition: u32) -> Result<(), Fault> {
    match disposition {
        CANCEL_OK_PARTIAL | CANCEL_FAILED | CANCEL_ABORTED => Ok(()),
        _ => Err(Fault::UnknownCode),
    }
}

/// A generation snapshot (`open`/`refresh`): its own size, the generation asked for, lists within
/// [`MAX_ROUTES`] and never counted with a NULL pointer.
///
/// # Errors
///
/// The rule the snapshot breaks.
pub fn check_snapshot(s: &PlaneSnapshot, generation: u64) -> Result<(), Fault> {
    if s.size as usize != core::mem::size_of::<PlaneSnapshot>() || s.generation != generation {
        return Err(Fault::WrongSnapshot);
    }
    if s.claims_len as u64 > MAX_ROUTES || s.admin_routes_len as u64 > MAX_ROUTES {
        return Err(Fault::OverMax);
    }
    if (s.claims_len > 0 && s.claims.is_null())
        || (s.admin_routes_len > 0 && s.admin_routes.is_null())
        || (s.openapi.len > 0 && s.openapi.ptr.is_null())
    {
        return Err(Fault::NullWithCount);
    }
    Ok(())
}

/// The Statement tail, at load: known flags, ingress bits and dispatch shape; at least one ingress
/// shape; no list counted with a NULL pointer.
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &PlaneTail) -> Result<(), Fault> {
    let ingress = INGRESS_REQUEST_RESPONSE
        | INGRESS_RESPONSE_STREAM
        | INGRESS_DUPLEX_SESSION
        | INGRESS_SUBSCRIPTION
        | INGRESS_ACCEPT_LOOP;
    if t.flags & !TAIL_FALLBACK != 0
        || t.ingress & !ingress != 0
        || t.ingress == 0
        || t.dispatch_shape > SHAPE_PIECEWISE
    {
        return Err(Fault::UnknownCode);
    }
    let lists: [(bool, usize); 11] = [
        (t.sections.is_null(), t.sections_len),
        (t.dialects.is_null(), t.dialects_len),
        (t.dialect_auth.is_null(), t.dialect_auth_len),
        (t.scope_kinds.is_null(), t.scope_kinds_len),
        (t.op_classes.is_null(), t.op_classes_len),
        (t.billable_classes.is_null(), t.billable_classes_len),
        (t.route_cost.is_null(), t.route_cost_len),
        (t.fee_units.is_null(), t.fee_units_len),
        (t.record_kinds.is_null(), t.record_kinds_len),
        (t.needs.is_null(), t.needs_len),
        (t.egress_targets.is_null(), t.egress_targets_len),
    ];
    if lists.iter().any(|&(null, len)| null && len > 0) {
        return Err(Fault::NullWithCount);
    }
    Ok(())
}

/// The tail's sections: known flags, and EXACTLY ONE is the declaring section.
///
/// # Errors
///
/// The rule the sections break.
pub fn check_sections(sections: &[Section]) -> Result<(), Fault> {
    let known = SECTION_DECLARING | SECTION_REQUIRED | SECTION_CONSUMED;
    if sections.iter().any(|s| s.flags & !known != 0) {
        return Err(Fault::UnknownCode);
    }
    let declaring = sections
        .iter()
        .filter(|s| s.flags & SECTION_DECLARING != 0)
        .count();
    if declaring != 1 {
        return Err(Fault::NotExactlyOne);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/plane_check_tests.rs"]
mod tests;
