// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ANSWER VALIDATORS (ARCHITECT rulings "answer validators live with the shape",
//! M-SB, P1, P3, P4): one pure `check_<op>` per answer, built from the shared helpers in
//! [`crate::abi::mechanism::check`]. The dispatcher turns an `Err` into FAULT.
//!
//! * Every host buffer follows M-SB: READY has `needed == 0`, `written <= cap`. A multi-buffer answer
//!   (`on_piece`, `refusal`, `serve`) is ONE short answer under the M-SB refinement: FAILED, every
//!   `needed` at its full size, at least one above its cap, nothing written or emitted.
//! * `on_piece`'s reply bytes are backpressure, never short: `emitted <= reply_cap`; `more = 1`
//!   needs at least one byte emitted and never comes with [`EMIT_DONE`] (P4).
//! * What was written is judged on EVERY outcome (P4): no early return skips a unit, record or
//!   field.
//! * The tail and every list element it names are checked at load (P3).

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::{
    AdminRoute, ArriveOut, BillableClass, Claim, DialectAuth, OnPieceOut, OutField, PlaneSnapshot,
    PlaneTail, RecordWrite, RefusalOut, RouteCost, Section, ServeOut, UnitCount, CANCEL_ABORTED,
    CANCEL_OK_PARTIAL, EMIT_DONE, EMIT_TO_FAR_END, INGRESS_ACCEPT_LOOP, INGRESS_DUPLEX_SESSION,
    INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, INGRESS_SUBSCRIPTION, MARK_GATE_REJECTED,
    PRINCIPAL_OPTIONAL, RECORD_DELETE, RECORD_PUT, SECTION_CONSUMED, SECTION_DECLARING,
    SECTION_REQUIRED, SHAPE_PIECEWISE, SHAPE_WHOLE, TAIL_FALLBACK, UNITS_ESTIMATED, UNITS_REPORTED,
};
use crate::abi::host::conn::connector::{Need, DIRECTION_INBOUND, DIRECTION_OUTBOUND};
use crate::abi::mechanism::call::{AbiStr, Outcome};
use crate::abi::mechanism::check::{
    bits, code, fault, first, index, listed, result, results, span, weight, Dim, Filled, MAX_BYTES,
};

/// The most unit counts one answer may carry.
pub const MAX_UNITS: u64 = 64;
/// The most head fields one answer may carry.
pub const MAX_FIELDS: u64 = 1024;
/// The most record writes one answer may carry.
pub const MAX_RECORDS: u64 = 1024;
/// The most claims or admin routes one snapshot may carry.
pub const MAX_ROUTES: u64 = 1024;

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

fn text(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    listed(s.ptr, s.len, field)
}

fn named(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    if s.len == 0 {
        return Err(fault(Rule::Missing, field));
    }
    text(s, field)
}

fn units(buf: &[UnitCount], n: u64, b: &Bounds) -> Result<(), Fault> {
    for u in first(buf, n, "unit")? {
        index(u.class, b.billable_classes, "unit.class")?;
        code(
            u64::from(u.source),
            u64::from(UNITS_ESTIMATED),
            u64::from(UNITS_REPORTED),
            "unit.source",
        )?;
    }
    Ok(())
}

fn fields(buf: &[OutField], n: u64, arena: u64) -> Result<(), Fault> {
    for f in first(buf, n, "field")? {
        span(f.name.offset, f.name.len, arena, "field.name")?;
        span(f.value.offset, f.value.len, arena, "field.value")?;
    }
    Ok(())
}

fn records(buf: &[RecordWrite], n: u64, arena: u64, b: &Bounds) -> Result<(), Fault> {
    for r in first(buf, n, "record")? {
        index(r.kind, b.record_kinds, "record.kind")?;
        code(
            u64::from(r.op),
            u64::from(RECORD_PUT),
            u64::from(RECORD_DELETE),
            "record.op",
        )?;
        span(r.key.offset, r.key.len, arena, "record.key")?;
        span(r.value.offset, r.value.len, arena, "record.value")?;
    }
    Ok(())
}

/// `arrive`: the expected units under M-SB and valid against the tail; on READY the indices name
/// tail entries and the principal need is known.
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
    let written = u64::from(out.units_written);
    result(
        outcome,
        written,
        u64::from(out.units_needed),
        units_cap,
        MAX_UNITS,
        "arrive.units",
    )?;
    units(units_buf, written, b)?;
    if outcome == Outcome::Ready {
        code(
            u64::from(out.principal_need),
            0,
            u64::from(PRINCIPAL_OPTIONAL),
            "arrive.principal_need",
        )?;
        index(out.op_class, b.op_classes, "arrive.op_class")?;
        index(out.dialect, b.dialects, "arrive.dialect")?;
    }
    Ok(())
}

/// `on_piece`: backpressure rules for the reply (P4), M-SB for every other buffer, a short answer
/// emits nothing, and every unit, record and field written is judged on any outcome.
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
        return Err(fault(Rule::OverCap, "on_piece.emitted"));
    }
    code(u64::from(out.more), 0, 1, "on_piece.more")?;
    bits(
        u64::from(out.flags),
        u64::from(EMIT_TO_FAR_END | EMIT_DONE),
        "on_piece.flags",
    )?;
    if out.more == 1 && out.emitted == 0 {
        return Err(fault(Rule::Contradiction, "on_piece.more_without_emitted"));
    }
    if out.more == 1 && out.flags & EMIT_DONE != 0 {
        return Err(fault(Rule::Contradiction, "on_piece.more_with_done"));
    }
    let dims = [
        Dim {
            written: u64::from(out.units_written),
            needed: u64::from(out.units_needed),
            cap: caps.units,
            max: MAX_UNITS,
            field: "on_piece.units",
        },
        Dim {
            written: u64::from(out.records_written),
            needed: u64::from(out.records_needed),
            cap: caps.records,
            max: MAX_RECORDS,
            field: "on_piece.records",
        },
        Dim {
            written: u64::from(out.fields_written),
            needed: u64::from(out.fields_needed),
            cap: caps.fields,
            max: MAX_FIELDS,
            field: "on_piece.fields",
        },
        Dim {
            written: out.arena_written,
            needed: out.arena_needed,
            cap: caps.arena,
            max: MAX_BYTES,
            field: "on_piece.arena",
        },
    ];
    if results(outcome, "on_piece", &dims)? == Filled::Short && out.emitted != 0 {
        return Err(fault(Rule::WrittenOnShort, "on_piece"));
    }
    units(bufs.0, u64::from(out.units_written), b)?;
    records(bufs.1, u64::from(out.records_written), out.arena_written, b)?;
    fields(bufs.2, u64::from(out.fields_written), out.arena_written)
}

/// `refusal`'s and `serve`'s shared reply: body, fields and arena under M-SB; a short answer writes
/// nothing; every field written is judged.
fn reply(
    outcome: Outcome,
    op: [&'static str; 4],
    reply: (u64, u64),
    fields_wn: (u32, u32),
    arena: (u64, u64),
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    let dims = [
        Dim {
            written: reply.0,
            needed: reply.1,
            cap: caps.reply,
            max: MAX_BYTES,
            field: op[0],
        },
        Dim {
            written: u64::from(fields_wn.0),
            needed: u64::from(fields_wn.1),
            cap: caps.fields,
            max: MAX_FIELDS,
            field: op[1],
        },
        Dim {
            written: arena.0,
            needed: arena.1,
            cap: caps.arena,
            max: MAX_BYTES,
            field: op[2],
        },
    ];
    results(outcome, op[3], &dims)?;
    fields(fields_buf, u64::from(fields_wn.0), arena.0)
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
    code(
        u64::from(out.marker),
        0,
        u64::from(MARK_GATE_REJECTED),
        "refusal.marker",
    )?;
    reply(
        outcome,
        [
            "refusal.reply",
            "refusal.fields",
            "refusal.arena",
            "refusal",
        ],
        (out.reply_written, out.reply_needed),
        (out.fields_written, out.fields_needed),
        (out.arena_written, out.arena_needed),
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
        ["serve.reply", "serve.fields", "serve.arena", "serve"],
        (out.reply_written, out.reply_needed),
        (out.fields_written, out.fields_needed),
        (out.arena_written, out.arena_needed),
        fields_buf,
        caps,
    )
}

/// The lifecycle `cancel`'s disposition: one of the plane's three (`0` = unwritten).
///
/// # Errors
///
/// [`Rule::UnknownCode`].
pub const fn check_cancel(disposition: u32) -> Result<(), Fault> {
    code(
        disposition as u64,
        CANCEL_OK_PARTIAL as u64,
        CANCEL_ABORTED as u64,
        "cancel.disposition",
    )
}

/// A generation snapshot (`open`/`refresh`): its own size, the generation asked for, lists within
/// [`MAX_ROUTES`] and never counted with a NULL pointer. Its elements: [`check_claims`],
/// [`check_admin_routes`].
///
/// # Errors
///
/// The rule the snapshot breaks.
pub fn check_snapshot(s: &PlaneSnapshot, generation: u64) -> Result<(), Fault> {
    if s.size as usize != core::mem::size_of::<PlaneSnapshot>() {
        return Err(fault(Rule::Foreign, "snapshot.size"));
    }
    if s.generation != generation {
        return Err(fault(Rule::Foreign, "snapshot.generation"));
    }
    if s.claims_len as u64 > MAX_ROUTES {
        return Err(fault(Rule::OverMax, "snapshot.claims"));
    }
    if s.admin_routes_len as u64 > MAX_ROUTES {
        return Err(fault(Rule::OverMax, "snapshot.admin_routes"));
    }
    listed(s.claims, s.claims_len, "snapshot.claims")?;
    listed(s.admin_routes, s.admin_routes_len, "snapshot.admin_routes")?;
    listed(s.openapi.ptr, s.openapi.len, "snapshot.openapi")?;
    text(s.audience, "snapshot.audience")?;
    text(s.resource_metadata, "snapshot.resource_metadata")
}

/// Every snapshot claim: a verb, a target and a carrier.
///
/// # Errors
///
/// The rule a claim breaks.
pub fn check_claims(claims: &[Claim]) -> Result<(), Fault> {
    for c in claims {
        named(c.verb, "claim.verb")?;
        named(c.target, "claim.target")?;
        named(c.carrier, "claim.carrier")?;
    }
    Ok(())
}

/// Every snapshot admin route: a verb and a target.
///
/// # Errors
///
/// The rule a route breaks.
pub fn check_admin_routes(routes: &[AdminRoute]) -> Result<(), Fault> {
    for r in routes {
        named(r.verb, "admin_route.verb")?;
        named(r.target, "admin_route.target")?;
    }
    Ok(())
}

/// The Statement tail, at load: known flags, ingress bits and dispatch shape; at least one ingress
/// shape; no string or list counted with a NULL pointer. Its elements: [`check_sections`],
/// [`check_dialect_auth`], [`check_route_cost`], [`check_billable_classes`], [`check_needs`].
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &PlaneTail) -> Result<(), Fault> {
    bits(u64::from(t.flags), u64::from(TAIL_FALLBACK), "tail.flags")?;
    let ingress = INGRESS_REQUEST_RESPONSE
        | INGRESS_RESPONSE_STREAM
        | INGRESS_DUPLEX_SESSION
        | INGRESS_SUBSCRIPTION
        | INGRESS_ACCEPT_LOOP;
    bits(u64::from(t.ingress), u64::from(ingress), "tail.ingress")?;
    if t.ingress == 0 {
        return Err(fault(Rule::Missing, "tail.ingress"));
    }
    code(
        u64::from(t.dispatch_shape),
        u64::from(SHAPE_WHOLE),
        u64::from(SHAPE_PIECEWISE),
        "tail.dispatch_shape",
    )?;
    for (s, field) in [
        (t.scope, "tail.scope"),
        (t.label, "tail.label"),
        (t.subject_noun, "tail.subject_noun"),
        (t.admin_noun, "tail.admin_noun"),
        (t.audit_kind, "tail.audit_kind"),
        (t.signing_domain, "tail.signing_domain"),
        (t.signing_kid_prefix, "tail.signing_kid_prefix"),
        (t.cli_help, "tail.cli_help"),
    ] {
        text(s, field)?;
    }
    listed(t.sections, t.sections_len, "tail.sections")?;
    listed(t.dialects, t.dialects_len, "tail.dialects")?;
    listed(t.dialect_auth, t.dialect_auth_len, "tail.dialect_auth")?;
    listed(t.scope_kinds, t.scope_kinds_len, "tail.scope_kinds")?;
    listed(t.op_classes, t.op_classes_len, "tail.op_classes")?;
    listed(
        t.billable_classes,
        t.billable_classes_len,
        "tail.billable_classes",
    )?;
    listed(t.route_cost, t.route_cost_len, "tail.route_cost")?;
    listed(t.fee_units, t.fee_units_len, "tail.fee_units")?;
    listed(t.record_kinds, t.record_kinds_len, "tail.record_kinds")?;
    listed(t.needs, t.needs_len, "tail.needs")?;
    listed(
        t.egress_targets,
        t.egress_targets_len,
        "tail.egress_targets",
    )
}

/// The tail's sections: each named, known flags, and EXACTLY ONE is the declaring section.
///
/// # Errors
///
/// The rule the sections break.
pub fn check_sections(sections: &[Section]) -> Result<(), Fault> {
    let known = SECTION_DECLARING | SECTION_REQUIRED | SECTION_CONSUMED;
    for s in sections {
        named(s.name, "section.name")?;
        bits(u64::from(s.flags), u64::from(known), "section.flags")?;
    }
    let declaring = sections
        .iter()
        .filter(|s| s.flags & SECTION_DECLARING != 0)
        .count();
    if declaring != 1 {
        return Err(fault(Rule::NotExactlyOne, "section.declaring"));
    }
    Ok(())
}

/// The dialects' default auth styles: each names a dialect and a style.
///
/// # Errors
///
/// The rule an entry breaks.
pub fn check_dialect_auth(entries: &[DialectAuth], dialects_len: u64) -> Result<(), Fault> {
    for d in entries {
        index(d.dialect, dialects_len, "dialect_auth.dialect")?;
        named(d.style, "dialect_auth.style")?;
    }
    Ok(())
}

/// The route cost: each term names a billable class and has a finite, non-negative weight.
///
/// # Errors
///
/// The rule a term breaks.
pub fn check_route_cost(terms: &[RouteCost], billable_classes_len: u64) -> Result<(), Fault> {
    for r in terms {
        index(r.class, billable_classes_len, "route_cost.class")?;
        weight(r.weight, "route_cost.weight")?;
    }
    Ok(())
}

/// The billable classes: each names its class and family.
///
/// # Errors
///
/// The rule an entry breaks.
pub fn check_billable_classes(classes: &[BillableClass]) -> Result<(), Fault> {
    for c in classes {
        named(c.class, "billable_class.class")?;
        named(c.family, "billable_class.family")?;
    }
    Ok(())
}

/// The needs: a known direction and a transport claim; strings and details never counted with a
/// NULL pointer.
///
/// # Errors
///
/// The rule a need breaks.
pub fn check_needs(needs: &[Need]) -> Result<(), Fault> {
    for n in needs {
        code(
            u64::from(n.direction),
            u64::from(DIRECTION_INBOUND),
            u64::from(DIRECTION_OUTBOUND),
            "need.direction",
        )?;
        named(n.transport, "need.transport")?;
        text(n.auth, "need.auth")?;
        text(n.target_from, "need.target_from")?;
        text(n.trust_from, "need.trust_from")?;
        listed(n.details.ptr, n.details.len, "need.details")?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/plane_check_tests.rs"]
mod tests;
