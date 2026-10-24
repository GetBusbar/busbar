// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ANSWER VALIDATORS, which live beside the shapes they judge: one pure `check_<op>` per answer, built from the shared helpers in
//! [`crate::abi::mechanism::check`]. The dispatcher turns an `Err` into FAULT.
//!
//! * Every host buffer follows the short-buffer rule: READY has `needed == 0`, `written <= cap`. A multi-buffer answer
//!   (`on_piece`, `refusal`, `serve`) is ONE short answer under the multi-buffer short-answer rule: FAILED, every
//!   `needed` at its full size, at least one above its cap, nothing written or emitted.
//! * `on_piece`'s reply bytes are backpressure, never short: `emitted <= reply_cap`; `more = 1`
//!   needs at least one byte emitted and never comes with [`EMIT_DONE`].
//! * What was written is judged on EVERY outcome: no early return skips a unit, record or
//!   field.
//! * The tail and every list element it names are checked at load.
//! * An ATTEMPT answer's verb and target come together, go to the far end and lie in the arena; a
//!   verdict is known and rides only a READY answer.
//! * `project`'s view points only into the host's buffers: its strings and body into the arena,
//!   its signals at `signals_buf`, its prompt turns at `messages_buf`; a rewritten body answers
//!   only a call that carried a rewrite.

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::reason_of;
use super::{units_bill, UNITS_FLOOR};
use super::{
    AdminRoute, ArriveOut, BillableClass, CatalogOut, Claim, DialectAuth, OnPieceOut, OutField,
    PinMechanism, PlaneDriveOut, PlaneSnapshot, PlaneTail, ProjectOut, RecordChain, RecordWrite,
    RefusalOut, RefusalStatus, RouteCost, ServeOut, TrustKey, UnitCount, CANCEL_ABORTED,
    CANCEL_OK_PARTIAL, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
    CLAIM_CATALOG, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN, CLAIM_RAW_AFFIX, CLAIM_SIGNED_INGRESS,
    DIALECT_PROVIDER, EMIT_DONE, EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END,
    EMIT_UNWATCH_CATALOGUE, EMIT_WATCH_CATALOGUE, INGRESS_ACCEPT_LOOP, INGRESS_DUPLEX_SESSION,
    INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, INGRESS_SUBSCRIPTION, MAX_METRIC_LANES,
    MAX_REFUSAL_TEXT, MECHANISM_PEER_KEY, MECHANISM_ROOT, PIECE_OUT_TEXT, PIN_FINGERPRINT,
    PRINCIPAL_OPTIONAL, RECORD_AUDIT, RECORD_PUT, REFUSAL_ANY_DIALECT, REFUSED_UNSUPPORTED_ACTION,
    ROUTE_CARRIES_OWN_TOKEN, ROUTE_COUNTED, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_ONCE, ROUTE_POOL,
    ROUTE_PUBLIC, ROUTE_SCOPE, ROUTE_SCOPE_LOCAL, ROUTE_SESSION, ROUTE_STREAM, SHAPE_PIECEWISE,
    SHAPE_WHOLE, TAIL_FALLBACK, TAIL_HOOKS_GATED, TAIL_PROBES, TAIL_REFUSED_PIECE, TAP_FAULT_NONE,
    TRUST_ITEM_APPROVALS, TRUST_PIN, TRUST_PRIVATE_REACH, UNITS_ESTIMATED, VERDICT_HARD,
};
use crate::abi::hook::{
    signal, MessageView, SignalEntry, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM,
    SIGNAL_TAG_BOOL, SIGNAL_TAG_STR, SIGNAL_TAG_U64,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_ABSENT, BLOB_OCTETS, MAX_TEXT};
use crate::abi::mechanism::check::{
    bits, code, fault, first, index, judged, listed, range, result, results, span, text, weight,
    Dim, Filled, MAX_BYTES,
};
use crate::abi::mechanism::door::{
    Section, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS,
};
use crate::grammar::{PathSeg, Selector};

/// The most unit counts one answer may carry.
pub const MAX_UNITS: u64 = 64;
/// The most head fields one answer may carry.
pub const MAX_FIELDS: u64 = 1024;
/// The most record writes one answer may carry.
pub const MAX_RECORDS: u64 = 1024;
/// The most claims or admin routes one snapshot may carry.
pub const MAX_ROUTES: u64 = 1024;
/// The most ready sessions one `drive` answer may name.
pub const MAX_SESSIONS: u64 = 1024;
/// The most signals one `project` answer may carry.
pub const MAX_SIGNALS: u64 = 64;
/// The most prompt turns one `project` answer may carry.
pub const MAX_TURNS: u64 = 65536;

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

fn named(s: AbiStr, field: &'static str) -> Result<(), Fault> {
    if s.len == 0 {
        return Err(fault(Rule::Missing, field));
    }
    text(s, field)
}

#[inline(always)]
fn units(buf: &[UnitCount], n: u64, b: &Bounds) -> Result<(), Fault> {
    let counts = judged!(first(buf, n, "unit"));
    // The (class, billing) pairs already seen, for the classes below 64: one bit per class, one
    // mask per billing kind. A class at 64 or above is looked up among the counts before it.
    let (mut seen_billing, mut seen_other) = (0_u64, 0_u64);
    let mut i = 0;
    while i < counts.len() {
        let u = &counts[i];
        judged!(index(u.class, b.billable_classes, "unit.class"));
        judged!(code(
            u.source as u64,
            UNITS_ESTIMATED as u64,
            UNITS_FLOOR as u64,
            "unit.source",
        ));
        // ONE CUMULATIVE COUNT per class and source, and ONE BILLING COUNT per class: a second is a
        // contradiction (two running totals of one thing), never a sum the host would have to add
        // and never a choice it would have to make between a reported count and a floor.
        let bill = units_bill(u.source);
        let again = if u.class < 64 {
            let bit = 1_u64 << u.class;
            let seen = if bill {
                &mut seen_billing
            } else {
                &mut seen_other
            };
            let again = *seen & bit != 0;
            *seen |= bit;
            again
        } else {
            let mut j = 0;
            let mut again = false;
            while j < i {
                let p = &counts[j];
                if p.class == u.class && units_bill(p.source) == bill {
                    again = true;
                    break;
                }
                j += 1;
            }
            again
        };
        if again {
            return Err(fault(Rule::Contradiction, "unit.class"));
        }
        i += 1;
    }
    Ok(())
}

#[inline(always)]
fn fields(buf: &[OutField], n: u64, arena: u64) -> Result<(), Fault> {
    let written = judged!(first(buf, n, "field"));
    let mut k = 0;
    while k < written.len() {
        let f = &written[k];
        judged!(span(f.name.offset, f.name.len, arena, "field.name"));
        judged!(span(f.value.offset, f.value.len, arena, "field.value"));
        k += 1;
    }
    Ok(())
}

#[inline(always)]
fn records(buf: &[RecordWrite], n: u64, arena: u64, b: &Bounds) -> Result<(), Fault> {
    for r in judged!(first(buf, n, "record")) {
        match r.op {
            RECORD_PUT => judged!(index(r.kind, b.record_kinds, "record.kind")),
            // The unit's audit row: its outcome where a put names its kind, and an action.
            RECORD_AUDIT => {
                judged!(code(
                    r.kind as u64,
                    super::AUDIT_APPLIED as u64,
                    super::AUDIT_DEGRADED as u64,
                    "record.audit_outcome",
                ));
                if r.key.len == 0 {
                    return Err(fault(Rule::Contradiction, "record.audit_without_action"));
                }
            }
            _ => return Err(fault(Rule::UnknownCode, "record.op")),
        }
        judged!(span(r.key.offset, r.key.len, arena, "record.key"));
        judged!(span(r.value.offset, r.value.len, arena, "record.value"));
    }
    Ok(())
}

/// `arrive`: the expected units under the short-buffer rule and valid against the tail; on READY the indices name
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
    let written = out.units_written as u64;
    judged!(result(
        outcome,
        written,
        out.units_needed as u64,
        units_cap,
        MAX_UNITS,
        "arrive.units",
    ));
    judged!(units(units_buf, written, b));
    // A refusal about an entry (abi/plane "A refused arrival", rule 6) names it, with its class.
    let about_entry = outcome == Outcome::Refused && (out.pool.len != 0 || !out.pool.ptr.is_null());
    if outcome == Outcome::Refused {
        if out.refusal == 0 {
            return Err(fault(Rule::Missing, "arrive.refusal"));
        }
        judged!(code(
            out.refusal_status as u64,
            400,
            if about_entry { 599 } else { 499 },
            "arrive.refusal_status",
        ));
        if out.refusal_flags & !REFUSED_UNSUPPORTED_ACTION != 0 {
            return Err(fault(Rule::UnknownCode, "arrive.refusal_flags"));
        }
    } else if out.refusal != 0 || out.refusal_status != 0 || out.refusal_flags != 0 {
        return Err(fault(Rule::Contradiction, "arrive.refusal"));
    }
    if outcome == Outcome::Ready {
        judged!(code(
            out.principal_need as u64,
            0,
            PRINCIPAL_OPTIONAL as u64,
            "arrive.principal_need",
        ));
        judged!(index(out.op_class, b.op_classes, "arrive.op_class"));
        judged!(index(out.dialect, b.dialects, "arrive.dialect"));
        if out.correlation != 0 && out.cancels != 0 {
            return Err(fault(Rule::Contradiction, "arrive.cancel_with_correlation"));
        }
        judged!(text(out.pool, "arrive.pool"));
        if out.pool.len > MAX_TEXT {
            return Err(fault(Rule::OverMax, "arrive.pool"));
        }
        if !matches!(
            out.route,
            ROUTE_POOL | ROUTE_DIRECT | ROUTE_LOCAL | ROUTE_SCOPE | ROUTE_SCOPE_LOCAL
        ) {
            return Err(fault(Rule::UnknownCode, "arrive.route"));
        }
        if out.route_flags & !(ROUTE_ONCE | ROUTE_SESSION | ROUTE_STREAM | ROUTE_COUNTED) != 0 {
            return Err(fault(Rule::UnknownCode, "arrive.route_flags"));
        }
        // A unit counted as an admitted call is one the plane answers itself.
        if out.route_flags & ROUTE_COUNTED != 0
            && out.route != ROUTE_LOCAL
            && out.route != ROUTE_SCOPE_LOCAL
        {
            return Err(fault(Rule::Contradiction, "arrive.route_flags"));
        }
        judged!(text(out.affinity, "arrive.affinity"));
        if out.affinity.len > MAX_TEXT {
            return Err(fault(Rule::OverMax, "arrive.affinity"));
        }
        // A unit the plane answers itself names no entry (one routed by scope may name its
        // candidates).
        if out.route == ROUTE_LOCAL && (out.pool.len != 0 || !out.pool.ptr.is_null()) {
            return Err(fault(Rule::Contradiction, "arrive.pool"));
        }
    } else if about_entry {
        judged!(index(out.op_class, b.op_classes, "arrive.op_class"));
        judged!(index(out.dialect, b.dialects, "arrive.dialect"));
        judged!(text(out.pool, "arrive.pool"));
        if out.pool.len > MAX_TEXT {
            return Err(fault(Rule::OverMax, "arrive.pool"));
        }
        if out.route != ROUTE_POOL && out.route != ROUTE_DIRECT {
            return Err(fault(Rule::UnknownCode, "arrive.route"));
        }
        if out.route_flags != 0 {
            return Err(fault(Rule::Contradiction, "arrive.route_flags"));
        }
    } else if out.pool.len != 0
        || !out.pool.ptr.is_null()
        || out.route != ROUTE_POOL
        || out.route_flags != 0
    {
        // The pool names where an admitted unit routes: an answer that admits nothing names none.
        return Err(fault(Rule::Contradiction, "arrive.pool"));
    }
    // The sticky key names how an admitted unit routes: an answer that admits nothing states none.
    if outcome != Outcome::Ready && (out.affinity.len != 0 || !out.affinity.ptr.is_null()) {
        return Err(fault(Rule::Contradiction, "arrive.affinity"));
    }
    judged!(trust_facts(outcome, out));
    if outcome == Outcome::Refused {
        judged!(text(out.head.error, "arrive.refusal_text"));
        if out.head.error.len as u64 > MAX_REFUSAL_TEXT {
            return Err(fault(Rule::OverMax, "arrive.refusal_text"));
        }
    }
    Ok(())
}

/// `arrive`'s TRUST FACTS (ARCHITECT 2026-10-06, the kernel's Approve): each a bounded text; a
/// item only with a counterparty, a digest only with an item; and an answer that admits
/// nothing states none.
#[inline(always)]
fn trust_facts(outcome: Outcome, out: &ArriveOut) -> Result<(), Fault> {
    #[inline(always)]
    fn stated(s: AbiStr) -> bool {
        s.len != 0 || !s.ptr.is_null()
    }
    let facts = [
        (out.trust_counterparty, "arrive.trust_counterparty"),
        (out.trust_item, "arrive.trust_item"),
        (out.trust_digest, "arrive.trust_digest"),
    ];
    if outcome != Outcome::Ready {
        if stated(facts[0].0) || stated(facts[1].0) || stated(facts[2].0) {
            return Err(fault(Rule::Contradiction, "arrive.trust"));
        }
        return Ok(());
    }
    let mut k = 0;
    while k < facts.len() {
        let (s, field) = facts[k];
        judged!(text(s, field));
        if s.len > MAX_TEXT {
            return Err(fault(Rule::OverMax, field));
        }
        k += 1;
    }
    if stated(out.trust_item) && out.trust_counterparty.len == 0 {
        return Err(fault(Rule::Contradiction, "arrive.trust_item"));
    }
    if stated(out.trust_digest) && out.trust_item.len == 0 {
        return Err(fault(Rule::Contradiction, "arrive.trust_digest"));
    }
    Ok(())
}

/// A PIECE'S FLAGS, as the kernel hands them to `on_piece`: [`super::PIECE_CUT`] only on the far
/// end's last piece, and [`super::PIECE_FINAL`] only on the far end's first piece (the one carrying
/// its status). The kernel holds every piece it pushes to this; a plane that reads either bit holds
/// the piece it is given to it and faults one that breaks it.
///
/// # Errors
///
/// The rule the flags break.
pub fn check_piece_in(from: u32, flags: u32) -> Result<(), Fault> {
    use super::{FROM_FAR_END, PIECE_CUT, PIECE_FINAL, PIECE_HAS_STATUS, PIECE_LAST};
    let far = from == FROM_FAR_END;
    if flags & PIECE_CUT != 0 && !(far && flags & PIECE_LAST != 0) {
        return Err(fault(Rule::Contradiction, "on_piece_in.cut"));
    }
    if flags & PIECE_FINAL != 0 && !(far && flags & PIECE_HAS_STATUS != 0) {
        return Err(fault(Rule::Contradiction, "on_piece_in.final"));
    }
    Ok(())
}

/// (`arrive` above: a REFUSED answer names the plane's own refusal code and a 4xx status; any other
/// outcome carries neither.)
///
/// `on_piece`: backpressure rules for the reply, the short-buffer rule for every other buffer, a short answer
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
    judged!(code(out.more as u64, 0, 1, "on_piece.more"));
    judged!(bits(
        out.flags as u64,
        (EMIT_TO_FAR_END
            | EMIT_DONE
            | EMIT_WATCH_CATALOGUE
            | EMIT_UNWATCH_CATALOGUE
            | PIECE_OUT_TEXT
            | EMIT_MESSAGE_END
            | EMIT_FINAL_STATUS) as u64,
        "on_piece.flags",
    ));
    judged!(final_status(out));
    // A text message is a whole message of at least one byte.
    if out.flags & PIECE_OUT_TEXT != 0 && (out.emitted == 0 || out.more != 0) {
        return Err(fault(Rule::Contradiction, "on_piece.text"));
    }
    if out.flags & EMIT_WATCH_CATALOGUE != 0 && out.flags & EMIT_UNWATCH_CATALOGUE != 0 {
        return Err(fault(Rule::Contradiction, "on_piece.watch_with_unwatch"));
    }
    if out.more == 1 && out.emitted == 0 {
        return Err(fault(Rule::Contradiction, "on_piece.more_without_emitted"));
    }
    if out.more == 1 && out.flags & EMIT_DONE != 0 {
        return Err(fault(Rule::Contradiction, "on_piece.more_with_done"));
    }
    let dims = [
        Dim {
            written: out.units_written as u64,
            needed: out.units_needed as u64,
            cap: caps.units,
            max: MAX_UNITS,
            field: "on_piece.units",
        },
        Dim {
            written: out.records_written as u64,
            needed: out.records_needed as u64,
            cap: caps.records,
            max: MAX_RECORDS,
            field: "on_piece.records",
        },
        Dim {
            written: out.fields_written as u64,
            needed: out.fields_needed as u64,
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
    if judged!(results(outcome, "on_piece", &dims)) == Filled::Short && out.emitted != 0 {
        return Err(fault(Rule::WrittenOnShort, "on_piece"));
    }
    judged!(verdict(outcome, out.verdict));
    judged!(fault_reading(outcome, out));
    judged!(request(out));
    // The unit's ledger lane, where the answer names one: inside the arena written.
    judged!(span(
        out.lane.offset,
        out.lane.len,
        out.arena_written,
        "on_piece.lane",
    ));
    // The attempt's counter labels, where the answer states them: inside the arena written.
    judged!(span(
        out.metric_pool.offset,
        out.metric_pool.len,
        out.arena_written,
        "on_piece.metric_pool",
    ));
    judged!(span(
        out.metric_lane.offset,
        out.metric_lane.len,
        out.arena_written,
        "on_piece.metric_lane",
    ));
    // The member whose wait a refusal answers, where the answer states one: inside the arena
    // written (the kernel judges that it names a member of the unit's pool).
    judged!(span(
        out.wait_member.offset,
        out.wait_member.len,
        out.arena_written,
        "on_piece.wait_member",
    ));
    // The reason a fault reading states, where the answer states one: inside the arena written,
    // and only beside a reading.
    judged!(span(
        out.fault_reason.offset,
        out.fault_reason.len,
        out.arena_written,
        "on_piece.fault_reason",
    ));
    if out.fault_reason.len != 0 && out.fault == crate::abi::transport::FAULT_NONE {
        return Err(fault(Rule::Contradiction, "on_piece.fault_reason_unread"));
    }
    judged!(units(bufs.0, out.units_written as u64, b));
    judged!(records(
        bufs.1,
        out.records_written as u64,
        out.arena_written,
        b
    ));
    fields(bufs.2, out.fields_written as u64, out.arena_written)
}

/// `on_piece`'s message boundary and final status: a boundary ends a message toward the caller,
/// never a request bound for the far end; a final status closes the reply ([`EMIT_DONE`]), its
/// message and details inside the arena written; without it the three fields are zero.
#[inline(always)]
fn final_status(out: &OnPieceOut) -> Result<(), Fault> {
    if out.flags & EMIT_MESSAGE_END != 0 && out.flags & EMIT_TO_FAR_END != 0 {
        return Err(fault(
            Rule::Contradiction,
            "on_piece.message_end_to_far_end",
        ));
    }
    if out.flags & EMIT_FINAL_STATUS == 0 {
        if out.final_status != 0 || out.final_message.len != 0 || out.final_details.len != 0 {
            return Err(fault(
                Rule::Contradiction,
                "on_piece.final_status_unflagged",
            ));
        }
        return Ok(());
    }
    if out.flags & EMIT_DONE == 0 || out.flags & EMIT_TO_FAR_END != 0 {
        return Err(fault(
            Rule::Contradiction,
            "on_piece.final_status_not_closing",
        ));
    }
    judged!(span(
        out.final_message.offset,
        out.final_message.len,
        out.arena_written,
        "on_piece.final_message",
    ));
    span(
        out.final_details.offset,
        out.final_details.len,
        out.arena_written,
        "on_piece.final_details",
    )
}

/// `on_piece`'s verdict: a known `VERDICT_*`, and none on an answer that is not READY.
#[inline(always)]
fn verdict(outcome: Outcome, v: u32) -> Result<(), Fault> {
    judged!(code(v as u64, 0, VERDICT_HARD as u64, "on_piece.verdict"));
    if v != 0 && outcome != Outcome::Ready {
        return Err(fault(Rule::Contradiction, "on_piece.verdict_not_ready"));
    }
    Ok(())
}

/// `on_piece`'s breaker fault reading: a known `FAULT_*` (the transport kind's one vocabulary), none
/// on an answer that is not READY, and its padding zero. Its usage-tap fault rides only a READY
/// answer; any value is admitted there, because the kernel counts a value outside the `TAP_FAULT_*`
/// vocabulary as `unknown` rather than refusing the answer it rides.
#[inline(always)]
fn fault_reading(outcome: Outcome, out: &OnPieceOut) -> Result<(), Fault> {
    use crate::abi::transport::{FAULT_HEALTHY, FAULT_NONE};
    judged!(code(
        out.fault as u64,
        0,
        FAULT_HEALTHY as u64,
        "on_piece.fault",
    ));
    if out.fault != FAULT_NONE && outcome != Outcome::Ready {
        return Err(fault(Rule::Contradiction, "on_piece.fault_not_ready"));
    }
    if out.tap_fault != TAP_FAULT_NONE && outcome != Outcome::Ready {
        return Err(fault(Rule::Contradiction, "on_piece.tap_fault_not_ready"));
    }
    if out._fault_reserved != [0; 2] {
        return Err(fault(Rule::Contradiction, "on_piece.fault_reserved"));
    }
    Ok(())
}

/// `on_piece`'s request for the far end: verb and target in the arena, both or neither, and only
/// on an answer that emits to the far end.
#[inline(always)]
fn request(out: &OnPieceOut) -> Result<(), Fault> {
    judged!(span(
        out.verb.offset,
        out.verb.len,
        out.arena_written,
        "on_piece.verb",
    ));
    judged!(span(
        out.target.offset,
        out.target.len,
        out.arena_written,
        "on_piece.target",
    ));
    let (verb, target) = (out.verb.len != 0, out.target.len != 0);
    if verb != target {
        return Err(fault(Rule::Contradiction, "on_piece.verb_without_target"));
    }
    if verb && out.flags & EMIT_TO_FAR_END == 0 {
        return Err(fault(
            Rule::Contradiction,
            "on_piece.request_not_to_far_end",
        ));
    }
    // The need a far request rides names a request bound for the far end, nothing else.
    if out.need != 0 && out.flags & EMIT_TO_FAR_END == 0 {
        return Err(fault(Rule::Contradiction, "on_piece.need_not_to_far_end"));
    }
    Ok(())
}

/// A string the plugin wrote into the host arena: empty, or inside the first `written` bytes that
/// start at `arena`; checked arithmetic.
#[inline(always)]
fn in_arena(s: AbiStr, arena: *const u8, written: u64, field: &'static str) -> Result<(), Fault> {
    if s.len == 0 {
        return Ok(());
    }
    let (at, base) = (s.ptr.addr(), arena.addr());
    if at < base {
        return Err(fault(Rule::SpanOutOfBounds, field));
    }
    let offset = at - base;
    range(offset as u64, s.len as u64, written, field)
}

/// `project`'s session ([`RequestView::session`](crate::abi::hook::RequestView::session)): absent
/// (a NULL, empty [`BLOB_ABSENT`] blob), or [`BLOB_OCTETS`] with no flag, inside the arena written.
#[inline(always)]
fn session(b: Blob, arena: *const u8, written: u64) -> Result<(), Fault> {
    const FIELD: &str = "project.view.session";
    if b.fmt == BLOB_ABSENT {
        return if b.ptr.is_null() && b.len == 0 && b.flags == 0 {
            Ok(())
        } else {
            Err(fault(Rule::Contradiction, FIELD))
        };
    }
    if b.fmt != BLOB_OCTETS || b.flags != 0 {
        return Err(fault(Rule::UnknownCode, FIELD));
    }
    if b.ptr.is_null() {
        return Err(fault(Rule::NullWithCount, FIELD));
    }
    let (at, base) = (b.ptr.addr(), arena.addr());
    if at < base {
        return Err(fault(Rule::SpanOutOfBounds, FIELD));
    }
    let offset = at - base;
    range(offset as u64, b.len as u64, written, FIELD)
}

/// The host buffers one `project` call lent, as its validator reads them.
#[derive(Debug, Clone, Copy)]
pub struct ProjectHost<'a> {
    /// The host's `signals_buf`, holding at least the signals written.
    pub signals: &'a [SignalEntry],
    /// `signals_cap`.
    pub signals_cap: u64,
    /// The host's `messages_buf`, holding at least the turns written.
    pub messages: &'a [MessageView],
    /// `messages_cap`.
    pub messages_cap: u64,
    /// The host's `arena_buf` and `arena_cap`.
    pub arena: (*const u8, u64),
    /// The call carried a rewrite ([`super::ProjectIn::rewrite`] present).
    pub rewrite: bool,
}

/// `project`: the signals, the prompt turns and the arena under the multi-buffer short-answer
/// rule; the view's signals are the host's `signals_buf` and its prompt turns the host's
/// `messages_buf`, its known flags, its strings (the view's, the prompt's, every turn's and the
/// end user) and the projected and rewritten bodies inside the arena written, a rewritten body only
/// for a call that carried a rewrite, no prompt body (the kernel lends the body itself), and every
/// signal written a known id and tag whose value is valid.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_project(
    outcome: Outcome,
    out: &ProjectOut,
    host: &ProjectHost<'_>,
) -> Result<(), Fault> {
    let v = &out.view;
    let p = &out.prompt;
    let (signals, arena) = (host.signals, host.arena);
    let written = v.signals_len as u64;
    let dims = [
        Dim {
            written,
            needed: out.signals_needed as u64,
            cap: host.signals_cap,
            max: MAX_SIGNALS,
            field: "project.signals",
        },
        Dim {
            written: p.message_count,
            needed: out.messages_needed as u64,
            cap: host.messages_cap,
            max: MAX_TURNS,
            field: "project.messages",
        },
        Dim {
            written: out.arena_written,
            needed: out.arena_needed,
            cap: arena.1,
            max: MAX_BYTES,
            field: "project.arena",
        },
    ];
    judged!(results(outcome, "project", &dims));
    if written != 0 && !core::ptr::eq(v.signals, signals.as_ptr()) {
        return Err(fault(Rule::Foreign, "project.view.signals"));
    }
    if p.message_count != 0 && !core::ptr::eq(p.messages, host.messages.as_ptr()) {
        return Err(fault(Rule::Foreign, "project.prompt.messages"));
    }
    if p.messages_len as u64 != p.message_count {
        return Err(fault(Rule::Contradiction, "project.prompt.messages_len"));
    }
    if p.body.len != 0 || !p.body.ptr.is_null() {
        return Err(fault(Rule::Foreign, "project.prompt.body"));
    }
    judged!(bits(
        v.flags as u64,
        (REQUEST_HAS_MAX_TOKENS | REQUEST_HAS_TOOLS | REQUEST_STREAM) as u64,
        "project.view.flags",
    ));
    judged!(in_arena(
        v.pool,
        arena.0,
        out.arena_written,
        "project.view.pool"
    ));
    judged!(in_arena(
        v.ingress_dialect,
        arena.0,
        out.arena_written,
        "project.view.ingress_dialect",
    ));
    judged!(in_arena(
        p.system,
        arena.0,
        out.arena_written,
        "project.prompt.system",
    ));
    judged!(in_arena(
        out.end_user,
        arena.0,
        out.arena_written,
        "project.end_user"
    ));
    judged!(session(v.session, arena.0, out.arena_written));
    judged!(span(
        out.body.offset,
        out.body.len,
        out.arena_written,
        "project.body",
    ));
    judged!(span(
        out.rewritten.offset,
        out.rewritten.len,
        out.arena_written,
        "project.rewritten",
    ));
    if out.rewritten.len != 0 && !host.rewrite {
        return Err(fault(
            Rule::Contradiction,
            "project.rewritten_without_rewrite",
        ));
    }
    for m in judged!(first(host.messages, p.message_count, "project.messages")) {
        judged!(in_arena(
            m.role,
            arena.0,
            out.arena_written,
            "project.message.role"
        ));
        judged!(in_arena(
            m.text,
            arena.0,
            out.arena_written,
            "project.message.text"
        ));
    }
    for e in judged!(first(signals, written, "project.signals")) {
        judged!(code(
            e.id as u64,
            0,
            signal::RESPONSE_TOKENS_OUT as u64,
            "project.signal.id",
        ));
        judged!(code(
            e.tag as u64,
            SIGNAL_TAG_U64 as u64,
            SIGNAL_TAG_BOOL as u64,
            "project.signal.tag",
        ));
        if e.tag == SIGNAL_TAG_STR {
            // SAFETY: the tag names `str_` live; every bit pattern of an `AbiStr` is a valid value.
            let s = unsafe { e.value.str_ };
            judged!(in_arena(
                s,
                arena.0,
                out.arena_written,
                "project.signal.value"
            ));
        } else if e.tag == SIGNAL_TAG_BOOL {
            // SAFETY: the tag names `boolean` live; every `u8` is a valid value.
            let b = unsafe { e.value.boolean };
            judged!(code(b as u64, 0, 1, "project.signal.value"));
        }
    }
    Ok(())
}

/// The plane's `drive`: the ready sessions under the short-buffer rule.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_drive(outcome: Outcome, out: &PlaneDriveOut, sessions_cap: u64) -> Result<(), Fault> {
    result(
        outcome,
        u64::from(out.sessions_written),
        u64::from(out.sessions_needed),
        sessions_cap,
        MAX_SESSIONS,
        "drive.sessions",
    )?;
    Ok(())
}

/// `refusal`'s and `serve`'s shared reply: body, fields and arena under the short-buffer rule; a short answer writes
/// nothing; every field written is judged.
#[inline(always)]
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
            written: fields_wn.0 as u64,
            needed: fields_wn.1 as u64,
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
    judged!(results(outcome, op[3], &dims));
    fields(fields_buf, fields_wn.0 as u64, arena.0)
}

/// `refusal`: the marker is `0` (the kernel sets [`super::MARK_GATE_REJECTED`], never a
/// plane); the reply is valid.
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
    judged!(code(out.marker as u64, 0, 0, "refusal.marker"));
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

/// `refusal`'s record writes (SEAM-L(o)): under the short-buffer rule over `records_buf`, each
/// write judged as an `on_piece` answer's, its bytes inside the arena written.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_refusal_records(
    outcome: Outcome,
    out: &RefusalOut,
    records_buf: &[RecordWrite],
    records_cap: u64,
    b: &Bounds,
) -> Result<(), Fault> {
    let n = (out.records_written, out.records_needed, out.arena_written);
    answer_records(outcome, n, records_buf, records_cap, b, "refusal.records")
}

/// `serve`'s record writes (SEAM-L(t)): as a refusal's ([`check_refusal_records`]).
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_serve_records(
    outcome: Outcome,
    out: &ServeOut,
    records_buf: &[RecordWrite],
    records_cap: u64,
    b: &Bounds,
) -> Result<(), Fault> {
    let n = (out.records_written, out.records_needed, out.arena_written);
    answer_records(outcome, n, records_buf, records_cap, b, "serve.records")
}

/// An answer's record writes, `(written, needed, arena written)`: the short-buffer rule over the
/// host's buffer, then each write judged as an `on_piece` answer's.
#[inline(always)]
fn answer_records(
    outcome: Outcome,
    (written, needed, arena): (u32, u32, u64),
    records_buf: &[RecordWrite],
    records_cap: u64,
    b: &Bounds,
    field: &'static str,
) -> Result<(), Fault> {
    let written = written as u64;
    judged!(result(
        outcome,
        written,
        needed as u64,
        records_cap,
        MAX_RECORDS,
        field,
    ));
    records(records_buf, written, arena, b)
}

/// `serve`: a known `AUDIT_*`, and the reply is valid.
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
    judged!(code(
        out.audit as u64,
        0,
        super::AUDIT_REJECTED as u64,
        "serve.audit",
    ));
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

/// `catalog`: the reply is valid.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_catalog(
    outcome: Outcome,
    out: &CatalogOut,
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    judged!(code(out._reserved as u64, 0, 0, "catalog._reserved"));
    reply(
        outcome,
        [
            "catalog.reply",
            "catalog.fields",
            "catalog.arena",
            "catalog",
        ],
        (out.reply_written, out.reply_needed),
        (out.fields_written, out.fields_needed),
        (out.arena_written, out.arena_needed),
        fields_buf,
        caps,
    )
}

/// The lifecycle `cancel`'s disposition: on READY, one of the plane's three (`0` = unwritten is
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
        CANCEL_OK_PARTIAL as u64,
        CANCEL_ABORTED as u64,
        "cancel.disposition",
    )
}

/// `cancel`'s record writes (SEAM-L(r)): `cancel` is never re-called, so the writes and the arena
/// they name fit the host's buffers or the answer is FAULT; each write is judged as an `on_piece`
/// answer's. A `cancel` that is not READY writes nothing.
///
/// # Errors
///
/// The rule the answer breaks.
pub fn check_cancel_records(
    outcome: Outcome,
    out: &super::PlaneCancelOut,
    records_buf: &[RecordWrite],
    (records_cap, arena_cap): (u64, u64),
    b: &Bounds,
) -> Result<(), Fault> {
    let written = u64::from(out.records_written);
    if written > records_cap || written > MAX_RECORDS {
        return Err(fault(Rule::OverCap, "cancel.records"));
    }
    if out.arena_written > arena_cap {
        return Err(fault(Rule::OverCap, "cancel.arena"));
    }
    if outcome != Outcome::Ready && (written != 0 || out.arena_written != 0) {
        return Err(fault(Rule::Contradiction, "cancel.records_not_ready"));
    }
    records(records_buf, written, out.arena_written, b)
}

/// A generation snapshot (`open`/`refresh`): its own size, the generation asked for, lists within
/// [`MAX_ROUTES`] and never counted with a NULL pointer, and arrival spans `0` or one per claim. Its
/// elements: [`check_claims`], [`check_admin_routes`], [`check_listed`], [`check_arrival_spans`].
///
/// The size is this build's, or that of a snapshot published before [`PlaneSnapshot::listed`] or
/// [`PlaneSnapshot::arrival_spans`] was appended (data structs grow by append under `honoured_size`): `s` is then the host's copy
/// of the publisher's own bytes over zeros, so its appended fields read as none.
///
/// # Errors
///
/// The rule the snapshot breaks.
pub fn check_snapshot(s: &PlaneSnapshot, generation: u64) -> Result<(), Fault> {
    let size = s.size as usize;
    if size != core::mem::size_of::<PlaneSnapshot>()
        && size != core::mem::offset_of!(PlaneSnapshot, listed)
        && size != core::mem::offset_of!(PlaneSnapshot, arrival_spans)
    {
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
    text(s.resource_metadata, "snapshot.resource_metadata")?;
    listed(
        s.resource_facts.ptr,
        s.resource_facts.len,
        "snapshot.resource_facts",
    )?;
    if s.listed_len as u64 > MAX_ROUTES {
        return Err(fault(Rule::OverMax, "snapshot.listed"));
    }
    listed(s.listed, s.listed_len, "snapshot.listed")?;
    if s.arrival_spans_len != 0 && s.arrival_spans_len != s.claims_len {
        return Err(fault(Rule::Contradiction, "snapshot.arrival_spans"));
    }
    listed(
        s.arrival_spans,
        s.arrival_spans_len,
        "snapshot.arrival_spans",
    )
}

/// Every arrival span a snapshot states ([`PlaneSnapshot::arrival_spans`]): empty (that claim opens
/// none), or a name of at most [`super::MAX_ARRIVAL_SPAN`] bytes. Its characters (`[a-z0-9_]`) are
/// judged by the host when it copies it.
///
/// # Errors
///
/// The rule a name breaks.
pub fn check_arrival_spans(names: &[AbiStr]) -> Result<(), Fault> {
    for n in names {
        text(*n, "snapshot.arrival_spans")?;
        if n.len > super::MAX_ARRIVAL_SPAN {
            return Err(fault(Rule::OverMax, "snapshot.arrival_spans"));
        }
    }
    Ok(())
}

/// Every name a snapshot lists: non-empty text. Its UTF-8 is judged by the host when it copies it.
///
/// # Errors
///
/// The rule a name breaks.
pub fn check_listed(names: &[AbiStr]) -> Result<(), Fault> {
    for n in names {
        named(*n, "snapshot.listed")?;
    }
    Ok(())
}

/// Every snapshot claim: a verb, a target, a carrier, known flags, never EXACT with PATTERN, and a
/// refusal dialect the tail declares (`0` when the tail declares none). The target's TEXT is judged
/// at bind by [`check_claim_target`], once the host has read it. Two claims of one route are not
/// judged here: overlapping claims resolve by precedence in the kernel's registry.
///
/// # Errors
///
/// The rule a claim breaks.
pub fn check_claims(claims: &[Claim], dialects_len: u64) -> Result<(), Fault> {
    for c in claims {
        named(c.verb, "claim.verb")?;
        named(c.target, "claim.target")?;
        named(c.carrier, "claim.carrier")?;
        bits(
            u64::from(c.flags),
            u64::from(
                CLAIM_OPEN
                    | CLAIM_EXACT
                    | CLAIM_PATTERN
                    | CLAIM_CATALOG
                    | CLAIM_SIGNED_INGRESS
                    | CLAIM_RAW_AFFIX,
            ),
            "claim.flags",
        )?;
        if dialects_len > 0 || c.refusal_dialect != 0 {
            index(
                u32::from(c.refusal_dialect),
                dialects_len,
                "claim.refusal_dialect",
            )?;
        }
        if c.flags & CLAIM_EXACT != 0 && c.flags & CLAIM_PATTERN != 0 {
            return Err(fault(Rule::Contradiction, "claim.flags"));
        }
    }
    Ok(())
}

/// THE PATTERN GRAMMAR, once: the target starts with `/`, and each `/`-separated segment is a
/// brace-free literal or a whole placeholder with a non-empty, brace-free name: `{name}` takes one
/// segment, `{name+}` one or more (it spans the arriving path's own `/`, raw or none; ARCHITECT
/// ruling 2026-10-16, 3b A). A pattern names at least one placeholder, and at most one `{name+}`;
/// one that names none is an exact target.
fn pattern_shape(target: &str) -> Result<(), Fault> {
    let bad = || fault(Rule::Contradiction, "claim.pattern");
    let rest = target.strip_prefix('/').ok_or_else(bad)?;
    let (mut placeholders, mut spans) = (0, 0);
    for seg in rest.split('/') {
        match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(n) if !n.is_empty() && !n.contains(['{', '}']) => {
                placeholders += 1;
                if let Some(name) = n.strip_suffix('+') {
                    if name.is_empty() || name.contains('+') {
                        return Err(bad());
                    }
                    spans += 1;
                }
            }
            None if !seg.is_empty() && !seg.contains(['{', '}']) => {}
            _ => return Err(bad()),
        }
    }
    if placeholders == 0 {
        return Err(fault(Rule::Missing, "claim.pattern"));
    }
    if spans > 1 {
        return Err(fault(Rule::Contradiction, "claim.pattern.spans"));
    }
    Ok(())
}

/// ONE CLAIM'S TARGET, judged at bind once the host has read it out of the snapshot: the flag pair
/// ([`CLAIM_EXACT`] never with [`CLAIM_PATTERN`]) and, for a pattern, its grammar
/// ([`claim_selector`] reads the same one). [`check_claims`] judges the claims' shape without
/// reading their text; the host runs this on every target it copies into the generation.
///
/// # Errors
///
/// [`Rule::Contradiction`] for both flags or a malformed pattern, [`Rule::Missing`] for a pattern
/// with no placeholder.
pub fn check_claim_target(target: &str, flags: u32) -> Result<(), Fault> {
    if flags & CLAIM_EXACT != 0 && flags & CLAIM_PATTERN != 0 {
        return Err(fault(Rule::Contradiction, "claim.flags"));
    }
    // A signed path is read off a raw affix alone, and a raw affix mounts no route, so it lists no
    // catalog (ARCHITECT ruling 2026-10-17).
    if (flags & CLAIM_SIGNED_INGRESS != 0 && flags & CLAIM_RAW_AFFIX == 0)
        || flags & (CLAIM_RAW_AFFIX | CLAIM_CATALOG) == CLAIM_RAW_AFFIX | CLAIM_CATALOG
    {
        return Err(fault(Rule::Contradiction, "claim.flags"));
    }
    if flags & CLAIM_RAW_AFFIX != 0 {
        if flags & (CLAIM_OPEN | CLAIM_EXACT | CLAIM_PATTERN) != 0 {
            return Err(fault(Rule::Contradiction, "claim.flags"));
        }
        raw_affix(target).ok_or_else(|| fault(Rule::Contradiction, "claim.affix"))?;
    }
    if flags & CLAIM_PATTERN != 0 {
        pattern_shape(target)?;
    }
    Ok(())
}

/// A [`CLAIM_RAW_AFFIX`] target's two affixes, `(prefix, suffix)`, or `None` when it is not one:
/// exactly one `*`, a prefix that starts with `/`, and a non-empty suffix.
#[must_use]
pub fn raw_affix(target: &str) -> Option<(&str, &str)> {
    let (prefix, suffix) = target.split_once('*')?;
    (prefix.starts_with('/') && !suffix.is_empty() && !suffix.contains('*'))
        .then_some((prefix, suffix))
}

/// Whether the raw, undecoded request `path` matches the [`CLAIM_RAW_AFFIX`] target `target`: it
/// starts with the prefix and ends with the suffix, as bytes and nothing else. A target that is no
/// raw affix matches nothing.
#[must_use]
pub fn raw_affix_matches(target: &str, path: &str) -> bool {
    raw_affix(target)
        .is_some_and(|(prefix, suffix)| path.starts_with(prefix) && path.ends_with(suffix))
}

/// A [`CLAIM_PATTERN`] target read as its segment pattern, by the one grammar
/// ([`check_claim_target`]): each literal segment is a [`PathSeg::Lit`], each `{name}` one
/// [`PathSeg::Var`] and a `{name+}` one [`PathSeg::Plus`].
///
/// # Errors
///
/// The grammar's fault: [`Rule::Contradiction`] for an empty or half-braced segment,
/// [`Rule::Missing`] for no placeholder.
pub fn claim_pattern(target: &'static str) -> Result<Vec<PathSeg>, Fault> {
    pattern_shape(target)?;
    Ok(target[1..]
        .split('/')
        .map(|seg| {
            if seg.starts_with('{') && seg.ends_with("+}") {
                PathSeg::Plus
            } else if seg.starts_with('{') {
                PathSeg::Var
            } else {
                PathSeg::Lit(seg)
            }
        })
        .collect())
}

/// THE HOST'S READING OF ONE PLANE CLAIM as the claim grammar's selector: [`CLAIM_EXACT`] is
/// [`Selector::ExactPath`], [`CLAIM_PATTERN`] is [`Selector::PathPattern`], and neither is
/// [`Selector::PrefixOneLevel`]. The registry orders and seals the result as it does every claim.
/// A pattern's segments are handed to `keep`, which decides how long they live: the host keeps
/// them with the generation that stated them. The contract holds nothing.
///
/// # Errors
///
/// [`Rule::Contradiction`] for both flags, or the pattern's own fault ([`claim_pattern`]).
pub fn claim_selector(
    target: &'static str,
    flags: u32,
    keep: impl FnOnce(Vec<PathSeg>) -> &'static [PathSeg],
) -> Result<Selector, Fault> {
    match (flags & CLAIM_EXACT != 0, flags & CLAIM_PATTERN != 0) {
        (true, true) => Err(fault(Rule::Contradiction, "claim.flags")),
        (true, false) => Ok(Selector::ExactPath(target)),
        (false, true) => Ok(Selector::PathPattern(keep(claim_pattern(target)?))),
        (false, false) => Ok(Selector::PrefixOneLevel(target)),
    }
}

/// Every snapshot admin route: a verb, a target and known flags; [`ROUTE_CARRIES_OWN_TOKEN`] only
/// beside [`ROUTE_PUBLIC`] (an admin route's `authorization` is the operator's credential, which
/// never crosses).
///
/// # Errors
///
/// The rule a route breaks.
pub fn check_admin_routes(routes: &[AdminRoute]) -> Result<(), Fault> {
    for r in routes {
        named(r.verb, "admin_route.verb")?;
        named(r.target, "admin_route.target")?;
        text(r.audit_verb, "admin_route.audit_verb")?;
        bits(
            u64::from(r.flags),
            u64::from(ROUTE_PUBLIC | ROUTE_CARRIES_OWN_TOKEN),
            "admin_route.flags",
        )?;
        if r.flags & ROUTE_CARRIES_OWN_TOKEN != 0 && r.flags & ROUTE_PUBLIC == 0 {
            return Err(fault(Rule::Contradiction, "admin_route.flags"));
        }
    }
    Ok(())
}

/// The Statement tail, at load: known flags, ingress bits and dispatch shape; at least one ingress
/// shape; no string or list counted with a NULL pointer. Its elements: [`check_sections`],
/// [`check_dialect_auth`], [`check_route_cost`], [`check_billable_classes`], [`check_fee_units`],
/// [`check_needs`], [`check_record_chains`], [`check_trust_keys`] and each pin's
/// [`check_pin_mechanisms`], and
/// [`check_refusal_statuses`].
///
/// # Errors
///
/// The rule the tail breaks.
pub fn check_tail(t: &PlaneTail) -> Result<(), Fault> {
    bits(
        u64::from(t.flags),
        u64::from(TAIL_FALLBACK | TAIL_PROBES | TAIL_HOOKS_GATED | TAIL_REFUSED_PIECE),
        "tail.flags",
    )?;
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
    listed(
        t.egress_targets,
        t.egress_targets_len,
        "tail.egress_targets",
    )?;
    listed(t.record_chains, t.record_chains_len, "tail.record_chains")?;
    listed(t.trust_keys, t.trust_keys_len, "tail.trust_keys")?;
    listed(
        t.refusal_statuses,
        t.refusal_statuses_len,
        "tail.refusal_statuses",
    )?;
    listed(t.admin_routes, t.admin_routes_len, "tail.admin_routes")?;
    listed(t.metric_lanes, t.metric_lanes_len, "tail.metric_lanes")?;
    if t.metric_lanes_len > MAX_METRIC_LANES {
        return Err(fault(Rule::OverMax, "tail.metric_lanes"));
    }
    listed(
        t.admin_openapi.ptr,
        t.admin_openapi.len,
        "tail.admin_openapi",
    )?;
    if t.admin_routes_len as u64 > MAX_ROUTES {
        return Err(fault(Rule::OverMax, "tail.admin_routes"));
    }
    // Absent is NULL; present is a sentence, never an empty one.
    if t.caller_credential_refusal.ptr.is_null() {
        text(
            t.caller_credential_refusal,
            "tail.caller_credential_refusal",
        )
    } else {
        named(
            t.caller_credential_refusal,
            "tail.caller_credential_refusal",
        )
    }
}

/// A plane's Statement sections: each named, known flags, and EXACTLY ONE is the declaring
/// section (the plane's verb).
///
/// # Errors
///
/// The rule the sections break.
pub fn check_sections(sections: &[Section]) -> Result<(), Fault> {
    let known = SECTION_DECLARING | SECTION_REQUIRED | SECTION_CONSUMED | SECTION_SELECTS;
    for s in sections {
        named(s.name, "section.name")?;
        bits(u64::from(s.flags), u64::from(known), "section.flags")?;
        // The verb selects its plane already: the selecting bit beside it is redundant.
        if s.flags & SECTION_DECLARING != 0 && s.flags & SECTION_SELECTS != 0 {
            return Err(fault(Rule::Contradiction, "section.flags"));
        }
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
        bits(
            u64::from(d.flags),
            u64::from(DIALECT_PROVIDER),
            "dialect_auth.flags",
        )?;
        named(d.style, "dialect_auth.style")?;
        crate::abi::mechanism::check::blob(
            &d.params,
            "dialect_auth.params",
            "dialect_auth.params",
        )?;
        if d.params.len > 0 && d.params.fmt != crate::abi::mechanism::call::BLOB_JSON {
            return Err(fault(Rule::Contradiction, "dialect_auth.params.fmt"));
        }
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

/// The fee units: each named and each ALSO one of the tail's billable classes, so the plane
/// reports "a fee unit was incurred" as a `UNITS_REPORTED` count of 0 or 1 on that class
/// (the design's money section: the plane reports whether a fee unit was incurred). A fee unit the
/// classes do not list is [`Rule::Contradiction`]: the plane could never report it.
///
/// # Errors
///
/// The rule a fee unit breaks.
pub fn check_fee_units(fee_units: &[AbiStr], classes: &[BillableClass]) -> Result<(), Fault> {
    const FIELD: &str = "tail.fee_units";
    for f in fee_units {
        named(*f, FIELD)?;
        // SAFETY: `named` checked the string non-NULL with its length; the plugin's static bytes.
        let fee = unsafe { core::slice::from_raw_parts(f.ptr, f.len) };
        let listed = classes.iter().any(|c| {
            c.class.len == fee.len()
                && !c.class.ptr.is_null()
                // SAFETY: a non-NULL class string of its stated length; the plugin's static bytes.
                && unsafe { core::slice::from_raw_parts(c.class.ptr, c.class.len) } == fee
        });
        if !listed {
            return Err(fault(Rule::Contradiction, FIELD));
        }
    }
    Ok(())
}

/// The tail's counter lane words ([`PlaneTail::metric_lanes`]): at most [`MAX_METRIC_LANES`],
/// each named, none twice (a word listed twice is [`Rule::Contradiction`]).
///
/// # Errors
///
/// The rule a word breaks.
pub fn check_metric_lanes(lanes: &[AbiStr]) -> Result<(), Fault> {
    const FIELD: &str = "tail.metric_lanes";
    if lanes.len() > MAX_METRIC_LANES {
        return Err(fault(Rule::OverMax, FIELD));
    }
    let mut seen: Vec<&[u8]> = Vec::with_capacity(lanes.len());
    for l in lanes {
        named(*l, FIELD)?;
        // SAFETY: `named` checked the string non-NULL with its length; the plugin's static bytes.
        let word = unsafe { core::slice::from_raw_parts(l.ptr, l.len) };
        // A label value: UTF-8, no control character (it is rendered into an exposition line).
        if core::str::from_utf8(word).is_err() || word.iter().any(u8::is_ascii_control) {
            return Err(fault(Rule::UnknownCode, FIELD));
        }
        if seen.contains(&word) {
            return Err(fault(Rule::Contradiction, FIELD));
        }
        seen.push(word);
    }
    Ok(())
}

/// The chained record kinds: each names a record kind at most once, with a known framing and
/// known flags.
///
/// # Errors
///
/// The rule an entry breaks.
pub fn check_record_chains(chains: &[RecordChain], record_kinds_len: u64) -> Result<(), Fault> {
    for (i, c) in chains.iter().enumerate() {
        index(c.kind, record_kinds_len, "record_chain.kind")?;
        code(
            u64::from(c.framing),
            u64::from(CHAIN_LENGTH_PREFIXED),
            u64::from(CHAIN_PIPE_SEPARATED),
            "record_chain.framing",
        )?;
        bits(
            u64::from(c.flags),
            u64::from(CHAIN_DIGESTS_SCOPE),
            "record_chain.flags",
        )?;
        if chains[..i].iter().any(|d| d.kind == c.kind) {
            return Err(fault(Rule::Contradiction, "record_chain.kind_twice"));
        }
    }
    Ok(())
}

/// The kernel-owned trust keys: each named, with a known role at most once; a pin names its
/// mechanisms and has no default; a duration key names no mechanism and carries no pin flag.
///
/// # Errors
///
/// The rule a key breaks.
pub fn check_trust_keys(keys: &[TrustKey]) -> Result<(), Fault> {
    for (i, k) in keys.iter().enumerate() {
        named(k.key, "trust_key.key")?;
        code(
            u64::from(k.role),
            u64::from(TRUST_PIN),
            u64::from(TRUST_ITEM_APPROVALS),
            "trust_key.role",
        )?;
        text(k.default, "trust_key.default")?;
        listed(k.mechanisms, k.mechanisms_len, "trust_key.mechanisms")?;
        if k.role == TRUST_PIN {
            bits(
                u64::from(k.flags),
                u64::from(PIN_FINGERPRINT),
                "trust_key.flags",
            )?;
            if k.mechanisms_len == 0 {
                return Err(fault(Rule::Missing, "trust_key.mechanisms"));
            }
            if !k.default.ptr.is_null() {
                return Err(fault(Rule::Contradiction, "trust_key.pin_default"));
            }
        } else {
            bits(u64::from(k.flags), 0, "trust_key.duration_flags")?;
            if k.mechanisms_len != 0 {
                return Err(fault(Rule::Contradiction, "trust_key.duration_mechanisms"));
            }
            if k.role == TRUST_PRIVATE_REACH && !k.default.ptr.is_null() {
                return Err(fault(Rule::Contradiction, "trust_key.reach_default"));
            }
            // The item approvals name the field each item's digest is written under.
            if k.role == TRUST_ITEM_APPROVALS && (k.default.ptr.is_null() || k.default.len == 0) {
                return Err(fault(Rule::Missing, "trust_key.approvals_field"));
            }
        }
        if keys[..i].iter().any(|p| p.role == k.role) {
            return Err(fault(Rule::Contradiction, "trust_key.role_twice"));
        }
    }
    Ok(())
}

/// The refusal statuses: each names a dialect the tail declares (or every dialect), a reason the
/// vocabulary holds and a status from 400 to 599, and no `(dialect, reason)` is stated twice.
///
/// # Errors
///
/// The rule an entry breaks.
pub fn check_refusal_statuses(rows: &[RefusalStatus], dialects_len: u64) -> Result<(), Fault> {
    for (i, r) in rows.iter().enumerate() {
        if r.dialect != REFUSAL_ANY_DIALECT {
            index(r.dialect, dialects_len, "refusal_status.dialect")?;
        }
        if reason_of(r.reason).is_none() {
            return Err(fault(Rule::UnknownCode, "refusal_status.reason"));
        }
        code(u64::from(r.status), 400, 599, "refusal_status.status")?;
        if rows[..i]
            .iter()
            .any(|d| d.dialect == r.dialect && d.reason == r.reason)
        {
            return Err(fault(Rule::Contradiction, "refusal_status.twice"));
        }
    }
    Ok(())
}

/// A pin's mechanisms: each named, with known flags.
///
/// # Errors
///
/// The rule a mechanism breaks.
pub fn check_pin_mechanisms(mechanisms: &[PinMechanism]) -> Result<(), Fault> {
    for m in mechanisms {
        named(m.token, "pin_mechanism.token")?;
        bits(
            u64::from(m.flags),
            u64::from(MECHANISM_ROOT | MECHANISM_PEER_KEY),
            "pin_mechanism.flags",
        )?;
        // A far-end key pin is an authenticity root: the no-root spelling carries no material.
        if m.flags & MECHANISM_PEER_KEY != 0 && m.flags & MECHANISM_ROOT == 0 {
            return Err(fault(Rule::Contradiction, "pin_mechanism.flags"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/plane_check_tests.rs"]
mod tests;
