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
    AdminRoute, ArriveOut, BillableClass, Claim, DialectAuth, OnPieceOut, OutField, PinMechanism,
    PlaneDriveOut, PlaneSnapshot, PlaneTail, ProjectOut, RecordChain, RecordWrite, RefusalOut,
    RefusalStatus, RouteCost, ServeOut, TrustKey, UnitCount, CANCEL_ABORTED, CANCEL_OK_PARTIAL,
    CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED, CLAIM_EXACT, CLAIM_OPEN,
    CLAIM_PATTERN, EMIT_DONE, EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END,
    EMIT_UNWATCH_CATALOGUE, EMIT_WATCH_CATALOGUE, INGRESS_ACCEPT_LOOP, INGRESS_DUPLEX_SESSION,
    INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, INGRESS_SUBSCRIPTION, MAX_REFUSAL_TEXT,
    MECHANISM_PEER_KEY, MECHANISM_ROOT, PIECE_OUT_TEXT, PIN_FINGERPRINT, PRINCIPAL_OPTIONAL,
    RECORD_AUDIT, RECORD_PUT, REFUSAL_ANY_DIALECT, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_ONCE,
    ROUTE_POOL, ROUTE_PUBLIC, ROUTE_SCOPE, ROUTE_SESSION, SHAPE_PIECEWISE, SHAPE_WHOLE,
    TAIL_FALLBACK, TAIL_HOOKS_GATED, TAIL_PROBES, TRUST_PIN, TRUST_PRIVATE_REACH, UNITS_ESTIMATED,
    VERDICT_HARD,
};
use crate::abi::hook::{
    signal, MessageView, SignalEntry, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM,
    SIGNAL_TAG_BOOL, SIGNAL_TAG_STR, SIGNAL_TAG_U64,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_ABSENT, BLOB_OCTETS, MAX_TEXT};
use crate::abi::mechanism::check::{
    bits, code, fault, first, index, listed, range, result, results, span, text, weight, Dim,
    Filled, MAX_BYTES,
};
use crate::abi::mechanism::door::{Section, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED};
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

fn units(buf: &[UnitCount], n: u64, b: &Bounds) -> Result<(), Fault> {
    let counts = first(buf, n, "unit")?;
    for (i, u) in counts.iter().enumerate() {
        index(u.class, b.billable_classes, "unit.class")?;
        code(
            u64::from(u.source),
            u64::from(UNITS_ESTIMATED),
            u64::from(UNITS_FLOOR),
            "unit.source",
        )?;
        // ONE CUMULATIVE COUNT per class and source, and ONE BILLING COUNT per class: a second is a
        // contradiction (two running totals of one thing), never a sum the host would have to add
        // and never a choice it would have to make between a reported count and a floor.
        if counts[..i]
            .iter()
            .any(|p| p.class == u.class && units_bill(p.source) == units_bill(u.source))
        {
            return Err(fault(Rule::Contradiction, "unit.class"));
        }
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
        match r.op {
            RECORD_PUT => index(r.kind, b.record_kinds, "record.kind")?,
            // The unit's audit row: its outcome where a put names its kind, and an action.
            RECORD_AUDIT => {
                code(
                    u64::from(r.kind),
                    u64::from(super::AUDIT_APPLIED),
                    u64::from(super::AUDIT_REJECTED),
                    "record.audit_outcome",
                )?;
                if r.key.len == 0 {
                    return Err(fault(Rule::Contradiction, "record.audit_without_action"));
                }
            }
            _ => return Err(fault(Rule::UnknownCode, "record.op")),
        }
        span(r.key.offset, r.key.len, arena, "record.key")?;
        span(r.value.offset, r.value.len, arena, "record.value")?;
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
    // A refusal about an entry (abi/plane "A refused arrival", rule 6) names it, with its class.
    let about_entry = outcome == Outcome::Refused && (out.pool.len != 0 || !out.pool.ptr.is_null());
    if outcome == Outcome::Refused {
        if out.refusal == 0 {
            return Err(fault(Rule::Missing, "arrive.refusal"));
        }
        code(
            u64::from(out.refusal_status),
            400,
            if about_entry { 599 } else { 499 },
            "arrive.refusal_status",
        )?;
    } else if out.refusal != 0 || out.refusal_status != 0 {
        return Err(fault(Rule::Contradiction, "arrive.refusal"));
    }
    if outcome == Outcome::Ready {
        code(
            u64::from(out.principal_need),
            0,
            u64::from(PRINCIPAL_OPTIONAL),
            "arrive.principal_need",
        )?;
        index(out.op_class, b.op_classes, "arrive.op_class")?;
        index(out.dialect, b.dialects, "arrive.dialect")?;
        if out.correlation != 0 && out.cancels != 0 {
            return Err(fault(Rule::Contradiction, "arrive.cancel_with_correlation"));
        }
        text(out.pool, "arrive.pool")?;
        if out.pool.len > MAX_TEXT {
            return Err(fault(Rule::OverMax, "arrive.pool"));
        }
        if ![ROUTE_POOL, ROUTE_DIRECT, ROUTE_LOCAL, ROUTE_SCOPE].contains(&out.route) {
            return Err(fault(Rule::UnknownCode, "arrive.route"));
        }
        if out.route_flags & !(ROUTE_ONCE | ROUTE_SESSION) != 0 {
            return Err(fault(Rule::UnknownCode, "arrive.route_flags"));
        }
        // A unit the plane answers itself names no entry (one routed by scope may name its
        // candidates).
        if out.route == ROUTE_LOCAL && (out.pool.len != 0 || !out.pool.ptr.is_null()) {
            return Err(fault(Rule::Contradiction, "arrive.pool"));
        }
    } else if about_entry {
        index(out.op_class, b.op_classes, "arrive.op_class")?;
        index(out.dialect, b.dialects, "arrive.dialect")?;
        text(out.pool, "arrive.pool")?;
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
    if outcome == Outcome::Refused {
        text(out.head.error, "arrive.refusal_text")?;
        if out.head.error.len as u64 > MAX_REFUSAL_TEXT {
            return Err(fault(Rule::OverMax, "arrive.refusal_text"));
        }
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
    code(u64::from(out.more), 0, 1, "on_piece.more")?;
    bits(
        u64::from(out.flags),
        u64::from(
            EMIT_TO_FAR_END
                | EMIT_DONE
                | EMIT_WATCH_CATALOGUE
                | EMIT_UNWATCH_CATALOGUE
                | PIECE_OUT_TEXT
                | EMIT_MESSAGE_END
                | EMIT_FINAL_STATUS,
        ),
        "on_piece.flags",
    )?;
    final_status(out)?;
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
    verdict(outcome, out.verdict)?;
    request(out)?;
    // The unit's ledger lane, where the answer names one: inside the arena written.
    span(
        out.lane.offset,
        out.lane.len,
        out.arena_written,
        "on_piece.lane",
    )?;
    units(bufs.0, u64::from(out.units_written), b)?;
    records(bufs.1, u64::from(out.records_written), out.arena_written, b)?;
    fields(bufs.2, u64::from(out.fields_written), out.arena_written)
}

/// `on_piece`'s message boundary and final status: a boundary ends a message toward the caller,
/// never a request bound for the far end; a final status closes the reply ([`EMIT_DONE`]), its
/// message and details inside the arena written; without it the three fields are zero.
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
    span(
        out.final_message.offset,
        out.final_message.len,
        out.arena_written,
        "on_piece.final_message",
    )?;
    span(
        out.final_details.offset,
        out.final_details.len,
        out.arena_written,
        "on_piece.final_details",
    )
}

/// `on_piece`'s verdict: a known `VERDICT_*`, and none on an answer that is not READY.
fn verdict(outcome: Outcome, v: u32) -> Result<(), Fault> {
    code(u64::from(v), 0, u64::from(VERDICT_HARD), "on_piece.verdict")?;
    if v != 0 && outcome != Outcome::Ready {
        return Err(fault(Rule::Contradiction, "on_piece.verdict_not_ready"));
    }
    Ok(())
}

/// `on_piece`'s request for the far end: verb and target in the arena, both or neither, and only
/// on an answer that emits to the far end.
fn request(out: &OnPieceOut) -> Result<(), Fault> {
    span(
        out.verb.offset,
        out.verb.len,
        out.arena_written,
        "on_piece.verb",
    )?;
    span(
        out.target.offset,
        out.target.len,
        out.arena_written,
        "on_piece.target",
    )?;
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
fn in_arena(s: AbiStr, arena: *const u8, written: u64, field: &'static str) -> Result<(), Fault> {
    if s.len == 0 {
        return Ok(());
    }
    let offset = s
        .ptr
        .addr()
        .checked_sub(arena.addr())
        .ok_or(fault(Rule::SpanOutOfBounds, field))?;
    range(offset as u64, s.len as u64, written, field)
}

/// `project`'s session ([`RequestView::session`](crate::abi::hook::RequestView::session)): absent
/// (a NULL, empty [`BLOB_ABSENT`] blob), or [`BLOB_OCTETS`] with no flag, inside the arena written.
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
    let offset = b
        .ptr
        .addr()
        .checked_sub(arena.addr())
        .ok_or(fault(Rule::SpanOutOfBounds, FIELD))?;
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
            needed: u64::from(out.signals_needed),
            cap: host.signals_cap,
            max: MAX_SIGNALS,
            field: "project.signals",
        },
        Dim {
            written: p.message_count,
            needed: u64::from(out.messages_needed),
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
    results(outcome, "project", &dims)?;
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
    bits(
        u64::from(v.flags),
        u64::from(REQUEST_HAS_MAX_TOKENS | REQUEST_HAS_TOOLS | REQUEST_STREAM),
        "project.view.flags",
    )?;
    in_arena(v.pool, arena.0, out.arena_written, "project.view.pool")?;
    in_arena(
        v.ingress_dialect,
        arena.0,
        out.arena_written,
        "project.view.ingress_dialect",
    )?;
    in_arena(
        p.system,
        arena.0,
        out.arena_written,
        "project.prompt.system",
    )?;
    in_arena(out.end_user, arena.0, out.arena_written, "project.end_user")?;
    session(v.session, arena.0, out.arena_written)?;
    span(
        out.body.offset,
        out.body.len,
        out.arena_written,
        "project.body",
    )?;
    span(
        out.rewritten.offset,
        out.rewritten.len,
        out.arena_written,
        "project.rewritten",
    )?;
    if out.rewritten.len != 0 && !host.rewrite {
        return Err(fault(
            Rule::Contradiction,
            "project.rewritten_without_rewrite",
        ));
    }
    for m in first(host.messages, p.message_count, "project.messages")? {
        in_arena(m.role, arena.0, out.arena_written, "project.message.role")?;
        in_arena(m.text, arena.0, out.arena_written, "project.message.text")?;
    }
    for e in first(signals, written, "project.signals")? {
        code(
            u64::from(e.id),
            0,
            u64::from(signal::RESPONSE_TOKENS_OUT),
            "project.signal.id",
        )?;
        code(
            u64::from(e.tag),
            u64::from(SIGNAL_TAG_U64),
            u64::from(SIGNAL_TAG_BOOL),
            "project.signal.tag",
        )?;
        if e.tag == SIGNAL_TAG_STR {
            // SAFETY: the tag names `str_` live; every bit pattern of an `AbiStr` is a valid value.
            let s = unsafe { e.value.str_ };
            in_arena(s, arena.0, out.arena_written, "project.signal.value")?;
        } else if e.tag == SIGNAL_TAG_BOOL {
            // SAFETY: the tag names `boolean` live; every `u8` is a valid value.
            let b = unsafe { e.value.boolean };
            code(u64::from(b), 0, 1, "project.signal.value")?;
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
    code(u64::from(out.marker), 0, 0, "refusal.marker")?;
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
fn answer_records(
    outcome: Outcome,
    (written, needed, arena): (u32, u32, u64),
    records_buf: &[RecordWrite],
    records_cap: u64,
    b: &Bounds,
    field: &'static str,
) -> Result<(), Fault> {
    let written = u64::from(written);
    result(
        outcome,
        written,
        u64::from(needed),
        records_cap,
        MAX_RECORDS,
        field,
    )?;
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
    code(
        u64::from(out.audit),
        0,
        u64::from(super::AUDIT_REJECTED),
        "serve.audit",
    )?;
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
    text(s.resource_metadata, "snapshot.resource_metadata")?;
    listed(
        s.resource_facts.ptr,
        s.resource_facts.len,
        "snapshot.resource_facts",
    )
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
            u64::from(CLAIM_OPEN | CLAIM_EXACT | CLAIM_PATTERN),
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
/// brace-free literal or a whole placeholder `{name}` with a non-empty, brace-free name. A pattern
/// names at least one placeholder; one that names none is an exact target.
fn pattern_shape(target: &str) -> Result<(), Fault> {
    let bad = || fault(Rule::Contradiction, "claim.pattern");
    let rest = target.strip_prefix('/').ok_or_else(bad)?;
    let mut placeholders = 0;
    for seg in rest.split('/') {
        match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(n) if !n.is_empty() && !n.contains(['{', '}']) => placeholders += 1,
            None if !seg.is_empty() && !seg.contains(['{', '}']) => {}
            _ => return Err(bad()),
        }
    }
    if placeholders == 0 {
        return Err(fault(Rule::Missing, "claim.pattern"));
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
    if flags & CLAIM_PATTERN != 0 {
        pattern_shape(target)?;
    }
    Ok(())
}

/// A [`CLAIM_PATTERN`] target read as its segment pattern, by the one grammar
/// ([`check_claim_target`]): each literal segment is a [`PathSeg::Lit`], each placeholder one
/// [`PathSeg::Var`].
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
            if seg.starts_with('{') {
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

/// Every snapshot admin route: a verb, a target and known flags.
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
            u64::from(ROUTE_PUBLIC),
            "admin_route.flags",
        )?;
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
        u64::from(TAIL_FALLBACK | TAIL_PROBES | TAIL_HOOKS_GATED),
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
            u64::from(TRUST_PRIVATE_REACH),
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
