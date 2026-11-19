// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE KIND'S ANSWER VALIDATORS, which live beside the shapes they judge: one pure `check_<op>` per answer, built from the shared helpers in

pub use crate::abi::mechanism::check::{Fault, Rule};

use super::reason_of;
use super::units_bill;
use super::{
    AdminRoute, ArriveOut, BillableClass, CatalogOut, Claim, ClassParent, DialectAuth, OnPieceOut,
    OutField, PinMechanism, PlaneDriveOut, PlaneSnapshot, PlaneTail, ProjectOut, RecordChain,
    RecordRetention, RecordWrite, RefusalOut, RefusalStatus, RouteCost, ServeOut, TrustKey,
    UnitCount, CANCEL_ABORTED, CANCEL_OK_PARTIAL, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED,
    CHAIN_PIPE_SEPARATED, CLAIM_CATALOG, CLAIM_ENTRY, CLAIM_EXACT, CLAIM_OPEN, CLAIM_PATTERN,
    CLAIM_RAW_AFFIX, CLAIM_SIGNED_INGRESS, CLAIM_TICKET, DIALECT_PROVIDER, EMIT_DONE,
    EMIT_FINAL_STATUS, EMIT_MESSAGE_END, EMIT_TO_FAR_END, EMIT_UNWATCH_CATALOGUE,
    EMIT_WATCH_CATALOGUE, INGRESS_ACCEPT_LOOP, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, INGRESS_SUBSCRIPTION, MAX_METRIC_LANES, MAX_REFUSAL_TEXT,
    PIECE_OUT_TEXT, RECORD_AUDIT, RECORD_PUT, SHAPE_PIECEWISE, SHAPE_WHOLE, TAIL_FALLBACK,
    TAIL_HOOKS_GATED, TAIL_PROBES, TAIL_REFUSED_PIECE, UNITS_ESTIMATED, VERDICT_COUNT_REFUSED,
};
use crate::abi::hook::{
    signal, MessageView, SignalEntry, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM,
};
use crate::abi::mechanism::call::{AbiStr, Blob, Outcome, BLOB_ABSENT, BLOB_OCTETS, MAX_TEXT};
use crate::abi::mechanism::check::{
    bits, code, fault, first, index, listed, range, result, results, span, text, weight, Dim,
    Filled, MAX_BYTES,
};
use crate::abi::mechanism::door::{
    Section, SECTION_CONSUMED, SECTION_DECLARING, SECTION_REQUIRED, SECTION_SELECTS,
};
use crate::grammar::{PathSeg, Selector};
use crate::host_records::RETENTION_TERMINAL_ONLY;

/// The most unit counts one answer may carry.
pub const MAX_UNITS: u64 = 64;
/// The most head fields one answer may carry.
pub const MAX_FIELDS: u64 = 1024;
/// The most record writes one answer may carry.
pub const MAX_RECORDS: u64 = 1024;
/// The most claims, admin routes or listed names one snapshot may carry, and the most admin routes
/// a plane tail may state.
pub const MAX_ROUTES: u64 = 1024;
/// The most ready sessions one `drive` answer may name.
pub const MAX_SESSIONS: u64 = 1024;

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
            u64::from(super::UNITS_FLOOR_MICROS),
            "unit.source",
        )?;
        if u.source >= super::UNITS_ESTIMATED_MICROS && u.amount > i64::MAX as u64 {
            return Err(fault(Rule::Contradiction, "unit.amount"));
        }

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

            RECORD_AUDIT => {
                code(
                    u64::from(r.kind),
                    u64::from(super::AUDIT_APPLIED),
                    u64::from(super::AUDIT_DEGRADED),
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

/// `on_piece`'s message boundary and final status: a boundary ends a message toward the caller,
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
    code(
        u64::from(v),
        0,
        u64::from(VERDICT_COUNT_REFUSED),
        "on_piece.verdict",
    )?;
    if v != 0 && outcome != Outcome::Ready {
        return Err(fault(Rule::Contradiction, "on_piece.verdict_not_ready"));
    }
    Ok(())
}

/// `on_piece`'s request for the far end: verb and target in the arena, both or neither, and only
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

    if out.need != 0 && out.flags & EMIT_TO_FAR_END == 0 {
        return Err(fault(Rule::Contradiction, "on_piece.need_not_to_far_end"));
    }
    Ok(())
}

/// `project`'s session ([`RequestView::session`](crate::abi::hook::RequestView::session)): absent
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

/// A reply is one short answer over body, fields, arena and records. Judge every dimension
fn reply(
    outcome: Outcome,
    op: [&'static str; 5],
    wn: [(u64, u64); 4],
    fields_buf: &[OutField],
    records_buf: &[RecordWrite],
    caps: &Caps,
    b: &Bounds,
) -> Result<(), Fault> {
    let caps = [caps.reply, caps.fields, caps.arena, caps.records];
    let max = [MAX_BYTES, MAX_FIELDS, MAX_BYTES, MAX_RECORDS];
    let dims: [Dim; 4] = core::array::from_fn(|i| Dim {
        written: wn[i].0,
        needed: wn[i].1,
        cap: caps[i],
        max: max[i],
        field: op[i],
    });
    results(outcome, op[4], &dims)?;
    fields(fields_buf, wn[1].0, wn[2].0)?;
    records(records_buf, wn[3].0, wn[2].0, b)
}

/// `serve`: a known `AUDIT_*`; body, fields, arena and records obey one short-buffer rule and
pub fn check_serve(
    outcome: Outcome,
    out: &ServeOut,
    fields_buf: &[OutField],
    records_buf: &[RecordWrite],
    caps: &Caps,
    b: &Bounds,
) -> Result<(), Fault> {
    code(
        u64::from(out.audit),
        0,
        u64::from(super::AUDIT_REJECTED),
        "serve.audit",
    )?;
    reply(
        outcome,
        [
            "serve.reply",
            "serve.fields",
            "serve.arena",
            "serve.records",
            "serve",
        ],
        [
            (out.reply_written, out.reply_needed),
            (u64::from(out.fields_written), u64::from(out.fields_needed)),
            (out.arena_written, out.arena_needed),
            (
                u64::from(out.records_written),
                u64::from(out.records_needed),
            ),
        ],
        fields_buf,
        records_buf,
        caps,
        b,
    )
}

/// `catalog`: the reply is valid. This operation has no record buffer.
pub fn check_catalog(
    outcome: Outcome,
    out: &CatalogOut,
    fields_buf: &[OutField],
    caps: &Caps,
) -> Result<(), Fault> {
    code(u64::from(out._reserved), 0, 0, "catalog._reserved")?;
    reply(
        outcome,
        [
            "catalog.reply",
            "catalog.fields",
            "catalog.arena",
            "catalog.records",
            "catalog",
        ],
        [
            (out.reply_written, out.reply_needed),
            (u64::from(out.fields_written), u64::from(out.fields_needed)),
            (out.arena_written, out.arena_needed),
            (0, 0),
        ],
        fields_buf,
        &[],
        caps,
        &Bounds::default(),
    )
}

/// The lifecycle `cancel`'s disposition: on READY, one of the plane's three (`0` = unwritten is
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

/// Every snapshot claim: a verb, a target, a carrier, known flags, never EXACT with PATTERN, and a
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
                    | CLAIM_RAW_AFFIX
                    | CLAIM_TICKET
                    | CLAIM_ENTRY,
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
        if c.flags & CLAIM_OPEN != 0 && c.flags & CLAIM_TICKET != 0 {
            return Err(fault(Rule::Contradiction, "claim.flags"));
        }
    }
    Ok(())
}

/// THE PATTERN GRAMMAR, once: the target starts with `/`, and each `/`-separated segment is a
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

/// One predicate of a [`CLAIM_ENTRY`] target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPredicate<'a> {
    /// A head field is present (`None`), or present with a value that starts with the prefix.
    Field(&'a str, Option<&'a str>),
    /// The raw path matches the pattern ([`entry_path_matches`]).
    Path(&'a str),
}

/// A [`CLAIM_ENTRY`] target's predicates, in order, or `None` when it is not one: at least one
#[must_use]
pub fn entry_fact(target: &str) -> Option<Vec<EntryPredicate<'_>>> {
    let out: Vec<EntryPredicate<'_>> = target
        .split(' ')
        .map(entry_predicate)
        .collect::<Option<_>>()?;
    let paths = out
        .iter()
        .filter(|p| matches!(p, EntryPredicate::Path(_)))
        .count();
    (!out.is_empty() && paths <= 1).then_some(out)
}

/// One predicate of an entry fact's target, or `None` when the token is not one.
fn entry_predicate(token: &str) -> Option<EntryPredicate<'_>> {
    if let Some(field) = token.strip_prefix("field:") {
        let (name, prefix) = match field.split_once('=') {
            Some((name, prefix)) if !prefix.is_empty() => (name, Some(prefix)),
            Some(_) => return None,
            None => (field, None),
        };
        let named = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        return named.then_some(EntryPredicate::Field(name, prefix));
    }
    let pattern = token.strip_prefix("path:")?;
    entry_pattern_shape(pattern).then_some(EntryPredicate::Path(pattern))
}

/// An entry path pattern's shape: it starts with `/` or `*`, and each `{` opens a whole segment
fn entry_pattern_shape(pattern: &str) -> bool {
    let b = pattern.as_bytes();
    if !matches!(b.first(), Some(b'/' | b'*')) {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => {
                let Some(close) = b[i..].iter().position(|&c| c == b'}').map(|j| i + j) else {
                    return false;
                };
                let name = &b[i + 1..close];
                let whole = b[i - 1] == b'/' && matches!(b.get(close + 1), None | Some(b'/'));
                let named = name
                    .iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
                if !whole || !named {
                    return false;
                }
                i = close + 1;
            }
            b'}' => return false,
            _ => i += 1,
        }
    }
    true
}

/// Whether the raw, undecoded request `path` matches the entry path `pattern`: its bytes, `*` any
#[must_use]
pub fn entry_path_matches<'p, 'q>(
    pattern: &'p str,
    path: &'q str,
    captures: &mut Vec<(&'p str, &'q [u8])>,
) -> bool {
    fn walk<'p, 'q>(pat: &'p [u8], path: &'q [u8], caps: &mut Vec<(&'p [u8], &'q [u8])>) -> bool {
        match pat.first() {
            None => path.is_empty(),
            Some(b'*') => (0..=path.len()).any(|i| walk(&pat[1..], &path[i..], caps)),
            Some(b'{') => {
                let Some(close) = pat.iter().position(|&c| c == b'}') else {
                    return false;
                };
                let end = path.iter().position(|&c| c == b'/').unwrap_or(path.len());
                if end == 0 {
                    return false;
                }
                let name = &pat[1..close];
                let at = caps.len();
                if !name.is_empty() {
                    caps.push((name, &path[..end]));
                }
                if walk(&pat[close + 1..], &path[end..], caps) {
                    return true;
                }
                caps.truncate(at);
                false
            }
            Some(c) => path.first() == Some(c) && walk(&pat[1..], &path[1..], caps),
        }
    }
    if !entry_pattern_shape(pattern) {
        return false;
    }
    let mut caps = Vec::new();
    if !walk(pattern.as_bytes(), path.as_bytes(), &mut caps) {
        return false;
    }

    captures.extend(
        caps.into_iter()
            .map(|(name, seg)| (std::str::from_utf8(name).unwrap_or_default(), seg)),
    );
    true
}

/// A [`CLAIM_RAW_AFFIX`] target's two affixes, `(prefix, suffix)`, or `None` when it is not one:
#[must_use]
pub fn raw_affix(target: &str) -> Option<(&str, &str)> {
    let (prefix, suffix) = target.split_once('*')?;
    (prefix.starts_with('/') && !suffix.is_empty() && !suffix.contains('*'))
        .then_some((prefix, suffix))
}

/// Whether the raw, undecoded request `path` matches the [`CLAIM_RAW_AFFIX`] target `target`: it
#[must_use]
pub fn raw_affix_matches(target: &str, path: &str) -> bool {
    raw_affix(target)
        .is_some_and(|(prefix, suffix)| path.starts_with(prefix) && path.ends_with(suffix))
}

/// A [`CLAIM_PATTERN`] target read as its segment pattern, by the one grammar
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

/// The Statement tail, at load: known flags, ingress bits and dispatch shape; at least one ingress
pub fn check_tail(t: &PlaneTail) -> Result<(), Fault> {
    bits(
        u64::from(t.flags),
        u64::from(
            TAIL_FALLBACK
                | TAIL_PROBES
                | TAIL_HOOKS_GATED
                | TAIL_REFUSED_PIECE
                | super::TAIL_AUTHENTICATED_ROUTE,
        ),
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
    listed(t.class_parents, t.class_parents_len, "tail.class_parents")?;
    listed(
        t.streaming_content_types,
        t.streaming_content_types_len,
        "tail.streaming_content_types",
    )?;
    listed(
        t.record_retentions,
        t.record_retentions_len,
        "tail.record_retentions",
    )?;
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

/// Validate every instance-local collection relationship before admission.
pub fn check_record_collections(
    collections: &[super::RecordCollection],
    kinds: u64,
) -> Result<(), Fault> {
    use super::CollectionMode;
    let mut indices = std::collections::BTreeMap::new();
    for (i, c) in collections.iter().enumerate() {
        index(c.kind, kinds, "collection.kind")?;
        if indices.insert(c.kind, i).is_some() {
            return Err(fault(Rule::Contradiction, "collection.kind_twice"));
        }
    }
    for c in collections {
        if let Some(parent) = c.parent {
            index(parent, kinds, "collection.parent")?;
            let parent = indices
                .get(&parent)
                .map(|&i| &collections[i])
                .ok_or_else(|| fault(Rule::Missing, "collection.parent"))?;
            if parent.mode != CollectionMode::Upsert {
                return Err(fault(Rule::Contradiction, "collection.parent_mode"));
            }
        }
    }
    // Each vertex is visited once: 0 unvisited, 1 on this path, 2 completed.
    let mut colors = vec![0u8; collections.len()];
    for start in 0..collections.len() {
        if colors[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut next = Some(start);
        while let Some(i) = next {
            match colors[i] {
                1 => return Err(fault(Rule::Contradiction, "collection.cycle")),
                2 => break,
                _ => {}
            }
            colors[i] = 1;
            path.push(i);
            next = collections[i].parent.and_then(|p| indices.get(&p).copied());
        }
        for i in path {
            colors[i] = 2;
        }
    }
    Ok(())
}
