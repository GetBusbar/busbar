// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECISIONS PLANE'S DOOR: the plane kind's memory-ABI table (`busbar_contract::abi::plane`)
//! built with the SDK's `plugin_door!` on its safe surface, over this plane's answers to the plane
//! driver ([`crate::driven`], `BUSBAR-1.6.0.md` Part 3, section 12). [`door`] is the LINKED door;
//! the same function is the DROPPED door once a `cdylib` exports it (`examples/decisions_door.rs`,
//! through `busbar_contract::export_door!`), so the two cannot answer differently.
//! `tests/conformance.rs` loads both through the one loader and requires one transcript.
//!
//! Nothing routes to this door yet: no production path loads it, and the composition root still
//! declares the plane with its inert claims (`crates/busbar/src/root/plane_decisions.rs`). Serving
//! it is the root's serve switch.
//!
//! * The Statement: the plane's key and version, `decisions:` declared and `providers:` consumed,
//!   its one outbound need, and the tail [`TAIL`] (every list read off [`crate::driven::tail`]).
//! * `validate`, `open`, `refresh`: the settings blob read as the `decisions:` section
//!   ([`crate::config::DecisionsSection`]); a generation's snapshot claims
//!   [`crate::driven::served_claims`] for its model count. `retire` drops a generation.
//! * `arrive`: [`crate::driven::arrive`]; an unclaimed request is refused at 404.
//! * `on_piece`: the ATTEMPT's request head ([`crate::driven::attempt`]), the caller's body to the
//!   far end unchanged ([`crate::driven::caller_piece`]), and the far end's answer relayed unchanged
//!   with its count read at the last piece ([`crate::driven::FarEndReading`]).
//! * `refusal`: [`crate::driven::refusal_body`].
//! * `serve` and `project` are REFUSED: the plane publishes no admin route and binds no hook view.
//!   `hydrate`, `start`, `tick`, `drive`, `cancel`, `release` and `close` hold nothing.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::ptr;
use std::sync::{Mutex, PoisonError};

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_PROVIDER};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::{
    KindTailHead, Section, Statement, SECTION_CONSUMED, SECTION_DECLARING,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, OnPieceIn, OnPieceOut, OpClass, OutField, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, CLAIM_EXACT,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, INGRESS_REQUEST_RESPONSE,
    PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_NONE, PRINCIPAL_OPTIONAL, PRINCIPAL_REQUIRED,
    SHAPE_WHOLE, UNITS_REPORTED,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::{ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::{
    open_failed, Generations, HostBuf, Instance, Lent, Out, Safe, SafeSlot,
};
use busbar_contract::plane::PlaneMeta;

use crate::codec::{CONTENT_TYPE_JSON, FIELD_CONTENT_TYPE};
use crate::config::DecisionsSection;
use crate::driven::{self, tail, CallerAnswer, FarEndReading, PrincipalNeed};
use crate::{claims, DecisionPlane};

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// The most calls the kernel keeps in flight on one instance.
const MAX_INFLIGHT: u32 = 64;

/// The most units the instance keeps state for at once; past it, the oldest is dropped first.
pub const MAX_UNITS: usize = 4096;

/// [`ArriveOut::refusal`]: the request names no operation this plane claims.
pub const UNCLAIMED: u32 = 1;

/// The status an unclaimed request is refused at.
const STATUS_NOT_FOUND: u32 = 404;

/// The human label.
const LABEL: &str = "Decisions";

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

/// `decisions:` declared, `providers:` consumed ([`tail::SECTION_DECLARING`],
/// [`tail::SECTIONS_CONSUMED`]).
const SECTIONS: &[Section] = &[
    Section {
        name: abi_str(tail::SECTION_DECLARING),
        flags: SECTION_DECLARING,
        _reserved: 0,
    },
    Section {
        name: abi_str(tail::SECTIONS_CONSUMED[0]),
        flags: SECTION_CONSUMED,
        _reserved: 0,
    },
];

const DIALECTS: &[AbiStr] = &[abi_str(tail::DIALECTS[0])];

const SCOPE_KINDS: &[AbiStr] = &[abi_str(tail::SCOPE_KINDS[0])];

const OP_CLASSES: &[OpClass] = &[OpClass {
    op: abi_str(tail::OP_CLASSES[0].as_str()),
    name: abi_str(tail::OP_CLASSES[0].as_str()),
}];

const BILLABLE_CLASSES: &[BillableClass] = &[BillableClass {
    class: abi_str(tail::BILLABLE_CLASSES[0].0.as_str()),
    family: abi_str(tail::BILLABLE_CLASSES[0].1),
}];

/// The far end's one response field the plane relays: the document type of the answer.
const KEEP_RESPONSE_HEADERS: &[AbiStr] = &[abi_str(FIELD_CONTENT_TYPE)];

/// THE PLANE'S ONE NEED ([`tail::NEEDS`]): outbound to a configured provider, over the claim's
/// transport, decorated under the egress scheme the kernel holds the credential for.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_PROVIDER,
    transport: abi_str(tail::NEEDS[0].0),
    auth: abi_str(tail::NEEDS[0].1),
    target_from: NONE,
    trust_from: NONE,
    details: Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: KEEP_RESPONSE_HEADERS.as_ptr(),
    keep_response_headers_len: KEEP_RESPONSE_HEADERS.len(),
    timeout_ms: 0,
}];

/// THE STATEMENT TAIL: the plane's static facts, every list [`crate::driven::tail`]'s.
pub const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE,
    // The kernel gathers the caller's whole body and pushes it as one piece.
    dispatch_shape: SHAPE_WHOLE,
    _reserved: 0,
    scope: abi_str(tail::SCOPE_KINDS[0]),
    label: abi_str(LABEL),
    subject_noun: abi_str(tail::SUBJECT_NOUN),
    admin_noun: abi_str(tail::ADMIN_NOUN),
    audit_kind: abi_str(tail::AUDIT_KIND),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: SCOPE_KINDS.as_ptr(),
    scope_kinds_len: SCOPE_KINDS.len(),
    op_classes: OP_CLASSES.as_ptr(),
    op_classes_len: OP_CLASSES.len(),
    billable_classes: BILLABLE_CLASSES.as_ptr(),
    billable_classes_len: BILLABLE_CLASSES.len(),
    route_cost: ptr::null(),
    route_cost_len: 0,
    // No fee unit ([`tail::FEE_UNITS`]).
    fee_units: ptr::null(),
    fee_units_len: 0,
    record_kinds: ptr::null(),
    record_kinds_len: 0,
    egress_targets: ptr::null(),
    egress_targets_len: 0,
    record_chains: ptr::null(),
    record_chains_len: 0,
    trust_keys: ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: ptr::null(),
    refusal_statuses_len: 0,
};

/// THE STATEMENT: the plane's key and version, its sections, its need and its tail.
pub const STATEMENT: Statement = Statement {
    kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
    sections: SECTIONS.as_ptr(),
    sections_len: SECTIONS.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(<DecisionPlane as PlaneMeta>::KEY, VERSION, MAX_INFLIGHT)
};

/// The settings blob read as the `decisions:` section; an empty blob is the empty section.
///
/// # Errors
///
/// The section's first broken rule, in the grammar's words.
pub fn read_settings(settings: &[u8]) -> Result<DecisionsSection, String> {
    if settings.is_empty() {
        return Ok(DecisionsSection::default());
    }
    serde_json::from_slice(settings).map_err(|e| e.to_string())
}

/// ONE GENERATION'S SNAPSHOT for a section with `models` configured models: the claims
/// [`driven::served_claims`] serves, each an exact target over the claim's transport.
#[must_use]
pub fn snapshot_spec(models: usize) -> SnapshotSpec {
    SnapshotSpec {
        claims: driven::served_claims(models)
            .iter()
            .map(|(verb, target)| ClaimSpec::new(verb, target, claims::TRANSPORT, CLAIM_EXACT))
            .collect(),
        ..SnapshotSpec::default()
    }
}

/// One unit the instance keeps, from its ATTEMPT to the far end's last piece.
#[derive(Debug, Default)]
struct Unit {
    /// An ATTEMPT opened the request bound for the far end; the caller's body follows it there.
    attempt: bool,
    /// The far end's answer, read as it is relayed.
    reading: FarEndReading,
    /// The piece answered short: its re-call carries the same piece, which is not read twice.
    recall: bool,
    /// What a `more = 1` answer still owes the host, and how much of it is written.
    owed: Vec<u8>,
    /// How much of [`Unit::owed`] is written.
    at: usize,
    /// The `EMIT_*` bits the owed bytes carry.
    owed_flags: u32,
}

/// One instance: every live generation's snapshot, and the units in flight.
#[derive(Debug)]
pub struct DecisionsDoor {
    generations: Generations<PlaneSnapshot>,
    units: Mutex<BTreeMap<u64, Unit>>,
}

/// One slot body on the SDK's safe surface, over this plane's [`DecisionsDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = DecisionsDoor;
            fn call($inst: Instance<'_, DecisionsDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match read_settings(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(words) => out.fail(Refusal::refused(words)),
        }
    }
);

slot!(
    /// `open`: the instance, and the first generation's snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        let open = input.field(|i| &i.open);
        let section = match read_settings(open.field(|o| &o.settings).bytes()) {
            Ok(section) => section,
            Err(words) => return open_failed(open, &mut out, |o| &o.open.err_len, &words),
        };
        let plane = DecisionsDoor {
            generations: Generations::new(),
            units: Mutex::new(BTreeMap::new()),
        };
        let spec = snapshot_spec(section.models.len());
        out.publish(|o| &o.snapshot, &plane.generations, open.generation, &spec);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let section = match read_settings(input.field(|i| &i.settings).bytes()) {
            Ok(section) => section,
            Err(words) => return out.fail(Refusal::refused(words)),
        };
        let spec = snapshot_spec(section.models.len());
        out.publish(|o| &o.snapshot, &plane.generations, input.generation, &spec);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: none wanted.
    Tick, TickIn, TickOut, |_, _, mut out| {
        out.set(|o| &o.next_tick_ns, 0);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: no session has unsolicited output.
    Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `cancel`: a unit is never answered before its far end has, so nothing is moved.
    Cancel, CancelIn, CancelOut, |_, _, mut out| {
        out.set(|o| &o.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `arrive`: a claimed request's op class, principal need and dialect; an unclaimed one is
    /// refused at 404.
    Arrive, ArriveIn, ArriveOut, |_, input, mut out| {
        let verb = input.field(|i| &i.method).as_str().unwrap_or_default();
        let target = input.field(|i| &i.target).as_str().unwrap_or_default();
        let Some(arrived) = driven::arrive(verb, target) else {
            out.set(|o| &o.refusal, UNCLAIMED);
            out.set(|o| &o.refusal_status, STATUS_NOT_FOUND);
            return out.fail(Refusal::bare());
        };
        out.set(|o| &o.op_class, arrived.op_class);
        out.set(|o| &o.dialect, arrived.dialect);
        out.set(
            |o| &o.principal_need,
            match arrived.principal {
                PrincipalNeed::None => PRINCIPAL_NONE,
                PrincipalNeed::Required => PRINCIPAL_REQUIRED,
                PrincipalNeed::Optional => PRINCIPAL_OPTIONAL,
            },
        );
        Outcome::Ready
    }
);

/// `(written, needed)` of every buffer an answer fills, short as a whole when one is short.
fn settle(
    out: &mut Out<'_, OnPieceOut>,
    fields: &HostBuf<'_, OutField>,
    units: &HostBuf<'_, UnitCount>,
    arena: &HostBuf<'_, u8>,
) -> bool {
    let short = !(fields.fits() && units.fits() && arena.fits());
    let (fw, fnd) = fields.settle(short);
    let (uw, und) = units.settle(short);
    let (aw, and) = arena.settle(short);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.units_written, uw as u32);
    out.set(|o| &o.units_needed, und as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    short
}

/// Write what `unit` owes into the reply buffer, as much as fits; `more = 1` while any is left,
/// and its flags (with `EMIT_DONE` held back until the last byte) on every write. Answers whether
/// the unit is done.
fn pay(unit: &mut Unit, input: Lent<'_, OnPieceIn>, out: &mut Out<'_, OnPieceOut>) -> bool {
    let n = input.reply_buf().stream(&unit.owed[unit.at..]);
    unit.at += n;
    let more = unit.at < unit.owed.len();
    let done = !more && unit.owed_flags & EMIT_DONE != 0;
    out.set(|o| &o.emitted, n as u64);
    out.set(|o| &o.more, u32::from(more));
    out.set(
        |o| &o.flags,
        if more {
            unit.owed_flags & !EMIT_DONE
        } else {
            unit.owed_flags
        },
    );
    if !more {
        unit.owed.clear();
        unit.at = 0;
    }
    done
}

/// Owe `bytes` under `flags`, and pay what fits now. Answers whether the unit is done.
fn owe(
    unit: &mut Unit,
    bytes: &[u8],
    flags: u32,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> bool {
    unit.owed.clear();
    unit.owed.extend_from_slice(bytes);
    unit.at = 0;
    unit.owed_flags = flags;
    pay(unit, input, out)
}

/// An ATTEMPT: the request bound for the far end, its verb, target and dialect fields. A new
/// attempt starts a new far-end answer.
fn attempt(unit: &mut Unit, input: Lent<'_, OnPieceIn>, out: &mut Out<'_, OnPieceOut>) -> Outcome {
    let request = driven::attempt(&[]);
    let (mut fields, units, mut arena) = (input.fields_buf(), input.units_buf(), input.arena_buf());
    let verb = arena.span(request.verb.as_bytes());
    let target = arena.span(request.target.as_bytes());
    for (name, value) in request.fields {
        fields.push(OutField {
            name: arena.span(name.as_bytes()),
            value: arena.span(value),
        });
    }
    if settle(out, &fields, &units, &arena) {
        return Outcome::Failed;
    }
    *unit = Unit {
        attempt: true,
        ..Unit::default()
    };
    out.set(|o| &o.verb, verb);
    out.set(|o| &o.target, target);
    out.set(|o| &o.flags, EMIT_TO_FAR_END);
    Outcome::Ready
}

/// One piece of the far end's answer: read, and relayed to the caller unchanged with its status
/// and document type on the first piece and its count on the last. Answers the outcome and
/// whether the unit is done.
fn far_end(
    unit: &mut Unit,
    input: Lent<'_, OnPieceIn>,
    out: &mut Out<'_, OnPieceOut>,
) -> (Outcome, bool) {
    let given = input.get();
    let bytes = input.field(|i| &i.bytes).bytes();
    let first = given.flags & PIECE_HAS_STATUS != 0;
    let last = given.flags & PIECE_LAST != 0;
    if !unit.recall {
        unit.reading.piece(bytes);
    }
    let (mut fields, mut units, mut arena) =
        (input.fields_buf(), input.units_buf(), input.arena_buf());
    if first {
        for f in input.head_fields().iter() {
            let name = f.field(|f| &f.name).bytes();
            if name.eq_ignore_ascii_case(FIELD_CONTENT_TYPE.as_bytes()) {
                fields.push(OutField {
                    name: arena.span(FIELD_CONTENT_TYPE.as_bytes()),
                    value: arena.span(f.field(|f| &f.value).bytes()),
                });
            }
        }
    }
    if last {
        if let Some(count) = unit.reading.units() {
            units.push(UnitCount {
                class: count.class,
                source: UNITS_REPORTED,
                amount: count.amount,
            });
        }
    }
    if settle(out, &fields, &units, &arena) {
        unit.recall = true;
        return (Outcome::Failed, false);
    }
    unit.recall = false;
    if first {
        out.set(|o| &o.reply_status, given.status_code);
    }
    let done = owe(unit, bytes, if last { EMIT_DONE } else { 0 }, input, out);
    (Outcome::Ready, done)
}

/// Keep `unit`'s state in `units`, dropping the smallest (oldest) keys first past [`MAX_UNITS`].
fn unit_of(units: &mut BTreeMap<u64, Unit>, key: u64) -> &mut Unit {
    while units.len() >= MAX_UNITS && !units.contains_key(&key) {
        if units.pop_first().is_none() {
            break;
        }
    }
    units.entry(key).or_default()
}

slot!(
    /// `on_piece`: the ATTEMPT's request head, the caller's body to the far end, and the far
    /// end's answer to the caller. A finished unit is forgotten.
    OnPiece, OnPieceIn, OnPieceOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let given = input.get();
        let bytes = input.field(|i| &i.bytes).bytes();
        let mut units = plane.units.lock().unwrap_or_else(PoisonError::into_inner);
        let unit = unit_of(&mut units, given.unit);
        // A re-call after `more = 1` carries no bytes, no flags and no attempt: it is paid from
        // what is owed.
        let continues = bytes.is_empty() && given.flags == 0 && given.attempt_no == 0;
        let (outcome, done) = if continues && unit.at < unit.owed.len() {
            (Outcome::Ready, pay(unit, input, &mut out))
        } else {
            match given.from {
                FROM_KERNEL if given.attempt_no != 0 => (attempt(unit, input, &mut out), false),
                FROM_CALLER => match driven::caller_piece(bytes, given.flags & PIECE_LAST != 0) {
                    CallerAnswer::Empty => (Outcome::Refused, true),
                    CallerAnswer::Keep if unit.attempt => {
                        owe(unit, bytes, EMIT_TO_FAR_END, input, &mut out);
                        (Outcome::Ready, false)
                    }
                    CallerAnswer::Keep => (Outcome::Ready, false),
                },
                FROM_FAR_END => far_end(unit, input, &mut out),
                _ => (Outcome::Refused, false),
            }
        };
        if done {
            units.remove(&given.unit);
        }
        outcome
    }
);

slot!(
    /// `refusal`: the kernel's status and text in this dialect's error shape, as JSON.
    RefusalSlot, RefusalIn, RefusalOut, |_, input, mut out| {
        let given = input.get();
        let status = u16::try_from(given.status).unwrap_or(0);
        let text = input.field(|i| &i.text).as_str().unwrap_or_default();
        let body = driven::refusal_body(status, text);
        let (mut reply, mut fields, mut arena) =
            (input.reply_buf(), input.fields_buf(), input.arena_buf());
        reply.extend(&body);
        fields.push(OutField {
            name: arena.span(FIELD_CONTENT_TYPE.as_bytes()),
            value: arena.span(CONTENT_TYPE_JSON),
        });
        let short = !(reply.fits() && fields.fits() && arena.fits());
        let (rw, rnd) = reply.settle(short);
        let (fw, fnd) = fields.settle(short);
        let (aw, and) = arena.settle(short);
        out.set(|o| &o.reply_written, rw as u64);
        out.set(|o| &o.reply_needed, rnd as u64);
        out.set(|o| &o.fields_written, fw as u32);
        out.set(|o| &o.fields_needed, fnd as u32);
        out.set(|o| &o.arena_written, aw as u64);
        out.set(|o| &o.arena_needed, and as u64);
        if short {
            Outcome::Failed
        } else {
            Outcome::Ready
        }
    }
);

slot!(
    /// `serve`: the plane publishes no admin route.
    Serve, ServeIn, ServeOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `hydrate`: the plane keeps no durable state.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `start`: the plane runs nothing of its own.
    Start, GenIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `project`: the plane binds no hook view; it never reads the decision content.
    Project, ProjectIn, ProjectOut, |_, _, _| { Outcome::Refused }
);

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}

#[cfg(test)]
#[path = "tests/plane_door.rs"]
mod tests;
