// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DOOR'S TEST PLUGIN — a minimal plane built with `plugin_door!`, one source compiled
//! into the test build (the LINKED door, its `door` function) and built as the `plane_door_plugin`
//! example `cdylib` (the DROPPED door, through `export_door!`).
//!
//! It answers every plane op through the SDK's trampolines: `open` and `refresh` publish a
//! generation snapshot (valid until `retire` of that generation), `arrive`, `on_piece`, `refusal`,
//! `serve` and `project` write only into the host's buffers, `drive` names the session with
//! unsolicited output, `cancel` answers a disposition and `tick` its next tick. The request-path
//! ops never allocate and never block: the only shared state they touch is one atomic.
//!
//! It is written on the SDK's SAFE surface (`abi::sdk::safe`, `abi::sdk::lent`): every slot is a
//! `SafeSlot`, the instance is the SDK's typed `Instance<Plane>`, host-lent bytes and host buffers
//! go through `Lent` and `HostBuf`. This file holds no `unsafe`.

#![forbid(unsafe_code)]

use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::hook::{signal, SignalEntry, SignalValue, SIGNAL_TAG_U64};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    AdminRoute, ArriveIn, ArriveOut, BillableClass, Claim, OnPieceIn, OnPieceOut, OpClass,
    OutField, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut,
    PlaneSnapshot, PlaneTail, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut, Section,
    ServeIn, ServeOut, UnitCount, CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE,
    MARK_GATE_REJECTED, PIECE_LAST, PRINCIPAL_NONE, RECORD_PUT, REFUSAL_GATE, SECTION_DECLARING,
    SHAPE_PIECEWISE, UNITS_ESTIMATED, UNITS_REPORTED, VERDICT_OK,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::{Instance, Lent, Published, Safe, SafeSlot};

/// An absent string.
const NONE: AbiStr = AbiStr {
    ptr: ptr::null(),
    len: 0,
};

const SECTIONS: &[Section] = &[Section {
    name: abi_str("door"),
    flags: SECTION_DECLARING,
    _reserved: 0,
}];
const DIALECTS: &[AbiStr] = &[abi_str("door/1")];
const OP_CLASSES: &[OpClass] = &[OpClass {
    op: abi_str("echo"),
    name: abi_str("Door"),
}];
const CLASSES: &[BillableClass] = &[BillableClass {
    class: abi_str("bytes"),
    family: abi_str("bytes"),
}];
const RECORD_KINDS: &[AbiStr] = &[abi_str("last")];

/// The Statement tail: one of each list the per-call indices name.
const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_DUPLEX_SESSION,
    dispatch_shape: SHAPE_PIECEWISE,
    _reserved: 0,
    scope: abi_str("door"),
    label: abi_str("Door"),
    subject_noun: abi_str("door"),
    admin_noun: abi_str("door"),
    audit_kind: abi_str("door"),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    sections: SECTIONS.as_ptr(),
    sections_len: SECTIONS.len(),
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    dialect_auth: ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: ptr::null(),
    scope_kinds_len: 0,
    op_classes: OP_CLASSES.as_ptr(),
    op_classes_len: OP_CLASSES.len(),
    billable_classes: CLASSES.as_ptr(),
    billable_classes_len: CLASSES.len(),
    route_cost: ptr::null(),
    route_cost_len: 0,
    fee_units: ptr::null(),
    fee_units_len: 0,
    record_kinds: RECORD_KINDS.as_ptr(),
    record_kinds_len: RECORD_KINDS.len(),
    needs: ptr::null(),
    needs_len: 0,
    egress_targets: ptr::null(),
    egress_targets_len: 0,
    record_chains: ptr::null(),
    record_chains_len: 0,
    trust_keys: ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: std::ptr::null(),
    refusal_statuses_len: 0,
};

/// Every generation's claim.
const CLAIMS: &[Claim] = &[Claim {
    verb: abi_str("POST"),
    target: abi_str("/echo"),
    carrier: abi_str("door"),
    flags: 0,
    refusal_dialect: 0,
    _pad: 0,
}];
/// The admin route a REFRESHED generation adds.
const ROUTES: &[AdminRoute] = &[AdminRoute {
    verb: abi_str("GET"),
    target: abi_str("/door/status"),
    flags: 0,
    _reserved: 0,
}];

/// The settings `validate` refuses.
pub const BAD_SETTINGS: &[u8] = b"bad";

/// One instance: the live generations' snapshots (control lane only) and the session with
/// unsolicited output, `0` = none (the one thing the request path touches).
struct Plane {
    #[allow(clippy::vec_box)] // boxed: a published snapshot's address outlives the Vec's growth
    snapshots: Mutex<Vec<Box<Published<PlaneSnapshot>>>>,
    ready: AtomicU64,
}

impl Plane {
    /// A snapshot of `generation`, kept until its `retire`; a refreshed one adds the admin route.
    fn publish(&self, generation: u64, refreshed: bool) -> *const PlaneSnapshot {
        let routes: &[AdminRoute] = if refreshed { ROUTES } else { &[] };
        let snap = Box::new(Published::new(PlaneSnapshot {
            size: size_of::<PlaneSnapshot>() as u32,
            _reserved: 0,
            generation,
            claims: CLAIMS.as_ptr(),
            claims_len: CLAIMS.len(),
            admin_routes: routes.as_ptr(),
            admin_routes_len: routes.len(),
            openapi: absent(),
            audience: NONE,
            resource_metadata: NONE,
        }));
        let p = snap.as_ptr();
        lock(&self.snapshots).push(snap);
        p
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn absent() -> Blob {
    Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: busbar_contract::abi::mechanism::call::BLOB_ABSENT,
        flags: 0,
    }
}

/// One slot body on the SDK's safe surface: `$name` reads `$in` and writes `$out` over the
/// instance's [`Plane`].
macro_rules! slot {
    ($name:ident, $in:ty, $out:ty, |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Plane;
            fn call($inst: Instance<'_, Plane>, $input: Lent<'_, $in>, $o: &mut $out) -> Outcome {
                $body
            }
        }
    };
}

slot!(Validate, ValidateIn, OutHead, |_, input, _| {
    if input.field(|i| &i.settings).bytes() == BAD_SETTINGS {
        Outcome::Refused
    } else {
        Outcome::Ready
    }
});

slot!(Open, PlaneOpenIn, PlaneOpenOut, |instance, input, out| {
    let p = Plane {
        snapshots: Mutex::new(Vec::new()),
        ready: AtomicU64::new(0),
    };
    out.snapshot = p.publish(input.open.generation, false);
    instance.open(p);
    Outcome::Ready
});

slot!(
    Refresh,
    RefreshIn,
    PlaneRefreshOut,
    |instance, input, out| {
        let Some(p) = instance.get() else {
            return Outcome::Failed;
        };
        out.snapshot = p.publish(input.generation, true);
        Outcome::Ready
    }
);

slot!(Retire, GenIn, OutHead, |instance, input, _| {
    if let Some(p) = instance.get() {
        lock(&p.snapshots).retain(|s| s.get().generation != input.generation);
    }
    Outcome::Ready
});

slot!(Tick, TickIn, TickOut, |_, input, out| {
    out.next_tick_ns = input.now_ns + 1_000_000;
    Outcome::Ready
});

slot!(
    Drive,
    PlaneDriveIn,
    PlaneDriveOut,
    |instance, input, out| {
        let Some(p) = instance.get() else {
            return Outcome::Failed;
        };
        let ready = p.ready.load(Ordering::Acquire);
        if ready == 0 {
            return Outcome::Ready;
        }
        let mut sessions = input.sessions_buf();
        sessions.push(ready);
        if !sessions.fits() {
            out.sessions_needed = sessions.needed() as u32;
            return Outcome::Failed;
        }
        out.sessions_written = sessions.written() as u32;
        p.ready.store(0, Ordering::Release);
        Outcome::Ready
    }
);

slot!(Cancel, CancelIn, CancelOut, |_, _, out| {
    out.disposition = CANCEL_ABORTED;
    Outcome::Ready
});

slot!(Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready });

// `close` answering READY: the SDK drops the instance's `Plane`.
slot!(Close, InHead, OutHead, |_, _, _| { Outcome::Ready });

slot!(Arrive, ArriveIn, ArriveOut, |_, input, out| {
    let mut units = input.units_buf();
    units.push(UnitCount {
        class: 0,
        source: UNITS_ESTIMATED,
        amount: input.body.len as u64,
    });
    if !units.fits() {
        out.units_needed = units.needed() as u32;
        return Outcome::Failed;
    }
    out.units_written = units.written() as u32;
    out.op_class = 0;
    out.dialect = 0;
    out.principal_need = PRINCIPAL_NONE;
    Outcome::Ready
});

slot!(OnPiece, OnPieceIn, OnPieceOut, |instance, input, out| {
    let piece = input.field(|i| &i.bytes).bytes();
    let mut arena = input.arena_buf();
    let mut reply = input.reply_buf();
    match (input.from, input.attempt_no) {
        // An ATTEMPT: the request bound for the member the kernel picked.
        (FROM_KERNEL, 1..) => {
            let (verb, target) = (arena.span(b"POST"), arena.span(b"/up"));
            if !arena.fits() {
                out.arena_needed = arena.needed() as u64;
                return Outcome::Failed;
            }
            (out.verb, out.target) = (verb, target);
            out.arena_written = arena.written() as u64;
            let member = input.field(|i| &i.member).bytes();
            out.emitted = reply.stream(member) as u64;
            out.flags = EMIT_TO_FAR_END;
        }
        // A session's unsolicited output, after `drive` named it.
        (FROM_KERNEL, 0) => {
            out.emitted = reply.stream(b"ping") as u64;
        }
        // The caller's piece opens a session with output to come.
        (FROM_CALLER, _) => {
            let Some(p) = instance.get() else {
                return Outcome::Failed;
            };
            p.ready.store(input.stream, Ordering::Release);
        }
        // The far end's answer: echoed to the caller, with a field, a count and a record.
        (FROM_FAR_END, _) => {
            let (mut fields, mut records, mut units) =
                (input.fields_buf(), input.records_buf(), input.units_buf());
            fields.push(OutField {
                name: arena.span(b"x-plane"),
                value: arena.span(b"door"),
            });
            records.push(RecordWrite {
                kind: 0,
                op: RECORD_PUT,
                key: arena.span(b"k"),
                value: arena.span(b"v"),
            });
            units.push(UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: piece.len() as u64,
            });
            // One short answer for every buffer (the multi-buffer rule).
            let short = !(fields.fits() && records.fits() && units.fits() && arena.fits());
            let (fw, fnd) = fields.settle(short);
            let (rw, rnd) = records.settle(short);
            let (uw, und) = units.settle(short);
            let (aw, and) = arena.settle(short);
            (out.fields_written, out.fields_needed) = (fw as u32, fnd as u32);
            (out.records_written, out.records_needed) = (rw as u32, rnd as u32);
            (out.units_written, out.units_needed) = (uw as u32, und as u32);
            (out.arena_written, out.arena_needed) = (aw as u64, and as u64);
            if short {
                return Outcome::Failed;
            }
            let n = reply.stream(piece);
            out.emitted = n as u64;
            out.reply_status = 200;
            out.verdict = VERDICT_OK;
            if n < piece.len() {
                out.more = 1;
            } else if input.flags & PIECE_LAST != 0 {
                out.flags = EMIT_DONE;
            }
        }
        _ => return Outcome::Refused,
    }
    Outcome::Ready
});

slot!(Refusal, RefusalIn, RefusalOut, |_, input, out| {
    let (mut reply, mut fields, mut arena) =
        (input.reply_buf(), input.fields_buf(), input.arena_buf());
    reply.extend(input.field(|i| &i.text).bytes());
    fields.push(OutField {
        name: arena.span(b"x-refusal"),
        value: arena.span(b"gate"),
    });
    let short = !(reply.fits() && fields.fits() && arena.fits());
    let (rw, rnd) = reply.settle(short);
    let (fw, fnd) = fields.settle(short);
    let (aw, and) = arena.settle(short);
    (out.reply_written, out.reply_needed) = (rw as u64, rnd as u64);
    (out.fields_written, out.fields_needed) = (fw as u32, fnd as u32);
    (out.arena_written, out.arena_needed) = (aw as u64, and as u64);
    if short {
        return Outcome::Failed;
    }
    if input.cause == REFUSAL_GATE {
        out.marker = MARK_GATE_REJECTED;
    }
    Outcome::Ready
});

slot!(Serve, ServeIn, ServeOut, |_, input, out| {
    let mut reply = input.reply_buf();
    reply.extend(b"ok");
    if !reply.fits() {
        out.reply_needed = reply.needed() as u64;
        return Outcome::Failed;
    }
    out.reply_written = reply.written() as u64;
    out.status = 200;
    Outcome::Ready
});

slot!(Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Ready });

slot!(Start, GenIn, OutHead, |_, _, _| { Outcome::Ready });

slot!(Project, ProjectIn, ProjectOut, |_, input, out| {
    let body = input.field(|i| &i.body).bytes();
    let (mut signals, mut arena) = (input.signals_buf(), input.arena_buf());
    let (pool, projected) = (arena.span(b"door"), arena.span(body));
    signals.push(SignalEntry {
        id: signal::REQUEST_TOTAL_CHARS,
        tag: SIGNAL_TAG_U64,
        value: SignalValue {
            u64_: body.len() as u64,
        },
    });
    let short = !(signals.fits() && arena.fits());
    let (sw, snd) = signals.settle(short);
    let (aw, and) = arena.settle(short);
    out.signals_needed = snd as u32;
    (out.arena_written, out.arena_needed) = (aw as u64, and as u64);
    if short {
        return Outcome::Failed;
    }
    out.body = projected;
    out.view.signals = signals.as_ptr();
    out.view.signals_len = sw;
    out.view.pool = arena.str_at(pool);
    Outcome::Ready
});

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        ..statement("plane-door", "1.0.0", 8)
    },
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<Refusal>, serve: Safe<Serve>,
        hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}

// The dropped door's one symbol. The test build links this source as a module beside the
// dispatcher's test plugin, which exports the same symbol, so only the `cdylib` emits it.
#[cfg(not(test))]
busbar_contract::export_door!(door);
