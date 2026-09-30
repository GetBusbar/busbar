// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER'S TEST PLANE — one source, compiled into the test build (the LINKED door) and
//! built as the `plane_driver_test_plane` example `cdylib` (the DROPPED door).
//!
//! It exports the one door over the plane table and defines no ABI shape of its own. What it does
//! with a unit is chosen by the member name the kernel hands its ATTEMPT piece (`ok`, `retry`,
//! `retry-late`, `pend`, `hang`, `wedge`, `fault`, `cancel-fault`, `short`, `short-twice`), and `arrive`
//! reacts to the request target (`/short`, `/short-twice`, `/refuse`, `/stats`). Its far-end
//! answer echoes the far end's bytes, in pieces of at most `reply_cap` (`more = 1` for the rest),
//! with cumulative far-end-reported units = the bytes emitted so far.
//!
//! It counts its own crossings and every call it makes into the host tables; `arrive` on `/stats`
//! answers the counters as unit amounts, in [`Stat`] order, so a linked and a dropped instance
//! report through the same table.

#![allow(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, OutHead, Outcome, RawOutcome, BLOB_ABSENT, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::call::{MetricEntry, METRIC_SET};
use busbar_contract::abi::mechanism::door::{
    Door, KindTailHead, MetricFamily, Statement, FAMILY_GAUGE,
};
use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, OpsHead, LIFECYCLE_SLOTS};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, Claim, OnPieceIn, OnPieceOut, OpClass, Ops, OutField,
    PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneSnapshot, PlaneTail, RefusalIn,
    RefusalOut, Section, Span, UnitCount, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL,
    EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, INGRESS_REQUEST_RESPONSE,
    INGRESS_RESPONSE_STREAM, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_OPTIONAL, SECTION_DECLARING,
    SHAPE_WHOLE, UNITS_ESTIMATED, UNITS_REPORTED, VERDICT_RETRY,
};

/// The counters `/stats` answers, in this order.
#[derive(Debug, Clone, Copy)]
pub enum Stat {
    /// `on_piece` crossings.
    OnPieces = 0,
    /// Calls this plane made into the host tables (the wake).
    HostCalls = 1,
    /// `cancel` crossings.
    Cancels = 2,
    /// `cancel` crossings the dispatcher made for a pending op, on the op's worker (its frame
    /// carries the op's Stream class; the driver's own ticketless `cancel` carries Call).
    CancelsOnWorker = 3,
    /// The last disposition `cancel` answered (`0` for FAULT).
    LastDisposition = 4,
    /// `drive` crossings.
    Drives = 5,
    /// The unit key the last `on_piece` carried.
    Unit = 6,
}
/// How many counters `/stats` answers.
pub const STATS: usize = 7;

struct Shared<T>(T);
// SAFETY: immutable `'static` data (pointers into other statics).
unsafe impl<T> Sync for Shared<T> {}

/// How long a `wedge` crossing runs: past the dispatcher's 1s Stream budget.
pub const WEDGE: Duration = Duration::from_millis(1500);

const fn s(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}
const NO_STR: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};
const NO_BLOB: Blob = Blob {
    ptr: std::ptr::null(),
    len: 0,
    fmt: BLOB_ABSENT,
    flags: 0,
};

static SECTIONS: Shared<[Section; 1]> = Shared([Section {
    name: s(b"test_plane"),
    flags: SECTION_DECLARING,
    _reserved: 0,
}]);
static DIALECTS: Shared<[AbiStr; 1]> = Shared([s(b"plain")]);
static OP_CLASSES: Shared<[OpClass; 1]> = Shared([OpClass {
    op: s(b"call"),
    name: s(b"test"),
}]);
static CLASSES: Shared<[BillableClass; 1]> = Shared([BillableClass {
    class: s(b"bytes"),
    family: s(b"bytes"),
}]);

static TAIL: Shared<PlaneTail> = Shared(PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM,
    dispatch_shape: SHAPE_WHOLE,
    _reserved: 0,
    scope: s(b"test"),
    label: s(b"Test plane"),
    subject_noun: NO_STR,
    admin_noun: NO_STR,
    audit_kind: NO_STR,
    signing_domain: NO_STR,
    signing_kid_prefix: NO_STR,
    cli_help: NO_STR,
    sections: &SECTIONS.0 as *const Section,
    sections_len: 1,
    dialects: &DIALECTS.0 as *const AbiStr,
    dialects_len: 1,
    dialect_auth: std::ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: std::ptr::null(),
    scope_kinds_len: 0,
    op_classes: &OP_CLASSES.0 as *const OpClass,
    op_classes_len: 1,
    billable_classes: &CLASSES.0 as *const BillableClass,
    billable_classes_len: 1,
    route_cost: std::ptr::null(),
    route_cost_len: 0,
    fee_units: std::ptr::null(),
    fee_units_len: 0,
    record_kinds: std::ptr::null(),
    record_kinds_len: 0,
    needs: std::ptr::null(),
    needs_len: 0,
    egress_targets: std::ptr::null(),
    egress_targets_len: 0,
    record_chains: std::ptr::null(),
    record_chains_len: 0,
});

static FAMILIES: Shared<[MetricFamily; 1]> = Shared([MetricFamily {
    name: s(b"plane_driver_test_drives"),
    help: NO_STR,
    unit: NO_STR,
    label_keys: std::ptr::null(),
    label_keys_len: 0,
    kind: FAMILY_GAUGE,
    _reserved: [0; 7],
}]);

static STATEMENT: Shared<Statement> = Shared(Statement {
    size: std::mem::size_of::<Statement>() as u32,
    kind: KindCode::Plane as u32,
    kind_abi: KindCode::Plane.abi_version(),
    max_inflight: 64,
    name: s(b"plane-driver-test-plane"),
    version: s(b"1.6.0"),
    families: &FAMILIES.0 as *const MetricFamily,
    families_len: 1,
    diag_ids: std::ptr::null(),
    diag_ids_len: 0,
    secret_refs: std::ptr::null(),
    secret_refs_len: 0,
    settings_schema: NO_BLOB,
    kind_tail: &TAIL.0.head as *const KindTailHead,
    extensions: NO_BLOB,
});

static OPS: Shared<Ops> = Shared(Ops {
    head: OpsHead {
        size: std::mem::size_of::<Ops>() as u32,
        slots: LIFECYCLE_SLOTS + busbar_contract::abi::plane::KIND_SLOTS,
        validate: Some(ready),
        open: Some(open),
        refresh: Some(ready),
        retire: Some(ready),
        tick: Some(ready),
        drive: Some(drive),
        cancel: Some(cancel),
        release: Some(ready),
        close: Some(close),
    },
    arrive: Some(arrive),
    on_piece: Some(on_piece),
    refusal: Some(refusal),
    serve: Some(refused),
    hydrate: Some(ready),
    start: Some(ready),
    project: Some(refused),
});

static DOOR: Shared<Door> = Shared(Door {
    magic: DOOR_MAGIC,
    mechanism_version: MECHANISM_VERSION,
    size: std::mem::size_of::<Door>() as u32,
    kind: KindCode::Plane as u32,
    kind_abi: KindCode::Plane.abi_version(),
    statement: &STATEMENT.0 as *const Statement,
    ops: &OPS.0 as *const Ops as *const OpsHead,
});

static CLAIMS: Shared<[Claim; 1]> = Shared([Claim {
    verb: s(b"POST"),
    target: s(b"/call"),
    carrier: s(b"inbound"),
}]);

/// THE DOOR: the `DoorFn` a compiled-in row holds.
pub extern "C" fn door() -> *const Door {
    &DOOR.0
}

busbar_contract::export_door!(door);

/// One unit, keyed by its kernel-minted `unit`.
#[derive(Default)]
struct Unit {
    mode: Vec<u8>,
    attempt: u32,
    body: Vec<u8>,
    pending: Vec<u8>,
    emitted: u64,
    far_pieces: u32,
    far_answered: bool,
    streamed: bool,
    saw_last: bool,
    pended: bool,
    /// The last answer was `more = 1` from this source: the next piece is its re-call.
    more_from: Option<u32>,
}

struct Inst {
    wake: WakeFn,
    ctx: HostCtx,
    snapshot: Box<PlaneSnapshot>,
    units: Mutex<HashMap<u64, Unit>>,
    /// The caller's target each unit's `arrive` carried, keyed by `unit`: it crosses once.
    heads: Mutex<HashMap<u64, Vec<u8>>>,
    /// The unit each ticket serves, for `cancel`.
    tickets: Mutex<HashMap<Ticket, u64>>,
    stats: [AtomicU64; STATS],
    /// The envelope `drive` answers: valid until the next op on the driver ticket.
    drive_metric: Box<Mutex<MetricEntry>>,
}
// SAFETY: the snapshot's pointers are `'static`; `ctx` is opaque; the wake is callable anywhere.
unsafe impl Send for Inst {}
unsafe impl Sync for Inst {}

impl Inst {
    fn count(&self, s: Stat) {
        self.stats[s as usize].fetch_add(1, Ordering::SeqCst);
    }
    fn wake_later(&'static self, t: Ticket, ms: u64) {
        let (wake, ctx) = (self.wake as usize, self.ctx.ptr as usize);
        self.count(Stat::HostCalls);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(ms));
            // SAFETY: the host's wake, with the context it handed `open`.
            let wake: WakeFn = unsafe { std::mem::transmute::<usize, WakeFn>(wake) };
            wake(
                HostCtx {
                    ptr: ctx as *mut c_void,
                },
                t,
            );
        });
    }
}

unsafe fn say(out: *mut c_void, o: Outcome) -> RawOutcome {
    (*out.cast::<OutHead>()).outcome = RawOutcome::of(o);
    RawOutcome::of(o)
}

unsafe fn inst(instance: *mut c_void) -> &'static Inst {
    &*instance.cast::<Inst>()
}

unsafe fn bytes<'a>(b: Blob) -> &'a [u8] {
    if b.ptr.is_null() || b.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(b.ptr, b.len)
    }
}

unsafe fn text<'a>(s: AbiStr) -> &'a [u8] {
    if s.ptr.is_null() || s.len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(s.ptr, s.len)
    }
}

extern "C" fn ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe { say(out, Outcome::Ready) }
}

extern "C" fn refused(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe { say(out, Outcome::Refused) }
}

extern "C" fn open(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let i = &*input.cast::<PlaneOpenIn>();
        let Some(host) = i.open.host.as_ref() else {
            return say(out, Outcome::Refused);
        };
        let Some(wake) = host.wake else {
            return say(out, Outcome::Refused);
        };
        let snapshot = Box::new(PlaneSnapshot {
            size: std::mem::size_of::<PlaneSnapshot>() as u32,
            _reserved: 0,
            generation: i.open.generation,
            claims: &CLAIMS.0 as *const Claim,
            claims_len: 1,
            admin_routes: std::ptr::null(),
            admin_routes_len: 0,
            openapi: NO_BLOB,
            audience: NO_STR,
            resource_metadata: NO_STR,
        });
        let me = Box::new(Inst {
            wake,
            ctx: host.ctx,
            snapshot,
            units: Mutex::new(HashMap::new()),
            heads: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            stats: Default::default(),
            drive_metric: Box::new(Mutex::new(MetricEntry {
                family_idx: 0,
                kind: METRIC_SET,
                _reserved: [0; 3],
                value: 0.0,
                label_vals: std::ptr::null(),
                label_vals_len: 0,
            })),
        });
        let o = &mut *out.cast::<PlaneOpenOut>();
        o.snapshot = &*me.snapshot as *const PlaneSnapshot;
        o.open.instance = Box::into_raw(me).cast();
        say(out, Outcome::Ready)
    }
}

extern "C" fn close(instance: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        if !instance.is_null() {
            drop(Box::from_raw(instance.cast::<Inst>()));
        }
        say(out, Outcome::Ready)
    }
}

/// `drive`: counts itself, names one ready session when the host's `in` carries the plane's
/// sessions buffer, and reports the count as its envelope gauge. It reads past the lifecycle's
/// `DriveIn` only when the host's `in` says it is a whole `PlaneDriveIn`.
extern "C" fn drive(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        let n = me.stats[Stat::Drives as usize].fetch_add(1, Ordering::SeqCst) + 1;
        let head = &*input.cast::<busbar_contract::abi::mechanism::call::InHead>();
        if head.size as usize >= std::mem::size_of::<PlaneDriveIn>() {
            let i = &*input.cast::<PlaneDriveIn>();
            if i.sessions_cap > 0
                && (*out.cast::<OutHead>()).size as usize >= std::mem::size_of::<PlaneDriveOut>()
            {
                *i.sessions_buf = 7;
                (*out.cast::<PlaneDriveOut>()).sessions_written = 1;
            }
        }
        let mut metric = me.drive_metric.lock().unwrap();
        metric.value = n as f64;
        let o = &mut *out.cast::<OutHead>();
        o.envelope.metrics = &*metric as *const MetricEntry;
        o.envelope.metrics_len = 1;
        say(out, Outcome::Ready)
    }
}

extern "C" fn arrive(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        let i = &*input.cast::<ArriveIn>();
        let o = &mut *out.cast::<ArriveOut>();
        let target = text(i.target);
        me.heads.lock().unwrap().insert(i.unit, target.to_vec());
        let cap = i.units_cap;
        let write = |units: &[UnitCount]| {
            for (k, u) in units.iter().enumerate() {
                *i.units_buf.add(k) = *u;
            }
        };
        let estimate = |amount: u64| UnitCount {
            class: 0,
            source: UNITS_ESTIMATED,
            amount,
        };
        let wants: Vec<UnitCount> = match target {
            b"/refuse" => return say(out, Outcome::Refused),
            b"/short-twice" => {
                o.units_needed = cap as u32 + 1;
                return say(out, Outcome::Failed);
            }
            b"/short" => vec![estimate(1), estimate(2)],
            t if t.starts_with(b"/wake:") => {
                // `/wake:<slot>:<generation>`: wake that ticket (the test's way to wake a driver
                // ticket, which only a plugin can).
                let text = std::str::from_utf8(&t[6..]).unwrap_or("");
                let (slot, generation) = text.split_once(':').unwrap_or(("", ""));
                let ticket = Ticket {
                    slot: slot.parse().unwrap_or(0),
                    generation: generation.parse().unwrap_or(0),
                };
                me.count(Stat::HostCalls);
                (me.wake)(me.ctx, ticket);
                vec![estimate(0)]
            }
            b"/stats" => me
                .stats
                .iter()
                .map(|v| estimate(v.load(Ordering::SeqCst)))
                .collect(),
            _ => vec![estimate(i.body.len as u64)],
        };
        if wants.len() > cap {
            o.units_needed = wants.len() as u32;
            return say(out, Outcome::Failed);
        }
        write(&wants);
        o.units_written = wants.len() as u32;
        o.op_class = 0;
        o.dialect = 0;
        o.principal_need = PRINCIPAL_OPTIONAL;
        say(out, Outcome::Ready)
    }
}

/// Copy `b` into the arena at `at`; its span.
unsafe fn put(i: &OnPieceIn, at: &mut usize, b: &[u8]) -> Span {
    std::ptr::copy_nonoverlapping(b.as_ptr(), i.arena_buf.add(*at), b.len());
    let span = Span {
        offset: *at as u32,
        len: b.len() as u32,
    };
    *at += b.len();
    span
}

extern "C" fn on_piece(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        me.count(Stat::OnPieces);
        let i = &*input.cast::<OnPieceIn>();
        let o = &mut *out.cast::<OnPieceOut>();
        let t = i.head.ticket;
        me.stats[Stat::Unit as usize].store(i.unit, Ordering::SeqCst);
        let Some(head) = me.heads.lock().unwrap().get(&i.unit).cloned() else {
            // A piece of a unit that never arrived: the caller's head is not re-sent.
            return RawOutcome::of(Outcome::Fault);
        };
        me.tickets.lock().unwrap().insert(t, i.unit);
        let mut units = me.units.lock().unwrap();
        let u = units.entry(i.unit).or_default();
        let piece = bytes(i.bytes);
        let resume = i.head.flags & FLAG_RESUME != 0;
        if let Some(from) = u.more_from.take() {
            // The re-call after `more = 1`: the same source, no bytes, no flags.
            if i.from != from || !piece.is_empty() || i.flags != 0 {
                return RawOutcome::of(Outcome::Fault);
            }
        }
        match i.from {
            FROM_KERNEL if i.attempt_no > 0 => {
                *u = Unit {
                    mode: text(i.member).to_vec(),
                    attempt: i.attempt_no,
                    ..Unit::default()
                };
                return say(out, Outcome::Ready);
            }
            FROM_CALLER => {
                u.body.extend_from_slice(piece);
                if i.flags & PIECE_LAST == 0 {
                    return say(out, Outcome::Ready);
                }
                let mut at = 0;
                o.verb = put(i, &mut at, b"POST");
                let target = [b"/far/".as_slice(), &u.mode, &head].concat();
                o.target = put(i, &mut at, &target);
                let name = put(i, &mut at, b"x-attempt");
                let value = put(i, &mut at, u.attempt.to_string().as_bytes());
                *i.fields_buf = OutField { name, value };
                o.fields_written = 1;
                o.arena_written = at as u64;
                let n = u.body.len().min(i.reply_cap);
                std::ptr::copy_nonoverlapping(u.body.as_ptr(), i.reply_buf, n);
                o.emitted = n as u64;
                o.flags = EMIT_TO_FAR_END;
                return say(out, Outcome::Ready);
            }
            _ => {}
        }
        // A far-end piece, or the empty piece that asks for more after `more = 1`.
        let fresh = i.from == FROM_FAR_END && (!piece.is_empty() || i.flags != 0) && !resume;
        if fresh {
            u.far_answered = true;
            u.far_pieces += 1;
            u.saw_last |= i.flags & PIECE_LAST != 0;
            match u.mode.as_slice() {
                b"fault" => return RawOutcome::of(Outcome::Fault),
                b"wedge" => {
                    // A crossing that outlives the watchdog's Stream budget: the host has
                    // answered FAULT long before it re-reads its piece and writes its reply buffer.
                    drop(units);
                    std::thread::sleep(WEDGE);
                    let n = piece.len().min(i.reply_cap);
                    std::ptr::copy(piece.as_ptr(), i.reply_buf, n);
                    return say(out, Outcome::Ready);
                }
                b"hang" | b"cancel-fault" => return say(out, Outcome::Pending),
                b"pend" if !u.pended => {
                    u.pended = true;
                    u.pending.extend_from_slice(piece);
                    me.wake_later(t, 30);
                    return say(out, Outcome::Pending);
                }
                b"retry" => {
                    o.verdict = VERDICT_RETRY;
                    return say(out, Outcome::Ready);
                }
                b"short" if i.units_cap < 12 => {
                    o.units_needed = 12;
                    return say(out, Outcome::Failed);
                }
                b"short-twice" => {
                    o.units_needed = i.units_cap as u32 + 1;
                    return say(out, Outcome::Failed);
                }
                _ => {}
            }
            u.pending.extend_from_slice(piece);
            if u.mode.as_slice() == b"retry-late" && u.far_pieces == 2 {
                o.verdict = VERDICT_RETRY;
            }
        }
        if u.far_pieces == 1 && !u.streamed {
            o.reply_status = if i.flags & PIECE_HAS_STATUS != 0 {
                i.status_code
            } else {
                200
            };
            let mut at = 0;
            let name = put(i, &mut at, b"content-type");
            let value = put(i, &mut at, b"text/plain");
            *i.fields_buf = OutField { name, value };
            o.fields_written = 1;
            o.arena_written = at as u64;
        }
        let n = u.pending.len().min(i.reply_cap);
        std::ptr::copy_nonoverlapping(u.pending.as_ptr(), i.reply_buf, n);
        u.pending.drain(..n);
        u.emitted += n as u64;
        u.streamed |= n > 0;
        o.emitted = n as u64;
        o.more = u32::from(!u.pending.is_empty() && n > 0);
        u.more_from = (o.more == 1).then_some(i.from);
        let wide = if u.mode.starts_with(b"short") { 12 } else { 1 };
        for k in 0..wide {
            *i.units_buf.add(k) = UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: u.emitted,
            };
        }
        o.units_written = wide as u32;
        if u.saw_last && u.pending.is_empty() {
            o.flags = EMIT_DONE;
            o.verdict = 0;
        }
        say(out, Outcome::Ready)
    }
}

extern "C" fn refusal(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let i = &*input.cast::<RefusalIn>();
        let o = &mut *out.cast::<RefusalOut>();
        let body = [
            b"refused:".as_slice(),
            i.status.to_string().as_bytes(),
            b":",
            text(i.text),
        ]
        .concat();
        let (name, value) = (b"content-type".as_slice(), b"text/plain".as_slice());
        let arena = name.len() + value.len();
        if body.len() > i.reply_cap || i.fields_cap < 1 || arena > i.arena_cap {
            o.reply_needed = body.len() as u64;
            o.fields_needed = 1;
            o.arena_needed = arena as u64;
            return say(out, Outcome::Failed);
        }
        std::ptr::copy_nonoverlapping(body.as_ptr(), i.reply_buf, body.len());
        o.reply_written = body.len() as u64;
        std::ptr::copy_nonoverlapping(name.as_ptr(), i.arena_buf, name.len());
        std::ptr::copy_nonoverlapping(value.as_ptr(), i.arena_buf.add(name.len()), value.len());
        *i.fields_buf = OutField {
            name: Span {
                offset: 0,
                len: name.len() as u32,
            },
            value: Span {
                offset: name.len() as u32,
                len: value.len() as u32,
            },
        };
        o.fields_written = 1;
        o.arena_written = arena as u64;
        say(out, Outcome::Ready)
    }
}

extern "C" fn cancel(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        me.count(Stat::Cancels);
        // No thread-local of this image is touched on a host thread: a dropped image's
        // thread-local destructors would outlive it on the dispatcher's workers.
        let cancel_in = &*input.cast::<CancelIn>();
        if cancel_in.head.deadline_class == DeadlineClass::Stream as u8 {
            me.count(Stat::CancelsOnWorker);
        }
        let t = cancel_in.ticket;
        let unit = me.tickets.lock().unwrap().remove(&t);
        let u = unit
            .and_then(|k| me.units.lock().unwrap().remove(&k))
            .unwrap_or_default();
        let last = &me.stats[Stat::LastDisposition as usize];
        if u.mode.as_slice() == b"cancel-fault" {
            last.store(0, Ordering::SeqCst);
            return RawOutcome::of(Outcome::Fault);
        }
        let d = if u.streamed {
            CANCEL_OK_PARTIAL
        } else if u.far_answered {
            CANCEL_FAILED
        } else {
            CANCEL_ABORTED
        };
        last.store(u64::from(d), Ordering::SeqCst);
        (*out.cast::<CancelOut>()).disposition = d;
        say(out, Outcome::Ready)
    }
}
