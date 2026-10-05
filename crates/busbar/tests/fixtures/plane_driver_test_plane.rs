// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DRIVER'S TEST PLANE — one source, compiled into the test build (the LINKED door) and
//! built as the `plane_driver_test_plane` example `cdylib` (the DROPPED door).
//!
//! It exports the one door over the plane table and defines no ABI shape of its own. What it does
//! with a unit is chosen by the member name the kernel hands its ATTEMPT piece (`ok`, `retry`,
//! `retry-late`, `pend`, `hang`, `wedge`, `fault`, `cancel-fault`, `short`, `short-twice`), and `arrive`
//! reacts to the request target (`/short`, `/short-twice`, `/refuse`, `/stats`, `/clock`). A unit
//! on `/call/local` answers its caller itself (an echo of the body); a unit on `/call/nest:<target>`
//! runs `POST <target>` as a NESTED unit through the host's `unit.nest` and answers its caller
//! `nested:<status>:<the child's body>` (`nest-refused:<reason>` when the host refused it); a unit on
//! `/call/services` passes its body through the host's `content.scan`, `hook.call` (a gate, then a
//! rewrite) and `verify.lookup` (keyed by the body), and answers `<op>=<value>` (or
//! `<op>!<reason>`) for each, space-separated. Its far-end
//! answer echoes the far end's bytes, in pieces of at most `reply_cap` (`more = 1` for the rest),
//! with cumulative far-end-reported units = the bytes emitted so far.
//!
//! It counts its own crossings and every call it makes into the host tables; `arrive` on `/stats`
//! answers the counters as unit amounts, in [`Stat`] order, so a linked and a dropped instance
//! report through the same table.
//!
//! Its `tick` asks for the next tick `/tick-every:<ms>` after the one it ran (`0`, the default, asks
//! for none); after `/tick-read` its next `tick` ESTABLISHes its one need and READs it on the
//! ticket `tick` was handed (a READ that pends makes that `tick` answer PENDING), and a `drive`
//! reads that stream again on its driver ticket. `/ticks`
//! answers the tick counters, in [`Ticked`] order.
//!
//! A DUPLEX SESSION's pieces (those with a stream) are answered by [`session_piece`]: a caller piece
//! `far:<x>` is bound for the far end (`POST /far/turn`, body `x`), `push:<x>` is held as the
//! session's unsolicited output and the instance's driver ticket woken (its `drive` then names the
//! session, and the collection `FROM_KERNEL` answers `x`), any other piece is echoed `echo:<x>`, and
//! the caller's last piece ends the reply. A far-end piece is answered `far-said:<x>`. `/sessions`
//! answers the session counters, in [`Sessions`] order.

#![allow(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use busbar_contract::abi::hook::{MessageView, PromptView};
use busbar_contract::abi::host::conn::connector::{
    service, ConnectorSlots, EstablishIn, IoIn, Need, DIRECTION_OUTBOUND,
};
use busbar_contract::abi::host::service::{
    op as service_op, ClockNowIn, ClockReading, ContentScanIn, HookCallIn, HostSlots, ItemSpan,
    ServiceBufs, ServiceFn, ServiceHead, ServiceOut, UnitNestIn, VerifyLookupIn, HOOK_GATE,
    HOOK_REWRITE,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, OutHead, Outcome, RawOutcome, Span, BLOB_ABSENT, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::call::{MetricEntry, METRIC_SET};
use busbar_contract::abi::mechanism::door::{
    Door, KindTailHead, MetricFamily, Section, Statement, FAMILY_GAUGE, SECTION_DECLARING,
};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, OpsHead, TickIn, TickOut, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, HostCtx, Ticket, WakeFn};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    AdminRoute, ArriveIn, ArriveOut, BillableClass, Claim, OnPieceIn, OnPieceOut, OpClass, Ops,
    OutField, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneSnapshot, PlaneTail,
    ProjectOut, RefusalIn, RefusalOut, RefusalStatus, ServeIn, ServeOut, UnitCount, AUDIT_APPLIED,
    AUDIT_NONE, AUDIT_REJECTED, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL, CLAIM_EXACT,
    CLAIM_OPEN, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE, INGRESS_RESPONSE_STREAM, PIECE_FIELDS,
    PIECE_HAS_STATUS, PIECE_LAST, PIECE_OUT_TEXT, PRINCIPAL_OPTIONAL, REFUSAL_ANY_DIALECT,
    ROUTE_DIRECT, ROUTE_POOL, ROUTE_PUBLIC, SHAPE_WHOLE, SPAN_ABSENT, UNITS_ESTIMATED,
    UNITS_REPORTED, VERDICT_RETRY,
};

/// The plane's own refusal code and the status `/clock` refuses with when the host will not read
/// its clock (`/refuse` is 7, `/post-only` is 9).
const CLOCK_REFUSED: (u32, u32) = (8, 403);

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

/// The counters `/ticks` answers, in this order.
#[derive(Debug, Clone, Copy)]
pub enum Ticked {
    /// `tick` crossings.
    Ticks = 0,
    /// The ticket the last `tick` was handed, `slot << 32 | generation` (`0` = none).
    Ticket = 1,
    /// `tick`s that came before the `next_tick_ns` the previous one asked for.
    Early = 2,
    /// READs inside `tick` that answered PENDING.
    ReadPended = 3,
    /// The bytes a `drive` read from the stream a `tick` left pending.
    DriveRead = 4,
    /// The `next_tick_ns` the last `tick` asked for.
    Next = 5,
}
/// How many counters `/ticks` answers.
pub const TICKED: usize = 6;

/// The counters `/sessions` answers, in this order.
#[derive(Debug, Clone, Copy)]
pub enum Sessions {
    /// The distinct tickets the last session's pieces crossed on.
    Tickets = 0,
    /// Collections of unsolicited output (`FROM_KERNEL`, no attempt).
    Collects = 1,
    /// ATTEMPT pieces of a session's turn legs.
    Attempts = 2,
}
/// How many counters `/sessions` answers.
pub const SESSIONS: usize = 3;

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
/// Twelve billable classes: the check refuses a class counted twice, so a report of several counts
/// (the short-buffer cases, `/stats`) names a distinct class for each.
static CLASSES: Shared<[BillableClass; 12]> = Shared([
    BillableClass {
        class: s(b"bytes"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c1"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c2"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c3"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c4"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c5"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c6"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c7"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c8"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c9"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c10"),
        family: s(b"bytes"),
    },
    BillableClass {
        class: s(b"c11"),
        family: s(b"bytes"),
    },
]);

/// The statuses its refusals wear where they are not the kernel's defaults (`plane_driver_cases`'s
/// `STATUSES`): `revoked` (code 14) is 403 in its one dialect and 451 in any other, and
/// `scope_denied` (code 15) is 404 in every dialect.
static STATUSES: Shared<[RefusalStatus; 3]> = Shared([
    RefusalStatus {
        dialect: 0,
        reason: 14,
        status: 403,
        _reserved: 0,
    },
    RefusalStatus {
        dialect: REFUSAL_ANY_DIALECT,
        reason: 14,
        status: 451,
        _reserved: 0,
    },
    RefusalStatus {
        dialect: REFUSAL_ANY_DIALECT,
        reason: 15,
        status: 404,
        _reserved: 0,
    },
]);

static TAIL: Shared<PlaneTail> = Shared(PlaneTail {
    head: KindTailHead {
        size: std::mem::size_of::<PlaneTail>() as u32,
        _reserved: 0,
    },
    flags: 0,
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_RESPONSE_STREAM | INGRESS_DUPLEX_SESSION,
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
    dialects: &DIALECTS.0 as *const AbiStr,
    dialects_len: 1,
    dialect_auth: std::ptr::null(),
    dialect_auth_len: 0,
    scope_kinds: std::ptr::null(),
    scope_kinds_len: 0,
    op_classes: &OP_CLASSES.0 as *const OpClass,
    op_classes_len: 1,
    billable_classes: &CLASSES.0 as *const BillableClass,
    billable_classes_len: 12,
    route_cost: std::ptr::null(),
    route_cost_len: 0,
    fee_units: std::ptr::null(),
    fee_units_len: 0,
    record_kinds: std::ptr::null(),
    record_kinds_len: 0,
    egress_targets: std::ptr::null(),
    egress_targets_len: 0,
    record_chains: std::ptr::null(),
    record_chains_len: 0,
    trust_keys: std::ptr::null(),
    trust_keys_len: 0,
    refusal_statuses: &STATUSES.0 as *const RefusalStatus,
    refusal_statuses_len: 3,
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
    marks: 0,
    mark_words: std::ptr::null(),
    mark_words_len: 0,
    rewrites: std::ptr::null(),
    rewrites_len: 0,
    sections: &SECTIONS.0 as *const Section,
    sections_len: 1,
    needs: &NEEDS.0 as *const Need,
    needs_len: 1,
    target_from: NO_STR,
    trust_from: NO_STR,
    answers: std::ptr::null(),
    answers_len: 0,
    claims: std::ptr::null(),
    claims_len: 0,
});

/// Its one outbound need: handed the host's connection slots only where the host binds a table.
static NEEDS: Shared<[Need; 1]> = Shared([Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: s(b"sock"),
    auth: NO_STR,
    target_from: NO_STR,
    trust_from: NO_STR,
    details: NO_BLOB,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}]);

static OPS: Shared<Ops> = Shared(Ops {
    head: OpsHead {
        size: std::mem::size_of::<Ops>() as u32,
        slots: LIFECYCLE_SLOTS + busbar_contract::abi::plane::KIND_SLOTS,
        validate: Some(ready),
        open: Some(open),
        refresh: Some(ready),
        retire: Some(ready),
        tick: Some(tick),
        drive: Some(drive),
        cancel: Some(cancel),
        release: Some(ready),
        close: Some(close),
    },
    arrive: Some(arrive),
    on_piece: Some(on_piece),
    refusal: Some(refusal),
    serve: Some(serve),
    hydrate: Some(ready),
    start: Some(ready),
    project: Some(project),
});

static DOOR: Shared<Door> = Shared(Door {
    magic: DOOR_MAGIC,
    mechanism_version: MECHANISM_VERSION,
    size: std::mem::size_of::<Door>() as u32,
    kind: KindCode::Plane as u32,
    kind_abi: KindCode::Plane.abi_version(),
    statement: &STATEMENT.0 as *const Statement,
    ops: &OPS.0 as *const Ops as *const OpsHead,
    ready: None,
});

/// The claims: every path under `/call` for POST, and `/open`, a claim that takes no inbound
/// credential (an anonymous unit, never billed).
static CLAIMS: Shared<[Claim; 2]> = Shared([
    Claim {
        verb: s(b"POST"),
        target: s(b"/call"),
        carrier: s(b"inbound"),
        flags: 0,
        refusal_dialect: 0,
        _pad: 0,
    },
    Claim {
        verb: s(b"POST"),
        target: s(b"/open"),
        carrier: s(b"inbound"),
        flags: CLAIM_OPEN | CLAIM_EXACT,
        refusal_dialect: 0,
        _pad: 0,
    },
]);

/// The admin routes the snapshot publishes, served through `serve`: an audited admin route, and a
/// public one the kernel's admin table never serves.
static ADMIN_ROUTES: Shared<[AdminRoute; 2]> = Shared([
    AdminRoute {
        verb: s(b"POST"),
        target: s(b"/items/{name}/act"),
        flags: 0,
        _reserved: 0,
        audit_verb: s(b"act"),
    },
    AdminRoute {
        verb: s(b"POST"),
        target: s(b"/items/{name}/hook"),
        flags: ROUTE_PUBLIC,
        _reserved: 0,
        audit_verb: NO_STR,
    },
]);

/// The reply bytes a `short` request needs: past the kernel's default reply buffer, so the first
/// answer is short and the one re-call is served.
const SHORT_REPLY: usize = 1 << 20;

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
    /// The host's service table, as `open` was handed it (`/clock` reads its `clock.now`).
    services: *const HostSlots,
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
    /// The host's connection slots (NULL without a table).
    conns: *const ConnectorSlots,
    /// The period `tick` asks for, in ms (`0` = no next tick).
    tick_every_ms: AtomicU64,
    /// The next `tick` reads its need.
    tick_read: AtomicBool,
    /// The stream a `tick`'s READ left pending (`0` = none).
    stream: AtomicU64,
    ticked: [AtomicU64; TICKED],
    /// The instance's driver ticket, as its last `tick` was handed it.
    driver: Mutex<Ticket>,
    /// Each session's unsolicited output, until it is collected.
    outbox: Mutex<HashMap<u64, Vec<u8>>>,
    /// The tickets each session's pieces crossed on.
    session_tickets: Mutex<HashMap<u64, Vec<Ticket>>>,
    sessions: [AtomicU64; SESSIONS],
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

/// `project`: an empty view (no pool, no dialect, no prompt turn, nothing rewritten), so a unit a
/// hook binds is read and its hooks see the shape only.
extern "C" fn project(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let o = &mut *out.cast::<ProjectOut>();
        let absent = Span {
            offset: SPAN_ABSENT,
            len: 0,
        };
        o.body = absent;
        o.rewritten = absent;
        say(out, Outcome::Ready)
    }
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
            claims_len: 2,
            admin_routes: ADMIN_ROUTES.0.as_ptr(),
            admin_routes_len: ADMIN_ROUTES.0.len(),
            openapi: NO_BLOB,
            audience: NO_STR,
            resource_metadata: NO_STR,
        });
        let me = Box::new(Inst {
            wake,
            services: host.services,
            ctx: host.ctx,
            snapshot,
            units: Mutex::new(HashMap::new()),
            heads: Mutex::new(HashMap::new()),
            tickets: Mutex::new(HashMap::new()),
            stats: Default::default(),
            conns: host.conns,
            tick_every_ms: AtomicU64::new(0),
            tick_read: AtomicBool::new(false),
            stream: AtomicU64::new(0),
            ticked: Default::default(),
            driver: Mutex::new(Ticket::NONE),
            outbox: Mutex::new(HashMap::new()),
            session_tickets: Mutex::new(HashMap::new()),
            sessions: Default::default(),
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
        // The stream a `tick` left pending: read again, on the driver ticket.
        let stream = me.stream.load(Ordering::SeqCst);
        if stream != 0 {
            let driver = (*input.cast::<DriveIn>()).driver;
            if let Some(len) = read(me, driver, stream) {
                me.ticked[Ticked::DriveRead as usize].store(len, Ordering::SeqCst);
                me.stream.store(0, Ordering::SeqCst);
            }
        }
        let head = &*input.cast::<busbar_contract::abi::mechanism::call::InHead>();
        if head.size as usize >= std::mem::size_of::<PlaneDriveIn>() {
            let i = &*input.cast::<PlaneDriveIn>();
            if (*out.cast::<OutHead>()).size as usize >= std::mem::size_of::<PlaneDriveOut>() {
                // The sessions with output held, as many as the host's buffer takes.
                let outbox = me.outbox.lock().unwrap();
                let ready = outbox.iter().filter(|(_, held)| !held.is_empty());
                let mut named = 0;
                for (stream, _) in ready.take(i.sessions_cap) {
                    *i.sessions_buf.add(named) = *stream;
                    named += 1;
                }
                (*out.cast::<PlaneDriveOut>()).sessions_written = named as u32;
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
        let estimate = |class: u32, amount: u64| UnitCount {
            class,
            source: UNITS_ESTIMATED,
            amount,
        };
        let wants: Vec<UnitCount> = match target {
            // A path that takes POST only: another method is the plane's own 405.
            b"/post-only" if text(i.method) != b"POST" => {
                o.refusal = 9;
                o.refusal_status = 405;
                return say(out, Outcome::Refused);
            }
            b"/refuse" => {
                // The plane's own decode refusal: its code, and the 4xx it wears.
                o.refusal = 7;
                o.refusal_status = 404;
                return say(out, Outcome::Refused);
            }
            b"/short-twice" => {
                o.units_needed = cap as u32 + 1;
                return say(out, Outcome::Failed);
            }
            b"/short" => vec![estimate(0, 1), estimate(1, 2)],
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
                vec![estimate(0, 0)]
            }
            b"/clock" => {
                // The host's own clock, through its service table: the reading, as two amounts. A
                // clock the host would not read (no table, no slot, not READY) refuses the arrival,
                // and like every REFUSED arrive it names the plane's own code and a 4xx status.
                me.count(Stat::HostCalls);
                let Some(now) = me.services.as_ref().and_then(|t| t.clock_now) else {
                    (o.refusal, o.refusal_status) = CLOCK_REFUSED;
                    return say(out, Outcome::Refused);
                };
                let mut reading = ClockReading {
                    size: std::mem::size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    wall_ns: 0,
                    mono_ns: 0,
                };
                let call = ClockNowIn {
                    head: ServiceHead {
                        size: std::mem::size_of::<ClockNowIn>() as u32,
                        op: service_op::CLOCK_NOW,
                        handle: CompletionHandle {
                            ticket: Ticket::NONE,
                            seq: 0,
                            _reserved: 0,
                        },
                    },
                    reading: &mut reading,
                };
                let mut answer = std::mem::zeroed::<ServiceOut>();
                if now(me.ctx, (&call as *const ClockNowIn).cast(), &mut answer).outcome()
                    != Outcome::Ready
                {
                    (o.refusal, o.refusal_status) = CLOCK_REFUSED;
                    return say(out, Outcome::Refused);
                }
                vec![estimate(0, reading.wall_ns), estimate(1, reading.mono_ns)]
            }
            b"/sessions" => me
                .sessions
                .iter()
                .enumerate()
                .map(|(k, v)| estimate(k as u32, v.load(Ordering::SeqCst)))
                .collect(),
            b"/ticks" => me
                .ticked
                .iter()
                .enumerate()
                .map(|(k, v)| estimate(k as u32, v.load(Ordering::SeqCst)))
                .collect(),
            b"/tick-read" => {
                me.tick_read.store(true, Ordering::SeqCst);
                vec![estimate(0, 0)]
            }
            t if t.starts_with(b"/tick-every:") => {
                let ms = std::str::from_utf8(&t[12..])
                    .unwrap_or("")
                    .parse()
                    .unwrap_or(0);
                me.tick_every_ms.store(ms, Ordering::SeqCst);
                vec![estimate(0, ms)]
            }
            t if t == b"/call/local" || t == b"/call/services" || t.starts_with(b"/call/nest:") => {
                // A local answer, or a nesting unit: each routes directly over the section's `m`.
                o.route = ROUTE_DIRECT;
                o.pool = AbiStr {
                    ptr: b"m".as_ptr(),
                    len: 1,
                };
                vec![estimate(0, i.body.len as u64)]
            }
            b"/open" => {
                // The open claim routes directly over the section's `m`.
                o.route = ROUTE_DIRECT;
                o.pool = AbiStr {
                    ptr: b"m".as_ptr(),
                    len: 1,
                };
                vec![estimate(0, i.body.len as u64)]
            }
            t if t.starts_with(b"/call/pool:") || t.starts_with(b"/call/direct:") => {
                // The route the target names (ARCHITECT Q-SW6/Q-FL3): `pool:<pool>` or
                // `direct:<entry>`; the name in plane memory that outlives the call, as an
                // answer's string must.
                let (class, at) = if t.starts_with(b"/call/pool:") {
                    (ROUTE_POOL, 11)
                } else {
                    (ROUTE_DIRECT, 13)
                };
                let name: &'static [u8] = Box::leak(t[at..].to_vec().into_boxed_slice());
                o.route = class;
                o.pool = AbiStr {
                    ptr: name.as_ptr(),
                    len: name.len(),
                };
                vec![estimate(0, i.body.len as u64)]
            }
            b"/stats" => me
                .stats
                .iter()
                .enumerate()
                .map(|(k, v)| estimate(k as u32, v.load(Ordering::SeqCst)))
                .collect(),
            _ => vec![estimate(0, i.body.len as u64)],
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
        if i.stream != 0 {
            return session_piece(me, i, o, t, out);
        }
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
                // A resumed crossing re-reads the piece it pended on: the body already holds it.
                if !resume {
                    u.body.extend_from_slice(piece);
                }
                if i.flags & PIECE_LAST == 0 {
                    return say(out, Outcome::Ready);
                }
                if let Some(child) = head.strip_prefix(b"/call/nest:") {
                    // A NESTED UNIT through the host's `unit.nest`, on the unit's own ticket; a
                    // PENDING answer pends this crossing, and the resumed crossing re-issues the
                    // same handle and reads the child's stored reply.
                    let reply = match nest(me, t, child, &u.body) {
                        None => return say(out, Outcome::Pending),
                        Some(reply) => reply,
                    };
                    o.reply_status = 200;
                    let n = reply.len().min(i.reply_cap);
                    std::ptr::copy_nonoverlapping(reply.as_ptr(), i.reply_buf, n);
                    o.emitted = n as u64;
                    o.flags = EMIT_DONE;
                    return say(out, Outcome::Ready);
                }
                if head.as_slice() == b"/call/services" {
                    // The in-session services, each on the unit's own ticket under its own handle;
                    // one that pends pends this crossing, and the resumed crossing re-issues every
                    // handle and reads what each stored.
                    let Some(reply) = in_session(me, t, &u.body) else {
                        return say(out, Outcome::Pending);
                    };
                    o.reply_status = 200;
                    let n = reply.len().min(i.reply_cap);
                    std::ptr::copy_nonoverlapping(reply.as_ptr(), i.reply_buf, n);
                    o.emitted = n as u64;
                    o.flags = EMIT_DONE;
                    return say(out, Outcome::Ready);
                }
                if head.as_slice() == b"/local" || head.as_slice() == b"/call/local" {
                    // A LOCAL ANSWER: the plane answers the caller itself (an echo of the body),
                    // with nothing for the far end.
                    o.reply_status = 200;
                    let n = u.body.len().min(i.reply_cap);
                    std::ptr::copy_nonoverlapping(u.body.as_ptr(), i.reply_buf, n);
                    o.emitted = n as u64;
                    o.flags = EMIT_DONE;
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
            if i.flags & PIECE_FIELDS == 0 {
                u.pending.extend_from_slice(piece);
            } else if u.mode.as_slice() == b"trailers" {
                // A plane that reads the far end's trailers.
                u.pending.push(b'[');
                u.pending.extend_from_slice(piece);
                u.pending.push(b']');
            }
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
                class: k as u32,
                source: UNITS_REPORTED,
                amount: u.emitted,
            };
        }
        o.units_written = wide as u32;
        if u.saw_last && u.pending.is_empty() {
            o.flags = EMIT_DONE;
            o.verdict = 0;
        }
        // A plane whose emitted messages are text (mode `text`): each whole message says so.
        if u.mode.as_slice() == b"text" && o.emitted > 0 && o.more == 0 {
            o.flags |= PIECE_OUT_TEXT;
        }
        say(out, Outcome::Ready)
    }
}

/// `POST <child>` as a nested unit of the unit on ticket `t`, through the host's `unit.nest`:
/// `None` while it pends; then `nested:<status>:<body>`, or `nest-refused:<reason>`.
unsafe fn nest(me: &'static Inst, t: Ticket, child: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    me.count(Stat::HostCalls);
    let Some(slot) = me.services.as_ref().and_then(|table| table.unit_nest) else {
        return Some(b"nest-refused:unserved".to_vec());
    };
    let mut buf = vec![0u8; 1 << 16];
    let blank = ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    };
    let mut spans = [blank; 32];
    let call = UnitNestIn {
        head: ServiceHead {
            size: std::mem::size_of::<UnitNestIn>() as u32,
            op: service_op::UNIT_NEST,
            handle: CompletionHandle {
                ticket: t,
                seq: 0,
                _reserved: 0,
            },
        },
        verb: s(b"POST"),
        target: AbiStr {
            ptr: child.as_ptr(),
            len: child.len(),
        },
        body: Blob {
            ptr: body.as_ptr(),
            len: body.len(),
            fmt: 0,
            flags: 0,
        },
        into: ServiceBufs {
            buf: buf.as_mut_ptr(),
            cap: buf.len(),
            spans: spans.as_mut_ptr(),
            spans_cap: spans.len(),
        },
    };
    let mut answer = std::mem::zeroed::<ServiceOut>();
    match slot(me.ctx, (&call as *const UnitNestIn).cast(), &mut answer).outcome() {
        Outcome::Pending => None,
        Outcome::Ready => {
            let first = spans[0].value;
            let at = first.offset as usize;
            let child_body = &buf[at..at + first.len as usize];
            Some([format!("nested:{}:", answer.value).as_bytes(), child_body].concat())
        }
        _ => {
            let why = if answer.error.ptr.is_null() {
                &[][..]
            } else {
                std::slice::from_raw_parts(answer.error.ptr, answer.error.len)
            };
            Some([b"nest-refused:".as_slice(), why].concat())
        }
    }
}

/// `content.scan`, `hook.call` (gate, rewrite) and `verify.lookup` over `body`, on ticket `t`
/// (handles `0..4`): `None` while one pends; then each one's `<op>=<value>` or `<op>!<reason>`.
unsafe fn in_session(me: &'static Inst, t: Ticket, body: &[u8]) -> Option<Vec<u8>> {
    let Some(table) = me.services.as_ref() else {
        return Some(b"unserved".to_vec());
    };
    let head = |op: u32, size: usize, seq: u32| ServiceHead {
        size: size as u32,
        op,
        handle: CompletionHandle {
            ticket: t,
            seq,
            _reserved: 0,
        },
    };
    let mut buf = vec![0u8; 1 << 12];
    let blank = ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    };
    let mut spans = [blank; 4];
    let mut into = || ServiceBufs {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
    };
    let blob = Blob {
        ptr: body.as_ptr(),
        len: body.len(),
        fmt: 0,
        flags: 0,
    };
    let message = MessageView {
        role: s(b"user"),
        text: AbiStr {
            ptr: body.as_ptr(),
            len: body.len(),
        },
    };
    let prompt = PromptView {
        system: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        message_count: 1,
        body: Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        },
        messages: &message,
        messages_len: 1,
    };
    let scan = ContentScanIn {
        head: head(
            service_op::CONTENT_SCAN,
            std::mem::size_of::<ContentScanIn>(),
            0,
        ),
        content: blob,
        into: into(),
    };
    let hook = |stage: u32, seq: u32, into: ServiceBufs| HookCallIn {
        head: head(
            service_op::HOOK_CALL,
            std::mem::size_of::<HookCallIn>(),
            seq,
        ),
        stage,
        from: 0,
        prompt: &prompt,
        into,
    };
    let gate = hook(HOOK_GATE, 1, into());
    let rewrite = hook(HOOK_REWRITE, 2, into());
    let verify = VerifyLookupIn {
        head: head(
            service_op::VERIFY_LOOKUP,
            std::mem::size_of::<VerifyLookupIn>(),
            3,
        ),
        key: AbiStr {
            ptr: body.as_ptr(),
            len: body.len(),
        },
        into: into(),
    };
    let calls: [(&str, Option<ServiceFn>, *const c_void); 4] = [
        (
            "scan",
            table.content_scan,
            (&scan as *const ContentScanIn).cast(),
        ),
        ("gate", table.hook_call, (&gate as *const HookCallIn).cast()),
        (
            "rewrite",
            table.hook_call,
            (&rewrite as *const HookCallIn).cast(),
        ),
        (
            "verify",
            table.verify_lookup,
            (&verify as *const VerifyLookupIn).cast(),
        ),
    ];
    let mut said = Vec::new();
    let mut pending = false;
    for (name, slot, input) in calls {
        me.count(Stat::HostCalls);
        let Some(slot) = slot else {
            said.push(format!("{name}!unserved"));
            continue;
        };
        let mut answer = std::mem::zeroed::<ServiceOut>();
        match slot(me.ctx, input, &mut answer).outcome() {
            Outcome::Pending => pending = true,
            Outcome::Ready => said.push(format!("{name}={}", answer.value)),
            _ => {
                let why = if answer.error.ptr.is_null() {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(answer.error.ptr, answer.error.len)
                };
                said.push(format!("{name}!{}", String::from_utf8_lossy(why)));
            }
        }
    }
    (!pending).then(|| said.join(" ").into_bytes())
}

/// Emit `b` toward the caller (or, with [`EMIT_TO_FAR_END`], toward the far end), cut to the reply
/// buffer.
unsafe fn emit(i: &OnPieceIn, o: &mut OnPieceOut, b: &[u8]) {
    let n = b.len().min(i.reply_cap);
    std::ptr::copy_nonoverlapping(b.as_ptr(), i.reply_buf, n);
    o.emitted = n as u64;
}

/// One piece of a duplex session (see the module's documentation).
unsafe fn session_piece(
    me: &'static Inst,
    i: &OnPieceIn,
    o: &mut OnPieceOut,
    t: Ticket,
    out: *mut c_void,
) -> RawOutcome {
    {
        let mut seen = me.session_tickets.lock().unwrap();
        let tickets = seen.entry(i.stream).or_default();
        if !tickets.contains(&t) {
            tickets.push(t);
        }
        let n = tickets.len() as u64;
        me.sessions[Sessions::Tickets as usize].store(n, Ordering::SeqCst);
    }
    let count = |c: Sessions| me.sessions[c as usize].fetch_add(1, Ordering::SeqCst);
    let piece = bytes(i.bytes);
    match i.from {
        FROM_KERNEL if i.attempt_no > 0 => {
            count(Sessions::Attempts);
        }
        FROM_KERNEL => {
            count(Sessions::Collects);
            let held = me
                .outbox
                .lock()
                .unwrap()
                .remove(&i.stream)
                .unwrap_or_default();
            emit(i, o, &held);
        }
        FROM_CALLER if i.flags & PIECE_LAST != 0 => o.flags = EMIT_DONE,
        FROM_CALLER => {
            if let Some(body) = piece.strip_prefix(b"far:") {
                let mut at = 0;
                o.verb = put(i, &mut at, b"POST");
                o.target = put(i, &mut at, b"/far/turn");
                o.arena_written = at as u64;
                emit(i, o, body);
                o.flags = EMIT_TO_FAR_END;
            } else if let Some(held) = piece.strip_prefix(b"push:") {
                let mut outbox = me.outbox.lock().unwrap();
                outbox.entry(i.stream).or_default().extend_from_slice(held);
                drop(outbox);
                me.count(Stat::HostCalls);
                (me.wake)(me.ctx, *me.driver.lock().unwrap());
            } else {
                emit(i, o, &[b"echo:".as_slice(), piece].concat());
            }
        }
        _ => {
            emit(i, o, &[b"far-said:".as_slice(), piece].concat());
            *i.units_buf = UnitCount {
                class: 0,
                source: UNITS_REPORTED,
                amount: o.emitted,
            };
            o.units_written = 1;
            if i.flags & PIECE_LAST != 0 {
                o.flags = EMIT_DONE;
            }
        }
    }
    say(out, Outcome::Ready)
}

extern "C" fn refusal(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let i = &*input.cast::<RefusalIn>();
        let o = &mut *out.cast::<RefusalOut>();
        // The reason crosses beside its text: a refusal whose code names another reason is FAULT.
        let named = busbar_contract::abi::plane::reason_of(i.reason).map(|r| r.as_str().as_bytes());
        if named != Some(text(i.text)) {
            return RawOutcome::of(Outcome::Fault);
        }
        let mut body = [
            b"refused:".as_slice(),
            i.status.to_string().as_bytes(),
            b":",
            text(i.text),
        ]
        .concat();
        // The target crosses beside every refusal (one may precede `arrive`): this plane names it
        // when the target asks.
        let target = text(i.target);
        if target == b"/target-echo" {
            body.extend_from_slice(b" for ");
            body.extend_from_slice(target);
        }
        // A Retry-After the kernel hands (the walk's exhaustion terminal): this plane names it.
        if i.retry_after_s != 0 {
            body.extend_from_slice(format!(":retry={}", i.retry_after_s).as_bytes());
        }
        if i.plane_code != 0 {
            body.extend_from_slice(format!(":{}@{}", i.plane_code, i.unit).as_bytes());
        }
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

/// `serve`, route 0 only. The body chooses the answer: `malformed` is 400 and unaudited,
/// `disagree` is 400 and audited `rejected`, `bad-audit` reports an unknown audit code, `short`
/// answers short once, `short-twice` on every call; anything else is 200 and audited `applied`.
/// The reply names the target and the head field names the plane was handed.
extern "C" fn serve(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let i = &*input.cast::<ServeIn>();
        let o = &mut *out.cast::<ServeOut>();
        if i.route != 0 {
            return say(out, Outcome::Refused);
        }
        let body = bytes(i.body);
        let (status, audit) = match body {
            b"malformed" => (400, AUDIT_NONE),
            b"disagree" => (400, AUDIT_REJECTED),
            b"bad-audit" => (200, AUDIT_REJECTED + 1),
            _ => (200, AUDIT_APPLIED),
        };
        let fields = if i.fields_len == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(i.fields, i.fields_len)
        };
        let names: Vec<&[u8]> = fields.iter().map(|f| text(f.name)).collect();
        let mut reply = [
            b"served ".as_slice(),
            text(i.target),
            b" fields=",
            names.join(&b","[..]).as_slice(),
        ]
        .concat();
        let need = match body {
            b"short" => SHORT_REPLY,
            b"short-twice" => i.reply_cap + 1,
            _ => reply.len(),
        };
        let (name, value) = (b"content-type".as_slice(), b"text/plain".as_slice());
        let arena = name.len() + value.len();
        if need > i.reply_cap || i.fields_cap < 1 || arena > i.arena_cap {
            o.reply_needed = need as u64;
            o.fields_needed = 1;
            o.arena_needed = arena as u64;
            return say(out, Outcome::Failed);
        }
        reply.truncate(i.reply_cap);
        std::ptr::copy_nonoverlapping(reply.as_ptr(), i.reply_buf, reply.len());
        o.reply_written = reply.len() as u64;
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
        o.status = status;
        o.audit = audit;
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

/// `tick`: counts itself, notes its ticket and whether it came early, runs a pending `/tick-read`,
/// and asks for the next tick `tick_every_ms` on.
extern "C" fn tick(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    unsafe {
        let me = inst(instance);
        let i = &*input.cast::<TickIn>();
        let t = i.head.ticket;
        *me.driver.lock().unwrap() = t;
        let n = |c: Ticked| &me.ticked[c as usize];
        n(Ticked::Ticks).fetch_add(1, Ordering::SeqCst);
        n(Ticked::Ticket).store(
            (u64::from(t.slot) << 32) | u64::from(t.generation),
            Ordering::SeqCst,
        );
        if i.now_ns < n(Ticked::Next).load(Ordering::SeqCst) {
            n(Ticked::Early).fetch_add(1, Ordering::SeqCst);
        }
        let pended = me.tick_read.swap(false, Ordering::SeqCst) && establish_and_read(me, t);
        let every = me.tick_every_ms.load(Ordering::SeqCst);
        let next = if every == 0 {
            0
        } else {
            i.now_ns + every * 1_000_000
        };
        n(Ticked::Next).store(next, Ordering::SeqCst);
        (*out.cast::<TickOut>()).next_tick_ns = next;
        say(
            out,
            if pended {
                Outcome::Pending
            } else {
                Outcome::Ready
            },
        )
    }
}

/// One host connection service call on `ticket`, its sequence `seq`.
unsafe fn conn_call<I>(
    me: &Inst,
    f: Option<busbar_contract::abi::host::service::ServiceFn>,
    input: &mut I,
    ticket: Ticket,
    seq: u32,
    op: u32,
) -> Option<ServiceOut> {
    let f = f?;
    let head = &mut *(input as *mut I).cast::<ServiceHead>();
    *head = ServiceHead {
        size: std::mem::size_of::<I>() as u32,
        op,
        handle: CompletionHandle {
            ticket,
            seq,
            _reserved: 0,
        },
    };
    me.count(Stat::HostCalls);
    let mut out = std::mem::zeroed::<ServiceOut>();
    f(me.ctx, (input as *const I).cast(), &mut out);
    Some(out)
}

/// ESTABLISH the one need, then READ it, on `ticket`; a PENDING read leaves its stream for `drive`
/// and answers `true`.
unsafe fn establish_and_read(me: &Inst, ticket: Ticket) -> bool {
    let Some(slots) = me.conns.as_ref() else {
        return false;
    };
    let mut est = EstablishIn {
        head: std::mem::zeroed(),
        need: 0,
        timeout_ms: 0,
        target: s(b"far"),
        within: NO_STR,
    };
    let Some(o) = conn_call(me, slots.establish, &mut est, ticket, 1, service::ESTABLISH) else {
        return false;
    };
    if o.outcome.outcome() != Outcome::Ready || read(me, ticket, o.value).is_some() {
        return false;
    }
    me.ticked[Ticked::ReadPended as usize].fetch_add(1, Ordering::SeqCst);
    me.stream.store(o.value, Ordering::SeqCst);
    true
}

/// READ `stream` on `ticket`: the bytes, or `None` while it pends.
unsafe fn read(me: &Inst, ticket: Ticket, stream: u64) -> Option<u64> {
    let slots = me.conns.as_ref()?;
    let mut buf = [0u8; 64];
    let mut io = IoIn {
        head: std::mem::zeroed(),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    let o = conn_call(me, slots.read, &mut io, ticket, 2, service::READ)?;
    (o.outcome.outcome() == Outcome::Ready).then_some(o.len)
}
