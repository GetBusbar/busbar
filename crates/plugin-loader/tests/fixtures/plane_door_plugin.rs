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

use std::ffi::c_void;
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
    ServeIn, ServeOut, Span, UnitCount, CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER,
    FROM_FAR_END, FROM_KERNEL, INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE,
    MARK_GATE_REJECTED, PIECE_LAST, PRINCIPAL_NONE, RECORD_PUT, REFUSAL_GATE, SECTION_DECLARING,
    SHAPE_PIECEWISE, UNITS_ESTIMATED, UNITS_REPORTED, VERDICT_OK,
};
use busbar_contract::abi::sdk::door::{abi_str, statement, Slot};

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
};

/// Every generation's claim.
const CLAIMS: &[Claim] = &[Claim {
    verb: abi_str("POST"),
    target: abi_str("/echo"),
    carrier: abi_str("door"),
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
    snapshots: Mutex<Vec<Box<PlaneSnapshot>>>,
    ready: AtomicU64,
}

impl Plane {
    /// A snapshot of `generation`, kept until its `retire`; a refreshed one adds the admin route.
    fn publish(&self, generation: u64, refreshed: bool) -> *const PlaneSnapshot {
        let routes: &[AdminRoute] = if refreshed { ROUTES } else { &[] };
        let snap = Box::new(PlaneSnapshot {
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
        });
        let p: *const PlaneSnapshot = &*snap;
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

/// # Safety
/// `instance` is the pointer this plugin's `open` handed out, not yet closed.
unsafe fn plane<'a>(instance: *mut c_void) -> &'a Plane {
    // SAFETY: the caller's contract.
    unsafe { &*instance.cast::<Plane>() }
}

/// Host-borrowed bytes as a slice.
fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the host lends `len` readable bytes at `p` for the call.
    unsafe { std::slice::from_raw_parts(p, len) }
}

/// A host arena being filled: each `put` copies bytes in and answers their [`Span`].
struct Arena {
    buf: *mut u8,
    cap: usize,
    at: usize,
}

impl Arena {
    fn put(&mut self, b: &[u8]) -> Span {
        let span = Span {
            offset: self.at as u32,
            len: b.len() as u32,
        };
        // SAFETY: the caller checked `fits` first; the host's arena holds `cap` writable bytes.
        unsafe { ptr::copy_nonoverlapping(b.as_ptr(), self.buf.add(self.at), b.len()) };
        self.at += b.len();
        span
    }
}

/// Copy `b` into a host buffer of `cap` bytes; answers how many went in.
fn emit(buf: *mut u8, cap: usize, b: &[u8]) -> usize {
    let n = b.len().min(cap);
    if n != 0 {
        // SAFETY: the host's buffer holds `cap >= n` writable bytes.
        unsafe { ptr::copy_nonoverlapping(b.as_ptr(), buf, n) };
    }
    n
}

struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, _: &mut OutHead) -> Outcome {
        if bytes(input.settings.ptr, input.settings.len) == BAD_SETTINGS {
            Outcome::Refused
        } else {
            Outcome::Ready
        }
    }
}

struct Open;
impl Slot for Open {
    type In = PlaneOpenIn;
    type Out = PlaneOpenOut;
    fn call(_: *mut c_void, input: &PlaneOpenIn, out: &mut PlaneOpenOut) -> Outcome {
        let p = Box::new(Plane {
            snapshots: Mutex::new(Vec::new()),
            ready: AtomicU64::new(0),
        });
        out.snapshot = p.publish(input.open.generation, false);
        out.open.instance = Box::into_raw(p).cast();
        Outcome::Ready
    }
}

struct Refresh;
impl Slot for Refresh {
    type In = RefreshIn;
    type Out = PlaneRefreshOut;
    fn call(instance: *mut c_void, input: &RefreshIn, out: &mut PlaneRefreshOut) -> Outcome {
        // SAFETY: the host calls `refresh` on the instance `open` answered.
        out.snapshot = unsafe { plane(instance) }.publish(input.generation, true);
        Outcome::Ready
    }
}

struct Retire;
impl Slot for Retire {
    type In = GenIn;
    type Out = OutHead;
    fn call(instance: *mut c_void, input: &GenIn, _: &mut OutHead) -> Outcome {
        // SAFETY: as `refresh`.
        lock(&unsafe { plane(instance) }.snapshots).retain(|s| s.generation != input.generation);
        Outcome::Ready
    }
}

struct Tick;
impl Slot for Tick {
    type In = TickIn;
    type Out = TickOut;
    fn call(_: *mut c_void, input: &TickIn, out: &mut TickOut) -> Outcome {
        out.next_tick_ns = input.now_ns + 1_000_000;
        Outcome::Ready
    }
}

struct Drive;
impl Slot for Drive {
    type In = PlaneDriveIn;
    type Out = PlaneDriveOut;
    fn call(instance: *mut c_void, input: &PlaneDriveIn, out: &mut PlaneDriveOut) -> Outcome {
        // SAFETY: as `refresh`.
        let p = unsafe { plane(instance) };
        let ready = p.ready.load(Ordering::Acquire);
        if ready == 0 {
            return Outcome::Ready;
        }
        if input.sessions_cap == 0 {
            out.sessions_needed = 1;
            return Outcome::Failed;
        }
        // SAFETY: the host's buffer of `sessions_cap >= 1` streams.
        unsafe { input.sessions_buf.write(ready) };
        out.sessions_written = 1;
        p.ready.store(0, Ordering::Release);
        Outcome::Ready
    }
}

struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(_: *mut c_void, _: &CancelIn, out: &mut CancelOut) -> Outcome {
        out.disposition = CANCEL_ABORTED;
        Outcome::Ready
    }
}

struct Release;
impl Slot for Release {
    type In = ReleaseIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &ReleaseIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Close;
impl Slot for Close {
    type In = InHead;
    type Out = OutHead;
    fn call(instance: *mut c_void, _: &InHead, _: &mut OutHead) -> Outcome {
        // SAFETY: `close` is the instance's last call; it came from `Box::into_raw` in `open`.
        drop(unsafe { Box::from_raw(instance.cast::<Plane>()) });
        Outcome::Ready
    }
}

struct Arrive;
impl Slot for Arrive {
    type In = ArriveIn;
    type Out = ArriveOut;
    fn call(_: *mut c_void, input: &ArriveIn, out: &mut ArriveOut) -> Outcome {
        if input.units_cap == 0 {
            out.units_needed = 1;
            return Outcome::Failed;
        }
        // SAFETY: the host's buffer of `units_cap >= 1` counts.
        unsafe {
            input.units_buf.write(UnitCount {
                class: 0,
                source: UNITS_ESTIMATED,
                amount: input.body.len as u64,
            });
        }
        out.units_written = 1;
        out.op_class = 0;
        out.dialect = 0;
        out.principal_need = PRINCIPAL_NONE;
        Outcome::Ready
    }
}

struct OnPiece;
impl Slot for OnPiece {
    type In = OnPieceIn;
    type Out = OnPieceOut;
    fn call(instance: *mut c_void, input: &OnPieceIn, out: &mut OnPieceOut) -> Outcome {
        let piece = bytes(input.bytes.ptr, input.bytes.len);
        let mut arena = Arena {
            buf: input.arena_buf,
            cap: input.arena_cap,
            at: 0,
        };
        match (input.from, input.attempt_no) {
            // An ATTEMPT: the request bound for the member the kernel picked.
            (FROM_KERNEL, 1..) => {
                if arena.cap < 7 {
                    out.arena_needed = 7;
                    return Outcome::Failed;
                }
                out.verb = arena.put(b"POST");
                out.target = arena.put(b"/up");
                out.arena_written = arena.at as u64;
                let member = bytes(input.member.ptr, input.member.len);
                out.emitted = emit(input.reply_buf, input.reply_cap, member) as u64;
                out.flags = EMIT_TO_FAR_END;
            }
            // A session's unsolicited output, after `drive` named it.
            (FROM_KERNEL, 0) => {
                out.emitted = emit(input.reply_buf, input.reply_cap, b"ping") as u64;
            }
            // The caller's piece opens a session with output to come.
            (FROM_CALLER, _) => {
                // SAFETY: the host calls `on_piece` on the instance `open` answered.
                unsafe { plane(instance) }
                    .ready
                    .store(input.stream, Ordering::Release);
            }
            // The far end's answer: echoed to the caller, with a field, a count and a record.
            (FROM_FAR_END, _) => {
                let need = (1_u32, 1_u32, 1_u32, 13_usize);
                if input.units_cap < 1
                    || input.records_cap < 1
                    || input.fields_cap < 1
                    || arena.cap < need.3
                {
                    out.units_needed = need.0;
                    out.records_needed = need.1;
                    out.fields_needed = need.2;
                    out.arena_needed = need.3 as u64;
                    return Outcome::Failed;
                }
                let field = OutField {
                    name: arena.put(b"x-plane"),
                    value: arena.put(b"door"),
                };
                let record = RecordWrite {
                    kind: 0,
                    op: RECORD_PUT,
                    key: arena.put(b"k"),
                    value: arena.put(b"v"),
                };
                // SAFETY: each host buffer holds at least one element (checked above).
                unsafe {
                    input.fields_buf.write(field);
                    input.records_buf.write(record);
                    input.units_buf.write(UnitCount {
                        class: 0,
                        source: UNITS_REPORTED,
                        amount: piece.len() as u64,
                    });
                }
                (out.fields_written, out.records_written, out.units_written) = (1, 1, 1);
                out.arena_written = arena.at as u64;
                let n = emit(input.reply_buf, input.reply_cap, piece);
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
    }
}

struct Refusal;
impl Slot for Refusal {
    type In = RefusalIn;
    type Out = RefusalOut;
    fn call(_: *mut c_void, input: &RefusalIn, out: &mut RefusalOut) -> Outcome {
        let text = bytes(input.text.ptr, input.text.len);
        if input.reply_cap < text.len() || input.fields_cap < 1 || input.arena_cap < 13 {
            out.reply_needed = text.len() as u64;
            out.fields_needed = 1;
            out.arena_needed = 13;
            return Outcome::Failed;
        }
        let mut arena = Arena {
            buf: input.arena_buf,
            cap: input.arena_cap,
            at: 0,
        };
        let field = OutField {
            name: arena.put(b"x-refusal"),
            value: arena.put(b"gate"),
        };
        // SAFETY: the host's `fields_buf` holds at least one field (checked above).
        unsafe { input.fields_buf.write(field) };
        out.fields_written = 1;
        out.arena_written = arena.at as u64;
        out.reply_written = emit(input.reply_buf, input.reply_cap, text) as u64;
        if input.cause == REFUSAL_GATE {
            out.marker = MARK_GATE_REJECTED;
        }
        Outcome::Ready
    }
}

struct Serve;
impl Slot for Serve {
    type In = ServeIn;
    type Out = ServeOut;
    fn call(_: *mut c_void, input: &ServeIn, out: &mut ServeOut) -> Outcome {
        if input.reply_cap < 2 {
            out.reply_needed = 2;
            return Outcome::Failed;
        }
        out.reply_written = emit(input.reply_buf, input.reply_cap, b"ok") as u64;
        out.status = 200;
        Outcome::Ready
    }
}

struct Hydrate;
impl Slot for Hydrate {
    type In = GenIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &GenIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Start;
impl Slot for Start {
    type In = GenIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &GenIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

struct Project;
impl Slot for Project {
    type In = ProjectIn;
    type Out = ProjectOut;
    fn call(_: *mut c_void, input: &ProjectIn, out: &mut ProjectOut) -> Outcome {
        let body = bytes(input.body.ptr, input.body.len);
        let need = 4 + body.len();
        if input.signals_cap < 1 || input.arena_cap < need {
            out.signals_needed = 1;
            out.arena_needed = need as u64;
            return Outcome::Failed;
        }
        let mut arena = Arena {
            buf: input.arena_buf,
            cap: input.arena_cap,
            at: 0,
        };
        let pool = arena.put(b"door");
        out.body = arena.put(body);
        out.arena_written = arena.at as u64;
        // SAFETY: the host's `signals_buf` holds at least one signal (checked above).
        unsafe {
            input.signals_buf.write(SignalEntry {
                id: signal::REQUEST_TOTAL_CHARS,
                tag: SIGNAL_TAG_U64,
                value: SignalValue {
                    u64_: body.len() as u64,
                },
            });
        }
        out.view.signals = input.signals_buf;
        out.view.signals_len = 1;
        out.view.pool = AbiStr {
            // SAFETY: `pool` lies inside the arena written above.
            ptr: unsafe { input.arena_buf.add(pool.offset as usize) },
            len: pool.len as usize,
        };
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        ..statement("plane-door", "1.0.0", 8)
    },
    lifecycle: {
        validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
        drive: Drive, cancel: Cancel, release: Release, close: Close,
    },
    kind_ops: {
        arrive: Arrive, on_piece: OnPiece, refusal: Refusal, serve: Serve, hydrate: Hydrate,
        start: Start, project: Project,
    },
}

// The dropped door's one symbol. The test build links this source as a module beside the
// dispatcher's test plugin, which exports the same symbol, so only the `cdylib` emits it.
#[cfg(not(test))]
busbar_contract::export_door!(door);
