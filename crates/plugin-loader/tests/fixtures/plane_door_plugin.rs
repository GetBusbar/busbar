// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE DOOR'S TEST PLUGIN — a minimal plane built with `plugin_door!`, one source compiled
//! into the test build (the LINKED door, its `door` function) and built as the `plane_door_plugin`
//! example `cdylib` (the DROPPED door, through `export_door!`).
//!
//! It answers every plane op through the SDK's trampolines: `open` and `refresh` publish a
//! generation snapshot (valid until `retire` of that generation; opened under a public URL, every
//! generation also claims the session door `GET /upgrade`), `arrive`, `on_piece`, `refusal`,
//! `serve` and `project` write only into the host's buffers (an arrival on the session door, claim
//! 1, states `ROUTE_SESSION`), `drive` names the session with unsolicited output, `cancel` answers a
//! disposition (one naming the ticket the session's caller piece crossed on ends the session) and
//! `tick` its next tick. Opened on a host that serves them, an ATTEMPT is sent only when the
//! kernel entitles the unit to `door:echo` and approves the member's `echo`; the far end's answer names
//! the ledger lane `lane` beside its record write; and `project` writes one `user` turn of the
//! body into a turns buffer the host lends. The request-path ops never allocate and never block:
//! the only shared state they touch is two atomics.
//!
//! It is written on the SDK's SAFE surface (`abi::sdk::safe`, `abi::sdk::lent`): every slot is a
//! `SafeSlot`, the instance is the SDK's typed `Instance<Plane>`, host-lent bytes and host buffers
//! go through `Lent` and `HostBuf`. This file holds no `unsafe`.

#![forbid(unsafe_code)]

use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::task::Poll;

use busbar_contract::abi::hook::signal;
use busbar_contract::abi::host::service::DISTRUST_NONE;
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{KindTailHead, Section, Statement, SECTION_DECLARING};
use busbar_contract::abi::mechanism::lifecycle::{
    GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, BillableClass, OnPieceIn, OnPieceOut, OpClass, OutField, PlaneDriveIn,
    PlaneDriveOut, PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, PlaneTail, ProjectIn,
    ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn, ServeOut, UnitCount, ANSWER_LAYOUT,
    CANCEL_ABORTED, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    INGRESS_DUPLEX_SESSION, INGRESS_REQUEST_RESPONSE, PIECE_LAST, PRINCIPAL_NONE, RECORD_PUT,
    SHAPE_PIECEWISE, UNITS_ESTIMATED, UNITS_REPORTED, VERDICT_OK,
};
use busbar_contract::abi::plane::{PlaneCancelIn, PlaneCancelOut};
use busbar_contract::abi::sdk::completion_retirement::{Domain, Handle, Retirement};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::Leases;
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, ClaimSpec, SnapshotSpec};
use busbar_contract::abi::sdk::services::Services;
use busbar_contract::abi::sdk::{Generations, Instance, Lent, Out, Safe, SafeSlot, SignalScalar};

/// An absent string.
const NONE: AbiStr = AbiStr::ZERO;

const SECTIONS: &[Section] = &[Section {
    name: abi_str("door"),
    flags: SECTION_DECLARING,
    ..Section::ZERO
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

/// The Statement tail: one of each list the per-call indices name. Its sections are the
/// Statement's own ([`SECTIONS`]).
const TAIL: &PlaneTail = &PlaneTail {
    head: KindTailHead {
        size: size_of::<PlaneTail>() as u32,
        ..KindTailHead::ZERO
    },
    ingress: INGRESS_REQUEST_RESPONSE | INGRESS_DUPLEX_SESSION,
    dispatch_shape: SHAPE_PIECEWISE,
    // The layout this plane writes its answers in: the contract's it was built against.
    answer_layout: ANSWER_LAYOUT,
    scope: abi_str("door"),
    label: abi_str("Door"),
    subject_noun: abi_str("door"),
    admin_noun: abi_str("door"),
    audit_kind: abi_str("door"),
    signing_domain: NONE,
    signing_kid_prefix: NONE,
    cli_help: NONE,
    dialects: DIALECTS.as_ptr(),
    dialects_len: DIALECTS.len(),
    op_classes: OP_CLASSES.as_ptr(),
    op_classes_len: OP_CLASSES.len(),
    billable_classes: CLASSES.as_ptr(),
    billable_classes_len: CLASSES.len(),
    record_kinds: RECORD_KINDS.as_ptr(),
    record_kinds_len: RECORD_KINDS.len(),
    caller_credential_refusal: NONE,
    admin_openapi: busbar_contract::abi::mechanism::call::Blob {
        fmt: busbar_contract::abi::mechanism::call::BLOB_ABSENT,
        ..busbar_contract::abi::mechanism::call::Blob::ZERO
    },
    ..PlaneTail::ZERO
};

/// Every generation's claims: the request door, and with a public URL the session door.
fn claims(public: bool) -> Vec<ClaimSpec> {
    let mut claims = vec![ClaimSpec::new("POST", "/echo", "door", 0)];
    if public {
        claims.push(ClaimSpec::new("GET", "/upgrade", "door", 0));
    }
    claims
}
/// The admin route a REFRESHED generation adds.
fn routes() -> Vec<AdminRouteSpec> {
    vec![AdminRouteSpec::new("GET", "/door/status", 0)]
}

/// The one name every generation lists.
pub const LISTED: &str = "door-listed";

/// The settings `validate` refuses.
pub const BAD_SETTINGS: &[u8] = b"bad";

pub const PENDING_DRIVE: &[u8] = b"pending-drive";
pub const PENDING_DRIVE_OVER_CAP: &[u8] = b"pending-drive-over-cap";
pub const PENDING_DRIVE_NEEDED: &[u8] = b"pending-drive-needed";
pub const DRIVE_RESUMES: u64 = u64::MAX - 1;
pub const DRIVE_RESTART: u64 = u64::MAX - 2;
pub const ACK_PENDING: &[u8] = b"ack-pending";
pub const ACK_READY: &[u8] = b"ack-ready";
pub const ACK_FAILED: &[u8] = b"ack-failed";
pub const ACK_SHORT: &[u8] = b"ack-short";
pub const ACK_MALFORMED: &[u8] = b"ack-malformed";
pub const ACK_WRONG_OWNER: &[u8] = b"ack-wrong-owner";
pub const ACK_WRONG_NONCE: &[u8] = b"ack-wrong-nonce";
pub const ACK_CANCEL: &[u8] = b"ack-cancel";

#[derive(Clone, Copy, PartialEq, Eq)]
enum AckMode {
    Pending,
    Ready,
    Failed,
    Short,
    Malformed,
    WrongOwner,
    WrongNonce,
    Cancel,
}

struct DriveProbe {
    ack: Option<AckMode>,
    retirement: Mutex<Retirement>,
    malformed: u8,
    completed: AtomicU64,
    resumes: AtomicU64,
    lease: AtomicU64,
    leases: Mutex<Leases>,
}

impl DriveProbe {
    fn new(settings: &[u8]) -> Option<Self> {
        let ack = match settings {
            ACK_PENDING => Some(AckMode::Pending),
            ACK_READY => Some(AckMode::Ready),
            ACK_FAILED => Some(AckMode::Failed),
            ACK_SHORT => Some(AckMode::Short),
            ACK_MALFORMED => Some(AckMode::Malformed),
            ACK_WRONG_OWNER => Some(AckMode::WrongOwner),
            ACK_WRONG_NONCE => Some(AckMode::WrongNonce),
            ACK_CANCEL => Some(AckMode::Cancel),
            _ => None,
        };
        let malformed = match settings {
            PENDING_DRIVE => 0,
            PENDING_DRIVE_OVER_CAP => 1,
            PENDING_DRIVE_NEEDED => 2,
            _ if ack.is_some() => 0,
            _ => return None,
        };
        Some(Self {
            ack,
            retirement: Mutex::new(Retirement::default()),
            malformed,
            completed: AtomicU64::new(0),
            resumes: AtomicU64::new(0),
            lease: AtomicU64::new(0),
            leases: Mutex::new(Leases::default()),
        })
    }
}

/// One instance: the live generations' snapshots (control lane only), the session with
/// unsolicited output, `0` = none, and the ticket its caller piece crossed on, packed, `0` = none
/// (the two things the request path touches).
struct Plane {
    snapshots: Generations<PlaneSnapshot>,
    ready: AtomicU64,
    session_ticket: AtomicU64,
    /// Opened under a public URL.
    public: bool,
    /// The host's services, when the host offers them: an ATTEMPT is then sent only when the
    /// kernel entitles the unit to `door:echo` and approves the member's `echo` (a service the
    /// host does not serve gates nothing).
    services: Option<Services>,
    drive_probe: Option<DriveProbe>,
}

impl Plane {
    /// The snapshot of a generation, held by the SDK until its `retire`; a refreshed one adds the
    /// admin route.
    fn spec(&self, refreshed: bool) -> SnapshotSpec {
        SnapshotSpec {
            claims: claims(self.public),
            admin_routes: if refreshed { routes() } else { Vec::new() },
            listed: vec![LISTED.to_string()],
            ..SnapshotSpec::default()
        }
    }
}

/// One slot body on the SDK's safe surface: `$name` reads `$in` and writes `$out` over the
/// instance's [`Plane`].
macro_rules! slot {
    ($name:ident, $in:ty, $out:ty, |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = Plane;
            fn call(
                $inst: Instance<'_, Plane>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome {
                $body
            }
        }
    };
}

slot!(Validate, ValidateIn, OutHead, |_, input, _out| {
    if input.field(|i| &i.settings).bytes() == BAD_SETTINGS {
        Outcome::Refused
    } else {
        Outcome::Ready
    }
});

slot!(Open, PlaneOpenIn, PlaneOpenOut, |instance, input, out| {
    let p = Plane {
        snapshots: Generations::new(),
        ready: AtomicU64::new(0),
        session_ticket: AtomicU64::new(0),
        drive_probe: DriveProbe::new(input.field(|i| &i.open.settings).bytes()),
        public: !input.field(|i| &i.public_url).bytes().is_empty(),
        services: input.field(|i| &i.open).host().and_then(Services::of),
    };
    out.publish(
        |o| &o.snapshot,
        &p.snapshots,
        input.open.generation,
        &p.spec(false),
    );
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
        out.publish(
            |o| &o.snapshot,
            &p.snapshots,
            input.generation,
            &p.spec(true),
        );
        Outcome::Ready
    }
);

slot!(Retire, GenIn, OutHead, |instance, input, _out| {
    if let Some(p) = instance.get() {
        p.snapshots.retire(input.generation);
    }
    Outcome::Ready
});

slot!(Tick, TickIn, TickOut, |instance, input, out| {
    if let Some(probe) = instance.get().and_then(|p| p.drive_probe.as_ref()) {
        let value = match input.now_ns {
            DRIVE_RESUMES => Some(probe.resumes.load(Ordering::Acquire)),
            DRIVE_RESTART => {
                probe.completed.store(0, Ordering::Release);
                Some(0)
            }
            _ => None,
        };
        if let Some(value) = value {
            out.set(|o| &o.next_tick_ns, value);
            return Outcome::Ready;
        }
    }
    out.set(|o| &o.next_tick_ns, input.now_ns + 1_000_000);
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
        let mut outcome = Outcome::Ready;
        if let Some(probe) = p.drive_probe.as_ref() {
            if probe.ack.is_some()
                && probe
                    .retirement
                    .lock()
                    .unwrap()
                    .begin(
                        input.drive.head.host,
                        input.drive.driver,
                        input.field(|i| &i.drive.head.extensions).bytes(),
                    )
                    .is_err()
            {
                return Outcome::Fault;
            }
            if input.drive.head.flags & FLAG_RESUME != 0 {
                probe.resumes.fetch_add(1, Ordering::AcqRel);
            }
            if probe.completed.load(Ordering::Acquire) == 0 {
                let Some(services) = p.services.as_ref() else {
                    return Outcome::Failed;
                };
                let handle = CompletionHandle {
                    ticket: input.drive.driver,
                    seq: 0,
                    ..CompletionHandle::ZERO
                };
                let mut bytes = [0; 16];
                match services.records_get(handle, "last", b"drive", &mut bytes) {
                    Poll::Pending => outcome = Outcome::Pending,
                    Poll::Ready(Ok(Some(bytes))) if bytes == b"completed" => {
                        probe.completed.store(1, Ordering::Release);
                        if probe.ack.is_some()
                            && probe
                                .retirement
                                .lock()
                                .unwrap()
                                .consumed(Handle {
                                    domain: Domain::Host,
                                    seq: 0,
                                })
                                .is_err()
                        {
                            return Outcome::Fault;
                        }
                    }
                    _ => return Outcome::Fault,
                }
            }
            let leases = probe.leases.lock().unwrap();
            if leases.held() != 0 {
                return Outcome::Fault;
            }
            out.lease_str(|o| &o.head.error, &leases, "drive-owned-answer".to_owned());
            if let Some(mode) = probe.ack {
                let mut retirement = probe.retirement.lock().unwrap();
                let Ok(ack) = retirement.acknowledgement(0) else {
                    return Outcome::Fault;
                };
                if let Some(mut ack) = ack {
                    if mode == AckMode::WrongOwner {
                        ack.capability.owner.handle ^= 1;
                    }
                    if mode == AckMode::WrongNonce {
                        ack.capability.nonce += 1;
                    }
                    if mode != AckMode::Cancel && out.completion_ack(&leases, &ack).is_err() {
                        return Outcome::Fault;
                    }
                }
                if retirement.queued() {
                    outcome = Outcome::Pending;
                }
                match mode {
                    AckMode::Ready => outcome = Outcome::Ready,
                    AckMode::Failed => outcome = Outcome::Failed,
                    AckMode::Short => {
                        out.set(|o| &o.sessions_needed, input.sessions_cap as u32 + 1);
                        outcome = Outcome::Failed;
                    }
                    AckMode::Malformed => {
                        out.set(|o| &o.sessions_written, input.sessions_cap as u32 + 1)
                    }
                    _ => {}
                }
            }
            probe.lease.store(out.get().head.lease, Ordering::Release);
            if probe.malformed == 1 {
                out.set(|o| &o.sessions_written, input.sessions_cap as u32 + 1);
                return outcome;
            }
            if probe.malformed == 2 {
                out.set(|o| &o.sessions_needed, input.sessions_cap as u32 + 1);
                return outcome;
            }
        }
        let ready = p.ready.load(Ordering::Acquire);
        if ready == 0 {
            return outcome;
        }
        let mut sessions = input.sessions_buf();
        sessions.push(ready);
        if !sessions.fits() {
            out.set(|o| &o.sessions_needed, sessions.needed() as u32);
            return Outcome::Failed;
        }
        out.set(|o| &o.sessions_written, sessions.written() as u32);
        p.ready.store(0, Ordering::Release);
        outcome
    }
);

/// A ticket as one word, `0` = none.
fn packed(t: Ticket) -> u64 {
    (u64::from(t.slot) << 32) | u64::from(t.generation)
}

// `cancel`: one naming the ticket the session's caller piece crossed on ends the session.
slot!(
    Cancel,
    PlaneCancelIn,
    PlaneCancelOut,
    |instance, input, out| {
        let named = packed(input.cancel.ticket);
        if let Some(p) = instance.get() {
            if let Some(probe) = p
                .drive_probe
                .as_ref()
                .filter(|p| p.ack == Some(AckMode::Cancel))
            {
                let Ok(Some(ack)) = probe.retirement.lock().unwrap().acknowledgement(0) else {
                    return Outcome::Fault;
                };
                let leases = probe.leases.lock().unwrap();
                if out.completion_ack(&leases, &ack).is_err() {
                    return Outcome::Fault;
                }
                probe
                    .lease
                    .store(out.get().cancel.head.lease, Ordering::Release);
            }
            if named != 0
                && p.session_ticket
                    .compare_exchange(named, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                p.ready.store(0, Ordering::Release);
            }
        }
        out.set(|o| &o.cancel.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
);

slot!(Release, ReleaseIn, OutHead, |instance, input, _out| {
    if let Some(probe) = instance.get().and_then(|p| p.drive_probe.as_ref()) {
        if probe
            .lease
            .compare_exchange(input.lease, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Outcome::Refused;
        }
        // The probe allows one outstanding answer. Dropping its owner releases the actual
        // allocated error bytes; the next DRIVE must observe no previous answer still held.
        let retired = std::mem::take(&mut *probe.leases.lock().unwrap());
        drop(retired);
        if let Some(services) = instance.get().and_then(|p| p.services.as_ref()) {
            let _ = services.entitled(CompletionHandle::ZERO, "door:drive-release");
        }
    }
    Outcome::Ready
});

// `close` answering READY: the SDK drops the instance's `Plane`.
slot!(Close, InHead, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Arrive, ArriveIn, ArriveOut, |_, input, out| {
    let mut units = input.units_buf();
    units.push(UnitCount {
        source: UNITS_ESTIMATED,
        amount: input.body.len as u64,
        ..UnitCount::ZERO
    });
    if !units.fits() {
        out.set(|o| &o.units_needed, units.needed() as u32);
        return Outcome::Failed;
    }
    out.set(|o| &o.units_written, units.written() as u32);
    out.set(|o| &o.op_class, 0);
    out.set(|o| &o.dialect, 0);
    out.set(|o| &o.principal_need, PRINCIPAL_NONE);
    if input.claim == 1 {
        out.session();
    }
    Outcome::Ready
});

slot!(OnPiece, OnPieceIn, OnPieceOut, |instance, input, out| {
    let piece = input.field(|i| &i.bytes).bytes();
    let mut arena = input.arena_buf();
    let mut reply = input.reply_buf();
    match (input.from, input.attempt_no) {
        // An ATTEMPT: the request bound for the member the kernel picked.
        (FROM_KERNEL, 1..) => {
            if let Some(s) = instance.get().and_then(|p| p.services) {
                let handle = |seq| CompletionHandle {
                    ticket: input.head.ticket,
                    seq,
                    ..CompletionHandle::ZERO
                };
                let member = input.field(|i| &i.member).as_str().unwrap_or_default();
                // A service the host does not serve gates nothing.
                let refused = s.entitled(handle(0), "door:echo") == Ok(false)
                    || s.trust_serves(handle(1), member, Some("echo"), None)
                        .is_ok_and(|v| v != DISTRUST_NONE);
                if refused {
                    return Outcome::Refused;
                }
            }
            let (verb, target) = (arena.span(b"POST"), arena.span(b"/up"));
            if !arena.fits() {
                out.set(|o| &o.arena_needed, arena.needed() as u64);
                return Outcome::Failed;
            }
            out.set(|o| &o.verb, verb);
            out.set(|o| &o.target, target);
            out.set(|o| &o.arena_written, arena.written() as u64);
            let member = input.field(|i| &i.member).bytes();
            out.set(|o| &o.emitted, reply.stream(member) as u64);
            out.set(|o| &o.flags, EMIT_TO_FAR_END);
        }
        // A session's unsolicited output, after `drive` named it.
        (FROM_KERNEL, 0) => {
            out.set(|o| &o.emitted, reply.stream(b"ping") as u64);
        }
        // The caller's piece opens a session with output to come.
        (FROM_CALLER, _) => {
            let Some(p) = instance.get() else {
                return Outcome::Failed;
            };
            p.ready.store(input.stream, Ordering::Release);
            p.session_ticket
                .store(packed(input.head.ticket), Ordering::Release);
            if p.drive_probe.is_some() && piece == b"pending-session" {
                return Outcome::Pending;
            }
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
                op: RECORD_PUT,
                key: arena.span(b"k"),
                value: arena.span(b"v"),
                ..RecordWrite::ZERO
            });
            let lane = arena.span(b"lane");
            units.push(UnitCount {
                source: UNITS_REPORTED,
                amount: piece.len() as u64,
                ..UnitCount::ZERO
            });
            // One short answer for every buffer (the multi-buffer rule).
            let short = !(fields.fits() && records.fits() && units.fits() && arena.fits());
            let (fw, fnd) = fields.settle(short);
            let (rw, rnd) = records.settle(short);
            let (uw, und) = units.settle(short);
            let (aw, and) = arena.settle(short);
            out.set(|o| &o.fields_written, fw as u32);
            out.set(|o| &o.fields_needed, fnd as u32);
            out.set(|o| &o.records_written, rw as u32);
            out.set(|o| &o.records_needed, rnd as u32);
            out.set(|o| &o.units_written, uw as u32);
            out.set(|o| &o.units_needed, und as u32);
            out.set(|o| &o.arena_written, aw as u64);
            out.set(|o| &o.arena_needed, and as u64);
            if short {
                return Outcome::Failed;
            }
            out.set(|o| &o.lane, lane);
            let n = reply.stream(piece);
            out.set(|o| &o.emitted, n as u64);
            out.set(|o| &o.reply_status, 200);
            out.set(|o| &o.verdict, VERDICT_OK);
            if n < piece.len() {
                out.set(|o| &o.more, 1);
            } else if input.flags & PIECE_LAST != 0 {
                out.set(|o| &o.flags, EMIT_DONE);
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
    out.set(|o| &o.reply_written, rw as u64);
    out.set(|o| &o.reply_needed, rnd as u64);
    out.set(|o| &o.fields_written, fw as u32);
    out.set(|o| &o.fields_needed, fnd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    Outcome::Ready
});

slot!(Serve, ServeIn, ServeOut, |_, input, out| {
    let mut reply = input.reply_buf();
    reply.extend(b"ok");
    if !reply.fits() {
        out.set(|o| &o.reply_needed, reply.needed() as u64);
        return Outcome::Failed;
    }
    out.set(|o| &o.reply_written, reply.written() as u64);
    out.set(|o| &o.status, 200);
    Outcome::Ready
});

slot!(Hydrate, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

slot!(Start, GenIn, OutHead, |_, _, _out| { Outcome::Ready });

// `project`: the body, its length as a signal and, when the host lends a turns buffer, one `user`
// turn of the body.
pub const PROJECT_ENTITLEMENT_TARGET: &[u8] = b"/__project_entitlement";

slot!(Project, ProjectIn, ProjectOut, |instance, input, out| {
    if input.field(|i| &i.target).bytes() == PROJECT_ENTITLEMENT_TARGET {
        let Some(services) = instance.get().and_then(|p| p.services) else {
            return Outcome::Fault;
        };
        let handle = CompletionHandle {
            ticket: input.head.ticket,
            seq: 0,
            ..CompletionHandle::ZERO
        };
        if services.entitled(handle, "door:project-scope") != Ok(true) {
            return Outcome::Refused;
        }
    }
    let body = input.field(|i| &i.body).bytes();
    let (mut signals, mut arena, mut turns) =
        (input.signals_buf(), input.arena_buf(), input.messages_buf());
    let (pool, projected) = (arena.span(b"door"), arena.span(body));
    if input.messages_cap > 0 {
        let role = arena.span(b"user");
        turns.push_turn(&arena, role, projected);
    }
    signals.push_signal(
        signal::REQUEST_TOTAL_CHARS,
        SignalScalar::U64(body.len() as u64),
    );
    let short = !(signals.fits() && arena.fits() && turns.fits());
    let (sw, snd) = signals.settle(short);
    let (aw, and) = arena.settle(short);
    let (tw, tnd) = turns.settle(short);
    out.set(|o| &o.messages_needed, tnd as u32);
    out.set(|o| &o.signals_needed, snd as u32);
    out.set(|o| &o.arena_written, aw as u64);
    out.set(|o| &o.arena_needed, and as u64);
    if short {
        return Outcome::Failed;
    }
    out.set(|o| &o.body, projected);
    out.host_list(|o| &o.view.signals, |o| &o.view.signals_len, &signals);
    debug_assert_eq!(out.get().view.signals_len, sw);
    out.host_str(|o| &o.view.pool, &arena, pool);
    if tw > 0 {
        out.host_rows(|o| &o.prompt.messages, &turns);
        out.set(|o| &o.prompt.messages_len, tw);
        out.set(|o| &o.prompt.message_count, tw as u64);
    }
    Outcome::Ready
});

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: Statement {
        kind_tail: ptr::from_ref(TAIL).cast::<KindTailHead>(),
        sections: SECTIONS.as_ptr(),
        sections_len: SECTIONS.len(),
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
