// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane lifecycle through the real trampoline: one plane door built with
//! `lifecycle: plane_life(P)`. `open` publishes the first generation's snapshot and holds the state,
//! `refresh` publishes the next with its value, `retire` drops one generation, a refused
//! `validate`/`open`/`refresh` answers the plane's text, `tick`/`drive` answer their defaults,
//! `cancel` is the plane's own, and `release`/`close` answer READY.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use crate::abi::mechanism::lifecycle::{
    slot, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use crate::abi::mechanism::ticket::{HostCtx, Ticket};
use crate::abi::plane::{
    Ops, PlaneCancelIn, PlaneCancelOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot, CANCEL_ABORTED,
};
use crate::abi::sdk::publish::Generations;

use super::*;

/// Generations whose `published` hook ran, summed; and those retired.
static PUBLISHED: AtomicU64 = AtomicU64::new(0);
static RETIRED: AtomicU64 = AtomicU64::new(0);

/// The test plane: its settings are its held value per generation.
#[derive(Default)]
struct Echo {
    generations: Generations<PlaneSnapshot, Vec<u8>>,
}

impl PlaneLife for Echo {
    type Held = Vec<u8>;

    fn generations(&self) -> &Generations<PlaneSnapshot, Vec<u8>> {
        &self.generations
    }

    fn open(input: &Lent<'_, PlaneOpenIn>) -> Result<Opened<Self>, Refusal> {
        let settings = input.open().settings().bytes().to_vec();
        if settings == b"refuse" {
            return Err(Refusal::refused("the echo plane refuses"));
        }
        Ok(Opened {
            plane: Echo::default(),
            first: Published {
                spec: SnapshotSpec::default(),
                held: settings,
            },
        })
    }

    fn refresh(&self, settings: &[u8], _: u64) -> Result<Published<Vec<u8>>, Refusal> {
        if settings == b"fail" {
            return Err(Refusal::failed(format!("refresh failed: {}", 7)));
        }
        Ok(Published {
            spec: SnapshotSpec::default(),
            held: settings.to_vec(),
        })
    }

    fn published(&self, generation: u64) {
        PUBLISHED.fetch_add(generation, Ordering::SeqCst);
    }

    fn retire(&self, generation: u64) {
        RETIRED.fetch_add(generation, Ordering::SeqCst);
    }

    fn cancel(
        _: Instance<'_, Self>,
        _: Lent<'_, PlaneCancelIn>,
        mut out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        out.set(|o| &o.cancel.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
}

mod plugin {
    use super::*;
    crate::plugin_door! {
        ops: crate::abi::plane::Ops,
        statement: crate::abi::sdk::door::statement("plane-life-echo", "0", 1),
        lifecycle: plane_life(Echo),
    }
}

fn table() -> &'static Ops {
    // SAFETY: the macro's `'static` door and its plane table.
    unsafe { &*plugin::door().ops.cast::<Ops>() }
}

fn in_head<T>(op: u32) -> InHead {
    InHead {
        size: size_of::<T>() as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx::NONE,
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: blob(b""),
    }
}

fn blob(b: &[u8]) -> Blob {
    Blob {
        ptr: if b.is_empty() {
            ptr::null()
        } else {
            b.as_ptr()
        },
        len: b.len(),
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

fn zeroed<T>() -> T {
    // SAFETY: every `in`/`out` here is plain data; all-zero is valid.
    unsafe { std::mem::zeroed() }
}

fn out_head<T>() -> OutHead {
    let mut h: OutHead = zeroed();
    h.size = size_of::<T>() as u32;
    h.outcome = RawOutcome::of(Outcome::Fault);
    h
}

fn call<I, O>(op: Option<Op>, instance: *mut c_void, input: &I, out: &mut O) -> Outcome {
    op.expect("every slot is filled")(
        instance,
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

fn text(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the plugin's error text, held by its instance or the lent buffer.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// `open` with `settings` at generation `1`: the outcome, the instance, the published snapshot's
/// generation (`0` = none), and the error text.
fn open(settings: &[u8]) -> (Outcome, *mut c_void, u64, String) {
    let mut input: PlaneOpenIn = zeroed();
    input.open.head = in_head::<PlaneOpenIn>(slot::OPEN);
    input.open.settings = blob(settings);
    input.open.generation = 1;
    let mut out: PlaneOpenOut = zeroed();
    out.open.head = out_head::<PlaneOpenOut>();
    let o = call(table().head.open, ptr::null_mut(), &input, &mut out);
    let generation = if out.snapshot.is_null() {
        0
    } else {
        // SAFETY: the snapshot the SDK holds until its generation retires.
        unsafe { (*out.snapshot).generation }
    };
    (o, out.open.instance, generation, text(out.open.head.error))
}

fn refresh(inst: *mut c_void, settings: &[u8], generation: u64) -> (Outcome, u64, String) {
    let mut input: RefreshIn = zeroed();
    input.head = in_head::<RefreshIn>(slot::REFRESH);
    input.settings = blob(settings);
    input.generation = generation;
    let mut out: PlaneRefreshOut = zeroed();
    out.head = out_head::<PlaneRefreshOut>();
    let o = call(table().head.refresh, inst, &input, &mut out);
    let published = if out.snapshot.is_null() {
        0
    } else {
        // SAFETY: as in `open`.
        unsafe { (*out.snapshot).generation }
    };
    (o, published, text(out.head.error))
}

fn close(inst: *mut c_void) -> Outcome {
    let input = in_head::<InHead>(slot::CLOSE);
    let mut out = out_head::<OutHead>();
    call(table().head.close, inst, &input, &mut out)
}

#[test]
fn open_publishes_the_first_generation_and_a_refusal_answers_the_planes_text() {
    let before = PUBLISHED.load(Ordering::SeqCst);
    let (o, inst, generation, _) = open(b"{}");
    assert_eq!(o, Outcome::Ready);
    assert!(!inst.is_null());
    assert_eq!(generation, 1, "the first generation's snapshot");
    assert!(
        PUBLISHED.load(Ordering::SeqCst) - before >= 1,
        "published ran"
    );
    assert_eq!(close(inst), Outcome::Ready);
    let (o, inst, generation, why) = open(b"refuse");
    assert_eq!(o, Outcome::Refused);
    assert!(inst.is_null());
    assert_eq!(generation, 0, "nothing published");
    assert_eq!(why, "the echo plane refuses");
}

#[test]
fn refresh_publishes_its_generation_or_answers_its_text_and_retire_drops_one() {
    let (_, inst, _, _) = open(b"{}");
    let (o, published, _) = refresh(inst, b"{\"n\":2}", 2);
    assert_eq!((o, published), (Outcome::Ready, 2));
    let (o, published, why) = refresh(inst, b"fail", 3);
    assert_eq!((o, published), (Outcome::Failed, 0));
    assert_eq!(why, "refresh failed: 7");
    // retire: the plane's hook runs after the snapshot is dropped
    let mut gi: GenIn = zeroed();
    gi.head = in_head::<GenIn>(slot::RETIRE);
    gi.generation = 5;
    let before = RETIRED.load(Ordering::SeqCst);
    let mut go = out_head::<OutHead>();
    assert_eq!(
        call(table().head.retire, inst, &gi, &mut go),
        Outcome::Ready
    );
    assert_eq!(RETIRED.load(Ordering::SeqCst) - before, 5);
    assert_eq!(close(inst), Outcome::Ready);
    // RED: a refresh with no instance is FAILED, never a publish
    let (o, published, _) = refresh(ptr::null_mut(), b"{}", 4);
    assert_eq!((o, published), (Outcome::Failed, 0));
}

#[test]
fn validate_tick_drive_cancel_and_release_answer_the_defaults_and_the_planes_cancel() {
    let mut vi: ValidateIn = zeroed();
    vi.head = in_head::<ValidateIn>(slot::VALIDATE);
    vi.settings = blob(b"[1]");
    let mut vo = out_head::<OutHead>();
    assert_eq!(
        call(table().head.validate, ptr::null_mut(), &vi, &mut vo),
        Outcome::Failed
    );
    assert_eq!(text(vo.error), "settings: must be a JSON object");
    let (_, inst, _, _) = open(b"{}");
    let mut ti: TickIn = zeroed();
    ti.head = in_head::<TickIn>(slot::TICK);
    ti.now_ns = 100;
    let mut to: TickOut = zeroed();
    to.head = out_head::<TickOut>();
    to.next_tick_ns = 9;
    assert_eq!(call(table().head.tick, inst, &ti, &mut to), Outcome::Ready);
    assert_eq!(to.next_tick_ns, 0, "no tick wanted");
    let mut di: PlaneDriveIn = zeroed();
    di.drive.head = in_head::<PlaneDriveIn>(slot::DRIVE);
    let mut dout: PlaneDriveOut = zeroed();
    dout.head = out_head::<PlaneDriveOut>();
    assert_eq!(
        call(table().head.drive, inst, &di, &mut dout),
        Outcome::Ready
    );
    let mut ci: PlaneCancelIn = zeroed();
    ci.cancel.head = in_head::<PlaneCancelIn>(slot::CANCEL);
    let mut co: PlaneCancelOut = zeroed();
    co.cancel.head = out_head::<PlaneCancelOut>();
    assert_eq!(
        call(table().head.cancel, inst, &ci, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.cancel.disposition, CANCEL_ABORTED);
    let mut ri: ReleaseIn = zeroed();
    ri.head = in_head::<ReleaseIn>(slot::RELEASE);
    ri.lease = 3;
    let mut ro = out_head::<OutHead>();
    assert_eq!(
        call(table().head.release, inst, &ri, &mut ro),
        Outcome::Ready
    );
    assert_eq!(close(inst), Outcome::Ready);
}

// ── export_plugin!'s plane arm ──────────────────────────────────────────────────────────────────

/// A kind op answering `$outcome` over `$in`/`$out`.
macro_rules! answers {
    ($name:ident, $in:ty, $out:ty, $outcome:expr) => {
        struct $name;
        impl crate::abi::sdk::door::Slot for $name {
            type In = $in;
            type Out = $out;
            fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                $outcome
            }
        }
    };
}

use crate::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut,
};

answers!(Arrive, ArriveIn, ArriveOut, Outcome::Ready);
answers!(OnPiece, OnPieceIn, OnPieceOut, Outcome::Ready);
answers!(Refuse, RefusalIn, RefusalOut, Outcome::Ready);
answers!(Project, ProjectIn, ProjectOut, Outcome::Ready);
answers!(Served, ServeIn, ServeOut, Outcome::Ready);
answers!(Hydrated, GenIn, OutHead, Outcome::Failed);

/// A plane naming no `serve`, `hydrate` or `start`: the arm's defaults.
mod defaulted {
    use super::*;
    crate::export_plugin! {
        plane: Echo,
        statement: crate::abi::sdk::door::statement("plane-arm-defaults", "0", 1),
        kind_ops: { arrive: Arrive, on_piece: OnPiece, refusal: Refuse, project: Project },
    }
}

/// A plane naming `serve` and `hydrate`: its own, and `start`'s default.
mod named {
    use super::*;
    crate::export_plugin! {
        plane: Echo,
        statement: crate::abi::sdk::door::statement("plane-arm-named", "0", 1),
        kind_ops: {
            arrive: Arrive, on_piece: OnPiece, refusal: Refuse, serve: Served,
            hydrate: Hydrated, project: Project,
        },
    }
}

fn arm_table(door: crate::abi::mechanism::door::DoorFn) -> &'static Ops {
    // SAFETY: the macro's `'static` door and its plane table.
    unsafe { &*door().ops.cast::<Ops>() }
}

fn gen_op(op: Option<Op>, index: u32) -> Outcome {
    let input = GenIn {
        head: in_head::<GenIn>(index),
        ..zeroed()
    };
    let mut out = out_head::<OutHead>();
    call(op, ptr::null_mut(), &input, &mut out)
}

fn serve_op(op: Option<Op>) -> Outcome {
    let input = ServeIn {
        head: in_head::<ServeIn>(crate::abi::plane::slot::SERVE),
        ..zeroed()
    };
    let mut out = ServeOut {
        head: out_head::<ServeOut>(),
        ..zeroed()
    };
    call(op, ptr::null_mut(), &input, &mut out)
}

#[test]
fn the_plane_arm_defaults_hydrate_and_start_to_ready_and_serve_to_refused() {
    use crate::abi::plane::slot::{HYDRATE, START};
    let t = arm_table(defaulted::door);
    assert_eq!(gen_op(t.hydrate, HYDRATE), Outcome::Ready);
    assert_eq!(gen_op(t.start, START), Outcome::Ready);
    assert_eq!(serve_op(t.serve), Outcome::Refused);
    assert!(t.catalog.is_none(), "an unnamed catalog stays absent");
    assert!(t.head.cancel.is_some(), "cancel is the plane's own");
}

#[test]
fn the_plane_arm_keeps_the_ops_a_plane_names() {
    use crate::abi::plane::slot::{HYDRATE, START};
    let t = arm_table(named::door);
    assert_eq!(gen_op(t.hydrate, HYDRATE), Outcome::Failed);
    assert_eq!(gen_op(t.start, START), Outcome::Ready);
    assert_eq!(serve_op(t.serve), Outcome::Ready);
}
