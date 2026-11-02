// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! One-off raw ABI controls for real dispatcher session custody. No business script interpreter.
use crate::dispatch::kinds::plane::{open_door, Plane};
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink, Plugin,
};
use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome, RawOutcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    slot, OnPieceIn, OnPieceOut, Ops, PlaneCancelIn, PlaneCancelOut, CANCEL_ABORTED, EMIT_DONE,
    FROM_CALLER,
};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
static SERIAL: Mutex<()> = Mutex::new(());
static MODE: AtomicUsize = AtomicUsize::new(0);
static CANCELS: AtomicUsize = AtomicUsize::new(0);
static SEEN: Mutex<Vec<(Ticket, u32, u64)>> = Mutex::new(Vec::new());
fn guarded(f: impl FnOnce() -> RawOutcome) -> RawOutcome {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
        .unwrap_or(RawOutcome::of(Outcome::Fault))
}
extern "C" fn piece(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: the dispatcher lends initialized, exclusive ABI frames of these exact slots.
        let (i, o) = unsafe { (&*input.cast::<OnPieceIn>(), &mut *out.cast::<OnPieceOut>()) };
        SEEN.lock()
            .unwrap()
            .push((i.head.ticket, i.head.flags, i.unit));
        let answer = if MODE.load(SeqCst) == 0 && i.head.flags & FLAG_RESUME == 0 {
            crate::dispatch::ticket::host_wake(i.head.host, i.head.ticket);
            Outcome::Pending
        } else {
            if MODE.load(SeqCst) == 1 {
                o.flags = EMIT_DONE;
            }
            Outcome::Ready
        };
        o.head.outcome = RawOutcome::of(answer);
        RawOutcome::of(answer)
    })
}
extern "C" fn cancel(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    guarded(|| {
        // SAFETY: exact initialized plane CANCEL frame and exclusive output.
        let (_i, o) = unsafe {
            (
                &*input.cast::<PlaneCancelIn>(),
                &mut *out.cast::<PlaneCancelOut>(),
            )
        };
        CANCELS.fetch_add(1, SeqCst);
        o.cancel.head.outcome = RawOutcome::of(Outcome::Ready);
        o.cancel.disposition = CANCEL_ABORTED;
        RawOutcome::of(Outcome::Ready)
    })
}
extern "C" fn door() -> &'static Door {
    static AT: OnceLock<usize> = OnceLock::new();
    let at = *AT.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        // SAFETY: actual retained MCP descriptor; only hostile raw session boundary slots replaced.
        let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        let ops = Box::leak(Box::new(Ops {
            on_piece: Some(piece),
            head: busbar_contract::abi::mechanism::lifecycle::OpsHead {
                cancel: Some(cancel),
                ..ops.head
            },
            ..ops
        }));
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: boxed immutable descriptor and backing actual product image remain process-live.
    unsafe { &*(at as *const Door) }
}
fn plugin(d: &Dispatcher) -> Plugin<Plane> {
    let p = load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: "session-host-boundary".into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    open_door(&p, b"{}", b"{}", None).expect("actual MCP empty component opens");
    p
}
fn frame(unit: u64) -> Frame<OnPieceIn, OnPieceOut> {
    // SAFETY: these ABI frames consist of zero-valid integers and pointer/length pairs.
    let (mut i, mut o): (OnPieceIn, OnPieceOut) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    i.head = in_head();
    i.unit = unit;
    i.stream = unit;
    i.from = FROM_CALLER;
    o.head = out_head();
    Frame::new(i, o)
}
#[test]
fn every_pending_piece_resumes_on_its_original_unit_ticket() {
    let _serial = SERIAL.lock().unwrap();
    MODE.store(0, SeqCst);
    SEEN.lock().unwrap().clear();
    let d = Dispatcher::new(DispatchConfig::default());
    let p = plugin(&d);
    let t = d.mint(0).unwrap();
    d.bind_plane_unit(&p, t, 73);
    for _ in 0..10 {
        let done = d
            .submit(&p, t, slot::ON_PIECE, frame(73), DeadlineClass::Stream, 0)
            .wait(Duration::from_secs(5))
            .expect("actual dispatcher resumes piece");
        assert_eq!(done.outcome, Outcome::Ready);
    }
    let seen = SEEN.lock().unwrap();
    assert_eq!(seen.len(), 20);
    for pair in seen.chunks_exact(2) {
        assert_eq!(pair[0].0, t);
        assert_eq!(pair[1].0, t);
        assert_ne!(t.generation, 0);
        assert_eq!(pair[0].1 & FLAG_RESUME, 0);
        assert_ne!(pair[1].1 & FLAG_RESUME, 0);
        assert_eq!((pair[0].2, pair[1].2), (73, 73));
    }
    drop(seen);
    assert_eq!(d.stats().deadline_without_wake, 0);
    d.recycle(t);
}
#[test]
fn terminal_session_refuses_another_crossing_and_allows_a_fresh_unit() {
    let _serial = SERIAL.lock().unwrap();
    MODE.store(1, SeqCst);
    SEEN.lock().unwrap().clear();
    let d = Dispatcher::new(DispatchConfig::default());
    let p = plugin(&d);
    let t = d.mint(0).unwrap();
    d.bind_plane_unit(&p, t, 73);
    let first = d
        .submit(&p, t, slot::ON_PIECE, frame(73), DeadlineClass::Stream, 0)
        .wait(Duration::from_secs(5))
        .unwrap();
    assert_eq!(first.outcome, Outcome::Ready);
    assert_ne!(first.frame.unwrap().out.flags & EMIT_DONE, 0);
    let count = SEEN.lock().unwrap().len();
    let denied = d
        .submit(&p, t, slot::ON_PIECE, frame(73), DeadlineClass::Stream, 0)
        .wait(Duration::from_secs(5))
        .unwrap();
    assert_eq!(denied.outcome, Outcome::Refused);
    assert_eq!(SEEN.lock().unwrap().len(), count, "no postDONE crossing");
    let fresh = d.mint(0).unwrap();
    d.bind_plane_unit(&p, fresh, 74);
    let next = d
        .submit(
            &p,
            fresh,
            slot::ON_PIECE,
            frame(74),
            DeadlineClass::Stream,
            0,
        )
        .wait(Duration::from_secs(5))
        .unwrap();
    assert_eq!(next.outcome, Outcome::Ready);
    assert_ne!(next.frame.unwrap().out.flags & EMIT_DONE, 0);
    assert_eq!(SEEN.lock().unwrap().len(), count + 1);
    d.recycle(t);
    d.recycle(fresh);
}
#[test]
fn cancelling_no_session_ticket_cannot_end_an_admitted_unit() {
    let _serial = SERIAL.lock().unwrap();
    MODE.store(1, SeqCst);
    SEEN.lock().unwrap().clear();
    CANCELS.store(0, SeqCst);
    let d = Dispatcher::new(DispatchConfig::default());
    let p = plugin(&d);
    let t = d.mint(0).unwrap();
    d.bind_plane_unit(&p, t, 73);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(runtime
        .block_on(d.cancel_plane_unit(&p, Ticket::NONE, 73))
        .is_none());
    assert_eq!(CANCELS.load(SeqCst), 0);
    let done = d
        .submit(&p, t, slot::ON_PIECE, frame(73), DeadlineClass::Stream, 0)
        .wait(Duration::from_secs(5))
        .unwrap();
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(SEEN.lock().unwrap().len(), 1);
    assert_eq!(CANCELS.load(SeqCst), 0);
    d.recycle(t);
}
