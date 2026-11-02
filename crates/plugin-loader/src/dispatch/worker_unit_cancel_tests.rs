// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real loaded Plane tables exercise the worker, ticket generations, replies and watchdog.
//! These regressions are source-authored only; no local runtime qualification is claimed.

use super::*;
use crate::dispatch::kinds::plane::Plane;
use crate::dispatch::{load_linked, Bind, ConnTable, LinkedRow, NoSink, NO_BLOB};
use busbar_contract::abi::mechanism::{
    call::{Blob, RawOutcome, Span, BLOB_OCTETS},
    door::{Door, DoorParts},
};
use busbar_contract::abi::plane::{
    self, PlaneCancelIn, PlaneCancelOut, PlaneOpenIn, PlaneOpenOut, RecordWrite, CANCEL_OK_PARTIAL,
    FROM_CALLER, RECORD_PUT,
};
use std::collections::HashMap;
use std::sync::OnceLock;

const WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Control {
    pieces: AtomicU64,
    cancels: Mutex<Vec<u64>>,
    block_cancel: AtomicBool,
    entered: AtomicBool,
    release: AtomicBool,
    returned: AtomicBool,
    pending_bytes: Mutex<Vec<(usize, usize)>>,
    bytes_checked: AtomicU64,
}

fn controls() -> &'static Mutex<HashMap<usize, Arc<Control>>> {
    static CONTROLS: OnceLock<Mutex<HashMap<usize, Arc<Control>>>> = OnceLock::new();
    CONTROLS.get_or_init(Mutex::default)
}

fn control(instance: *mut std::ffi::c_void) -> Arc<Control> {
    controls()
        .lock()
        .unwrap()
        .get(&(instance as usize))
        .unwrap()
        .clone()
}

crate::dispatch_tests::c_abi! {
    fn piece(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let control = control(instance);
        let (input, out) = unsafe { (&*input.cast::<OnPieceIn>(), &mut *out.cast::<OnPieceOut>()) };
        control.pieces.fetch_add(1, Ordering::SeqCst);
        let outcome = match input.stream {
            9 => {
                control.entered.store(true, Ordering::Release);
                let start = Instant::now();
                while !control.release.load(Ordering::Acquire) {
                    assert!(start.elapsed() < WAIT, "piece gate was not released");
                    std::thread::yield_now();
                }
                Outcome::Ready
            }
            0 => {
                if input.bytes.len != 0 {
                    control.pending_bytes.lock().unwrap().push((input.bytes.ptr as usize, input.bytes.len));
                }
                Outcome::Pending
            }
            1 | 2 => {
                out.flags = EMIT_DONE;
                out.verdict = if input.stream == 2 { VERDICT_RETRY } else { 0 };
                Outcome::Ready
            }
            _ => Outcome::Ready,
        };
        out.head.outcome = RawOutcome::of(outcome);
        RawOutcome::of(outcome)
    }
    fn cancel(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        let control = control(instance);
        let (input, out) = unsafe { (&*input.cast::<PlaneCancelIn>(), &mut *out.cast::<PlaneCancelOut>()) };
        control.cancels.lock().unwrap().push(input.unit);
        control.entered.store(true, Ordering::Release);
        let start = Instant::now();
        while control.block_cancel.load(Ordering::Acquire) && !control.release.load(Ordering::Acquire) {
            assert!(start.elapsed() < WAIT, "cancel gate was not released");
            std::thread::yield_now();
        }
        // The test keeps a safety owner even if the retention assertion fails. These reads
        // therefore never probe freed memory; Arc counts separately witness loader custody.
        for &(ptr, len) in control.pending_bytes.lock().unwrap().iter() {
            let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
            assert!(bytes.iter().all(|byte| *byte == 0x5a));
            control.bytes_checked.fetch_add(1, Ordering::SeqCst);
        }
        assert!(input.records_cap >= 1 && input.arena_cap >= 2);
        unsafe {
            input.arena_buf.write(b'k'); input.arena_buf.add(1).write(b'v');
            input.records_buf.write(RecordWrite { kind: 0, op: RECORD_PUT,
                key: Span { offset: 0, len: 1 }, value: Span { offset: 1, len: 1 } });
        }
        out.records_written = 1;
        out.arena_written = 2;
        out.cancel.disposition = CANCEL_OK_PARTIAL;
        out.cancel.head.outcome = RawOutcome::of(Outcome::Ready);
        control.returned.store(true, Ordering::Release);
        RawOutcome::of(Outcome::Ready)
    }
    fn close(instance: *mut std::ffi::c_void, input: *const std::ffi::c_void, out: *mut std::ffi::c_void) -> RawOutcome {
        controls().lock().unwrap().remove(&(instance as usize));
        let real = crate::plane_door_plugin::door().parts();
        let ops = unsafe { &*real.ops };
        // SAFETY: original SDK fixture owns this exact opened instance and these close heads.
        unsafe { (ops.close.unwrap())(instance, input, out) }
    }
    fn door() -> &'static Door {
        static ADDRESS: OnceLock<usize> = OnceLock::new();
        let address = *ADDRESS.get_or_init(|| {
            let real = crate::plane_door_plugin::door().parts();
            let mut ops = unsafe { *real.ops.cast::<plane::Ops>() };
            ops.on_piece = Some(piece); ops.head.cancel = Some(cancel); ops.head.close = Some(close);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: original static Statement/tail and full Plane table; overrides above use
            // each slot's exact C frames. The original SDK fixture still owns open/close state.
            let door = unsafe { Door::__from_parts(DoorParts { ops: &ops.head, ..real }) };
            Box::into_raw(Box::new(door)) as usize
        });
        unsafe { &*(address as *const Door) }
    }
}

fn rig(config: DispatchConfig) -> (Dispatcher, Plugin<Plane>, Arc<Control>) {
    let dispatcher = Dispatcher::new(config);
    let (plugin, control) = plugin(&dispatcher);
    (dispatcher, plugin, control)
}

fn plugin(dispatcher: &Dispatcher) -> (Plugin<Plane>, Arc<Control>) {
    let plugin = load_linked::<Plane>(
        &LinkedRow::of(door).unwrap(),
        Bind {
            instance: Arc::from("unit-cancel"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    // SAFETY: these ABI frames consist only of integer, pointer and span fields; zero is valid.
    let (mut input, mut out): (PlaneOpenIn, PlaneOpenOut) = unsafe { std::mem::zeroed() };
    input.open.head = in_head();
    input.open.generation = 1;
    input.open.settings = NO_BLOB;
    out.open.head = out_head();
    let mut frame = Frame::new(input, out);
    assert_eq!(plugin.call(slot::OPEN, &mut frame).outcome, Outcome::Ready);
    let control = Arc::new(Control::default());
    controls()
        .lock()
        .unwrap()
        .insert(frame.out.open.instance as usize, control.clone());
    (plugin, control)
}

fn frame(unit: u64, mode: u64, flags: u32) -> Frame<OnPieceIn, OnPieceOut> {
    // SAFETY: these ABI frames consist only of integer, pointer and span fields; zero is valid.
    let (mut input, mut out): (OnPieceIn, OnPieceOut) = unsafe { std::mem::zeroed() };
    input.head = in_head();
    input.unit = unit;
    input.from = FROM_CALLER;
    input.stream = mode;
    input.flags = flags;
    out.head = out_head();
    Frame::new(input, out)
}

fn until(mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while !predicate() {
        assert!(
            start.elapsed() < WAIT,
            "worker did not reach the expected state"
        );
        std::thread::yield_now();
    }
}

fn answer(
    mut future: Pin<Box<dyn Future<Output = Option<Cancelled>> + Send>>,
) -> Option<Cancelled> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let start = Instant::now();
    loop {
        if let Poll::Ready(answer) = future.as_mut().poll(&mut context) {
            return answer;
        }
        assert!(start.elapsed() < WAIT, "cancellation future did not settle");
        std::thread::yield_now();
    }
}

fn pair(dispatcher: &Dispatcher, plugin: &Plugin<Plane>, unit: u64) -> (Ticket, Ticket) {
    let near = dispatcher.mint(0).unwrap();
    let far = dispatcher.mint(0).unwrap();
    dispatcher.bind_plane_unit(plugin, near, unit);
    dispatcher.bind_plane_unit(plugin, far, unit);
    (near, far)
}

#[test]
fn drop_of_two_pending_legs_cancels_once_and_only_trigger_owns_writes() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 73);
    let a = d.submit(
        &p,
        near,
        plane_slot::ON_PIECE,
        frame(73, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    let b = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(73, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| d.is_pending(near) && d.is_pending(far));
    d.drop_client(near);
    d.drop_client(far);
    let (a, b) = (a.wait(WAIT).unwrap(), b.wait(WAIT).unwrap());
    assert_eq!(*c.cancels.lock().unwrap(), vec![73]);
    assert_eq!(
        (a.disposition, b.disposition),
        (Some(CANCEL_OK_PARTIAL), Some(CANCEL_OK_PARTIAL))
    );
    assert_eq!(a.cancel_writes.len(), 1);
    assert!(b.cancel_writes.is_empty());
    assert!(answer(d.cancel_plane_unit(&p, far, 73))
        .unwrap()
        .writes
        .is_empty());
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn explicit_cancel_is_eager_and_retires_pending_and_queued_siblings() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 74);
    let a = d.submit(
        &p,
        near,
        plane_slot::ON_PIECE,
        frame(74, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    let b = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(74, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| d.is_pending(near) && d.is_pending(far));
    let queued = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(74, 5, 0),
        DeadlineClass::Stream,
        0,
    );
    let cancel = d.cancel_plane_unit(&p, near, 74);
    // No poll has occurred: worker entry is proof that submission was eager.
    until(|| c.entered.load(Ordering::Acquire));
    assert_eq!(answer(cancel).unwrap().writes.len(), 1);
    for done in [
        a.wait(WAIT).unwrap(),
        b.wait(WAIT).unwrap(),
        queued.wait(WAIT).unwrap(),
    ] {
        assert_eq!(done.disposition, Some(CANCEL_OK_PARTIAL));
        assert!(done.cancel_writes.is_empty());
    }
    assert_eq!(c.pieces.load(Ordering::SeqCst), 2);
    assert_eq!(*c.cancels.lock().unwrap(), vec![74]);
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn normal_terminal_reply_tombstones_sibling_before_caller_consumes_it() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 75);
    let pending = d.submit(
        &p,
        near,
        plane_slot::ON_PIECE,
        frame(75, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| d.is_pending(near));
    let done = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(75, 1, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| c.pieces.load(Ordering::SeqCst) == 2 && !d.is_pending(near));
    d.drop_client(near);
    assert!(answer(d.cancel_plane_unit(&p, near, 75)).is_none());
    assert_eq!(done.wait(WAIT).unwrap().outcome, Outcome::Ready);
    assert!(pending.wait(WAIT).unwrap().disposition.is_none());
    assert!(c.cancels.lock().unwrap().is_empty());
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn retry_and_refused_piece_keep_unit_but_final_retry_closes_it() {
    for (unit, mode, flags, cancel_count) in [
        (76, 2, 0, 1),
        (77, 1, PIECE_REFUSED, 1),
        (78, 2, PIECE_FINAL, 0),
    ] {
        let (d, p, c) = rig(DispatchConfig::default());
        let (near, far) = pair(&d, &p, unit);
        let done = d
            .submit(
                &p,
                near,
                plane_slot::ON_PIECE,
                frame(unit, mode, flags),
                DeadlineClass::Stream,
                0,
            )
            .wait(WAIT)
            .unwrap();
        assert_eq!(done.outcome, Outcome::Ready);
        let cancelled = answer(d.cancel_plane_unit(&p, far, unit));
        assert_eq!(cancelled.is_some(), cancel_count != 0);
        assert_eq!(c.cancels.lock().unwrap().len(), cancel_count);
        d.recycle(near);
        d.recycle(far);
    }
}

#[test]
fn same_numeric_unit_in_distinct_instances_and_recycled_generations_is_independent() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (other, other_control) = plugin(&d);
    let (a, b) = pair(&d, &p, 79);
    let (x, y) = pair(&d, &other, 79);
    assert!(answer(d.cancel_plane_unit(&p, a, 79)).is_some());
    assert!(other_control.cancels.lock().unwrap().is_empty());
    assert!(answer(d.cancel_plane_unit(&other, x, 79)).is_some());
    assert_eq!(c.cancels.lock().unwrap().len(), 1);
    assert_eq!(other_control.cancels.lock().unwrap().len(), 1);
    d.recycle(a);
    d.recycle(b);
    until(|| !d.slot_state(a).0 && !d.slot_state(b).0);
    let fresh = d.mint(0).unwrap();
    d.bind_plane_unit(&p, fresh, 80);
    assert!(answer(d.cancel_plane_unit(&p, a, 79)).is_none());
    assert!(answer(d.cancel_plane_unit(&p, fresh, 80)).is_some());
    assert_eq!(*c.cancels.lock().unwrap(), vec![79, 80]);
    d.recycle(fresh);
    d.recycle(x);
    d.recycle(y);
}

#[test]
fn cancel_watchdog_fault_keeps_both_lent_ranges_until_native_return() {
    let mut config = DispatchConfig::default();
    config.budgets.stream = Duration::from_millis(20);
    config.watchdog_period = Duration::from_millis(2);
    let (d, p, c) = rig(config);
    let (near, far) = pair(&d, &p, 81);
    c.block_cancel.store(true, Ordering::Release);
    let a_owner = Arc::new(vec![0x5a; 32]);
    let b_owner = Arc::new(vec![0x5a; 48]);
    let (a_weak, b_weak) = (Arc::downgrade(&a_owner), Arc::downgrade(&b_owner));
    let mut a_frame = frame(81, 0, 0);
    let mut b_frame = frame(81, 0, 0);
    a_frame.input.bytes = Blob {
        ptr: a_owner.as_ptr(),
        len: a_owner.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    b_frame.input.bytes = Blob {
        ptr: b_owner.as_ptr(),
        len: b_owner.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let a = d.submit_lent(
        &p,
        near,
        plane_slot::ON_PIECE,
        a_frame,
        DeadlineClass::Stream,
        0,
        a_owner.clone(),
    );
    let b = d.submit_lent(
        &p,
        far,
        plane_slot::ON_PIECE,
        b_frame,
        DeadlineClass::Stream,
        0,
        b_owner.clone(),
    );
    until(|| d.is_pending(near) && d.is_pending(far));
    // Keep one independent owner so a broken implementation cannot make the native
    // callback read freed memory. Any additional strong owner belongs to dispatch custody.
    let cancel = d.cancel_plane_unit(&p, near, 81);
    until(|| c.entered.load(Ordering::Acquire));
    let (a_done, b_done) = (a.wait(WAIT).unwrap(), b.wait(WAIT).unwrap());
    let held = Arc::strong_count(&a_owner) > 1 && Arc::strong_count(&b_owner) > 1;
    // Release before any assertion, so even a failing regression cannot strand the worker.
    c.release.store(true, Ordering::Release);
    assert!(held, "watchdog freed memory still lent to native cancel");
    assert_eq!(
        (a_done.outcome, b_done.outcome),
        (Outcome::Fault, Outcome::Fault)
    );
    assert!(answer(cancel).is_none());
    until(|| c.returned.load(Ordering::Acquire));
    assert_eq!(c.bytes_checked.load(Ordering::SeqCst), 2);
    drop(a_owner);
    drop(b_owner);
    until(|| a_weak.upgrade().is_none() && b_weak.upgrade().is_none());
    assert_eq!(*c.cancels.lock().unwrap(), vec![81]);
}

#[test]
fn two_pending_deadlines_cancel_once_and_late_wake_never_recalls() {
    let (d, p, c) = rig(DispatchConfig::default());
    let (near, far) = pair(&d, &p, 82);
    let deadline = now_ns().saturating_add(100_000_000);
    let a = d.submit(
        &p,
        near,
        plane_slot::ON_PIECE,
        frame(82, 0, 0),
        DeadlineClass::Stream,
        deadline,
    );
    let b = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(82, 0, 0),
        DeadlineClass::Stream,
        deadline,
    );
    until(|| d.is_pending(near) && d.is_pending(far));
    let (a, b) = (a.wait(WAIT).unwrap(), b.wait(WAIT).unwrap());
    assert_eq!(a.cancel_writes.len() + b.cancel_writes.len(), 1);
    assert_eq!(*c.cancels.lock().unwrap(), vec![82]);
    let waking = crate::dispatch::ticket::Waking::of(p.inner.wake).unwrap();
    waking.wake(near);
    waking.wake(far);
    assert!(answer(d.cancel_plane_unit(&p, near, 82))
        .unwrap()
        .writes
        .is_empty());
    assert_eq!(c.pieces.load(Ordering::SeqCst), 2);
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn replaced_worker_groups_healthy_orphan_siblings_into_one_cancel() {
    let mut config = DispatchConfig::default();
    config.budgets.stream = Duration::from_millis(20);
    config.watchdog_period = Duration::from_millis(2);
    let (d, p, c) = rig(config);
    let (wedged, wedge) = plugin(&d);
    let (near, far) = pair(&d, &p, 83);
    let a = d.submit(
        &p,
        near,
        plane_slot::ON_PIECE,
        frame(83, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    let b = d.submit(
        &p,
        far,
        plane_slot::ON_PIECE,
        frame(83, 0, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| d.is_pending(near) && d.is_pending(far));
    let blocked = d.mint(0).unwrap();
    let hung = d.submit(
        &wedged,
        blocked,
        plane_slot::ON_PIECE,
        frame(84, 9, 0),
        DeadlineClass::Stream,
        0,
    );
    until(|| wedge.entered.load(Ordering::Acquire));
    let fault = hung.wait(WAIT).unwrap();
    wedge.release.store(true, Ordering::Release);
    assert_eq!(fault.outcome, Outcome::Fault);
    let (a, b) = (a.wait(WAIT).unwrap(), b.wait(WAIT).unwrap());
    assert_eq!((a.outcome, b.outcome), (Outcome::Fault, Outcome::Fault));
    assert_eq!(
        (a.disposition, b.disposition),
        (Some(CANCEL_OK_PARTIAL), Some(CANCEL_OK_PARTIAL))
    );
    assert_eq!(a.cancel_writes.len() + b.cancel_writes.len(), 1);
    assert_eq!(*c.cancels.lock().unwrap(), vec![83]);
}

#[test]
fn explicit_cancel_completion_wakes_a_reentrant_host_outside_worker_lock() {
    struct Reenter {
        dispatcher: Arc<Dispatcher>,
        finished: std::sync::mpsc::Sender<()>,
    }
    impl std::task::Wake for Reenter {
        fn wake(self: Arc<Self>) {
            let ticket = self.dispatcher.mint(0).unwrap();
            self.dispatcher.recycle(ticket);
            let _ = self.finished.send(());
        }
    }
    let (dispatcher, p, c) = rig(DispatchConfig::default());
    let d = Arc::new(dispatcher);
    let (near, far) = pair(&d, &p, 85);
    c.block_cancel.store(true, Ordering::Release);
    let mut cancel = d.cancel_plane_unit(&p, near, 85);
    until(|| c.entered.load(Ordering::Acquire));
    let (tx, rx) = std::sync::mpsc::channel();
    let waker = Waker::from(Arc::new(Reenter {
        dispatcher: d.clone(),
        finished: tx,
    }));
    let mut context = Context::from_waker(&waker);
    assert!(cancel.as_mut().poll(&mut context).is_pending());
    c.release.store(true, Ordering::Release);
    rx.recv_timeout(WAIT)
        .expect("cancel completion woke under worker state lock");
    assert!(answer(cancel).is_some());
    d.recycle(near);
    d.recycle(far);
}

#[test]
fn zero_unit_never_creates_a_group_or_calls_cancel() {
    let (d, p, c) = rig(DispatchConfig::default());
    let ticket = d.mint(0).unwrap();
    d.bind_plane_unit(&p, ticket, 0);
    assert!(answer(d.cancel_plane_unit(&p, ticket, 0)).is_none());
    assert!(c.cancels.lock().unwrap().is_empty());
    d.recycle(ticket);
}

#[test]
fn a_stale_plane_submission_remains_a_routing_fault() {
    let (d, p, c) = rig(DispatchConfig::default());
    let stale = d.mint(0).unwrap();
    d.recycle(stale);
    until(|| !d.slot_state(stale).0);
    let done = d
        .submit(
            &p,
            stale,
            plane_slot::ON_PIECE,
            frame(86, 1, 0),
            DeadlineClass::Stream,
            0,
        )
        .wait(WAIT)
        .unwrap();
    assert_eq!(done.outcome, Outcome::Fault);
    assert_eq!(c.pieces.load(Ordering::SeqCst), 0);
    assert!(c.cancels.lock().unwrap().is_empty());
}
