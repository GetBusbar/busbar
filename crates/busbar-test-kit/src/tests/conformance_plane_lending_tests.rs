// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual serve frame points into its retained owner after watchdog abandonment.
use super::*;
use std::sync::{Condvar, Mutex, OnceLock, Weak};
use std::time::Instant;
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::plane::Ops;
use crate::conformance::{test_door, test_op, TestDoor, TestOp};
use crate::dispatch::{Budgets, DispatchConfig};

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool, bool)>, // released, finished, live input observed
    changed: Condvar,
    owner: Mutex<Weak<ServeLend>>,
}
static GATE: OnceLock<Arc<Gate>> = OnceLock::new();
static DOOR: OnceLock<usize> = OnceLock::new();
struct LateServe;
impl TestOp for LateServe {
    fn op(_: *mut std::ffi::c_void, input: *const std::ffi::c_void,
          out: *mut std::ffi::c_void) -> RawOutcome {
        let gate = GATE.get().expect("test installed its gate");
        let state = gate.state.lock().unwrap();
        let (state, _) = gate.changed.wait_timeout_while(
            state, Duration::from_secs(10), |s| !s.0,
        ).unwrap();
        let released = state.0;
        drop(state);
        // Acquire the actual owner before any nested pointer read. Weak adds no ownership while
        // the crossing waits past its watchdog budget; failure is observed without probing freed memory.
        let observed = released && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = gate.owner.lock().unwrap().upgrade().expect("actual loan is alive");
            // SAFETY: loader supplied this frame. Establish all nested allocation identities first.
            let i = unsafe { input.cast::<ServeIn>().read() };
            assert_eq!((i.target.ptr, i.target.len), (owner.request.target.as_ptr(), owner.request.target.len()));
            assert_eq!((i.body.ptr, i.body.len), (owner.request.body.as_ptr(), owner.request.body.len()));
            assert_eq!((i.fields, i.fields_len), (owner.request_fields.as_ptr(), owner.request_fields.len()));
            // SAFETY: exact live initialized allocation bounds established above.
            assert_eq!(unsafe { std::slice::from_raw_parts(i.target.ptr, i.target.len) }, b"/late");
            assert_eq!(unsafe { std::slice::from_raw_parts(i.body.ptr, i.body.len) }, b"body");
            let field = unsafe { i.fields.read() };
            assert_eq!((field.name.ptr, field.name.len), (owner.request.fields[0].0.as_ptr(), owner.request.fields[0].0.len()));
            assert_eq!((field.value.ptr, field.value.len), (owner.request.fields[0].1.as_ptr(), owner.request.fields[0].1.len()));
            assert_eq!(unsafe { std::slice::from_raw_parts(field.value.ptr, field.value.len) }, b"v");
        })).is_ok();
        let mut state = gate.state.lock().unwrap();
        state.1 = true;
        state.2 = observed;
        drop(state);
        gate.changed.notify_all();
        // SAFETY: loader owns this initialized exclusive ServeOut until crossing return.
        unsafe { (*out.cast::<ServeOut>()).head.outcome = RawOutcome::of(Outcome::Fault) };
        RawOutcome::of(Outcome::Fault)
    }
}
struct LateDoor;
impl TestDoor for LateDoor {
    fn door() -> *const Door {
        *DOOR.get_or_init(|| {
            let real = *crate::plane_door_plugin::door();
            // SAFETY: the fixture's table and statement are static.
            let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            let ops = Box::leak(Box::new(Ops { serve: Some(test_op::<LateServe>), ..ops }));
            let door = unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(), ..real.parts()
            }) };
            Box::into_raw(Box::new(door)) as usize
        }) as *const Door
    }
}

#[test]
fn an_abandoned_serve_keeps_its_actual_inputs_until_its_crossing_returns() {
    let gate = Arc::new(Gate::default());
    assert!(GATE.set(Arc::clone(&gate)).is_ok());
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets { call: Duration::from_millis(100), ..Budgets::default() },
        watchdog_period: Duration::from_millis(10),
        ..DispatchConfig::default()
    }));
    let s = Subject::of_raw(test_door::<LateDoor>, "unused", "{}");
    let p = load::<Plane>(&s, Leg::Linked, s.bind(&d, "late-serve")).unwrap();
    assert!(open(&p, b"{}", None).starts_with("Ready"));
    let request = ServeFirst { route: 0, target: b"/late".to_vec(),
        fields: vec![("k".into(), "v".into())], body: b"body".to_vec() };
    let (lend, frame) = ServeLend::frame(Some(&request));
    let held = Arc::downgrade(&lend);
    *gate.owner.lock().unwrap() = held.clone();
    drop(request);
    let (called, frame) = on_ticket_frame(&p, &d, slot::SERVE, frame,
        DeadlineClass::Call, 0, lend);
    let alive = held.upgrade().is_some();
    // Release before asserting so a failure cannot leave a blocked worker.
    gate.state.lock().unwrap().0 = true;
    gate.changed.notify_all();
    assert_eq!(called.outcome, Outcome::Fault);
    assert!(frame.is_none(), "the watchdog abandoned the crossing");
    assert!(alive, "the frame's actual owner survived the caller");
    let state = gate.state.lock().unwrap();
    let (state, timeout) = gate.changed.wait_timeout_while(
        state, Duration::from_secs(10), |s| !s.1,
    ).unwrap();
    assert!(!timeout.timed_out() && state.1 && state.2, "late read lacked its live owner");
    drop(state);
    let until = Instant::now() + Duration::from_secs(10);
    while held.upgrade().is_some() {
        assert!(Instant::now() < until, "loan retained after crossing return");
        std::thread::sleep(Duration::from_millis(1));
    }
}

static FAULT_DOOR: OnceLock<usize> = OnceLock::new();
const UNJUDGED: &[u8] = b"unjudged";
struct ArriveFault;
impl TestOp for ArriveFault {
    fn op(_: *mut std::ffi::c_void, _: *const std::ffi::c_void,
          out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: loader's exclusive typed output; sentinel bytes are live static storage.
        unsafe {
            let out = &mut *out.cast::<ArriveOut>();
            out.pool = abi(UNJUDGED);
            out.head.outcome = RawOutcome::of(Outcome::Fault);
        }
        RawOutcome::of(Outcome::Fault)
    }
}
struct ProjectFault;
impl TestOp for ProjectFault {
    fn op(_: *mut std::ffi::c_void, input: *const std::ffi::c_void,
          out: *mut std::ffi::c_void) -> RawOutcome {
        // SAFETY: loader's typed frame; caller lends an initialized message slot. Sentinel text
        // remains static so the regression never probes invalid or freed memory.
        unsafe {
            let input = &*input.cast::<ProjectIn>();
            if input.messages_cap > 0 {
                let mut turn: MessageView = z();
                turn.role = abi(UNJUDGED);
                turn.text = abi(UNJUDGED);
                input.messages_buf.write(turn);
            }
            let out = &mut *out.cast::<ProjectOut>();
            out.prompt.messages_len = 1;
            out.head.outcome = RawOutcome::of(Outcome::Fault);
        }
        RawOutcome::of(Outcome::Fault)
    }
}
struct FaultDoor;
impl TestDoor for FaultDoor {
    fn door() -> *const Door {
        *FAULT_DOOR.get_or_init(|| {
            let real = *crate::plane_door_plugin::door();
            // SAFETY: real static plane table, with only these two answers restated.
            let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            let ops = Box::leak(Box::new(Ops { arrive: Some(test_op::<ArriveFault>),
                project: Some(test_op::<ProjectFault>), ..ops }));
            let door = unsafe { Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(), ..real.parts()
            }) };
            Box::into_raw(Box::new(door)) as usize
        }) as *const Door
    }
}
#[test]
fn fault_arrival_and_projection_leave_their_borrowed_outputs_unread() {
    let s = Subject::of_raw(test_door::<FaultDoor>, "unused", "{}");
    let d = dispatcher();
    let p = load::<Plane>(&s, Leg::Linked, s.bind(&d, "unjudged-plane")).unwrap();
    assert!(open(&p, b"{}", None).starts_with("Ready"));
    let arrival = Arrival { unit: 1, claim: 0, method: b"GET".to_vec(),
        target: b"/".to_vec(), fields: Vec::new(), route: true };
    let session = Session::of(&serde_json::json!({"name":"unjudged","unit":1,"steps":[]}), 0);
    for line in [arrive(&p, &arrival, b""), project(&p, &session, b"/", b"body", None)] {
        assert!(line.starts_with("Fault ") && line.ends_with(" UNREAD"), "{line}");
        assert!(!line.contains("unjudged"));
    }
    // Positive counterpart over the unchanged real plane uses the same actual caller/buffers.
    let honest = Subject::new(crate::plane_door_plugin::door, "unused", "{}");
    let p = load::<Plane>(&honest, Leg::Linked, honest.bind(&d, "judged-plane")).unwrap();
    assert!(open(&p, b"{}", None).starts_with("Ready"));
    let line = project(&p, &session, b"/", b"body", None);
    assert!(line.starts_with("Ready ") && line.contains("user:body"), "{line}");
}

#[test]
fn the_plane_host_dispatcher_reports_real_deadline_without_wake() {
    use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life, TickIn, TickOut};
    use crate::conformance::{bind, on_ticket, woken};
    use crate::dispatch::{in_head, load_linked, out_head, LinkedRow};
    use crate::dispatch_test_plugin as plug;
    use crate::dispatch_tests::TestKind;
    for missed_wake in [false, true] {
        let _ = woken();
        let host = host::Host::of(&serde_json::json!({})).map(Arc::new);
        assert!(host.is_some());
        let d = leg_dispatcher(host);
        let row = LinkedRow::of_raw(plug::busbar_plugin_door).unwrap();
        let p = load_linked::<TestKind>(&row, bind(&d, "plane-host-wake")).unwrap();
        assert_eq!(crate::conformance::open(&p, b"{}").outcome, Outcome::Ready);
        let mode: &[u8] = if missed_wake { plug::PEND_HOLD } else { plug::PEND_AFTER };
        let mut head = in_head();
        head.extensions = Blob { ptr: mode.as_ptr(), len: mode.len(), fmt: BLOB_OCTETS, flags: 0 };
        let frame = Frame::new(TickIn { head, now_ns: now_ns() },
            TickOut { head: out_head(), next_tick_ns: 0 });
        let until = now_ns().saturating_add(if missed_wake { 50_000_000 } else { 10_000_000_000 });
        let answer = on_ticket(&p, &d, life::TICK, frame, DeadlineClass::Call, until, Arc::new(()));
        if missed_wake {
            assert_ne!(answer.outcome, Outcome::Ready);
            assert!(woken().unwrap_err().contains("bb_deadline_without_wake_total = 1"));
        } else {
            assert_eq!(answer.outcome, Outcome::Ready);
            woken().unwrap();
        }
    }
}
