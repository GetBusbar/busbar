// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ordinary dispatcher loan controls. The only operation replacements below are
//! the original hostile ABI answers; all descriptors and live instances are MCP.

use crate::dispatch::kinds::plane::{open_door, Plane};
use crate::dispatch::lifecycle::blob;
use crate::dispatch::{
    in_head, load_linked, out_head, Bind, Budgets, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, DeadlineClass, Outcome, RawOutcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::plane::{slot, FieldList, Ops, ServeIn, ServeOut};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

fn blank<T>() -> T {
    // SAFETY: used only for the ABI's plain integer/raw-pointer frames.
    unsafe { std::mem::zeroed() }
}
fn bound(door: DoorFn, d: &Dispatcher, label: &str) -> Plugin<Plane> {
    let row = LinkedRow::of(door).expect("actual MCP descriptor");
    let p = load_linked::<Plane>(
        &row,
        Bind {
            instance: label.into(),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual MCP instance binds");
    open_door(&p, b"{}", b"{}", None).expect("actual MCP opens");
    p
}
struct ServeLoan {
    target: Vec<u8>,
    fields: FieldList,
    body: Vec<u8>,
}

#[derive(Default)]
struct Gate {
    state: Mutex<(bool, bool, bool)>,
    changed: Condvar,
    owner: Mutex<Weak<ServeLoan>>,
}
static GATE: OnceLock<Arc<Gate>> = OnceLock::new();
static DOOR: OnceLock<usize> = OnceLock::new();
extern "C" fn late_serve(
    _: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    let gate = GATE.get().expect("test installed its gate");
    let state = gate.state.lock().unwrap();
    let (state, _) = gate
        .changed
        .wait_timeout_while(state, Duration::from_secs(10), |s| !s.0)
        .unwrap();
    let released = state.0;
    drop(state);

    let observed = released
        && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = gate
                .owner
                .lock()
                .unwrap()
                .upgrade()
                .expect("actual loan is alive");
            // SAFETY: loader supplied this frame. Establish all nested allocation identities first.
            let i = unsafe { input.cast::<ServeIn>().read() };
            assert_eq!(
                (i.target.ptr, i.target.len),
                (owner.target.as_ptr(), owner.target.len())
            );
            assert_eq!(
                (i.body.ptr, i.body.len),
                (owner.body.as_ptr(), owner.body.len())
            );
            assert_eq!(
                (i.fields, i.fields_len),
                (owner.fields.as_ptr(), owner.fields.len())
            );
            // SAFETY: exact live initialized allocation bounds established above.
            assert_eq!(
                unsafe { std::slice::from_raw_parts(i.target.ptr, i.target.len) },
                b"/late"
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(i.body.ptr, i.body.len) },
                b"body"
            );
            let field = unsafe { i.fields.read() };
            let owned = unsafe { owner.fields.as_ptr().read() };
            assert_eq!(
                (field.name.ptr, field.name.len),
                (owned.name.ptr, owned.name.len)
            );
            assert_eq!(
                (field.value.ptr, field.value.len),
                (owned.value.ptr, owned.value.len)
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(field.name.ptr, field.name.len) },
                b"k"
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(field.value.ptr, field.value.len) },
                b"v"
            );
        }))
        .is_ok();
    let mut state = gate.state.lock().unwrap();
    state.1 = true;
    state.2 = observed;
    drop(state);
    gate.changed.notify_all();
    // SAFETY: loader owns this initialized exclusive ServeOut until crossing return.
    unsafe { (*out.cast::<ServeOut>()).head.outcome = RawOutcome::of(Outcome::Fault) };
    RawOutcome::of(Outcome::Fault)
}
extern "C" fn late_door() -> &'static Door {
    let at = *DOOR.get_or_init(|| {
        let real = *crate::actual_mcp::door();
        // SAFETY: the fixture's table and statement are static.
        let ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        let ops = Box::leak(Box::new(Ops {
            serve: Some(late_serve),
            ..ops
        }));
        let door = unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: the descriptor and backing actual product image remain process-live.
    unsafe { &*(at as *const Door) }
}

#[test]
fn an_abandoned_serve_keeps_its_actual_inputs_until_its_crossing_returns() {
    let gate = Arc::new(Gate::default());
    assert!(GATE.set(Arc::clone(&gate)).is_ok());
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets {
            call: Duration::from_millis(100),
            ..Budgets::default()
        },
        watchdog_period: Duration::from_millis(10),
        ..DispatchConfig::default()
    }));
    let p = bound(late_door, &d, "late-serve");
    let loan = Arc::new(ServeLoan {
        target: b"/late".to_vec(),
        fields: FieldList::new(vec![(b"k".to_vec(), b"v".to_vec())]),
        body: b"body".to_vec(),
    });
    let mut input: ServeIn = blank();
    input.head = in_head();
    input.target = AbiStr::over(&loan.target);
    input.body = blob(&loan.body, BLOB_OCTETS, 0);
    input.fields = loan.fields.as_ptr();
    input.fields_len = loan.fields.len();
    let mut out: ServeOut = blank();
    out.head = out_head();
    let held = Arc::downgrade(&loan);
    *gate.owner.lock().unwrap() = held.clone();
    let ticket = d.mint(0).expect("a unit ticket");
    let reply = d.submit_lent(
        &p,
        ticket,
        slot::SERVE,
        Frame::new(input, out),
        DeadlineClass::Call,
        0,
        loan,
    );
    let called = reply
        .wait(Duration::from_secs(10))
        .expect("watchdog answers abandoned crossing");
    let alive = held.upgrade().is_some();

    gate.state.lock().unwrap().0 = true;
    gate.changed.notify_all();
    assert_eq!(called.outcome, Outcome::Fault);
    assert!(
        called.frame.is_none(),
        "the watchdog abandoned the crossing"
    );
    assert!(alive, "the frame's actual owner survived the caller");
    let state = gate.state.lock().unwrap();
    let (state, timeout) = gate
        .changed
        .wait_timeout_while(state, Duration::from_secs(10), |s| !s.1)
        .unwrap();
    assert!(
        !timeout.timed_out() && state.1 && state.2,
        "late read lacked its live owner"
    );
    drop(state);
    let until = Instant::now() + Duration::from_secs(10);
    while held.upgrade().is_some() {
        assert!(
            Instant::now() < until,
            "loan retained after crossing return"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    d.recycle(ticket);
}
