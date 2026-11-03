// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::RawSlot;
use busbar_contract::abi::store::{GetPlaneRecordIn, HostBytesOut, OpId, RecordGetIn};
use busbar_contract::records::RecordStore;
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, Budgets, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

struct Gate {
    state: Mutex<(bool, Option<Vec<u8>>)>,
    cv: Condvar,
}

impl Gate {
    const fn new() -> Self {
        Self {
            state: Mutex::new((false, None)),
            cv: Condvar::new(),
        }
    }

    fn hold_then_read(&self, ptr: *const u8, len: usize) {
        let mut g = self.state.lock().unwrap();
        while !g.0 {
            g = self.cv.wait(g).unwrap();
        }
        // SAFETY: the bytes the op's `in` names; the host keeps them alive until the crossing
        // returns (the property under test).
        let read = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        g.1 = Some(read);
        self.cv.notify_all();
    }

    fn release_and_read(&self) -> Vec<u8> {
        let mut g = self.state.lock().unwrap();
        g.0 = true;
        self.cv.notify_all();
        let (mut g, timeout) = self
            .cv
            .wait_timeout_while(g, Duration::from_secs(10), |s| s.1.is_none())
            .unwrap();
        assert!(!timeout.timed_out(), "the wedged crossing never returned");
        g.1.take().unwrap()
    }
}

static GET_GATE: Gate = Gate::new();
static PLANE_GATE: Gate = Gate::new();

struct WedgedGet;
impl RawSlot for WedgedGet {
    type In = RecordGetIn;
    type Out = HostBytesOut;
    unsafe fn call(_: *mut c_void, i: &RecordGetIn, _: &mut HostBytesOut) -> Outcome {
        GET_GATE.hold_then_read(i.key.ptr, i.key.len);
        Outcome::Ready
    }
}

struct WedgedPlaneGet;
impl RawSlot for WedgedPlaneGet {
    type In = GetPlaneRecordIn;
    type Out = HostBytesOut;
    unsafe fn call(_: *mut c_void, i: &GetPlaneRecordIn, _: &mut HostBytesOut) -> Outcome {
        PLANE_GATE.hold_then_read(i.id.ptr, i.id.len);
        Outcome::Ready
    }
}

use crate::actual_store;

mod wedged {
    use super::*;
    use busbar_contract::abi::mechanism::call::RawOutcome;
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::store::Ops;
    use std::sync::OnceLock;
    extern "C" fn record_get(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: this existing adversarial slot receives the production dispatcher’s
        // correctly typed live frame; no business Store behavior is substituted.
        unsafe {
            let output = &mut *out.cast::<HostBytesOut>();
            let answer = WedgedGet::call(instance, &*input.cast::<RecordGetIn>(), output);
            (*out.cast::<busbar_contract::abi::mechanism::call::OutHead>()).outcome =
                RawOutcome::of(answer);
            RawOutcome::of(answer)
        }
    }
    extern "C" fn get_plane_record(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: this existing adversarial slot receives the production dispatcher’s
        // correctly typed live frame; no business Store behavior is substituted.
        unsafe {
            let output = &mut *out.cast::<HostBytesOut>();
            let answer = WedgedPlaneGet::call(instance, &*input.cast::<GetPlaneRecordIn>(), output);
            (*out.cast::<busbar_contract::abi::mechanism::call::OutHead>()).outcome =
                RawOutcome::of(answer);
            RawOutcome::of(answer)
        }
    }
    pub(super) extern "C" fn door() -> &'static Door {
        static HELD: OnceLock<usize> = OnceLock::new();
        let ptr = *HELD.get_or_init(|| {
            let real = *actual_store::door();
            // SAFETY: actual_store retains the validated real SQLite descriptor/table.
            let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
            ops.record_get = Some(record_get);
            ops.get_plane_record = Some(get_plane_record);
            let ops = Box::leak(Box::new(ops));
            // SAFETY: retain every genuine lifecycle/kind operation except the narrowly
            // overridden adversarial slots above, and retain the copied table forever.
            let door = unsafe {
                Door::__from_parts(DoorParts {
                    ops: std::ptr::from_ref(ops).cast(),
                    ..real.parts()
                })
            };
            Box::into_raw(Box::new(door)) as usize
        });
        // SAFETY: HELD contains a permanent immutable descriptor allocation.
        unsafe { &*(ptr as *const Door) }
    }
}

fn open() -> LoadedStore {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets {
            call: Duration::from_millis(50),
            ..Budgets::default()
        },
        watchdog_period: Duration::from_millis(10),
        ..DispatchConfig::default()
    }));
    let row = LinkedRow::of(wedged::door).expect("the wedged door states its Statement");
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: crate::dispatch::ConnTable::NoNeeds,
        },
    )
    .expect("the wedged door loads");
    LoadedStore::open(p, d, &actual_store::settings(), mint).expect("it opens")
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x1e47,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

const LENT: u8 = 0xab;

#[test]
fn a_watchdog_faulted_typed_call_keeps_the_memory_it_lent() {
    let s = open();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    let mut key = vec![LENT; 64];
    let answered = rt.block_on(StoreCalls::record_get(&s, "sch", &key));
    assert!(
        answered.is_err(),
        "the watchdog faults the wedged op and the caller is answered: {answered:?}"
    );

    key.fill(0);
    let read = GET_GATE.release_and_read();
    assert_eq!(
        read,
        vec![LENT; 64],
        "the abandoned crossing read the caller's memory after the call returned"
    );
    drop(key);
}

#[test]
fn a_watchdog_faulted_bridge_call_keeps_the_memory_it_lent() {
    let s = open();
    let mut id = String::from_utf8(vec![b'q'; 48]).unwrap();
    let answered = RecordStore::get_plane_record(&s, "kind", &id);
    assert!(
        answered.is_err(),
        "the watchdog faults the wedged op and the caller is answered: {answered:?}"
    );
    // SAFETY: ASCII over ASCII keeps the string valid UTF-8.
    unsafe { id.as_bytes_mut() }.fill(b'z');
    let read = PLANE_GATE.release_and_read();
    assert_eq!(
        read,
        vec![b'q'; 48],
        "the abandoned crossing read the caller's memory after the call returned"
    );
    drop(id);
}
