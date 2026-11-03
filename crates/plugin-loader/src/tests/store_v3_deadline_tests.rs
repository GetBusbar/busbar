// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ffi::c_void;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::RawSlot;
use busbar_contract::abi::store::{AddUsageBatchIn, HostBytesOut, OpId, RecordGetIn};
use busbar_contract::records::UsageDelta;
use busbar_contract::store_calls::StoreCalls;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink};
use crate::store_v3::LoadedStore;

struct HangsWriteBehind;
impl RawSlot for HangsWriteBehind {
    type In = AddUsageBatchIn;
    type Out = OutHead;
    unsafe fn call(_: *mut c_void, _: &AddUsageBatchIn, _: &mut OutHead) -> Outcome {
        Outcome::Pending
    }
}

struct HangsCall;
impl RawSlot for HangsCall {
    type In = RecordGetIn;
    type Out = HostBytesOut;
    unsafe fn call(_: *mut c_void, _: &RecordGetIn, _: &mut HostBytesOut) -> Outcome {
        Outcome::Pending
    }
}

use crate::actual_store;

mod hung {
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
            let answer = HangsCall::call(instance, &*input.cast::<RecordGetIn>(), output);
            (*out.cast::<busbar_contract::abi::mechanism::call::OutHead>()).outcome =
                RawOutcome::of(answer);
            RawOutcome::of(answer)
        }
    }
    extern "C" fn add_usage_batch(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        // SAFETY: this existing adversarial slot receives the production dispatcher’s
        // correctly typed live frame; no business Store behavior is substituted.
        unsafe {
            let output = &mut *out.cast::<OutHead>();
            let answer =
                HangsWriteBehind::call(instance, &*input.cast::<AddUsageBatchIn>(), output);
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
            ops.add_usage_batch = Some(add_usage_batch);
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

fn open() -> (LoadedStore, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(hung::door).expect("the hung door states its Statement");
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
    .expect("the hung door loads");
    (
        LoadedStore::open(p, d.clone(), &actual_store::settings(), mint).expect("it opens"),
        d,
    )
}

fn mint() -> OpId {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    OpId::from_parts(
        0x7e59,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn a_hung_write_behind_op_does_not_hold_the_reload_drain() {
    let (s, d) = open();
    let s = Arc::new(s);
    let rt = runtime();
    let bg = s.clone();
    let task = rt.spawn(async move {
        let cells = [("k", 60u64, UsageDelta::default())];
        let _ = bg.add_usage_batch(OpId([1; 16]), &cells).await;
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        d.drain(s.plugin(), Duration::from_millis(200)),
        "the drain waits on no WriteBehind op"
    );
    task.abort();
}

#[test]
fn a_hung_call_op_holds_the_reload_drain() {
    let (s, d) = open();
    let s = Arc::new(s);
    let rt = runtime();
    let bg = s.clone();
    let task = rt.spawn(async move {
        let _ = StoreCalls::record_get(&*bg, "sch", b"k").await;
    });
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !d.drain(s.plugin(), Duration::from_millis(200)),
        "a Call-class op in flight is waited on"
    );
    task.abort();
}
