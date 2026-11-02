// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPEN/READY/CLOSE ownership through the qualified actual SQLite descriptor.

#[allow(unsafe_code)]
#[path = "actual_store.rs"]
mod actual_store;

use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::{OutHead, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::OpenOut;
use busbar_contract::abi::store::Ops;
use std::ffi::c_void;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, OnceLock,
};

static OPENED: AtomicUsize = AtomicUsize::new(0);
static CLOSED: AtomicUsize = AtomicUsize::new(0);
static CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn original() -> &'static Ops {
    // SAFETY: actual_store validates the real Store descriptor and retains its image.
    unsafe { &*actual_store::door().ops().cast::<Ops>() }
}

extern "C" fn open(instance: *mut c_void, input: *const c_void, output: *mut c_void) -> RawOutcome {
    // SAFETY: unchanged initialized OPEN frames are forwarded to the real Store slot.
    let result = unsafe { original().head.open.unwrap()(instance, input, output) };
    if result.outcome() == Outcome::Ready {
        // SAFETY: successful real OPEN initialized its live OpenOut instance.
        OPENED.store(
            unsafe { (*output.cast::<OpenOut>()).instance } as usize,
            Ordering::SeqCst,
        );
    }
    result
}

extern "C" fn close(
    instance: *mut c_void,
    input: *const c_void,
    output: *mut c_void,
) -> RawOutcome {
    // SAFETY: the host owns this real instance and initialized CLOSE frames, with no live call.
    let result = unsafe { original().head.close.unwrap()(instance, input, output) };
    CLOSED.store(instance as usize, Ordering::SeqCst);
    if result.outcome() == Outcome::Ready {
        CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    result
}

extern "C" fn failed_ready(_: *mut c_void, _: *const c_void, output: *mut c_void) -> RawOutcome {
    let result = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY receives a live exclusive initialized OutHead.
    unsafe { (*output.cast::<OutHead>()).outcome = result };
    result
}

fn restated(slot: &OnceLock<usize>, failed: bool) -> &'static Door {
    let address = *slot.get_or_init(|| {
        let real = actual_store::door();
        let mut ops = *original();
        ops.head.open = Some(open);
        ops.head.close = Some(close);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: the retained real descriptor/table stays kind-correct; OPEN/CLOSE only
        // forward unchanged frames. The hostile READY slot obeys the declared output shape.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ready: if failed {
                    Some(failed_ready)
                } else {
                    real.parts().ready
                },
                ..real.parts()
            })
        };
        Box::into_raw(Box::new(door)) as usize
    });
    // SAFETY: the descriptor and its copied table were permanently retained above.
    unsafe { &*(address as *const Door) }
}

extern "C" fn failing_door() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    restated(&SLOT, true)
}
extern "C" fn honest_door() -> &'static Door {
    static SLOT: OnceLock<usize> = OnceLock::new();
    restated(&SLOT, false)
}

#[test]
fn an_opened_store_is_closed_when_readiness_fails() {
    for (door, fails) in [
        (
            failing_door as busbar_contract::abi::mechanism::door::DoorFn,
            true,
        ),
        (
            honest_door as busbar_contract::abi::mechanism::door::DoorFn,
            false,
        ),
    ] {
        OPENED.store(0, Ordering::SeqCst);
        CLOSED.store(0, Ordering::SeqCst);
        CLOSE_COUNT.store(0, Ordering::SeqCst);
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let row = LinkedRow::of(door).expect("actual SQLite metadata");
        let plugin = load_linked::<Store>(
            &row,
            Bind {
                instance: "actual-ready-cleanup".into(),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("actual SQLite binds");
        let result = LoadedStore::open(
            plugin,
            dispatcher,
            &actual_store::settings(),
            actual_store::mint,
        );
        let instance = OPENED.load(Ordering::SeqCst);
        assert_ne!(instance, 0, "real OPEN created the instance");
        if fails {
            assert!(result.unwrap_err().contains("ready failed: Failed"));
            assert_eq!(
                CLOSE_COUNT.load(Ordering::SeqCst),
                1,
                "failed READY closes OPEN's instance exactly once"
            );
            assert_eq!(CLOSED.load(Ordering::SeqCst), instance);
        } else {
            let store = result.expect("the actual successful Store opens");
            assert_eq!(
                CLOSE_COUNT.load(Ordering::SeqCst),
                0,
                "successful OPEN retains its live instance"
            );
            drop(store);
            assert_eq!(
                CLOSE_COUNT.load(Ordering::SeqCst),
                1,
                "normal drop closes the actual instance exactly once"
            );
            assert_eq!(CLOSED.load(Ordering::SeqCst), instance);
        }
    }
}
