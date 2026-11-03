// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The existing pending-OPEN scheduling control, retaining an actual SQLite instance.
use crate::actual_store;
use crate::dispatch::kinds::store::Store;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::store_v3::LoadedStore;
use busbar_contract::abi::mechanism::call::{InHead, Outcome, RawOutcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::door::{Door, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::OpenOut;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::store::Ops;
use busbar_contract::records::RecordStore;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static OPEN_CALLS: AtomicU32 = AtomicU32::new(0);
static RESUMED: AtomicU32 = AtomicU32::new(0);
static KEPT: OnceLock<Mutex<HashMap<(u64, Ticket), usize>>> = OnceLock::new();

extern "C" fn open_pending(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    // SAFETY: the loader supplies OPEN's live input/output frame and retains its
    // settings and host tables until this pending crossing has settled.
    unsafe {
        let head = &*input.cast::<InHead>();
        let key = (head.host.handle, head.ticket);
        let kept = KEPT.get_or_init(Default::default);
        if head.flags & FLAG_RESUME != 0 {
            if let Some(instance) = kept.lock().unwrap().remove(&key) {
                let output = &mut *out.cast::<OpenOut>();
                *output = crate::dispatch::lifecycle::open_out();
                output.instance = instance as *mut c_void;
                output.head.outcome = RawOutcome::of(Outcome::Ready);
                RESUMED.fetch_add(1, Ordering::SeqCst);
                return RawOutcome::of(Outcome::Ready);
            }
        }
        let ops = &*actual_store::door().ops().cast::<Ops>();
        OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
        let answer = (ops.head.open.expect("actual SQLite OPEN"))(instance, input, out);
        let output = &mut *out.cast::<OpenOut>();
        if answer != RawOutcome::of(Outcome::Ready) || output.head.lease != 0 {
            return answer;
        }
        kept.lock().unwrap().insert(key, output.instance as usize);
        output.instance = std::ptr::null_mut();
        output.head.outcome = RawOutcome::of(Outcome::Pending);
        output.head.wake_at_ns = crate::dispatch::now_ns().saturating_add(1_000_000);
        RawOutcome::of(Outcome::Pending)
    }
}

extern "C" fn pending_door() -> &'static Door {
    static HELD: OnceLock<usize> = OnceLock::new();
    let pointer = *HELD.get_or_init(|| {
        let real = *actual_store::door();
        // SAFETY: actual_store retains the validated real SQLite descriptor/table.
        let mut ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        ops.head.open = Some(open_pending);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: only OPEN's original hostile scheduling boundary is replaced;
        // all SQLite business operations/lifecycle entries and its identity are retained.
        Box::into_raw(Box::new(unsafe {
            Door::__from_parts(DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        })) as usize
    });
    // SAFETY: the descriptor/table above are immutable permanent allocations.
    unsafe { &*(pointer as *const Door) }
}

#[test]
fn a_store_pending_in_open_completes_the_load_and_serves() {
    let before = (
        OPEN_CALLS.load(Ordering::SeqCst),
        RESUMED.load(Ordering::SeqCst),
    );
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(pending_door).expect("actual SQLite metadata");
    let plugin = load_linked::<Store>(
        &row,
        Bind {
            instance: "pending-open-sqlite".into(),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("actual SQLite links");
    let store = LoadedStore::open(
        plugin,
        dispatcher,
        &actual_store::settings(),
        actual_store::mint,
    )
    .expect("the pending actual SQLite OPEN settles");
    assert_eq!(
        OPEN_CALLS.load(Ordering::SeqCst) - before.0,
        1,
        "RESUME returns the instance actual OPEN answered; OPEN runs once"
    );
    assert_eq!(
        RESUMED.load(Ordering::SeqCst) - before.1,
        1,
        "the actual loader resumed exactly one injected pending OPEN"
    );
    RecordStore::add_denylist(&store, "carol", "test").expect("the opened Store serves");
    assert_eq!(
        RecordStore::list_denylist(&store).expect("it reads back"),
        vec!["carol".to_string()]
    );
    assert!(
        KEPT.get().unwrap().lock().unwrap().is_empty(),
        "the settled OPEN retains no orphan instance"
    );
}
