// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #74 ON THE CALLER'S THREAD: a forged context handed to the host from inside a NON-lifecycle op
//! (a plane's `arrive`, crossed on the calling thread, not on the FFI worker) quarantines the
//! instance, and the forging op itself answers FAULT.
//!
//! The plane is the plane-driver test plane, LINKED, its door wrapped: `open` keeps the host tables
//! it is handed, and `arrive` first hands the host's `wake` its own context one tag bit off, then
//! answers as the plane does. The plane fixture itself is unchanged.

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::mechanism::call::{AbiStr, InHead, Outcome as AbiOutcome, RawOutcome};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{OpenIn, OpsHead};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, Ops, PlaneOpenIn, PlaneOpenOut, UnitCount,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_plugin_loader::dispatch::{
    kinds::plane::Plane, load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, NO_BLOB,
};

/// A `'static` table of raw pointers, shared read-only.
struct Shared<T>(T);
// SAFETY: written once (`OnceLock`) before any read, never mutated after; the pointers it holds
// are to `'static` plugin data.
unsafe impl<T> Sync for Shared<T> {}
// SAFETY: as above.
unsafe impl<T> Send for Shared<T> {}

/// The host tables `open` was handed: `'static` host memory, kept for the instance's life.
static TABLES: AtomicUsize = AtomicUsize::new(0);

fn inner() -> &'static Ops {
    static INNER: OnceLock<Shared<Ops>> = OnceLock::new();
    &INNER
        .get_or_init(|| {
            // SAFETY: the test plane's door is `'static`; a plane door's `ops` is a plane `Ops`.
            Shared(unsafe { *(*plane::door()).ops.cast::<Ops>() })
        })
        .0
}

extern "C" fn open(i: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    // SAFETY: the host's `open` in, which leads with an `OpenIn`.
    let host = unsafe { (*input.cast::<OpenIn>()).host };
    TABLES.store(host as usize, Ordering::SeqCst);
    (inner().head.open.expect("the plane opens"))(i, input, out)
}

extern "C" fn arrive(i: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    // SAFETY: the tables `open` was handed are the host's, alive for the instance's life; the `in`
    // leads with its `InHead`.
    unsafe {
        let tables = &*(TABLES.load(Ordering::SeqCst) as *const HostTables);
        let ctx = (*input.cast::<InHead>()).host;
        let forged = HostCtx {
            handle: ctx.handle ^ (1 << 24),
        };
        (tables.wake.expect("the host's wake"))(forged, Ticket::NONE);
    }
    (inner().arrive.expect("the plane arrives"))(i, input, out)
}

extern "C" fn door() -> *const Door {
    static OPS: OnceLock<Shared<Ops>> = OnceLock::new();
    static DOOR: OnceLock<Shared<Door>> = OnceLock::new();
    let ops = &OPS
        .get_or_init(|| {
            let mut ops = *inner();
            ops.head.open = Some(open);
            ops.arrive = Some(arrive);
            Shared(ops)
        })
        .0;
    &DOOR
        .get_or_init(|| {
            Shared(Door {
                ops: (ops as *const Ops).cast::<OpsHead>(),
                // SAFETY: the test plane's door is `'static`.
                ..unsafe { *plane::door() }
            })
        })
        .0
}

#[test]
fn a_forged_context_in_a_non_lifecycle_op_answers_fault_and_quarantines() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of(door).expect("the plane states its Statement");
    let plugin = load_linked::<Plane>(&row, bind).expect("the linked door loads");
    let mut open_frame = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                settings: NO_BLOB,
                generation: 1,
                ..blank_in()
            },
            owned: NO_BLOB,
            ..blank_in()
        },
        blank_out::<PlaneOpenOut>(),
    );
    assert_eq!(plugin.open(&mut open_frame).0.outcome, AbiOutcome::Ready);

    let mut units = vec![
        UnitCount {
            class: 0,
            source: 0,
            amount: 0
        };
        16
    ];
    let mut arrive_frame = Frame::new(
        ArriveIn {
            target: AbiStr::over(b"/stats"),
            method: AbiStr::over(b"POST"),
            body: NO_BLOB,
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            ..blank_in()
        },
        blank_out::<ArriveOut>(),
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut arrive_frame).outcome,
        AbiOutcome::Fault,
        "the forging arrive answered other than FAULT"
    );
    assert!(
        plugin.is_faulted(),
        "the forging instance was not quarantined"
    );
    assert_eq!(
        plugin.call(slot::ARRIVE, &mut arrive_frame).outcome,
        AbiOutcome::Fault,
        "a quarantined instance was called again"
    );
}
