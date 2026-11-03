// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicPtr, Ordering};

use busbar_contract::abi::export::{CheckOut, Ops, ServeOut, StatusOut, CHECK_PHASE_LIMITS};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;

use std::sync::Arc;

use crate::dispatch::kinds::export::Export;
use crate::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use crate::export_door::{check, ExportInstance};
use busbar_contract::export_calls::{ExportCalls as _, ServeRequest};

const GARBAGE: *const u8 = 0x10 as *const u8;
const HUGE: usize = 1 << 40;

static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

struct StatusFaults;

impl StatusFaults {
    extern "C" fn op(
        _i: *mut std::ffi::c_void,
        _in: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        // SAFETY: the host hands `status` a `StatusOut`.
        unsafe {
            let o = &mut *out.cast::<StatusOut>();
            o.status = Blob {
                ptr: GARBAGE,
                len: HUGE,
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            o.head.outcome = RawOutcome::of(Outcome::Fault);
        }
        RawOutcome::of(Outcome::Fault)
    }
}

struct CheckFaults;

impl CheckFaults {
    extern "C" fn op(
        _i: *mut std::ffi::c_void,
        _in: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        // SAFETY: the host hands `check` a `CheckOut`.
        unsafe {
            let o = &mut *out.cast::<CheckOut>();
            o.findings = Blob {
                ptr: GARBAGE,
                len: HUGE,
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            o.head.outcome = RawOutcome::of(Outcome::Fault);
        }
        RawOutcome::of(Outcome::Fault)
    }
}

struct ServeFaults;

impl ServeFaults {
    extern "C" fn op(
        _i: *mut std::ffi::c_void,
        _in: *const std::ffi::c_void,
        out: *mut std::ffi::c_void,
    ) -> RawOutcome {
        // SAFETY: the host hands `serve` a `ServeOut`.
        unsafe {
            let o = &mut *out.cast::<ServeOut>();
            o.headers_out = GARBAGE.cast::<AbiStr>();
            o.headers_out_len = HUGE;
            o.body = Blob {
                ptr: GARBAGE,
                len: HUGE,
                fmt: BLOB_OCTETS,
                flags: 0,
            };
            o.head.outcome = RawOutcome::of(Outcome::Fault);
        }
        RawOutcome::of(Outcome::Fault)
    }
}

struct FaultingDoor;

impl FaultingDoor {
    extern "C" fn door() -> &'static Door {
        let have = SLOT.load(Ordering::SeqCst);
        if !have.is_null() {
            // SAFETY: SLOT owns an immutable leaked descriptor.
            return unsafe { &*have };
        }
        let real: Door = *crate::export_door::tests::SCRAPE_DOOR();
        // SAFETY: the real sink's door and its export table are `'static`.
        let ops: Ops = unsafe { real.ops().cast::<Ops>().read_unaligned() };
        let ops: &'static Ops = Box::leak(Box::new(Ops {
            status: Some(StatusFaults::op),
            check: Some(CheckFaults::op),
            serve: Some(ServeFaults::op),
            ..ops
        }));
        let door = Box::into_raw(Box::new(unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
        }));
        SLOT.store(door, Ordering::SeqCst);
        // SAFETY: the descriptor is leaked and its real-image code remains loaded.
        unsafe { &*door }
    }
}

#[test]
fn red_a_fault_answers_garbage_and_the_script_reads_none_of_it() {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(FaultingDoor::door).expect("the restated actual door states itself");
    let p = load_linked::<Export>(
        &row,
        Bind {
            instance: Arc::from("export-unjudged"),
            max_inflight_cap: 16,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .expect("the restated actual door loads");
    let opened = ExportInstance::open(p, d, br#"{ "buffer_seconds": 60 }"#);
    assert!(
        opened.is_ok(),
        "the real Prometheus open must answer READY: {opened:?}"
    );
    let sink = opened.expect("the real Prometheus instance opens");
    assert!(
        sink.status().is_none(),
        "a FAULT status leaves its garbage payload unread",
    );
    let findings = check(sink.plugin(), CHECK_PHASE_LIMITS, &[]);
    assert!(
        matches!(&findings, Err(reason) if reason == "Fault"),
        "a FAULT check leaves its garbage findings unread: {findings:?}",
    );
    let served = sink.serve(&ServeRequest {
        method: "GET",
        path: "/",
        query: None,
        headers: &[],
        body: &[],
    });
    assert!(
        matches!(&served, Err(reason) if reason == "Fault"),
        "a FAULT serve leaves its garbage headers and body unread: {served:?}",
    );
}
