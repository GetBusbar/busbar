// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (audit loader-conformance #4): the export script reads what an answer names only when the
//! host JUDGED it (THE DESIGN §11.13 M1). A door whose `status`, `check` and `serve` answer FAULT
//! with garbage pointers and lengths in their `out` fails the script's line cleanly; a script that
//! forms slices from them anyway reads arbitrary memory (and crashes the test process).

use std::sync::atomic::{AtomicPtr, Ordering};

use busbar_contract::abi::export::{CheckOut, Ops, ServeOut, StatusOut, CHECK_PHASE_LIMITS};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::door::Door;

use super::{check, serve, status};
use crate::conformance::{
    dispatcher, load, open, test_door, test_op, Leg, Subject, TestDoor, TestOp,
};
use crate::dispatch::kinds::export::Export;

/// An address no allocation holds, and a length no slice may have.
const GARBAGE: *const u8 = 0x10 as *const u8;
const HUGE: usize = 1 << 40;

static SLOT: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());

/// FAULT, every pointer in its `out` garbage.
struct StatusFaults;

impl TestOp for StatusFaults {
    fn op(
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

impl TestOp for CheckFaults {
    fn op(
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

impl TestOp for ServeFaults {
    fn op(
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

impl TestDoor for FaultingDoor {
    fn door() -> *const Door {
        let have = SLOT.load(Ordering::SeqCst);
        if !have.is_null() {
            return have;
        }
        // SAFETY: the real sink's door and its export table are `'static`.
        let real: Door = unsafe { busbar_export_prometheus::door::door().read_unaligned() };
        let ops: Ops = unsafe { real.ops.cast::<Ops>().read_unaligned() };
        let ops: &'static Ops = Box::leak(Box::new(Ops {
            status: Some(test_op::<StatusFaults>),
            check: Some(test_op::<CheckFaults>),
            serve: Some(test_op::<ServeFaults>),
            ..ops
        }));
        let door = Box::into_raw(Box::new(Door {
            ops: std::ptr::from_ref(ops).cast(),
            ..real
        }));
        SLOT.store(door, Ordering::SeqCst);
        door
    }
}

#[test]
fn red_a_fault_answers_garbage_and_the_script_reads_none_of_it() {
    let s = Subject::new(test_door::<FaultingDoor>, "unused", "{}");
    let d = dispatcher();
    let p = load::<Export>(&s, Leg::Linked, s.bind(&d, "export")).expect("the restated door loads");
    let opened = open(&p, br#"{ "buffer_seconds": 60 }"#);
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
    let (line, _) = status(&p);
    assert!(
        line.starts_with("Fault ") && line.ends_with(" status=<unread>"),
        "{line}"
    );
    let (line, _) = check(&p, CHECK_PHASE_LIMITS, &[]);
    assert!(
        line.starts_with("Fault ") && line.ends_with(" findings=<unread>"),
        "{line}"
    );
    let (line, _) = serve(&p, &serde_json::json!({ "path": "/" }));
    assert!(
        line.starts_with("Fault ") && line.ends_with(" headers=<unread> body=<unread>"),
        "{line}"
    );
}
