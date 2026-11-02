// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Honest readiness must succeed, in addition to having the right invocation count.
use super::*;
use std::sync::OnceLock;
use crate::dispatch_tests::TestKind;
static PASSES: OnceLock<usize> = OnceLock::new();
static FAILS: OnceLock<usize> = OnceLock::new();
struct Ready<const FAIL: bool>;
impl<const FAIL: bool> TestOp for Ready<FAIL> {
    fn op(_: *mut std::ffi::c_void, _: *const std::ffi::c_void,
          out: *mut std::ffi::c_void) -> RawOutcome {
        let answer = RawOutcome::of(if FAIL { Outcome::Failed } else { Outcome::Ready });
        // SAFETY: ready receives the host's initialized exclusive OutHead.
        unsafe { (*out.cast::<OutHead>()).outcome = answer };
        answer
    }
}
impl<const FAIL: bool> TestDoor for Ready<FAIL> {
    fn door() -> *const Door {
        let slot = if FAIL { &FAILS } else { &PASSES };
        *slot.get_or_init(|| {
            let raw = crate::dispatch_test_plugin::busbar_plugin_door();
            // SAFETY: the real test door and all tables it names are static.
            let real = unsafe { Door::read_parts(raw) };
            let door = unsafe { Door::__from_parts(DoorParts {
                ready: Some(test_op::<Ready<FAIL>>), ..real
            }) };
            Box::into_raw(Box::new(door)) as usize
        }) as *const Door
    }
}
fn run<const FAIL: bool>() {
    let d = dispatcher();
    let s = Subject::of_raw(test_door::<Ready<FAIL>>, "unused", "{}");
    let p = load::<TestKind>(&s, Leg::Linked, s.bind(&d, "ready-result")).unwrap();
    assert_eq!(open(&p, b"{}").outcome, Outcome::Ready);
    let mut rec = Recorder::new(crossings(&p));
    ready_step(&mut rec, &s, &p, &d);
    let fold = rec.fold();
    exact(&fold).unwrap();
    assert_eq!(fold.len(), 1);
    assert_eq!(fold[0].answer, "has_ready=true Ok(())");
}
#[test]
fn honest_failed_ready_is_rejected_even_at_its_exact_crossing_count() {
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run::<true>));
    let error = failed.expect_err("failed readiness cannot be an honest fold");
    let text = error.downcast_ref::<String>().map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied()).unwrap_or_default();
    assert!(text.contains("honest door must become ready"), "{text}");
}
#[test]
fn the_same_door_with_successful_ready_passes_at_its_exact_count() {
    run::<false>();
}
