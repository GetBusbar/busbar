// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{Op as Crossing, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::store::Ops;
use std::ffi::c_void;
use std::sync::OnceLock;

busbar_contract::statement_extensions!(APPLIED: [(rewrap::RESULT, b"applied")]);
busbar_contract::statement_extensions!(INVALID: [(rewrap::RESULT, b"unknown-result")]);

struct Fixture(Door, Ops);
// SAFETY: initialized once from static SDK data, with an immutable table held in its box.
unsafe impl Send for Fixture {}
// SAFETY: the initialized box and every pointer it names stay immutable for the process.
unsafe impl Sync for Fixture {}

fn door(cell: &'static OnceLock<Box<Fixture>>, slot: Crossing) -> &'static Door {
    &cell
        .get_or_init(|| {
            let original = capable::door();
            // SAFETY: the SDK door owns the static store table.
            let mut ops = unsafe { *original.ops().cast::<Ops>() };
            ops.put_credential = Some(slot);
            let mut fixture = Box::new(Fixture(*original, ops));
            let parts = busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(&fixture.1).cast(),
                ..original.parts()
            };
            // SAFETY: the SDK's static Statement and lifecycle over the boxed immutable table.
            // Its replacement slot honors the same BlobIn/OutHead call shapes.
            fixture.0 = unsafe { Door::__from_parts(parts) };
            fixture
        })
        .0
}

fn corrupt(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
    invalid: bool,
) -> RawOutcome {
    // SAFETY: this is the SDK's static store table.
    let ops = unsafe { &*capable::door().ops().cast::<Ops>() };
    let Some(call) = ops.put_credential else {
        return RawOutcome::of(Outcome::Fault);
    };
    let ran = call(instance, input, out);
    if ran.outcome() == Outcome::Ready {
        // SAFETY: the loader lent this exact live OutHead. Preserve the SDK lease so the
        // real release path still retires its result memory.
        let head = unsafe { &mut *out.cast::<OutHead>() };
        head.extensions = if invalid { INVALID } else { Blob::ABSENT };
    }
    ran
}

extern "C" fn missing(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    corrupt(instance, input, out, false)
}
extern "C" fn invalid(instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    corrupt(instance, input, out, true)
}
extern "C" fn unleased(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
    let ran = RawOutcome::of(Outcome::Ready);
    let mut head = out_head();
    head.outcome = ran;
    head.extensions = APPLIED;
    // SAFETY: the exact OutHead lent by the loader. Static result bytes intentionally have no
    // lease, so READY must not become a claimed successful CAS.
    unsafe { out.cast::<OutHead>().write_unaligned(head) };
    ran
}

extern "C" fn missing_door() -> &'static Door {
    static ONE: OnceLock<Box<Fixture>> = OnceLock::new();
    door(&ONE, missing)
}
extern "C" fn invalid_door() -> &'static Door {
    static ONE: OnceLock<Box<Fixture>> = OnceLock::new();
    door(&ONE, invalid)
}
extern "C" fn unleased_door() -> &'static Door {
    static ONE: OnceLock<Box<Fixture>> = OnceLock::new();
    door(&ONE, unleased)
}

pub const CASES: [(DoorFn, &str); 3] = [
    (missing_door, "result is missing or invalid"),
    (invalid_door, "result is missing or invalid"),
    (unleased_door, "without a leased result"),
];
