// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable retired business-table shape solely for strict admission refusal.
use busbar_contract::abi::mechanism::call::{Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::lifecycle::{OpsHead, LIFECYCLE_SLOTS};
pub(crate) const TABLE_SLOTS: u32 = LIFECYCLE_SLOTS + 31;
pub(crate) const LAYOUT: u64 = 0x56bdc8a89ba6e6e0;
/// The unreleased four-primitive table is also refused by the mandatory bootstrap ABI.
pub(crate) const FOUR_PRIMITIVE_LAYOUT: u64 = 0x0cb2ebaf6bc9975a;
#[repr(C)]
struct RetiredTable {
    head: OpsHead,
    slots: [Option<Op>; 31],
}
extern "C" fn refused(
    _: *mut core::ffi::c_void,
    _: *const core::ffi::c_void,
    _: *mut core::ffi::c_void,
) -> RawOutcome {
    RawOutcome::of(Outcome::Refused)
}
pub(crate) fn table() -> *const OpsHead {
    table_with(refused)
}
pub(crate) fn table_with(call: Op) -> *const OpsHead {
    let op = Some(call);
    let table = RetiredTable {
        head: OpsHead {
            size: core::mem::size_of::<RetiredTable>() as u32,
            slots: TABLE_SLOTS,
            validate: op,
            open: op,
            refresh: op,
            retire: op,
            tick: op,
            drive: op,
            cancel: op,
            release: op,
            close: op,
        },
        slots: [op; 31],
    };
    Box::into_raw(Box::new(table)).cast()
}
