// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/host.rs`.

use super::*;

#[test]
fn empty_vtable_grants_nothing() {
    let vt = &PlaneHostVtable::EMPTY;
    assert!(vt.govern_admit.is_none());
    assert!(vt.egress_open.is_none());
    assert!(vt.auth_resolve.is_none());
    assert!(vt.journal_register.is_none());
    assert!(vt.journal_append_scoped.is_none());
    assert!(vt.journal_verify_scoped.is_none());
    assert!(vt.cost_reserve.is_none());
    assert!(vt.cost_settle.is_none());
    assert_eq!(crate::check_preamble(&vt.abi), Ok(()));
}

#[test]
fn stub_vtable_populates_every_slot() {
    let vt = &PlaneHostVtable::STUB;
    assert!(vt.govern_admit.is_some());
    assert!(vt.meter_charge.is_some());
    assert!(vt.breaker_admit.is_some());
    assert!(vt.breaker_settle.is_some());
    assert!(vt.verify_lookup.is_some());
    assert!(vt.verify_store.is_some());
    assert!(vt.egress_open.is_some());
    assert!(vt.egress_poll.is_some());
    assert!(vt.egress_write.is_some());
    assert!(vt.egress_close.is_some());
    assert!(vt.journal_append.is_some());
    assert!(vt.journal_read.is_some());
    assert!(vt.nested_dispatch.is_some());
    assert!(vt.workhandle_open.is_some());
    assert!(vt.workhandle_resume.is_some());
    assert!(vt.drift_quarantine.is_some());
    assert!(vt.approval_redeem.is_some());
    assert!(vt.metrics_emit.is_some());
    assert!(vt.clock_now.is_some());
    assert!(vt.auth_resolve.is_some());
    assert!(vt.trust_evaluate.is_some());
    assert!(vt.entitlement_check.is_some());
    assert!(vt.gate_scan.is_some());
    assert!(vt.journal_register.is_some());
    assert!(vt.journal_append_scoped.is_some());
    assert!(vt.journal_read_scoped.is_some());
    assert!(vt.journal_restore.is_some());
    assert!(vt.journal_seed.is_some());
    assert!(vt.journal_forget.is_some());
    assert!(vt.journal_compact.is_some());
    assert!(vt.journal_verify_scoped.is_some());
    assert!(vt.subkey_sign.is_some());
    assert!(vt.guard_url.is_some());
    assert!(vt.identity_admit.is_some());
    assert!(vt.gate_decide.is_some());
    assert!(vt.cost_reserve.is_some());
    assert!(vt.cost_settle.is_some());
    assert_eq!(vt.size as usize, core::mem::size_of::<PlaneHostVtable>());
}

/// The minor-19 METERING-LEASE seam: the two stub slots are real, well-typed `extern "C-unwind"`
/// fn-pointers that panic when invoked (the type-level proof the surface compiles). We drive
/// `cost_reserve` with an over-estimate/fee/cap and a null out-param — it must reach the `unimplemented!`.
#[test]
#[should_panic(expected = "cost_reserve")]
fn stub_cost_reserve_is_unimplemented() {
    let vt = &PlaneHostVtable::STUB;
    (vt.cost_reserve.unwrap())(
        core::ptr::null_mut(),
        1_000,
        0,
        10_000,
        true,
        core::ptr::null_mut(),
    );
}

#[test]
#[should_panic(expected = "govern_admit")]
fn stub_slot_is_unimplemented() {
    let vt = &PlaneHostVtable::STUB;
    let g = Facts::new(1, 10, 0, 0, 0, b"p");
    (vt.govern_admit.unwrap())(core::ptr::null_mut(), &*g as *const Facts);
}
