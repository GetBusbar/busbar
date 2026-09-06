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

/// EVERY slot of the stub vtable, checked STRUCTURALLY. The list below is a destructuring pattern,
/// not a series of field reads: adding a slot to `PlaneHostVtable` without naming it here fails to
/// COMPILE ("pattern does not mention field ..."), so the assertion set cannot silently fall behind
/// the ABI the way an append-only surface always eventually does. The previous form asserted 37 of
/// the 44 slots and nothing said so.
#[test]
fn stub_vtable_populates_every_slot() {
    let PlaneHostVtable {
        abi: _,
        size: _,
        version: _,
        govern_admit,
        meter_charge,
        breaker_admit,
        breaker_settle,
        verify_lookup,
        verify_store,
        egress_open,
        egress_poll,
        egress_write,
        egress_close,
        journal_append,
        journal_read,
        nested_dispatch,
        workhandle_open,
        workhandle_resume,
        drift_quarantine,
        approval_redeem,
        metrics_emit,
        clock_now,
        auth_resolve,
        trust_evaluate,
        entitlement_check,
        gate_scan,
        breaker_admit_reason,
        verify_decide,
        approval_redeem_q,
        govern_admit_reason,
        pipe_read,
        pipe_write,
        egress_fault,
        journal_register,
        journal_append_scoped,
        journal_read_scoped,
        journal_restore,
        journal_seed,
        journal_forget,
        journal_compact,
        journal_verify_scoped,
        subkey_sign,
        guard_url,
        identity_admit,
        gate_decide,
        cost_reserve,
        cost_settle,
    } = PlaneHostVtable::STUB;

    for (name, slot) in [
        ("govern_admit", govern_admit.is_some()),
        ("meter_charge", meter_charge.is_some()),
        ("breaker_admit", breaker_admit.is_some()),
        ("breaker_settle", breaker_settle.is_some()),
        ("verify_lookup", verify_lookup.is_some()),
        ("verify_store", verify_store.is_some()),
        ("egress_open", egress_open.is_some()),
        ("egress_poll", egress_poll.is_some()),
        ("egress_write", egress_write.is_some()),
        ("egress_close", egress_close.is_some()),
        ("journal_append", journal_append.is_some()),
        ("journal_read", journal_read.is_some()),
        ("nested_dispatch", nested_dispatch.is_some()),
        ("workhandle_open", workhandle_open.is_some()),
        ("workhandle_resume", workhandle_resume.is_some()),
        ("drift_quarantine", drift_quarantine.is_some()),
        ("approval_redeem", approval_redeem.is_some()),
        ("metrics_emit", metrics_emit.is_some()),
        ("clock_now", clock_now.is_some()),
        ("auth_resolve", auth_resolve.is_some()),
        ("trust_evaluate", trust_evaluate.is_some()),
        ("entitlement_check", entitlement_check.is_some()),
        ("gate_scan", gate_scan.is_some()),
        ("breaker_admit_reason", breaker_admit_reason.is_some()),
        ("verify_decide", verify_decide.is_some()),
        ("approval_redeem_q", approval_redeem_q.is_some()),
        ("govern_admit_reason", govern_admit_reason.is_some()),
        ("pipe_read", pipe_read.is_some()),
        ("pipe_write", pipe_write.is_some()),
        ("egress_fault", egress_fault.is_some()),
        ("journal_register", journal_register.is_some()),
        ("journal_append_scoped", journal_append_scoped.is_some()),
        ("journal_read_scoped", journal_read_scoped.is_some()),
        ("journal_restore", journal_restore.is_some()),
        ("journal_seed", journal_seed.is_some()),
        ("journal_forget", journal_forget.is_some()),
        ("journal_compact", journal_compact.is_some()),
        ("journal_verify_scoped", journal_verify_scoped.is_some()),
        ("subkey_sign", subkey_sign.is_some()),
        ("guard_url", guard_url.is_some()),
        ("identity_admit", identity_admit.is_some()),
        ("gate_decide", gate_decide.is_some()),
        ("cost_reserve", cost_reserve.is_some()),
        ("cost_settle", cost_settle.is_some()),
    ] {
        assert!(slot, "STUB leaves `{name}` unpopulated");
    }

    let vt = &PlaneHostVtable::STUB;
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
