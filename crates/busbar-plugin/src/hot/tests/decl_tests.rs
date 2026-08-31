// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/decl.rs`.

use super::*;

#[test]
fn carriers_reserve_all_five() {
    for c in [
        IngressCarrier::RequestResponse,
        IngressCarrier::ResponseStream,
        IngressCarrier::DuplexSession,
        IngressCarrier::Subscription,
        IngressCarrier::AcceptLoop,
    ] {
        assert_ne!(c.bit(), 0);
    }
    // The five bits are distinct.
    assert_eq!(
        IngressCarrier::AcceptLoop.bit(),
        1 << 4,
        "carrier bit layout is part of the ABI"
    );
}

#[test]
fn stub_decl_declares_three_wired_carriers() {
    let d = &PlaneDecl::STUB;
    assert!(d.provides(IngressCarrier::RequestResponse));
    assert!(d.provides(IngressCarrier::ResponseStream));
    assert!(d.provides(IngressCarrier::DuplexSession));
    assert!(!d.provides(IngressCarrier::Subscription));
    assert!(!d.provides(IngressCarrier::AcceptLoop));
    assert_eq!(crate::check_preamble(&d.abi), Ok(()));
    assert!(d.build.is_some());
    assert!(d.dispatch.is_some());
}

#[test]
fn free_noop_tolerates_null() {
    free_noop(core::ptr::null_mut());
}

// ── Plugin#1 regression: a plugin-implemented slot returns its status BY VALUE as a `RawStatus`
//    u8, NOT the `StatusClass` enum, so a hostile/buggy cdylib returning an out-of-range byte can
//    never materialize an invalid-discriminant enum (UB). Core decodes through the checked
//    `RawStatus::class`, which maps anything outside 0..=4 to the safe `Fault` class. ──

/// A stand-in for a HOSTILE plane slot: it has the exact `HydrateFn` signature but returns a status
/// byte (`7`) that is NOT a valid `StatusClass` discriminant.
extern "C-unwind" fn hostile_hydrate(
    _state: *mut std::os::raw::c_void,
) -> crate::hot::pod::RawStatus {
    crate::hot::pod::RawStatus(7)
}

#[test]
fn out_of_range_slot_return_maps_to_fault_not_ub() {
    use crate::hot::pod::{RawStatus, StatusClass};

    // The bare conversion: every out-of-range byte decodes to the safe Fault class.
    assert_eq!(RawStatus(7).class(), StatusClass::Fault);
    assert_eq!(RawStatus(255).class(), StatusClass::Fault);
    assert_eq!(RawStatus(5).class(), StatusClass::Fault);
    // The valid range round-trips exactly.
    for c in [
        StatusClass::Ok,
        StatusClass::Refused,
        StatusClass::Gone,
        StatusClass::Unsupported,
        StatusClass::Fault,
    ] {
        assert_eq!(RawStatus::of(c).class(), c);
    }

    // The full slot path: a `HydrateFn`-typed pointer returning a hostile 7 is decoded to Fault
    // WITHOUT ever constructing a `StatusClass` from the raw byte (which would be UB).
    let slot: HydrateFn = hostile_hydrate;
    let raw: RawStatus = slot(core::ptr::null_mut());
    assert_eq!(raw.class(), StatusClass::Fault);
}
