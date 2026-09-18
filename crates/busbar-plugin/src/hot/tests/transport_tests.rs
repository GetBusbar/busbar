// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/transport.rs`.

use super::*;

#[test]
fn facets_are_the_two_bidirectional_directions() {
    // Direction is a binary usage-mode axis (DECISIONS #3), so exactly two facets, distinct bits.
    assert_ne!(TransportFacet::Accept.bit(), 0);
    assert_ne!(TransportFacet::Connect.bit(), 0);
    assert_eq!(
        TransportFacet::Accept.bit(),
        1 << 0,
        "facet bit layout is part of the ABI"
    );
    assert_eq!(
        TransportFacet::Connect.bit(),
        1 << 1,
        "facet bit layout is part of the ABI"
    );
    assert_eq!(
        TransportFacet::bidirectional(),
        TransportFacet::Accept.bit() | TransportFacet::Connect.bit()
    );
}

#[test]
fn stub_decl_declares_both_directions_and_type_checks() {
    let d = &TransportDecl::STUB;
    // A stub carrier is fully bidirectional — both server-accept and client-connect.
    assert!(d.provides(TransportFacet::Accept));
    assert!(d.provides(TransportFacet::Connect));
    assert_eq!(crate::check_preamble(&d.abi), Ok(()));
    assert!(d.build.is_some());
    assert!(d.accept.is_some());
    assert!(d.connect.is_some());
    assert!(d.write.is_some());
    assert!(d.read.is_some());
    // The decl attests its own size (the sized-struct guard the loader honours).
    assert_eq!(d.size as usize, core::mem::size_of::<TransportDecl>());
}

// ── Same hostile-slot regression as the plane decl: a slot returns its status BY VALUE as a
//    `RawStatus` byte, so an out-of-range byte maps to the safe `Fault` class, never UB. ──
extern "C-unwind" fn hostile_accept(
    _state: *mut std::os::raw::c_void,
    _out_conn: *mut core::mem::MaybeUninit<super::super::decl::OpaqueHandle>,
) -> crate::hot::pod::RawStatus {
    crate::hot::pod::RawStatus(9)
}

#[test]
fn out_of_range_slot_return_maps_to_fault_not_ub() {
    use crate::hot::pod::StatusClass;
    let s = hostile_accept(core::ptr::null_mut(), core::ptr::null_mut());
    assert_eq!(s.class(), StatusClass::Fault);
}
