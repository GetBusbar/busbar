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
