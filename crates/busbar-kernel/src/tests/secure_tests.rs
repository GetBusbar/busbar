// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/secure.rs`: the egress-trust capability's install and its
//! fail-closed pass-through. The guarded capability's judgement is the connector's
//! (`busbar_core_connector::tls::trust`).

use super::*;

#[test]
fn the_composition_root_install_hands_the_installed_capability_back() {
    // This test installs its own and reads it back, exercising the OnceLock accessor the
    // composition root uses.
    install_egress_trust_host(Arc::new(PassThroughEgressTrust));
    assert!(
        egress_trust_host().is_some(),
        "the just-installed capability reads back"
    );
}

/// THE DESTINATION JUDGEMENT ON THE SEAM (ARCHITECT ruling (C)): the pass-through has no guard
/// behind it and refuses every answer (fail closed).
#[test]
fn the_pass_through_seam_fails_closed() {
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    let refused = PassThroughEgressTrust
        .judge_answer("api.test", &[public], 0)
        .unwrap_err();
    assert_eq!(
        refused.verdict,
        busbar_contract::abi::host::service::DEST_NO_HOST
    );
    assert!(PassThroughEgressTrust.secure_layer().is_none());
}
