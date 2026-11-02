// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::protocol::{ClaimStrength, IngressAuth, ProtocolDecl};
use busbar_kernel::ingress::protocols as kernel;
use busbar_kernel_testkit::test_support::protocols::register_test_protocols;

fn claim(path: &str) -> Option<ClaimStrength> {
    (path == "/registered").then_some(ClaimStrength(1))
}

static FIRST: ProtocolDecl = ProtocolDecl {
    residual_default: true,
    ingress_auth: IngressAuth::SigV4,
    residual_claims: Some(claim),
    auth_failure_message: "registered refusal",
    quota_exceeded_status: 418,
    auth_failure_status_and_kind: (403, "registered-denied"),
    ..ProtocolDecl::named("registered-protocol")
};
static SECOND: ProtocolDecl = ProtocolDecl {
    quota_exceeded_status: 409,
    ..ProtocolDecl::named("later-protocol")
};

#[test]
fn registration_installs_once_and_callbacks_read_later_registry_updates() {
    assert_eq!(kernel::residual_default_dialect(), None);
    assert!(!kernel::uses_signed_ingress_auth(FIRST.name));
    register_test_protocols(&[&FIRST]);
    assert_eq!(kernel::residual_default_dialect(), Some(FIRST.name));
    assert_eq!(
        kernel::residual_dialect_for_path("/registered"),
        Some(FIRST.name)
    );
    assert_eq!(
        kernel::vendor_auth_failure_message(FIRST.name),
        "registered refusal"
    );
    assert_eq!(kernel::quota_exceeded_status(FIRST.name), 418);
    assert_eq!(
        kernel::auth_failure_status_and_kind(FIRST.name),
        (403, "registered-denied")
    );
    assert!(kernel::uses_signed_ingress_auth(FIRST.name));
    register_test_protocols(&[&FIRST, &SECOND]);
    assert!(!kernel::uses_signed_ingress_auth(SECOND.name));
    assert!(!kernel::uses_signed_ingress_auth("unknown-protocol"));
    assert_eq!(kernel::quota_exceeded_status(SECOND.name), 409);
    assert_eq!(kernel::residual_default_dialect(), Some(FIRST.name));
    assert_eq!(kernel::residual_dialect_for_path("/unknown"), None);
}
