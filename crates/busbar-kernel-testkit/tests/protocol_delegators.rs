// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::ingress::protocols::{self, ProtocolTestHooks};

#[test]
fn a_test_install_delegates_every_existing_fallback_call() {
    assert_eq!(protocols::residual_dialect_for_path("/fixture"), None);
    assert_eq!(protocols::residual_default_dialect(), None);
    assert_eq!(
        protocols::vendor_auth_failure_message("fixture"),
        "authentication failed"
    );
    assert_eq!(protocols::quota_exceeded_status("fixture"), 429);
    assert_eq!(protocols::auth_failure_status_and_kind("fixture").0, 401);
    assert_eq!(
        protocols::error_parts("fixture", 400, "kind", "message").0["error"]["message"],
        "message"
    );

    assert!(!protocols::uses_signed_ingress_auth("fixture"));

    protocols::install_test_hooks(ProtocolTestHooks {
        residual_dialect_for_path: |path| (path == "/fixture").then_some("fixture-path"),
        residual_default_dialect: || Some("fixture-default"),
        vendor_auth_failure_message: |_| "fixture refused",
        quota_exceeded_status: |_| 418,
        auth_failure_status_and_kind: |_| (403, "fixture-denied"),
        signed_ingress: |proto| proto == "fixture",
        error_parts: |_, _, _, _| {
            (
                Default::default(),
                vec![("fixture-field".to_owned(), b"value".to_vec())],
            )
        },
    });
    assert_eq!(
        protocols::residual_dialect_for_path("/fixture"),
        Some("fixture-path")
    );
    assert_eq!(protocols::residual_dialect_for_path("/other"), None);
    assert_eq!(
        protocols::residual_default_dialect(),
        Some("fixture-default")
    );
    assert_eq!(
        protocols::vendor_auth_failure_message("fixture"),
        "fixture refused"
    );
    assert_eq!(protocols::quota_exceeded_status("fixture"), 418);
    assert_eq!(
        protocols::auth_failure_status_and_kind("fixture"),
        (403, "fixture-denied")
    );
    assert!(protocols::uses_signed_ingress_auth("fixture"));
    assert!(!protocols::uses_signed_ingress_auth("other"));
    let (body, fields) = protocols::error_parts("fixture", 400, "kind", "message");
    assert!(body.is_null(), "the kit's answer is used whole");
    assert_eq!(
        fields,
        vec![("fixture-field".to_owned(), b"value".to_vec())]
    );
}
