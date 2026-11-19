// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel gate's credential carriers on the actual root build.
//!
//! THE DESIGN (c3faaa06c1 "Delete the kernel's plugin auth axis", pinned in busbar-kernel
//! `auth/tests/no_axis_tests.rs`): with no `kind: auth` plugin axis the data chain has no
//! credential readers and no carriers, and the operator carries nothing. A data credential is read
//! natively, from `authorization` and the D_CRED_HEADER lines the chain's instances declare
//! (`auth::native_data::withheld_carriers`), never from a default inbound style. So the kernel gate
//! reads no credential from any header a chain did not declare, and `x-admin-token` is no operator
//! carrier (Bearer only, ADMIN-API-1.6-ONE-MODEL §8.1).
//!
//! The extraction rule a declared carrier list is read by (`carried_credential`) is pinned here
//! over explicit lists: `authorization` yields only a non-empty Bearer, any other carrier only a
//! non-empty value, the first carrier in list order wins, and a header not in the list is never read.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, Request};
use busbar_kernel::auth::{carried_credential, AuthMiddleware};
use busbar_kernel::config::{AuthCfg, AuthChainEntry};

const X_ADMIN_TOKEN: &str = "x-admin-token";

/// The carriers the deleted axis' default inbound style named, in its order.
fn formerly_default_carriers() -> [HeaderName; 3] {
    [
        HeaderName::from_static("authorization"),
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("x-goog-api-key"),
    ]
}

fn headers(lines: &[(&str, &str)]) -> HeaderMap {
    let mut req = Request::builder().uri("/v1/messages");
    for (name, value) in lines {
        req = req.header(*name, *value);
    }
    req.body(Body::empty())
        .expect("test request must build")
        .headers()
        .clone()
}

fn gate(cfg: &AuthCfg) -> AuthMiddleware {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    AuthMiddleware::new(
        cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual data chain builds")
}

fn keys_chain() -> AuthCfg {
    let mut cfg = AuthCfg::default_none();
    cfg.chain = vec![AuthChainEntry::bare(busbar_kernel::config::KEYS_MODULE)];
    cfg
}

/// Every carrier the deleted default inbound style read, alone and together.
fn every_formerly_carried_head() -> Vec<HeaderMap> {
    vec![
        headers(&[("authorization", "Bearer tok-abc")]),
        headers(&[("x-api-key", "tok-x-api-key")]),
        headers(&[("x-goog-api-key", "tok-x-goog-api-key")]),
        headers(&[
            ("authorization", "Bearer from-auth"),
            ("x-api-key", "from-x-api-key"),
            ("x-goog-api-key", "from-goog"),
        ]),
    ]
}

#[test]
fn test_default_chain_reads_no_undeclared_carrier() {
    let mw = gate(&AuthCfg::default_none());
    for head in every_formerly_carried_head() {
        assert_eq!(
            mw.extract_client_token(&head),
            None,
            "a chain that declares no carrier reads no credential (no default inbound style): \
             {head:?}"
        );
    }
}

#[test]
fn test_keys_chain_reads_no_undeclared_carrier() {
    let mw = gate(&keys_chain());
    assert!(mw.keys_in_chain);
    for head in every_formerly_carried_head() {
        assert_eq!(
            mw.extract_client_token(&head),
            None,
            "the kernel gate of a keys chain declares no carrier; keys is judged natively: \
             {head:?}"
        );
    }
}

#[test]
fn test_keys_chain_without_carried_credential_is_denied() {
    let mw = gate(&keys_chain());
    let head = headers(&[("authorization", "Bearer tok-abc")]);
    let candidate = mw.extract_client_token(&head);
    assert!(
        !mw.validate_token(candidate.as_deref()),
        "a keys chain that reads no credential denies; it never opens"
    );
}

#[test]
fn test_carried_credential_each_carrier_alone() {
    let carriers = formerly_default_carriers();
    for (line, value, expected) in [
        ("authorization", "Bearer tok-abc", "tok-abc"),
        ("x-api-key", "tok-x-api-key", "tok-x-api-key"),
        ("x-goog-api-key", "tok-x-goog-api-key", "tok-x-goog-api-key"),
    ] {
        assert_eq!(
            carried_credential(&carriers, &headers(&[(line, value)])),
            Some(expected.to_string()),
            "{line}"
        );
    }
    assert_eq!(carried_credential(&carriers, &headers(&[])), None);
}

#[test]
fn test_carried_credential_precedence_is_list_order() {
    let carriers = formerly_default_carriers();
    let all = headers(&[
        ("authorization", "Bearer from-auth"),
        ("x-api-key", "from-x-api-key"),
        ("x-goog-api-key", "from-goog"),
    ]);
    assert_eq!(
        carried_credential(&carriers, &all),
        Some("from-auth".to_string())
    );
    let no_bearer = headers(&[
        ("x-api-key", "from-x-api-key"),
        ("x-goog-api-key", "from-goog"),
    ]);
    assert_eq!(
        carried_credential(&carriers, &no_bearer),
        Some("from-x-api-key".to_string())
    );
}

#[test]
fn test_carried_credential_empty_carrier_falls_through() {
    let carriers = formerly_default_carriers();
    let head = headers(&[("x-api-key", ""), ("x-goog-api-key", "tok-x-goog-api-key")]);
    assert_eq!(
        carried_credential(&carriers, &head),
        Some("tok-x-goog-api-key".to_string())
    );
    let blank_bearer = headers(&[("authorization", "Bearer "), ("x-api-key", "")]);
    assert_eq!(carried_credential(&carriers, &blank_bearer), None);
}

#[test]
fn test_carried_credential_non_bearer_authorization_falls_through() {
    let carriers = formerly_default_carriers();
    for non_bearer in [
        "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/svc/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef",
        "Basic dXNlcjpwYXNz",
    ] {
        assert_eq!(
            carried_credential(
                &carriers,
                &headers(&[("authorization", non_bearer), ("x-api-key", "tok")])
            ),
            Some("tok".to_string()),
            "a non-bearer Authorization ('{non_bearer}') must fall through to x-api-key"
        );
        assert_eq!(
            carried_credential(
                &carriers,
                &headers(&[
                    ("authorization", non_bearer),
                    ("x-goog-api-key", "goog-tok")
                ])
            ),
            Some("goog-tok".to_string()),
            "a non-bearer Authorization ('{non_bearer}') must fall through to x-goog-api-key"
        );
        assert_eq!(
            carried_credential(&carriers, &headers(&[("authorization", non_bearer)])),
            None,
            "a non-bearer Authorization is never taken as the credential"
        );
    }
}

#[test]
fn test_carried_credential_never_reads_an_undeclared_line() {
    let bearer_only = [HeaderName::from_static("authorization")];
    let head = headers(&[
        ("x-api-key", "tok-x-api-key"),
        ("x-goog-api-key", "tok-x-goog-api-key"),
        (X_ADMIN_TOKEN, "admintok"),
    ]);
    assert_eq!(carried_credential(&bearer_only, &head), None);
    assert_eq!(carried_credential(&[], &head), None);
}

#[test]
fn test_operator_carries_nothing_and_x_admin_token_is_no_carrier() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding());
    let admin = busbar_kernel::auth::AdminAuthChain::build(
        &AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual operator row opens without a configured credential");
    assert!(
        admin.operator.carriers().is_empty(),
        "with no plugin auth axis the operator carries nothing (c3faaa06c1)"
    );

    // The operator credential is Bearer only (ADMIN-API-1.6-ONE-MODEL §8.1): read off
    // `authorization`, never off `x-admin-token`, blank or not.
    let bearer_only = [HeaderName::from_static("authorization")];
    for value in ["", "admintok"] {
        assert_eq!(
            carried_credential(&bearer_only, &headers(&[(X_ADMIN_TOKEN, value)])),
            None,
            "x-admin-token ('{value}') is no operator carrier"
        );
    }
    assert_eq!(
        carried_credential(&bearer_only, &headers(&[("authorization", "Bearer ")])),
        None,
        "a blank Bearer is absent"
    );
    assert_eq!(
        carried_credential(
            &bearer_only,
            &headers(&[("authorization", "Bearer admintok")])
        ),
        Some("admintok".to_string())
    );
}
