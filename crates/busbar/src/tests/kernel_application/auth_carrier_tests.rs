// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::body::Body;
use axum::http::{HeaderName, Request};
use busbar_kernel::auth::{carried_credential, AuthMiddleware};

const X_ADMIN_TOKEN: &str = "x-admin-token";

fn req_with(name: &str, value: &str) -> Request<Body> {
    Request::builder()
        .uri("/v1/messages")
        .header(name, value)
        .body(Body::empty())
        .expect("test request must build")
}

#[test]
fn test_extract_client_token_authorization_bearer() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = req_with("authorization", "Bearer tok-abc");
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("tok-abc".to_string())
    );
}

#[test]
fn test_extract_client_token_x_api_key() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = req_with("x-api-key", "tok-x-api-key");
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("tok-x-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_x_goog_api_key() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = req_with("x-goog-api-key", "tok-x-goog-api-key");
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("tok-x-goog-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_precedence_is_authorization_first() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = Request::builder()
        .uri("/v1/messages")
        .header("authorization", "Bearer from-auth")
        .header("x-api-key", "from-x-api-key")
        .header("x-goog-api-key", "from-goog")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("from-auth".to_string())
    );

    let req = Request::builder()
        .uri("/v1/messages")
        .header("x-api-key", "from-x-api-key")
        .header("x-goog-api-key", "from-goog")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("from-x-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_empty_carrier_falls_through() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = Request::builder()
        .uri("/v1/messages")
        .header("x-api-key", "")
        .header("x-goog-api-key", "tok-x-goog-api-key")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("tok-x-goog-api-key".to_string())
    );
}

#[test]
fn test_extract_client_token_none_when_no_carrier() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = Request::builder()
        .uri("/v1/messages")
        .body(Body::empty())
        .unwrap();
    assert_eq!(mw.extract_client_token(req.headers()), None);
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_api_key() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    for non_bearer in [
        "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/svc/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef",
        "Basic dXNlcjpwYXNz",
    ] {
        let req = Request::builder()
            .uri("/v1/messages")
            .header("authorization", non_bearer)
            .header("x-api-key", "tok")
            .body(Body::empty())
            .expect("test request must build");
        assert_eq!(
            mw.extract_client_token(req.headers()),
            Some("tok".to_string()),
            "a non-bearer Authorization ('{non_bearer}') must fall through to x-api-key"
        );
    }
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_goog_api_key() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual default inbound style constructs");
    let req = Request::builder()
        .uri("/v1/messages")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA.../svc/aws4_request",
        )
        .header("x-goog-api-key", "goog-tok")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(
        mw.extract_client_token(req.headers()),
        Some("goog-tok".to_string()),
        "a non-bearer Authorization must fall through to x-goog-api-key"
    );
}

#[test]
fn test_extract_admin_header_token_empty_filtered() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let operator = busbar_kernel::auth::open_operator(&registry, None, &Default::default())
        .expect("the actual operator row opens without a configured credential");
    let carriers: Vec<HeaderName> = operator
        .carriers()
        .iter()
        .map(|name| {
            name.parse()
                .expect("the actual operator carrier is a header name")
        })
        .collect();
    assert!(
        !carriers.is_empty(),
        "the actual operator declares its carriers"
    );
    let blank = req_with(X_ADMIN_TOKEN, "");
    assert_eq!(
        carried_credential(&carriers, blank.headers()),
        None,
        "a blank x-admin-token must be treated as absent (None)"
    );

    let present = req_with(X_ADMIN_TOKEN, "admintok");
    assert_eq!(
        carried_credential(&carriers, present.headers()),
        Some("admintok".to_string()),
        "a non-empty x-admin-token must be carried verbatim"
    );

    let absent = Request::builder()
        .uri("/api/v1/admin/keys")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(carried_credential(&carriers, absent.headers()), None);
}
