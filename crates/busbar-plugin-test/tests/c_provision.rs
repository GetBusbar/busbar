// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PROVISION (ABI-MIN3-INTERFACE §14): The provisioning mount (CA-2, IF §12.29) and the guard's admin, a wave-2
//! mount (W2-K8P). The two-replica hold arm (FU5 (a)) drives two kernel directories over one store and lives in
//! the kernel's own directory tests (`directory::tests::two_replicas`), where the store's internals are in reach.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};

use busbar_core_admin::provision::{
    admitted, capped, client_entry, mount_path, mounted, refusal, strip_credentials, Verified,
};

/// The instance's D_CRED_HEADER headers.
fn creds() -> Vec<HeaderName> {
    vec![HeaderName::from_static("x-api-key")]
}

fn clients() -> Vec<Box<str>> {
    vec!["scim-client".into()]
}

fn request(body: &'static str) -> Request<Body> {
    Request::builder()
        .uri("/provision/scim/Users")
        .header("authorization", "Bearer secret")
        .header("cookie", "a=b")
        .header("x-api-key", "k")
        .header("x-keep", "yes")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn the_mount_pattern_names_the_instance() {
    assert_eq!(mount_path("scim"), "/provision/scim/{*rest}");
}

#[tokio::test]
async fn only_an_instance_declaring_fb_provision_with_a_block_is_mounted() {
    use busbar_kernel::config::min3::{ProvisioningCfg, ProvisioningGuard};
    let cfg = ProvisioningCfg {
        clients: clients(),
        link: None,
        guard: ProvisioningGuard {
            max: 10,
            window_s: 3600,
        },
    };
    let mut blocks = std::collections::BTreeMap::new();
    blocks.insert("scim".into(), cfg.clone());
    blocks.insert("plain".into(), cfg);
    assert_eq!(mounted(&blocks, |n| n == "scim"), vec!["scim"]);
}

#[tokio::test]
async fn a_request_without_a_credential_is_401_with_a_bearer_challenge_and_serve_is_not_called() {
    let request = capped(request("{}"), 16).await.unwrap();
    // No `Admitted` is made, so there is nothing to serve.
    let status = admitted(request, Verified::NoCredential, &clients(), &creds())
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let resp = refusal(status);
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("www-authenticate"),
        Some(&HeaderValue::from_static("Bearer"))
    );
}

#[tokio::test]
async fn a_refused_credential_is_401_and_a_failed_verify_keeps_its_mapped_status() {
    let refused = capped(request("{}"), 16).await.unwrap();
    assert_eq!(
        admitted(refused, Verified::Refused, &clients(), &creds())
            .err()
            .unwrap(),
        StatusCode::UNAUTHORIZED
    );
    let failed = capped(request("{}"), 16).await.unwrap();
    assert_eq!(
        admitted(
            failed,
            Verified::Failed(StatusCode::SERVICE_UNAVAILABLE),
            &clients(),
            &creds()
        )
        .err()
        .unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn a_verified_principal_that_is_not_a_client_is_403_with_no_serve() {
    let request = capped(request("{}"), 16).await.unwrap();
    let status = admitted(
        request,
        Verified::Principal("someone-else".into()),
        &clients(),
        &creds(),
    )
    .err()
    .unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refusal(status).status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_oversized_body_is_413_before_any_verify() {
    // No `Capped` is made, so there is nothing to verify.
    let status = capped(request("0123456789abcdef0123456789abcdef"), 16)
        .await
        .err()
        .unwrap();
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_client_is_served_with_q_client_and_the_credentials_stripped() {
    let request = capped(request("{}"), 16).await.unwrap();
    let allowed = clients();
    let served = admitted(
        request,
        Verified::Principal("scim-client".into()),
        &allowed,
        &creds(),
    )
    .ok()
    .unwrap();
    assert_eq!(served.client, "scim-client");
    let head = served.request.headers();
    for gone in ["authorization", "cookie", "x-api-key"] {
        assert!(head.get(gone).is_none(), "{gone} reached serve");
    }
    assert_eq!(head.get("x-keep").unwrap(), "yes");
}

#[test]
fn client_match_is_exact_bytes_and_strip_removes_only_credentials() {
    assert_eq!(client_entry(&clients(), "scim-client"), Some("scim-client"));
    assert_eq!(client_entry(&clients(), "SCIM-CLIENT"), None);
    let mut h = HeaderMap::new();
    h.insert("authorization", HeaderValue::from_static("x"));
    h.insert("x-other", HeaderValue::from_static("y"));
    strip_credentials(&mut h, &[]);
    assert!(h.get("authorization").is_none() && h.get("x-other").is_some());
}

#[tokio::test]
async fn own_instance_verify_receives_the_complete_original_request() {
    let request = Request::builder()
        .method("PATCH")
        .uri("/provision/scim/Groups/g?version=2")
        .header("authorization", "Bearer original")
        .body(Body::from("patch body"))
        .unwrap();
    let request = capped(request, 1024).await.unwrap();
    let seen = request.request();
    assert_eq!(seen.method().to_string(), "PATCH");
    assert_eq!(seen.uri().to_string(), "/provision/scim/Groups/g?version=2");
    assert_eq!(
        seen.headers().get("authorization").unwrap(),
        "Bearer original"
    );
    assert_eq!(seen.body().to_vec(), b"patch body".to_vec());
}
