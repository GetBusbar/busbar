// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PROVISION (ABI-MIN3-INTERFACE §14): The provisioning mount (CA-2, IF §12.29) and the guard's admin, a wave-2
//! mount (W2-K8P). The two-replica hold arm (FU5 (a)) drives two kernel directories over one store and lives in
//! the kernel's own directory tests (`directory::tests::two_replicas`), where the store's internals are in reach.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use busbar_core_admin::provision::{
    client_entry, mount, mount_path, mounted, strip_credentials, ProvisionInstance, Verified,
};

struct Fake {
    verdict: Verified,
    cap: usize,
    creds: Vec<HeaderName>,
    served: Mutex<Vec<(String, HeaderMap)>>,
    verified: AtomicUsize,
    request_seen: Mutex<Option<(String, String, Vec<u8>)>>,
}

impl Fake {
    fn new(verdict: Verified) -> Self {
        Self {
            verdict,
            cap: 16,
            creds: vec![HeaderName::from_static("x-api-key")],
            served: Mutex::new(Vec::new()),
            verified: AtomicUsize::new(0),
            request_seen: Mutex::new(None),
        }
    }
}

impl ProvisionInstance for Fake {
    fn name(&self) -> &str {
        "scim"
    }
    fn body_cap(&self) -> usize {
        self.cap
    }
    fn cred_headers(&self) -> &[HeaderName] {
        &self.creds
    }
    async fn verify(&self, request: &Request<Bytes>) -> Verified {
        *self.request_seen.lock().unwrap() = Some((request.method().to_string(), request.uri().to_string(), request.body().to_vec()));
        self.verified.fetch_add(1, Ordering::SeqCst);
        self.verdict.clone()
    }
    async fn serve(&self, client: &str, req: Request<Bytes>) -> Response {
        self.served
            .lock()
            .unwrap()
            .push((client.to_string(), req.headers().clone()));
        StatusCode::NO_CONTENT.into_response()
    }
    fn refused(&self, _status: StatusCode) {}
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
    let inst = Fake::new(Verified::NoCredential);
    let resp = mount(&inst, &clients(), request("{}")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get("www-authenticate"),
        Some(&HeaderValue::from_static("Bearer"))
    );
    assert!(inst.served.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_refused_credential_is_401_and_a_failed_verify_keeps_its_mapped_status() {
    let refused = Fake::new(Verified::Refused);
    assert_eq!(
        mount(&refused, &clients(), request("{}")).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let failed = Fake::new(Verified::Failed(StatusCode::SERVICE_UNAVAILABLE));
    assert_eq!(
        mount(&failed, &clients(), request("{}")).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn a_verified_principal_that_is_not_a_client_is_403_with_no_serve() {
    let inst = Fake::new(Verified::Principal("someone-else".into()));
    let resp = mount(&inst, &clients(), request("{}")).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(inst.served.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_oversized_body_is_413_before_any_verify() {
    let inst = Fake::new(Verified::Principal("scim-client".into()));
    let resp = mount(
        &inst,
        &clients(),
        request("0123456789abcdef0123456789abcdef"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(inst.verified.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_client_is_served_with_q_client_and_the_credentials_stripped() {
    let inst = Fake::new(Verified::Principal("scim-client".into()));
    let resp = mount(&inst, &clients(), request("{}")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let served = inst.served.lock().unwrap();
    let (client, head) = &served[0];
    assert_eq!(client, "scim-client");
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
    let instance = Fake::new(Verified::Principal("scim-client".into()));
    let request = Request::builder()
        .method("PATCH")
        .uri("/provision/scim/Groups/g?version=2")
        .header("authorization", "Bearer original")
        .body(Body::from("patch body"))
        .unwrap();
    let response = mount(&instance, &clients(), request).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        *instance.request_seen.lock().unwrap(),
        Some(("PATCH".into(), "/provision/scim/Groups/g?version=2".into(), b"patch body".to_vec()))
    );
}
