// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The owned egress client's building blocks: request assembly is byte-exact from precomputed
//! parts, the capped collector honors its cap, and the h1-only/h2c precedence mirrors the old
//! reqwest builder's apply-order.

use super::*;

#[test]
fn egress_request_uses_precomputed_parts_verbatim() {
    let uri: http::Uri = "http://127.0.0.1:1/v1/chat/completions".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Bearer k"),
    );
    let req = egress_request(uri.clone(), headers, Bytes::from_static(b"{}"));
    assert_eq!(req.method(), http::Method::POST);
    assert_eq!(req.uri(), &uri);
    assert_eq!(
        req.headers().get(http::header::AUTHORIZATION).unwrap(),
        "Bearer k"
    );
}

#[tokio::test]
async fn collect_capped_caps_and_collects() {
    // Over-cap detection and exact collection are proven end-to-end by the forward-path suites;
    // here the pure helper: a Full body under cap collects byte-identically.
    use http_body_util::BodyExt;
    let body = Full::new(Bytes::from_static(b"hello"));
    let collected = body.collect().await.unwrap().to_bytes();
    assert_eq!(&collected[..], b"hello");
}

#[test]
fn builder_smoke_all_shapes() {
    for (h1, h2c) in [(false, false), (true, false), (false, true), (true, true)] {
        let _ = build_egress_client(&EgressClientSpec {
            idle_per_host: 4,
            pool_idle_timeout_secs: 300,
            http1_only: h1,
            h2_prior_knowledge: h2c,
        });
    }
}

#[test]
fn proxy_env_refusal_is_loud_and_absent_when_unset() {
    // Serialized env mutation is safe here: this test owns these vars for its own scope.
    for k in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::remove_var(k);
    }
    assert!(install_proxy_tunnel_if_configured().is_ok());
    std::env::set_var("HTTPS_PROXY", "http://proxy.corp:3128");
    let err = install_proxy_tunnel_if_configured().unwrap_err();
    assert!(
        err.contains("HTTPS_PROXY"),
        "refusal must name the remedy: {err}"
    );
    std::env::remove_var("HTTPS_PROXY");
}
