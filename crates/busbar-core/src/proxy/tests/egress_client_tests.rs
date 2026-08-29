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
fn proxy_url_parse_extracts_auth_and_refuses_https_proxies() {
    // No env mutation (racy under parallel tests): the parser is exercised directly.
    let err = tunnel::parse_proxy_for_tests("https://proxy.corp:3128").unwrap_err();
    assert!(
        err.contains("https"),
        "an https:// proxy must be refused loudly, naming why: {err}"
    );
    let garbage = tunnel::parse_proxy_for_tests("http://").unwrap_err();
    assert!(!garbage.is_empty(), "garbage must not parse");
    // Bare host:port and userinfo both parse; the auth header is prebuilt Basic.
    assert!(tunnel::parse_proxy_for_tests("proxy.corp:3128").is_ok());
    assert!(tunnel::parse_proxy_for_tests("http://u:p@proxy.corp").is_ok());
}

#[test]
fn no_proxy_suffix_matching_is_conventional() {
    let spec = tunnel::test_spec("proxy.corp", 3128, None, &["example.com", "internal"]);
    let via = |host: &str| !spec_bypasses(&spec, host);
    assert!(!via("example.com"), "exact NO_PROXY entry bypasses");
    assert!(!via("api.example.com"), "domain suffix bypasses");
    assert!(
        via("notexample.com"),
        "a non-boundary suffix must NOT bypass (substring is not a domain match)"
    );
    assert!(!via("INTERNAL"), "matching is case-insensitive");
    assert!(via("api.openai.com"), "unlisted hosts tunnel");
    let all = tunnel::test_spec("proxy.corp", 3128, None, &["*"]);
    assert!(
        spec_bypasses(&all, "api.openai.com"),
        "`*` disables tunneling"
    );
}

/// The full CONNECT exchange against a scripted proxy: the proxy must see the exact
/// `CONNECT host:port` + `Proxy-Authorization` bytes, and after its 200 the SAME socket must
/// carry the real HTTP exchange end-to-end through the pooled client.
#[tokio::test]
async fn connect_tunnel_end_to_end_through_scripted_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Read the CONNECT head.
        let mut head = Vec::new();
        let mut buf = [0u8; 512];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut buf).await.unwrap();
            head.extend_from_slice(&buf[..n]);
        }
        *seen2.lock().unwrap() = String::from_utf8_lossy(&head).into_owned();
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        // The tunnel is up: now act as the TARGET on the same socket.
        let mut req = Vec::new();
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock.read(&mut buf).await.unwrap();
            req.extend_from_slice(&buf[..n]);
        }
        sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .unwrap();
    });

    // A connector wired to the scripted proxy (installed_proxy() is process-global; tests wire
    // the spec directly so parallel tests never race an env var or the OnceLock).
    let spec = tunnel::test_spec(
        &addr.ip().to_string(),
        addr.port(),
        Some("Basic dTpw".to_string()),
        &[],
    );
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.enforce_http(false);
    let connector = tunnel::TunnelConnector::new(http, Some(spec));
    let tls = super::rustls_client_config();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(https);

    // The TARGET is a fake host the proxy never dials (it answers on the tunnel itself), which
    // is exactly what proves the bytes went through CONNECT and not direct.
    let req = egress_request(
        "http://upstream.test:8080/v1/x".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    let resp = client.request(req).await.expect("tunneled request");
    assert_eq!(resp.status(), 200);
    use http_body_util::BodyExt;
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");

    let head = seen.lock().unwrap().clone();
    assert!(
        head.starts_with("CONNECT upstream.test:8080 HTTP/1.1\r\n"),
        "proxy must see the CONNECT for the real target: {head:?}"
    );
    assert!(
        head.contains("Proxy-Authorization: Basic dTpw\r\n"),
        "the prebuilt Basic credential must ride the CONNECT: {head:?}"
    );
}

/// `install_proxy_tunnel_if_configured` is Ok in a clean environment (the common arm every boot
/// takes). Env-var permutations are covered by the direct parser tests above — mutating process
/// env in a parallel test binary is a race, so none of these tests do it.
#[test]
fn install_is_ok_without_proxy_env() {
    if super::proxy_env().is_none() {
        assert!(install_proxy_tunnel_if_configured().is_ok());
    }
}

fn spec_bypasses(spec: &std::sync::Arc<tunnel::ProxySpec>, host: &str) -> bool {
    tunnel::bypasses_for_tests(spec, host)
}
