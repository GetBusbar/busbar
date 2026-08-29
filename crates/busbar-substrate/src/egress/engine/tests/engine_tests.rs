// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The owned egress client's building blocks: request assembly is byte-exact from precomputed
//! parts, the h1-only/h2c precedence mirrors the old reqwest builder's apply-order, and the
//! proxy-env machinery matches reqwest 0.12's scoping — per-scheme slot resolution
//! (HTTPS_PROXY/HTTP_PROXY with ALL_PROXY fallback), scheme-scoped selection, and the full
//! NO_PROXY rule set (host, domain suffix, IP literal, CIDR). Every proxy test drives the parse/
//! resolve/select functions directly — NEVER by mutating process env, which races under the
//! parallel test runner.

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
        build_client(&EngineSpec::llm_lane(4, 300, h1, h2c)).expect("the LLM-lane posture builds");
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

/// Precedence resolution, table-driven over the pure value bag (reqwest via hyper-util
/// `matcher::Builder::build`: scheme-specific var first, ALL_PROXY fallback for BOTH slots).
/// Each row: (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY) → (https slot host:port, http slot host:port).
#[test]
fn resolve_config_matches_reqwest_precedence() {
    /// (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY, expected https slot, expected http slot).
    type Row = (
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
    );
    let rows: &[Row] = &[
        // No proxy env at all → no config (the direct arm every known deployment takes).
        (None, None, None, None, None),
        // HTTPS_PROXY alone scopes to https targets ONLY — http targets go direct, never
        // through the https proxy (gap (b): we used to send them through it).
        (Some("hs.corp:1"), None, None, Some("hs.corp:1"), None),
        // HTTP_PROXY alone scopes to http targets ONLY (gap (a): we used to ignore it and go
        // direct — the dangerous direction).
        (None, Some("h.corp:2"), None, None, Some("h.corp:2")),
        // ALL_PROXY alone fills BOTH slots.
        (
            None,
            None,
            Some("all.corp:3"),
            Some("all.corp:3"),
            Some("all.corp:3"),
        ),
        // Scheme-specific var beats ALL_PROXY for its scheme; ALL_PROXY still fills the other.
        (
            Some("hs.corp:1"),
            None,
            Some("all.corp:3"),
            Some("hs.corp:1"),
            Some("all.corp:3"),
        ),
        (
            None,
            Some("h.corp:2"),
            Some("all.corp:3"),
            Some("all.corp:3"),
            Some("h.corp:2"),
        ),
        // All three set: each scheme var wins its own slot.
        (
            Some("hs.corp:1"),
            Some("h.corp:2"),
            Some("all.corp:3"),
            Some("hs.corp:1"),
            Some("h.corp:2"),
        ),
    ];
    for (https, http, all, want_https, want_http) in rows {
        let env = tunnel::ProxyEnvValuesForTests {
            https: https.map(String::from),
            http: http.map(String::from),
            all: all.map(String::from),
            no: None,
        };
        let config = tunnel::resolve_config_for_tests(&env).unwrap();
        match (want_https, want_http) {
            (None, None) => assert!(
                config.is_none(),
                "no proxy vars must resolve to no config: {https:?}/{http:?}/{all:?}"
            ),
            _ => {
                let config = config.expect("some slot is set, a config must exist");
                let got_https = tunnel::select_for_tests(&config, true, "api.example.com");
                let got_http = tunnel::select_for_tests(&config, false, "api.example.com");
                assert_eq!(
                    got_https.as_deref(),
                    *want_https,
                    "https slot for {https:?}/{http:?}/{all:?}"
                );
                assert_eq!(
                    got_http.as_deref(),
                    *want_http,
                    "http slot for {https:?}/{http:?}/{all:?}"
                );
            }
        }
    }
}

/// A garbage value in ANY set proxy var fails resolution loudly — busbar refuses to boot rather
/// than silently egressing direct past a configured proxy (documented deviation from reqwest's
/// silent fall-through).
#[test]
fn resolve_config_fail_louds_on_garbage_in_any_slot() {
    for (https, http, all) in [
        (Some("https://tls-proxy.corp"), None, None),
        (None, Some("http://"), None),
        (None, None, Some("https://tls-proxy.corp")),
    ] {
        let env = tunnel::ProxyEnvValuesForTests {
            https: https.map(String::from),
            http: http.map(String::from),
            all: all.map(String::from),
            no: None,
        };
        assert!(
            tunnel::resolve_config_for_tests(&env).is_err(),
            "garbage in {https:?}/{http:?}/{all:?} must refuse to resolve"
        );
    }
}

#[test]
fn no_proxy_suffix_matching_is_conventional() {
    let config = tunnel::test_config("proxy.corp", 3128, None, "example.com, internal");
    let via = |host: &str| tunnel::select_for_tests(&config, true, host).is_some();
    assert!(!via("example.com"), "exact NO_PROXY entry bypasses");
    assert!(!via("api.example.com"), "domain suffix bypasses");
    assert!(
        via("notexample.com"),
        "a non-boundary suffix must NOT bypass (substring is not a domain match)"
    );
    assert!(!via("INTERNAL"), "matching is case-insensitive");
    assert!(via("api.openai.com"), "unlisted hosts tunnel");
    let all = tunnel::test_config("proxy.corp", 3128, None, "*");
    assert!(
        tunnel::select_for_tests(&all, true, "api.openai.com").is_none(),
        "`*` disables tunneling"
    );
    // Leading dots are equivalent to none (curl/reqwest): `.example.com` ≡ `example.com`.
    assert!(tunnel::no_proxy_matches_for_tests(
        ".example.com",
        "example.com"
    ));
    assert!(tunnel::no_proxy_matches_for_tests(
        ".example.com",
        "api.example.com"
    ));
}

/// NO_PROXY IP-literal and CIDR matching (gap (c)) — the matrix over families, boundary prefix
/// lengths (/0, /8, /32, /128), containment edges, and the documented non-special-casing of
/// v6-mapped addresses.
#[test]
fn no_proxy_ip_and_cidr_matrix() {
    let m = tunnel::no_proxy_matches_for_tests;
    // IP literals: exact match only, and never as a domain suffix.
    assert!(m("10.1.2.3", "10.1.2.3"));
    assert!(!m("10.1.2.3", "10.1.2.30"));
    assert!(!m("10.1.2.3", "110.1.2.3"));
    assert!(m("::1", "::1"));
    assert!(m("::1", "[::1]"), "bracketed v6 literal hosts match too");
    // v4 CIDR containment, boundary prefixes.
    assert!(m("10.0.0.0/8", "10.255.255.255"));
    assert!(m("10.0.0.0/8", "10.0.0.1"));
    assert!(!m("10.0.0.0/8", "11.0.0.0"));
    assert!(!m("10.0.0.0/8", "9.255.255.255"));
    assert!(m("0.0.0.0/0", "203.0.113.7"), "/0 matches every v4 address");
    assert!(m("192.168.1.42/32", "192.168.1.42"), "/32 is exact");
    assert!(!m("192.168.1.42/32", "192.168.1.43"));
    // Non-octet-aligned prefix: the partial-byte mask must apply.
    assert!(m("192.168.1.0/25", "192.168.1.127"));
    assert!(!m("192.168.1.0/25", "192.168.1.128"));
    // v6 CIDR containment, boundary prefixes.
    assert!(m("fd00::/8", "fd12:3456::1"));
    assert!(!m("fd00::/8", "fe80::1"));
    assert!(m("::/0", "2001:db8::1"), "/0 matches every v6 address");
    assert!(m("2001:db8::1/128", "2001:db8::1"), "/128 is exact");
    assert!(!m("2001:db8::1/128", "2001:db8::2"));
    // Families never cross — INCLUDING v6-mapped forms: `::ffff:10.0.0.1` is a v6 address, so a
    // v4 block does not match it (same as ipnet/reqwest, which do not special-case mapped
    // addresses).
    assert!(!m("10.0.0.0/8", "::ffff:10.0.0.1"));
    assert!(!m("::/0", "10.0.0.1"), "a v6 catch-all does not catch v4");
    assert!(
        !m("0.0.0.0/0", "2001:db8::1"),
        "a v4 catch-all does not catch v6"
    );
    // An IP-literal host never matches domain entries (reqwest checks IP hosts only against
    // IP/CIDR entries).
    assert!(!m("0.0.1", "10.0.0.1"));
    // A malformed CIDR degrades to a never-matching domain entry, exactly as ipnet parse
    // failure does under reqwest — it must not poison the other entries.
    assert!(!m("10.0.0.0/40", "10.0.0.1"));
    assert!(m("10.0.0.0/40, example.com", "example.com"));
}

/// Scheme-scoped selection with NO_PROXY layered on top: exclusion applies to both slots.
#[test]
fn selection_is_scheme_scoped_and_no_proxy_excludes_both() {
    let env = tunnel::ProxyEnvValuesForTests {
        https: Some("hs.corp:1".to_string()),
        http: Some("h.corp:2".to_string()),
        all: None,
        no: Some("internal.corp, 10.0.0.0/8".to_string()),
    };
    let config = tunnel::resolve_config_for_tests(&env).unwrap().unwrap();
    assert_eq!(
        tunnel::select_for_tests(&config, true, "api.openai.com").as_deref(),
        Some("hs.corp:1")
    );
    assert_eq!(
        tunnel::select_for_tests(&config, false, "api.openai.com").as_deref(),
        Some("h.corp:2")
    );
    for is_https in [true, false] {
        assert!(
            tunnel::select_for_tests(&config, is_https, "db.internal.corp").is_none(),
            "NO_PROXY domain excludes the {} slot",
            if is_https { "https" } else { "http" }
        );
        assert!(
            tunnel::select_for_tests(&config, is_https, "10.20.30.40").is_none(),
            "NO_PROXY CIDR excludes the {} slot",
            if is_https { "https" } else { "http" }
        );
    }
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
    // the config directly so parallel tests never race an env var or the OnceLock).
    let config = tunnel::test_config(
        &addr.ip().to_string(),
        addr.port(),
        Some("Basic dTpw".to_string()),
        "",
    );
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(
        EgressResolver::system(),
    );
    http.enforce_http(false);
    let connector = tunnel::TunnelConnector::new(http, Some(config));
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
/// takes). Env-var permutations are covered by the direct resolve/select tests above — mutating
/// process env in a parallel test binary is a race, so none of these tests do it.
#[test]
fn install_is_ok_without_proxy_env() {
    let env = tunnel::ProxyEnvValuesForTests::from_process_env();
    if env.https.is_none() && env.http.is_none() && env.all.is_none() {
        assert!(install_proxy_tunnel_if_configured().is_ok());
    }
}

/// The connect gate bounds ESTABLISHMENT concurrency per authority and shares nothing across
/// authorities — the overload-cliff fix's core invariant. Driven directly (the semaphore IS the
/// mechanism); the storm-scale proof lives on the bench rig's overload rungs.
#[tokio::test]
async fn connect_gate_bounds_per_authority_establishment() {
    let gate = tunnel::ConnectGate::new_for_tests();
    let a = gate.slot_for_tests("upstream.test:443");
    // Same authority → the same semaphore (the bound is shared)…
    assert!(std::sync::Arc::ptr_eq(
        &a,
        &gate.slot_for_tests("upstream.test:443")
    ));
    // …a different authority gets its own (no cross-destination interference).
    assert!(!std::sync::Arc::ptr_eq(
        &a,
        &gate.slot_for_tests("other.test:443")
    ));
    // Exactly the per-shard share of the GLOBAL budget (64 / the published establishment-shard
    // count): the next establishment past the bound WAITS until one finishes.
    let share = tunnel::connects_per_shard_for_tests();
    assert_eq!(
        share,
        64 / super::establishment_shards_or_one(),
        "the share must divide the constant global budget by the shard count"
    );
    let mut held = Vec::new();
    for _ in 0..share {
        held.push(a.clone().try_acquire_owned().expect("within the bound"));
    }
    assert!(
        a.clone().try_acquire_owned().is_err(),
        "the establishment past the per-shard share must queue, not dial"
    );
    drop(held.pop());
    assert!(
        a.clone().try_acquire_owned().is_ok(),
        "a finished establishment frees the slot FIFO-fair"
    );
}
