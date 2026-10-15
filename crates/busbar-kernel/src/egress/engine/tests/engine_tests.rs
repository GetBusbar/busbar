// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The owned egress client's building blocks: request assembly is byte-exact from precomputed
//! parts, the h1-only/h2c precedence mirrors the old reqwest builder's apply-order, and the CONNECT
//! tunnel runs the exchange a proxy choice names. The proxy environment's parse and the choice's
//! rules are the connector's (`busbar_core_connector::proxy`, status row 130 E5a) and its suite
//! holds them; this suite wires a choice directly, never by mutating process env.

use super::*;

#[test]
fn egress_request_uses_precomputed_parts_verbatim() {
    let uri: http::Uri = "http://127.0.0.1:1/v1/chat/completions".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Token k"),
    );
    let req = egress_request(uri.clone(), headers, Bytes::from_static(b"{}"));
    assert_eq!(req.method(), http::Method::POST);
    assert_eq!(req.uri(), &uri);
    assert_eq!(
        req.headers().get(http::header::AUTHORIZATION).unwrap(),
        "Token k"
    );
}

#[test]
fn builder_smoke_all_shapes() {
    for (h1, h2c) in [(false, false), (true, false), (false, true), (true, true)] {
        build_client(&EngineSpec::pooled_webpki(4, 300, h1, h2c))
            .expect("the pooled posture builds");
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

    // A connector wired to the scripted proxy (tunnel::installed_proxy() is process-global; tests wire
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
    let connector = tunnel::TunnelConnector::new(
        http,
        Some(config),
        tunnel::connects_per_shard_for_tests(),
        tunnel::loopback_listed_for_tests(),
    );
    let https = super::https::HttpsConnector::new(
        connector,
        super::client_tls(&EngineSpec::pooled_webpki(4, 300, true, false), &[])
            .expect("the pooled tls posture builds"),
    );
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

/// The reqwest-parity userinfo move on the general request builder used for operator-spelled
/// URLs: `user:pass@` leaves the URI (so it can never sit in hyper's per-authority pool key,
/// which hyper traces at debug level) and becomes an `Authorization: Basic` header marked
/// sensitive — unless the caller set its own Authorization, which wins. The boot-validated
/// forward-path `egress_request` is deliberately untouched by this (its URI is validated at
/// boot with no userinfo possible, so the forward path keeps zero per-request branches).
#[test]
fn request_moves_url_userinfo_into_a_sensitive_basic_auth_header() {
    use base64::Engine as _;
    let req = request(
        http::Method::POST,
        "https://user:hunter2@sink.test:8443/log".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    assert_eq!(req.uri().to_string(), "https://sink.test:8443/log");
    let auth = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .expect("the userinfo must become Basic credentials");
    assert!(auth.is_sensitive(), "the moved credential is sensitive");
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("user:hunter2")
    );
    assert_eq!(auth.to_str().unwrap(), expected);

    // A lone username is an empty password (RFC 7617's shape, reqwest's behaviour).
    let req = request(
        http::Method::GET,
        "https://tok@sink.test/".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("tok:")
    );
    assert_eq!(
        req.headers()
            .get(http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap(),
        expected
    );

    // An explicit Authorization wins over the URL's, but the userinfo still leaves the URI.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("Token explicit"),
    );
    let req = request(
        http::Method::GET,
        "https://user:pass@sink.test/".parse().unwrap(),
        headers,
        Bytes::new(),
    );
    assert_eq!(req.uri().to_string(), "https://sink.test/");
    assert_eq!(
        req.headers().get(http::header::AUTHORIZATION).unwrap(),
        "Token explicit"
    );

    // No userinfo: untouched, no header invented.
    let req = request(
        http::Method::GET,
        "https://sink.test/".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    assert!(req.headers().get(http::header::AUTHORIZATION).is_none());
}

/// 1.5.5's reqwest client added `accept: */*` to every request that named no Accept, after the
/// caller's own fields: the token hop went out `content-type, accept, host, content-length` and the
/// plugin fetch `accept, host` (golden/1.5.5 egress.auth|jwt-bearer|mint-refresh,
/// egress.fetch|plugins|url). A URL's userinfo becomes `authorization` before the default, as
/// reqwest's builder did. A caller's own Accept is kept as it is.
#[test]
fn client_request_adds_the_reqwest_default_accept_after_the_callers_fields() {
    let fields = |req: &http::Request<Full<Bytes>>| -> Vec<(String, String)> {
        req.headers()
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap().to_owned()))
            .collect()
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let req = client_request(
        http::Method::POST,
        "http://127.0.0.1:1/token".parse().unwrap(),
        headers,
        Bytes::from_static(b"grant_type=x"),
    );
    let want = [
        ("content-type", "application/x-www-form-urlencoded"),
        ("accept", "*/*"),
    ];
    assert_eq!(
        fields(&req),
        want.map(|(n, v)| (n.to_owned(), v.to_owned()))
    );

    let fetch = client_request(
        http::Method::GET,
        "http://127.0.0.1:1/releases/p.tar.gz".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    assert_eq!(fields(&fetch), [("accept".to_owned(), "*/*".to_owned())]);

    let login = client_request(
        http::Method::POST,
        "http://u:p@127.0.0.1:1/token".parse().unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    let names: Vec<String> = fields(&login).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["authorization", "accept"]);

    let mut own = http::HeaderMap::new();
    own.insert(
        http::header::ACCEPT,
        http::HeaderValue::from_static("application/json"),
    );
    let req = client_request(
        http::Method::POST,
        "http://127.0.0.1:1/rpc".parse().unwrap(),
        own,
        Bytes::new(),
    );
    let accepts: Vec<_> = req.headers().get_all(http::header::ACCEPT).iter().collect();
    assert_eq!(accepts, ["application/json"]);
}

/// A plane hop goes out with exactly the fields its plane named: `request` adds no Accept (the new
/// planes' bytes are predev's, e.g. the a2a fence cell's `[host]`-only hops). Only the four 1.5.5
/// reqwest hops take the client default, through `client_request`.
#[test]
fn request_adds_no_accept_a_plane_hop_did_not_name() {
    let req = request(
        http::Method::GET,
        "http://127.0.0.1:1/.well-known/agent-card.json"
            .parse()
            .unwrap(),
        http::HeaderMap::new(),
        Bytes::new(),
    );
    assert!(req.headers().get(http::header::ACCEPT).is_none());
    assert!(req.headers().is_empty());
}

/// ROW 74 (F25): a provider base URL's `user[:pass]@` becomes the Basic value 1.5.5's reqwest built
/// (`extract_authority` + `util::basic_auth`, reqwest 0.12.28): the LAST `@` of the authority ends
/// the userinfo, the first `:` splits user from pass, both are percent-decoded, an empty pass is
/// none, and a spelling with neither user nor pass (or a user that is not UTF-8) presents nothing. The
/// value is sensitive and its `Debug` is a marker.
#[test]
fn a_base_url_userinfo_becomes_the_basic_value_reqwest_built() {
    use base64::Engine as _;
    let basic = |plain: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(plain)
        )
    };
    for (url, plain) in [
        (
            "https://svcuser:hunter2-P4ss@api.example.com/v1",
            "svcuser:hunter2-P4ss",
        ),
        (
            "https://svcuser:hun@ter2@api.example.com",
            "svcuser:hun@ter2",
        ),
        (
            "https://svcuser:p%40ss%3A1@api.example.com",
            "svcuser:p@ss:1",
        ),
        ("https://svcuser@api.example.com", "svcuser:"),
        ("https://svcuser:@api.example.com", "svcuser:"),
        ("https://:hunter2@api.example.com", ":hunter2"),
        // A pass that does not decode to UTF-8 is no pass (reqwest's `password` arm).
        ("https://svcuser:%FF@api.example.com", "svcuser:"),
    ] {
        let userinfo = UrlUserinfo::of(url).expect("the userinfo presents");
        assert_eq!(userinfo.value().to_str().unwrap(), basic(plain), "{url}");
        assert!(userinfo.value().is_sensitive(), "{url}");
        assert_eq!(format!("{userinfo:?}"), "UrlUserinfo(<redacted>)");
    }
    for url in [
        "https://api.example.com/v1",
        "https://api.example.com/x@y",
        "https://@api.example.com",
        "https://:@api.example.com",
        // A user that does not decode to UTF-8 presents nothing (reqwest's `username` arm).
        "https://%FF:hunter2@api.example.com",
        "https://:%FF@api.example.com",
        "api.example.com",
    ] {
        assert!(UrlUserinfo::of(url).is_none(), "{url} presents nothing");
    }
}

/// ROW 74 (F25), THE HOP: a request carrying a [`UrlUserinfo`] goes out with the Basic field FIRST
/// when its own fields name no `authorization` (a dialect whose credential rides another field),
/// and without it when they do (the credential replaced it in 1.5.5's `replace_headers`). The
/// extension never survives the hop; a request without one is untouched.
#[test]
fn the_hop_presents_the_userinfo_first_unless_the_request_names_authorization() {
    let userinfo =
        UrlUserinfo::of("https://svcuser:hunter2-P4ss@api.example.com").expect("a userinfo");
    let request_with = |fields: &[(&'static str, &'static str)], carry: bool| {
        let mut headers = http::HeaderMap::new();
        for (n, v) in fields {
            headers.append(*n, http::HeaderValue::from_static(v));
        }
        let mut req = egress_request(
            "https://api.example.com/v1/messages".parse().unwrap(),
            headers,
            Bytes::new(),
        );
        if carry {
            req.extensions_mut().insert(userinfo.clone());
        }
        present_url_userinfo(&mut req);
        assert!(req.extensions().get::<UrlUserinfo>().is_none());
        req.headers()
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap().to_string()))
            .collect::<Vec<_>>()
    };
    let basic = userinfo.value().to_str().unwrap().to_string();
    let owned = |v: &[(&str, &str)]| -> Vec<(String, String)> {
        v.iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    };
    assert_eq!(
        request_with(
            &[("x-api-key", "k"), ("content-type", "application/json")],
            true
        ),
        owned(&[
            ("authorization", &basic),
            ("x-api-key", "k"),
            ("content-type", "application/json"),
        ]),
        "a credential under another field leaves the Basic field in, first"
    );
    assert_eq!(
        request_with(
            &[
                ("authorization", "Bearer k"),
                ("content-type", "application/json")
            ],
            true
        ),
        owned(&[
            ("authorization", "Bearer k"),
            ("content-type", "application/json")
        ]),
        "a credential named `authorization` displaces it"
    );
    assert_eq!(
        request_with(&[("x-api-key", "k")], false),
        owned(&[("x-api-key", "k")]),
        "no userinfo, nothing presented"
    );
}
