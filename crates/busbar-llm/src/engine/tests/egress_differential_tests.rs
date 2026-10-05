// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS DIFFERENTIAL HARNESS — the gate the one-egress-stack migration re-runs at every step.
//!
//! Two stacks serve busbar's outbound hops today: stack A, the owned hyper engine
//! (`crate::engine::build_egress_client` — the LLM lanes), and stack B, the pinned reqwest client
//! (`busbar_kernel::egress::build_pinned_client` — the plane hops). The owner ruling folds them
//! into ONE engine, and "no behavior change on any plane" is provable only by DIFFERENTIAL
//! observation: drive both stacks against the same recording fixtures and compare what each one
//! did — status, body bytes, the peer identity observed, and the error CLASS on the refusing arms
//! (never the error string: the two stacks wrap causes differently, and the strings are
//! documented drift).
//!
//! Each stack is driven on the postures it supports: stack A on the open-web LLM posture (webpki
//! trust, system DNS), stack B on the pinned posture (address pin, refusing resolver, private
//! roots, optional client identity). The rows where both can speak — plaintext status/body, the
//! redirect canary — are asserted equal across stacks; the pinned-only rows pin stack B's
//! observable behavior so the engine that later replaces it has a recorded target to match.
//!
//! The fixtures live in `busbar_kernel::egress::fixtures` so the engine's own tests and this harness
//! drive the SAME servers. The TLS rows (the known-leaf pin and SNI under the pin, the
//! client-certificate fixture) need a REAL handshake, which is the connector's: TLS stays in the
//! connector, so those rows are the connector's own `tls/engine_tests.rs`, over the same two
//! stacks.

use std::net::SocketAddr;
use std::sync::Arc;

use busbar_kernel::egress::fixtures::{spawn_http, CannedResponse, RebindingResolver};
use busbar_kernel::egress::{build_pinned_client, with_cause, RefuseSecondLookup};
use bytes::Bytes;
use http_body_util::BodyExt;

/// What one hop OBSERVABLY did, reduced to the vocabulary both stacks share. The error arm keeps
/// only the CLASS — both `hyper_util::client::legacy::Error::is_connect` and
/// `reqwest::Error::is_connect` (which wraps it) answer the same question, and string parity is
/// explicitly not a goal of the migration.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Answered {
        status: u16,
        location: Option<String>,
        body: String,
    },
    /// The hop failed before or during connection establishment (TCP, TLS, resolver refusal).
    RefusedAtConnect,
    /// The hop failed AFTER the client-side handshake completed — the class TLS 1.3 gives a peer's
    /// post-handshake refusal (an mTLS server discovers the missing client certificate only after
    /// the client already considers the handshake done, so its alert lands on the first exchange,
    /// not the connect). Recorded distinctly because the reference stack really does report it
    /// this way, and the engine must match the reference, not the intuition.
    RefusedInFlight,
}

/// Drive ONE hop through stack A — the owned hyper engine on the LLM posture (webpki trust,
/// system DNS, no pin). `uri` must therefore be dialable as written (an IP-literal host).
async fn stack_a(uri: &str, body: &str) -> Outcome {
    let client = crate::engine::build_egress_client(
        &crate::engine::EgressClientSpec::pooled_webpki(4, 300, false, false),
    );
    let req = crate::engine::egress_request(
        uri.parse().expect("fixture uri"),
        http::HeaderMap::new(),
        Bytes::from(body.to_string()),
    );
    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .map(|v| v.to_str().expect("location").to_string());
            let body = resp.into_body().collect().await.expect("body").to_bytes();
            Outcome::Answered {
                status,
                location,
                body: String::from_utf8_lossy(&body).into_owned(),
            }
        }
        Err(e) if e.is_connect() => Outcome::RefusedAtConnect,
        Err(_) => Outcome::RefusedInFlight,
    }
}

/// Drive ONE hop through stack B — the pinned reqwest client on the production posture
/// ([`RefuseSecondLookup`], host→addr pin, optional identity/extra root). Returns the outcome plus
/// the peer SPKI pin read off `reqwest::tls::TlsInfo`, where the hop ran over TLS.
async fn stack_b(
    host: &str,
    addr: SocketAddr,
    url: &str,
    body: &str,
    identity: Option<reqwest::Identity>,
    extra_roots: &[reqwest::Certificate],
) -> (Outcome, Option<String>) {
    let client = build_pinned_client(
        host,
        addr,
        Arc::new(RefuseSecondLookup),
        identity,
        extra_roots,
    )
    .expect("pinned client");
    match client.post(url).body(body.to_string()).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(http::header::LOCATION)
                .map(|v| v.to_str().expect("location").to_string());
            let leaf_pin = resp
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|t| t.peer_certificate())
                .map(|der| busbar_kernel::plane_host::spki::pin(der).expect("walkable leaf"));
            let body = resp.bytes().await.expect("body");
            (
                Outcome::Answered {
                    status,
                    location,
                    body: String::from_utf8_lossy(&body).into_owned(),
                },
                leaf_pin,
            )
        }
        Err(e) if e.is_connect() => (Outcome::RefusedAtConnect, None),
        Err(_) => (Outcome::RefusedInFlight, None),
    }
}

/// Plaintext status/body parity: the one row both stacks speak natively. Same fixture, same
/// request body, same observed (status, body).
#[tokio::test]
async fn plaintext_status_and_body_are_identical_across_stacks() {
    crate::testkit::install_test_seams();
    let fixture = spawn_http(CannedResponse::ok(r#"{"answer":42}"#), 4);
    let a = stack_a(&format!("http://{}/v1/x", fixture.addr), r#"{"q":"hop"}"#).await;
    let (b, leaf_pin) = stack_b(
        "plain.test",
        fixture.addr,
        &format!("http://plain.test:{}/v1/x", fixture.addr.port()),
        r#"{"q":"hop"}"#,
        None,
        &[],
    )
    .await;
    assert_eq!(a, b, "the two stacks must observe the same answer");
    assert_eq!(
        a,
        Outcome::Answered {
            status: 200,
            location: None,
            body: r#"{"answer":42}"#.to_string()
        }
    );
    assert_eq!(
        leaf_pin, None,
        "a plaintext hop has no peer identity to observe"
    );
    assert_eq!(
        fixture.request_lines().len(),
        2,
        "one request per stack reached the fixture"
    );
}

/// The redirect canary: a 3xx is surfaced with its `Location` VERBATIM and followed by NEITHER
/// stack — the follow would be an unguarded second hop, the SSRF class the guard exists for. The
/// fixture's request count is the structural proof no second exchange happened.
#[tokio::test]
async fn redirects_surface_verbatim_and_are_followed_by_neither_stack() {
    crate::testkit::install_test_seams();
    let fixture = spawn_http(
        CannedResponse::redirect(302, "http://203.0.113.9/metadata"),
        4,
    );
    let a = stack_a(&format!("http://{}/v1/x", fixture.addr), "{}").await;
    let (b, _) = stack_b(
        "redir.test",
        fixture.addr,
        &format!("http://redir.test:{}/v1/x", fixture.addr.port()),
        "{}",
        None,
        &[],
    )
    .await;
    let expected = Outcome::Answered {
        status: 302,
        location: Some("http://203.0.113.9/metadata".to_string()),
        body: String::new(),
    };
    assert_eq!(a, expected);
    assert_eq!(b, expected);
    assert_eq!(
        fixture.request_lines().len(),
        2,
        "exactly one request per stack: the Location was never followed"
    );
}

/// The pin makes the resolver STRUCTURALLY unreachable for the pinned host: a rebinding resolver
/// wired in as the client's DNS is never consulted for the pinned name (zero calls across the
/// exchange), and only a request for a DIFFERENT name reaches it. The production posture goes one
/// step further: [`RefuseSecondLookup`] fails that different name loudly with the doctrine text.
#[tokio::test]
async fn the_pin_never_consults_the_resolver_and_the_doctrine_refuses_other_names() {
    crate::testkit::install_test_seams();
    let fixture = spawn_http(CannedResponse::ok("pinned"), 4);
    let evil: SocketAddr = "203.0.113.9:80".parse().expect("addr");
    let rebinding = Arc::new(RebindingResolver::new(fixture.addr, evil));

    let client = build_pinned_client(
        "pinned.test",
        fixture.addr,
        Arc::clone(&rebinding) as Arc<dyn reqwest::dns::Resolve>,
        None,
        &[],
    )
    .expect("pinned client");
    let resp = client
        .post(format!("http://pinned.test:{}/v1/x", fixture.addr.port()))
        .send()
        .await
        .expect("pinned hop");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        rebinding.calls(),
        0,
        "the pinned name must resolve through the pin, NEVER the resolver"
    );

    // The production posture: any other name is refused with the doctrine message.
    let production = build_pinned_client(
        "pinned.test",
        fixture.addr,
        Arc::new(RefuseSecondLookup),
        None,
        &[],
    )
    .expect("pinned client");
    let err = production
        .post(format!("http://other.test:{}/v1/x", fixture.addr.port()))
        .send()
        .await
        .expect_err("a second lookup must refuse");
    let rendered = with_cause(&err);
    assert!(
        rendered.contains("resolves each name exactly once"),
        "the refusal must carry the doctrine text: {rendered}"
    );
}
