// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS DIFFERENTIAL HARNESS — the gate the one-egress-stack migration re-runs at every step.
//!
//! Two stacks serve busbar's outbound hops today: stack A, the owned hyper engine
//! (`crate::proxy::build_egress_client` — the LLM lanes), and stack B, the pinned reqwest client
//! (`busbar_substrate::egress::build_pinned_client` — the plane hops). The owner ruling folds them
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
//! The fixtures live in `busbar_substrate::egress::fixtures` so the engine's own tests (in the
//! substrate crate) and this harness drive the SAME servers.

use std::net::SocketAddr;
use std::sync::Arc;

use busbar_substrate::egress::fixtures::{
    ca_and_leaf, spawn_http, spawn_tls, CannedResponse, ClientAuth, RebindingResolver,
    TlsServerSpec,
};
use busbar_substrate::egress::{build_pinned_client, with_cause, RefuseSecondLookup};
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
    let client = crate::proxy::build_egress_client(&crate::proxy::EgressClientSpec::llm_lane(
        4, 300, false, false,
    ));
    let req = crate::proxy::egress_request(
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
            let spki = resp
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|t| t.peer_certificate())
                .map(|der| busbar_substrate::plane_host::spki::pin(der).expect("walkable leaf"));
            let body = resp.bytes().await.expect("body");
            (
                Outcome::Answered {
                    status,
                    location,
                    body: String::from_utf8_lossy(&body).into_owned(),
                },
                spki,
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
    let fixture = spawn_http(CannedResponse::ok(r#"{"answer":42}"#), 4);
    let a = stack_a(&format!("http://{}/v1/x", fixture.addr), r#"{"q":"hop"}"#).await;
    let (b, spki) = stack_b(
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
        spki, None,
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

/// The known-leaf TLS row: the pinned stack (with the private CA as an extra root) completes the
/// handshake WITH THE HOSTNAME — SNI and the certificate name check stay on `pinned.test` while
/// the socket goes to the pinned loopback address — and the observed peer SPKI equals a pin
/// computed DIRECTLY from the served leaf, outside the stack under test. The open-web stack
/// (webpki trust only) refuses the same server at the connect class: the private CA is not in its
/// trust story, and "refused" is the correct differential record for that posture.
#[tokio::test]
async fn known_leaf_tls_spki_and_sni_are_observed_and_webpki_refuses_the_private_ca() {
    let material = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("over tls"),
        max_requests_per_connection: 4,
    });
    let root = reqwest::Certificate::from_pem(material.ca_pem.as_bytes()).expect("ca root");

    let (b, spki) = stack_b(
        "pinned.test",
        fixture.addr,
        &format!("https://pinned.test:{}/v1/x", fixture.addr.port()),
        "{}",
        None,
        std::slice::from_ref(&root),
    )
    .await;
    assert_eq!(
        b,
        Outcome::Answered {
            status: 200,
            location: None,
            body: "over tls".to_string()
        }
    );
    let expected_pin =
        busbar_substrate::plane_host::spki::pin(&material.leaf_der).expect("fixture leaf");
    assert_eq!(
        spki.as_deref(),
        Some(expected_pin.as_str()),
        "the observed SPKI must equal the pin of the leaf the fixture served"
    );

    // Without the extra root the same posture refuses — the "accepted only with the root" arm.
    let (without_root, _) = stack_b(
        "pinned.test",
        fixture.addr,
        &format!("https://pinned.test:{}/v1/x", fixture.addr.port()),
        "{}",
        None,
        &[],
    )
    .await;
    assert_eq!(without_root, Outcome::RefusedAtConnect);

    // Stack A, webpki-only trust: the private CA is refused at the same class.
    let a = stack_a(&format!("https://{}/v1/x", fixture.addr), "{}").await;
    assert_eq!(a, Outcome::RefusedAtConnect);

    let records = fixture.records();
    let succeeded: Vec<_> = records.iter().filter(|r| r.handshake_ok).collect();
    assert_eq!(succeeded.len(), 1, "only the rooted pinned hop completed");
    assert_eq!(
        succeeded[0].sni.as_deref(),
        Some("pinned.test"),
        "the SNI stayed on the hostname while the socket went to the pinned address"
    );
    assert_eq!(
        succeeded[0].client_cert, None,
        "no identity was configured, none may be presented"
    );
    // The refusing connections still recorded what their ClientHello said.
    assert_eq!(records.len(), 3, "every connection was recorded");
}

/// The mTLS row: a server that REQUIRES a client certificate accepts the hop only when the client
/// carries the identity, and the certificate the server records is byte-identical to the identity's
/// leaf. Without the identity the handshake is refused by the peer — connect class, presenting
/// nothing rather than forging something.
#[tokio::test]
async fn mtls_fixture_accepts_only_the_carried_identity() {
    let server = ca_and_leaf(&["mtls.test"]);
    let client = ca_and_leaf(&["client.busbar.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server.leaf_pem.clone(),
        key_pem: server.leaf_key_pem.clone(),
        client_auth: ClientAuth::Required {
            ca_pem: client.ca_pem.clone(),
        },
        response: CannedResponse::ok("mutually authenticated"),
        max_requests_per_connection: 4,
    });
    let root = reqwest::Certificate::from_pem(server.ca_pem.as_bytes()).expect("ca root");
    let identity_pem = format!("{}{}", client.leaf_pem, client.leaf_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).expect("client identity");

    let (with_identity, _) = stack_b(
        "mtls.test",
        fixture.addr,
        &format!("https://mtls.test:{}/v1/x", fixture.addr.port()),
        "{}",
        Some(identity),
        std::slice::from_ref(&root),
    )
    .await;
    assert_eq!(
        with_identity,
        Outcome::Answered {
            status: 200,
            location: None,
            body: "mutually authenticated".to_string()
        }
    );

    let (without_identity, _) = stack_b(
        "mtls.test",
        fixture.addr,
        &format!("https://mtls.test:{}/v1/x", fixture.addr.port()),
        "{}",
        None,
        std::slice::from_ref(&root),
    )
    .await;
    // TLS 1.3: the server's `CertificateRequired` alert arrives after the client-side handshake
    // completed, so the reference stack reports the refusal on the exchange, not the connect.
    assert_eq!(without_identity, Outcome::RefusedInFlight);

    let records = fixture.records();
    let accepted: Vec<_> = records.iter().filter(|r| r.handshake_ok).collect();
    assert_eq!(accepted.len(), 1);
    assert_eq!(
        accepted[0].client_cert.as_deref(),
        Some(client.leaf_der.as_slice()),
        "the server must have seen exactly the identity's leaf certificate"
    );
}

/// The pin makes the resolver STRUCTURALLY unreachable for the pinned host: a rebinding resolver
/// wired in as the client's DNS is never consulted for the pinned name (zero calls across the
/// exchange), and only a request for a DIFFERENT name reaches it. The production posture goes one
/// step further: [`RefuseSecondLookup`] fails that different name loudly with the doctrine text.
#[tokio::test]
async fn the_pin_never_consults_the_resolver_and_the_doctrine_refuses_other_names() {
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
