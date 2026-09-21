// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE R1 SPIKE AND THE CONNECTOR-LAYER PROOFS. The design's keystone is that `Connected::extra`
//! extras propagate through hyper_util's legacy pool onto EVERY response a pooled connection
//! serves — the spike test here pins it with two sequential requests over ONE connection, both
//! carrying [`PeerSpki`]. Beside it: SNI stays on the hostname under an address pin (and the
//! certificate NAME check runs against the hostname, so a wrong-name cert at the pinned address
//! is refused), the URI's port beats any port a resolver answers, and the connect deadline
//! bounds a black-holing TLS peer that hyper's TCP-only connect timeout never would.
//!
//! These tests hand-build the connector stack (fixture-rooted trust arrives with the TLS-posture
//! step; the stack shape is `EngineConnector` exactly), except where noted client-level through
//! `build_client`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;

use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::{
    ca_and_leaf, certs_from_pem, spawn_tls, CannedResponse, ClientAuth, TlsServerSpec,
};

/// Build the ENGINE'S connector shape over a fixture-rooted trust store: the same
/// `SpkiObserve<ConnectDeadline<HttpsConnector<TunnelConnector>>>` stack `build_client` wires,
/// with the trust source swapped for the fixture CA (the `WebpkiPlus` arm of the spec is the
/// TLS-posture step; the connector layering under test here is identical either way).
fn fixture_connector(
    root_pem: &str,
    resolver: EgressResolver,
    deadline: Duration,
    observe: bool,
) -> EngineConnector {
    let mut roots = rustls::RootCertStore::empty();
    for der in certs_from_pem(root_pem) {
        roots.add(der).expect("fixture root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    let http = tunnel::TunnelConnector::new(http, None, tunnel::connects_per_shard_for_tests());
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    SpkiObserve::new(ConnectDeadline::new(https, deadline), observe)
}

fn pooled_client(connector: EngineConnector) -> EngineClient {
    // The OWNED pool over the fixture connector — the same knobs the legacy builder took here
    // (idle cap 4, idle timeout 300s), so the spike below now pins OUR pool's extras replay.
    EngineClient::assemble(
        connector,
        super::client::PoolConfig {
            idle_cap_per_host: 4,
            idle_timeout: Duration::from_secs(300),
            http1_only: false,
            h2_prior_knowledge: false,
            h2_keepalive: None,
            dial_bound: 4,
        },
    )
}

fn get(uri: String) -> http::Request<Full<Bytes>> {
    egress_request(
        uri.parse().expect("uri"),
        http::HeaderMap::new(),
        Bytes::new(),
    )
}

/// R1 — THE MANDATORY SPIKE. Two sequential requests ride ONE pooled connection (the fixture's
/// per-connection request count is the proof of reuse), and BOTH responses carry the connection's
/// [`PeerSpki`] in their extensions, equal to a pin computed directly from the served leaf. If
/// hyper_util ever stopped copying `Connected` extras onto pooled-reuse responses, this goes red
/// and the design's fallback (a per-connection slot keyed through the pin pool) activates.
#[tokio::test]
async fn extras_propagate_through_pooled_reuse_both_responses_carry_peer_spki() {
    let material = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("observed"),
        max_requests_per_connection: 4,
    });
    let resolver = EgressResolver::Pinned {
        host: Arc::from("pinned.test"),
        addr: fixture.addr.ip(),
    };
    let client = pooled_client(fixture_connector(
        &material.ca_pem,
        resolver,
        Duration::from_secs(10),
        true,
    ));
    let expected = crate::plane_host::spki::pin(&material.leaf_der).expect("fixture leaf");

    for round in 1..=2 {
        let resp = client
            .request(get(format!(
                "https://pinned.test:{}/v1/x",
                fixture.addr.port()
            )))
            .await
            .expect("the observed hop answers");
        assert_eq!(resp.status(), 200);
        assert_eq!(
            peer_spki(&resp),
            Some(expected.as_str()),
            "request {round} must carry the connection's observed SPKI"
        );
        // Drain the body so the connection returns to the pool for the next round.
        let _ = resp.into_body().collect().await.expect("body");
    }

    let records = fixture.records();
    assert_eq!(records.len(), 1, "both requests must ride ONE connection");
    assert_eq!(
        records[0].requests, 2,
        "the fixture must have served two requests on that connection"
    );
}

/// SNI preservation under the pin: the socket goes to the pinned loopback address, but the SNI —
/// and therefore the certificate NAME check — stays on the hostname. The refusing twin: a cert
/// for a DIFFERENT name served at the same pinned address fails the handshake (connect class),
/// which is precisely the check an address-rewriting pin would have silently destroyed.
#[tokio::test]
async fn sni_stays_on_the_hostname_and_a_wrong_name_cert_is_refused() {
    let right = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: right.leaf_pem.clone(),
        key_pem: right.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("named"),
        max_requests_per_connection: 4,
    });
    let client = pooled_client(fixture_connector(
        &right.ca_pem,
        EgressResolver::Pinned {
            host: Arc::from("pinned.test"),
            addr: fixture.addr.ip(),
        },
        Duration::from_secs(10),
        true,
    ));
    let resp = client
        .request(get(format!(
            "https://pinned.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect("the rightly-named hop answers");
    assert_eq!(resp.status(), 200);
    let records = fixture.records();
    assert_eq!(records[0].sni.as_deref(), Some("pinned.test"));
    assert!(records[0].handshake_ok);

    // Same CA, but the leaf names `other.test` — served at the address `pinned.test` is pinned
    // to. The name check runs against the hostname, so the handshake is REFUSED.
    let wrong = {
        let mut wrong = ca_and_leaf(&["other.test"]);
        // Trust the WRONG server's CA too, so the refusal below can only be the NAME check.
        wrong.ca_pem = format!("{}{}", wrong.ca_pem, right.ca_pem);
        wrong
    };
    let wrong_fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: wrong.leaf_pem.clone(),
        key_pem: wrong.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("misnamed"),
        max_requests_per_connection: 4,
    });
    let client = pooled_client(fixture_connector(
        &wrong.ca_pem,
        EgressResolver::Pinned {
            host: Arc::from("pinned.test"),
            addr: wrong_fixture.addr.ip(),
        },
        Duration::from_secs(10),
        true,
    ));
    let err = client
        .request(get(format!(
            "https://pinned.test:{}/v1/x",
            wrong_fixture.addr.port()
        )))
        .await
        .expect_err("a wrong-name certificate must refuse");
    assert!(err.is_connect(), "refused at the handshake, connect class");
    // The client learns of the refusal the moment it sends its alert; wait for the fixture
    // thread to finish writing what the connection told it.
    let records = wrong_fixture.records_when(|r| r.first().is_some_and(|c| c.sni.is_some()));
    assert_eq!(
        records[0].sni.as_deref(),
        Some("pinned.test"),
        "the ClientHello carried the hostname even though the handshake was refused"
    );
    assert!(!records[0].handshake_ok);
}

/// R2 — the URI's port wins over any port a resolver answers. A scripted resolver answers the
/// fixture's ADDRESS with a garbage port; the request still lands on the URI's explicit port,
/// because `HttpConnector` overwrites the resolved port with the destination's — the same
/// layering that makes the pinned arm's port-0 answer correct.
#[tokio::test]
async fn the_uri_port_wins_over_a_garbage_resolver_port() {
    struct GarbagePort {
        ip: std::net::IpAddr,
        calls: AtomicUsize,
    }
    impl ResolveNames for GarbagePort {
        fn resolve(
            &self,
            _name: &str,
        ) -> futures::future::BoxFuture<
            'static,
            Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>>,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = SocketAddr::new(self.ip, 1); // a port nothing listens on
            Box::pin(std::future::ready(Ok(vec![answer])))
        }
    }

    let material = ca_and_leaf(&["ported.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("right port"),
        max_requests_per_connection: 4,
    });
    let scripted = Arc::new(GarbagePort {
        ip: fixture.addr.ip(),
        calls: AtomicUsize::new(0),
    });
    let client = pooled_client(fixture_connector(
        &material.ca_pem,
        EgressResolver::Custom(Arc::clone(&scripted) as Arc<dyn ResolveNames>),
        Duration::from_secs(10),
        true,
    ));
    let resp = client
        .request(get(format!(
            "https://ported.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect("the hop lands on the URI's port, not the resolver's");
    assert_eq!(resp.status(), 200);
    assert_eq!(scripted.calls.load(Ordering::SeqCst), 1);
}

/// The connect deadline bounds the WHOLE connect: a peer that completes TCP and then black-holes
/// the TLS handshake fails at the deadline — the case hyper's TCP-only connect timeout never
/// catches and reqwest's `connect_timeout` always did.
#[tokio::test]
async fn a_black_holed_tls_handshake_fails_at_the_connect_deadline() {
    // A listener that accepts and then says NOTHING: TCP succeeds, TLS never answers.
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            held.push(stream); // hold the socket open, never write a byte
        }
    });

    let material = ca_and_leaf(&["hole.test"]);
    let client = pooled_client(fixture_connector(
        &material.ca_pem,
        EgressResolver::Pinned {
            host: Arc::from("hole.test"),
            addr: addr.ip(),
        },
        Duration::from_millis(250),
        true,
    ));
    let started = Instant::now();
    let err = client
        .request(get(format!("https://hole.test:{}/v1/x", addr.port())))
        .await
        .expect_err("a black-holed handshake must fail at the deadline");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline must fire promptly, not at some request-level timeout"
    );
    assert!(
        err.is_connect(),
        "a deadline on the connect is connect-class"
    );
    let rendered = crate::egress::with_cause(&err);
    assert!(
        rendered.contains("exceeded the connect deadline"),
        "the refusal names the deadline: {rendered}"
    );
}
