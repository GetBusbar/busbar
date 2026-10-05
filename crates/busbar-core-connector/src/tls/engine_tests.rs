// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TLS, OVER THE CONNECTOR'S REAL WRAP. TLS stays in the connector (THE DESIGN; 1.6.0-TODO
//! P2: "TLS lives only in the connector"), so the rows that need a REAL handshake through the
//! kernel's outbound engine and its TLS listener live here, beside the wrap they prove (this crate
//! depends one way on the kernel, so both are named). The kernel's own suites drive the same postures over a TLS
//! test double (`busbar_kernel::egress::fixtures::TlsDouble`) and prove the engine's side of the
//! seam; these prove the composition:
//!
//! * the R4 parity corpus — the identity PEM walk (`ClientIdentity::from_pem`, the connector's walk)
//!   against `reqwest::Identity::from_pem`, verdict for verdict;
//! * the mutual handshake through the pinned posture recording exactly the engine identity's leaf,
//!   and the peer refusing a hop that carried none;
//! * 1.5.5's ALPN offer reaching the ClientHello (`http/1.1` under http1-only);
//! * the private CA accepted only with its extra root, and a garbage root failing the build loudly;
//! * the SNI staying on the hostname under the pin, and a wrong-name certificate refused;
//! * a judged dial keeping the name for SNI and `Host`;
//! * a trust refusal rendering the TLS stack's own cause;
//! * the egress differential's TLS rows: the owned engine beside 1.5.5's pinned reqwest client
//!   against one recording TLS fixture (the known leaf's pin and SNI under the pin, webpki refusing
//!   the private CA, the client-certificate fixture accepting only the carried identity);
//! * the TLS listener (`busbar_kernel::tls::serve`) over the connector's production wrap
//!   (`busbar_core_connector::tls::prepare`): a trusted client's 200, mutual TLS admitting a client
//!   certificate chaining to `client_ca` and refusing none or a foreign one while still serving.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::test_support::{certs_from_pem, spawn_tls, ClientAuth, TlsServerSpec};
use busbar_kernel::egress::engine::{
    build_client, egress_request, peer_key_pin, ClientIdentity, Dns, EngineSpec, Trust,
};
use busbar_kernel::egress::fixtures::{
    ca_and_leaf, private_refusing, CannedResponse, RebindingResolver,
};
use bytes::Bytes;
use http_body_util::BodyExt;

/// The connector's wrap under this test binary's kernel, as the composition root's egress-trust
/// capability carries it at boot.
fn connector_tls() {
    crate::tls::engine::install();
}

fn get(url: &str) -> axum::http::Request<http_body_util::Full<Bytes>> {
    egress_request(
        url.parse().expect("uri"),
        axum::http::HeaderMap::new(),
        Bytes::new(),
    )
}

/// A SEC1 (`EC PRIVATE KEY`) fixture key — rcgen serializes PKCS#8 only, and the SEC1 arm of both
/// parsers deserves a live row in the corpus. Test material, minted for this file, secures
/// nothing.
const SEC1_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEGvZhCJq9mnmyFgzu3/Kone9sktg5fOWjUdVp3CjZZ8oAoGCCqGSM49
AwEHoUQDQgAEHpmiCMNHO2qpAWzrA2ymuDz/l1Q2LsGDrAOmph5G8YSP2dpSumq2
PDvx27nZzMGwuG5lKYUjN4F6SAeqZZdiPw==
-----END EC PRIVATE KEY-----
";

/// A PKCS#1 (`RSA PRIVATE KEY`) fixture key, for the same reason. Test material, secures nothing.
const PKCS1_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAku7Ajjob4QjsP1oyaRYB7LLZ2Hebh3SgMmaUF8YqUqs0Na7h
J3H5xttQfGUzbGWh9W8DJcdiiK8dP50lmUz4+Sp57ktpnqwGgexkeyR1J9CMzkIJ
FY7ZruSDXEIQVytQmHKjia/dN3Kb0ObXYDZP+UnPAB2aiaKfwK8Fis6xi+rm+CW5
+DN0UW8HTS2XOlvvKk1n6T4CjboaQMvVhx0A+0ZMXusjRZ1RI4q7yd+r2BKK0H6B
PCMfj+/9PZN/ht4doc1dtJbJba3CE0yhXH6mRCbiid1ou/2CXevY1vGRO69/Q0cy
ZBgCSqGfLwd4iN6KOqwzUquLDiv527jGnhDLKQIDAQABAoIBAAIGoffMEBCYIobE
l/uYMrZYaHXKP2Ycmu1a+fmCcViytN11H/Re51BhO4C9lfoNhDBJw6+4ijCjhnoX
MPqmQ6wO1H/PQSFvkobl0yRaBjYCc4CQC0dFcRWu36tM22QSTDIP6ZaXSsvuC/0z
Q563XP6tUHn6ToRNjlmWKDPH4g2Rbhw4kfONNcn+ueXXroOdq477xx6S544lfcZl
y3vZHeVOf7PYVNrXzWdLZHt3PvUgVjtRg05MY9Fk8E5+7RvrxHLcQmgQaoPMUwU7
MHVNbxnAWoQYJlqNkr8fFsNYjp1nCMP0NoRmZnrCofsBEEOc37ulLA6CVaA7ZJEj
DCrLlPECgYEAyEBnGgcnINMRJWffqL0FOaUIxLLgurk21ztMbojWAF259G3h2p+r
dvKrGzJKGBl0s4yQdYv20my8yoAzBZaWrGDgwXVbcWZu1rnQ4/phWKwmK39QOdln
Bc4966M/EBFJ4qfdOmO4V/3idtKf6+wbvUyB2g6mt7G0zvefyKRR3JECgYEAu9Zl
gy/uYGWJt/KGvTd81bPq+nDlKKb+cz/64qZswRs5Ht1fWfN9amZ5xayXHyFxA095
2ye0/2V9uIxeyD6Tnfq2Wluu6MVjTexjNz3PtJfElDWsQUccQzU++aZ8cKy1qw8U
ItGv+v7pp+EnsdEY9+qLdu0BNe6S6tskIcBysRkCgYEAhuDKEP/sXPGNRPKX9OGL
2W3NYB9TurDxvTqVmoXUDl8S1w4D5+tP5EhC84iF24GZ1y3AR0xErSrMZmC+/O6X
AfgmqmdPdiwWT87MYiHM25roArg34x8JgyGNF1/XJA1hBKcoHSH5klrQ5FOtn4xi
irgzZhokNOoe7KBhIRV8heECgYBIFUizhWtXNuAY5UtrxaV0ZS0hmr12Uk+HbuAa
pn9Jw+axv4ZeAKD6egT1JPyBh9XUzWUYAy7ka9BJSCT/d3QyxgnAtzpyPX2UY8jX
ZDMXPL7FmatXCbEA4agfKhLLMpws3wZ9Ljb4fWaxdChFhtasHSgUJXO3fKyI0DwX
b8ET0QKBgAPj12loN8nXjAtbZRMiOUQ8xjHKsR7uHuyWZnhBw7opymMMK+E9VkT1
azIEjY3bAGG06Ty/5mupuPP8ELc8c/UvwKs5C5erzjareg87DlPbdfNXFmyGqngY
3EDXcGwftvgsgdj/B9mYV1TVHDt4XoGgZDuy4GH1JY/k6chBjFzN
-----END RSA PRIVATE KEY-----
";

/// R4 — THE PARITY CORPUS. Every buffer goes through BOTH parsers — the engine's
/// (`ClientIdentity::from_pem`, the connector's PEM walk) and `reqwest::Identity::from_pem` — and
/// the verdicts must AGREE, and where a verdict is pinned it is pinned for both. The rows cover
/// order-independence, chains, each private-key encoding, and the adversarial forms (nothing,
/// certs-only, key-only, foreign section kinds, interleaved plain text, and the more-than-one-key
/// tolerance reqwest ships).
#[test]
fn client_identity_from_pem_verdicts_match_reqwest() {
    connector_tls();
    let a = ca_and_leaf(&["ident-a.test"]);
    let b = ca_and_leaf(&["ident-b.test"]);

    let rows: Vec<(&str, String, Option<bool>)> = vec![
        (
            "cert then key",
            format!("{}{}", a.leaf_pem, a.leaf_key_pem),
            Some(true),
        ),
        (
            "key then cert",
            format!("{}{}", a.leaf_key_pem, a.leaf_pem),
            Some(true),
        ),
        (
            "chain of two certs plus key",
            format!("{}{}{}", a.leaf_pem, a.ca_pem, a.leaf_key_pem),
            Some(true),
        ),
        (
            "SEC1 key with a cert",
            format!("{}{}", a.leaf_pem, SEC1_KEY_PEM),
            Some(true),
        ),
        (
            "PKCS#1 key with a cert",
            format!("{}{}", a.leaf_pem, PKCS1_KEY_PEM),
            Some(true),
        ),
        (
            "interleaved plain text is skipped by the PEM walk",
            format!("operator note\n{}\nmore prose\n{}", a.leaf_pem, a.leaf_key_pem),
            Some(true),
        ),
        (
            "two keys: reqwest loads the LAST, so must the engine (R4 tolerance)",
            format!("{}{}{}", a.leaf_pem, b.leaf_key_pem, a.leaf_key_pem),
            Some(true),
        ),
        ("empty buffer", String::new(), Some(false)),
        ("certs only", a.leaf_pem.clone(), Some(false)),
        ("key only", a.leaf_key_pem.clone(), Some(false)),
        (
            "a section kind that is not identity material",
            format!(
                "{}{}-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n",
                a.leaf_pem, a.leaf_key_pem
            ),
            Some(false),
        ),
        ("non-PEM garbage", "not a pem at all".to_string(), Some(false)),
        (
            "truncated base64 in a section",
            "-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----\n".to_string(),
            None, // whatever the shared PEM walk says — only the AGREEMENT is pinned
        ),
    ];

    for (what, buf, expected) in rows {
        let engine = ClientIdentity::from_pem(buf.as_bytes());
        let reference = reqwest::Identity::from_pem(buf.as_bytes());
        assert_eq!(
            engine.is_ok(),
            reference.is_ok(),
            "verdict drift on {what:?}: engine {:?} vs reqwest {:?}",
            engine.as_ref().err(),
            reference.as_ref().err().map(|e| e.to_string()),
        );
        if let Some(expected) = expected {
            assert_eq!(engine.is_ok(), expected, "unexpected verdict on {what:?}");
        }
    }
}

/// The mTLS handshake through the REAL pinned posture: `EngineSpec::pinned` with the identity is
/// accepted, the server records EXACTLY the identity's leaf, and the response carries the server's
/// observed SPKI (the pinned posture observes by construction). Without the identity the peer
/// refuses — busbar presents nothing rather than forging something.
#[tokio::test]
async fn the_mtls_fixture_accepts_the_engine_identity_and_records_its_leaf() {
    connector_tls();
    let server = ca_and_leaf(&["mtls.test"]);
    let client_material = ca_and_leaf(&["engine.busbar.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server.leaf_pem.clone(),
        key_pem: server.leaf_key_pem.clone(),
        client_auth: ClientAuth::Required {
            ca_pem: client_material.ca_pem.clone(),
        },
        response: CannedResponse::ok("mutual").render(),
        max_requests_per_connection: 4,
    });
    let identity = ClientIdentity::from_pem(
        format!(
            "{}{}",
            client_material.leaf_pem, client_material.leaf_key_pem
        )
        .as_bytes(),
    )
    .expect("the engine identity parses");
    let url = format!("https://mtls.test:{}/v1/x", fixture.addr.port());

    let spec = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        Some(identity),
        certs_from_pem(&server.ca_pem),
    );
    let client = build_client(&spec).expect("the pinned mTLS posture builds");
    let resp = client
        .request(get(&url))
        .await
        .expect("the mutual handshake completes");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        peer_key_pin(&resp),
        Some(
            busbar_kernel::plane_host::spki::pin(&server.leaf_der)
                .expect("server leaf")
                .as_str()
        ),
        "the pinned posture observes the real peer by construction"
    );
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"mutual");
    let records = fixture.records_when(|r| r.first().is_some_and(|c| c.client_cert.is_some()));
    assert_eq!(
        records[0].client_cert.as_deref(),
        Some(client_material.leaf_der.as_slice()),
        "the server must have seen exactly the engine identity's leaf"
    );

    // Without the identity, the peer refuses the handshake — nothing was presented. (TLS 1.3
    // surfaces the peer's refusal after the client-side handshake, so the CLASS is whatever the
    // exchange yields.)
    let without = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&server.ca_pem),
    );
    let client = build_client(&without).expect("the identityless posture still builds");
    assert!(
        client.request(get(&url)).await.is_err(),
        "an mTLS peer must refuse a hop that carried no identity"
    );
}

/// 1.5.5's ClientHello offered ALPN `http/1.1` under the http1-only key, and `h2, http/1.1`
/// otherwise. The fixture serves only `http/1.1`, so what it agrees tells whether the hello carried
/// the extension: an empty offer agrees nothing.
#[tokio::test]
async fn the_http1_only_hello_offers_http_1_1_as_1_5_5_did() {
    connector_tls();
    for http1_only in [true, false] {
        let server = ca_and_leaf(&["alpn.test"]);
        let fixture = spawn_tls(TlsServerSpec {
            cert_chain_pem: server.leaf_pem.clone(),
            key_pem: server.leaf_key_pem.clone(),
            client_auth: ClientAuth::None,
            response: CannedResponse::ok("alpn").render(),
            max_requests_per_connection: 1,
        });
        let mut spec = EngineSpec::pinned(
            Arc::from("alpn.test"),
            fixture.addr.ip(),
            None,
            certs_from_pem(&server.ca_pem),
        );
        spec.http1_only = http1_only;
        let client = build_client(&spec).expect("the posture builds");
        let resp = client
            .request(get(&format!(
                "https://alpn.test:{}/v1/x",
                fixture.addr.port()
            )))
            .await
            .expect("the handshake completes");
        assert_eq!(resp.status(), 200);
        let records = fixture.records_when(|r| r.first().is_some_and(|c| c.handshake_ok));
        assert_eq!(
            records[0].alpn.as_deref(),
            Some(&b"http/1.1"[..]),
            "http1_only = {http1_only}: the hello must carry ALPN http/1.1"
        );
    }
}

/// The private-CA posture: accepted ONLY with the extra root. The extras JOIN the webpki store
/// (`Trust::WebpkiPlus`), they never replace it; without them the private chain has no anchor and
/// the connect refuses.
#[tokio::test]
async fn the_private_ca_fixture_is_accepted_only_with_the_extra_root() {
    connector_tls();
    let material = ca_and_leaf(&["private.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("privately rooted").render(),
        max_requests_per_connection: 4,
    });
    let url = format!("https://private.test:{}/v1/x", fixture.addr.port());
    let rooted = EngineSpec::pinned(
        Arc::from("private.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&material.ca_pem),
    );
    let client = build_client(&rooted).expect("the rooted posture builds");
    let resp = client
        .request(get(&url))
        .await
        .expect("the rooted hop answers");
    assert_eq!(resp.status(), 200);

    let unrooted = EngineSpec::pinned(
        Arc::from("private.test"),
        fixture.addr.ip(),
        None,
        Vec::new(),
    );
    let client = build_client(&unrooted).expect("webpki-only still builds");
    let err = client
        .request(get(&url))
        .await
        .expect_err("a private CA without its root must refuse");
    assert!(err.is_connect(), "refused at the handshake, connect class");
}

/// An extra root the store cannot take fails the CLIENT BUILD loudly — never skipped silently.
#[test]
fn a_garbage_extra_root_fails_the_build_loudly() {
    connector_tls();
    let spec = EngineSpec::pinned(
        Arc::from("private.test"),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        vec![b"not a certificate".to_vec()],
    );
    let Err(err) = build_client(&spec) else {
        panic!("a garbage root must fail the build");
    };
    assert!(
        err.contains("extra trust root"),
        "the refusal names the root: {err}"
    );
}

/// SNI preservation under the pin: the socket goes to the pinned loopback address, but the SNI —
/// and therefore the certificate NAME check — stays on the hostname. The refusing twin: a cert for a
/// DIFFERENT name served at the same pinned address fails the handshake (connect class), which is
/// precisely the check an address-rewriting pin would have silently destroyed.
#[tokio::test]
async fn sni_stays_on_the_hostname_and_a_wrong_name_cert_is_refused() {
    connector_tls();
    let right = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: right.leaf_pem.clone(),
        key_pem: right.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("named").render(),
        max_requests_per_connection: 4,
    });
    let spec = EngineSpec::pinned(
        Arc::from("pinned.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&right.ca_pem),
    );
    let resp = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://pinned.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect("the rightly-named hop answers");
    assert_eq!(resp.status(), 200);
    let records = fixture.records();
    assert_eq!(records[0].sni.as_deref(), Some("pinned.test"));
    assert!(records[0].handshake_ok);

    // Its own CA trusted too, but the leaf names `other.test` — served at the address
    // `pinned.test` is pinned to. The name check runs against the hostname, so the handshake is
    // REFUSED.
    let wrong = ca_and_leaf(&["other.test"]);
    let wrong_fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: wrong.leaf_pem.clone(),
        key_pem: wrong.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("misnamed").render(),
        max_requests_per_connection: 4,
    });
    let mut roots = certs_from_pem(&wrong.ca_pem);
    roots.extend(certs_from_pem(&right.ca_pem));
    let spec = EngineSpec::pinned(
        Arc::from("pinned.test"),
        wrong_fixture.addr.ip(),
        None,
        roots,
    );
    let err = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://pinned.test:{}/v1/x",
            wrong_fixture.addr.port()
        )))
        .await
        .expect_err("a wrong-name certificate must refuse");
    assert!(err.is_connect(), "refused at the handshake, connect class");
    let records = wrong_fixture.records_when(|r| r.first().is_some_and(|c| c.sni.is_some()));
    assert_eq!(
        records[0].sni.as_deref(),
        Some("pinned.test"),
        "the ClientHello carried the hostname even though the handshake was refused"
    );
    assert!(!records[0].handshake_ok);
}

/// THE NAME STAYS ON THE WIRE. A judged TLS dial connects to the address the name answered with and
/// presents the configured NAME: the ClientHello's SNI is the name, the certificate is verified
/// against it (the leaf is minted for the name only), and the request head carries it as `Host`.
#[tokio::test]
async fn a_judged_tls_dial_keeps_the_name_for_sni_and_host() {
    connector_tls();
    let material = ca_and_leaf(&["provider.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("named").render(),
        max_requests_per_connection: 4,
    });
    let judged = EngineSpec {
        dns: Dns::Custom(Arc::new(RebindingResolver::counting(fixture.addr))),
        judge: Some(private_refusing(&["provider.test"])),
        trust: Trust::WebpkiPlus(certs_from_pem(&material.ca_pem)),
        ..EngineSpec::pooled_webpki(4, 300, false, false)
    };
    let resp = build_client(&judged)
        .expect("builds")
        .request(get(&format!(
            "https://provider.test:{}/v1/x",
            fixture.addr.port()
        )))
        .await
        .expect("the named dial");
    assert_eq!(resp.status(), 200);
    let _ = resp.into_body().collect().await;
    let records = fixture.records_when(|r| r.first().is_some_and(|c| c.requests == 1));
    assert!(records[0].handshake_ok, "verified against the name");
    assert_eq!(records[0].sni.as_deref(), Some("provider.test"));
    let host_line = format!("host: provider.test:{}", fixture.addr.port());
    assert!(
        records[0].heads[0]
            .lines()
            .any(|l| l.eq_ignore_ascii_case(&host_line)),
        "Host is the name: {:?}",
        records[0].heads[0]
    );
}

/// Dial-error cause QUALITY: a TLS trust refusal renders the TLS stack's own cause through the
/// engine — never a vague "channel closed".
#[tokio::test]
async fn a_tls_trust_refusal_renders_the_real_cause() {
    connector_tls();
    let server_material = ca_and_leaf(&["refused.test"]);
    let other_ca = ca_and_leaf(&["refused.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server_material.leaf_pem.clone(),
        key_pem: server_material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("never").render(),
        max_requests_per_connection: 4,
    });
    // Trust ONLY an unrelated CA beside the webpki roots, so the handshake refuses on trust.
    let spec = EngineSpec::pinned(
        Arc::from("refused.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&other_ca.ca_pem),
    );
    let err = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://refused.test:{}/x",
            fixture.addr.port()
        )))
        .await
        .expect_err("refused trust");
    assert!(err.is_connect());
    let cause = busbar_kernel::egress::with_cause(&err);
    assert!(
        cause.contains("invalid peer certificate"),
        "the TLS stack's own refusal: {cause}"
    );
    assert!(
        !cause.to_ascii_lowercase().contains("channel closed"),
        "never a vague channel-closed: {cause}"
    );
}

// ── THE DIFFERENTIAL'S TLS ROWS: the owned engine (stack A) beside 1.5.5's pinned reqwest client
// (stack B), against the same recording TLS fixture (moved here from busbar-llm's
// `egress_differential_tests`, whose plaintext rows stay there) ───────────────────────────────────

/// What one hop came to, across the two stacks.
#[derive(Debug, PartialEq, Eq)]
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
    /// the client already considers the handshake done).
    RefusedInFlight,
}

/// Drive ONE hop through stack A — the owned engine on the open-web posture (webpki trust, system
/// DNS, no pin). `uri` must be dialable as written (an IP-literal host).
async fn stack_a(uri: &str, body: &str) -> Outcome {
    let client = busbar_kernel::proxy::build_egress_client(
        &busbar_kernel::proxy::EgressClientSpec::pooled_webpki(4, 300, false, false),
    );
    let req = egress_request(
        uri.parse().expect("fixture uri"),
        axum::http::HeaderMap::new(),
        Bytes::from(body.to_string()),
    );
    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(axum::http::header::LOCATION)
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
/// (`RefuseSecondLookup`, host→addr pin, optional identity/extra root). Returns the outcome plus the
/// peer SPKI pin read off `reqwest::tls::TlsInfo`, where the hop ran over TLS.
async fn stack_b(
    host: &str,
    addr: SocketAddr,
    url: &str,
    body: &str,
    identity: Option<reqwest::Identity>,
    extra_roots: &[reqwest::Certificate],
) -> (Outcome, Option<String>) {
    let client = busbar_kernel::egress::build_pinned_client(
        host,
        addr,
        Arc::new(busbar_kernel::egress::RefuseSecondLookup),
        identity,
        extra_roots,
    )
    .expect("pinned client");
    match client.post(url).body(body.to_string()).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
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

/// The known-leaf TLS row: the pinned stack (with the private CA as an extra root) completes the
/// handshake WITH THE HOSTNAME — SNI and the certificate name check stay on `pinned.test` while
/// the socket goes to the pinned loopback address — and the observed peer SPKI equals a pin
/// computed DIRECTLY from the served leaf, outside the stack under test. The open-web stack
/// (webpki trust only) refuses the same server at the connect class: the private CA is not in its
/// trust story, and "refused" is the correct differential record for that posture.
#[tokio::test]
async fn known_leaf_tls_pin_and_sni_are_observed_and_webpki_refuses_the_private_ca() {
    connector_tls();
    let material = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("over tls").render(),
        max_requests_per_connection: 4,
    });
    let root = reqwest::Certificate::from_pem(material.ca_pem.as_bytes()).expect("ca root");

    let (b, leaf_pin) = stack_b(
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
        busbar_kernel::plane_host::spki::pin(&material.leaf_der).expect("fixture leaf");
    assert_eq!(
        leaf_pin.as_deref(),
        Some(expected_pin.as_str()),
        "the observed leaf pin must equal the pin of the leaf the fixture served"
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
async fn client_cert_fixture_accepts_only_the_carried_identity() {
    connector_tls();
    let server = ca_and_leaf(&["client-cert.test"]);
    let client = ca_and_leaf(&["client.busbar.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server.leaf_pem.clone(),
        key_pem: server.leaf_key_pem.clone(),
        client_auth: ClientAuth::Required {
            ca_pem: client.ca_pem.clone(),
        },
        response: CannedResponse::ok("mutually authenticated").render(),
        max_requests_per_connection: 4,
    });
    let root = reqwest::Certificate::from_pem(server.ca_pem.as_bytes()).expect("ca root");
    let identity_pem = format!("{}{}", client.leaf_pem, client.leaf_key_pem);
    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes()).expect("client identity");

    let (with_identity, _) = stack_b(
        "client-cert.test",
        fixture.addr,
        &format!("https://client-cert.test:{}/v1/x", fixture.addr.port()),
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
        "client-cert.test",
        fixture.addr,
        &format!("https://client-cert.test:{}/v1/x", fixture.addr.port()),
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

// ── THE REFUSALS A PLANE'S TRANSPORT ROWS STAND ON: the a2a card transport's batteries ride the
// kernel's TLS double (that crate names no TLS), so each certificate-verification refusal they
// once drove over a real handshake is proven here, one for one, through the same engine ──────────

/// THE CHAIN CHECK STAYS ON UNDER THE PIN: a self-signed leaf no root vouches for, served at the
/// pinned address, is refused at the handshake and the cause names the chain check
/// (`UnknownIssuer`). The ClientHello still carried the hostname, and no request rode the refused
/// handshake — no response, so no peer pin could ever be read off it. (The real handshake under
/// a2a's `a_hop_with_no_extra_root_trusts_the_webpki_roots_alone_and_carries_the_refusal` and
/// `a_refused_handshake_produces_no_card_and_therefore_no_pin`.)
#[tokio::test]
async fn an_untrusted_self_signed_leaf_is_refused_under_the_pin_naming_unknown_issuer() {
    connector_tls();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["untrusted.test".to_string()])
            .expect("self-signed");
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: cert.pem(),
        key_pem: signing_key.serialize_pem(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("never").render(),
        max_requests_per_connection: 4,
    });
    let spec = EngineSpec::pinned(
        Arc::from("untrusted.test"),
        fixture.addr.ip(),
        None,
        Vec::new(),
    );
    let err = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://untrusted.test:{}/card",
            fixture.addr.port()
        )))
        .await
        .expect_err("an untrusted certificate must not produce a response");
    assert!(err.is_connect(), "refused at the handshake, connect class");
    let cause = busbar_kernel::egress::with_cause(&err);
    assert!(
        cause.contains("invalid peer certificate") && cause.contains("UnknownIssuer"),
        "the refusal must be the certificate chain check, named: {cause}"
    );
    let records = fixture.records_when(|r| r.first().is_some_and(|c| c.sni.is_some()));
    assert_eq!(
        records[0].sni.as_deref(),
        Some("untrusted.test"),
        "the ClientHello carried the hostname even though the socket was pinned"
    );
    assert!(!records[0].handshake_ok);
    assert!(
        records.iter().all(|r| r.requests == 0),
        "no request rode a refused handshake: {records:?}"
    );
}

/// THE NAME CHECK, NAMED: the leaf's CA is trusted and the socket is the pinned one, so the only
/// thing left to refuse on is the NAME — and the cause says so, naming both the hostname the hop
/// verified against and the name the certificate carries. (The real handshake under a2a's
/// `a_trusted_root_rides_the_hop_and_the_name_it_is_checked_against_is_the_hostname`.)
#[tokio::test]
async fn a_wrong_name_refusal_names_the_hostname_and_the_certificates_name() {
    connector_tls();
    let other = ca_and_leaf(&["attacker.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: other.leaf_pem.clone(),
        key_pem: other.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("never").render(),
        max_requests_per_connection: 4,
    });
    let spec = EngineSpec::pinned(
        Arc::from("pinned.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&other.ca_pem),
    );
    let err = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://pinned.test:{}/card",
            fixture.addr.port()
        )))
        .await
        .expect_err("a certificate for a different name must be refused");
    assert!(err.is_connect(), "refused at the handshake, connect class");
    let cause = busbar_kernel::egress::with_cause(&err);
    assert!(
        cause.contains("invalid peer certificate")
            && cause.contains("certificate not valid for name \"pinned.test\"")
            && cause.contains("attacker.test"),
        "the CA is trusted and the socket is the same; the refusal must name the NAME: {cause}"
    );
}

/// THE PIN READ OFF A REAL HANDSHAKE IS THE SERVING LEAF'S KEY: two leaves for the same name, each
/// from its own CA, have different key pins, and the pin the engine reads off the verified
/// handshake is the serving leaf's — never the look-alike's. That difference is what an operator's
/// key pin refuses a look-alike endpoint on. (The real handshake under a2a's
/// `a_card_served_under_a_certificate_whose_key_pin_does_not_match_the_pin_is_refused`,
/// `a_mutual_tls_look_alike_endpoint_is_named_as_one_rather_than_as_a_missing_certificate`.)
#[tokio::test]
async fn the_pin_off_a_real_handshake_is_the_serving_leafs_key_and_not_a_look_alikes() {
    connector_tls();
    let serving = ca_and_leaf(&["pinned.test"]);
    let look_alike = ca_and_leaf(&["pinned.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: serving.leaf_pem.clone(),
        key_pem: serving.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("card").render(),
        max_requests_per_connection: 4,
    });
    let spec = EngineSpec::pinned(
        Arc::from("pinned.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&serving.ca_pem),
    );
    let resp = build_client(&spec)
        .expect("builds")
        .request(get(&format!(
            "https://pinned.test:{}/card",
            fixture.addr.port()
        )))
        .await
        .expect("the rooted hop answers");
    assert_eq!(resp.status(), 200);
    let expected = busbar_kernel::plane_host::spki::pin(&serving.leaf_der).expect("serving leaf");
    let other = busbar_kernel::plane_host::spki::pin(&look_alike.leaf_der).expect("look-alike");
    assert_ne!(expected, other, "two keys, two pins");
    assert_eq!(
        peer_key_pin(&resp),
        Some(expected.as_str()),
        "the pin is read off the handshake that served, so it is the serving leaf's key"
    );
}

/// What a mutual-TLS far end decided about each connection: `Ok(n)` when the handshake completed
/// with `n` client certificates presented, `Err(reason)` — this end's OWN refusal, as the TLS stack
/// words it — when it did not.
type PeerVerdicts = Arc<std::sync::Mutex<Vec<Result<usize, String>>>>;

/// A REAL far end that REQUIRES a client certificate chaining to `client_ca_pem` (a
/// `WebPkiClientVerifier`, as busbar's own mutual listener), recording its verdict on every
/// connection and answering a completed one with `200 ok`.
fn spawn_mtls_peer(
    server: &busbar_kernel::egress::fixtures::CaLeaf,
    client_ca_pem: &str,
) -> (SocketAddr, PeerVerdicts) {
    use std::io::{Read as _, Write as _};
    let tls = crate::test_support::ServerTls::from_pem(
        &server.leaf_pem,
        &server.leaf_key_pem,
        Some(client_ca_pem),
        &[b"http/1.1"],
    )
    .expect("the peer's material");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let verdicts: PeerVerdicts = Arc::default();
    let recorder = Arc::clone(&verdicts);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let Ok(mut session) = tls.accept_std(stream) else {
                continue;
            };
            if let Some(reason) = session.refusal() {
                recorder
                    .lock()
                    .expect("verdicts")
                    .push(Err(reason.to_string()));
                continue;
            }
            recorder
                .lock()
                .expect("verdicts")
                .push(Ok(session.peer_certs().len()));
            let mut head = Vec::new();
            let mut buf = [0_u8; 512];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match session.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let _ = session
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
            let _ = session.flush();
            session.close();
        }
    });
    (addr, verdicts)
}

/// The peer's verdicts once `n` have been recorded (a refused handshake's verdict can land just
/// after the client hears the refusal). Panics at the bound.
fn verdicts_when(verdicts: &PeerVerdicts, n: usize) -> Vec<Result<usize, String>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let seen = verdicts.lock().expect("verdicts").clone();
        if seen.len() >= n {
            return seen;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the peer's verdicts never settled: {seen:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The client identity the engine presents, from a leaf and its key.
fn identity_of(material: &busbar_kernel::egress::fixtures::CaLeaf) -> ClientIdentity {
    ClientIdentity::from_pem(format!("{}{}", material.leaf_pem, material.leaf_key_pem).as_bytes())
        .expect("the identity parses")
}

/// AN mTLS PEER REFUSES A HOP THAT PRESENTS NOTHING, AND SAYS SO: the engine built with no identity
/// presents none (it never forges one), the peer refuses at the handshake, and the peer's OWN
/// reason is that no certificate was sent — not that a wrong one was. (The real handshake under
/// a2a's `a_mutual_tls_peer_refuses_a_card_fetch_that_presents_no_client_certificate`.)
#[tokio::test]
async fn an_mtls_peer_refuses_a_hop_that_presents_no_client_certificate_for_that_reason() {
    connector_tls();
    let server = ca_and_leaf(&["mtls-peer.test"]);
    let client = ca_and_leaf(&["engine.busbar.test"]);
    let (addr, verdicts) = spawn_mtls_peer(&server, &client.ca_pem);
    let spec = EngineSpec::pinned(
        Arc::from("mtls-peer.test"),
        addr.ip(),
        None,
        certs_from_pem(&server.ca_pem),
    );
    let res = build_client(&spec)
        .expect("the identityless posture builds")
        .request(get(&format!("https://mtls-peer.test:{}/card", addr.port())))
        .await;
    assert!(
        res.is_err(),
        "a peer that demands a client certificate must not answer a hop that has none"
    );
    let seen = verdicts_when(&verdicts, 1);
    let [Err(reason)] = seen.as_slice() else {
        panic!("the refusal must be the PEER's, at the handshake: {seen:?}");
    };
    assert!(
        reason.contains("no certificates"),
        "and the peer's objection must be that nothing was presented: {reason}"
    );
}

/// AN mTLS PEER ADMITS ONLY ITS OWN CLIENT'S CERTIFICATE: the engine presenting the identity that
/// chains to the peer's client CA completes (the peer saw exactly one certificate); the engine
/// presenting another CA's identity is refused by the peer as an INVALID certificate — something
/// was offered and refused, which is not the same refusal as nothing offered. (The real handshake
/// under a2a's `each_registration_presents_its_own_certificate_and_not_another_registrations`,
/// `a_mutual_tls_peer_accepts_the_card_fetch_when_the_registration_names_a_client_identity`,
/// `the_verb_layers_probe_fetches_a_mutual_tls_vendors_card_with_that_registrations_certificate`,
/// `a_mutual_tls_registration_that_presents_its_client_certificate_verifies`.)
#[tokio::test]
async fn an_mtls_peer_accepts_its_own_clients_certificate_and_refuses_a_foreign_one_as_invalid() {
    connector_tls();
    let server = ca_and_leaf(&["mtls-peer.test"]);
    let own = ca_and_leaf(&["engine.busbar.test"]);
    let foreign = ca_and_leaf(&["engine.busbar.test"]);
    let (addr, verdicts) = spawn_mtls_peer(&server, &own.ca_pem);
    let url = format!("https://mtls-peer.test:{}/card", addr.port());
    let posture = |identity| {
        EngineSpec::pinned(
            Arc::from("mtls-peer.test"),
            addr.ip(),
            Some(identity),
            certs_from_pem(&server.ca_pem),
        )
    };

    let resp = build_client(&posture(identity_of(&own)))
        .expect("builds")
        .request(get(&url))
        .await
        .expect("the peer's own client certificate is admitted");
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    assert_eq!(&body[..], b"ok");
    assert_eq!(verdicts_when(&verdicts, 1), vec![Ok(1)]);

    let res = build_client(&posture(identity_of(&foreign)))
        .expect("builds")
        .request(get(&url))
        .await;
    assert!(
        res.is_err(),
        "another CA's certificate must not authenticate at this peer"
    );
    let seen = verdicts_when(&verdicts, 2);
    let [Ok(1), Err(reason)] = seen.as_slice() else {
        panic!("own admitted, foreign refused: {seen:?}");
    };
    assert!(
        reason.contains("invalid peer certificate"),
        "the foreign certificate is refused AS a certificate: {reason}"
    );
}

// ── THE TLS LISTENER over the connector's production wrap ───────────────────────────────────────

fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "busbar-engine-tls-{tag}-{}-{:?}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::write(&p, contents).expect("write pem");
    p
}

fn file(path: &std::path::Path) -> busbar_kernel::config::SecretRef {
    busbar_kernel::config::SecretRef::file(path.to_string_lossy().into_owned())
}

/// A self-signed server cert for `localhost`/`127.0.0.1`: (cert_pem, key_pem).
fn gen_self_signed() -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("self-signed");
    (cert.pem(), signing_key.serialize_pem())
}

/// Boot the busbar TLS listener (`busbar_kernel::tls::serve`) from a `TlsCfg` on an ephemeral port,
/// secured by the connector's PRODUCTION wrap (`busbar_core_connector::tls::prepare`), exactly as
/// `main`'s TLS branch does. Returns the bound address and a shutdown sender.
async fn spawn_tls_server(
    tls: &busbar_kernel::config::sections::TlsCfg,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let security = crate::tls::prepare(
        "engine-tls test",
        Some(tls),
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
        true,
    )
    .expect("valid test TLS config");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let router = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        busbar_kernel::tls::serve(listener, router, security, shutdown, None)
            .await
            .expect("serve");
    });
    (addr, tx)
}

/// TLS happy path: a client trusting the server's self-signed cert completes an https request and
/// gets 200.
#[tokio::test]
async fn tls_happy_path_trusted_client_gets_200() {
    let (cert_pem, key_pem) = gen_self_signed();
    let tls = busbar_kernel::config::sections::TlsCfg {
        cert: file(&temp_pem("srv-cert", &cert_pem)),
        key: file(&temp_pem("srv-key", &key_pem)),
        client_ca: None,
    };
    let (addr, _stop) = spawn_tls_server(&tls).await;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("cert"))
        .build()
        .expect("client");
    let resp = client
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("https request should succeed over TLS");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "ok");
}

/// A CA and a leaf it signed for `sans`: (ca_pem, leaf_pem, leaf_key_pem).
fn gen_ca_and_leaf(sans: &[&str]) -> (String, String, String) {
    let m = ca_and_leaf(sans);
    (m.ca_pem, m.leaf_pem, m.leaf_key_pem)
}

/// The mutual listener: client certificates must chain to the CA it names.
fn mutual(
    srv_cert_pem: &str,
    srv_key_pem: &str,
    ca_pem: &str,
) -> busbar_kernel::config::sections::TlsCfg {
    busbar_kernel::config::sections::TlsCfg {
        cert: file(&temp_pem("m-srv-cert", srv_cert_pem)),
        key: file(&temp_pem("m-srv-key", srv_key_pem)),
        client_ca: Some(file(&temp_pem("m-ca", ca_pem))),
    }
}

fn client_with(srv_cert_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).expect("cert"),
        )
        .use_rustls_tls();
    if let Some((leaf, key)) = identity {
        builder = builder.identity(
            reqwest::Identity::from_pem(format!("{leaf}{key}").as_bytes()).expect("identity"),
        );
    }
    builder.build().expect("client")
}

/// mTLS required + valid client cert: a client presenting a leaf signed by the configured CA gets
/// 200.
#[tokio::test]
async fn mtls_valid_client_cert_gets_200() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let (addr, _stop) = spawn_tls_server(&mutual(&srv_cert_pem, &srv_key_pem, &ca_pem)).await;
    let resp = client_with(&srv_cert_pem, Some((&leaf_pem, &leaf_key_pem)))
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("mTLS request with valid client cert should succeed");
    assert_eq!(resp.status(), 200);
}

/// mTLS required + no/wrong client cert: the handshake is rejected, the server stays up, and a
/// subsequent valid client still succeeds.
#[tokio::test]
async fn mtls_rejects_bad_client_then_serves_valid() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let (addr, _stop) = spawn_tls_server(&mutual(&srv_cert_pem, &srv_key_pem, &ca_pem)).await;
    let url = format!("https://localhost:{}/healthz", addr.port());

    // (a) Client presenting NO client cert ⇒ rejected (server requires one).
    assert!(
        client_with(&srv_cert_pem, None)
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client with no certificate"
    );
    // (b) Client presenting a cert from a DIFFERENT CA ⇒ also rejected.
    let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(&["impostor"]);
    assert!(
        client_with(&srv_cert_pem, Some((&wrong_leaf, &wrong_key)))
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client cert from an untrusted CA"
    );
    // (c) Server survived both rejections and still serves a valid client.
    let resp = client_with(&srv_cert_pem, Some((&leaf_pem, &leaf_key_pem)))
        .get(&url)
        .send()
        .await
        .expect("server must remain up and serve a valid client after rejecting bad ones");
    assert_eq!(resp.status(), 200);
}
