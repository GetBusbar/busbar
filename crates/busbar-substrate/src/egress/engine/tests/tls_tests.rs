// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS POSTURES, proven two ways. The R4 parity corpus drives every identity buffer — the
//! rcgen-minted fixtures plus the adversarial forms — through BOTH parsers
//! (`ClientIdentity::from_pem` and `reqwest::Identity::from_pem`) and asserts the accept/reject
//! VERDICTS agree, so a config that loaded under the reqwest stack keeps loading under the
//! engine. The handshake tests then drive the real `EngineSpec::pinned` posture through
//! `build_client`: the mTLS fixture accepts the engine's identity and records exactly its leaf;
//! the private-CA fixture is accepted only with the extra root.

use std::sync::Arc;

use http_body_util::BodyExt;

use super::*;
use crate::egress::fixtures::{
    ca_and_leaf, certs_from_pem, spawn_tls, CannedResponse, ClientAuth, TlsServerSpec,
};

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

/// R4 — THE PARITY CORPUS. Every buffer goes through BOTH parsers; the verdicts must AGREE, and
/// where a verdict is pinned it is pinned for both. The rows cover order-independence, chains,
/// each private-key encoding, and the adversarial forms (nothing, certs-only, key-only, foreign
/// section kinds, interleaved plain text, and the more-than-one-key tolerance reqwest ships).
#[test]
fn client_identity_from_pem_verdicts_match_reqwest() {
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
/// accepted, the server records EXACTLY the identity's leaf, and the response carries the
/// server's observed SPKI (the pinned posture observes by construction). Without the identity
/// the peer refuses — busbar presents nothing rather than forging something.
#[tokio::test]
async fn the_mtls_fixture_accepts_the_engine_identity_and_records_its_leaf() {
    let server = ca_and_leaf(&["mtls.test"]);
    let client_material = ca_and_leaf(&["engine.busbar.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server.leaf_pem.clone(),
        key_pem: server.leaf_key_pem.clone(),
        client_auth: ClientAuth::Required {
            ca_pem: client_material.ca_pem.clone(),
        },
        response: CannedResponse::ok("mutual"),
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

    let spec = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        Some(identity),
        certs_from_pem(&server.ca_pem),
    );
    let client = build_client(&spec).expect("the pinned mTLS posture builds");
    let resp = client
        .request(egress_request(
            format!("https://mtls.test:{}/v1/x", fixture.addr.port())
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            Bytes::new(),
        ))
        .await
        .expect("the mutual handshake completes");
    assert_eq!(resp.status(), 200);
    assert_eq!(
        peer_spki(&resp),
        Some(
            crate::plane_host::spki::pin(&server.leaf_der)
                .expect("server leaf")
                .as_str()
        ),
        "the pinned posture observes the peer by construction"
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
    // exchange yields; the differential harness pinned the same fact for the reqwest stack.)
    let without = EngineSpec::pinned(
        Arc::from("mtls.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&server.ca_pem),
    );
    let client = build_client(&without).expect("the identityless posture still builds");
    let refused = client
        .request(egress_request(
            format!("https://mtls.test:{}/v1/x", fixture.addr.port())
                .parse()
                .expect("uri"),
            http::HeaderMap::new(),
            Bytes::new(),
        ))
        .await;
    assert!(
        refused.is_err(),
        "an mTLS peer must refuse a hop that carried no identity"
    );
}

/// The private-CA posture: accepted ONLY with the extra root. The extras JOIN the webpki store
/// (`Trust::WebpkiPlus`), they never replace it; without them the private chain has no anchor and
/// the connect refuses.
#[tokio::test]
async fn the_private_ca_fixture_is_accepted_only_with_the_extra_root() {
    let material = ca_and_leaf(&["private.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: material.leaf_pem.clone(),
        key_pem: material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("privately rooted"),
        max_requests_per_connection: 4,
    });

    let rooted = EngineSpec::pinned(
        Arc::from("private.test"),
        fixture.addr.ip(),
        None,
        certs_from_pem(&material.ca_pem),
    );
    let client = build_client(&rooted).expect("the rooted posture builds");
    let uri: http::Uri = format!("https://private.test:{}/v1/x", fixture.addr.port())
        .parse()
        .expect("uri");
    let resp = client
        .request(egress_request(
            uri.clone(),
            http::HeaderMap::new(),
            Bytes::new(),
        ))
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
        .request(egress_request(uri, http::HeaderMap::new(), Bytes::new()))
        .await
        .expect_err("a private CA without its root must refuse");
    assert!(err.is_connect(), "refused at the handshake, connect class");
}

/// An extra root the store cannot take fails the CLIENT BUILD loudly — never skipped silently.
#[test]
fn a_garbage_extra_root_fails_the_build_loudly() {
    let spec = EngineSpec::pinned(
        Arc::from("private.test"),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        None,
        vec![rustls_pki_types::CertificateDer::from(
            b"not a certificate".to_vec(),
        )],
    );
    let err = build_client(&spec).expect_err("a garbage root must fail the build");
    assert!(
        err.contains("extra trust root"),
        "the refusal names the root: {err}"
    );
}
