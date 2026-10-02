// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The outbound half of connection security: each trust setting is proven by a real client
//! handshake through [`TlsDial`] against a real rustls server, over an in-memory duplex pipe.

use super::*;
use crate::tls::Tls;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

// ── the unset trust is the posture every outbound connection already had ───────────────────────

/// The default trust is genuinely nothing decided — the whole basis for the byte-identity claim.
#[test]
fn a_default_egress_trust_is_unset() {
    assert!(EgressTrust::default().is_unset());
    assert!(EgressTrust {
        extra_anchors: Vec::new(),
        pinned_public_keys: Vec::new(),
        client_identity: None,
    }
    .is_unset());
}

/// A hand-built DER certificate whose SubjectPublicKeyInfo is the seventh TBS member: the walk lands
/// on exactly it, header and all, so a pin taken over the returned bytes is a pin over the SPKI.
#[test]
fn the_key_info_walk_lands_on_the_key() {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 0x80, "short-form only in this fixture");
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }
    let serial = tlv(0x02, &[1]);
    let sig = tlv(0x30, &[]);
    let issuer = tlv(0x30, &[]);
    let validity = tlv(0x30, &[]);
    let subject = tlv(0x30, &[]);
    let key_info = tlv(0x30, &[0xAA, 0xBB, 0xCC]);
    let mut tbs_contents = Vec::new();
    for part in [&serial, &sig, &issuer, &validity, &subject, &key_info] {
        tbs_contents.extend_from_slice(part);
    }
    let tbs = tlv(0x30, &tbs_contents);
    let cert = tlv(0x30, &tbs);
    let found = subject_public_key_info(&cert).expect("the walk reaches the key");
    assert_eq!(
        found,
        key_info.as_slice(),
        "the whole key-info element, header included"
    );
}

/// Non-DER and truncated inputs produce no pin rather than a wrong one.
#[test]
fn the_key_info_walk_refuses_what_is_not_a_certificate() {
    assert!(subject_public_key_info(&[]).is_none());
    assert!(subject_public_key_info(&[0x30, 0x80]).is_none()); // indefinite length is BER, not DER
    assert!(subject_public_key_info(&[0x02, 0x01, 0x01]).is_none()); // an INTEGER, not a certificate
}

// ── each trust setting, through a real handshake ───────────────────────────────────────────────

/// A CA and a leaf it signs for `sans`: (ca_der, leaf_chain_der, leaf_key_der).
fn ca_and_leaf(sans: &[&str]) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf_kp.serialize_pem().as_bytes()).unwrap();
    (
        ca_cert.der().to_vec(),
        vec![leaf_cert.der().to_vec()],
        key.secret_der().to_vec(),
    )
}

/// A server for `chain`/`key`, requiring a client certificate under `client_ca` when one is given.
fn server(chain: &[Vec<u8>], key: &[u8], client_ca: Option<&[u8]>) -> Tls {
    install_crypto_provider();
    let certs: Vec<CertificateDer<'static>> =
        chain.iter().cloned().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::try_from(key.to_vec()).unwrap();
    let builder = rustls::ServerConfig::builder();
    let config = match client_ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(ca.to_vec())).unwrap();
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap();
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(certs, key)
    .unwrap();
    Tls::new(Arc::new(config))
}

/// Dial `server` through a [`TlsDial`] built from `trust`, offering `name`, and exchange one
/// message. `Err` carries whichever side refused.
async fn dial(server: Tls, trust: &EgressTrust, name: &str) -> Result<(), String> {
    let (server_io, client_io) = tokio::io::duplex(8192);
    let serving = tokio::spawn(async move {
        let raw: Box<dyn RawIo> = Box::new(TokioAsyncReadCompatExt::compat(server_io));
        let mut secured = server.wrap(raw).await.map_err(|e| e.to_string())?;
        let mut buf = [0u8; 4];
        futures::io::AsyncReadExt::read_exact(&mut secured, &mut buf)
            .await
            .map_err(|e| e.to_string())?;
        futures::io::AsyncWriteExt::write_all(&mut secured, b"pong")
            .await
            .map_err(|e| e.to_string())?;
        futures::io::AsyncWriteExt::flush(&mut secured)
            .await
            .map_err(|e| e.to_string())
    });

    let dial = TlsDial::new(
        Arc::new(build_client_config(trust).expect("a usable client config")),
        ServerName::try_from(name.to_string()).unwrap(),
    );
    let raw: Box<dyn RawIo> = Box::new(TokioAsyncReadCompatExt::compat(client_io));
    let client = async {
        let mut secured = dial.wrap(raw).await.map_err(|e| e.to_string())?;
        futures::io::AsyncWriteExt::write_all(&mut secured, b"ping")
            .await
            .map_err(|e| e.to_string())?;
        futures::io::AsyncWriteExt::flush(&mut secured)
            .await
            .map_err(|e| e.to_string())?;
        let mut got = [0u8; 4];
        futures::io::AsyncReadExt::read_exact(&mut secured, &mut got)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(&got, b"pong");
        Ok::<(), String>(())
    };
    let client_result = client.await;
    let server_result = serving.await.unwrap();
    client_result.and(server_result)
}

/// The SHA-256 of `leaf`'s whole SubjectPublicKeyInfo — the form an SPKI pin is written in.
fn pin_of(leaf: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(subject_public_key_info(leaf).unwrap()).into()
}

/// An extra trust anchor is what lets a dial reach a peer whose chain the platform roots do not
/// cover, and without it the same dial is refused: the anchor is the difference.
#[tokio::test]
async fn an_extra_anchor_is_what_lets_a_dial_trust_a_private_ca() {
    let (ca, chain, key) = ca_and_leaf(&["upstream.test"]);
    dial(
        server(&chain, &key, None),
        &EgressTrust::default(),
        "upstream.test",
    )
    .await
    .expect_err("the platform roots alone do not cover a private CA");

    let trust = EgressTrust {
        extra_anchors: vec![ca],
        ..EgressTrust::default()
    };
    dial(server(&chain, &key, None), &trust, "upstream.test")
        .await
        .expect("the anchor the host added covers the peer's chain");
}

/// A pin is layered OVER chain verification: the peer whose key hashes to the pin is reached, and a
/// peer with a valid chain but another key is refused.
#[tokio::test]
async fn a_pinned_dial_reaches_only_the_pinned_key() {
    let (ca, chain, key) = ca_and_leaf(&["upstream.test"]);
    let pinned = EgressTrust {
        extra_anchors: vec![ca.clone()],
        pinned_public_keys: vec![pin_of(&chain[0])],
        client_identity: None,
    };
    dial(server(&chain, &key, None), &pinned, "upstream.test")
        .await
        .expect("the pinned key is reached");

    let other = EgressTrust {
        extra_anchors: vec![ca],
        pinned_public_keys: vec![[0u8; 32]],
        client_identity: None,
    };
    let err = dial(server(&chain, &key, None), &other, "upstream.test")
        .await
        .expect_err("a valid chain under a key nobody pinned is refused");
    assert!(
        err.contains("not one this destination is pinned to"),
        "the dial failed for the wrong reason: {err}"
    );
}

/// A client identity is presented for a mutual handshake: a server that requires a certificate
/// under the identity's CA serves the dial that carries it and refuses the one that does not.
#[tokio::test]
async fn a_client_identity_is_presented_to_a_mutual_peer() {
    let (server_ca, server_chain, server_key) = ca_and_leaf(&["upstream.test"]);
    let (client_ca, client_chain, client_key) = ca_and_leaf(&["busbar-client"]);

    let anonymous = EgressTrust {
        extra_anchors: vec![server_ca.clone()],
        ..EgressTrust::default()
    };
    dial(
        server(&server_chain, &server_key, Some(&client_ca)),
        &anonymous,
        "upstream.test",
    )
    .await
    .expect_err("a mutual peer refuses a dial that presents no certificate");

    let identified = EgressTrust {
        extra_anchors: vec![server_ca],
        pinned_public_keys: Vec::new(),
        client_identity: Some(busbar_contract::transport::trust::ClientIdentity {
            cert_chain: client_chain,
            private_key: client_key.into(),
        }),
    };
    dial(
        server(&server_chain, &server_key, Some(&client_ca)),
        &identified,
        "upstream.test",
    )
    .await
    .expect("the identity the host configured is presented and accepted");
}

/// RED: a client identity whose key does not parse refuses, naming the need, where it once fell
/// back silently to presenting no certificate at all.
#[test]
fn a_client_identity_that_does_not_parse_refuses_the_boot_naming_the_need() {
    let (_, chain, _) = ca_and_leaf(&["busbar-client"]);
    let bad = EgressTrust {
        client_identity: Some(busbar_contract::transport::trust::ClientIdentity {
            cert_chain: chain,
            private_key: b"not a private key".to_vec().into(),
        }),
        ..EgressTrust::default()
    };
    assert!(matches!(
        build_client_config(&bad),
        Err(BadClientIdentity(_))
    ));
    let refused = need_client_config("upstream-mtls", &bad).expect_err("refused at boot");
    assert!(
        refused.contains("need `upstream-mtls`") && refused.contains("client identity"),
        "{refused}"
    );
    assert!(
        need_client_config("plain", &EgressTrust::default()).is_ok(),
        "a need with no identity configured is unchanged"
    );
}
