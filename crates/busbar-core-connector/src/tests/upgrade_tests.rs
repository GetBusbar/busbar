// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MID-STREAM SECURITY UPGRADE (ldaps and StartTLS work as they did in
//! 1.5.5; `abi::host::conn::connector::service::UPGRADE_SECURE`). Through the connector, over real
//! TLS far ends whose certificates chain to a private CA:
//!
//! * a raw stream to a TLS far end does not round-trip in the clear, and does once it is upgraded
//!   before any byte (TLS from the first byte, ldaps);
//! * StartTLS: the plugin's own negotiation in the clear, then the upgrade, then TLS, with the far
//!   end's certificate hash in the stream's facts;
//! * the upgrade trusts the need's anchors: refused over the public roots alone, accepted with the
//!   operator CA the need's `trust_from` names; any other trust reference is refused.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

const OWNER: InstanceId = InstanceId(1);

/// A private CA and a `localhost` leaf it signed: (ca_pem, leaf_der, key_der).
fn private_ca() -> (String, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let kp = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&kp, &issuer)
        .unwrap();
    (ca.pem(), leaf.der().to_vec(), kp.serialize_der())
}

/// [`private_ca`] whose CA key is P-384, so the leaf it signs is signed `ecdsa-with-SHA384`.
fn private_p384_ca() -> (String, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let ca_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let kp = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&kp, &issuer)
        .unwrap();
    (ca.pem(), leaf.der().to_vec(), kp.serialize_der())
}

fn acceptor(leaf: Vec<u8>, key: Vec<u8>) -> tokio_rustls::TlsAcceptor {
    crate::tls::install_crypto_provider();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(server))
}

/// A far end on loopback that, per connection, reads `starttls` in the clear and answers `OK\n`
/// (none when `starttls` is empty: TLS from the first byte), then runs the TLS handshake and echoes
/// the first five bytes. Answers its address.
async fn far_end(leaf: Vec<u8>, key: Vec<u8>, starttls: &'static [u8]) -> String {
    let acceptor = acceptor(leaf, key);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if !starttls.is_empty() {
                    let mut asked = vec![0_u8; starttls.len()];
                    if s.read_exact(&mut asked).await.is_err() || asked != starttls {
                        return;
                    }
                    if s.write_all(b"OK\n").await.is_err() {
                        return;
                    }
                }
                if let Ok(mut s) = acceptor.accept(s).await {
                    let mut buf = [0_u8; 5];
                    if s.read_exact(&mut buf).await.is_ok() {
                        let _ = s.write_all(&buf).await;
                        let _ = s.flush().await;
                    }
                }
            });
        }
    });
    far
}

/// The process's connector shape over a RAW byte-stream door (no framing of its own, the plugin
/// speaks its own protocol): every literal admitted, the default outbound trust.
fn raw_connector() -> Connector {
    crate::tls::install_crypto_provider();
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Vec::new(),
    }])
    .unwrap();
    let tls = crate::tls::client::build_client_config(&Default::default()).expect("the config");
    Connector::serving(
        view,
        crate::tests::loopback_literals(),
        Some(Arc::new(tls)),
        Arc::new(|_, _| {}),
    )
}

/// An outbound raw need, the plugin naming its target, its trust from `trust_from`, declared with
/// `pem` as what that path resolved to.
fn declare(c: &Connector, trust_from: &str, pem: Option<&str>) {
    declare_class(c, trust_from, pem, crate::DEFAULT_CLASS);
}

/// [`declare`] under egress class `class`.
fn declare_class(c: &Connector, trust_from: &str, pem: Option<&str>, class: u32) {
    let need = ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: "bytes".to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: trust_from.to_owned(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    };
    assert_eq!(
        DeclaredConns::declare(c, OWNER, NeedId(0), &need, None, pem),
        Ok(())
    );
}

fn open(c: &Connector, far: &str) -> ConnId {
    c.open(
        OWNER,
        NeedId(0),
        &OpenDesc {
            target: far,
            ..OpenDesc::default()
        },
    )
    .expect("the raw stream opens")
}

/// Drive the upgrade to its answer, as a plugin's re-entries on its ticket would.
async fn upgrade(c: &Connector, id: ConnId, trust: Option<&str>) -> Result<(), ConnError> {
    upgrade_with(c, id, trust, false).await
}

/// [`upgrade`], `verify_off` the operator's opt-in to an unverified handshake.
async fn upgrade_with(
    c: &Connector,
    id: ConnId,
    trust: Option<&str>,
    verify_off: bool,
) -> Result<(), ConnError> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match DeclaredConns::upgrade_secure(
                c,
                OWNER,
                id,
                Some("localhost"),
                trust,
                verify_off,
                NO_TICKET,
            ) {
                Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
                answered => return answered,
            }
        }
    })
    .await
    .expect("the upgrade settles")
}

/// Write all of `bytes`, driving the connection while its buffer is full.
async fn send(c: &Connector, id: ConnId, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        match c.write(OWNER, id, &bytes[at..], false, false) {
            Ok(n) => at += n,
            Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
            Err(e) => panic!("the write was refused: {e:?}"),
        }
    }
}

/// Read until `want` bytes came, the stream ended or it failed: what came, or the failure.
async fn gather(c: &Connector, id: ConnId, want: usize) -> Result<Vec<u8>, ConnError> {
    let mut got = Vec::new();
    let mut buf = [0_u8; 64];
    tokio::time::timeout(Duration::from_secs(10), async {
        while got.len() < want {
            let piece = std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf)).await?;
            if piece.kind == PieceKind::Completion {
                break;
            }
            got.extend_from_slice(&buf[..piece.len]);
        }
        Ok(got)
    })
    .await
    .expect("the read settles")
}

/// RED: a raw stream to a far end that speaks TLS from the first byte does not round-trip in the
/// clear; upgraded at once, before any byte (ldaps), it does.
#[test]
fn a_raw_stream_to_a_tls_far_end_round_trips_only_once_upgraded_at_establish() {
    let (ca, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"").await;
        let c = raw_connector();
        declare(&c, "settings.ca", Some(&ca));

        let clear = open(&c, &far);
        send(&c, clear, b"hello").await;
        assert_ne!(
            gather(&c, clear, 5).await.as_deref(),
            Ok(&b"hello"[..]),
            "in the clear the far end's TLS never answers the bytes"
        );
        c.close(OWNER, clear).unwrap();

        let secured = open(&c, &far);
        assert_eq!(upgrade(&c, secured, None).await, Ok(()));
        send(&c, secured, b"hello").await;
        assert_eq!(gather(&c, secured, 5).await.as_deref(), Ok(&b"hello"[..]));
        c.close(OWNER, secured).unwrap();
    });
}

/// RED: StartTLS. The plugin's own negotiation crosses in the clear, the upgrade secures the same
/// stream from its next byte, the exchange then round-trips over TLS, and the stream's facts carry
/// the far end's certificate hash (SHA-256 of its certificate, the channel-binding input), absent
/// before the upgrade.
#[test]
fn starttls_upgrades_the_stream_mid_way_and_its_facts_carry_the_peer_cert_hash() {
    use sha2::Digest as _;
    let (ca, leaf, key) = private_ca();
    let expected: String = sha2::Sha256::digest(&leaf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"STARTTLS\n").await;
        let c = raw_connector();
        declare(&c, "settings.ca", Some(&ca));
        let id = open(&c, &far);
        send(&c, id, b"STARTTLS\n").await;
        assert_eq!(gather(&c, id, 3).await.as_deref(), Ok(&b"OK\n"[..]));
        assert_eq!(c.facts(OWNER, id).unwrap().peer_cert, None, "in the clear");
        assert_eq!(upgrade(&c, id, Some("settings.ca")).await, Ok(()));
        let facts = c.facts(OWNER, id).unwrap();
        assert_eq!(
            facts.peer_cert.map(|p| p.fingerprint).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(facts.sni.as_deref(), Some("localhost"));
        send(&c, id, b"hello").await;
        assert_eq!(gather(&c, id, 5).await.as_deref(), Ok(&b"hello"[..]));
        c.close(OWNER, id).unwrap();
    });
}

/// RED: the upgrade trusts the need's anchors. A far end whose certificate chains to a private CA
/// is refused over the public roots alone (a need with no `trust_from`) and accepted once the
/// need's `trust_from` names that CA; a trust reference other than the need's own is refused.
#[test]
fn an_upgrade_to_a_private_ca_is_refused_without_trust_from_and_accepted_with_it() {
    let (ca, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"").await;
        let c = raw_connector();
        declare(&c, "", None);
        let id = open(&c, &far);
        assert_eq!(upgrade(&c, id, None).await, Err(ConnError::Refused));
        c.close(OWNER, id).unwrap();

        declare(&c, "settings.ca", Some(&ca));
        let id = open(&c, &far);
        assert_eq!(
            upgrade(&c, id, Some("settings.other")).await,
            Err(ConnError::Refused),
            "only the need's own trust reference"
        );
        assert_eq!(upgrade(&c, id, None).await, Ok(()));
        send(&c, id, b"hello").await;
        assert_eq!(gather(&c, id, 5).await.as_deref(), Ok(&b"hello"[..]));
        c.close(OWNER, id).unwrap();
    });
}

/// A SELF-SIGNED far end (no CA anyone trusts): `localhost`'s certificate signed by its own key.
fn self_signed() -> (Vec<u8>, Vec<u8>) {
    let kp = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    (cert.der().to_vec(), kp.serialize_der())
}

/// RED (1.5.5's `rediss://…#insecure`): a self-signed far
/// end is REFUSED by a verifying upgrade; with the operator's verify-off opt-in on an
/// operator-infrastructure need it is ACCEPTED and carries bytes; the opt-in on a need of any other
/// class is REFUSED.
#[test]
fn verify_off_accepts_a_self_signed_far_end_for_operator_infrastructure_only() {
    let (leaf, key) = self_signed();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"").await;

        let c = raw_connector();
        declare_class(&c, "", None, EGRESS_OPERATOR_INFRASTRUCTURE);
        let verified = open(&c, &far);
        assert!(
            upgrade(&c, verified, None).await.is_err(),
            "a self-signed certificate fails verification"
        );
        let unverified = open(&c, &far);
        assert_eq!(upgrade_with(&c, unverified, None, true).await, Ok(()));
        send(&c, unverified, b"hello").await;
        assert_eq!(
            gather(&c, unverified, 5).await.as_deref(),
            Ok(&b"hello"[..])
        );

        let other = raw_connector();
        declare_class(&other, "", None, crate::DEFAULT_CLASS);
        let refused = open(&other, &far);
        assert_eq!(
            upgrade_with(&other, refused, None, true).await,
            Err(ConnError::Refused),
            "verify-off is an operator-infrastructure need's only"
        );
    });
}

/// What an on-path attacker appends to the far end's clear "begin TLS" answer.
const FORGED: &[u8] = b"FORGED-PLAINTEXT";

/// A far end that reads `STARTTLS\n` in the clear and answers `OK\n` with [`FORGED`] behind it: in
/// the same segment (`gap` = `None`), or as a segment of its own `gap` later; then the TLS
/// handshake, and an echo of the first five bytes. Answers its address.
async fn injecting_far_end(leaf: Vec<u8>, key: Vec<u8>, gap: Option<Duration>) -> String {
    let acceptor = acceptor(leaf, key);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut asked = [0_u8; 9];
        if s.read_exact(&mut asked).await.is_err() || &asked != b"STARTTLS\n" {
            return;
        }
        let wrote = match gap {
            None => s.write_all(&[&b"OK\n"[..], FORGED].concat()).await,
            Some(gap) => {
                let _ = s.write_all(b"OK\n").await;
                let _ = s.flush().await;
                tokio::time::sleep(gap).await;
                s.write_all(FORGED).await
            }
        };
        if wrote.is_err() || s.flush().await.is_err() {
            return;
        }
        if let Ok(mut s) = acceptor.accept(s).await {
            let mut buf = [0_u8; 5];
            if s.read_exact(&mut buf).await.is_ok() {
                let _ = s.write_all(&buf).await;
                let _ = s.flush().await;
            }
        }
    });
    far
}

/// Read exactly `want` bytes with a caller buffer no longer than what is still wanted (a plugin
/// reading a one-line answer), leaving whatever else the piece carried unread.
async fn read_short(c: &Connector, id: ConnId, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while got.len() < want {
            let mut buf = vec![0_u8; want - got.len()];
            let piece = std::future::poll_fn(|cx| c.poll_read(OWNER, id, cx, &mut buf))
                .await
                .expect("the clear answer reads");
            got.extend_from_slice(&buf[..piece.len]);
        }
    })
    .await
    .expect("the read settles");
    got
}

/// RED: the far end's clear `OK\n` arrives
/// with forged bytes behind it in ONE segment. The plugin reads its three-byte answer with a
/// three-byte buffer, so the forged bytes are a short read's rest when it asks for the upgrade.
/// The upgrade is refused and the stream fails: the forged bytes are never read, least of all as
/// the verified far end's.
#[test]
fn an_upgrade_over_a_short_reads_unread_rest_is_refused_and_the_stream_fails() {
    let (ca, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = injecting_far_end(leaf, key, None).await;
        let c = raw_connector();
        declare(&c, "settings.ca", Some(&ca));
        let id = open(&c, &far);
        send(&c, id, b"STARTTLS\n").await;
        assert_eq!(read_short(&c, id, 3).await, b"OK\n");
        assert_eq!(
            upgrade(&c, id, None).await,
            Err(ConnError::Refused),
            "clear bytes are still unread: no upgrade over them"
        );
        let after = gather(&c, id, FORGED.len()).await;
        assert!(
            after.is_err(),
            "the stream failed, closed; it answered {after:?}"
        );
    });
}

/// RED: the forged bytes come as a segment of their own after the clear
/// `OK\n`, and a readiness wait takes them off the socket onto the line before the plugin asks for
/// the upgrade. Parked and unread, they refuse the upgrade and fail the stream.
#[test]
fn an_upgrade_over_a_piece_parked_on_the_line_is_refused_and_the_stream_fails() {
    let (ca, leaf, key) = private_ca();
    worker().block_on(async move {
        let far = injecting_far_end(leaf, key, Some(Duration::from_millis(200))).await;
        let c = raw_connector();
        declare(&c, "settings.ca", Some(&ca));
        let id = open(&c, &far);
        send(&c, id, b"STARTTLS\n").await;
        assert_eq!(gather(&c, id, 3).await.as_deref(), Ok(&b"OK\n"[..]));
        tokio::time::timeout(Duration::from_secs(10), async {
            while Conns::wait(&c, OWNER, &[id], NO_TICKET) != Ok(0) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("the forged segment arrives");
        assert_eq!(
            upgrade(&c, id, None).await,
            Err(ConnError::Refused),
            "a parked clear piece is still unread: no upgrade over it"
        );
        let after = gather(&c, id, FORGED.len()).await;
        assert!(
            after.is_err(),
            "the stream failed, closed; it answered {after:?}"
        );
    });
}

/// RED: the channel-binding input is the far end's certificate hashed
/// as RFC 5929 section 4.1 `tls-server-end-point` says: with the certificate's signature hash. A
/// leaf signed `ecdsa-with-SHA384` binds with SHA-384 (a SCRAM-*-PLUS server computes the same).
#[test]
fn a_sha384_signed_far_end_binds_with_sha384() {
    use sha2::Digest as _;
    let (ca, leaf, key) = private_p384_ca();
    let expected: String = sha2::Sha384::digest(&leaf)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"STARTTLS\n").await;
        let c = raw_connector();
        declare(&c, "settings.ca", Some(&ca));
        let id = open(&c, &far);
        send(&c, id, b"STARTTLS\n").await;
        assert_eq!(gather(&c, id, 3).await.as_deref(), Ok(&b"OK\n"[..]));
        assert_eq!(upgrade(&c, id, Some("settings.ca")).await, Ok(()));
        assert_eq!(
            c.facts(OWNER, id)
                .unwrap()
                .peer_cert
                .map(|p| p.fingerprint)
                .as_deref(),
            Some(expected.as_str()),
            "the binding hashes with the certificate's signature hash"
        );
        c.close(OWNER, id).unwrap();
    });
}
