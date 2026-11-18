// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MID-STREAM SECURITY UPGRADE (ldaps and StartTLS work as they did in

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::crypto::testing::rcgen;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::registry::{Entry, Transports};
use crate::support::{worker, TestDoor};

const OWNER: InstanceId = InstanceId(1);

/// A private CA and a `localhost` leaf it signed: (ca_pem, leaf_der, key_der).
fn private_ca() -> (String, Vec<u8>, Vec<u8>) {
    use busbar_contract::crypto::testing::rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
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
    use busbar_contract::crypto::testing::rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
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
    let server = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
        })
        .unwrap(),
    );
    tokio_rustls::TlsAcceptor::from(Arc::new(server))
}

/// A far end on loopback that, per connection, reads `starttls` in the clear and answers `OK\n`
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
fn raw_connector() -> Connector {
    let view = Transports::new(vec![Entry {
        door: Arc::new(TestDoor::identity("bytes")),
        alpn: Arc::default(),
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
fn declare(c: &Connector, trust_from: &str, pem: Option<&str>) {
    declare_class(c, trust_from, pem, crate::DEFAULT_CLASS);
}

/// [`declare`] under egress class `class`.
fn declare_class(c: &Connector, trust_from: &str, pem: Option<&str>, class: u32) {
    declare_class_timeout(c, trust_from, pem, class, 0);
}

fn declare_class_timeout(
    c: &Connector,
    trust_from: &str,
    pem: Option<&str>,
    class: u32,
    timeout_ms: u64,
) {
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
        timeout_ms,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
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
#[test]
fn starttls_upgrades_the_stream_mid_way_and_its_facts_carry_the_peer_cert_hash() {
    let (ca, leaf, key) = private_ca();
    let expected: String = busbar_contract::crypto::sha256(&leaf)
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

/// CLEAN-1.6: the retired verify-off flag cannot bypass certificate verification in any class.
#[test]
fn verify_off_refuses_even_operator_infrastructure() {
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
        assert_eq!(
            upgrade_with(&c, unverified, None, true).await,
            Err(ConnError::Refused)
        );

        let other = raw_connector();
        declare_class(&other, "", None, crate::DEFAULT_CLASS);
        let refused = open(&other, &far);
        assert_eq!(
            upgrade_with(&other, refused, None, true).await,
            Err(ConnError::Refused),
            "verify-off is refused for every need"
        );
    });
}

/// What an on-path attacker appends to the far end's clear "begin TLS" answer.
const FORGED: &[u8] = b"FORGED-PLAINTEXT";

/// A far end that reads `STARTTLS\n` in the clear and answers `OK\n` with [`FORGED`] behind it: in
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
#[test]
fn a_sha384_signed_far_end_binds_with_sha384() {
    let (ca, leaf, key) = private_p384_ca();
    let expected: String = busbar_contract::crypto::sha384(&leaf)
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

/// A mid-stream handshake uses the same selected bound as the raw dial, including
/// a per-open override. A peer accepting TCP without answering TLS must time out.
#[test]
fn security_upgrade_inherits_the_declared_or_per_open_timeout() {
    worker().block_on(async {
        for (explicit, request) in [(0, 0), (100, 0), (0, 100)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let far = listener.local_addr().unwrap().to_string();
            let c = raw_connector();
            declare_class_timeout(
                &c,
                "",
                None,
                crate::DEFAULT_CLASS,
                if explicit == 0 && request == 0 {
                    100
                } else {
                    30_000
                },
            );
            let id = c
                .open_request(
                    OWNER,
                    NeedId(0),
                    &OpenDesc {
                        target: &far,
                        timeout_ms: request,
                        ..Default::default()
                    },
                    false,
                    explicit,
                )
                .unwrap();
            let peer = listener.accept().await.unwrap().0;
            loop {
                match c.landed(OWNER, id, NO_TICKET) {
                    Ok(()) => break,
                    Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
                    other => panic!("the raw dial must land before its handshake: {other:?}"),
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(2), upgrade(&c, id, None))
                .await
                .expect("the selected 100ms bound, not the host's 10s default");
            assert_eq!(result, Err(ConnError::Timeout));
            c.close(OWNER, id).unwrap();
            drop(peer);
        }
    });
}

/// A declared 30-second handshake must also work past the old 10-second cap.
#[test]
fn a_declared_security_upgrade_can_outlive_the_default_ten_seconds() {
    let (ca, leaf, key) = private_ca();
    worker().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(11)).await;
            acceptor(leaf, key).accept(socket).await
        });
        let c = raw_connector();
        declare_class_timeout(&c, "settings.ca", Some(&ca), crate::DEFAULT_CLASS, 30_000);
        let id = open(&c, &far);
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match c.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET) {
                    Err(ConnError::Pending) => tokio::time::sleep(Duration::from_millis(2)).await,
                    answer => break answer,
                }
            }
        })
        .await
        .expect("the delayed handshake finishes within its declared bound");
        assert_eq!(result, Ok(()));
        send(&c, id, b"x").await;
        let peer = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("the client flushes its final handshake flight")
            .unwrap()
            .expect("the server also completed TLS");
        c.close(OWNER, id).unwrap();
        drop(peer);
    });
}

/// BUSBAR-6014 (R2.2.5): the offered name (`UpgradeIn::offered_name`, the SNI and the name verified)
/// must be the dialled host when the dial names a host (compared as the guard maps names: case,
/// a trailing dot, IDNA); a dial to an IP literal may offer any name (libpq `hostaddr` + `host`).
#[test]
fn an_offered_name_must_be_the_dialled_host_unless_the_dial_is_an_ip_literal() {
    for (target, offered) in [
        ("db.internal:5432", "db.internal"),
        ("DB.Internal.:5432", "db.internal"),
        ("db.internal:5432", "DB.INTERNAL."),
        ("bücher.example:443", "xn--bcher-kva.example"),
        ("127.0.0.1:5432", "db.internal"),
        ("[::1]:5432", "db.internal"),
        ("\x310.0.0.5:6379", "cache.internal"),
    ] {
        assert!(
            crate::offered_name_admitted(target, offered),
            "{target} offering {offered}"
        );
    }
    for (target, offered) in [
        ("prod-db.internal:5432", "lab.internal"),
        ("db.internal:5432", "db.internal.evil.test"),
        ("db.internal:5432", ""),
        ("db.internal:5432", "%zz"),
    ] {
        assert!(
            !crate::offered_name_admitted(target, offered),
            "{target} offering {offered}"
        );
    }
}

/// BUSBAR-6015: the retired flag is refused and reported once per instance.
#[test]
fn a_refused_verify_off_is_flagged_once_per_instance() {
    let (leaf, key) = self_signed();
    worker().block_on(async move {
        let far = far_end(leaf, key, b"").await;
        let c = raw_connector();
        declare_class(&c, "", None, EGRESS_OPERATOR_INFRASTRUCTURE);
        assert!(c.abi_flags().is_empty());
        for _ in 0..2 {
            let id = open(&c, &far);
            assert_eq!(
                upgrade_with(&c, id, None, true).await,
                Err(ConnError::Refused)
            );
        }
        assert_eq!(c.abi_flags(), vec![(OWNER, 6015)]);
    });
}

/// #245, DES-245 r3 C8 and C8b: a far end that resets (C8) or closes (C8b) the stream during the
/// in-Open upgrade's handshake failed the transport, so the cause stage is `CAUSE_CONNECT`, not
/// `CAUSE_SECURITY`.
#[test]
fn an_upgrade_handshake_the_far_end_resets_or_closes_is_a_connect_failure() {
    use busbar_contract::abi::host::conn::connector::CAUSE_CONNECT;
    worker().block_on(async move {
        for reset in [true, false] {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let far = l.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let (mut s, _) = l.accept().await.unwrap();
                let mut header = [0_u8; 5];
                let _ = s.read_exact(&mut header).await;
                if reset {
                    s.set_zero_linger().unwrap();
                }
                drop(s);
            });
            let c = raw_connector();
            declare(&c, "", None);
            let id = open(&c, &far);
            assert!(upgrade(&c, id, None).await.is_err(), "reset {reset}");
            let cause = c.cause(OWNER, id).expect("a cause");
            assert_eq!(cause.stage, CAUSE_CONNECT, "reset {reset}: {}", cause.text);
        }
    });
}
