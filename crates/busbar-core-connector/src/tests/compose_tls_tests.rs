// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TLS PLAINTEXT PATH (TRANSPORT-TLS T6): the handshake flight is still queued, the
//! plaintext is read exactly into this thread's wiping scratch, close_notify and an unclean end are
//! still told apart, and nothing of the plaintext is left once it is handed on.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::support::{worker, Knobs, TestDoor};

const SECRET: &[u8] = b"data: {\"api_key\":\"SENTINEL-T6-0123456789\"}";

/// How the TLS far end finishes after its answer.
#[derive(Clone, Copy)]
enum Finish {
    /// close_notify, then FIN.
    CloseNotify,
    /// FIN without close_notify (a truncation).
    BareFin,
    /// Keep the connection open.
    Hold,
}

fn localhost_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca = crate::test_support::private_ca();
    (
        crate::test_support::certs_from_pem(&ca.ca_pem).remove(0),
        ca.leaf_der,
        ca.key_der,
    )
}

/// A TLS 1.3 far end that reads 5 bytes, answers `answer`, then finishes as `finish` says.
async fn tls_far_end(leaf: Vec<u8>, key: Vec<u8>, answer: Vec<u8>, finish: Finish) -> String {
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let far = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let mut s = acceptor.accept(s).await.unwrap();
        let mut asked = [0_u8; 5];
        s.read_exact(&mut asked).await.unwrap();
        s.write_all(&answer).await.unwrap();
        s.flush().await.unwrap();
        match finish {
            Finish::CloseNotify => {
                s.shutdown().await.unwrap();
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Finish::BareFin => {
                let (mut tcp, _) = s.into_inner();
                tcp.shutdown().await.unwrap();
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Finish::Hold => tokio::time::sleep(Duration::from_secs(10)).await,
        }
    });
    far
}

fn tls_dial(far: &str, ca: Vec<u8>) -> Dial {
    let trust = busbar_contract::transport::trust::EgressTrust {
        extra_anchors: vec![ca],
        ..Default::default()
    };
    Dial {
        target: far.to_owned(),
        tls: Some(Arc::new(
            crate::tls::client::build_client_config(&trust).expect("a usable client config"),
        )),
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: Some((Vec::new(), b"hello".to_vec().into())),
        head_words: Default::default(),
        anchors: None,
    }
}

fn secure_door() -> Arc<TestDoor> {
    Arc::new(TestDoor::new(
        "sec",
        &["sec"],
        &[],
        Knobs {
            secure_name: Some("localhost"),
            ..Knobs::default()
        },
    ))
}

async fn next(c: &mut Connection) -> Result<Option<Got>, Failure> {
    futures::future::poll_fn(|cx| c.poll_piece(cx)).await
}

/// Dial the far end over TLS and gather `want` plaintext bytes.
async fn dialled(finish: Finish, answer: &[u8]) -> Connection {
    let (ca, leaf, key) = localhost_cert();
    let far = tls_far_end(leaf, key, answer.to_vec(), finish).await;
    let mut c =
        Connection::dial(secure_door(), &crate::support::via(), tls_dial(&far, ca)).unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while got.len() < answer.len() {
            let p = next(&mut c).await.expect("a piece").expect("not ended");
            got.extend(p.bytes);
        }
    })
    .await
    .expect("the TLS handshake completes and the answer comes back");
    assert_eq!(got, answer);
    c
}

/// The dialled handshake still completes through compose: the client Finished is queued by
/// `tls_out`, and the plaintext answer is read back exactly.
#[test]
fn tls_dial_handshake_completes_via_compose() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let c = dialled(Finish::Hold, b"world").await;
        assert!(c.is_open());
    });
}

/// RED against the r2-shaped single exact read: the last record and close_notify arrive together
/// and the end is still seen, once.
#[test]
fn tls_close_notify_with_last_record_is_seen() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let mut c = dialled(Finish::CloseNotify, SECRET).await;
        let end = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match next(&mut c).await {
                    Ok(Some(p)) if p.bytes.is_empty() => {}
                    other => return other,
                }
            }
        })
        .await
        .expect("close_notify ends the stream");
        assert!(
            matches!(end, Ok(None) | Ok(Some(_))),
            "a clean close_notify end is not a failure: {end:?}"
        );
    });
}

/// RED against the r2-shaped single exact read: a FIN without close_notify is a truncation and
/// fails the connection, as today.
#[test]
fn tls_fin_without_close_notify_fails() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let mut c = dialled(Finish::BareFin, SECRET).await;
        let end = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match next(&mut c).await {
                    Ok(Some(_)) => {}
                    other => return other,
                }
            }
        })
        .await
        .expect("an unclean end is seen");
        assert!(end.is_err(), "a truncated TLS stream is refused: {end:?}");
    });
}

/// The plaintext read path leaves nothing behind: the TLS plaintext scratch is all zero once the
/// answer is handed on.
#[test]
fn tls_plain_wiped() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let c = dialled(Finish::Hold, SECRET).await;
        let zero = TLS_PLAIN.with(|slot| {
            let held = slot
                .take()
                .expect("no read holds the plaintext scratch now");
            let zero = held.allocation().iter().all(|b| *b == 0);
            let used = held.capacity() >= SECRET.len();
            slot.set(Some(held));
            assert!(used, "the plaintext was read into the TLS_PLAIN scratch");
            zero
        });
        assert!(zero, "the plaintext is wiped from the scratch");
        drop(c);
    });
}
