// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A composed connection against a REAL far end on a real socket: bytes in and out through the
//! framer, TLS with the protocol offer, the endpoint check before any dial, a silent far end held to
//! the framer's deadline and the open held to its own, and no thread per connection.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::support::{worker, Knobs, TestDoor};

/// An echo far end on the worker's own runtime: every connection, every byte back.
async fn echo() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0_u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A far end that accepts and never says a word.
async fn silent() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    addr
}

fn dial(target: &str) -> Dial {
    Dial {
        target: target.to_owned(),
        tls: None,
        alpn: Vec::new(),
        open_timeout: Duration::from_secs(5),
        opening: None,
        head_words: Default::default(),
    }
}

async fn next(c: &mut Connection) -> Result<Option<Got>, Failure> {
    futures::future::poll_fn(|cx| c.poll_piece(cx)).await
}

/// Read pieces until `want` bytes have come back.
async fn gather(c: &mut Connection, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want {
        let p = next(c).await.expect("a piece").expect("not ended");
        assert_eq!(p.stream, 0);
        got.extend(p.bytes);
    }
    got
}

#[test]
fn bytes_go_through_the_framer_both_ways_byte_exact() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut d = dial(&far);
        d.opening = Some((Vec::new(), b"hello ".to_vec()));
        let mut c = Connection::dial(door.clone(), d).expect("dials");
        let waker = std::task::Waker::noop();
        let sent: Vec<u8> = (0..=255_u8).cycle().take(100_000).collect();
        c.write(
            &sent,
            true,
            false,
            &mut std::task::Context::from_waker(waker),
        )
        .unwrap();
        let got = gather(&mut c, 6 + sent.len()).await;
        assert_eq!(&got[..6], b"hello ", "the opening message goes first");
        assert_eq!(
            &got[6..],
            &sent[..],
            "every byte, in order, through the framer"
        );
        assert!(door.count("ingest") >= 1 && door.count("emit") >= 2);
        c.close();
        assert_eq!(door.count("finish"), 1);
    });
}

#[test]
fn the_far_ends_close_ends_the_connection() {
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"bye").await.unwrap();
        });
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, dial(&far)).unwrap();
        assert_eq!(gather(&mut c, 3).await, b"bye");
        assert_eq!(
            next(&mut c).await,
            Ok(None),
            "the end, once the bytes are taken"
        );
    });
}

/// RED: the cloud metadata refusal still fires before any dial — on the target, and on the
/// authority the entry's `locate` names for it.
#[test]
fn a_metadata_host_is_refused_before_any_socket_exists() {
    worker().block_on(async {
        for target in [
            "169.254.169.254:80",
            "[::ffff:169.254.169.254]:80",
            "metadata.google.internal:80",
            "0xa9fea9fe:80",
        ] {
            let door = Arc::new(TestDoor::identity("bytes"));
            let r = Connection::dial(door.clone(), dial(target));
            assert!(matches!(r, Err(Failure::Refused(_))), "{target}");
            assert_eq!(
                door.count("locate"),
                0,
                "{target}: refused before the entry is asked"
            );
        }
        let door = Arc::new(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                authority: Some("169.254.169.254:80"),
                ..Knobs::default()
            },
        ));
        let r = Connection::dial(door.clone(), dial("127.0.0.1:9"));
        assert!(matches!(r, Err(Failure::Refused(_))));
        assert_eq!(door.count("begin"), 0, "no framing on a refused authority");
    });
}

/// RED: a far end that accepts and then says nothing is held to the deadline the framer states:
/// the connector calls `timer` at it, and the connection fails there — not before, not never.
#[test]
fn a_silent_far_end_is_held_to_the_framers_deadline() {
    worker().block_on(async {
        let far = silent().await;
        let door = Arc::new(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                silence: Some(Duration::from_millis(300)),
                ..Knobs::default()
            },
        ));
        let start = Instant::now();
        let mut c = Connection::dial(door.clone(), dial(&far)).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(10), next(&mut c))
            .await
            .expect("the deadline fires, the connection does not hang");
        assert_eq!(r, Err(Failure::Timeout));
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(300),
            "not before the deadline: {took:?}"
        );
        assert!(took < Duration::from_secs(5), "at the deadline: {took:?}");
        assert!(
            door.count("timer") >= 1,
            "the deadline reached the framer as `timer`"
        );
    });
}

/// The open is bounded on its own: a far end that never answers the TLS handshake times out.
#[test]
fn an_open_that_never_completes_is_held_to_its_timeout() {
    crate::tls::install_crypto_provider();
    worker().block_on(async {
        let far = silent().await;
        let door = Arc::new(TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                ..Knobs::default()
            },
        ));
        let mut d = dial(&far);
        d.tls = Some(Arc::new(
            crate::tls::client::build_client_config(&Default::default())
                .expect("the default config"),
        ));
        d.open_timeout = Duration::from_millis(300);
        let start = Instant::now();
        let mut c = Connection::dial(door.clone(), d).unwrap();
        assert_eq!(next(&mut c).await, Err(Failure::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(door.count("begin"), 0, "no framing before the handshake");
    });
}

/// A self-signed CA and a leaf for `localhost`: (ca_der, leaf_der, key_der).
fn localhost_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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
    (ca.der().to_vec(), leaf.der().to_vec(), kp.serialize_der())
}

/// TLS is the connector's, with the protocol offer the registration states: the framer is told
/// what the handshake agreed, and the bytes cross encrypted.
#[test]
fn tls_and_the_protocol_offer_are_the_connectors() {
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut s = acceptor.accept(s).await.unwrap();
            let mut buf = [0_u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        });
        let door = Arc::new(TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                ..Knobs::default()
            },
        ));
        let trust = busbar_contract::transport::trust::EgressTrust {
            extra_anchors: vec![ca],
            ..Default::default()
        };
        let mut d = dial(&far);
        d.tls = Some(Arc::new(
            crate::tls::client::build_client_config(&trust).expect("a usable client config"),
        ));
        d.alpn = vec![b"h2".to_vec()];
        d.opening = Some((Vec::new(), b"hello".to_vec()));
        let mut c = Connection::dial(door, d).unwrap();
        assert_eq!(gather(&mut c, 5).await, b"hello");
        assert_eq!(c.established().agreed_protocol.as_deref(), Some(&b"h2"[..]));
        assert_eq!(c.established().offered_name.as_deref(), Some("localhost"));
    });
}

/// THE OFFER IS THE FRAMER'S (THE DESIGN, connections): the protocols the handshake offers are
/// what the entry's `locate` answered, most preferred first, and the registration's offer stands
/// only for an entry that answers none. A far end agreeing `h2` or `http/1.1` agrees what the
/// framer offered, whatever the registration says.
#[test]
fn the_handshake_offers_what_the_framer_located() {
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        // (the framer's offer, the registration's, what a far end serving h2 and http/1.1 agrees)
        type Case = (Option<&'static [u8]>, Vec<Vec<u8>>, Option<&'static [u8]>);
        let cases: [Case; 4] = [
            (Some(b"\x02h2\x08http/1.1"), Vec::new(), Some(b"h2")),
            (
                Some(b"\x08http/1.1"),
                vec![b"h2".to_vec()],
                Some(b"http/1.1"),
            ),
            (Some(b"\x02h2"), Vec::new(), Some(b"h2")),
            (None, vec![b"http/1.1".to_vec()], Some(b"http/1.1")),
        ];
        for (offer, registered, agreed) in cases {
            let mut server = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf.clone().into()],
                    rustls_pki_types::PrivateKeyDer::try_from(key.clone()).unwrap(),
                )
                .unwrap();
            server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let far = l.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                let (s, _) = l.accept().await.unwrap();
                let mut s = acceptor.accept(s).await.unwrap();
                let mut buf = [0_u8; 5];
                s.read_exact(&mut buf).await.unwrap();
                s.write_all(&buf).await.unwrap();
                s.flush().await.unwrap();
            });
            let door = Arc::new(TestDoor::new(
                "sec",
                &["sec"],
                &[],
                Knobs {
                    secure_name: Some("localhost"),
                    offer,
                    ..Knobs::default()
                },
            ));
            let trust = busbar_contract::transport::trust::EgressTrust {
                extra_anchors: vec![ca.clone()],
                ..Default::default()
            };
            let mut d = dial(&far);
            d.tls = Some(Arc::new(
                crate::tls::client::build_client_config(&trust).expect("a usable client config"),
            ));
            d.alpn = registered;
            d.opening = Some((Vec::new(), b"hello".to_vec()));
            let mut c = Connection::dial(door, d).unwrap();
            assert_eq!(gather(&mut c, 5).await, b"hello");
            assert_eq!(
                c.established().agreed_protocol.as_deref(),
                agreed,
                "the framer offered {offer:?}"
            );
        }
    });
}

/// A framer's protocol offer that is not a protocol list is refused at `locate`, before any dial.
#[test]
fn a_malformed_protocol_offer_refuses_the_dial() {
    worker().block_on(async {
        let door = Arc::new(TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                offer: Some(b"\x05h2"),
                ..Knobs::default()
            },
        ));
        let got = Connection::dial(door, dial("127.0.0.1:9"));
        assert!(
            matches!(&got, Err(Failure::Refused(why)) if why.contains("protocol offer")),
            "{got:?}"
        );
    });
}

/// RED: a far end that never reads cannot grow the host's memory. Writes are taken while the
/// connection's buffer has room; once the socket stops taking bytes the buffer fills to
/// [`WRITE_BUFFER_BYTES`] and a write is taken not at all (`Ok(0)`), and stays so.
#[test]
fn a_far_end_that_never_reads_fills_the_buffer_and_writes_are_refused_room() {
    worker().block_on(async {
        let far = silent().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, dial(&far)).expect("dials");
        let waker = std::task::Waker::noop();
        let chunk = vec![7_u8; 64 * 1024];
        let mut full = false;
        for _ in 0..2000 {
            let n = c
                .write(
                    &chunk,
                    false,
                    false,
                    &mut std::task::Context::from_waker(waker),
                )
                .expect("the connection lives");
            assert!(
                c.buffered() <= WRITE_BUFFER_BYTES,
                "the buffer stays under its cap"
            );
            if n == 0 {
                full = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            full,
            "a far end that never reads leaves no room, in bounded writes"
        );
        assert!(
            matches!(
                c.write(
                    &chunk,
                    false,
                    false,
                    &mut std::task::Context::from_waker(waker)
                ),
                Ok(0)
            ),
            "and a full buffer keeps refusing room"
        );
        c.close();
    });
}
