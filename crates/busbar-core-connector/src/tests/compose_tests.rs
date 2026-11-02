// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A composed connection against a REAL far end on a real socket: bytes in and out through the

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::support::{worker, Knobs, TestDoor};

#[path = "compose_sensitive_tests.rs"]
#[allow(unsafe_code)]
mod sensitive_tests;

#[path = "compose_close_deadline_tests.rs"]
mod close_deadline_tests;

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
        anchors: None,
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
        d.opening = Some((Vec::new(), b"hello ".to_vec().into()));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).expect("dials");
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
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).unwrap();
        assert_eq!(gather(&mut c, 3).await, b"bye");
        assert_eq!(
            next(&mut c).await,
            Ok(None),
            "the end, once the bytes are taken"
        );
    });
}

/// RED: the cloud metadata refusal still fires before any dial — on the target, and on the
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
            let r = Connection::dial(door.clone(), &crate::support::via(), dial(target));
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
        let r = Connection::dial(door.clone(), &crate::support::via(), dial("127.0.0.1:9"));
        assert!(matches!(r, Err(Failure::Refused(_))));
        assert_eq!(door.count("begin"), 0, "no framing on a refused authority");
    });
}

/// RED: a far end that accepts and then says nothing is held to the deadline the framer states:
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
        let mut c = Connection::dial(door.clone(), &crate::support::via(), dial(&far)).unwrap();
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
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
        assert_eq!(next(&mut c).await, Err(Failure::Timeout));
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(door.count("begin"), 0, "no framing before the handshake");
    });
}

/// A self-signed CA and a leaf for `localhost`: (ca_der, leaf_der, key_der).
fn localhost_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca = crate::test_support::private_ca();
    (
        crate::test_support::certs_from_pem(&ca.ca_pem).remove(0),
        ca.leaf_der,
        ca.key_der,
    )
}

/// TLS is the connector's, with the protocol offer the registration states: the framer is told
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
        d.opening = Some((Vec::new(), b"hello".to_vec().into()));
        let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
        assert_eq!(gather(&mut c, 5).await, b"hello");
        assert_eq!(c.established().agreed_protocol.as_deref(), Some(&b"h2"[..]));
        assert_eq!(c.established().offered_name.as_deref(), Some("localhost"));
    });
}

/// THE OFFER IS THE FRAMER'S (THE DESIGN, connections): the protocols the handshake offers are
#[test]
fn the_handshake_offers_what_the_framer_located() {
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
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
            d.opening = Some((Vec::new(), b"hello".to_vec().into()));
            let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
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
        let got = Connection::dial(door, &crate::support::via(), dial("127.0.0.1:9"));
        assert!(
            matches!(&got, Err(Failure::Refused(why)) if why.contains("protocol offer")),
            "{got:?}"
        );
    });
}

/// RED: a far end that never reads cannot grow the host's memory. Writes are taken while the
#[test]
fn a_far_end_that_never_reads_fills_the_buffer_and_writes_are_refused_room() {
    worker().block_on(async {
        let far = silent().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).expect("dials");
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

/// An EMPTY message, binary or text, is relayed as a message, its text bit kept; the stream ends
#[test]
fn empty_messages_relay_and_the_stream_ends_only_on_its_flag() {
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"btxe").await.unwrap();
            let mut hold = [0_u8; 1];
            let _ = s.read(&mut hold).await;
        });
        let door = Arc::new(TestDoor::new(
            "messages",
            &["messages"],
            &[],
            Knobs {
                messages: Some(0),
                ..Knobs::default()
            },
        ));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).unwrap();
        let mut got = Vec::new();
        while got.len() < 4 {
            got.push(next(&mut c).await.expect("a piece").expect("not ended"));
        }
        let seen: Vec<_> = got
            .iter()
            .map(|g| (g.bytes.as_slice(), g.text, g.end_of_frame, g.ends_stream()))
            .collect();
        assert_eq!(
            seen,
            [
                (&b""[..], false, true, false),
                (&b""[..], true, true, false),
                (&b"x"[..], false, true, false),
                (&b""[..], false, true, true),
            ],
            "an empty binary and an empty text message are messages; the end is the flag"
        );
    });
}

/// RED (Autobahn 3.2, 3.3, 4.1.3, 4.1.4, 4.2.3, 4.2.4, 5.15 NON-STRICT): the far side's frames
#[test]
fn a_message_handed_up_with_the_frames_end_is_still_answered() {
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let heard = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(b"hello").await.unwrap();
            s.shutdown().await.unwrap();
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got)).await;
            got
        });
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).unwrap();
        assert_eq!(gather(&mut c, 5).await, b"hello");
        assert_eq!(next(&mut c).await, Ok(None), "the far side's frames ended");
        let waker = std::task::Waker::noop();
        let took = c.emit(
            0,
            b"answer",
            true,
            false,
            &mut std::task::Context::from_waker(waker),
        );
        assert_eq!(
            took,
            Ok(6),
            "the answer to the last message is still written"
        );
        c.close();
        assert_eq!(heard.await.unwrap(), b"answer", "and the far side hears it");
    });
}

/// WHY A CONNECTION FAILED, named by stage and the underlying error's own words: a closed port
#[test]
fn a_failed_connection_names_its_stage_and_the_underlying_error() {
    use busbar_contract::abi::host::conn::connector::{
        CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_SECURITY,
    };
    crate::tls::install_crypto_provider();
    let (_, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let here = std::net::TcpStream::connect(closed)
            .expect_err("nothing listens")
            .to_string();
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c =
            Connection::dial(door, &crate::support::via(), dial(&closed.to_string())).unwrap();
        assert!(matches!(next(&mut c).await, Err(Failure::Refused(_))));
        assert_eq!(
            c.cause(),
            Some(&ConnCause {
                stage: CAUSE_CONNECT,
                text: here
            })
        );

        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let _ = acceptor.accept(s).await;
            }
        });
        let secure = |far: &str| {
            let mut d = dial(far);
            d.tls = Some(Arc::new(
                crate::tls::client::build_client_config(&Default::default())
                    .expect("the default config"),
            ));
            d
        };
        let door = Arc::new(TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                ..Knobs::default()
            },
        ));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), secure(&far)).unwrap();
        assert!(matches!(next(&mut c).await, Err(Failure::Refused(_))));
        let unknown = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(
            c.cause(),
            Some(&ConnCause {
                stage: CAUSE_SECURITY,
                text: unknown.to_string()
            })
        );

        let mut d = secure(&silent().await);
        d.open_timeout = Duration::from_millis(200);
        let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
        assert_eq!(next(&mut c).await, Err(Failure::Timeout));
        assert_eq!(
            c.cause(),
            Some(&ConnCause {
                stage: CAUSE_DEADLINE,
                text: String::new()
            })
        );
    });
}

/// The connection's own layer, STARTTLS response injection: a raw
#[test]
fn an_upgrade_over_a_piece_still_in_the_inbox_is_refused_and_the_connection_fails() {
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let _ = s.write_all(b"OK\nFORGED-PLAINTEXT").await;
            let mut sink = [0_u8; 1024];
            while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
        });
        let mut c = Planned::carried(crate::support::via(), dial(&far))
            .and_then(|p| p.dial_at(far.parse().unwrap()))
            .expect("dials");
        tokio::time::timeout(
            Duration::from_secs(10),
            futures::future::poll_fn(|cx| c.poll_ready(cx)),
        )
        .await
        .expect("the far end's clear answer arrives");
        crate::tls::install_crypto_provider();
        let config = Arc::new(
            crate::tls::client::build_client_config(&Default::default())
                .expect("the default config"),
        );
        let answer = futures::future::poll_fn(|cx| {
            c.upgrade_secure(&config, "localhost", Duration::from_secs(5), cx)
        })
        .await;
        assert!(
            matches!(answer, Err(Failure::Refused(_))),
            "a clear piece is still unread: no upgrade over it; it answered {answer:?}"
        );
        assert!(
            next(&mut c).await.is_err(),
            "the connection failed, closed: the clear piece is never read"
        );
    });
}

/// A far end that sends far more than its holder reads (64 MiB, the
#[test]
fn a_holder_that_does_not_read_holds_the_far_end_back() {
    const SENT: usize = 64 * 1024 * 1024;
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&written);
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let chunk = vec![7_u8; 64 * 1024];
            for _ in 0..SENT / chunk.len() {
                if s.write_all(&chunk).await.is_err() {
                    return;
                }
                counted.fetch_add(chunk.len(), std::sync::atomic::Ordering::SeqCst);
            }
        });
        let conn = Planned::carried(crate::support::via(), dial(&far))
            .and_then(|p| p.dial_at(far.parse().unwrap()))
            .expect("dials");
        let line = crate::line::Line::new(conn);
        let waker = std::task::Waker::noop();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            let _ = line.poll_ready(EXCHANGE_STREAM, &mut std::task::Context::from_waker(waker));
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let written = written.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            written < SENT / 2,
            "the far end wrote {written} of {SENT} bytes to a holder that never read: the line took \
             them all"
        );
    });
}

/// RED (THE DESIGN §5 "Writes are back-pressured (a full buffer answers not-ready)"; resource
#[test]
fn a_far_end_that_never_reads_is_not_read_past_the_answers_it_is_owed() {
    const SENT: usize = 64 * 1024 * 1024;
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let chunk = vec![7_u8; 64 * 1024];
            for _ in 0..SENT / chunk.len() {
                if s.write_all(&chunk).await.is_err() {
                    return;
                }
            }

            let _keep = s;
            std::future::pending::<()>().await;
        });
        let door = Arc::new(TestDoor::new(
            "echo",
            &["echo"],
            &[],
            Knobs {
                echo: true,
                ..Knobs::default()
            },
        ));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).expect("dials");
        let waker = std::task::Waker::noop();
        let started = Instant::now();
        let mut most = 0;
        while started.elapsed() < Duration::from_secs(3) {
            while let std::task::Poll::Ready(Ok(Some(_))) =
                c.poll_piece(&mut std::task::Context::from_waker(waker))
            {}
            most = most.max(c.out.len());
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            most <= 4 * WRITE_BUFFER_BYTES,
            "{most} bytes owed to a far end that never reads"
        );
    });
}

/// RED (A PENDING ANSWER PARKS ONLY ITS OWN STREAM, on one connection): two streams on one
#[test]
fn one_stream_pending_auth_holds_only_that_stream_on_the_connection() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(crate::support::PendingDoor::new(
            TestDoor::identity("bytes"),
            EXCHANGE_STREAM,
        ));
        let mut d = dial(&far);
        d.opening = Some((Vec::new(), b"first ".to_vec().into()));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).expect("dials");
        let waker = std::task::Waker::noop();
        c.open_exchange(
            3,
            Some((Vec::new(), b"second".to_vec().into())),
            HeadWords::default(),
            &mut std::task::Context::from_waker(waker),
        )
        .unwrap();
        assert_eq!(
            gather(&mut c, 6).await,
            b"second",
            "the second stream's request completes while the first waits on its auth"
        );
        assert_eq!(door.host.calls(), 1, "the first stream's auth is running");
        door.host.complete(1);
        assert_eq!(
            gather(&mut c, 6).await,
            b"first ",
            "the first stream goes once its auth answered"
        );
        assert_eq!(
            door.host.calls(),
            1,
            "exactly one auth call across the not-ready"
        );
        assert_eq!(
            door.emitted.lock().unwrap().as_slice(),
            &[(EXCHANGE_STREAM, 6, 1), (3, 6, 1)],
            "each head emit states its opening body's length"
        );
    });
}

#[test]
fn a_parked_streams_empty_write_backpressures_only_that_stream() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(crate::support::PendingDoor::new(
            TestDoor::identity("bytes"),
            EXCHANGE_STREAM,
        ));
        let mut d = dial(&far);
        d.opening = Some((Vec::new(), b"held".to_vec().into()));
        let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        c.open_exchange(
            3,
            Some((Vec::new(), b"second".to_vec().into())),
            HeadWords::default(),
            &mut cx,
        )
        .unwrap();
        assert_eq!(gather(&mut c, 6).await, b"second");
        assert_eq!(c.emit(EXCHANGE_STREAM, b"", true, true, &mut cx), Ok(0));
        assert_eq!(
            c.emit(EXCHANGE_STREAM, b"", false, false, &mut cx)
                .map_err(|f| crate::map(&f)),
            Err(busbar_contract::conn::ConnError::Pending)
        );
        assert_eq!(c.emit(3, b"next", true, false, &mut cx), Ok(4));
        assert_eq!(gather(&mut c, 4).await, b"next");
        assert!(c.live(), "backpressure does not fail the connection");
        assert!(c.cause().is_none());
    });
}

/// RED (THE DESIGN §5: TLS is the connector's, "today's code moved byte-identically"; a write is
#[test]
fn one_write_larger_than_the_tls_send_buffer_crosses_whole() {
    const SENT: usize = 200_000;
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut s = acceptor.accept(s).await.unwrap();
            let mut buf = vec![0_u8; 16 * 1024];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 || s.write_all(&buf[..n]).await.is_err() || s.flush().await.is_err() {
                    break;
                }
            }
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
        d.opening = Some((Vec::new(), b"hello".to_vec().into()));
        let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
        assert_eq!(gather(&mut c, 5).await, b"hello", "the handshake completed");
        let sent: Vec<u8> = (0..=255_u8).cycle().take(SENT).collect();
        let waker = std::task::Waker::noop();
        let taken = c
            .write(
                &sent,
                true,
                false,
                &mut std::task::Context::from_waker(waker),
            )
            .expect("the write is taken, not failed");
        assert_eq!(taken, SENT, "the whole write fits the write buffer");
        assert_eq!(gather(&mut c, SENT).await, sent, "every byte, in order");
    });
}

/// The agreed protocol is judged against the offer the handshake made (`check_agreed`) before the
#[test]
fn the_agreed_protocol_is_one_the_handshake_offered() {
    let offer = protocol_name_list(&[b"pa".to_vec(), Vec::new(), b"proto-b/1".to_vec()]);
    assert_eq!(offer, b"\x02pa\x09proto-b/1");
    assert!(agreed_was_offered(&offer, None).is_ok());
    assert!(agreed_was_offered(&offer, Some(b"pa")).is_ok());
    assert!(agreed_was_offered(&offer, Some(b"proto-b/1")).is_ok());
    assert!(matches!(
        agreed_was_offered(&offer, Some(b"pc")),
        Err(Failure::Refused(_))
    ));
    assert!(matches!(
        agreed_was_offered(&[], Some(b"pa")),
        Err(Failure::Refused(_))
    ));
    assert!(protocol_name_list(&[vec![b'x'; 256]]).is_empty());
}

/// The contract ( `busbar_contract::abi::transport`, "A STREAM'S OWN BACKPRESSURE":
#[test]
fn a_full_stream_takes_nothing_more_until_the_framer_says_it_is_writable() {
    worker().block_on(async {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let (go, went) = tokio::sync::oneshot::channel::<()>();
        let (seen, saw) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut first = [0_u8; 1];
            s.read_exact(&mut first).await.unwrap();
            let _ = went.await;

            s.write_all(b"wz").await.unwrap();
            let mut second = [0_u8; 1];
            s.read_exact(&mut second).await.unwrap();
            let _ = seen.send([first, second].concat());
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest).await;
        });
        let door = Arc::new(TestDoor::new(
            "messages",
            &["messages"],
            &[],
            Knobs {
                messages: Some(EXCHANGE_STREAM),
                full_at: Some(1),
                ..Knobs::default()
            },
        ));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).expect("dials");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), taken(&mut c, b"a"))
                .await
                .expect("the first message is taken"),
            Ok(1)
        );
        tokio::time::timeout(Duration::from_secs(5), opened(&mut c))
            .await
            .expect("the connection opens and its framing begins");
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        assert_eq!(
            c.write(b"b", true, false, &mut cx),
            Ok(0),
            "the stream is full: nothing more is taken on it"
        );
        let _ = go.send(());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), taken(&mut c, b"b"))
                .await
                .expect("the writable piece releases the held write"),
            Ok(1)
        );
        let p = tokio::time::timeout(Duration::from_secs(5), next(&mut c))
            .await
            .expect("a piece")
            .expect("not failed")
            .expect("not ended");
        assert_eq!(
            p.bytes, b"z",
            "the writable piece is never a piece the reader reads"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), saw)
                .await
                .expect("the far end heard both")
                .unwrap(),
            b"ab"
        );
        c.close();
    });
}

/// Write `bytes` as a whole message, waiting while the connection takes none of them.
async fn taken(c: &mut Connection, bytes: &[u8]) -> Result<usize, Failure> {
    futures::future::poll_fn(|cx| match c.write(bytes, true, false, cx) {
        Ok(0) => std::task::Poll::Pending,
        r => std::task::Poll::Ready(r),
    })
    .await
}

/// Drive the connection until it is open (its framing begun, its early writes framed).
async fn opened(c: &mut Connection) {
    futures::future::poll_fn(|cx| {
        let _ = c.poll_ready(cx);
        if c.is_open() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
}

/// An opening as a test writes it: its fields and its body.
type Asked<'a> = (Vec<(&'a str, &'a [u8])>, &'a [u8]);

/// RED: A LOCATED OPENING CARRIES THE HEAD THE FRAMER SAID IT WOULD NOT ADD (THE DESIGN section 6,
#[test]
fn a_located_opening_carries_the_framers_lines_and_the_bodys_length_last() {
    let stating = Arc::new(TestDoor::new(
        "stating",
        &["stating"],
        &[],
        Knobs {
            head_lines: Some(b"accept: */*\r\nhost: 127.0.0.1:9\r\n"),
            states_length: true,
            ..Knobs::default()
        },
    ));
    let silent = Arc::new(
        TestDoor::new("silent", &["silent"], &[], Knobs::default())
            .with_role(busbar_contract::abi::transport::ROLE_FRAMER),
    );
    let located = |door: &Arc<TestDoor>, opening: Option<Asked<'_>>| {
        let mut d = dial("127.0.0.1:9");
        d.opening = opening.map(|(fields, body)| {
            (
                fields
                    .into_iter()
                    .map(|(n, v)| (n.to_owned(), v.to_vec()))
                    .collect(),
                body.to_vec().into(),
            )
        });
        let door: Arc<dyn FramerDoor> = door.clone();
        Planned::locate(door, crate::support::via(), d)
            .expect("located")
            .dial()
            .opening
            .clone()
            .map(|(fields, body)| {
                let fields: Vec<(String, String)> = fields
                    .into_iter()
                    .map(|(n, v)| (n, String::from_utf8(v).unwrap()))
                    .collect();
                (fields, body.to_vec())
            })
    };
    let pairs = |p: &[(&str, &str)]| -> Vec<(String, String)> {
        p.iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    };

    assert_eq!(
        located(
            &stating,
            Some((vec![("content-type", b"application/json")], b"{}"))
        ),
        Some((
            pairs(&[
                ("content-type", "application/json"),
                ("accept", "*/*"),
                ("host", "127.0.0.1:9"),
                ("content-length", "2"),
            ]),
            b"{}".to_vec()
        ))
    );

    assert_eq!(
        located(&stating, Some((vec![("Accept", b"text/plain")], b""))),
        Some((
            pairs(&[("Accept", "text/plain"), ("host", "127.0.0.1:9")]),
            Vec::new()
        ))
    );

    assert_eq!(
        located(
            &silent,
            Some((vec![("content-type", b"application/json")], b"{}"))
        ),
        Some((
            pairs(&[("content-type", "application/json")]),
            b"{}".to_vec()
        ))
    );

    assert_eq!(
        located(&stating, Some((Vec::new(), b""))),
        Some((Vec::new(), Vec::new()))
    );
    assert_eq!(located(&stating, None), None);
}

/// RED (TSEAL; "the plane never sees credential bytes"): OVER A FRAMER THAT RENDERS SEALED VALUES
#[test]
fn a_sealed_credential_reaches_the_far_end_and_never_the_framer() {
    use busbar_contract::conn::SEALED_FIELDS_FIELD;
    const SECRET: &[u8] = b"Bearer sealed-credential-0123456789";
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    let opening = || {
        Some((
            vec![
                ("authorization".to_owned(), SECRET.to_vec()),
                ("x-plain".to_owned(), b"visible".to_vec()),
                (SEALED_FIELDS_FIELD.to_owned(), b"authorization".to_vec()),
            ],
            b"BODY".to_vec().into(),
        ))
    };
    let knobs = |secure: bool| Knobs {
        secure_name: secure.then_some("localhost"),
        seals: true,
        render_fields: true,
        ..Knobs::default()
    };
    worker().block_on(async move {
        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let read = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut s = acceptor.accept(s).await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0_u8; 512];
            while !got.ends_with(b"BODY") {
                match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            got
        });
        let door = Arc::new(TestDoor::new("sec", &["sec"], &[], knobs(true)));
        let trust = busbar_contract::transport::trust::EgressTrust {
            extra_anchors: vec![ca],
            ..Default::default()
        };
        let mut d = dial(&far);
        d.tls = Some(Arc::new(
            crate::tls::client::build_client_config(&trust).expect("a usable client config"),
        ));
        d.opening = opening();
        let mut c = Connection::dial(
            Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
            &crate::support::via(),
            d,
        )
        .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), next(&mut c)).await;
        let got = read.await.unwrap();
        let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
        assert!(
            contains(&got, SECRET),
            "the far end reads the credential: {}",
            String::from_utf8_lossy(&got)
        );
        assert!(contains(&got, b"x-plain: visible"));
        assert!(
            !contains(&got, SEALED_FIELDS_FIELD.as_bytes()),
            "the host's field is never sent"
        );
        let handed = door.handed.lock().unwrap().clone();
        assert!(!handed.is_empty(), "the framer framed the opening");
        assert!(
            !contains(&handed, &SECRET[7..]),
            "the framer was handed the credential: {}",
            String::from_utf8_lossy(&handed)
        );

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = l.local_addr().unwrap().to_string();
        let read = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut got)).await;
            got
        });
        let door = Arc::new(TestDoor::new("sec", &["sec"], &[], knobs(false)));
        let mut d = dial(&far);
        d.opening = opening();
        let mut c = Connection::dial(
            Arc::clone(&door) as Arc<dyn crate::framer::FramerDoor>,
            &crate::support::via(),
            d,
        )
        .unwrap();
        let failed = tokio::time::timeout(Duration::from_secs(2), next(&mut c)).await;
        assert!(
            matches!(failed, Ok(Err(_))),
            "a sealed value in the clear fails the open: {failed:?}"
        );
        drop(c);
        let got = read.await.unwrap();
        assert!(
            !contains(&got, &SECRET[7..]),
            "nothing of the credential is sent in the clear"
        );
        assert!(!contains(&door.handed.lock().unwrap(), &SECRET[7..]));
    });
}

#[path = "compose_receive_tests.rs"]
#[allow(unsafe_code)]
mod receive_tests;

#[test]
fn a_nonsealing_wire_yield_is_wiped_after_its_bytes_are_copied_for_sending() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut c = Connection::dial(door, &crate::support::via(), dial(&far)).unwrap();
        opened(&mut c).await;
        let value = b"/path?key=unsealed-secret".to_vec();
        let pointer = value.as_ptr();
        let len = value.len();
        let (_, wiped, _) = crate::support::observe_wipe(pointer, len, || {
            let mut yielded = Yielded::default();
            yielded.wire = value;
            c.absorb(yielded).unwrap();
        });
        assert_eq!(wiped, Some(true));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), gather(&mut c, len))
                .await
                .unwrap(),
            b"/path?key=unsealed-secret"
        );
    });
}

#[test]
fn duplex_pending_writes_survive_the_incoming_streams_clean_end() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(crate::support::PendingDoor::new(
            TestDoor::identity("bytes"),
            7,
        ));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), dial(&far)).unwrap();
        opened(&mut c).await;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(c.emit(7, b"first", false, false, &mut cx).unwrap(), 5);
        assert_eq!(c.emit(7, b"second", true, false, &mut cx).unwrap(), 6);
        let mut yielded = Yielded::default();
        yielded.pieces = vec![Got {
            stream: 7,
            bytes: Vec::new(),
            end_of_frame: true,
            status_code: None,
            handoff: false,
            status_class: 0,
            fault: 0,
            retry_after_secs: None,
            declared_len: None,
            fields: false,
            text: false,
            reason: None,
            failed: false,
            end: true,
        }];
        c.absorb(yielded).unwrap();
        assert!(next(&mut c).await.unwrap().unwrap().end);
        door.host.complete(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), gather(&mut c, 5))
                .await
                .unwrap(),
            b"first"
        );
        door.host.complete(1);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), gather(&mut c, 6))
                .await
                .unwrap(),
            b"second",
            "incoming EOF does not discard the queued answer"
        );
    });
}

#[test]
fn query_credentials_reach_the_secure_target_without_crossing_the_framer_as_plaintext() {
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
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let far = listener.local_addr().unwrap().to_string();
        let read = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0_u8; 512];
            while !got.ends_with(b"BODY") {
                match tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => got.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            got
        });
        let door = Arc::new(TestDoor::new(
            "sec",
            &["sec"],
            &[],
            Knobs {
                secure_name: Some("localhost"),
                seals: true,
                render_fields: true,
                render_target: true,
                ..Knobs::default()
            },
        ));
        let trust = busbar_contract::transport::trust::EgressTrust {
            extra_anchors: vec![ca],
            ..Default::default()
        };
        let mut d = dial(&far);
        d.tls = Some(Arc::new(
            crate::tls::client::build_client_config(&trust).unwrap(),
        ));
        d.head_words = (b"POST".to_vec(), b"/v1?existing=1#fragment".to_vec());
        d.opening = Some((
            vec![
                (
                    "busbar-sealed-query".into(),
                    b"key=first%20credential".to_vec(),
                ),
                (
                    "busbar-sealed-query".into(),
                    b"key=second%2Bcredential".to_vec(),
                ),
                ("x-visible".into(), b"yes".to_vec()),
            ],
            b"BODY".to_vec().into(),
        ));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), next(&mut c)).await;
        let got = read.await.unwrap();
        assert!(got.starts_with(
            b"/v1?existing=1&key=first%20credential&key=second%2Bcredential#fragment\r\n"
        ));
        assert!(!got
            .windows(b"busbar-sealed-query".len())
            .any(|w| w == b"busbar-sealed-query"));
        let handed = door.handed.lock().unwrap();
        assert!(!handed
            .windows(b"credential".len())
            .any(|w| w == b"credential"));
        assert_eq!(
            c.target(),
            far,
            "dial identity stays free of query credentials"
        );
    });
}
