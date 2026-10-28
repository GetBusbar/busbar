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
        d.opening = Some((Vec::new(), b"hello".to_vec().into()));
        let mut c = Connection::dial(door, &crate::support::via(), d).unwrap();
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
/// connection's buffer has room; once the socket stops taking bytes the buffer fills to
/// [`WRITE_BUFFER_BYTES`] and a write is taken not at all (`Ok(0)`), and stays so.
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

/// RED (ARCHITECT, the stream-end ruling): an EMPTY message, binary or text, is relayed as a
/// message, its text bit kept; the stream ends only on the framer's `PIECE_END`, never on an empty
/// piece.
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
/// ENDED in the same answer that handed up its last message (a ws peer breaking the protocol right
/// after a message, here a peer that sent a message and half-closed), and the host still answers
/// that message: `YIELD_ENDED` says no frame follows, not that this side may no longer write. On
/// the parent the answer was refused as `Closed`, so the peer heard the close and no answer.
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

/// WHY A CONNECTION FAILED, named by stage and the underlying error's own words (ARCHITECT
/// ruling on a plane's guard words): a closed port fails the socket's open with the socket's own error
/// (the one this host's own connect to it answers); a far end whose certificate no anchor signs
/// fails connection security with the TLS stack's own error; a handshake that never finishes is a
/// deadline.
#[test]
fn a_failed_connection_names_its_stage_and_the_underlying_error() {
    use busbar_contract::abi::host::conn::connector::{
        CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_SECURITY,
    };
    crate::tls::install_crypto_provider();
    let (_, leaf, key) = localhost_cert();
    worker().block_on(async move {
        // The socket's open.
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
        // Connection security.
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
        // A handshake that never finishes.
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

/// RED (audit core-connector#3, STARTTLS response injection), the connection's own layer: a raw
/// stream whose far end answered `OK\n` with forged bytes behind it, the piece taken off the socket
/// into the connection's inbox and not read. The upgrade is refused and the connection fails: the
/// forged bytes are never read, least of all as a verified far end's.
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

/// RED (audit core-connector#6): a far end that sends far more than its holder reads (64 MiB, the
/// holder only waiting on readiness) is held back by the receive cap: the line stops reading, so
/// the far end's own flow control stops it, short of what it meant to send.
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
/// bounds): what the framer answers to what it read on its own (an h2 PING's ack, a ws pong) is
/// bounded too. A far end that sends and never reads stops being read once those answers fill the
/// write side; queued with no cap while the socket kept being read, they grew host memory at the
/// far end's line rate.
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
            // Held open, never read.
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
            // The holder takes every piece it is handed: only the owed answers can pile up.
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
/// dialled connection. The first stream's head emit calls the auth, which pends; the second
/// stream's request goes out and its answer comes back while the first waits; then the auth
/// answers, the first stream's request goes out, and its answer comes back, with exactly one auth
/// call. Each head emit states the length of the body it opens with.
#[test]
fn one_stream_pending_auth_holds_only_that_stream_on_the_connection() {
    worker().block_on(async {
        let far = echo().await;
        let door = Arc::new(crate::support::PendingDoor::new(
            TestDoor::identity("bytes"),
            EXCHANGE_STREAM,
        ));
        let mut d = dial(&far);
        d.opening = Some((Vec::new(), b"first ".to_vec()));
        let mut c = Connection::dial(door.clone(), &crate::support::via(), d).expect("dials");
        let waker = std::task::Waker::noop();
        c.open_exchange(
            3,
            Some((Vec::new(), b"second".to_vec())),
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

/// RED (THE DESIGN §5: TLS is the connector's, "today's code moved byte-identically"; a write is
/// taken up to `WRITE_BUFFER_BYTES`): one write larger than the TLS library's default send buffer
/// (64 KiB) crosses whole, encrypted, in order. Handed to the TLS writer in one piece past that
/// buffer, the write failed the connection ("failed to write whole buffer").
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

/// The agreed protocol is judged against the offer the handshake made (`check_agreed`, audit
/// contract-src #11) before the framer is handed it: none agreed or an offered id passes, an id
/// never offered fails the connection, and an id the encoding cannot carry is never offered.
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

/// RED (Q128 arch u22 MEDIUM 4; `busbar_contract::abi::transport`, "A STREAM'S OWN BACKPRESSURE":
/// "the host emits nothing more on that stream, holding whatever feeds it (not-ready, with a
/// wake), until the framer hands a `PIECE_WRITABLE` piece"): once the framer answers an emit
/// `YIELD_STREAM_FULL`, the connection takes nothing more on that stream (`Ok(0)`, the writer's
/// waker parked on the socket) until the far end's bytes bring the framer's writable piece; then
/// the held write goes out, and the writable piece itself never reaches the reader. The host kept
/// emitting past the mark, which a framer is entitled to fail the stream for.
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
            // The window opens: the framer's writable piece, then one message.
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
