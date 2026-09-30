// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One listener per inbound need, against REAL clients on real sockets: an accepted connection's
//! bytes go through the framer begun on the accept side and the answer goes back on the piece's
//! own stream, TLS is the connector's server with the framer's protocol offer, the connection cap
//! closes the one past it without a byte, and a silent TLS client is dropped at its handshake
//! deadline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as Client;

use super::*;
use crate::compose::Failure;
use crate::framer::Got;
use crate::support::{worker, TestDoor};

async fn accept(l: &mut Listening) -> Accepted {
    futures::future::poll_fn(|cx| l.poll_accept(cx))
        .await
        .expect("composed")
}

async fn next(c: &mut Connection) -> Result<Option<Got>, Failure> {
    futures::future::poll_fn(|cx| c.poll_piece(cx)).await
}

/// Serve `conn` as an echo: every piece answered, whole, on the stream it came on.
async fn echo(mut conn: Connection) {
    while let Ok(Some(p)) = next(&mut conn).await {
        let waker = std::task::Waker::noop();
        if conn
            .emit(
                p.stream,
                &p.bytes,
                false,
                &mut std::task::Context::from_waker(waker),
            )
            .is_err()
        {
            break;
        }
    }
    conn.close();
}

fn plain(door: Arc<TestDoor>, limits: AcceptLimits) -> Listening {
    Listening::bind(door, "127.0.0.1:0", None, Vec::new(), limits).expect("binds")
}

/// A client's bytes reach the framer begun on `SIDE_ACCEPT`, and the answer the host emits on the
/// piece's stream reaches the client byte-exact.
#[test]
fn an_accepted_connection_is_framed_on_the_accept_side_and_answered() {
    worker().block_on(async {
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut l = plain(door.clone(), AcceptLimits::default());
        let addr = l.local_addr();
        let client = tokio::spawn(async move {
            let mut s = Client::connect(addr).await.unwrap();
            let sent: Vec<u8> = (0..=255_u8).cycle().take(50_000).collect();
            s.write_all(&sent).await.unwrap();
            let mut got = vec![0_u8; sent.len()];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(got, sent, "every byte back, in order, through the framer");
        });
        let a = accept(&mut l).await;
        assert_eq!(a.peer.ip(), addr.ip());
        assert!(a.conn.is_open(), "a clear connection frames at once");
        assert_eq!(l.live(), 1);
        tokio::spawn(echo(a.conn));
        client.await.unwrap();
        assert!(door.count("begin") == 1 && door.count("emit") >= 1);
    });
}

fn localhost_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, IsCa, Issuer, KeyPair};
    let kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.clone().self_signed(&kp).unwrap();
    let issuer = Issuer::new(ca_params, &kp);
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&kp, &issuer)
        .unwrap();
    (ca.der().to_vec(), leaf.der().to_vec(), kp.serialize_der())
}

fn server(leaf: Vec<u8>, key: Vec<u8>) -> Arc<rustls::ServerConfig> {
    let mut s = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.into()],
            rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
        )
        .unwrap();
    // The operator's config may pin its own offer; the listener's is the framer's.
    s.alpn_protocols = vec![b"x-config".to_vec()];
    Arc::new(s)
}

/// TLS on an inbound need is the connector's server: the client's handshake completes, the
/// protocol agreed is the claiming framer's offer (not the server config's own), the name the
/// client offered is an established fact, and the bytes cross encrypted both ways.
#[test]
fn tls_on_a_listener_is_the_connectors_server_with_the_framers_offer() {
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let door = Arc::new(TestDoor::identity("sec"));
        let mut l = Listening::bind(
            door,
            "127.0.0.1:0",
            Some(server(leaf, key)),
            vec![b"x-framer".to_vec()],
            AcceptLimits::default(),
        )
        .unwrap();
        let addr = l.local_addr();
        let client = tokio::spawn(async move {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.into()).unwrap();
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"x-framer".to_vec(), b"x-config".to_vec()];
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let s = Client::connect(addr).await.unwrap();
            let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            let mut s = tls.connect(name, s).await.expect("the handshake completes");
            assert_eq!(s.get_ref().1.alpn_protocol(), Some(&b"x-framer"[..]));
            s.write_all(b"hello").await.unwrap();
            let mut got = [0_u8; 5];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello");
        });
        let a = accept(&mut l).await;
        assert!(!a.conn.is_open(), "the framing waits for the handshake");
        let mut conn = a.conn;
        let p = next(&mut conn).await.unwrap().unwrap();
        assert_eq!(
            conn.established().agreed_protocol.as_deref(),
            Some(&b"x-framer"[..])
        );
        assert_eq!(
            conn.established().offered_name.as_deref(),
            Some("localhost")
        );
        let waker = std::task::Waker::noop();
        conn.emit(
            p.stream,
            &p.bytes,
            false,
            &mut std::task::Context::from_waker(waker),
        )
        .unwrap();
        let mut rest = p.bytes.len();
        while rest < 5 {
            let p = next(&mut conn).await.unwrap().unwrap();
            rest += p.bytes.len();
            conn.emit(
                p.stream,
                &p.bytes,
                false,
                &mut std::task::Context::from_waker(waker),
            )
            .unwrap();
        }
        tokio::spawn(async move { while let Ok(Some(_)) = next(&mut conn).await {} });
        client.await.unwrap();
    });
}

/// RED: the connection past the cap is accepted and closed at once, no byte written, while the
/// ones held are still served; a slot frees when its connection is dropped.
#[test]
fn the_connection_past_the_cap_is_closed_without_a_byte() {
    worker().block_on(async {
        let door = Arc::new(TestDoor::identity("bytes"));
        let mut l = plain(
            door,
            AcceptLimits {
                max_conns: 2,
                ..AcceptLimits::default()
            },
        );
        let addr = l.local_addr();
        let mut held = Vec::new();
        for _ in 0..2 {
            let c = Client::connect(addr).await.unwrap();
            held.push((c, accept(&mut l).await.conn));
        }
        assert_eq!(l.live(), 2);
        let mut third = Client::connect(addr).await.unwrap();
        // The listener takes the third off the queue and closes it; nothing is admitted.
        let polled = tokio::time::timeout(Duration::from_millis(300), accept(&mut l)).await;
        assert!(polled.is_err(), "the one past the cap is never admitted");
        let mut buf = [0_u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
            .await
            .expect("closed at once, not held")
            .unwrap_or(0);
        assert_eq!(n, 0, "not a byte written to the one past the cap");
        // The held ones are still served.
        let (mut c0, conn0) = held.remove(0);
        tokio::spawn(echo(conn0));
        c0.write_all(b"ping").await.unwrap();
        let mut got = [0_u8; 4];
        c0.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        // Dropping one frees its slot for the next client.
        let (_c1, conn1) = held.remove(0);
        drop(conn1);
        let _c3 = Client::connect(addr).await.unwrap();
        let a = tokio::time::timeout(Duration::from_secs(2), accept(&mut l))
            .await
            .expect("a freed slot admits the next");
        assert!(a.conn.is_open());
    });
}

/// RED: a TLS client that never speaks is dropped at the handshake deadline (1.5.5's handshake
/// timeout), never answered, and its slot frees.
#[test]
fn a_silent_tls_client_is_dropped_at_the_handshake_deadline() {
    crate::tls::install_crypto_provider();
    let (_, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let door = Arc::new(TestDoor::identity("sec"));
        let mut l = Listening::bind(
            door.clone(),
            "127.0.0.1:0",
            Some(server(leaf, key)),
            Vec::new(),
            AcceptLimits {
                handshake_timeout: Duration::from_millis(200),
                ..AcceptLimits::default()
            },
        )
        .unwrap();
        let mut silent = Client::connect(l.local_addr()).await.unwrap();
        let mut conn = accept(&mut l).await.conn;
        let at = Instant::now();
        assert_eq!(next(&mut conn).await, Err(Failure::Timeout));
        let took = at.elapsed();
        assert!(
            took >= Duration::from_millis(150) && took < Duration::from_secs(2),
            "held to the handshake deadline: {took:?}"
        );
        assert_eq!(door.count("begin"), 0, "the framer never saw it");
        conn.close();
        assert_eq!(l.live(), 0, "its slot is free");
        let mut buf = [0_u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), silent.read(&mut buf))
            .await
            .expect("dropped")
            .unwrap_or(0);
        assert_eq!(n, 0, "no byte answered");
    });
}

/// 1.5.5's accept backoff: an aborted or interrupted accept retries at once; anything else backs
/// off 5 ms, doubling to 250 ms, and a success resets it.
#[test]
fn accept_errors_back_off_as_1_5_5s_did() {
    worker().block_on(async {
        let mut l = plain(
            Arc::new(TestDoor::identity("bytes")),
            AcceptLimits::default(),
        );
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE);
        let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        assert_eq!(l.next_delay(&aborted), None);
        let delays: Vec<_> = (0..8).map(|_| l.next_delay(&emfile).unwrap()).collect();
        assert_eq!(delays[0], Duration::from_millis(5));
        assert_eq!(delays[1], Duration::from_millis(10));
        assert_eq!(*delays.last().unwrap(), Duration::from_millis(250));
        assert_eq!(l.next_delay(&aborted), None);
        assert_eq!(l.next_delay(&emfile), Some(Duration::from_millis(5)));
    });
}
