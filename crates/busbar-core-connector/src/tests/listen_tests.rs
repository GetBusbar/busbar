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
    Listening::bind(
        Some(door),
        &crate::support::via(),
        "127.0.0.1:0",
        None,
        Vec::new(),
        limits,
    )
    .expect("binds")
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
    let ca = crate::test_support::private_ca();
    (
        crate::test_support::certs_from_pem(&ca.ca_pem).remove(0),
        ca.leaf_der,
        ca.key_der,
    )
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
            Some(door),
            &crate::support::via(),
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
            Some(door.clone()),
            &crate::support::via(),
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

/// A STREAM listener (the root's own binds) hands each admitted socket up as it arrived, bytes
/// untouched and nothing framed; the connection past the cap is closed without a byte; the slot
/// the kernel holds frees when the served connection ends.
#[test]
fn a_stream_listener_hands_up_the_socket_as_it_arrived_under_the_cap() {
    use crate::listen::Admits;
    worker().block_on(async {
        let via = crate::support::via();
        let mut l = Listening::bind_stream(
            Some(&via),
            "127.0.0.1:0",
            AcceptLimits {
                max_conns: 1,
                ..AcceptLimits::default()
            },
        )
        .unwrap();
        let addr = l.local_addr();
        let mut c = Client::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let a = l.admit().await;
        assert_eq!(a.peer.ip(), addr.ip());
        assert_eq!(l.live(), 1, "the kernel holds the slot while it serves");
        let mut s = tokio::net::TcpStream::from_std(a.stream).unwrap();
        let mut got = [0_u8; 16];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(
            &got, b"GET / HTTP/1.1\r\n",
            "the bytes as the client sent them"
        );
        // One past the cap: accepted and closed, never admitted.
        let mut past = Client::connect(addr).await.unwrap();
        let polled = tokio::time::timeout(Duration::from_millis(300), l.admit()).await;
        assert!(polled.is_err(), "the one past the cap is never admitted");
        let mut buf = [0_u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(2), past.read(&mut buf))
            .await
            .expect("closed at once")
            .unwrap_or(0);
        assert_eq!(n, 0);
        drop(a.hold);
        assert_eq!(l.live(), 0, "the slot frees with the served connection");
        let framed = futures::future::poll_fn(|cx| std::task::Poll::Ready(l.poll_accept(cx))).await;
        assert!(
            matches!(framed, std::task::Poll::Ready(Err(_))),
            "a stream listener frames nothing"
        );
    });
}

/// RED (`BUSBAR-1.6.0.md` l.477-478): THE LISTENER'S PROTOCOL OFFER IS THE ENTRY'S
/// OFFER FOR ITS ACCEPTING SIDE. An entry that dials offering `x-two, x-one` and listens offering
/// `x-one` alone answers the two apart, and a TLS client offering `x-two, x-one` to the need's
/// listener (bound through the connector) agrees `x-one`: never the dial offer, never the server
/// config's own (v1.5.5's client offered two protocols, its listener one).
#[test]
fn a_listener_offers_the_entrys_accept_offer_not_its_dial_offer() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        crate::support::Knobs {
            secure_name: Some("localhost"),
            offer: Some(b"\x05x-two\x05x-one"),
            accept_offer: Some(b"\x05x-one"),
            ..crate::support::Knobs::default()
        },
    );
    assert_eq!(
        crate::framer::locate(&door, "127.0.0.1:443").unwrap().offer,
        vec![b"x-two".to_vec(), b"x-one".to_vec()],
        "the dial offer"
    );
    assert_eq!(
        crate::framer::accept_offer(&door).unwrap(),
        vec![b"x-one".to_vec()],
        "the accept offer is the entry's own, and not its dial offer"
    );
    // The entry's own accept offer wins over the transport's registered list.
    assert_eq!(
        agreed_on_the_listener(door, vec![b"x-two".to_vec()]).as_deref(),
        Some(&b"x-one"[..]),
        "the listener agreed off the entry's accept offer"
    );
}

/// RED (`BUSBAR-1.6.0.md` l.477-478): AN ENTRY THAT STATES NO ACCEPT OFFER
/// LISTENS WITH THE TRANSPORT'S REGISTERED PROTOCOL LIST (the registry's `Entry::alpn`, the
/// operator's settings dealt at boot), as a dial whose `locate` answers no offer dials with it
/// (`compose`, "the registration's stands only for an entry that answers none"). A TLS listener
/// whose entry answers no accepting offer still agrees a protocol off its registration: a client
/// that needs one negotiated refuses a connection that agreed none. RED before the fix: the
/// bind took the entry's accept offer alone (`accept_offer(..).unwrap_or_default()`), so the
/// listener offered nothing and the handshake agreed no protocol.
#[test]
fn a_listener_whose_entry_states_no_accept_offer_offers_the_transports_list() {
    let door = TestDoor::new(
        "sec",
        &["sec"],
        &[],
        crate::support::Knobs {
            secure_name: Some("localhost"),
            ..crate::support::Knobs::default()
        },
    );
    assert_eq!(
        crate::framer::accept_offer(&door).unwrap(),
        Vec::<Vec<u8>>::new(),
        "the entry states no accept offer"
    );
    assert_eq!(
        agreed_on_the_listener(door, vec![b"x-one".to_vec()]).as_deref(),
        Some(&b"x-one"[..]),
        "the listener agreed off the transport's registered list"
    );
}

/// What a TLS client offering `x-two, x-one` agrees with the listener the connector binds for an
/// inbound need declared over `door`'s scheme (`sec`), the entry registered with the protocol list
/// `registered`. The entry is a FRAMER (it names a secure layer), so its listener rides the address
/// carrier the view holds beside it, as every connector does (`Connector::listen`).
fn agreed_on_the_listener(door: TestDoor, registered: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    use busbar_contract::conn::{ConnError, Conns as _, InstanceId, NeedId};
    const OWNER: InstanceId = InstanceId(1);
    crate::tls::install_crypto_provider();
    let (ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let view = crate::registry::Transports::new(vec![
            crate::registry::Entry {
                door: Arc::new(door),
                alpn: registered,
            },
            crate::registry::Entry {
                door: Arc::new(TestDoor::identity("carrier")),
                alpn: Vec::new(),
            },
        ])
        .unwrap();
        let c = crate::Connector::serving(
            view,
            crate::tests::loopback_literals(),
            None,
            Arc::new(|_, _| {}),
        );
        c.declare_over(OWNER, NeedId(0), "sec")
            .expect("a served scheme declares");
        let addr = c
            .listen(
                OWNER,
                NeedId(0),
                "127.0.0.1:0",
                Some(server(leaf, key)),
                AcceptLimits::default(),
            )
            .expect("listens");
        let client = tokio::spawn(async move {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.into()).unwrap();
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"x-two".to_vec(), b"x-one".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let s = Client::connect(addr).await.unwrap();
            let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            let mut s = connector
                .connect(name, s)
                .await
                .expect("the handshake completes");
            let agreed = s.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            s.write_all(b"knock").await.unwrap();
            let mut got = [0_u8; 1];
            let _ = s.read(&mut got).await;
            agreed
        });
        let id = loop {
            match c.accept(OWNER, NeedId(0), 3) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                other => break other.expect("accepted").0,
            }
        };
        let mut buf = [0_u8; 64];
        let mut got = 0;
        while got < 5 {
            match c.read(OWNER, id, 3, &mut buf) {
                Err(ConnError::Pending) => tokio::task::yield_now().await,
                Ok(p) => got += p.len,
                Err(e) => panic!("{e:?}"),
            }
        }
        c.close(OWNER, id).unwrap();
        client.await.unwrap()
    })
}

/// /status row 192 B, the agreed protocol: the protocol an accepting framer states it agreed
/// (`FramerYield::agreed`, a 1-based position in its accepting offer) is read back by the
/// connector, resolved against the offer the listener made ([`Connection::agreed`]); a framer that
/// states `0` agreed nothing the host knows of; and a position past the offer is the framer's
/// fault, refusing the connection.
#[test]
fn an_accepting_framers_agreed_protocol_is_read_back_against_the_listeners_offer() {
    use crate::support::Knobs;
    let offer = vec![b"proto-a".to_vec(), b"proto-b".to_vec()];
    let listener = |agreed: Option<u32>| {
        let door = Arc::new(TestDoor::new(
            "bytes",
            &["bytes"],
            &[],
            Knobs {
                agreed,
                ..Knobs::default()
            },
        ));
        Listening::bind(
            Some(door),
            &crate::support::via(),
            "127.0.0.1:0",
            None,
            offer.clone(),
            AcceptLimits::default(),
        )
        .expect("binds")
    };
    worker().block_on(async {
        for (stated, want) in [
            (Some(2), Some(&b"proto-b"[..])),
            (Some(1), Some(&b"proto-a"[..])),
            (Some(0), None),
            (None, None),
        ] {
            let mut l = listener(stated);
            let addr = l.local_addr();
            let client = tokio::spawn(async move { Client::connect(addr).await.unwrap() });
            let a = accept(&mut l).await;
            let held = client.await.unwrap();
            assert_eq!(a.conn.agreed(), want, "stated {stated:?}");
            drop((a, held));
        }
        let mut l = listener(Some(3));
        let addr = l.local_addr();
        let client = tokio::spawn(async move { Client::connect(addr).await.unwrap() });
        let got = futures::future::poll_fn(|cx| l.poll_accept(cx)).await;
        let held = client.await.unwrap();
        match got {
            Err(Failure::Failed(e)) => assert!(e.contains("agreed"), "{e}"),
            Err(other) => panic!("refused for another reason: {other:?}"),
            Ok(a) => panic!("a position past the offer was taken: {:?}", a.conn.agreed()),
        }
        drop(held);
    });
}
