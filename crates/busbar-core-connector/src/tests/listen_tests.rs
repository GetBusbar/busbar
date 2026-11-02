// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One listener per inbound need, against REAL clients on real sockets: an accepted connection's

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as Client;

use super::*;
use crate::compose::Failure;
use crate::framer::Got;
use crate::support::{worker, TestDoor};

struct LifecycleDoor {
    inner: TestDoor,
    listen: Option<Outcome>,
    accept: Option<Outcome>,
    bound: std::sync::Mutex<Option<(u64, String)>>,
    accepted: std::sync::Mutex<Option<(u64, Vec<u8>)>>,
    cancelled: std::sync::atomic::AtomicUsize,
}

impl LifecycleDoor {
    #[allow(unsafe_code)]
    fn replay_peer(peer: &[u8], into: &mut AcceptIn) {
        assert!(peer.len() <= into.peer_cap);
        // SAFETY: this fixture is a carrier; the host supplied peer_cap writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(peer.as_ptr(), into.peer_buf, peer.len());
        }
    }

    fn new(listen: Option<Outcome>, accept: Option<Outcome>) -> Self {
        Self {
            inner: TestDoor::identity("listener-lifecycle"),
            listen,
            accept,
            bound: std::sync::Mutex::new(None),
            accepted: std::sync::Mutex::new(None),
            cancelled: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl crate::framer::FramerDoor for LifecycleDoor {
    fn facts(&self) -> &crate::framer::DoorFacts {
        self.inner.facts()
    }

    fn cross(&self, call: crate::framer::Call<'_>) -> crate::framer::Crossed {
        self.inner.cross(call)
    }

    fn side(&self) -> Option<Box<dyn crate::carrier::Side>> {
        self.inner.side()
    }

    fn carry(
        &self,
        side: &dyn crate::carrier::Side,
        resume: bool,
        call: crate::carrier::Carry<'_>,
    ) -> crate::framer::Crossed {
        match call {
            Carry::Listen(i, o) => {
                let crossed = self.inner.carry(side, resume, Carry::Listen(i, o));
                if crossed.outcome != Outcome::Ready {
                    return crossed;
                }
                let address = crate::support::lent(i.addr_buf, o.addr_written as usize);
                *self.bound.lock().unwrap() =
                    Some((o.listener, String::from_utf8_lossy(&address).into_owned()));
                crate::framer::Crossed {
                    outcome: self.listen.unwrap_or(Outcome::Ready),
                    error: Some(b"scripted listen result".to_vec()),
                }
            }
            Carry::Accept(i, o) => {
                if resume {
                    if let Some((conn, peer)) = self.accepted.lock().unwrap().as_ref() {
                        Self::replay_peer(peer, i);
                        o.conn = *conn;
                        o.peer_written = peer.len() as u64;
                        return crate::framer::Crossed {
                            outcome: Outcome::Ready,
                            error: None,
                        };
                    }
                }
                let crossed = self.inner.carry(side, resume, Carry::Accept(i, o));
                if crossed.outcome != Outcome::Ready {
                    return crossed;
                }
                let peer = crate::support::lent(i.peer_buf, o.peer_written as usize);
                *self.accepted.lock().unwrap() = Some((o.conn, peer));
                crate::framer::Crossed {
                    outcome: self.accept.unwrap_or(Outcome::Ready),
                    error: Some(b"scripted accept result".to_vec()),
                }
            }
            Carry::Cancel(i, o) => {
                self.cancelled.fetch_add(1, Ordering::SeqCst);
                self.inner.carry(side, resume, Carry::Cancel(i, o))
            }
            other => self.inner.carry(side, resume, other),
        }
    }
}

fn lifecycle_via(door: &Arc<LifecycleDoor>) -> Via {
    Via {
        door: Arc::clone(door) as Arc<dyn FramerDoor>,
        io: crate::hostio::process(),
    }
}

#[test]
fn a_failed_or_pending_listen_retires_the_socket_it_made() {
    use busbar_contract::io_host::IoHost;
    worker().block_on(async {
        for outcome in [
            Outcome::Failed,
            Outcome::Refused,
            Outcome::Fault,
            Outcome::Pending,
        ] {
            let door = Arc::new(LifecycleDoor::new(Some(outcome), None));
            let via = lifecycle_via(&door);
            let result = Listening::bind_stream(Some(&via), "127.0.0.1:0", AcceptLimits::default());
            let (handle, address) = door.bound.lock().unwrap().clone().unwrap();
            let retired = via.io.ends(crate::support::OWNER, handle).is_err();
            let stopped = Client::connect(&address).await.is_err();

            via.io.retire_listener(handle);
            assert!(result.is_err(), "the carrier did not finish listening");
            assert!(
                retired && stopped,
                "a failed {outcome:?} bind left its socket live"
            );
            assert_eq!(
                door.cancelled.load(Ordering::SeqCst),
                usize::from(outcome == Outcome::Pending)
            );
        }
    });
}

#[test]
fn a_completed_accept_transfers_its_handle_and_withdraws_its_ticket_record() {
    use busbar_contract::io_host::IoHost;
    worker().block_on(async {
        for pending in [false, true] {
            let door = Arc::new(LifecycleDoor::new(
                None,
                pending.then_some(Outcome::Pending),
            ));
            let via = lifecycle_via(&door);
            let mut listening = Listening::bind(
                None,
                &via,
                "127.0.0.1:0",
                None,
                Vec::new(),
                AcceptLimits::default(),
            )
            .unwrap();
            let ticket = match &listening.source {
                Source::Carrier { side, .. } => side.ticket(),
                Source::Host(_) => unreachable!(),
            };
            let client = Client::connect(listening.local_addr()).await.unwrap();
            if pending {
                let waker = std::task::Waker::noop();
                let mut cx = Context::from_waker(waker);
                while door.accepted.lock().unwrap().is_none() {
                    assert!(listening.poll_accept(&mut cx).is_pending());
                    tokio::task::yield_now().await;
                }
            }
            let accepted = accept(&mut listening).await;
            let handle = door.accepted.lock().unwrap().as_ref().unwrap().0;
            let withdrawn = via.io.made(ticket).is_none();
            let _ = via.io.settle(ticket);
            drop(listening);
            let transferred = via.io.ends(crate::support::OWNER, handle).is_ok();
            accepted.conn.close();
            drop(client);
            assert!(
                withdrawn,
                "a terminal accept left its ticket's made handle behind"
            );
            assert!(
                transferred,
                "dropping the listener closed an accepted connection"
            );
        }
    });
}

#[test]
fn dropping_a_listener_cancels_and_retires_a_partly_made_accept() {
    use busbar_contract::io_host::IoHost;
    worker().block_on(async {
        let door = Arc::new(LifecycleDoor::new(None, Some(Outcome::Pending)));
        let via = lifecycle_via(&door);
        let mut listening = Listening::bind(
            None,
            &via,
            "127.0.0.1:0",
            None,
            Vec::new(),
            AcceptLimits::default(),
        )
        .unwrap();
        let ticket = match &listening.source {
            Source::Carrier { side, .. } => side.ticket(),
            Source::Host(_) => unreachable!(),
        };
        let client = Client::connect(listening.local_addr()).await.unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        while door.accepted.lock().unwrap().is_none() {
            assert!(listening.poll_accept(&mut cx).is_pending());
            tokio::task::yield_now().await;
        }
        let handle = door.accepted.lock().unwrap().as_ref().unwrap().0;
        drop(listening);
        let withdrawn = via.io.made(ticket).is_none();
        let retired = via.io.ends(crate::support::OWNER, handle).is_err();
        let _ = via.io.settle(ticket);
        let _ = via.io.close(crate::support::OWNER, handle);
        drop(client);
        assert!(
            withdrawn && retired,
            "a cancelled accept retained its record or socket"
        );
        assert_eq!(door.cancelled.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn a_failed_accept_retires_its_untransferred_socket() {
    use busbar_contract::io_host::IoHost;
    worker().block_on(async {
        let door = Arc::new(LifecycleDoor::new(None, Some(Outcome::Refused)));
        let via = lifecycle_via(&door);
        let mut listening = Listening::bind(
            None,
            &via,
            "127.0.0.1:0",
            None,
            Vec::new(),
            AcceptLimits::default(),
        )
        .unwrap();
        let client = Client::connect(listening.local_addr()).await.unwrap();
        let Source::Carrier { listener, side, .. } = &mut listening.source else {
            unreachable!()
        };
        let ticket = side.ticket();
        let result = futures::future::poll_fn(|cx| accept_through(&via, *listener, side, cx)).await;
        let handle = door.accepted.lock().unwrap().as_ref().unwrap().0;
        let withdrawn = via.io.made(ticket).is_none();
        let retired = via.io.ends(crate::support::OWNER, handle).is_err();
        let _ = via.io.settle(ticket);
        let _ = via.io.close(crate::support::OWNER, handle);
        drop((listening, client));
        assert!(result.is_err());
        assert!(
            withdrawn && retired,
            "a failed accept retained its record or socket"
        );
    });
}

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

    s.alpn_protocols = vec![b"x-config".to_vec()];
    Arc::new(s)
}

/// TLS on an inbound need is the connector's server: the client's handshake completes, the

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

        let polled = tokio::time::timeout(Duration::from_millis(300), accept(&mut l)).await;
        assert!(polled.is_err(), "the one past the cap is never admitted");
        let mut buf = [0_u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf))
            .await
            .expect("closed at once, not held")
            .unwrap_or(0);
        assert_eq!(n, 0, "not a byte written to the one past the cap");

        let (mut c0, conn0) = held.remove(0);
        tokio::spawn(echo(conn0));
        c0.write_all(b"ping").await.unwrap();
        let mut got = [0_u8; 4];
        c0.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

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

    assert_eq!(
        agreed_on_the_listener(door, vec![b"x-two".to_vec()]).as_deref(),
        Some(&b"x-one"[..]),
        "the listener agreed off the entry's accept offer"
    );
}

/// RED (`BUSBAR-1.6.0.md` l.477-478): AN ENTRY THAT STATES NO ACCEPT OFFER

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

/// RED (T1, tcp TT1): A RETIRED LISTENER IS UNBOUND WHEN IT IS DROPPED. A listener bound through a

#[test]
fn a_dropped_listener_stops_accepting_at_once() {
    worker().block_on(async {
        for l in [
            plain(
                Arc::new(TestDoor::identity("bytes")),
                AcceptLimits::default(),
            ),
            Listening::bind_stream(
                Some(&crate::support::via()),
                "127.0.0.1:0",
                AcceptLimits::default(),
            )
            .unwrap(),
        ] {
            let addr = l.local_addr();
            let live = Client::connect(addr).await;
            assert!(live.is_ok(), "a live listener accepts");
            drop(live);
            drop(l);
            let after = Client::connect(addr).await;
            assert!(
                after.is_err(),
                "a dropped listener's address accepts nothing: {after:?}"
            );
        }
    });
}
