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
    let mut s = std::sync::Arc::unwrap_or_clone(
        busbar_contract::crypto::tls::server_config(|b| {
            b.with_no_client_auth().with_single_cert(
                vec![leaf.into()],
                rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
            )
        })
        .unwrap(),
    );

    s.alpn_protocols = vec![b"x-config".to_vec()];
    Arc::new(s)
}

/// TLS on an inbound need is the connector's server: the client's handshake completes, the
#[test]
fn tls_on_a_listener_is_the_connectors_server_with_the_framers_offer() {
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
            let mut cfg = std::sync::Arc::unwrap_or_clone(
                busbar_contract::crypto::tls::client_config(|b| {
                    Ok(b.with_root_certificates(roots).with_no_client_auth())
                })
                .unwrap(),
            );
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

/// AN ACCEPTED CONNECTION'S REFUSAL IS NOT EXPLAINED AS A DIAL'S (design mcp-issuer §3.1, §4): on a
/// listener that demands a client certificate under its `client_ca`, a client presenting one from
/// another CA is refused with the security stack's words exactly. The dial-side sentence (the
/// server's chain, a `cert_spki` pin) is about a far end busbar dialled and would be wrong here.
#[test]
fn an_accepted_client_under_an_unknown_ca_is_refused_in_the_stacks_words_exactly() {
    use busbar_contract::conn::codes::CAUSE_SECURITY;
    use busbar_contract::crypto::testing::rcgen;
    let (ca, leaf, key) = localhost_cert();
    // The stranger CA must carry its OWN subject name: rcgen names every certificate
    // `CN=rcgen self signed cert` by default, and a leaf whose issuer name matches the trusted
    // `client_ca` is tried against it and refused as `BadSignature`, never as an unknown issuer.
    let (stranger_leaf, stranger_key) = {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "listen test stranger root");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::new(params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        (leaf.der().to_vec(), leaf_key.serialize_der())
    };
    worker().block_on(async move {
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(ca.clone().into()).unwrap();
        let verifier =
            busbar_contract::crypto::tls::client_verifier(Arc::new(client_roots), |b| b).unwrap();
        let server = std::sync::Arc::unwrap_or_clone(
            busbar_contract::crypto::tls::server_config(|b| {
                b.with_client_cert_verifier(verifier).with_single_cert(
                    vec![leaf.into()],
                    rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
                )
            })
            .unwrap(),
        );
        let door = Arc::new(TestDoor::identity("sec"));
        let mut l = Listening::bind(
            Some(door.clone()),
            &crate::support::via(),
            "127.0.0.1:0",
            Some(Arc::new(server)),
            Vec::new(),
            AcceptLimits::default(),
        )
        .unwrap();
        let addr = l.local_addr();
        let client = tokio::spawn(async move {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca.into()).unwrap();
            let cfg = std::sync::Arc::unwrap_or_clone(
                busbar_contract::crypto::tls::client_config(|b| {
                    b.with_root_certificates(roots).with_client_auth_cert(
                        vec![stranger_leaf.into()],
                        rustls_pki_types::PrivateKeyDer::try_from(stranger_key).unwrap(),
                    )
                })
                .unwrap(),
            );
            let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let s = Client::connect(addr).await.unwrap();
            let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            if let Ok(mut s) = tls.connect(name, s).await {
                let _ = s.write_all(b"hello").await;
                let mut sink = [0_u8; 8];
                let _ = s.read(&mut sink).await;
            }
        });
        let mut conn = accept(&mut l).await.conn;
        assert!(matches!(next(&mut conn).await, Err(Failure::Refused(_))));
        let unknown = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let cause = conn.cause().expect("a cause");
        assert_eq!(cause.stage, CAUSE_SECURITY);
        assert_eq!(cause.text, unknown.to_string(), "the stack's own words");
        assert!(
            !cause.text.contains("does not chain") && !cause.text.contains("cert_spki"),
            "no dial-side sentence on an accepted connection: {}",
            cause.text
        );
        assert_eq!(door.count("begin"), 0, "the framer never saw it");
        conn.close();
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

/// A dropped listener stops accepting at once.
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

/// The whole accept-backoff sequence, at the resolution tokio's timer sleeps (whole milliseconds,
/// rounded up): 5 ms doubling to the 250 ms cap, no jitter, no retry limit.
#[test]
fn the_accept_backoff_sequence_is_5ms_doubling_to_a_250ms_cap() {
    worker().block_on(async {
        let mut l = plain(
            Arc::new(TestDoor::identity("bytes")),
            AcceptLimits::default(),
        );
        let emfile = std::io::Error::from_raw_os_error(libc::EMFILE);
        let tick_ms = |d: Duration| d.as_nanos().div_ceil(1_000_000);
        let delays: Vec<_> = (0..64)
            .map(|_| tick_ms(l.next_delay(&emfile).unwrap()))
            .collect();
        let mut want = vec![5, 10, 20, 40, 80, 160];
        want.resize(64, 250);
        assert_eq!(delays, want);
    });
}

/// #245, DES-245 r3 C6: an accepted client that resets mid-handshake failed the transport, so the
/// cause stage is `CAUSE_CONNECT`; a client the listener's `client_ca` refuses stays
/// `CAUSE_SECURITY` (the test above).
#[test]
fn an_accepted_client_that_resets_mid_handshake_is_a_connect_failure() {
    use busbar_contract::conn::codes::CAUSE_CONNECT;
    let (_ca, leaf, key) = localhost_cert();
    worker().block_on(async move {
        let server = std::sync::Arc::unwrap_or_clone(
            busbar_contract::crypto::tls::server_config(|b| {
                b.with_no_client_auth().with_single_cert(
                    vec![leaf.into()],
                    rustls_pki_types::PrivateKeyDer::try_from(key).unwrap(),
                )
            })
            .unwrap(),
        );
        let door = Arc::new(TestDoor::identity("sec"));
        let mut l = Listening::bind(
            Some(door.clone()),
            &crate::support::via(),
            "127.0.0.1:0",
            Some(Arc::new(server)),
            Vec::new(),
            AcceptLimits::default(),
        )
        .unwrap();
        let addr = l.local_addr();
        let client = tokio::spawn(async move {
            let mut s = Client::connect(addr).await.unwrap();
            // A ClientHello record header and the start of its body, then a reset.
            s.write_all(&[0x16, 0x03, 0x01, 0x00, 0x80, 0x01, 0x00])
                .await
                .unwrap();
            s.set_zero_linger().unwrap();
            drop(s);
        });
        let mut conn = accept(&mut l).await.conn;
        client.await.unwrap();
        assert!(next(&mut conn).await.is_err());
        let cause = conn.cause().expect("a cause");
        assert_eq!(cause.stage, CAUSE_CONNECT, "{}", cause.text);
        assert_eq!(door.count("begin"), 0, "the framer never saw it");
        conn.close();
    });
}

/// PROBE of the kernel the stop relies on (prints its readings; run with `--no-capture`): a `SO_REUSEPORT` listener
/// that never accepts keeps its share of new connections; shut down, it leaves the group, and the connections
/// already queued on it are reset unless `net.ipv4.tcp_migrate_req` is 1 (then the kernel moves them to another
/// listener of the group).
#[cfg(target_os = "linux")]
#[test]
fn probe_a_shut_reuseport_listener_leaves_the_group_and_resets_its_queue() {
    use std::io::Read;
    let listen = |port: u16| {
        let l = crate::socket::listen(&format!("127.0.0.1:{port}")).unwrap();
        l.set_nonblocking(true).unwrap();
        l
    };
    let drain = |l: &std::net::TcpListener| std::iter::from_fn(|| l.accept().ok()).count();
    let hung = listen(0);
    let port = hung.local_addr().unwrap().port();
    let live = listen(port);
    let migrate = std::fs::read_to_string("/proc/sys/net/ipv4/tcp_migrate_req")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let queued: Vec<_> = (0..64)
        .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let live_before = drain(&live);
    let on_hung = queued.len() - live_before;
    assert!(
        on_hung > 0,
        "a listener that never accepts still gets its share"
    );
    socket2::SockRef::from(&hung)
        .shutdown(std::net::Shutdown::Both)
        .unwrap();
    let after: Vec<_> = (0..64)
        .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let live_after = drain(&live);
    let reset = queued
        .iter()
        .filter(|c| {
            // A queued client the live listener drained was closed (EOF); one reset by the shut queue is RST.
            let mut c: &std::net::TcpStream = c;
            c.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
            matches!(c.read(&mut [0u8; 1]), Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
        })
        .count();
    println!(
        "probe: tcp_migrate_req={migrate} queued on the idle listener={on_hung}/64; after shutdown: new to the \
         live listener={live_after}/{} (migrated from the shut queue included), queued clients reset={reset}",
        after.len()
    );
    assert!(
        live_after >= after.len(),
        "every new connection reaches the listener still in the group"
    );
    if !migrate {
        assert!(
            reset >= on_hung,
            "without tcp_migrate_req the shut listener's queue is reset"
        );
    }
}

/// A stopped stream listener leaves its `SO_REUSEPORT` group: with two listeners on one port and the first stopped
/// from another thread (as the core watch stops a hung core's door), every new connection reaches the second.
#[cfg(target_os = "linux")]
#[test]
fn a_stopped_listener_leaves_its_reuseport_group() {
    worker().block_on(async {
        let mut first =
            Listening::bind_stream(None, "127.0.0.1:0", AcceptLimits::default()).unwrap();
        let port = first.local_addr().port();
        let mut second =
            Listening::bind_stream(None, &format!("127.0.0.1:{port}"), AcceptLimits::default())
                .unwrap();
        let stop = first.stopper();
        std::thread::spawn(move || stop.stop()).join().unwrap();
        let clients: Vec<_> = (0..32)
            .map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        for n in 0..clients.len() {
            assert!(
                tokio::time::timeout(Duration::from_secs(2), second.admit())
                    .await
                    .is_ok(),
                "connection {n} of {} did not reach the listener still in the group",
                clients.len()
            );
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            first.poll_accept_stream(&mut cx).is_pending(),
            "a stopped listener admits nothing"
        );
    });
}
