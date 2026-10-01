// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `grpc` DOOR AGAINST REAL tonic PEERS, on real sockets.
//!
//! Dialled: tonic's own server (`tonic::transport::Server`) on a TCP listener in the clear (h2c,
//! HTTP/2 by prior knowledge). Over TLS, the host offers exactly what `locate` answered, and the
//! same tonic service answers behind hyper's HTTP/2 server. Accepted: tonic's `Channel` dials a
//! listener the test holds, and the host answers each call through this door.
//!
//! The host (`common`) owns the socket and the clock, as the connector does in production.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{SIDE_ACCEPT, SIDE_DIAL, STATUS_CALLER_FAULT};
use common::*;

const QUIET: Duration = Duration::from_millis(300);
const BOUND: Duration = Duration::from_secs(5);

/// tonic's own server, in the clear, on a fresh port.
fn tonic_h2c(rt: &tokio::runtime::Runtime) -> std::net::SocketAddr {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    rt.spawn(
        tonic::transport::Server::builder()
            .add_service(TestSvc)
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
    );
    addr
}

/// A host dialled to tonic in the clear.
fn dialled_h2c(rt: &tokio::runtime::Runtime) -> Host {
    let addr = tonic_h2c(rt);
    let target = format!("http://{addr}");
    let mut host = Host::open(linked(), "{}", ROOMY);
    let loc = host.locate(&target).expect("locate");
    assert!(
        !loc.secure && loc.offer.is_empty(),
        "the clear offers nothing"
    );
    let tcp = rt
        .block_on(tokio::net::TcpStream::connect(loc.authority.as_str()))
        .expect("connect");
    host.begin(SIDE_DIAL, &target, "", Some(bridge(rt, tcp)));
    host
}

fn ended(stream: u64) -> impl Fn(&[Got]) -> bool {
    move |got| over(got, stream).is_some()
}

#[test]
fn a_unary_call_half_closes_and_tonic_answers_it() {
    let rt = runtime();
    let mut host = dialled_h2c(&rt);
    let t0 = host.now;
    let c = host.encode("/t.T/Unary", &[("x-meta", "one")], b"hello");
    assert_eq!(host.emit(1, &c, true, t0 + 30 * SEC), Outcome::Ready);
    let started = Instant::now();
    assert_eq!(host.pump_until(BOUND, ended(1)), Outcome::Ready);
    assert!(started.elapsed() < BOUND, "answered well inside the bound");
    let f = host.frames(1);
    println!("PROOF h2c unary: {:?}", String::from_utf8_lossy(&f[1]));
    assert_eq!(f[1..], [lpm(b"got:hello;timeout=30000000u;meta=one")]);
    assert_eq!(host.terminal(1).map(|t| t.0), Some(0));
    host.close();
}

#[test]
fn a_unary_peer_waits_for_end_stream_and_the_frames_end_is_it() {
    // tonic's unary handler reads the one message and then waits for the request's end (its
    // trailers or END_STREAM). A call whose head states no length and whose frame has not ended
    // leaves the stream open, and tonic does not answer. The bound keeps this test from hanging.
    let rt = runtime();
    let mut host = dialled_h2c(&rt);
    let mut c = b"path: /t.T/Unary\r\n\r\n".to_vec();
    // (The door's own head block: `path` names the method where no head word states it.)
    c.extend_from_slice(&lpm(b"hello"));
    assert_eq!(host.emit(1, &c, false, 0), Outcome::Ready);
    assert_eq!(
        host.pump_until(Duration::from_millis(800), ended(1)),
        Outcome::Ready
    );
    println!(
        "PROOF open request: terminal after 800ms = {:?}",
        host.terminal(1)
    );
    assert!(
        host.terminal(1).is_none(),
        "RED: without END_STREAM tonic's unary peer never answers"
    );
    // The frame's end is the half-close: END_STREAM goes out, and tonic answers.
    assert_eq!(host.emit(1, b"", true, 0), Outcome::Ready);
    assert_eq!(host.pump_until(BOUND, ended(1)), Outcome::Ready);
    println!("PROOF half-closed: terminal {:?}", host.terminal(1));
    assert_eq!(host.terminal(1).map(|t| t.0), Some(0));
    assert_eq!(host.frames(1)[1..], [lpm(b"got:hello;timeout=300000m")]);
    host.close();
}

#[test]
fn a_server_stream_from_tonic_arrives_message_by_message() {
    let rt = runtime();
    let mut host = dialled_h2c(&rt);
    host.ask(1, "/t.T/List", b"q", 0);
    assert_eq!(host.pump_until(BOUND, ended(1)), Outcome::Ready);
    assert_eq!(host.frames(1)[1..], [lpm(b"a"), lpm(b"bb"), lpm(b"ccc")]);
    assert_eq!(host.terminal(1).map(|t| t.0), Some(0));
    host.close();
}

#[test]
fn a_non_zero_status_from_tonic_fails_the_stream_with_its_message() {
    let rt = runtime();
    let mut host = dialled_h2c(&rt);
    host.ask(1, "/t.T/Fail", b"k", 0);
    assert_eq!(host.pump_until(BOUND, ended(1)), Outcome::Ready);
    println!("PROOF h2c fail: {:?}", host.terminal(1));
    assert_eq!(
        host.terminal(1),
        Some((5, STATUS_CALLER_FAULT, true, FAIL_TEXT.as_bytes().to_vec()))
    );
    host.close();
}

// ── TLS, ALPN h2 ─────────────────────────────────────────────────────────────────────────────────

struct Tls {
    addr: std::net::SocketAddr,
    roots: rustls::RootCertStore,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// tonic's service behind hyper's HTTP/2 server, over TLS offering `h2` only.
fn tls_peer(rt: &tokio::runtime::Runtime) -> Tls {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("cert");
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("server config");
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_h2(tls).await;
                }
            });
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).expect("root");
    Tls { addr, roots }
}

/// The ids in a ProtocolNameList.
fn ids(mut offer: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some((&n, rest)) = offer.split_first() {
        out.push(rest[..usize::from(n)].to_vec());
        offer = &rest[usize::from(n)..];
    }
    out
}

#[test]
fn over_tls_the_offer_is_h2_and_the_agreed_h2_carries_the_call() {
    let rt = runtime();
    let peer = tls_peer(&rt);
    let target = format!("https://localhost:{}", peer.addr.port());
    let mut host = Host::open(linked(), "{}", ROOMY);
    let loc = host.locate(&target).expect("locate");
    assert!(loc.secure);
    assert_eq!(ids(&loc.offer), vec![b"h2".to_vec()]);

    // The host's handshake offers exactly the framer's ids.
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(peer.roots)
        .with_no_client_auth();
    cfg.alpn_protocols = ids(&loc.offer);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let name = rustls::pki_types::ServerName::try_from(loc.name.clone()).expect("name");
    let tls = rt
        .block_on(async {
            let tcp = tokio::net::TcpStream::connect(peer.addr).await?;
            connector.connect(name, tcp).await
        })
        .expect("TLS");
    let agreed =
        String::from_utf8(tls.get_ref().1.alpn_protocol().expect("agreed").to_vec()).expect("text");
    println!(
        "PROOF tls: offered {:?}, agreed {agreed:?}",
        ids(&loc.offer)
    );
    assert_eq!(agreed, "h2");
    host.begin(SIDE_DIAL, &target, &agreed, Some(bridge(&rt, tls)));
    host.ask(1, "/t.T/Unary", b"sealed", 0);
    assert_eq!(host.pump_until(BOUND, ended(1)), Outcome::Ready);
    assert_eq!(host.frames(1)[1..], [lpm(b"got:sealed;timeout=300000m")]);
    assert_eq!(host.terminal(1).map(|t| t.0), Some(0));
    host.close();
}

#[test]
fn a_connection_that_agreed_another_protocol_is_refused_at_begin() {
    let mut host = Host::open(linked(), "{}", ROOMY);
    let r = host.try_begin(SIDE_DIAL, "https://peer.test", "http/1.1", None);
    println!("PROOF agreed http/1.1: begin answers {r:?}");
    assert_eq!(r, Outcome::Refused);
    host.close();
}

// ── accepted: tonic's client calls this door ─────────────────────────────────────────────────────

/// A listener the test holds, and tonic's (lazy) `Channel` to it: the channel connects on its
/// first call.
fn listening(
    rt: &tokio::runtime::Runtime,
) -> (
    std::sync::mpsc::Receiver<tokio::net::TcpStream>,
    tonic::transport::Channel,
) {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = std::sync::mpsc::channel();
    rt.spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = tx.send(tcp);
        }
    });
    // The lazy channel's connector lives on the runtime.
    let _in_rt = rt.enter();
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_lazy();
    (rx, channel)
}

/// A host that accepted the connection tonic's call opened.
fn accept(
    rt: &tokio::runtime::Runtime,
    rx: &std::sync::mpsc::Receiver<tokio::net::TcpStream>,
) -> Host {
    let tcp = rx.recv_timeout(BOUND).expect("tonic connected");
    let mut host = Host::open(linked(), "{}", ROOMY);
    host.begin(SIDE_ACCEPT, "", "", Some(bridge(rt, tcp)));
    host
}

fn last_in(stream: u64) -> impl Fn(&[Got]) -> bool {
    move |got| {
        got.iter()
            .any(|g| g.stream == stream && g.bytes.is_empty() && !g.coded() && !g.fields())
    }
}

#[test]
fn tonic_calls_the_door_unary_and_gets_the_hosts_answer() {
    let rt = runtime();
    let (rx, channel) = listening(&rt);
    let call = rt.spawn(async move {
        let mut g = tonic::client::Grpc::new(channel);
        g.ready().await.expect("ready");
        g.unary(
            tonic::Request::new(b"ping".to_vec()),
            http::uri::PathAndQuery::from_static("/t.T/Unary"),
            RawCodec,
        )
        .await
    });
    let mut host = accept(&rt, &rx);
    assert_eq!(host.pump_until(BOUND, last_in(1)), Outcome::Ready);
    let f = host.frames(1);
    let (method, target, _) = host.head_words(1).expect("the call's head words");
    assert_eq!((method.as_str(), target.as_str()), ("POST", "/t.T/Unary"));
    assert_eq!(field(&f[0], "path"), None, "no pseudo-field");
    assert_eq!(f[1..], [lpm(b"ping"), vec![]]);
    let mut answer = b"\r\n".to_vec();
    answer.extend_from_slice(&lpm(b"pong"));
    assert_eq!(host.emit(1, &answer, true, 0), Outcome::Ready);
    assert_eq!(host.refuse(1, b"grpc-status: 0\r\n"), Outcome::Ready);
    host.pump(QUIET);
    let r = rt
        .block_on(async { tokio::time::timeout(BOUND, call).await })
        .expect("bounded")
        .expect("join")
        .expect("OK");
    println!("PROOF accepted unary: client got {:?}", r.get_ref());
    assert_eq!(r.get_ref().as_ref(), b"pong");
    host.close();
}

#[test]
fn tonic_reads_a_stream_the_host_answers_message_by_message() {
    let rt = runtime();
    let (rx, channel) = listening(&rt);
    let call = rt.spawn(async move {
        let mut g = tonic::client::Grpc::new(channel);
        g.ready().await.expect("ready");
        let mut s = g
            .server_streaming(
                tonic::Request::new(b"q".to_vec()),
                http::uri::PathAndQuery::from_static("/t.T/List"),
                RawCodec,
            )
            .await?
            .into_inner();
        let mut got = Vec::new();
        while let Some(m) = s.message().await? {
            got.push(m.to_vec());
        }
        Ok::<_, tonic::Status>(got)
    });
    let mut host = accept(&rt, &rx);
    assert_eq!(host.pump_until(BOUND, last_in(1)), Outcome::Ready);
    assert_eq!(host.emit(1, b"\r\n", false, 0), Outcome::Ready);
    for m in [&b"a"[..], b"bb", b"ccc"] {
        assert_eq!(host.emit(1, &lpm(m), true, 0), Outcome::Ready);
        host.pump(Duration::from_millis(20));
    }
    assert_eq!(host.refuse(1, b"grpc-status: 0\r\n"), Outcome::Ready);
    host.pump(QUIET);
    let got = rt
        .block_on(async { tokio::time::timeout(BOUND, call).await })
        .expect("bounded")
        .expect("join")
        .expect("OK");
    assert_eq!(got, vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()]);
    host.close();
}

#[test]
fn tonic_sees_the_status_and_message_the_host_refuses_with() {
    let rt = runtime();
    let (rx, channel) = listening(&rt);
    let call = rt.spawn(async move {
        let mut g = tonic::client::Grpc::new(channel);
        g.ready().await.expect("ready");
        g.unary(
            tonic::Request::new(b"k".to_vec()),
            http::uri::PathAndQuery::from_static("/t.T/Get"),
            RawCodec,
        )
        .await
    });
    let mut host = accept(&rt, &rx);
    assert_eq!(host.pump_until(BOUND, last_in(1)), Outcome::Ready);
    // Trailers-only: nothing emitted, the status goes out in the one HEADERS frame.
    assert_eq!(
        host.refuse(1, b"grpc-status: 7\r\ngrpc-message: denied%20here\r\n"),
        Outcome::Ready
    );
    host.pump(QUIET);
    let st = rt
        .block_on(async { tokio::time::timeout(BOUND, call).await })
        .expect("bounded")
        .expect("join")
        .expect_err("a status");
    println!("PROOF accepted refusal: {:?} {:?}", st.code(), st.message());
    assert_eq!(
        (st.code(), st.message()),
        (tonic::Code::PermissionDenied, "denied here")
    );
    host.close();
}
