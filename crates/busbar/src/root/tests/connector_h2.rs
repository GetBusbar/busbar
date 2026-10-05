// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HTTP DOOR SPEAKS HTTP/2 UPSTREAM THROUGH THE ONE CONNECTOR, as 1.5.5's egress client did:
//! the linked http framer door, opened with the deployment's settings, dialled by the connector
//! over a real loopback socket to a far end that speaks HTTP/2 frames.
//!
//! * h2c PRIOR KNOWLEDGE (`advanced.upstream_h2_prior_knowledge`, or the deprecated
//!   `BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE` pin): no handshake, the connection preface first;
//! * ALPN OVER TLS: the connector secures the connection and offers what the framer's `locate`
//!   answered, `h2, http/1.1` (1.5.5's offer), and the framer speaks what was agreed;
//! * TWO REQUESTS, ONE CONNECTION: an exchange that ended whole hands its connection back to the
//!   worker's pool, and the next open to the same place rides it as the next stream (1, then 3), as
//!   1.5.5's pooled client sent it (`wire.h2|two-requests|same-conn`);
//! * on HTTP/1.1 a keep-alive answer whole hands the connection back the same way.
//!
//! The far end is written here from the frames up (preface, SETTINGS and its ACK, HEADERS, DATA,
//! PING ACK), so what the client put on the wire is read frame by frame rather than through a
//! library that would hide it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::conn::{ConnId, Conns, InstanceId, NeedId, OpenDesc, PieceKind, PollConns};
use busbar_contract::transport::trust::EgressTrust;
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::pool::PoolPosture;
use busbar_core_connector::registry::Transports;
use busbar_core_connector::{process, Connector, DEFAULT_CLASS};
use busbar_kernel::config::Destinations;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

const OWNER: InstanceId = InstanceId(7);
const NEED: NeedId = NeedId(0);
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One frame the far end read: type, flags, stream.
type Seen = (u8, u8, u32);

/// What the far end saw: every connection it accepted, every frame on them, and (TLS) the
/// protocols each ClientHello offered and the one agreed.
#[derive(Default)]
struct FarEnd {
    accepted: AtomicUsize,
    /// HTTP/2: answer only once this many request streams have ended on one connection (`0` or
    /// `1`: each at once), so an answer proves the requests were in flight TOGETHER.
    hold: AtomicUsize,
    frames: Mutex<Vec<Seen>>,
    offered: Mutex<Vec<Vec<Vec<u8>>>>,
    agreed: Mutex<Vec<Option<Vec<u8>>>>,
}

impl FarEnd {
    /// The streams the client opened a request on (a HEADERS frame each), in order.
    fn request_streams(&self) -> Vec<u32> {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .filter(|(t, _, _)| *t == 1)
            .map(|(_, _, s)| *s)
            .collect()
    }
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).expect("a small frame");
    let mut f = Vec::with_capacity(9 + payload.len());
    f.extend_from_slice(&len.to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Serve HTTP/2 on `s`: the server preface, every SETTINGS acknowledged, every PING answered, and
/// each request stream answered `:status 200` (HPACK static index 8) with the body `ok` once the
/// client ended it (and, under `hold`, once that many had ended).
async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, far: Arc<FarEnd>) {
    let mut pending: Vec<u32> = Vec::new();
    let mut pre = [0_u8; 24];
    if s.read_exact(&mut pre).await.is_err() {
        return;
    }
    assert_eq!(
        &pre, PREFACE,
        "the client speaks HTTP/2 from its first byte"
    );
    if s.write_all(&frame(4, 0, 0, &[])).await.is_err() {
        return;
    }
    loop {
        let mut h = [0_u8; 9];
        if s.read_exact(&mut h).await.is_err() {
            return;
        }
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let (kind, flags) = (h[3], h[4]);
        let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let mut payload = vec![0_u8; len];
        if s.read_exact(&mut payload).await.is_err() {
            return;
        }
        far.frames
            .lock()
            .expect("frames")
            .push((kind, flags, stream));
        let answer = match kind {
            // SETTINGS: acknowledged.
            4 if flags & 1 == 0 => frame(4, 1, 0, &[]),
            // PING: answered with its payload.
            6 if flags & 1 == 0 => frame(6, 1, 0, &payload),
            // HEADERS or DATA ending the stream: the answer, once `hold` streams have ended.
            0 | 1 if flags & 1 != 0 => {
                pending.push(stream);
                if pending.len() < far.hold.load(Ordering::SeqCst) {
                    continue;
                }
                let mut a = Vec::new();
                for stream in pending.drain(..) {
                    a.extend(frame(1, 4, stream, &[0x88]));
                    a.extend(frame(0, 1, stream, b"ok"));
                }
                a
            }
            // GOAWAY: the client is done.
            7 => return,
            _ => continue,
        };
        if s.write_all(&answer).await.is_err() {
            return;
        }
    }
}

/// A cleartext HTTP/2 far end on loopback.
async fn h2c_far_end() -> (u16, Arc<FarEnd>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_h2(s, Arc::clone(&seen)));
        }
    });
    (port, far)
}

/// A TLS far end on loopback, its certificate for `127.0.0.1` issued by the returned CA: it reads
/// the protocols each ClientHello offers, agrees `h2` (else `http/1.1`) and serves HTTP/2 when
/// `h2` was agreed.
async fn tls_far_end() -> (u16, Arc<FarEnd>, Vec<u8>) {
    let ca_key = rcgen::KeyPair::generate().expect("a CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("the CA");
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().expect("a leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("leaf params")
        .signed_by(&leaf_key, &issuer)
        .expect("the leaf");
    busbar_core_connector::tls::install_crypto_provider();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).expect("a key"),
        )
        .expect("a server config");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let (seen, config) = (Arc::clone(&seen), Arc::clone(&config));
            tokio::spawn(async move {
                let acceptor =
                    tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), s);
                let Ok(start) = acceptor.await else { return };
                let offered: Vec<Vec<u8>> = start
                    .client_hello()
                    .alpn()
                    .map(|names| names.map(<[u8]>::to_vec).collect())
                    .unwrap_or_default();
                seen.offered.lock().expect("offered").push(offered);
                let Ok(tls) = start.into_stream(config).await else {
                    return;
                };
                let agreed = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                seen.agreed.lock().expect("agreed").push(agreed.clone());
                if agreed.as_deref() == Some(b"h2") {
                    serve_h2(tls, seen).await;
                }
            });
        }
    });
    (port, far, ca.der().to_vec())
}

/// A cleartext HTTP/1.1 far end that keeps its connections alive: each request answered `200`
/// with a `content-length`, the connection left open for the next.
async fn h1_far_end() -> (u16, Arc<FarEnd>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0_u8; 4096];
                loop {
                    // One request: its head, then the body its content-length states.
                    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if got.len() < at + 4 + length {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => got.extend_from_slice(&buf[..n]),
                        }
                        continue;
                    }
                    got.drain(..at + 4 + length);
                    seen.frames.lock().expect("frames").push((1, 0, 0));
                    let answer = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                    if s.write_all(answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, far)
}

/// The connector over this build's linked transport doors, each opened with `settings`, judging
/// with a guard that admits loopback, securing with `trust`, pooling as 1.5.5's client did.
fn connector(settings: &TransportSettings, trust: &EgressTrust) -> Connector {
    let dest = crate::root::connector::guard_for(&Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    })
    .expect("the guard");
    let view = Transports::new(
        crate::root::connector::entries(crate::LINKED_TRANSPORT_DOORS, settings)
            .expect("the linked doors open"),
    )
    .expect("the view");
    let tls = busbar_core_connector::tls::client::build_client_config(trust).expect("the trust");
    let c = Connector::serving(
        view,
        process::judge(dest, &[]),
        Some(Arc::new(tls)),
        Arc::new(|_| {}),
    )
    .pooling(crate::root::connector::pool_posture(settings));
    c.declare_need(OWNER, NEED, "http", DEFAULT_CLASS)
        .expect("the http door serves the need");
    c
}

/// One request through the connector, read to its completion: the status and the body. The
/// connection is closed (handed back to the pool when the exchange ended whole).
async fn ask(c: &Connector, url: &str) -> (Option<u32>, Vec<u8>) {
    let conn = start(c, url);
    finish(c, conn).await
}

/// Open one request (its opening message on its way, nothing read).
fn start(c: &Connector, url: &str) -> ConnId {
    c.open(
        OWNER,
        NEED,
        &OpenDesc {
            target: url,
            fields: &[("content-type", b"application/json")],
            body: b"{\"model\":\"m\"}",
            timeout_ms: 5_000,
            method: b"POST",
            head_target: b"/v1/chat/completions",
            within: &[],
            member: "",
        },
    )
    .expect("the open")
}

/// Read `conn` to its completion: the status and the body; then close it.
async fn finish(c: &Connector, conn: ConnId) -> (Option<u32>, Vec<u8>) {
    let (mut status, mut body) = (None, Vec::new());
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let piece = tokio::time::timeout(
            Duration::from_secs(10),
            std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
        )
        .await
        .expect("the exchange completes without waiting for the connection to close")
        .expect("a piece");
        match piece.kind {
            PieceKind::Completion => break,
            PieceKind::Fields if status.is_none() => status = piece.status_code,
            PieceKind::Body => body.extend_from_slice(&buf[..piece.len]),
            _ => {}
        }
    }
    c.close(OWNER, conn).expect("the close");
    (status, body)
}

fn pooled(settings: TransportSettings) -> TransportSettings {
    TransportSettings {
        pool_max_idle_per_host: 32,
        pool_idle_timeout_secs: 90,
        ..settings
    }
}

/// h2c PRIOR KNOWLEDGE: the door opened with the prior-knowledge key speaks HTTP/2 from its first
/// byte, and the second request rides the first one's connection as stream 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn h2c_prior_knowledge_two_requests_ride_one_connection() {
    let (port, far) = h2c_far_end().await;
    let settings = pooled(TransportSettings {
        upstream_h2_prior_knowledge: true,
        ..TransportSettings::default()
    });
    let c = connector(&settings, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    for _ in 0..2 {
        let (status, body) = ask(&c, &url).await;
        assert_eq!(status, Some(200));
        assert_eq!(body, b"ok");
    }
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(far.request_streams(), vec![1, 3], "stream 1, then stream 3");
}

/// The deprecated env pin opens the door the same way: `client_settings` reads it over the config.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_deprecated_env_pin_turns_prior_knowledge_on() {
    let (port, far) = h2c_far_end().await;
    let limits = busbar_kernel::config::LimitsResolved::default();
    assert!(!limits.upstream_h2_prior_knowledge);
    let settings = crate::root::policy::client_settings_under(&limits, |name| {
        (name == "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE").then(|| "1".into())
    });
    let c = connector(&settings, &EgressTrust::default());
    let (status, body) = ask(&c, &format!("http://127.0.0.1:{port}/v1/chat/completions")).await;
    assert_eq!((status, body.as_slice()), (Some(200), &b"ok"[..]));
    assert_eq!(far.request_streams(), vec![1]);
}

/// ALPN OVER TLS: the connector offers the framer's `h2, http/1.1` in the ClientHello (no offer of
/// its own: the registration states none), the far end agrees `h2`, the framer speaks HTTP/2 over
/// it, and the second request rides the same connection as stream 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn alpn_h2_over_tls_is_the_framers_offer_and_one_connection_carries_two() {
    let (port, far, ca) = tls_far_end().await;
    let settings = pooled(TransportSettings::default());
    let trust = EgressTrust {
        extra_anchors: vec![ca],
        ..EgressTrust::default()
    };
    let c = connector(&settings, &trust);
    let url = format!("https://127.0.0.1:{port}/v1/chat/completions");
    for _ in 0..2 {
        let (status, body) = ask(&c, &url).await;
        assert_eq!((status, body.as_slice()), (Some(200), &b"ok"[..]));
    }
    assert_eq!(
        *far.offered.lock().expect("offered"),
        vec![vec![b"h2".to_vec(), b"http/1.1".to_vec()]],
        "1.5.5's offer, made once: one handshake"
    );
    assert_eq!(
        *far.agreed.lock().expect("agreed"),
        vec![Some(b"h2".to_vec())]
    );
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(far.request_streams(), vec![1, 3]);
}

/// Under the http1-only key the offer is `http/1.1` alone, as 1.5.5's was.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_http1_only_key_offers_http1_alone() {
    let (port, far, ca) = tls_far_end().await;
    let settings = TransportSettings {
        upstream_http1_only: true,
        ..TransportSettings::default()
    };
    let trust = EgressTrust {
        extra_anchors: vec![ca],
        ..EgressTrust::default()
    };
    let c = connector(&settings, &trust);
    let url = format!("https://127.0.0.1:{port}/v1/chat/completions");
    let conn = c
        .open(
            OWNER,
            NEED,
            &OpenDesc {
                target: &url,
                fields: &[],
                body: b"",
                timeout_ms: 5_000,
                method: b"GET",
                head_target: b"/v1/chat/completions",
                within: &[],
                member: "",
            },
        )
        .expect("the open");
    let mut buf = [0_u8; 1024];
    // The far end agrees and serves nothing on http/1.1: the handshake is what this reads.
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
    )
    .await;
    let _ = c.close(OWNER, conn);
    assert_eq!(
        *far.offered.lock().expect("offered"),
        vec![vec![b"http/1.1".to_vec()]]
    );
}

/// HTTP/1.1 keep-alive: an answer whole ends the exchange (not the far end closing), and the next
/// request rides the same connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_http1_keep_alive_connection_carries_the_next_request() {
    let (port, far) = h1_far_end().await;
    let c = connector(
        &pooled(TransportSettings::default()),
        &EgressTrust::default(),
    );
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    for _ in 0..2 {
        let (status, body) = ask(&c, &url).await;
        assert_eq!((status, body.as_slice()), (Some(200), &b"ok"[..]));
    }
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(far.request_streams().len(), 2, "two requests");
}

/// No pool posture, no reuse: each open dials (the posture is the deployment's).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn without_a_pool_each_request_dials() {
    let (port, far) = h2c_far_end().await;
    let settings = TransportSettings {
        upstream_h2_prior_knowledge: true,
        pool_max_idle_per_host: 0,
        ..TransportSettings::default()
    };
    assert_eq!(
        crate::root::connector::pool_posture(&settings),
        PoolPosture {
            max_idle_per_host: 0,
            idle_timeout: Duration::from_secs(settings.pool_idle_timeout_secs),
        }
    );
    let c = connector(&settings, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    for _ in 0..2 {
        let (status, _) = ask(&c, &url).await;
        assert_eq!(status, Some(200));
    }
    assert_eq!(far.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(far.request_streams(), vec![1, 1]);
}

/// Drive `conn` until `ready` holds (each read attempt bounded, its piece, if any, ignored).
async fn drive_until(c: &Connector, conn: ConnId, ready: impl Fn() -> bool) {
    let mut buf = vec![0_u8; 4096];
    for _ in 0..200 {
        if ready() {
            return;
        }
        let _ = tokio::time::timeout(
            Duration::from_millis(20),
            std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
        )
        .await;
    }
    assert!(ready(), "the condition held within the bound");
}

/// THE MUX (ARCHITECT ruling Q-L18-MUX): two CONCURRENT requests to one h2c origin share one
/// connection as streams 1 and 3. The far end answers neither until both have arrived, so the
/// answers prove both were in flight together on the one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn concurrent_h2c_requests_share_one_connection() {
    let (port, far) = h2c_far_end().await;
    far.hold.store(2, Ordering::SeqCst);
    let settings = pooled(TransportSettings {
        upstream_h2_prior_knowledge: true,
        ..TransportSettings::default()
    });
    let c = connector(&settings, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let (a, b) = (start(&c, &url), start(&c, &url));
    let (ra, rb) = tokio::join!(finish(&c, a), finish(&c, b));
    assert_eq!((ra.0, ra.1.as_slice()), (Some(200), &b"ok"[..]));
    assert_eq!((rb.0, rb.1.as_slice()), (Some(200), &b"ok"[..]));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(far.request_streams(), vec![1, 3], "two streams of it");
    // The shared line goes back to the pool whole: a third request rides it as stream 5.
    far.hold.store(0, Ordering::SeqCst);
    let (status, _) = ask(&c, &url).await;
    assert_eq!(status, Some(200));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(far.request_streams(), vec![1, 3, 5]);
}

/// Over TLS the protocol is known once the handshake agreed it: a request opened while the first
/// one's answer is outstanding on an agreed `h2` connection rides it as stream 3.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_concurrent_request_rides_an_agreed_h2_tls_connection() {
    let (port, far, ca) = tls_far_end().await;
    far.hold.store(2, Ordering::SeqCst);
    let trust = EgressTrust {
        extra_anchors: vec![ca],
        ..EgressTrust::default()
    };
    let c = connector(&pooled(TransportSettings::default()), &trust);
    let url = format!("https://127.0.0.1:{port}/v1/chat/completions");
    let a = start(&c, &url);
    drive_until(&c, a, || far.request_streams().len() == 1).await;
    let b = start(&c, &url);
    let (ra, rb) = tokio::join!(finish(&c, a), finish(&c, b));
    assert_eq!((ra.0, rb.0), (Some(200), Some(200)));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(
        far.offered.lock().expect("offered").len(),
        1,
        "one handshake"
    );
    assert_eq!(far.request_streams(), vec![1, 3]);
}

/// HTTP/1.1 stays one request per connection: two concurrent requests take two connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn concurrent_http1_requests_each_take_a_connection() {
    let (port, far) = h1_far_end().await;
    let c = connector(
        &pooled(TransportSettings::default()),
        &EgressTrust::default(),
    );
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let (a, b) = (start(&c, &url), start(&c, &url));
    let (ra, rb) = tokio::join!(finish(&c, a), finish(&c, b));
    assert_eq!((ra.0, rb.0), (Some(200), Some(200)));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 2, "a connection each");
}

/// An h2c far end whose FIRST connection takes its first request, says nothing, and on `rst` is
/// reset (SO_LINGER 0); every connection after it is served as [`serve_h2`] serves.
async fn resetting_far_end() -> (u16, Arc<FarEnd>, tokio::sync::mpsc::Sender<()>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    let (rst, mut reset) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let Ok((mut s, _)) = l.accept().await else {
            return;
        };
        seen.accepted.fetch_add(1, Ordering::SeqCst);
        let first = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut pre = [0_u8; 24];
            if s.read_exact(&mut pre).await.is_err() {
                return;
            }
            let _ = s.write_all(&frame(4, 0, 0, &[])).await;
            let mut buf = [0_u8; 4096];
            // Read until the request's HEADERS (type 1 on stream 1) has been seen, roughly: the
            // test waits on the recorded frame.
            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == [0x01, 0x04, 0x00, 0x00]) || got.len() < 24 {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            first.frames.lock().expect("frames").push((1, 0, 1));
            let _ = reset.recv().await;
            // A reset, not a goodbye: SO_LINGER 0 (its blocking-on-drop warning is about a
            // non-zero linger; zero drops at once).
            #[allow(deprecated)]
            let _ = s.set_linger(Some(Duration::ZERO));
            drop(s);
        });
        while let Ok((s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_h2(s, Arc::clone(&seen)));
        }
    });
    (port, far, rst)
}

/// THE ONE REDIAL (ARCHITECT ruling Q-L18-RETRY): a request lent a pooled h2 line the far end has
/// reset, before any byte of the request left, is dialled once on a fresh connection and served
/// there: the caller sees one answered exchange, no failover. The request the reset cut, whose
/// bytes had left, is not re-sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_lent_line_reset_before_any_byte_left_is_redialled_once() {
    let (port, far, rst) = resetting_far_end().await;
    let settings = pooled(TransportSettings {
        upstream_h2_prior_knowledge: true,
        ..TransportSettings::default()
    });
    let c = connector(&settings, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let a = start(&c, &url);
    drive_until(&c, a, || far.request_streams().len() == 1).await;
    rst.send(()).await.expect("the reset");
    // The reset reaches this side; nothing drives the line meanwhile.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = start(&c, &url);
    let (status, body) = finish(&c, b).await;
    assert_eq!((status, body.as_slice()), (Some(200), &b"ok"[..]));
    assert_eq!(
        far.accepted.load(Ordering::SeqCst),
        2,
        "the redial is one fresh connection"
    );
    assert_eq!(
        far.request_streams(),
        vec![1, 1],
        "the cut request once, the redialled one once, as stream 1 of its own connection"
    );
    let mut buf = [0_u8; 1024];
    let cut = tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| c.poll_read(OWNER, a, cx, &mut buf)),
    )
    .await
    .expect("the cut request answers at once");
    assert!(
        cut.is_err() || cut.as_ref().is_ok_and(|p| p.kind == PieceKind::Completion),
        "the request whose bytes had left is not re-sent: {cut:?}"
    );
    let _ = c.close(OWNER, a);
    assert_eq!(far.accepted.load(Ordering::SeqCst), 2);
}

/// An h2c far end that answers stream 1 and then, on the next request, closes the connection
/// without answering it.
async fn closing_far_end() -> (u16, Arc<FarEnd>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut pre = [0_u8; 24];
                if s.read_exact(&mut pre).await.is_err() {
                    return;
                }
                let _ = s.write_all(&frame(4, 0, 0, &[])).await;
                loop {
                    let mut h = [0_u8; 9];
                    if s.read_exact(&mut h).await.is_err() {
                        return;
                    }
                    let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
                    let (kind, flags) = (h[3], h[4]);
                    let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
                    let mut payload = vec![0_u8; len];
                    if s.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    seen.frames
                        .lock()
                        .expect("frames")
                        .push((kind, flags, stream));
                    let answer = match kind {
                        4 if flags & 1 == 0 => frame(4, 1, 0, &[]),
                        6 if flags & 1 == 0 => frame(6, 1, 0, &payload),
                        // The second request: the connection closes under it.
                        1 if stream > 1 => return,
                        0 | 1 if flags & 1 != 0 => {
                            let mut a = frame(1, 4, stream, &[0x88]);
                            a.extend(frame(0, 1, stream, b"ok"));
                            a
                        }
                        _ => continue,
                    };
                    if s.write_all(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, far)
}

/// NO DOUBLE SEND: a request whose bytes LEFT on a pooled line before the far end closed it is not
/// redialled; it fails, and its far end saw it exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_request_whose_bytes_left_is_not_redialled() {
    let (port, far) = closing_far_end().await;
    let settings = pooled(TransportSettings {
        upstream_h2_prior_knowledge: true,
        ..TransportSettings::default()
    });
    let c = connector(&settings, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let (status, _) = ask(&c, &url).await;
    assert_eq!(status, Some(200));
    let b = start(&c, &url);
    let mut buf = [0_u8; 1024];
    let mut answered = false;
    loop {
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| c.poll_read(OWNER, b, cx, &mut buf)),
        )
        .await
        .expect("the closed line answers at once");
        match got {
            Err(_) => break,
            Ok(p) if p.kind == PieceKind::Completion => break,
            Ok(p) => answered |= p.kind == PieceKind::Fields,
        }
    }
    let _ = c.close(OWNER, b);
    assert!(!answered, "nothing answered the request the close cut");
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "no redial");
    assert_eq!(
        far.request_streams(),
        vec![1, 3],
        "the cut request was sent once"
    );
}
