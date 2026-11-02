// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    fn request_stream_ids(&self) -> Vec<u32> {
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
            4 if flags & 1 == 0 => frame(4, 1, 0, &[]),

            6 if flags & 1 == 0 => frame(6, 1, 0, &payload),

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

            7 => return,
            _ => continue,
        };
        if s.write_all(&answer).await.is_err() {
            return;
        }
    }
}

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

async fn tls_far_end() -> (u16, Arc<FarEnd>, Vec<u8>) {
    let (config, ca) = tls_server();
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_tls(s, Arc::clone(&seen), Arc::clone(&config)));
        }
    });
    (port, far, ca)
}

fn tls_server() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
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
    (Arc::new(config), ca.der().to_vec())
}

async fn accept_tls(
    s: tokio::net::TcpStream,
    seen: &FarEnd,
    config: Arc<rustls::ServerConfig>,
) -> Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), s);
    let start = acceptor.await.ok()?;
    let offered: Vec<Vec<u8>> = start
        .client_hello()
        .alpn()
        .map(|names| names.map(<[u8]>::to_vec).collect())
        .unwrap_or_default();
    seen.offered.lock().expect("offered").push(offered);
    let tls = start.into_stream(config).await.ok()?;
    let agreed = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    seen.agreed.lock().expect("agreed").push(agreed);
    Some(tls)
}

async fn serve_tls(s: tokio::net::TcpStream, seen: Arc<FarEnd>, config: Arc<rustls::ServerConfig>) {
    if let Some(tls) = accept_tls(s, &seen, config).await {
        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            serve_h2(tls, seen).await;
        }
    }
}

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

fn connector(settings: &TransportSettings, trust: &EgressTrust) -> Connector {
    let dest = crate::root::connector::guard_for(&Destinations {
        block_private_addresses: false,
        ..Destinations::default()
    })
    .expect("the guard");
    connector_judged(settings, trust, dest)
}

fn connector_judged(
    settings: &TransportSettings,
    trust: &EgressTrust,
    dest: Arc<dyn busbar_kernel::host_services::DestJudge>,
) -> Connector {
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
        Arc::new(|_, _| {}),
    )
    .pooling(crate::root::connector::pool_posture(settings));

    c.declare_need(
        OWNER,
        NEED,
        busbar_core_admin::admin_codec::claims::TRANSPORT,
        DEFAULT_CLASS,
    )
    .expect("the request/response framer's door serves the need");
    c
}

async fn ask(c: &Connector, url: &str) -> (Option<u32>, Vec<u8>) {
    let conn = start(c, url);
    finish(c, conn).await
}

fn start(c: &Connector, url: &str) -> ConnId {
    start_need(c, NEED, url)
}

fn start_need(c: &Connector, need: NeedId, url: &str) -> ConnId {
    c.open(
        OWNER,
        need,
        &OpenDesc {
            target: url,
            fields: &[("content-type", b"application/json")],
            body: busbar_contract::conn::Bytes::from_static(b"{\"model\":\"m\"}"),
            timeout_ms: 5_000,
            method: b"POST",
            head_target: b"/v1/chat/completions",
            within: &[],
            member: "",
            unit: 0,
        },
    )
    .expect("the open")
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn recovered_transport_and_pool_settings_leave_the_bootstrap_anchor_serving() {
    let (anchor_port, anchor_far) = h1_far_end().await;
    let (effective_port, effective_far) = h2c_far_end().await;
    let base = pooled(TransportSettings::default());
    let c = connector(&base, &EgressTrust::default());
    let anchor_url = format!("http://127.0.0.1:{anchor_port}/store-overlay");
    let pending_anchor = start(&c, &anchor_url);
    let effective = TransportSettings {
        upstream_h2_prior_knowledge: true,
        pool_max_idle_per_host: 0,
        ..base
    };
    super::finalize_prepared(
        &c,
        crate::LINKED_TRANSPORT_DOORS,
        &effective,
        &["127.0.0.1:19080", "127.0.0.1:19081"],
        crate::root::registry::Dropped::NONE,
    )
    .expect("effective transports open before publication");
    c.declare_need(
        OWNER,
        NeedId(1),
        busbar_core_admin::admin_codec::claims::TRANSPORT,
        DEFAULT_CLASS,
    )
    .unwrap();
    assert_eq!(
        finish(&c, pending_anchor).await,
        (Some(200), b"ok".to_vec())
    );
    let effective_url = format!("http://127.0.0.1:{effective_port}/request");
    for _ in 0..2 {
        let request = start_need(&c, NeedId(1), &effective_url);
        assert_eq!(finish(&c, request).await, (Some(200), b"ok".to_vec()));
    }
    assert_eq!(
        effective_far.accepted.load(Ordering::SeqCst),
        2,
        "effective pooling is disabled"
    );
    assert_eq!(
        effective_far.request_stream_ids(),
        vec![1, 1],
        "fresh effective doors speak h2c"
    );

    assert_eq!(ask(&c, &anchor_url).await, (Some(200), b"ok".to_vec()));
    assert_eq!(anchor_far.frames.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn failed_effective_transport_preparation_keeps_the_anchor_and_base_view() {
    let (port, far) = h1_far_end().await;
    let base = pooled(TransportSettings::default());
    let c = connector(&base, &EgressTrust::default());
    let scheme = busbar_core_admin::admin_codec::claims::TRANSPORT;
    let base_door = c.framer_for(scheme).unwrap();
    let url = format!("http://127.0.0.1:{port}/store-overlay");
    let pending_anchor = start(&c, &url);

    let repeated: Vec<_> = crate::LINKED_TRANSPORT_DOORS
        .iter()
        .chain(crate::LINKED_TRANSPORT_DOORS.iter())
        .copied()
        .collect();
    let effective = TransportSettings {
        upstream_h2_prior_knowledge: true,
        pool_max_idle_per_host: 0,
        ..base
    };
    assert!(super::finalize_prepared(
        &c,
        &repeated,
        &effective,
        &[],
        crate::root::registry::Dropped::NONE,
    )
    .is_err());
    assert!(
        Arc::ptr_eq(&base_door, &c.framer_for(scheme).unwrap()),
        "no effective door was published"
    );
    assert_eq!(
        finish(&c, pending_anchor).await,
        (Some(200), b"ok".to_vec())
    );
    assert_eq!(ask(&c, &url).await, (Some(200), b"ok".to_vec()));
    assert_eq!(
        far.accepted.load(Ordering::SeqCst),
        1,
        "the base pool was not changed on failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn recovered_http1_only_changes_the_offer_of_a_newly_declared_need() {
    let (port, far, ca) = tls_far_end().await;
    let base = TransportSettings::default();
    let c = connector(
        &base,
        &EgressTrust {
            extra_anchors: vec![ca],
            ..EgressTrust::default()
        },
    );
    let effective = TransportSettings {
        upstream_http1_only: true,
        ..base
    };
    super::finalize_prepared(
        &c,
        crate::LINKED_TRANSPORT_DOORS,
        &effective,
        &[],
        crate::root::registry::Dropped::NONE,
    )
    .unwrap();
    c.declare_over(
        OWNER,
        NeedId(1),
        busbar_core_admin::admin_codec::claims::TRANSPORT,
    )
    .unwrap();
    let url = format!("https://127.0.0.1:{port}/request");
    let conn = start_need(&c, NeedId(1), &url);
    let mut buf = [0; 1024];
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
    )
    .await;
    c.close(OWNER, conn).unwrap();
    assert_eq!(
        *far.offered.lock().unwrap(),
        vec![vec![b"http/1.1".to_vec()]]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn recovered_body_cap_and_request_timeout_apply_while_the_anchor_keeps_its_door() {
    let (port, _) = h1_far_end().await;
    let base = TransportSettings::default();
    let c = connector(&base, &EgressTrust::default());
    let url = format!("http://127.0.0.1:{port}/store-overlay");
    let effective = TransportSettings {
        request_body_max_bytes: 8,
        request_timeout_secs: 1,
        ..base
    };
    super::finalize_prepared(
        &c,
        crate::LINKED_TRANSPORT_DOORS,
        &effective,
        &[],
        crate::root::registry::Dropped::NONE,
    )
    .unwrap();
    c.declare_over(
        OWNER,
        NeedId(1),
        busbar_core_admin::admin_codec::claims::TRANSPORT,
    )
    .unwrap();

    assert_eq!(ask(&c, &url).await, (Some(200), b"ok".to_vec()));
    match c.open(
        OWNER,
        NeedId(1),
        &OpenDesc {
            target: &url,
            body: busbar_contract::conn::Bytes::from_static(b"123456789"),
            method: b"POST",
            head_target: b"/request",
            ..OpenDesc::default()
        },
    ) {
        Err(error) => assert_ne!(error, busbar_contract::conn::ConnError::Pending),
        Ok(conn) => {
            let mut buf = [0; 1024];
            let answer = tokio::time::timeout(
                Duration::from_secs(3),
                std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
            )
            .await
            .expect("oversized effective body refuses promptly");
            assert!(answer.is_err());
            c.close(OWNER, conn).unwrap();
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_url = format!("http://{}/request", listener.local_addr().unwrap());
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        held_tx.send(socket).unwrap();
    });
    let conn = c
        .open(
            OWNER,
            NeedId(1),
            &OpenDesc {
                target: &stalled_url,
                method: b"GET",
                head_target: b"/request",
                ..OpenDesc::default()
            },
        )
        .unwrap();
    let mut buf = [0; 1024];
    let answer = tokio::time::timeout(
        Duration::from_secs(3),
        std::future::poll_fn(|cx| c.poll_read(OWNER, conn, cx, &mut buf)),
    )
    .await
    .expect("the recovered one-second request clock must expire without a caller timeout");
    assert!(answer.is_err());
    let socket = tokio::time::timeout(Duration::from_secs(3), held_rx)
        .await
        .expect("the timed-out request reached its held-open peer")
        .unwrap();
    c.close(OWNER, conn).unwrap();
    drop(socket);
    server.await.unwrap();
    assert_eq!(ask(&c, &url).await, (Some(200), b"ok".to_vec()));
}

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
    assert_eq!(
        far.request_stream_ids(),
        vec![1, 3],
        "stream 1, then stream 3"
    );
}

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
    assert_eq!(far.request_stream_ids(), vec![1]);
}

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
    assert_eq!(far.request_stream_ids(), vec![1, 3]);
}

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
                body: busbar_contract::conn::Bytes::from_static(b""),
                timeout_ms: 5_000,
                method: b"GET",
                head_target: b"/v1/chat/completions",
                within: &[],
                member: "",
                unit: 0,
            },
        )
        .expect("the open");
    let mut buf = [0_u8; 1024];

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
    assert_eq!(far.request_stream_ids().len(), 2, "two requests");
}

async fn closing_h1_far_end() -> (u16, Arc<FarEnd>, Arc<tokio::sync::Notify>) {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    let close = Arc::new(tokio::sync::Notify::new());
    let closing = Arc::clone(&close);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let (seen, closing) = (Arc::clone(&seen), Arc::clone(&closing));
            tokio::spawn(async move {
                let (mut got, mut buf) = (Vec::new(), [0_u8; 4096]);
                loop {
                    if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            break;
                        }
                    }
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                seen.frames.lock().expect("frames").push((1, 0, 0));
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;

                closing.notified().await;
            });
        }
    });
    (port, far, close)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_idle_http1_line_the_far_end_closed_is_let_go_not_spun_on() {
    let (port, far, close) = closing_h1_far_end().await;
    let c = Arc::new(connector(
        &pooled(TransportSettings::default()),
        &EgressTrust::default(),
    ));
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");

    let (ask_tx, asks) = std::sync::mpsc::channel::<()>();
    let (opened_tx, opened) = std::sync::mpsc::channel();
    let (on, at, rt) = (
        Arc::clone(&c),
        url.clone(),
        tokio::runtime::Handle::current(),
    );
    std::thread::spawn(move || {
        let _entered = rt.enter();
        while asks.recv().is_ok() {
            let _ = opened_tx.send(start(&on, &at));
        }
    });
    let opened = Arc::new(Mutex::new(opened));
    let open = || {
        ask_tx.send(()).expect("the opening thread");
        let opened = Arc::clone(&opened);
        tokio::task::spawn_blocking(move || {
            opened
                .lock()
                .expect("opened")
                .recv_timeout(Duration::from_secs(5))
        })
    };
    let a = open()
        .await
        .expect("the wait")
        .expect("the first open answers");
    let (status, body) = finish(&c, a).await;
    assert_eq!((status, body.as_slice()), (Some(200), &b""[..]));

    close.notify_one();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = open()
        .await
        .expect("the wait")
        .expect("the open answers at once: the far end's end is read once, not spun on");
    let (status, body) = finish(&c, b).await;
    assert_eq!((status, body.as_slice()), (Some(200), &b""[..]));
    assert_eq!(
        far.accepted.load(Ordering::SeqCst),
        2,
        "the spent line is let go and the open dials afresh"
    );
}

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
    assert_eq!(far.request_stream_ids(), vec![1, 1]);
}

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
    assert_eq!(far.request_stream_ids(), vec![1, 3], "two requests on it");

    far.hold.store(0, Ordering::SeqCst);
    let (status, _) = ask(&c, &url).await;
    assert_eq!(status, Some(200));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(far.request_stream_ids(), vec![1, 3, 5]);
}

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
    drive_until(&c, a, || far.request_stream_ids().len() == 1).await;
    let b = start(&c, &url);
    let (ra, rb) = tokio::join!(finish(&c, a), finish(&c, b));
    assert_eq!((ra.0, rb.0), (Some(200), Some(200)));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "one connection");
    assert_eq!(
        far.offered.lock().expect("offered").len(),
        1,
        "one handshake"
    );
    assert_eq!(far.request_stream_ids(), vec![1, 3]);
}

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

            let mut got = Vec::new();
            while !got.windows(4).any(|w| w == [0x01, 0x04, 0x00, 0x00]) || got.len() < 24 {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            first.frames.lock().expect("frames").push((1, 0, 1));
            let _ = reset.recv().await;

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
    drive_until(&c, a, || far.request_stream_ids().len() == 1).await;
    rst.send(()).await.expect("the reset");

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
        far.request_stream_ids(),
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
        far.request_stream_ids(),
        vec![1, 3],
        "the cut request was sent once"
    );
}

async fn breaking_far_end() -> (
    u16,
    Arc<FarEnd>,
    Vec<u8>,
    tokio::sync::mpsc::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (config, ca) = tls_server();
    let l = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = l.local_addr().expect("its address").port();
    let far = Arc::new(FarEnd::default());
    let seen = Arc::clone(&far);
    let (break_in, mut broken) = tokio::sync::mpsc::channel::<()>(1);
    let (wrote_tx, wrote) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let Ok((s, _)) = l.accept().await else {
            return;
        };
        seen.accepted.fetch_add(1, Ordering::SeqCst);
        let (first, first_config) = (Arc::clone(&seen), Arc::clone(&config));
        tokio::spawn(async move {
            let Some(mut tls) = accept_tls(s, &first, first_config).await else {
                return;
            };
            let mut pre = [0_u8; 24];
            if tls.read_exact(&mut pre).await.is_err() {
                return;
            }
            let _ = tls.write_all(&frame(4, 0, 0, &[])).await;
            let mut wrote_tx = Some(wrote_tx);

            let (mut got, mut buf) = (Vec::new(), [0_u8; 4096]);
            loop {
                tokio::select! {
                    r = tls.read(&mut buf) => match r {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    },
                    Some(()) = broken.recv() => {
                        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                        record.extend_from_slice(&[0_u8; 0x20]);
                        let _ = tls.get_mut().0.write_all(&record).await;
                        if let Some(tx) = wrote_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
                while got.len() >= 9 {
                    let len = u32::from_be_bytes([0, got[0], got[1], got[2]]) as usize;
                    if got.len() < 9 + len {
                        break;
                    }
                    let stream = u32::from_be_bytes([got[5], got[6], got[7], got[8]]) & 0x7fff_ffff;
                    first
                        .frames
                        .lock()
                        .expect("frames")
                        .push((got[3], got[4], stream));
                    got.drain(..9 + len);
                }
            }
        });
        while let Ok((s, _)) = l.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_tls(s, Arc::clone(&seen), Arc::clone(&config)));
        }
    });
    (port, far, ca, break_in, wrote)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_request_whose_opening_left_before_the_line_failed_is_not_redialled() {
    let (port, far, ca, break_in, wrote) = breaking_far_end().await;
    let trust = EgressTrust {
        extra_anchors: vec![ca],
        ..EgressTrust::default()
    };
    let c = connector(&pooled(TransportSettings::default()), &trust);
    let url = format!("https://127.0.0.1:{port}/v1/chat/completions");
    let a = start(&c, &url);
    drive_until(&c, a, || far.request_stream_ids().len() == 1).await;
    break_in.send(()).await.expect("the break");
    wrote.await.expect("the record is on the wire");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let b = start(&c, &url);
    let mut buf = [0_u8; 1024];
    let mut answered = false;
    loop {
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| c.poll_read(OWNER, b, cx, &mut buf)),
        )
        .await
        .expect("the broken line answers at once");
        match got {
            Err(_) => break,
            Ok(p) if p.kind == PieceKind::Completion => break,
            Ok(p) => answered |= p.kind == PieceKind::Fields,
        }
    }

    for _ in 0..250 {
        if far.request_stream_ids().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = c.close(OWNER, b);
    let _ = c.close(OWNER, a);
    assert!(!answered, "nothing answered the request the break cut");
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "no redial");
    assert_eq!(
        far.request_stream_ids(),
        vec![1, 3],
        "the cut request was sent once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_idn_destination_resolves_as_its_punycode_name_and_is_served() {
    use busbar_core_connector::guard::{Guard, Resolve, Resolved};

    const PUNYCODE: &str = "xn--bcher-kva.example";

    /// The names asked, answered from a table: the punycode name is the loopback far end.
    #[derive(Default)]
    struct Names(Mutex<Vec<String>>);
    impl Resolve for Names {
        fn resolve(&self, host: &str, done: Resolved) {
            self.0.lock().expect("names").push(host.to_owned());
            done(if host == PUNYCODE {
                Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()])
            } else {
                Err("NXDOMAIN".into())
            });
        }
    }
    let asked = |names: &Names| std::mem::take(&mut *names.0.lock().expect("names"));

    let (port, far) = h1_far_end().await;
    let guard = Guard::from_config(&Destinations {
        block_private_addresses: true,
        allow: vec![PUNYCODE.to_owned()],
        ..Destinations::default()
    })
    .expect("the deployment's guard");
    let names = Arc::new(Names::default());
    let resolver = Arc::clone(&names) as Arc<dyn Resolve>;
    let dest = Arc::new(process::GuardJudge::new(guard, resolver));

    let (tx, rx) = std::sync::mpsc::channel();
    let dial = process::judge(Arc::clone(&dest) as _, &[]);
    let at_once = dial.judge_dial(
        &format!("b\u{fc}cher.example:{port}"),
        DEFAULT_CLASS,
        Box::new(move |v| {
            let _ = tx.send(v);
        }),
    );
    let judged = match at_once {
        Some(v) => v,
        None => rx.recv_timeout(Duration::from_secs(10)).expect("answered"),
    };
    let pinned = judged.expect("the allowlisted IDN destination is admitted");
    let at = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
    assert_eq!(pinned, at);
    assert_eq!(
        asked(&names),
        vec![PUNYCODE.to_owned()],
        "the punycode name, once"
    );

    let c = connector_judged(&TransportSettings::default(), &EgressTrust::default(), dest);
    let host = busbar_contract::net::url_host_to_ascii("b\u{fc}cher.example")
        .expect("an IDN name maps")
        .into_owned();
    let (status, body) = ask(&c, &format!("http://{host}:{port}/v1/chat/completions")).await;
    assert_eq!((status, body.as_slice()), (Some(200), &b"ok"[..]));
    assert_eq!(far.accepted.load(Ordering::SeqCst), 1, "served");
    assert_eq!(
        asked(&names),
        vec![PUNYCODE.to_owned()],
        "the dial resolved it"
    );
}
