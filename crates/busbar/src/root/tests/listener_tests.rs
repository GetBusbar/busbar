// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct HelloWrap;

impl busbar_contract::transport::wire::ConnectionSecurity for HelloWrap {
    fn wrap<'a>(
        &'a self,
        mut io: Box<dyn busbar_contract::transport::wire::RawIo>,
    ) -> busbar_contract::transport::wire::SecuredIoFut<'a> {
        Box::pin(async move {
            use futures::io::AsyncReadExt as _;
            let mut line = Vec::new();
            let mut byte = [0_u8; 1];
            while io.read(&mut byte).await? == 1 && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            if line == b"LET-ME-IN" {
                Ok(io)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "the wrap refused the connection",
                ))
            }
        })
    }
}

use busbar_kernel_testkit::limits::LIMITS_TEST_LOCK;

#[test]
fn accept_backoff_spins_only_on_per_connection_transients() {
    use std::io::{Error, ErrorKind};
    let mut b = super::AcceptBackoff::new();

    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None,
        "a per-connection transient must retry immediately"
    );
    assert_eq!(b.next_delay(&Error::from(ErrorKind::Interrupted)), None);

    let emfile = Error::from_raw_os_error(24);
    let first = b.next_delay(&emfile).expect("exhaustion must back off");
    assert_eq!(first, super::AcceptBackoff::FIRST);
    let second = b.next_delay(&emfile).expect("still failing");
    assert!(
        second > first,
        "the backoff must GROW: {first:?} -> {second:?}"
    );
    for _ in 0..20 {
        let d = b.next_delay(&emfile).expect("still failing");
        assert!(d <= super::AcceptBackoff::CAP, "capped at CAP, got {d:?}");
    }
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::CAP));

    b.reset();
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));

    let _ = b.next_delay(&emfile);
    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None
    );
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));
}

fn test_router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}

async fn spawn_secured_server(
    security: std::sync::Arc<dyn busbar_contract::transport::wire::ConnectionSecurity>,
) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        super::serve(listener, test_router(), security, shutdown, None)
            .await
            .unwrap();
    });

    (addr, tx)
}

async fn healthz_after(addr: SocketAddr, hello: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let _ = s.write_all(hello).await;
    let _ = s
        .write_all(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
        .await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got)).await;
    got
}

#[tokio::test]
async fn every_connection_is_served_through_the_wrap_and_a_refused_one_is_dropped_alone() {
    let (addr, _stop) = spawn_secured_server(std::sync::Arc::new(HelloWrap)).await;

    let served = healthz_after(addr, b"LET-ME-IN\n").await;
    assert!(
        served.starts_with(b"HTTP/1.1 200"),
        "an admitted connection is served: {:?}",
        String::from_utf8_lossy(&served)
    );

    for refused_hello in [&b"\n"[..], b"IMPOSTOR\n"] {
        let refused = healthz_after(addr, refused_hello).await;
        assert!(
            refused.is_empty(),
            "a refused connection is dropped unanswered: {:?}",
            String::from_utf8_lossy(&refused)
        );
    }

    let after = healthz_after(addr, b"LET-ME-IN\n").await;
    assert!(
        after.starts_with(b"HTTP/1.1 200"),
        "the listener survives the refusals and serves the next admitted connection"
    );
}

#[tokio::test]
async fn plain_http_still_works_without_tls() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        axum::serve(listener, test_router())
            .with_graceful_shutdown(shutdown)
            .await
            .unwrap();
    });

    let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", addr.port()))
        .await
        .expect("plain HTTP must still work when tls is absent");
    assert_eq!(resp.status(), 200);
    let _ = tx.send(());
}

#[tokio::test]
async fn body_read_timeout_trips_on_stalled_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;

    let limits = busbar_kernel::config::LimitsResolved {
        request_body_read_timeout_secs: 1,
        ..busbar_kernel::config::LimitsResolved::default()
    };
    let _limits_guard = busbar_kernel_testkit::limits::InstallGuard::install(&limits);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };

        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();

    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) => {}
        Ok(Ok(_n)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!(
            "body-read timeout did NOT trip: the server kept the stalled-body connection open \
                 past the deadline (slow-loris body regression)"
        ),
    }

    let _ = tx.send(());
}

#[tokio::test]
async fn a_rejected_configs_limits_do_not_govern_later_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;

    let _baseline = busbar_kernel_testkit::limits::InstallGuard::install(
        &busbar_kernel::config::LimitsResolved::default(),
    );
    {
        let _rejected = busbar_kernel_testkit::limits::InstallGuard::install(
            &busbar_kernel::config::LimitsResolved {
                request_body_read_timeout_secs: 1,
                ..busbar_kernel::config::LimitsResolved::default()
            },
        );
        assert_eq!(
            busbar_kernel::limits::request_body_read_timeout_secs(),
            1,
            "sanity: the candidate's bound must really be installed, or the rollback below \
                 proves nothing"
        );
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "a REJECTED config's 1s body-read timeout governed a connection accepted after its \
             guard was dropped: the rollback never reached the live limits ({outcome:?})"
    );

    let _ = tx.send(());
}

#[tokio::test]
async fn throughput_floor_trips_on_a_dribble_the_inter_frame_timer_cannot_catch() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;

    let _limits_guard = busbar_kernel_testkit::limits::InstallGuard::install(
        &busbar_kernel::config::LimitsResolved::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = sock.into_split();
    wr.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\r\n")
        .await
        .unwrap();
    wr.flush().await.unwrap();

    let start = Instant::now();
    let writer = tokio::spawn(async move {
        loop {
            if wr.write_all(b"x").await.is_err() {
                break;
            }
            let _ = wr.flush().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(20), rd.read(&mut buf)).await;
    let elapsed = start.elapsed();
    writer.abort();

    match outcome {
        Ok(Ok(0)) => {}
        Ok(Ok(_n)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!(
            "throughput floor did NOT trip: the server kept a 5 B/s dribble open past the \
                 generous outer bound"
        ),
    }

    assert!(
        elapsed < Duration::from_secs(25),
        "elapsed {elapsed:?} is too close to the 30s inter-frame timeout to attribute the \
             teardown to the throughput floor"
    );
    assert!(
        elapsed >= Duration::from_secs(9),
        "elapsed {elapsed:?} tripped before the throughput floor's own 10s grace period \
             elapsed — something else tore the connection down"
    );

    let _ = tx.send(());
}

#[tokio::test]
async fn a_fast_large_upload_is_not_killed_by_the_throughput_floor() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;

    let _limits_guard = busbar_kernel_testkit::limits::InstallGuard::install(
        &busbar_kernel::config::LimitsResolved::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: bytes::Bytes| async move { body.len().to_string() }),
        );
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    let body = vec![b'x'; 200_000];
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(
        format!(
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    sock.write_all(&body).await.unwrap();
    sock.flush().await.unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("200000") {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    assert!(
        outcome.is_ok(),
        "a promptly-delivered large body must not be killed by the throughput floor/total deadline"
    );
    let resp = String::from_utf8_lossy(&buf);
    assert!(
        resp.contains("200000"),
        "the full body must have been echoed back: {resp}"
    );

    let _ = tx.send(());
}

#[tokio::test]
async fn total_deadline_trips_on_a_body_that_stays_above_the_floor_forever() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    let limits = busbar_kernel::config::LimitsResolved {
        request_body_max_bytes: 2048,
        ..busbar_kernel::config::LimitsResolved::default()
    };

    let _limits_guard = busbar_kernel_testkit::limits::InstallGuard::install(&limits);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = sock.into_split();

    wr.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000000\r\n\r\n")
        .await
        .unwrap();
    wr.flush().await.unwrap();

    let start = Instant::now();

    let writer = tokio::spawn(async move {
        let chunk = vec![b'x'; 200];
        loop {
            if wr.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(8), rd.read(&mut buf)).await;
    let elapsed = start.elapsed();
    writer.abort();

    match outcome {
        Ok(Ok(0)) => {}
        Ok(Ok(_n)) => {}
        Ok(Err(_)) => {}
        Err(_) => panic!(
            "total deadline did NOT trip: the server kept an above-floor-forever body open \
                 past the generous outer bound"
        ),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "elapsed {elapsed:?} is too far past the 2s total deadline to attribute the teardown \
             to it rather than some other bound"
    );

    let _ = tx.send(());
}

async fn socket_pair(
    listener: &tokio::net::TcpListener,
) -> (
    tokio::net::TcpStream,
    tokio::net::TcpStream,
    std::net::SocketAddr,
) {
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (server, peer) = listener.accept().await.unwrap();
    (client, server, peer)
}

fn admitted(
    s: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
) -> busbar_core_connector::listen::Admitted {
    busbar_core_connector::listen::Admitted {
        stream: s.into_std().unwrap(),
        peer,
        hold: None,
    }
}

#[tokio::test]
async fn balancer_hands_off_only_past_margin_and_counts_exactly() {
    let mut handles = super::ConnBalancer::build(3);
    let b2 = handles.pop().unwrap();
    let b1 = handles.pop().unwrap();
    let b0 = handles.pop().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let (_c1, s1, p1) = socket_pair(&listener).await;
    let kept = b0.try_hand_off(admitted(s1, p1));
    assert!(kept.is_some(), "at equal load the connection stays local");
    let g1 = b0.place_local();

    let (_c2, s2, p2) = socket_pair(&listener).await;
    assert!(b0.try_hand_off(admitted(s2, p2)).is_some());
    let g2 = b0.place_local();

    let (_c3, s3, p3) = socket_pair(&listener).await;
    assert!(
        b0.try_hand_off(admitted(s3, p3)).is_none(),
        "at min+2 the connection must be handed to the least-loaded worker"
    );
    let others: u32 = [&b1, &b2]
        .iter()
        .map(|b| b.counts[b.me].0.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(others, 1, "exactly one target counted the handoff");

    let target = if b1.counts[b1.me]
        .0
        .load(std::sync::atomic::Ordering::Relaxed)
        == 1
    {
        &b1
    } else {
        &b2
    };
    let g3 = target.adopt();
    drop(g3);
    drop(g2);
    drop(g1);
    let total: u32 = b0
        .counts
        .iter()
        .map(|c| c.0.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(
        total, 0,
        "all guards dropped — every count must return to zero"
    );

    let mut local_guards = Vec::new();
    for _ in 0..2 {
        let (_c, s, p) = socket_pair(&listener).await;
        assert!(b0.try_hand_off(admitted(s, p)).is_some());
        local_guards.push(b0.place_local());
    }

    let mut fillers = Vec::new();
    loop {
        let (_c, s, p) = socket_pair(&listener).await;
        fillers.push(_c);
        match b0.txs[1].try_send(admitted(s, p)) {
            Ok(()) => continue,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => break,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                panic!("worker 1's channel must remain open for the full-channel fallback")
            }
        }
    }

    b2.counts[b2.me]
        .0
        .store(100, std::sync::atomic::Ordering::Relaxed);
    let before = b1.counts[b1.me]
        .0
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        b0.counts[b0.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        before + super::REBALANCE_MARGIN,
        "the local guards must keep the handoff threshold reached"
    );
    let (_c, s, p) = socket_pair(&listener).await;
    let kept = b0.try_hand_off(admitted(s, p));
    assert!(
        kept.is_some(),
        "a full target channel must fall back to serving locally, never dropping the connection"
    );
    assert_eq!(
        b1.counts[b1.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        before,
        "the failed handoff must roll its increment back"
    );
    drop(local_guards);
    assert_eq!(
        b0.counts[b0.me]
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "releasing the local connections restores this worker's count"
    );
    drop(b1);
}

#[test]
fn recv_side_from_std_failure_releases_the_sender_increment() {
    let mut handles = super::ConnBalancer::build(2);
    let recv = handles.pop().unwrap();
    let _sender = handles.pop().unwrap();
    use std::sync::atomic::Ordering;

    let baseline = recv.counts[recv.me].0.load(Ordering::Relaxed);

    recv.counts[recv.me].0.fetch_add(1, Ordering::Relaxed);
    assert_eq!(recv.counts[recv.me].0.load(Ordering::Relaxed), baseline + 1);

    {
        let _guard = recv.adopt();
    }

    assert_eq!(
        recv.counts[recv.me].0.load(Ordering::Relaxed),
        baseline,
        "a from_std-failure continue must release the sender's increment, not strand it"
    );
}

#[tokio::test]
async fn server_posture_matches_the_1_5_5_defaults() {
    let _guard = LIMITS_TEST_LOCK.lock().await;

    assert_eq!(
        busbar_kernel::limits::tls_handshake_timeout_secs(),
        10,
        "tls_handshake_timeout_secs default"
    );
    assert_eq!(
        busbar_kernel::limits::request_body_read_timeout_secs(),
        30,
        "request_body_read_timeout_secs default"
    );

    use std::future::Future as _;
    use tokio::io::AsyncWriteExt as _;
    tokio::time::pause();
    let (mut client, server) = tokio::io::duplex(1024);
    client.write_all(b"GET / HTTP/1.1\r\nhost:").await.unwrap();
    let service = hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
        Ok::<_, std::convert::Infallible>(hyper::Response::new(
            http_body_util::Empty::<bytes::Bytes>::new(),
        ))
    });
    struct DeadlineTimer(std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>);
    impl hyper::rt::Timer for DeadlineTimer {
        fn sleep(&self, duration: Duration) -> std::pin::Pin<Box<dyn hyper::rt::Sleep>> {
            hyper::rt::Timer::sleep(&hyper_util::rt::TokioTimer::new(), duration)
        }
        fn sleep_until(
            &self,
            deadline: std::time::Instant,
        ) -> std::pin::Pin<Box<dyn hyper::rt::Sleep>> {
            *self.0.lock().unwrap() = Some(deadline);
            hyper::rt::Timer::sleep_until(&hyper_util::rt::TokioTimer::new(), deadline)
        }
        fn now(&self) -> std::time::Instant {
            hyper::rt::Timer::now(&hyper_util::rt::TokioTimer::new())
        }
        fn reset(
            &self,
            sleep: &mut std::pin::Pin<Box<dyn hyper::rt::Sleep>>,
            deadline: std::time::Instant,
        ) {
            *self.0.lock().unwrap() = Some(deadline);
            hyper::rt::Timer::reset(&hyper_util::rt::TokioTimer::new(), sleep, deadline);
        }
    }
    let deadline = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut builder = super::hardened_conn_builder();
    builder
        .http1()
        .timer(DeadlineTimer(std::sync::Arc::clone(&deadline)));
    let mut conn =
        Box::pin(builder.serve_connection(hyper_util::rt::TokioIo::new(server), service));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let armed_at = tokio::time::Instant::now();
    assert!(conn.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(
        conn.as_mut().poll(&mut cx).is_pending(),
        "a valid reader still has its 30-second header window"
    );
    tokio::time::advance(Duration::from_secs(1)).await;

    let error = tokio::time::timeout(Duration::from_secs(1), conn)
        .await
        .expect("the armed header timer must end the incomplete request")
        .expect_err("an incomplete header ends with a timeout error");
    assert_eq!(
        tokio::time::Instant::from_std(
            deadline
                .lock()
                .unwrap()
                .expect("the header timer was armed")
        ),
        armed_at + Duration::from_secs(30),
        "the watchdog permits scheduling progress, not a later header deadline"
    );
    assert!(
        error
            .downcast_ref::<hyper::Error>()
            .is_some_and(hyper::Error::is_timeout),
        "the connection ended for the header timeout: {error}"
    );
}

fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "busbar-engine-tls-{tag}-{}-{:?}.pem",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::write(&p, contents).expect("write pem");
    p
}

fn file(path: &std::path::Path) -> busbar_kernel::config::SecretRef {
    busbar_kernel::config::SecretRef::file(path.to_string_lossy().into_owned())
}

fn gen_self_signed() -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("self-signed");
    (cert.pem(), signing_key.serialize_pem())
}

async fn spawn_tls_server(
    tls: &busbar_kernel::config::sections::TlsCfg,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let security = busbar_core_connector::tls::prepare(
        "engine-tls test",
        Some(tls),
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
        true,
    )
    .expect("valid test TLS config");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let router = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        super::serve(listener, router, security, shutdown, None)
            .await
            .expect("serve");
    });
    (addr, tx)
}

#[tokio::test]
async fn tls_happy_path_trusted_client_gets_200() {
    let (cert_pem, key_pem) = gen_self_signed();
    let tls = busbar_kernel::config::sections::TlsCfg {
        cert: file(&temp_pem("srv-cert", &cert_pem)),
        key: file(&temp_pem("srv-key", &key_pem)),
        client_ca: None,
    };
    let (addr, _stop) = spawn_tls_server(&tls).await;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("cert"))
        .build()
        .expect("client");
    let resp = client
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("https request should succeed over TLS");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.expect("body"), "ok");
}

fn gen_ca_and_leaf(sans: &[&str]) -> (String, String, String) {
    let ca_kp = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_pem = ca_params.self_signed(&ca_kp).expect("self-signed ca").pem();
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = rcgen::KeyPair::generate().expect("leaf key");
    let leaf =
        rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("leaf params")
            .signed_by(&leaf_kp, &issuer)
            .expect("leaf");
    (ca_pem, leaf.pem(), leaf_kp.serialize_pem())
}

fn mutual(
    srv_cert_pem: &str,
    srv_key_pem: &str,
    ca_pem: &str,
) -> busbar_kernel::config::sections::TlsCfg {
    busbar_kernel::config::sections::TlsCfg {
        cert: file(&temp_pem("m-srv-cert", srv_cert_pem)),
        key: file(&temp_pem("m-srv-key", srv_key_pem)),
        client_ca: Some(file(&temp_pem("m-ca", ca_pem))),
    }
}

fn client_with(srv_cert_pem: &str, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).expect("cert"),
        )
        .use_rustls_tls();
    if let Some((leaf, key)) = identity {
        builder = builder.identity(
            reqwest::Identity::from_pem(format!("{leaf}{key}").as_bytes()).expect("identity"),
        );
    }
    builder.build().expect("client")
}

#[tokio::test]
async fn mtls_valid_client_cert_gets_200() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let (addr, _stop) = spawn_tls_server(&mutual(&srv_cert_pem, &srv_key_pem, &ca_pem)).await;
    let resp = client_with(&srv_cert_pem, Some((&leaf_pem, &leaf_key_pem)))
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("mTLS request with valid client cert should succeed");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn mtls_rejects_bad_client_then_serves_valid() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let (addr, _stop) = spawn_tls_server(&mutual(&srv_cert_pem, &srv_key_pem, &ca_pem)).await;
    let url = format!("https://localhost:{}/healthz", addr.port());

    assert!(
        client_with(&srv_cert_pem, None)
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client with no certificate"
    );

    let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(&["impostor"]);
    assert!(
        client_with(&srv_cert_pem, Some((&wrong_leaf, &wrong_key)))
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client cert from an untrusted CA"
    );

    let resp = client_with(&srv_cert_pem, Some((&leaf_pem, &leaf_key_pem)))
        .get(&url)
        .send()
        .await
        .expect("server must remain up and serve a valid client after rejecting bad ones");
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn a_listener_states_its_scheme_on_every_request() {
    use busbar_contract::abi::host::service::{SCHEME_PLAIN, SCHEME_SECURE};
    use busbar_kernel::plane_routes::ListenerScheme;
    fn scheme_router() -> Router {
        Router::new().route(
            "/healthz",
            get(
                |l: Option<axum::extract::Extension<ListenerScheme>>| async move {
                    format!("scheme={}", l.map_or(0, |axum::extract::Extension(l)| l.0))
                },
            ),
        )
    }
    let body = |got: &[u8]| String::from_utf8_lossy(got).into_owned();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secured = listener.local_addr().unwrap();
    let (stop_secured, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let wrap: std::sync::Arc<dyn busbar_contract::transport::wire::ConnectionSecurity> =
            std::sync::Arc::new(HelloWrap);
        super::serve(listener, scheme_router(), wrap, shutdown, None)
            .await
            .unwrap();
    });
    let got = body(&healthz_after(secured, b"LET-ME-IN\n").await);
    assert!(got.ends_with(&format!("scheme={SCHEME_SECURE}")), "{got}");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain = listener.local_addr().unwrap();
    let (stop_plain, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        super::serve_plain(listener, scheme_router(), shutdown, None)
            .await
            .unwrap();
    });
    let got = body(&healthz_after(plain, b"").await);
    assert!(got.ends_with(&format!("scheme={SCHEME_PLAIN}")), "{got}");
    let _ = (stop_secured.send(()), stop_plain.send(()));
}

#[tokio::test]
async fn an_oversize_body_sent_slowly_still_reads_its_413() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        let router = Router::new()
            .route(
                "/echo",
                axum::routing::post(
                    |body: axum::body::Bytes| async move { body.len().to_string() },
                ),
            )
            .layer(axum::extract::DefaultBodyLimit::max(1024));
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

    const CHUNK: usize = 64 * 1024;
    const CHUNKS: usize = 64;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        CHUNK * CHUNKS
    );
    sock.write_all(head.as_bytes()).await.unwrap();
    let (mut rd, mut wr) = sock.into_split();

    let upload = tokio::spawn(async move {
        let chunk = vec![b'x'; CHUNK];
        for _ in 0..CHUNKS {
            if wr.write_all(&chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let _ = wr.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), rd.read_to_end(&mut got)).await;
    let _ = upload.await;
    assert!(
        matches!(read, Ok(Ok(_))) && got.starts_with(b"HTTP/1.1 413"),
        "the client reads the 413 (read: {read:?}): {:?}",
        String::from_utf8_lossy(&got)
    );
    let _ = tx.send(());
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_dropped_at_the_limit() {
    use tokio::io::AsyncReadExt;
    let _guard = LIMITS_TEST_LOCK.lock().await;
    let limits = busbar_kernel::config::LimitsResolved {
        tls_handshake_timeout_secs: 2,
        ..busbar_kernel::config::LimitsResolved::default()
    };
    let _limits_guard = busbar_kernel_testkit::limits::InstallGuard::install(&limits);

    let (cert_pem, key_pem) = gen_self_signed();
    let tls = busbar_kernel::config::sections::TlsCfg {
        cert: file(&temp_pem("stall-cert", &cert_pem)),
        key: file(&temp_pem("stall-key", &key_pem)),
        client_ca: None,
    };
    let (addr, stop) = spawn_tls_server(&tls).await;

    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    let at = Instant::now();
    let mut buf = [0_u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(8), stalled.read(&mut buf)).await;
    let took = at.elapsed();
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("{n} bytes answered a client that never spoke"),
        Err(_) => {
            panic!("the stalled handshake was still held after {took:?}: the limit is not enforced")
        }
    }
    assert!(
        took >= Duration::from_millis(1800),
        "dropped before the 2 s limit, after {took:?}"
    );
    assert!(
        took < Duration::from_secs(6),
        "dropped long after the 2 s limit, after {took:?}"
    );

    let resp = client_with(&cert_pem, None)
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("the listener serves after dropping a stalled handshake");
    assert_eq!(resp.status(), 200);
    let _ = stop.send(());
}

#[test]
fn a_refused_handshake_logs_at_debug_only() {
    use busbar_kernel_testkit::test_support::warn_capture::WarnCapture;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing_subscriber::layer::SubscriberExt as _;

    let loud = WarnCapture::default();
    let debug = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry()
        .with(loud.clone())
        .with(debug.clone());
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, _leaf_pem, _leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let tls = mutual(&srv_cert_pem, &srv_key_pem, &ca_pem);

    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (addr, stop) = spawn_tls_server(&tls).await;

            let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
            plain
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut sink = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(5), plain.read_to_end(&mut sink)).await;

            let certless = client_with(&srv_cert_pem, None)
                .get(format!("https://localhost:{}/healthz", addr.port()))
                .send()
                .await;
            assert!(certless.is_err(), "a certless client is refused");

            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = stop.send(());
        });
    });

    assert!(
        debug.contains("handshake failed"),
        "the refusal is logged at debug: {:?}",
        debug.messages()
    );
    assert!(
        !loud.contains("handshake failed") && !loud.contains("handshake timed out"),
        "a refused handshake is never logged at warn or error: {:?}",
        loud.messages()
    );

    let key_body: String = srv_key_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert!(
        !debug.messages().iter().any(|m| m.contains(&key_body)),
        "a log line echoed the server key"
    );
}

#[tokio::test]
async fn shutdown_retires_the_listening_socket_before_an_accepted_request_finishes_draining() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = busbar_core_connector::listen::Listening::bind_stream(
        None,
        "127.0.0.1:0",
        busbar_core_connector::listen::AcceptLimits::default(),
    )
    .unwrap();
    let addr = listener.local_addr();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let router = Router::new().route(
        "/held",
        get({
            let entered = entered.clone();
            let release = release.clone();
            move || {
                let entered = entered.clone();
                let release = release.clone();
                async move {
                    entered.notify_one();
                    release.notified().await;
                    "finished"
                }
            }
        }),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    let (observed, shutdown_observed) = oneshot::channel::<()>();
    let serving = tokio::spawn(super::serve_admitted(
        listener,
        router,
        None,
        async move {
            let _ = stopped.await;
            let _ = observed.send(());
        },
        None,
    ));
    let mut existing = tokio::net::TcpStream::connect(addr).await.unwrap();
    existing
        .write_all(b"GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), entered.notified())
        .await
        .expect("the accepted request reached its held handler");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), shutdown_observed)
        .await
        .expect("the accept loop polled shutdown")
        .unwrap();
    let was_draining = !serving.is_finished();
    let new_connection =
        tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr))
            .await
            .expect("a new TCP handshake resolves while the accepted request is held");
    let still_accepting = new_connection.is_ok();
    drop(new_connection);
    release.notify_one();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), existing.read_to_end(&mut response))
        .await
        .expect("the accepted request completes during drain")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), serving)
        .await
        .expect("drain completes after the held request finishes")
        .unwrap()
        .unwrap();
    assert!(was_draining, "shutdown waited for the accepted request");
    assert!(
        !still_accepting,
        "shutdown kept the listener open and completed a new TCP handshake during drain"
    );
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    assert!(response.windows(8).any(|bytes| bytes == b"finished"));
}
