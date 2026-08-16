// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/tls.rs`.

//! End-to-end TLS / mTLS transport tests. Each spins a real busbar TLS listener on an ephemeral
//! port with rcgen-generated certs and drives it with a real reqwest https client over the wire —
//! exercising the actual rustls handshake (incl. client-cert verification), not a mock.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use rcgen::{CertificateParams, CertifiedKey, IsCa, Issuer, KeyPair};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::TlsCfg;

/// `crate::limits::install` is a PROCESS-GLOBAL swap, and cargo runs this file's `#[tokio::test]`
/// fns concurrently by default. Any test that installs a non-default `LimitsResolved` (the
/// body-read-timeout / throughput-floor / total-deadline tests below) can otherwise stomp a
/// concurrently-running sibling's installed value mid-test — observed directly: the throughput
/// floor and total-deadline tests both pass in isolation but fail when run alongside each other.
/// Every test that calls `crate::limits::install` holds this for its ENTIRE body (not just the
/// install call), so no two such tests are ever mid-flight at once. An async-aware
/// `tokio::sync::Mutex`, not `std::sync::Mutex`: every holder awaits (socket I/O) while holding
/// it, and holding a `std` mutex guard across an await point risks blocking the executor thread
/// underneath a parked task (clippy's `await_holding_lock`, correctly `-D warnings` here).
/// MOVED to `crate::limits` (same lock, same rules) so that the `InstallGuard` tests living
/// beside the static they mutate are serialized against these too — a lock only this file held
/// protected these tests from each other but not from those, or those from these.
use crate::limits::LIMITS_TEST_LOCK;

/// THE ACCEPT-ERROR POLICY, asserted directly. Both listener loops route every `accept()` error
/// through `AcceptBackoff`, so this covers the class rather than one loop.
///
/// The hazard is resource exhaustion, not a peer reset: on `EMFILE`/`ENFILE` `accept()` fails
/// INSTANTLY and keeps failing until something releases an fd, so a bare `continue` -- which is
/// what both loops did -- spins a full core rejecting connections, starving the very tasks whose
/// completion would free the fds.
#[test]
fn accept_backoff_spins_only_on_per_connection_transients() {
    use std::io::{Error, ErrorKind};
    let mut b = super::AcceptBackoff::new();

    // A peer that resets between SYN and accept: the next accept will very likely succeed.
    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None,
        "a per-connection transient must retry immediately"
    );
    assert_eq!(b.next_delay(&Error::from(ErrorKind::Interrupted)), None);

    // fd exhaustion: back off, growing, and CAPPED so shutdown is never parked for long.
    let emfile = Error::from_raw_os_error(24); // EMFILE
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

    // A successful accept clears the schedule, so an isolated blip does not leave the listener
    // permanently slow.
    b.reset();
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));

    // And a transient arriving mid-backoff resets it too -- it is not the exhaustion class.
    let _ = b.next_delay(&emfile);
    assert_eq!(
        b.next_delay(&Error::from(ErrorKind::ConnectionAborted)),
        None
    );
    assert_eq!(b.next_delay(&emfile), Some(super::AcceptBackoff::FIRST));
}

/// A trivial router standing in for busbar's real one — the TLS transport is protocol-agnostic,
/// so a `/healthz` that returns 200 is enough to prove a request completed over the secure hop.
fn test_router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}

/// Write `contents` to a uniquely-named temp file and return its path. Used to hand the
/// PEM-on-disk config grammar the same file paths an operator would.
fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let uniq = format!(
        "busbar-tls-test-{tag}-{}-{:?}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    p.push(uniq);
    std::fs::write(&p, contents).unwrap();
    p
}

/// Generate a self-signed server cert for `localhost`/`127.0.0.1`. Returns (cert_pem, key_pem).
fn gen_self_signed() -> (String, String) {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    (cert.pem(), signing_key.serialize_pem())
}

/// Generate a CA + a leaf signed by it (for mTLS). Returns (ca_cert_pem, leaf_cert_pem,
/// leaf_key_pem). The leaf is the client identity; the CA is what the server verifies against.
fn gen_ca_and_leaf(cn_sans: Vec<String>) -> (String, String, String) {
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

    // rcgen 0.14: leaf signing goes through an `Issuer` (CA params + CA key) rather than
    // passing the CA cert + key positionally. `from_params` borrows the CA params and takes
    // ownership of the CA key pair, which we no longer need after this.
    let issuer = Issuer::from_params(&ca_params, ca_kp);
    let leaf_kp = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(cn_sans).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

    (ca_cert.pem(), leaf_cert.pem(), leaf_kp.serialize_pem())
}

/// Boot a busbar TLS listener from a `TlsCfg` on an ephemeral port. Returns the bound address and
/// a shutdown sender (drop or send to stop + drain). Mirrors `main`'s TLS branch exactly:
/// install provider → build ServerConfig → `tls::serve`.
async fn spawn_tls_server(tls: &TlsCfg) -> (SocketAddr, oneshot::Sender<()>) {
    super::install_crypto_provider();
    let server_config =
        super::build_server_config(tls, &crate::config::secret::SecretResolver::builtins_only())
            .expect("valid test TLS config");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        super::serve(listener, test_router(), server_config, shutdown)
            .await
            .unwrap();
    });
    // Give the spawned task a tick to begin accepting before the client connects.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, tx)
}

/// TEST 1 — TLS happy path: a client trusting the server's self-signed cert completes an https
/// request and gets 200.
#[tokio::test]
async fn tls_happy_path_trusted_client_gets_200() {
    let (cert_pem, key_pem) = gen_self_signed();
    let cert_file = temp_pem("srv-cert", &cert_pem);
    let key_file = temp_pem("srv-key", &key_pem);
    let tls = TlsCfg {
        cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: None,
    };
    let (addr, _stop) = spawn_tls_server(&tls).await;

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap())
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("https request should succeed over TLS");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}

/// TEST 2 — mTLS required + valid client cert: client presents a leaf signed by the configured
/// CA ⇒ 200.
#[tokio::test]
async fn mtls_valid_client_cert_gets_200() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

    let cert_file = temp_pem("m2-srv-cert", &srv_cert_pem);
    let key_file = temp_pem("m2-srv-key", &srv_key_pem);
    let ca_file = temp_pem("m2-ca", &ca_pem);
    let tls = TlsCfg {
        cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: Some(crate::config::SecretRef::file(
            ca_file.to_string_lossy().into_owned(),
        )),
    };
    let (addr, _stop) = spawn_tls_server(&tls).await;

    let identity =
        reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
        .identity(identity)
        .use_rustls_tls()
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{}/healthz", addr.port()))
        .send()
        .await
        .expect("mTLS request with valid client cert should succeed");
    assert_eq!(resp.status(), 200);
}

/// TEST 3 — mTLS required + no/wrong client cert: the handshake is rejected, the server stays up,
/// and a subsequent valid client still succeeds.
#[tokio::test]
async fn mtls_rejects_bad_client_then_serves_valid() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(vec!["busbar-client".into()]);

    let cert_file = temp_pem("m3-srv-cert", &srv_cert_pem);
    let key_file = temp_pem("m3-srv-key", &srv_key_pem);
    let ca_file = temp_pem("m3-ca", &ca_pem);
    let tls = TlsCfg {
        cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: Some(crate::config::SecretRef::file(
            ca_file.to_string_lossy().into_owned(),
        )),
    };
    let (addr, _stop) = spawn_tls_server(&tls).await;
    let url = format!("https://localhost:{}/healthz", addr.port());

    // (a) Client presenting NO client cert ⇒ rejected (server requires one).
    let no_cert_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
        .use_rustls_tls()
        .build()
        .unwrap();
    let err = no_cert_client.get(&url).send().await;
    assert!(
        err.is_err(),
        "mTLS server must reject a client with no certificate"
    );

    // (b) Client presenting a cert from a DIFFERENT CA ⇒ also rejected.
    let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(vec!["impostor".into()]);
    let wrong_identity =
        reqwest::Identity::from_pem(format!("{wrong_leaf}{wrong_key}").as_bytes()).unwrap();
    let wrong_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
        .identity(wrong_identity)
        .use_rustls_tls()
        .build()
        .unwrap();
    let wrong = wrong_client.get(&url).send().await;
    assert!(
        wrong.is_err(),
        "mTLS server must reject a client cert from an untrusted CA"
    );

    // (c) Server survived both rejections and still serves a valid client.
    let good_identity =
        reqwest::Identity::from_pem(format!("{leaf_pem}{leaf_key_pem}").as_bytes()).unwrap();
    let good_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(srv_cert_pem.as_bytes()).unwrap())
        .identity(good_identity)
        .use_rustls_tls()
        .build()
        .unwrap();
    let resp = good_client
        .get(&url)
        .send()
        .await
        .expect("server must remain up and serve a valid client after rejecting bad ones");
    assert_eq!(resp.status(), 200);
}

/// TEST 4a — config regression: with NO `tls` block the plain-HTTP path still works. Drives the
/// historical `axum::serve` over a plain TcpListener (the exact `None` branch in `main`).
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
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", addr.port()))
        .await
        .expect("plain HTTP must still work when tls is absent");
    assert_eq!(resp.status(), 200);
    let _ = tx.send(());
}

/// TEST 4b — fail-fast: a bad cert path produces a clear, file-named error from
/// `build_server_config` (which `main` turns into `die`). No server is started.
#[test]
fn bad_cert_path_errors_clearly() {
    let tls = TlsCfg {
        cert: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-cert.pem"),
        key: crate::config::SecretRef::file("/nonexistent/busbar/does-not-exist-key.pem"),
        client_ca: None,
    };
    let err = super::build_server_config(
        &tls,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("missing cert file must error");
    assert!(
        err.contains("cert") && err.contains("does-not-exist-cert.pem"),
        "error must name the offending file: {err}"
    );
}

/// TEST 4c — fail-fast: a syntactically invalid PEM cert errors with the file named, not a panic.
#[test]
fn malformed_cert_errors_clearly() {
    let cert_file = temp_pem("bad-cert", "-----BEGIN CERTIFICATE-----\nnot base64\n");
    let (_c, key_pem) = gen_self_signed();
    let key_file = temp_pem("ok-key", &key_pem);
    let tls = TlsCfg {
        cert: crate::config::SecretRef::file(cert_file.to_string_lossy().into_owned()),
        key: crate::config::SecretRef::file(key_file.to_string_lossy().into_owned()),
        client_ca: None,
    };
    let err = super::build_server_config(
        &tls,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect_err("malformed cert must error");
    assert!(err.contains("cert"), "error must reference the cert: {err}");
}

/// TEST 5 - REGRESSION (slow-loris BODY): the inbound body-read timeout trips on a stalled
/// request body. Before the fix, only the header-read phase was bounded; a client that finished
/// its headers then dribbled (here: never sent) the promised body would pin the connection task,
/// its FD, and one of the finite inbound-concurrency permits INDEFINITELY. This drives the plain
/// serve loop (same `BodyTimeoutService` seam the TLS loop uses) over a raw socket: send a POST
/// with a `Content-Length` but NO body, and assert the server closes the connection promptly
/// (well inside a generous deadline) rather than hanging forever. A short body-read timeout is
/// installed process-wide for the test, through `InstallGuard` so it is restored to whatever was
/// there before when the test ends — `install` REPLACES the whole struct behind the shared
/// `RwLock`, not just the one field named here, so an unguarded install would leave this
/// non-default value behind for every other test in the binary that reads limits afterward.
#[tokio::test]
async fn body_read_timeout_trips_on_stalled_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    // Install a SHORT body-read timeout (1s) so the test is fast, through the RAII guard rather
    // than the bare test-only setter: `install` REPLACES the whole struct behind the
    // process-global RwLock with no restore, so a bare install here would leave this
    // non-default value behind for every OTHER test in the binary reading limits after this one
    // — LIMITS_TEST_LOCK only serializes the four installers in THIS file against each other,
    // not against every reader elsewhere. The guard restores whatever was installed before it
    // (never committed, so it always rolls back) when it drops at the end of this test.
    let limits = crate::config::LimitsResolved {
        request_body_read_timeout_secs: 1,
        ..crate::config::LimitsResolved::default()
    };
    let _limits_guard = crate::limits::InstallGuard::install(&limits);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let shutdown = async {
            let _ = rx.await;
        };
        // A route that WOULD read the body (POST /echo), so the server actually awaits body frames.
        let router = Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
        super::serve_plain(listener, router, shutdown)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    // Headers announce a 100-byte body; we send NONE of it, then stall.
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    // The server must close the connection (read yields EOF/reset) once the body-read bound (1s)
    // elapses with no body forthcoming. Bound the whole wait generously (5s): pre-fix this would
    // hang until the test's own deadline. `read` returning Ok(0) is a clean EOF; an Err is a
    // reset - either proves the server tore the stalled connection down.
    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await;
    match outcome {
        Ok(Ok(0)) => {}  // clean EOF: server closed the stalled connection
        Ok(Ok(_n)) => {} // server may first write a 4xx/408-ish response, then close
        Ok(Err(_)) => {} // connection reset: also acceptable
        Err(_) => panic!(
            "body-read timeout did NOT trip: the server kept the stalled-body connection open \
                 past the deadline (slow-loris body regression)"
        ),
    }

    let _ = tx.send(());
}

/// TEST — AN UNCOMMITTED `InstallGuard`'s ROLLBACK GOVERNS A REAL INBOUND CONNECTION.
///
/// The end-to-end half of the `InstallGuard` coverage in `limits/tests/limits_tests.rs`: those
/// tests assert the rolled-back value through the accessors (including from another thread),
/// this one asserts the SERVER BEHAVIOUR an actual client gets. It is the same slow-loris
/// scenario as `body_read_timeout_trips_on_stalled_body` with the sign flipped: a rejected
/// candidate config carrying a 1s body-read timeout is installed through a guard and then
/// dropped WITHOUT commit (the failed-apply path), and only AFTER that rollback is the
/// connection made. The stalled body must now survive well past 1s, because the bound in force
/// is the restored 30s default that `serve_one_plain` reads per connection.
///
/// This is the test that cannot be satisfied by anything except a working rollback: delete the
/// `Drop` impl and the rejected 1s timeout stays installed process-wide, the server tears this
/// connection down at ~1s, and the assertion below fires. That is exactly the production symptom
/// the guard exists to prevent — a 400-ed `POST /config/apply` changing how the still-running
/// gateway treats live traffic.
#[tokio::test]
async fn a_rejected_configs_limits_do_not_govern_later_connections() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    // The "accepted config that is already serving": the historical defaults (30s inter-frame).
    // Itself guarded so this test leaks nothing to the rest of the binary.
    let _baseline = crate::limits::InstallGuard::install(&crate::config::LimitsResolved::default());
    {
        // A candidate config whose build then FAILS. Its limits are live while the build runs…
        let _rejected = crate::limits::InstallGuard::install(&crate::config::LimitsResolved {
            request_body_read_timeout_secs: 1,
            ..crate::config::LimitsResolved::default()
        });
        assert_eq!(
            crate::limits::request_body_read_timeout_secs(),
            1,
            "sanity: the candidate's bound must really be installed, or the rollback below \
                 proves nothing"
        );
    }
    // …and here it is rejected. Everything after this line must behave as if it never existed.

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
        super::serve_plain(listener, router, shutdown)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    // 3s: comfortably past the rejected 1s bound, comfortably inside the restored 30s one, and
    // inside both hardcoded backstops (the throughput floor's 10s grace, and a total deadline of
    // 32 MiB / 1 KiB/s). So a close here can ONLY be the rejected config's timeout still in
    // force.
    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "a REJECTED config's 1s body-read timeout governed a connection accepted after its \
             guard was dropped: the rollback never reached the live limits ({outcome:?})"
    );

    let _ = tx.send(());
}

/// TEST — the MINIMUM-THROUGHPUT floor cuts a body that dribbles fast enough that the
/// inter-frame timer alone (which resets on ANY progress, `poll_frame`'s `this.sleep = None`)
/// provably CANNOT be what tears the connection down. Copies the shape of
/// `body_read_timeout_trips_on_stalled_body`: raw socket, `serve_plain`, a route that reads the
/// body. The inter-frame timeout is set generously (30s, the historical default) and the client
/// sends one byte every 200ms — far under the 30s inter-frame bound, so that timer never once
/// arms long enough to fire. Only the hardcoded throughput floor (1 KiB/s after a 10s grace,
/// `MIN_BODY_THROUGHPUT_BYTES_PER_SEC`/`BODY_THROUGHPUT_GRACE`) can catch this client, since
/// `bytes/elapsed` at 5 B/s stays far below 1024 B/s for the whole test.
///
/// SLOW BY CONSTRUCTION: the floor/grace are hardcoded consts, not operator knobs (per design),
/// so this test cannot be sped up by installing a smaller limit — it must actually wait out the
/// 10s grace period before the floor is even evaluated.
#[tokio::test]
async fn throughput_floor_trips_on_a_dribble_the_inter_frame_timer_cannot_catch() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    // Deliberately generous / left at the historical default: the point of this test is that
    // this timer NEVER fires (the dribble is far faster than 30s per byte).
    crate::limits::install(&crate::config::LimitsResolved::default());

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
        super::serve_plain(listener, router, shutdown)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

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

    // Generous outer bound: must trip once the 10s grace elapses, well before the 30s
    // inter-frame timeout would ever have a chance to (it never stops being reset).
    let mut buf = [0u8; 256];
    let outcome = tokio::time::timeout(Duration::from_secs(20), rd.read(&mut buf)).await;
    let elapsed = start.elapsed();
    writer.abort();

    match outcome {
        Ok(Ok(0)) => {}  // clean EOF: server tore the connection down
        Ok(Ok(_n)) => {} // server may write a response first, then close
        Ok(Err(_)) => {} // reset: also acceptable
        Err(_) => panic!(
            "throughput floor did NOT trip: the server kept a 5 B/s dribble open past the \
                 generous outer bound"
        ),
    }
    // SANITY GATE: elapsed must be well under the 30s inter-frame timeout, or the inter-frame
    // timer (not the floor) is what fired and this test is measuring the wrong thing.
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

/// TEST — a legitimate fast large upload is NOT killed by the throughput floor or the total
/// deadline. REGRESSION PROOF (passes before AND after the floor/deadline existed — a body that
/// arrives promptly and in one shot was never at risk from the inter-frame timer either). Exists
/// to catch a floor/grace/total value that false-positives on honest traffic.
#[tokio::test]
async fn a_fast_large_upload_is_not_killed_by_the_throughput_floor() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    crate::limits::install(&crate::config::LimitsResolved::default());

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
        super::serve_plain(listener, router, shutdown)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

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

    // `read_to_end` would block on EOF that never arrives: the connection is a normal HTTP/1.1
    // keep-alive connection, so the server holds it open after responding rather than closing it.
    // Read until the expected echoed length shows up in the response instead — that is the
    // observable "a promptly-delivered body was not killed" signal, not connection closure.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF: connection closed (also acceptable if it happens after the body)
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

/// TEST — the TOTAL deadline trips on a body that stays ABOVE the throughput floor forever (so
/// the floor itself never fires) — the backstop for a client that paces itself just fast enough
/// to never trip the floor but never finishes either. `total_body_deadline` is DERIVED from
/// `request_body_max_bytes / MIN_BODY_THROUGHPUT_BYTES_PER_SEC`, so shrinking the configured cap
/// to 2048 bytes gives a fast (~2s) deadline without touching either hardcoded const — this is
/// also, incidentally, the regression proof that the total is derived rather than a bare
/// constant (a fixed 600s total would make this test take ten minutes).
#[tokio::test]
async fn total_deadline_trips_on_a_body_that_stays_above_the_floor_forever() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = LIMITS_TEST_LOCK.lock().await;
    let limits = crate::config::LimitsResolved {
        request_body_max_bytes: 2048, // total_body_deadline() = 2048 / 1024 B/s = 2s
        ..crate::config::LimitsResolved::default()
    };
    // Through the RAII guard, not the bare setter: a bare `install` of this 2 KiB cap LEAKS it
    // to every test in the binary that reads limits afterward (`install` replaces the whole
    // struct with no restore), and `limits/tests/limits_tests.rs`'s
    // `uninstalled_accessors_return_historical_defaults` asserts
    // `translate_body_max_bytes() == DEFAULT_REQUEST_BODY_MAX_BYTES` — so whether the suite
    // passed depended on that test happening to run BEFORE this one. Never committed, so it
    // always rolls back at the end of this test.
    let _limits_guard = crate::limits::InstallGuard::install(&limits);

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
        super::serve_plain(listener, router, shutdown)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = sock.into_split();
    // A Content-Length the body never reaches, so the ONLY way this connection ends is a bound
    // tripping.
    wr.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000000\r\n\r\n")
        .await
        .unwrap();
    wr.flush().await.unwrap();

    let start = Instant::now();
    // 200 bytes every 100ms = 2000 B/s, comfortably ABOVE the 1024 B/s floor for the whole test
    // (and well before the 10s grace period even starts mattering, since the 2s total fires
    // first) - this dribble is never what tears the connection down.
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
