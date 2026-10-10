// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/root/listener.rs`.

//! The TLS listener's serving loop (`serve`) over its opaque connection-security wrap. The wrap
//! itself is the connector's — TLS stays in the connector and the composition root names no TLS
//! library — so the loop is driven here over a connection-security TEST DOUBLE (a one-line hello,
//! no cryptography): every accepted connection goes through the wrap, a connection the wrap refuses
//! is dropped alone and the listener keeps serving. The same loop over the connector's REAL wrap —
//! the trusted client's 200, the mutual handshake accepting a client certificate chaining to
//! `client_ca` and refusing none or a foreign one — is the rows at the end of this file, moved
//! here with the listener from the connector's `tls/engine_tests.rs`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A connection-security TEST DOUBLE: a connection whose first line is `LET-ME-IN` is admitted
/// (handed back as it is, the line consumed); any other is refused, as a handshake the wrap refuses
/// is. The real wrap is the connector's.
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
use busbar_kernel::config::limits::LIMITS_TEST_LOCK;

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

/// Boot the busbar TLS listener's serving loop on an ephemeral port over the connection-security
/// wrap `security` (what `main` hands it from `busbar_core_connector::tls::prepare`). Returns the
/// bound address and a shutdown sender (drop or send to stop + drain).
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
    // No startup sleep: `TcpListener::bind` above ALREADY listens, so the kernel queues an inbound
    // SYN in the accept backlog whether or not the spawned task has reached its first `accept()`
    // yet. A wall-clock "give it a tick" pause is therefore not a synchronisation primitive at all
    // — it is a fixed tax on every run and, on a loaded machine, a bound that can be too short.
    (addr, tx)
}

/// One `GET /healthz` over a fresh connection that opens with `hello`: the response's bytes, empty
/// when the server dropped the connection without answering.
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

/// TESTS 1-3 — the serving loop over its wrap: a connection the wrap admits is served (200), a
/// connection the wrap refuses is dropped unanswered, and the listener survives the refusals and
/// keeps serving admitted connections.
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

    let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", addr.port()))
        .await
        .expect("plain HTTP must still work when tls is absent");
    assert_eq!(resp.status(), 200);
    let _ = tx.send(());
}

// TEST 4b — fail-fast: a bad cert path produces a clear, file-named error from
// `busbar_core_connector::tls::build_server_config` (which `main` turns into `die`). MOVED to
// `busbar-core-connector`'s own test suite (DECISIONS #40): that crate now owns the function and
// its exact error-message format, so its error-path coverage belongs there, not a second copy
// here pointed at this file's test-only fixture (whose error strings intentionally do not try to
// match production's byte-for-byte). See `busbar_core_connector::tls::tests::prepare_fails_closed_on_missing_cert`.

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
    let limits = busbar_kernel::config::LimitsResolved {
        request_body_read_timeout_secs: 1,
        ..busbar_kernel::config::LimitsResolved::default()
    };
    let _limits_guard = busbar_kernel::config::limits::InstallGuard::install(&limits);

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
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

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
    let _baseline = busbar_kernel::config::limits::InstallGuard::install(
        &busbar_kernel::config::LimitsResolved::default(),
    );
    {
        // A candidate config whose build then FAILS. Its limits are live while the build runs…
        let _rejected = busbar_kernel::config::limits::InstallGuard::install(
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
        super::serve_plain(listener, router, shutdown, None)
            .await
            .unwrap();
    });

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
    // this timer NEVER fires (the dribble is far faster than 30s per byte). Through the RAII guard,
    // not the bare setter, for the reason the sibling tests in this file already write down: a bare
    // `install` REPLACES the whole struct behind the process-global RwLock with no restore, so it
    // leaves the limits INSTALLED for every later reader in the binary — and `limits_tests.rs`'s
    // `uninstalled_accessors_return_historical_defaults` asserts against the UNINSTALLED state.
    // That it currently passes is an accident of the values happening to equal the defaults; the
    // guard makes it a property instead of a coincidence.
    let _limits_guard = busbar_kernel::config::limits::InstallGuard::install(
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
    // Through the RAII guard, not the bare setter — see the note in
    // `throughput_floor_trips_on_a_dribble_the_inter_frame_timer_cannot_catch`.
    let _limits_guard = busbar_kernel::config::limits::InstallGuard::install(
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
    let limits = busbar_kernel::config::LimitsResolved {
        request_body_max_bytes: 2048, // total_body_deadline() = 2048 / 1024 B/s = 2s
        ..busbar_kernel::config::LimitsResolved::default()
    };
    // Through the RAII guard, not the bare setter: a bare `install` of this 2 KiB cap LEAKS it
    // to every test in the binary that reads limits afterward (`install` replaces the whole
    // struct with no restore), and `limits/tests/limits_tests.rs`'s
    // `uninstalled_accessors_return_historical_defaults` asserts
    // `busbar_kernel::proxy::max_translate_body_bytes() == DEFAULT_REQUEST_BODY_MAX_BYTES` — so whether the suite
    // passed depended on that test happening to run BEFORE this one. Never committed, so it
    // always rolls back at the end of this test.
    let _limits_guard = busbar_kernel::config::limits::InstallGuard::install(&limits);

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

// ── ConnBalancer placement tests (thread-per-core accept-time rebalancing) ─────────────────────

/// A connected (client, server-accepted) TCP pair on loopback, for feeding the placement seam.
async fn tcp_pair(
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

/// A server-accepted stream as the accept source admits it.
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

    // Below the margin (0 vs 0): serve locally — no handoff.
    let (_c1, s1, p1) = tcp_pair(&listener).await;
    let kept = b0.try_hand_off(admitted(s1, p1));
    assert!(kept.is_some(), "at equal load the connection stays local");
    let g1 = b0.place_local();

    // One more local: still below margin (1 vs 0 < 0+2).
    let (_c2, s2, p2) = tcp_pair(&listener).await;
    assert!(b0.try_hand_off(admitted(s2, p2)).is_some());
    let g2 = b0.place_local();

    // Now 2 vs 0 == min+2: the margin is met — the next accept hands off to a least-loaded
    // worker, its count incremented by the SENDER.
    let (_c3, s3, p3) = tcp_pair(&listener).await;
    assert!(
        b0.try_hand_off(admitted(s3, p3)).is_none(),
        "at min+2 the connection must be handed to the least-loaded worker"
    );
    let others: u32 = [&b1, &b2]
        .iter()
        .map(|b| b.counts[b.me].0.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    assert_eq!(others, 1, "exactly one target counted the handoff");

    // The target adopts without double-counting, and guards decrement on drop.
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

    // A full handoff channel rolls the increment back and serves locally: fill worker 1's
    // channel to capacity, then force a handoff attempt at margin.
    for _ in 0..2 {
        let (_c, s, p) = tcp_pair(&listener).await;
        b0.try_hand_off(admitted(s, p));
        b0.place_local();
    }
    // b1/b2 both at 0; drain nothing — fill b1's queue directly.
    let mut fillers = Vec::new();
    loop {
        let (_c, s, p) = tcp_pair(&listener).await;
        fillers.push(_c);
        match b0.txs[1].try_send(admitted(s, p)) {
            Ok(()) => continue,
            Err(_) => break, // full
        }
    }
    // Park worker 2 at a high count so worker 1 (full channel) is the unique argmin.
    b2.counts[b2.me]
        .0
        .store(100, std::sync::atomic::Ordering::Relaxed);
    let before = b1.counts[b1.me]
        .0
        .load(std::sync::atomic::Ordering::Relaxed);
    let (_c, s, p) = tcp_pair(&listener).await;
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
    drop(b1);
}

/// The receiver-side skew invariant behind the `from_std`-failure fix in the accept/drain loops:
/// the sender increments the TARGET's count BEFORE handing off (so the count is never transiently
/// low), and the receiver owns the matching decrement via a guard it adopts. If the receiver's
/// `from_std` re-adopt fails and it `continue`s, the ONLY thing that releases the sender's
/// increment is a guard adopted BEFORE that fallible conversion — which is exactly the ordering the
/// fix installs. This test pins that invariant: a hand-off increment paired with an adopted guard
/// that is dropped WITHOUT ever serving (the `continue` path) nets the count back to baseline.
/// Against the pre-fix ordering the guard was built only AFTER `from_std` succeeded, so the
/// `continue` skipped it and the increment was stranded high forever (permanent balancer skew).
#[test]
fn recv_side_from_std_failure_releases_the_sender_increment() {
    let mut handles = super::ConnBalancer::build(2);
    let recv = handles.pop().unwrap();
    let _sender = handles.pop().unwrap();
    use std::sync::atomic::Ordering;

    let baseline = recv.counts[recv.me].0.load(Ordering::Relaxed);

    // Sender's increment-before-send lands on the receiver's slot.
    recv.counts[recv.me].0.fetch_add(1, Ordering::Relaxed);
    assert_eq!(recv.counts[recv.me].0.load(Ordering::Relaxed), baseline + 1);

    // Receiver adopts the decrement BEFORE the (here, simulated-failed) `from_std`, then `continue`s
    // — modeled as dropping the guard without serving.
    {
        let _guard = recv.adopt();
        // `from_std` fails here in the real loop; the guard drops on `continue`.
    }

    assert_eq!(
        recv.counts[recv.me].0.load(Ordering::Relaxed),
        baseline,
        "a from_std-failure continue must release the sender's increment, not strand it"
    );
}

/// Binding: the ingress server posture is a hyper HTTP/1 header-read timeout of 30s, a
/// `tls_handshake_timeout_secs` default of 10, and a `request_body_read_timeout_secs` default of
/// 30, asserted against the real default-limits accessors (uninstalled state), not a re-typed copy
/// of the literals. Its ALPN half — `h2, http/1.1` (owner ruling Q137, 2026-10-04; 1.5.5 offered
/// `http/1.1` alone) — is the connector's `build_server_config`, asserted on its real output by
/// `busbar_core_connector::tls::tests::build_server_config_and_prepare_build_from_operator_config`
/// (TLS stays in the connector).
#[tokio::test]
async fn server_posture_matches_the_1_5_5_defaults() {
    let _guard = LIMITS_TEST_LOCK.lock().await;
    // Uninstalled `crate::limits` state: the historical hardcoded defaults these two accessors
    // fall back to, exactly like `uninstalled_accessors_return_historical_defaults` pins for the
    // sibling probe-interval/timeout accessors.
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

    // The hyper HTTP/1 connection builder: `header_read_timeout` requires a `Timer` or hyper
    // panics on the call, so simply building it without panicking is a live regression guard on
    // the `.timer(...)` wiring that makes the 30s `header_read_timeout` at this call site (see its
    // doc comment) actually take effect rather than being silently ignored.
    let _ = super::hardened_conn_builder();
}

/// THE KERNEL SERVES NO HTTP (BUSBAR-1.6.0.md: the kernel is a byte pump; the connector accepts and
/// hands each stream up; the root serves it, here). The accept loop, the hyper connection builder
/// and the graceful drain moved out of `busbar-kernel` into this module; a kernel source naming
/// any of them again is a second serve loop in the wrong home.
#[test]
fn the_kernel_serves_no_http() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read kernel source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-kernel/src"));
    let mut files = Vec::new();
    walk(root, &mut files);
    assert!(
        !files.is_empty(),
        "no kernel sources under {}",
        root.display()
    );
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read kernel source");
        for needle in [
            "hyper_util::server",
            "TowerToHyperService",
            "GracefulShutdown",
        ] {
            if text.contains(needle) {
                hits.push(format!("{}: {needle}", file.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the kernel serves HTTP again; the serve loop lives in `busbar::root::listener`:\n{}",
        hits.join("\n")
    );
}

// ── THE TLS LISTENER over the connector's production wrap ───────────────────────────────────────

fn temp_pem(tag: &str, contents: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "busbar-engine-tls-{tag}-{}-{:?}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::write(&p, contents).expect("write pem");
    p
}

fn file(path: &std::path::Path) -> busbar_kernel::config::SecretRef {
    busbar_kernel::config::SecretRef::file(path.to_string_lossy().into_owned())
}

/// A self-signed server cert for `localhost`/`127.0.0.1`: (cert_pem, key_pem).
fn gen_self_signed() -> (String, String) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("self-signed");
    (cert.pem(), signing_key.serialize_pem())
}

/// Boot the busbar TLS listener (`super::serve`) from a `TlsCfg` on an ephemeral port,
/// secured by the connector's PRODUCTION wrap (`busbar_core_connector::tls::prepare`), exactly as
/// `main`'s TLS branch does. Returns the bound address and a shutdown sender.
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

/// TLS happy path: a client trusting the server's self-signed cert completes an https request and
/// gets 200.
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

/// A CA and a leaf it signed for `sans`: (ca_pem, leaf_pem, leaf_key_pem).
fn gen_ca_and_leaf(sans: &[&str]) -> (String, String, String) {
    let m = busbar_kernel::egress::fixtures::ca_and_leaf(sans);
    (m.ca_pem, m.leaf_pem, m.leaf_key_pem)
}

/// The mutual listener: client certificates must chain to the CA it names.
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

/// mTLS required + valid client cert: a client presenting a leaf signed by the configured CA gets
/// 200.
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

/// mTLS required + no/wrong client cert: the handshake is rejected, the server stays up, and a
/// subsequent valid client still succeeds.
#[tokio::test]
async fn mtls_rejects_bad_client_then_serves_valid() {
    let (srv_cert_pem, srv_key_pem) = gen_self_signed();
    let (ca_pem, leaf_pem, leaf_key_pem) = gen_ca_and_leaf(&["busbar-client"]);
    let (addr, _stop) = spawn_tls_server(&mutual(&srv_cert_pem, &srv_key_pem, &ca_pem)).await;
    let url = format!("https://localhost:{}/healthz", addr.port());

    // (a) Client presenting NO client cert ⇒ rejected (server requires one).
    assert!(
        client_with(&srv_cert_pem, None)
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client with no certificate"
    );
    // (b) Client presenting a cert from a DIFFERENT CA ⇒ also rejected.
    let (_other_ca, wrong_leaf, wrong_key) = gen_ca_and_leaf(&["impostor"]);
    assert!(
        client_with(&srv_cert_pem, Some((&wrong_leaf, &wrong_key)))
            .get(&url)
            .send()
            .await
            .is_err(),
        "mTLS server must reject a client cert from an untrusted CA"
    );
    // (c) Server survived both rejections and still serves a valid client.
    let resp = client_with(&srv_cert_pem, Some((&leaf_pem, &leaf_key_pem)))
        .get(&url)
        .send()
        .await
        .expect("server must remain up and serve a valid client after rejecting bad ones");
    assert_eq!(resp.status(), 200);
}
