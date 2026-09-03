// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED-POOL PINNING BATTERY — the semantics-preservation matrix, test for test. Every row that names a behavior the
//! legacy `hyper_util` client exhibited is pinned here against the OWNED pool: the byte-level
//! wire differential (request line + Host vs the legacy client on the same connector), the
//! coalescing invariant (dial counts under bursts, cancels, and dead upstreams), FIFO fairness,
//! the park-at-cap and idle-FIN behaviors, the h2 singleflight/broadcast/generation story with
//! the KnownProto transition rule, the `take_message()` retry boundary with its over-retry
//! falsifier (a billing POST must arrive exactly once), the DOA checkout-level retry, and the
//! error-chain contract core's ERR_NET_TIMEOUT walk depends on.
//!
//! Scripted DIALS drive the deterministic rows: a `ResolveNames` double owns each dial's fate
//! (answer, fail after a delay, block, wait for a latch), so "how many dials exist" is the
//! resolver's call count and no test ever sleeps hoping a race resolves the right way.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};

use super::client::PoolConfig;
use super::pool;
use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::{ca_and_leaf, certs_from_pem, spawn_http, CannedResponse};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ── Scripted dials ───────────────────────────────────────────────────────────────────────────────

/// What one dial attempt does, chosen by attempt index.
pub(super) enum DialScript {
    /// Resolve to this address (the URI's port wins — pass port 0).
    Answer(SocketAddr),
    /// Fail the dial after a delay (a refused upstream with a visible latency).
    FailAfter(Duration),
    /// Never resolve (a black hole; the ConnectDeadline is the only exit).
    Block,
    /// Hold until the latch flips, then resolve — the "dials in flight" freeze-frame.
    AnswerWhen(Arc<AtomicBool>, SocketAddr),
}

pub(super) struct ScriptedDial {
    calls: AtomicUsize,
    script: Box<dyn Fn(usize) -> DialScript + Send + Sync>,
}

impl ScriptedDial {
    pub(super) fn new(script: impl Fn(usize) -> DialScript + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(ScriptedDial {
            calls: AtomicUsize::new(0),
            script: Box::new(script),
        })
    }

    /// Dial attempts so far — the resolver is consulted exactly once per dial, so this IS the
    /// dial count the coalescing rows assert on.
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ResolveNames for ScriptedDial {
    fn resolve(
        &self,
        _name: &str,
    ) -> futures::future::BoxFuture<'static, Result<Vec<SocketAddr>, BoxError>> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        match (self.script)(n) {
            DialScript::Answer(addr) => Box::pin(std::future::ready(Ok(vec![addr]))),
            DialScript::FailAfter(delay) => Box::pin(async move {
                tokio::time::sleep(delay).await;
                Err::<Vec<SocketAddr>, BoxError>("scripted dial refusal".into())
            }),
            DialScript::Block => Box::pin(std::future::pending()),
            DialScript::AnswerWhen(latch, addr) => Box::pin(async move {
                while !latch.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Ok(vec![addr])
            }),
        }
    }
}

/// An address whose IP answers and whose port the URI overrides (`HttpConnector` always takes
/// the destination's port).
pub(super) fn ip_only(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip(), 0)
}

// ── Client assembly over fixture connectors ──────────────────────────────────────────────────────

/// The engine's exact connector shape over a resolver double, h1-pinned ALPN (the plain-http
/// rows never handshake TLS at all).
pub(super) fn plain_connector(
    resolver: EgressResolver,
    dial_bound: usize,
    deadline: Duration,
) -> EngineConnector {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    let http = tunnel::TunnelConnector::new(http, None, dial_bound);
    let tls = rustls_client_config(&EngineSpec::pooled_webpki(4, 300, false, false)).expect("tls");
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    SpkiObserve::new(ConnectDeadline::new(https, deadline), false)
}

/// The same shape over a fixture CA with the FULL ALPN offer (h2 then h1) — the evidence-learning
/// rows.
pub(super) fn tls_connector_all_versions(
    root_pem: &str,
    resolver: EgressResolver,
    dial_bound: usize,
    deadline: Duration,
) -> EngineConnector {
    let mut roots = rustls::RootCertStore::empty();
    for der in certs_from_pem(root_pem) {
        roots.add(der).expect("fixture root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);
    let http = tunnel::TunnelConnector::new(http, None, dial_bound);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http);
    SpkiObserve::new(ConnectDeadline::new(https, deadline), false)
}

pub(super) fn cfg(dial_bound: usize) -> PoolConfig {
    PoolConfig {
        idle_cap_per_host: 64,
        idle_timeout: Duration::from_secs(300),
        http1_only: false,
        h2_prior_knowledge: false,
        h2_keepalive: None,
        dial_bound,
    }
}

fn client_over(resolver: EgressResolver, config: PoolConfig) -> EngineClient {
    let bound = config.dial_bound;
    EngineClient::assemble(
        plain_connector(resolver, bound, Duration::from_secs(10)),
        config,
    )
}

pub(super) fn get(uri: &str) -> http::Request<Full<Bytes>> {
    request(
        http::Method::GET,
        uri.parse().expect("test uri"),
        http::HeaderMap::new(),
        Bytes::new(),
    )
}

pub(super) fn key_of(uri: &str) -> pool::PoolKey {
    let u: http::Uri = uri.parse().expect("test uri");
    (
        u.scheme().expect("scheme").clone(),
        u.authority().expect("authority").clone(),
    )
}

/// Poll `probe` until it holds or the bound elapses (never a bare sleep-and-hope).
pub(super) async fn eventually(what: &str, mut probe: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !probe() {
        assert!(Instant::now() < deadline, "never settled: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ── Bound derivation ─────────────────────────────────────────────────────────────────────────────

/// Pinned single-client postures take the UNDIVIDED global establishment budget; sharded clients
/// take the per-shard share — and the pool's bound function IS the gate's number (bound ==
/// permits, resolved once in `build_client` from one variable). The cross-crate half of this pin
/// (core's fallback publishes the shard count) lives in busbar-core's worker_shard_tests.
#[test]
fn dial_bound_resolution_pinned_undivided_sharded_divided() {
    let pin = PinnedDest {
        host: Arc::from("pinned.test"),
        addr: std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    assert_eq!(
        dial_bound_for(Some(&pin)),
        tunnel::CONNECTS_PER_AUTHORITY_GLOBAL,
        "a pinned plane's one client is its authority's whole budget"
    );
    assert_eq!(
        dial_bound_for(None),
        (tunnel::CONNECTS_PER_AUTHORITY_GLOBAL / establishment_shards_or_one()).max(1),
        "a sharded client takes the per-shard share of the same constant"
    );
    // Through the real builder: the spec's posture fields alone select the resolution.
    let pinned = build_client(&EngineSpec::pinned(
        Arc::from("pinned.test"),
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        Vec::new(),
    ))
    .expect("pinned build");
    assert_eq!(
        pinned.dial_bound_for_tests(),
        tunnel::CONNECTS_PER_AUTHORITY_GLOBAL
    );
    let sharded =
        build_client(&EngineSpec::pooled_webpki(4, 300, false, false)).expect("llm build");
    assert_eq!(sharded.dial_bound_for_tests(), dial_bound_for(None));
}

// ── Config-off zero cost ─────────────────────────────────────────────────────────────────────────

/// A fresh client has an empty authority map and NO background task: the reaper spawns on first
/// idle insertion, authority entries on first request — an unbuilt/unused plane costs nothing.
#[tokio::test]
async fn a_fresh_client_holds_no_state_and_runs_no_tasks() {
    let script = ScriptedDial::new(|_| DialScript::Block);
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(4));
    let (authorities, reaper) = client.pool_stats_for_tests();
    assert_eq!(
        authorities, 0,
        "no authority entry before the first request"
    );
    assert!(!reaper, "no reaper task before the first idle insertion");
    assert_eq!(script.calls(), 0, "no dial without a request");
}

// ── The coalescing invariant ─────────────────────────────────────────────────────────────────────

/// Cancel M of N waiters mid-dial: the dial count on the wire is exactly the invariant's
/// `min(waiters, dial_bound)` — cancellation kills NO dial (they are detached), the survivors
/// are served, and the surplus conn parks idle. The overshoot mechanism does not exist.
#[tokio::test]
async fn cancel_m_of_n_waiters_dials_exactly_the_invariant_count() {
    let fixture = spawn_http(CannedResponse::ok("pooled"), 100);
    let latch = Arc::new(AtomicBool::new(false));
    let answer = ip_only(fixture.addr);
    let latch2 = Arc::clone(&latch);
    let script = ScriptedDial::new(move |_| DialScript::AnswerWhen(Arc::clone(&latch2), answer));
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(4));
    let uri = format!("http://coalesce.test:{}/v1/x", fixture.addr.port());

    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let client = client.clone();
            let uri = uri.clone();
            tokio::spawn(async move {
                let resp = client.request(get(&uri)).await?;
                let _ = resp.into_body().collect().await;
                Ok::<_, EngineError>(())
            })
        })
        .collect();

    // 6 waiters, bound 4 → exactly 4 dials exist, and the count HOLDS (no racing extras).
    eventually("4 dials in flight", || script.calls() == 4).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(script.calls(), 4, "the invariant caps dials at min(6, 4)");

    // Cancel 3 of the 6 — a dropped waiter is a corpse; no dial dies with it.
    for task in [&tasks[0], &tasks[2], &tasks[4]] {
        task.abort();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        script.calls(),
        4,
        "cancellation must not add or destroy dials"
    );

    // Release the dials: 4 conns complete → 3 survivors served, 1 parks idle, zero new dials.
    latch.store(true, Ordering::SeqCst);
    for (i, task) in tasks.into_iter().enumerate() {
        if i % 2 == 0 && i != 5 {
            let _ = task.await; // aborted
        } else {
            task.await
                .expect("join")
                .expect("a surviving waiter completes");
        }
    }
    // Every conn is CONSUMED (served a survivor and returned, or parked directly): none is
    // dropped, none leaks. The exact count is the invariant re-run at each delivery: corpses
    // still occupy the deque until a deliverer walks past them, so the FIRST completion (which
    // consumes one corpse + one live waiter) re-arms one extra dial — an accepted, provably
    // bounded transient (one per corpse-pop era, never a race, never per-request). Here that is
    // exactly 5 dials for 3 survivors: 3 conns served-and-returned, 2 parked straight to idle.
    let key = key_of(&uri);
    eventually("every dialed conn lands in the idle pool", || {
        pool::snapshot_authority(client.inner_for_tests(), &key)
            .is_some_and(|s| s.idle == 5 && s.inflight_dials == 0 && s.waiters == 0)
    })
    .await;
    assert_eq!(
        script.calls(),
        5,
        "the invariant's total: min(6,4) while frozen, plus ONE corpse-transient re-arm"
    );
}

/// FIFO fairness end to end: with one usable connection, queued requests reach the upstream in
/// enqueue order — the dial-completion delivery and the return-path watcher both serve the queue
/// front-first (this is also the return-path watcher row: the drained body hands the conn to the NEXT
/// WAITER, not the idle list).
#[tokio::test]
async fn queued_waiters_are_served_in_fifo_order_through_the_return_path() {
    // A single-connection server: first conn served (slowly), later conns accepted but never
    // answered — so every request MUST ride conn 1 and arrival order is grant order.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let order2 = Arc::clone(&order);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        let mut first = true;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            if !first {
                held.push(stream);
                continue;
            }
            first = false;
            let order = Arc::clone(&order2);
            std::thread::spawn(move || {
                use std::io::Write;
                while let Some(head) = read_head(&mut stream) {
                    let line = head.lines().next().unwrap_or_default().to_string();
                    order.lock().expect("order").push(line);
                    std::thread::sleep(Duration::from_millis(80));
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                    );
                }
            });
        }
    });

    let answer = ip_only(addr);
    let script = ScriptedDial::new(move |n| {
        if n == 0 {
            DialScript::Answer(answer)
        } else {
            DialScript::Block
        }
    });
    let client = client_over(EgressResolver::Custom(script), cfg(1));

    let mut tasks = Vec::new();
    for i in 1..=3 {
        let client = client.clone();
        let uri = format!("http://fifo.test:{}/{i}", addr.port());
        tasks.push(tokio::spawn(async move {
            let resp = client.request(get(&uri)).await.expect("served");
            let _ = resp.into_body().collect().await;
        }));
        // Fix the enqueue order (each request parks before the next arrives).
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    for task in tasks {
        task.await.expect("join");
    }
    let arrived = order.lock().expect("order").clone();
    assert_eq!(
        arrived,
        vec![
            "GET /1 HTTP/1.1".to_string(),
            "GET /2 HTTP/1.1".to_string(),
            "GET /3 HTTP/1.1".to_string(),
        ],
        "waiters must be served in enqueue order, via the return path"
    );
}

// ── Park-at-cap and idle expiry ──────────────────────────────────────────────────────────────────

/// `idle_cap_per_host` is enforced at PARK time: with cap 2 and three simultaneous conns, the
/// third return closes its socket (the upstream sees EOF) while two stay parked — and no
/// checkout was ever refused.
#[tokio::test]
async fn the_conn_past_the_idle_cap_is_closed_at_park_time() {
    // Hold responses until 3 requests arrived, so three REAL conns must exist; then count EOFs.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let arrived = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let (arrived2, closed2) = (Arc::clone(&arrived), Arc::clone(&closed));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let arrived = Arc::clone(&arrived2);
            let closed = Arc::clone(&closed2);
            std::thread::spawn(move || {
                use std::io::Write;
                if read_head(&mut stream).is_none() {
                    return;
                }
                arrived.fetch_add(1, Ordering::SeqCst);
                while arrived.load(Ordering::SeqCst) < 3 {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                );
                // Keep reading: the next event is either another request or the pool's FIN.
                if read_head(&mut stream).is_none() {
                    closed.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    let answer = ip_only(addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = client_over(
        EgressResolver::Custom(script),
        PoolConfig {
            idle_cap_per_host: 2,
            ..cfg(4)
        },
    );
    let uri = format!("http://cap.test:{}/v1/x", addr.port());
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            let client = client.clone();
            let uri = uri.clone();
            tokio::spawn(async move {
                let resp = client.request(get(&uri)).await.expect("served");
                let _ = resp.into_body().collect().await;
            })
        })
        .collect();
    for task in tasks {
        task.await.expect("join");
    }
    let key = key_of(&uri);
    eventually("two conns parked, one closed", || {
        let idle_ok =
            pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.idle == 2);
        idle_ok && closed.load(Ordering::SeqCst) == 1
    })
    .await;
}

/// `pool_idle_timeout`: an idle conn is reused BEFORE the timeout (same socket, second request)
/// and the upstream sees the FIN within one reaper wakeup AFTER it; with nothing left to expire
/// the reaper exits (zero quiescent tasks).
#[tokio::test]
async fn an_idle_conn_is_reused_before_the_timeout_and_finned_after_it() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let fin_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let (requests2, fin2) = (Arc::clone(&requests), Arc::clone(&fin_at));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let requests = Arc::clone(&requests2);
            let fin_at = Arc::clone(&fin2);
            std::thread::spawn(move || {
                use std::io::Write;
                while read_head(&mut stream).is_some() {
                    requests.fetch_add(1, Ordering::SeqCst);
                    if stream
                        .write_all(
                            b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                        )
                        .is_err()
                    {
                        return;
                    }
                }
                *fin_at.lock().expect("fin") = Some(Instant::now());
            });
        }
    });

    let answer = ip_only(addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = client_over(
        EgressResolver::Custom(script.clone()),
        PoolConfig {
            idle_timeout: Duration::from_millis(300),
            ..cfg(4)
        },
    );
    let uri = format!("http://fin.test:{}/v1/x", addr.port());

    let resp = client.request(get(&uri)).await.expect("first");
    let _ = resp.into_body().collect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Before the timeout: the SAME conn serves (one dial total).
    let resp = client.request(get(&uri)).await.expect("second");
    let _ = resp.into_body().collect().await;
    eventually("both requests on one conn", || {
        requests.load(Ordering::SeqCst) == 2
    })
    .await;
    assert_eq!(script.calls(), 1, "reuse before the timeout means one dial");

    // After the timeout: the reaper drops the conn — the upstream OBSERVES the FIN — and then
    // exits, leaving no background task.
    let parked = Instant::now();
    eventually("the upstream sees the FIN", || {
        fin_at.lock().expect("fin").is_some()
    })
    .await;
    let waited = parked.elapsed();
    assert!(
        waited >= Duration::from_millis(250),
        "the FIN must not arrive before the idle timeout (arrived after {waited:?})"
    );
    eventually("the reaper exits at zero idle", || {
        !client.pool_stats_for_tests().1
    })
    .await;
}

// ── Dead-upstream delivery ───────────────────────────────────────────────────────────────────────

/// h2-known (posture-pinned here) dial failure is a BROADCAST: N parked waiters all receive the
/// Connect-class error inside ONE connect attempt — one dial on the wire, no waiter reclassified
/// into its own deadline (legacy pool parity: a failed h2 Connecting removed every waiter).
#[tokio::test]
async fn h2_dead_upstream_errors_all_waiters_within_one_connect_attempt() {
    let script = ScriptedDial::new(|n| {
        if n == 0 {
            DialScript::FailAfter(Duration::from_millis(150))
        } else {
            DialScript::Block
        }
    });
    let client = client_over(
        EgressResolver::Custom(script.clone()),
        PoolConfig {
            h2_prior_knowledge: true,
            ..cfg(4)
        },
    );
    let started = Instant::now();
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.request(get("http://h2dead.test:1/x")).await })
        })
        .collect();
    for task in tasks {
        let err = task
            .await
            .expect("join")
            .expect_err("a dead h2 upstream errors every waiter");
        assert!(err.is_connect(), "the broadcast carries the Connect class");
        let rendered = crate::egress::with_cause(&err);
        assert!(
            rendered.contains("scripted dial refusal"),
            "the Arc-shared cause chain must survive the fan-out: {rendered}"
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "all eight must error within one connect attempt, not one per attempt"
    );
    assert_eq!(
        script.calls(),
        1,
        "h2-known coalesces to ONE dial (singleflight)"
    );
}

/// The h1/Unknown failure arm stays UNICAST: one dial failure consumes one live waiter; the
/// other waiter keeps waiting on its own (re-armed) dial.
#[tokio::test]
async fn unknown_proto_dial_failure_reaches_exactly_one_waiter() {
    let script = ScriptedDial::new(|n| {
        if n == 0 {
            DialScript::FailAfter(Duration::from_millis(150))
        } else {
            DialScript::Block
        }
    });
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(1));
    let c1 = client.clone();
    let r1 = tokio::spawn(async move { c1.request(get("http://uni.test:1/a")).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let c2 = client.clone();
    let r2 = tokio::spawn(async move { c2.request(get("http://uni.test:1/b")).await });

    let err = r1
        .await
        .expect("join")
        .expect_err("the front waiter takes the dial error");
    assert!(err.is_connect());
    // The second waiter is NOT broadcast to — its own redial (blocked) is its fate.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !r2.is_finished(),
        "unicast: the second waiter must still be parked"
    );
    assert_eq!(
        script.calls(),
        2,
        "the failure re-armed one dial for the survivor"
    );
    r2.abort();
}

/// F7: a cancelled FRONT waiter must not swallow the dial error — the failure walk pops corpses
/// until a LIVE waiter accepts, in the SAME connect attempt (never one full round later).
#[tokio::test]
async fn cancelled_front_waiter_does_not_delay_error_to_live_waiter() {
    let script = ScriptedDial::new(|n| {
        if n == 0 {
            DialScript::FailAfter(Duration::from_millis(250))
        } else {
            DialScript::Block
        }
    });
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(1));
    let c1 = client.clone();
    let r1 = tokio::spawn(async move { c1.request(get("http://corpse.test:1/a")).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let c2 = client.clone();
    let r2 = tokio::spawn(async move { c2.request(get("http://corpse.test:1/b")).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    // The front waiter cancels while the (only) dial is still in flight.
    r1.abort();
    let _ = r1.await;

    let err = r2
        .await
        .expect("join")
        .expect_err("the live waiter behind the corpse takes the error");
    assert!(err.is_connect());
    assert_eq!(
        script.calls(),
        1,
        "the error must reach the live waiter in the SAME attempt — a second dial means it \
         was lost in the corpse's oneshot"
    );
}

/// A waiter parked past its caller's deadline classifies as the caller's DEADLINE (the
/// structural `timeout_at` wrapper), never as some new pool-specific error.
#[tokio::test]
async fn a_waiter_queued_past_its_deadline_classifies_as_deadline() {
    let script = ScriptedDial::new(|_| DialScript::Block);
    let client = client_over(EgressResolver::Custom(script), cfg(1));
    let err = send_bounded(
        &client,
        get("http://parked.test:1/x"),
        tokio::time::Instant::now() + Duration::from_millis(200),
    )
    .await
    .expect_err("a black-holed dial parks the waiter past the deadline");
    assert!(
        matches!(err, HopError::Deadline),
        "queued-past-deadline is the caller's Deadline class"
    );
}

// ── The error-chain contract ─────────────────────────────────────────────────────────────────────

/// The ConnectDeadline's expiry must survive the owned pool as an ERROR OBJECT: core's
/// `EgressSendError::is_timeout()` walks `source()` downcasting for `io::ErrorKind::TimedOut` to
/// classify ERR_NET_TIMEOUT — this test runs that exact walk over the owned `EngineError`, and
/// pins the `with_cause()` rendering the operator sees.
#[tokio::test]
async fn connect_deadline_expiry_classifies_err_net_timeout_via_owned_pool() {
    let script = ScriptedDial::new(|_| DialScript::Block);
    let connector = plain_connector(
        EgressResolver::Custom(script),
        1,
        Duration::from_millis(250),
    );
    let client = EngineClient::assemble(connector, cfg(1));
    let err = client
        .request(get("http://blackhole.test:1/x"))
        .await
        .expect_err("a black-holed connect fails at the deadline");
    assert!(
        err.is_connect(),
        "a connect-deadline expiry is connect-class"
    );

    // Core's downcast walk, verbatim (proxy/engine/mod.rs `is_timeout`).
    let mut found_timeout = false;
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(&err);
    while let Some(cur) = src {
        if let Some(io) = cur.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::TimedOut {
                found_timeout = true;
            }
        }
        src = cur.source();
    }
    assert!(
        found_timeout,
        "the io::ErrorKind::TimedOut object must survive the pool unflattened — without it \
         every connect timeout silently reclassifies as ERR_NET_CONNECT"
    );
    let rendered = crate::egress::with_cause(&err);
    assert!(
        rendered.contains("exceeded the connect deadline"),
        "with_cause renders the deadline's own words: {rendered}"
    );
}

/// Dial-error cause QUALITY is legacy parity: a TLS trust refusal renders the real rustls cause
/// through both clients — never a vague \"channel closed\" (the h1 err_rx correlation).
#[tokio::test]
async fn tls_refused_dial_renders_the_real_cause_on_both_clients() {
    use crate::egress::fixtures::{spawn_tls, ClientAuth, TlsServerSpec};
    let server_material = ca_and_leaf(&["refused.test"]);
    let other_ca = ca_and_leaf(&["refused.test"]);
    let fixture = spawn_tls(TlsServerSpec {
        cert_chain_pem: server_material.leaf_pem.clone(),
        key_pem: server_material.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok("never"),
        max_requests_per_connection: 4,
    });
    // Trust ONLY the unrelated CA, so the handshake refuses on trust, deterministically.
    let connector = |bound| {
        tls_connector_all_versions(
            &other_ca.ca_pem,
            EgressResolver::Pinned {
                host: Arc::from("refused.test"),
                addr: fixture.addr.ip(),
            },
            bound,
            Duration::from_secs(10),
        )
    };
    let uri = format!("https://refused.test:{}/x", fixture.addr.port());

    let owned = EngineClient::assemble(connector(4), cfg(4));
    let owned_err = owned
        .request(get(&uri))
        .await
        .expect_err("owned: refused trust");
    let legacy: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector(4));
    let legacy_err = legacy
        .request(get(&uri))
        .await
        .expect_err("legacy: refused trust");

    let owned_cause = crate::egress::with_cause(&owned_err);
    let legacy_cause = crate::egress::with_cause(&legacy_err);
    assert!(owned_err.is_connect() && legacy_err.is_connect());
    for (who, cause) in [("owned", &owned_cause), ("legacy", &legacy_cause)] {
        assert!(
            cause.contains("invalid peer certificate"),
            "{who} must surface the real rustls refusal, got: {cause}"
        );
        assert!(
            !cause.to_ascii_lowercase().contains("channel closed"),
            "{who} must never degrade to a vague channel-closed: {cause}"
        );
    }
}

// ── The wire differential ────────────────────────────────────────────────────────────────────────

/// Build the LEGACY client over the same connector shape — the parity reference the differential
/// rows drive beside the owned client.
fn legacy_client(
    connector: EngineConnector,
) -> hyper_util::client::legacy::Client<EngineConnector, Full<Bytes>> {
    let mut builder =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
    builder
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .timer(hyper_util::rt::TokioTimer::new());
    builder.build(connector)
}

/// The byte-level h1 wire pin: request line + Host through the owned client equal the legacy
/// client's EXACTLY — origin-form target, injected Host with host:port for a non-default port,
/// caller-set Host never clobbered, empty path spelled `/`.
#[tokio::test]
async fn h1_wire_request_line_and_host_match_legacy() {
    let fixture = spawn_http(CannedResponse::ok("wire"), 100);
    let port = fixture.addr.port();
    let mk_resolver = || EgressResolver::Pinned {
        host: Arc::from("wire.test"),
        addr: fixture.addr.ip(),
    };
    let legacy = legacy_client(plain_connector(mk_resolver(), 4, Duration::from_secs(10)));
    let owned = EngineClient::assemble(
        plain_connector(mk_resolver(), 4, Duration::from_secs(10)),
        cfg(4),
    );

    // Case 1: path + query, non-default port → origin-form line + host:port Host.
    // Case 2: caller-set Host → never clobbered.
    // Case 3: no path at all → `/`.
    let case_uris = [
        format!("http://wire.test:{port}/v1/messages?stream=false"),
        format!("http://wire.test:{port}/hosted"),
        format!("http://wire.test:{port}"),
    ];
    let mk_req = |case: usize| {
        let mut headers = http::HeaderMap::new();
        if case == 1 {
            headers.insert(
                http::header::HOST,
                http::HeaderValue::from_static("custom.example"),
            );
        }
        request(
            http::Method::GET,
            case_uris[case].parse().expect("uri"),
            headers,
            Bytes::new(),
        )
    };
    for case in 0..case_uris.len() {
        let resp = legacy.request(mk_req(case)).await.expect("legacy sends");
        let _ = resp.into_body().collect().await;
    }
    for case in 0..case_uris.len() {
        let resp = owned.request(mk_req(case)).await.expect("owned sends");
        let _ = resp.into_body().collect().await;
    }

    let heads = fixture.request_heads();
    assert_eq!(heads.len(), 6, "three cases through each client");
    for case in 0..3 {
        assert_eq!(
            heads[case],
            heads[case + 3],
            "case {case}: the owned client's wire head must be byte-identical to legacy's"
        );
    }
    // And the shape itself (so the differential can never green on two identical defects):
    assert!(heads[0].starts_with("GET /v1/messages?stream=false HTTP/1.1\r\n"));
    assert!(heads[0].contains(&format!("host: wire.test:{port}\r\n")));
    assert!(heads[1].contains("host: custom.example\r\n"));
    assert!(heads[2].starts_with("GET / HTTP/1.1\r\n"));
}

/// Host formatting drops the scheme-default port exactly as legacy's `get_non_default_port`
/// (443-on-https / 80-on-http off the header; everything else on it). Unit-pinned because no
/// loopback fixture can listen on the default ports.
#[test]
fn host_injection_drops_only_the_scheme_default_port() {
    let host_for = |uri: &str| {
        let mut req = get(uri);
        super::client::set_host_header_for_tests(&mut req);
        req.headers()
            .get(http::header::HOST)
            .expect("injected")
            .to_str()
            .expect("ascii")
            .to_string()
    };
    assert_eq!(host_for("https://api.example/v1"), "api.example");
    assert_eq!(host_for("https://api.example:443/v1"), "api.example");
    assert_eq!(host_for("https://api.example:8443/v1"), "api.example:8443");
    assert_eq!(host_for("http://api.example:80/v1"), "api.example");
    assert_eq!(host_for("http://api.example:8080/v1"), "api.example:8080");
}

/// A relative URI errors on BOTH clients (there is no pool key to check out against) — the
/// version-gate/absolute-form surface row.
#[tokio::test]
async fn a_relative_uri_is_refused_by_both_clients() {
    let script = ScriptedDial::new(|_| DialScript::Block);
    let owned = client_over(EgressResolver::Custom(script), cfg(1));
    let mk = || {
        let mut req = http::Request::new(Full::new(Bytes::new()));
        *req.uri_mut() = "/only/a/path".parse().expect("relative uri");
        req
    };
    assert!(owned.request(mk()).await.is_err(), "owned refuses relative");
    let script = ScriptedDial::new(|_| DialScript::Block);
    let legacy = legacy_client(plain_connector(
        EgressResolver::Custom(script),
        1,
        Duration::from_secs(10),
    ));
    assert!(
        legacy.request(mk()).await.is_err(),
        "legacy refuses relative"
    );
}

// ── The take_message retry boundary ──────────────────────────────────────────────────────────────

/// Under-retry direction: the upstream closes the parked conn between requests; the second
/// request still succeeds, on a SECOND connection — exactly two dials total, no error escapes.
#[tokio::test]
async fn a_server_closed_idle_conn_is_recovered_with_exactly_two_dials() {
    // Every conn serves ONE request and then closes (with a keep-alive header, so the client
    // parks it believing it reusable — the reuse race the retry/liveness machinery covers).
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let conns2 = Arc::clone(&conns);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            conns2.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                use std::io::Write;
                if read_head(&mut stream).is_some() {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                    );
                }
                // …and close.
            });
        }
    });
    let answer = ip_only(addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(4));
    let uri = format!("http://oneshot.test:{}/v1/x", addr.port());

    let resp = client.request(get(&uri)).await.expect("first");
    let _ = resp.into_body().collect().await;
    // Give the close time to land so the parked conn is discovered dead (liveness pop or
    // take_message bounce — either recovery path must end in success, invisibly).
    tokio::time::sleep(Duration::from_millis(150)).await;
    let resp = client.request(get(&uri)).await.expect("second succeeds");
    assert_eq!(resp.status(), 200);
    let _ = resp.into_body().collect().await;
    assert_eq!(
        script.calls(),
        2,
        "exactly two dials: one per real connection"
    );
    assert_eq!(conns.load(Ordering::SeqCst), 2);
}

/// THE OVER-RETRY FALSIFIER: a request the dispatcher ACCEPTED (headers written, then the conn
/// died without a response) is NEVER retried — the non-idempotent POST arrives at the upstream
/// exactly once and the caller gets the error. A duplicate arrival is the failure this test
/// exists to make impossible.
#[tokio::test]
async fn dispatched_then_died_is_not_retried() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let billing_posts = Arc::new(AtomicUsize::new(0));
    let (conns2, posts2) = (Arc::clone(&conns), Arc::clone(&billing_posts));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let n = conns2.fetch_add(1, Ordering::SeqCst);
            let posts = Arc::clone(&posts2);
            std::thread::spawn(move || {
                use std::io::Write;
                if n == 0 {
                    // Conn 1: serve the warm-up GET, then read the POST — count its arrival —
                    // and kill the socket without a response byte.
                    if read_head(&mut stream).is_some() {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                        );
                    }
                    if let Some(head) = read_head(&mut stream) {
                        if head.starts_with("POST ") {
                            posts.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    // Drop = abrupt close after accepting the request for processing.
                } else {
                    // Any LATER conn would be a retry vehicle: count what it carries.
                    if let Some(head) = read_head(&mut stream) {
                        if head.starts_with("POST ") {
                            posts.fetch_add(1, Ordering::SeqCst);
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 X\r\ncontent-length: 2\r\nconnection: keep-alive\r\n\r\nok",
                        );
                    }
                }
            });
        }
    });
    let answer = ip_only(addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(4));
    let uri = format!("http://billing.test:{}/v1/charge", addr.port());

    // Warm-up: park a REUSED conn (the retry precondition — a fresh conn is never retried).
    let resp = client.request(get(&uri)).await.expect("warm-up");
    let _ = resp.into_body().collect().await;
    eventually("conn parked", || {
        pool::snapshot_authority(client.inner_for_tests(), &key_of(&uri))
            .is_some_and(|s| s.idle == 1)
    })
    .await;

    let billing = request(
        http::Method::POST,
        uri.parse().expect("uri"),
        http::HeaderMap::new(),
        Bytes::from_static(b"charge-once"),
    );
    let err = client
        .request(billing)
        .await
        .expect_err("a dispatched-then-died POST surfaces the error to the caller");
    assert!(
        !err.is_connect(),
        "the request reached the wire — not connect-class"
    );
    // Settle, then the exactly-once assertion: one arrival, no retry conn, no retry dial.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        billing_posts.load(Ordering::SeqCst),
        1,
        "the non-idempotent POST must arrive EXACTLY once — a duplicate is the defect"
    );
    assert_eq!(
        conns.load(Ordering::SeqCst),
        1,
        "no retry connection was opened"
    );
    assert_eq!(script.calls(), 1, "no retry dial was started");
}

/// Delivered-conn dead-on-arrival: a waiter handed a conn that died in flight drops it and re-enters
/// checkout — a CHECKOUT-level retry, exempt from request-level accounting: the request is sent
/// once, on the live conn, and succeeds.
#[tokio::test]
async fn a_dead_on_arrival_delivery_re_enters_checkout() {
    // A victim server that closes instantly (the dead conn), and a healthy fixture.
    let dead_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let dead_addr = dead_listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in dead_listener.incoming() {
            drop(stream); // accept, close: the conn dies the moment it exists
        }
    });
    let fixture = spawn_http(CannedResponse::ok("alive"), 100);

    // The client's own dials BLOCK: the only conns it can get are the ones this test delivers.
    let script = ScriptedDial::new(|_| DialScript::Block);
    let client = client_over(EgressResolver::Custom(script), cfg(1));
    let uri = format!("http://doa.test:{}/v1/x", fixture.addr.port());
    let key = key_of(&uri);

    let c1 = client.clone();
    let uri2 = uri.clone();
    let task = tokio::spawn(async move { c1.request(get(&uri2)).await });
    eventually("the request parks as a waiter", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.waiters == 1)
    })
    .await;

    // Hand the waiter a conn that is already dead (closed by its server).
    let dead = raw_h1_conn(dead_addr).await;
    eventually("the victim conn observes its close", || {
        dead_is_closed(&dead)
    })
    .await;
    pool::return_h1_conn(
        client.inner_for_tests(),
        &key,
        dead,
        pool::ConnSnapshot {
            spki: None,
            negotiated_h2: false,
        },
    );
    // The waiter must NOT error: it re-enters checkout and parks again.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !task.is_finished(),
        "a DOA delivery re-enters checkout, never errors"
    );
    eventually("the waiter re-parked", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.waiters == 1)
    })
    .await;

    // Now hand it a LIVE conn: the request completes, sent exactly once.
    let live = raw_h1_conn(fixture.addr).await;
    pool::return_h1_conn(
        client.inner_for_tests(),
        &key,
        live,
        pool::ConnSnapshot {
            spki: None,
            negotiated_h2: false,
        },
    );
    let resp = task
        .await
        .expect("join")
        .expect("the re-checked-out waiter completes");
    assert_eq!(resp.status(), 200);
    let records = fixture.records();
    assert_eq!(records.len(), 1, "one live conn");
    assert_eq!(records[0].requests, 1, "the request was sent exactly once");
}

/// THE FRESH HALF of the DOA boundary: a conn delivered as a FRESH dial's conn that is already
/// dead when the waiter wakes goes to the CALLER and errors terminally — it never re-enters
/// checkout and never starts another dial.
///
/// This is the boundary legacy drew without a line of code: `hyper_util` never liveness-gated a
/// fresh connect's conn (only a pooled value could be `CheckedOutClosedValue`), so a conn that
/// died between connect-complete and dispatch surfaced through the send, terminally. The first
/// cut of the owned pool ran the DOA re-checkout on fresh conns too, and against a peer that
/// ACCEPTS the connect and then kills the conn that was an UNBOUNDED redial loop for one logical
/// request: under TLS 1.3 an mTLS server that refuses the client certificate does so after the
/// client's own handshake completes, so every dial "succeeds", can be delivered, die on arrival,
/// and re-enter checkout for another full handshake. The a2a mtls isolation test caught its peer
/// recording TWO refused handshakes for one GET (dev CI run 33275270894, `[Ok(1), Err, Err]`
/// where the shape pins `[Ok(1), Err]`); widening the delivery-to-liveness-check window by 2ms
/// turned that into hundreds. Only the REUSED arm re-checks out (the test above), which is what
/// makes the checkout-level retry terminate structurally.
#[tokio::test]
async fn a_dead_on_arrival_fresh_conn_is_terminal_never_re_dialed() {
    // A victim server that closes instantly: the conn is dead the moment it exists — the same
    // observable shape as a post-handshake TLS refusal landing before the waiter wakes.
    let dead_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let dead_addr = dead_listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in dead_listener.incoming() {
            drop(stream);
        }
    });

    // The client's own dials BLOCK: the only conn it can get is the one this test delivers, and
    // the call count exposes any redial the DOA path would start.
    let script = ScriptedDial::new(|_| DialScript::Block);
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(1));
    let uri = format!("http://freshdoa.test:{}/v1/x", dead_addr.port());
    let key = key_of(&uri);

    let c1 = client.clone();
    let uri2 = uri.clone();
    let task = tokio::spawn(async move { c1.request(get(&uri2)).await });
    eventually("the request parks as a waiter", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.waiters == 1)
    })
    .await;

    // An already-dead conn, delivered through the dial-success walk marked FRESH.
    let dead = raw_h1_conn(dead_addr).await;
    eventually("the victim conn observes its close", || {
        dead_is_closed(&dead)
    })
    .await;
    pool::deliver_fresh_h1_for_tests(
        client.inner_for_tests(),
        &key,
        dead,
        pool::ConnSnapshot {
            spki: None,
            negotiated_h2: false,
        },
    );

    // The caller ERRORS, promptly — under the fresh-DOA-re-checkout defect it re-parked forever
    // (the timeout is the red half of this pin, not a race allowance).
    let err = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("a fresh conn dead on arrival errors the caller — it must not re-enter checkout")
        .expect("join")
        .expect_err("a fresh conn dead on arrival is real and terminal");
    assert!(
        !err.is_connect(),
        "the conn was established — legacy surfaced this timing through the send, never as \
         connect-class"
    );
    assert_eq!(
        client.retry_bounces_for_tests(),
        0,
        "a fresh conn never enters the request-level retry loop either"
    );
    assert_eq!(
        script.calls(),
        1,
        "the one original (still-blocked) dial is all that ever existed — no redial"
    );
    let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("authority");
    assert_eq!(snap.waiters, 0, "the waiter did not re-park");
}

/// Hand-shake a bare h1 conn (no pool) — the DOA test's delivery vehicle.
async fn raw_h1_conn(addr: SocketAddr) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (tx, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    tx
}

fn dead_is_closed(tx: &hyper::client::conn::http1::SendRequest<Full<Bytes>>) -> bool {
    tx.is_closed()
}

// ── Raw-server plumbing ──────────────────────────────────────────────────────────────────────────

/// Read one request head + its content-length body off a std stream; `None` at EOF/error.
fn read_head(stream: &mut std::net::TcpStream) -> Option<String> {
    use std::io::Read;
    let mut head: Vec<u8> = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    let split_at = loop {
        if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&buf[..n]);
    };
    let (head_bytes, over_read) = head.split_at(split_at);
    let head_text = String::from_utf8_lossy(head_bytes).into_owned();
    let content_length: usize = head_text
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(over_read.len());
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let n = stream.read(&mut buf[..want]).ok()?;
        if n == 0 {
            return None;
        }
        remaining -= n;
    }
    Some(head_text)
}

// ── The take_message bounce itself, staged deterministically ────────────────────────────────────
//
// The server-closed-idle test above pins the OUTCOME of the reuse race but usually recovers via
// the pop-time liveness check, so the bounce → URI-restore → retry branch itself needs its own
// pin. The bounce's precondition is precise: hyper's h1 dispatcher must terminate WITHOUT ever
// dequeuing the queued request (a dispatcher that dequeues cannot give the message back). A
// socket-level FIN cannot stage that deterministically — tokio's cached readiness lets the
// dispatcher dequeue-and-write before it observes a buffered EOF — so these tests stage it at
// the dispatch level with a REAL hyper conn whose driver is a PAUSABLE pump: pause the driver
// (a descheduled driver, exactly what the production race is), deliver the conn, let the send
// queue its message against the frozen dispatcher, then drop the conn — the unconsumed message
// comes back through `take_message()`, which is the branch under test.

/// A real h1 conn to `addr` whose driver can be paused (polls return Pending without touching
/// the conn) and then killed (conn dropped un-polled, closing the dispatch channel with any
/// queued message unconsumed).
struct PausableConn {
    sender: Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>>,
    /// While false, the pump refuses to poll the conn.
    run: Arc<AtomicBool>,
    /// Set by the pump each time it is woken while paused — the "a message was queued against
    /// the frozen dispatcher" observable.
    poked: Arc<AtomicBool>,
    /// Flipping this makes the pump exit, DROPPING the conn.
    drop_now: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<std::task::Waker>>>,
}

impl PausableConn {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (mut tx, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(
            hyper_util::rt::TokioIo::new(stream),
        )
        .await
        .expect("handshake");
        let run = Arc::new(AtomicBool::new(true));
        let poked = Arc::new(AtomicBool::new(false));
        let drop_now = Arc::new(AtomicBool::new(false));
        let waker: Arc<Mutex<Option<std::task::Waker>>> = Arc::new(Mutex::new(None));
        let (run2, poked2, drop2, waker2) = (
            Arc::clone(&run),
            Arc::clone(&poked),
            Arc::clone(&drop_now),
            Arc::clone(&waker),
        );
        tokio::spawn(async move {
            let mut conn = Box::pin(conn);
            std::future::poll_fn(move |cx| {
                if drop2.load(Ordering::SeqCst) {
                    return std::task::Poll::Ready(()); // exit: `conn` drops un-polled
                }
                if !run2.load(Ordering::SeqCst) {
                    poked2.store(true, Ordering::SeqCst);
                    *waker2.lock().expect("waker") = Some(cx.waker().clone());
                    return std::task::Poll::Pending;
                }
                *waker2.lock().expect("waker") = Some(cx.waker().clone());
                std::future::Future::poll(conn.as_mut(), cx).map(|_| ())
            })
            .await;
        });
        // Drive the dispatcher to readiness (want registered) while the pump still runs — the
        // conn is now indistinguishable from a healthy parked one: ready, not closed.
        tx.ready().await.expect("conn readies up");
        PausableConn {
            sender: Some(tx),
            run,
            poked,
            drop_now,
            waker,
        }
    }

    fn take_sender(&mut self) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        self.sender.take().expect("sender taken once")
    }

    fn pause(&self) {
        self.run.store(false, Ordering::SeqCst);
    }

    /// Kill the conn: the pump exits on its next poll, dropping the conn and closing the
    /// dispatch channel — any queued, un-dequeued message is handed back to its sender.
    fn drop_conn(&self) {
        self.drop_now.store(true, Ordering::SeqCst);
        if let Some(w) = self.waker.lock().expect("waker").take() {
            w.wake();
        }
    }

    async fn wait_poked(&self) {
        eventually(
            "the frozen dispatcher was poked by a queued message",
            || self.poked.load(Ordering::SeqCst),
        )
        .await;
    }
}

/// THE BOUNCE PIN: a REUSED conn whose dispatcher dies without dequeuing hands the request back;
/// the retry loop takes EXACTLY ONE bounce (counted directly), restores the ORIGINAL
/// absolute-form URI, re-checks out fresh, and the request succeeds — the surviving connection's
/// wire head carries the origin-form of the original URI with the re-injected Host, which a lost
/// restore cannot produce (attempt 2 would re-prepare an already-origin-form URI and die on the
/// missing host).
#[tokio::test]
async fn a_take_message_bounce_retries_once_with_the_original_uri_restored() {
    let fixture = spawn_http(CannedResponse::ok("retried"), 100);
    let answer = ip_only(fixture.addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(2));
    let port = fixture.addr.port();
    let uri = format!("http://bounce.test:{port}/v1/retry?attempt=one");
    let key = key_of(&uri);

    // A healthy real conn whose driver FREEZES: ready, not closed — the descheduled-driver
    // shape — PARKED IDLE, so the request checks it out as a REUSED conn.
    let mut doctored = PausableConn::connect(fixture.addr).await;
    doctored.pause();
    pool::ensure_authority_for_tests(client.inner_for_tests(), &key);
    pool::return_h1_conn(
        client.inner_for_tests(),
        &key,
        doctored.take_sender(),
        pool::ConnSnapshot {
            spki: None,
            negotiated_h2: false,
        },
    );
    eventually("the doctored conn parks idle", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.idle == 1)
    })
    .await;

    // The request pops it (liveness passes: ready, not closed) and queues its message against
    // the frozen dispatcher (the poke). THEN the conn dies — the message comes back un-dequeued
    // and the retry loop restores the URI and dials fresh.
    let c1 = client.clone();
    let uri2 = uri.clone();
    let task = tokio::spawn(async move { c1.request(get(&uri2)).await });
    doctored.wait_poked().await;
    doctored.drop_conn();

    let resp = task
        .await
        .expect("join")
        .expect("the bounced request is retried and succeeds");
    assert_eq!(resp.status(), 200);
    let _ = resp.into_body().collect().await;

    assert_eq!(
        client.retry_bounces_for_tests(),
        1,
        "the retry loop must take exactly ONE take_message bounce — zero means this pin went \
         through some other recovery and is vacuous"
    );
    assert_eq!(
        script.calls(),
        1,
        "exactly ONE pool dial exists: the post-bounce redial (the doctored conn was parked, \
         never dialed)"
    );
    let heads = fixture.request_heads();
    assert_eq!(
        heads.len(),
        1,
        "the bounced request never reached the doctored conn's wire; only the retry lands"
    );
    assert!(
        heads[0].starts_with("GET /v1/retry?attempt=one HTTP/1.1\r\n"),
        "attempt 2 must carry the ORIGINAL URI's origin-form — the per-attempt restore: {}",
        heads[0]
    );
    assert!(
        heads[0].contains(&format!("host: bounce.test:{port}\r\n")),
        "attempt 2 re-injects Host from the restored absolute-form URI: {}",
        heads[0]
    );
    // The doctored conn contributed a connection that served zero requests.
    let records = fixture.records();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records.iter().map(|r| r.requests).sum::<usize>(),
        1,
        "exactly one request total crossed the wire — no duplicate from the retry"
    );
}

/// THE TERMINAL HALF of the retry boundary: the same un-dequeued bounce on a conn delivered as a
/// FRESH dial's conn is NOT retried — the error surfaces (not connect-class: the conn existed),
/// the bounce counter stays at zero, and no redial is started.
#[tokio::test]
async fn a_fresh_conn_take_message_bounce_is_terminal_not_retried() {
    let fixture = spawn_http(CannedResponse::ok("never"), 100);
    let script = ScriptedDial::new(|_| DialScript::Block);
    let client = client_over(EgressResolver::Custom(script.clone()), cfg(1));
    let uri = format!("http://freshfin.test:{}/v1/x", fixture.addr.port());
    let key = key_of(&uri);

    let c1 = client.clone();
    let uri2 = uri.clone();
    let task = tokio::spawn(async move { c1.request(get(&uri2)).await });
    eventually("the request parks as a waiter", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| s.waiters == 1)
    })
    .await;

    let mut doctored = PausableConn::connect(fixture.addr).await;
    doctored.pause();
    // Delivered through the dial-success walk, marked FRESH.
    pool::deliver_fresh_h1_for_tests(
        client.inner_for_tests(),
        &key,
        doctored.take_sender(),
        pool::ConnSnapshot {
            spki: None,
            negotiated_h2: false,
        },
    );
    doctored.wait_poked().await;
    doctored.drop_conn();

    let err = task
        .await
        .expect("join")
        .expect_err("a fresh conn's bounce is real and terminal");
    assert!(
        !err.is_connect(),
        "the conn was established — the Canceled class, not Connect"
    );
    assert_eq!(
        client.retry_bounces_for_tests(),
        0,
        "a fresh conn's take_message bounce must never enter the retry loop"
    );
    assert_eq!(
        script.calls(),
        1,
        "no retry dial follows a fresh-conn bounce"
    );
    assert_eq!(
        fixture.records().iter().map(|r| r.requests).sum::<usize>(),
        0,
        "nothing ever reached the wire"
    );
}
