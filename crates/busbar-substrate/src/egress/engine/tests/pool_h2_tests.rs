// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OWNED-POOL h2 ROWS: one multiplexed conn per authority (singleflight on
//! the wire), the `:authority` differential against the legacy client, the last-CHECKOUT idle
//! clock, the generation-guarded clear that lets a stale driver exit clear nothing, and the
//! KnownProto transition rule — h2 evidence dies with the entry that carried it, so a fleet that
//! rolls back to h1 gets the h1 dial bound and unicast failures again.
//!
//! Two fixtures: an h2c (prior-knowledge) hyper server on plain TCP, and an ALPN-SWITCH TLS
//! server that offers `h2,http/1.1` to one era of connections and `http/1.1`-only to the next —
//! the evidence-learning and evidence-revoking halves of the transition rule.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use rustls_pki_types::pem::PemObject;

use super::client::PoolConfig;
use super::pool;
use super::resolve::ResolveNames;
use super::*;
use crate::egress::fixtures::{ca_and_leaf, certs_from_pem};

// The scripted-dial machinery and connector builders are shared with the h1 battery.
use super::pool_tests::{
    cfg, eventually, get, ip_only, key_of, plain_connector, tls_connector_all_versions, DialScript,
    ScriptedDial,
};

/// A plain-TCP hyper h2c server: per-connection tasks on a dedicated runtime thread, recording
/// what each request carried (method, uri, Host header presence) and how many CONNECTIONS were
/// accepted — the singleflight observable.
struct H2cFixture {
    addr: SocketAddr,
    conns: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

fn spawn_h2c(close_after_first_response: bool) -> H2cFixture {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let conns = Arc::new(AtomicUsize::new(0));
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let (conns2, seen2) = (Arc::clone(&conns), Arc::clone(&seen));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture runtime");
        listener.set_nonblocking(true).expect("nonblocking");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let conn_index = conns2.fetch_add(1, Ordering::SeqCst);
                // Only the FIRST connection GOAWAYs after its first exchange — later conns
                // must stay healthy so the generation-guard rows can observe reuse.
                let close_after_first_response = close_after_first_response && conn_index == 0;
                let seen = Arc::clone(&seen2);
                tokio::spawn(async move {
                    let served = Arc::new(tokio::sync::Notify::new());
                    let served_tx = Arc::clone(&served);
                    let svc = hyper::service::service_fn(
                        move |req: http::Request<hyper::body::Incoming>| {
                            let seen = Arc::clone(&seen);
                            let served = Arc::clone(&served_tx);
                            async move {
                                seen.lock().expect("seen").push(format!(
                                    "{} {} host={:?}",
                                    req.method(),
                                    req.uri(),
                                    req.headers().get(http::header::HOST)
                                ));
                                served.notify_one();
                                Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                    Bytes::from_static(b"h2ok"),
                                )))
                            }
                        },
                    );
                    let conn = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc);
                    if close_after_first_response {
                        tokio::pin!(conn);
                        tokio::select! {
                            _ = conn.as_mut() => {}
                            _ = served.notified() => {
                                // GOAWAY after the first exchange: graceful, streams drain.
                                conn.as_mut().graceful_shutdown();
                                let _ = conn.await;
                            }
                        }
                    } else {
                        let _ = conn.await;
                    }
                });
            }
        });
    });
    H2cFixture { addr, conns, seen }
}

fn h2c_client(calls: &Arc<ScriptedDial>) -> EngineClient {
    EngineClient::assemble(
        plain_connector(
            EgressResolver::Custom(Arc::clone(calls) as Arc<dyn ResolveNames>),
            4,
            Duration::from_secs(10),
        ),
        PoolConfig {
            h2_prior_knowledge: true,
            ..cfg(4)
        },
    )
}

/// h2 requests keep the absolute-form URI (`:authority` derived from it, no Host header) — the
/// no-preparation differential: what the upstream sees through the owned client equals what it sees
/// through the legacy client (`http2_only`), and N concurrent requests ride ONE connection on
/// both (the multiplexing observable).
#[tokio::test]
async fn h2_authority_and_multiplexing_match_legacy() {
    let answer_fixture = spawn_h2c(false);
    let answer = ip_only(answer_fixture.addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let uri = format!(
        "http://h2wire.test:{}/v1/messages",
        answer_fixture.addr.port()
    );

    // Legacy, prior-knowledge (http2_only) over the same connector shape.
    let mut builder =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new());
    builder
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .timer(hyper_util::rt::TokioTimer::new())
        .http2_only(true);
    let legacy: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        builder.build(plain_connector(
            EgressResolver::Custom(Arc::clone(&script) as Arc<dyn ResolveNames>),
            4,
            Duration::from_secs(10),
        ));
    for _ in 0..3 {
        let resp = legacy.request(get(&uri)).await.expect("legacy h2c");
        let _ = resp.into_body().collect().await;
    }
    let legacy_conns = answer_fixture.conns.load(Ordering::SeqCst);
    assert_eq!(legacy_conns, 1, "legacy multiplexes onto one conn");

    let owned = h2c_client(&script);
    for _ in 0..3 {
        let resp = owned.request(get(&uri)).await.expect("owned h2c");
        let _ = resp.into_body().collect().await;
    }
    assert_eq!(
        answer_fixture.conns.load(Ordering::SeqCst),
        2,
        "the owned client multiplexes onto ONE conn of its own"
    );

    let seen = answer_fixture.seen.lock().expect("seen").clone();
    assert_eq!(seen.len(), 6);
    for i in 0..3 {
        assert_eq!(
            seen[i],
            seen[i + 3],
            "request {i}: the owned h2 wire view must equal legacy's (:authority, :path, Host)"
        );
    }
}

/// The h2 idle clock is time-since-last-CHECKOUT: checkouts inside the window keep refreshing it
/// (no eviction even past the timeout since install), and a quiet window past the timeout evicts
/// — the next request dials a SECOND connection.
#[tokio::test]
async fn h2_entry_expires_on_the_last_checkout_clock() {
    let fixture = spawn_h2c(false);
    let answer = ip_only(fixture.addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = EngineClient::assemble(
        plain_connector(
            EgressResolver::Custom(Arc::clone(&script) as Arc<dyn ResolveNames>),
            4,
            Duration::from_secs(10),
        ),
        PoolConfig {
            h2_prior_knowledge: true,
            idle_timeout: Duration::from_millis(400),
            ..cfg(4)
        },
    );
    let uri = format!("http://h2clock.test:{}/v1/x", fixture.addr.port());

    // Three checkouts, each inside the window of the previous — total elapsed exceeds the
    // timeout, but the CLOCK is per-checkout, so the conn survives.
    for _ in 0..3 {
        let resp = client.request(get(&uri)).await.expect("in-window");
        let _ = resp.into_body().collect().await;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(
        fixture.conns.load(Ordering::SeqCst),
        1,
        "recent checkouts must keep refreshing the idle clock"
    );

    // A quiet window past the timeout: the reaper evicts; the next request redials.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let resp = client.request(get(&uri)).await.expect("after eviction");
    let _ = resp.into_body().collect().await;
    assert_eq!(
        fixture.conns.load(Ordering::SeqCst),
        2,
        "a quiescent h2 conn is evicted on timeout-since-last-checkout"
    );
    assert_eq!(script.calls(), 2);
}

/// The generation guard: a STALE driver exit (its conn long since replaced) clears nothing — the
/// newer healthy entry stays installed and the next checkout reuses it with zero extra dials.
/// The stale exit is delivered through the same `clear_h2_generation` the real driver-exit task
/// calls, with the generation a late gen-1 exit would carry.
#[tokio::test]
async fn stale_h2_driver_exit_does_not_clear_newer_conn() {
    let fixture = spawn_h2c(true); // every conn GOAWAYs after its first response
    let answer = ip_only(fixture.addr);
    let script = ScriptedDial::new(move |_| DialScript::Answer(answer));
    let client = h2c_client(&script);
    let uri = format!("http://h2gen.test:{}/v1/x", fixture.addr.port());
    let key = key_of(&uri);

    // Gen 1 installs, serves once, GOAWAYs; the driver-exit clear reverts the entry.
    let resp = client.request(get(&uri)).await.expect("gen-1");
    let _ = resp.into_body().collect().await;
    eventually("gen-1 cleared after GOAWAY", || {
        pool::snapshot_authority(client.inner_for_tests(), &key).is_some_and(|s| !s.has_h2)
    })
    .await;

    // Gen 2 installs.
    let resp = client.request(get(&uri)).await.expect("gen-2");
    let _ = resp.into_body().collect().await;
    eventually("gen-2 installed", || {
        pool::snapshot_authority(client.inner_for_tests(), &key)
            .is_some_and(|s| s.has_h2 && s.h2_generation == 2)
    })
    .await;

    // The stale gen-1 exit lands LATE — after gen-2 installed. It must clear nothing.
    pool::clear_h2_generation(client.inner_for_tests(), &key, 1);
    let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("state");
    assert!(snap.has_h2, "a stale exit must not clear the newer conn");
    assert_eq!(snap.h2_generation, 2);

    // And the next checkout RIDES gen 2 — zero extra dials, zero extra connections.
    let dials_before = script.calls();
    let resp = client.request(get(&uri)).await.expect("reuses gen-2");
    let _ = resp.into_body().collect().await;
    assert_eq!(
        script.calls(),
        dials_before,
        "no redial after a stale clear attempt"
    );
}

// ── The KnownProto transition rule ───────────────────────────────────────────────────────────────

/// The evidence-learning/revoking fixture: TLS where the ALPN OFFER is switchable per
/// connection era, h2 conns served by hyper's h2 server (with a GOAWAY trigger), h1 conns by
/// hyper's h1 server. `stall_tls` freezes the handshake so a burst's dials can be counted while
/// they exist.
struct AlpnSwitchFixture {
    addr: SocketAddr,
    offer_h2: Arc<AtomicBool>,
    stall_tls: Arc<AtomicBool>,
    goaway: Arc<tokio::sync::Notify>,
    /// Connections ACCEPTED (pre-TLS) — the dial-count observable.
    accepted: Arc<AtomicUsize>,
    /// Serve loops that ENDED (conn closed by either side) — the straggler-close observable.
    ended: Arc<AtomicUsize>,
}

fn spawn_alpn_switch(material: &crate::egress::fixtures::CaLeaf) -> AlpnSwitchFixture {
    let chain = certs_from_pem(&material.leaf_pem);
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(material.leaf_key_pem.as_bytes())
        .expect("fixture key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mk = |alpn: Vec<Vec<u8>>| {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain.clone(), key.clone_key())
            .expect("fixture cert");
        config.alpn_protocols = alpn;
        Arc::new(config)
    };
    let cfg_h2 = mk(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    let cfg_h1 = mk(vec![b"http/1.1".to_vec()]);
    let offer_h2 = Arc::new(AtomicBool::new(true));
    let stall_tls = Arc::new(AtomicBool::new(false));
    let goaway = Arc::new(tokio::sync::Notify::new());
    let accepted = Arc::new(AtomicUsize::new(0));
    let ended = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (offer2, stall2, goaway2, accepted2, ended2) = (
        Arc::clone(&offer_h2),
        Arc::clone(&stall_tls),
        Arc::clone(&goaway),
        Arc::clone(&accepted),
        Arc::clone(&ended),
    );
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture runtime");
        listener.set_nonblocking(true).expect("nonblocking");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                accepted2.fetch_add(1, Ordering::SeqCst);
                let config = if offer2.load(Ordering::SeqCst) {
                    Arc::clone(&cfg_h2)
                } else {
                    Arc::clone(&cfg_h1)
                };
                let stall = Arc::clone(&stall2);
                let goaway = Arc::clone(&goaway2);
                let ended = Arc::clone(&ended2);
                tokio::spawn(async move {
                    while stall.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    let acceptor = tokio_rustls::TlsAcceptor::from(config);
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let negotiated_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    let svc = hyper::service::service_fn(
                        |_req: http::Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from_static(b"ok"),
                            )))
                        },
                    );
                    if negotiated_h2 {
                        let conn = hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), svc);
                        tokio::pin!(conn);
                        loop {
                            tokio::select! {
                                _ = conn.as_mut() => break,
                                _ = goaway.notified() => conn.as_mut().graceful_shutdown(),
                            }
                        }
                    } else {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                            .await;
                    }
                    ended.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
    });
    AlpnSwitchFixture {
        addr,
        offer_h2,
        stall_tls,
        goaway,
        accepted,
        ended,
    }
}

/// The transition rule, end to end over real ALPN: an authority LEARNS h2 from one negotiation, a GOAWAY clears
/// the entry AND the learned proto (evidence dies with the entry), and the next cold burst
/// against the now-h1 fleet runs the FULL h1 dial bound in parallel — not the h2 singleflight of
/// 1 — then completes on h1. (The unicast half of the reverted regime is pinned by
/// `unknown_proto_dial_failure_reaches_exactly_one_waiter` — Unknown IS the reverted state.)
#[tokio::test]
async fn goaway_then_h1_redial_reverts_to_unknown_bound_and_unicast() {
    let material = ca_and_leaf(&["alpn.test"]);
    let fixture = spawn_alpn_switch(&material);
    let connector = tls_connector_all_versions(
        &material.ca_pem,
        EgressResolver::Pinned {
            host: Arc::from("alpn.test"),
            addr: fixture.addr.ip(),
        },
        3,
        Duration::from_secs(10),
    );
    let client = EngineClient::assemble(connector, cfg(3));
    let uri = format!("https://alpn.test:{}/v1/x", fixture.addr.port());
    let key = key_of(&uri);

    // Evidence: ALPN negotiates h2, the entry installs, proto learns H2.
    let resp = client.request(get(&uri)).await.expect("h2 era");
    let _ = resp.into_body().collect().await;
    {
        let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("state");
        assert!(snap.has_h2, "ALPN h2 must install the shared entry");
        assert_eq!(snap.proto, pool::KnownProto::H2);
    }

    // The fleet rolls over: h1-only ALPN from now on, and the live conn GOAWAYs.
    fixture.offer_h2.store(false, Ordering::SeqCst);
    fixture.goaway.notify_waiters();
    eventually("the GOAWAY clears the entry AND reverts the proto", || {
        pool::snapshot_authority(client.inner_for_tests(), &key)
            .is_some_and(|s| !s.has_h2 && s.proto == pool::KnownProto::Unknown)
    })
    .await;

    // Cold burst with the handshake frozen: the dial count must be the h1 bound (3), not the
    // h2 singleflight (1) a stuck proto would impose.
    fixture.stall_tls.store(true, Ordering::SeqCst);
    let tasks: Vec<_> = (0..4)
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
    eventually("the burst dials at the h1 bound", || {
        pool::snapshot_authority(client.inner_for_tests(), &key)
            .is_some_and(|s| s.inflight_dials == 3)
    })
    .await;
    {
        let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("state");
        assert_eq!(
            snap.inflight_dials, 3,
            "the reverted authority must dial at the h1 bound, not singleflight"
        );
    }

    // Thaw: the burst completes over h1 — the authority now carries h1 evidence.
    fixture.stall_tls.store(false, Ordering::SeqCst);
    for task in tasks {
        task.await.expect("join").expect("h1-era request completes");
    }
    let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("state");
    assert_eq!(
        snap.proto,
        pool::KnownProto::H1,
        "h1 success re-learns the proto"
    );
    assert!(!snap.has_h2);
}

/// THE STRAGGLER-CLOSE PIN: two Unknown-era dials race against an h2 upstream; the first
/// completion installs the shared entry and drains BOTH waiters, the second is a straggler and
/// is CLOSED — never parked (the h1-typed idle deque cannot hold it, and a second shared conn is
/// refused exactly as legacy's put() refused one). The upstream observes exactly one surviving
/// connection, the generation counter shows exactly one install, and no further dial is started.
#[tokio::test]
async fn the_second_unknown_era_h2_dial_is_closed_never_parked() {
    let material = ca_and_leaf(&["straggle.test"]);
    let fixture = spawn_alpn_switch(&material); // offers h2 to every connection
    let connector = tls_connector_all_versions(
        &material.ca_pem,
        EgressResolver::Pinned {
            host: Arc::from("straggle.test"),
            addr: fixture.addr.ip(),
        },
        2,
        Duration::from_secs(10),
    );
    let client = EngineClient::assemble(connector, cfg(2));
    let uri = format!("https://straggle.test:{}/v1/x", fixture.addr.port());
    let key = key_of(&uri);

    // Freeze the handshakes so BOTH Unknown-era dials exist at once (proto Unknown → h1 bound).
    fixture.stall_tls.store(true, Ordering::SeqCst);
    let tasks: Vec<_> = (0..2)
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
    eventually("two Unknown-era dials in flight", || {
        pool::snapshot_authority(client.inner_for_tests(), &key)
            .is_some_and(|s| s.inflight_dials == 2)
    })
    .await;

    // Thaw: both negotiate h2. One installs and serves everyone; the other must be closed.
    fixture.stall_tls.store(false, Ordering::SeqCst);
    for task in tasks {
        task.await.expect("join").expect("both requests complete");
    }
    eventually("the straggler is closed and the winner survives", || {
        fixture.accepted.load(Ordering::SeqCst) == 2 && fixture.ended.load(Ordering::SeqCst) == 1
    })
    .await;
    let snap = pool::snapshot_authority(client.inner_for_tests(), &key).expect("state");
    assert!(snap.has_h2, "the winner is installed as the shared entry");
    assert_eq!(
        snap.h2_generation, 1,
        "exactly ONE install — the straggler never replaced the winner"
    );
    assert_eq!(
        snap.idle, 0,
        "the straggler is never parked in the h1 idle deque"
    );
    assert_eq!(snap.inflight_dials, 0);
    assert_eq!(snap.waiters, 0);
    assert_eq!(snap.proto, pool::KnownProto::H2);

    // And the survivor serves the next request — no new connection, no new dial.
    let resp = client.request(get(&uri)).await.expect("rides the winner");
    let _ = resp.into_body().collect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        fixture.accepted.load(Ordering::SeqCst),
        2,
        "the third request multiplexes onto the surviving conn"
    );
    assert_eq!(
        fixture.ended.load(Ordering::SeqCst),
        1,
        "the winner stays alive"
    );
}
