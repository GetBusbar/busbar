// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEND-ENVELOPE DIFFERENTIAL (audit finding F1) — every attempt, streaming included, runs
//! under ONE bounded deadline covering connect + response headers, exactly the envelope reqwest's
//! client-level total timeout provided. The regression this pins: the owned-client cutover first
//! re-provided the deadline only for NON-streaming sends and for stream BODIES (armed at
//! headers-arrival), leaving the stream HEAD unbounded — an upstream that completed TCP+TLS and
//! then never sent response headers hung a streaming request forever, holding its permit, with no
//! breaker transient and no in-request failover. reqwest cut that at
//! `limits.upstream_request_timeout_secs`, classified it a timeout, and failed over; so must we.
//!
//! The clock is tokio's PAUSED test clock: the black-holed socket leaves the runtime idle, so the
//! multi-minute ceiling auto-advances instantly — the test proves the 300s-class bound without
//! waiting on it, and a regression back to the unbounded send hangs the test's own 30s guard
//! rather than passing vacuously.

use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

fn member(idx: usize) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

/// A listener that accepts, reads the request, and never writes a byte — the black-holed-headers
/// upstream: connect succeeds, the stream head never arrives.
async fn black_hole() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4096];
                // Consume the request, then hold the socket open forever without responding.
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_black_holed_stream_send_times_out_at_the_ceiling_and_records_the_failure() {
    crate::testkit::install_test_seams();
    let (addr, server) = black_hole().await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            &format!("http://{addr}"),
        ))
        .pool("p", &[(0, 1)])
        .build();

    let body: bytes::Bytes = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{ "role": "user", "content": "hi" }],
        "stream": true,
    }))
    .unwrap()
    .into();

    // The 30s REAL-time guard is the regression detector: with the send envelope in place the
    // paused clock auto-advances through the ceiling instantly; without it (the F1 bug) the send
    // awaits socket I/O forever and this test fails by its own bound instead of hanging CI.
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(30_000), // paused-clock units; auto-advance skips to timers
        crate::engine::forward_with_pool(
            &app,
            vec![member(0)],
            body,
            None,
            "p",
            None,
            "openai",
            crate::test_support::CHAT,
            None,
        ),
    )
    .await
    .expect("the stream send must resolve at the ceiling, never hang");

    // One lane, its only attempt timed out → the request surfaces an upstream-failure status
    // (never a 2xx, never a hang) and the breaker recorded the transient against the pool cell —
    // asserted directly (the re-audit noted a status-only assertion under-pins the claim).
    assert!(
        resp.status().is_server_error(),
        "black-holed headers must classify as an upstream failure, got {}",
        resp.status()
    );
    assert_eq!(
        app.store.snapshot(0, busbar_substrate::store::now()).err,
        1,
        "the ceiling expiry must record a breaker transient, not just an error status"
    );
    server.abort();
}

/// The SAME hole on the DEGRADED WALK (`forward_once`) — the re-audit found the first fix closed
/// only the main path, and the degraded walk fires precisely when lanes are unhealthy: exactly
/// where black-holing upstreams live. One lane, breaker forced Open, `least_bad` licensed → the
/// dispatch takes `forward_once`; its stream send must ride the same ceiling envelope.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_black_holed_stream_send_on_the_degraded_walk_times_out_at_the_ceiling() {
    crate::testkit::install_test_seams();
    let (addr, server) = black_hole().await;
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            &format!("http://{addr}"),
        ))
        .pool("p", &[(0, 1)])
        .on_exhausted("p", busbar_core::config::OnExhausted::LeastBad)
        .build();
    // The only member's breaker is Open → the pool is exhausted → least_bad degrades onto it.
    app.store
        .force_open_in("p", 0, busbar_substrate::store::now() + 300);

    let body: bytes::Bytes = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{ "role": "user", "content": "hi" }],
        "stream": true,
    }))
    .unwrap()
    .into();

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(30_000), // paused-clock guard; see the sibling test
        crate::engine::forward_with_pool(
            &app,
            vec![member(0)],
            body,
            None,
            "p",
            None,
            "openai",
            crate::test_support::CHAT,
            None,
        ),
    )
    .await
    .expect("the degraded stream send must resolve at the ceiling, never hang");

    assert!(
        resp.status().is_server_error(),
        "black-holed headers on the degraded walk must classify as an upstream failure, got {}",
        resp.status()
    );
    assert_eq!(
        app.store.snapshot(0, busbar_substrate::store::now()).err,
        1,
        "the degraded-path ceiling expiry must record the breaker transient too"
    );
    server.abort();
}
