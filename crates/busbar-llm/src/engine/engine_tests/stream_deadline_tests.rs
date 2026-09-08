// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PROXIED STREAM IS CUT BY ONE TIMER, AND IT IS THE OPERATOR'S.
//!
//! The design binding this file exists for says the `max_unit_duration` stall sweep only ALARMS on
//! an `http`/`sse` unit, so the only thing that ever cuts such a stream is the total
//! `limits.upstream_request_timeout_secs` deadline — and that there is no idle timer anywhere on
//! the path. Two claims, both about a NEGATIVE, which is why they need driving rather than reading:
//! the way an idle timer arrives is by nobody noticing it did.
//!
//! `send_envelope_tests.rs` already proves a black-holed stream head is cut AT ALL. It cannot prove
//! WHICH timer cut it: the fixture stamped `upstream_request_timeout_secs: 0`, the send site raises
//! that to its one-second floor, and a cut at one second is what a floor, an idle timer, a
//! handshake timer and the operator's own number all look like. So the cut is measured here against
//! a CONFIGURED number, twice, at two different numbers.
//!
//! An idle timer would show up as a cut that does not move: the black hole is idle from the first
//! instant, so anything counting silence fires at its own interval whatever the total deadline
//! says. A cut that lands exactly on the configured second, and moves when that second moves, is
//! the total deadline and nothing else.

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

/// Accepts, drains the request, and never writes a byte: connect succeeds, nothing else happens.
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

/// Drive one streaming request at a black hole under `secs`, and return how much VIRTUAL time
/// passed before it resolved.
async fn cut_after(secs: u64) -> std::time::Duration {
    crate::testkit::install_test_seams();
    let (addr, server) = black_hole().await;
    let app = TestApp::new()
        .upstream_request_timeout_secs(secs)
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

    let started = tokio::time::Instant::now();
    // The real-time guard is the regression detector: a stream nothing cuts hangs on socket I/O,
    // and the paused clock cannot auto-advance past a wait that is not a timer.
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(30_000),
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
    .expect("a black-holed stream must resolve at the deadline, never hang");
    let elapsed = started.elapsed();

    assert!(
        resp.status().is_server_error(),
        "a cut stream is an upstream failure, got {}",
        resp.status()
    );
    server.abort();
    elapsed
}

/// The cut lands on the configured second, and moves when the configuration moves.
///
/// Two runs of the same black hole under two different values of
/// `limits.upstream_request_timeout_secs`. Each resolves at EXACTLY its own number of virtual
/// seconds. That is the whole proof of both halves of the binding at once:
///
///   * the timer that fired is the operator's total deadline, because its expiry is the operator's
///     number and not a floor, a default or an interval of the runtime's own;
///   * there is no idle timer, because the upstream is idle from the first instant and a timer
///     counting that silence would fire at the same moment in both runs instead of tracking a
///     number it knows nothing about.
///
/// Both numbers are deliberately far apart and far from the 1 s send-site floor and the 300 s
/// default, so neither can be hit by accident.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_proxied_stream_is_cut_at_the_configured_second_and_by_nothing_earlier() {
    assert_eq!(
        cut_after(7).await,
        std::time::Duration::from_secs(7),
        "cut at the configured seven seconds"
    );
    assert_eq!(
        cut_after(23).await,
        std::time::Duration::from_secs(23),
        "the same hole, cut at twenty-three: the deadline tracks the configuration",
    );
}

/// The default the binding names, at the value it names.
#[test]
fn the_total_deadline_the_stream_rides_defaults_to_five_minutes() {
    assert_eq!(
        busbar_substrate::config::limits::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS,
        300,
    );
}
