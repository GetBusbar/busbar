// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ALLOCATION-COUNT PERF-REGRESSION GATE — deterministic, machine-independent, fast.
//!
//! WHY THIS EXISTS. A ~20% throughput gap once appeared between two releases. Most of it was a
//! build-config mismatch (now caught structurally by the build-provenance stamp + PGO pin), but a
//! REAL ~1-3% code regression rode along inside it: the crate extraction made the request hot path
//! re-resolve its protocol codec by NAME every request, and `decl_for(name).dialect()` allocates a
//! fresh `Box<dyn DialectCodec>` per call (substrate `proto.rs::dialect`). No existing test flagged
//! it, because no test asserted anything about per-request ALLOCATION. This gate is that assertion:
//! a NEW per-request heap allocation of that class pushes the measured count over a committed bound
//! and turns CI red — the owner's hard line ("I can't have a 20% regression ever ship") made
//! deterministic. Wall-clock RPS flakes on shared CI runners; an allocation COUNT does not.
//!
//! TWO GATES, TWO GRAINS:
//!   * [`alloc_gate_translate_write_stable`] — the SURGICAL one. It calls the same-protocol write
//!     path (`translate_request_cross_protocol`, `wire.rs`) DIRECTLY: no tokio, no sockets, no mock
//!     — a pure synchronous function whose allocation count is fully deterministic. It pins the
//!     exact per-call count, so the single stray `Box::new` of the FIX-9 class is a +1 that fails
//!     the equality. This is the FIX-9 regression test.
//!   * [`alloc_gate_openai_passthrough_forward`] — the WHOLE-PATH one. It drives ONE openai>openai
//!     passthrough request end-to-end through `forward_with_pool` against the in-process MockServer
//!     and bounds the total heap-allocation count of a warmed, steady-state request. Coarser (it
//!     includes the in-process mock + reqwest + tokio), so it carries headroom sized to observed
//!     jitter and catches GROSS regressions (a ~20%-class allocation blow-up), while the surgical
//!     gate catches the single-allocation class.
//!
//! THE INSTRUMENT is [`crate::CountingJemalloc`] (see the `#[global_allocator]` site in `lib.rs`): a
//! jemalloc wrapper counting allocations PER THREAD. Per-thread so concurrent `cargo test` threads
//! never inflate the measured thread's count. jemalloc-only, hence this whole module is
//! `not(target_env = "msvc")`, the same guard the telemetry-counter tests carry.
//!
//! RE-BASELINING. If an INTENTIONAL change moves a bound, run the test with `--nocapture`; each gate
//! prints its measured count. Update the `const` here to the new measured value (+ the documented
//! headroom for the coarse gate) IN THE SAME COMMIT, so the number is always the reviewed truth.

use crate::state::WeightedLane;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use crate::CountingJemalloc;
use serde_json::json;
use std::sync::Arc;

fn member(idx: usize) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

/// A minimal, well-formed OpenAI chat-completions request body.
fn openai_chat_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 16,
    }))
    .unwrap()
    .into()
}

/// A canned upstream OpenAI chat-completions success.
fn openai_ok() -> MockResponse {
    MockResponse::Ok {
        status: reqwest::StatusCode::OK,
        body: json!({
            "id": "chatcmpl-gate",
            "object": "chat.completion",
            "created": 0,
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "ok" },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2 }
        }),
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// GATE 1 (surgical / FIX-9): the same-protocol WRITE path, called directly.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// COMMITTED BASELINE — the exact heap-allocation count of ONE same-protocol openai>openai call to
/// `translate_request_cross_protocol`, measured on this tree. It is exact (not `<=`) because the
/// call is a pure synchronous function with no I/O: its allocation count does not vary run to run.
///
/// ZERO, and zero is the CONTRACT, not a measurement that happened to come out low: the plane
/// docs' perf ruling is "no malloc on hot calls", and this path now honors it. The `1` this
/// replaced was the per-request `Box<dyn DialectCodec>` that `decl_for(..).dialect()` used to mint
/// (`proto.rs`'s old `fn() -> Box<..>` codec field) — a gate baselined to the defect it existed to
/// catch. With `codec` now a `&'static dyn` (pure-memory borrow, same shape as `handler`),
/// `dialect()` allocates nothing, and ANY stray per-request allocation that ever lands on this
/// path again fails this equality RED. Do not raise this number to make a change green — a raise
/// IS the regression, and the right fix is on the hot path, not here.
const TRANSLATE_WRITE_ALLOCS: u64 = 0; // the seam contract: no malloc on hot calls

#[test]
fn alloc_gate_translate_write_stable() {
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto::Protocol::openai(),
            "http://127.0.0.1:1", // never dialed — this path does no I/O
        ))
        .pool("", &[(0, 1)])
        .build();

    let hop_bytes = openai_chat_body();
    let body_value: serde_json::Value = serde_json::from_slice(&hop_bytes).unwrap();

    // WARM the path once OUTSIDE the measured window: first-touch lazy statics (the protocol
    // registry, etc.) allocate once per process, not per request, and must not be charged to the
    // per-request count.
    let _ = crate::proxy::translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::CHAT,
        Some(body_value.clone()),
        "application/json",
        false,
        &hop_bytes,
        "anonymous",
    );

    let before = CountingJemalloc::reset();
    let out = crate::proxy::translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::CHAT,
        Some(body_value),
        "application/json",
        false,
        &hop_bytes,
        "anonymous",
    );
    let allocs = CountingJemalloc::count();
    let _ = before;

    assert!(out.is_ok(), "same-proto passthrough must translate cleanly");
    eprintln!("[alloc-gate] translate_request_cross_protocol allocations = {allocs}");

    assert_eq!(
        allocs, TRANSLATE_WRITE_ALLOCS,
        "PER-REQUEST ALLOCATION COUNT ON THE SAME-PROTO WRITE PATH CHANGED: measured {allocs}, \
         committed baseline {TRANSLATE_WRITE_ALLOCS}. A NEW per-request heap allocation (the FIX-9 \
         class — e.g. a redundant `decl_for(..).dialect()` boxing) regresses the hot path. If this \
         change is intentional, update TRANSLATE_WRITE_ALLOCS to {allocs} in this commit and say why."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// GATE 2 (coarse / whole-path): one openai>openai request end-to-end through forward_with_pool.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// COMMITTED BOUND — the maximum heap-allocation count for ONE warmed, steady-state openai>openai
/// passthrough request driven end-to-end through `forward_with_pool` against the in-process
/// MockServer. A `<=` bound (not equality) because this path spans tokio + reqwest + the in-process
/// mock, whose bookkeeping jitters by a few allocations run to run; the headroom over the measured
/// steady-state count is sized to that observed jitter (see the module header). It still catches a
/// GROSS regression — a ~20%-class allocation blow-up, or a per-request allocation that scales — the
/// owner's headline case. The surgical gate above catches the single-allocation FIX-9 class.
// Measured after the owned hyper egress client (wave 7): a warmed steady-state request allocates
// 87 (was 125 after the wave-4b egress-target precompute, 140 on dev @ d86b896b) — reqwest's
// per-send RequestBuilder machinery, URL re-parse and response wrappers left the hot path. The
// bound is 107 — the same +20 headroom for cross-platform/CI allocator jitter (dep versions are
// lockfile-pinned). Lowered IN THE SAME COMMIT as the improvement so the gate keeps its
// sensitivity: a regression back to builder-per-send (+38/request) fails RED.
const FORWARD_PASSTHROUGH_MAX_ALLOCS: u64 = 107;

#[tokio::test(flavor = "current_thread")]
async fn alloc_gate_openai_passthrough_forward() {
    let state = Arc::new(MockServerState::new());
    // One response per request we send (LIFO stack): 1 warm-up + several measured iterations.
    for _ in 0..8 {
        state.push(openai_ok());
    }
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto::Protocol::openai(),
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    async fn one_request(app: &Arc<crate::state::App>) {
        let resp = crate::proxy::forward_with_pool(
            app,
            vec![member(0)],
            openai_chat_body(),
            None,
            "",
            None,
            "openai",
            crate::handlers::CHAT,
            None,
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200, "passthrough must be 200");
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    }

    // WARM UP: the first request opens a fresh upstream connection (its own allocations), primes
    // per-thread pools and lazy statics — none of it per-request steady-state cost. Measure only
    // warmed requests.
    one_request(&app).await;

    // Measure several steady-state requests; report the MINIMUM (the cleanest, least-jittered
    // observation) and assert it is within the committed bound.
    let mut min_allocs = u64::MAX;
    for _ in 0..4 {
        let _ = CountingJemalloc::reset();
        one_request(&app).await;
        let allocs = CountingJemalloc::count();
        min_allocs = min_allocs.min(allocs);
    }
    eprintln!(
        "[alloc-gate] forward_with_pool openai>openai steady-state min allocations = {min_allocs}"
    );

    assert!(
        min_allocs <= FORWARD_PASSTHROUGH_MAX_ALLOCS,
        "OPENAI>OPENAI FORWARD-PATH ALLOCATION COUNT REGRESSED: measured {min_allocs} > committed \
         bound {FORWARD_PASSTHROUGH_MAX_ALLOCS}. A new per-request allocation on the forward path \
         (or a scaling one) pushed it over. If intentional, update FORWARD_PASSTHROUGH_MAX_ALLOCS \
         in this commit."
    );

    server.shutdown().await;
}
