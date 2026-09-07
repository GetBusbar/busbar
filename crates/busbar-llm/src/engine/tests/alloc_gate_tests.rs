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

use crate::engine::WeightedLane;
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
    crate::testkit::install_test_seams();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            "http://127.0.0.1:1", // never dialed — this path does no I/O
        ))
        .pool("", &[(0, 1)])
        .build();

    let hop_bytes = openai_chat_body();
    let body_value: serde_json::Value = serde_json::from_slice(&hop_bytes).unwrap();

    // App-retype WEDGE 3: the surgical write path now takes the neutral `host`/`rt` the production
    // forward thread passes. Both are resolved ONCE, OUTSIDE the measured window (the host is one
    // `Arc::new`, the runtime an alloc-free slot read), so the pinned per-call count still measures
    // ONLY `translate_request_cross_protocol`'s own allocations — which stay ZERO.
    let host = busbar_substrate::testkit::engine_host(&app);
    let rt = crate::engine::native_runtime_arc(host.as_ref());

    // WARM the path once OUTSIDE the measured window: first-touch lazy statics (the protocol
    // registry, etc.) allocate once per process, not per request, and must not be charged to the
    // per-request count.
    let _ = crate::engine::translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        crate::test_support::CHAT,
        Some(body_value.clone()),
        "application/json",
        false,
        &hop_bytes,
        "anonymous",
    );

    let before = CountingJemalloc::reset();
    let out = crate::engine::translate_request_cross_protocol(
        &host,
        &rt,
        0,
        "openai",
        crate::test_support::CHAT,
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

/// GATE 1b — the SEAM itself, for ALL SIX dialects, not just the one the surgical gate routes.
///
/// The surgical gate above measures an openai lane, so it only catches a resolution allocation in
/// the OPENAI dialect. The allocation it caught was not openai's, though: it was the neutral
/// forwarder's, which resolved a whole `Protocol` (two `Box`es) to ask one writer one stateless
/// question — and it went unseen for as long as the openai writer happened to be zero-sized. Every
/// writer now carries per-stream state, so the same question asked of any of the six would have cost
/// the same allocation. This asserts the seam is allocation-free for each dialect BY NAME, so a
/// future field on any writer cannot re-open the hole in a dialect the routed gate never exercises.
#[test]
fn alloc_gate_dialect_seam_resolution_is_free_for_every_dialect() {
    use crate::proto_codec::ProtocolWriter;

    /// Ask ONE dialect the SAME stateless question twice — once through the neutral seam
    /// (`decl_for(name).dialect()`), once on the writer directly — and require the two to allocate
    /// the SAME number of times. Comparing the two isolates the SEAM's cost from the QUESTION's
    /// (some writers answer this one by walking a JSON pointer, which allocates in `serde_json`
    /// itself); the difference is exactly what resolving the dialect costs, and it must be nothing.
    fn seam_costs_what_the_writer_costs<W: ProtocolWriter>(
        name: &'static str,
        mint: impl Fn() -> W,
        body: &serde_json::Value,
    ) {
        let dialect = busbar_substrate::proto::decl_for(name)
            .and_then(|d| d.dialect())
            .unwrap_or_else(|| panic!("{name} declares a codec"));
        // WARM both sides outside the measured windows: a first touch of the registry or of a lazy
        // static a writer reads is a per-process cost, not a per-request one.
        let _ = dialect.requested_candidate_count(body);
        let _ = mint().requested_candidate_count(body);

        let _ = CountingJemalloc::reset();
        let _ = mint().requested_candidate_count(body);
        let direct = CountingJemalloc::count();

        let _ = CountingJemalloc::reset();
        let _ = dialect.requested_candidate_count(body);
        let seam = CountingJemalloc::count();

        eprintln!("[alloc-gate] {name} seam allocations = {seam}, direct = {direct}");
        assert_eq!(
            seam, direct,
            "ASKING THE `{name}` DIALECT ONE STATELESS QUESTION COST {seam} ALLOCATION(S) THROUGH \
             THE NEUTRAL SEAM BUT {direct} ON THE WRITER ITSELF. The difference is the seam's own \
             per-call cost, and the seam contract is that it has none: `decl_for(..).dialect()` is a \
             pure-memory `&'static dyn` borrow and the forwarder builds its writer on the STACK. A \
             difference here means something behind the seam went back to boxing a codec per call — \
             which the request hot path then pays on EVERY request, for this dialect."
        );
    }

    crate::testkit::install_test_seams();
    let body = json!({ "model": "m", "messages": [] });
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_ANTHROPIC,
        || crate::anthropic::AnthropicWriter,
        &body,
    );
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_BEDROCK,
        || crate::bedrock::BedrockWriter,
        &body,
    );
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_COHERE,
        || crate::cohere::CohereWriter,
        &body,
    );
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_GEMINI,
        || crate::gemini::GeminiWriter,
        &body,
    );
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_OPENAI,
        || crate::openai_chat::OpenAiWriter,
        &body,
    );
    seam_costs_what_the_writer_costs(
        crate::proto_codec::PROTO_RESPONSES,
        || crate::openai_responses::ResponsesWriter,
        &body,
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
// Measured after the owned hyper egress client landed: a warmed steady-state request allocates
// 87 (was 125 after the wave-4b egress-target precompute, 140 on dev @ d86b896b) — reqwest's
// per-send RequestBuilder machinery, URL re-parse and response wrappers left the hot path. The
// bound is 107 — the same +20 headroom for cross-platform/CI allocator jitter (dep versions are
// lockfile-pinned). Lowered IN THE SAME COMMIT as the improvement so the gate keeps its
// sensitivity: a regression back to builder-per-send (+38/request) fails RED.
const FORWARD_PASSTHROUGH_MAX_ALLOCS: u64 = 107;

#[tokio::test(flavor = "current_thread")]
async fn alloc_gate_openai_passthrough_forward() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    // One response per request we send (LIFO stack): 1 warm-up + several measured iterations.
    for _ in 0..8 {
        state.push(openai_ok());
    }
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    async fn one_request<A: busbar_substrate::testkit::BuiltAppSeam + ?Sized>(app: &Arc<A>) {
        let resp = crate::engine::forward_with_pool(
            app,
            vec![member(0)],
            openai_chat_body(),
            None,
            "",
            None,
            "openai",
            crate::test_support::CHAT,
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

// ─────────────────────────────────────────────────────────────────────────────────────────────
// GATE 3 (scaling / delivery arm): the request body must be materialized ONCE, not twice.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// How many `messages` entries the large body carries. Sized so the per-node cost of ONE extra
/// materialization of the parsed request body is far larger than the run-to-run jitter of the
/// surrounding tokio/reqwest/mock machinery — the gate below measures a difference, so the signal
/// has to clear the noise by a wide margin rather than by a few allocations.
const ECHO_SCALING_MESSAGES: usize = 4_000;

/// COMMITTED BOUND — the maximum number of heap allocations by which a request carrying
/// [`ECHO_SCALING_MESSAGES`] messages may exceed the SAME request carrying one message, on the
/// buffered delivery arm (`attempt/respond.rs`, taken here because the client asked to stream and
/// the upstream answered one JSON body).
///
/// WHAT THIS PINS, and it is a SCALING ceiling rather than a fixed cost: the client chooses the node
/// count of the body, so every per-node wave this arm performs is work an unauthenticated-size input
/// multiplies. The arm legitimately performs several — the parse that builds the request-echo
/// context, the translate, the re-serialize — and this gate does not claim to count them. What it
/// catches is a wave being ADDED.
///
/// MEASURED, both sides, on this tree at 4_000 messages: 84_005 (21 per message) with the parsed
/// body handed to the buffered translate by MOVE; 104_000 (26 per message) with the deep clone that
/// preceded it. The bound sits between them with jitter headroom, so re-introducing that clone — or
/// any other whole-body materialization of the same class — fails RED. It is a DIFFERENCE, not a
/// total, so it does not move when unrelated FIXED per-request costs change.
const ECHO_BODY_SCALING_MAX_ALLOCS: u64 = 92_000;

/// A well-formed OpenAI chat-completions request with `n` messages, asking to STREAM.
///
/// `stream: true` is what puts this on the buffered delivery arm even though ingress and egress
/// speak the same dialect: the client asked for a stream and the upstream answered one JSON body,
/// so the answer is buffered, translated and re-framed rather than relayed.
fn openai_stream_body(n: usize) -> bytes::Bytes {
    let messages: Vec<serde_json::Value> = (0..n)
        .map(|i| json!({ "role": "user", "content": format!("message {i}") }))
        .collect();
    serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "messages": messages,
        "max_tokens": 16,
        "stream": true,
    }))
    .unwrap()
    .into()
}

#[tokio::test(flavor = "current_thread")]
async fn alloc_gate_request_echo_body_materialized_once() {
    crate::testkit::install_test_seams();
    let state = Arc::new(MockServerState::new());
    // One canned response per request below: 2 warm-ups + 2 measured.
    for _ in 0..4 {
        state.push(openai_ok());
    }
    let server = MockServer::new(state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "gpt-4o",
            crate::proto_codec::PROTO_OPENAI,
            &server.base_url(),
        ))
        .pool("", &[(0, 1)])
        .build();

    async fn one_request<A: busbar_substrate::testkit::BuiltAppSeam + ?Sized>(
        app: &Arc<A>,
        body: bytes::Bytes,
    ) {
        let resp = crate::engine::forward_with_pool(
            app,
            vec![member(0)],
            body,
            None,
            "",
            None,
            "openai",
            crate::test_support::CHAT,
            None,
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "the arm under test must be 200"
        );
        let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    }

    // WARM both shapes outside the measured window: the first request opens the upstream connection
    // and primes lazy statics, none of it per-request steady-state cost.
    one_request(&app, openai_stream_body(1)).await;
    one_request(&app, openai_stream_body(ECHO_SCALING_MESSAGES)).await;

    let _ = CountingJemalloc::reset();
    one_request(&app, openai_stream_body(1)).await;
    let small = CountingJemalloc::count();

    let _ = CountingJemalloc::reset();
    one_request(&app, openai_stream_body(ECHO_SCALING_MESSAGES)).await;
    let large = CountingJemalloc::count();

    let delta = large.saturating_sub(small);
    eprintln!(
        "[alloc-gate] buffered delivery arm: small={small} large={large} \
         delta={delta} over {ECHO_SCALING_MESSAGES} messages"
    );

    assert!(
        delta <= ECHO_BODY_SCALING_MAX_ALLOCS,
        "THE BUFFERED DELIVERY ARM GAINED A PER-NODE ALLOCATION WAVE: a body with \
         {ECHO_SCALING_MESSAGES} messages cost {delta} allocations more than a one-message body, \
         over the committed bound {ECHO_BODY_SCALING_MAX_ALLOCS}. The client chooses that node \
         count, so a wave added here is work an attacker-sized body multiplies — the last one to be \
         removed was a deep clone of the whole parsed request body. If a new wave is genuinely \
         required, say why and re-measure this bound in the same commit."
    );

    server.shutdown().await;
}
