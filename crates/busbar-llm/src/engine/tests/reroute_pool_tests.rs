// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! KILL-THE-UPSTREAM-MID-POOL, MODEL (LLM) client leg — the same claim the MCP and A2A batteries
//! make, on the same mechanism, proven at this plane's front door on outputs the caller and the two
//! real mock upstreams can see.
//!
//! This is the `failover-reroute x llm` cell, and after the one-selection-loop unification it closes
//! on `failover::walk_with` — the SAME function `failover::walk` hands the MCP and A2A candidate sets
//! to. The model plane supplies an ORDER (SWRR / routing policy / session affinity) and an ADMISSION
//! (`try_admit` = `try_admit_breaker` plus this plane's concurrency permit); it owns no loop.
//!
//! The claims, each an observable behaviour of this plane:
//!
//! 1. REROUTE BEFORE FIRST BYTE: the pool's primary is breaker-Open, so NOTHING LEAVES BUSBAR for
//!    it — its own mock upstream never sees a byte — and the caller gets the TWIN's answer inside
//!    the same request.
//! 2. THE PRIMARY STAYS UNTOUCHED: a reroute is not a probe. The Open member is not dispatched to
//!    and its mock's request record stays empty.
//!
//! The PROVING MUTATION is on the shared loop, not on this plane: make `failover::walk_with` refuse
//! every position after the primary (`if position != 0 { break }`) and this test goes red together
//! with `mcp::tests::reroute_pool_tests` and `a2a::tests::reroute_pool_tests` — three planes, one
//! loop, one mutation. That simultaneity is the cell's real evidence; a per-plane test that survives
//! a mutation of the shared loop would be proving a plane-local copy instead.

use crate::engine::WeightedLane;
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
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

fn chat_body() -> bytes::Bytes {
    serde_json::to_vec(&json!({
        "model": "test-model",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 16,
    }))
    .unwrap()
    .into()
}

/// A tripped pool primary reroutes the request to its twin BEFORE THE FIRST BYTE, and the primary is
/// never dispatched to.
///
/// Each member gets its OWN mock upstream, which is what makes "nothing left busbar for the primary"
/// observable rather than asserted: the primary's mock records every request body it receives, and
/// after the request it has received none.
#[tokio::test]
async fn a_tripped_pool_primary_reroutes_the_request_to_its_twin_and_stays_untouched() {
    crate::testkit::install_test_seams();
    let primary_state = Arc::new(MockServerState::new());
    let twin_state = Arc::new(MockServerState::new());

    // The primary is armed with an answer it must never get to give.
    primary_state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_primary",
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "text", "text": "from the primary" }],
            "model": "test-model",
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 1, "output_tokens": 1 },
        }),
    });
    twin_state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_twin",
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "text", "text": "from the twin" }],
            "model": "test-model",
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 1, "output_tokens": 1 },
        }),
    });

    let primary = MockServer::new(primary_state.clone()).await;
    let twin = MockServer::new(twin_state.clone()).await;

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "primary",
            crate::proto_codec::PROTO_ANTHROPIC,
            &primary.base_url(),
        ))
        .lane(LaneSpec::new(
            "twin",
            crate::proto_codec::PROTO_ANTHROPIC,
            &twin.base_url(),
        ))
        // The test `forward` helper dispatches against the default (`""`) pool cell.
        .pool("", &[(0, 1), (1, 1)])
        .build();

    // Trip the PRIMARY's cell Open with a cooldown far past the real wall clock the selection reads,
    // so it is genuinely inadmissible rather than merely unlucky in the weighted draw.
    app.store
        .force_open_in("", 0, busbar_substrate::store::now() + 1_000_000);

    let response = crate::engine::forward_with_pool(
        &app,
        vec![member(0), member(1)],
        chat_body(),
        None,
        "",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "the pool still serves: the twin is admissible"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a buffered body");
    let seen = String::from_utf8_lossy(&body);
    assert!(
        seen.contains("from the twin"),
        "the caller must be served BY THE TWIN, not the tripped primary; got {seen}"
    );

    // THE LOAD-BEARING ASSERTION: nothing left busbar for the primary. This is what makes it a
    // REROUTE (before the first byte) and not a RETRY (after one).
    assert!(
        primary_state.get_last_request_body().is_none(),
        "the tripped primary must never be dispatched to — a reroute duplicates nothing because \
         nothing was sent"
    );
    assert!(
        twin_state.get_last_request_body().is_some(),
        "the twin is the member that actually received the request"
    );

    primary.shutdown().await;
    twin.shutdown().await;
}

/// A primary that the ORDER offers but the ADMISSION refuses is PASSED OVER INSIDE THE LOOP, and the
/// twin serves — the model plane's spelling of the walk's refuse-and-continue arm.
///
/// This is the case the test above deliberately does NOT cover, and the distinction is load-bearing.
/// A breaker-Open member is filtered out by SWRR's own health filter before the walk ever sees it, so
/// that test proves the walk REACHES a non-primary position but never exercises its refusal arm. A
/// SATURATED member is different: `select_weighted_in` consults the breaker and lane admissibility but
/// NOT concurrency permits, so the order legitimately offers it, `try_admit` answers `AtCapacity`, and
/// it is the ONE LOOP — not the model plane — that records the reason and asks the order for the next
/// candidate. That is the same sequence `failover::walk` runs for a `tool_pools:` member whose breaker
/// denies it, in the same function.
///
/// MUTATION: make the model plane's `Order` unable to walk past a refusal (`if refused.is_some() {
/// return None }` at the top of `SwrrOrder::next`) and this test goes red while the breaker-Open test
/// above stays green — which is exactly why both are here.
#[tokio::test]
async fn a_saturated_primary_is_passed_over_inside_the_one_loop_and_the_twin_serves() {
    crate::testkit::install_test_seams();
    let primary_state = Arc::new(MockServerState::new());
    let twin_state = Arc::new(MockServerState::new());
    primary_state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_primary",
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "text", "text": "from the primary" }],
            "model": "test-model",
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 1, "output_tokens": 1 },
        }),
    });
    twin_state.push(MockResponse::Ok {
        status: axum::http::StatusCode::OK,
        body: json!({
            "id": "msg_twin",
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "text", "text": "from the twin" }],
            "model": "test-model",
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 1, "output_tokens": 1 },
        }),
    });

    let primary = MockServer::new(primary_state.clone()).await;
    let twin = MockServer::new(twin_state.clone()).await;

    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "primary",
                crate::proto_codec::PROTO_ANTHROPIC,
                &primary.base_url(),
            )
            // One slot, which the test then holds for the whole request.
            .max(1),
        )
        .lane(LaneSpec::new(
            "twin",
            crate::proto_codec::PROTO_ANTHROPIC,
            &twin.base_url(),
        ))
        .pool("", &[(0, 1), (1, 1)])
        .build();

    // Saturate the primary WITHOUT touching its breaker: its cell stays Closed and ready, so the
    // order still offers it and only the admission can refuse it.
    let _held = app
        .store
        .try_acquire(0)
        .expect("the primary's only permit is available before the request");

    let response = crate::engine::forward_with_pool(
        &app,
        vec![member(0), member(1)],
        chat_body(),
        None,
        "",
        None,
        "anthropic",
        crate::test_support::CHAT,
        None,
    )
    .await;

    assert_eq!(response.status().as_u16(), 200, "the twin still serves");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a buffered body");
    let seen = String::from_utf8_lossy(&body);
    assert!(
        seen.contains("from the twin"),
        "a saturated primary must be passed over to the twin; got {seen}"
    );
    assert!(
        primary_state.get_last_request_body().is_none(),
        "the saturated primary must never be dispatched to — it had no slot to dispatch in"
    );

    primary.shutdown().await;
    twin.shutdown().await;
}
