// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODEL PLANE'S CHAIN, PROVEN FROM THE OUTSIDE: a real model request, over a real socket,
//! through `crate::build_router` and the real governance guards, landing a real hash-chained record
//! that is then read back and RECOMPUTED.
//!
//! ## Why this battery does not touch the log's write surface
//!
//! The MCP call log had a complete substrate — a chain, a verifier, a restore path and its own
//! passing tests — and **no production call site at all** for an entire release. Everything was
//! exercised by driving the log directly, so the whole subsystem could be, and was, correct and
//! unreached. A test that called `REQUESTS.record(..)` itself would reproduce exactly that: it
//! proves the substrate and says nothing about whether a customer's request ever reaches it.
//!
//! So nothing below writes a record. Each test drives `POST /<pool>/v1/messages` at a real listener
//! and then LOOKS at what the plane left behind. Delete the append in `ingress::finish_inner` and
//! every assertion here fails, while every other test in this crate stays green — which is the
//! property that makes this evidence for the `audit-chain x llm` equality cell rather than evidence
//! that a chain exists.
//!
//! ## Both halves, on ONE chain, because the refusal is the half that gets dropped
//!
//! A log that records only what succeeded cannot answer the question an audit is actually asked —
//! "was this caller ever turned away, and why" — and a plane that chains dispatches while dropping
//! refusals looks identical, from the records, to a plane nobody ever refused. So the dispatch and
//! the governance refusal below are asserted as consecutive links of the SAME principal's chain,
//! `prev_hash` to `hash`, which is also the only way to prove the refusal was not written onto a
//! second chain of its own.

use crate::governance::{GovState, MemoryStore};
use crate::proxy::reqlog::{
    LlmRequestRecord, OUTCOME_DISPATCHED, OUTCOME_REFUSED, PRINCIPAL_UNGOVERNED,
    REASON_NOT_GRANTED, REQUESTS,
};
use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use serde_json::json;
use std::sync::Arc;

/// The Anthropic backend body the mock answers with, so the ingress writer has a full IR to
/// translate. Copied in shape from `ingress/tests/tests.rs::anthropic_ok_body` deliberately: this
/// file must not depend on that module's private helpers to stand up.
fn anthropic_ok_body() -> serde_json::Value {
    json!({
        "id": "msg_x",
        "type": "message",
        "role": "assistant",
        "model": "claude-x",
        "content": [{"type": "text", "text": "hi there"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 5, "output_tokens": 3}
    })
}

/// A deployment with two pools, `A` (a reachable mock) and `B` (unreachable, and never reached),
/// plus a governed key allowed ONLY on `A`. Hands back the listener, the caller's secret and the key
/// id the chain is scoped to.
async fn a_governed_deployment(
    answers: usize,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    MockServer,
    String,
    String,
) {
    crate::metrics::init();
    let state = Arc::new(MockServerState::new());
    for _ in 0..answers {
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: anthropic_ok_body(),
        });
    }
    let server = MockServer::new(state).await;
    let a_url = server.base_url();

    let store = Arc::new(MemoryStore::new());
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[9u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(GovState::new_with_signer(store, None, Some(signer)).unwrap());
    let (key, secret) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "chained".to_string(),
                // Allowed on A and NOT on B, so a request to B is refused by the pool ACL —
                // a real governance decision, taken before any upstream is contacted.
                allowed_pools: Some(vec!["A".to_string()]),
                group: None,
                labels: Default::default(),
            },
            2_000_000_000,
            1_000_000_000,
        )
        .unwrap();

    let app = TestApp::new()
        .keys_chain()
        .governance(gov)
        .lane(LaneSpec::new("A", crate::proto::Protocol::anthropic(), &a_url).provider("zai"))
        .lane(
            LaneSpec::new(
                "B",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1",
            )
            .provider("zai"),
        )
        .pool("A", &[(0, 1)])
        .pool("B", &[(1, 1)])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, server, secret, key.id)
}

/// Send one native Anthropic request at `pool` as `secret`, and hand back the status.
async fn call(addr: std::net::SocketAddr, pool: &str, secret: &str) -> u16 {
    reqwest::Client::new()
        .post(format!("http://{addr}/{pool}/v1/messages"))
        .bearer_auth(secret)
        .body(json!({"model": pool, "messages": [{"role": "user", "content": "hi"}]}).to_string())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// EVERY MODEL REQUEST LANDS ON THE PRESENTING KEY'S HASH CHAIN — the dispatch and the refusal
/// alike, as consecutive links of one chain, and the chain RECOMPUTES.
///
/// This is the `audit-chain x llm` cell. Before it, `grep crate::audit` over `proxy/` and
/// `handlers/` returned nothing at all: model traffic reached billing and telemetry and no
/// tamper-evident record of any kind, while the other two planes chained theirs.
///
/// A chain nothing ever recomputes proves nothing, so this recomputes it rather than counting rows.
#[tokio::test]
async fn every_model_request_lands_on_the_presenting_keys_hash_chain_dispatch_and_refusal_alike() {
    let (addr, handle, server, secret, key_id) = a_governed_deployment(1).await;

    let dispatched = call(addr, "A", &secret).await;
    assert_eq!(
        dispatched, 200,
        "pool A is reachable and the key is allowed on it"
    );
    let refused = call(addr, "B", &secret).await;
    assert_eq!(
        refused, 403,
        "the key is not allowed on pool B, so this must be a governance refusal and not a dispatch"
    );

    handle.abort();
    server.shutdown().await;

    let records: Vec<LlmRequestRecord> = REQUESTS.records_for(&key_id);
    assert_eq!(
        records.len(),
        2,
        "two requests were answered under key `{key_id}`, so the chain owes two records — got \
         {records:#?}"
    );

    // ── THE DISPATCH ────────────────────────────────────────────────────────────────────────────
    assert_eq!(records[0].seq, 1, "the first record of a chain is seq 1");
    assert_eq!(records[0].outcome, OUTCOME_DISPATCHED);
    assert_eq!(records[0].status, 200);
    assert_eq!(
        records[0].pool, "A",
        "the record carries the BOUNDED pool label, which is what an auditor can join on"
    );
    assert_eq!(
        records[0].ingress_protocol, "anthropic",
        "the plane speaks six dialects, so which one the caller used is part of what happened"
    );

    // ── THE REFUSAL, ON THE SAME CHAIN ──────────────────────────────────────────────────────────
    assert_eq!(records[1].seq, 2);
    assert_eq!(
        records[1].outcome, OUTCOME_REFUSED,
        "a request the pool ACL turned away never went out; recording it as dispatched would say \
         the opposite of what happened"
    );
    assert_eq!(
        records[1].reason, REASON_NOT_GRANTED,
        "403 on this plane is the pool ACL or a frozen group — the caller holds no grant here"
    );
    assert_eq!(records[1].status, 403);
    assert_eq!(
        records[1].prev_hash, records[0].hash,
        "the refusal must be LINKED to the dispatch before it, not written onto a chain of its own \
         — an unlinked pair of records is two chains that each verify and together describe nothing"
    );

    // ── AND IT VERIFIES ─────────────────────────────────────────────────────────────────────────
    REQUESTS
        .verify_principal_chain(&key_id)
        .expect("the presenting key's chain must recompute");
}

/// AN UNGOVERNED REQUEST IS STILL EVIDENCE. With no key resolved the record chains under the fixed
/// engine-chosen sentinel rather than being dropped: a chain that silently omits every anonymous
/// request is a chain with a hole an attacker can choose, and "run it without a key" is not a way to
/// go unrecorded.
#[tokio::test]
async fn a_request_with_no_resolved_key_is_chained_under_the_sentinel_rather_than_dropped() {
    crate::metrics::init();
    let before = REQUESTS.records_for(PRINCIPAL_UNGOVERNED).len();

    // No `governance(..)`: nothing resolves a key, and the request is refused for want of a route.
    // The refusal is the point — this is the path that had no evidence of any kind.
    let app = TestApp::new().build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let status = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .body(
            json!({"model": "no-such-model", "messages": [{"role": "user", "content": "hi"}]})
                .to_string(),
        )
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    handle.abort();
    assert!(
        (400..600).contains(&status),
        "an unroutable model is turned away; got {status}"
    );

    let after = REQUESTS.records_for(PRINCIPAL_UNGOVERNED);
    assert!(
        after.len() > before,
        "the ungoverned request left no record at all — a principal-less request is exactly the \
         one an attacker would choose to make"
    );
    REQUESTS
        .verify_principal_chain(PRINCIPAL_UNGOVERNED)
        .expect("the sentinel's chain must recompute too");
}
