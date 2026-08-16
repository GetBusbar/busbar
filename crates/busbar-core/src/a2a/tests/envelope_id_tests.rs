// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC `id` MEMBER, on the A2A RECEIVING plane — the SAME three cases as
//! `mcp/tests/envelope_id_tests.rs`, asserted against the same shared reader.
//!
//! ## Why this file exists as a near-copy of its MCP sibling, and why that is the point
//!
//! The defect that produced it was reported on the MCP plane only. It was present on this one too,
//! and worse, because this plane had no envelope validation at all: no `jsonrpc` version check, no
//! `id` check, and `ingress.rs` collapsed a MISSING id and an explicit `null` id into the same
//! `Value::Null` before either could be distinguished. A property that holds on one plane and not
//! the other is not a property; it is a coincidence on the plane somebody happened to test.
//!
//! So the two files assert the same list, and they are deliberately readable side by side. If one
//! ever grows a case the other lacks, that difference is the finding.
//!
//! ## The clauses, quoted
//!
//! - JSON-RPC 2.0 section 4.1: *"A Notification is a Request object without an `id` member. … The Server
//!   MUST NOT reply to a Notification."*
//! - JSON-RPC 2.0 section 5: the response `id` *"MUST be the same as the value of the id member in the
//!   Request Object. If there was an error in detecting the id in the Request object (e.g. Parse
//!   error/Invalid Request), it MUST be Null."*
//! - JSON-RPC 2.0 section 4, footnote [1], which is the whole argument for refusing `null` here even
//!   though A2A adds no clause of its own: *"The use of Null as a value for the id member in a
//!   Request object is discouraged, because this specification uses a value of Null for the id
//!   member in a Response object to indicate an unknown id."*
//!
//! A2A v0.3 section 3 binds this plane to JSON-RPC 2.0 and adds no `id` rule, so the base spec's
//! `SHOULD normally not be Null` is the only text that names `null` directly. busbar refuses it,
//! and the reason is stated where the code does it (`ingress::jsonrpc`): a SUCCESS response echoing
//! `"id": null` is byte-identical to the envelope section 5 reserves for "I could not tell which request
//! this was", so serving one publishes an answer no caller can safely attribute. Refusing is
//! permitted (nothing obliges a server to accept a discouraged id) and it is the only reading under
//! which both planes can share one reader.

use super::relay_harness::*;

/// POST raw bytes to the agent endpoint and read the status and body AS TEXT.
///
/// Text rather than JSON for the same reason the MCP sibling does it: the notification cases assert
/// the body is EMPTY, and a `.json()` helper would silently turn "no body" into `null`.
async fn post_raw(h: &Harness, body: &serde_json::Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("http://{}/a2a/agents/planner", h.addr))
        .header("authorization", format!("Bearer {}", h.bearer))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(body).expect("serialise"))
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// The `params` of a well-formed `message/send`, held apart so a case varies `id` and nothing else.
fn params() -> serde_json::Value {
    serde_json::json!({
        "message": {
            "role": "user",
            "contextId": "ctx-abc",
            "parts": [{ "kind": "text", "text": "PLAN THE MIGRATION" }]
        }
    })
}

// ══ (1) `"id": null` ═════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn a_null_id_is_never_answered_with_a_success_result() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, text) = post_raw(
        &h,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "message/send",
            "params": params(),
        }),
    )
    .await;

    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    assert!(
        body.get("result").is_none(),
        "a request with `\"id\": null` was answered with a SUCCESS result. That envelope is \
         indistinguishable from the one JSON-RPC 2.0 section 5 reserves for an unknown id, so no caller \
         can attribute it: status={status} body={text}"
    );
    assert_ne!(status, 200, "status={status} body={text}");
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32600),
        "an illegal `id` is an Invalid Request: status={status} body={text}"
    );
    assert_eq!(
        body.get("id"),
        Some(&serde_json::Value::Null),
        "the refusal must carry `\"id\": null` (JSON-RPC 2.0 section 5): body={text}"
    );

    // AND THE HOP MUST NOT HAVE HAPPENED. A plane that refuses at the wire but has already spent a
    // credential on a backend agent has refused nothing that matters.
    assert!(
        h.sent().is_empty(),
        "a refused envelope was still relayed to the backend: {:?}",
        h.sent()
    );
}

// ══ (2) NO `id` MEMBER ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn a_request_method_with_no_id_is_a_notification_and_gets_no_response_body() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, text) = post_raw(
        &h,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": params(),
        }),
    )
    .await;

    assert!(
        text.trim().is_empty(),
        "a message with NO `id` member is a notification, and JSON-RPC 2.0 section 4.1 says \"The Server \
         MUST NOT reply to a Notification\" — but a body came back: status={status} body={text}"
    );
    assert_eq!(
        status, 202,
        "a notification is acknowledged and not answered: status={status} body={text}"
    );
}

// ══ (3) A `jsonrpc` MEMBER THAT IS NOT `"2.0"` ═══════════════════════════════════════════════════

/// Not an `id` case, and here because the fix moves BOTH planes onto one reader and this is the
/// check this plane never had. Before it, an envelope with no `jsonrpc` member at all — or with
/// `"1.0"` — was relayed to a backend agent as though it were valid A2A.
#[tokio::test]
async fn an_envelope_that_is_not_jsonrpc_2_0_is_refused_before_any_hop() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, text) = post_raw(
        &h,
        &serde_json::json!({
            "id": 7,
            "method": "message/send",
            "params": params(),
        }),
    )
    .await;

    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32600),
        "an envelope with no `jsonrpc` member is an Invalid Request: status={status} body={text}"
    );
    assert!(
        h.sent().is_empty(),
        "a non-JSON-RPC envelope was relayed to the backend: {:?}",
        h.sent()
    );
}

// ══ (4) THE CONTROL ══════════════════════════════════════════════════════════════════════════════

/// A real id is served, echoed verbatim, and DOES reach the backend. Without it every assertion
/// above is satisfied by a plane that refuses everything.
#[tokio::test]
async fn a_real_id_is_served_echoed_verbatim_and_relayed() {
    let h = harness(Outcome::Answers(200, backend_ok()), false).await;
    let (status, body) = call(&h).await;
    assert_eq!(status, 200, "the control must be served: {body}");
    assert!(body.get("result").is_some(), "no result: {body}");
    assert_eq!(body["id"], serde_json::json!(7), "id not echoed: {body}");
    assert_eq!(h.sent().len(), 1, "the control must reach the backend");
}
