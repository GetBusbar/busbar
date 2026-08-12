// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON-RPC `id` MEMBER, on the MCP SERVER plane, driven through a real router over a real
//! socket.
//!
//! ## The three cases, and why they are three
//!
//! An implementation that gets `id` wrong almost always gets it wrong by collapsing two of these
//! into one. They are distinct, they have different required outcomes, and a test that covers only
//! the middle one passes against a server that is wrong about both the others:
//!
//! | the request carries | what it IS | the required answer |
//! |---|---|---|
//! | `"id": null` | a REQUEST with an illegal id | a refusal; NEVER a `result` |
//! | no `id` member at all | a NOTIFICATION | NO response body |
//! | no `id`, and a `notifications/*` method | a NOTIFICATION | NO response body |
//!
//! ## The clauses, quoted
//!
//! - JSON-RPC 2.0 section 4: *"An identifier established by the Client that MUST contain a String, Number,
//!   or NULL value if included. If it is not included it is assumed to be a notification. The value
//!   SHOULD normally not be Null."*
//! - JSON-RPC 2.0 section 4.1: *"A Notification is a Request object without an `id` member. … The Server
//!   MUST NOT reply to a Notification."*
//! - JSON-RPC 2.0 section 5: *"[the response `id`] MUST be the same as the value of the id member in the
//!   Request Object. If there was an error in detecting the id in the Request object (e.g. Parse
//!   error/Invalid Request), it MUST be Null."*
//! - MCP `2026-07-28` `basic#requests`, and this is the clause that makes `null` a REFUSAL rather
//!   than merely discouraged: *"Requests MUST include a string or integer ID."* and *"Unlike base
//!   JSON-RPC, the ID MUST NOT be `null`."*
//! - MCP `2026-07-28` `basic#notifications`: *"Notifications MUST NOT include an ID."* and *"The
//!   receiver MUST NOT send a response."*
//!
//! The in-house battery's `CONC.NULL-ID-REJECTED` cites the same clause under the id
//! `BASE.REQ.ID-NOT-NULL`; see `testing/mcp-conformance/src/core/spec.mjs`.

use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";

async fn serve() -> (String, tokio::task::JoinHandle<()>) {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec!["https://login.example.com".to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}/mcp"), handle)
}

/// The `params` every request on this revision carries. Held apart from the envelope so a test can
/// vary the `id` member and NOTHING else — the whole point of these cases is that one member
/// decides the outcome.
fn params() -> serde_json::Value {
    serde_json::json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    })
}

/// POST raw bytes and read the status, the content type and the body AS TEXT.
///
/// As TEXT, deliberately: the notification cases assert the body is EMPTY, and a helper that parsed
/// the answer as JSON would turn "there was no body" into `Value::Null` and assert nothing. That is
/// exactly how a server that replies to notifications passes a test suite.
async fn post_raw(url: &str, body: &serde_json::Value, method: &str) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(url)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", method)
        .body(serde_json::to_vec(body).expect("serialise"))
        .send()
        .await
        .expect("the call completes");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

// ══ (1) `"id": null` — A REQUEST WITH AN ILLEGAL ID ══════════════════════════════════════════════

/// `BASE.REQ.ID-NOT-NULL` (MUST NOT). A `null` id must never be answered with a SUCCESS result.
///
/// This is the reported defect, stated as the battery states it: a `result` carried under
/// `"id": null` is uncorrelatable by construction — JSON-RPC section 5 reserves a `null` response id to
/// mean "the server could not tell which request this was", so a success under it claims a
/// correlation the protocol has already spent that value denying.
#[tokio::test]
async fn a_null_id_is_never_answered_with_a_success_result() {
    let (url, _h) = serve().await;
    let (status, text) = post_raw(
        &url,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "server/discover",
            "params": params(),
        }),
        "server/discover",
    )
    .await;

    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    assert!(
        body.get("result").is_none(),
        "a request with `\"id\": null` was answered with a SUCCESS result, which no client can \
         correlate. MCP 2026-07-28 basic#requests: \"Unlike base JSON-RPC, the ID MUST NOT be \
         `null`.\" status={status} body={text}"
    );
    assert_ne!(
        status, 200,
        "a refusal must not be dressed as a 200: status={status} body={text}"
    );
    assert_eq!(
        body.pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32600),
        "an illegal `id` is an Invalid Request: status={status} body={text}"
    );
    // JSON-RPC section 5: when the id could not be established, the response id MUST be Null — and it must
    // be PRESENT, because `id` is a REQUIRED member of a Response object.
    assert_eq!(
        body.get("id"),
        Some(&serde_json::Value::Null),
        "the refusal must carry `\"id\": null` (JSON-RPC 2.0 section 5, `id` is REQUIRED on a Response): \
         body={text}"
    );
}

// ══ (2) NO `id` MEMBER ON AN ORDINARY METHOD — A NOTIFICATION ════════════════════════════════════

/// JSON-RPC section 4.1 and MCP `basic#notifications` (both MUST NOT). A message with no `id` member is a
/// notification WHATEVER its method is, and a notification gets no response body.
///
/// Separate from case (3) on purpose. A server that special-cases the `notifications/` PREFIX and
/// answers everything else passes (3) and fails this one — and the prefix is not what makes a
/// message a notification. The absence of `id` is.
#[tokio::test]
async fn a_request_method_with_no_id_is_a_notification_and_gets_no_response_body() {
    let (url, _h) = serve().await;
    let (status, text) = post_raw(
        &url,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "server/discover",
            "params": params(),
        }),
        "server/discover",
    )
    .await;

    assert!(
        text.trim().is_empty(),
        "a message with NO `id` member is a notification, and JSON-RPC 2.0 section 4.1 says \"The Server \
         MUST NOT reply to a Notification\" — but a body came back: status={status} body={text}"
    );
    assert_eq!(
        status, 202,
        "MCP Streamable HTTP: a notification is acknowledged with `202 Accepted` and no body, \
         got status={status} body={text}"
    );
}

// ══ (3) A GENUINE NOTIFICATION METHOD ════════════════════════════════════════════════════════════

/// The same MUST NOT, on the shape a real client actually sends. `notifications/cancelled` is the
/// one every MCP client emits, and busbar's method table does not implement it — so before this
/// test it was answered `-32601`, which is a response to a notification.
#[tokio::test]
async fn a_genuine_notification_gets_no_response_body_not_even_an_error() {
    let (url, _h) = serve().await;
    let (status, text) = post_raw(
        &url,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": { "requestId": "whatever" },
        }),
        "notifications/cancelled",
    )
    .await;

    assert!(
        text.trim().is_empty(),
        "a notification was answered. `MUST NOT send a response` has no exception for \"but the \
         method was unknown\" — an error IS a response, and one arriving out of band corrupts a \
         client's id bookkeeping: status={status} body={text}"
    );
    assert_eq!(status, 202, "got status={status} body={text}");
}

// ══ (4) THE CONTROL ══════════════════════════════════════════════════════════════════════════════

/// A REAL id still works, and is echoed EXACTLY.
///
/// Without this, every assertion above is satisfied by a server that refuses everything. It also
/// pins the third of the three: `id` is a string or a number, it survives round trip, and it is not
/// coerced.
#[tokio::test]
async fn a_string_id_is_served_and_echoed_verbatim() {
    let (url, _h) = serve().await;
    let (status, text) = post_raw(
        &url,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-7",
            "method": "server/discover",
            "params": params(),
        }),
        "server/discover",
    )
    .await;
    assert_eq!(status, 200, "the control must be served: {text}");
    let body: serde_json::Value = serde_json::from_str(&text).expect("the control answers JSON");
    assert!(body.get("result").is_some(), "no result: {text}");
    assert_eq!(
        body["id"],
        serde_json::json!("req-7"),
        "id not echoed: {text}"
    );
}
