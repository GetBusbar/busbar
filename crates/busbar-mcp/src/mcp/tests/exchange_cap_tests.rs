// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RFC 8693 TOKEN-EXCHANGE RESPONSE BODY IS CAPPED, not merely time-bounded.
//!
//! `exchange()` used to read the token endpoint's response body with
//! `response.into_body().collect()` — bounded only by the caller's wall-clock deadline, with NO byte
//! cap. A compromised or hostile authorization server can stream an arbitrarily large body inside
//! that deadline and busbar buffers all of it, per call: memory exhaustion from an untrusted party
//! that only has to answer inside the timeout. The fix reads the body through the SAME capped-read
//! primitive every other upstream body read in this crate already uses
//! (`busbar_kernel::proxy::read_capped`, `busbar_kernel::proxy::max_upstream_buffered_bytes()`), and
//! refuses to PARSE a truncated body as a token rather than silently minting a credential off a
//! partial response.
//!
//! Driven directly against [`crate::mcp::upstream::exchange`] rather than through a full `tools/call`
//! round trip: the claim under test is about ONE function's byte accounting, and the surrounding gate
//! machinery (`egress.rs`'s battery) already has its own tests.

use crate::mcp::client::egress::ExchangeRequest;
use crate::mcp::client::pool::McpConnectionPool;
use crate::mcp::client::ssrf::SsrfPolicy;
use busbar_api::Redacted;
use std::time::Duration;

/// A fake RFC 8693 token endpoint that answers every POST with exactly `body`, over a real socket.
async fn start_token_endpoint(body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    async fn respond(axum::extract::State(body): axum::extract::State<Vec<u8>>) -> Vec<u8> {
        body
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = axum::Router::new()
        .route("/token", axum::routing::post(respond))
        .with_state(body);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{addr}/token"), task)
}

fn request(token_url: &str) -> ExchangeRequest {
    ExchangeRequest {
        token_url: token_url.to_string(),
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: Redacted::new("busbar-own-subject-token".to_string()),
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token".to_string(),
        resource: "https://upstream.example.com/mcp".to_string(),
        scope: "read".to_string(),
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    }
}

/// AN OVERSIZED TOKEN-EXCHANGE RESPONSE BODY IS REFUSED, not silently buffered and parsed.
///
/// The fake authorization server answers with a SYNTACTICALLY VALID JSON body carrying a genuine
/// `access_token` field, padded past the installed cap. Without a byte cap the exchange would parse
/// it and hand back the token; with the cap it must refuse BEFORE parsing, so the truncated bytes are
/// never handed to `serde_json` at all — this is the "refuse on truncation" half of the fix, not just
/// "the response happens to error".
#[tokio::test]
async fn an_oversized_token_response_is_refused_not_buffered() {
    let cap = busbar_kernel::proxy::max_upstream_buffered_bytes();
    let padding = "A".repeat(cap + 4096);
    let body = serde_json::json!({ "access_token": padding }).to_string();
    assert!(
        body.len() > cap,
        "the fixture must exceed the installed cap for this test to mean anything"
    );
    let (token_url, _task) = start_token_endpoint(body.into_bytes()).await;
    let pool = McpConnectionPool::new();
    let req = request(&token_url);
    let policy = SsrfPolicy {
        allow_private: true,
    };
    let result = crate::mcp::upstream::exchange(&pool, &req, policy, Duration::from_secs(10)).await;
    let err = result.expect_err("an over-cap body must never be parsed into a usable token");
    assert!(
        err.contains("cap") || err.contains("truncat"),
        "the refusal must name the byte cap, not read as a generic parse failure: {err}"
    );
    assert!(
        !err.contains("not JSON"),
        "an over-cap body must be refused for BEING over-cap, not reported as a parse failure — \
         the truncated bytes must never reach serde_json: {err}"
    );
}

/// A GENUINELY MALFORMED BODY, UNDER THE CAP, IS REFUSED FOR A DIFFERENT REASON — proving the
/// oversized-body refusal above is not just "make every exchange fail" but names the cap
/// specifically.
#[tokio::test]
async fn a_small_malformed_body_is_refused_as_unparseable_not_as_oversized() {
    let (token_url, _task) = start_token_endpoint(b"not json at all".to_vec()).await;
    let pool = McpConnectionPool::new();
    let req = request(&token_url);
    let policy = SsrfPolicy {
        allow_private: true,
    };
    let result = crate::mcp::upstream::exchange(&pool, &req, policy, Duration::from_secs(10)).await;
    let err = result.expect_err("a non-JSON body must not be parsed as a token");
    assert!(
        err.contains("not JSON"),
        "a small malformed body must be refused as unparseable: {err}"
    );
    assert!(
        !err.contains("cap") && !err.contains("truncat"),
        "a small body must not be blamed on the byte cap: {err}"
    );
}

/// A LEGITIMATE, SMALL RESPONSE STILL WORKS. The cap must have zero effect on ordinary traffic — a
/// real OAuth token response is well under 1 KiB.
#[tokio::test]
async fn a_small_legitimate_response_still_mints_the_token() {
    let body = serde_json::json!({ "access_token": "the-issued-token" }).to_string();
    let (token_url, _task) = start_token_endpoint(body.into_bytes()).await;
    let pool = McpConnectionPool::new();
    let req = request(&token_url);
    let policy = SsrfPolicy {
        allow_private: true,
    };
    let result = crate::mcp::upstream::exchange(&pool, &req, policy, Duration::from_secs(10)).await;
    assert_eq!(result, Ok("the-issued-token".to_string()));
}
