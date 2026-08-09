// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `params._meta` IS PART OF THE PARAMS, so a defect in it answers `-32602`, not `-32020`.
//!
//! Under `2026-07-28` there is no handshake, so every request states its own protocol version and
//! its own client capabilities in `params._meta`, and the schema makes both members required. This
//! module pins the three ways that can be wrong and the two things each refusal has to be:
//!
//! * the JSON-RPC code is `-32602` (invalid params) — the STANDARD code for a params defect, not
//!   `-32020`, which is the MCP `HeaderMismatchError` and is a statement about a HEADER
//!   disagreeing with the body. Answering `-32020` for an incomplete body told a client its
//!   headers were wrong when its params were, which sends an operator to fix the one thing that
//!   was right;
//! * the HTTP status is `400`, never `200`. A `200` carrying an error object is what JSON-RPC over
//!   HTTP has meant everywhere else for a decade and is exactly what this revision forbids.
//!
//! The CONTROL matters as much as the refusals: a server that answered `-32602` to everything would
//! satisfy all three refusals and serve nothing, so a fully-formed `_meta` must still reach the
//! method table — and a genuine header disagreement must still answer `-32020`, or this change
//! would have replaced one wrong code with another.

use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

/// Serve an MCP-enabled app. The auth chain is open because these tests are about the request
/// ENVELOPE and every one of them must reach the handler to say anything; the audience boundary is
/// owned by `auth::tests::test_mcp_token_is_confined_to_the_mcp_plane` and the refusal to CONFIGURE
/// an anonymous MCP deployment is owned by `tests/mcp_open_front_door.rs`.
async fn serve() -> (String, tokio::task::JoinHandle<()>) {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&McpCfg {
            canonical_uri: "https://gateway.example.com/mcp".to_string(),
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

/// POST `params` verbatim under a `tools/list` envelope whose mirrored headers are all correct, so
/// the ONLY thing a test varies is `_meta` and nothing else can be responsible for the answer.
async fn post_params(
    url: &str,
    params: serde_json::Value,
    version_header: &str,
) -> (u16, serde_json::Value) {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/list",
        "params": params,
    });
    let resp = reqwest::Client::new()
        .post(url)
        .header("mcp-protocol-version", version_header.to_string())
        .header("mcp-method", "tools/list")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or_default())
}

fn code(v: &serde_json::Value) -> i64 {
    v.pointer("/error/code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(|| panic!("response carried no JSON-RPC error: {v}"))
}

/// A fully-formed `_meta`: both required members, both correct.
fn full_meta() -> serde_json::Value {
    serde_json::json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    })
}

#[tokio::test]
async fn params_with_no_meta_at_all_is_invalid_params_400() {
    let (url, h) = serve().await;
    let (status, json) = post_params(&url, serde_json::json!({}), PROTOCOL_VERSION).await;
    assert_eq!(
        (status, code(&json)),
        (400, -32602),
        "`params` with no `_meta` is a PARAMS defect"
    );
    assert_eq!(json["id"], 42, "the request id is echoed on the refusal");
    h.abort();
}

#[tokio::test]
async fn meta_without_the_protocol_version_is_invalid_params_400() {
    let (url, h) = serve().await;
    let params = serde_json::json!({
        "_meta": { "io.modelcontextprotocol/clientCapabilities": {} }
    });
    let (status, json) = post_params(&url, params, PROTOCOL_VERSION).await;
    assert_eq!(
        (status, code(&json)),
        (400, -32602),
        "this revision negotiates per request; an absent version cannot be inferred"
    );
    h.abort();
}

/// The one that used to be admitted. Absent client capabilities were treated as the EMPTY
/// capability set, on the reasoning that a server must never INFER a capability the client did not
/// declare. That reasoning is sound and it is not what the omission means: with no handshake there
/// is no earlier message the client could have declared in, so "declared nothing" is not "declared
/// none", and filling the gap in is the server deciding on the client's behalf what that client can
/// do. `{}` is how a client declares none, and it is one keystroke away.
#[tokio::test]
async fn meta_without_client_capabilities_is_invalid_params_400() {
    let (url, h) = serve().await;
    let params = serde_json::json!({
        "_meta": { "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION }
    });
    let (status, json) = post_params(&url, params, PROTOCOL_VERSION).await;
    assert_eq!(
        (status, code(&json)),
        (400, -32602),
        "an omitted `clientCapabilities` must be refused, not defaulted"
    );
    h.abort();
}

/// THE CONTROL. Without it every assertion above is equally satisfied by a server that refuses
/// everything, which would be a conforming-looking deployment that serves nobody.
#[tokio::test]
async fn a_complete_meta_still_reaches_the_method_table() {
    let (url, h) = serve().await;
    let (status, json) = post_params(&url, full_meta(), PROTOCOL_VERSION).await;
    assert_eq!(status, 200, "a well-formed request must still be served");
    assert!(
        json.pointer("/result/tools").is_some(),
        "expected a ListToolsResult, got {json}"
    );
    h.abort();
}

/// THE OTHER CONTROL: the `-32020` vocabulary still belongs to the headers. Moving the `_meta`
/// refusals to `-32602` must not take the header-mismatch code with them — a header that disagrees
/// with the body is a different defect (two readings of one request, which is request smuggling
/// spelled in JSON) and it keeps its own code.
#[tokio::test]
async fn a_header_that_disagrees_with_a_complete_meta_is_still_header_mismatch() {
    let (url, h) = serve().await;
    let (status, json) = post_params(&url, full_meta(), "1999-01-01").await;
    assert_eq!(
        (status, code(&json)),
        (400, -32020),
        "header-vs-body disagreement keeps `HeaderMismatchError`"
    );
    h.abort();
}
