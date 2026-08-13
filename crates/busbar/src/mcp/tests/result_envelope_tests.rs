// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RESULT ENVELOPE of revision `2026-07-28`: `resultType` on every result, `cacheScope` and
//! `ttlMs` on every cacheable one, and `supportedVersions` on `server/discover`.
//!
//! These are not decoration and they are not optional. A `ListToolsResult` without `cacheScope`,
//! `resultType` and `ttlMs` does not validate against the revision's own schema, so a strict client
//! rejects the whole answer — the catalogue is correct and unusable.
//!
//! ## What the VALUES are asserted to be, and why the test names them rather than just checking
//! presence
//!
//! A cache hint that lies is worse than none, so "the field is there" is the weaker half of the
//! property. `cacheScope` must be `private` because every answer here is computed under the
//! CALLER'S GRANT: `public` licenses a shared intermediary to serve one caller's authorized
//! catalogue to a caller who holds none of it, which is the grant boundary being crossed by a
//! cache. `ttlMs` must be `0` because this deployment has no invalidation channel — `listChanged`
//! is `false` under a stateless revision — so any positive window is a promise of freshness the
//! server cannot keep, and a client honouring it would keep offering a de-approved tool.
//!
//! `supportedVersions` on `server/discover` is asserted to be the SAME list the ingress refuses an
//! unsupported version against, not merely a non-empty list: the two are what a client correlates
//! when it is told to retry, and two lists that could disagree is a client told to retry with a
//! version it will be refused for.

use crate::mcp::envelope::{PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
use crate::mcp::McpCfg;
use crate::test_support::TestApp;

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

/// Call `method` with a fully-formed envelope and return its `result` object.
async fn call(url: &str, method: &str) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    });
    let resp = reqwest::Client::new()
        .post(url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", method)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json: serde_json::Value = resp.json().await.unwrap_or_default();
    assert_eq!(status, 200, "`{method}` did not answer 200: {json}");
    json.get("result")
        .unwrap_or_else(|| panic!("`{method}` returned no result: {json}"))
        .clone()
}

/// The five results this revision calls CACHEABLE and busbar can answer without a registered
/// upstream, each paired with the array member the schema requires alongside the hints. Named as
/// data rather than as five near-identical tests so a sixth cacheable method joins the assertion
/// instead of escaping it.
const CACHEABLE: &[(&str, &str)] = &[
    ("server/discover", "supportedVersions"),
    ("tools/list", "tools"),
    ("prompts/list", "prompts"),
    ("resources/list", "resources"),
    ("resources/templates/list", "resourceTemplates"),
];

#[tokio::test]
async fn every_cacheable_result_carries_the_caching_hints_and_a_result_type() {
    let (url, h) = serve().await;
    for (method, member) in CACHEABLE {
        let result = call(&url, method).await;
        assert!(
            result.get(member).is_some(),
            "`{method}` result is missing its `{member}` member: {result}"
        );
        assert_eq!(
            result.get("resultType").and_then(|v| v.as_str()),
            Some("complete"),
            "`{method}` must state `resultType`: {result}"
        );
        assert_eq!(
            result.get("cacheScope").and_then(|v| v.as_str()),
            Some("private"),
            "`{method}` must be `private`: every answer here is scoped to the caller's grant, so a \
             shared cache serving it across authorization contexts is a grant bypass"
        );
        assert_eq!(
            result.get("ttlMs").and_then(serde_json::Value::as_i64),
            Some(0),
            "`{method}` must publish a zero freshness window: there is no invalidation channel, so \
             any positive value is a promise this server cannot keep"
        );
    }
    h.abort();
}

/// `resources/templates/list` is IMPLEMENTED and answers an empty list, which is a different
/// statement from `-32601`. `-32601` claims this server does not do templates at all; `[]` states
/// that this deployment exposes none, which is the claim that is true — busbar's registry approves
/// concrete resources by URI and has no way to express an approval of a URI SHAPE.
#[tokio::test]
async fn resource_templates_are_an_empty_list_not_a_method_not_found() {
    let (url, h) = serve().await;
    let result = call(&url, "resources/templates/list").await;
    assert_eq!(
        result.get("resourceTemplates"),
        Some(&serde_json::json!([])),
        "expected an empty template catalogue, got {result}"
    );
    h.abort();
}

/// `server/discover` must advertise the versions this server will ACCEPT, and they must be the
/// exact list the ingress refuses against — see the module header for why the identity matters
/// rather than mere non-emptiness.
#[tokio::test]
async fn discover_advertises_exactly_the_versions_the_ingress_accepts() {
    let (url, h) = serve().await;
    let result = call(&url, "server/discover").await;
    let advertised: Vec<String> = result
        .get("supportedVersions")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("discover carried no `supportedVersions`: {result}"))
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    let accepted: Vec<String> = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        advertised, accepted,
        "the discovered list and the accepted list must be one list, or a client is invited to \
         retry with a version it will be refused for"
    );
    assert!(
        result.get("capabilities").is_some(),
        "discover must carry `capabilities`: {result}"
    );
    h.abort();
}
