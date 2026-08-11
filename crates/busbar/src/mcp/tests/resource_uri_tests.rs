// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A1.3 — A RESOURCE IS ADDRESSABLE BY THE URI THE PROTOCOL DEFINES.
//!
//! Busbar keyed every exposed resource by `{server}_{uri}` and published THAT on the wire, so the
//! identifier the MCP resource model fixes — the resource's own URI — answered `404`. A client told a
//! URI out of band, which is the ordinary way a resource URI travels, could not read it. Four
//! official scenarios address a resource by its own URI and were unreachable for that reason alone.
//!
//! The namespacing was not gratuitous and is not simply deleted here. It fixed a real defect, and
//! `ResourceEntry`'s own doc comment records it: two servers exposing the SAME URI collided, the
//! collision was SILENT (`BTreeMap::insert` is last-write-wins over an insertion-ordered config), and
//! a caller granted the first server was served the second server's content. That is content
//! confusion across a trust boundary, arriving through a key nobody thought of as a name.
//!
//! **So both properties must hold at once**, and that is what this file pins:
//!
//! | property | before | after |
//! |---|---|---|
//! | addressable by the protocol's own identifier | ✗ | ✓ |
//! | two servers cannot silently serve each other's content | ✓ | ✓ |
//!
//! The mechanism is `design/mcp-resource-routing-key.md` option 5, owner-approved as "option (a)":
//! the URI is the identity, the SERVER is resolved by the CALLER'S GRANT, and a genuine ambiguity —
//! one caller granted two servers that both expose one URI — is **REFUSED and named**, never guessed.
//! The defect being fixed was a silent resolution; the worst case here is a loud refusal, which is
//! categorically better than a quiet pick even when the quiet pick would usually be right.

use crate::mcp::config::McpServerDefCfg;
use crate::mcp::ingress::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use crate::state::{App, AppHandle};
use crate::test_support::TestApp;
use std::sync::Arc;

/// The client capabilities every case here declares. Each test module carries its own rather than
/// sharing one, which is the existing convention on this plane.
/// NO CUSTOM `Mcp-Param-*` HEADERS. Every `Ctx` built here drives a method directly rather than
/// through the HTTP ingress, so there is no header map to inherit and an empty one is the honest
/// stand-in. The SEP-2243 custom-param validation this field feeds is a header/body agreement
/// check: with no headers and no annotated tool it has nothing to compare and correctly passes.
static NO_HEADERS: std::sync::LazyLock<axum::http::HeaderMap> =
    std::sync::LazyLock::new(axum::http::HeaderMap::new);

static ALL_CAPABILITIES: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(
    || serde_json::json!({ "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } }),
);

const CANONICAL: &str = "https://gw.example.com/mcp";

fn mcp_cfg() -> McpCfg {
    McpCfg {
        canonical_uri: CANONICAL.to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

fn def(yaml: &str) -> McpServerDefCfg {
    serde_yaml::from_str(yaml)
        .unwrap_or_else(|e| panic!("the `tools:` registration was refused by the grammar: {e}"))
}

/// A server exposing ONE resource at `uri`, whose text names the server so a test can tell whose
/// content it was served.
fn server_exposing(uri: &str, marker: &str) -> McpServerDefCfg {
    def(&format!(
        r#"
url: "https://tools.example.com/mcp"
pin: {{ mechanism: unpinned }}
resources_allow:
  "{uri}":
    name: "A resource"
    mime_type: "text/plain"
    text: "{marker}"
"#
    ))
}

/// A `GovCtx` holding a key whose `allowed_scopes` is exactly `pairs`.
fn gov_with_scopes(pairs: &[(&str, &str)]) -> crate::governance::GovCtx {
    let key = busbar_api::VirtualKey {
        id: "k-test".to_string(),
        name: "test".to_string(),
        generation_hash: String::new(),
        enabled: true,
        allowed_scopes: Some(
            pairs
                .iter()
                .map(|(k, v)| busbar_api::ScopeRef {
                    kind: (*k).to_string(),
                    value: (*v).to_string(),
                })
                .collect(),
        ),
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        created_at: 0,
        revision: 0,
    };
    crate::governance::GovCtx {
        key: Some(Arc::new(key)),
    }
}

async fn call(
    app: &Arc<App>,
    gov: &crate::governance::GovCtx,
    method: &str,
    params: serde_json::Value,
) -> (u16, serde_json::Value) {
    let handle = Arc::new(AppHandle::new(app.clone()));
    let ctx = crate::mcp::method::Ctx {
        app,
        handle: &handle,
        gov,
        actor: "test-principal",
        capabilities: &ALL_CAPABILITIES,
        headers: &NO_HEADERS,
    };
    let response = crate::mcp::method::dispatch(&ctx, method, Some(&params), Some(1.into()))
        .await
        .unwrap_or_else(|| panic!("`{method}` must be in the method table"));
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

// ── THE WIRE, judged over a real socket ────────────────────────────────────────────────────────

/// `resources/read` addressed by the resource's OWN uri answers the content.
///
/// Driven over a real socket rather than through `dispatch`, because the claim is about what a
/// CLIENT can do: the four official scenarios send this exact request and were answered `404`.
#[tokio::test]
async fn a_resource_is_readable_by_the_uri_the_protocol_defines() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("test", server_exposing("test://static-text", "hello"))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let url = format!("http://{addr}/mcp");

    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "resources/read",
        "params": {
            "uri": "test://static-text",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        }
    });
    let resp = reqwest::Client::new()
        .post(&url)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .header("mcp-method", "resources/read")
        .header("mcp-name", "test://static-text")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let out: serde_json::Value = resp.json().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "the protocol's own identifier must address the resource: {out}"
    );
    assert_eq!(out["result"]["contents"][0]["text"], "hello", "{out}");
    // The uri ECHOED BACK is the one the caller asked for. A client correlates the content block to
    // its own request by this field, so answering a different spelling than the one asked for is a
    // correlation bug even when the content is right.
    assert_eq!(
        out["result"]["contents"][0]["uri"], "test://static-text",
        "{out}"
    );
}

/// `resources/list` publishes the raw URI, because that is what a client will hand back.
#[tokio::test]
async fn the_catalogue_publishes_the_uri_a_client_can_read_back() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("test", server_exposing("test://static-text", "hello"))
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", "test"),
        ("mcp_tool", "test_test://static-text"),
    ]);
    let (status, body) = call(&app, &g, "resources/list", serde_json::json!({})).await;
    assert_eq!(status, 200, "{body}");
    let uris: Vec<&str> = body["result"]["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    assert_eq!(
        uris,
        vec!["test://static-text"],
        "the catalogue must publish the identifier a client can read back: {body}"
    );
}

// ── THE PROPERTY THE NAMESPACING EXISTED TO HOLD, which must survive ───────────────────────────

/// TWO servers expose ONE uri. A caller granted only ONE is served ITS content — and never the
/// other's, **in either declaration order**.
///
/// This is the assertion the original defect needed and did not have. The old collision was decided
/// by `BTreeMap::insert` over an insertion-ordered config, so which server won was decided by the
/// order of two unrelated blocks in a config file. Asserting one order proves nothing; the bug WAS
/// an order dependency.
#[tokio::test]
async fn a_caller_granted_one_server_is_never_served_the_others_content() {
    crate::metrics::init();
    for (first, second) in [("alpha", "beta"), ("beta", "alpha")] {
        let app = TestApp::new()
            .mcp(&mcp_cfg())
            .mcp_server(first, server_exposing("shared://doc", first))
            .mcp_server(second, server_exposing("shared://doc", second))
            .build();
        // Granted ALPHA only, whichever order the config declared them in.
        let g = gov_with_scopes(&[("mcp_server", "alpha"), ("mcp_tool", "alpha_shared://doc")]);
        let (status, body) = call(
            &app,
            &g,
            "resources/read",
            serde_json::json!({ "uri": "shared://doc" }),
        )
        .await;
        assert_eq!(status, 200, "declared {first} then {second}: {body}");
        assert_eq!(
            body["result"]["contents"][0]["text"], "alpha",
            "a caller granted alpha was served another server's content \
             (declared {first} then {second}): {body}"
        );
    }
}

/// TWO servers expose ONE uri and the caller is granted BOTH. That is the only genuinely ambiguous
/// case, and it is REFUSED, naming both servers — never resolved by picking one.
#[tokio::test]
async fn a_genuine_ambiguity_is_refused_and_names_both_servers() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("alpha", server_exposing("shared://doc", "alpha"))
        .mcp_server("beta", server_exposing("shared://doc", "beta"))
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", "alpha"),
        ("mcp_tool", "alpha_shared://doc"),
        ("mcp_server", "beta"),
        ("mcp_tool", "beta_shared://doc"),
    ]);
    let (status, body) = call(
        &app,
        &g,
        "resources/read",
        serde_json::json!({ "uri": "shared://doc" }),
    )
    .await;
    assert_eq!(
        status, 409,
        "an ambiguity must be refused, not resolved: {body}"
    );
    assert_eq!(
        body["error"]["data"]["reason"], "resource_ambiguous",
        "{body}"
    );
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("alpha") && msg.contains("beta"),
        "the refusal must name both servers so the operator can act on it: {body}"
    );
}

/// A uri no server exposes is still not-found, and a uri the caller is not granted answers the SAME
/// way — the catalogue must not distinguish "no such resource" from "not yours", or it leaks the
/// existence of what it hides.
#[tokio::test]
async fn not_found_and_not_granted_are_indistinguishable() {
    crate::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("alpha", server_exposing("shared://doc", "alpha"))
        .build();
    let ungranted = gov_with_scopes(&[("mcp_server", "other")]);
    // The SAME uri against two deployments: one where it exists but is not granted, one where it
    // does not exist at all. Comparing two DIFFERENT uris would compare two messages that each echo
    // the caller's own input and would differ for that reason alone, proving nothing.
    let absent_app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("alpha", server_exposing("shared://other", "alpha"))
        .build();

    let (hidden_status, hidden) = call(
        &app,
        &ungranted,
        "resources/read",
        serde_json::json!({ "uri": "shared://doc" }),
    )
    .await;
    let (missing_status, missing) = call(
        &absent_app,
        &ungranted,
        "resources/read",
        serde_json::json!({ "uri": "shared://doc" }),
    )
    .await;

    assert_eq!(hidden_status, 404, "{hidden}");
    assert_eq!(missing_status, 404, "{missing}");
    assert_eq!(
        missing["error"]["message"], hidden["error"]["message"],
        "a hidden resource must answer identically to an absent one, or the difference \
         is a probe for what the caller is not allowed to see"
    );
}
