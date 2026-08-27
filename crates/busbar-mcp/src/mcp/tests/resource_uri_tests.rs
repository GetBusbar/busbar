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
use crate::mcp::envelope::PROTOCOL_VERSION;
use crate::mcp::McpCfg;
use busbar_core::state::{App, AppHandle};
use busbar_core::test_support::TestApp;
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

/// A server exposing ONE PARAMETERISED address, whose text names the server so a test can tell
/// whose content it was served.
///
/// The same shape as [`server_exposing`] one line up, and deliberately so: the two differ only in
/// whether the address the operator approved carries a parameter, which is exactly the difference
/// the cases below say must NOT change the answer.
fn server_exposing_template(template: &str, marker: &str) -> McpServerDefCfg {
    def(&format!(
        r#"
url: "https://tools.example.com/mcp"
pin: {{ mechanism: unpinned }}
resource_templates_allow:
  "{template}":
    name: "A parameterised resource"
    mime_type: "text/plain"
    text: "{marker}/{{id}}"
"#
    ))
}

/// A `PlaneRequestCtx` holding a key whose `allowed_scopes` is exactly `pairs`.
fn gov_with_scopes(pairs: &[(&str, &str)]) -> busbar_api::PlaneRequestCtx {
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
        ..Default::default()
    };
    busbar_api::PlaneRequestCtx {
        key: Some(Arc::new(key)),
    }
}

async fn call(
    app: &Arc<App>,
    gov: &busbar_api::PlaneRequestCtx,
    method: &str,
    params: serde_json::Value,
) -> (u16, serde_json::Value) {
    let handle = Arc::new(AppHandle::new(app.clone()));
    let ctx = crate::mcp::method::Ctx {
        host: busbar_core::plane_host::engine_host_from_handle(&handle),
        gov,
        actor: "test-principal",
        capabilities: &ALL_CAPABILITIES,
        headers: &NO_HEADERS,
        scope: None,
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
    busbar_core::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("test", server_exposing("test://static-text", "hello"))
        .build();
    let router = busbar_core::build_router(app);
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
    busbar_core::metrics::init();
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
    busbar_core::metrics::init();
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
    busbar_core::metrics::init();
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
    busbar_core::metrics::init();
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

// ── THE SAME PROPERTY WHERE THE ADDRESS CARRIES A PARAMETER ────────────────────────────────────
//
// Everything above is about an address the operator wrote out in full. An operator may also approve
// a SHAPE — `shared://doc/{id}` — and a caller then addresses one expansion of it. That is a second
// way for two upstreams a caller can reach to answer for one address, and the answer to "which one
// did you mean" cannot depend on which of the two spellings the operator happened to use. A
// deployment where the literal address refuses an ambiguity and the parameterised one quietly picks
// is a deployment where the refusal is bypassed by writing the approval differently.

/// TWO servers expose ONE parameterised address. A caller granted only ONE is served ITS content —
/// and never the other's, **in either declaration order**.
///
/// The control for the case below it: this must go through, or the refusal there would be proving
/// only that the plane refuses everything.
#[tokio::test]
async fn a_caller_granted_one_server_is_never_served_the_others_templated_content() {
    busbar_core::metrics::init();
    for (first, second) in [("alpha", "beta"), ("beta", "alpha")] {
        let app = TestApp::new()
            .mcp(&mcp_cfg())
            .mcp_server(first, server_exposing_template("shared://doc/{id}", first))
            .mcp_server(
                second,
                server_exposing_template("shared://doc/{id}", second),
            )
            .build();
        let g = gov_with_scopes(&[
            ("mcp_server", "alpha"),
            ("mcp_tool", "alpha_shared://doc/{id}"),
        ]);
        let (status, body) = call(
            &app,
            &g,
            "resources/read",
            serde_json::json!({ "uri": "shared://doc/42" }),
        )
        .await;
        assert_eq!(status, 200, "declared {first} then {second}: {body}");
        assert!(
            body["result"]["contents"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .contains("alpha"),
            "a caller granted alpha was served another server's content \
             (declared {first} then {second}): {body}"
        );
    }
}

/// TWO servers expose ONE parameterised address and the caller is granted BOTH. **Refused, naming
/// both** — exactly as the literal spelling of the same ambiguity is, and never resolved by picking
/// one.
///
/// The pick is not a coin toss and that is what makes it worth refusing: the two candidates are
/// compared in a stable order derived from the upstream's own identifier, so whoever chooses the
/// identifier chooses the winner, on every process, silently, for as long as the config stands.
#[tokio::test]
async fn a_genuine_template_ambiguity_is_refused_and_names_both_servers() {
    busbar_core::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server(
            "alpha",
            server_exposing_template("shared://doc/{id}", "alpha"),
        )
        .mcp_server(
            "beta",
            server_exposing_template("shared://doc/{id}", "beta"),
        )
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", "alpha"),
        ("mcp_tool", "alpha_shared://doc/{id}"),
        ("mcp_server", "beta"),
        ("mcp_tool", "beta_shared://doc/{id}"),
    ]);
    let (status, body) = call(
        &app,
        &g,
        "resources/read",
        serde_json::json!({ "uri": "shared://doc/42" }),
    )
    .await;
    assert_eq!(
        status, 409,
        "an ambiguity must be refused, not resolved, whether the address the operator approved \
         was literal or parameterised: {body}"
    );
    assert_eq!(
        body["error"]["data"]["reason"], "resource_ambiguous",
        "one ambiguity, one reason word — an operator reading the audit must not have to know \
         which spelling produced it: {body}"
    );
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("alpha") && msg.contains("beta"),
        "the refusal must name both servers so the operator can act on it: {body}"
    );
}

/// TWO parameterised addresses on ONE server both match one expansion, and the caller is granted
/// that server. Still a question the registry cannot answer, and still refused.
///
/// This is the case the code's own comment described and then resolved anyway: an operator who
/// wrote two overlapping approvals is an operator who has to say which they meant.
#[tokio::test]
async fn two_overlapping_templates_on_one_server_are_refused_rather_than_ordered() {
    busbar_core::metrics::init();
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server(
            "alpha",
            def(r#"
url: "https://tools.example.com/mcp"
pin: { mechanism: unpinned }
resource_templates_allow:
  "shared://doc/{id}":
    mime_type: "text/plain"
    text: "by-id {id}"
  "shared://{kind}/42":
    mime_type: "text/plain"
    text: "by-kind {kind}"
"#),
        )
        .build();
    let g = gov_with_scopes(&[
        ("mcp_server", "alpha"),
        ("mcp_tool", "alpha_shared://doc/{id}"),
        ("mcp_tool", "alpha_shared://{kind}/42"),
    ]);
    let (status, body) = call(
        &app,
        &g,
        "resources/read",
        serde_json::json!({ "uri": "shared://doc/42" }),
    )
    .await;
    assert_eq!(
        status, 409,
        "two approvals that both cover one address is an ambiguity the operator must resolve, \
         not one the registry may resolve for them: {body}"
    );
    assert_eq!(
        body["error"]["data"]["reason"], "resource_ambiguous",
        "{body}"
    );
}
