// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An engine-minted token is good on the plane it was minted for and on no other. The MCP plane's
//! audience is its `canonical_uri`: a key minted for that audience is admitted at `/mcp`; a key
//! minted for no audience, or for another resource, is refused there; and the MCP key is refused
//! on the plane that binds no audience. Each refusal is the one unverified answer.

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use e2e_support::{chat_answer, llm, post_json, send, Node, Reply, Scripted, CHAT};
use serde_json::json;

const INITIALIZE: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}"#;

/// The MCP plane's section in the 1.6 form (the plane's settings `format` 2, as plane-mcp's
/// `migrate::settle` writes back an older bag): the audience (`canonical_uri`, core's word), the
/// resource facts, and the one tool server inside the section.
const MCP_SECTION: &str = "mcp:\n  canonical_uri: \"http://127.0.0.1:{data_port}/mcp\"\n  \
     format: 2\n  resource:\n    authorization_servers: [\"http://127.0.0.1:{admin_port}\"]\n    \
     scopes_supported: []\n    allowed_origins: []\n  servers:\n    \
     t1: { pin: { mechanism: unpinned }, core_upstream: true, url: \"https://t.example/rpc\" }\n";

fn boot(tag: &str, upstream: &Scripted) -> Node {
    llm(tag, upstream, None).section(MCP_SECTION).boot()
}

fn audience(node: &Node) -> String {
    format!("http://127.0.0.1:{}/mcp", node.data)
}

/// The MCP plane's refusal of a caller it did not verify: the one answer with the plane's own
/// challenge, and exactly what a caller with no credential at all is told, so the refusal says
/// nothing about why.
fn assert_refused_at_mcp(node: &Node, reply: &Reply, what: &str) {
    assert!(
        reply.is_the_unverified_answer(),
        "{what}: answered {} {}",
        reply.status,
        reply.text()
    );
    let challenge = reply.header("www-authenticate").unwrap_or_default();
    assert!(
        challenge.starts_with("Bearer") && challenge.contains("resource_metadata=\"http"),
        "{what}: the plane's challenge, got {challenge:?}"
    );
    let nobody = send(
        node.data,
        "POST",
        "/mcp",
        &[("Content-Type", "application/json")],
        INITIALIZE,
    );
    assert_eq!(
        (reply.status, &reply.body, reply.header("www-authenticate")),
        (
            nobody.status,
            &nobody.body,
            nobody.header("www-authenticate")
        ),
        "{what} is told something a caller with no credential is not"
    );
    assert_eq!(reply.header_names(), nobody.header_names(), "{what}");
}

#[test]
fn a_key_minted_for_the_mcp_audience_is_admitted_at_mcp() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("mcp-right", &upstream);
    let key = node.mint(&json!({ "name": "e2e-mcp", "audience": audience(&node) }));

    let reply = post_json(node.data, "/mcp", &key.token, INITIALIZE);

    assert!(
        reply.admitted(),
        "a key minted for the plane's audience: answered {} {}",
        reply.status,
        reply.text()
    );
    assert_eq!(
        reply.header("www-authenticate"),
        None,
        "an admitted caller is not challenged"
    );
}

#[test]
fn a_key_minted_for_no_audience_is_refused_at_mcp() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("mcp-plain", &upstream);
    let key = node.mint(&json!({ "name": "e2e-plain" }));

    let reply = post_json(node.data, "/mcp", &key.token, INITIALIZE);

    assert_refused_at_mcp(&node, &reply, "a key minted for the data plane");
}

#[test]
fn a_key_minted_for_another_resource_is_refused_at_mcp() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("mcp-other", &upstream);
    // Another resource of the same origin, one path segment away: equality, never a prefix.
    let key = node.mint(&json!({
        "name": "e2e-other",
        "audience": format!("http://127.0.0.1:{}/mcp-staging", node.data),
    }));

    let reply = post_json(node.data, "/mcp", &key.token, INITIALIZE);

    assert_refused_at_mcp(&node, &reply, "a key minted for another resource");
}

#[test]
fn a_key_minted_for_the_mcp_audience_is_refused_on_the_llm_plane() {
    let upstream = Scripted::start(200, &chat_answer(1, 1));
    let node = boot("mcp-elsewhere", &upstream);
    let key = node.mint(&json!({ "name": "e2e-mcp", "audience": audience(&node) }));

    let reply = post_json(node.data, "/v1/chat/completions", &key.token, CHAT);

    assert!(
        reply.is_the_unverified_answer(),
        "an MCP key on a plane that binds no audience: answered {} {}",
        reply.status,
        reply.text()
    );
    assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
    assert_eq!(
        upstream.posts("chat/completions"),
        0,
        "a refused request reached the provider"
    );
    // The same node serves the same request to a key minted for this plane.
    let plain = node.mint(&json!({ "name": "e2e-plain" }));
    let served = post_json(node.data, "/v1/chat/completions", &plain.token, CHAT);
    assert_eq!(
        served.status,
        200,
        "the data plane's own key: {}",
        served.text()
    );
}
