// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `roots/list`, SATISFIED — the coverage instrument for
//! `mcp|streamable-http|client|server|roots/list`.
//!
//! The cell was waived on the sentence "busbar has no filesystem to describe", and the waiver's own
//! text named what was actually missing: *"There is no roots policy in 1.6.0 for an operator to
//! declare one from."* This battery is the policy working end to end: an upstream returns an
//! `InputRequiredResult` naming `roots/list`, the per-round grant gate admits it, and the retry
//! carries the OPERATOR'S declared roots — read off the peer's own transcript, because what busbar
//! disclosed is a claim about bytes the peer received.
//!
//! What stays true from the waiver era, asserted rather than assumed:
//!
//! - the ask TERMINATES at busbar in every arm — the caller is answered a result or a
//!   busbar-attributed refusal, never handed the upstream's ask;
//! - deny-by-default did not move — no grant, no disclosure, and the refusal names the grant;
//! - the grant without a declaration discloses NOTHING — `Unsatisfiable`, naming
//!   `tools.<server>.roots`, because a grant is an operator admitting the ask and the declaration
//!   is the operator saying what may answer it, and neither implies the other.

use super::upstream_support::{call, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer};
use crate::testkit::TestAppMcpExt;
use busbar_core::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// The operator's declaration: what THIS server may be told about.
fn declared_roots() -> Vec<crate::mcp::config::RootCfg> {
    vec![
        crate::mcp::config::RootCfg {
            uri: "file:///workspace/project".to_string(),
            name: Some("project".to_string()),
        },
        crate::mcp::config::RootCfg {
            uri: "file:///workspace/shared".to_string(),
            name: None,
        },
    ]
}

/// The registration with the ask ADMITTED (`grants.roots`) and the answer DECLARED (`roots:`).
fn rooted_server(peer: &Peer) -> crate::mcp::config::McpServerDefCfg {
    let mut cfg = exchanging_server(peer, SUBJECT);
    cfg.grants.roots = true;
    cfg.roots = declared_roots();
    cfg
}

/// THE CELL. A granted, declared `roots/list` ask is satisfied: the retry carries the operator's
/// roots and the upstream's own `requestState`, the exchange completes, and the caller sees the
/// final result and nothing of the ask.
#[tokio::test]
async fn a_granted_roots_ask_is_answered_with_the_operators_declared_roots() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForRoots, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", rooted_server(&peer))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "README" } }),
    )
    .await;

    assert_eq!(status, 200, "the satisfied exchange must complete: {body}");
    assert_eq!(
        body.pointer("/result/content/0/text").unwrap(),
        "ROOTS RECEIVED",
        "the caller is handed the upstream's FINAL result: {body}"
    );
    // The ask terminated at busbar: nothing of it reaches the caller.
    assert!(
        body.pointer("/result/inputRequests").is_none()
            && body.pointer("/result/requestState").is_none(),
        "an upstream's ask must never surface in the caller's result: {body}"
    );

    // TWO round trips: the ask, then the answered retry.
    assert_eq!(peer.mcp_hits(), 2, "one ask, one satisfied retry");
    let retry = peer.last_mcp().json();
    assert_eq!(
        retry.pointer("/params/inputResponses/workspace/roots"),
        Some(&serde_json::json!([
            { "uri": "file:///workspace/project", "name": "project" },
            { "uri": "file:///workspace/shared" },
        ])),
        "the disclosure is the OPERATOR'S declaration, verbatim — never busbar's own filesystem: \
         {retry}"
    );
    assert_eq!(
        retry.pointer("/params/requestState"),
        Some(&serde_json::json!("peer-opaque-roots-state")),
        "the upstream's opaque state is echoed exactly — it is meaningful only to the server that \
         minted it: {retry}"
    );
    // And the retry still carries the same arguments and tool: it is the SAME logical call.
    assert_eq!(retry.pointer("/params/name").unwrap(), "read");
    assert_eq!(
        retry.pointer("/params/arguments/path").unwrap(),
        "README",
        "the continuation continues the call it answers: {retry}"
    );

    // THE CAPABILITY WAS DECLARED FROM THE FIRST REQUEST. MRTR forbids a server sending an ask the
    // client has not declared, so a busbar that can answer must say so before it is asked.
    let first = peer
        .log
        .lock()
        .unwrap()
        .mcp
        .first()
        .cloned()
        .unwrap()
        .json();
    assert_eq!(
        first.pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities/roots"),
        Some(&serde_json::json!({})),
        "a deployment that will answer `roots/list` for this server declares the capability on \
         every request to it: {first}"
    );
}

/// DENY-BY-DEFAULT DID NOT MOVE. No `grants.roots`, no disclosure, and the refusal names the grant
/// — the `Ungranted` arm, whose remedy is a config key.
#[tokio::test]
async fn an_ungranted_roots_ask_is_still_refused_and_names_the_grant() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForRoots, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        // The stock registration: all grants false, nothing declared.
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "README" } }),
    )
    .await;

    assert_ne!(status, 200, "an ungranted ask must refuse the call: {body}");
    assert_eq!(
        peer.mcp_hits(),
        1,
        "the ask round happened and no retry followed it — nothing was disclosed"
    );
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("roots") && message.contains("grants"),
        "the refusal must name the grant an operator would set: {body}"
    );
    // And with nothing declared and nothing granted, the capability was never advertised.
    let first = peer
        .log
        .lock()
        .unwrap()
        .mcp
        .first()
        .cloned()
        .unwrap()
        .json();
    assert_eq!(
        first.pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities"),
        Some(&serde_json::json!({})),
        "a busbar that will not answer must not declare that it will: {first}"
    );
}

/// THE GRANT ALONE DISCLOSES NOTHING. `grants.roots: true` with no `roots:` declaration is the
/// `Unsatisfiable` arm — a different answer with a different remedy, naming the exact key.
#[tokio::test]
async fn a_granted_ask_with_no_declaration_refuses_and_names_the_key() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForRoots, ISSUED).await;
    let mut cfg = exchanging_server(&peer, SUBJECT);
    cfg.grants.roots = true;
    // NO `roots:` — the grant admits the ask and there is nothing the operator said to answer with.
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", cfg)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "README" } }),
    )
    .await;

    assert_ne!(
        status, 200,
        "a grant with nothing declared must refuse: {body}"
    );
    assert_eq!(peer.mcp_hits(), 1, "no retry, so nothing was disclosed");
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("tools.fs.roots"),
        "`Unsatisfiable`'s contract is that the message is the remedy — the exact key: {body}"
    );
}

/// THE DECLARATION IS VETTED AT BOOT. A root that is not a `file://` URI, and a declaration on a
/// server whose `grants.roots` is false, are both operator errors answered where the operator is.
#[test]
fn the_roots_policy_is_refused_at_boot_when_it_cannot_mean_what_it_says() {
    let base = || {
        let mut cfg: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(
            "url: https://tools.internal.example/mcp\npin: { mechanism: cert_spki, key: \"sha256/AAA=\" }\n",
        )
        .expect("a minimal registration parses");
        cfg.grants.roots = true;
        cfg
    };

    let mut https_root = base();
    https_root.roots = vec![crate::mcp::config::RootCfg {
        uri: "https://example.com/".to_string(),
        name: None,
    }];
    let err = crate::mcp::config::validate_server("fs", &https_root)
        .expect_err("a non-file root must be refused");
    assert!(err.contains("file://"), "the refusal names the rule: {err}");

    let mut undeclared_grant = base();
    undeclared_grant.grants.roots = false;
    undeclared_grant.roots = vec![crate::mcp::config::RootCfg {
        uri: "file:///workspace".to_string(),
        name: None,
    }];
    let err = crate::mcp::config::validate_server("fs", &undeclared_grant)
        .expect_err("a declaration behind a closed gate is unreachable and must be refused");
    assert!(
        err.contains("grants.roots"),
        "the refusal names the missing grant: {err}"
    );
}
