// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `notifications/roots/list_changed`, RECEIVED — the coverage instrument for
//! `mcp|streamable-http|server|client|notifications/roots/list_changed`.
//!
//! The claim under test is the one the module header of `crate::mcp::roots` makes: the ONE
//! roots-derived fact busbar holds on a caller's behalf is the life of a sealed roots-bearing
//! `requestState`, and the notification is what ends it. So the battery is built around a real
//! operator-configured `roots/list` ask, a real sealed state, and the caller's own announcement —
//! and every case is judged from outside: what the caller is answered, and whether the upstream's
//! own call counter moved.
//!
//! What is deliberately NOT here: any assertion that busbar "re-requests roots". There is no
//! standing roots list to re-request — busbar asks on the request that needs them — and a test
//! asserting a fabricated cache would be pinning behaviour the design refuses to have.

use crate::mcp::connect::connect_support::{
    approved_hash, call, gov_with_key, gov_with_scopes, mcp_cfg, server_cfg, wire_tool, Peer,
};
use crate::test_support::TestApp;
use std::sync::Arc;

const TOOL: &str = "probe";
const NAMESPACED: &str = "ws_probe";
const DESCRIPTION: &str = "probes the workspace";

fn schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "path": { "type": "string" } },
    })
}

fn arguments() -> serde_json::Value {
    serde_json::json!({ "path": "src" })
}

/// A deployment that can seal state — without a signing key the plane refuses to ask at all, so an
/// unsigned fixture would exercise the `NoSealer` refusal instead of the epoch.
fn signing_governance() -> Arc<crate::governance::GovState> {
    Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("a governance state with a signer"),
    )
}

/// One registration whose only tool asks the caller for its roots before it runs — or, when
/// `ask_method` says so, for something that is not roots, which is the negative control's fixture.
fn asking_server(peer: &Peer, ask_method: &str) -> crate::mcp::config::McpServerDefCfg {
    let mut round = crate::mcp::config::AskRoundCfg::new();
    round.insert(
        "workspace".to_string(),
        crate::mcp::config::AskEntryCfg {
            method: ask_method.to_string(),
            params: Some(if ask_method == "roots/list" {
                serde_json::json!({})
            } else {
                serde_json::json!({
                    "message": "Proceed?",
                    "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
                })
            }),
        },
    );
    let mut cfg = server_cfg(
        peer,
        &[(TOOL, Some(approved_hash(TOOL, DESCRIPTION, schema())))],
    );
    let entry = cfg
        .tools_allow
        .get_mut(TOOL)
        .expect("the registration we just built declares the tool");
    entry.description = Some(DESCRIPTION.to_string());
    entry.input_schema = Some(schema());
    entry.ask_caller = vec![round];
    cfg
}

async fn deployment(ask_method: &str) -> (Peer, Arc<crate::state::App>, crate::governance::GovCtx) {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("ws", asking_server(&peer, ask_method))
        .governance(signing_governance())
        .build();
    let gov = gov_with_scopes(&[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);
    (peer, app, gov)
}

/// Ask the operator's question and hand back the sealed continuation state.
async fn obtain_state(app: &Arc<crate::state::App>, gov: &crate::governance::GovCtx) -> String {
    let (status, body) = call(
        app,
        gov,
        "tools/call",
        serde_json::json!({ "name": NAMESPACED, "arguments": arguments() }),
    )
    .await;
    assert_eq!(
        status, 200,
        "the configured ask must be a question, not an error: {body}"
    );
    body.pointer("/result/requestState")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("the caller must be issued continuation state: {body}"))
        .to_string()
}

/// The caller's answer, addressed to the operator's `workspace` entry.
fn redemption(state: &str) -> serde_json::Value {
    serde_json::json!({
        "name": NAMESPACED,
        "arguments": arguments(),
        "requestState": state,
        "inputResponses": {
            "workspace": { "roots": [{ "uri": "file:///home/user/project" }] },
        },
    })
}

/// SEND the notification through the REAL ingress — `envelope::rpc`, the same function the router
/// mounts — as the principal `gov` authenticates. The bump is asserted only through its observable
/// consequences in the cases below; here the assertion is the transport's own contract: `202`,
/// empty body, even for a plane fact the notification moved.
async fn announce_roots_changed(app: &Arc<crate::state::App>, gov: &crate::governance::GovCtx) {
    let handle = Arc::new(crate::state::AppHandle::new(app.clone()));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/roots/list_changed",
    });
    let response = crate::mcp::envelope::rpc(
        axum::extract::State(handle),
        axum::extract::Extension(gov.clone()),
        axum::extract::Extension(crate::auth::AuthPrincipal(None)),
        axum::http::HeaderMap::new(),
        axum::body::Bytes::from(serde_json::to_vec(&body).expect("the notification serialises")),
    )
    .await;
    assert_eq!(
        response.status().as_u16(),
        202,
        "JSON-RPC 2.0 section 4.1: a notification is answered 202 and MUST NOT be replied to"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the 202 body reads");
    assert!(
        bytes.is_empty(),
        "the 202 carries NO body — acting on a notification is permitted, answering is not"
    );
}

/// THE CELL'S CENTRAL CLAIM. State sealed over a roots answer, presented after the caller's own
/// `notifications/roots/list_changed`, is refused — and the refusal is recoverable: restarting the
/// exchange asks again, and the fresh answer dispatches.
#[tokio::test]
async fn roots_state_minted_before_a_roots_change_is_refused_after_it() {
    let (peer, app, gov) = deployment("roots/list").await;
    let state = obtain_state(&app, &gov).await;
    assert_eq!(peer.calls(), 0, "asking must not itself run the tool");

    announce_roots_changed(&app, &gov).await;

    let (status, body) = call(&app, &gov, "tools/call", redemption(&state)).await;
    assert_ne!(
        status, 200,
        "a roots answer the caller itself disavowed must not be redeemed: {body}"
    );
    assert_eq!(
        peer.calls(),
        0,
        "the refused redemption must never reach the upstream: {body}"
    );
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("notifications/roots/list_changed"),
        "the refusal must name the caller's own announcement — it is the one state refusal whose \
         reader is provably the legitimate holder, and the remedy is different: {body}"
    );

    // RECOVERY: the exchange restarts, asks again, and the caller's CURRENT roots dispatch.
    let fresh = obtain_state(&app, &gov).await;
    assert_ne!(fresh, state, "the fresh exchange must mint fresh state");
    let (status, body) = call(&app, &gov, "tools/call", redemption(&fresh)).await;
    assert_eq!(
        status, 200,
        "an answer given AFTER the change is current and must dispatch: {body}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "the recovered exchange reaches the upstream once"
    );
}

/// THE SCOPE OF THE BUMP IS THE PRINCIPAL WHO ANNOUNCED IT. Caller B's roots changing says nothing
/// about caller A's, and a bump that crossed principals would be a lever any tenant could pull on
/// every other tenant's in-flight confirmations.
#[tokio::test]
async fn one_principals_roots_change_does_not_invalidate_anothers_state() {
    let (peer, app, _) = deployment("roots/list").await;
    let alice = gov_with_key("k-alice", &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);
    let bob = gov_with_key("k-bob", &[("mcp_server", "ws"), ("mcp_tool", NAMESPACED)]);

    let state = obtain_state(&app, &alice).await;
    announce_roots_changed(&app, &bob).await;

    let (status, body) = call(&app, &alice, "tools/call", redemption(&state)).await;
    assert_eq!(
        status, 200,
        "another principal's announcement must not invalidate this caller's state: {body}"
    );
    assert_eq!(peer.calls(), 1);
}

/// THE SCOPE OF THE BUMP IS ROOTS-BEARING STATE. An exchange that never asked for roots seals no
/// epoch, so the caller's announcement leaves its unrelated confirmations standing — a chatty
/// client must not be able to void its own elicitation gate by narrating its filesystem.
#[tokio::test]
async fn a_roots_change_leaves_an_exchange_without_a_roots_ask_standing() {
    let (peer, app, gov) = deployment("elicitation/create").await;
    let state = obtain_state(&app, &gov).await;

    announce_roots_changed(&app, &gov).await;

    let (status, body) = call(&app, &gov, "tools/call", redemption(&state)).await;
    assert_eq!(
        status, 200,
        "state for an exchange with no roots ask carries no epoch and must survive the \
         announcement: {body}"
    );
    assert_eq!(peer.calls(), 1);
}

/// The notification is judged by the shared envelope reader, so a MALFORMED one — an `id` member
/// would make it a request — takes the request path and cannot reach the observer. What is
/// asserted here is the half that matters for the epoch: a `notifications/roots/list_changed`
/// spelled as a REQUEST does not bump, because a request obliges an answer and `-32601` is it.
#[tokio::test]
async fn the_same_name_with_an_id_is_a_request_and_moves_nothing() {
    let (_peer, app, gov) = deployment("roots/list").await;
    let state = obtain_state(&app, &gov).await;

    let handle = Arc::new(crate::state::AppHandle::new(app.clone()));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "notifications/roots/list_changed",
    });
    let response = crate::mcp::envelope::rpc(
        axum::extract::State(handle),
        axum::extract::Extension(gov.clone()),
        axum::extract::Extension(crate::auth::AuthPrincipal(None)),
        axum::http::HeaderMap::new(),
        axum::body::Bytes::from(serde_json::to_vec(&body).expect("serialises")),
    )
    .await;
    assert_ne!(
        response.status().as_u16(),
        202,
        "a message with an `id` is a REQUEST, and a request is answered, not observed"
    );

    let (status, body) = call(&app, &gov, "tools/call", redemption(&state)).await;
    assert_eq!(
        status, 200,
        "the malformed spelling must not have bumped the epoch: {body}"
    );
}
