// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEP-2243 HEADER/BODY MIRROR CHECK, RE-RUN AFTER THE ASK-ANSWER MERGE.
//!
//! Rule 4 of the mirror check refuses a request whose body sets an `x-mcp-header` property but omits
//! the mirrored `Mcp-Param-*` header — an intermediary would route on a parameter it cannot see. The
//! check ran BEFORE `inputResponses` were merged into the arguments, so a property carrying that
//! annotation, supplied through an ask answer rather than the original body, reached the upstream
//! with no mirrored header. This drives that exact path and asserts the upstream — the witness — is
//! never contacted.

use crate::mcp::connect::connect_support::{
    approved_hash, call, gov_with_scopes, mcp_cfg, server_cfg, wire_tool, Peer,
};
use crate::testkit::TestAppMcpExt;
use busbar_core::test_support::TestApp;
use std::sync::Arc;

const TOOL: &str = "lookup";
const NAMESPACED: &str = "geo_lookup";
const DESCRIPTION: &str = "looks up a record in a region";

/// `region` carries the routing annotation: an intermediary routes on `Mcp-Param-region`.
fn schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "record": { "type": "string" },
            "region": { "type": "string", "x-mcp-header": "region" },
        },
    })
}

fn signing_governance() -> Arc<busbar_core::governance::GovState> {
    Arc::new(
        busbar_core::governance::GovState::new_with_signer(
            Arc::new(busbar_core::governance::MemoryStore::new()),
            None,
            Some(
                busbar_core::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_core::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("a governance state with a signer"),
    )
}

/// A registration whose tool ASKS the caller for `region` — the routing-annotated argument — before
/// it runs. `region` is gathered by the ask, not sent in the original body.
fn asking_server(peer: &Peer) -> crate::mcp::config::McpServerDefCfg {
    let mut round = crate::mcp::config::AskRoundCfg::new();
    round.insert(
        "region".to_string(),
        crate::mcp::config::AskEntryCfg {
            method: "elicitation/create".to_string(),
            params: Some(serde_json::json!({
                "message": "which region?",
                "requestedSchema": { "type": "string" },
            })),
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

async fn deployment() -> (
    Peer,
    Arc<busbar_core::state::App>,
    busbar_api::PlaneRequestCtx,
) {
    busbar_core::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("geo", asking_server(&peer))
        .governance(signing_governance())
        .build();
    let gov = gov_with_scopes(&[("mcp_server", "geo"), ("mcp_tool", NAMESPACED)]);
    (peer, app, gov)
}

/// An `x-mcp-header` argument supplied through the ASK ANSWER, with no mirrored header, is refused
/// BEFORE the upstream is contacted — the mirror check is re-run on the merged arguments.
#[tokio::test]
async fn an_ask_supplied_x_mcp_header_argument_with_no_header_is_refused_before_the_upstream() {
    let (peer, app, gov) = deployment().await;

    // First call: the plane asks `region` and issues continuation state. `region` is NOT in the body.
    let (status, body) = call(
        &app,
        &gov,
        "tools/call",
        serde_json::json!({ "name": NAMESPACED, "arguments": { "record": "r1" } }),
    )
    .await;
    assert_eq!(
        status, 200,
        "the operator-configured ask must produce a question, not an error: {body}"
    );
    let state = body
        .pointer("/result/requestState")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("the caller must be issued continuation state: {body}"))
        .to_string();

    // Redemption: answer `region` as a string via `inputResponses`. The harness sends NO
    // `Mcp-Param-region` header. After the merge the body carries `region` with no mirrored header —
    // rule 4 — which the re-check must catch before the upstream is contacted.
    let (status, body) = call(
        &app,
        &gov,
        "tools/call",
        serde_json::json!({
            "name": NAMESPACED,
            "arguments": { "record": "r1" },
            "requestState": state,
            "inputResponses": { "region": "us-east-1" },
        }),
    )
    .await;

    assert_ne!(
        status, 200,
        "an ask-supplied x-mcp-header argument with no mirrored header must be refused: {body}"
    );
    assert_eq!(
        peer.calls(),
        0,
        "the refusal must happen before the upstream is contacted — the unmirrored parameter must \
         never reach it: {:?}",
        peer.call_arguments()
    );
}
