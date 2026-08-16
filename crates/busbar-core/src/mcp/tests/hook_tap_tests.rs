// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ACCEPTANCE TEST FOR "A TAP OBSERVES A NON-LLM PROTOCOL": a global `kind: tap` hook is
//! configured, a real `tools/call` is dispatched at the real method table against a real upstream,
//! and the tap is DELIVERED THE TOOL CALL — the arguments it was going to send upstream.
//!
//! ## The cells, and what would make a green here a lie
//!
//! `hooks-tap x mcp-server` and `hooks-tap x mcp-client` in `qa/capability-equality.json`. Both were
//! `missing`, and their notes said the same thing: *"grep transform under `mcp/`: zero production
//! hits ... the tap half of the hook surface is LLM-only today."*
//!
//! The lie a weaker test would tell is "a tap fired". A tap that fires with an EMPTY projection is
//! worse than a tap that does not fire: an operator's audit trail then contains a row per call and
//! no fact about any of them, and the row is what stops anyone looking. So the assertion here is on
//! the CONTENT — a token that appears nowhere in the deployment except inside the `arguments` of
//! the call under test — and the recorder hands the test the payload rather than a count, precisely
//! so that assertion is possible.
//!
//! ## Why ONE battery covers both MCP cells
//!
//! The same argument the ledger already records for `hooks-gate x mcp-client`: the firing site is
//! the method layer, AFTER the ask answers are merged and BEFORE the upstream leg, so the arguments
//! it projects are the arguments THAT GO UPSTREAM, and there is no ungated production entry to the
//! client leg. A tap here observes the outbound leg's payload and the inbound method's, and a second
//! firing at the leg itself would deliver the same document twice.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::test_support::{RecordingTap, TestApp};

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// A token that exists nowhere in this deployment except inside the tool call's `arguments`. Its
/// arrival at the tap is the whole finding: it can only have come from the projection.
const NEEDLE: &str = "/etc/shadow-tap-needle-4c1f";

/// THE ACCEPTANCE TEST. A global tap holding `prompt: ro` is delivered the `tools/call`, and what
/// it is delivered carries the ARGUMENTS that were about to go upstream.
///
/// The control half is the same deployment with no tap attached: it must serve the identical call,
/// or a delivery here would be evidence about a fixture rather than about a tap.
#[tokio::test]
async fn a_tools_call_reaches_a_global_tap_carrying_its_arguments() {
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": { "path": NEEDLE } });

    // ── THE CONTROL: no tap attached, and the call is served exactly as it always was. ───────────
    let untapped = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let (status, body) = call_as(&untapped, &g, "tap-control", "tools/call", params.clone()).await;
    assert_eq!(
        status, 200,
        "the fixture must serve this call with no tap attached, or a delivery below proves nothing \
         about the tap: {body}"
    );

    // ── THE TEST: the identical deployment, with a global request-stage tap. ─────────────────────
    let (tap, entry) = RecordingTap::entry(true);
    let mut app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    std::sync::Arc::get_mut(&mut app)
        .expect("sole owner of the app under test")
        .tap_hooks = vec![entry];

    let (status, body) = call_as(&app, &g, "tap-observed", "tools/call", params).await;
    assert_eq!(
        status, 200,
        "a tap is fire-and-forget and can never fail the request it observes: {body}"
    );

    let seen = tap.wait_for(1).await;
    let projection = &seen[0];
    assert_eq!(
        projection["op"], "notify",
        "a tap is delivered the NOTIFY op — the write-only verb, not a decide: {projection}"
    );
    assert_eq!(
        projection["request"]["ingress_protocol"], "mcp",
        "the projection must name the plane the request arrived on, as DATA the tap can read: \
         {projection}"
    );
    assert_eq!(
        projection["request"]["pool"], "fs",
        "`pool` is the CONTAINER the request is addressed to — here the registered MCP server: \
         {projection}"
    );
    assert_eq!(
        projection["request"]["has_tools"], true,
        "an invocation IS a tool call; a tap told otherwise is reading a contradiction: \
         {projection}"
    );

    let text = tap.seen_text();
    assert!(
        text.contains(NEEDLE),
        "the tool call's ARGUMENTS must reach the tap. Without them the tap fired with nothing in \
         it, which records a call per row and a fact about none of them. Got: {text}"
    );
    // THE TARGET IS NOT ON THIS WIRE, and that is a RECORDED LIMITATION rather than a defect in the
    // firing site — it is shared, byte for byte, with the gate cell that is already `proven`.
    // `ir::invoke` projects the invocation as ONE content item whose LABEL is the target, but the
    // hook wire's message shape is `{role, text}` and carries no label, so `subject::project` drops
    // it on every plane. Asserting the tool name here would be asserting a wire member that does not
    // exist; the honest assertion is that the tap sees exactly what the gate sees, which is what the
    // shared projection guarantees by construction.
    assert!(
        !text.contains("fs_read"),
        "if the target has started arriving, the wire gained a label member — extend the gate's \
         projection assertions in the same change rather than letting the two seams diverge. \
         Got: {text}"
    );
}

/// THE GRANT HOLDS ON THIS PLANE TOO. A tap without `prompt: ro` (the default) is delivered the
/// SHAPE and never the content — the arguments must not have been built for it, let alone sent.
///
/// This is the half that stops the cell being closed by a firing site that ignores the grant: a tap
/// seam that over-shares on a plane the operator's grant was written for is a disclosure, and it
/// would pass every assertion in the test above.
#[tokio::test]
async fn an_ungranted_tap_is_delivered_the_shape_and_never_the_arguments() {
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let (tap, entry) = RecordingTap::entry(false);
    let mut app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    std::sync::Arc::get_mut(&mut app)
        .expect("sole owner of the app under test")
        .tap_hooks = vec![entry];

    let (status, _) = call_as(
        &app,
        &g,
        "tap-ungranted",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": NEEDLE } }),
    )
    .await;
    assert_eq!(status, 200);

    let seen = tap.wait_for(1).await;
    let projection = &seen[0];
    assert!(
        projection["request"].get("messages").is_none()
            || projection["request"]["messages"].is_null(),
        "a `prompt: no` tap must have NO content projection on its wire at all: {projection}"
    );
    assert!(
        !projection.to_string().contains(NEEDLE),
        "the arguments must not appear ANYWHERE in an ungranted tap's payload: {projection}"
    );
    assert_eq!(
        projection["request"]["has_tools"], true,
        "the SHAPE is still delivered — that is what an ungranted tap is for: {projection}"
    );
}
