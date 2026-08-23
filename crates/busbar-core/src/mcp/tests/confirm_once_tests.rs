// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN APPROVAL IS SPENT ONCE, AND IT PAYS FOR THE CALL IT WAS SHOWN ABOUT.
//!
//! ## Why this file exists beside fourteen tests that look like it
//!
//! `askstate_tests.rs` and `callerask_tests.rs` prove, between them, that continuation state cannot
//! be forged, cannot be redeemed by a different caller, cannot be spent on a different method, a
//! different capability or a different argument set, cannot outlive its expiry, cannot survive an
//! approval moving underneath it, and cannot be replayed from an earlier round to buy extra rounds.
//!
//! **None of them proves the same valid state, at the same round, cannot be redeemed TWICE.** That
//! is not a gap of the same size as the others. Every property above is about a caller presenting
//! state it should not have; this one is about a caller presenting state it legitimately holds, a
//! second time. On a tool an operator gated because it moves money, an approval that can be redeemed
//! N times is confirm-once-execute-many — which is the exact thing the gate exists to stop, so a
//! gate without it is decoration.
//!
//! ## And the second half, which is the same defect in a different hat
//!
//! A confirmation that approves one payload and carries out another is not a lesser bug than one
//! that approves nothing at all. The argument binding is proven at the seal layer — `AskState`
//! carries a digest and `matches` compares it — but nothing proved END TO END that the arguments
//! DISPATCHED after an approval are the arguments the question was DISPLAYED about. That claim
//! spans the mint, the caller's answer, the verification and the outbound call, and it can only be
//! settled by asking the upstream what it was actually told to do.
//!
//! ## Everything here is judged from outside
//!
//! No case reaches into the seal, names a refusal variant, or counts anything busbar holds. A case
//! either sees the upstream contacted or it does not, and the upstream's own bookkeeping is the
//! witness — because the accused cannot be the witness, and because these assertions have to
//! survive the rebuild that is coming for this tree.

use crate::mcp::connect::connect_support::{
    approved_hash, call, gov_with_scopes, mcp_cfg, server_cfg, wire_tool, Peer,
};
use crate::test_support::TestApp;
use std::sync::Arc;

const TOOL: &str = "transfer";
const NAMESPACED: &str = "bank_transfer";
const DESCRIPTION: &str = "moves money between accounts";

fn schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "to": { "type": "string" }, "amount": { "type": "integer" } },
    })
}

/// The payload the operator's question is asked ABOUT.
fn honest_arguments() -> serde_json::Value {
    serde_json::json!({ "to": "alice", "amount": 10 })
}

/// The payload an attacker would rather have carried out.
fn swapped_arguments() -> serde_json::Value {
    serde_json::json!({ "to": "mallory", "amount": 1_000_000 })
}

/// A deployment that can seal state.
///
/// A signing key is not optional scaffolding here: with none, the plane refuses to ask at all
/// rather than issue state it could not later verify, so a fixture without one would exercise the
/// refusal instead of the gate.
fn signing_governance() -> Arc<crate::governance::GovState> {
    Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[9u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("a governance state with a signer"),
    )
}

/// One registration whose only tool requires ONE round of operator-configured confirmation before
/// it runs.
fn confirming_server(peer: &Peer) -> crate::mcp::config::McpServerDefCfg {
    let mut round = crate::mcp::config::AskRoundCfg::new();
    round.insert(
        "confirm".to_string(),
        crate::mcp::config::AskEntryCfg {
            method: "elicitation/create".to_string(),
            params: Some(serde_json::json!({
                "message": "Approve moving 10 to alice?",
                "requestedSchema": { "type": "object", "properties": { "ok": { "type": "boolean" } } },
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

/// The deployment under test, plus the peer that is the witness.
async fn deployment() -> (
    Peer,
    Arc<crate::state::App>,
    crate::governance::PlaneRequestCtx,
) {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool(TOOL, DESCRIPTION, schema())]).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("bank", confirming_server(&peer))
        .governance(signing_governance())
        .build();
    let gov = gov_with_scopes(&[("mcp_server", "bank"), ("mcp_tool", NAMESPACED)]);
    (peer, app, gov)
}

/// Ask the operator's question, and hand back the continuation state the caller was issued.
async fn obtain_approval(
    app: &Arc<crate::state::App>,
    gov: &crate::governance::PlaneRequestCtx,
    arguments: &serde_json::Value,
) -> (String, serde_json::Value) {
    let (status, body) = call(
        app,
        gov,
        "tools/call",
        serde_json::json!({ "name": NAMESPACED, "arguments": arguments }),
    )
    .await;
    assert_eq!(
        status, 200,
        "an operator-configured confirmation must produce a question, not an error: {body}"
    );
    let state = body
        .pointer("/result/requestState")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("the caller must be issued continuation state with the question: {body}")
        })
        .to_string();
    (state, body)
}

/// The caller's answer to the question, replayed verbatim as often as a test likes.
fn redemption(arguments: &serde_json::Value, state: &str) -> serde_json::Value {
    serde_json::json!({
        "name": NAMESPACED,
        "arguments": arguments,
        "requestState": state,
        "inputResponses": { "confirm": { "action": "accept", "content": { "ok": true } } },
    })
}

// ── AN APPROVAL IS SPENT ONCE ──────────────────────────────────────────────────────────────────

/// ONE approval, redeemed TWICE, byte for byte. The tool runs ONCE.
///
/// The control is in the same case and is load-bearing: the FIRST redemption must reach the
/// upstream. A plane that refused both would satisfy the second assertion and have deleted the
/// feature.
#[tokio::test]
async fn an_approval_is_redeemable_exactly_once() {
    let (peer, app, gov) = deployment().await;
    let args = honest_arguments();
    let (state, _) = obtain_approval(&app, &gov, &args).await;
    assert_eq!(
        peer.calls(),
        0,
        "asking the question must not itself run the tool"
    );

    let (first_status, first) = call(&app, &gov, "tools/call", redemption(&args, &state)).await;
    assert_eq!(
        first_status, 200,
        "the caller answered the operator's question, so the call must be carried out: {first}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "the approved call must actually reach the upstream, or this case proves nothing"
    );

    // THE SAME ANSWER, THE SAME STATE, A SECOND TIME.
    let (second_status, second) = call(&app, &gov, "tools/call", redemption(&args, &state)).await;
    assert_eq!(
        peer.calls(),
        1,
        "one approval carried out the tool {} times — an approval a caller can present again is \
         confirm-once, execute-many, and on a tool an operator gated because it moves money that \
         is the whole of the defect: {second}",
        peer.calls()
    );
    assert_ne!(
        second_status, 200,
        "a spent approval must be refused, not honoured again: {second}"
    );
    assert!(
        second.pointer("/result/content").is_none(),
        "a spent approval must not answer a tool RESULT: {second}"
    );
}

/// A spent approval is refused the SAME WAY every other bad state is, and says no more.
///
/// The refusal of continuation state is deliberately one message for every cause, because telling a
/// caller which check its state failed is an oracle. A newly added cause that announced itself
/// would reopen that by itself — so this asserts the new refusal is indistinguishable, on the wire,
/// from the refusal of a state that was simply tampered with.
#[tokio::test]
async fn a_spent_approval_refuses_with_the_same_message_a_forged_one_does() {
    let (_peer, app, gov) = deployment().await;
    let args = honest_arguments();
    let (state, _) = obtain_approval(&app, &gov, &args).await;
    let (_, _) = call(&app, &gov, "tools/call", redemption(&args, &state)).await;

    let (_, spent) = call(&app, &gov, "tools/call", redemption(&args, &state)).await;
    let (_, forged) = call(
        &app,
        &gov,
        "tools/call",
        redemption(&args, &format!("{state}-TAMPERED")),
    )
    .await;
    assert_eq!(
        spent["error"]["message"], forged["error"]["message"],
        "a spent approval that announces itself is an oracle: a caller learns that its state WAS \
         valid, which no other refusal tells it. spent={spent} forged={forged}"
    );
}

/// A second, INDEPENDENT approval of the same call still works after the first was spent.
///
/// Without this, "redeemable once" could be satisfied by a plane that permanently blacklisted the
/// request rather than the approval — which would break the ordinary case of a caller who runs the
/// same gated tool twice, with two confirmations, as designed.
#[tokio::test]
async fn spending_one_approval_does_not_block_the_next() {
    let (peer, app, gov) = deployment().await;
    let args = honest_arguments();

    let (first, _) = obtain_approval(&app, &gov, &args).await;
    call(&app, &gov, "tools/call", redemption(&args, &first)).await;
    let (second, _) = obtain_approval(&app, &gov, &args).await;
    assert_ne!(
        first, second,
        "two approvals of one call must be two different values"
    );
    let (status, body) = call(&app, &gov, "tools/call", redemption(&args, &second)).await;

    assert_eq!(
        status, 200,
        "a fresh approval of the same call must still be honoured: {body}"
    );
    assert_eq!(
        peer.calls(),
        2,
        "two approvals, two calls — spending one must not blacklist the request itself"
    );
}

// ── THE CALL CARRIED OUT IS THE CALL THE QUESTION WAS ABOUT ────────────────────────────────────

/// Every field the question was DISPLAYED about reaches the upstream UNCHANGED, and the only thing
/// added is what the operator's own question asked for.
///
/// The second half is deliberate rather than a loosening: an ask keyed `confirm` binds the caller's
/// answer to the tool argument of that name, which is what an operator writing the ask means by it.
/// What must not happen is anything ELSE arriving — the approved payload is what the caller agreed
/// to, and a field it never saw is a field it never approved.
#[tokio::test]
async fn the_call_dispatched_after_an_approval_is_the_call_that_was_described() {
    let (peer, app, gov) = deployment().await;
    let args = honest_arguments();
    let (state, asked) = obtain_approval(&app, &gov, &args).await;
    // The question really was put — otherwise this is a test of an ungated tool.
    assert!(
        asked.pointer("/result/inputRequests").is_some()
            || asked.pointer("/result/resultType").is_some(),
        "the operator's question must have been put to the caller: {asked}"
    );

    call(&app, &gov, "tools/call", redemption(&args, &state)).await;
    let dispatched = peer.call_arguments();
    assert_eq!(
        dispatched.len(),
        1,
        "one approval, one call: {dispatched:?}"
    );
    let dispatched = dispatched[0].as_object().expect("an arguments object");
    for (field, approved) in args.as_object().expect("an arguments object") {
        assert_eq!(
            dispatched.get(field),
            Some(approved),
            "`{field}` reached the upstream as something other than what the caller was asked \
             to approve: {dispatched:?}"
        );
    }
    let unasked: Vec<&String> = dispatched
        .keys()
        .filter(|k| !args.get(*k).is_some() && k.as_str() != "confirm")
        .collect();
    assert!(
        unasked.is_empty(),
        "the upstream was told about {unasked:?}, which is neither part of the payload the caller \
         approved nor an answer the operator's question asked for"
    );
}

/// An answer that names an ARGUMENT THE QUESTION WAS SHOWN FOR does not rewrite it, and the call is
/// refused outright rather than carried out under the caller's substitution.
///
/// This is the sharpest form of the property, and it is reachable: the seal covers `arguments`, so a
/// value smuggled in through the sibling `inputResponses` field passes every integrity check and
/// then overwrites the approved one on the way out. A caller shown "approve moving 10 to alice?"
/// answers `{"amount": 1000000}` and the upstream is told to move a million. Nothing about that is
/// distinguishable, from the operator's side, from a confirmation that was never required.
#[tokio::test]
async fn an_answer_cannot_rewrite_an_argument_the_question_was_shown_for() {
    let (peer, app, gov) = deployment().await;
    let args = honest_arguments();
    let (state, _) = obtain_approval(&app, &gov, &args).await;

    let (status, body) = call(
        &app,
        &gov,
        "tools/call",
        serde_json::json!({
            "name": NAMESPACED,
            "arguments": args,
            "requestState": state,
            // A well-formed answer to the question that was asked, carrying one extra key that
            // names the approved payload's own field.
            "inputResponses": {
                "confirm": { "action": "accept", "content": { "ok": true } },
                "amount": 1_000_000,
            },
        }),
    )
    .await;

    assert_ne!(
        status, 200,
        "an answer that rewrites the approved payload must refuse the call: {body}"
    );
    assert_eq!(
        peer.calls(),
        0,
        "the rewritten call reached the upstream — the refusal, if any, happened after the money \
         moved: {:?}",
        peer.call_arguments()
    );
}

/// An approval is redeemed with DIFFERENT arguments. The upstream is never contacted at all.
///
/// Asserted at the wire rather than at the status code: a refusal that still reached the upstream
/// would be a tool that ran and was then disowned, and no HTTP status can tell those apart.
#[tokio::test]
async fn an_approval_cannot_be_spent_on_arguments_it_was_never_shown() {
    let (peer, app, gov) = deployment().await;
    let (state, _) = obtain_approval(&app, &gov, &honest_arguments()).await;

    let (status, body) = call(
        &app,
        &gov,
        "tools/call",
        redemption(&swapped_arguments(), &state),
    )
    .await;
    assert_ne!(
        status, 200,
        "an approval displayed for one payload must not carry out another: {body}"
    );
    assert_eq!(
        peer.call_arguments(),
        Vec::<serde_json::Value>::new(),
        "the swapped payload reached the upstream — the refusal happened after the money moved"
    );
}

/// The approval is still spendable on the call it WAS shown about, after a swap was refused.
///
/// The refused attempt must not consume the caller's approval either: a plane where an attacker can
/// burn a legitimate caller's confirmation by presenting it with different arguments has traded one
/// defect for another.
#[tokio::test]
async fn a_refused_argument_swap_does_not_consume_the_approval() {
    let (peer, app, gov) = deployment().await;
    let args = honest_arguments();
    let (state, _) = obtain_approval(&app, &gov, &args).await;

    call(
        &app,
        &gov,
        "tools/call",
        redemption(&swapped_arguments(), &state),
    )
    .await;
    let (status, body) = call(&app, &gov, "tools/call", redemption(&args, &state)).await;

    assert_eq!(
        status, 200,
        "a refused swap must not burn the approval the caller legitimately holds: {body}"
    );
    assert_eq!(
        peer.calls(),
        1,
        "exactly the approved call ran, and it ran once: {body}"
    );
    assert_eq!(
        peer.call_arguments()[0]["amount"],
        args["amount"],
        "and it ran with the payload the question was shown for: {body}"
    );
}
