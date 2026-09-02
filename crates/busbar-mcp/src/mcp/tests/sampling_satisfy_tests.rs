// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `sampling/createMessage`, SATISFIED — the coverage instrument for
//! `mcp|streamable-http|client|server|sampling/createMessage`.
//!
//! The cell was queued on the sentence "blocked on a per-upstream sampling budget an operator can
//! cap", and this battery is that budget working end to end beside the satisfier it unblocked: an
//! upstream returns an `InputRequiredResult` naming `sampling/createMessage`, the per-round grant
//! gate admits it, ONE governed completion runs on the OPERATOR'S declared model — read off the
//! fake provider's own transcript, because what busbar spent is a claim about bytes a provider
//! received — and the retry carries the completion under the upstream's own `requestState`.
//!
//! What stays true from the refusal era, asserted rather than assumed:
//!
//! - the ask TERMINATES at busbar in every arm — the caller is answered a result or a
//!   busbar-attributed refusal, never handed the upstream's ask;
//! - deny-by-default did not move — no grant, no completion, and the refusal names the grant;
//! - the grant without a policy spends NOTHING — `Unsatisfiable`, naming `tools.<server>.sampling`,
//!   because a grant is an operator admitting the ask and the policy is the operator saying what
//!   may answer it, and neither implies the other;
//! - the completion rides the ONE governed pathway: it is admitted under the INBOUND caller's own
//!   key, so a caller whose key does not reach the declared pool cannot be spent through, whatever
//!   the upstream asked.

use super::upstream_support::{call, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer};
use crate::testkit::TestAppMcpExt;
use axum::http::StatusCode;
use busbar_core::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
use std::sync::Arc;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";
/// The model the OPERATOR declares. The completion must run here and nowhere the upstream names.
const MODEL: &str = "sampler-model";

/// The operator's policy: where a granted sampling ask runs, and both ceilings.
fn declared_sampling(per_minute: u32) -> crate::mcp::config::SamplingCfg {
    crate::mcp::config::SamplingCfg {
        model: MODEL.to_string(),
        max_tokens: 64,
        max_requests_per_minute: per_minute,
    }
}

/// The registration with the ask ADMITTED (`grants.sampling`) and the answer DECLARED
/// (`sampling:`).
fn sampling_server(peer: &Peer, per_minute: u32) -> crate::mcp::config::McpServerDefCfg {
    let mut cfg = exchanging_server(peer, SUBJECT);
    cfg.grants.sampling = true;
    cfg.sampling = Some(declared_sampling(per_minute));
    cfg
}

/// One OpenAI-dialect completion the fake provider serves, with a DIFFERENT model string than the
/// operator declared, so the test can tell "relayed from the provider" apart from "copied from
/// config".
fn provider_completion() -> serde_json::Value {
    serde_json::json!({
        "id": "cmpl-1",
        "object": "chat.completion",
        "model": "sampler-model-v2",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": "One-line summary." },
            "finish_reason": "stop",
        }],
        "usage": { "prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17 },
    })
}

/// A fake provider plus a `TestApp` whose catalogue can dispatch to it under [`MODEL`].
async fn app_with_provider(
    peer: &Peer,
    per_minute: u32,
    completions: usize,
) -> (
    Arc<MockServerState>,
    MockServer,
    Arc<busbar_core::state::App>,
) {
    let state = Arc::new(MockServerState::new());
    for _ in 0..completions {
        state.push(MockResponse::Ok {
            status: StatusCode::OK,
            body: provider_completion(),
        });
    }
    let provider = MockServer::new(state.clone()).await;
    // The sampling completion runs a REAL upstream chat on the operator's `openai` lane, so the LLM
    // dialect declarations AND the LLM plane must be registered the way the composition root registers
    // them: the protocol decls give the openai codec, and the fallback PLANE_DECL is what makes the LLM
    // the process fallback plane — so `TestApp::build` seeds the data-plane runtime slot the money path
    // reads `lanes`/`by_model` through (R3/R4 sub-phase B moved those off the flat `App.llm_runtime`
    // field into that slot, populated only when a fallback LLM plane is registered).
    busbar_substrate::proto::register_test_protocols(busbar_llm::DECLS);
    busbar_substrate::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);
    let app = TestApp::new()
        .lane(LaneSpec::new(
            MODEL,
            busbar_core::proto::PROTO_OPENAI,
            &provider.base_url(),
        ))
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", sampling_server(peer, per_minute))
        .build();
    (state, provider, app)
}

/// The caller's grant, INCLUDING the pool: the completion is admitted as the caller, so the
/// caller's key must reach the declared model exactly as if it had asked for the completion
/// itself.
fn gov_with_pool() -> busbar_api::PlaneRequestCtx {
    gov_with_scopes(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("pool", MODEL),
    ])
}

/// THE CELL. A granted, declared `sampling/createMessage` ask is satisfied: one completion runs on
/// the operator's model within the operator's ceilings, the retry carries it under the upstream's
/// own `requestState`, the exchange completes, and the caller sees the final result and nothing of
/// the ask.
#[tokio::test]
async fn a_granted_sampling_ask_is_completed_on_the_operators_model_and_answered() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSampling, ISSUED).await;
    let (state, _provider, app) = app_with_provider(&peer, 5, 1).await;
    let g = gov_with_pool();

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
        "SAMPLING RECEIVED",
        "the caller is handed the upstream's FINAL result: {body}"
    );
    // The ask terminated at busbar: nothing of it reaches the caller.
    assert!(
        body.pointer("/result/inputRequests").is_none()
            && body.pointer("/result/requestState").is_none(),
        "an upstream's ask must never surface in the caller's result: {body}"
    );

    // WHAT BUSBAR SPENT, read off the provider's own transcript. The model is the OPERATOR'S
    // declaration; the ask's `maxTokens: 4096` was clamped to the declared ceiling; and both the
    // system prompt and the message the upstream asked about actually reached the model.
    let spent: serde_json::Value = serde_json::from_slice(
        &state
            .get_last_request_body()
            .expect("the provider was reached"),
    )
    .expect("the provider received JSON");
    assert_eq!(
        spent.get("model").and_then(|m| m.as_str()),
        Some(MODEL),
        "the completion runs on the operator's declared model, never one the upstream named: \
         {spent}"
    );
    assert_eq!(
        spent.get("max_tokens").and_then(|m| m.as_u64()),
        Some(64),
        "the ask's maxTokens is clamped to the operator's ceiling: {spent}"
    );
    assert_eq!(
        spent.pointer("/messages/0/role").and_then(|r| r.as_str()),
        Some("system"),
        "the ask's systemPrompt leads the conversation: {spent}"
    );
    assert_eq!(
        spent
            .pointer("/messages/1/content")
            .and_then(|c| c.as_str()),
        Some("Draft a one-line summary of the diff."),
        "the ask's message is what the model was asked: {spent}"
    );

    // TWO round trips to the peer: the ask, then the answered retry carrying the completion in
    // MRTR's own continuation members.
    assert_eq!(peer.mcp_hits(), 2, "one ask, one satisfied retry");
    let retry = peer.last_mcp().json();
    assert_eq!(
        retry.pointer("/params/inputResponses/draft"),
        Some(&serde_json::json!({
            "role": "assistant",
            "content": { "type": "text", "text": "One-line summary." },
            "model": "sampler-model-v2",
            "stopReason": "endTurn",
        })),
        "the answer is the protocol's CreateMessageResult, relaying what the provider actually \
         said — text, model and stop reason: {retry}"
    );
    assert_eq!(
        retry.pointer("/params/requestState"),
        Some(&serde_json::json!("upstream-opaque-state-blob")),
        "the upstream's opaque state is echoed exactly: {retry}"
    );
    // And the retry still carries the same arguments and tool: it is the SAME logical call.
    assert_eq!(retry.pointer("/params/name").unwrap(), "read");
    assert_eq!(retry.pointer("/params/arguments/path").unwrap(), "README");

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
        first.pointer("/params/_meta/io.modelcontextprotocol~1clientCapabilities/sampling"),
        Some(&serde_json::json!({})),
        "a deployment that will answer `sampling/createMessage` for this server declares the \
         capability on every request to it: {first}"
    );
}

/// THE PER-UPSTREAM BUDGET. A two-entry ask against a budget of one: the first entry's completion
/// runs, the second is refused naming the budget key, the whole dispatch fails busbar-attributed —
/// and the provider was reached EXACTLY once, because the budget is spent before the model leg.
#[tokio::test]
async fn the_per_upstream_budget_refuses_the_completion_past_the_cap_before_it_runs() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSamplingPair, ISSUED).await;
    let (state, _provider, app) = app_with_provider(&peer, 1, 2).await;
    let g = gov_with_pool();

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_ne!(status, 200, "the exhausted budget must refuse: {body}");
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("tools.fs.sampling.max_requests_per_minute"),
        "the refusal names the exact budget key an operator would raise: {body}"
    );
    assert!(
        message.contains("terminates at busbar") || body.pointer("/error/data/reason").is_some(),
        "the refusal is busbar-attributed: {body}"
    );
    // The provider's LAST transcript entry is the witness for "exactly one completion ran": the
    // entries are answered in order (`draft`, then `title`), so if the cap had failed to bite the
    // last body the provider saw would be `title`'s prompt, and if the charge ran after the model
    // leg the provider would have a body at all for the refused entry.
    let spent: serde_json::Value =
        serde_json::from_slice(&state.get_last_request_body().expect("the first entry ran"))
            .expect("the provider received JSON");
    assert_eq!(
        spent
            .pointer("/messages/0/content")
            .and_then(|c| c.as_str()),
        Some("Draft it."),
        "the completion past the cap must never reach a provider: charge precedes the model leg; \
         the provider's last transcript entry was {spent}"
    );
    assert_eq!(
        peer.mcp_hits(),
        1,
        "the refused ask produces no retry — nothing was disclosed to the upstream"
    );
}

/// DENY-BY-DEFAULT DID NOT MOVE. No `grants.sampling`, no completion, and the refusal names the
/// grant — the `Ungranted` arm, whose remedy is a config key. The provider is never reached.
#[tokio::test]
async fn an_ungranted_sampling_ask_is_still_refused_and_spends_nothing() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSampling, ISSUED).await;
    let state = Arc::new(MockServerState::new());
    let provider = MockServer::new(state.clone()).await;
    // The stock registration: all grants false, nothing declared — but the pool EXISTS, so a
    // breach would have somewhere to land.
    // The sampling completion runs a REAL upstream chat on the operator's `openai` lane, so the LLM
    // dialect declarations AND the LLM plane must be registered the way the composition root registers
    // them: the protocol decls give the openai codec, and the fallback PLANE_DECL is what makes the LLM
    // the process fallback plane — so `TestApp::build` seeds the data-plane runtime slot the money path
    // reads `lanes`/`by_model` through (R3/R4 sub-phase B moved those off the flat `App.llm_runtime`
    // field into that slot, populated only when a fallback LLM plane is registered).
    busbar_substrate::proto::register_test_protocols(busbar_llm::DECLS);
    busbar_substrate::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);
    let app = TestApp::new()
        .lane(LaneSpec::new(
            MODEL,
            busbar_core::proto::PROTO_OPENAI,
            &provider.base_url(),
        ))
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_pool();

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_ne!(status, 200, "an ungranted ask must refuse the call: {body}");
    assert_eq!(
        body.pointer("/error/data/reason").unwrap(),
        "ask_ungranted",
        "deny-by-default, with its own reason word: {body}"
    );
    assert!(
        state.get_last_request_body().is_none(),
        "no grant, no completion: the provider must never have been reached"
    );
    // And with nothing granted and nothing declared, the capability was never advertised.
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

/// THE GRANT ALONE SPENDS NOTHING. `grants.sampling: true` with no `sampling:` policy is the
/// `Unsatisfiable` arm — a different answer with a different remedy, naming the exact key.
#[tokio::test]
async fn a_granted_ask_with_no_policy_refuses_and_names_the_key() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSampling, ISSUED).await;
    let mut cfg = exchanging_server(&peer, SUBJECT);
    cfg.grants.sampling = true;
    // NO `sampling:` — the grant admits the ask and there is nothing the operator said to answer
    // with.
    // The sampling completion runs a REAL upstream chat on the operator's `openai` lane, so the LLM
    // dialect declarations AND the LLM plane must be registered the way the composition root registers
    // them: the protocol decls give the openai codec, and the fallback PLANE_DECL is what makes the LLM
    // the process fallback plane — so `TestApp::build` seeds the data-plane runtime slot the money path
    // reads `lanes`/`by_model` through (R3/R4 sub-phase B moved those off the flat `App.llm_runtime`
    // field into that slot, populated only when a fallback LLM plane is registered).
    busbar_substrate::proto::register_test_protocols(busbar_llm::DECLS);
    busbar_substrate::plane::registry::register_test_plane(&busbar_llm::PLANE_DECL);
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", cfg)
        .build();
    let g = gov_with_pool();

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_ne!(status, 200, "a grant with no policy must refuse: {body}");
    assert_eq!(peer.mcp_hits(), 1, "no retry, so nothing was spent");
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("tools.fs.sampling"),
        "`Unsatisfiable`'s contract is that the message is the remedy — the exact key: {body}"
    );
}

/// THE ONE PATHWAY, proven at its gate: the completion is admitted under the INBOUND caller's own
/// key, so a caller whose key does not reach the declared pool is refused — by busbar's own
/// pipeline, before any provider is touched — however enthusiastically the upstream asked.
#[tokio::test]
async fn a_caller_whose_key_does_not_reach_the_pool_cannot_be_spent_through() {
    busbar_core::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSampling, ISSUED).await;
    let (state, _provider, app) = app_with_provider(&peer, 5, 1).await;
    // The caller may reach the tool — and holds NO pool grant, so the completion the upstream
    // wants is one this caller could not have asked for itself.
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_ne!(
        status, 200,
        "a completion the caller's own key could not make must refuse: {body}"
    );
    assert!(
        state.get_last_request_body().is_none(),
        "the pool refusal happens at admission: the provider must never have been reached"
    );
    assert_eq!(
        peer.mcp_hits(),
        1,
        "and the refused ask produces no retry to the upstream"
    );
}

/// THE POLICY IS VETTED AT BOOT. A policy behind a closed grant, an empty model, and a zero on
/// either ceiling are operator errors answered where the operator is.
#[test]
fn the_sampling_policy_is_refused_at_boot_when_it_cannot_mean_what_it_says() {
    let base = || {
        let mut cfg: crate::mcp::config::McpServerDefCfg = serde_yaml::from_str(
            "url: https://tools.internal.example/mcp\npin: { mechanism: cert_spki, key: \"sha256/AAA=\" }\n",
        )
        .expect("a minimal registration parses");
        cfg.grants.sampling = true;
        cfg.sampling = Some(declared_sampling(5));
        cfg
    };

    let mut ungranted = base();
    ungranted.grants.sampling = false;
    let err = crate::mcp::config::validate_server("fs", &ungranted)
        .expect_err("a policy behind a closed gate is unreachable and must be refused");
    assert!(
        err.contains("grants.sampling"),
        "the refusal names the missing grant: {err}"
    );

    let mut nameless = base();
    nameless.sampling.as_mut().unwrap().model = String::new();
    let err = crate::mcp::config::validate_server("fs", &nameless)
        .expect_err("an empty model dispatches nowhere and must be refused");
    assert!(err.contains("sampling.model"), "names the key: {err}");

    let mut zero_tokens = base();
    zero_tokens.sampling.as_mut().unwrap().max_tokens = 0;
    let err = crate::mcp::config::validate_server("fs", &zero_tokens)
        .expect_err("a zero token ceiling is a withheld grant in a budget's clothes");
    assert!(err.contains("max_tokens"), "names the key: {err}");

    let mut zero_budget = base();
    zero_budget
        .sampling
        .as_mut()
        .unwrap()
        .max_requests_per_minute = 0;
    let err = crate::mcp::config::validate_server("fs", &zero_budget)
        .expect_err("a zero request budget is a withheld grant in a budget's clothes");
    assert!(
        err.contains("max_requests_per_minute"),
        "names the key: {err}"
    );
}
