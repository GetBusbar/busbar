// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A WRITER'S DROP IS ON THE ONE DROP PATH (design F3 "Drops"). Inside a TRANSLATE attempt, a member
//! or block a dialect writer cannot carry is warned once on the drop path (its diagnostic, the
//! direction, both dialects, and the SOURCE side's wire path) and audited. A member is named by the
//! source dialect's row for it, a block by the source dialect's block container with its kind as
//! that dialect spells it. On a request the source is the caller, on an answer the far end. Outside
//! an attempt (a direct writer call) the writer's own warn is emitted unchanged and nothing is
//! audited.

use crate::codec::proto_codec::protocol_for;
use crate::codec::translate::{TranslateCodec as _, TranslateReqInput};
use busbar_contract::ir::egress_prep::EgressPrep;
use busbar_contract::operation::OpVerb;
use busbar_contract::testkit::WarnCapture;
use serde_json::{json, Value};

/// Translate `body` from `ingress` onto `egress`: what the seam audits, and the warns.
fn translate(ingress: &str, egress: &str, body: &Value) -> (Vec<String>, WarnCapture) {
    let _ = protocol_for(ingress);
    let handler = crate::codec::decl_of(ingress)
        .and_then(|d| d.handler)
        .and_then(|h| h.operation_handler(OpVerb::CHAT))
        .expect("a chat handler");
    let prep = EgressPrep {
        ingress_protocol: ingress,
        egress_requires_max_tokens: true,
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
        cache_control_cap: None,
        lane_caps: Default::default(),
        thought_signature_fill: false,
    };
    let cap = WarnCapture::default();
    let out = tracing::subscriber::with_default(cap.clone(), || {
        handler.translate_request(TranslateReqInput::Json(body), Some(egress), &prep, "m")
    });
    let Ok(out) = out else {
        panic!("{ingress} -> {egress}: the request must translate");
    };
    (out.dropped_controls, cap)
}

/// Translate the far end's answer `body` (`egress`) for a caller of `ingress`: the audit rows and
/// the warns.
fn answer(egress: &str, ingress: &str, body: &Value) -> (Vec<String>, WarnCapture) {
    let _ = protocol_for(egress);
    let ctx = crate::exchange::reply::whole::WholeCtx {
        ingress,
        egress,
        operation: OpVerb::CHAT,
        model: "m",
        wants_stream: false,
        json_array: false,
        request: None,
        now_s: 1,
        elapsed_ms: None,
    };
    let bytes = serde_json::to_vec(body).unwrap();
    let cap = WarnCapture::default();
    let whole = tracing::subscriber::with_default(cap.clone(), || {
        crate::exchange::reply::whole::translate(&ctx, 200, &bytes)
    });
    (whole.dropped, cap)
}

/// The one captured warn that carries exactly `path=<path>` and contains `text`.
fn warn_of(cap: &WarnCapture, path: &str, text: &str) -> Option<String> {
    let field = format!("path={path}");
    cap.messages()
        .into_iter()
        .find(|m| m.contains(text) && m.split_whitespace().any(|w| w == field))
}

/// The writer's drop is audited as `path` and warned once on the drop path with `diag`, keeping the
/// writer's text.
fn on_the_drop_path(audited: &[String], cap: &WarnCapture, path: &str, diag: &str, text: &str) {
    assert!(
        audited.iter().any(|a| a == path),
        "the writer's drop is audited as `{path}`: {audited:?}"
    );
    let warn = warn_of(cap, path, text).unwrap_or_else(|| {
        panic!(
            "one drop-path warn names `{path}` with the writer's text `{text}`: {:?}",
            cap.messages()
        )
    });
    assert!(
        warn.contains(&format!("diag={diag}")),
        "the drop-path warn carries {diag}: {warn}"
    );
    assert_eq!(
        cap.messages().iter().filter(|m| m.contains(text)).count(),
        1,
        "the writer's warn is said once, on the drop path: {:?}",
        cap.messages()
    );
}

// ───────────────────────────── (1) a member, by the caller's row ─────────────────────────────

/// openai_chat writer: a Gemini caller's reasoning-off ask (`thinkingBudget: 0`) on a Chat lane that
/// does not declare `"none"` is named by Gemini's own row for it.
#[test]
fn a_request_member_drop_is_named_by_the_callers_row() {
    let (audited, cap) = translate(
        "gemini",
        "openai",
        &json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"thinkingConfig": {"thinkingBudget": 0}}}),
    );
    on_the_drop_path(
        &audited,
        &cap,
        "generationConfig.thinkingConfig.thinkingBudget",
        "BUSBAR-7079",
        "omitting reasoning OFF on OpenAI Chat egress",
    );
}

// ───────────────────────────── (2) a block, by the caller's container ─────────────────────────────

/// anthropic writer: a Responses caller's `input_image` by OpenAI `file_id` has no Anthropic source,
/// and is named by the Responses block container, its kind as Responses spells it.
#[test]
fn a_request_block_drop_is_named_by_the_callers_block_container() {
    let (audited, cap) = translate(
        "responses",
        "anthropic",
        &json!({"model": "m", "input": [{"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "hi"},
            {"type": "input_image", "file_id": "file-1"}
        ]}]}),
    );
    let text = "dropping unresolvable vendor-scoped image reference on Anthropic egress";
    on_the_drop_path(&audited, &cap, "input[].content[]", "BUSBAR-7085", text);
    let warn = warn_of(&cap, "input[].content[]", text).unwrap();
    assert!(
        warn.contains("kind=type=input_image"),
        "the block's kind as the caller's dialect spells it: {warn}"
    );
}

// ───────────────────────────── (3) an answer, by the far end's container ─────────────────────────────

/// openai_chat response writer: an Anthropic answer's thinking block has no Chat completion field,
/// and is named by the Anthropic answer's block container (the bytes that held it).
#[test]
fn an_answer_drop_is_named_by_the_far_ends_block_container() {
    let (audited, cap) = answer(
        "anthropic",
        "openai",
        &json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
            "content": [
                {"type": "thinking", "thinking": "hm", "signature": "s"},
                {"type": "text", "text": "hi"}
            ],
            "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}}),
    );
    let text = "dropping a reasoning/thinking block on OpenAI Chat egress";
    on_the_drop_path(&audited, &cap, "content[]", "BUSBAR-7085", text);
    let warn = warn_of(&cap, "content[]", text).unwrap();
    assert!(
        warn.contains("direction=response") && warn.contains("kind=type=thinking"),
        "{warn}"
    );
}

// ───────────────────────────── the other writers ─────────────────────────────

#[test]
fn gemini_writer_drop_is_on_the_drop_path() {
    let (audited, cap) = translate(
        "openai",
        "gemini",
        &json!({"model": "m", "parallel_tool_calls": true,
            "messages": [{"role": "user", "content": "hi"}]}),
    );
    on_the_drop_path(
        &audited,
        &cap,
        "parallel_tool_calls",
        "BUSBAR-7085",
        "dropping parallel_tool_calls on Gemini egress",
    );
}

#[test]
fn cohere_writer_drop_is_on_the_drop_path() {
    let (audited, cap) = translate(
        "responses",
        "cohere",
        &json!({"model": "m", "parallel_tool_calls": false, "input": "hi"}),
    );
    on_the_drop_path(
        &audited,
        &cap,
        "parallel_tool_calls",
        "BUSBAR-7085",
        "dropping parallel_tool_calls on Cohere egress",
    );
}

#[test]
fn bedrock_writer_drop_is_on_the_drop_path() {
    let (audited, cap) = translate(
        "responses",
        "bedrock",
        &json!({"model": "m", "parallel_tool_calls": true, "input": "hi"}),
    );
    on_the_drop_path(
        &audited,
        &cap,
        "parallel_tool_calls",
        "BUSBAR-7085",
        "dropping parallel_tool_calls on Bedrock egress",
    );
}

#[test]
fn responses_writer_drop_is_on_the_drop_path() {
    let (audited, cap) = translate(
        "anthropic",
        "responses",
        &json!({"model": "m", "max_tokens": 10, "tool_choice": {"type": "auto"},
            "messages": [{"role": "user", "content": "hi"}]}),
    );
    on_the_drop_path(
        &audited,
        &cap,
        "tool_choice",
        "BUSBAR-7085",
        "dropping tool_choice on Responses egress",
    );
}

/// Outside a TRANSLATE attempt (a direct writer call) the writer's own warn is said unchanged, with
/// its own fields and no drop-path fields.
#[test]
fn outside_an_attempt_the_writers_own_warn_is_said() {
    use crate::codec::proto_codec::ProtocolWriter as _;
    let ir = crate::codec::ir::IrRequest {
        parallel_tool_calls: Some(true),
        ..Default::default()
    };
    let cap = WarnCapture::default();
    let writer = crate::codec::gemini::GeminiWriter;
    tracing::subscriber::with_default(cap.clone(), || writer.write_request(&ir));
    let text = "dropping parallel_tool_calls on Gemini egress";
    assert_eq!(cap.count(text), 1, "{:?}", cap.messages());
    assert!(
        !cap.contains("path=") && !cap.contains("diag="),
        "no drop-path fields outside an attempt: {:?}",
        cap.messages()
    );
}
