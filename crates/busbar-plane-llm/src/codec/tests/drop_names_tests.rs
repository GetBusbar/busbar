// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DROP IS NAMED BY THE CALLER'S WIRE PATH (design F3 "Drops"). A seam gate (`n`, the reasoning
//! ask, the prompt-cache breakpoints, the stop cap) and a control the far end's dialect has no
//! form for are named, in the warn's `path=` field and in the seam's audit, by the path the
//! caller's own dialect spells them at (its map file's row, notation A): a Gemini caller's
//! `generationConfig.candidateCount`, not the IR slot `n`. A slot the caller's map file has no row
//! for keeps the slot's name.

use crate::codec::proto_codec::protocol_for;
use crate::codec::translate::{TranslateCodec as _, TranslateReqInput};
use busbar_contract::ir::egress_prep::EgressPrep;
use busbar_contract::operation::OpVerb;
use busbar_contract::testkit::WarnCapture;
use serde_json::{json, Value};

/// The seam's gates for the test: closed (`false`) gates drop the reasoning ask and the cache
/// breakpoints.
#[derive(Clone, Copy)]
struct Gates {
    reasoning: bool,
    caching: bool,
}

const OPEN: Gates = Gates {
    reasoning: true,
    caching: true,
};
const CLOSED: Gates = Gates {
    reasoning: false,
    caching: false,
};

/// Translate `body` from `ingress` onto `egress`: what the seam audits, and the warns.
fn translate(
    ingress: &str,
    egress: &str,
    body: &Value,
    gates: Gates,
) -> (Vec<String>, WarnCapture) {
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
        reasoning_allowed: gates.reasoning,
        reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: gates.caching,
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

/// Whether a captured warn carries exactly `path=<path>` as one of its fields; `drop_path` picks the
/// one drop path's warn (it carries `diag=`) or a writer's control warn (it does not).
fn warned(cap: &WarnCapture, path: &str, drop_path: bool) -> bool {
    let field = format!("path={path}");
    cap.messages()
        .iter()
        .any(|m| m.split_whitespace().any(|w| w == field) && m.contains("diag=") == drop_path)
}

/// A seam gate's drop is warned on the one drop path and audited under `path`, and never under the
/// IR name `slot` (unless the two are the same).
fn gate_named(ingress: &str, egress: &str, body: Value, path: &str, slot: &str) {
    let (audited, cap) = translate(ingress, egress, &body, CLOSED);
    assert!(
        audited.iter().any(|a| a == path),
        "{ingress} -> {egress}: the gate's drop is audited as `{path}`: {audited:?}"
    );
    assert!(
        warned(&cap, path, true),
        "{ingress} -> {egress}: the gate's warn carries path={path}: {:?}",
        cap.messages()
    );
    if slot != path {
        assert!(
            !audited.iter().any(|a| a == slot),
            "{ingress} -> {egress}: the IR name `{slot}` is not the caller's path: {audited:?}"
        );
        assert!(
            !warned(&cap, slot, true),
            "{ingress} -> {egress}: no warn names the IR slot `{slot}`: {:?}",
            cap.messages()
        );
    }
}

/// A control the far end's dialect has no form for is warned by the far end's writer and audited
/// under `path`, never under the IR name `slot` (unless the two are the same).
fn control_named(ingress: &str, egress: &str, body: Value, path: &str, slot: &str) {
    let (audited, cap) = translate(ingress, egress, &body, OPEN);
    assert!(
        audited.iter().any(|a| a == path),
        "{ingress} -> {egress}: the dropped control is audited as `{path}`: {audited:?}"
    );
    assert!(
        warned(&cap, path, false),
        "{ingress} -> {egress}: the writer's control warn carries path={path}: {:?}",
        cap.messages()
    );
    if slot != path {
        assert!(
            !audited.iter().any(|a| a == slot),
            "{ingress} -> {egress}: the IR name `{slot}` is not the caller's path: {audited:?}"
        );
    }
}

// ───────────────────────────── OpenAI Chat: the slot names are its own ─────────────────────────────

#[test]
fn openai_chat_gates_are_named_by_its_own_wire_path() {
    gate_named(
        "openai",
        "anthropic",
        json!({"model": "m", "n": 3, "messages": [{"role": "user", "content": "hi"}]}),
        "n",
        "n",
    );
    gate_named(
        "openai",
        "anthropic",
        json!({"model": "m", "reasoning_effort": "high",
            "messages": [{"role": "user", "content": "hi"}]}),
        "reasoning_effort",
        "reasoning",
    );
}

#[test]
fn openai_chat_control_drop_is_named_by_its_own_wire_path() {
    control_named(
        "openai",
        "anthropic",
        json!({"model": "m", "seed": 7, "messages": [{"role": "user", "content": "hi"}]}),
        "seed",
        "seed",
    );
}

// ───────────────────────────── OpenAI Responses ─────────────────────────────

#[test]
fn responses_gate_is_named_by_its_wire_path() {
    gate_named(
        "responses",
        "anthropic",
        json!({"model": "m", "reasoning": {"effort": "high"}, "input": "hi"}),
        "reasoning.effort",
        "reasoning",
    );
}

#[test]
fn responses_control_drop_is_named_by_its_wire_path() {
    control_named(
        "responses",
        "anthropic",
        json!({"model": "m", "text": {"verbosity": "low"}, "input": "hi"}),
        "text.verbosity",
        "verbosity",
    );
}

// ───────────────────────────── Anthropic ─────────────────────────────

#[test]
fn anthropic_gate_is_named_by_its_wire_path() {
    gate_named(
        "anthropic",
        "openai",
        json!({"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": [
            {"type": "text", "text": "hi", "cache_control": {"type": "ephemeral"}}
        ]}]}),
        "messages[].content[].cache_control",
        "cache_control",
    );
}

#[test]
fn anthropic_control_drop_is_named_by_its_wire_path() {
    control_named(
        "anthropic",
        "responses",
        json!({"model": "m", "max_tokens": 10, "stop_sequences": ["END"],
            "messages": [{"role": "user", "content": "hi"}]}),
        "stop_sequences",
        "stop",
    );
}

// ───────────────────────────── Gemini ─────────────────────────────

#[test]
fn gemini_gate_is_named_by_its_wire_path() {
    gate_named(
        "gemini",
        "anthropic",
        json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"candidateCount": 3}}),
        "generationConfig.candidateCount",
        "n",
    );
}

#[test]
fn gemini_control_drop_is_named_by_its_wire_path() {
    control_named(
        "gemini",
        "anthropic",
        json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "generationConfig": {"seed": 7}}),
        "generationConfig.seed",
        "seed",
    );
}

// ───────────────────────────── Bedrock ─────────────────────────────

#[test]
fn bedrock_gate_is_named_by_its_wire_path() {
    gate_named(
        "bedrock",
        "openai",
        json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 5,
                "stopSequences": ["a", "b", "c", "d", "e", "f"]}}),
        "inferenceConfig.stopSequences",
        "stop",
    );
}

#[test]
fn bedrock_control_drop_is_named_by_its_wire_path() {
    control_named(
        "bedrock",
        "cohere",
        json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 5}, "serviceTier": {"type": "flex"}}),
        "serviceTier.type",
        "service_tier",
    );
}

// ───────────────────────────── Cohere ─────────────────────────────

#[test]
fn cohere_gate_is_named_by_its_wire_path() {
    gate_named(
        "cohere",
        "openai",
        json!({"model": "m", "stop_sequences": ["a", "b", "c", "d", "e"],
            "messages": [{"role": "user", "content": "hi"}]}),
        "stop_sequences",
        "stop",
    );
}

#[test]
fn cohere_control_drop_is_named_by_its_wire_path() {
    control_named(
        "cohere",
        "openai",
        json!({"model": "m", "k": 5, "messages": [{"role": "user", "content": "hi"}]}),
        "k",
        "top_k",
    );
}

/// A member the caller's map file has no row for, carried by the reader's own code: Cohere's
/// budget ask is its `thinking.token_budget` member, and the gate's drop is named by it (DF-SITES: the
/// reader's request code names), not by the IR name.
#[test]
fn a_slot_the_callers_reader_carries_by_code_is_named_by_its_wire_path() {
    gate_named(
        "cohere",
        "openai",
        json!({"model": "m", "thinking": {"type": "enabled", "token_budget": 100},
            "messages": [{"role": "user", "content": "hi"}]}),
        "thinking.token_budget",
        "reasoning",
    );
}
