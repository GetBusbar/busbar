// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping round 3 (IR-INTEGRATE, Q57): the OpenAI Chat share of items 11 and 12.
use crate::proto_codec::{protocol_for, LaneCaps};
use serde_json::json;

fn anthropic_off() -> crate::ir::IrRequest {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 64, "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    ir.extra.clear();
    ir
}

/// Item 12: a lane declaring `reasoning_none` gets `reasoning_effort: "none"` for an Off ask; the
/// default lane keeps today's bytes (omitted).
#[test]
fn item12_off_is_reasoning_effort_none_on_a_declaring_lane() {
    let w = protocol_for("openai").unwrap();
    let none_lane = LaneCaps {
        reasoning_none: true,
        ..Default::default()
    };
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-5.1", &none_lane);
    assert_eq!(out["reasoning_effort"], "none", "{out}");
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-4o", &Default::default());
    assert!(out.get("reasoning_effort").is_none(), "{out}");
}

// ───────────────────────── item 11: OpenAI custom / grammar tools ─────────────────────────

fn chat_with_custom_tool() -> serde_json::Value {
    json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "run it"}],
        "tools": [
            {"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}},
            {"type": "custom", "custom": {"name": "code_exec", "description": "run code",
                "format": {"type": "grammar", "grammar": {"syntax": "lark", "definition": "start: /.+/"}}}}
        ]
    })
}

fn to_egress(egress: &str, body: &serde_json::Value) -> serde_json::Value {
    let mut ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(body)
        .expect("read");
    crate::chat_handle::chat_prepare_for_egress(
        &mut ir,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "openai",
            egress_requires_max_tokens: true,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    protocol_for(egress).unwrap().writer().write_request(&ir)
}

/// Item 11 (OAI-09): a Chat custom (grammar) tool reaches a Responses lane as the flat Responses
/// custom tool, beside the function tool; the seam no longer drops it.
#[test]
fn item11_chat_custom_tool_reaches_a_responses_lane() {
    let out = to_egress("responses", &chat_with_custom_tool());
    let tools = out["tools"].as_array().cloned().unwrap_or_default();
    assert!(
        tools.contains(&json!({"type": "custom", "name": "code_exec", "description": "run code",
            "format": {"type": "grammar", "grammar": {"syntax": "lark", "definition": "start: /.+/"}}})),
        "{out}"
    );
    assert!(tools.iter().any(|t| t["name"] == "f"), "{out}");
}

/// Item 11: a lane with no custom tool (Anthropic) drops it and reports the drop; an OpenAI-origin
/// IR writes it back in the Chat spelling.
#[test]
fn item11_custom_tool_dropped_and_reported_where_not_representable() {
    let out = to_egress("anthropic", &chat_with_custom_tool());
    let tools = out["tools"].as_array().cloned().unwrap_or_default();
    assert_eq!(tools.len(), 1, "{out}");
    let ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(&chat_with_custom_tool())
        .unwrap();
    assert!(protocol_for("anthropic")
        .unwrap()
        .writer()
        .dropped_egress_controls(&ir)
        .contains(&"custom_tool"));
    let same = protocol_for("openai").unwrap().writer().write_request(&ir);
    assert!(
        same["tools"]
            .as_array()
            .unwrap()
            .contains(&chat_with_custom_tool()["tools"][1]),
        "{same}"
    );
}
