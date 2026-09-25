// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING (owner directive Q57) — the Bedrock reasoning ask (BED-06) and structured output
//! (BED-08). Split from `ir_mapping_tests.rs` because each moves a committed request golden
//! (`req_a2b_thinking_metadata.json`, `req_o2b_tools.json`).

use super::*;
use serde_json::json;

/// BED-06 (reader): `additionalModelRequestFields.thinking` / Nova `reasoningConfig` were never
/// read, so a Bedrock caller's reasoning ask died at the seam.
#[test]
fn bed06_reasoning_ask_is_read_from_additional_model_request_fields() {
    let body = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 20000},
        "additionalModelRequestFields": {"thinking": {"type": "enabled", "budget_tokens": 4096}}
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Budget(4096)));
    let nova = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "additionalModelRequestFields": {"reasoningConfig": {"type": "enabled", "maxReasoningEffort": "high"}}
    });
    let ir = BedrockReader.read_request(&nova).expect("read");
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::High
        ))
    );
    // Same-protocol: the native object is re-emitted verbatim, not re-synthesized over.
    let back = writer().write_request(&ir);
    assert_eq!(
        back["additionalModelRequestFields"],
        json!({"reasoningConfig": {"type": "enabled", "maxReasoningEffort": "high"}}),
        "{back}"
    );
}

/// BED-06 (writer): a foreign reasoning ask was never written; it projects onto
/// `additionalModelRequestFields.thinking` with the Anthropic budget rules, and knobs Claude rejects
/// alongside thinking are omitted.
#[test]
fn bed06_foreign_reasoning_ask_writes_thinking() {
    let mut ir = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".into(),
                cache_control: None,
                citations: Vec::new(),
                refusal: false,
            }],
        }],
        max_tokens: Some(8192),
        temperature: Some(0.5),
        top_p: Some(0.9),
        top_k: Some(40),
        reasoning: Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::High,
        )),
        ..Default::default()
    };
    let out = writer().write_request(&ir);
    assert_eq!(
        out["additionalModelRequestFields"]["thinking"],
        json!({"type": "enabled", "budget_tokens": 7168}),
        "budget clamped to leave 1024 under maxTokens: {out}"
    );
    assert!(out["inferenceConfig"].get("temperature").is_none(), "{out}");
    assert!(out["inferenceConfig"].get("topP").is_none(), "{out}");
    assert!(
        out["additionalModelRequestFields"].get("top_k").is_none(),
        "{out}"
    );
    // No room for the 1024 minimum: dropped, sampling knobs kept.
    ir.max_tokens = Some(1500);
    let out = writer().write_request(&ir);
    assert!(
        out.pointer("/additionalModelRequestFields/thinking")
            .is_none(),
        "{out}"
    );
    assert_eq!(out["inferenceConfig"]["temperature"], 0.5, "{out}");
}

/// BED-08: Converse's `outputConfig.textFormat` and `toolSpec.strict` are read into the IR and
/// written back, so a JSON-schema directive and per-tool strict cross in both directions.
#[test]
fn bed08_output_config_and_tool_strict_map_both_ways() {
    let body = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "outputConfig": {"textFormat": {"type": "json_schema", "structure": {"jsonSchema": {
            "schema": "{\"type\":\"object\"}", "name": "extract", "description": "d"}}}},
        "toolConfig": {"tools": [{"toolSpec": {"name": "f", "strict": true,
            "inputSchema": {"json": {"type": "object"}}}}]}
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    let rf = ir.response_format.clone().expect("response_format");
    assert!(rf.json);
    assert_eq!(rf.schema, Some(json!({"type": "object"})));
    assert_eq!(rf.name.as_deref(), Some("extract"));
    assert_eq!(rf.description.as_deref(), Some("d"));
    assert_eq!(ir.tools[0].strict, Some(true));
    // Same-protocol round trip keeps the native bytes (the raw textFormat wins).
    let back = writer().write_request(&ir);
    assert_eq!(back["outputConfig"], body["outputConfig"], "{back}");
    assert_eq!(
        back["toolConfig"]["tools"][0]["toolSpec"]["strict"], true,
        "{back}"
    );
    // Cross-protocol: the typed directive is projected from the IR alone.
    let mut cross = ir.clone();
    cross.extra.clear();
    let out = writer().write_request(&cross);
    assert_eq!(
        out["outputConfig"]["textFormat"]["type"], "json_schema",
        "{out}"
    );
    assert_eq!(
        out["outputConfig"]["textFormat"]["structure"]["jsonSchema"]["name"], "extract",
        "{out}"
    );
    assert!(writer().dropped_egress_controls(&cross).is_empty());
}

/// A fresh writer per use (the const constructor carries per-stream state).
fn writer() -> BedrockWriter {
    BedrockWriter
}
