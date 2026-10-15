// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING (owner directive Q57) — the Bedrock reasoning ask (dropped both ways, as in 1.5.5)
//! and structured output (BED-08). Split from `ir_mapping_tests.rs`; BED-08 moves a committed
//! request golden (`req_o2b_tools.json`).

use super::*;
use serde_json::json;

/// The reader promotes no `additionalModelRequestFields` reasoning ask, as in 1.5.5 (v1.5.5
/// `crates/busbar/src/proto/bedrock/reader.rs:678`, `reasoning: None`): the native object stays a
/// same-protocol member and is re-emitted verbatim. RED while `thinking` read as `Budget(4096)` and
/// Nova `reasoningConfig` as `Effort(High)`.
#[test]
fn a_native_reasoning_ask_is_not_promoted_to_the_ir() {
    let body = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 20000},
        "additionalModelRequestFields": {"thinking": {"type": "enabled", "budget_tokens": 4096}}
    });
    let ir = BedrockReader.read_request(&body).expect("read");
    assert_eq!(ir.reasoning, None);
    let nova = json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "additionalModelRequestFields": {"reasoningConfig": {"type": "enabled", "maxReasoningEffort": "high"}}
    });
    let ir = BedrockReader.read_request(&nova).expect("read");
    assert_eq!(ir.reasoning, None);
    // Same-protocol: the native object is re-emitted verbatim.
    let back = writer().write_request(crate::codec::test_host::HOST, &ir);
    assert_eq!(
        back["additionalModelRequestFields"],
        json!({"reasoningConfig": {"type": "enabled", "maxReasoningEffort": "high"}}),
        "{back}"
    );
}

/// A foreign reasoning ask is DROPPED on Bedrock egress, as in 1.5.5 (v1.5.5
/// `crates/busbar/src/proto/bedrock/writer.rs:139-146`): no `thinking` is written, so no thinking
/// tokens are billed, and the sampling knobs (`temperature`, `topP`, `top_k`) are sent as 1.5.5
/// sent them. RED while the ask wrote `thinking {enabled, 7168}` and stripped the knobs.
#[test]
fn a_foreign_reasoning_ask_is_dropped_on_bedrock_egress() {
    let ir = crate::codec::ir::IrRequest {
        messages: vec![crate::codec::ir::IrMessage {
            role: crate::codec::ir::IrRole::User,
            content: vec![crate::codec::ir::IrBlock::Text {
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
        reasoning: Some(crate::codec::ir::IrReasoningAsk::Effort(
            crate::codec::ir::IrReasoningEffort::High,
        )),
        ..Default::default()
    };
    let out = writer().write_request(crate::codec::test_host::HOST, &ir);
    assert!(
        out.pointer("/additionalModelRequestFields/thinking")
            .is_none(),
        "{out}"
    );
    assert_eq!(out["inferenceConfig"]["temperature"], 0.5, "{out}");
    assert_eq!(out["inferenceConfig"]["topP"], 0.9, "{out}");
    assert_eq!(out["additionalModelRequestFields"]["top_k"], 40, "{out}");
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
    let back = writer().write_request(crate::codec::test_host::HOST, &ir);
    assert_eq!(back["outputConfig"], body["outputConfig"], "{back}");
    assert_eq!(
        back["toolConfig"]["tools"][0]["toolSpec"]["strict"], true,
        "{back}"
    );
    // Cross-protocol: the typed directive is projected from the IR alone, on a lane that declares
    // native structured outputs.
    let mut cross = ir.clone();
    cross.extra.clear();
    let native = LaneCaps {
        native_structured_output: true,
        ..Default::default()
    };
    let out = writer().write_request_for_lane(
        crate::codec::test_host::HOST,
        &cross,
        "anthropic.claude-opus-4-7",
        &native,
    );
    assert_eq!(
        out["outputConfig"]["textFormat"]["type"], "json_schema",
        "{out}"
    );
    assert_eq!(
        out["outputConfig"]["textFormat"]["structure"]["jsonSchema"]["name"], "extract",
        "{out}"
    );
    assert!(writer()
        .dropped_egress_controls_for_lane(&cross, &native)
        .is_empty());
    // A lane that does not declare them drops the directive (the pre-structured-output form) and
    // says so; per-tool strict still rides.
    let out = writer().write_request(crate::codec::test_host::HOST, &cross);
    assert!(out.get("outputConfig").is_none(), "{out}");
    assert_eq!(
        out["toolConfig"]["tools"][0]["toolSpec"]["strict"], true,
        "{out}"
    );
    assert_eq!(
        writer().dropped_egress_controls(&cross),
        vec!["response_format"]
    );
}

/// A fresh writer per use (the const constructor carries per-stream state).
fn writer() -> BedrockWriter {
    BedrockWriter
}
