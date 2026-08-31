// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIELD-COVERAGE CARRY instruments for the AWS Bedrock Converse dialect (`bedrock/` field ids).
//!
//! Each test here is the named instrument a `qa/field-coverage.status` line points at, and each
//! genuinely FAILS if its field stops surviving — that is the whole contract of the coverage gate
//! (`crates/busbar/tests/field_coverage.rs`): a `carried` claim is admissible only with a test that
//! would miss the field being dropped. The tests are grouped by wire construct, but EVERY named
//! field carries its own field-level assertion.
//!
//! Two carry disciplines, matching the two field classes:
//!
//! * CROSS-PROTOCOL-MEANINGFUL (messages, content blocks, sampling knobs, toolConfig, usage,
//!   stopReason, stream events): the field must reach the NEUTRAL IR (the cross-protocol carrier —
//!   `extra` is cleared at the seam, so anything left there dies on a cross-protocol hop). The tests
//!   assert on the typed IR directly AND on the Bedrock writer's re-emission, so a regression in
//!   either the reader (stops populating the IR) or the writer (stops emitting) is caught.
//!
//! * PROVIDER-SPECIFIC, no cross-protocol equivalent (`additionalModelRequestFields`,
//!   `promptVariables`, `guardContent`, `cachePoint`, s3 sources, response `trace`/`performanceConfig`
//!   …): lossless SAME-protocol via the reader's verbatim `extra`/positional-stash capture (asserted
//!   as a Bedrock->Bedrock read->write survival), and — where there is genuinely no target slot — a
//!   DOCUMENTED cross-protocol drop the test pins (never a waiver).

use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — cross-protocol-meaningful fields (must reach the neutral IR)
// ─────────────────────────────────────────────────────────────────────────────

/// `bedrock/request/inferenceConfig.stopSequences` — Bedrock nests stop sequences under
/// `inferenceConfig`; they must land in the universal `IrRequest.stop` (the cross-protocol carrier)
/// and re-emit in Bedrock's nested slot.
#[test]
fn bedrock_carry_request_stop_sequences() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "inferenceConfig": {"maxTokens": 50, "stopSequences": ["STOP", "END"]}
    });
    let ir = reader.read_request(&body).expect("read");
    // Cross-protocol carrier: the typed IR, not `extra`.
    assert_eq!(
        ir.stop,
        vec!["STOP".to_string(), "END".to_string()],
        "stopSequences must reach IrRequest.stop"
    );
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/inferenceConfig/stopSequences"),
        Some(&serde_json::json!(["STOP", "END"])),
        "stopSequences must re-emit under inferenceConfig; got {out}"
    );
}

/// `bedrock/request/toolConfig.tools` and `bedrock/request/toolConfig.toolChoice` — the tool
/// definitions must reach `IrRequest.tools` and the force-tool-use directive must reach
/// `IrRequest.tool_choice` (Bedrock `{any:{}}` == the neutral `Required`), so both survive the
/// cross-protocol seam instead of degrading to `auto`.
#[test]
fn bedrock_carry_request_tool_config() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "weather?"}]}],
        "toolConfig": {
            "tools": [{"toolSpec": {
                "name": "get_weather",
                "description": "Get weather",
                "inputSchema": {"json": {"type": "object"}}
            }}],
            "toolChoice": {"any": {}}
        }
    });
    let ir = reader.read_request(&body).expect("read");

    // toolConfig.tools
    assert_eq!(
        ir.tools.len(),
        1,
        "toolConfig.tools must reach IrRequest.tools"
    );
    assert_eq!(ir.tools[0].name, "get_weather");
    // toolConfig.toolChoice — Bedrock `{any:{}}` is the neutral `Required`.
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Required),
        "toolConfig.toolChoice `{{any:{{}}}}` must reach IrRequest.tool_choice as Required"
    );

    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/toolConfig/tools/0/toolSpec/name")
            .and_then(|v| v.as_str()),
        Some("get_weather"),
        "toolConfig.tools must re-emit; got {out}"
    );
    assert!(
        out.pointer("/toolConfig/toolChoice/any").is_some(),
        "toolConfig.toolChoice must re-emit as {{any:{{}}}}; got {out}"
    );

    // Cross-protocol proof: the force-tool-use directive projects into OpenAI's `required`, not
    // degrading to `auto` — the exact loss `IrToolChoice` exists to prevent.
    if let Some(openai) = super::super::proto_codec::protocol_for("openai") {
        let oai = openai.writer().write_request(&ir);
        assert_eq!(
            oai.pointer("/tool_choice").and_then(|v| v.as_str()),
            Some("required"),
            "Bedrock `{{any:{{}}}}` must cross-project to OpenAI `required`; got {oai}"
        );
    }
}

/// `bedrock/request/content[].toolUse.{toolUseId,name,input}` — an assistant turn's tool call must
/// reach `IrBlock::ToolUse` field-for-field and re-emit natively.
#[test]
fn bedrock_carry_request_tool_use() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "tu_9", "name": "lookup", "input": {"q": "x"}}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::ToolUse {
            id, name, input, ..
        } => {
            assert_eq!(
                id, "tu_9",
                "toolUse.toolUseId must reach IrBlock::ToolUse.id"
            );
            assert_eq!(
                name, "lookup",
                "toolUse.name must reach IrBlock::ToolUse.name"
            );
            assert_eq!(
                input,
                &serde_json::json!({"q": "x"}),
                "toolUse.input must reach IrBlock::ToolUse.input"
            );
        }
        other => panic!("expected ToolUse, got {other:?}"),
    }
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/0/toolUse/toolUseId")
            .and_then(|v| v.as_str()),
        Some("tu_9"),
        "toolUse.toolUseId must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/toolUse/name")
            .and_then(|v| v.as_str()),
        Some("lookup"),
        "toolUse.name must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/toolUse/input"),
        Some(&serde_json::json!({"q": "x"})),
        "toolUse.input must re-emit; got {out}"
    );
}

/// `bedrock/request/content[].toolResult.{toolUseId,content,status}` — a tool result must reach
/// `IrBlock::ToolResult` (id + nested content + the error status) and re-emit natively.
#[test]
fn bedrock_carry_request_tool_result() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"toolResult": {
                "toolUseId": "tu_9",
                "content": [{"text": "boom"}],
                "status": "error"
            }}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => {
            assert_eq!(
                tool_use_id, "tu_9",
                "toolResult.toolUseId must reach IrBlock::ToolResult.tool_use_id"
            );
            assert!(
                matches!(&content[0], crate::ir::IrBlock::Text { text, .. } if text == "boom"),
                "toolResult.content must reach IrBlock::ToolResult.content"
            );
            assert!(
                *is_error,
                "toolResult.status=error must reach IrBlock::ToolResult.is_error"
            );
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/0/toolResult/toolUseId")
            .and_then(|v| v.as_str()),
        Some("tu_9"),
        "toolResult.toolUseId must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/toolResult/content/0/text")
            .and_then(|v| v.as_str()),
        Some("boom"),
        "toolResult.content must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/toolResult/status")
            .and_then(|v| v.as_str()),
        Some("error"),
        "toolResult.status must re-emit; got {out}"
    );
}

/// `bedrock/request/content[].reasoningContent.reasoningText.{text,signature}` and
/// `bedrock/request/content[].reasoningContent.redactedContent` — an assistant turn's extended
/// thinking (plaintext + signature) and its redacted variant must reach `IrBlock::Thinking` and
/// re-emit. Bedrock REQUIRES the signed reasoning echoed back on a follow-up turn, so this is
/// load-bearing, not cosmetic.
#[test]
fn bedrock_carry_request_reasoning_content() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "assistant", "content": [
            {"reasoningContent": {"reasoningText": {"text": "let me think", "signature": "sig-abc"}}},
            {"reasoningContent": {"redactedContent": "ciphertext-bytes"}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Thinking {
            text,
            signature,
            redacted,
            ..
        } => {
            assert_eq!(
                text, "let me think",
                "reasoningText.text must reach IrBlock::Thinking.text"
            );
            assert_eq!(
                signature.as_deref(),
                Some("sig-abc"),
                "reasoningText.signature must reach IrBlock::Thinking.signature"
            );
            assert!(!redacted, "a reasoningText block is not redacted");
        }
        other => panic!("expected Thinking, got {other:?}"),
    }
    match &ir.messages[0].content[1] {
        crate::ir::IrBlock::Thinking { redacted, text, .. } => {
            assert!(
                *redacted,
                "redactedContent must reach IrBlock::Thinking with redacted=true"
            );
            assert_eq!(
                text, "ciphertext-bytes",
                "redacted bytes ride in Thinking.text"
            );
        }
        other => panic!("expected redacted Thinking, got {other:?}"),
    }
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/0/reasoningContent/reasoningText/text")
            .and_then(|v| v.as_str()),
        Some("let me think"),
        "reasoningText.text must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/reasoningContent/reasoningText/signature")
            .and_then(|v| v.as_str()),
        Some("sig-abc"),
        "reasoningText.signature must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/1/reasoningContent/redactedContent")
            .and_then(|v| v.as_str()),
        Some("ciphertext-bytes"),
        "redactedContent must re-emit; got {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — provider-specific fields (lossless SAME-protocol via verbatim capture)
// ─────────────────────────────────────────────────────────────────────────────

/// `bedrock/request/additionalModelRequestFields` — the model-specific escape hatch. Captured
/// verbatim and re-emitted on a Bedrock->Bedrock hop (the reader also overlays the typed `top_k`
/// here, so this proves the caller's OWN keys survive alongside).
#[test]
fn bedrock_carry_request_additional_model_request_fields() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "additionalModelRequestFields": {"custom_param": 42, "nested": {"a": true}}
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/additionalModelRequestFields/custom_param")
            .and_then(|v| v.as_i64()),
        Some(42),
        "additionalModelRequestFields must round-trip verbatim; got {out}"
    );
    assert_eq!(
        out.pointer("/additionalModelRequestFields/nested/a")
            .and_then(|v| v.as_bool()),
        Some(true),
        "nested additionalModelRequestFields must round-trip; got {out}"
    );
}

/// `bedrock/request/additionalModelResponseFieldPaths` — the array of response paths the caller
/// wants echoed. No cross-protocol analog; captured into `extra` and re-emitted verbatim.
#[test]
fn bedrock_carry_request_additional_model_response_field_paths() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "additionalModelResponseFieldPaths": ["/foo/bar", "/baz"]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/additionalModelResponseFieldPaths"),
        Some(&serde_json::json!(["/foo/bar", "/baz"])),
        "additionalModelResponseFieldPaths must round-trip verbatim; got {out}"
    );
}

/// `bedrock/request/promptVariables` — prompt-management template variables. Bedrock-specific;
/// captured into `extra` and re-emitted verbatim.
#[test]
fn bedrock_carry_request_prompt_variables() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "promptVariables": {"topic": {"text": "weather"}}
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/promptVariables/topic/text")
            .and_then(|v| v.as_str()),
        Some("weather"),
        "promptVariables must round-trip verbatim; got {out}"
    );
}

/// `bedrock/request/requestMetadata` — the caller's key/value request tags. Bedrock-specific;
/// captured into `extra` and re-emitted verbatim.
#[test]
fn bedrock_carry_request_request_metadata() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "requestMetadata": {"team": "search", "env": "prod"}
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/requestMetadata/team")
            .and_then(|v| v.as_str()),
        Some("search"),
        "requestMetadata must round-trip verbatim; got {out}"
    );
    assert_eq!(
        out.pointer("/requestMetadata/env").and_then(|v| v.as_str()),
        Some("prod"),
        "requestMetadata must round-trip verbatim; got {out}"
    );
}

/// `bedrock/request/performanceConfig` — the latency/cost optimization selector. Bedrock-specific;
/// captured into `extra` and re-emitted verbatim.
#[test]
fn bedrock_carry_request_performance_config() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [{"text": "hi"}]}],
        "performanceConfig": {"latency": "optimized"}
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/performanceConfig/latency")
            .and_then(|v| v.as_str()),
        Some("optimized"),
        "performanceConfig must round-trip verbatim; got {out}"
    );
}

/// `bedrock/request/content[].image.source.s3Location` — an S3-referenced image (no inline bytes).
/// Carried on the typed `IrImageSource::Vendor` escape so `source.s3Location` (uri + bucketOwner)
/// re-emits on a same-protocol hop rather than being dropped as `data = ""`.
#[test]
fn bedrock_carry_request_image_s3_location() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"image": {"format": "png", "source": {"s3Location": {"uri": "s3://b/i", "bucketOwner": "123456789012"}}}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/0/image/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://b/i"),
        "image.source.s3Location.uri must round-trip; got {out}"
    );
    assert_eq!(
        out.pointer("/messages/0/content/0/image/source/s3Location/bucketOwner")
            .and_then(|v| v.as_str()),
        Some("123456789012"),
        "image.source.s3Location.bucketOwner must round-trip; got {out}"
    );
}

/// `bedrock/request/content[].document.source.s3Location`, `.document.citations`, `.document.context`
/// — a Converse `document` block carries an S3 source plus citation-enable and context members that
/// have no neutral-IR home. They ride the positional verbatim stash so a same-protocol hop re-emits
/// the whole block intact (the modelled `Media` block is suppressed to avoid a double emit).
#[test]
fn bedrock_carry_request_document_provider_fields() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"text": "read this"},
            {"document": {
                "format": "pdf",
                "name": "spec",
                "source": {"s3Location": {"uri": "s3://b/spec.pdf"}},
                "citations": {"enabled": true},
                "context": "a quarterly memo"
            }}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    let doc = out
        .pointer("/messages/0/content/1/document")
        .unwrap_or_else(|| panic!("document block must re-emit exactly once; got {out}"));
    assert_eq!(
        doc.pointer("/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://b/spec.pdf"),
        "document.source.s3Location must round-trip; got {out}"
    );
    assert_eq!(
        doc.pointer("/citations/enabled").and_then(|v| v.as_bool()),
        Some(true),
        "document.citations must round-trip; got {out}"
    );
    assert_eq!(
        doc.pointer("/context").and_then(|v| v.as_str()),
        Some("a quarterly memo"),
        "document.context must round-trip; got {out}"
    );
    // The block must be emitted EXACTLY once (verbatim stash XOR modelled projection).
    let docs = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .map(|a| a.iter().filter(|b| b.get("document").is_some()).count());
    assert_eq!(
        docs,
        Some(1),
        "document must be emitted exactly once; got {out}"
    );
}

/// `bedrock/request/content[].video.source.s3Location` — a Converse `video` block with an S3 source.
/// Rides the same positional verbatim stash as `document`, re-emitting `source.s3Location` intact.
#[test]
fn bedrock_carry_request_video_s3_location() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"text": "watch"},
            {"video": {"format": "mp4", "source": {"s3Location": {"uri": "s3://b/clip.mp4"}}}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    assert_eq!(
        out.pointer("/messages/0/content/1/video/source/s3Location/uri")
            .and_then(|v| v.as_str()),
        Some("s3://b/clip.mp4"),
        "video.source.s3Location.uri must round-trip; got {out}"
    );
}

/// `bedrock/request/content[].cachePoint.type` — an inline prompt-cache breakpoint. The native
/// marker (with its `type`) is captured at its original array position and re-spliced on a
/// same-protocol hop.
#[test]
fn bedrock_carry_request_cache_point() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"text": "cache the prefix"},
            {"cachePoint": {"type": "default"}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("content array");
    let cp = content
        .iter()
        .find_map(|b| b.pointer("/cachePoint/type").and_then(|v| v.as_str()));
    assert_eq!(
        cp,
        Some("default"),
        "cachePoint.type must round-trip at its position; got {out}"
    );
}

/// `bedrock/request/content[].guardContent` — an inline Guardrails span. Bedrock-specific; captured
/// at its original array position and re-spliced on a same-protocol hop (disabling it silently would
/// turn a customer's guardrail off while the request still looked accepted).
#[test]
fn bedrock_carry_request_guard_content() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": [
            {"text": "hi"},
            {"guardContent": {"text": {"text": "screen me", "qualifiers": ["grounding_source"]}}}
        ]}]
    });
    let ir = reader.read_request(&body).expect("read");
    let out = writer.write_request(&ir);
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("content array");
    let gc = content.iter().find_map(|b| {
        b.pointer("/guardContent/text/text")
            .and_then(|v| v.as_str())
    });
    assert_eq!(
        gc,
        Some("screen me"),
        "guardContent must round-trip at its position; got {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE — cross-protocol-meaningful fields
// ─────────────────────────────────────────────────────────────────────────────

/// `bedrock/response/output.message.role`, `bedrock/response/output.message.content` and
/// `bedrock/response/stopReason` — the response envelope must reach the neutral `IrResponse` (role,
/// content blocks, typed stop reason) and re-emit natively (`tool_use` reverses byte-exact).
#[test]
fn bedrock_carry_response_output_and_stop_reason() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [
            {"text": "on it"},
            {"toolUse": {"toolUseId": "t1", "name": "go", "input": {}}}
        ]}},
        "stopReason": "tool_use",
        "usage": {"inputTokens": 3, "outputTokens": 4, "totalTokens": 7}
    });
    let resp = reader.read_response(&body).expect("read");
    // output.message.role
    assert_eq!(
        resp.role,
        crate::ir::IrRole::Assistant,
        "output.message.role must reach IrResponse.role"
    );
    // output.message.content
    assert_eq!(
        resp.content.len(),
        2,
        "output.message.content must reach IrResponse.content"
    );
    assert!(
        matches!(&resp.content[0], crate::ir::IrBlock::Text { text, .. } if text == "on it"),
        "output.message.content[0] must reach IrResponse.content"
    );
    // stopReason
    assert_eq!(
        resp.stop_reason,
        Some(crate::ir::IrStopReason::ToolUse),
        "stopReason `tool_use` must reach IrResponse.stop_reason"
    );

    let out = writer.write_response(&resp);
    assert_eq!(
        out.pointer("/output/message/role").and_then(|v| v.as_str()),
        Some("assistant"),
        "output.message.role must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/output/message/content/0/text")
            .and_then(|v| v.as_str()),
        Some("on it"),
        "output.message.content must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/stopReason").and_then(|v| v.as_str()),
        Some("tool_use"),
        "stopReason must re-emit; got {out}"
    );
}

/// `bedrock/response/usage.{inputTokens,outputTokens,totalTokens,cacheReadInputTokens,
/// cacheWriteInputTokens}` — the whole token-usage vector, including Bedrock's ADDITIVE cache
/// buckets, must reach `IrUsage` (billing-reconcilable) and re-emit natively. `totalTokens` is
/// re-derived by the writer.
#[test]
fn bedrock_carry_response_usage() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {
            "inputTokens": 100,
            "outputTokens": 25,
            "totalTokens": 125,
            "cacheReadInputTokens": 40,
            "cacheWriteInputTokens": 10
        }
    });
    let resp = reader.read_response(&body).expect("read");
    assert_eq!(
        resp.usage.input_tokens, 100,
        "usage.inputTokens must reach IrUsage"
    );
    assert_eq!(
        resp.usage.output_tokens, 25,
        "usage.outputTokens must reach IrUsage"
    );
    assert_eq!(
        resp.usage.cache_read_input_tokens,
        Some(40),
        "usage.cacheReadInputTokens must reach IrUsage"
    );
    assert_eq!(
        resp.usage.cache_creation_input_tokens,
        Some(10),
        "usage.cacheWriteInputTokens must reach IrUsage.cache_creation_input_tokens"
    );

    let out = writer.write_response(&resp);
    assert_eq!(
        out.pointer("/usage/inputTokens").and_then(|v| v.as_u64()),
        Some(100),
        "usage.inputTokens must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/usage/outputTokens").and_then(|v| v.as_u64()),
        Some(25),
        "usage.outputTokens must re-emit; got {out}"
    );
    // totalTokens is re-derived by the writer (input + output).
    assert_eq!(
        out.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
        Some(125),
        "usage.totalTokens must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/usage/cacheReadInputTokens")
            .and_then(|v| v.as_u64()),
        Some(40),
        "usage.cacheReadInputTokens must re-emit; got {out}"
    );
    assert_eq!(
        out.pointer("/usage/cacheWriteInputTokens")
            .and_then(|v| v.as_u64()),
        Some(10),
        "usage.cacheWriteInputTokens must re-emit; got {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE — provider-specific fields
// ─────────────────────────────────────────────────────────────────────────────

/// `bedrock/response/metrics.latencyMs` — a native Converse response always carries the request
/// latency. The writer omits it in `write_response` (timing is unknown there) and INJECTS the proxy's
/// own measured wall-clock via `inject_response_metrics`, so the field survives to the client (as
/// busbar's real latency, not a fabricated `0`).
#[test]
fn bedrock_carry_response_metrics_latency_ms() {
    let writer = BedrockWriter;
    let mut value = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}
    });
    writer.inject_response_metrics(&mut value, Some(137));
    assert_eq!(
        value.pointer("/metrics/latencyMs").and_then(|v| v.as_u64()),
        Some(137),
        "metrics.latencyMs must be emitted from the measured elapsed time; got {value}"
    );
    // And the never-fabricate-a-tell rule: absent timing omits the field rather than emitting 0.
    let mut value2 = serde_json::json!({"output": {}});
    writer.inject_response_metrics(&mut value2, None);
    assert!(
        value2.pointer("/metrics/latencyMs").is_none(),
        "metrics.latencyMs must be OMITTED (not fabricated as 0) when timing is unavailable; got {value2}"
    );
}

/// `bedrock/response/trace.guardrail` and `bedrock/response/trace.promptRouter` — Bedrock-only
/// diagnostic members with NO neutral-IR carrier and no equivalent in any other protocol. DOCUMENTED
/// cross-protocol drop (never waived): a Bedrock backend response feeding a non-Bedrock client loses
/// them. The reader warns; this pins the drop in both the Bedrock re-emit and a foreign egress.
#[test]
fn bedrock_carry_response_trace_documented_drop() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "trace": {
            "guardrail": {"modelOutput": ["blocked"]},
            "promptRouter": {"invokedModelId": "arn:aws:...:model/x"}
        }
    });
    let resp = reader.read_response(&body).expect("read");
    let out = writer.write_response(&resp);
    assert!(
        out.pointer("/trace").is_none(),
        "trace (guardrail + promptRouter) has no cross-protocol carrier and must drop; got {out}"
    );
    // Cross-protocol egress likewise carries neither.
    if let Some(anthropic) = super::super::proto_codec::protocol_for("anthropic") {
        let a = anthropic.writer().write_response(&resp);
        assert!(
            a.to_string().find("promptRouter").is_none()
                && a.to_string().find("guardrail").is_none(),
            "trace members must not leak onto a foreign egress; got {a}"
        );
    }
}

/// `bedrock/response/additionalModelResponseFields` — model-specific echoed fields with no
/// neutral-IR carrier. DOCUMENTED cross-protocol drop; the reader warns.
#[test]
fn bedrock_carry_response_additional_model_response_fields_documented_drop() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "additionalModelResponseFields": {"foo": "bar"}
    });
    let resp = reader.read_response(&body).expect("read");
    let out = writer.write_response(&resp);
    assert!(
        out.pointer("/additionalModelResponseFields").is_none(),
        "additionalModelResponseFields has no cross-protocol carrier and must drop; got {out}"
    );
}

/// `bedrock/response/performanceConfig` — the echoed latency/cost selector with no neutral-IR
/// carrier. DOCUMENTED cross-protocol drop; the reader warns.
#[test]
fn bedrock_carry_response_performance_config_documented_drop() {
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let body = serde_json::json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        "performanceConfig": {"latency": "optimized"}
    });
    let resp = reader.read_response(&body).expect("read");
    let out = writer.write_response(&resp);
    assert!(
        out.pointer("/performanceConfig").is_none(),
        "response performanceConfig has no cross-protocol carrier and must drop; got {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE STREAM — the binary eventstream frame types (read + write)
// ─────────────────────────────────────────────────────────────────────────────

/// `bedrock/response/stream:{messageStart,contentBlockStart,contentBlockDelta,contentBlockStop,
/// messageStop,metadata}` — every frame type of Bedrock's ConverseStream must decode into the
/// neutral `IrStreamEvent` sequence (so a cross-protocol ingress sees native stream events) AND
/// re-encode from the IR into its native frame type. Each frame carries its own read+write assertion.
#[test]
fn bedrock_carry_stream_frame_types() {
    use crate::ir::{IrDelta, IrStreamEvent};
    let reader = BedrockReader;
    let writer = BedrockWriter;
    let mut state = crate::ir::StreamDecodeState::default();

    // ---- READ: each native frame → the expected IR event -----------------------------------
    // messageStart
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStart", "role": "assistant"}),
        &mut state,
    );
    assert!(
        matches!(ev.first(), Some(IrStreamEvent::MessageStart { role, .. }) if *role == crate::ir::IrRole::Assistant),
        "stream:messageStart must decode to IrStreamEvent::MessageStart; got {ev:?}"
    );

    // contentBlockStart (toolUse — the only native ContentBlockStart$start member)
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockStart",
            "contentBlockIndex": 0,
            "start": {"toolUse": {"toolUseId": "t1", "name": "go"}}
        }),
        &mut state,
    );
    assert!(
        matches!(
            ev.first(),
            Some(IrStreamEvent::BlockStart { block: crate::ir::IrBlockMeta::ToolUse { name, .. }, .. }) if name == "go"
        ),
        "stream:contentBlockStart must decode to a ToolUse BlockStart; got {ev:?}"
    );

    // contentBlockDelta (tool input json delta)
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({
            "type": "contentBlockDelta",
            "contentBlockIndex": 0,
            "delta": {"toolUse": {"input": "{\"q\":"}}
        }),
        &mut state,
    );
    assert!(
        matches!(ev.first(), Some(IrStreamEvent::BlockDelta { delta: IrDelta::InputJsonDelta(s), .. }) if s == "{\"q\":"),
        "stream:contentBlockDelta must decode to a BlockDelta; got {ev:?}"
    );

    // contentBlockStop
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        &mut state,
    );
    assert!(
        matches!(ev.first(), Some(IrStreamEvent::BlockStop { index: 0 })),
        "stream:contentBlockStop must decode to a BlockStop; got {ev:?}"
    );

    // messageStop — its stopReason is BUFFERED and paired with the following metadata usage.
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({"type": "messageStop", "stopReason": "tool_use"}),
        &mut state,
    );
    assert!(
        ev.is_empty(),
        "stream:messageStop buffers its stopReason for the metadata frame; got {ev:?}"
    );

    // metadata — emits the combined MessageDelta (buffered stopReason + usage) then MessageStop.
    let ev = reader.read_response_events(
        "",
        &serde_json::json!({"type": "metadata", "usage": {"inputTokens": 9, "outputTokens": 3}}),
        &mut state,
    );
    assert!(
        matches!(
            ev.first(),
            Some(IrStreamEvent::MessageDelta { stop_reason: Some(crate::ir::IrStopReason::ToolUse), usage, .. })
                if usage.input_tokens == 9 && usage.output_tokens == 3
        ),
        "stream:metadata must decode to the combined MessageDelta (buffered stopReason + usage); got {ev:?}"
    );
    assert!(
        matches!(ev.get(1), Some(IrStreamEvent::MessageStop)),
        "stream:metadata must also emit the terminal MessageStop; got {ev:?}"
    );

    // ---- WRITE: each IR event → its native frame type --------------------------------------
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .map(|(t, _)| t),
        Some("messageStart".to_string()),
        "IrStreamEvent::MessageStart must write a messageStart frame"
    );
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "t1".into(),
                    name: "go".into()
                },
            })
            .map(|(t, _)| t),
        Some("contentBlockStart".to_string()),
        "a ToolUse BlockStart must write a contentBlockStart frame"
    );
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::TextDelta("hi".into()),
            })
            .map(|(t, _)| t),
        Some("contentBlockDelta".to_string()),
        "a BlockDelta must write a contentBlockDelta frame"
    );
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .map(|(t, _)| t),
        Some("contentBlockStop".to_string()),
        "a BlockStop must write a contentBlockStop frame"
    );
    // A stop-only MessageDelta writes messageStop; a usage-only one writes metadata (the two native
    // frames the IR's single combined delta fans out to on a Bedrock ingress).
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some(crate::ir::IrStopReason::ToolUse),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                    detail: crate::ir::IrUsageDetail::default(),
                },
            })
            .map(|(t, _)| t),
        Some("messageStop".to_string()),
        "a stop-only MessageDelta must write a messageStop frame"
    );
    assert_eq!(
        writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: None,
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 9,
                    output_tokens: 3,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                    detail: crate::ir::IrUsageDetail::default(),
                },
            })
            .map(|(t, _)| t),
        Some("metadata".to_string()),
        "a usage-only MessageDelta must write a metadata frame"
    );
}
