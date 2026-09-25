// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping (owner directive Q57): a field the Gemini dialect carries that the IR and the other
//! dialect CAN carry must map, never drop. One probe per defect id of the IR mapping audit
//! (`GEM-nn`), driven through the production seam: reader → `chat_prepare_for_egress` /
//! `chat_prepare_for_ingress` → writer, and `StreamTranslate` for streams.

use super::*;
use serde_json::{json, Value};

/// Cross-protocol REQUEST: `ingress` client body → `egress` backend body, through the seam.
fn xreq(ingress: &'static str, egress: &str, body: &Value) -> Value {
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress");
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress");
    let mut req = ingress_p.reader().read_request(body).expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: egress_p.decl().is_some_and(|d| d.requires_max_tokens),
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
        },
    );
    egress_p.writer().write_request(&req)
}

/// Cross-protocol buffered RESPONSE: `egress` backend body → `ingress` client body.
fn xresp(egress: &str, ingress: &'static str, body: &Value) -> Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress");
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress");
    let mut resp = egress_p
        .reader()
        .read_response(body)
        .expect("read_response");
    crate::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&resp)
}

/// Cross-protocol STREAM: `egress` backend SSE bytes → `ingress` client bytes.
fn xstream(egress: &str, ingress: &str, raw: &str) -> String {
    let mut st = crate::proto_stream::StreamTranslate::new(ingress, egress).expect("translator");
    let mut out = st.feed(raw.as_bytes());
    out.extend(st.finish());
    String::from_utf8(out).expect("utf8")
}

/// The `data:` payloads of an SSE byte stream, parsed.
fn sse_payloads(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

/// Gemini SSE bytes from chunk objects.
fn gemini_sse(chunks: &[Value]) -> String {
    chunks
        .iter()
        .map(|c| format!("data: {c}\n\n"))
        .collect::<String>()
}

/// GEM-08 (reader): a native `functionCall.id` / `functionResponse.id` carries the pair to a
/// foreign backend verbatim, instead of a synthesized id on the call and the NAME on the result.
#[test]
fn gem08_native_call_ids_pair_on_a_foreign_backend() {
    let body = json!({"contents": [
        {"role": "user", "parts": [{"text": "q"}]},
        {"role": "model", "parts": [{"functionCall": {"id": "fc1", "name": "f", "args": {"a": 1}}}]},
        {"role": "user", "parts": [{"functionResponse": {"id": "fc1", "name": "f", "response": {"r": 1}}}]}
    ]});
    let out = xreq("gemini", "openai", &body);
    let msgs = out["messages"].as_array().expect("messages");
    let call_id = msgs
        .iter()
        .find_map(|m| m["tool_calls"][0]["id"].as_str())
        .expect("tool call");
    let result_id = msgs
        .iter()
        .find_map(|m| m["tool_call_id"].as_str())
        .expect("tool result");
    assert_eq!(call_id, "fc1", "{out}");
    assert_eq!(result_id, "fc1", "{out}");

    // Buffered response: the model's `functionCall.id` is the IR tool-use id.
    let resp = json!({"candidates": [{"content": {"role": "model", "parts": [
        {"functionCall": {"id": "fc9", "name": "f", "args": {}}}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}});
    let ir = GeminiReader.read_response(&resp).expect("read");
    assert!(
        matches!(&ir.content[0], crate::ir::IrBlock::ToolUse { id, .. } if id == "fc9"),
        "{:?}",
        ir.content
    );

    // Stream: the same id on the tool block start.
    let raw = gemini_sse(&[
        json!({"candidates": [{"content": {"role": "model", "parts": [
        {"functionCall": {"id": "fc7", "name": "f", "args": {}}}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}, "responseId": "r"}),
    ]);
    let out = xstream("gemini", "openai", &raw);
    let streamed_id = sse_payloads(&out)
        .iter()
        .find_map(|c| {
            c["choices"][0]["delta"]["tool_calls"][0]["id"]
                .as_str()
                .map(str::to_string)
        })
        .expect("streamed tool call id");
    // The OpenAI client sees the id in its native shape, which decodes back to the model's own.
    assert_eq!(
        crate::proto_codec::decode_native_tool_id("openai", &streamed_id).as_deref(),
        Some("fc7"),
        "{out}"
    );
}

/// GEM-02: a Bedrock `{"json": …}` tool result reaches Gemini as the `response` object, not an
/// empty `{"output":""}`.
#[test]
fn gem02_bedrock_json_tool_result_reaches_gemini() {
    let body = json!({"messages": [
        {"role": "user", "content": [{"text": "q"}]},
        {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
        {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [{"json": {"x": 1}}]}}]}
    ]});
    let out = xreq("bedrock", "gemini", &body);
    let fr = out["contents"]
        .as_array()
        .expect("contents")
        .iter()
        .flat_map(|c| c["parts"].as_array().cloned().unwrap_or_default())
        .find_map(|p| p.get("functionResponse").cloned())
        .expect("functionResponse");
    assert_eq!(fr["response"], json!({"x": 1}), "{out}");
}

/// GEM-03: `parametersJsonSchema` is the tool's schema (it used to be ignored: Anthropic got
/// `input_schema: null`).
#[test]
fn gem03_parameters_json_schema_is_the_tool_schema() {
    let schema = json!({"type": "object", "properties": {"x": {"type": "string"}}});
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"functionDeclarations": [{"name": "g", "parametersJsonSchema": schema}]}]});
    let out = xreq("gemini", "anthropic", &body);
    assert_eq!(out["tools"][0]["input_schema"], schema, "{out}");
}

/// GEM-04: `responseJsonSchema` is the JSON-mode schema (it used to be dropped, leaving a bare
/// `json_object`).
#[test]
fn gem04_response_json_schema_carries_to_openai() {
    let schema = json!({"type": "object", "properties": {"n": {"type": "integer"}}});
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema}});
    let out = xreq("gemini", "openai", &body);
    assert_eq!(
        out["response_format"]["json_schema"]["schema"], schema,
        "{out}"
    );
}

/// GEM-05: a failed tool call crosses as Gemini's documented `response.error`, and a Gemini
/// `response.error` crosses as a failed tool result.
#[test]
fn gem05_tool_error_maps_both_ways() {
    let body = json!({"model": "m", "max_tokens": 100, "messages": [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "f", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "is_error": true, "content": "boom"}]}
    ]});
    let out = xreq("anthropic", "gemini", &body);
    let fr = out["contents"][2]["parts"][0]["functionResponse"].clone();
    assert_eq!(fr["response"], json!({"error": "boom"}), "{out}");

    let body = json!({"contents": [
        {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "f", "args": {}}}]},
        {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "f", "response": {"error": "boom"}}}]}
    ]});
    let out = xreq("gemini", "anthropic", &body);
    let result = out["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
        .find(|b| b["type"] == "tool_result")
        .expect("tool_result");
    assert_eq!(result["is_error"], json!(true), "{out}");
}

/// GEM-06: an image a tool returned rides `functionResponse.parts` instead of vanishing.
#[test]
fn gem06_tool_result_image_reaches_gemini() {
    let body = json!({"model": "m", "max_tokens": 100, "messages": [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "shot", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": [
            {"type": "text", "text": "ok"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}}]}]}
    ]});
    let out = xreq("anthropic", "gemini", &body);
    let fr = out["contents"][2]["parts"][0]["functionResponse"].clone();
    assert_eq!(
        fr["parts"],
        json!([{"inlineData": {"mimeType": "image/png", "data": "iVBO"}}]),
        "{out}"
    );
}

/// GEM-07: `functionResponse.parts` (a multimodal result) reaches a foreign backend's tool result.
#[test]
fn gem07_function_response_parts_reach_anthropic() {
    let body = json!({"contents": [
        {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "f", "args": {}}}]},
        {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "f", "response": {"ok": true},
            "parts": [{"inlineData": {"mimeType": "image/png", "data": "iVBO"}}]}}]}
    ]});
    let out = xreq("gemini", "anthropic", &body);
    let result = out["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
        .find(|b| b["type"] == "tool_result")
        .expect("tool_result");
    assert!(
        result["content"]
            .as_array()
            .expect("content")
            .iter()
            .any(|c| c["type"] == "image" && c["source"]["data"] == "iVBO"),
        "{out}"
    );
}

/// GEM-09: Gemini 3's `thinkingLevel` is the effort ask a foreign backend receives.
#[test]
fn gem09_thinking_level_is_the_effort_ask() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"thinkingConfig": {"thinkingLevel": "high"}}});
    let ir = GeminiReader.read_request(&body).expect("read");
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::High
        ))
    );
    let out = xreq("gemini", "openai", &body);
    assert_eq!(out["reasoning_effort"], json!("high"), "{out}");
}

/// GEM-10: a hosted tool (`googleSearch`) is read as a hosted IR tool, not silently lost in the
/// reader; the cross-protocol seam then drops it by name (the neutral kind is IR-11).
#[test]
fn gem10_hosted_tool_is_read_as_hosted() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"googleSearch": {}}, {"functionDeclarations": [{"name": "g", "parameters": {"type": "object"}}]}]});
    let ir = GeminiReader.read_request(&body).expect("read");
    assert!(
        ir.tools
            .iter()
            .any(|t| t.hosted == Some(json!({"googleSearch": {}}))),
        "{:?}",
        ir.tools
    );
    // The function tool beside it still reaches a foreign backend; the hosted one does not.
    let out = xreq("gemini", "openai", &body);
    assert_eq!(out["tools"].as_array().map(Vec::len), Some(1), "{out}");
}

/// GEM-11: an OpenAPI-subset schema (`OBJECT`, `nullable`) reaches a JSON-Schema target as JSON
/// Schema.
#[test]
fn gem11_openapi_schema_normalizes_to_json_schema() {
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"functionDeclarations": [{"name": "g", "parameters": {
            "type": "OBJECT",
            "properties": {"x": {"type": "STRING", "nullable": true, "enum": ["OBJECT"]},
                           "l": {"type": "ARRAY", "items": {"type": "INTEGER"}}},
            "required": ["x"]}}]}]});
    let out = xreq("gemini", "openai", &body);
    assert_eq!(
        out["tools"][0]["function"]["parameters"],
        json!({"type": "object",
               "properties": {"x": {"type": ["string", "null"], "enum": ["OBJECT"]},
                              "l": {"type": "array", "items": {"type": "integer"}}},
               "required": ["x"]}),
        "{out}"
    );
}

/// GEM-12: the AUDIO slices of `promptTokensDetails` / `candidatesTokensDetails` reach OpenAI's
/// `audio_tokens`.
#[test]
fn gem12_audio_token_details_reach_openai() {
    let body = json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 30, "candidatesTokenCount": 8, "totalTokenCount": 38,
            "promptTokensDetails": [{"modality": "TEXT", "tokenCount": 10}, {"modality": "AUDIO", "tokenCount": 20}],
            "candidatesTokensDetails": [{"modality": "AUDIO", "tokenCount": 5}, {"modality": "TEXT", "tokenCount": 3}]}});
    let out = xresp("gemini", "openai", &body);
    assert_eq!(
        out["usage"]["prompt_tokens_details"]["audio_tokens"],
        json!(20),
        "{out}"
    );
    assert_eq!(
        out["usage"]["completion_tokens_details"]["audio_tokens"],
        json!(5),
        "{out}"
    );
    // Attribution only: the billed totals are unchanged.
    assert_eq!(out["usage"]["prompt_tokens"], json!(30), "{out}");
    assert_eq!(out["usage"]["completion_tokens"], json!(8), "{out}");
}

/// GEM-14: a refusal reaches a Gemini client as its policy stop `SAFETY`, not `OTHER`.
#[test]
fn gem14_refusal_is_safety_for_a_gemini_client() {
    let body = json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
        "content": [{"type": "text", "text": "no"}], "stop_reason": "refusal", "stop_sequence": null,
        "usage": {"input_tokens": 1, "output_tokens": 1}});
    let out = xresp("anthropic", "gemini", &body);
    assert_eq!(
        out["candidates"][0]["finishReason"],
        json!("SAFETY"),
        "{out}"
    );
}

/// GEM-15: the image content-policy stops are policy stops, and an unexpected tool call is a failed
/// generation, not an unenumerated `OTHER`.
#[test]
fn gem15_image_policy_and_unexpected_tool_call_stops() {
    use crate::ir::IrStopReason as S;
    for (token, want) in [
        ("IMAGE_PROHIBITED_CONTENT", S::Safety),
        ("IMAGE_RECITATION", S::Safety),
        ("UNEXPECTED_TOOL_CALL", S::Error),
    ] {
        let body = json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "x"}]},
            "finishReason": token}], "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}});
        let ir = GeminiReader.read_response(&body).expect("read");
        assert_eq!(ir.stop_reason, Some(want), "{token}");
    }
    let body = json!({"promptFeedback": {"blockReason": "IMAGE_SAFETY"},
        "usageMetadata": {"promptTokenCount": 1}});
    let ir = GeminiReader.read_response(&body).expect("read");
    assert_eq!(ir.stop_reason, Some(S::Safety));
}

/// GEM-16 (writer): a streamed foreign citation's CHARACTER offsets become Gemini's candidate-wide
/// BYTE offsets, as they do on the buffered path.
#[test]
fn gem16_streamed_citation_offsets_are_bytes_for_a_gemini_client() {
    let writer = GeminiWriter;
    // "héllo " is 6 characters and 7 bytes; "wörld" is 5 characters and 6 bytes.
    let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::Text,
    });
    let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
        index: 0,
        delta: crate::ir::IrDelta::TextDelta("héllo wörld".to_string()),
    });
    let citation = crate::ir::IrCitation {
        kind: Some("url_citation".to_string()),
        cited_text: None,
        title: None,
        url: Some("https://c".to_string()),
        document_index: None,
        start_index: Some(6),
        end_index: Some(11),
        encrypted_index: None,
        raw: None,
    };
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::CitationsDelta(vec![citation]),
        })
        .expect("citation frame");
    let src = &frame["candidates"][0]["citationMetadata"]["citationSources"][0];
    assert_eq!(src["startIndex"], json!(7), "{frame}");
    assert_eq!(src["endIndex"], json!(13), "{frame}");
}

/// GEM-18: Vertex's `createTime` is the `created` a foreign client sees, not a seam-stamped now.
#[test]
fn gem18_create_time_is_created() {
    let body = json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
        "createTime": "2025-06-01T12:34:56.789012Z"});
    let out = xresp("gemini", "openai", &body);
    assert_eq!(out["created"], json!(1_748_781_296u64), "{out}");
    // An offset spelling of the same instant; a malformed value leaves the seam's stamp.
    for (create_time, want) in [
        ("2025-06-01T14:34:56+02:00", 1_748_781_296u64),
        ("not a time", 1_752_000_000u64),
    ] {
        let mut body = body.clone();
        body["createTime"] = json!(create_time);
        let out = xresp("gemini", "openai", &body);
        assert_eq!(out["created"], json!(want), "{create_time}: {out}");
    }
}

/// GEM-20: a citation Gemini sends after a functionCall closed the text block annotates THAT text
/// block — no new, empty text block is opened beside the still-open tool.
#[test]
fn gem20_late_stream_citation_annotates_the_closed_text_block() {
    let raw = gemini_sse(&[
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hello"}]}}], "responseId": "r", "modelVersion": "g"}),
        json!({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "f", "args": {"a": 1}}}]}}]}),
        json!({"candidates": [{"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "STOP",
            "citationMetadata": {"citationSources": [{"startIndex": 0, "endIndex": 5, "uri": "https://c"}]}}],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1}}),
    ]);
    let out = xstream("gemini", "anthropic", &raw);
    let events = sse_payloads(&out);
    let text_starts: Vec<&Value> = events
        .iter()
        .filter(|e| e["type"] == "content_block_start" && e["content_block"]["type"] == "text")
        .collect();
    assert_eq!(text_starts.len(), 1, "one text block, not two: {out}");
    let text_index = &text_starts[0]["index"];
    let citation = events
        .iter()
        .find(|e| e["type"] == "content_block_delta" && e["delta"]["type"] == "citations_delta")
        .expect("citation delta");
    assert_eq!(&citation["index"], text_index, "{out}");
}

/// GEM-01: with no native ids, every tool result pairs with the call it answers — positionally,
/// same-name parallel calls included — so Anthropic / OpenAI see no orphan `tool_result` (they used
/// to get a synthesized id on the call and the function NAME on the result).
#[test]
fn gem01_tool_results_pair_with_their_calls_without_ids() {
    let body = json!({"contents": [
        {"role": "user", "parts": [{"text": "q"}]},
        {"role": "model", "parts": [
            {"functionCall": {"name": "f", "args": {"a": 1}}},
            {"functionCall": {"name": "f", "args": {"a": 2}}},
            {"functionCall": {"name": "g", "args": {}}}]},
        {"role": "user", "parts": [
            {"functionResponse": {"name": "f", "response": {"r": 1}}},
            {"functionResponse": {"name": "g", "response": {"r": 3}}},
            {"functionResponse": {"name": "f", "response": {"r": 2}}}]},
        {"role": "model", "parts": [{"functionCall": {"name": "f", "args": {"a": 4}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "f", "response": {"r": 4}}}]}
    ]});
    let out = xreq("gemini", "anthropic", &body);
    let blocks: Vec<Value> = out["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
        .collect();
    let uses: Vec<&str> = blocks
        .iter()
        .filter(|b| b["type"] == "tool_use")
        .filter_map(|b| b["id"].as_str())
        .collect();
    let results: Vec<&str> = blocks
        .iter()
        .filter(|b| b["type"] == "tool_result")
        .filter_map(|b| b["tool_use_id"].as_str())
        .collect();
    assert_eq!(uses.len(), 4, "{out}");
    assert_eq!(
        results,
        vec![uses[0], uses[2], uses[1], uses[3]],
        "each result pairs with its own call: {out}"
    );

    // The same pairing reaches OpenAI's `tool_call_id`.
    let out = xreq("gemini", "openai", &body);
    let msgs = out["messages"].as_array().expect("messages");
    let calls: Vec<String> = msgs
        .iter()
        .flat_map(|m| m["tool_calls"].as_array().cloned().unwrap_or_default())
        .filter_map(|c| c["id"].as_str().map(str::to_string))
        .collect();
    let answered: Vec<String> = msgs
        .iter()
        .filter_map(|m| m["tool_call_id"].as_str().map(str::to_string))
        .collect();
    assert_eq!(calls.len(), 4, "{out}");
    assert_eq!(
        answered,
        vec![
            calls[0].clone(),
            calls[2].clone(),
            calls[1].clone(),
            calls[3].clone()
        ],
        "{out}"
    );
}

/// GEM-08 (writer): an IR call id reaches Gemini as `functionCall.id` — on a request (with the
/// matching `functionResponse.id`), a buffered response and a stream — so the pair survives a
/// round-trip through a Gemini client or backend.
#[test]
fn gem08_call_ids_reach_gemini() {
    let body = json!({"model": "m", "max_tokens": 100, "messages": [
        {"role": "user", "content": "q"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "f", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]}
    ]});
    let out = xreq("anthropic", "gemini", &body);
    assert_eq!(
        out["contents"][1]["parts"][0]["functionCall"]["id"],
        json!("toolu_1"),
        "{out}"
    );
    assert_eq!(
        out["contents"][2]["parts"][0]["functionResponse"]["id"],
        json!("toolu_1"),
        "{out}"
    );

    let resp = json!({"id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": null, "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}});
    let out = xresp("openai", "gemini", &resp);
    assert_eq!(
        out["candidates"][0]["content"]["parts"][0]["functionCall"]["id"],
        json!("call_1"),
        "{out}"
    );

    let writer = GeminiWriter;
    let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::ToolUse {
            id: "call_9".to_string(),
            name: "f".to_string(),
        },
    });
    let (_, frame) = writer
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("functionCall frame");
    assert_eq!(
        frame["candidates"][0]["content"]["parts"][0]["functionCall"]["id"],
        json!("call_9"),
        "{frame}"
    );
}
