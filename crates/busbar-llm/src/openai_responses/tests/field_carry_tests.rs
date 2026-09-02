// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIELD-COVERAGE CARRY INSTRUMENTS for the `responses` (OpenAI Responses API) dialect.
//!
//! Every test here is named by a `carried <fn>` line in `qa/field-coverage.status`, and each is a
//! genuine WATCHER: it drives a real read→IR→write hop (or a same-protocol byte-identity check, or a
//! documented drop+warn) and asserts the named field SURVIVES. If a future edit drops or ignores the
//! field, the corresponding assertion fails. A field with no target equivalent is carried as a
//! documented drop+warn+test (per the owner ruling: ZERO waivers), never silently and never waived.

use super::*;
use busbar_core::test_support::warn_capture::WarnCapture;
use tracing_subscriber::layer::SubscriberExt as _;

// ─────────────────────────────────────── helpers ───────────────────────────────────────

fn read_req(body: &serde_json::Value) -> crate::ir::IrRequest {
    ResponsesReader
        .read_request(body)
        .expect("read_request should succeed")
}

fn write_req(ir: &crate::ir::IrRequest) -> serde_json::Value {
    // Bind the interior-mutable const to a local before borrowing (clippy::borrow_interior_mutable_const).
    let w = ResponsesWriter;
    w.write_request(ir)
}

/// Read a request JSON, translate to IR, and write it back on the SAME dialect — the round-trip a
/// same-protocol Responses→Responses hop performs. Returns the re-emitted request body.
fn roundtrip_req(body: &serde_json::Value) -> serde_json::Value {
    write_req(&read_req(body))
}

/// Every content-part object across the written `input` array (flattening message `content[]` and
/// the flat top-level tool/reasoning items), so an assertion can look for one by shape.
fn input_parts(body: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for item in body
        .get("input")
        .and_then(|i| i.as_array())
        .into_iter()
        .flatten()
    {
        if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
            for part in content {
                out.push(part.clone());
            }
        } else {
            out.push(item.clone());
        }
    }
    out
}

/// The first input part whose `type` equals `ty`.
fn part_of_type(body: &serde_json::Value, ty: &str) -> Option<serde_json::Value> {
    input_parts(body)
        .into_iter()
        .find(|p| p.get("type").and_then(|t| t.as_str()) == Some(ty))
}

fn usage(input: u64, output: u64) -> crate::ir::IrUsage {
    crate::ir::IrUsage {
        input_tokens: input,
        output_tokens: output,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
        detail: crate::ir::IrUsageDetail::default(),
    }
}

fn mk_response(
    content: Vec<crate::ir::IrBlock>,
    stop: Option<crate::ir::IrStopReason>,
) -> crate::ir::IrResponse {
    crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content,
        stop_reason: stop,
        usage: usage(3, 5),
        model: Some("gpt-carry".to_string()),
        id: Some("resp_carry".to_string()),
        created: Some(1_700_000_000),
        system_fingerprint: None,
        stop_sequence: None,
    }
}

fn write_response(resp: &crate::ir::IrResponse) -> serde_json::Value {
    // Bind the interior-mutable const to a local before borrowing (clippy::borrow_interior_mutable_const).
    let w = ResponsesWriter;
    w.write_response(resp)
}

fn text_block(text: &str) -> crate::ir::IrBlock {
    crate::ir::IrBlock::Text {
        text: text.to_string(),
        cache_control: None,
        citations: Vec::new(),
    }
}

/// Run `f` with a warn-capturing subscriber and return whatever it produced plus the capture.
fn with_warns<T>(f: impl FnOnce() -> T) -> (T, WarnCapture) {
    let cap = WarnCapture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(sub, f);
    (out, cap)
}

/// Emit `ev` through `w` and return the ordered wire event-type names.
fn event_names(w: &ResponsesWriter, ev: crate::ir::IrStreamEvent) -> Vec<String> {
    w.write_response_events(&ev)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

// ─────────────────────────── request: core modeled fields ───────────────────────────

/// responses/request/{model,input,instructions,max_output_tokens,temperature,top_p,stream}
#[test]
fn responses_request_core_fields_survive_roundtrip() {
    let body = serde_json::json!({
        "model": "gpt-4.1-mini",
        "instructions": "You are terse.",
        "input": [{ "type": "input_text", "text": "ping" }],
        "max_output_tokens": 321,
        "temperature": 0.42,
        "top_p": 0.77,
        "stream": true
    });
    let out = roundtrip_req(&body);

    assert_eq!(out["model"], "gpt-4.1-mini", "model must survive: {out}");
    assert_eq!(
        out["instructions"], "You are terse.",
        "instructions must survive: {out}"
    );
    // input: the user turn's text reaches the re-emitted `input` array.
    assert!(
        input_parts(&out)
            .iter()
            .any(|p| p.get("text").and_then(|t| t.as_str()) == Some("ping")),
        "input turn must survive: {out}"
    );
    assert_eq!(
        out["max_output_tokens"], 321,
        "max_output_tokens must survive: {out}"
    );
    assert_eq!(out["temperature"], 0.42, "temperature must survive: {out}");
    assert_eq!(out["top_p"], 0.77, "top_p must survive: {out}");
    assert_eq!(out["stream"], true, "stream must survive: {out}");
}

/// responses/request/{tools,tool_choice,parallel_tool_calls}
#[test]
fn responses_request_tools_survive_roundtrip() {
    let body = serde_json::json!({
        "input": [{ "type": "input_text", "text": "go" }],
        "tools": [{
            "type": "function",
            "name": "lookup",
            "description": "look it up",
            "parameters": { "type": "object", "properties": { "q": { "type": "string" } } },
            "strict": true
        }],
        "tool_choice": { "type": "function", "name": "lookup" },
        "parallel_tool_calls": false
    });
    let out = roundtrip_req(&body);

    let tool = out["tools"]
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .expect("a tool must survive");
    assert_eq!(tool["type"], "function", "tool type: {out}");
    assert_eq!(tool["name"], "lookup", "tool name must survive: {out}");
    assert!(
        tool["parameters"]["properties"]["q"].is_object(),
        "tool parameters must survive: {out}"
    );
    assert_eq!(tool["strict"], true, "tool strict must survive: {out}");

    // tool_choice: a targeted function directive re-emits in the FLAT Responses shape.
    assert_eq!(out["tool_choice"]["type"], "function", "tool_choice: {out}");
    assert_eq!(
        out["tool_choice"]["name"], "lookup",
        "tool_choice target name must survive: {out}"
    );

    assert_eq!(
        out["parallel_tool_calls"], false,
        "parallel_tool_calls must survive: {out}"
    );
}

/// responses/request/{text.format,text.verbosity}
#[test]
fn responses_request_text_format_and_verbosity_survive_roundtrip() {
    let body = serde_json::json!({
        "input": [{ "type": "input_text", "text": "structured" }],
        "text": {
            "format": {
                "type": "json_schema",
                "name": "Weather",
                "schema": { "type": "object", "properties": { "t": { "type": "number" } } },
                "strict": true
            },
            "verbosity": "high"
        }
    });
    let out = roundtrip_req(&body);

    // text.format: the flat json_schema shape survives.
    assert_eq!(
        out["text"]["format"]["type"], "json_schema",
        "text.format.type must survive: {out}"
    );
    assert_eq!(
        out["text"]["format"]["name"], "Weather",
        "text.format.name must survive: {out}"
    );
    assert!(
        out["text"]["format"]["schema"]["properties"]["t"].is_object(),
        "text.format.schema must survive: {out}"
    );
    assert_eq!(
        out["text"]["format"]["strict"], true,
        "text.format.strict must survive: {out}"
    );
    // text.verbosity: a non-`format` `text` sub-key busbar does not model must survive via extra.
    assert_eq!(
        out["text"]["verbosity"], "high",
        "text.verbosity must survive alongside format: {out}"
    );
}

/// responses/request/{reasoning.effort,reasoning.summary}
#[test]
fn responses_request_reasoning_survives_roundtrip() {
    let body = serde_json::json!({
        "input": [{ "type": "input_text", "text": "think" }],
        "reasoning": { "effort": "high", "summary": "auto" }
    });
    let out = roundtrip_req(&body);

    // The verbatim `reasoning` object (effort + summary) round-trips through `extra`.
    assert_eq!(
        out["reasoning"]["effort"], "high",
        "reasoning.effort must survive: {out}"
    );
    assert_eq!(
        out["reasoning"]["summary"], "auto",
        "reasoning.summary must survive: {out}"
    );
}

/// responses/request/{max_tool_calls,top_logprobs,store,stream_options,truncation,include,metadata,
/// prompt,prompt_cache_key,safety_identifier,service_tier,background,user} — provider-specific knobs
/// with no cross-protocol target, carried LOSSLESS SAME-PROTOCOL via the pass-through `extra` map.
#[test]
fn responses_request_provider_specific_fields_survive_same_protocol() {
    let body = serde_json::json!({
        "input": [{ "type": "input_text", "text": "x" }],
        "max_tool_calls": 4,
        "top_logprobs": 3,
        "store": false,
        "stream_options": { "include_usage": true },
        "truncation": "auto",
        "include": ["reasoning.encrypted_content"],
        "metadata": { "trace": "abc123" },
        "prompt": { "id": "pmpt_1", "version": "2" },
        "prompt_cache_key": "cache-key-9",
        "safety_identifier": "user-hash-7",
        "service_tier": "priority",
        "background": true,
        "user": "end-user-5"
    });
    let out = roundtrip_req(&body);

    assert_eq!(out["max_tool_calls"], 4, "max_tool_calls: {out}");
    assert_eq!(out["top_logprobs"], 3, "top_logprobs: {out}");
    assert_eq!(out["store"], false, "store: {out}");
    assert_eq!(
        out["stream_options"]["include_usage"], true,
        "stream_options: {out}"
    );
    assert_eq!(out["truncation"], "auto", "truncation: {out}");
    assert_eq!(
        out["include"][0], "reasoning.encrypted_content",
        "include: {out}"
    );
    assert_eq!(out["metadata"]["trace"], "abc123", "metadata: {out}");
    assert_eq!(out["prompt"]["id"], "pmpt_1", "prompt: {out}");
    assert_eq!(
        out["prompt_cache_key"], "cache-key-9",
        "prompt_cache_key: {out}"
    );
    assert_eq!(
        out["safety_identifier"], "user-hash-7",
        "safety_identifier: {out}"
    );
    assert_eq!(out["service_tier"], "priority", "service_tier: {out}");
    assert_eq!(out["background"], true, "background: {out}");
    assert_eq!(out["user"], "end-user-5", "user: {out}");
}

// ─────────────────────────── request: content parts ───────────────────────────

/// responses/request/content[].type={input_text.text,output_text.text,input_image.image_url,
/// input_image.file_id}
#[test]
fn responses_request_content_parts_survive_roundtrip() {
    let body = serde_json::json!({
        "input": [
            { "type": "input_text", "text": "user says hi" },
            { "type": "input_image", "image_url": "data:image/png;base64,QUJD" },
            { "type": "input_image", "file_id": "file-42" },
            { "type": "output_text", "text": "assistant said hi" }
        ]
    });
    let out = roundtrip_req(&body);
    let parts = input_parts(&out);

    assert!(
        parts.iter().any(
            |p| p.get("type").and_then(|t| t.as_str()) == Some("input_text")
                && p.get("text").and_then(|t| t.as_str()) == Some("user says hi")
        ),
        "input_text.text must survive: {out}"
    );
    assert!(
        parts.iter().any(
            |p| p.get("type").and_then(|t| t.as_str()) == Some("output_text")
                && p.get("text").and_then(|t| t.as_str()) == Some("assistant said hi")
        ),
        "output_text.text must survive: {out}"
    );
    assert!(
        parts.iter().any(
            |p| p.get("type").and_then(|t| t.as_str()) == Some("input_image")
                && p.get("image_url").and_then(|u| u.as_str())
                    == Some("data:image/png;base64,QUJD")
        ),
        "input_image.image_url must survive: {out}"
    );
    assert!(
        parts.iter().any(
            |p| p.get("type").and_then(|t| t.as_str()) == Some("input_image")
                && p.get("file_id").and_then(|f| f.as_str()) == Some("file-42")
        ),
        "input_image.file_id must survive: {out}"
    );
}

/// responses/request/content[].type=input_image.detail — no IR slot and no cross-protocol analog, so
/// carried as a DOCUMENTED DROP+WARN (never silently, never waived). The image itself still survives.
#[test]
fn responses_request_input_image_detail_dropped_with_warn() {
    let body = serde_json::json!({
        "input": [{ "type": "input_image", "image_url": "data:image/png;base64,QUJD", "detail": "high" }]
    });
    let (ir, cap) = with_warns(|| read_req(&body));

    // The image survives (the detail hint is what drops).
    assert!(
        ir.messages
            .iter()
            .flat_map(|m| &m.content)
            .any(|b| matches!(b, crate::ir::IrBlock::Image { .. })),
        "the image block must survive even as detail drops: {:?}",
        ir.messages
    );
    assert!(
        cap.contains("detail"),
        "dropping input_image.detail must warn, naming the field: {:?}",
        cap.messages()
    );
}

/// responses/request/content[].type=output_text.annotations — a prior-turn assistant `output_text`
/// input part's URL-citation annotations are carried into the IR Text block's citations (the same
/// neutral slot the response reader uses), so the citation survives the hop instead of being dropped.
#[test]
fn responses_request_output_text_annotations_survive() {
    let body = serde_json::json!({
        "input": [{
            "type": "output_text",
            "text": "grounded claim",
            "annotations": [
                { "type": "url_citation", "url_citation": { "url": "https://src.example/doc", "title": "Doc" } }
            ]
        }]
    });
    let ir = read_req(&body);

    let carried_url = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .find_map(|b| match b {
            crate::ir::IrBlock::Text { citations, .. } if !citations.is_empty() => {
                citations[0].url.clone()
            }
            _ => None,
        });
    assert_eq!(
        carried_url.as_deref(),
        Some("https://src.example/doc"),
        "output_text.annotations url must be carried into IR citations: {:?}",
        ir.messages
    );
}

// ─────────────────────────── request: flat input items ───────────────────────────

/// responses/request/input[].type={function_call.*,function_call_output.*}
#[test]
fn responses_request_function_call_items_survive_roundtrip() {
    let body = serde_json::json!({
        "input": [
            {
                "type": "function_call",
                "call_id": "call_abc",
                "name": "get_weather",
                "arguments": "{\"city\":\"Paris\"}"
            },
            {
                "type": "function_call_output",
                "call_id": "call_abc",
                "output": "sunny, 21C"
            }
        ]
    });
    let out = roundtrip_req(&body);

    let fc = part_of_type(&out, "function_call").expect("function_call item must survive");
    assert_eq!(fc["call_id"], "call_abc", "function_call.call_id: {out}");
    assert_eq!(fc["name"], "get_weather", "function_call.name: {out}");
    // arguments survive as a JSON string carrying the same object.
    assert_eq!(
        fc["arguments"].as_str().map(|s| s.contains("Paris")),
        Some(true),
        "function_call.arguments must survive: {out}"
    );

    let fco =
        part_of_type(&out, "function_call_output").expect("function_call_output must survive");
    assert_eq!(
        fco["call_id"], "call_abc",
        "function_call_output.call_id: {out}"
    );
    assert_eq!(
        fco["output"], "sunny, 21C",
        "function_call_output.output must survive: {out}"
    );
}

/// responses/request/input[].type=reasoning.{summary,content,encrypted_content}
#[test]
fn responses_request_reasoning_items_survive_roundtrip() {
    let body = serde_json::json!({
        "input": [{
            "type": "reasoning",
            "id": "rs_carrytest_1",
            "summary": [{ "type": "summary_text", "text": "SUMMARY_MARK" }],
            "content": [{ "type": "reasoning_text", "text": "CONTENT_MARK" }],
            "encrypted_content": "ENC_BLOB_MARK"
        }]
    });
    let out = roundtrip_req(&body);

    // A reasoning item is a top-level `input` entry (a sibling of the message), not nested in a
    // message's content — find it directly rather than via the content-flattening helper.
    let rs = out["input"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|it| it.get("type").and_then(|t| t.as_str()) == Some("reasoning"))
        })
        .cloned()
        .expect("reasoning item must survive");
    // The reasoning-text content survives (content array holds the reasoning_text part).
    let content_text = rs["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        content_text.contains("CONTENT_MARK"),
        "reasoning.content text must survive: {out}"
    );
    // Summary text is folded into the reasoning text on the neutral hop, so it survives too.
    assert!(
        content_text.contains("SUMMARY_MARK"),
        "reasoning.summary text must survive the hop: {out}"
    );
    assert_eq!(
        rs["encrypted_content"], "ENC_BLOB_MARK",
        "reasoning.encrypted_content must survive: {out}"
    );
}

/// responses/request/input[].type=reasoning.id — the opaque reasoning-item id has no IR slot and no
/// cross-protocol analog, so it is a DOCUMENTED DROP+WARN (the reasoning text/blob still survive).
#[test]
fn responses_request_reasoning_id_dropped_with_warn() {
    let body = serde_json::json!({
        "input": [{
            "type": "reasoning",
            "id": "rs_carrytest_1",
            "content": [{ "type": "reasoning_text", "text": "deep" }],
            "encrypted_content": "BLOB"
        }]
    });
    let (ir, cap) = with_warns(|| read_req(&body));

    assert!(
        ir.messages
            .iter()
            .flat_map(|m| &m.content)
            .any(|b| matches!(b, crate::ir::IrBlock::Thinking { .. })),
        "the reasoning text/blob must survive even as the id drops: {:?}",
        ir.messages
    );
    assert!(
        cap.contains("rs_carrytest_1"),
        "dropping reasoning-item id must warn, naming the id: {:?}",
        cap.messages()
    );
}

// ─────────────────────────── response: top-level fields ───────────────────────────

/// responses/response/{id,object,created_at,model,status}
#[test]
fn responses_response_identity_fields_emitted() {
    let out = write_response(&mk_response(
        vec![text_block("hi")],
        Some(crate::ir::IrStopReason::EndTurn),
    ));

    assert_eq!(out["id"], "resp_carry", "response.id must survive: {out}");
    assert_eq!(out["object"], "response", "response.object: {out}");
    assert_eq!(
        out["created_at"], 1_700_000_000u64,
        "response.created_at must survive: {out}"
    );
    assert_eq!(
        out["model"], "gpt-carry",
        "response.model must survive: {out}"
    );
    assert_eq!(out["status"], "completed", "response.status: {out}");
}

/// responses/response/{output,output_text}
///
/// `output` is emitted as native message items. `output_text` is the SDK-COMPUTED aggregate of the
/// assistant text across `output[]` — NOT a raw wire field (a native `/v1/responses` body does not
/// serialize it; emitting it would be a distinguishability tell), so its carry is that the underlying
/// text survives in `output[]`, from which any SDK reconstructs `output_text`. This asserts that
/// reconstruction: if the assistant text stops reaching `output[]`, the aggregate is lost.
#[test]
fn responses_response_output_and_output_text_emitted() {
    let out = write_response(&mk_response(
        vec![text_block("Hello "), text_block("world")],
        Some(crate::ir::IrStopReason::EndTurn),
    ));

    let output = out["output"].as_array().expect("output must be an array");
    assert!(
        output
            .iter()
            .any(|it| it.get("type").and_then(|t| t.as_str()) == Some("message")),
        "output must carry message item(s): {out}"
    );

    // Reconstruct `output_text` exactly as an SDK does — concatenate every message part's text.
    let reconstructed: String = output
        .iter()
        .filter(|it| it.get("type").and_then(|t| t.as_str()) == Some("message"))
        .flat_map(|it| it["content"].as_array().cloned().unwrap_or_default())
        .filter(|part| part.get("type").and_then(|t| t.as_str()) == Some("output_text"))
        .filter_map(|part| part.get("text").and_then(|t| t.as_str()).map(String::from))
        .collect();
    assert_eq!(
        reconstructed, "Hello world",
        "output_text (SDK aggregate of output[]) data must survive: {out}"
    );
    // And the tell is NOT emitted: a native body carries no top-level `output_text`.
    assert!(
        out.get("output_text").is_none(),
        "output_text must NOT be a raw wire key (SDK-computed only): {out}"
    );
}

/// responses/response/error
#[test]
fn responses_response_error_field_carried() {
    // Success body: `error` is present-and-null (a REQUIRED nullable member).
    let ok = write_response(&mk_response(
        vec![text_block("hi")],
        Some(crate::ir::IrStopReason::EndTurn),
    ));
    assert!(
        ok.get("error").is_some() && ok["error"].is_null(),
        "a successful response must carry error:null: {ok}"
    );

    // A failed BODY's `error` is READ back into the IR error signal, not masked as success.
    let failed = serde_json::json!({
        "status": "failed",
        "output": [],
        "error": { "code": "rate_limit_exceeded", "message": "slow down" }
    });
    let err = ResponsesReader
        .read_response(&failed)
        .expect_err("a failed body must surface as an error");
    assert_eq!(
        err.provider_signal.as_deref(),
        Some("rate_limit_exceeded"),
        "response.error.code must be read: {err:?}"
    );
}

/// responses/response/incomplete_details
#[test]
fn responses_response_incomplete_details_carried() {
    // Write side: a truncation stop reason renders status incomplete + incomplete_details.reason.
    let out = write_response(&mk_response(
        vec![text_block("partial")],
        Some(crate::ir::IrStopReason::MaxTokens),
    ));
    assert_eq!(
        out["status"], "incomplete",
        "status must be incomplete: {out}"
    );
    assert_eq!(
        out["incomplete_details"]["reason"], "max_output_tokens",
        "incomplete_details.reason must be emitted: {out}"
    );

    // Read side: incomplete_details.reason is decoded into the stop reason.
    let body = serde_json::json!({
        "status": "incomplete",
        "incomplete_details": { "reason": "max_output_tokens" },
        "output": [],
        "usage": { "input_tokens": 1, "output_tokens": 1 }
    });
    let ir = ResponsesReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::MaxTokens),
        "incomplete_details.reason must be read: {ir:?}"
    );
}

/// responses/response/usage.input_tokens_details.cached_tokens
#[test]
fn responses_response_cached_tokens_survive_roundtrip() {
    let body = serde_json::json!({
        "status": "completed",
        "output": [],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "input_tokens_details": { "cached_tokens": 40 },
            "output_tokens_details": { "reasoning_tokens": 0 }
        }
    });
    let ir = ResponsesReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(40),
        "cached_tokens must read into cache_read_input_tokens: {ir:?}"
    );

    let out = write_response(&ir);
    assert_eq!(
        out["usage"]["input_tokens_details"]["cached_tokens"], 40,
        "cached_tokens must re-emit: {out}"
    );
    // And the cache-inclusive input_tokens total is reconstructed (uncached 60 + cached 40).
    assert_eq!(
        out["usage"]["input_tokens"], 100,
        "input_tokens total must include the cached prefix: {out}"
    );
}

/// responses/response/output[].type={message.id,message.status,message.content,reasoning.summary,
/// reasoning.encrypted_content,function_call.call_id,function_call.name,function_call.arguments}
#[test]
fn responses_response_output_items_emitted() {
    let content = vec![
        text_block("answer"),
        crate::ir::IrBlock::ToolUse {
            id: "call_z".to_string(),
            name: "search".to_string(),
            input: serde_json::json!({ "q": "rust" }),
            cache_control: None,
            thought_signature: None,
        },
        crate::ir::IrBlock::Thinking {
            text: "reasoned".to_string(),
            signature: Some("ENC".to_string()),
            redacted: false,
            cache_control: None,
        },
    ];
    let out = write_response(&mk_response(
        content,
        Some(crate::ir::IrStopReason::ToolUse),
    ));
    let output = out["output"].as_array().expect("output array");

    let msg = output
        .iter()
        .find(|it| it["type"] == "message")
        .expect("message item");
    assert!(
        msg["id"].as_str().is_some_and(|s| s.starts_with("msg")),
        "message.id must be emitted: {out}"
    );
    assert_eq!(msg["status"], "completed", "message.status: {out}");
    assert_eq!(
        msg["content"][0]["text"], "answer",
        "message.content must be emitted: {out}"
    );

    let fc = output
        .iter()
        .find(|it| it["type"] == "function_call")
        .expect("function_call item");
    assert_eq!(fc["call_id"], "call_z", "function_call.call_id: {out}");
    assert_eq!(fc["name"], "search", "function_call.name: {out}");
    assert!(
        fc["arguments"].as_str().is_some_and(|s| s.contains("rust")),
        "function_call.arguments: {out}"
    );

    let rs = output
        .iter()
        .find(|it| it["type"] == "reasoning")
        .expect("reasoning item");
    assert!(
        rs["summary"].is_array(),
        "reasoning.summary must be present (array): {out}"
    );
    assert_eq!(
        rs["encrypted_content"], "ENC",
        "reasoning.encrypted_content must survive: {out}"
    );
}

/// responses/response/output[].type=web_search_call.{id,status} — a hosted-tool invocation record
/// with no neutral IR form and no cross-protocol analog: DOCUMENTED DROP+WARN. The assistant's own
/// message/tool/reasoning output is unaffected.
#[test]
fn responses_response_web_search_call_dropped_with_warn() {
    let body = serde_json::json!({
        "status": "completed",
        "output": [
            { "type": "web_search_call", "id": "ws_1", "status": "completed" },
            { "type": "message", "role": "assistant",
              "content": [{ "type": "output_text", "text": "kept", "annotations": [] }] }
        ],
        "usage": { "input_tokens": 1, "output_tokens": 1 }
    });
    let (ir, cap) = with_warns(|| ResponsesReader.read_response(&body).expect("read_response"));

    assert!(
        ir.content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::Text { text, .. } if text == "kept")),
        "the assistant message must survive even as web_search_call drops: {ir:?}"
    );
    assert!(
        cap.contains("web_search_call"),
        "dropping a web_search_call output item must warn, naming the type: {:?}",
        cap.messages()
    );
}

/// responses/response/{instructions,metadata} — the request-echo members a native response carries
/// have no IrResponse slot and no other-protocol analog: DOCUMENTED DROP+WARN on read (the request
/// side of instructions/metadata is separately carried on the request hop).
#[test]
fn responses_response_instructions_metadata_dropped_with_warn() {
    let body = serde_json::json!({
        "status": "completed",
        "instructions": "system prompt echo",
        "metadata": { "trace": "abc" },
        "output": [
            { "type": "message", "role": "assistant",
              "content": [{ "type": "output_text", "text": "hi", "annotations": [] }] }
        ],
        "usage": { "input_tokens": 1, "output_tokens": 1 }
    });
    let (_ir, cap) = with_warns(|| ResponsesReader.read_response(&body).expect("read_response"));

    assert!(
        cap.contains("instructions"),
        "dropping the response instructions echo must warn: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("metadata"),
        "dropping the response metadata echo must warn: {:?}",
        cap.messages()
    );
}

// ─────────────────────────── response: streaming events ───────────────────────────

/// responses/response/stream:{response.created,response.output_item.added,response.output_item.done,
/// response.content_part.added,response.content_part.done,response.output_text.delta,
/// response.output_text.done,response.function_call_arguments.delta,response.completed}
#[test]
fn responses_stream_events_emitted_by_writer() {
    let w = ResponsesWriter;
    let mut seen: Vec<String> = Vec::new();

    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_s".to_string()),
            created: Some(1_700_000_000),
            model: Some("gpt-s".to_string()),
        },
    ));
    // A text part: BlockStart → delta → BlockStop drives the full content-part bracket.
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        },
    ));
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        },
    ));
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockStop { index: 0 },
    ));
    // A function-call part at a distinct index: added → args delta → done.
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_s".to_string(),
                name: "f".to_string(),
            },
        },
    ));
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
        },
    ));
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::BlockStop { index: 1 },
    ));
    seen.extend(event_names(
        &w,
        crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: usage(1, 1),
        },
    ));

    for expected in [
        EVT_RESPONSE_CREATED,
        EVT_OUTPUT_ITEM_ADDED,
        EVT_OUTPUT_ITEM_DONE,
        EVT_CONTENT_PART_ADDED,
        EVT_CONTENT_PART_DONE,
        EVT_OUTPUT_TEXT_DELTA,
        EVT_OUTPUT_TEXT_DONE,
        EVT_FUNCTION_CALL_ARGS_DELTA,
        EVT_RESPONSE_COMPLETED,
    ] {
        assert!(
            seen.iter().any(|n| n == expected),
            "stream event {expected} must be emitted; saw {seen:?}"
        );
    }
}

/// responses/response/stream:response.incomplete
#[test]
fn responses_stream_incomplete_event_emitted() {
    let w = ResponsesWriter;
    let _ = event_names(
        &w,
        crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_i".to_string()),
            created: Some(1),
            model: Some("m".to_string()),
        },
    );
    let names = event_names(
        &w,
        crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
            stop_sequence: None,
            usage: usage(1, 1),
        },
    );
    assert!(
        names.iter().any(|n| n == EVT_RESPONSE_INCOMPLETE),
        "a truncated terminal must emit response.incomplete: {names:?}"
    );
}

/// responses/response/stream:response.failed
#[test]
fn responses_stream_failed_event_emitted() {
    let w = ResponsesWriter;
    let names = event_names(
        &w,
        crate::ir::IrStreamEvent::Error(busbar_substrate::proto::IrError {
            class: busbar_substrate::breaker::StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        }),
    );
    assert!(
        names.iter().any(|n| n == EVT_RESPONSE_FAILED),
        "an Error event must emit response.failed: {names:?}"
    );
}

/// responses/response/stream:response.in_progress — the reader CONSUMES the in-progress lifecycle
/// event (aliased with response.created) to open the translated message.
#[test]
fn responses_stream_in_progress_consumed_by_reader() {
    let mut state = crate::ir::StreamDecodeState::default();
    let data = serde_json::json!({
        "response": { "id": "resp_p", "created_at": 1, "model": "m" }
    });
    let events = ResponsesReader.read_response_events("response.in_progress", &data, &mut state);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageStart { .. })),
        "response.in_progress must open the message: {events:?}"
    );
}

/// responses/response/stream:response.reasoning_summary_text.delta — the reader CONSUMES the
/// reasoning-summary delta event, routing it to the reasoning block as a ThinkingDelta.
#[test]
fn responses_stream_reasoning_summary_delta_consumed_by_reader() {
    let mut state = crate::ir::StreamDecodeState::default();
    let data = serde_json::json!({ "output_index": 0, "delta": "musing" });
    let events = ResponsesReader.read_response_events(
        "response.reasoning_summary_text.delta",
        &data,
        &mut state,
    );
    assert!(
        events.iter().any(|e| matches!(
            e,
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::ThinkingDelta(t),
                ..
            } if t == "musing"
        )),
        "reasoning_summary_text.delta must route to a ThinkingDelta: {events:?}"
    );
}

// Chat#3: a Responses request `top_logprobs` must SURVIVE — both a same-protocol round-trip and a
// cross-protocol hop to the OpenAI Chat dialect (where it forces the enabling `logprobs` flag).
// Pre-fix the reader hardcoded it `None` and it was absent from `responses_modeled_keys`, so it was
// cleared at the seam with no drop-warn — total loss for a Responses caller who set it.
#[test]
fn top_logprobs_carries_responses_roundtrip_and_cross_to_openai() {
    let body = serde_json::json!({"model": "x", "input": "hi", "top_logprobs": 5});

    // (a) same-protocol Responses→Responses re-emits `top_logprobs` verbatim.
    let rt = roundtrip_req(&body);
    assert_eq!(
        rt.get("top_logprobs"),
        Some(&serde_json::json!(5)),
        "top_logprobs must round-trip on the Responses surface: {rt}"
    );

    // (b) cross-protocol Responses→OpenAI-Chat: the ask reaches the OpenAI writer, which emits
    //     `top_logprobs` AND forces `logprobs: true` (OpenAI requires the enabling flag).
    let ir = read_req(&body);
    assert_eq!(
        ir.top_logprobs,
        Some(5),
        "IR must carry the top_logprobs ask"
    );
    let openai = crate::openai_chat::OpenAiWriter.write_request(&ir);
    assert_eq!(
        openai.get("top_logprobs"),
        Some(&serde_json::json!(5)),
        "top_logprobs must survive the cross-protocol hop to OpenAI Chat: {openai}"
    );
    assert_eq!(
        openai.get("logprobs"),
        Some(&serde_json::json!(true)),
        "the OpenAI writer must force the enabling logprobs flag: {openai}"
    );
}

// Chat#4: the Responses create API models none of `frequency_penalty`/`presence_penalty`/`seed`/`n`.
// A cross-protocol source carrying them must have each dropped OBSERVABLY — a per-control `warn!` and
// a `dropped_egress_controls` entry — not silently as before.
#[test]
fn responses_drops_penalties_seed_n_observably() {
    let ir = crate::ir::IrRequest {
        frequency_penalty: Some(0.5),
        presence_penalty: Some(0.25),
        seed: Some(42),
        n: Some(3),
        ..Default::default()
    };
    let (_out, cap) = with_warns(|| write_req(&ir));
    for field in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            cap.contains(field),
            "dropping {field} on Responses egress must warn: {:?}",
            cap.messages()
        );
    }
    // …and each is reported to the cross-protocol seam for audit. Bind the interior-mutable const to a
    // local before borrowing (clippy::borrow_interior_mutable_const), matching `write_req`.
    let w = ResponsesWriter;
    let dropped = w.dropped_egress_controls(&ir);
    for field in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            dropped.contains(&field),
            "{field} must be reported by dropped_egress_controls: {dropped:?}"
        );
    }
}

// ─────────────────────── T3 stateful Responses: previous_response_id / store ───────────────────────

/// responses/request/{previous_response_id,store} — the server-side conversation-state knobs a proxy
/// must carry LOSSLESSLY. Both ride `extra` (busbar is a translator; the upstream owns the state), so a
/// same-protocol Responses→Responses hop re-emits them byte-for-byte. `previous_response_id` threads
/// this turn onto an upstream-stored prior response; `store: true` asks the upstream to persist this
/// response for a later `previous_response_id`.
#[test]
fn responses_stateful_previous_response_id_and_store_survive_same_protocol() {
    let body = serde_json::json!({
        "model": "gpt-4o",
        "input": [{ "type": "input_text", "text": "continue" }],
        "previous_response_id": "resp_prev_9f8e7d",
        "store": true,
    });
    let out = roundtrip_req(&body);
    assert_eq!(
        out["previous_response_id"], "resp_prev_9f8e7d",
        "previous_response_id must round-trip verbatim: {out}"
    );
    assert_eq!(out["store"], true, "store:true must round-trip: {out}");

    // `store: false` is a DISTINCT intent (do not persist) and must not collapse to absent/true.
    let body_false = serde_json::json!({
        "model": "gpt-4o",
        "input": "x",
        "store": false,
    });
    let out_false = roundtrip_req(&body_false);
    assert_eq!(
        out_false["store"], false,
        "store:false must round-trip as false: {out_false}"
    );
}

/// responses/response/id — the STORED-RESPONSE id echo / `response.id` correlation. When a client uses
/// server-side conversation state, THIS response's `id` becomes the NEXT request's
/// `previous_response_id`, so the id must survive a read→IR→write hop unchanged. A native upstream id is
/// carried verbatim (never re-synthesized) so the client's stored linkage is not broken.
#[test]
fn responses_stateful_response_id_correlation_round_trips() {
    let upstream = serde_json::json!({
        "id": "resp_stored_abc123",
        "object": "response",
        "created_at": 1_700_000_500u64,
        "model": "gpt-4o",
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "output_text", "text": "ok" }],
        }],
        "usage": { "input_tokens": 3, "output_tokens": 1 },
    });
    let ir = ResponsesReader
        .read_response(&upstream)
        .expect("read_response ok");
    assert_eq!(
        ir.id.as_deref(),
        Some("resp_stored_abc123"),
        "the upstream stored-response id must be captured into IR for correlation"
    );
    let out = write_response(&ir);
    assert_eq!(
        out["id"], "resp_stored_abc123",
        "the stored-response id must be echoed verbatim so the client's linkage survives: {out}"
    );
}
