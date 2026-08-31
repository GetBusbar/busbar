// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIELD-COVERAGE CARRY TESTS for the Gemini (generateContent) dialect.
//!
//! Each test here is the named instrument behind a `carried` line in `qa/field-coverage.status`:
//! it FAILS if the field it names stops surviving. Two carriage mechanisms, matching the owner's
//! classification:
//!
//! * CROSS-PROTOCOL-MEANINGFUL fields (sampling knobs, systemInstruction, tools, citations, usage
//!   buckets, …): a read → IR → write round trip that asserts the value reaches the IR's typed
//!   carrier AND is re-emitted by the writer. A future edit that drops the promotion, or the
//!   re-emit, turns the assertion red.
//! * PROVIDER-SPECIFIC fields with no cross-protocol home (safetySettings, labels, safetyRatings,
//!   code-execution parts, …): REQUEST-side provider fields ride the reader's `extra` passthrough
//!   and are re-emitted verbatim by the writer, so a same-protocol read → write proves losslessness
//!   AND a cleared-`extra` write proves the cross-protocol drop. RESPONSE-side provider fields have
//!   no IR carrier at all: same-protocol Gemini→Gemini relay is byte-verbatim (never rebuilt from
//!   the IR — generically pinned by `gemini_sse_round_trip_byte_exact`), so these are carried as a
//!   DOCUMENTED DROP — the test pins that the reader neither corrupts them into content nor leaks
//!   them onto a foreign egress, which is the owner-sanctioned carriage for a no-home field.
//!
//! Paths use `super::super::proto_codec` (portable across both `#[path]`-compile shapes) rather than
//! the concrete `StreamTranslate`, which is netted under a different name in each crate.

// `super::super` (not `crate`): this file is `#[path]`-compiled into BOTH busbar-llm (where the
// dialect's parent is the crate root) AND busbar-core's witness test build (where the parent is
// `crate::proto`). `proto_codec` is netted under the same name in both parents, so `super::super`
// resolves in both — the same portability the sibling `logprobs_carry_tests.rs` relies on.
use super::super::proto_codec::Protocol;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — generationConfig sampling knobs (cross-protocol; promoted into typed IR)
// ─────────────────────────────────────────────────────────────────────────────

/// The `generationConfig` sampling knobs are each promoted into a typed IR field on read and
/// re-emitted on write. Carries: temperature, topP, topK, candidateCount, maxOutputTokens,
/// stopSequences, seed, presencePenalty, frequencyPenalty.
#[test]
fn gemini_request_sampling_knobs_survive() {
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {
            "temperature": 0.35,
            "topP": 0.8,
            "topK": 40,
            "candidateCount": 2,
            "maxOutputTokens": 256,
            "stopSequences": ["END", "STOP"],
            "seed": 12345,
            "presencePenalty": 0.5,
            "frequencyPenalty": 0.25
        }
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    // Each field reaches its typed IR carrier.
    assert_eq!(ir.temperature, Some(0.35));
    assert_eq!(ir.top_p, Some(0.8));
    assert_eq!(ir.top_k, Some(40));
    assert_eq!(ir.n, Some(2)); // candidateCount → n
    assert_eq!(ir.max_tokens, Some(256));
    assert_eq!(ir.stop, vec!["END".to_string(), "STOP".to_string()]);
    assert_eq!(ir.seed, Some(12345));
    assert_eq!(ir.presence_penalty, Some(0.5));
    assert_eq!(ir.frequency_penalty, Some(0.25));

    let out = Protocol::gemini().writer().write_request(&ir);
    let gc = &out["generationConfig"];
    assert_eq!(gc["temperature"], 0.35);
    assert_eq!(gc["topP"], 0.8);
    assert_eq!(gc["topK"], 40);
    assert_eq!(gc["candidateCount"], 2);
    assert_eq!(gc["maxOutputTokens"], 256);
    assert_eq!(gc["stopSequences"], json!(["END", "STOP"]));
    assert_eq!(gc["seed"], 12345);
    assert_eq!(gc["presencePenalty"], 0.5);
    assert_eq!(gc["frequencyPenalty"], 0.25);
}

/// The logprobs ask: boolean `responseLogprobs` + top-count `logprobs`, promoted and re-emitted.
#[test]
fn gemini_request_logprobs_ask_survives() {
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"responseLogprobs": true, "logprobs": 3}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    assert_eq!(ir.logprobs, Some(true)); // responseLogprobs
    assert_eq!(ir.top_logprobs, Some(3)); // logprobs (top-count)

    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(out["generationConfig"]["responseLogprobs"], true);
    assert_eq!(out["generationConfig"]["logprobs"], 3);
}

/// Structured output: `responseMimeType` + `responseSchema` normalize into the IR response_format
/// and re-emit.
#[test]
fn gemini_request_response_format_survives() {
    let schema = json!({"type": "object", "properties": {"x": {"type": "string"}}});
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": schema
        }
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    let rf = ir
        .response_format
        .as_ref()
        .expect("response_format present");
    assert!(rf.json, "responseMimeType application/json → json output");
    assert!(rf.schema.is_some(), "responseSchema must reach the IR");

    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(
        out["generationConfig"]["responseMimeType"],
        "application/json"
    );
    assert_eq!(
        out["generationConfig"]["responseSchema"]["properties"]["x"]["type"],
        "string"
    );
}

/// The thinking ask `generationConfig.thinkingConfig.thinkingBudget` reaches the IR reasoning
/// carrier and re-emits in Gemini's native spelling.
#[test]
fn gemini_request_thinking_budget_survives() {
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "generationConfig": {"thinkingConfig": {"thinkingBudget": 2048}}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Budget(2048)),
        "thinkingBudget must reach the IR reasoning carrier"
    );
    let out = Protocol::gemini().writer().write_request(&ir);
    // Same-protocol keeps the caller's native thinkingConfig (seeded from extra) verbatim.
    assert_eq!(
        out["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        2048
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — top-level structural (cross-protocol)
// ─────────────────────────────────────────────────────────────────────────────

/// `systemInstruction` → IR system blocks → re-emitted `systemInstruction.parts[].text`.
#[test]
fn gemini_request_system_instruction_survives() {
    let body = json!({
        "systemInstruction": {"parts": [{"text": "be terse"}]},
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}]
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    assert!(
        ir.system.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Text { text, .. } if text == "be terse"
        )),
        "systemInstruction must reach the IR system carrier: {:?}",
        ir.system
    );
    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(out["systemInstruction"]["parts"][0]["text"], "be terse");
}

/// `tools[].functionDeclarations[]` → IR tools → re-emitted.
#[test]
fn gemini_request_tools_survive() {
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"functionDeclarations": [
            {"name": "get_weather", "description": "look up weather",
             "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}
        ]}]
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    assert_eq!(ir.tools.len(), 1);
    assert_eq!(ir.tools[0].name, "get_weather");
    assert_eq!(ir.tools[0].description.as_deref(), Some("look up weather"));

    let out = Protocol::gemini().writer().write_request(&ir);
    let decl = &out["tools"][0]["functionDeclarations"][0];
    assert_eq!(decl["name"], "get_weather");
    assert_eq!(decl["description"], "look up weather");
    assert_eq!(decl["parameters"]["properties"]["city"]["type"], "string");
}

/// `toolConfig.functionCallingConfig` → IR tool_choice → re-emitted (the raw toolConfig also rides
/// `extra` for same-protocol byte-identity, overlaid by the typed choice).
#[test]
fn gemini_request_tool_config_survives() {
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"functionDeclarations": [{"name": "f", "parameters": {"type": "object"}}]}],
        "toolConfig": {"functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": ["f"]}}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");
    assert!(
        ir.tool_choice.is_some(),
        "toolConfig must reach the IR tool_choice carrier"
    );
    let out = Protocol::gemini().writer().write_request(&ir);
    // The functionCallingConfig survives (mode re-emitted from the typed choice).
    assert!(
        out["toolConfig"]["functionCallingConfig"].is_object(),
        "toolConfig.functionCallingConfig must be re-emitted: {out}"
    );
    assert_eq!(out["toolConfig"]["functionCallingConfig"]["mode"], "ANY");
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — provider-specific (no cross-protocol home): lossless same-protocol via `extra`,
// dropped (not leaked) cross-protocol.
// ─────────────────────────────────────────────────────────────────────────────

/// `safetySettings`, `labels`, and the unmodeled `generationConfig` sub-fields
/// (`responseModalities`, `mediaResolution`, `speechConfig`, `thinkingConfig.includeThoughts`) have
/// no cross-protocol analog. They survive a same-protocol read → write BYTE-for-byte via the
/// reader's `extra` passthrough (top-level keys) / the `generationConfig` overlay, and are DROPPED
/// (never leaked to a foreign backend) once the cross-protocol seam clears `extra`.
#[test]
fn gemini_request_provider_specific_fields_survive_same_proto() {
    let safety = json!([{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"}]);
    let labels = json!({"team": "search", "env": "prod"});
    let speech = json!({"voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}});
    let body = json!({
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "safetySettings": safety,
        "labels": labels,
        "generationConfig": {
            "responseModalities": ["TEXT", "AUDIO"],
            "mediaResolution": "MEDIA_RESOLUTION_HIGH",
            "speechConfig": speech,
            "thinkingConfig": {"includeThoughts": true}
        }
    });
    let mut ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");

    // SAME-PROTOCOL: every provider field is re-emitted verbatim.
    let out = Protocol::gemini().writer().write_request(&ir);
    assert_eq!(out["safetySettings"], safety, "safetySettings must survive");
    assert_eq!(out["labels"], labels, "labels must survive");
    assert_eq!(
        out["generationConfig"]["responseModalities"],
        json!(["TEXT", "AUDIO"]),
        "responseModalities must survive"
    );
    assert_eq!(
        out["generationConfig"]["mediaResolution"], "MEDIA_RESOLUTION_HIGH",
        "mediaResolution must survive"
    );
    assert_eq!(
        out["generationConfig"]["speechConfig"], speech,
        "speechConfig must survive"
    );
    assert_eq!(
        out["generationConfig"]["thinkingConfig"]["includeThoughts"], true,
        "thinkingConfig.includeThoughts must survive"
    );

    // CROSS-PROTOCOL: the seam clears `extra`, so none of these Gemini-only fields leak onto a
    // foreign backend. (Simulate the seam by clearing extra, then re-emit to Gemini's own writer:
    // with no typed carrier, each provider field is gone.)
    ir.extra.clear();
    let dropped = Protocol::gemini().writer().write_request(&ir);
    assert!(
        dropped.get("safetySettings").is_none(),
        "safetySettings must drop cross-protocol"
    );
    assert!(
        dropped.get("labels").is_none(),
        "labels must drop cross-protocol"
    );
    let gc = dropped.get("generationConfig");
    let has = |k: &str| gc.and_then(|g| g.get(k)).is_some();
    assert!(
        !has("responseModalities"),
        "responseModalities must drop cross-protocol"
    );
    assert!(
        !has("mediaResolution"),
        "mediaResolution must drop cross-protocol"
    );
    assert!(
        !has("speechConfig"),
        "speechConfig must drop cross-protocol"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST — content parts (cross-protocol)
// ─────────────────────────────────────────────────────────────────────────────

/// Every representable `parts[]` construct survives read → write: text, a `thought` reasoning part
/// with its `thoughtSignature`, a `functionCall{name,args}`, a `functionResponse{name,response}`,
/// and a `fileData{fileUri,mimeType}` reference.
#[test]
fn gemini_request_content_parts_survive() {
    let body = json!({
        "contents": [
            {"role": "model", "parts": [
                {"text": "visible answer"},
                {"thought": true, "text": "let me think", "thoughtSignature": "SIG-abc"},
                {"functionCall": {"name": "search", "args": {"q": "rust"}}}
            ]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "search", "response": {"hits": 3}}},
                {"fileData": {"fileUri": "gs://bucket/doc.pdf", "mimeType": "application/pdf"}}
            ]}
        ]
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&body)
        .expect("read");

    let model_turn = &ir.messages[0].content;
    // parts[].text
    assert!(
        model_turn.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Text { text, .. } if text == "visible answer"
        )),
        "parts[].text must reach the IR"
    );
    // parts[].thought + parts[].thoughtSignature
    assert!(
        model_turn.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Thinking { text, signature, .. }
            if text == "let me think" && signature.as_deref() == Some("SIG-abc")
        )),
        "parts[].thought + thoughtSignature must reach the IR Thinking carrier: {model_turn:?}"
    );
    // parts[].functionCall.name / .args
    assert!(
        model_turn.iter().any(|b| matches!(
            b, crate::ir::IrBlock::ToolUse { name, input, .. }
            if name == "search" && input["q"] == "rust"
        )),
        "parts[].functionCall name+args must reach the IR ToolUse carrier"
    );
    // parts[].functionResponse.name / .response
    let user_turn = &ir.messages[1].content;
    assert!(
        user_turn.iter().any(|b| matches!(
            b, crate::ir::IrBlock::ToolResult { tool_use_id, content, .. }
            if tool_use_id == "search"
               && content.iter().any(|c| matches!(c, crate::ir::IrBlock::Text { text, .. } if text.contains("\"hits\":3")))
        )),
        "parts[].functionResponse name+response must reach the IR ToolResult carrier: {user_turn:?}"
    );
    // parts[].fileData.fileUri / .mimeType
    assert!(
        user_turn.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                source: crate::ir::IrImageSource::Url(uri), ..
            } if uri == "gs://bucket/doc.pdf"
        )),
        "parts[].fileData (pdf) must reach the IR as a Document URL Media block: {user_turn:?}"
    );

    // Re-emit and assert each construct is back in its native part shape.
    let out = Protocol::gemini().writer().write_request(&ir);
    let mparts = out["contents"][0]["parts"].as_array().expect("model parts");
    assert!(
        mparts.iter().any(|p| p["text"] == "visible answer"),
        "text re-emit"
    );
    assert!(
        mparts.iter().any(|p| p["thought"] == true
            && p["text"] == "let me think"
            && p["thoughtSignature"] == "SIG-abc"),
        "thought + thoughtSignature re-emit: {out}"
    );
    assert!(
        mparts
            .iter()
            .any(|p| p["functionCall"]["name"] == "search"
                && p["functionCall"]["args"]["q"] == "rust"),
        "functionCall re-emit: {out}"
    );
    let uparts = out["contents"][1]["parts"].as_array().expect("user parts");
    assert!(
        uparts
            .iter()
            .any(|p| p["functionResponse"]["name"] == "search"
                && p["functionResponse"]["response"]["hits"] == 3),
        "functionResponse re-emit: {out}"
    );
    assert!(
        uparts
            .iter()
            .any(|p| p["fileData"]["fileUri"] == "gs://bucket/doc.pdf"
                && p["fileData"]["mimeType"] == "application/pdf"),
        "fileData fileUri+mimeType re-emit: {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST/RESPONSE — code-execution parts (provider-specific, no cross-protocol home)
// ─────────────────────────────────────────────────────────────────────────────

/// `parts[].executableCode` and `parts[].codeExecutionResult` are the code-interpreter tool's
/// model-authored artifacts. They have no cross-protocol analog, so they are carried as a DOCUMENTED
/// DROP: same-protocol Gemini→Gemini relay is byte-verbatim (never rebuilt from the IR, generically
/// pinned by `gemini_sse_round_trip_byte_exact`), and CROSS-protocol the reader drops them with a
/// `warn!` rather than corrupting them into a text block. This test pins the drop AND the
/// no-corruption guarantee on BOTH the request-replay and the response path — a future edit that
/// promoted either part into a `Text` block (leaking model-authored code as visible answer text) or
/// leaked it onto a foreign egress turns it red.
#[test]
fn gemini_code_execution_parts_drop_cross_proto_without_corruption() {
    // CROSS-PROTOCOL: the reader drops both (they never become a corrupt text block) — asserted on
    // both the request replay path and the response path.
    let req = json!({
        "contents": [{"role": "model", "parts": [
            {"executableCode": {"language": "PYTHON", "code": "print(1)"}},
            {"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": "1"}}
        ]}]
    });
    let ir = Protocol::gemini()
        .reader()
        .read_request(&req)
        .expect("read");
    assert!(
        ir.messages[0].content.is_empty(),
        "executableCode/codeExecutionResult request parts must be dropped, not corrupted: {:?}",
        ir.messages[0].content
    );

    let resp = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [
                {"executableCode": {"language": "PYTHON", "code": "print(1)"}},
                {"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": "1"}}
            ]},
            "finishReason": "STOP"
        }],
        "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 3, "totalTokenCount": 8}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&resp)
        .expect("read");
    assert!(
        ir.content.is_empty(),
        "executableCode/codeExecutionResult response parts must be dropped, not corrupted: {:?}",
        ir.content
    );
    // ...and the cross-protocol egress (OpenAI) carries no synthetic text for them.
    let openai = Protocol::openai().writer().write_response(&ir);
    let msg = openai["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    assert!(
        !msg.contains("executableCode") && !msg.contains("print(1)"),
        "code-execution artifacts must not leak into cross-protocol text: {openai}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE — core fields (cross-protocol)
// ─────────────────────────────────────────────────────────────────────────────

/// `candidates[].content`, `candidates[].finishReason`, top-level `modelVersion` and `responseId`
/// survive read → write.
#[test]
fn gemini_response_core_fields_survive() {
    let body = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "the answer"}]},
            "finishReason": "MAX_TOKENS"
        }],
        "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 6, "totalTokenCount": 10},
        "modelVersion": "gemini-2.5-flash-001",
        "responseId": "PXmFaPzVMIabcdef"
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    // candidates[].content
    assert!(
        ir.content.iter().any(|b| matches!(
            b, crate::ir::IrBlock::Text { text, .. } if text == "the answer"
        )),
        "candidates[].content must reach the IR"
    );
    // candidates[].finishReason
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::MaxTokens));
    // modelVersion / responseId
    assert_eq!(ir.model.as_deref(), Some("gemini-2.5-flash-001"));
    assert_eq!(ir.id.as_deref(), Some("PXmFaPzVMIabcdef"));

    let out = Protocol::gemini().writer().write_response(&ir);
    assert_eq!(
        out["candidates"][0]["content"]["parts"][0]["text"],
        "the answer"
    );
    assert_eq!(out["candidates"][0]["finishReason"], "MAX_TOKENS");
    assert_eq!(out["modelVersion"], "gemini-2.5-flash-001");
    assert_eq!(out["responseId"], "PXmFaPzVMIabcdef");
}

/// `candidates[].citationMetadata` re-emits same-protocol, and `candidates[].groundingMetadata`
/// reaches the IR citation carrier (and thus a foreign client).
#[test]
fn gemini_response_citations_survive() {
    // citationMetadata → IR citation → re-emitted as citationMetadata.
    let cited = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Paris is the capital."}]},
            "finishReason": "STOP",
            "citationMetadata": {"citationSources": [
                {"startIndex": 0, "endIndex": 5, "uri": "https://atlas", "title": "Atlas"}
            ]}
        }],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&cited)
        .expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("expected a Text block, got {:?}", ir.content[0]);
    };
    assert_eq!(citations.len(), 1, "citationMetadata must reach the IR");
    assert_eq!(citations[0].url.as_deref(), Some("https://atlas"));
    let out = Protocol::gemini().writer().write_response(&ir);
    assert!(
        out["candidates"][0]["citationMetadata"]["citationSources"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "citationMetadata must be re-emitted same-protocol: {out}"
    );

    // groundingMetadata → IR citation → reaches a foreign (Anthropic) client.
    let grounded = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Paris is the capital."}]},
            "finishReason": "STOP",
            "groundingMetadata": {
                "groundingChunks": [{"web": {"uri": "https://atlas", "title": "Atlas"}}],
                "groundingSupports": [{
                    "segment": {"startIndex": 0, "endIndex": 5, "text": "Paris"},
                    "groundingChunkIndices": [0]
                }]
            }
        }],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 4, "totalTokenCount": 7}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&grounded)
        .expect("read");
    let crate::ir::IrBlock::Text { citations, .. } = &ir.content[0] else {
        panic!("expected a Text block, got {:?}", ir.content[0]);
    };
    assert_eq!(
        citations.len(),
        1,
        "groundingMetadata source must reach the IR"
    );
    assert_eq!(citations[0].url.as_deref(), Some("https://atlas"));
    let anthropic = Protocol::anthropic().writer().write_response(&ir);
    assert!(
        anthropic["content"][0]["citations"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "the grounding source must reach an Anthropic client: {anthropic}"
    );
}

/// `candidates[].logprobsResult` reaches the IR logprobs carrier and re-emits.
#[test]
fn gemini_response_logprobs_result_survives() {
    let body = json!({
        "candidates": [{
            "content": {"role": "model", "parts": [{"text": "Hi"}]},
            "finishReason": "STOP",
            "logprobsResult": {
                "chosenCandidates": [{"token": "Hi", "logProbability": -0.031}],
                "topCandidates": [{"candidates": [
                    {"token": "Hi", "logProbability": -0.031},
                    {"token": "Hello", "logProbability": -3.5}
                ]}]
            }
        }],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2, "totalTokenCount": 5}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    assert_eq!(ir.logprobs.len(), 1, "logprobsResult must reach the IR");
    assert_eq!(ir.logprobs[0].token, "Hi");
    assert_eq!(ir.logprobs[0].top.len(), 2);

    let out = Protocol::gemini().writer().write_response(&ir);
    assert_eq!(
        out["candidates"][0]["logprobsResult"]["chosenCandidates"][0]["token"], "Hi",
        "logprobsResult must be re-emitted: {out}"
    );
}

/// `usageMetadata.cachedContentTokenCount` (→ cache_read) and `usageMetadata.toolUsePromptTokenCount`
/// (→ the tool-use prompt sub-bucket) survive read → write.
#[test]
fn gemini_response_usage_buckets_survive() {
    let body = json!({
        "candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": 100,
            "candidatesTokenCount": 20,
            "cachedContentTokenCount": 30,
            "toolUsePromptTokenCount": 12,
            "totalTokenCount": 120
        }
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    // cachedContentTokenCount → cache_read (input normalized to uncached: 100 - 30 = 70).
    assert_eq!(
        ir.usage.cache_read_input_tokens,
        Some(30),
        "cachedContentTokenCount must reach the IR"
    );
    assert_eq!(ir.usage.input_tokens, 70);
    // toolUsePromptTokenCount → the tool-use prompt sub-bucket.
    assert_eq!(
        ir.usage.detail.tool_use_prompt_tokens,
        Some(12),
        "toolUsePromptTokenCount must reach the IR usage detail"
    );

    let out = Protocol::gemini().writer().write_response(&ir);
    assert_eq!(
        out["usageMetadata"]["cachedContentTokenCount"], 30,
        "cachedContentTokenCount must be re-emitted: {out}"
    );
    assert_eq!(
        out["usageMetadata"]["toolUsePromptTokenCount"], 12,
        "toolUsePromptTokenCount must be re-emitted: {out}"
    );
}

/// `promptFeedback.blockReason` (a prompt-level content block, no candidates) reaches the IR as a
/// safety stop reason rather than a spurious parse error.
#[test]
fn gemini_response_prompt_feedback_block_reason_survives() {
    let body = json!({
        "promptFeedback": {"blockReason": "SAFETY"},
        "usageMetadata": {"promptTokenCount": 8, "totalTokenCount": 8}
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::Safety),
        "promptFeedback.blockReason SAFETY must map to a Safety stop reason"
    );
    assert!(
        ir.content.is_empty(),
        "a prompt-blocked response carries no content"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE — provider-specific (no cross-protocol home): documented cross-protocol DROP.
// ─────────────────────────────────────────────────────────────────────────────

/// The provider-specific response fields have no cross-protocol home, so they are carried as a
/// DOCUMENTED DROP: same-protocol Gemini→Gemini relay is byte-verbatim (never rebuilt from the IR,
/// generically pinned by `gemini_sse_round_trip_byte_exact`), and CROSS-protocol the reader does not
/// model them — so they neither corrupt the IR nor leak onto a foreign egress. This test pins that
/// on read: a body carrying every one of them yields exactly the visible answer text (no spurious
/// blocks synthesized from a safety rating / token count), and a foreign (OpenAI) egress carries
/// none of the Gemini-only field names. Carries: candidates[].index, candidates[].safetyRatings,
/// candidates[].avgLogprobs, candidates[].tokenCount, promptFeedback.safetyRatings,
/// usageMetadata.promptTokensDetails.
#[test]
fn gemini_response_provider_specific_fields_drop_cross_proto_without_corruption() {
    let body = json!({
        "candidates": [{
            "index": 0,
            "content": {"role": "model", "parts": [{"text": "the answer"}]},
            "finishReason": "STOP",
            "avgLogprobs": -0.125,
            "tokenCount": 7,
            "safetyRatings": [{"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"}]
        }],
        "promptFeedback": {
            "safetyRatings": [{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "NEGLIGIBLE"}]
        },
        "usageMetadata": {
            "promptTokenCount": 5,
            "candidatesTokenCount": 4,
            "totalTokenCount": 9,
            "promptTokensDetails": [{"modality": "TEXT", "tokenCount": 5}]
        }
    });
    let ir = Protocol::gemini()
        .reader()
        .read_response(&body)
        .expect("read");
    // NO CORRUPTION: the only content is the visible answer — candidates[].index / safetyRatings /
    // avgLogprobs / tokenCount / promptFeedback.safetyRatings / promptTokensDetails were each read
    // WITHOUT being turned into a spurious IR block.
    assert_eq!(
        ir.content.len(),
        1,
        "no provider field may synthesize an extra block: {:?}",
        ir.content
    );
    assert!(
        matches!(&ir.content[0], crate::ir::IrBlock::Text { text, .. } if text == "the answer"),
        "the only content block is the visible answer: {:?}",
        ir.content[0]
    );

    // DOCUMENTED CROSS-PROTOCOL DROP: a foreign (OpenAI) egress carries none of the Gemini-only
    // field names — they are not leaked onto a backend that has no slot for them. A future edit that
    // began modelling any of these would turn this red (allow-list discipline), never pass silently.
    let openai = Protocol::openai().writer().write_response(&ir).to_string();
    for field in [
        "safetyRatings",
        "avgLogprobs",
        "tokenCount",
        "promptFeedback",
        "promptTokensDetails",
    ] {
        assert!(
            !openai.contains(field),
            "provider-specific field {field:?} must not leak onto a foreign egress: {openai}"
        );
    }
}
