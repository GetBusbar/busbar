//! FIELD-COVERAGE CARRY tests for the anthropic dialect (qa/field-coverage.status).
//!
//! Each `#[test]` here is the named INSTRUMENT for one or more `anthropic/*` field ids: it drives the
//! real reader→IR→writer path (or the same-protocol byte short-circuit, for a keepalive) and asserts,
//! per field, that the field SURVIVES. A mutation that stops carrying a field breaks the matching
//! assertion — which is the whole contract of the field-coverage gate. Provider-specific fields with
//! no cross-protocol slot are carried 100% lossless SAME-protocol (read→write) and, where they are
//! dropped on a foreign egress, that drop is asserted too.
use super::super::proto_codec::{ProtocolReader, ProtocolWriter};
use super::{AnthropicReader, AnthropicWriter};

// ---------------------------------------------------------------------------------------------
// Request-level provider-specific fields — carried verbatim through `extra` (same-protocol lossless).
// ---------------------------------------------------------------------------------------------

/// `metadata`, `service_tier`, `container`, `mcp_servers`, `betas`: Anthropic-specific request knobs
/// with no cross-protocol analog. They ride `extra` and must re-emit byte-exact on a same-protocol
/// (Anthropic→Anthropic) hop. Each has its OWN assertion so dropping any one fails this test.
#[test]
fn anthropic_request_provider_specific_fields_carry() {
    let body = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_id": "u-42", "custom": "keep-me"},
        "service_tier": "priority",
        "container": "container-abc",
        "mcp_servers": [{"type": "url", "url": "https://mcp.example/sse", "name": "srv"}],
        "betas": ["token-counting-2024-11-01", "pdfs-2024-09-25"]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);

    // metadata: the WHOLE object survives (user_id is also promoted to `user`, but the verbatim
    // extra overlay wins so custom keys are not lost).
    assert_eq!(out["metadata"], body["metadata"], "metadata must survive");
    assert_eq!(out["metadata"]["custom"], "keep-me");
    assert_eq!(out["service_tier"], "priority", "service_tier must survive");
    assert_eq!(out["container"], "container-abc", "container must survive");
    assert_eq!(
        out["mcp_servers"], body["mcp_servers"],
        "mcp_servers survive"
    );
    assert_eq!(out["betas"], body["betas"], "betas must survive");
}

/// `top_k` is a first-class sampling knob (cross-protocol): read into `ir.top_k` and re-emitted 1:1.
#[test]
fn anthropic_request_top_k_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "top_k": 40
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(ir.top_k, Some(40), "top_k read first-class");
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["top_k"], 40, "top_k must re-emit");
}

/// `tools`: a tool definition survives read→write (name / description / input_schema / cache_control).
#[test]
fn anthropic_request_tools_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{
            "name": "get_weather",
            "description": "Look up weather",
            "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
            "cache_control": {"type": "ephemeral"}
        }]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    let tool = &out["tools"][0];
    assert_eq!(tool["name"], "get_weather", "tool name survives");
    assert_eq!(
        tool["description"], "Look up weather",
        "tool description survives"
    );
    assert_eq!(
        tool["input_schema"], body["tools"][0]["input_schema"],
        "tool input_schema survives"
    );
    assert_eq!(
        tool["cache_control"]["type"], "ephemeral",
        "tool cache_control survives"
    );
}

/// `tool_choice`: a forced/targeted directive (`{type:"tool",name}`) survives read→write.
#[test]
fn anthropic_request_tool_choice_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "f", "input_schema": {"type": "object"}}],
        "tool_choice": {"type": "tool", "name": "f"}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["tool_choice"]["type"], "tool",
        "tool_choice type survives"
    );
    assert_eq!(out["tool_choice"]["name"], "f", "tool_choice name survives");
}

/// `thinking` (the request ASK): `{type:"enabled",budget_tokens}` promotes to the IR reasoning ask
/// and re-emits as Anthropic's `thinking` param.
#[test]
fn anthropic_request_thinking_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 16000,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 6000}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Budget(6000)),
        "thinking read into the reasoning ask"
    );
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["thinking"]["type"], "enabled",
        "thinking param re-emitted"
    );
    assert_eq!(
        out["thinking"]["budget_tokens"], 6000,
        "thinking budget survives"
    );
}

// ---------------------------------------------------------------------------------------------
// Content-block sub-fields — read→write same-protocol.
// ---------------------------------------------------------------------------------------------

/// text.cache_control / text.citations / image.source.url / image.cache_control /
/// tool_use.cache_control / tool_result.is_error / tool_result.cache_control — each with its OWN
/// assertion so a mutation dropping any single one fails.
#[test]
fn anthropic_content_block_field_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "grounded",
                 "cache_control": {"type": "ephemeral"},
                 "citations": [{"type": "char_location", "cited_text": "q",
                                "document_index": 0, "start_char_index": 1, "end_char_index": 2}]},
                {"type": "image",
                 "source": {"type": "url", "url": "https://img.example/p.png"},
                 "cache_control": {"type": "ephemeral"}}
            ]},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "tu_1", "name": "f", "input": {"a": 1},
                 "cache_control": {"type": "ephemeral"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1",
                 "content": [{"type": "text", "text": "boom"}],
                 "is_error": true, "cache_control": {"type": "ephemeral"}}
            ]}
        ]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    let user0 = out["messages"][0]["content"].as_array().unwrap();
    let text = &user0[0];
    assert_eq!(
        text["cache_control"]["type"], "ephemeral",
        "text.cache_control survives"
    );
    assert_eq!(
        text["citations"][0]["cited_text"], "q",
        "text.citations survive"
    );
    let image = &user0[1];
    assert_eq!(
        image["source"]["type"], "url",
        "image.source.url shape survives"
    );
    assert_eq!(
        image["source"]["url"], "https://img.example/p.png",
        "image.source.url survives"
    );
    assert_eq!(
        image["cache_control"]["type"], "ephemeral",
        "image.cache_control survives"
    );

    let tool_use = &out["messages"][1]["content"][0];
    assert_eq!(tool_use["type"], "tool_use");
    assert_eq!(
        tool_use["cache_control"]["type"], "ephemeral",
        "tool_use.cache_control survives"
    );

    let tool_result = &out["messages"][2]["content"][0];
    assert_eq!(
        tool_result["is_error"], true,
        "tool_result.is_error survives"
    );
    assert_eq!(
        tool_result["cache_control"]["type"], "ephemeral",
        "tool_result.cache_control survives"
    );
}

/// thinking.thinking / thinking.signature — an assistant `thinking` block (with the mandatory
/// signature so the request writer does not drop it) round-trips both fields.
#[test]
fn anthropic_thinking_content_block_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "let me reason", "signature": "sig-xyz"}
        ]}]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    let block = &out["messages"][0]["content"][0];
    assert_eq!(block["type"], "thinking");
    assert_eq!(
        block["thinking"], "let me reason",
        "thinking.thinking survives"
    );
    assert_eq!(block["signature"], "sig-xyz", "thinking.signature survives");
}

/// document.source.url / document.context / document.citations / document.cache_control.
///
/// SAME-protocol: a document carrying `context`/`citations` is spliced back byte-exact (all four
/// survive). CROSS-protocol (extra cleared at the seam): the `IrBlock::Media` projection keeps
/// source.url + cache_control but DROPS context/citations (they have no neutral slot) — asserted so
/// the documented drop is watched, not silent.
#[test]
fn anthropic_document_block_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": [
            {"type": "document",
             "source": {"type": "url", "url": "https://docs.example/f.pdf"},
             "title": "Doc",
             "context": "quarterly report",
             "citations": {"enabled": true},
             "cache_control": {"type": "ephemeral"}}
        ]}]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");

    // SAME-protocol: everything survives verbatim.
    let out = AnthropicWriter.write_request(&ir);
    let doc = &out["messages"][0]["content"][0];
    assert_eq!(doc["type"], "document");
    assert_eq!(
        doc["source"]["url"], "https://docs.example/f.pdf",
        "document.source.url survives same-protocol"
    );
    assert_eq!(
        doc["context"], "quarterly report",
        "document.context survives same-protocol"
    );
    assert_eq!(
        doc["citations"],
        serde_json::json!({"enabled": true}),
        "document.citations survive"
    );
    assert_eq!(
        doc["cache_control"]["type"], "ephemeral",
        "document.cache_control survives same-protocol"
    );

    // CROSS-protocol seam clears extra → Media projection; url + cache_control survive, context and
    // citations are the documented drop.
    let mut crossed = ir.clone();
    crossed.extra.clear();
    let cout = AnthropicWriter.write_request(&crossed);
    let cdoc = &cout["messages"][0]["content"][0];
    assert_eq!(cdoc["type"], "document");
    assert_eq!(
        cdoc["source"]["url"], "https://docs.example/f.pdf",
        "document.source.url survives cross-protocol via Media"
    );
    assert_eq!(cdoc["cache_control"]["type"], "ephemeral");
    assert!(
        cdoc.get("context").is_none(),
        "document.context dropped cross-protocol: {cdoc}"
    );
    assert!(
        cdoc.get("citations").is_none(),
        "document.citations dropped cross-protocol: {cdoc}"
    );
}

/// search_result.source / search_result.title / search_result.content — a `search_result` block is
/// stashed and spliced back byte-exact on the same-protocol hop, so all three survive.
#[test]
fn anthropic_search_result_block_carry() {
    let body = serde_json::json!({
        "model": "m", "max_tokens": 64,
        "messages": [{"role": "user", "content": [
            {"type": "search_result",
             "source": "https://kb.example/a",
             "title": "Article A",
             "content": [{"type": "text", "text": "retrieved passage"}],
             "citations": {"enabled": true}}
        ]}]
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    let sr = &out["messages"][0]["content"][0];
    assert_eq!(sr["type"], "search_result");
    assert_eq!(
        sr["source"], "https://kb.example/a",
        "search_result.source survives"
    );
    assert_eq!(sr["title"], "Article A", "search_result.title survives");
    assert_eq!(
        sr["content"][0]["text"], "retrieved passage",
        "search_result.content survives"
    );
}

// ---------------------------------------------------------------------------------------------
// Response usage attribution — read_response → write_response.
// ---------------------------------------------------------------------------------------------

/// usage.server_tool_use.web_search_requests / usage.service_tier — Anthropic usage attribution now
/// modelled on `IrUsageDetail`, so both survive a buffered response round-trip.
#[test]
fn anthropic_response_usage_extras_carry() {
    let body = serde_json::json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-3-5-sonnet",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 5, "output_tokens": 3,
            "server_tool_use": {"web_search_requests": 2},
            "service_tier": "priority"
        }
    });
    let ir = AnthropicReader.read_response(&body).expect("parses");
    assert_eq!(
        ir.usage.detail.web_search_requests,
        Some(2),
        "web_search_requests read into IR"
    );
    assert_eq!(
        ir.usage.detail.service_tier.as_deref(),
        Some("priority"),
        "service_tier read into IR"
    );
    let out = AnthropicWriter.write_response(&ir);
    assert_eq!(
        out["usage"]["server_tool_use"]["web_search_requests"], 2,
        "usage.server_tool_use.web_search_requests survives"
    );
    assert_eq!(
        out["usage"]["service_tier"], "priority",
        "usage.service_tier survives"
    );
}

// ---------------------------------------------------------------------------------------------
// Streaming events — read_response_event → write_response_event.
// ---------------------------------------------------------------------------------------------

/// stream:message_start / content_block_start / content_block_stop / message_delta / message_stop —
/// each event type read into an `IrStreamEvent` and re-emitted, with a per-event assertion.
#[test]
fn anthropic_stream_event_roundtrip_carry() {
    let rw = |et: &str, data: serde_json::Value| -> (String, serde_json::Value) {
        let ev = AnthropicReader
            .read_response_event(et, &data)
            .unwrap_or_else(|| panic!("read event {et}"));
        AnthropicWriter
            .write_response_event(&ev)
            .unwrap_or_else(|| panic!("write event {et}"))
    };

    // message_start
    let (et, out) = rw(
        "message_start",
        serde_json::json!({
            "type": "message_start",
            "message": {"id": "msg_1", "role": "assistant", "model": "claude-x",
                        "usage": {"input_tokens": 11, "output_tokens": 1}}
        }),
    );
    assert_eq!(et, "message_start");
    assert_eq!(out["message"]["id"], "msg_1", "message_start id survives");
    assert_eq!(out["message"]["role"], "assistant");
    assert_eq!(out["message"]["model"], "claude-x");
    assert_eq!(out["message"]["usage"]["input_tokens"], 11);

    // content_block_start
    let (et, out) = rw(
        "content_block_start",
        serde_json::json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""}
        }),
    );
    assert_eq!(et, "content_block_start");
    assert_eq!(out["index"], 0);
    assert_eq!(
        out["content_block"]["type"], "text",
        "content_block_start block type survives"
    );

    // content_block_stop
    let (et, out) = rw(
        "content_block_stop",
        serde_json::json!({"type": "content_block_stop", "index": 0}),
    );
    assert_eq!(et, "content_block_stop");
    assert_eq!(out["index"], 0, "content_block_stop index survives");

    // message_delta
    let (et, out) = rw(
        "message_delta",
        serde_json::json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": null},
            "usage": {"output_tokens": 7}
        }),
    );
    assert_eq!(et, "message_delta");
    assert_eq!(
        out["delta"]["stop_reason"], "end_turn",
        "message_delta stop_reason survives"
    );
    assert_eq!(
        out["usage"]["output_tokens"], 7,
        "message_delta usage survives"
    );

    // message_stop
    let (et, out) = rw("message_stop", serde_json::json!({"type": "message_stop"}));
    assert_eq!(et, "message_stop", "message_stop survives");
    assert_eq!(out["type"], "message_stop");
}

/// stream:content_block_delta.{text_delta,input_json_delta,thinking_delta,signature_delta,
/// citations_delta} — each delta kind read and re-emitted, with a per-kind assertion.
#[test]
fn anthropic_stream_delta_roundtrip_carry() {
    let rw = |delta: serde_json::Value| -> serde_json::Value {
        let data = serde_json::json!({"type": "content_block_delta", "index": 0, "delta": delta});
        let ev = AnthropicReader
            .read_response_event("content_block_delta", &data)
            .expect("read delta");
        AnthropicWriter
            .write_response_event(&ev)
            .expect("write delta")
            .1
    };

    let out = rw(serde_json::json!({"type": "text_delta", "text": "hi"}));
    assert_eq!(out["delta"]["type"], "text_delta");
    assert_eq!(out["delta"]["text"], "hi", "text_delta survives");

    let out = rw(serde_json::json!({"type": "input_json_delta", "partial_json": "{\"a\":1}"}));
    assert_eq!(out["delta"]["type"], "input_json_delta");
    assert_eq!(
        out["delta"]["partial_json"], "{\"a\":1}",
        "input_json_delta survives"
    );

    let out = rw(serde_json::json!({"type": "thinking_delta", "thinking": "reason"}));
    assert_eq!(out["delta"]["type"], "thinking_delta");
    assert_eq!(
        out["delta"]["thinking"], "reason",
        "thinking_delta survives"
    );

    let out = rw(serde_json::json!({"type": "signature_delta", "signature": "sig"}));
    assert_eq!(out["delta"]["type"], "signature_delta");
    assert_eq!(out["delta"]["signature"], "sig", "signature_delta survives");

    let out = rw(serde_json::json!({
        "type": "citations_delta",
        "citation": {"type": "char_location", "cited_text": "c",
                     "document_index": 0, "start_char_index": 1, "end_char_index": 2}
    }));
    assert_eq!(out["delta"]["type"], "citations_delta");
    assert_eq!(
        out["delta"]["citation"]["cited_text"], "c",
        "citations_delta survives"
    );
}

/// stream:ping — a keepalive that carries NO data. Its carry has two halves:
///   * SAME-protocol: it rides the byte-verbatim SSE short-circuit unchanged (that path is generic —
///     it copies every frame and never calls this reader — and is pinned by
///     `proto::tests::same_proto_fidelity_tests::anthropic_sse_round_trip_byte_exact`; a ping is just
///     another frame it copies, so it is preserved byte-exact same-protocol).
///   * CROSS-protocol: a keepalive has no semantic payload to reconstruct, so the reader deliberately
///     produces NO `IrStreamEvent` — it is a documented no-op drop. This is the anthropic-side
///     behaviour a mutation could break (e.g. mapping `ping` to a spurious block event that would
///     inject junk into a translated stream), so it is asserted directly here.
///
/// (This file is dual-compiled into busbar-core for its test build, where `StreamTranslate` lives at
/// a different path, so the same-protocol half is intentionally left to the crate-local
/// `same_proto_fidelity_tests` rather than reached from here.)
#[test]
fn anthropic_stream_ping_same_proto_carry() {
    assert!(
        AnthropicReader
            .read_response_event("ping", &serde_json::json!({"type": "ping"}))
            .is_none(),
        "a ping keepalive must produce no cross-protocol event (no payload to reconstruct)"
    );
    // A ping must not leak into the multi-event reader path either (no spurious BlockStart/Delta).
    let mut state = crate::ir::StreamDecodeState::default();
    let events = AnthropicReader.read_response_events(
        "ping",
        &serde_json::json!({"type": "ping"}),
        &mut state,
    );
    assert!(
        events.is_empty(),
        "a ping must expand to zero IR stream events, got {events:?}"
    );
}

// Chat#4: Anthropic's Messages API models none of `frequency_penalty`/`presence_penalty`/`seed`/`n`.
// A cross-protocol source carrying them must have each dropped OBSERVABLY — a per-control `warn!` and
// a `dropped_egress_controls` entry — not silently as before (the writer never referenced them).
#[test]
fn anthropic_drops_penalties_seed_n_observably() {
    use busbar_core::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ir = crate::ir::IrRequest {
        frequency_penalty: Some(0.5),
        presence_penalty: Some(0.25),
        seed: Some(42),
        n: Some(3),
        ..Default::default()
    };

    let cap = WarnCapture::default();
    let sub = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(sub, || AnthropicWriter.write_request(&ir));

    // None of the four leaks onto the Anthropic wire.
    for field in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            out.get(field).is_none(),
            "{field} must not be emitted on the Anthropic wire: {out}"
        );
        assert!(
            cap.contains(field),
            "dropping {field} on Anthropic egress must warn: {:?}",
            cap.messages()
        );
    }
    // …and each is reported to the cross-protocol seam for audit.
    let dropped = AnthropicWriter.dropped_egress_controls(&ir);
    for field in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            dropped.contains(&field),
            "{field} must be reported by dropped_egress_controls: {dropped:?}"
        );
    }
}

// Chat#5: a streamed REDACTED (encrypted) reasoning block must be PRESERVED on Anthropic egress, not
// dropped. The IR carries `BlockStart{RedactedThinking}` + `RedactedReasoningDelta(bytes)` + BlockStop;
// the writer re-emits the native redacted shape — a `redacted_thinking` content_block_start carrying
// the opaque `data` INLINE (native Anthropic streams redacted bytes on the start, not a delta), with
// NO plaintext `thinking` seed, closed by content_block_stop. This is the encrypted reasoning-reuse
// blob a later turn must replay for extended-thinking continuity.
#[test]
fn streamed_redacted_reasoning_preserves_bytes_on_anthropic_egress() {
    let w = AnthropicWriter;

    // 1. The redacted BlockStart emits NO wire event (the plaintext thinking seed is suppressed; the
    //    native start is emitted from the delta below).
    let start = w.write_response_event(&crate::ir::IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::RedactedThinking,
    });
    assert!(
        start.is_none(),
        "a RedactedThinking BlockStart must emit no plaintext thinking seed: {start:?}"
    );

    // 2. The delta emits the native redacted_thinking content_block_start carrying the opaque bytes.
    let (evt, body) = w
        .write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::RedactedReasoningDelta("ENCRYPTED_BLOB".to_string()),
        })
        .expect("the redacted delta must emit the native redacted_thinking start");
    assert_eq!(
        evt, "content_block_start",
        "redacted bytes re-emit as a content_block_start, not a delta"
    );
    assert_eq!(
        body.pointer("/content_block/type").and_then(|v| v.as_str()),
        Some("redacted_thinking"),
        "the block must be typed redacted_thinking, never plaintext thinking: {body}"
    );
    assert_eq!(
        body.pointer("/content_block/data").and_then(|v| v.as_str()),
        Some("ENCRYPTED_BLOB"),
        "the opaque encrypted bytes must ride under `data` intact: {body}"
    );
    // The bytes must NOT leak as visible plaintext thinking anywhere in the frame.
    assert!(
        !body.to_string().contains("\"thinking\""),
        "a redacted block must never emit a plaintext `thinking` field: {body}"
    );

    // 3. The BlockStop closes the block with content_block_stop.
    let (stop_evt, _) = w
        .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
        .expect("the redacted block must close");
    assert_eq!(stop_evt, "content_block_stop");
}
