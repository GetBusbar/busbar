// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FIELD-COVERAGE CARRY TESTS for the Cohere v2 Chat dialect.
//!
//! Each `#[test]` here is the instrument named by a `qa/field-coverage.status` `carried` line: it
//! reads a native Cohere body, drives it through the neutral IR, writes it back on the Cohere wire,
//! and asserts — field by field — that the named field SURVIVED. A field whose assertion is deleted
//! is a field a future edit can drop in silence, which is the whole failure mode the field-coverage
//! gate exists to make impossible, so every field id in the status file has its OWN assertion below.
//!
//! Classification (see the module docs on `reader.rs`/`writer.rs`):
//! * CROSS-PROTOCOL-MEANINGFUL fields (messages, tools, sampling knobs, response_format, tool_plan,
//!   citations, logprobs ask, usage, finish_reason, the stream frames) are watched on the read→IR→
//!   write round trip, which is exactly the path a cross-protocol hop takes.
//! * PROVIDER-SPECIFIC fields with no cross-protocol analog (`citation_options`, `safety_mode`,
//!   `strict_tools`) survive a SAME-protocol hop via the `extra` echo and are dropped-with-warn on a
//!   cross-protocol hop; they are watched on the same-protocol round trip here. The RESPONSE
//!   `logprobs` (token-id sequences, no neutral shape) is watched by asserting its documented
//!   drop-with-warn.

use super::*;
use busbar_substrate::testkit::warn_capture::WarnCapture;
use serde_json::json;
use tracing_subscriber::layer::SubscriberExt as _;

/// Read a Cohere request body → IR → write it back on the Cohere wire.
fn request_roundtrip(body: serde_json::Value) -> serde_json::Value {
    let ir = CohereReader
        .read_request(&body)
        .expect("cohere request parses");
    // Bind the writer to a local (the `CohereWriter` const carries a Mutex; borrowing the const
    // directly trips clippy's interior-mutability lint).
    let w = CohereWriter;
    w.write_request(&ir)
}

/// Read a Cohere response body → IR → write it back on the Cohere wire.
fn response_roundtrip(body: serde_json::Value) -> serde_json::Value {
    let ir = CohereReader
        .read_response(&body)
        .expect("cohere response parses");
    let w = CohereWriter;
    w.write_response(&ir)
}

/// A rich Cohere v2 request exercising every request member the gate enumerates. Callers assert on
/// the ROUND-TRIPPED form of individual fields.
fn rich_request() -> serde_json::Value {
    json!({
        "model": "command-r-plus",
        "messages": [
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": [
                {"type": "text", "text": "look at this"},
                {"type": "image_url", "image_url": {"url": "https://example.com/i.png"}}
            ]},
            {"role": "assistant",
             "tool_plan": "I will search for it",
             "tool_calls": [
                {"id": "t1", "type": "function",
                 "function": {"name": "search", "arguments": "{\"q\":\"x\"}"}}
             ]},
            {"role": "tool", "tool_call_id": "t1", "content": [{"type": "text", "text": "the result"}]},
            {"role": "assistant",
             "content": [{"type": "text", "text": "grounded answer"}],
             "citations": [
                {"start": 0, "end": 8, "text": "grounded", "type": "TEXT_CONTENT",
                 "sources": [{"type": "document", "id": "d1",
                              "document": {"title": "T", "url": "https://src/1"}}]}
             ]}
        ],
        "tools": [
            {"type": "function", "function": {
                "name": "search", "description": "search the web",
                "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}
            }}
        ],
        "tool_choice": "REQUIRED",
        "citation_options": {"mode": "FAST"},
        "response_format": {"type": "json_object"},
        "safety_mode": "CONTEXTUAL",
        "max_tokens": 100,
        "stop_sequences": ["STOP"],
        "temperature": 0.5,
        "seed": 42,
        "frequency_penalty": 0.3,
        "presence_penalty": 0.2,
        "k": 10,
        "p": 0.9,
        "logprobs": true,
        "strict_tools": true,
        "stream": true
    })
}

/// The assistant message the writer emits carrying `tool_calls` (the 3rd inbound message: index 3 on
/// the wire once the leading `system` is folded to a `role:"system"` message and the user message is
/// kept — system(0), user(1), assistant-tool_calls(2), tool(3), assistant-grounded(4)).
fn find_message<'a>(
    out: &'a serde_json::Value,
    role: &str,
    has_key: &str,
) -> &'a serde_json::Value {
    out["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .find(|m| m["role"] == role && m.get(has_key).is_some())
        .unwrap_or_else(|| panic!("no {role} message carrying `{has_key}` in {out}"))
}

// ─────────────────────────────── REQUEST: messages / tools ───────────────────────────────

/// Watches: `messages[].role`, `messages[].content`, `content[].type=text.text`,
/// `content[].type=image_url.image_url.url`, `tools`, `tool_choice`, `messages[].tool_plan`,
/// `messages[].citations`.
#[test]
fn cohere_request_messages_and_tools_survive_roundtrip() {
    let out = request_roundtrip(rich_request());
    let msgs = out["messages"].as_array().expect("messages array");

    // messages[].role — every inbound role is present on egress (system is folded to a leading
    // system message; the roles set must still contain user/assistant/tool).
    let roles: Vec<&str> = msgs.iter().filter_map(|m| m["role"].as_str()).collect();
    assert!(roles.contains(&"system"), "system role must survive: {out}");
    assert!(roles.contains(&"user"), "user role must survive: {out}");
    assert!(
        roles.contains(&"assistant"),
        "assistant role must survive: {out}"
    );
    assert!(roles.contains(&"tool"), "tool role must survive: {out}");

    // messages[].content + content[].type=text.text — the plain user text survives (either as a bare
    // string or a text part).
    let user = msgs
        .iter()
        .find(|m| m["role"] == "user")
        .expect("user message");
    let user_dump = serde_json::to_string(user).unwrap();
    assert!(
        user_dump.contains("look at this"),
        "user text content must survive: {out}"
    );

    // content[].type=image_url.image_url.url — the image part re-emits with its URL intact.
    let img_url = user["content"]
        .as_array()
        .expect("user content is a parts array when an image is present")
        .iter()
        .find(|p| p["type"] == "image_url")
        .expect("image_url part survives")["image_url"]["url"]
        .as_str()
        .expect("image url string");
    assert_eq!(
        img_url, "https://example.com/i.png",
        "the image_url must survive verbatim"
    );

    // tools — the function tool round-trips with its name/description/parameters.
    let tool = &out["tools"].as_array().expect("tools array")[0];
    assert_eq!(tool["function"]["name"], "search", "tool name must survive");
    assert_eq!(
        tool["function"]["description"], "search the web",
        "tool description must survive"
    );
    assert_eq!(
        tool["function"]["parameters"]["properties"]["q"]["type"], "string",
        "tool parameters schema must survive"
    );

    // tool_choice — REQUIRED survives (Cohere's forced-tool directive).
    assert_eq!(
        out["tool_choice"], "REQUIRED",
        "tool_choice must survive: {out}"
    );

    // messages[].tool_plan — the assistant's pre-tool-call plan re-emits into the native `tool_plan`
    // slot (NOT as visible content).
    let tool_call_msg = find_message(&out, "assistant", "tool_calls");
    assert_eq!(
        tool_call_msg["tool_plan"], "I will search for it",
        "assistant tool_plan must survive in its native slot: {out}"
    );
    let tc_content = serde_json::to_string(&tool_call_msg["content"]).unwrap();
    assert!(
        !tc_content.contains("I will search for it"),
        "tool_plan must NOT leak into visible content: {out}"
    );

    // messages[].citations — the grounded assistant message keeps its citations.
    let grounded = find_message(&out, "assistant", "citations");
    let cit = &grounded["citations"].as_array().expect("citations array")[0];
    assert_eq!(cit["start"], 0, "citation start offset must survive");
    assert_eq!(cit["end"], 8, "citation end offset must survive");
    assert_eq!(cit["text"], "grounded", "citation text must survive");
}

// ─────────────────────────── REQUEST: sampling / output controls ───────────────────────────

/// Watches: `max_tokens`, `stop_sequences`, `temperature`, `seed`, `frequency_penalty`,
/// `presence_penalty`, `k`, `p`, `logprobs`, `stream`, `response_format`.
#[test]
fn cohere_request_sampling_controls_survive_roundtrip() {
    let out = request_roundtrip(rich_request());

    assert_eq!(out["max_tokens"], 100, "max_tokens must survive");
    assert_eq!(
        out["stop_sequences"],
        json!(["STOP"]),
        "stop_sequences must survive"
    );
    assert_eq!(out["temperature"], 0.5, "temperature must survive");
    assert_eq!(out["seed"], 42, "seed must survive");
    assert_eq!(
        out["frequency_penalty"], 0.3,
        "frequency_penalty must survive"
    );
    assert_eq!(
        out["presence_penalty"], 0.2,
        "presence_penalty must survive"
    );
    assert_eq!(out["k"], 10, "k (top_k) must survive");
    assert_eq!(out["p"], 0.9, "p (top_p) must survive");
    assert_eq!(
        out["logprobs"], true,
        "logprobs (bool ask) must survive: {out}"
    );
    assert_eq!(out["stream"], true, "stream must survive");
    // response_format — the structured-output directive re-emits in Cohere's native shape.
    assert_eq!(
        out["response_format"]["type"], "json_object",
        "response_format must survive: {out}"
    );
}

// ─────────────────── REQUEST: provider-specific (same-protocol carry) ───────────────────

/// Watches: `citation_options`, `safety_mode`, `strict_tools` — Cohere-specific request members with
/// NO cross-protocol analog. They survive a SAME-protocol hop via the `extra` echo (asserted here)
/// and are dropped-with-warn on a cross-protocol hop by the generic chat-seam unmodeled-key warn.
#[test]
fn cohere_request_provider_specific_survive_same_proto() {
    let out = request_roundtrip(rich_request());

    assert_eq!(
        out["citation_options"],
        json!({"mode": "FAST"}),
        "citation_options must survive a same-protocol hop: {out}"
    );
    assert_eq!(
        out["safety_mode"], "CONTEXTUAL",
        "safety_mode must survive a same-protocol hop: {out}"
    );
    assert_eq!(
        out["strict_tools"], true,
        "strict_tools must survive a same-protocol hop: {out}"
    );
}

// ─────────────────────────────────── REQUEST: model ───────────────────────────────────

/// Watches: `model`. The chat `model` is NOT carried by the reader/writer pair — it is stamped onto
/// the egress body by the routing lane via `ProtocolWriter::rewrite_model_if_needed` (the same
/// mechanism `proxy/wire.rs` drives). This asserts the Cohere writer stamps it (rather than, say,
/// having its `rewrite_model_if_needed` overridden to a no-op that would drop the routed model).
#[test]
fn cohere_request_model_is_stamped_by_routing_lane() {
    let mut body = request_roundtrip(rich_request());
    // The reader/writer pair does not carry model, so the freshly round-tripped body has none…
    assert!(
        body.get("model").is_none(),
        "the cohere writer does not itself emit model (the routing lane does): {body}"
    );
    // …until the routing lane stamps it.
    let w = CohereWriter;
    let changed = w.rewrite_model_if_needed(&mut body, "command-r-plus");
    assert!(changed, "stamping a fresh model must report a change");
    assert_eq!(
        body["model"], "command-r-plus",
        "the routed model must land on the cohere egress body"
    );
    // Idempotent: stamping the same model again is a no-op (keeps a same-proto passthrough pristine).
    assert!(
        !w.rewrite_model_if_needed(&mut body, "command-r-plus"),
        "re-stamping an identical model must not report a change"
    );
}

// ─────────────────────────────────── RESPONSE: identity ───────────────────────────────────

/// Watches: `id`, `finish_reason`, `message.tool_calls`.
#[test]
fn cohere_response_identity_and_tool_calls_survive_roundtrip() {
    let out = response_roundtrip(json!({
        "id": "c-abc-123",
        "finish_reason": "TOOL_CALL",
        "message": {
            "role": "assistant",
            "tool_calls": [
                {"id": "tc1", "type": "function",
                 "function": {"name": "lookup", "arguments": "{\"a\":1}"}}
            ]
        },
        "usage": {"tokens": {"input_tokens": 3, "output_tokens": 4}}
    }));

    assert_eq!(out["id"], "c-abc-123", "response id must survive: {out}");
    // finish_reason: Cohere's TOOL_CALL maps to the IR tool-use stop and back to TOOL_CALL.
    assert_eq!(
        out["finish_reason"], "TOOL_CALL",
        "finish_reason must survive: {out}"
    );
    let tc = &out["message"]["tool_calls"]
        .as_array()
        .expect("tool_calls array")[0];
    assert_eq!(tc["id"], "tc1", "tool_call id must survive");
    assert_eq!(
        tc["function"]["name"], "lookup",
        "tool_call name must survive"
    );
    assert_eq!(
        tc["function"]["arguments"], "{\"a\":1}",
        "tool_call arguments must survive"
    );
}

// ─────────────────────────────────── RESPONSE: usage ───────────────────────────────────

/// Watches: `usage.billed_units.input_tokens`, `usage.billed_units.output_tokens`,
/// `usage.billed_units.classifications`. Cohere reports a raw `tokens` bucket AND a separately-metered
/// `billed_units` bucket; the billed attribution is invisible in a token total that reconciles, so a
/// dropped billed count goes unnoticed unless an instrument watches it.
#[test]
fn cohere_response_billed_units_survive_roundtrip() {
    let out = response_roundtrip(json!({
        "id": "c1",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
        "finish_reason": "COMPLETE",
        "usage": {
            "tokens": {"input_tokens": 10, "output_tokens": 5},
            "billed_units": {"input_tokens": 9, "output_tokens": 4, "classifications": 2}
        }
    }));

    let bu = &out["usage"]["billed_units"];
    assert_eq!(
        bu["input_tokens"], 9,
        "billed_units.input_tokens must survive: {out}"
    );
    assert_eq!(
        bu["output_tokens"], 4,
        "billed_units.output_tokens must survive: {out}"
    );
    assert_eq!(
        bu["classifications"], 2,
        "billed_units.classifications must survive: {out}"
    );
}

/// Watches: `response/logprobs`. Cohere v2 response logprobs are TOKEN-ID sequences with no neutral
/// (token-string) shape, so they are NOT promoted to the IR — a same-protocol hop keeps them via the
/// verbatim relay, and a cross-protocol hop DROPS them with a documented `warn!`. This asserts the
/// drop is warned (never silent) and that the round-tripped body carries no fabricated `logprobs`.
#[test]
fn cohere_response_logprobs_drop_is_warned() {
    let body = json!({
        "id": "c1",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
        "finish_reason": "COMPLETE",
        "logprobs": [{"token_ids": [4, 2], "text": "hi", "logprobs": [-0.1, -0.2]}],
        "usage": {"tokens": {"input_tokens": 1, "output_tokens": 1}}
    });

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        let ir = CohereReader
            .read_response(&body)
            .expect("cohere response parses");
        let w = CohereWriter;
        w.write_response(&ir)
    });

    assert!(
        cap.messages()
            .iter()
            .any(|m| m.contains("logprobs") && m.contains("no")),
        "dropping cohere response logprobs cross-protocol must warn (never silent): {:?}",
        cap.messages()
    );
    assert!(
        out.get("logprobs").is_none(),
        "the round trip must not fabricate a `logprobs` field it cannot faithfully carry: {out}"
    );
}

// ─────────────────────────────────── RESPONSE: stream frames ───────────────────────────────────

/// Build the IR usage a stream terminal carries.
fn stream_usage() -> crate::ir::IrUsage {
    crate::ir::IrUsage {
        input_tokens: 7,
        output_tokens: 3,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
        detail: crate::ir::IrUsageDetail::default(),
    }
}

/// Watches: `stream:message-start`, `stream:content-start`, `stream:content-delta`,
/// `stream:content-end`, `stream:tool-call-start`, `stream:tool-call-delta`, `stream:tool-call-end`,
/// `stream:message-end`. Drives the IR stream-event lifecycle through the Cohere writer and asserts
/// each native frame type is produced with its native shape.
#[test]
fn cohere_stream_events_reach_a_cohere_client() {
    use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent};
    let w = CohereWriter;

    // message-start
    let (_, start) = w
        .write_response_event(&IrStreamEvent::MessageStart {
            role: IrRole::Assistant,
            usage: None,
            id: Some("co_1".to_string()),
            created: None,
            model: None,
        })
        .expect("message-start frame");
    assert_eq!(start["type"], "message-start", "stream:message-start");
    assert_eq!(start["id"], "co_1", "message-start carries the id");

    // content-start
    let (_, cs) = w
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Text,
        })
        .expect("content-start frame");
    assert_eq!(cs["type"], "content-start", "stream:content-start");

    // content-delta
    let (_, cd) = w
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::TextDelta("hi".to_string()),
        })
        .expect("content-delta frame");
    assert_eq!(cd["type"], "content-delta", "stream:content-delta");
    assert_eq!(
        cd["delta"]["message"]["content"]["text"], "hi",
        "content-delta carries the text chunk"
    );

    // content-end (BlockStop on the text index)
    let (_, ce) = w
        .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
        .expect("content-end frame");
    assert_eq!(ce["type"], "content-end", "stream:content-end");

    // tool-call-start
    let (_, ts) = w
        .write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: IrBlockMeta::ToolUse {
                id: "tc1".to_string(),
                name: "search".to_string(),
            },
        })
        .expect("tool-call-start frame");
    assert_eq!(ts["type"], "tool-call-start", "stream:tool-call-start");
    assert_eq!(
        ts["delta"]["message"]["tool_calls"]["function"]["name"], "search",
        "tool-call-start carries the tool name"
    );

    // tool-call-delta
    let (_, td) = w
        .write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: IrDelta::InputJsonDelta("{\"q\":".to_string()),
        })
        .expect("tool-call-delta frame");
    assert_eq!(td["type"], "tool-call-delta", "stream:tool-call-delta");
    assert_eq!(
        td["delta"]["message"]["tool_calls"]["function"]["arguments"], "{\"q\":",
        "tool-call-delta carries the argument fragment"
    );

    // tool-call-end (BlockStop on the tool index)
    let (_, te) = w
        .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
        .expect("tool-call-end frame");
    assert_eq!(te["type"], "tool-call-end", "stream:tool-call-end");

    // message-end
    let (_, me) = w
        .write_response_event(&IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: stream_usage(),
        })
        .expect("message-end frame");
    assert_eq!(me["type"], "message-end", "stream:message-end");
    assert_eq!(
        me["delta"]["usage"]["tokens"]["input_tokens"], 7,
        "message-end carries stream usage"
    );
}

/// Watches: `stream:citation-end`. Cohere natively brackets each citation with a `citation-start`
/// (carrying the Citation) and a matching `citation-end` (a bare structural close). The Cohere writer
/// emits the PAIR via its multi-frame `write_response_events` override, so a streamed citation is
/// bracketed exactly like a native one instead of leaving an unbalanced lone `citation-start`.
#[test]
fn cohere_stream_citation_end_pairs_with_start() {
    use crate::ir::{IrCitation, IrDelta, IrStreamEvent};
    let w = CohereWriter;

    let citation = IrCitation {
        kind: Some("char_location".to_string()),
        cited_text: Some("grounded".to_string()),
        title: None,
        url: None,
        document_index: None,
        start_index: Some(0),
        end_index: Some(8),
        encrypted_index: None,
        raw: None,
    };

    let frames = w.write_response_events(&IrStreamEvent::BlockDelta {
        index: 0,
        delta: IrDelta::CitationsDelta(vec![citation]),
    });

    assert_eq!(
        frames.len(),
        2,
        "a streamed citation must emit a start AND an end frame: {frames:?}"
    );
    assert_eq!(
        frames[0].1["type"], "citation-start",
        "the first frame is the native citation-start"
    );
    assert_eq!(
        frames[1].1["type"], "citation-end",
        "stream:citation-end must be emitted, paired with the start"
    );
    assert_eq!(
        frames[1].1["index"], 0,
        "citation-end carries the same index as its start"
    );
}
