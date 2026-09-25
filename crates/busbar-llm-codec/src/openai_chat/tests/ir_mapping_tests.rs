// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING tests for the OpenAI Chat Completions dialect (owner directive Q57: a field the source
//! dialect carries that the IR and the target can carry must map). One test (or group) per defect id
//! of the 1.6.0 IR mapping audit, `OAI-xx`. Each drives the PRODUCTION step list on a real body:
//! reader → `chat_prepare_for_egress` / `chat_prepare_for_ingress` → writer, and streams through
//! `StreamTranslate` — the same seam a cross-protocol request takes.

use serde_json::{json, Value};

/// Cross-protocol REQUEST: `ingress` reader → the egress seam → `egress` writer.
fn xreq(ingress: &'static str, egress: &str, body: &Value) -> Value {
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress protocol");
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress protocol");
    let mut req = ingress_p
        .reader()
        .read_request(body)
        .expect("ingress body reads");
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
            lane_caps: Default::default(),
        },
    );
    egress_p.writer().write_request(&req)
}

/// Cross-protocol BUFFERED RESPONSE: `egress` (backend) reader → the ingress seam → `ingress` writer.
fn xresp(egress: &str, ingress: &'static str, body: &Value) -> Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress protocol");
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress protocol");
    let mut resp = egress_p
        .reader()
        .read_response(body)
        .expect("backend body reads");
    crate::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&resp)
}

/// Cross-protocol STREAM: raw `egress` (backend) SSE bytes → `ingress` client bytes.
fn xstream(egress: &str, ingress: &str, raw: &str) -> String {
    let mut st =
        crate::proto_stream::StreamTranslate::new(ingress, egress).expect("stream translator");
    let mut out = st.feed(raw.as_bytes());
    out.extend(st.finish());
    String::from_utf8_lossy(&out).into_owned()
}

/// OpenAI chat SSE body from a list of chunk objects.
fn oai_sse(chunks: &[Value]) -> String {
    let mut s = String::new();
    for c in chunks {
        s.push_str("data: ");
        s.push_str(&c.to_string());
        s.push_str("\n\n");
    }
    s.push_str("data: [DONE]\n\n");
    s
}

/// The decoded IR events of an OpenAI chat SSE body (the reader alone, no writer).
fn oai_stream_events(chunks: &[Value]) -> Vec<crate::ir::IrStreamEvent> {
    use crate::proto_codec::ProtocolReader;
    let reader = super::OpenAiReader;
    let mut st = crate::ir::StreamDecodeState::default();
    let mut out = Vec::new();
    for c in chunks {
        out.extend(reader.read_response_events("", c, &mut st));
    }
    out
}

fn anthropic_req(extra: Value) -> Value {
    let mut body = json!({
        "model": "claude-x",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}]
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    body
}

// ── OAI-01: the output cap crossing into an OpenAI lane ─────────────────────────────────────────

/// OAI-01 (codec half, architect ruling). The codec writer does NOT pick the spelling blind: a
/// cross-protocol cap is written as `max_tokens` (the key every OpenAI-compatible host accepts), and
/// the lane's provider entry decides at the egress seam whether it becomes `max_completion_tokens`.
/// An OpenAI-origin IR keeps the caller's own spelling, and the sentinel never leaks.
#[test]
fn oai01_codec_writes_source_spelling_or_max_tokens() {
    use crate::proto_codec::{ProtocolReader, ProtocolWriter};
    let out = xreq("anthropic", "openai", &anthropic_req(json!({})));
    assert_eq!(out["max_tokens"], json!(100), "{out}");
    assert!(out.get("max_completion_tokens").is_none(), "{out}");

    for (key, other) in [
        ("max_tokens", "max_completion_tokens"),
        ("max_completion_tokens", "max_tokens"),
    ] {
        let ir = super::OpenAiReader
            .read_request(&json!({
                "model": "gpt-5",
                "messages": [{"role": "user", "content": "hi"}],
                key: 9
            }))
            .expect("reads");
        let out = super::openai_writer().write_request(&ir);
        assert_eq!(out[key], json!(9), "{out}");
        assert!(out.get(other).is_none(), "{out}");
        assert!(
            !out.to_string().contains("__busbar"),
            "sentinel leaked: {out}"
        );
    }
}

// ── OAI-04: a structured-json tool result reaches the OpenAI tool message ───────────────────────

/// OAI-04. A Bedrock `toolResult` whose content is `{"json":…}` is written as the serialized JSON
/// string in the OpenAI `tool` message, after any text in the same result.
#[test]
fn oai04_json_tool_result_is_serialized_into_tool_content() {
    let bedrock = json!({
        "messages": [
            {"role": "user", "content": [{"text": "q"}]},
            {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t1",
                "content": [{"text": "bad:"}, {"json": {"x": 1}}]}}]}
        ],
        "inferenceConfig": {"maxTokens": 10}
    });
    let out = xreq("bedrock", "openai", &bedrock);
    let tool = out["messages"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["role"] == "tool"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(tool["content"], json!("bad:{\"x\":1}"), "{out}");
}

// ── OAI-10: `reasoning_effort: "xhigh"` ─────────────────────────────────────────────────────────

/// OAI-10. `xhigh` reaches the IR as the highest effort the IR has (`High`) instead of no ask, and
/// an OpenAI-origin re-serialize still writes `xhigh` verbatim.
#[test]
fn oai10_xhigh_effort_maps_to_high() {
    use crate::proto_codec::{ProtocolReader, ProtocolWriter};
    let body = json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "hi"}],
        "reasoning_effort": "xhigh"
    });
    let ir = super::OpenAiReader.read_request(&body).expect("reads");
    // IR-09 landed: `xhigh` is the IR's own word now (its budget projection is still High's).
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::XHigh
        ))
    );
    let same = super::openai_writer().write_request(&ir);
    assert_eq!(same["reasoning_effort"], json!("xhigh"), "{same}");

    // Cross-protocol: the ask reaches a Gemini lane as a thinking budget (the High table entry).
    let out = xreq("openai", "gemini", &body);
    assert_eq!(
        out.pointer("/generationConfig/thinkingConfig/thinkingBudget"),
        Some(&json!(crate::ir::REASONING_BUDGET_DEFAULTS[3])),
        "{out}"
    );
}

// ── OAI-11: an assistant turn with no Chat-expressible content ──────────────────────────────────

/// OAI-11. An Anthropic assistant turn carrying only `thinking` is written with `content: ""`,
/// never `content: null` without `tool_calls` (an OpenAI 400).
#[test]
fn oai11_thinking_only_assistant_turn_is_not_null_content() {
    let body = anthropic_req(json!({
        "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "thinking", "thinking": "hmm", "signature": "s"}]},
            {"role": "user", "content": "again"}
        ]
    }));
    let out = xreq("anthropic", "openai", &body);
    let msgs = out["messages"].as_array().cloned().unwrap_or_default();
    for m in &msgs {
        assert!(
            !(m["content"].is_null() && m.get("tool_calls").is_none()),
            "null content without tool_calls: {out}"
        );
    }
    let asst = msgs
        .iter()
        .find(|m| m["role"] == "assistant")
        .cloned()
        .unwrap_or_default();
    assert_eq!(asst["content"], json!(""), "{out}");
}

// ── stream helpers ───────────────────────────────────────────────────────────────────────────────

/// Assert the IR stream is strictly balanced: every index opens at most once, every delta lands on
/// an OPEN index, every open index closes exactly once.
fn assert_balanced(events: &[crate::ir::IrStreamEvent]) {
    use crate::ir::IrStreamEvent as E;
    let mut opened = std::collections::BTreeSet::new();
    let mut open = std::collections::BTreeSet::new();
    for e in events {
        match e {
            E::BlockStart { index, .. } => {
                assert!(
                    opened.insert(*index),
                    "index {index} opened twice: {events:?}"
                );
                open.insert(*index);
            }
            E::BlockDelta { index, .. } => {
                assert!(
                    open.contains(index),
                    "delta on closed index {index}: {events:?}"
                );
            }
            E::BlockStop { index } => {
                assert!(
                    open.remove(index),
                    "stop on non-open index {index}: {events:?}"
                );
            }
            _ => {}
        }
    }
    assert!(open.is_empty(), "blocks left open {open:?}: {events:?}");
}

fn text_deltas(events: &[crate::ir::IrStreamEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::TextDelta(t),
                ..
            } => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

fn thinking_deltas(events: &[crate::ir::IrStreamEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::ThinkingDelta(t),
                ..
            } => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

// ── OAI-02: streamed `delta.annotations` ─────────────────────────────────────────────────────────

/// OAI-02. A streamed `delta.annotations` url_citation reaches the IR as a CitationsDelta on the
/// text block and a foreign client (Anthropic) receives it.
#[test]
fn oai02_stream_annotations_become_citations() {
    let chunks = [
        json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "gpt",
               "choices": [{"index": 0, "delta": {"role": "assistant", "content": "hello"}, "finish_reason": null}]}),
        json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "gpt",
               "choices": [{"index": 0, "delta": {"annotations": [{"type": "url_citation",
                   "url_citation": {"url": "https://c.example", "title": "t", "start_index": 0, "end_index": 5}}]},
                   "finish_reason": null}]}),
        json!({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "gpt",
               "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ];
    let events = oai_stream_events(&chunks);
    assert_balanced(&events);
    let cites: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            crate::ir::IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::CitationsDelta(c),
            } => Some((*index, c.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(cites.len(), 1, "{events:?}");
    assert_eq!(cites[0].0, 0, "the citation rides the text block");
    assert_eq!(cites[0].1[0].url.as_deref(), Some("https://c.example"));

    let out = xstream("openai", "anthropic", &oai_sse(&chunks));
    assert!(out.contains("https://c.example"), "{out}");
}

// ── OAI-14: interleaved reasoning / text after tool calls ────────────────────────────────────────

/// OAI-14 (text). Preamble text → tool call → MORE text: the resumed text is carried in a NEW text
/// block at a fresh index (not dropped, not reopened at the closed index).
#[test]
fn oai14_text_after_tool_calls_is_carried() {
    let chunks = [
        json!({"id": "c", "created": 1, "model": "m",
               "choices": [{"index": 0, "delta": {"role": "assistant", "content": "before "}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
               "function": {"name": "f", "arguments": "{}"}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"content": "after"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
    ];
    let events = oai_stream_events(&chunks);
    assert_balanced(&events);
    assert_eq!(text_deltas(&events), "before after", "{events:?}");

    let out = xstream("openai", "anthropic", &oai_sse(&chunks));
    assert!(out.contains("\"after\""), "{out}");
}

/// OAI-14 (reasoning). Text → reasoning → text: the late reasoning is carried as a Thinking block at
/// a fresh index, and no already-opened index shifts.
#[test]
fn oai14_reasoning_after_text_is_carried() {
    let chunks = [
        json!({"id": "c", "created": 1, "model": "m",
               "choices": [{"index": 0, "delta": {"role": "assistant", "content": "a"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"reasoning_content": "think"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"content": "b"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
               "function": {"name": "f", "arguments": "{}"}}]}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"reasoning_content": "more"}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ];
    let events = oai_stream_events(&chunks);
    assert_balanced(&events);
    assert_eq!(text_deltas(&events), "ab", "{events:?}");
    assert_eq!(thinking_deltas(&events), "thinkmore", "{events:?}");
    // The first text block keeps index 0.
    assert!(matches!(
        events
            .iter()
            .find(|e| matches!(e, crate::ir::IrStreamEvent::BlockStart { .. })),
        Some(crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
            refusal: _,
        })
    ));
}

// ── OAI-03: service_tier ─────────────────────────────────────────────────────────────────────────

fn oai_resp(extra: Value) -> Value {
    let mut body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    body
}

/// OAI-03. OpenAI `service_tier` is read into the IR tier (`default` ↔ `standard`, `priority` ↔
/// `priority`) and written back as OpenAI's top-level member, buffered and streamed.
#[test]
fn oai03_service_tier_maps_both_ways() {
    // OpenAI backend → Anthropic client.
    let out = xresp(
        "openai",
        "anthropic",
        &oai_resp(json!({"service_tier": "priority"})),
    );
    assert_eq!(
        out.pointer("/usage/service_tier"),
        Some(&json!("priority")),
        "{out}"
    );

    // Anthropic backend → OpenAI client.
    let anthropic = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 1, "service_tier": "standard"}
    });
    let out = xresp("anthropic", "openai", &anthropic);
    assert_eq!(out["service_tier"], json!("default"), "{out}");

    // Stream: the tier on the finish / usage chunk reaches the IR usage detail.
    let events = oai_stream_events(&[
        json!({"id": "c", "created": 1, "model": "m", "service_tier": "priority",
               "choices": [{"index": 0, "delta": {"role": "assistant", "content": "hi"}, "finish_reason": null}]}),
        json!({"id": "c", "created": 1, "model": "m", "service_tier": "priority",
               "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ]);
    let tier = events.iter().find_map(|e| match e {
        crate::ir::IrStreamEvent::MessageDelta { usage, .. } => usage.detail.service_tier.clone(),
        _ => None,
    });
    assert_eq!(tier.as_deref(), Some("priority"), "{events:?}");

    // …and the OpenAI stream writer puts it on the terminal chunk.
    use crate::proto_codec::ProtocolWriter;
    let w = super::openai_writer();
    let (_, chunk) = w
        .write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 3,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
                detail: crate::ir::IrUsageDetail {
                    service_tier: Some("standard".to_string()),
                    ..Default::default()
                },
            },
            stop_detail: None,
        })
        .expect("terminal chunk");
    assert_eq!(chunk["service_tier"], json!("default"), "{chunk}");
}

// ── OAI-12: a refused turn in `message.refusal` ──────────────────────────────────────────────────

/// OAI-12. An Anthropic `stop_reason: "refusal"` response reaches an OpenAI client as a native
/// refusal — the text in `message.refusal`, `content: null` — and an OpenAI refusal survives the
/// IR round trip in the same slot.
#[test]
fn oai12_refusal_text_is_written_to_message_refusal() {
    let anthropic = json!({
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-x",
        "content": [{"type": "text", "text": "I can't help with that."}],
        "stop_reason": "refusal", "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 5}
    });
    let out = xresp("anthropic", "openai", &anthropic);
    let msg = &out["choices"][0]["message"];
    assert_eq!(msg["refusal"], json!("I can't help with that."), "{out}");
    assert!(msg["content"].is_null(), "{out}");

    // A non-refused turn keeps its text in `content`.
    let out = xresp(
        "anthropic",
        "openai",
        &json!({
            "id": "msg_2", "type": "message", "role": "assistant", "model": "claude-x",
            "content": [{"type": "text", "text": "sure"}],
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": {"input_tokens": 3, "output_tokens": 1}
        }),
    );
    assert_eq!(
        out["choices"][0]["message"]["content"],
        json!("sure"),
        "{out}"
    );
    assert!(out["choices"][0]["message"]["refusal"].is_null(), "{out}");

    // OpenAI refusal → IR → OpenAI writer: the refusal stays a refusal.
    use crate::proto_codec::{ProtocolReader, ProtocolWriter};
    let body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": null, "refusal": "no"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
    });
    let ir = super::OpenAiReader.read_response(&body).expect("reads");
    let out = super::openai_writer().write_response(&ir);
    assert_eq!(
        out["choices"][0]["message"]["refusal"],
        json!("no"),
        "{out}"
    );
    assert!(out["choices"][0]["message"]["content"].is_null(), "{out}");
}

// ── OAI-08: legacy `function_call` responses ─────────────────────────────────────────────────────

/// OAI-08. A legacy `message.function_call` response becomes a tool call for a foreign client
/// (buffered and streamed), not a `tool_use` stop with no block.
#[test]
fn oai08_legacy_function_call_response_is_a_tool_use() {
    let body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt-3.5-turbo",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": null,
            "function_call": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}},
            "finish_reason": "function_call"}],
        "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4}
    });
    let out = xresp("openai", "anthropic", &body);
    let tool = out["content"]
        .as_array()
        .and_then(|a| a.iter().find(|b| b["type"] == "tool_use"))
        .cloned()
        .unwrap_or_default();
    assert_eq!(tool["name"], json!("get_weather"), "{out}");
    assert_eq!(tool["input"], json!({"city": "Paris"}), "{out}");
    assert!(tool["id"].as_str().is_some_and(|s| !s.is_empty()), "{out}");
    assert_eq!(out["stop_reason"], json!("tool_use"), "{out}");

    let chunks = [
        json!({"id": "c", "created": 1, "model": "m",
               "choices": [{"index": 0, "delta": {"role": "assistant", "content": null,
                   "function_call": {"name": "get_weather", "arguments": ""}}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"function_call": {"arguments": "{\"city\":"}}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {"function_call": {"arguments": "\"Paris\"}"}}, "finish_reason": null}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "function_call"}]}),
    ];
    let events = oai_stream_events(&chunks);
    assert_balanced(&events);
    assert!(events.iter().any(|e| matches!(e,
        crate::ir::IrStreamEvent::BlockStart { block: crate::ir::IrBlockMeta::ToolUse { name, id }, .. }
            if name == "get_weather" && !id.is_empty())), "{events:?}");
    let args: String = events
        .iter()
        .filter_map(|e| match e {
            crate::ir::IrStreamEvent::BlockDelta {
                delta: crate::ir::IrDelta::InputJsonDelta(a),
                ..
            } => Some(a.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(args, "{\"city\":\"Paris\"}");
}

// ── OAI-09: `tools[type:"custom"]` ───────────────────────────────────────────────────────────────

/// OAI-09. A Chat `custom` tool is not turned into an empty-name function tool: cross-protocol it is
/// dropped (no foreign dialect has a free-text tool), the function tools beside it survive, and an
/// OpenAI-origin IR re-emits it verbatim.
#[test]
fn oai09_custom_tool_is_not_an_empty_name_function() {
    use crate::proto_codec::{ProtocolReader, ProtocolWriter};
    let custom = json!({"type": "custom", "custom": {"name": "code_exec", "description": "run",
        "format": {"type": "text"}}});
    let body = json!({
        "model": "gpt-5",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [
            custom.clone(),
            {"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}
        ]
    });
    let out = xreq("openai", "anthropic", &body);
    let tools = out["tools"].as_array().cloned().unwrap_or_default();
    assert_eq!(tools.len(), 1, "{out}");
    assert_eq!(tools[0]["name"], json!("f"), "{out}");

    let ir = super::OpenAiReader.read_request(&body).expect("reads");
    let same = super::openai_writer().write_request(&ir);
    // Round 3 item 11: the custom tool now rides the typed hosted-tool slot and is written after
    // the function tools (same members, same object).
    assert!(
        same["tools"].as_array().unwrap().contains(&custom),
        "{same}"
    );
}

// ── OAI-06: bare-base64 `file.file_data` ─────────────────────────────────────────────────────────

/// OAI-06. A `file.file_data` sent as BARE base64 (no `data:` prefix) is the file's content, typed
/// by its filename — it reaches a foreign lane as a base64 document, not as a URL every writer drops.
#[test]
fn oai06_bare_base64_file_data_is_base64() {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "read"},
            {"type": "file", "file": {"filename": "a.pdf", "file_data": "JVBERi0xLjQ="}}
        ]}]
    });
    use crate::proto_codec::ProtocolReader;
    let ir = super::OpenAiReader.read_request(&body).expect("reads");
    let media = ir.messages[0].content.iter().find_map(|b| match b {
        crate::ir::IrBlock::Media { source, .. } => Some(source.clone()),
        _ => None,
    });
    assert_eq!(
        media,
        Some(crate::ir::IrImageSource::Base64 {
            media_type: "application/pdf".to_string(),
            data: "JVBERi0xLjQ=".to_string()
        })
    );
    let out = xreq("openai", "responses", &body);
    let s = out.to_string();
    assert!(
        s.contains("data:application/pdf;base64,JVBERi0xLjQ="),
        "{out}"
    );
}

// ── OAI-07: legacy function-calling requests ─────────────────────────────────────────────────────

fn legacy_request() -> Value {
    json!({
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "user", "content": "weather?"},
            {"role": "assistant", "content": null,
             "function_call": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}},
            {"role": "function", "name": "get_weather", "content": "sunny"}
        ],
        "functions": [{"name": "get_weather", "description": "d",
                       "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}],
        "function_call": {"name": "get_weather"}
    })
}

/// OAI-07. Legacy `functions` / `function_call` / `role:"function"` map onto the modern IR (tools,
/// tool choice, a paired ToolUse / ToolResult) and reach a foreign lane; an OpenAI-origin
/// re-serialize writes the legacy shape back unchanged.
#[test]
fn oai07_legacy_function_calling_request_maps() {
    use crate::proto_codec::{ProtocolReader, ProtocolWriter};
    let out = xreq("openai", "anthropic", &legacy_request());
    assert_eq!(out["tools"][0]["name"], json!("get_weather"), "{out}");
    assert_eq!(
        out["tool_choice"],
        json!({"type": "tool", "name": "get_weather"}),
        "{out}"
    );
    let msgs = out["messages"].as_array().cloned().unwrap_or_default();
    let call = msgs
        .iter()
        .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
        .find(|b| b["type"] == "tool_use")
        .unwrap_or_default();
    let result = msgs
        .iter()
        .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
        .find(|b| b["type"] == "tool_result")
        .unwrap_or_default();
    assert_eq!(call["name"], json!("get_weather"), "{out}");
    assert_eq!(call["input"], json!({"city": "Paris"}), "{out}");
    assert!(call["id"].as_str().is_some_and(|s| !s.is_empty()), "{out}");
    assert_eq!(
        result["tool_use_id"], call["id"],
        "result pairs with its call: {out}"
    );

    // OpenAI-origin re-serialize: the legacy shape, not a mixed legacy/modern body.
    let ir = super::OpenAiReader
        .read_request(&legacy_request())
        .expect("reads");
    let same = super::openai_writer().write_request(&ir);
    assert!(same.get("tools").is_none(), "{same}");
    assert!(same.get("tool_choice").is_none(), "{same}");
    assert_eq!(same["functions"], legacy_request()["functions"], "{same}");
    assert_eq!(
        same["function_call"],
        json!({"name": "get_weather"}),
        "{same}"
    );
    let m = same["messages"].as_array().cloned().unwrap_or_default();
    assert!(m[1].get("tool_calls").is_none(), "{same}");
    assert_eq!(
        m[1]["function_call"]["name"],
        json!("get_weather"),
        "{same}"
    );
    assert_eq!(
        m[2],
        json!({"role": "function", "name": "get_weather", "content": "sunny"}),
        "{same}"
    );
    assert!(!same.to_string().contains("__busbar"), "{same}");
}

/// OAI-01 (lane half, architect ruling). A lane that declares `max_output_key:
/// max_completion_tokens` receives a cross-protocol cap — the caller's, and the one the seam injects
/// — as `max_completion_tokens`; a lane that declares nothing receives `max_tokens`.
#[test]
fn oai01_lane_max_output_key_decides_the_cross_protocol_spelling() {
    use crate::proto_codec::{LaneCaps, MaxOutputKey, ProtocolReader, ProtocolWriter};
    let completion_lane = LaneCaps {
        max_output_key: MaxOutputKey::MaxCompletionTokens,
        ..LaneCaps::default()
    };
    let mut ir = crate::proto_codec::protocol_for("anthropic")
        .expect("anthropic")
        .reader()
        .read_request(&anthropic_req(json!({})))
        .expect("reads");
    ir.extra.clear();
    let w = super::openai_writer();
    let on = w.write_request_for_lane(&ir, "gpt-5", &completion_lane);
    assert_eq!(on["max_completion_tokens"], json!(100), "{on}");
    assert!(on.get("max_tokens").is_none(), "{on}");
    let off = w.write_request_for_lane(&ir, "llama-3", &LaneCaps::default());
    assert_eq!(off["max_tokens"], json!(100), "{off}");
    assert!(off.get("max_completion_tokens").is_none(), "{off}");

    // A caller's own `max_completion_tokens` is never downgraded, whatever the lane declares.
    let origin = super::OpenAiReader
        .read_request(
            &json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "max_completion_tokens": 5}),
        )
        .expect("reads");
    let kept = w.write_request_for_lane(&origin, "llama-3", &LaneCaps::default());
    assert_eq!(kept["max_completion_tokens"], json!(5), "{kept}");
}
