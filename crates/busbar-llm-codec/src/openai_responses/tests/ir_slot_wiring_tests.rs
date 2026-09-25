// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping round 2 (Q57, ir-slots-landed.md): the Responses reader FILLS and the writer EMITS the
//! typed IR slots. Each request probe drives reader → `chat_prepare_for_egress` → writer, and the
//! seam clears `extra`, so a member reaches the far side ONLY through its typed slot.

use super::*;

/// Responses reader → cross-protocol seam (which clears `extra`) → `egress` writer.
fn seam(egress: &str, body: &serde_json::Value) -> serde_json::Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress protocol");
    let mut req = ResponsesReader.read_request(body).expect("read_request");
    crate::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_substrate_values::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "chat",
            egress_requires_max_tokens: false,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    assert!(req.extra.is_empty(), "the seam clears extra");
    egress_p.writer().write_request(&req)
}

fn thinking(
    text: &str,
    signature: Option<&str>,
    origin: Option<crate::ir::IrSignatureOrigin>,
    redacted: bool,
) -> crate::ir::IrBlock {
    crate::ir::IrBlock::Thinking {
        text: text.to_string(),
        signature: signature.map(String::from),
        redacted,
        cache_control: None,
        kind: None,
        signature_origin: origin,
    }
}

fn request_with(messages: Vec<crate::ir::IrMessage>) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages,
        ..ResponsesReader
            .read_request(&serde_json::json!({"model": "gpt", "input": "hi"}))
            .expect("read")
    }
}

fn reasoning_items(out: &serde_json::Value) -> Vec<serde_json::Value> {
    out["input"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i["type"] == "reasoning")
        .cloned()
        .collect()
}

// ─────────────────────────────── RSP-14 / IR-09 reasoning off ───────────────────────────────

/// RSP-14 (IR-09): `reasoning.effort: "none"` is reasoning switched OFF, not "nothing said": it
/// reaches an Anthropic backend as `thinking:{type:"disabled"}`, and a foreign lane is never handed
/// an ENABLE ask projected from it (the Responses writer omits it — no lane declares `"none"`).
#[test]
fn rsp14_effort_none_is_reasoning_off() {
    let body = serde_json::json!({"model": "gpt", "input": "hi", "max_output_tokens": 64,
        "reasoning": {"effort": "none"}});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    let anthropic = seam("anthropic", &body);
    assert_eq!(anthropic["thinking"]["type"], "disabled", "{anthropic}");
    let responses = seam("responses", &body);
    assert!(responses.get("reasoning").is_none(), "{responses}");
}

// ─────────────────────────────── IR-03 .. IR-07 (Chat ↔ Responses shared members) ───────────────

/// IR-03 metadata, IR-04 service_tier, IR-05 store, IR-06 safety_identifier / prompt_cache_key,
/// IR-07 text.verbosity: each crosses the seam in its typed slot.
#[test]
fn ir03_07_shared_request_members_cross_the_seam() {
    let body = serde_json::json!({"model": "gpt", "input": "hi",
        "metadata": {"b": "2", "a": "1"}, "service_tier": "flex", "store": false,
        "safety_identifier": "sid-1", "prompt_cache_key": "pck-1",
        "text": {"verbosity": "low"}});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert_eq!(ir.service_tier, Some(crate::ir::IrServiceTier::Flex));
    assert_eq!(ir.store, Some(false));
    assert_eq!(ir.verbosity, Some(crate::ir::IrVerbosity::Low));

    let out = seam("responses", &body);
    assert_eq!(
        out["metadata"],
        serde_json::json!({"a": "1", "b": "2"}),
        "{out}"
    );
    assert_eq!(out["service_tier"], "flex", "{out}");
    assert_eq!(out["store"], false, "{out}");
    assert_eq!(out["safety_identifier"], "sid-1", "{out}");
    assert_eq!(out["prompt_cache_key"], "pck-1", "{out}");
    assert_eq!(out["text"]["verbosity"], "low", "{out}");
}

/// IR-07: verbosity sits beside a structured-output `format` in the one `text` object.
#[test]
fn ir07_verbosity_merges_with_text_format() {
    let body = serde_json::json!({"model": "gpt", "input": "hi",
        "text": {"verbosity": "high", "format": {"type": "json_object"}}});
    let out = seam("responses", &body);
    assert_eq!(out["text"]["verbosity"], "high", "{out}");
    assert_eq!(out["text"]["format"]["type"], "json_object", "{out}");
}

// ─────────────────────────────── IR-14 developer role ───────────────────────────────

/// IR-14: a system prompt written as `developer` items goes back as a `developer` item; a `system`
/// one keeps the `instructions` member.
#[test]
fn ir14_developer_role_crosses_the_seam() {
    let dev = serde_json::json!({"model": "gpt", "input": [
        {"type": "message", "role": "developer", "content": "be terse"},
        {"type": "message", "role": "user", "content": "hi"}]});
    let ir = ResponsesReader.read_request(&dev).expect("read");
    assert_eq!(ir.system_role, Some(crate::ir::IrSystemRole::Developer));
    let out = seam("responses", &dev);
    assert_eq!(
        out["input"][0],
        serde_json::json!({"role": "developer", "content": "be terse"}),
        "{out}"
    );
    assert!(out.get("instructions").is_none(), "{out}");

    let sys = serde_json::json!({"model": "gpt", "input": [
        {"role": "system", "content": "be terse"}, {"role": "user", "content": "hi"}]});
    let ir = ResponsesReader.read_request(&sys).expect("read");
    assert_eq!(ir.system_role, Some(crate::ir::IrSystemRole::System));
    assert_eq!(seam("responses", &sys)["instructions"], "be terse");

    // `instructions` names no role: beside a developer item the role is unknown.
    let mixed = serde_json::json!({"model": "gpt", "instructions": "x", "input": [
        {"role": "developer", "content": "y"}, {"role": "user", "content": "hi"}]});
    let ir = ResponsesReader.read_request(&mixed).expect("read");
    assert_eq!(ir.system_role, None);
}

// ─────────────────────────────── IR-08 image detail ───────────────────────────────

/// IR-08: `input_image.detail` crosses the seam, in a message and in a tool result.
#[test]
fn ir08_image_detail_crosses_the_seam() {
    let body = serde_json::json!({"model": "gpt", "input": [
        {"role": "user", "content": [
            {"type": "input_image", "image_url": "https://x/a.png", "detail": "low"}]},
        {"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "c1", "output": [
            {"type": "input_image", "image_url": "https://x/b.png", "detail": "high"}]}]});
    let out = seam("responses", &body);
    let input = out["input"].as_array().expect("input");
    assert_eq!(input[0]["content"][0]["detail"], "low", "{out}");
    let fco = input
        .iter()
        .find(|i| i["type"] == "function_call_output")
        .expect("fco");
    assert_eq!(fco["output"][0]["detail"], "high", "{out}");
}

// ─────────────────────────────── IR-10 / RSP-15 allowed_tools ───────────────────────────────

/// RSP-15 (IR-10): the `allowed_tools` tool choice is read into the subset slot and written back,
/// mode included, instead of vanishing.
#[test]
fn rsp15_allowed_tools_cross_the_seam() {
    let tool = |n: &str| serde_json::json!({"type": "function", "name": n, "parameters": {}});
    let body = serde_json::json!({"model": "gpt", "input": "hi",
        "tools": [tool("a"), tool("b"), tool("c")],
        "tool_choice": {"type": "allowed_tools", "mode": "required", "tools": [
            {"type": "function", "name": "a"}, {"type": "function", "name": "c"}]}});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert_eq!(
        ir.allowed_tools,
        Some(vec!["a".to_string(), "c".to_string()])
    );
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
    let out = seam("responses", &body);
    assert_eq!(
        out["tool_choice"],
        serde_json::json!({"type": "allowed_tools", "mode": "required", "tools": [
            {"type": "function", "name": "a"}, {"type": "function", "name": "c"}]}),
        "{out}"
    );

    let auto = serde_json::json!({"model": "gpt", "input": "hi", "tools": [tool("a")],
        "tool_choice": {"type": "allowed_tools", "mode": "auto", "tools": [
            {"type": "function", "name": "a"}]}});
    assert_eq!(seam("responses", &auto)["tool_choice"]["mode"], "auto");
}

// ─────────────────────────────── IR-11 hosted tools ───────────────────────────────

/// IR-11: a web search and an auto-container code interpreter cross the seam in the neutral
/// hosted slot and are written back in the Responses spelling.
#[test]
fn ir11_hosted_tools_cross_the_seam() {
    let body = serde_json::json!({"model": "gpt", "input": "hi", "tools": [
        {"type": "web_search", "search_context_size": "high",
         "filters": {"allowed_domains": ["example.com"]},
         "user_location": {"type": "approximate", "country": "GB", "city": "London"}},
        {"type": "code_interpreter", "container": {"type": "auto"}}]});
    let out = seam("responses", &body);
    let tools = out["tools"].as_array().expect("tools");
    assert_eq!(
        tools[0],
        serde_json::json!({"type": "web_search", "search_context_size": "high",
            "filters": {"allowed_domains": ["example.com"]},
            "user_location": {"type": "approximate", "country": "GB", "city": "London"}}),
        "{out}"
    );
    assert_eq!(
        tools[1],
        serde_json::json!({"type": "code_interpreter", "container": {"type": "auto"}}),
        "{out}"
    );

    // A kind with no Responses tool is dropped and reported.
    let mut req = request_with(Vec::new());
    req.hosted_tools = vec![crate::ir::IrHostedTool::WebFetch(Default::default())];
    let w = ResponsesWriter;
    assert!(w.write_request(&req).get("tools").is_none());
    assert!(w.dropped_egress_controls(&req).contains(&"web_fetch"));

    // A code interpreter bound to explicit files has no neutral form: it stays raw (same-protocol
    // only), never a typed tool that silently lost its files.
    let files = serde_json::json!({"model": "gpt", "input": "hi", "tools": [
        {"type": "code_interpreter", "container": {"type": "auto", "file_ids": ["f1"]}}]});
    let ir = ResponsesReader.read_request(&files).expect("read");
    assert!(ir.hosted_tools.is_empty());
    assert!(ir.tools[0].hosted.is_some());
}

// ─────────────────────────────── IR-02 refusal ───────────────────────────────

/// IR-02: an assistant-history refusal part goes back as a refusal part.
#[test]
fn ir02_request_history_refusal_stays_a_refusal() {
    let body = serde_json::json!({"model": "gpt", "input": [
        {"role": "user", "content": "do the bad thing"},
        {"type": "message", "role": "assistant", "content": [
            {"type": "refusal", "refusal": "I can't help with that."}]},
        {"role": "user", "content": "ok"}]});
    let out = seam("responses", &body);
    assert_eq!(
        out["input"][1]["content"][0],
        serde_json::json!({"type": "refusal", "refusal": "I can't help with that."}),
        "{out}"
    );
}

/// IR-02: a buffered refusal answer reaches the Responses client as a refusal part, and the
/// stream reader flags the refusal block the way the buffered read does.
#[test]
fn ir02_response_refusal_is_a_refusal_part_buffered_and_streamed() {
    let output = serde_json::json!([{"type": "message", "id": "msg_1", "role": "assistant",
        "status": "completed", "content": [{"type": "refusal", "refusal": "No."}]}]);
    let body = serde_json::json!({"id": "resp_1", "object": "response", "created_at": 1,
        "status": "completed", "model": "gpt", "output": output,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}});
    let ir = ResponsesReader.read_response(&body).expect("read");
    assert!(matches!(
        &ir.content[0],
        crate::ir::IrBlock::Text { refusal: true, text, .. } if text == "No."
    ));
    let w = ResponsesWriter;
    let out = w.write_response(&ir);
    assert_eq!(
        out["output"][0]["content"],
        serde_json::json!([{"type": "refusal", "refusal": "No."}]),
        "{out}"
    );

    let mut state = crate::ir::StreamDecodeState::default();
    let evs = ResponsesReader.read_response_events(
        "response.completed",
        &serde_json::json!({"type": "response.completed", "response": {"id": "resp_1",
            "status": "completed", "output": output,
            "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        &mut state,
    );
    assert!(
        evs.iter().any(|e| matches!(
            e,
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::Text,
                refusal: true,
                ..
            }
        )),
        "{evs:?}"
    );
}

/// IR-02: a streamed refusal block is written as the refusal part lifecycle — `content_part.added`
/// with a `refusal` part, `refusal.delta`, `refusal.done`, and the finalized item — which is what the
/// buffered body carries.
#[test]
fn ir02_stream_refusal_block_writes_refusal_events() {
    let w = ResponsesWriter;
    let mut frames = Vec::new();
    for ev in [
        IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        },
        IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
            refusal: true,
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("No.".to_string()),
        },
        IrStreamEvent::BlockStop { index: 0 },
    ] {
        frames.extend(w.write_response_events(&ev));
    }
    let names: Vec<&str> = frames.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "response.created",
            "response.output_item.added",
            "response.content_part.added",
            "response.refusal.delta",
            "response.refusal.done",
            "response.content_part.done",
            "response.output_item.done"
        ]
    );
    assert_eq!(
        frames[2].1["part"],
        serde_json::json!({"type": "refusal", "refusal": ""})
    );
    assert_eq!(frames[3].1["delta"], "No.");
    assert_eq!(frames[4].1["refusal"], "No.");
    assert_eq!(
        frames[6].1["item"]["content"],
        serde_json::json!([{"type": "refusal", "refusal": "No."}])
    );
}

// ─────────────────────────────── IR-18 / RSP-13 signature provenance ───────────────────────────

/// RSP-13 (IR-18): a foreign thinking signature is never sent as `encrypted_content`. A
/// signature-only foreign block becomes no item at all (no fabricated `rs_` item); a foreign block
/// with text keeps the text and loses only the blob; an OpenAI or unknown-origin blob is sent.
#[test]
fn rsp13_foreign_signature_is_not_sent_as_encrypted_content() {
    use crate::ir::IrSignatureOrigin as O;
    let assistant = |block| crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![block],
    };
    let w = ResponsesWriter;

    let out = w.write_request(&request_with(vec![assistant(thinking(
        "",
        Some("SIG-ANTHROPIC"),
        Some(O::Anthropic),
        false,
    ))]));
    assert!(reasoning_items(&out).is_empty(), "{out}");

    let out = w.write_request(&request_with(vec![assistant(thinking(
        "hmm",
        Some("SIG-GEMINI"),
        Some(O::Gemini),
        false,
    ))]));
    let items = reasoning_items(&out);
    assert_eq!(items.len(), 1, "{out}");
    assert!(items[0].get("encrypted_content").is_none(), "{out}");

    for origin in [Some(O::OpenAi), None] {
        let out = w.write_request(&request_with(vec![assistant(thinking(
            "",
            Some("ENC"),
            origin,
            false,
        ))]));
        assert_eq!(
            reasoning_items(&out)[0]["encrypted_content"],
            "ENC",
            "{out}"
        );
    }

    // A redacted block (a vendor's opaque bytes) is never sent, whatever its origin.
    let out = w.write_request(&request_with(vec![assistant(thinking(
        "OPAQUE",
        Some("SIG"),
        Some(O::Anthropic),
        true,
    ))]));
    assert!(reasoning_items(&out).is_empty(), "{out}");
}

/// IR-18 reader half: a Responses `encrypted_content` is OpenAI-minted, on a request and a response.
#[test]
fn ir18_responses_encrypted_content_is_openai_origin() {
    let body = serde_json::json!({"model": "gpt", "input": [
        {"type": "reasoning", "summary": [], "encrypted_content": "ENC"},
        {"role": "user", "content": "hi"}]});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert!(matches!(
        &ir.messages[0].content[0],
        crate::ir::IrBlock::Thinking {
            signature_origin: Some(crate::ir::IrSignatureOrigin::OpenAi),
            ..
        }
    ));
    let resp = serde_json::json!({"id": "resp_1", "object": "response", "created_at": 1,
        "status": "completed", "model": "gpt", "output": [
            {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "ENC"}],
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}});
    let ir = ResponsesReader.read_response(&resp).expect("read");
    assert!(matches!(
        &ir.content[0],
        crate::ir::IrBlock::Thinking {
            signature_origin: Some(crate::ir::IrSignatureOrigin::OpenAi),
            ..
        }
    ));
}

// ─────────────────────────────── IR-17 thinking kind ───────────────────────────────

/// IR-17: a summary-only reasoning item is a Summary, and goes back into `summary[]`; a content-only
/// item is Full and keeps the `reasoning_text` part.
#[test]
fn ir17_reasoning_summary_stays_a_summary() {
    let body = serde_json::json!({"model": "gpt", "input": [
        {"type": "reasoning", "summary": [{"type": "summary_text", "text": "short"}]},
        {"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "long"}]},
        {"role": "user", "content": "hi"}]});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert!(matches!(
        &ir.messages[0].content[0],
        crate::ir::IrBlock::Thinking {
            kind: Some(crate::ir::IrThinkingKind::Summary),
            ..
        }
    ));
    assert!(matches!(
        &ir.messages[1].content[0],
        crate::ir::IrBlock::Thinking {
            kind: Some(crate::ir::IrThinkingKind::Full),
            ..
        }
    ));
    let out = seam("responses", &body);
    let items = reasoning_items(&out);
    assert_eq!(
        items[0]["summary"],
        serde_json::json!([{"type": "summary_text", "text": "short"}]),
        "{out}"
    );
    assert!(items[0].get("content").is_none(), "{out}");
    assert_eq!(items[1]["content"][0]["text"], "long", "{out}");
}

// ─────────────────────────────── SHR-03 OpenAI file ids ───────────────────────────────

/// SHR-03: an OpenAI Files id a Chat reader tagged (`"openai"`) reaches the Responses writer as
/// `input_image.file_id` / `input_file.file_id` — one namespace — instead of being dropped as a
/// foreign vendor handle.
#[test]
fn shr03_chat_file_id_reaches_responses_input() {
    let vendor = |id: &str| crate::ir::IrImageSource::Vendor {
        vendor: "openai",
        value: serde_json::json!({ "file_id": id }),
    };
    let req = request_with(vec![crate::ir::IrMessage {
        role: crate::ir::IrRole::User,
        content: vec![
            crate::ir::IrBlock::Image {
                source: vendor("file-img"),
                cache_control: None,
                detail: None,
            },
            crate::ir::IrBlock::Media {
                kind: crate::ir::IrMediaKind::Document,
                source: vendor("file-doc"),
                name: None,
                cache_control: None,
                citations: None,
                context: None,
            },
        ],
    }]);
    let w = ResponsesWriter;
    let out = w.write_request(&req);
    assert_eq!(
        out["input"][0]["content"],
        serde_json::json!([
            {"type": "input_image", "file_id": "file-img"},
            {"type": "input_file", "file_id": "file-doc"}]),
        "{out}"
    );
}
