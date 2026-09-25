// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR MAPPING (owner directive Q57): every field the Responses dialect carries that the IR and the
//! other dialect can also carry must cross the seam. One probe per defect id (RSP-xx), each driving
//! the production step list — reader → `chat_prepare_for_egress`/`_ingress` → writer on a real body,
//! or `StreamTranslate` on a real SSE stream — and asserting the field arrives.

use super::*;

// ─────────────────────────────────────── harness ───────────────────────────────────────

/// A cross-protocol REQUEST hop: `ingress` reader → egress seam → `egress` writer.
fn xreq(ingress: &'static str, egress: &str, body: &serde_json::Value) -> serde_json::Value {
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress protocol");
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress protocol");
    let mut req = ingress_p
        .reader()
        .read_request(body)
        .expect("read_request should succeed");
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
    let mut out = egress_p.writer().write_request(&req);
    crate::wire_shim::strip_router_shim_keys(&mut out, egress);
    out
}

/// A cross-protocol buffered RESPONSE hop: `egress` reader → ingress seam → `ingress` writer.
fn xresp(egress: &str, ingress: &'static str, body: &serde_json::Value) -> serde_json::Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress protocol");
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress protocol");
    let mut resp = egress_p
        .reader()
        .read_response(body)
        .expect("read_response should succeed");
    crate::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&resp)
}

/// A cross-protocol STREAM: the `egress` upstream's SSE bytes translated for an `ingress` client.
fn xstream(egress: &str, ingress: &str, raw: &str) -> (String, Option<String>) {
    let mut st = crate::proto_stream::StreamTranslate::new(ingress, egress).expect("translator");
    let mut out = st.feed(raw.as_bytes());
    out.extend(st.finish());
    let terminal_error = st.terminal_error().map(String::from);
    (String::from_utf8_lossy(&out).into_owned(), terminal_error)
}

/// SSE bytes for `(event, data)` frames.
fn sse(frames: &[(&str, serde_json::Value)]) -> String {
    frames
        .iter()
        .map(|(ev, data)| format!("event: {ev}\ndata: {data}\n\n"))
        .collect()
}

/// Every `data:` payload of an SSE body, parsed.
fn sse_payloads(body: &str) -> Vec<serde_json::Value> {
    body.lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect()
}

/// An Anthropic stream: a thinking block carrying `thinking` text AND a `signature_delta`, then text.
fn anthropic_thinking_stream() -> String {
    sse(&[
        (
            "message_start",
            serde_json::json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":1}}}),
        ),
        (
            "content_block_start",
            serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}),
        ),
        (
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm"}}),
        ),
        (
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"SIG-ANTHROPIC"}}),
        ),
        (
            "content_block_stop",
            serde_json::json!({"type":"content_block_stop","index":0}),
        ),
        (
            "content_block_start",
            serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
        ),
        (
            "content_block_delta",
            serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"hello"}}),
        ),
        (
            "content_block_stop",
            serde_json::json!({"type":"content_block_stop","index":1}),
        ),
        (
            "message_delta",
            serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":5}}),
        ),
        ("message_stop", serde_json::json!({"type":"message_stop"})),
    ])
}

fn responses_created() -> (&'static str, serde_json::Value) {
    (
        "response.created",
        serde_json::json!({"type":"response.created","sequence_number":0,"response":{"id":"resp_1","object":"response","created_at":1,"status":"in_progress","model":"gpt","output":[]}}),
    )
}

fn responses_completed(output: serde_json::Value) -> (&'static str, serde_json::Value) {
    (
        "response.completed",
        serde_json::json!({"type":"response.completed","response":{"id":"resp_1","object":"response","created_at":1,"status":"completed","model":"gpt","output":output,"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}}),
    )
}

// ─────────────────────────────────────── RSP-01 ───────────────────────────────────────

/// RSP-01: a streamed thinking signature reaches the Responses client as the reasoning item's
/// `encrypted_content` — on its `output_item.done` AND in the terminal `output[]` — exactly as the
/// buffered body carries it.
#[test]
fn rsp01_stream_signature_becomes_reasoning_encrypted_content() {
    let (out, _) = xstream("anthropic", "responses", &anthropic_thinking_stream());
    let payloads = sse_payloads(&out);
    let done = payloads
        .iter()
        .find(|p| p["type"] == "response.output_item.done" && p["item"]["type"] == "reasoning")
        .expect("a reasoning output_item.done");
    // IR-18: a Claude signature rides the Responses carrier inside busbar's
    // provenance envelope, which the Responses reader unwraps back to these exact bytes.
    let claude_sig =
        crate::ir::sig_envelope::wrap(crate::ir::IrSignatureOrigin::Anthropic, "SIG-ANTHROPIC");
    assert_eq!(
        done["item"]["encrypted_content"], claude_sig,
        "the streamed signature must ride the reasoning item: {done}"
    );
    let completed = payloads
        .iter()
        .find(|p| p["type"] == "response.completed")
        .expect("response.completed");
    let reasoning = completed["response"]["output"]
        .as_array()
        .and_then(|o| o.iter().find(|i| i["type"] == "reasoning"))
        .expect("reasoning item in the terminal output[]");
    assert_eq!(reasoning["encrypted_content"], claude_sig);
}

// ─────────────────────────────────────── RSP-02 ───────────────────────────────────────

/// RSP-02: a Responses reasoning item's `encrypted_content` (on `output_item.done`) reaches an
/// Anthropic stream client as the thinking block's `signature_delta`, before its block closes.
#[test]
fn rsp02_stream_reasoning_encrypted_content_becomes_signature_delta() {
    let raw = sse(&[
        responses_created(),
        (
            "response.output_item.added",
            serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[]}}),
        ),
        (
            "response.reasoning_summary_text.delta",
            serde_json::json!({"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":"sum"}),
        ),
        (
            "response.output_item.done",
            serde_json::json!({"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"sum"}],"encrypted_content":"ENC-RESPONSES"}}),
        ),
        responses_completed(serde_json::json!([])),
    ]);
    let (out, _) = xstream("responses", "anthropic", &raw);
    let payloads = sse_payloads(&out);
    let sig_pos = payloads
        .iter()
        .position(|p| p["delta"]["type"] == "signature_delta")
        .unwrap_or_else(|| panic!("no signature_delta in: {out}"));
    // IR-18: the OpenAI blob rides the Anthropic carrier inside busbar's
    // provenance envelope, which the Anthropic reader unwraps back to these exact bytes.
    assert_eq!(
        payloads[sig_pos]["delta"]["signature"],
        crate::ir::sig_envelope::wrap(crate::ir::IrSignatureOrigin::OpenAi, "ENC-RESPONSES")
    );
    let stop_pos = payloads
        .iter()
        .position(|p| p["type"] == "content_block_stop" && p["index"] == 0)
        .expect("thinking block closes");
    assert!(
        sig_pos < stop_pos,
        "the signature must precede the block's close"
    );
}

/// RSP-02: a reasoning item whose `reasoning_text` part closes (`content_part.done`) BEFORE the
/// item's `output_item.done` still carries the item's `encrypted_content` — the part close must not
/// end the block before the blob arrives.
#[test]
fn rsp02_reasoning_part_done_does_not_close_before_item_done() {
    let raw = sse(&[
        responses_created(),
        (
            "response.output_item.added",
            serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[],"content":[]}}),
        ),
        (
            "response.reasoning_text.delta",
            serde_json::json!({"type":"response.reasoning_text.delta","output_index":0,"content_index":0,"delta":"think"}),
        ),
        (
            "response.content_part.done",
            serde_json::json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":{"type":"reasoning_text","text":"think"}}),
        ),
        (
            "response.output_item.done",
            serde_json::json!({"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[],"content":[{"type":"reasoning_text","text":"think"}],"encrypted_content":"ENC-2"}}),
        ),
        responses_completed(serde_json::json!([])),
    ]);
    let (out, _) = xstream("responses", "anthropic", &raw);
    assert!(
        sse_payloads(&out)
            .iter()
            .any(|p| p["delta"]["type"] == "signature_delta"
                && p["delta"]["signature"]
                    == crate::ir::sig_envelope::wrap(
                        crate::ir::IrSignatureOrigin::OpenAi,
                        "ENC-2"
                    )),
        "encrypted_content lost when the reasoning part closed first: {out}"
    );
}

// ─────────────────────────────────────── RSP-03 ───────────────────────────────────────

/// RSP-03: a buffered Responses answer's `output_text.logprobs` reach a Chat client.
#[test]
fn rsp03_buffered_output_text_logprobs_reach_chat() {
    let body = serde_json::json!({
        "id": "resp_1", "object": "response", "created_at": 1, "status": "completed", "model": "gpt",
        "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": "hi", "annotations": [],
                "logprobs": [{"token": "hi", "logprob": -0.25, "bytes": [104, 105],
                    "top_logprobs": [{"token": "hey", "logprob": -1.5, "bytes": [104, 101, 121]}]}]}]}],
        "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
    });
    let out = xresp("responses", "openai", &body);
    let lp = &out["choices"][0]["logprobs"]["content"][0];
    assert_eq!(lp["token"], "hi", "logprobs dropped: {out}");
    assert_eq!(lp["logprob"], -0.25);
    assert_eq!(lp["top_logprobs"][0]["token"], "hey");
}

// ─────────────────────────────────────── RSP-04 ───────────────────────────────────────

/// RSP-04: a streamed `output_text.delta.logprobs` reaches a Chat stream client.
#[test]
fn rsp04_stream_output_text_delta_logprobs_reach_chat() {
    let raw = sse(&[
        responses_created(),
        (
            "response.output_item.added",
            serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","content":[]}}),
        ),
        (
            "response.output_text.delta",
            serde_json::json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"hello","logprobs":[{"token":"hello","logprob":-0.1,"top_logprobs":[]}]}),
        ),
        (
            "response.output_item.done",
            serde_json::json!({"type":"response.output_item.done","output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","content":[]}}),
        ),
        responses_completed(serde_json::json!([])),
    ]);
    let (out, _) = xstream("responses", "openai", &raw);
    assert!(
        sse_payloads(&out)
            .iter()
            .any(|p| p["choices"][0]["logprobs"]["content"][0]["token"] == "hello"),
        "streamed logprobs dropped: {out}"
    );
}

// ─────────────────────────────────────── RSP-05 / RSP-06 ───────────────────────────────────────

/// RSP-05: a Responses client's `user` reaches a Chat backend.
#[test]
fn rsp05_responses_user_reaches_chat() {
    let body = serde_json::json!({"model": "gpt", "input": "hi", "user": "end-user-7"});
    let out = xreq("responses", "openai", &body);
    assert_eq!(out["user"], "end-user-7", "user dropped: {out}");
}

/// RSP-06: a Chat client's `user` reaches a Responses backend.
#[test]
fn rsp06_chat_user_reaches_responses() {
    let body = serde_json::json!({"model": "gpt", "messages": [{"role": "user", "content": "hi"}],
        "user": "end-user-8"});
    let out = xreq("openai", "responses", &body);
    assert_eq!(out["user"], "end-user-8", "user dropped: {out}");
}

// ─────────────────────────────────────── RSP-07 / RSP-08 ───────────────────────────────────────

/// RSP-07: a Chat logprobs ask reaches a Responses backend as the `include` entry that makes it
/// return logprobs (`top_logprobs` alone does not).
#[test]
fn rsp07_chat_logprobs_ask_becomes_include() {
    let body = serde_json::json!({"model": "gpt", "messages": [{"role": "user", "content": "hi"}],
        "logprobs": true, "top_logprobs": 2});
    let out = xreq("openai", "responses", &body);
    assert_eq!(out["top_logprobs"], 2);
    let include = out["include"].as_array().expect("include array");
    assert!(
        include.iter().any(|v| v == "message.output_text.logprobs"),
        "no logprobs include: {out}"
    );
}

/// RSP-08: a Responses client's `include: ["message.output_text.logprobs"]` reaches a Chat backend
/// as `logprobs: true`.
#[test]
fn rsp08_responses_include_logprobs_reaches_chat() {
    // No `top_logprobs`: the `include` entry alone is the ask (a Chat writer would otherwise
    // force the flag from `top_logprobs`, hiding the drop).
    let body = serde_json::json!({"model": "gpt", "input": "hi",
        "include": ["message.output_text.logprobs"]});
    let out = xreq("responses", "openai", &body);
    assert_eq!(out["logprobs"], true, "logprobs ask dropped: {out}");
}

// ─────────────────────────────────────── RSP-09 ───────────────────────────────────────

/// RSP-09: an assistant-history `refusal` part keeps its text, and a user `input_audio` part
/// reaches a Chat backend as `input_audio` — neither becomes an empty text block.
#[test]
fn rsp09_refusal_and_input_audio_survive() {
    let body = serde_json::json!({"model": "gpt", "input": [
        {"role": "user", "content": [
            {"type": "input_text", "text": "listen"},
            {"type": "input_audio", "input_audio": {"data": "UklGRg==", "format": "wav"}}
        ]},
        {"role": "assistant", "content": [{"type": "refusal", "refusal": "I can't help with that."}]},
        {"role": "user", "content": "why?"}
    ]});
    let chat = xreq("responses", "openai", &body);
    let msgs = chat["messages"].as_array().expect("messages");
    let audio = msgs[0]["content"]
        .as_array()
        .and_then(|c| c.iter().find(|p| p["type"] == "input_audio"))
        .unwrap_or_else(|| panic!("input_audio dropped: {chat}"));
    assert_eq!(audio["input_audio"]["data"], "UklGRg==");
    assert_eq!(audio["input_audio"]["format"], "wav");
    let assistant = msgs
        .iter()
        .find(|m| m["role"] == "assistant")
        .expect("assistant turn");
    assert!(
        assistant.to_string().contains("I can't help with that."),
        "refusal text lost: {assistant}"
    );

    let anthropic = xreq("responses", "anthropic", &body);
    assert!(
        !anthropic.to_string().contains(r#""text":"""#),
        "an empty text block reached Anthropic: {anthropic}"
    );
}

// ─────────────────────────────────────── RSP-10 ───────────────────────────────────────

/// RSP-10: a tool result carrying an image reaches a Responses backend as a
/// `function_call_output.output` part array (text + image), not as an image-less string.
#[test]
fn rsp10_tool_result_image_reaches_function_call_output() {
    let body = serde_json::json!({"model": "claude", "max_tokens": 100, "messages": [
        {"role": "user", "content": "look"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "shot", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": [
            {"type": "text", "text": "here"},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
        ]}]}
    ]});
    let out = xreq("anthropic", "responses", &body);
    let fco = out["input"]
        .as_array()
        .and_then(|i| i.iter().find(|it| it["type"] == "function_call_output"))
        .expect("function_call_output item");
    let parts = fco["output"]
        .as_array()
        .unwrap_or_else(|| panic!("output is not a part array: {fco}"));
    assert!(parts
        .iter()
        .any(|p| p["type"] == "input_text" && p["text"] == "here"));
    assert!(
        parts.iter().any(|p| p["type"] == "input_image"
            && p["image_url"] == "data:image/png;base64,iVBORw0KGgo="),
        "tool-result image dropped: {fco}"
    );
}

/// RSP-10: a structured-JSON tool result (Bedrock `{"json": …}`) reaches a Responses backend as the
/// JSON text of `function_call_output.output`, not as `""`.
#[test]
fn rsp10_tool_result_json_reaches_function_call_output() {
    let body = serde_json::json!({"modelId": "m", "messages": [
        {"role": "user", "content": [{"text": "go"}]},
        {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "f", "input": {}}}]},
        {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "content": [{"json": {"temp": 21}}]}}]}
    ]});
    let out = xreq("bedrock", "responses", &body);
    let fco = out["input"]
        .as_array()
        .and_then(|i| i.iter().find(|it| it["type"] == "function_call_output"))
        .expect("function_call_output item");
    let output = fco["output"].as_str().expect("string output");
    let parsed: serde_json::Value =
        serde_json::from_str(output).unwrap_or_else(|_| panic!("not JSON text: {fco}"));
    assert_eq!(parsed, serde_json::json!({"temp": 21}));
}

// ─────────────────────────────────────── RSP-11 ───────────────────────────────────────

/// RSP-11: a FAILED generation streamed from Gemini (`MALFORMED_FUNCTION_CALL`) reaches a
/// Responses client as a `response.failed` terminal — and ONLY that: no `response.completed`
/// claiming the failed turn completed.
#[test]
fn rsp11_stream_failed_generation_is_response_failed_only() {
    let raw = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}],\"role\":\"model\"},\"finishReason\":\"MALFORMED_FUNCTION_CALL\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":1,\"totalTokenCount\":4}}\n\n";
    let (out, terminal_error) = xstream("gemini", "responses", raw);
    assert!(
        terminal_error.is_some(),
        "the failure must reach the breaker"
    );
    let payloads = sse_payloads(&out);
    let terminals: Vec<&str> = payloads
        .iter()
        .filter_map(|p| p["type"].as_str())
        .filter(|t| {
            matches!(
                *t,
                "response.completed" | "response.incomplete" | "response.failed"
            )
        })
        .collect();
    assert_eq!(
        terminals,
        vec!["response.failed"],
        "exactly one terminal, and it is response.failed: {out}"
    );
}

/// RSP-11: an `Error` stop reason on the terminal `MessageDelta` with no preceding `Error` event
/// is written as `response.failed` with a `server_error`, never `completed`.
#[test]
fn rsp11_error_stop_reason_message_delta_writes_response_failed() {
    let w = ResponsesWriter;
    w.write_response_events(&IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    });
    let frames = w.write_response_events(&IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::Error),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            detail: crate::ir::IrUsageDetail::default(),
        },
        stop_detail: None,
    });
    assert_eq!(frames.len(), 1);
    let (name, data) = &frames[0];
    assert_eq!(name, "response.failed");
    assert_eq!(data["response"]["status"], "failed");
    assert_eq!(data["response"]["error"]["code"], "server_error");
}

// ─────────────────────────────────────── RSP-12 ───────────────────────────────────────

/// RSP-12: the Responses stream's top-level `error` event surfaces as a stream error — the breaker
/// sees `terminal_error`, and an Anthropic client gets an `error` event instead of a clean close.
#[test]
fn rsp12_top_level_error_event_is_a_stream_error() {
    let raw = sse(&[
        responses_created(),
        (
            "response.output_text.delta",
            serde_json::json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"par"}),
        ),
        (
            "error",
            serde_json::json!({"type":"error","code":"server_error","message":"The server had an error.","param":null}),
        ),
    ]);
    let (out, terminal_error) = xstream("responses", "anthropic", &raw);
    assert_eq!(terminal_error.as_deref(), Some("server_error"));
    assert!(
        sse_payloads(&out).iter().any(|p| p["type"] == "error"),
        "no error event reached the client: {out}"
    );
}

// ─────────────────────────────────────── RSP-14 ───────────────────────────────────────

/// RSP-14: `reasoning.effort: "xhigh"` is carried as the IR's top effort rung, not dropped.
#[test]
fn rsp14_xhigh_effort_is_carried_as_high() {
    // IR-09: `xhigh` is the IR's own `XHigh` rung now; a Chat lane (no declared `xhigh`) still
    // receives the nearest word every model accepts.
    let body = serde_json::json!({"model": "gpt", "input": "hi", "reasoning": {"effort": "xhigh"}});
    let ir = ResponsesReader.read_request(&body).expect("read");
    assert_eq!(
        ir.reasoning,
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::XHigh
        ))
    );
    let chat = xreq("responses", "openai", &body);
    assert_eq!(chat["reasoning_effort"], "high", "effort dropped: {chat}");
}

// ─────────────────────────────────────── RSP-16 ───────────────────────────────────────

/// RSP-16: a streamed function call with a BLANK `call_id` gets the same synthesized id the
/// buffered read of the same answer gets — never an empty tool_use id.
#[test]
fn rsp16_stream_blank_call_id_is_synthesized_like_buffered() {
    let item = serde_json::json!({"type":"function_call","id":"fc_1","call_id":"","name":"lookup","arguments":""});
    let raw = sse(&[
        responses_created(),
        (
            "response.output_item.added",
            serde_json::json!({"type":"response.output_item.added","output_index":0,"item":item.clone()}),
        ),
        (
            "response.function_call_arguments.delta",
            serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"{}"}),
        ),
        (
            "response.output_item.done",
            serde_json::json!({"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"","name":"lookup","arguments":"{}"}}),
        ),
        responses_completed(serde_json::json!([
            {"type":"function_call","id":"fc_1","call_id":"","name":"lookup","arguments":"{}"}
        ])),
    ]);
    let (out, _) = xstream("responses", "anthropic", &raw);
    let start = sse_payloads(&out)
        .into_iter()
        .find(|p| p["content_block"]["type"] == "tool_use")
        .expect("tool_use block");
    assert!(
        !start["content_block"]["id"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "blank tool_use id reached the client: {out}"
    );

    // The reader's own id (before the cross-protocol id remap) equals the buffered read's.
    let mut state = crate::ir::StreamDecodeState::default();
    let streamed_id = ResponsesReader
        .read_response_events(
            "response.output_item.added",
            &serde_json::json!({"type":"response.output_item.added","output_index":0,"item":item}),
            &mut state,
        )
        .into_iter()
        .find_map(|e| match e {
            IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::ToolUse { id, .. },
                ..
            } => Some(id),
            _ => None,
        })
        .expect("a ToolUse BlockStart");

    let buffered = ResponsesReader
        .read_response(&serde_json::json!({
            "id": "resp_1", "object": "response", "created_at": 1, "status": "completed",
            "output": [{"type":"function_call","id":"fc_1","call_id":"","name":"lookup","arguments":"{}"}],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        }))
        .expect("buffered read");
    let buffered_id = match &buffered.content[0] {
        crate::ir::IrBlock::ToolUse { id, .. } => id.clone(),
        other => panic!("expected ToolUse, got {other:?}"),
    };
    assert_eq!(streamed_id, buffered_id, "stream and buffered disagree");
}

// ─────────────────────────────────────── RSP-17 ───────────────────────────────────────

/// RSP-17: the served tier crosses in both directions, buffered and streamed.
#[test]
fn rsp17_service_tier_crosses_both_directions() {
    // Anthropic → Responses client (buffered).
    let anthropic = serde_json::json!({"id": "msg_1", "type": "message", "role": "assistant",
        "model": "claude", "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 1, "service_tier": "priority"}});
    let out = xresp("anthropic", "responses", &anthropic);
    assert_eq!(out["service_tier"], "priority", "tier dropped: {out}");

    // Responses → Anthropic client (buffered): OpenAI `default` is the standard tier.
    let responses = serde_json::json!({"id": "resp_1", "object": "response", "created_at": 1,
        "status": "completed", "model": "gpt", "service_tier": "default",
        "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": "hi", "annotations": []}]}],
        "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}});
    let a = xresp("responses", "anthropic", &responses);
    assert_eq!(a["usage"]["service_tier"], "standard", "tier dropped: {a}");
    let ir = ResponsesReader.read_response(&responses).expect("read");
    assert_eq!(ir.usage.detail.service_tier.as_deref(), Some("standard"));

    // Responses stream → the IR terminal usage carries the tier.
    let mut state = crate::ir::StreamDecodeState::default();
    let evs = ResponsesReader.read_response_events(
        "response.completed",
        &serde_json::json!({"type":"response.completed","response":{"id":"resp_1","status":"completed","service_tier":"priority","output":[],"usage":{"input_tokens":1,"output_tokens":1}}}),
        &mut state,
    );
    let tier = evs.iter().find_map(|e| match e {
        IrStreamEvent::MessageDelta { usage, .. } => usage.detail.service_tier.clone(),
        _ => None,
    });
    assert_eq!(tier.as_deref(), Some("priority"));

    // … and a Responses stream client receives it on the terminal event.
    let w = ResponsesWriter;
    let frames = w.write_response_events(&IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            detail: crate::ir::IrUsageDetail {
                service_tier: Some("priority".to_string()),
                ..Default::default()
            },
        },
        stop_detail: None,
    });
    assert_eq!(frames[0].1["response"]["service_tier"], "priority");
}
