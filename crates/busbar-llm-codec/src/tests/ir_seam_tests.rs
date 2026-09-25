// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping Q57 — the cross-protocol SEAM (IR-CORE): what `chat_prepare_for_ingress` and the
//! shared OpenAI annotation mapping keep. Probe-style: a real upstream body goes through the egress
//! dialect's reader, the production seam step, and the ingress dialect's writer, exactly as the
//! forward path runs them.

use serde_json::{json, Value};

/// Buffered cross-protocol response: egress reader -> `chat_prepare_for_ingress` -> ingress writer.
fn xresp(egress: &str, ingress: &'static str, body: &Value) -> Value {
    let egress_p = crate::proto_codec::protocol_for(egress).expect("egress dialect");
    let ingress_p = crate::proto_codec::protocol_for(ingress).expect("ingress dialect");
    let mut ir = egress_p
        .reader()
        .read_response(body)
        .expect("egress reader accepts the body");
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, ingress, 1_752_000_000);
    ingress_p.writer().write_response(&ir)
}

/// Every `url_citation` annotation anywhere in a written body, whichever OpenAI shape it has.
fn url_citations(v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let mut stack = vec![v];
    while let Some(n) = stack.pop() {
        match n {
            Value::Object(m) => {
                if m.get("type").and_then(Value::as_str) == Some("url_citation") {
                    // Chat nests the fields under `url_citation`; Responses flattens them.
                    out.push(m.get("url_citation").cloned().unwrap_or_else(|| n.clone()));
                }
                stack.extend(m.values());
            }
            Value::Array(a) => stack.extend(a.iter()),
            _ => {}
        }
    }
    out
}

/// SHR-01: an OpenAI Chat backend's `url_citation` (with its character span) reaches a Responses
/// client. Before, the shared reader dropped the span and the Responses writer, which requires one,
/// dropped the whole citation — `annotations: []`.
#[test]
fn shr01_chat_citation_with_its_span_reaches_a_responses_client() {
    let body = json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "gpt",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {
            "role": "assistant", "content": "hello world",
            "annotations": [{"type": "url_citation", "url_citation": {
                "url": "https://c.example", "title": "t", "start_index": 6, "end_index": 11}}]}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}
    });
    let out = xresp("openai", "responses", &body);
    let cites = url_citations(&out);
    assert_eq!(
        cites.len(),
        1,
        "citation lost on openai -> responses: {out}"
    );
    assert_eq!(cites[0]["url"], "https://c.example");
    assert_eq!(cites[0]["start_index"], 6);
    assert_eq!(cites[0]["end_index"], 11);
}

/// SHR-01, the reverse hop: a Responses backend's citation keeps its span for a Chat client.
#[test]
fn shr01_responses_citation_keeps_its_span_for_a_chat_client() {
    let body = json!({
        "id": "resp_1", "object": "response", "created_at": 1, "status": "completed",
        "model": "gpt",
        "output": [{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": "hello world", "annotations": [
                {"type": "url_citation", "url": "https://c.example", "title": "t",
                 "start_index": 6, "end_index": 11}]}]}],
        "usage": {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}
    });
    let out = xresp("responses", "openai", &body);
    let cites = url_citations(&out);
    assert_eq!(
        cites.len(),
        1,
        "citation lost on responses -> openai: {out}"
    );
    assert_eq!(cites[0]["start_index"], 6, "span dropped: {out}");
    assert_eq!(cites[0]["end_index"], 11, "span dropped: {out}");
}

/// The span rule's other half: offsets a citation carries into the CITED DOCUMENT (an Anthropic
/// `char_location`) are not a span of the answer text and must never be written as one.
#[test]
fn shr01_document_offsets_are_never_written_as_an_answer_span() {
    let c = crate::ir::IrCitation {
        kind: Some("char_location".to_string()),
        url: Some("https://doc.example".to_string()),
        start_index: Some(0),
        end_index: Some(5),
        ..Default::default()
    };
    let chat =
        crate::openai_annotations::chat_url_annotations("hello world", 0, std::slice::from_ref(&c));
    assert_eq!(chat.len(), 1);
    assert!(
        chat[0]["url_citation"].get("start_index").is_none(),
        "a document offset was written as an answer span: {chat:?}"
    );
    // A text-span kind keeps its carried span.
    let web = crate::ir::IrCitation {
        kind: Some("web_search_result_location".to_string()),
        ..c
    };
    let chat = crate::openai_annotations::chat_url_annotations("hello world", 0, &[web]);
    assert_eq!(chat[0]["url_citation"]["start_index"], 0);
    assert_eq!(chat[0]["url_citation"]["end_index"], 5);
}

/// SEAM (`chat_prepare_for_ingress`): the matched stop string survives the buffered seam. A
/// Bedrock Converse body carries it (`additionalModelResponseFields.stop_sequence`) and the
/// Anthropic writer emits it; the seam used to null it, so the buffered answer said `null` where
/// the stream path (`MessageDelta.stop_sequence`, never stripped) kept it. Driven from the IR the
/// egress reader hands the seam, so it pins the seam step itself whichever reader filled the field.
#[test]
fn seam_matched_stop_sequence_survives_the_buffered_seam() {
    let mut ir = crate::ir::IrResponse {
        content: vec![crate::ir::IrBlock::Text {
            text: "one two".to_string(),
            cache_control: None,
            citations: vec![],
        }],
        stop_reason: Some(crate::ir::IrStopReason::StopSequence),
        stop_sequence: Some("###".to_string()),
        usage: crate::ir::IrUsage {
            input_tokens: 3,
            output_tokens: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    crate::chat_handle::chat_prepare_for_ingress(&mut ir, "anthropic", 1_752_000_000);
    let out = crate::proto_codec::protocol_for("anthropic")
        .expect("anthropic")
        .writer()
        .write_response(&ir);
    assert_eq!(out["stop_reason"], "stop_sequence", "{out}");
    assert_eq!(
        out["stop_sequence"], "###",
        "matched stop string lost: {out}"
    );
}

/// The seam still normalizes what no target can carry: the backend's id format never reaches a
/// different dialect's client, and `system_fingerprint` (OpenAI Chat only) is cleared.
#[test]
fn seam_still_mints_a_native_id_and_clears_the_chat_only_fingerprint() {
    let body = json!({
        "id": "chatcmpl-abc", "object": "chat.completion", "created": 1, "model": "gpt",
        "system_fingerprint": "fp_1",
        "choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "hi"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    });
    let out = xresp("openai", "anthropic", &body);
    let id = out["id"].as_str().expect("anthropic id");
    assert!(id.starts_with("msg_"), "foreign id leaked: {out}");
    assert!(out.get("system_fingerprint").is_none(), "{out}");
}

/// SHR-03: one OpenAI Files id namespace, two dialect tags. The shared helper reads the id off a
/// reference either OpenAI reader produced, and nothing else.
#[test]
fn shr03_openai_file_id_is_read_from_either_openai_dialects_reference() {
    use crate::ir::IrImageSource;
    for vendor in crate::openai_annotations::OPENAI_FILES_VENDOR_TAGS {
        let src = IrImageSource::Vendor {
            vendor,
            value: json!({"file_id": "file-abc"}),
        };
        assert_eq!(
            crate::openai_annotations::openai_file_id(&src),
            Some("file-abc"),
            "{vendor}"
        );
    }
    let s3 = IrImageSource::Vendor {
        vendor: "bedrock",
        value: json!({"file_id": "file-abc"}),
    };
    assert_eq!(crate::openai_annotations::openai_file_id(&s3), None);
    let empty = IrImageSource::Vendor {
        vendor: "openai",
        value: json!({"file_id": ""}),
    };
    assert_eq!(crate::openai_annotations::openai_file_id(&empty), None);
}

/// The tags ARE what the two OpenAI readers stamp: a Chat `file.file_id` part and a Responses
/// `input_file.file_id` part both read into a reference the helper resolves — if either reader
/// renames its tag, this fails rather than the id silently stopping to cross.
#[test]
fn shr03_both_openai_readers_produce_a_reference_the_helper_resolves() {
    fn first_media_source(ir: &crate::ir::IrRequest) -> crate::ir::IrImageSource {
        ir.messages
            .iter()
            .flat_map(|m| m.content.iter())
            .find_map(|b| match b {
                crate::ir::IrBlock::Media { source, .. } => Some(source.clone()),
                _ => None,
            })
            .expect("a Media block")
    }
    let chat = json!({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "file", "file": {"file_id": "file-abc"}}]}]});
    let responses = json!({"model": "m", "input": [{"role": "user", "content": [
        {"type": "input_file", "file_id": "file-abc"}]}]});
    for (dialect, body) in [("openai", chat), ("responses", responses)] {
        let ir = crate::proto_codec::protocol_for(dialect)
            .expect("dialect")
            .reader()
            .read_request(&body)
            .expect("read_request");
        let src = first_media_source(&ir);
        assert_eq!(
            crate::openai_annotations::openai_file_id(&src),
            Some("file-abc"),
            "{dialect}: {src:?}"
        );
    }
}

/// BED-06 family gate through the production write (`write_egress_request` with the lane model):
/// a cross-protocol reasoning ask becomes Converse `thinking` on a Claude lane and is dropped on a
/// Nova lane, whose reasoning field is spelled differently.
#[test]
fn bed06_bedrock_thinking_is_written_only_for_a_claude_lane_model() {
    use busbar_substrate_values::ir::handle::IrHandle;
    let body = json!({
        "model": "claude-x", "max_tokens": 8192,
        "thinking": {"type": "enabled", "budget_tokens": 4096},
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = crate::proto_codec::protocol_for("anthropic")
        .expect("anthropic")
        .reader()
        .read_request(&body)
        .expect("read");
    let write = |model: &str| {
        let mut h = crate::chat_handle::ChatReqHandle(ir.clone());
        match h.write_egress_request("bedrock", model) {
            busbar_substrate_values::wire::EgressWire::Json(v) => v,
            _ => panic!("chat writes JSON"),
        }
    };
    for claude in [
        "anthropic.claude-sonnet-4-5-20250929-v1:0",
        "us.anthropic.claude-opus-4-1-20250805-v1:0",
        "arn:aws:bedrock:us-east-1:123:inference-profile/global.anthropic.claude-sonnet-4-5",
    ] {
        let out = write(claude);
        assert_eq!(
            out["additionalModelRequestFields"]["thinking"]["type"], "enabled",
            "{claude}: {out}"
        );
    }
    let nova = write("amazon.nova-pro-v1:0");
    assert!(
        nova.pointer("/additionalModelRequestFields/thinking")
            .is_none(),
        "Claude's thinking field reached a Nova lane: {nova}"
    );
}
