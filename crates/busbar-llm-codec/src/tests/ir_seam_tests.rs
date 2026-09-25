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
