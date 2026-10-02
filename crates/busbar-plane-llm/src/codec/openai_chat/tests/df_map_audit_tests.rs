//! DF-MAP audit (ARCHITECT rulings 2026-10-02): what the Chat reader now maps into the IR's answer
//! slots, and the reader-tolerance fix for a replayed custom-tool call.
use super::super::proto_codec::protocol_for;
use serde_json::json;

fn answer(extra: serde_json::Value) -> serde_json::Value {
    let mut body = json!({"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}});
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    body
}

fn read(body: &serde_json::Value) -> crate::codec::ir::IrResponse {
    protocol_for("openai")
        .unwrap()
        .reader()
        .read_response(body)
        .expect("reads")
}

/// Ruling 3 (F2 reader tolerance): a replayed custom-tool call is a valid native message; the reader
/// used to refuse the whole request (400) because the call has no `function` member.
#[test]
fn a_replayed_custom_tool_call_is_not_refused() {
    let body = json!({"model": "m", "messages": [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": null, "tool_calls": [
            {"id": "call_1", "type": "custom", "custom": {"name": "grep", "input": "a b"}}]},
        {"role": "user", "content": "next"}]});
    let req = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(&body)
        .expect("a custom tool call must not be refused");
    assert_eq!(req.messages.len(), 3);
}

#[test]
fn moderation_results_read_as_safety_verdicts() {
    let resp = read(&answer(json!({"moderation": {
        "input": {"type": "moderation_results", "model": "omni", "results": [
            {"type": "moderation_result", "flagged": true, "model": "omni",
             "categories": {"violence": true, "hate": false},
             "category_scores": {"violence": 0.9, "hate": 0.1}}]}}})));
    assert_eq!(
        resp.safety,
        vec![crate::codec::ir::IrSafetyVerdict {
            category: "violence".to_string(),
            flagged: true,
            blocked: false,
        }]
    );
}

#[test]
fn message_audio_reads_as_audio_output() {
    let mut body = answer(json!({}));
    body["choices"][0]["message"]["audio"] =
        json!({"id": "audio_1", "data": "UklGRg==", "expires_at": 9, "transcript": "hello"});
    let resp = read(&body);
    assert_eq!(
        resp.audio,
        Some(crate::codec::ir::IrAudioOutput {
            data: Some("UklGRg==".to_string()),
            format: None,
            transcript: Some("hello".to_string()),
        })
    );
}

#[test]
fn usage_modality_slices_cross_both_ways() {
    let mut body = answer(json!({}));
    body["usage"]["prompt_tokens_details"] = json!({"text_tokens": 7, "image_tokens": 3});
    body["usage"]["completion_tokens_details"] = json!({"text_tokens": 4});
    let resp = read(&body);
    let m = resp.usage.detail.by_modality.clone().expect("by_modality");
    assert_eq!(
        (m.input.text, m.input.image, m.output.text),
        (Some(7), Some(3), Some(4))
    );
    let out = protocol_for("openai")
        .unwrap()
        .writer()
        .write_response(&resp);
    assert_eq!(out["usage"]["prompt_tokens_details"]["text_tokens"], 7);
    assert_eq!(out["usage"]["prompt_tokens_details"]["image_tokens"], 3);
    assert_eq!(out["usage"]["completion_tokens_details"]["text_tokens"], 4);
}
