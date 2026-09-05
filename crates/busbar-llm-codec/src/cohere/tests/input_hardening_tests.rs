// Input-hardening (1.6.0): the Cohere reader EDGE-VALIDATES structural types. Top-level `messages`
// is array-only (already strict); per-message `content` is string-or-array, so a present number/
// bool/object is a genuine TYPE violation → native 400 (ClientError / ir_parse). A `tool_calls`
// entry must carry a non-empty `id`. These pin BOTH the reject AND the preserved leniency.

use super::*;

fn assert_ir_parse_reject(res: Result<crate::ir::IrRequest, IrError>, ctx: &str) {
    let err = res.expect_err(ctx);
    assert_eq!(
        err.class,
        StatusClass::ClientError,
        "{ctx}: must be a client 400"
    );
    assert_eq!(
        err.provider_signal.as_deref(),
        Some(busbar_substrate::proto::SIGNAL_IR_PARSE),
        "{ctx}: must carry the ir_parse signal"
    );
}

// ── Fix 1: top-level `messages` type ─────────────────────────────────────────

#[test]
fn top_level_messages_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "messages": "nope"}),
        serde_json::json!({"model": "x", "messages": 7}),
        serde_json::json!({"model": "x", "messages": {"a": 1}}),
    ] {
        assert_ir_parse_reject(
            CohereReader.read_request(&bad),
            "a present non-array `messages` must reject",
        );
    }
}

#[test]
fn empty_messages_array_stays_lenient() {
    // NOTE: Cohere pre-1.6.0 already REQUIRES the `messages` key to be present (an absent key is a
    // separate, pre-existing 400 unrelated to this hardening). A PRESENT-but-empty array, however,
    // is well-typed and must still parse — an empty conversation is not a type violation.
    let ir = CohereReader
        .read_request(&serde_json::json!({"model": "x", "messages": []}))
        .expect("empty messages array must not reject");
    assert!(ir.messages.is_empty());
}

// ── Fix 1: per-message `content` type ────────────────────────────────────────

#[test]
fn per_message_wrong_typed_content_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "messages": [{"role": "user", "content": 5}]}),
        serde_json::json!({"model": "x", "messages": [{"role": "user", "content": {"a": 1}}]}),
        serde_json::json!({"model": "x", "messages": [{"role": "user", "content": true}]}),
    ] {
        assert_ir_parse_reject(
            CohereReader.read_request(&bad),
            "a present wrong-typed per-message content must reject",
        );
    }
}

#[test]
fn per_message_string_and_array_content_stay_lenient() {
    CohereReader
        .read_request(
            &serde_json::json!({"model": "x", "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("string content must parse");
    CohereReader
        .read_request(&serde_json::json!({"model": "x", "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]}))
        .expect("array content must parse");
}

// ── Fix 2: tool_calls `id` ───────────────────────────────────────────────────

#[test]
fn tool_call_missing_id_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "tool_calls": [{"type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}),
        serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "tool_calls": [{"id": "", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}),
    ] {
        assert_ir_parse_reject(
            CohereReader.read_request(&bad),
            "a tool_call with no usable id must reject",
        );
    }
}

#[test]
fn tool_call_with_id_parses() {
    let ir = CohereReader
        .read_request(&serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "tool_calls": [{"id": "call_abc", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}))
        .expect("a tool_call with a non-empty id must parse");
    let has_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { id, .. } if id == "call_abc"));
    assert!(
        has_id,
        "the tool_call id must be carried into the IR verbatim"
    );
}
