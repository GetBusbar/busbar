// Input-hardening (1.6.0): the reader EDGE-VALIDATES structural types — a PRESENT-but-wrong-typed
// field is rejected with a native 400 (ClientError / ir_parse) — while staying exactly as lenient as
// the provider otherwise (absent/optional fields, empty arrays, and unknown well-typed fields all
// still pass). These tests pin BOTH the reject AND the preserved leniency so a mutation that flips
// either direction is caught.

use super::*;

/// Assert a reader result is the canonical structural-parse rejection: a client 400 carrying the
/// `ir_parse` signal (the shape busbar renders into the ingress dialect's native error envelope).
fn assert_ir_parse_reject(res: Result<crate::ir::IrRequest, IrError>, ctx: &str) {
    let err = res.expect_err(ctx);
    assert_eq!(
        err.class,
        StatusClass::ClientError,
        "{ctx}: must be a client 400"
    );
    assert_eq!(
        err.provider_signal.as_deref(),
        Some(busbar_substrate_values::proto::SIGNAL_IR_PARSE),
        "{ctx}: must carry the ir_parse signal"
    );
}

// ── Fix 1: top-level `messages` type ─────────────────────────────────────────

#[test]
fn top_level_messages_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "messages": "not-an-array"}),
        serde_json::json!({"model": "x", "messages": 42}),
        serde_json::json!({"model": "x", "messages": {"a": 1}}),
    ] {
        assert_ir_parse_reject(
            OpenAiReader.read_request(&bad),
            "a present non-array `messages` must reject",
        );
    }
}

#[test]
fn absent_messages_and_empty_array_stay_lenient() {
    // Absent `messages` → still parses (leniency preserved).
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x"}))
        .expect("absent messages must not reject");
    // Empty array → still parses (an empty conversation is legal, not a type violation).
    let ir = OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": []}))
        .expect("empty messages array must not reject");
    assert!(ir.messages.is_empty());
    // Unknown well-typed field → passes through (forward-compat).
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": [], "future_key": {"x": 1}}))
        .expect("unknown well-typed field must not reject");
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
            OpenAiReader.read_request(&bad),
            "a present wrong-typed per-message content must reject",
        );
    }
}

#[test]
fn per_message_string_array_and_null_content_stay_lenient() {
    // String content — legal.
    OpenAiReader
        .read_request(
            &serde_json::json!({"model": "x", "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("string content must parse");
    // Array content — legal.
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]}))
        .expect("array content must parse");
    // Null content on an assistant turn carrying only tool_calls — legal (absent-equivalent).
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "content": serde_json::Value::Null,
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}))
        .expect("null content with tool_calls must parse");
}

// ── Fix 2: tool_call `id` ────────────────────────────────────────────────────

#[test]
fn tool_call_missing_id_rejects() {
    for bad in [
        // id absent
        serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "tool_calls": [{"type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}),
        // id present but empty
        serde_json::json!({"model": "x", "messages": [{
            "role": "assistant",
            "tool_calls": [{"id": "", "type": "function", "function": {"name": "f", "arguments": "{}"}}]
        }]}),
    ] {
        assert_ir_parse_reject(
            OpenAiReader.read_request(&bad),
            "a tool_call with no usable id must reject (never invent one)",
        );
    }
}

#[test]
fn tool_call_with_id_parses() {
    let ir = OpenAiReader
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

// ── Chat#2: top-level `tools` type ───────────────────────────────────────────
// A PRESENT-but-wrong-typed `tools` was silently coerced to empty, so a client sending
// `"tools":{...}` proceeded TOOL-LESS at HTTP 200. It must reject like `messages` does.
#[test]
fn top_level_tools_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "messages": [], "tools": {"a": 1}}),
        serde_json::json!({"model": "x", "messages": [], "tools": "nope"}),
        serde_json::json!({"model": "x", "messages": [], "tools": 7}),
    ] {
        assert_ir_parse_reject(
            OpenAiReader.read_request(&bad),
            "a present-but-wrong-typed tools must reject",
        );
    }
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": []}))
        .expect("absent tools must stay lenient");
    OpenAiReader
        .read_request(&serde_json::json!({"model": "x", "messages": [], "tools": []}))
        .expect("empty-array tools must parse");
}
