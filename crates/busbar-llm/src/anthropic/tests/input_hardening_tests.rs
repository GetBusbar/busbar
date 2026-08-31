// Input-hardening (1.6.0): the Anthropic reader EDGE-VALIDATES structural types — a PRESENT-but-
// wrong-typed field is rejected with a native 400 (ClientError / ir_parse) — while staying as
// lenient as the provider otherwise. These pin BOTH the reject AND the preserved leniency.

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
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": "nope"}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": 7}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": {"a": 1}}),
    ] {
        assert_ir_parse_reject(
            AnthropicReader.read_request(&bad),
            "a present non-array `messages` must reject",
        );
    }
}

#[test]
fn absent_and_empty_messages_stay_lenient() {
    AnthropicReader
        .read_request(&serde_json::json!({"model": "x", "max_tokens": 16}))
        .expect("absent messages must not reject");
    let ir = AnthropicReader
        .read_request(&serde_json::json!({"model": "x", "max_tokens": 16, "messages": []}))
        .expect("empty messages array must not reject");
    assert!(ir.messages.is_empty());
}

// ── Fix 1: per-message `content` type ────────────────────────────────────────

#[test]
fn per_message_wrong_typed_content_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user", "content": 5}]}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user", "content": {"a": 1}}]}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user", "content": true}]}),
    ] {
        assert_ir_parse_reject(
            AnthropicReader.read_request(&bad),
            "a present wrong-typed per-message content must reject",
        );
    }
}

#[test]
fn per_message_string_and_array_content_stay_lenient() {
    AnthropicReader
        .read_request(&serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}))
        .expect("string content must parse");
    AnthropicReader
        .read_request(&serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]}))
        .expect("array content must parse");
    // Absent content — legal (degenerate empty turn), not a type violation.
    AnthropicReader
        .read_request(
            &serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{"role": "user"}]}),
        )
        .expect("absent content must parse");
}

// ── Fix 2: tool_use `id` ─────────────────────────────────────────────────────

#[test]
fn tool_use_missing_id_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{
            "role": "assistant",
            "content": [{"type": "tool_use", "name": "f", "input": {}}]
        }]}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "", "name": "f", "input": {}}]
        }]}),
    ] {
        assert_ir_parse_reject(
            AnthropicReader.read_request(&bad),
            "a tool_use block with no usable id must reject",
        );
    }
}

#[test]
fn tool_use_with_id_parses() {
    let ir = AnthropicReader
        .read_request(
            &serde_json::json!({"model": "x", "max_tokens": 16, "messages": [{
                "role": "assistant",
                "content": [{"type": "tool_use", "id": "toolu_1", "name": "f", "input": {}}]
            }]}),
        )
        .expect("a tool_use with a non-empty id must parse");
    let has_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { id, .. } if id == "toolu_1"));
    assert!(
        has_id,
        "the tool_use id must be carried into the IR verbatim"
    );
}

// ── Chat#2: top-level `tools` type ───────────────────────────────────────────
// A PRESENT-but-wrong-typed `tools` was silently coerced to empty (`as_array().unwrap_or(&[])`),
// so a client sending `"tools":{...}` proceeded TOOL-LESS at HTTP 200 — its tools stripped with no
// error. It must reject like `messages`/`content` do.
#[test]
fn top_level_tools_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [], "tools": {"a": 1}}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [], "tools": "nope"}),
        serde_json::json!({"model": "x", "max_tokens": 16, "messages": [], "tools": 7}),
    ] {
        assert_ir_parse_reject(
            AnthropicReader.read_request(&bad),
            "a present-but-wrong-typed tools must reject",
        );
    }
    // An ABSENT or empty-array `tools` stays lenient.
    AnthropicReader
        .read_request(&serde_json::json!({"model": "x", "max_tokens": 16, "messages": []}))
        .expect("absent tools must stay lenient");
    AnthropicReader
        .read_request(
            &serde_json::json!({"model": "x", "max_tokens": 16, "messages": [], "tools": []}),
        )
        .expect("empty-array tools must parse");
}
