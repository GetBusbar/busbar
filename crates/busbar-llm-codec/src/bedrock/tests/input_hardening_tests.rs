// Input-hardening (1.6.0): the Bedrock Converse reader EDGE-VALIDATES structural types. Top-level
// `messages` and per-message `content` are ARRAY-ONLY, so a present string/number/object in either
// position is a genuine TYPE violation → native 400 (ClientError / ir_parse). A `toolUse` block must
// carry a non-empty `toolUseId`. These pin BOTH the reject AND the preserved leniency.

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
        Some(busbar_substrate_values::proto::SIGNAL_IR_PARSE),
        "{ctx}: must carry the ir_parse signal"
    );
}

// ── Fix 1: top-level `messages` type ─────────────────────────────────────────

#[test]
fn top_level_messages_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"messages": "nope"}),
        serde_json::json!({"messages": 7}),
        serde_json::json!({"messages": {"a": 1}}),
    ] {
        assert_ir_parse_reject(
            BedrockReader.read_request(&bad),
            "a present non-array `messages` must reject",
        );
    }
}

#[test]
fn absent_and_empty_messages_stay_lenient() {
    BedrockReader
        .read_request(&serde_json::json!({}))
        .expect("absent messages must not reject");
    let ir = BedrockReader
        .read_request(&serde_json::json!({"messages": []}))
        .expect("empty messages array must not reject");
    assert!(ir.messages.is_empty());
}

// ── Fix 1: per-message `content` type (array-only) ───────────────────────────

#[test]
fn per_message_wrong_typed_content_rejects() {
    for bad in [
        serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}),
        serde_json::json!({"messages": [{"role": "user", "content": 5}]}),
        serde_json::json!({"messages": [{"role": "user", "content": {"text": "hi"}}]}),
    ] {
        assert_ir_parse_reject(
            BedrockReader.read_request(&bad),
            "a present non-array `content` must reject",
        );
    }
}

#[test]
fn array_and_absent_content_stay_lenient() {
    BedrockReader
        .read_request(
            &serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
        )
        .expect("array content must parse");
    BedrockReader
        .read_request(&serde_json::json!({"messages": [{"role": "user"}]}))
        .expect("absent content must parse");
}

// ── Fix 2: toolUse `toolUseId` ───────────────────────────────────────────────

#[test]
fn tool_use_missing_id_rejects() {
    for bad in [
        serde_json::json!({"messages": [{
            "role": "assistant",
            "content": [{"toolUse": {"name": "f", "input": {}}}]
        }]}),
        serde_json::json!({"messages": [{
            "role": "assistant",
            "content": [{"toolUse": {"toolUseId": "", "name": "f", "input": {}}}]
        }]}),
    ] {
        assert_ir_parse_reject(
            BedrockReader.read_request(&bad),
            "a toolUse block with no usable toolUseId must reject",
        );
    }
}

#[test]
fn tool_use_with_id_parses() {
    let ir = BedrockReader
        .read_request(&serde_json::json!({"messages": [{
            "role": "assistant",
            "content": [{"toolUse": {"toolUseId": "tu_1", "name": "f", "input": {}}}]
        }]}))
        .expect("a toolUse with a non-empty id must parse");
    let has_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { id, .. } if id == "tu_1"));
    assert!(has_id, "the toolUseId must be carried into the IR verbatim");
}
