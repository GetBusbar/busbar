// Input-hardening (1.6.0): the Responses reader EDGE-VALIDATES structural types. Top-level `input`
// is legally a bare string or an array of input items; a present number/bool/object is a genuine
// TYPE violation → native 400 (ClientError / ir_parse). A `message` item's `content` must be
// string/array/absent, and a `function_call` item must carry a non-empty `call_id`. These pin BOTH
// the reject AND the preserved leniency.

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

// ── Fix 1: top-level `input` type ────────────────────────────────────────────

#[test]
fn top_level_input_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "input": 42}),
        serde_json::json!({"model": "x", "input": {"a": 1}}),
        serde_json::json!({"model": "x", "input": true}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a present non-string/non-array `input` must reject",
        );
    }
}

#[test]
fn string_array_and_instructions_only_input_stay_lenient() {
    // Bare string input — legal.
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": "hi"}))
        .expect("string input must parse");
    // Empty array input — legal (an empty conversation is not a type violation).
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": []}))
        .expect("empty array input must parse");
    // Null input WITH instructions — an instructions-only request stays valid (null == absent).
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "instructions": "be nice", "input": serde_json::Value::Null}))
        .expect("null input with instructions must parse");
}

// ── Fix 1: per-message `content` type ────────────────────────────────────────

#[test]
fn per_message_wrong_typed_content_rejects() {
    for bad in [
        // typed message item
        serde_json::json!({"model": "x", "input": [{"type": "message", "role": "user", "content": 5}]}),
        serde_json::json!({"model": "x", "input": [{"type": "message", "role": "user", "content": {"a": 1}}]}),
        // untyped role-keyed item
        serde_json::json!({"model": "x", "input": [{"role": "user", "content": 9}]}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a present wrong-typed message content must reject",
        );
    }
}

#[test]
fn per_message_string_and_array_content_stay_lenient() {
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": [{"type": "message", "role": "user", "content": "hi"}]}))
        .expect("string message content must parse");
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]}]}))
        .expect("array message content must parse");
}

// ── Fix 2: function_call `call_id` ───────────────────────────────────────────

#[test]
fn function_call_missing_id_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "input": [{"type": "function_call", "name": "f", "arguments": "{}"}]}),
        serde_json::json!({"model": "x", "input": [{"type": "function_call", "call_id": "", "name": "f", "arguments": "{}"}]}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a function_call item with no usable call_id must reject",
        );
    }
}

#[test]
fn function_call_with_id_parses() {
    let ir = ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": [
            {"type": "function_call", "call_id": "call_abc", "name": "f", "arguments": "{}"}
        ]}))
        .expect("a function_call with a non-empty call_id must parse");
    let has_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { id, .. } if id == "call_abc"));
    assert!(has_id, "the call_id must be carried into the IR verbatim");
}

// ── Chat#2: top-level `tools` type ───────────────────────────────────────────
// A PRESENT-but-wrong-typed `tools` was silently coerced to empty, so a client sending
// `"tools":{...}` proceeded TOOL-LESS at HTTP 200. It must reject like `input` does.
#[test]
fn top_level_tools_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "input": "hi", "tools": {"a": 1}}),
        serde_json::json!({"model": "x", "input": "hi", "tools": "nope"}),
        serde_json::json!({"model": "x", "input": "hi", "tools": 7}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a present-but-wrong-typed tools must reject",
        );
    }
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": "hi"}))
        .expect("absent tools must stay lenient");
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": "hi", "tools": []}))
        .expect("empty-array tools must parse");
}

// ── T3 stateful Responses: `previous_response_id` / `store` type discipline ───
// The server-side conversation-state knobs ride `extra` verbatim (busbar is a translator; the
// upstream owns the state), but a PRESENT value of the wrong TYPE is a house-policy 400: the extra
// pass-through would otherwise relay a malformed field to the backend. `previous_response_id` is a
// string; `store` is a bool. Absent/null stays lenient.
#[test]
fn stateful_previous_response_id_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "input": "hi", "previous_response_id": 5}),
        serde_json::json!({"model": "x", "input": "hi", "previous_response_id": true}),
        serde_json::json!({"model": "x", "input": "hi", "previous_response_id": {"id": "resp_1"}}),
        serde_json::json!({"model": "x", "input": "hi", "previous_response_id": ["resp_1"]}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a present non-string previous_response_id must reject",
        );
    }
}

#[test]
fn stateful_store_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"model": "x", "input": "hi", "store": "yes"}),
        serde_json::json!({"model": "x", "input": "hi", "store": 1}),
        serde_json::json!({"model": "x", "input": "hi", "store": {"enabled": true}}),
    ] {
        assert_ir_parse_reject(
            ResponsesReader.read_request(&bad),
            "a present non-bool store must reject",
        );
    }
}

#[test]
fn stateful_knobs_stay_lenient_when_absent_null_or_correctly_typed() {
    // Absent — lenient.
    ResponsesReader
        .read_request(&serde_json::json!({"model": "x", "input": "hi"}))
        .expect("absent stateful knobs must parse");
    // Null — treated as absent, lenient.
    ResponsesReader
        .read_request(&serde_json::json!({
            "model": "x", "input": "hi",
            "previous_response_id": serde_json::Value::Null,
            "store": serde_json::Value::Null
        }))
        .expect("null stateful knobs must parse");
    // Correctly typed — parse (and, per the round-trip test, ride extra).
    ResponsesReader
        .read_request(&serde_json::json!({
            "model": "x", "input": "hi",
            "previous_response_id": "resp_abc123",
            "store": false
        }))
        .expect("correctly-typed stateful knobs must parse");
}
