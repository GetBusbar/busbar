// Input-hardening (1.6.0): the Gemini reader EDGE-VALIDATES structural types. Gemini's `contents`
// and per-turn `parts` are ARRAY-ONLY, so a present string/number/object in either position is a
// genuine TYPE violation → native 400 (ClientError / ir_parse). Gemini carries NO wire tool-call id
// (busbar synthesizes one), so there is no id to reject — the Fix-2 analog here is the no-regression
// pin that a functionCall still parses. These pin BOTH the reject AND the preserved leniency.

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

// ── Fix 1: top-level `contents` type ─────────────────────────────────────────

#[test]
fn top_level_contents_wrong_typed_rejects() {
    for bad in [
        serde_json::json!({"contents": "nope"}),
        serde_json::json!({"contents": 7}),
        serde_json::json!({"contents": {"a": 1}}),
    ] {
        assert_ir_parse_reject(
            GeminiReader.read_request(&bad),
            "a present non-array `contents` must reject",
        );
    }
}

#[test]
fn absent_and_empty_contents_stay_lenient() {
    GeminiReader
        .read_request(&serde_json::json!({}))
        .expect("absent contents must not reject");
    let ir = GeminiReader
        .read_request(&serde_json::json!({"contents": []}))
        .expect("empty contents array must not reject");
    assert!(ir.messages.is_empty());
}

// ── Fix 1: per-turn `parts` type (array-only) ────────────────────────────────

#[test]
fn per_turn_wrong_typed_parts_rejects() {
    for bad in [
        // A string where the array is required is itself a TYPE violation for Gemini.
        serde_json::json!({"contents": [{"role": "user", "parts": "hi"}]}),
        serde_json::json!({"contents": [{"role": "user", "parts": 5}]}),
        serde_json::json!({"contents": [{"role": "user", "parts": {"text": "hi"}}]}),
    ] {
        assert_ir_parse_reject(
            GeminiReader.read_request(&bad),
            "a present non-array `parts` must reject",
        );
    }
}

#[test]
fn array_and_absent_parts_stay_lenient() {
    GeminiReader
        .read_request(
            &serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
        )
        .expect("array parts must parse");
    // A turn with no `parts` is degenerate but not a type violation.
    GeminiReader
        .read_request(&serde_json::json!({"contents": [{"role": "user"}]}))
        .expect("absent parts must parse");
}

// ── Fix 2 analog: no tool-call id to reject; a functionCall still parses ──────

#[test]
fn function_call_without_wire_id_still_parses() {
    // Gemini's functionCall carries no id; busbar synthesizes a non-empty one. Pin that this is
    // NOT rejected (no over-reach) and the synthesized id is non-empty.
    let ir = GeminiReader
        .read_request(
            &serde_json::json!({"contents": [{"role": "model", "parts": [
                {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}
            ]}]}),
        )
        .expect("a Gemini functionCall (no wire id) must still parse");
    let non_empty_id = ir
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { id, .. } if !id.is_empty()));
    assert!(
        non_empty_id,
        "the synthesized tool_use id must be non-empty"
    );
}
